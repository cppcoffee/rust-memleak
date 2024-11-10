use std::collections::{BTreeMap, HashMap};
use std::env;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use aya::maps::stack_trace::StackTrace;
use aya::maps::{HashMap as EbpfHashMap, StackTraceMap};
use aya::programs::UProbe;
use aya::util::kernel_symbols;
use aya::{Btf, Ebpf, EbpfLoader};
use blazesym::symbolize::{CodeInfo, Input, Process, Source, Sym, Symbolizer};
use blazesym::Pid;
use clap::Parser;
use libc::pid_t;
use log::{debug, info, warn};
use tokio::time::sleep;

use rust_memleak::util::{dump_to_file, get_binary_path_by_pid};
use rust_memleak_common::AllocInfo;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, help = "pid of the process")]
    pid: pid_t,

    #[clap(short, long, help = "binary path [optional]")]
    bin: Option<PathBuf>,

    #[clap(short, long, default_value = "30", help = "timeout in seconds")]
    timeout: u64,

    #[clap(short, long, default_value = "/tmp/memleak.out", help = "output file")]
    output: PathBuf,

    #[clap(short, long, default_value = "false", help = "verbose mode")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // set log level, when RUST_LOG env not set
    if env::var("RUST_LOG").is_err() {
        let s = if opt.verbose { "debug" } else { "info" };

        env::var("RUST_LOG")
            .err()
            .map(|_| env::set_var("RUST_LOG", s));
    }

    env_logger::init();

    let exe_path = opt.bin.unwrap_or(get_binary_path_by_pid(opt.pid).await?);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global("TRACE_ALL", &(opt.verbose as u8), true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/rust-memleak"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    attach_uprobes(&mut ebpf, &exe_path, Some(opt.pid))?;

    info!("attached uprobes to {}", exe_path.display());

    info!("wait for {}s or press ctrl+c to start dump", opt.timeout);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received Ctrl-C, dump stack frames starting...")
        },
        _ = sleep(Duration::from_secs(opt.timeout)) => {
            info!("time is up, dump stack frames starting...")
        }
    }

    let map = dump_stack_frames(&mut ebpf, opt.pid).await?;
    dump_to_file(&opt.output, &map).await?;

    info!("dump stack frame to {:?}", opt.output);

    Ok(())
}

fn attach_uprobes(ebpf: &mut Ebpf, bin: &Path, pid: Option<i32>) -> Result<()> {
    let probes = [
        ("__rust_alloc", "rust_alloc_enter"),
        ("__rust_alloc", "rust_alloc_exit"),
        ("__rust_dealloc", "rust_dealloc_enter"),
        ("__rust_realloc", "rust_realloc_enter"),
        ("__rust_realloc", "rust_realloc_exit"),
        ("__rust_alloc_zeroed", "rust_alloc_zeroed_enter"),
        ("__rust_alloc_zeroed", "rust_alloc_zeroed_exit"),
    ];

    for probe in &probes {
        debug!("attach uprobe {} to {}", probe.1, probe.0);

        let program: &mut UProbe = ebpf.program_mut(probe.1).unwrap().try_into()?;
        program.load()?;
        program.attach(Some(probe.0), 0, &bin, pid)?;
    }

    Ok(())
}

async fn dump_stack_frames(ebpf: &mut Ebpf, pid: pid_t) -> Result<HashMap<String, u64>> {
    let mut count = 0;
    let mut result: HashMap<String, u64> = HashMap::new();

    let src = Source::Process(Process::new(Pid::Pid(NonZeroU32::new(pid as u32).unwrap())));
    let symbolizer = Symbolizer::new();
    let ksyms = kernel_symbols().context("failed to load kernel symbols")?;

    let stack_traces = StackTraceMap::try_from(ebpf.map("STACK_TRACES").unwrap())?;
    let allocs: EbpfHashMap<_, u64, AllocInfo> =
        EbpfHashMap::try_from(ebpf.map("ALLOCS").unwrap())?;

    for item in allocs.iter() {
        let (_key, value) = item.context("failed to iter ALLOCS map")?;

        let heap_size = value.size;
        let stack_id = value.stack_id as u32;

        let stack_trace = stack_traces.get(&stack_id, 0)?;
        let stack_frame = symbolize_stack_frames(&stack_trace, &symbolizer, &src, &ksyms)?;

        *result.entry(stack_frame).or_default() += heap_size;

        count += 1;
    }

    info!("total {} stack frames, collapse to {}", count, result.len());

    Ok(result)
}

fn symbolize_stack_frames(
    stack_trace: &StackTrace,
    symbolizer: &Symbolizer,
    src: &Source,
    ksyms: &BTreeMap<u64, String>,
) -> Result<String> {
    let addrs: Vec<_> = stack_trace.frames().iter().rev().map(|x| x.ip).collect();

    let syms = symbolizer
        .symbolize(src, Input::AbsAddr(&addrs))
        .map_err(|e| anyhow!(format!("symbolize fail: {}", e)))?;

    let mut buffer = String::with_capacity(128);

    for (sym, addr) in syms.iter().zip(addrs.iter()) {
        if !buffer.is_empty() {
            buffer.push(';');
        }

        let name = match sym.as_sym() {
            Some(x) => format_symbolize(x),
            None => {
                ksymbols_search(ksyms, *addr).unwrap_or_else(|| format!("unknown_0x{:08x}", addr))
            }
        };

        buffer.push_str(&name);
    }

    Ok(buffer)
}

fn format_symbolize(sym: &Sym<'_>) -> String {
    let mut s = sym.name.to_string();

    if let Some(code_info) = &sym.code_info {
        s += format!(" ({})", format_code_info(&code_info)).as_ref();
    } else {
        if sym.inlined.len() > 0 {
            let inlined = &sym.inlined[0];

            s += format!(" <inlined:{}>", inlined.name).as_ref();

            if let Some(code_info) = &inlined.code_info {
                s += format!(" ({})", format_code_info(&code_info)).as_ref();
            }
        }
    }

    s += format!(" +0x{:x}", sym.offset).as_ref();

    s
}

fn format_code_info(code_info: &CodeInfo<'_>) -> String {
    match (code_info.dir.as_ref(), code_info.line) {
        (Some(dir), Some(line)) => {
            format!(
                "{}/{}:{}",
                dir.display(),
                code_info.file.to_string_lossy(),
                line
            )
        }
        (Some(dir), None) => format!("{}/{}", dir.display(), code_info.file.to_string_lossy()),
        (None, Some(line)) => format!("{}:{}", code_info.file.to_string_lossy(), line),
        (None, None) => format!("{}", code_info.file.to_string_lossy()),
    }
}

fn ksymbols_search(ksyms: &BTreeMap<u64, String>, ip: u64) -> Option<String> {
    let (sym_addr, name) = ksyms.range(..=ip).next_back()?;

    let kernel_addr_start = if cfg!(target_pointer_width = "64") {
        0xFFFF_8000_0000_0000
    } else {
        0xC000_0000
    };

    let result = if ip >= kernel_addr_start {
        let offset = ip - sym_addr;
        format!("{}+0x{:x}", name, offset)
    } else {
        name.to_string()
    };

    Some(result)
}
