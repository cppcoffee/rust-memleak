use std::collections::HashMap;
use std::env;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{HashMap as EbpfHashMap, StackTraceMap};
use aya::programs::UProbe;
use aya::util::kernel_symbols;
use aya::Ebpf;
use blazesym::symbolize::{Input, Process, Source, Symbolizer};
use blazesym::Pid;
use clap::Parser;
use libc::pid_t;
use log::{debug, info, warn};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

use rust_memleak::util::get_binary_path_by_pid;
use rust_memleak_common::AllocInfo;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, help = "pid of the process")]
    pid: pid_t,

    #[clap(short, long, help = "binary path [optional]")]
    bin: Option<PathBuf>,

    #[clap(short, long, default_value = "10", help = "interval in seconds")]
    interval: u64,

    #[clap(short, long, default_value = "/tmp/memleak.out", help = "output file")]
    output: PathBuf,

    #[clap(short, long, default_value = "false", help = "verbose mode")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    if opt.verbose {
        env::var("RUST_LOG")
            .err()
            .map(|_| env::set_var("RUST_LOG", "debug"));
    }

    env_logger::init();

    let exe_path = opt.bin.unwrap_or(get_binary_path_by_pid(opt.pid)?);

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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rust-memleak"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    attach_uprobes(&mut ebpf, &exe_path, Some(opt.pid))?;

    // TODO: more debug message

    // TODO: sleep and ctrl_c, both are supported
    //tokio::signal::ctrl_c().await?;
    sleep(Duration::from_secs(opt.interval)).await;

    let map = dump_stack_frames(&mut ebpf, opt.pid).await?;
    dump_to_file(&opt.output, &map).await?;

    Ok(())
}

fn attach_uprobes(ebpf: &mut Ebpf, bin: &Path, pid: Option<i32>) -> Result<()> {
    // __rust_alloc
    let program: &mut UProbe = ebpf.program_mut("rust_alloc_enter").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__rust_alloc"), 0, &bin, pid)?;

    let program: &mut UProbe = ebpf.program_mut("rust_alloc_exit").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__rust_alloc"), 0, &bin, pid)?;

    // __rust_dealloc
    let program: &mut UProbe = ebpf.program_mut("rust_dealloc_enter").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__rust_dealloc"), 0, &bin, pid)?;

    let program: &mut UProbe = ebpf.program_mut("rust_realloc_enter").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__rust_realloc"), 0, &bin, pid)?;

    // __rust_realloc
    let program: &mut UProbe = ebpf.program_mut("rust_realloc_exit").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("__rust_realloc"), 0, &bin, pid)?;

    // __rust_alloc_zeroed
    let program: &mut UProbe = ebpf
        .program_mut("rust_alloc_zeroed_enter")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("__rust_alloc_zeroed"), 0, &bin, pid)?;

    let program: &mut UProbe = ebpf
        .program_mut("rust_alloc_zeroed_exit")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach(Some("__rust_alloc_zeroed"), 0, &bin, pid)?;

    Ok(())
}

async fn dump_stack_frames(ebpf: &mut Ebpf, pid: pid_t) -> Result<HashMap<String, u64>> {
    let mut result: HashMap<String, u64> = HashMap::new();
    let mut buffer = String::with_capacity(4096);

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

        buffer.clear();

        for frame in stack_trace.frames().iter().rev() {
            match symbolizer.symbolize_single(&src, Input::AbsAddr(frame.ip)) {
                Ok(sym) => {
                    let name = sym
                        .as_sym()
                        .map(|x| format!("{}+0x{:x}", x.name, x.offset))
                        .unwrap_or(format!("unknown_0x{:08x}", frame.ip));

                    if buffer.len() > 0 {
                        buffer.push(';');
                    }

                    buffer.push_str(&name);
                }
                Err(e) => {
                    match ksyms
                        .range(..=frame.ip)
                        .next_back()
                        .map(|(&sym_addr, name)| {
                            let offset = frame.ip - sym_addr;
                            (name.clone(), offset)
                        }) {
                        Some((name, offset)) => {
                            if buffer.len() > 0 {
                                buffer.push(';')
                            }

                            buffer.push_str(&format!("{}+0x{:x}", name, offset));
                        }
                        None => {
                            warn!("failed to symbolize frame ip=0x{:08x}: {}", frame.ip, e)
                        }
                    }
                }
            }
        }

        *result.entry(buffer.clone()).or_default() += heap_size;
    }

    Ok(result)
}

async fn dump_to_file(path: &Path, map: &HashMap<String, u64>) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .context(format!("failed to open file: {:?}", path))?;

    for (k, v) in map.iter() {
        let s = format!("{} {}\n", k, v);

        file.write_all(s.as_bytes())
            .await
            .context(format!("failed to write file: {:?}", path))?;
    }

    info!("dump stack frame to {:?}", path);

    Ok(())
}
