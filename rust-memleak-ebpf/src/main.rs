#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_FAST_STACK_CMP, BPF_F_REUSE_STACKID, BPF_F_USER_STACK},
    cty::c_long,
    helpers::{bpf_get_current_pid_tgid, gen::bpf_ktime_get_ns},
    macros::{map, uprobe, uretprobe},
    maps::{stack_trace::StackTrace, HashMap},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;
use rust_memleak_common::{AllocInfo, ALLOCS_MAX_ENTRIES};

#[map]
static SIZES: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static ALLOCS: HashMap<u64, AllocInfo> = HashMap::with_max_entries(ALLOCS_MAX_ENTRIES, 0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(10240, 0);

#[no_mangle]
static TRACE_ALL: bool = false;

#[inline]
fn round_up_size(size: usize, align: usize) -> u64 {
    ((size + align - 1) & !(align - 1)) as u64
}

#[uprobe]
pub fn rust_alloc_enter(ctx: ProbeContext) -> u32 {
    match try_rust_alloc_entry(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_rust_alloc_entry(ctx: ProbeContext) -> Result<u32, c_long> {
    let size: usize = ctx.arg(0).ok_or(1)?;
    let align: usize = ctx.arg(1).ok_or(1)?;

    gen_alloc_entry(&ctx, size, align)
}

#[uretprobe]
pub fn rust_alloc_exit(ctx: RetProbeContext) -> u32 {
    match try_rust_alloc_exit(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_rust_alloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn rust_dealloc_enter(ctx: ProbeContext) -> u32 {
    match try_rust_dealloc_enter(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_rust_dealloc_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.arg(0).ok_or(1)?;
    gen_free_enter(&ctx, ptr)
}

#[uprobe]
pub fn rust_realloc_enter(ctx: ProbeContext) -> u32 {
    match try_rust_realloc_entry(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_rust_realloc_entry(ctx: ProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.arg(0).ok_or(1)?;
    //let old_size: u64 = ctx.arg(1).ok_or(1)?;
    let align: usize = ctx.arg(2).ok_or(1)?;
    let new_size: usize = ctx.arg(3).ok_or(1)?;

    gen_free_enter(&ctx, ptr)?;
    gen_alloc_entry(&ctx, new_size, align)?;

    Ok(0)
}

#[uretprobe]
pub fn rust_realloc_exit(ctx: RetProbeContext) -> u32 {
    match try_rust_realloc_exit(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_rust_realloc_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

#[uprobe]
pub fn rust_alloc_zeroed_enter(ctx: ProbeContext) -> u32 {
    match try_rust_alloc_zeroed_entry(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_rust_alloc_zeroed_entry(ctx: ProbeContext) -> Result<u32, c_long> {
    let size: usize = ctx.arg(0).ok_or(1)?;
    let align: usize = ctx.arg(1).ok_or(1)?;

    gen_alloc_entry(&ctx, size, align)
}

#[uretprobe]
pub fn rust_alloc_zeroed_exit(ctx: RetProbeContext) -> u32 {
    match try_rust_alloc_zeroed_exit(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_rust_alloc_zeroed_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ptr: u64 = ctx.ret().ok_or(1)?;
    gen_alloc_exit(&ctx, ptr)
}

fn gen_alloc_entry(ctx: &ProbeContext, size: usize, align: usize) -> Result<u32, c_long> {
    let size_rounded_up = round_up_size(size, align);
    let tid = bpf_get_current_pid_tgid() as u32;

    SIZES.insert(&tid, &size_rounded_up, 0)?;

    let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
    if trace_all {
        info!(ctx, "alloc entered, size={}", size_rounded_up);
    }

    Ok(0)
}

fn gen_alloc_exit(ctx: &RetProbeContext, ptr: u64) -> Result<u32, c_long> {
    const STACK_FLAGS: u32 = BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID;

    if ptr == 0 {
        return Ok(0);
    }

    let tid = bpf_get_current_pid_tgid() as u32;

    let sz = unsafe { SIZES.get(&tid).ok_or(1)? };
    SIZES.remove(&tid)?;

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let stack_id = unsafe { STACK_TRACES.get_stackid(ctx, STACK_FLAGS as u64)? };

    let value = AllocInfo::new(*sz, timestamp_ns, stack_id);
    ALLOCS.insert(&ptr, &value, 0)?;

    let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
    if trace_all {
        info!(ctx, "alloc exited, size = {}, result = {:x}", *sz, ptr);
    }

    Ok(0)
}

fn gen_free_enter(ctx: &ProbeContext, ptr: u64) -> Result<u32, c_long> {
    let alloc_info = unsafe { ALLOCS.get(&ptr).ok_or(1)? };

    ALLOCS.remove(&ptr)?;

    let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
    if trace_all {
        info!(
            ctx,
            "dealloc entered, address={:x}, size={}\n", ptr, alloc_info.size
        );
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
