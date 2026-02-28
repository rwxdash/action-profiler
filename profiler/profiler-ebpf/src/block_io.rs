use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_comm, bpf_ktime_get_boot_ns},
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray},
    programs::TracePointContext,
};
use profiler_common::*;

#[map]
static IO_START: LruHashMap<u64, BlockIoStash> = LruHashMap::with_max_entries(10240, 0);

#[map]
static BLOCK_IO_SCRATCH: PerCpuArray<BlockIoEvent> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn io_key(dev: u32, sector: u64) -> u64 {
    ((dev as u64) << 40) | (sector & 0xFF_FFFF_FFFF)
}

// Tracepoint: block:block_rq_issue
#[tracepoint]
pub fn handle_block_rq_issue(ctx: TracePointContext) -> u32 {
    match try_handle_block_rq_issue(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_block_rq_issue(ctx: &TracePointContext) -> Result<u32, i64> {
    let dev: u32 = unsafe { ctx.read_at(8).map_err(|e| e as i64)? };
    let sector: u64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    let nr_sectors: u32 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };

    let mut rwbs = [0u8; 8];
    unsafe {
        let src = ctx.as_ptr().add(32) as *const [u8; 8];
        let _ = aya_ebpf::helpers::bpf_probe_read_kernel(src).map(|v| rwbs = v);
    }

    let stash = BlockIoStash {
        time_ns: unsafe { bpf_ktime_get_boot_ns() },
        pid: (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32,
        name: bpf_get_current_comm().unwrap_or([0u8; 16]),
        rwbs,
        nr_sectors,
    };

    let key = io_key(dev, sector);
    let _ = IO_START.insert(&key, &stash, 0);

    Ok(0)
}

// Tracepoint: block:block_rq_complete
#[tracepoint]
pub fn handle_block_rq_complete(ctx: TracePointContext) -> u32 {
    match try_handle_block_rq_complete(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_block_rq_complete(ctx: &TracePointContext) -> Result<u32, i64> {
    let dev: u32 = unsafe { ctx.read_at(8).map_err(|e| e as i64)? };
    let sector: u64 = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };

    let key = io_key(dev, sector);

    let stash = match unsafe { IO_START.get(&key) } {
        Some(s) => *s,
        None => return Ok(0), // started before profiler
    };
    let _ = IO_START.remove(&key);

    let now = unsafe { bpf_ktime_get_boot_ns() };
    let latency_ns = now.saturating_sub(stash.time_ns);

    let threshold = crate::CONFIG
        .get(profiler_common::CONFIG_BLOCK_IO_THRESHOLD_NS)
        .copied()
        .unwrap_or(1_000_000);
    if latency_ns < threshold {
        return Ok(0);
    }

    let event_ptr = BLOCK_IO_SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    event.time_ns = now;
    event.event_type = EVENT_BLOCK_IO;
    event.dev = dev;
    event.sector = sector;
    event.nr_sectors = stash.nr_sectors;
    event.latency_ns = latency_ns;
    event.rwbs = stash.rwbs;
    event.pid = stash.pid;
    event.name = stash.name;

    if let Some(mut buf) = crate::EVENTS.reserve::<BlockIoEvent>(0) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                event_ptr as *const BlockIoEvent,
                buf.as_mut_ptr() as *mut BlockIoEvent,
                1,
            );
        }
        buf.submit(0);
    }

    Ok(0)
}
