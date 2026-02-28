use aya_ebpf::{
    EbpfContext,
    helpers::bpf_ktime_get_boot_ns,
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray},
    programs::TracePointContext,
};
use profiler_common::*;

// Pairs wakeup with switch. Key: pid, Value: wakeup timestamp (ns).
#[map]
static WAKEUP_START: LruHashMap<u32, u64> = LruHashMap::with_max_entries(10240, 0);

#[map]
static SCHED_SCRATCH: PerCpuArray<SchedLatencyEvent> = PerCpuArray::with_max_entries(1, 0);

// Tracepoint: sched:sched_wakeup
#[tracepoint]
pub fn handle_sched_wakeup(ctx: TracePointContext) -> u32 {
    record_wakeup(&ctx)
}

// Tracepoint: sched:sched_wakeup_new (same format, catches new forks)
#[tracepoint]
pub fn handle_sched_wakeup_new(ctx: TracePointContext) -> u32 {
    record_wakeup(&ctx)
}

#[inline(always)]
fn record_wakeup(ctx: &TracePointContext) -> u32 {
    let pid: i32 = match unsafe { ctx.read_at(24) } {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let now = unsafe { bpf_ktime_get_boot_ns() };
    let _ = WAKEUP_START.insert(&(pid as u32), &now, 0);
    0
}

// Tracepoint: sched:sched_switch — measure run queue latency
#[tracepoint]
pub fn handle_sched_switch(ctx: TracePointContext) -> u32 {
    match try_handle_sched_switch(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_sched_switch(ctx: &TracePointContext) -> Result<u32, i64> {
    let next_pid: i32 = unsafe { ctx.read_at(56).map_err(|e| e as i64)? };
    let pid = next_pid as u32;

    let wakeup_ns = match unsafe { WAKEUP_START.get(&pid) } {
        Some(ts) => *ts,
        None => return Ok(0),
    };
    let _ = WAKEUP_START.remove(&pid);

    let now = unsafe { bpf_ktime_get_boot_ns() };
    let latency_ns = now.saturating_sub(wakeup_ns);

    let threshold = crate::CONFIG
        .get(CONFIG_SCHED_THRESHOLD_NS)
        .copied()
        .unwrap_or(5_000_000);
    if latency_ns < threshold {
        return Ok(0);
    }

    let event_ptr = SCHED_SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    event.time_ns = now;
    event.event_type = EVENT_SCHED_LATENCY;
    event.pid = pid;
    event.latency_ns = latency_ns;

    event.prio = unsafe { ctx.read_at::<i32>(60).unwrap_or(0) };
    event.target_cpu = -1; // not available in sched_switch

    // next_comm at offset 40
    unsafe {
        core::ptr::write_bytes(event.name.as_mut_ptr(), 0, MAX_PROC_NAME_LEN);
        let src = ctx.as_ptr().add(40) as *const [u8; 16];
        let _ = aya_ebpf::helpers::bpf_probe_read_kernel(src).map(|v| event.name = v);
    }

    if let Some(mut buf) = crate::EVENTS.reserve::<SchedLatencyEvent>(0) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                event_ptr as *const SchedLatencyEvent,
                buf.as_mut_ptr() as *mut SchedLatencyEvent,
                1,
            );
        }
        buf.submit(0);
    }

    Ok(0)
}
