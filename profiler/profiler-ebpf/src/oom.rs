use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_ktime_get_boot_ns, bpf_probe_read_kernel_str_bytes},
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use profiler_common::*;

#[map]
static OOM_SCRATCH: PerCpuArray<OomKillEvent> = PerCpuArray::with_max_entries(1, 0);

// Tracepoint: oom:mark_victim
#[tracepoint]
pub fn handle_oom_kill(ctx: TracePointContext) -> u32 {
    match try_handle_oom_kill(&ctx) {
        Ok(_) => 0,
        Err(_) => {
            aya_log_ebpf::error!(&ctx, "OOM handler failed");
            0
        }
    }
}

fn try_handle_oom_kill(ctx: &TracePointContext) -> Result<u32, i64> {
    let event_ptr = OOM_SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    event.time_ns = unsafe { bpf_ktime_get_boot_ns() };
    event.event_type = EVENT_OOM_KILL;

    event.pid = unsafe { ctx.read_at::<i32>(8).map_err(|e| e as i64)? } as u32;

    aya_log_ebpf::info!(ctx, "OOM kill: victim pid={}", event.pid);

    // __data_loc encoding: lower 16 bits = offset, upper 16 bits = length
    let data_loc: u32 = unsafe { ctx.read_at(12).map_err(|e| e as i64)? };
    let str_offset = (data_loc & 0xFFFF) as usize;
    unsafe {
        core::ptr::write_bytes(event.victim_name.as_mut_ptr(), 0, MAX_PROC_NAME_LEN);
        let base = ctx.as_ptr().add(str_offset);
        let _ = bpf_probe_read_kernel_str_bytes(base as *const u8, &mut event.victim_name);
    }

    // Memory stats (all in KB)
    event.total_vm_kb = unsafe { ctx.read_at(16).map_err(|e| e as i64)? };
    event.anon_rss_kb = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };
    event.file_rss_kb = unsafe { ctx.read_at(32).map_err(|e| e as i64)? };
    event.shmem_rss_kb = unsafe { ctx.read_at(40).map_err(|e| e as i64)? };

    event.uid = unsafe { ctx.read_at(48).map_err(|e| e as i64)? };
    event.pgtables_kb = unsafe { ctx.read_at(56).map_err(|e| e as i64)? };
    event.oom_score_adj = unsafe { ctx.read_at(64).map_err(|e| e as i64)? };

    if let Some(mut buf) = crate::OOM_EVENTS.reserve::<OomKillEvent>(0) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                event_ptr as *const OomKillEvent,
                buf.as_mut_ptr() as *mut OomKillEvent,
                1,
            );
        }
        buf.submit(0);
        aya_log_ebpf::info!(ctx, "OOM event submitted to ring buffer");
    } else {
        aya_log_ebpf::error!(ctx, "OOM: failed to reserve ring buffer slot");
    }

    Ok(0)
}
