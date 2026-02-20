#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use profiler_common::*;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Scratch space: one ProcessEvent-sized buffer per CPU core
// We can't put ProcessEvent on the stack (512 byte limit),
// so we write into this pre-allocated buffer instead
#[map]
static SCRATCH: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn handle_exec(ctx: TracePointContext) -> u32 {
    match try_handle_exec(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let event_ptr = SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    // Assign small fields directly to the scratch space
    event.time_ns = unsafe { bpf_ktime_get_ns() };
    event.event_type = 0;

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    event.ppid = 0;
    event.exit_code = 0;

    event.name = bpf_get_current_comm().map_err(|e| e as i64)?;

    unsafe {
        // Zero out the large arrays directly in memory (no stack allocation)
        core::ptr::write_bytes(event.filename.as_mut_ptr(), 0, MAX_FILENAME_LEN);
        core::ptr::write_bytes(
            event.args.as_mut_ptr() as *mut u8,
            0,
            MAX_ARG_LEN * MAX_ARG_COUNT,
        );
    }

    // Reserve space in the ring buffer
    if let Some(mut buf) = EVENTS.reserve::<ProcessEvent>(0) {
        unsafe {
            // Copy Memory-to-Memory (Map -> RingBuf) without touching the stack
            core::ptr::copy_nonoverlapping(
                event_ptr as *const ProcessEvent,
                buf.as_mut_ptr() as *mut ProcessEvent,
                1, // Copy 1 instance of ProcessEvent
            );
        }
        buf.submit(0);
    }

    info!(ctx, "Successfully intercepted exec from PID: {}", event.pid);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
