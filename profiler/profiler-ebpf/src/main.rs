#![no_std]
#![no_main]

#[allow(
    non_upper_case_globals,
    non_snake_case,
    non_camel_case_types,
    dead_code
)]
mod vmlinux;

use core::ptr::addr_of;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, generated::bpf_get_current_task,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use profiler_common::*;
use vmlinux::task_struct;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map] // Stores the string names ("node", "sh")
static IGNORED_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

#[map] // Stores active PIDs to cascade the ignore to children
static IGNORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

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

#[tracepoint]
pub fn handle_fork(ctx: TracePointContext) -> u32 {
    // In the Linux kernel format for sched_process_fork:
    // Parent PID is at byte offset 24
    // Child PID is at byte offset 44
    let parent_pid: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let child_pid: u32 = unsafe { ctx.read_at(44).unwrap_or(0) };

    // If the parent is ignored, the child inherits the ignored status!
    if unsafe { IGNORED_PIDS.get(&parent_pid).is_some() } {
        let _ = IGNORED_PIDS.insert(&child_pid, &1, 0);
    }

    0
}

#[tracepoint]
pub fn handle_exit(_ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let _ = IGNORED_PIDS.remove(&pid);

    0
}

fn try_handle_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|e| e as i64)?;

    // 1. Is this command explicitly ignored by name?
    if unsafe { IGNORED_NAMES.get(&comm).is_some() } {
        // Add this PID to the active blocklist!
        let _ = IGNORED_PIDS.insert(&pid, &1, 0);
        return Ok(0); // Drop event
    }

    // 2. Is this PID already in the active blocklist?
    // (We will populate this from the fork tracepoint below)
    if unsafe { IGNORED_PIDS.get(&pid).is_some() } {
        return Ok(0); // Drop event
    }

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

    // Read PPID via CO-RE: task_struct->real_parent->tgid
    // Uses vmlinux bindings so offsets are resolved at load time via BTF
    event.ppid = unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        let parent: *const task_struct =
            bpf_probe_read_kernel(addr_of!((*task).real_parent) as *const *const task_struct)
                .unwrap_or(core::ptr::null());
        if !parent.is_null() {
            bpf_probe_read_kernel(addr_of!((*parent).tgid) as *const i32).unwrap_or(0) as u32
        } else {
            0
        }
    };
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
