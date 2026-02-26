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
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes, generated::bpf_get_current_task,
    },
    macros::{map, raw_tracepoint, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{RawTracePointContext, TracePointContext},
};
use profiler_common::*;
use vmlinux::{linux_binprm, task_struct};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map] // Stores the string names ("node", "sh")
static IGNORED_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

#[map] // Stores active PIDs to cascade the ignore to children
static IGNORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[map]
static EXEC_START: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

// Temporary stash for argv between sys_enter_execve → sched_process_exec.
// sys_enter_execve writes here (argv is in user memory at that point).
// sched_process_exec reads, copies into the event, and deletes.
// Short-lived: entries exist for microseconds. 1024 is plenty.
#[map]
static EXEC_ARGS: HashMap<u32, [[u8; MAX_ARG_LEN]; MAX_ARG_COUNT]> =
    HashMap::with_max_entries(1024, 0);

// Scratch space: one ProcessEvent-sized buffer per CPU core.
// We can't put ProcessEvent on the stack (512 byte limit),
// so we write into this pre-allocated buffer instead.
#[map]
static SCRATCH: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

// Scratch space for argv capture in sys_enter_execve.
// 10 args × 128 bytes = 1280 bytes — way over the 512-byte stack limit.
// Same pattern as SCRATCH: pre-allocated per-CPU buffer.
#[map]
static ARGS_SCRATCH: PerCpuArray<[[u8; MAX_ARG_LEN]; MAX_ARG_COUNT]> =
    PerCpuArray::with_max_entries(1, 0);

// Fires BEFORE the kernel processes the exec. At this point the filename
// and argv pointers still live in USER-SPACE memory (the calling process).
//
// Syscall signature:  int execve(const char *filename,
//                                char *const argv[],
//                                char *const envp[])
//
// Tracepoint data layout (stable syscall ABI):
//   offset 16: filename pointer  (we already get this from linux_binprm)
//   offset 24: argv pointer      (what we need here)
//   offset 32: envp pointer      (not needed)
//
// We read argv here and stash it in EXEC_ARGS for handle_exec to pick up.

#[tracepoint]
pub fn handle_sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_handle_sys_enter_execve(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_sys_enter_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Read the argv pointer from tracepoint data at offset 24.
    // This is a user-space pointer to an array of string pointers:
    //   argv[0] → "git\0"
    //   argv[1] → "clone\0"
    //   argv[2] → "https://...\0"
    //   argv[N] → NULL  (end of array)
    let argv_ptr: u64 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? };

    // Get scratch buffer (too large for eBPF stack)
    let args_ptr = ARGS_SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let args = unsafe { &mut *args_ptr };

    // Zero out the scratch buffer
    unsafe {
        core::ptr::write_bytes(args.as_mut_ptr() as *mut u8, 0, MAX_ARG_LEN * MAX_ARG_COUNT);
    }

    // Walk argv[]. Each entry is a pointer (8 bytes on x86_64) to a
    // null-terminated string in user-space memory.
    let mut i = 0u32;
    while i < MAX_ARG_COUNT as u32 {
        // Read the i-th pointer from the argv array.
        // argv[i] lives at address: argv_ptr + i * 8
        let arg_ptr: u64 =
            unsafe { bpf_probe_read_user((argv_ptr + (i as u64) * 8) as *const u64).unwrap_or(0) };

        // NULL pointer = end of argv
        if arg_ptr == 0 {
            break;
        }

        // Read the actual string from user-space into our scratch buffer.
        // Stops at \0 or MAX_ARG_LEN, whichever comes first.
        let _ =
            unsafe { bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut args[i as usize]) };

        i += 1;
    }

    // Stash in the map for handle_exec (sched_process_exec) to pick up
    let _ = EXEC_ARGS.insert(&pid, args, 0);

    Ok(0)
}

// Fires AFTER the kernel has loaded the new binary. The process is now
// running the new code. Raw tracepoint args:
//   arg(0): *const task_struct
//   arg(1): old_pid
//   arg(2): *const linux_binprm  ← we read filename from here via CO-RE
#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn handle_exec(ctx: RawTracePointContext) -> u32 {
    match try_handle_exec(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_exec(ctx: &RawTracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|e| e as i64)?;

    // 1. Is this command explicitly ignored by name?
    if unsafe { IGNORED_NAMES.get(&comm).is_some() } {
        let _ = IGNORED_PIDS.insert(&pid, &1, 0);
        let _ = EXEC_ARGS.remove(&pid); // Clean up stashed args
        return Ok(0);
    }

    // 2. Is this PID already in the active blocklist?
    if unsafe { IGNORED_PIDS.get(&pid).is_some() } {
        let _ = EXEC_ARGS.remove(&pid); // Clean up stashed args
        return Ok(0);
    }

    let event_ptr = SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    event.time_ns = unsafe { bpf_ktime_get_ns() };
    event.event_type = 0; // exec

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    // Read PPID via CO-RE: task_struct->real_parent->tgid
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
    event.duration_ns = 0;
    event.name = bpf_get_current_comm().map_err(|e| e as i64)?;

    // Read filename via CO-RE: linux_binprm->filename
    unsafe {
        core::ptr::write_bytes(event.filename.as_mut_ptr(), 0, MAX_FILENAME_LEN);

        let bprm: *const linux_binprm = ctx.arg(2);
        let filename_ptr: *const u8 =
            bpf_probe_read_kernel(addr_of!((*bprm).filename) as *const *const u8)
                .map_err(|e| e as i64)?;
        let _ = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename);
    }

    // Look up args stashed by sys_enter_execve, copy into event
    unsafe {
        if let Some(args) = EXEC_ARGS.get(&pid) {
            core::ptr::copy_nonoverlapping(
                args.as_ptr() as *const u8,
                event.args.as_mut_ptr() as *mut u8,
                MAX_ARG_LEN * MAX_ARG_COUNT,
            );
        } else {
            core::ptr::write_bytes(
                event.args.as_mut_ptr() as *mut u8,
                0,
                MAX_ARG_LEN * MAX_ARG_COUNT,
            );
        }
    }
    let _ = EXEC_ARGS.remove(&pid);

    // Submit to ring buffer
    if let Some(mut buf) = EVENTS.reserve::<ProcessEvent>(0) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                event_ptr as *const ProcessEvent,
                buf.as_mut_ptr() as *mut ProcessEvent,
                1,
            );
        }
        buf.submit(0);

        let _ = EXEC_START.insert(&pid, &event.time_ns, 0);
    }

    aya_log_ebpf::info!(ctx, "Successfully intercepted exec from PID: {}", event.pid);

    Ok(0)
}

#[tracepoint]
pub fn handle_fork(ctx: TracePointContext) -> u32 {
    let parent_pid: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let child_pid: u32 = unsafe { ctx.read_at(44).unwrap_or(0) };

    if unsafe { IGNORED_PIDS.get(&parent_pid).is_some() } {
        let _ = IGNORED_PIDS.insert(&child_pid, &1, 0);
    }

    0
}

#[tracepoint]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    match try_handle_exit(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let was_ignored = unsafe { IGNORED_PIDS.get(&pid).is_some() };
    let _ = IGNORED_PIDS.remove(&pid);

    if was_ignored {
        let _ = EXEC_START.remove(&pid);
        return Ok(0);
    }

    let event_ptr = SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    let now = unsafe { bpf_ktime_get_ns() };
    event.time_ns = now;
    event.event_type = 1; // exit

    // Compute duration from start time
    event.duration_ns = if let Some(start) = unsafe { EXEC_START.get(&pid) } {
        now - *start
    } else {
        0 // No matching exec (e.g. process was already running when profiler started)
    };
    let _ = EXEC_START.remove(&pid);

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    // Read PPID and exit_code via CO-RE from task_struct
    unsafe {
        let task = bpf_get_current_task() as *const task_struct;

        let parent: *const task_struct =
            bpf_probe_read_kernel(addr_of!((*task).real_parent) as *const *const task_struct)
                .unwrap_or(core::ptr::null());
        event.ppid = if !parent.is_null() {
            bpf_probe_read_kernel(addr_of!((*parent).tgid) as *const i32).unwrap_or(0) as u32
        } else {
            0
        };

        // exit_code upper 8 bits = exit status, lower 8 bits = signal number
        let raw_exit =
            bpf_probe_read_kernel(addr_of!((*task).exit_code) as *const i32).unwrap_or(0) as u32;
        event.exit_code = raw_exit >> 8;
    }

    event.name = bpf_get_current_comm().map_err(|e| e as i64)?;

    // Zero out fields not relevant for exit events
    unsafe {
        core::ptr::write_bytes(event.filename.as_mut_ptr(), 0, MAX_FILENAME_LEN);
        core::ptr::write_bytes(
            event.args.as_mut_ptr() as *mut u8,
            0,
            MAX_ARG_LEN * MAX_ARG_COUNT,
        );
    }

    if let Some(mut buf) = EVENTS.reserve::<ProcessEvent>(0) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                event_ptr as *const ProcessEvent,
                buf.as_mut_ptr() as *mut ProcessEvent,
                1,
            );
        }
        buf.submit(0);
    }

    aya_log_ebpf::info!(
        ctx,
        "Process exited PID: {} exit_code: {}",
        event.pid,
        event.exit_code
    );

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
