use core::ptr::addr_of;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_boot_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes, generated::bpf_get_current_task,
    },
    macros::{map, raw_tracepoint, tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::{RawTracePointContext, TracePointContext},
};
use profiler_common::*;

use crate::vmlinux::{linux_binprm, task_struct};

#[map]
static EXEC_START: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

// Stash argv between sys_enter_execve -> sched_process_exec
#[map]
static EXEC_ARGS: HashMap<u32, [[u8; MAX_ARG_LEN]; MAX_ARG_COUNT]> =
    HashMap::with_max_entries(1024, 0);

// Per-CPU scratch (ProcessEvent is too large for the 512-byte eBPF stack)
#[map]
static SCRATCH: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

// Per-CPU scratch for argv capture
#[map]
static ARGS_SCRATCH: PerCpuArray<[[u8; MAX_ARG_LEN]; MAX_ARG_COUNT]> =
    PerCpuArray::with_max_entries(1, 0);

// Tracepoint: syscalls:sys_enter_execve — capture argv while still in user memory
#[tracepoint]
pub fn handle_sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_handle_sys_enter_execve(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_sys_enter_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let argv_ptr: u64 = unsafe { ctx.read_at(24).map_err(|e| e as i64)? }; // argv userspace ptr

    let args_ptr = ARGS_SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let args = unsafe { &mut *args_ptr };
    unsafe {
        core::ptr::write_bytes(args.as_mut_ptr() as *mut u8, 0, MAX_ARG_LEN * MAX_ARG_COUNT);
    }

    let mut i = 0u32;
    while i < MAX_ARG_COUNT as u32 {
        let arg_ptr: u64 =
            unsafe { bpf_probe_read_user((argv_ptr + (i as u64) * 8) as *const u64).unwrap_or(0) };
        if arg_ptr == 0 {
            break;
        }
        let _ =
            unsafe { bpf_probe_read_user_str_bytes(arg_ptr as *const u8, &mut args[i as usize]) };
        i += 1;
    }

    let _ = EXEC_ARGS.insert(&pid, args, 0);

    Ok(0)
}

// Raw tracepoint: sched_process_exec
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

    if unsafe { crate::IGNORED_NAMES.get(&comm).is_some() } {
        let _ = crate::IGNORED_PIDS.insert(&pid, &1, 0);
        let _ = EXEC_ARGS.remove(&pid);
        return Ok(0);
    }

    if unsafe { crate::IGNORED_PIDS.get(&pid).is_some() } {
        let _ = EXEC_ARGS.remove(&pid);
        return Ok(0);
    }

    let event_ptr = SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    event.time_ns = unsafe { bpf_ktime_get_boot_ns() };
    event.event_type = EVENT_EXEC;

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

    event.ppid = unsafe {
        // CO-RE: task->real_parent->tgid
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

    unsafe {
        // CO-RE: linux_binprm->filename
        core::ptr::write_bytes(event.filename.as_mut_ptr(), 0, MAX_FILENAME_LEN);

        let bprm: *const linux_binprm = ctx.arg(2);
        let filename_ptr: *const u8 =
            bpf_probe_read_kernel(addr_of!((*bprm).filename) as *const *const u8)
                .map_err(|e| e as i64)?;
        let _ = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename);
    }

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

    if let Some(mut buf) = crate::EVENTS.reserve::<ProcessEvent>(0) {
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

    Ok(0)
}

// Tracepoint: sched:sched_process_fork
#[tracepoint]
pub fn handle_fork(ctx: TracePointContext) -> u32 {
    let parent_pid: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let child_pid: u32 = unsafe { ctx.read_at(44).unwrap_or(0) };

    if unsafe { crate::IGNORED_PIDS.get(&parent_pid).is_some() } {
        let _ = crate::IGNORED_PIDS.insert(&child_pid, &1, 0);
    }

    0
}

// Tracepoint: sched:sched_process_exit
#[tracepoint]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    match try_handle_exit(&ctx) {
        Ok(0) => 0,
        _ => 0,
    }
}

fn try_handle_exit(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let was_ignored = unsafe { crate::IGNORED_PIDS.get(&pid).is_some() };
    let _ = crate::IGNORED_PIDS.remove(&pid);

    if was_ignored {
        let _ = EXEC_START.remove(&pid);
        return Ok(0);
    }

    let event_ptr = SCRATCH.get_ptr_mut(0).ok_or(0i64)?;
    let event = unsafe { &mut *event_ptr };

    let now = unsafe { bpf_ktime_get_boot_ns() };
    event.time_ns = now;
    event.event_type = EVENT_EXIT;

    event.duration_ns = if let Some(start) = unsafe { EXEC_START.get(&pid) } {
        now - *start
    } else {
        0 // process started before profiler
    };
    let _ = EXEC_START.remove(&pid);

    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;

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

        let raw_exit = // kernel format: bits 8-15 = exit status, bits 0-7 = signal
            bpf_probe_read_kernel(addr_of!((*task).exit_code) as *const i32).unwrap_or(0) as u32;
        event.exit_code = raw_exit >> 8;
    }

    event.name = bpf_get_current_comm().map_err(|e| e as i64)?;

    unsafe {
        core::ptr::write_bytes(event.filename.as_mut_ptr(), 0, MAX_FILENAME_LEN);
        core::ptr::write_bytes(
            event.args.as_mut_ptr() as *mut u8,
            0,
            MAX_ARG_LEN * MAX_ARG_COUNT,
        );
    }

    if let Some(mut buf) = crate::EVENTS.reserve::<ProcessEvent>(0) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                event_ptr as *const ProcessEvent,
                buf.as_mut_ptr() as *mut ProcessEvent,
                1,
            );
        }
        buf.submit(0);
    }

    Ok(0)
}
