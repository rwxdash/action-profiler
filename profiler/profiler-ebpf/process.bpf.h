// SPDX-License-Identifier: Dual MIT/GPL
#if !defined(__PROCESS_BPF_H)
#define __PROCESS_BPF_H

#include "profiler.bpf.h"

// ============================================================
// Stash filename + argv from execve syscall entry.
// Fired BEFORE the exec happens - sched_process_exec fires after.
//
// ctx is struct trace_event_raw_sys_enter from vmlinux.h (full record
// including common header). SEC("tp/...") receives the full tracepoint record.
//
// execve(const char *filename, const char *const argv[], const char *const envp[])
//   ctx->args[0] = filename (userspace pointer)
//   ctx->args[1] = argv     (userspace pointer to array of char*)
//   ctx->args[2] = envp     (userspace pointer, unused)
// ------------------------------------------------------------
// name: sys_enter_execve
// ID: _
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
//
//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * filename;    offset:16;      size:8; signed:0;
//         field:const char *const * argv; offset:24;      size:8; signed:0;
//         field:const char *const * envp; offset:32;      size:8; signed:0;
//
// print fmt:
// "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx",
// ((unsigned long)(REC->filename)),
// ((unsigned long)(REC->argv)),
// ((unsigned long)(REC->envp))
// ============================================================
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    const char        *filename = (const char *) ctx->args[0];
    const char *const *argv     = (const char *const *) ctx->args[1];

    __u32             zero    = 0;
    struct exec_args *scratch = bpf_map_lookup_elem(&ARGS_SCRATCH, &zero);
    if (!scratch) {
        return 0;
    }

#pragma unroll
    for (int i = 0; i < MAX_ARG_COUNT; i++) {
        scratch->args[i][0] = '\0';
    }

    // Skip argv[0] (program name) — it duplicates filename
#pragma unroll
    for (int i = 1; i < MAX_ARG_COUNT + 1; i++) {
        const char *arg;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) || !arg) {
            break;
        }
        bpf_probe_read_user_str(scratch->args[i - 1], MAX_ARG_LEN, arg);
    }

    bpf_map_update_elem(&EXEC_ARGS, &pid, scratch, BPF_ANY);
    return 0;
}

// ============================================================
// Exec handler - fires AFTER exec succeeds.
// Uses raw_tracepoint to access linux_binprm for the full filename path.
//
// We don't read tracepoint format fields from ctx here. Instead:
// - pid/uid/name come from BPF helpers
// - ppid comes from CO-RE (task_struct->real_parent->tgid)
// - filename comes from CO-RE (linux_binprm->filename via ctx->args[2])
// - argv comes from EXEC_ARGS map (stashed by sys_enter_execve)
//
// raw_tracepoint args for sched_process_exec (from kernel source / vmlinux.h):
//   ctx->args[0] = struct task_struct *     (the task)
//   ctx->args[1] = pid_t old_pid
//   ctx->args[2] = struct linux_binprm *    (contains filename, argc, etc.)
// ------------------------------------------------------------
// Note: raw_tracepoint has no format file in tracefs. The args come from the
// kernel trace function signature, not a formatted record. Use CO-RE to read
// struct fields - offsets are patched at load time by aya.
// ============================================================
SEC("raw_tracepoint/sched_process_exec")
int handle_sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    __u32 tgid     = (__u32) pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid     = (__u32) uid_gid;
    __u32 gid     = uid_gid >> 32;

    // Check if this PID was inherited as ignored from a parent (via fork handler)
    if (bpf_map_lookup_elem(&IGNORED_PIDS, &pid)) {
        bpf_map_delete_elem(&EXEC_ARGS, &pid);
        return 0;
    }

    char name[MAX_PROC_NAME_LEN];
    bpf_get_current_comm(name, sizeof(name));
    if (bpf_map_lookup_elem(&IGNORED_NAMES, name)) {
        __u8 ignored = 1;
        bpf_map_update_elem(&IGNORED_PIDS, &pid, &ignored, BPF_ANY);
        bpf_map_delete_elem(&EXEC_ARGS, &pid);

        return 0;
    }

    struct process_event *evt = bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&EXEC_ARGS, &pid);
        return 0;
    }

    evt->time_ns     = bpf_ktime_get_ns();
    evt->event_type  = EVENT_EXEC;
    evt->pid         = pid;
    evt->tgid        = tgid;
    evt->uid         = uid;
    evt->gid         = gid;
    evt->exit_code   = 0;
    evt->duration_ns = 0;
    __builtin_memcpy(evt->name, name, sizeof(evt->name));

    struct task_struct *task = (struct task_struct *) bpf_get_current_task_btf();
    evt->ppid                = BPF_CORE_READ(task, real_parent, tgid);

    // Cast to __u64* to avoid CO-RE relocation on the flexible array member.
    // aya's relocator rejects ctx->args[2] because bpf_raw_tracepoint_args.args
    // has nr_elems=0 in BTF (flexible array). Casting bypasses the BTF type.
    struct linux_binprm *bprm  = (struct linux_binprm *) ((__u64 *) ctx)[2];
    const char          *fname = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(evt->filename, MAX_FILENAME_LEN, fname);

    struct exec_args *stashed = bpf_map_lookup_elem(&EXEC_ARGS, &pid);
    if (stashed) {
#pragma unroll
        for (int i = 0; i < MAX_ARG_COUNT; i++) {
            __builtin_memcpy(evt->args[i], stashed->args[i], MAX_ARG_LEN);
        }
    } else {
#pragma unroll
        for (int i = 0; i < MAX_ARG_COUNT; i++) {
            evt->args[i][0] = '\0';
        }
    }

    __u64 ts = evt->time_ns;
    bpf_map_update_elem(&EXEC_START, &pid, &ts, BPF_ANY);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&EXEC_ARGS, &pid);

    return 0;
}

// ============================================================
// Fork handler - propagate ignored PIDs to children.
// No event emitted, just bookkeeping.
//
// Uses raw_tracepoint for CO-RE access to parent/child task_struct,
// avoiding hardcoded offsets into the tracepoint format record.
// ------------------------------------------------------------
// raw_tracepoint args for sched_process_fork (from kernel source):
//   ctx->args[0] = struct task_struct *parent
//   ctx->args[1] = struct task_struct *child
// ============================================================
SEC("raw_tracepoint/sched_process_fork")
int handle_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    // Cast to __u64* to avoid CO-RE relocation on the flexible array member.
    // aya's relocator rejects ctx->args[N] because bpf_raw_tracepoint_args.args
    // has nr_elems=0 in BTF (flexible array). Same workaround as sched_process_exec.
    struct task_struct *parent = (struct task_struct *) ((__u64 *) ctx)[0];
    struct task_struct *child  = (struct task_struct *) ((__u64 *) ctx)[1];

    __u32 parent_pid = BPF_CORE_READ(parent, tgid);
    __u32 child_pid  = BPF_CORE_READ(child, tgid);

    if (bpf_map_lookup_elem(&IGNORED_PIDS, &parent_pid)) {
        __u8 ignored = 1;
        bpf_map_update_elem(&IGNORED_PIDS, &child_pid, &ignored, BPF_ANY);
    }

    return 0;
}

// ============================================================
// Exit handler - emit EXIT event with duration and exit code.
// Only emits events for processes we saw exec (in EXEC_START map).
//
// We don't read from tracepoint ctx at all here.
// pid comes from bpf_get_current_pid_tgid().
// exit_code comes from BPF_CORE_READ on task_struct.
// ------------------------------------------------------------
// name: sched_process_exit
// ID: _
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
//
//         field:char comm[16];    offset:8;       size:16;        signed:0;
//         field:pid_t pid;        offset:24;      size:4; signed:1;
//         field:int prio; offset:28;      size:4; signed:1;
//
// print fmt:
// "comm=%s pid=%d prio=%d", REC->comm, REC->pid, REC->prio
// ============================================================
SEC("tp/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Always clean up ignored pids on exit (prevent map leak)
    bpf_map_delete_elem(&IGNORED_PIDS, &pid);

    __u64 *start_time = bpf_map_lookup_elem(&EXEC_START, &pid);
    if (!start_time) {
        return 0;
    }

    struct process_event *evt = bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&EXEC_START, &pid);
        return 0;
    }

    evt->time_ns     = bpf_ktime_get_ns();
    evt->event_type  = EVENT_EXIT;
    evt->pid         = pid;
    evt->tgid        = (__u32) bpf_get_current_pid_tgid();
    evt->duration_ns = evt->time_ns - *start_time;

    // NOTE: BPF_CORE_READ(task, exit_code) gives the raw kernel exit code
    // The raw value encodes: lower 8 bits = signal, upper bits = status
    // Shift right by 8 to get the actual exit status (like WEXITSTATUS)
    //
    // In Rust, we should do:
    //   let raw = event.exit_code;
    //   let status = raw >> 8;
    //   let signal = raw & 0x7F;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task_btf();
    evt->exit_code           = BPF_CORE_READ(task, exit_code);

    bpf_get_current_comm(evt->name, sizeof(evt->name));

    // Clear fields not relevant for exit events
    evt->uid         = 0;
    evt->gid         = 0;
    evt->ppid        = 0;
    evt->filename[0] = '\0';

#pragma unroll
    for (int i = 0; i < MAX_ARG_COUNT; i++) {
        evt->args[i][0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&EXEC_START, &pid);

    return 0;
}

#endif // __PROCESS_BPF_H
