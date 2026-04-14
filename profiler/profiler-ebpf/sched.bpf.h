// SPDX-License-Identifier: Dual MIT/GPL
#if !defined(__SCHED_BPF_H)
#define __SCHED_BPF_H

#include "profiler.bpf.h"

// ============================================================
// Scheduler latency tracking via tp_btf (BTF-enabled tracepoints).
//
// Uses tp_btf instead of tp/ for CO-RE struct access. BCC's
// runqlat.bpf.c uses the same approach.
//
// tp_btf parameters (from kernel trace function signature):
//   sched_wakeup/new: struct task_struct *p
//   sched_switch:     bool preempt, struct task_struct *prev, struct task_struct *next
//
// Key struct task_struct fields (explore with: bpftrace -lv 'struct task_struct'):
//   pid    (pid_t)    - kernel pid = userspace tid (thread ID)
//   tgid   (pid_t)    - kernel tgid = userspace pid (process ID)
//   prio   (int)      - dynamic priority (0-139), matches tracepoint's "next_prio"
//   comm   (char[16]) - process name (use BPF_CORE_READ_STR_INTO for strings)
//
// See also: tests/bpftrace-cheatsheet.bt "SCHEDULER LATENCY" and
// "EXPLORING KERNEL STRUCTS" sections.
// ============================================================

// ============================================================
// Wakeup handler - record when a task becomes runnable.
// Stash timestamp in WAKEUP_START keyed by thread ID (task->pid).
// When sched_switch fires for this thread, we compute the latency.
// ------------------------------------------------------------
// tp_btf params: struct task_struct *p
// ============================================================
SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u64 now = bpf_ktime_get_boot_ns();

    bpf_map_update_elem(&WAKEUP_START, &pid, &now, BPF_ANY);

    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u64 now = bpf_ktime_get_boot_ns();

    bpf_map_update_elem(&WAKEUP_START, &pid, &now, BPF_ANY);

    return 0;
}

// ============================================================
// Switch handler - measure run-queue latency.
//
// When a task gets CPU, we look up its wakeup timestamp and compute
// the run-queue latency. Events below CONFIG_SCHED_THRESHOLD_NS
// are dropped in kernel to reduce overhead.
// ------------------------------------------------------------
// tp_btf params: bool preempt, struct task_struct *prev, struct task_struct *next
//   "next" = task being scheduled IN (getting CPU time)
//   "prev" = task being scheduled OUT
//
// Fields used from next:
//   pid  -> map key to match wakeup (thread ID)
//   tgid -> user-visible process ID in the event
//   prio -> dynamic priority (matches tracepoint's "next_prio")
//   comm -> process name (read with BPF_CORE_READ_STR_INTO)
//
// target_cpu: bpf_get_smp_processor_id() gives the CPU this handler
// runs on, which is the CPU "next" is about to execute on.
// ============================================================
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    __u32 tid = BPF_CORE_READ(next, pid);

    __u64 *wakeup_ns = bpf_map_lookup_elem(&WAKEUP_START, &tid);
    if (!wakeup_ns) {
        return 0;
    }

    __u64 saved_wakeup = *wakeup_ns;
    bpf_map_delete_elem(&WAKEUP_START, &tid);

    __u64 now        = bpf_ktime_get_boot_ns();
    __u64 latency_ns = now - saved_wakeup;

    // Apply threshold filter in kernel
    __u32  key       = CONFIG_SCHED_THRESHOLD_NS;
    __u64 *threshold = bpf_map_lookup_elem(&CONFIG, &key);
    __u64  thresh    = threshold ? *threshold : 5000000; // default 5ms
    if (latency_ns < thresh) {
        return 0;
    }

    struct sched_latency_event *evt = bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->time_ns    = now;
    evt->event_type = EVENT_SCHED_LATENCY;
    evt->pid        = BPF_CORE_READ(next, tgid);
    evt->latency_ns = latency_ns;

    // task_struct.prio is the dynamic priority (0-139). This matches
    // what the tracepoint format calls "next_prio"
    // the kernel's __trace_sched_switch_tp() passes
    // entry->prio which is task->prio.
    evt->prio = BPF_CORE_READ(next, prio);

    // The switch handler runs on the CPU that "next" is about to
    // execute on, so bpf_get_smp_processor_id() gives us the target CPU.
    evt->target_cpu = bpf_get_smp_processor_id();

    // Read comm string from task_struct (use _STR variant for char arrays)
    BPF_CORE_READ_STR_INTO(&evt->name, next, comm);

    bpf_ringbuf_submit(evt, 0);

    return 0;
}

#endif // __SCHED_BPF_H
