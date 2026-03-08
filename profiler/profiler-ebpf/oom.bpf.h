#if !defined(__OOM_BPF_H)
#define __OOM_BPF_H

#include "profiler.bpf.h"

// ============================================================
// OOM kill handler via kprobe on mark_oom_victim.
//
// Uses kprobe instead of tp/oom/mark_victim because the tracepoint
// format changed significantly in kernel 6.8 (added total_vm, rss
// fields that don't exist on older kernels like 5.15). The kprobe
// target mark_oom_victim(struct task_struct *tsk) has been stable
// since kernel 4.6 and gives us CO-RE access to all victim fields.
//
// The on-CPU process (bpf_get_current_comm) is the one running the
// OOM killer, NOT the victim -- victim info comes from the
// task_struct parameter.
// ------------------------------------------------------------
// kprobe target: void mark_oom_victim(struct task_struct *tsk)
//   PT_REGS_PARM1(ctx) = struct task_struct *victim
//
// Key fields via CO-RE:
//   victim->tgid             - victim PID (user-visible process ID)
//   victim->comm             - victim process name
//   victim->cred->uid.val    - victim UID
//   victim->signal->oom_score_adj - OOM score adjustment
//   victim->mm->total_vm     - total virtual memory (in pages)
//   victim->mm->pgtables_bytes - page table memory (atomic_long_t, in bytes)
//   victim->mm->rss_stat[N]   - RSS counters (in pages, struct changed in 6.2)
//     N=0: MM_FILEPAGES (file-backed RSS)
//     N=1: MM_ANONPAGES (anonymous RSS)
//     N=3: MM_SHMEMPAGES (shared memory RSS)
//
// Unit conversions (x86_64, 4KB pages):
//   pages -> KB: multiply by 4 (or << 2)
//   bytes -> KB: divide by 1024 (or >> 10)
//
// CO-RE Flavors:
//   rss_stat changed structure in kernel 6.2:
//     < 6.2: struct mm_rss_stat { atomic_long_t count[4]; } (embedded)
//     6.2+ : struct percpu_counter rss_stat[4]              (array)
//   We define both flavors and use bpf_core_field_exists() to pick
//   the right path at load time. The verifier dead-code-eliminates
//   the invalid branch.
// ============================================================

// CO-RE flavor structs for rss_stat compatibility (5.15 vs 6.8)
struct mm_rss_stat___old {
    atomic_long_t count[4];
};

struct mm_struct___old {
    struct mm_rss_stat___old rss_stat;
} __attribute__((preserve_access_index));

struct mm_struct___new {
    struct percpu_counter rss_stat[4];
} __attribute__((preserve_access_index));

// x86_64 uses 4KB pages. Convert page count to KB.
#define PG_TO_KB(pages) ((__u64) (pages) << 2)

// ============================================================
// OOM kill handler
// ------------------------------------------------------------
// kprobe/mark_oom_victim receives: struct task_struct *tsk (via PT_REGS_PARM1)
// We read all victim info directly from task_struct via CO-RE,
// avoiding the fragile tp/oom/mark_victim tracepoint format.
// ============================================================
SEC("kprobe/mark_oom_victim")
int handle_oom_kill(struct pt_regs *ctx)
{
    struct task_struct *victim = (struct task_struct *) PT_REGS_PARM1(ctx);
    if (!victim) {
        return 0;
    }

    struct oom_kill_event *evt = bpf_ringbuf_reserve(&OOM_EVENTS, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->time_ns       = bpf_ktime_get_boot_ns();
    evt->event_type    = EVENT_OOM_KILL;
    evt->pid           = BPF_CORE_READ(victim, tgid);
    evt->uid           = BPF_CORE_READ(victim, cred, uid.val);
    evt->oom_score_adj = BPF_CORE_READ(victim, signal, oom_score_adj);

    BPF_CORE_READ_STR_INTO(&evt->victim_name, victim, comm);
    bpf_get_current_comm(evt->oncpu_name, sizeof(evt->oncpu_name));

    // Memory stats from victim's mm_struct.
    // Kernel threads have mm=NULL, we zero out all fields in that case.
    struct mm_struct *mm = BPF_CORE_READ(victim, mm);
    if (mm) {
        evt->total_vm_kb = PG_TO_KB(BPF_CORE_READ(mm, total_vm));
        evt->pgtables_kb = BPF_CORE_READ(mm, pgtables_bytes.counter) >> 10;

        // RSS counters
        // CO-RE flavor check for rss_stat structural change.
        // Kernel 6.2+ uses percpu_counter array, older uses mm_rss_stat with
        // atomic_long_t. bpf_core_field_exists picks the right path at load time.
        if (bpf_core_field_exists(((struct mm_struct___new *) 0)->rss_stat[0].count)) {
            // Kernel 6.2+ (Ubuntu 24.04): struct percpu_counter rss_stat[4]
            struct mm_struct___new *mm_new = (struct mm_struct___new *) mm;
            evt->file_rss_kb               = PG_TO_KB(BPF_CORE_READ(mm_new, rss_stat[0].count));
            evt->anon_rss_kb               = PG_TO_KB(BPF_CORE_READ(mm_new, rss_stat[1].count));
            evt->shmem_rss_kb              = PG_TO_KB(BPF_CORE_READ(mm_new, rss_stat[3].count));
        } else {
            // Kernel < 6.2 (Ubuntu 22.04): struct mm_rss_stat { atomic_long_t count[4]; }
            struct mm_struct___old *mm_old = (struct mm_struct___old *) mm;
            evt->file_rss_kb               = PG_TO_KB(BPF_CORE_READ(mm_old, rss_stat.count[0].counter));
            evt->anon_rss_kb               = PG_TO_KB(BPF_CORE_READ(mm_old, rss_stat.count[1].counter));
            evt->shmem_rss_kb              = PG_TO_KB(BPF_CORE_READ(mm_old, rss_stat.count[3].counter));
        }
    } else {
        evt->total_vm_kb  = 0;
        evt->pgtables_kb  = 0;
        evt->file_rss_kb  = 0;
        evt->anon_rss_kb  = 0;
        evt->shmem_rss_kb = 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

#endif // __OOM_BPF_H
