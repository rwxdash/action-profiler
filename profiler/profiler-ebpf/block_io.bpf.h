// SPDX-License-Identifier: Dual MIT/GPL
#if !defined(__BLOCK_IO_BPF_H)
#define __BLOCK_IO_BPF_H

#include "profiler.bpf.h"

// ============================================================
// Block I/O latency tracking via tp_btf (BTF-enabled tracepoints).
//
// Uses tp_btf instead of tp/ because the block tracepoint formats
// isn't stable. tp_btf gives us struct request * directly with CO-RE.
//
// tp_btf parameters (from kernel trace function signature):
//   block_rq_issue:    struct request *rq
//   block_rq_complete: struct request *rq, int error, unsigned int nr_bytes
//
// Key struct request fields (explore with: bpftrace -lv 'struct request'):
//   __sector   (__u64)  - starting sector
//   __data_len (__u32)  - request size in bytes (sectors = bytes >> 9)
//   cmd_flags  (__u32)  - operation bitmask, lower 8 bits = op type:
//                         0=READ, 1=WRITE, 2=FLUSH, 3=DISCARD
//   q          (struct request_queue *) - queue, chase to q->disk for device
//
// Map key strategy:
//   The struct request * pointer is unique per I/O request and stable
//   from issue to complete. We cast it to __u64 and use it as the
//   IO_START map key, same approach as BCC's biolatency/biosnoop.
//   No bit-packing or composite keys needed.
// ============================================================

// Get device major:minor from struct request.
// Path: rq->q->disk->major / first_minor (kernel 5.11+).
// rq_disk was removed in 5.11; our minimum target is 5.15 (Ubuntu 22.04).
static __always_inline __u32 get_dev(struct request *rq)
{
    struct gendisk *disk  = BPF_CORE_READ(rq, q, disk);
    __u32           major = BPF_CORE_READ(disk, major);
    __u32           minor = BPF_CORE_READ(disk, first_minor);

    return (major << 20) | minor;
}

// ============================================================
// Issue handler - stash request info at issue time.
//
// We use the struct request pointer as the map key (unique per I/O).
// When block_rq_complete fires with the same rq pointer, we match.
// ------------------------------------------------------------
// tp_btf params: struct request *rq
// Explore fields: bpftrace -lv 'struct request'
// See also: tests/bpftrace-cheatsheet.bt "EXPLORING KERNEL STRUCTS"
// ============================================================
SEC("tp_btf/block_rq_issue")
int BPF_PROG(handle_block_rq_issue, struct request *rq)
{
    struct block_io_stash stash = {};
    stash.time_ns               = bpf_ktime_get_boot_ns();
    stash.pid                   = bpf_get_current_pid_tgid() >> 32;
    stash.cmd_flags             = BPF_CORE_READ(rq, cmd_flags);
    stash.nr_sectors            = BPF_CORE_READ(rq, __data_len) >> 9; // bytes / 512

    bpf_get_current_comm(stash.name, sizeof(stash.name));

    __u64 key = (__u64) rq;
    bpf_map_update_elem(&IO_START, &key, &stash, BPF_ANY);

    return 0;
}

// ============================================================
// Complete handler - match with issue, compute latency.
//
// Looks up the stash by rq pointer, computes I/O latency, and
// emits an event if above the threshold (CONFIG_BLOCK_IO_THRESHOLD_NS).
// Device info (dev, sector) is read from rq here since we need it
// for the event output but don't need it for matching.
// ------------------------------------------------------------
// tp_btf params: struct request *rq, int error, unsigned int nr_bytes
// ============================================================
SEC("tp_btf/block_rq_complete")
int BPF_PROG(handle_block_rq_complete, struct request *rq, int error, unsigned int nr_bytes)
{
    __u64 key = (__u64) rq;

    struct block_io_stash *stash = bpf_map_lookup_elem(&IO_START, &key);
    if (!stash) {
        return 0; // started before profiler
    }

    __u64 now        = bpf_ktime_get_boot_ns();
    __u64 latency_ns = now - stash->time_ns;

    // Apply threshold filter in kernel
    __u32  config_key = CONFIG_BLOCK_IO_THRESHOLD_NS;
    __u64 *threshold  = bpf_map_lookup_elem(&CONFIG, &config_key);
    __u64  thresh     = threshold ? *threshold : 1000000; // default 1ms

    // Save stash values before deleting (verifier may invalidate pointer)
    struct block_io_stash saved = *stash;
    bpf_map_delete_elem(&IO_START, &key);

    if (latency_ns < thresh) {
        return 0;
    }

    // Reserve space directly in the ring buffer (no scratch map needed)
    struct block_io_event *evt = bpf_ringbuf_reserve(&EVENTS, sizeof(*evt), 0);
    if (!evt) {
        return 0; // ring buffer full
    }

    evt->time_ns    = now;
    evt->event_type = EVENT_BLOCK_IO;
    evt->dev        = get_dev(rq);
    evt->sector     = BPF_CORE_READ(rq, __sector);
    evt->nr_sectors = saved.nr_sectors;
    evt->latency_ns = latency_ns;
    evt->cmd_flags  = saved.cmd_flags;
    evt->pid        = saved.pid;

    __builtin_memcpy(evt->name, saved.name, sizeof(evt->name));

    bpf_ringbuf_submit(evt, 0);

    return 0;
}

#endif // __BLOCK_IO_BPF_H
