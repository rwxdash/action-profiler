#if !defined(__PROFILER_BPF_H)
#define __PROFILER_BPF_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// Constants

#define MAX_PROC_NAME_LEN            16
#define MAX_FILENAME_LEN             256
#define MAX_ARG_LEN                  128
#define MAX_ARG_COUNT                10

#define EVENT_EXEC                   0
#define EVENT_EXIT                   1
#define EVENT_OOM_KILL               2
#define EVENT_BLOCK_IO               3
#define EVENT_SCHED_LATENCY          4

#define CONFIG_SCHED_THRESHOLD_NS    0
#define CONFIG_BLOCK_IO_THRESHOLD_NS 1
#define CONFIG_MAX                   8

// Structs
struct process_event {
    __u64 time_ns;
    __u8  event_type;                       // 0=exec, 1=exit
    __u32 exit_code;                        // -
    __u64 duration_ns;                      // -
    __u32 uid;                              // User ID
    __u32 gid;                              // Group ID
    __u32 pid;                              // Process ID
    __u32 tgid;                             // Thread Group ID
    __u32 ppid;                             // Parent Process ID
    char  name[MAX_PROC_NAME_LEN];          // Command Name
    char  filename[MAX_FILENAME_LEN];       // File Name
    char  args[MAX_ARG_COUNT][MAX_ARG_LEN]; // Full command with args
};

struct oom_kill_event {
    __u64 time_ns;
    __u8  event_type;                     // EVENT_OOM_KILL (2)
    __u32 pid;                            // Victim PID
    __u32 uid;                            // Victim UID
    __u64 total_vm_kb;                    // Total virtual memory (KB, via PG_COUNT_TO_KB)
    __u64 anon_rss_kb;                    // Anonymous RSS (KB)
    __u64 file_rss_kb;                    // File-backed RSS (KB)
    __u64 shmem_rss_kb;                   // Shared memory RSS (KB)
    __u64 pgtables_kb;                    // Page table memory (KB, mm_pgtables_bytes >> 10)
    __s16 oom_score_adj;                  // OOM score adjustment
    char  victim_name[MAX_PROC_NAME_LEN]; // Victim comm (from __data_loc)
    char  oncpu_name[MAX_PROC_NAME_LEN];  // on-CPU when OOM fired (not necessarily the cause)}
};

struct block_io_event {
    __u64 time_ns;
    __u8  event_type;              // EVENT_BLOCK_IO (3)
    __u32 dev;                     // Device major:minor
    __u64 sector;                  // Starting sector
    __u32 nr_sectors;              // Request size in sectors
    __u64 latency_ns;              // Time from issue to complete
    char  rwbs[8];                 // R/W/D flags (raw from tracepoint)
    __u32 pid;                     // Process that issued the I/O
    char  name[MAX_PROC_NAME_LEN]; // Process comm
};

struct block_io_stash {
    __u64 time_ns;
    __u32 pid;                     // Process ID
    char  name[MAX_PROC_NAME_LEN]; // Process comm
    char  rwbs[8];                 // RWBS flags
    __u32 nr_sectors;              // Number of sectors
};

struct sched_latency_event {
    __u64 time_ns;
    __u8  event_type;              // EVENT_SCHED_LATENCY (4)
    __u32 pid;                     // Process ID
    __u64 latency_ns;              // Time spent waiting in run queue
    __s32 prio;                    // Task priority
    __s32 target_cpu;              // CPU the task was scheduled on
    char  name[MAX_PROC_NAME_LEN]; // Process comm
};

// Helper struct for argv stashing between sys_enter_execve and exec
struct exec_args {
    char args[MAX_ARG_COUNT][MAX_ARG_LEN];
};

// Maps

// Event Ring Buffers
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024);
} OOM_EVENTS SEC(".maps");

// Configuration Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CONFIG_MAX);
    __type(key, __u32);
    __type(value, __u64);
} CONFIG SEC(".maps");

// Ignore Lists
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[MAX_PROC_NAME_LEN]);
    __type(value, __u8);
} IGNORED_NAMES SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} IGNORED_PIDS SEC(".maps");

// Process Tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} EXEC_START SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct exec_args);
} EXEC_ARGS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_event);
} SCRATCH SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_args);
} ARGS_SCRATCH SEC(".maps");

// Scheduler Tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} WAKEUP_START SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sched_latency_event);
} SCHED_SCRATCH SEC(".maps");

// Block I/O Tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct block_io_stash);
} IO_START SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct block_io_event);
} BLOCK_IO_SCRATCH SEC(".maps");

// OOM Tracking
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct oom_kill_event);
} OOM_SCRATCH SEC(".maps");

#endif // __PROFILER_BPF_H
