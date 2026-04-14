// SPDX-License-Identifier: Dual MIT/GPL
#if !defined(__PROFILER_BPF_H)
#define __PROFILER_BPF_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
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
#define EVENT_TCP                    5

#define TCP_TYPE_CONNECT             0
#define TCP_TYPE_ACCEPT              1
#define TCP_TYPE_CLOSE               2

// TCP states (from include/net/tcp_states.h)
#define TCP_ST_ESTABLISHED           1
#define TCP_ST_SYN_SENT              2
#define TCP_ST_SYN_RECV              3
#define TCP_ST_FIN_WAIT1             4
#define TCP_ST_CLOSE                 7
#define TCP_ST_CLOSE_WAIT            8
#define TCP_ST_LAST_ACK              9
#define TCP_ST_LISTEN                10
#define TCP_ST_NEW_SYN_RECV          12

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
    char  victim_name[MAX_PROC_NAME_LEN]; // Victim comm (from task->comm via CO-RE)
    char  oncpu_name[MAX_PROC_NAME_LEN];  // on-CPU when OOM fired (not necessarily the cause)}
};

struct block_io_event {
    __u64 time_ns;
    __u8  event_type;              // EVENT_BLOCK_IO (3)
    __u32 dev;                     // Device major:minor
    __u64 sector;                  // Starting sector
    __u32 nr_sectors;              // Request size in sectors
    __u64 latency_ns;              // Time from issue to complete
    __u32 cmd_flags;               // cmd_flags bitmask (lower 8 bits = op: 0=read,1=write,2=flush,3=discard)
    __u32 pid;                     // Process that issued the I/O
    char  name[MAX_PROC_NAME_LEN]; // Process comm
};

struct block_io_stash {
    __u64 time_ns;
    __u32 pid;                     // Process ID
    char  name[MAX_PROC_NAME_LEN]; // Process comm
    __u32 cmd_flags;               // cmd_flags bitmask
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

struct tcp_event {
    __u64 time_ns;
    __u8  event_type;              // EVENT_TCP (5)
    __u8  type;                    // TCP_TYPE_CONNECT/ACCEPT/CLOSE
    __u16 family;                  // AF_INET=2, AF_INET6=10
    __u32 pid;                     // Process ID
    __u32 saddr_v4;                // Source IPv4 (network byte order)
    __u32 daddr_v4;                // Dest IPv4 (network byte order)
    __u8  saddr_v6[16];            // Source IPv6
    __u8  daddr_v6[16];            // Dest IPv6
    __u16 sport;                   // Source port (host byte order)
    __u16 dport;                   // Dest port (host byte order)
    __u64 duration_ns;             // For close events: time since ESTABLISHED
    char  name[MAX_PROC_NAME_LEN]; // Process comm
};

struct tcp_conn_stash {
    __u64 time_ns;                 // When connection was established
    __u32 pid;                     // Process that opened it
    char  name[MAX_PROC_NAME_LEN]; // Process comm at open time
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
    __type(value, struct exec_args);
} ARGS_SCRATCH SEC(".maps");

// Scheduler Tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} WAKEUP_START SEC(".maps");

// Block I/O Tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct block_io_stash);
} IO_START SEC(".maps");

// TCP Connection Tracking
// Key: skaddr (kernel socket pointer)
// unique per socket, stable across state transitions
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct tcp_conn_stash);
} TCP_CONN_START SEC(".maps");

#endif // __PROFILER_BPF_H
