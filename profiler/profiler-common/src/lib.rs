#![no_std]

pub const MAX_PROC_NAME_LEN: usize = 16;
pub const MAX_FILENAME_LEN: usize = 256;
pub const MAX_ARG_LEN: usize = 128;
pub const MAX_ARG_COUNT: usize = 10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub time_ns: u64,
    pub event_type: u8,                           // 0=exec, 1=exit
    pub exit_code: u32,                           // -
    pub duration_ns: u64,                         // -
    pub uid: u32,                                 // User ID
    pub gid: u32,                                 // Group ID
    pub pid: u32,                                 // Process ID
    pub tgid: u32,                                // Thread Group ID
    pub ppid: u32,                                // Parent Process ID
    pub name: [u8; MAX_PROC_NAME_LEN],            // Command Name
    pub filename: [u8; MAX_FILENAME_LEN],         // File Name
    pub args: [[u8; MAX_ARG_LEN]; MAX_ARG_COUNT], // Full command with args
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub time_ns: u64,
    pub event_type: u8,
}

pub const CONFIG_SCHED_THRESHOLD_NS: u32 = 0;
pub const CONFIG_BLOCK_IO_THRESHOLD_NS: u32 = 1;
pub const CONFIG_MAX: u32 = 8;

pub const EVENT_EXEC: u8 = 0;
pub const EVENT_EXIT: u8 = 1;
pub const EVENT_OOM_KILL: u8 = 2;
pub const EVENT_BLOCK_IO: u8 = 3;
pub const EVENT_SCHED_LATENCY: u8 = 4;
pub const EVENT_TCP: u8 = 5;

pub const TCP_TYPE_CONNECT: u8 = 0;
pub const TCP_TYPE_ACCEPT: u8 = 1;
pub const TCP_TYPE_CLOSE: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OomKillEvent {
    pub time_ns: u64,
    pub event_type: u8,                       // EVENT_OOM_KILL (2)
    pub pid: u32,                             // Victim PID
    pub uid: u32,                             // Victim UID
    pub total_vm_kb: u64,                     // Total virtual memory (KB, via PG_TO_KB)
    pub anon_rss_kb: u64,                     // Anonymous RSS (KB)
    pub file_rss_kb: u64,                     // File-backed RSS (KB)
    pub shmem_rss_kb: u64,                    // Shared memory RSS (KB)
    pub pgtables_kb: u64,                     // Page table memory (KB, mm_pgtables_bytes >> 10)
    pub oom_score_adj: i16,                   // OOM score adjustment
    pub victim_name: [u8; MAX_PROC_NAME_LEN], // Victim comm (from task->comm via CO-RE)
    pub oncpu_name: [u8; MAX_PROC_NAME_LEN],  // on-CPU when OOM fired (not necessarily the cause)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockIoEvent {
    pub time_ns: u64,
    pub event_type: u8,                // EVENT_BLOCK_IO (3)
    pub dev: u32,                      // Device major:minor
    pub sector: u64,                   // Starting sector
    pub nr_sectors: u32,               // Request size in sectors
    pub latency_ns: u64,               // Time from issue to complete
    pub cmd_flags: u32,                // cmd_flags bitmask (lo8 bits op: 0=r,1=w,2=flush,3=discard)
    pub pid: u32,                      // Process that issued the I/O
    pub name: [u8; MAX_PROC_NAME_LEN], // Process comm
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockIoStash {
    pub time_ns: u64,
    pub pid: u32,                      // Process ID
    pub name: [u8; MAX_PROC_NAME_LEN], // Process comm
    pub cmd_flags: u32,                // cmd_flags bitmask
    pub nr_sectors: u32,               // Number of sectors
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedLatencyEvent {
    pub time_ns: u64,
    pub event_type: u8,                // EVENT_SCHED_LATENCY (4)
    pub pid: u32,                      // Process ID
    pub latency_ns: u64,               // Time spent waiting in run queue
    pub prio: i32,                     // Task priority
    pub target_cpu: i32,               // CPU the task was scheduled on
    pub name: [u8; MAX_PROC_NAME_LEN], // Process comm
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpEvent {
    pub time_ns: u64,
    pub event_type: u8,                // EVENT_TCP (5)
    pub tcp_type: u8,                  // TCP_TYPE_CONNECT/ACCEPT/CLOSE
    pub family: u16,                   // AF_INET=2, AF_INET6=10
    pub pid: u32,                      // -
    pub saddr_v4: u32,                 // Source IPv4 (network byte order)
    pub daddr_v4: u32,                 // Dest IPv4 (network byte order)
    pub saddr_v6: [u8; 16],            // Source IPv6
    pub daddr_v6: [u8; 16],            // Dest IPv6
    pub sport: u16,                    // Source port
    pub dport: u16,                    // Dest port
    pub duration_ns: u64,              // Connect latency or connection duration
    pub name: [u8; MAX_PROC_NAME_LEN], // Process comm
}
