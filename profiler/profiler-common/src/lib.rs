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
pub struct NetworkEvent {
    pub time_ns: u64,
    pub pid: u32,        // Process ID
    pub tgid: u32,       // Thread Group ID
    pub saddr: u32,      // Source IPv4
    pub daddr: u32,      // Destination IPv4
    pub sport: u16,      // Source Port
    pub dport: u16,      // Destination Port
    pub bytes_sent: u64, // -
    pub bytes_recv: u64, // -
    pub protocol: u8,    // TCP=6, UDP=17
    pub state: u8,       // Connection State
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoEvent {
    pub time_ns: u64,
    pub pid: u32,        // Process ID
    pub tgid: u32,       // Thread Group ID
    pub bytes: u64,      // -
    pub latency_ns: u64, // -
    pub op: u8,          // 0=read, 1=write
    pub filename: [u8; MAX_FILENAME_LEN],
}
