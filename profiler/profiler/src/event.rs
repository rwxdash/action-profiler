use std::path::Path;

use profiler_common::{BlockIoEvent, OomKillEvent, ProcessEvent, SchedLatencyEvent};
use serde::Serialize;

use crate::utils::bytes_to_string;

const WRAPPER_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh"];

fn signal_name(sig: u32) -> Option<&'static str> {
    match sig {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        4 => Some("SIGILL"),
        5 => Some("SIGTRAP"),
        6 => Some("SIGABRT"),
        7 => Some("SIGBUS"),
        8 => Some("SIGFPE"),
        9 => Some("SIGKILL"),
        10 => Some("SIGUSR1"),
        11 => Some("SIGSEGV"),
        12 => Some("SIGUSR2"),
        13 => Some("SIGPIPE"),
        14 => Some("SIGALRM"),
        15 => Some("SIGTERM"),
        17 => Some("SIGCHLD"),
        18 => Some("SIGCONT"),
        19 => Some("SIGSTOP"),
        20 => Some("SIGTSTP"),
        24 => Some("SIGXCPU"),
        25 => Some("SIGXFSZ"),
        31 => Some("SIGSYS"),
        _ => None,
    }
}

#[derive(Serialize)]
pub struct ProcessEventRecord {
    pub time_ns: u64,
    pub event_type: &'static str,
    pub exit_code: u32,
    pub signal: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<&'static str>,
    pub duration_ns: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub name: String,
    pub filename: String,
    pub display_name: String,
    pub wrapper: bool,
    pub args: Vec<String>,
}

impl From<&ProcessEvent> for ProcessEventRecord {
    fn from(e: &ProcessEvent) -> Self {
        let name = bytes_to_string(&e.name);
        let filename = bytes_to_string(&e.filename);

        let display_name = if !filename.is_empty() {
            Path::new(&filename)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&name)
                .to_string()
        } else {
            name.clone()
        };

        let wrapper = WRAPPER_SHELLS.contains(&display_name.as_str());

        // Raw kernel exit_code: lower 8 bits = signal, upper bits = status
        let exit_code = e.exit_code >> 8;
        let signal = e.exit_code & 0x7F;
        let signal_name = signal_name(signal);

        Self {
            time_ns: e.time_ns,
            event_type: match e.event_type {
                0 => "exec",
                1 => "exit",
                _ => "unknown",
            },
            exit_code,
            signal,
            signal_name,
            duration_ns: e.duration_ns,
            uid: e.uid,
            gid: e.gid,
            pid: e.pid,
            tgid: e.tgid,
            ppid: e.ppid,
            name,
            filename,
            display_name,
            wrapper,
            args: e
                .args
                .iter()
                .map(|a| bytes_to_string(a))
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub struct OomKillRecord {
    pub time_ns: u64,
    pub event_type: &'static str,
    pub pid: u32,
    pub uid: u32,
    pub total_vm_kb: u64,
    pub anon_rss_kb: u64,
    pub file_rss_kb: u64,
    pub shmem_rss_kb: u64,
    pub pgtables_kb: u64,
    pub oom_score_adj: i16,
    pub victim_name: String,
}

impl From<&OomKillEvent> for OomKillRecord {
    fn from(e: &OomKillEvent) -> Self {
        Self {
            time_ns: e.time_ns,
            event_type: "oom_kill",
            pid: e.pid,
            uid: e.uid,
            total_vm_kb: e.total_vm_kb,
            anon_rss_kb: e.anon_rss_kb,
            file_rss_kb: e.file_rss_kb,
            shmem_rss_kb: e.shmem_rss_kb,
            pgtables_kb: e.pgtables_kb,
            oom_score_adj: e.oom_score_adj,
            victim_name: bytes_to_string(&e.victim_name),
        }
    }
}

#[derive(Serialize)]
pub struct BlockIoRecord {
    pub time_ns: u64,
    pub event_type: &'static str,
    pub dev: u32,
    pub sector: u64,
    pub nr_sectors: u32,
    pub latency_ns: u64,
    pub rwbs: String,
    pub pid: u32,
    pub name: String,
}

impl From<&BlockIoEvent> for BlockIoRecord {
    fn from(e: &BlockIoEvent) -> Self {
        Self {
            time_ns: e.time_ns,
            event_type: "block_io",
            dev: e.dev,
            sector: e.sector,
            nr_sectors: e.nr_sectors,
            latency_ns: e.latency_ns,
            rwbs: bytes_to_string(&e.rwbs),
            pid: e.pid,
            name: bytes_to_string(&e.name),
        }
    }
}

#[derive(Serialize)]
pub struct SchedLatencyRecord {
    pub time_ns: u64,
    pub event_type: &'static str,
    pub pid: u32,
    pub latency_ns: u64,
    pub prio: i32,
    pub target_cpu: i32,
    pub name: String,
}

impl From<&SchedLatencyEvent> for SchedLatencyRecord {
    fn from(e: &SchedLatencyEvent) -> Self {
        Self {
            time_ns: e.time_ns,
            event_type: "sched_latency",
            pid: e.pid,
            latency_ns: e.latency_ns,
            prio: e.prio,
            target_cpu: e.target_cpu,
            name: bytes_to_string(&e.name),
        }
    }
}
