use profiler_common::ProcessEvent;
use serde::Serialize;

use crate::utils::bytes_to_string;

#[derive(Serialize)]
pub struct ProcessEventRecord {
    pub time_ns: u64,
    pub event_type: &'static str,
    pub exit_code: u32,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub name: String,
    pub filename: String,
    pub args: Vec<String>,
}

impl From<&ProcessEvent> for ProcessEventRecord {
    fn from(e: &ProcessEvent) -> Self {
        Self {
            time_ns: e.time_ns,
            event_type: match e.event_type {
                0 => "exec",
                1 => "exit",
                _ => "unknown",
            },
            exit_code: e.exit_code,
            uid: e.uid,
            gid: e.gid,
            pid: e.pid,
            tgid: e.tgid,
            ppid: e.ppid,
            name: bytes_to_string(&e.name),
            filename: bytes_to_string(&e.filename),
            args: e
                .args
                .iter()
                .map(|a| bytes_to_string(a))
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }
}
