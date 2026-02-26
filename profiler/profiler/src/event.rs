use std::path::Path;

use profiler_common::ProcessEvent;
use serde::Serialize;

use crate::utils::bytes_to_string;

/// Shell wrappers: these spawn child processes that do the real work.
/// Kept in the data but marked so frontends can hide/dim them by default.
const WRAPPER_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh"];

#[derive(Serialize)]
pub struct ProcessEventRecord {
    pub time_ns: u64,
    pub event_type: &'static str,
    pub exit_code: u32,
    pub duration_ns: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    /// Kernel comm (truncated to 16 bytes)
    pub name: String,
    /// Full binary path from linux_binprm (exec events only)
    pub filename: String,
    /// Display name: basename of filename if available, otherwise comm
    pub display_name: String,
    /// True for shell wrappers (sh, bash, dash, zsh) — frontends can hide/dim these
    pub wrapper: bool,
    pub args: Vec<String>,
}

impl From<&ProcessEvent> for ProcessEventRecord {
    fn from(e: &ProcessEvent) -> Self {
        let name = bytes_to_string(&e.name);
        let filename = bytes_to_string(&e.filename);

        // Use basename of filename when available (not truncated like comm).
        // Fall back to comm name for exit events or when filename is empty.
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

        Self {
            time_ns: e.time_ns,
            event_type: match e.event_type {
                0 => "exec",
                1 => "exit",
                _ => "unknown",
            },
            exit_code: e.exit_code,
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
