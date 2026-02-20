use std::fs;

pub fn name_to_bytes(name: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let name_bytes = name.as_bytes();
    // Copy up to 15 characters (leaving at least one null byte at the end)
    let len = name_bytes.len().min(15);
    bytes[..len].copy_from_slice(&name_bytes[..len]);
    bytes
}

pub fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Scan /proc for running processes whose cmdline contains any of the given patterns.
/// Returns the PIDs of all matching processes.
pub fn scan_ignored_pids(patterns: &[&str]) -> Vec<u32> {
    let mut pids = Vec::new();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return pids,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at numeric directories (PIDs)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Read cmdline (null-separated args)
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let cmdline = match fs::read(&cmdline_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Replace null bytes with spaces for pattern matching
        let cmdline_str = cmdline
            .split(|&b| b == 0)
            .map(|seg| String::from_utf8_lossy(seg))
            .collect::<Vec<_>>()
            .join(" ");

        for pattern in patterns {
            if cmdline_str.contains(pattern) {
                pids.push(pid);
                break;
            }
        }
    }

    pids
}
