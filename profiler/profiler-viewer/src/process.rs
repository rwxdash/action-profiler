use std::collections::HashMap;

use crate::{
    ns_to_s,
    types::{ProcessEventRaw, ProcessOut},
};

const WRAPPER_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh"];

pub fn pair_processes(events: &[ProcessEventRaw], t0: u64) -> Vec<ProcessOut> {
    let mut exec_map: HashMap<u32, &ProcessEventRaw> = HashMap::new();
    let mut results = Vec::new();

    for e in events {
        match e.event_type.as_str() {
            "exec" => {
                exec_map.insert(e.pid, e);
            }
            "exit" => {
                if let Some(exec) = exec_map.remove(&e.pid) {
                    let duration_ns = if e.duration_ns > 0 {
                        e.duration_ns
                    } else {
                        e.time_ns - exec.time_ns
                    };
                    results.push(ProcessOut {
                        pid: e.pid,
                        ppid: exec.ppid,
                        display_name: exec.display_name.clone(),
                        name: exec.name.clone(),
                        filename: exec.filename.clone(),
                        wrapper: WRAPPER_SHELLS.contains(&exec.display_name.as_str()),
                        args: exec.args.clone(),
                        exit_code: Some(e.exit_code),
                        start_s: ns_to_s(exec.time_ns, t0),
                        end_s: Some(ns_to_s(e.time_ns, t0)),
                        duration_ms: duration_ns as f64 / 1e6,
                    });
                }
            }
            _ => {}
        }
    }

    for (_, exec) in exec_map {
        results.push(ProcessOut {
            pid: exec.pid,
            ppid: exec.ppid,
            display_name: exec.display_name.clone(),
            name: exec.name.clone(),
            filename: exec.filename.clone(),
            wrapper: WRAPPER_SHELLS.contains(&exec.display_name.as_str()),
            args: exec.args.clone(),
            exit_code: None,
            start_s: ns_to_s(exec.time_ns, t0),
            end_s: None,
            duration_ms: 0.0,
        });
    }

    results
}
