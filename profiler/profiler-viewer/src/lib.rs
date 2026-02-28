mod aggregate;
mod anomaly;
mod process;
mod tree;
mod types;

use types::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn process_jsonl(text: &str) -> String {
    let result = process(text);
    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}

fn process(text: &str) -> ViewerResult {
    let mut process_events = Vec::new();
    let mut metrics_events = Vec::new();
    let mut block_io_events = Vec::new();
    let mut sched_events = Vec::new();
    let mut oom_events = Vec::new();
    let mut total_events = 0u64;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        total_events += 1;

        let raw: RawEvent = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        match raw.event_type.as_str() {
            "exec" | "exit" => {
                if let Ok(e) = serde_json::from_str::<ProcessEventRaw>(line) {
                    process_events.push(e);
                }
            }
            "metrics" => {
                if let Ok(e) = serde_json::from_str::<MetricsEventRaw>(line) {
                    metrics_events.push(e);
                }
            }
            "block_io" => {
                if let Ok(e) = serde_json::from_str::<BlockIoEventRaw>(line) {
                    block_io_events.push(e);
                }
            }
            "sched_latency" => {
                if let Ok(e) = serde_json::from_str::<SchedLatencyEventRaw>(line) {
                    sched_events.push(e);
                }
            }
            "oom_kill" => {
                if let Ok(e) = serde_json::from_str::<OomKillEventRaw>(line) {
                    oom_events.push(e);
                }
            }
            _ => {}
        }
    }

    let mut t0 = u64::MAX;
    for e in &process_events {
        t0 = t0.min(e.time_ns);
    }
    for e in &metrics_events {
        t0 = t0.min(e.time_ns);
    }
    for e in &block_io_events {
        t0 = t0.min(e.time_ns);
    }
    for e in &sched_events {
        t0 = t0.min(e.time_ns);
    }
    for e in &oom_events {
        t0 = t0.min(e.time_ns);
    }
    if t0 == u64::MAX {
        t0 = 0;
    }

    let processes = process::pair_processes(&process_events, t0);

    let metrics: Vec<MetricsOut> = metrics_events
        .iter()
        .map(|m| MetricsOut {
            time_s: ns_to_s(m.time_ns, t0),
            time_ns: m.time_ns,
            cpu: m.cpu.clone(),
            memory: m.memory.clone(),
            disk: m.disk.clone(),
            network: m.network.clone(),
        })
        .collect();

    let block_io: Vec<BlockIoOut> = block_io_events
        .iter()
        .map(|e| BlockIoOut {
            time_s: ns_to_s(e.time_ns, t0),
            latency_ms: e.latency_ns as f64 / 1e6,
            is_read: e.rwbs.starts_with('R'),
            rwbs: e.rwbs.clone(),
            nr_sectors: e.nr_sectors,
            name: e.name.clone(),
            pid: e.pid,
        })
        .collect();

    let sched_latency: Vec<SchedLatencyOut> = sched_events
        .iter()
        .map(|e| SchedLatencyOut {
            time_s: ns_to_s(e.time_ns, t0),
            latency_ms: e.latency_ns as f64 / 1e6,
            name: e.name.clone(),
            pid: e.pid,
        })
        .collect();

    let block_io_summaries = aggregate::aggregate_block_io(&block_io_events, t0);
    let sched_summaries = aggregate::aggregate_sched_latency(&sched_events, t0);

    let oom_kills: Vec<OomKillOut> = oom_events
        .iter()
        .map(|e| OomKillOut {
            time_s: ns_to_s(e.time_ns, t0),
            time_ns: e.time_ns,
            pid: e.pid,
            uid: e.uid,
            victim_name: e.victim_name.clone(),
            total_vm_kb: e.total_vm_kb,
            anon_rss_kb: e.anon_rss_kb,
            file_rss_kb: e.file_rss_kb,
            shmem_rss_kb: e.shmem_rss_kb,
            pgtables_kb: e.pgtables_kb,
            oom_score_adj: e.oom_score_adj,
        })
        .collect();

    let duration_s = if !processes.is_empty() {
        let max_end = processes
            .iter()
            .filter_map(|p| p.end_s)
            .fold(0.0f64, f64::max);
        let min_start = processes
            .iter()
            .map(|p| p.start_s)
            .fold(f64::INFINITY, f64::min);
        max_end - min_start
    } else {
        0.0
    };

    let stats = Stats {
        total_events,
        duration_s,
        process_count: processes.len() as u64,
        block_io_count: block_io_events.len() as u64,
        sched_latency_count: sched_events.len() as u64,
        metrics_count: metrics_events.len() as u64,
        oom_kill_count: oom_events.len() as u64,
    };

    let process_tree = tree::build_process_tree(&processes, &block_io_events, &sched_events);
    let anomalies = anomaly::compute_anomalies(&oom_events, &sched_events, &processes);

    ViewerResult {
        processes,
        process_tree,
        anomalies,
        metrics,
        block_io,
        sched_latency,
        block_io_summaries,
        sched_summaries,
        oom_kills,
        stats,
    }
}

pub fn ns_to_s(ns: u64, t0: u64) -> f64 {
    (ns.saturating_sub(t0)) as f64 / 1e9
}
