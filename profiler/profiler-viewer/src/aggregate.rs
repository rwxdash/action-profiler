use std::collections::HashMap;

use crate::types::*;

pub fn aggregate_block_io(events: &[BlockIoEventRaw], t0: u64) -> Vec<BlockIoSummaryOut> {
    if events.is_empty() {
        return Vec::new();
    }

    let window_ns: u64 = 5_000_000_000;
    let window_s = 5.0;

    let mut windows: HashMap<u64, (Vec<u64>, u64, Vec<u64>, u64)> = HashMap::new();

    for e in events {
        let bucket = (e.time_ns - t0) / window_ns;
        let entry = windows
            .entry(bucket)
            .or_insert_with(|| (Vec::new(), 0, Vec::new(), 0));
        if e.rwbs.starts_with('R') {
            entry.0.push(e.latency_ns);
            entry.1 += e.nr_sectors as u64;
        } else {
            entry.2.push(e.latency_ns);
            entry.3 += e.nr_sectors as u64;
        }
    }

    let mut summaries: Vec<BlockIoSummaryOut> = windows
        .into_iter()
        .map(
            |(bucket, (mut reads, read_sectors, mut writes, write_sectors))| {
                BlockIoSummaryOut {
                    time_s: (bucket + 1) as f64 * window_s, // window end time
                    window_s,
                    reads: IoStatsOut::from_latencies(&mut reads, read_sectors),
                    writes: IoStatsOut::from_latencies(&mut writes, write_sectors),
                }
            },
        )
        .collect();

    summaries.sort_by(|a, b| a.time_s.partial_cmp(&b.time_s).unwrap());
    summaries
}

pub fn aggregate_sched_latency(events: &[SchedLatencyEventRaw], t0: u64) -> Vec<SchedSummaryOut> {
    if events.is_empty() {
        return Vec::new();
    }

    let window_ns: u64 = 5_000_000_000;
    let window_s = 5.0;

    let mut windows: HashMap<u64, (Vec<u64>, HashMap<String, (u64, u64)>)> = HashMap::new();

    for e in events {
        let bucket = (e.time_ns - t0) / window_ns;
        let entry = windows
            .entry(bucket)
            .or_insert_with(|| (Vec::new(), HashMap::new()));
        entry.0.push(e.latency_ns);

        let proc_entry = entry.1.entry(e.name.clone()).or_insert((0, 0));
        proc_entry.0 += 1;
        proc_entry.1 = proc_entry.1.max(e.latency_ns);
    }

    let mut summaries: Vec<SchedSummaryOut> = windows
        .into_iter()
        .map(|(bucket, (mut latencies, by_process))| {
            let count = latencies.len() as u64;
            let latency = LatencyStatsOut::from_latencies(&mut latencies);

            let mut top_processes: Vec<ProcessLatencyOut> = by_process
                .into_iter()
                .map(|(name, (count, max_ns))| ProcessLatencyOut {
                    name,
                    count,
                    max_latency_ms: max_ns as f64 / 1e6,
                })
                .collect();
            top_processes.sort_by(|a, b| b.max_latency_ms.partial_cmp(&a.max_latency_ms).unwrap());
            top_processes.truncate(5);

            SchedSummaryOut {
                time_s: (bucket + 1) as f64 * window_s,
                window_s,
                count,
                latency,
                top_processes,
            }
        })
        .collect();

    summaries.sort_by(|a, b| a.time_s.partial_cmp(&b.time_s).unwrap());
    summaries
}

impl LatencyStatsOut {
    pub fn from_latencies(latencies: &mut Vec<u64>) -> Self {
        if latencies.is_empty() {
            return Self {
                min_ms: 0.0,
                max_ms: 0.0,
                avg_ms: 0.0,
                p50_ms: 0.0,
                p95_ms: 0.0,
                p99_ms: 0.0,
            };
        }
        latencies.sort_unstable();
        let n = latencies.len();
        let sum: u64 = latencies.iter().sum();
        Self {
            min_ms: latencies[0] as f64 / 1e6,
            max_ms: latencies[n - 1] as f64 / 1e6,
            avg_ms: (sum as f64 / n as f64) / 1e6,
            p50_ms: latencies[n * 50 / 100] as f64 / 1e6,
            p95_ms: latencies[n * 95 / 100] as f64 / 1e6,
            p99_ms: latencies[(n * 99 / 100).min(n - 1)] as f64 / 1e6,
        }
    }
}

impl IoStatsOut {
    pub fn from_latencies(latencies: &mut Vec<u64>, total_sectors: u64) -> Self {
        Self {
            count: latencies.len() as u64,
            total_sectors,
            latency: LatencyStatsOut::from_latencies(latencies),
        }
    }
}
