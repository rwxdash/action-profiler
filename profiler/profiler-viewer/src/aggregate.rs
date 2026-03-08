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
        if e.operation == "read" {
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

pub fn pair_tcp_connections(events: &[TcpEventRaw], t0: u64) -> Vec<TcpConnectionOut> {
    use std::collections::VecDeque;

    use crate::ns_to_s;

    if events.is_empty() {
        return Vec::new();
    }

    // Key: (pid, daddr, dport) -- sport excluded because kernel clears it
    // before CLOSE state transition (close events always have sport=0).
    // VecDeque for FIFO matching when multiple connections to same endpoint.
    let mut pending: HashMap<(u32, String, u16), VecDeque<&TcpEventRaw>> = HashMap::new();
    let mut connections = Vec::new();

    let max_time_ns = events.iter().map(|e| e.time_ns).max().unwrap_or(0);

    for e in events {
        let key = (e.pid, e.daddr.clone(), e.dport);

        match e.tcp_type {
            TcpType::Connect | TcpType::Accept => {
                pending.entry(key).or_default().push_back(e);
            }
            TcpType::Close => {
                let start_event = pending.get_mut(&key).and_then(|q| q.pop_front());
                let (start_ns, connect_ms, sport) = if let Some(conn) = start_event {
                    (conn.time_ns, conn.duration_ns as f64 / 1e6, conn.sport)
                } else {
                    // Close without matching connect -- started before profiler
                    (e.time_ns.saturating_sub(e.duration_ns), 0.0, e.sport)
                };
                connections.push(TcpConnectionOut {
                    start_s: ns_to_s(start_ns, t0),
                    end_s: ns_to_s(e.time_ns, t0),
                    duration_ms: e.duration_ns as f64 / 1e6,
                    connect_ms,
                    pid: e.pid,
                    name: e.name.clone(),
                    saddr: e.saddr.clone(),
                    daddr: e.daddr.clone(),
                    sport,
                    dport: e.dport,
                    endpoint: format!("{}:{}", e.daddr, e.dport),
                    closed: true,
                });
            }
        }
    }

    // Emit unpaired connects as open connections
    for (_, queue) in pending {
        for e in queue {
            connections.push(TcpConnectionOut {
                start_s: ns_to_s(e.time_ns, t0),
                end_s: ns_to_s(max_time_ns, t0),
                duration_ms: (max_time_ns - e.time_ns) as f64 / 1e6,
                connect_ms: e.duration_ns as f64 / 1e6,
                pid: e.pid,
                name: e.name.clone(),
                saddr: e.saddr.clone(),
                daddr: e.daddr.clone(),
                sport: e.sport,
                dport: e.dport,
                endpoint: format!("{}:{}", e.daddr, e.dport),
                closed: false,
            });
        }
    }

    connections.sort_by(|a, b| a.start_s.partial_cmp(&b.start_s).unwrap());
    connections
}

// Per-type window bucket: (latencies_ns, endpoint_counts)
type TcpWindowBucket = (Vec<u64>, HashMap<String, (u64, u64)>);

pub fn aggregate_tcp(events: &[TcpEventRaw], t0: u64) -> Vec<TcpSummaryOut> {
    if events.is_empty() {
        return Vec::new();
    }

    let window_ns: u64 = 5_000_000_000;
    let window_s = 5.0;

    // Per bucket: (connects, accepts, closes)
    let mut windows: HashMap<u64, (TcpWindowBucket, TcpWindowBucket, TcpWindowBucket)> =
        HashMap::new();

    for e in events {
        let bucket = (e.time_ns - t0) / window_ns;
        let entry = windows.entry(bucket).or_insert_with(|| {
            (
                (Vec::new(), HashMap::new()),
                (Vec::new(), HashMap::new()),
                (Vec::new(), HashMap::new()),
            )
        });

        let endpoint = format!("{}:{}", e.daddr, e.dport);
        let type_bucket = match e.tcp_type {
            TcpType::Connect => &mut entry.0,
            TcpType::Accept => &mut entry.1,
            TcpType::Close => &mut entry.2,
        };

        type_bucket.0.push(e.duration_ns);
        let ep_entry = type_bucket.1.entry(endpoint).or_insert((0, 0));
        ep_entry.0 += 1;
        ep_entry.1 += e.duration_ns;
    }

    let mut summaries: Vec<TcpSummaryOut> = windows
        .into_iter()
        .map(|(bucket, (connects, accepts, closes))| TcpSummaryOut {
            time_s: (bucket + 1) as f64 * window_s,
            window_s,
            connects: tcp_type_stats(connects),
            accepts: tcp_type_stats(accepts),
            closes: tcp_type_stats(closes),
        })
        .collect();

    summaries.sort_by(|a, b| a.time_s.partial_cmp(&b.time_s).unwrap());
    summaries
}

fn tcp_type_stats((mut latencies, by_endpoint): TcpWindowBucket) -> TcpTypeStats {
    let count = latencies.len() as u64;
    let latency = LatencyStatsOut::from_latencies(&mut latencies);

    let mut top_endpoints: Vec<EndpointStats> = by_endpoint
        .into_iter()
        .map(|(endpoint, (count, total_ns))| EndpointStats {
            endpoint,
            count,
            avg_ms: if count > 0 {
                (total_ns as f64 / count as f64) / 1e6
            } else {
                0.0
            },
        })
        .collect();
    top_endpoints.sort_by(|a, b| b.count.cmp(&a.count));
    top_endpoints.truncate(5);

    TcpTypeStats {
        count,
        latency,
        top_endpoints,
    }
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
