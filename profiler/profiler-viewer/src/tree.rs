use std::collections::HashMap;

use crate::types::*;

pub fn build_process_tree(
    processes: &[ProcessOut],
    block_io_events: &[BlockIoEventRaw],
    sched_events: &[SchedLatencyEventRaw],
) -> Vec<ProcessTreeNode> {
    let mut sched_by_pid: HashMap<u32, Vec<f64>> = HashMap::new();
    for e in sched_events {
        sched_by_pid
            .entry(e.pid)
            .or_default()
            .push(e.latency_ns as f64 / 1e6);
    }

    let mut bio_read_by_pid: HashMap<u32, Vec<f64>> = HashMap::new();
    let mut bio_write_by_pid: HashMap<u32, Vec<f64>> = HashMap::new();
    for e in block_io_events {
        let ms = e.latency_ns as f64 / 1e6;
        if e.rwbs.starts_with('R') {
            bio_read_by_pid.entry(e.pid).or_default().push(ms);
        } else {
            bio_write_by_pid.entry(e.pid).or_default().push(ms);
        }
    }

    let pid_set: std::collections::HashSet<u32> = processes.iter().map(|p| p.pid).collect();
    let mut children_map: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, p) in processes.iter().enumerate() {
        children_map.entry(p.ppid).or_default().push(i);
    }

    let roots: Vec<usize> = processes
        .iter()
        .enumerate()
        .filter(|(_, p)| !pid_set.contains(&p.ppid))
        .map(|(i, _)| i)
        .collect();

    fn build_node(
        idx: usize,
        processes: &[ProcessOut],
        children_map: &HashMap<u32, Vec<usize>>,
        sched_by_pid: &HashMap<u32, Vec<f64>>,
        bio_read_by_pid: &HashMap<u32, Vec<f64>>,
        bio_write_by_pid: &HashMap<u32, Vec<f64>>,
    ) -> ProcessTreeNode {
        let p = &processes[idx];

        let ebpf = compute_process_ebpf(p.pid, sched_by_pid, bio_read_by_pid, bio_write_by_pid);

        let mut child_nodes: Vec<ProcessTreeNode> = children_map
            .get(&p.pid)
            .map(|indices| {
                indices
                    .iter()
                    .map(|&ci| {
                        build_node(
                            ci,
                            processes,
                            children_map,
                            sched_by_pid,
                            bio_read_by_pid,
                            bio_write_by_pid,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        child_nodes.sort_by(|a, b| {
            a.start_s
                .partial_cmp(&b.start_s)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // span_ms = time from own start to the latest end among self + all descendants
        let own_end = p.end_s.unwrap_or(p.start_s + p.duration_ms / 1000.0);
        let child_max_end = child_nodes
            .iter()
            .filter_map(|c| {
                let c_end = c.start_s + c.span_ms / 1000.0;
                Some(c_end)
            })
            .fold(f64::NEG_INFINITY, f64::max);
        let span_end = if child_max_end > f64::NEG_INFINITY {
            own_end.max(child_max_end)
        } else {
            own_end
        };
        let span_ms = (span_end - p.start_s) * 1000.0;

        ProcessTreeNode {
            pid: p.pid,
            ppid: p.ppid,
            display_name: p.display_name.clone(),
            name: p.name.clone(),
            filename: p.filename.clone(),
            wrapper: p.wrapper,
            args: p.args.clone(),
            exit_code: p.exit_code,
            signal: p.signal,
            signal_name: p.signal_name.clone(),
            start_s: p.start_s,
            end_s: p.end_s,
            duration_ms: p.duration_ms,
            span_ms,
            on_critical_path: false,
            ebpf,
            children: child_nodes,
        }
    }

    let mut tree: Vec<ProcessTreeNode> = roots
        .iter()
        .map(|&i| {
            build_node(
                i,
                processes,
                &children_map,
                &sched_by_pid,
                &bio_read_by_pid,
                &bio_write_by_pid,
            )
        })
        .collect();
    tree.sort_by(|a, b| {
        a.start_s
            .partial_cmp(&b.start_s)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for node in &mut tree {
        mark_critical_path(node);
    }

    tree
}

fn compute_process_ebpf(
    pid: u32,
    sched_by_pid: &HashMap<u32, Vec<f64>>,
    bio_read_by_pid: &HashMap<u32, Vec<f64>>,
    bio_write_by_pid: &HashMap<u32, Vec<f64>>,
) -> ProcessEbpfStats {
    let mut stats = ProcessEbpfStats::default();

    if let Some(latencies) = sched_by_pid.get(&pid) {
        if !latencies.is_empty() {
            let n = latencies.len();
            let sum: f64 = latencies.iter().sum();
            let max = latencies.iter().cloned().fold(0.0f64, f64::max);
            let mut sorted = latencies.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            stats.sched_count = n as u64;
            stats.sched_avg_ms = sum / n as f64;
            stats.sched_max_ms = max;
            stats.sched_p99_ms = sorted[(n * 99 / 100).min(n - 1)];
        }
    }

    if let Some(latencies) = bio_read_by_pid.get(&pid) {
        if !latencies.is_empty() {
            let n = latencies.len();
            let sum: f64 = latencies.iter().sum();
            let max = latencies.iter().cloned().fold(0.0f64, f64::max);
            stats.block_io_read_count = n as u64;
            stats.block_io_read_avg_ms = sum / n as f64;
            stats.block_io_read_max_ms = max;
        }
    }

    if let Some(latencies) = bio_write_by_pid.get(&pid) {
        if !latencies.is_empty() {
            let n = latencies.len();
            let sum: f64 = latencies.iter().sum();
            let max = latencies.iter().cloned().fold(0.0f64, f64::max);
            stats.block_io_write_count = n as u64;
            stats.block_io_write_avg_ms = sum / n as f64;
            stats.block_io_write_max_ms = max;
        }
    }

    stats
}

fn mark_critical_path(node: &mut ProcessTreeNode) {
    node.on_critical_path = true;
    if node.children.is_empty() {
        return;
    }
    let longest_idx = node
        .children
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.duration_ms
                .partial_cmp(&b.duration_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(i, _)| i);
    if let Some(idx) = longest_idx {
        mark_critical_path(&mut node.children[idx]);
    }
}
