use crate::types::*;

pub fn compute_anomalies(
    oom_events: &[OomKillEventRaw],
    sched_events: &[SchedLatencyEventRaw],
    processes: &[ProcessOut],
) -> AnomalySummary {
    let max_sched_latency_ms = sched_events
        .iter()
        .map(|e| e.latency_ns as f64 / 1e6)
        .fold(0.0f64, f64::max);

    let failed_process_count = processes
        .iter()
        .filter(|p| matches!(p.exit_code, Some(code) if code != 0))
        .count() as u64;

    AnomalySummary {
        oom_count: oom_events.len() as u64,
        high_sched_latency: max_sched_latency_ms > 50.0,
        max_sched_latency_ms,
        failed_process_count,
    }
}
