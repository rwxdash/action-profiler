use serde::{Deserialize, Serialize};

// Input types (deserialized from JSONL)

#[derive(Deserialize)]
pub struct RawEvent {
    pub event_type: String,
}

#[derive(Deserialize)]
pub struct ProcessEventRaw {
    pub time_ns: u64,
    pub event_type: String,
    pub exit_code: u32,
    #[serde(default)]
    pub signal: u32,
    #[serde(default)]
    pub signal_name: Option<String>,
    pub duration_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Deserialize)]
pub struct MetricsEventRaw {
    pub time_ns: u64,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: DiskMetrics,
    pub network: NetworkMetrics,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct CpuMetrics {
    pub user_pct: f64,
    pub system_pct: f64,
    pub total_pct: f64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct MemoryMetrics {
    pub total_mb: f64,
    pub available_mb: f64,
    pub active_mb: f64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct DiskMetrics {
    pub read_mbps: f64,
    pub write_mbps: f64,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct NetworkMetrics {
    pub rx_mbps: f64,
    pub tx_mbps: f64,
}

#[derive(Deserialize)]
pub struct BlockIoEventRaw {
    pub time_ns: u64,
    pub latency_ns: u64,
    pub rwbs: String,
    pub nr_sectors: u32,
    pub pid: u32,
    pub name: String,
}

#[derive(Deserialize)]
pub struct SchedLatencyEventRaw {
    pub time_ns: u64,
    pub latency_ns: u64,
    pub pid: u32,
    pub name: String,
}

#[derive(Deserialize)]
pub struct OomKillEventRaw {
    pub time_ns: u64,
    pub pid: u32,
    #[serde(default)]
    pub uid: u32,
    pub victim_name: String,
    #[serde(default)]
    pub total_vm_kb: u64,
    #[serde(default)]
    pub anon_rss_kb: u64,
    #[serde(default)]
    pub file_rss_kb: u64,
    #[serde(default)]
    pub shmem_rss_kb: u64,
    #[serde(default)]
    pub pgtables_kb: u64,
    #[serde(default)]
    pub oom_score_adj: i16,
}

// Output types (serialized to JSON for JS)

#[derive(Serialize)]
pub struct ViewerResult {
    pub processes: Vec<ProcessOut>,
    pub process_tree: Vec<ProcessTreeNode>,
    pub anomalies: AnomalySummary,
    pub metrics: Vec<MetricsOut>,
    pub block_io: Vec<BlockIoOut>,
    pub sched_latency: Vec<SchedLatencyOut>,
    pub block_io_summaries: Vec<BlockIoSummaryOut>,
    pub sched_summaries: Vec<SchedSummaryOut>,
    pub oom_kills: Vec<OomKillOut>,
    pub stats: Stats,
}

#[derive(Serialize)]
pub struct ProcessOut {
    pub pid: u32,
    pub ppid: u32,
    pub display_name: String,
    pub name: String,
    pub filename: String,
    pub wrapper: bool,
    pub args: Vec<String>,
    pub exit_code: Option<u32>,
    pub signal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
    pub start_s: f64,
    pub end_s: Option<f64>,
    pub duration_ms: f64,
}

#[derive(Serialize)]
pub struct MetricsOut {
    pub time_s: f64,
    pub time_ns: u64,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: DiskMetrics,
    pub network: NetworkMetrics,
}

#[derive(Serialize)]
pub struct BlockIoOut {
    pub time_s: f64,
    pub latency_ms: f64,
    pub is_read: bool,
    pub rwbs: String,
    pub nr_sectors: u32,
    pub name: String,
    pub pid: u32,
}

#[derive(Serialize)]
pub struct SchedLatencyOut {
    pub time_s: f64,
    pub latency_ms: f64,
    pub name: String,
    pub pid: u32,
}

#[derive(Serialize)]
pub struct BlockIoSummaryOut {
    pub time_s: f64,
    pub window_s: f64,
    pub reads: IoStatsOut,
    pub writes: IoStatsOut,
}

#[derive(Serialize)]
pub struct IoStatsOut {
    pub count: u64,
    pub total_sectors: u64,
    pub latency: LatencyStatsOut,
}

#[derive(Serialize)]
pub struct LatencyStatsOut {
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

#[derive(Serialize)]
pub struct SchedSummaryOut {
    pub time_s: f64,
    pub window_s: f64,
    pub count: u64,
    pub latency: LatencyStatsOut,
    pub top_processes: Vec<ProcessLatencyOut>,
}

#[derive(Serialize)]
pub struct ProcessLatencyOut {
    pub name: String,
    pub count: u64,
    pub max_latency_ms: f64,
}

#[derive(Serialize)]
pub struct OomKillOut {
    pub time_s: f64,
    pub time_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub victim_name: String,
    pub total_vm_kb: u64,
    pub anon_rss_kb: u64,
    pub file_rss_kb: u64,
    pub shmem_rss_kb: u64,
    pub pgtables_kb: u64,
    pub oom_score_adj: i16,
}

#[derive(Serialize)]
pub struct Stats {
    pub total_events: u64,
    pub duration_s: f64,
    pub process_count: u64,
    pub block_io_count: u64,
    pub sched_latency_count: u64,
    pub metrics_count: u64,
    pub oom_kill_count: u64,
}

#[derive(Serialize)]
pub struct ProcessTreeNode {
    pub pid: u32,
    pub ppid: u32,
    pub display_name: String,
    pub name: String,
    pub filename: String,
    pub wrapper: bool,
    pub args: Vec<String>,
    pub exit_code: Option<u32>,
    pub signal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
    pub start_s: f64,
    pub end_s: Option<f64>,
    pub duration_ms: f64,
    pub span_ms: f64,
    pub on_critical_path: bool,
    pub ebpf: ProcessEbpfStats,
    pub children: Vec<ProcessTreeNode>,
}

#[derive(Serialize, Default)]
pub struct ProcessEbpfStats {
    pub sched_count: u64,
    pub sched_avg_ms: f64,
    pub sched_max_ms: f64,
    pub sched_p99_ms: f64,
    pub block_io_read_count: u64,
    pub block_io_read_avg_ms: f64,
    pub block_io_read_max_ms: f64,
    pub block_io_write_count: u64,
    pub block_io_write_avg_ms: f64,
    pub block_io_write_max_ms: f64,
}

#[derive(Serialize)]
pub struct AnomalySummary {
    pub oom_count: u64,
    pub high_sched_latency: bool,
    pub max_sched_latency_ms: f64,
    pub failed_process_count: u64,
}
