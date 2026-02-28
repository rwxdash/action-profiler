use std::{fs::File, io::Read};

use serde::Serialize;

#[derive(Serialize, Default)]
pub struct CpuMetrics {
    pub user_pct: f64,
    pub system_pct: f64,
    pub total_pct: f64,
}

#[derive(Serialize, Default)]
pub struct MemoryMetrics {
    pub total_mb: f64,
    pub available_mb: f64,
    pub active_mb: f64,
}

#[derive(Serialize, Default)]
pub struct DiskMetrics {
    pub read_mbps: f64,
    pub write_mbps: f64,
}

#[derive(Serialize, Default)]
pub struct NetworkMetrics {
    pub rx_mbps: f64,
    pub tx_mbps: f64,
}

#[derive(Serialize)]
pub struct SystemMetricsRecord {
    pub time_ns: u64,
    pub event_type: &'static str,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: DiskMetrics,
    pub network: NetworkMetrics,
}

#[derive(Default)]
struct CpuSample {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuSample {
    fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    fn busy(&self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq + self.steal
    }
}

#[derive(Default)]
struct DiskSample {
    read_sectors: u64,
    write_sectors: u64,
}

#[derive(Default)]
struct NetSample {
    rx_bytes: u64,
    tx_bytes: u64,
}

pub struct MetricsState {
    prev_time_ns: Option<u64>,
    prev_cpu: Option<CpuSample>,
    prev_disk: Option<DiskSample>,
    prev_net: Option<NetSample>,
    buf: String,
}

impl Default for MetricsState {
    fn default() -> Self {
        Self {
            prev_time_ns: None,
            prev_cpu: None,
            prev_disk: None,
            prev_net: None,
            buf: String::with_capacity(4096),
        }
    }
}

impl MetricsState {
    fn read_proc(&mut self, path: &str) -> Option<&str> {
        self.buf.clear();
        File::open(path).ok()?.read_to_string(&mut self.buf).ok()?;
        Some(&self.buf)
    }
}

pub fn collect(state: &mut MetricsState, time_ns: u64) -> SystemMetricsRecord {
    let elapsed_sec = state
        .prev_time_ns
        .map(|prev| (time_ns.saturating_sub(prev)) as f64 / 1_000_000_000.0)
        .unwrap_or(0.0);

    let elapsed_sec = if elapsed_sec < 0.01 { 0.0 } else { elapsed_sec };

    state.prev_time_ns = Some(time_ns);

    let mut record = SystemMetricsRecord {
        time_ns,
        event_type: "metrics",
        cpu: collect_cpu(state),
        memory: collect_memory(state),
        disk: collect_disk(state, elapsed_sec),
        network: collect_network(state, elapsed_sec),
    };

    // Clamp near-zero floating point noise (e.g. 1.7e-13) to exactly 0.0
    clamp_noise(&mut record.cpu.user_pct);
    clamp_noise(&mut record.cpu.system_pct);
    clamp_noise(&mut record.cpu.total_pct);
    clamp_noise(&mut record.disk.read_mbps);
    clamp_noise(&mut record.disk.write_mbps);
    clamp_noise(&mut record.network.rx_mbps);
    clamp_noise(&mut record.network.tx_mbps);

    record
}

// Clamp values below a threshold to 0.0 to avoid floating point dust
// in the JSONL output (e.g. 1.7e-13 from cumulative counter rounding).
fn clamp_noise(val: &mut f64) {
    if val.abs() < 1e-6 {
        *val = 0.0;
    }
}

fn parse_cpu_sample(buf: &str) -> Option<CpuSample> {
    let line = buf.lines().next()?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1) // skip "cpu"
        .filter_map(|f| f.parse().ok())
        .collect();

    if fields.len() < 8 {
        return None;
    }

    Some(CpuSample {
        user: fields[0],
        nice: fields[1],
        system: fields[2],
        idle: fields[3],
        iowait: fields[4],
        irq: fields[5],
        softirq: fields[6],
        steal: fields[7],
    })
}

fn collect_cpu(state: &mut MetricsState) -> CpuMetrics {
    let sample = state.read_proc("/proc/stat");
    let current = match sample.and_then(parse_cpu_sample) {
        Some(s) => s,
        None => return CpuMetrics::default(),
    };

    let metrics = if let Some(prev) = &state.prev_cpu {
        let total_delta = current.total().saturating_sub(prev.total());
        if total_delta == 0 {
            CpuMetrics::default()
        } else {
            let user_delta = (current.user + current.nice).saturating_sub(prev.user + prev.nice);
            let system_delta = current.system.saturating_sub(prev.system);
            let busy_delta = current.busy().saturating_sub(prev.busy());
            CpuMetrics {
                user_pct: user_delta as f64 / total_delta as f64 * 100.0,
                system_pct: system_delta as f64 / total_delta as f64 * 100.0,
                total_pct: busy_delta as f64 / total_delta as f64 * 100.0,
            }
        }
    } else {
        CpuMetrics::default()
    };

    state.prev_cpu = Some(current);
    metrics
}

fn collect_memory(state: &mut MetricsState) -> MemoryMetrics {
    let mut total_kb: f64 = 0.0;
    let mut available_kb: f64 = 0.0;
    let mut active_kb: f64 = 0.0;

    if let Some(content) = state.read_proc("/proc/meminfo") {
        for line in content.lines() {
            if let Some(val) = parse_meminfo_line(line, "MemTotal:") {
                total_kb = val;
            } else if let Some(val) = parse_meminfo_line(line, "MemAvailable:") {
                available_kb = val;
            } else if let Some(val) = parse_meminfo_line(line, "Active:") {
                active_kb = val;
            }
        }
    }

    MemoryMetrics {
        total_mb: total_kb / 1024.0,
        available_mb: available_kb / 1024.0,
        active_mb: active_kb / 1024.0,
    }
}

fn parse_meminfo_line(line: &str, key: &str) -> Option<f64> {
    if !line.starts_with(key) {
        return None;
    }
    line[key.len()..].split_whitespace().next()?.parse().ok()
}

fn parse_disk_sample(buf: &str) -> Option<DiskSample> {
    let mut read_sectors: u64 = 0;
    let mut write_sectors: u64 = 0;

    for line in buf.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 14 {
            continue;
        }

        let name = fields[2];
        if !is_whole_disk(name) {
            continue;
        }

        let rd: u64 = fields[5].parse().unwrap_or(0);
        let wr: u64 = fields[9].parse().unwrap_or(0);
        read_sectors += rd;
        write_sectors += wr;
    }

    Some(DiskSample {
        read_sectors,
        write_sectors,
    })
}

// Heuristic: a "whole disk" device name doesn't end with a digit
// (e.g. "sda" not "sda1"), unless it's NVMe ("nvme0n1" is a whole
// disk, "nvme0n1p1" is a partition). Skip virtual devices.
fn is_whole_disk(name: &str) -> bool {
    if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
        return false;
    }

    // NVMe: "nvme0n1" is a whole disk, "nvme0n1p1" is a partition
    if name.starts_with("nvme") {
        return !name.contains('p') || name.ends_with(|c: char| !c.is_ascii_digit());
    }

    // Traditional: "sda"/"vda"/"xvda" are whole disks; "sda1" is a partition
    !name.ends_with(|c: char| c.is_ascii_digit())
}

fn collect_disk(state: &mut MetricsState, elapsed_sec: f64) -> DiskMetrics {
    let sample = state.read_proc("/proc/diskstats");
    let current = match sample.and_then(parse_disk_sample) {
        Some(s) => s,
        None => return DiskMetrics::default(),
    };

    let metrics = if let Some(prev) = &state.prev_disk {
        if elapsed_sec == 0.0 {
            DiskMetrics::default()
        } else {
            let rd_delta = current.read_sectors.saturating_sub(prev.read_sectors);
            let wr_delta = current.write_sectors.saturating_sub(prev.write_sectors);
            DiskMetrics {
                read_mbps: (rd_delta as f64 * 512.0 / 1024.0 / 1024.0) / elapsed_sec,
                write_mbps: (wr_delta as f64 * 512.0 / 1024.0 / 1024.0) / elapsed_sec,
            }
        }
    } else {
        DiskMetrics::default()
    };

    state.prev_disk = Some(current);
    metrics
}

fn parse_net_sample(buf: &str) -> Option<NetSample> {
    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;

    for line in buf.lines().skip(2) {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let iface = parts[0].trim();
        if iface == "lo" {
            continue;
        }

        let fields: Vec<u64> = parts[1]
            .split_whitespace()
            .filter_map(|f| f.parse().ok())
            .collect();

        if fields.len() < 10 {
            continue;
        }

        rx_bytes += fields[0];
        tx_bytes += fields[8];
    }

    Some(NetSample { rx_bytes, tx_bytes })
}

fn collect_network(state: &mut MetricsState, elapsed_sec: f64) -> NetworkMetrics {
    let sample = state.read_proc("/proc/net/dev");
    let current = match sample.and_then(parse_net_sample) {
        Some(s) => s,
        None => return NetworkMetrics::default(),
    };

    let metrics = if let Some(prev) = &state.prev_net {
        if elapsed_sec == 0.0 {
            NetworkMetrics::default()
        } else {
            let rx_delta = current.rx_bytes.saturating_sub(prev.rx_bytes);
            let tx_delta = current.tx_bytes.saturating_sub(prev.tx_bytes);
            NetworkMetrics {
                rx_mbps: (rx_delta as f64 / 1024.0 / 1024.0) / elapsed_sec,
                tx_mbps: (tx_delta as f64 / 1024.0 / 1024.0) / elapsed_sec,
            }
        }
    } else {
        NetworkMetrics::default()
    };

    state.prev_net = Some(current);
    metrics
}
