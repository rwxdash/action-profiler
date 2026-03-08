mod event;
mod loader;
mod metrics;
mod utils;

use std::{
    fs::File,
    io::{BufWriter, Write, stdout},
    path::PathBuf,
    ptr,
    time::Duration,
};

use aya::maps::RingBuf;
use clap::Parser;
use profiler_common::*;
use tokio::{io::unix::AsyncFd, signal, time};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::event::{BlockIoRecord, OomKillRecord, ProcessEventRecord, SchedLatencyRecord};

#[derive(Parser)]
#[command(name = "profiler", about = "eBPF process event tracer")]
pub struct Args {
    /// Output file path for JSONL events (defaults to stdout)
    #[arg(short, long, env = "PROFILER_OUTPUT")]
    output: Option<PathBuf>,

    /// System metrics collection interval in seconds (0 to disable)
    #[arg(long, default_value = "5", env = "PROFILER_METRIC_FREQUENCY")]
    metric_frequency: u64,

    /// Disable the default ignore list (awk, cat, grep, ls, etc.)
    #[arg(long, env = "PROFILER_NO_DEFAULT_IGNORE")]
    pub no_default_ignore: bool,

    /// Comma-separated list of command names to ignore (e.g. "node,python3")
    #[arg(long, env = "PROFILER_IGNORE", value_delimiter = ',')]
    pub ignore: Vec<String>,

    /// Comma-separated cmdline patterns - ignore running processes whose cmdline matches
    #[arg(long, env = "PROFILER_IGNORE_PATTERN", value_delimiter = ',')]
    pub ignore_pattern: Vec<String>,

    /// Disable OOM kill detection
    #[arg(long, env = "PROFILER_NO_OOM")]
    pub no_oom: bool,

    /// Disable block I/O latency tracking
    #[arg(long, env = "PROFILER_NO_BLOCK_IO")]
    pub no_block_io: bool,

    /// Disable scheduler latency tracking
    #[arg(long, env = "PROFILER_NO_SCHED_LATENCY")]
    pub no_sched_latency: bool,

    /// Minimum scheduler latency to report in milliseconds (default: 5ms)
    #[arg(long, default_value = "5", env = "PROFILER_SCHED_THRESHOLD_MS")]
    pub sched_latency_threshold_ms: u64,

    /// Minimum block I/O latency to report in milliseconds (default: 1ms)
    #[arg(long, default_value = "1", env = "PROFILER_BLOCK_IO_THRESHOLD_MS")]
    pub block_io_threshold_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/profiler.bpf.o"
    )))?;

    loader::attach_programs(&mut ebpf, &args)?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let oom_ring_buf = RingBuf::try_from(ebpf.take_map("OOM_EVENTS").unwrap())?;
    let mut oom_async_fd = AsyncFd::with_interest(oom_ring_buf, tokio::io::Interest::READABLE)?;

    let mut writer: BufWriter<Box<dyn Write>> = match &args.output {
        Some(path) => BufWriter::new(Box::new(File::create(path)?)),
        None => BufWriter::new(Box::new(stdout().lock())),
    };

    let mut metrics_state = metrics::MetricsState::default();
    let mut metrics_interval = if args.metric_frequency > 0 {
        let mut interval = time::interval(Duration::from_secs(args.metric_frequency));
        interval.tick().await; // consume the immediate first tick
        let _ = metrics::collect(&mut metrics_state, 0);
        info!(
            "System metrics enabled (every {}s). Use --metric-frequency 0 to disable.",
            args.metric_frequency
        );
        Some(interval)
    } else {
        None
    };

    info!("Profiler running. Press Ctrl-C to stop.");

    loop {
        tokio::select! {
            ready = async_fd.readable_mut() => {
                let mut guard = ready?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    dispatch_event(&item, &mut writer);
                }
                let _ = writer.flush();
                guard.clear_ready();
            }
            ready = oom_async_fd.readable_mut() => {
                let mut guard = ready?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    dispatch_event(&item, &mut writer);
                }
                let _ = writer.flush();
                guard.clear_ready();
            }
            _ = async { metrics_interval.as_mut().unwrap().tick().await }, if metrics_interval.is_some() => {
                // Use CLOCK_BOOTTIME to match eBPF's bpf_ktime_get_boot_ns()
                let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
                let now = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
                let record = metrics::collect(&mut metrics_state, now);
                if let Ok(json) = serde_json::to_string(&record) {
                    let _ = writeln!(writer, "{json}");
                    let _ = writer.flush();
                }
            }
            _ = signal::ctrl_c() => {
                match &args.output {
                    Some(path) => info!("Exiting. Events written to {}", path.display()),
                    None => info!("Exiting."),
                }
                break;
            }
        }
    }

    let mut ring_buf = async_fd.into_inner();
    while let Some(item) = ring_buf.next() {
        dispatch_event(&item, &mut writer);
    }
    let mut oom_ring_buf = oom_async_fd.into_inner();
    while let Some(item) = oom_ring_buf.next() {
        dispatch_event(&item, &mut writer);
    }
    writer.flush()?;

    Ok(())
}

fn dispatch_event(item: &[u8], writer: &mut BufWriter<Box<dyn Write>>) {
    if item.len() < size_of::<EventHeader>() {
        warn!(
            "Dropped malformed event (too small for header: {} bytes)",
            item.len()
        );
        return;
    }

    let header = unsafe { ptr::read_unaligned(item.as_ptr() as *const EventHeader) };

    macro_rules! parse_event {
        ($type:ty) => {{
            if item.len() >= size_of::<$type>() {
                Some(unsafe { ptr::read_unaligned(item.as_ptr() as *const $type) })
            } else {
                warn!(
                    "Dropped truncated {} (expected {}, got {})",
                    stringify!($type),
                    size_of::<$type>(),
                    item.len()
                );
                None
            }
        }};
    }

    let json = match header.event_type {
        EVENT_EXEC | EVENT_EXIT => parse_event!(ProcessEvent)
            .and_then(|e| serde_json::to_string(&ProcessEventRecord::from(&e)).ok()),
        EVENT_OOM_KILL => parse_event!(OomKillEvent).and_then(|e| {
            let record = OomKillRecord::from(&e);
            info!(
                "OOM kill detected: pid={} victim=\"{}\" total_vm={}KB",
                record.pid, record.victim_name, record.total_vm_kb
            );
            serde_json::to_string(&record).ok()
        }),
        EVENT_BLOCK_IO => parse_event!(BlockIoEvent)
            .and_then(|e| serde_json::to_string(&BlockIoRecord::from(&e)).ok()),
        EVENT_SCHED_LATENCY => parse_event!(SchedLatencyEvent)
            .and_then(|e| serde_json::to_string(&SchedLatencyRecord::from(&e)).ok()),
        _ => {
            warn!(
                "Unknown event type: {} (len={})",
                header.event_type,
                item.len()
            );
            None
        }
    };

    if let Some(json) = json {
        let _ = writeln!(writer, "{json}");
    }
}
