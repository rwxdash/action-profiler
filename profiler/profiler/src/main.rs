mod event;
mod metrics;
mod utils;

use std::{
    env,
    fs::File,
    io::{BufWriter, Write, stdout},
    path::PathBuf,
    time::Duration,
};

use aya::{
    maps::{HashMap, RingBuf},
    programs::{RawTracePoint, TracePoint},
};
use clap::Parser;
use profiler_common::ProcessEvent;
use tokio::{io::unix::AsyncFd, signal, time};
use tracing::{debug, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    event::ProcessEventRecord,
    utils::{name_to_bytes, scan_ignored_pids},
};

// Note: "sh" is excluded — it's often used as `sh -c "real command"` and
// our fork inheritance would hide the child process too.
const DEFAULT_IGNORE: &[&str] = &[
    "awk", "basename", "cat", "cut", "date", "echo", "envsubst", "expr", "dirname", "grep", "head",
    "id", "ip", "ln", "ls", "lsblk", "mkdir", "mktemp", "mv", "ps", "readlink", "rm", "sed", "seq",
    "uname", "whoami",
];

#[derive(Parser)]
#[command(name = "profiler", about = "eBPF process event tracer")]
struct Args {
    /// Output file path for JSONL events (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Disable the default ignore list (awk, cat, grep, ls, etc.)
    #[arg(long)]
    no_default_ignore: bool,

    /// System metrics collection interval in seconds (0 to disable)
    #[arg(long, default_value = "5")]
    metric_frequency: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))) // Defaults to info, overridable via RUST_LOG
        .init();

    let args = Args::parse();

    let ignore_env = env::var("PROFILER_IGNORE").unwrap_or_else(|_| "".to_string());
    let ignore_list: Vec<&str> = ignore_env.split(',').filter(|s| !s.is_empty()).collect();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/profiler"
    )))?;

    let mut ignored_names: HashMap<_, [u8; 16], u8> =
        HashMap::try_from(ebpf.map_mut("IGNORED_NAMES").unwrap())?;

    // Seed default ignore list (unless opted out)
    if !args.no_default_ignore {
        for cmd in DEFAULT_IGNORE {
            ignored_names.insert(name_to_bytes(cmd), 1, 0)?;
        }
        info!(
            "Default ignore list active ({} commands). Use --no-default-ignore to disable.",
            DEFAULT_IGNORE.len()
        );
    }

    for cmd in ignore_list {
        ignored_names.insert(name_to_bytes(cmd.trim()), 1, 0)?;
        info!("Ignoring by name: {}", cmd.trim());
    }

    // Seed IGNORED_PIDS from running processes matching cmdline patterns
    let pattern_env = env::var("PROFILER_IGNORE_PATTERN").unwrap_or_default();
    let patterns: Vec<&str> = pattern_env.split(',').filter(|s| !s.is_empty()).collect();

    if !patterns.is_empty() {
        let mut ignored_pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IGNORED_PIDS").unwrap())?;

        let pids = scan_ignored_pids(&patterns);
        for pid in &pids {
            ignored_pids.insert(*pid, 1, 0)?;
        }
        if pids.is_empty() {
            warn!("No running processes matched patterns: {:?}", patterns);
        } else {
            info!(
                "Ignoring {} processes matching {:?}: {:?}",
                pids.len(),
                patterns,
                pids
            );
        }
    }

    // Set up eBPF logger
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Load and attach the raw tracepoint for exec (gives CO-RE access to linux_binprm)
    let program_exec: &mut RawTracePoint = ebpf.program_mut("handle_exec").unwrap().try_into()?;
    program_exec.load()?;
    program_exec.attach("sched_process_exec")?;

    let program_fork: &mut TracePoint = ebpf.program_mut("handle_fork").unwrap().try_into()?;
    program_fork.load()?;
    program_fork.attach("sched", "sched_process_fork")?;

    let program_exit: &mut TracePoint = ebpf.program_mut("handle_exit").unwrap().try_into()?;
    program_exit.load()?;
    program_exit.attach("sched", "sched_process_exit")?;

    // Attach sys_enter_execve to capture argv (user-space memory, stashed for handle_exec)
    let program_sys_exec: &mut TracePoint = ebpf
        .program_mut("handle_sys_enter_execve")
        .unwrap()
        .try_into()?;
    program_sys_exec.load()?;
    program_sys_exec.attach("syscalls", "sys_enter_execve")?;

    // Set up the event ring buffer reader
    let ring_buf = ebpf.take_map("EVENTS").unwrap();
    let ring_buf = RingBuf::try_from(ring_buf)?;
    let mut async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    // Set up the output writer
    let mut writer: BufWriter<Box<dyn Write>> = match &args.output {
        Some(path) => BufWriter::new(Box::new(File::create(path)?)),
        None => BufWriter::new(Box::new(stdout().lock())),
    };

    // Set up system metrics polling
    let mut metrics_state = metrics::MetricsState::default();
    let metrics_enabled = args.metric_frequency > 0;
    let mut metrics_interval = time::interval(Duration::from_secs(if metrics_enabled {
        args.metric_frequency
    } else {
        3600
    }));

    metrics_interval.tick().await;
    if metrics_enabled {
        let _ = metrics::collect(&mut metrics_state, 0);
        info!(
            "System metrics enabled (every {}s). Use --metric-frequency 0 to disable.",
            args.metric_frequency
        );
    }

    info!("Profiler running. Press Ctrl-C to stop.");

    loop {
        tokio::select! {
            ready = async_fd.readable_mut() => {
                let mut guard = ready?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() == size_of::<ProcessEvent>() {
                        let event = unsafe { &*(item.as_ptr() as *const ProcessEvent) };
                        let record = ProcessEventRecord::from(event);
                        if let Ok(json) = serde_json::to_string(&record) {
                            let _ = writeln!(writer, "{json}");
                        }
                    }
                }
                let _ = writer.flush();
                guard.clear_ready();
            }
            _ = metrics_interval.tick(), if metrics_enabled => {
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

    // Final drain — catch any events that arrived after the last poll
    let mut ring_buf = async_fd.into_inner();
    while let Some(item) = ring_buf.next() {
        if item.len() == size_of::<ProcessEvent>() {
            let event = unsafe { &*(item.as_ptr() as *const ProcessEvent) };
            let record = ProcessEventRecord::from(event);
            if let Ok(json) = serde_json::to_string(&record) {
                let _ = writeln!(writer, "{json}");
            }
        }
    }
    writer.flush()?;

    Ok(())
}
