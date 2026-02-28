use aya::{
    Ebpf,
    maps::{Array, HashMap},
    programs::{RawTracePoint, TracePoint},
};
use tracing::{info, warn};

use crate::utils::{name_to_bytes, scan_ignored_pids};

// "sh" excluded: `sh -c "real command"` would hide the child via fork inheritance
const DEFAULT_IGNORE: &[&str] = &[
    "awk", "basename", "cat", "cut", "date", "echo", "envsubst", "expr", "dirname", "grep", "head",
    "id", "ip", "ln", "ls", "lsblk", "mkdir", "mktemp", "mv", "ps", "readlink", "rm", "sed", "seq",
    "uname", "whoami",
];

pub fn attach_programs(ebpf: &mut Ebpf, args: &crate::Args) -> anyhow::Result<()> {
    setup_config(ebpf, args)?;
    setup_ignore_lists(ebpf, args)?;
    setup_ebpf_logger(ebpf)?;
    attach_process_tracing(ebpf)?;
    if !args.no_oom {
        attach_oom(ebpf)?;
    }
    if !args.no_block_io {
        attach_block_io(ebpf)?;
    }
    if !args.no_sched_latency {
        attach_sched_latency(ebpf)?;
    }

    Ok(())
}

fn setup_config(ebpf: &mut Ebpf, args: &crate::Args) -> anyhow::Result<()> {
    use profiler_common::{CONFIG_BLOCK_IO_THRESHOLD_NS, CONFIG_SCHED_THRESHOLD_NS};

    let mut config: Array<_, u64> = Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;

    let sched_threshold_ns = args.sched_latency_threshold_ms * 1_000_000;
    config.set(CONFIG_SCHED_THRESHOLD_NS, sched_threshold_ns, 0)?;
    info!(
        "Config: sched latency threshold = {}ms",
        args.sched_latency_threshold_ms
    );

    let block_io_threshold_ns = args.block_io_threshold_ms * 1_000_000;
    config.set(CONFIG_BLOCK_IO_THRESHOLD_NS, block_io_threshold_ns, 0)?;
    info!(
        "Config: block I/O latency threshold = {}ms",
        args.block_io_threshold_ms
    );

    Ok(())
}

fn setup_ignore_lists(ebpf: &mut Ebpf, args: &crate::Args) -> anyhow::Result<()> {
    let mut ignored_names: HashMap<_, [u8; 16], u8> =
        HashMap::try_from(ebpf.map_mut("IGNORED_NAMES").unwrap())?;

    if !args.no_default_ignore {
        for cmd in DEFAULT_IGNORE {
            ignored_names.insert(name_to_bytes(cmd), 1, 0)?;
        }
        info!(
            "Default ignore list active ({} commands). Use --no-default-ignore to disable.",
            DEFAULT_IGNORE.len()
        );
    }

    for cmd in &args.ignore {
        ignored_names.insert(name_to_bytes(cmd.trim()), 1, 0)?;
        info!("Ignoring by name: {}", cmd.trim());
    }

    let patterns: Vec<&str> = args.ignore_pattern.iter().map(|s| s.as_str()).collect();

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

    Ok(())
}

fn setup_ebpf_logger(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    match aya_log::EbpfLogger::init(ebpf) {
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
    Ok(())
}

fn attach_process_tracing(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program_exec: &mut RawTracePoint = ebpf.program_mut("handle_exec").unwrap().try_into()?;
    program_exec.load()?;
    program_exec.attach("sched_process_exec")?;

    let program_fork: &mut TracePoint = ebpf.program_mut("handle_fork").unwrap().try_into()?;
    program_fork.load()?;
    program_fork.attach("sched", "sched_process_fork")?;

    let program_exit: &mut TracePoint = ebpf.program_mut("handle_exit").unwrap().try_into()?;
    program_exit.load()?;
    program_exit.attach("sched", "sched_process_exit")?;

    let program_sys_exec: &mut TracePoint = ebpf
        .program_mut("handle_sys_enter_execve")
        .unwrap()
        .try_into()?;
    program_sys_exec.load()?;
    program_sys_exec.attach("syscalls", "sys_enter_execve")?;

    info!("Process tracing attached (exec/fork/exit)");
    Ok(())
}

fn attach_oom(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("handle_oom_kill").unwrap().try_into()?;
    program.load()?;
    program.attach("oom", "mark_victim")?;
    info!("OOM kill detection attached");
    Ok(())
}

fn attach_block_io(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let issue: &mut TracePoint = ebpf
        .program_mut("handle_block_rq_issue")
        .unwrap()
        .try_into()?;
    issue.load()?;
    issue.attach("block", "block_rq_issue")?;

    let complete: &mut TracePoint = ebpf
        .program_mut("handle_block_rq_complete")
        .unwrap()
        .try_into()?;
    complete.load()?;
    complete.attach("block", "block_rq_complete")?;

    info!("Block I/O latency tracking attached");
    Ok(())
}

fn attach_sched_latency(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let wakeup: &mut TracePoint = ebpf
        .program_mut("handle_sched_wakeup")
        .unwrap()
        .try_into()?;
    wakeup.load()?;
    wakeup.attach("sched", "sched_wakeup")?;

    let wakeup_new: &mut TracePoint = ebpf
        .program_mut("handle_sched_wakeup_new")
        .unwrap()
        .try_into()?;
    wakeup_new.load()?;
    wakeup_new.attach("sched", "sched_wakeup_new")?;

    let switch: &mut TracePoint = ebpf
        .program_mut("handle_sched_switch")
        .unwrap()
        .try_into()?;
    switch.load()?;
    switch.attach("sched", "sched_switch")?;

    info!("Scheduler latency tracking attached");
    Ok(())
}
