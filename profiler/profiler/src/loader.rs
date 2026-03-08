use aya::{
    Btf, Ebpf,
    maps::{Array, HashMap},
    programs::{BtfTracePoint, KProbe, RawTracePoint, TracePoint},
};
use tracing::{info, warn};

use crate::utils::{name_to_bytes, scan_ignored_pids};

/// Parse kernel version (major, minor) from uname release string.
fn kernel_version() -> Option<(u32, u32)> {
    let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut utsname) } != 0 {
        return None;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(utsname.release.as_ptr()) }
        .to_str()
        .ok()?;
    let mut parts = release.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

// "sh" excluded: `sh -c "real command"` would hide the child via fork inheritance
const DEFAULT_IGNORE: &[&str] = &[
    "awk", "basename", "cat", "cut", "date", "echo", "envsubst", "expr", "dirname", "grep", "head",
    "id", "ip", "less", "ln", "ls", "lsblk", "more", "mkdir", "mktemp", "mv", "ps", "readlink",
    "rm", "sed", "seq", "tail", "uname", "which", "whoami",
];

pub fn attach_programs(ebpf: &mut Ebpf, args: &crate::Args) -> anyhow::Result<()> {
    setup_config(ebpf, args)?;
    setup_ignore_lists(ebpf, args)?;
    attach_process_tracing(ebpf)?;

    if !args.no_oom {
        attach_oom(ebpf)?;
    }
    if !args.no_block_io {
        attach_block_io(ebpf)?;
    }
    // TODO: Uncomment when sched_switch and tcp handlers are implemented
    // if !args.no_sched_latency {
    //     attach_sched_latency(ebpf)?;
    // }
    // if !args.no_tcp {
    //     attach_tcp(ebpf)?;
    // }

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

fn attach_process_tracing(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    // C BPF function names match the tracepoint names
    let program_sys_exec: &mut TracePoint = ebpf
        .program_mut("handle_sys_enter_execve")
        .unwrap()
        .try_into()?;
    program_sys_exec.load()?;
    program_sys_exec.attach("syscalls", "sys_enter_execve")?;

    let program_exec: &mut RawTracePoint = ebpf
        .program_mut("handle_sched_process_exec")
        .unwrap()
        .try_into()?;
    program_exec.load()?;
    program_exec.attach("sched_process_exec")?;

    let program_fork: &mut RawTracePoint = ebpf
        .program_mut("handle_sched_process_fork")
        .unwrap()
        .try_into()?;
    program_fork.load()?;
    program_fork.attach("sched_process_fork")?;

    let program_exit: &mut TracePoint = ebpf
        .program_mut("handle_sched_process_exit")
        .unwrap()
        .try_into()?;
    program_exit.load()?;
    program_exit.attach("sched", "sched_process_exit")?;

    info!("Process tracing attached (exec/fork/exit)");
    Ok(())
}

fn attach_oom(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf.program_mut("handle_oom_kill").unwrap().try_into()?;
    program.load()?;
    program.attach("mark_oom_victim", 0)?;
    info!("OOM kill detection attached (kprobe)");
    Ok(())
}

fn attach_block_io(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    // tp_btf/block_rq_* uses rq->q->disk which requires kernel >= 5.11
    if let Some((major, minor)) = kernel_version()
        && (major, minor) < (5, 11)
    {
        warn!(
            "Block I/O tracking requires kernel >= 5.11 (found {}.{}), skipping",
            major, minor
        );
        return Ok(());
    }

    let btf = Btf::from_sys_fs()?;

    let issue: &mut BtfTracePoint = ebpf
        .program_mut("handle_block_rq_issue")
        .unwrap()
        .try_into()?;
    issue.load("block_rq_issue", &btf)?;
    issue.attach()?;

    let complete: &mut BtfTracePoint = ebpf
        .program_mut("handle_block_rq_complete")
        .unwrap()
        .try_into()?;
    complete.load("block_rq_complete", &btf)?;
    complete.attach()?;

    info!("Block I/O latency tracking attached (tp_btf)");
    Ok(())
}

// fn attach_sched_latency(ebpf: &mut Ebpf) -> anyhow::Result<()> {
//     let btf = Btf::from_sys_fs()?;
//
//     let wakeup: &mut BtfTracePoint = ebpf
//         .program_mut("handle_sched_wakeup")
//         .unwrap()
//         .try_into()?;
//     wakeup.load("sched_wakeup", &btf)?;
//     wakeup.attach()?;
//
//     let wakeup_new: &mut BtfTracePoint = ebpf
//         .program_mut("handle_sched_wakeup_new")
//         .unwrap()
//         .try_into()?;
//     wakeup_new.load("sched_wakeup_new", &btf)?;
//     wakeup_new.attach()?;
//
//     let switch: &mut BtfTracePoint = ebpf
//         .program_mut("handle_sched_switch")
//         .unwrap()
//         .try_into()?;
//     switch.load("sched_switch", &btf)?;
//     switch.attach()?;
//
//     info!("Scheduler latency tracking attached (tp_btf)");
//     Ok(())
// }

// fn attach_tcp(ebpf: &mut Ebpf) -> anyhow::Result<()> {
//     let program: &mut TracePoint = ebpf
//         .program_mut("handle_inet_sock_set_state")
//         .unwrap()
//         .try_into()?;
//     program.load()?;
//     program.attach("sock", "inet_sock_set_state")?;
//     info!("TCP connection tracking attached");
//     Ok(())
// }
