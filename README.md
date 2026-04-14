# Action Profiler

A GitHub Action that profiles CI workflows using eBPF. Captures process
execution, system metrics, scheduler latency, block I/O, and OOM events.

Generates interactive HTML reports as downloadable artifacts.

## Quick Start

```yaml
- uses: rwxdash/action-profiler@v1

# ... your build steps ...

# Post phase runs automatically: stops profiler, uploads report artifact
```

With options:

```yaml
- uses: rwxdash/action-profiler@v1
  with:
    metric_frequency: "10"
    ignore_processes: "node,sh"
    ignore_patterns: "vscode-server"
    enable_oom: "false"
    sched_latency_threshold_ms: "10"
```

The action runs transparently. It starts an eBPF profiler at the beginning of
your job and generates a report when the job finishes.

No changes to your existing workflow steps needed.

## What It Captures

| Data | Source | Description |
|------|--------|-------------|
| Process execution | `exec`/`fork`/`exit` tracepoints | Full process tree with durations, exit codes, args |
| System metrics | `/proc` polling | CPU, memory, disk, network at configurable intervals |
| Scheduler latency | `sched_wakeup`/`sched_switch` | Time between wakeup and actually running on CPU |
| Block I/O latency | `block_rq_issue`/`complete` | Disk read/write latency per request |
| OOM kills | `oom:mark_victim` | Which process was killed and memory state |

## Report

The action uploads a self-contained HTML report as a GitHub Actions artifact.
Open it in any browser, no server needed. It includes:

- Process Gantt chart (execution timeline with parent-child nesting)
- Process tree with critical path highlighting
- System metrics charts (CPU, memory, disk, network)
- Block I/O and scheduler latency scatter plots
- OOM kill alerts with memory breakdown
- Anomaly detection flags

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `metric_frequency` | `5` | System metrics polling interval in seconds (0 to disable) |
| `proc_trace_sys_enable` | `false` | Include system processes (awk, cat, grep, etc.) |
| `ignore_processes` | | Comma-separated command names to ignore (e.g. `node,sh`) |
| `ignore_patterns` | | Comma-separated cmdline substrings to ignore (e.g. `vscode-server`) |
| `enable_oom` | `true` | Enable OOM kill detection |
| `enable_block_io` | `true` | Enable block I/O latency tracing |
| `enable_sched_latency` | `true` | Enable scheduler latency tracing |
| `sched_latency_threshold_ms` | `5` | Minimum scheduler latency in ms to report |

## Outputs

| Output | Description |
|--------|-------------|
| `artifact-id` | ID of the uploaded report artifact |
| `artifact-url` | URL to download the report artifact |

## Requirements

- **Linux runners only** - eBPF requires the Linux kernel. The action skips
  gracefully on other platforms.
- **Ubuntu 22.04+** - needs BTF support (`/sys/kernel/btf/vmlinux`). GitHub's
  `ubuntu-latest` and `ubuntu-22.04`/`ubuntu-24.04` runners all work.

## How It Works

The profiler attaches to kernel tracepoints via eBPF at the start of your job.
It captures every process, subprocess, and short-lived command with zero code
changes and minimal overhead.

The eBPF programs are written in C with CO-RE (Compile Once - Run Everywhere),
so a single binary works across kernel versions. The userspace daemon is Rust,
and the report viewer is a WASM module that processes events client-side.

For technical details, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

[MIT](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.
