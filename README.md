# Action Profiler

A GitHub Action that profiles CI workflows using eBPF kernel-level tracing. Captures process execution, system metrics, scheduler latency, block I/O, and OOM events — then generates interactive HTML reports.

## Architecture

```
action-profiler/
├── src/                   # TypeScript GitHub Action (entry + post-job reporting)
├── profiler/
│   ├── profiler/          # Rust userspace daemon (loads eBPF, collects events + metrics)
│   ├── profiler-ebpf/     # C eBPF programs (compiled with clang, loaded via aya)
│   ├── profiler-common/   # Shared Rust types (events, constants)
│   └── profiler-viewer/   # WASM viewer (processes JSONL → interactive HTML)
├── action.yml
└── package.json
```

### eBPF: C programs + Rust userspace

eBPF programs are written in C and use CO-RE (Compile Once - Run Everywhere) via `BPF_CORE_READ`. This means a single binary works across kernel versions — no per-kernel builds needed.

- **C BPF programs** (`profiler-ebpf/`) — compiled by clang during `build.rs`
- **Rust userspace** (`profiler/`) — loads the compiled `.bpf.o` via aya's `EbpfLoader`, which resolves BTF relocations at load time
- **libbpf** — git submodule providing `bpf_helpers.h` and `bpf_core_read.h`

### Tracepoints

| Program | Tracepoint | Purpose |
|---------|-----------|---------|
| `handle_sys_enter_execve` | `syscalls/sys_enter_execve` | Stash filename + argv before exec |
| `handle_sched_process_exec` | `raw_tp/sched_process_exec` | Emit EXEC event with CO-RE access to `linux_binprm` |
| `handle_sched_process_fork` | `sched/sched_process_fork` | Propagate ignored PIDs to children |
| `handle_sched_process_exit` | `sched/sched_process_exit` | Emit EXIT event with duration + exit code |
| `handle_sched_wakeup[_new]` | `sched/sched_wakeup[_new]` | Record wakeup timestamp |
| `handle_sched_switch` | `sched/sched_switch` | Compute scheduler latency |
| `handle_block_rq_issue` | `block/block_rq_issue` | Record I/O request start |
| `handle_block_rq_complete` | `block/block_rq_complete` | Compute block I/O latency |
| `handle_oom_kill` | `oom/mark_victim` | Capture OOM kill events |

### Viewer

The WASM viewer (`profiler-viewer/`) processes raw JSONL events into:
- Process tree with parent-child relationships and span computation
- Anomaly detection (OOM kills, high scheduler latency)
- Per-process eBPF correlation (sched latency, block I/O stats)
- System metrics timelines

The HTML report uses ECharts for interactive gantt charts, scatter plots, and time-series graphs.

## Build

Requires Linux with BTF support (`/sys/kernel/btf/vmlinux`), clang, and Rust stable.

```bash
cd profiler && cargo build --release
```

The build process:
1. `build.rs` invokes clang to compile `profiler-ebpf/profiler.bpf.c` → `profiler.bpf.o`
2. The compiled BPF object is embedded into the Rust binary via `include_bytes!`
3. At runtime, aya's `EbpfLoader` resolves CO-RE relocations against the host kernel's BTF

## Usage

```bash
# Basic - output events to stdout
sudo ./target/release/profiler

# Write events to a JSONL file
sudo ./target/release/profiler --output /tmp/events.jsonl
```

### Filtering Processes

#### Ignore by command name

`PROFILER_IGNORE` takes a comma-separated list of command names. Ignored processes and all their children (via fork cascade) are suppressed.

```bash
sudo PROFILER_IGNORE="cpuUsage.sh,node" ./target/release/profiler --output /tmp/events.jsonl
```

#### Ignore by cmdline pattern

`PROFILER_IGNORE_PATTERN` scans `/proc/*/cmdline` at startup for processes matching any of the given substrings, then seeds the eBPF ignore list with their PIDs. Children inherit the ignore via fork cascade.

```bash
# Ignore all VSCode server processes and their children
sudo PROFILER_IGNORE_PATTERN="vscode-server,ptyHost" ./target/release/profiler --output /tmp/events.jsonl
```

Both can be combined:

```bash
sudo PROFILER_IGNORE="sh,node" \
     PROFILER_IGNORE_PATTERN="vscode-server" \
     ./target/release/profiler --output /tmp/events.jsonl
```

### Log verbosity

Controlled via `RUST_LOG` (defaults to `info`):

```bash
sudo RUST_LOG=debug ./target/release/profiler
```

## Output Format

Events are written as JSON Lines (one JSON object per line):

```json
{"time_ns":123456789,"event_type":"exec","exit_code":0,"signal":0,"uid":1000,"gid":1000,"pid":4567,"tgid":4567,"ppid":1234,"name":"make","filename":"/usr/bin/make","args":["make","-j8"]}
```

| Field | Description |
|-------|-------------|
| `time_ns` | Kernel timestamp (monotonic, nanoseconds) |
| `event_type` | `"exec"`, `"exit"`, `"metrics"`, `"block_io"`, `"sched_latency"`, `"oom_kill"` |
| `pid` | Process ID |
| `tgid` | Thread group ID |
| `ppid` | Parent process ID |
| `uid` / `gid` | User / group ID |
| `name` | Command name (max 16 chars) |
| `filename` | Executable path |
| `args` | Command arguments |
| `exit_code` | Process exit code (exit events) |
| `signal` | Signal number if killed (exit events) |
| `signal_name` | Signal name, e.g. `SIGKILL` (exit events) |
| `duration_ns` | Process duration in nanoseconds (exit events) |

## Verification

### OOM Kill
```bash
sudo ./target/release/profiler --output tests/profiler-events.jsonl --enable-oom

# In another terminal, trigger OOM:
python3 -c "x = [bytearray(10**6) for _ in range(10000)]"

jq 'select(.event_type == "oom_kill")' tests/profiler-events.jsonl
```

### Block I/O
```bash
sudo ./target/release/profiler --output tests/profiler-events.jsonl --enable-block-io

# Generate I/O:
dd if=/dev/zero of=/tmp/testfile bs=1M count=500 oflag=direct
sync

jq 'select(.event_type == "block_io") | {latency_ms: (.latency_ns / 1e6), op, name}' tests/profiler-events.jsonl
```

### Scheduler Latency
```bash
sudo ./target/release/profiler --output tests/profiler-events.jsonl --enable-sched-latency

# Generate CPU contention:
stress-ng --cpu 8 --timeout 10s

jq 'select(.event_type == "sched_latency") | {latency_ms: (.latency_ns / 1e6), name}' tests/profiler-events.jsonl
```
