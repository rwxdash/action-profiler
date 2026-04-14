# Architecture

## Overview

```
action-profiler/
  src/                     TypeScript GitHub Action (entry + post-job reporting)
  profiler/                Rust workspace
    profiler/                Userspace daemon (loads eBPF, collects events + metrics)
    profiler-ebpf/           C eBPF programs (compiled with clang, loaded via aya)
    profiler-common/         Shared Rust types (events, constants)
    profiler-viewer/         WASM viewer (processes JSONL into structured data for JS)
  libbpf/                  Git submodule (bpf_helpers.h, bpf_core_read.h)
  action.yml               GitHub Action definition
```

## eBPF: C Programs + Rust Userspace

eBPF programs are written in C (not Rust) because aya-rs does not support CO-RE
relocations - the Rust compiler cannot emit BTF relocation records that the
kernel needs to patch struct field offsets at load time.

The hybrid approach:
- **C BPF programs** (`profiler-ebpf/*.bpf.h`) - compiled by clang during
  `build.rs`, emits proper CO-RE relocations
- **Rust userspace** (`profiler/src/`) - loads the compiled `.bpf.o` via aya's
  `EbpfLoader`, which resolves BTF relocations at load time
- **libbpf** headers - git submodule providing `bpf_helpers.h` and
  `bpf_core_read.h`

All BPF handlers live in `.bpf.h` files included by `profiler.bpf.c` so they
share the same maps and types. Compiled with:
```
clang -target bpf -O2 -g -c profiler.bpf.c -o profiler.bpf.o
```

## Tracepoints

| Program | Type | Tracepoint | Purpose |
|---------|------|-----------|---------|
| `handle_sys_enter_execve` | `tp/syscalls` | `sys_enter_execve` | Stash filename + argv before exec |
| `handle_sched_process_exec` | `raw_tp` | `sched_process_exec` | Emit EXEC event with CO-RE `linux_binprm` access |
| `handle_sched_process_fork` | `tp/sched` | `sched_process_fork` | Propagate ignored PIDs to children |
| `handle_sched_process_exit` | `tp/sched` | `sched_process_exit` | Emit EXIT event with duration + exit code |
| `handle_sched_wakeup[_new]` | `tp/sched` | `sched_wakeup[_new]` | Record wakeup timestamp |
| `handle_sched_switch` | `tp/sched` | `sched_switch` | Compute scheduler latency |
| `handle_block_rq_issue` | `tp/block` | `block_rq_issue` | Record I/O request start |
| `handle_block_rq_complete` | `tp/block` | `block_rq_complete` | Compute block I/O latency |
| `handle_oom_kill` | `tp/oom` | `mark_victim` | Capture OOM kill events |

### BPF program types

- `SEC("tp/...")` - regular tracepoints. Context receives the full tracepoint
  record including the 8-byte common header. Offsets are baked in but stable
  (kernel tracepoint ABI).
- `SEC("raw_tracepoint/...")` - raw tracepoints. Context is
  `bpf_raw_tracepoint_args` with raw kernel function parameters as `args[0]`,
  `args[1]`, etc. Used for `sched_process_exec` to access `linux_binprm`.
- CO-RE (`BPF_CORE_READ`) is used for kernel struct access (`task_struct`,
  `linux_binprm`). Offsets differ between kernels but are patched at load time.

### exit_code encoding

`BPF_CORE_READ(task, exit_code)` returns the raw kernel exit code. Lower 8 bits
= signal number, upper bits = exit status. Stored raw in BPF, decoded in Rust:

```rust
let status = raw >> 8;    // WEXITSTATUS
let signal = raw & 0x7F;  // WTERMSIG
```

## WASM Viewer

The `profiler-viewer` crate compiles to WASM and runs client-side in the HTML
report. It processes raw JSONL events into structured JSON that the JavaScript
renderer consumes:

- Process tree with parent-child relationships and span computation
- Windowed aggregation (block I/O + scheduler latency per-second summaries)
- Anomaly detection (OOM kills, high scheduler latency, failed processes)
- Per-process eBPF correlation (sched latency, block I/O stats)

The HTML report uses ECharts for interactive charts (Gantt, scatter, time-series).
ECharts is vendored from npm (not CDN) to avoid supply chain risk.

## System Metrics

Collected by polling `/proc` at configurable intervals:

- CPU: user load %, system load %
- Memory: total, active, available (MB)
- Network I/O: read/write (MB cumulative)
- Disk I/O: read/write (MB cumulative)

## TypeScript Action Layer

- **`src/main.ts`** - starts the profiler binary as a detached background
  process, records PID and output path in action state
- **`src/post.ts`** - stops the profiler (SIGINT), reads JSONL output, builds a
  self-contained HTML artifact (inlines ECharts + WASM + JSONL data), uploads via
  `actions/upload-artifact`

## Build Chain

1. `build.rs` invokes clang to compile `profiler-ebpf/profiler.bpf.c` into
   `profiler.bpf.o`
2. The compiled BPF object is embedded into the Rust binary via `include_bytes!`
3. At runtime, aya's `EbpfLoader` resolves CO-RE relocations against the host
   kernel's BTF (`/sys/kernel/btf/vmlinux`)
4. `wasm-pack` compiles `profiler-viewer` to WASM
5. `scripts/build.sh` copies viewer assets (ECharts, WASM, HTML) to `bin/out/`
6. Rollup bundles the TypeScript action into `dist/`

## Output Format

Events are written as JSON Lines (one JSON object per line):

```json
{"time_ns":123456789,"event_type":"exec","pid":4567,"tgid":4567,"ppid":1234,"name":"make","filename":"/usr/bin/make","args":["make","-j8"]}
```

| Field | Description |
|-------|-------------|
| `time_ns` | Kernel timestamp (monotonic, nanoseconds) |
| `event_type` | `exec`, `exit`, `metrics`, `block_io`, `sched_latency`, `oom_kill` |
| `pid` / `tgid` / `ppid` | Process, thread group, and parent IDs |
| `uid` / `gid` | User / group ID |
| `name` | Command name (max 16 chars) |
| `filename` | Executable path (exec events) |
| `args` | Command arguments (exec events) |
| `exit_code` | Process exit code (exit events) |
| `signal` / `signal_name` | Signal number and name if killed (exit events) |
| `duration_ns` | Process duration in nanoseconds (exit events) |

## Process Filtering

Two mechanisms, combinable:

- **`PROFILER_IGNORE`** - comma-separated command names. Ignored processes and
  all children (via fork cascade) are suppressed.
- **`PROFILER_IGNORE_PATTERN`** - scans `/proc/*/cmdline` at startup for
  matching substrings, seeds the eBPF ignore list with their PIDs.
