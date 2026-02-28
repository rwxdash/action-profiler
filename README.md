# Action Profiler

A GitHub Action profiler using Rust + eBPF (via `aya-rs`). Monitors CI workflow resources and process execution using kernel-level tracing.

## Build

Requires Linux with BTF support, Rust nightly, and `bpf-linker`.

```bash
cd profiler && cargo build --release
```

## Usage

```bash
# Basic — output events to stdout
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
{"time_ns":123456789,"event_type":"exec","exit_code":0,"uid":1000,"gid":1000,"pid":4567,"tgid":4567,"ppid":1234,"name":"make","filename":"","args":[]}
```

| Field | Description |
|-------|-------------|
| `time_ns` | Kernel timestamp (monotonic, nanoseconds) |
| `event_type` | `"exec"` or `"exit"` |
| `pid` | Process ID |
| `tgid` | Thread group ID |
| `ppid` | Parent process ID |
| `uid` / `gid` | User / group ID |
| `name` | Command name (max 16 chars) |
| `filename` | Executable path (when available) |
| `args` | Command arguments (when available) |
| `exit_code` | Process exit code (for exit events) |


## Verification

### OOM Kill
```bash
# Run profiler
sudo ./target/release/profiler --output tests/profiler-events.jsonl --enable-oom

# In another terminal, trigger OOM:
python3 -c "x = [bytearray(10**6) for _ in range(10000)]"

# Check output:
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
