#!/usr/bin/env bash
# Integration test - exercises all event types.
# Usage: sudo ./tests/run-profiler-test.sh
set -euo pipefail

# Preserve user's PATH under sudo (cargo, rustup, etc.)
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(eval echo "~$SUDO_USER")
    export PATH="$USER_HOME/.cargo/bin:$USER_HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin:/usr/local/bin:$PATH"
    export RUSTUP_HOME="$USER_HOME/.rustup"
    export CARGO_HOME="$USER_HOME/.cargo"
fi
export RUSTUP_TOOLCHAIN=nightly

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MICI_DIR="/home/oz/workspace/projects/mici"
OUTPUT="$SCRIPT_DIR/profiler-events.jsonl"
PROFILER_PID=""
CHILD_PIDS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[test]${NC} $*"; }
pass() { echo -e "${GREEN}[pass]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
fail() { echo -e "${RED}[fail]${NC} $*"; }

cleanup() {
    log "Cleaning up..."

    # Kill child workloads first
    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    # Gracefully stop the profiler (SIGINT = Ctrl-C)
    if [[ -n "$PROFILER_PID" ]] && kill -0 "$PROFILER_PID" 2>/dev/null; then
        log "Sending SIGINT to profiler (pid=$PROFILER_PID)..."
        kill -INT "$PROFILER_PID" 2>/dev/null || true
        # Wait up to 5 seconds for graceful shutdown
        for _ in $(seq 1 50); do
            kill -0 "$PROFILER_PID" 2>/dev/null || break
            sleep 0.1
        done
        # Force kill if still alive
        if kill -0 "$PROFILER_PID" 2>/dev/null; then
            warn "Profiler didn't exit gracefully, sending SIGKILL"
            kill -9 "$PROFILER_PID" 2>/dev/null || true
        fi
        wait "$PROFILER_PID" 2>/dev/null || true
    fi

    # Clean up temp files
    rm -f /tmp/profiler-test-blockio-* 2>/dev/null || true

    log "Cleanup complete."
}

trap cleanup EXIT

# ─── Preflight ───────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    fail "Must run as root (eBPF requires CAP_BPF). Try: sudo $0"
    exit 1
fi

# ─── Build ───────────────────────────────────────────────────────────────────

log "Building profiler..."
pushd "$PROFILER_DIR" > /dev/null
cargo build --release 2>&1 | tail -3
popd > /dev/null

# ─── Start profiler ─────────────────────────────────────────────────────────

log "Starting profiler → $OUTPUT"
rm -f "$OUTPUT"

pushd "$PROFILER_DIR" > /dev/null
PROFILER_IGNORE_PATTERN="debian-sa1,vscode-server,cpuUsage.sh" \
    cargo run --release -- \
    --output "$OUTPUT" \
    --block-io-threshold-ms 1 \
    --sched-latency-threshold-ms 5 &
PROFILER_PID=$!
popd > /dev/null

# Give the profiler time to load eBPF programs and attach
sleep 3
if ! kill -0 "$PROFILER_PID" 2>/dev/null; then
    fail "Profiler failed to start"
    exit 1
fi
pass "Profiler started (pid=$PROFILER_PID)"

# ─── Test 1: OOM Kill ───────────────────────────────────────────────────────
#
# Trigger an OOM kill inside a memory-limited cgroup so it doesn't kill
# anything important. We use systemd-run to create a transient scope with
# a 32MB memory limit, then allocate way more than that.

log "Test 1: Triggering OOM kill (32MB cgroup limit)..."
(
    # Clean up stale unit from previous runs
    systemctl reset-failed profiler-oom-test.scope 2>/dev/null || true
    systemctl stop profiler-oom-test.scope 2>/dev/null || true

    systemd-run --scope --unit=profiler-oom-test \
        -p MemoryMax=32M -p MemorySwapMax=0 \
        -- python3 -c "
import sys
blocks = []
try:
    while True:
        blocks.append(b'X' * (1024 * 1024))  # 1MB chunks
except (MemoryError, Exception):
    sys.exit(137)
" 2>&1 || true
    log "OOM test process exited (expected)"
) &
CHILD_PIDS+=($!)
# Don't wait - let it run async

# ─── Test 2: Block I/O ──────────────────────────────────────────────────────
#
# Generate synchronous disk I/O with oflag=direct to bypass page cache.
# This ensures block_rq_issue/block_rq_complete tracepoints fire.

log "Test 2: Generating block I/O (direct writes + sync reads)..."
(
    TESTFILE="/tmp/profiler-test-blockio-$$"

    # Direct write - bypasses page cache, hits disk
    dd if=/dev/zero of="$TESTFILE" bs=1M count=64 oflag=direct conv=fsync 2>/dev/null

    # Drop caches to force reads from disk
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true

    # Direct read
    dd if="$TESTFILE" of=/dev/null bs=1M iflag=direct 2>/dev/null

    # fsync to flush any remaining writes
    sync

    rm -f "$TESTFILE"
    log "Block I/O test complete"
) &
CHILD_PIDS+=($!)

# ─── Test 3: Scheduler Latency ──────────────────────────────────────────────
#
# Spawn many CPU-bound processes to create scheduler contention.
# When more processes compete than CPUs available, run-queue latency spikes.

log "Test 3: Creating scheduler pressure (CPU contention)..."
(
    NCPUS=$(nproc)
    # Spawn 4x the number of CPUs to guarantee contention
    NPROCS=$((NCPUS * 4))

    STRESS_PIDS=()
    for _ in $(seq 1 "$NPROCS"); do
        # Each process burns CPU for 5 seconds
        timeout 5 sh -c 'while true; do :; done' &
        STRESS_PIDS+=($!)
    done

    # Wait for all stress processes
    for pid in "${STRESS_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    log "Scheduler pressure test complete"
) &
CHILD_PIDS+=($!)

# ─── Test 4: Real workload (cargo build) ────────────────────────────────────
#
# Run a cargo build one level up to generate realistic process tree data
# (compiler invocations, linker, etc.)

log "Test 4: Running cargo check on profiler-common..."
(
    pushd "$PROFILER_DIR" > /dev/null
    cargo check -p profiler-common 2>&1 | tail -5
    popd > /dev/null
    log "Cargo check test complete"
) &
CHILD_PIDS+=($!)

log "Test 5: Running cargo build/test in mici for a basic test suite..."
(
    pushd "$MICI_DIR" > /dev/null

    cargo clean
    cargo build
    cargo test
    popd > /dev/null
    log "Cargo build test complete"
) &
CHILD_PIDS+=($!)

# ─── Wait for all workloads ─────────────────────────────────────────────────

log "Waiting for all workloads to finish..."
for pid in "${CHILD_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# Give profiler a moment to drain ring buffers
sleep 2

pass "All workloads finished"

# ─── Stop profiler and print summary ────────────────────────────────────────

log "Stopping profiler..."
kill -INT "$PROFILER_PID" 2>/dev/null || true
wait "$PROFILER_PID" 2>/dev/null || true
PROFILER_PID=""  # prevent double-kill in cleanup

echo ""
log "═══════════════════════════════════════════════════════════"
log "  Results: $OUTPUT"
log "═══════════════════════════════════════════════════════════"
echo ""

if [[ ! -f "$OUTPUT" ]]; then
    fail "Output file not found!"
    exit 1
fi

TOTAL=$(wc -l < "$OUTPUT")
EXEC=$(grep -c '"exec"' "$OUTPUT" || true)
EXIT=$(grep -c '"exit"' "$OUTPUT" || true)
OOM=$(grep -c '"oom_kill"' "$OUTPUT" || true)
BLOCKIO=$(grep -c '"block_io"' "$OUTPUT" || true)
SCHED=$(grep -c '"sched_latency"' "$OUTPUT" || true)
METRICS=$(grep -c '"metrics"' "$OUTPUT" || true)

printf "  %-25s %s\n" "Total lines:" "$TOTAL"
printf "  %-25s %s\n" "exec:" "$EXEC"
printf "  %-25s %s\n" "exit:" "$EXIT"
printf "  %-25s %s\n" "oom_kill:" "$OOM"
printf "  %-25s %s\n" "block_io:" "$BLOCKIO"
printf "  %-25s %s\n" "sched_latency:" "$SCHED"
printf "  %-25s %s\n" "metrics:" "$METRICS"
echo ""

# Validate we got at least some events of each type
PASS=true

check() {
    local label=$1 count=$2
    if [[ "$count" -gt 0 ]]; then
        pass "$label: $count events"
    else
        fail "$label: 0 events - expected at least 1"
        PASS=false
    fi
}

check "exec"                  "$EXEC"
check "exit"                  "$EXIT"
check "oom_kill"              "$OOM"
check "block_io"              "$BLOCKIO"
check "sched_latency"         "$SCHED"
check "metrics"               "$METRICS"

echo ""
if $PASS; then
    pass "All event types captured successfully!"
else
    fail "Some event types were missing - check the output above"
    exit 1
fi
