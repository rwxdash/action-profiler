#!/usr/bin/env bash
# Dump kernel tracepoint formats and task_struct info for eBPF debugging.
# Run on the target machine (GitHub Actions runner or local Linux).
set -euo pipefail

OUT="${1:-kernel-debug.txt}"

{
echo "===== Date & Hostname ====="
date
hostname

echo ""
echo "===== Kernel Version ====="
uname -a

echo ""
echo "===== OS Release ====="
cat /etc/os-release 2>/dev/null || echo "(not available)"

echo ""
echo "===== BTF Available? ====="
if [ -f /sys/kernel/btf/vmlinux ]; then
    ls -lh /sys/kernel/btf/vmlinux
    echo "BTF is available"
else
    echo "NO /sys/kernel/btf/vmlinux — CO-RE will NOT work"
fi

echo ""
echo "===== Tracefs Mount ====="
mount | grep tracefs || echo "(tracefs not mounted, trying to mount...)"
sudo mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true

TRACEFS=""
for p in /sys/kernel/tracing /sys/kernel/debug/tracing; do
    if [ -d "$p/events" ]; then
        TRACEFS="$p"
        break
    fi
done

if [ -z "$TRACEFS" ]; then
    echo "ERROR: Cannot find tracefs events directory"
else
    echo "Tracefs at: $TRACEFS"

    echo ""
    echo "===== sched_process_exec format ====="
    sudo cat "$TRACEFS/events/sched/sched_process_exec/format" 2>/dev/null || echo "(not available)"

    echo ""
    echo "===== sched_process_exit format ====="
    sudo cat "$TRACEFS/events/sched/sched_process_exit/format" 2>/dev/null || echo "(not available)"

    echo ""
    echo "===== sched_process_fork format ====="
    sudo cat "$TRACEFS/events/sched/sched_process_fork/format" 2>/dev/null || echo "(not available)"

    echo ""
    echo "===== syscalls/sys_enter_execve format ====="
    sudo cat "$TRACEFS/events/syscalls/sys_enter_execve/format" 2>/dev/null || echo "(not available)"

    echo ""
    echo "===== oom/mark_victim format ====="
    sudo cat "$TRACEFS/events/oom/mark_victim/format" 2>/dev/null || echo "(not available)"

    echo ""
    echo "===== block/block_rq_issue format ====="
    sudo cat "$TRACEFS/events/block/block_rq_issue/format" 2>/dev/null || echo "(not available)"

    echo ""
    echo "===== block/block_rq_complete format ====="
    sudo cat "$TRACEFS/events/block/block_rq_complete/format" 2>/dev/null || echo "(not available)"
fi

echo ""
echo "===== task_struct BTF dump (pahole) ====="
if command -v pahole &>/dev/null; then
    # Dump task_struct with field offsets — focus on exit_code, real_parent, tgid, pid
    pahole -C task_struct /sys/kernel/btf/vmlinux 2>/dev/null | head -200
    echo "..."
    echo ""
    echo "-- Specific fields --"
    pahole -C task_struct /sys/kernel/btf/vmlinux 2>/dev/null | grep -E '(exit_code|real_parent|tgid|pid|__state)' || true
else
    echo "(pahole not installed — install dwarves package)"
    echo "Trying bpftool btf dump instead..."
    if command -v bpftool &>/dev/null; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -A2 -B2 'exit_code' | head -20
        echo "..."
        bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -A2 -B2 'real_parent' | head -20
    else
        echo "(bpftool not installed either)"
        echo "Trying python3 BTF parse..."
        python3 -c "
import struct, os

# Read raw BTF from vmlinux
with open('/sys/kernel/btf/vmlinux', 'rb') as f:
    data = f.read()
print(f'BTF size: {len(data)} bytes')
# Magic check
magic = struct.unpack('<H', data[0:2])[0]
print(f'BTF magic: 0x{magic:04x} (expected 0xEB9F)')
" 2>/dev/null || echo "(python3 BTF parse failed)"
    fi
fi

echo ""
echo "===== /proc/version ====="
cat /proc/version

echo ""
echo "===== Available BPF helpers ====="
if command -v bpftool &>/dev/null; then
    sudo bpftool feature probe kernel 2>/dev/null | grep -E '(program_type|map_type|helper)' | head -30 || true
    echo "..."
else
    echo "(bpftool not installed)"
fi

echo ""
echo "===== CAP_BPF check ====="
if capsh --print 2>/dev/null | grep -q cap_bpf; then
    echo "CAP_BPF available"
else
    echo "CAP_BPF not in current caps (sudo required for eBPF)"
fi

echo ""
echo "===== Done ====="
} | tee "$OUT"

echo ""
echo "Output saved to: $OUT"
