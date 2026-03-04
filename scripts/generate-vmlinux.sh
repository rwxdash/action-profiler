#!/usr/bin/env bash
# Generate vmlinux.rs bindings from the current kernel's BTF.
# Run this on any Linux machine before building the eBPF program.
#
# Usage:
#   ./scripts/generate-vmlinux.sh          # generates from running kernel
#   ./scripts/generate-vmlinux.sh --check  # just check if vmlinux.rs exists
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$REPO_ROOT/profiler/profiler-ebpf/src/vmlinux.rs"

if [ "${1:-}" = "--check" ]; then
    if [ -f "$TARGET" ]; then
        echo "vmlinux.rs exists ($(wc -l < "$TARGET") lines)"
        exit 0
    else
        echo "vmlinux.rs missing — run: ./scripts/generate-vmlinux.sh"
        exit 1
    fi
fi

if ! command -v bpftool &>/dev/null; then
    echo "bpftool not found. Install with: sudo apt install linux-tools-\$(uname -r)"
    echo "Or download prebuilt from: https://github.com/libbpf/bpftool/releases"
    exit 1
fi

if ! command -v aya-tool &>/dev/null; then
    echo "aya-tool not found. Install with: cargo install --git https://github.com/aya-rs/aya -- aya-tool"
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found."
    echo "Your kernel needs CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

echo "Kernel: $(uname -r)"
echo "Generating vmlinux.rs for: task_struct, linux_binprm"
aya-tool generate task_struct linux_binprm > "$TARGET"
echo "Done: $(wc -l < "$TARGET") lines → $TARGET"
