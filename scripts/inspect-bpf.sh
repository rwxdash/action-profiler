#!/usr/bin/env bash
# Build the profiler and inspect the compiled BPF object file.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)/profiler"

PROFILE="${1:-debug}"

if [ "$PROFILE" = "release" ]; then
    cargo build --release 2>&1
else
    cargo build 2>&1
fi

BPF_OBJ=$(find "target/$PROFILE/build" -name "profiler.bpf.o" -print -quit 2>/dev/null)

if [ -z "$BPF_OBJ" ]; then
    echo "ERROR: profiler.bpf.o not found in target/$PROFILE/build"
    exit 1
fi

echo "=== BPF Object: $BPF_OBJ ==="
echo

echo "--- Sections (readelf -S) ---"
readelf -S "$BPF_OBJ"
echo

echo "--- Symbols (readelf -s) ---"
readelf -s "$BPF_OBJ"
echo

echo "--- BTF Types (bpftool btf dump) ---"
bpftool btf dump file "$BPF_OBJ"
echo

echo "--- Disassembly (llvm-objdump -S) ---"
llvm-objdump -S "$BPF_OBJ"

echo "--- Sections (maps, programs, BTF) (llvm-objdump -S) ---"
llvm-objdump -h "$BPF_OBJ"
