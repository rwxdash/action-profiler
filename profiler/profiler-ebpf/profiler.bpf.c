// SPDX-License-Identifier: Dual MIT/GPL
//
// Main BPF compilation unit - includes all handler files.
//
// All handlers are in .bpf.h files so they share the same maps and types
// defined in profiler.bpf.h. This is the standard pattern for BPF programs
// that need shared state (maps) across multiple tracepoint handlers.
//
// Compiled with: clang -target bpf -O2 -g -c profiler.bpf.c -o profiler.bpf.o
// The -g flag emits BTF + CO-RE relocation records in the ELF output.

#include "profiler.bpf.h"
#include "process.bpf.h"
#include "block_io.bpf.h"
#include "oom.bpf.h"
// #include "sched.bpf.h"
// #include "tcp.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
