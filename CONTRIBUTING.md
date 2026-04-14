# Contributing

## Prerequisites

- Linux with BTF support (`/sys/kernel/btf/vmlinux`)
- Rust stable toolchain
- clang (for compiling eBPF C programs)
- Node.js 24+ and npm
- wasm-pack (for building the WASM viewer)

## Setup

```bash
git clone --recurse-submodules https://github.com/rwxdash/action-profiler.git
cd action-profiler
npm ci

# Mark compiled binaries as skip-worktree
# so local builds don't show them as modified in git
bash scripts/dev-setup.sh
```

The `dev-setup.sh` script marks `profiler/bin/profiler` and the WASM binary as
skip-worktree. These files are only updated through the `update-artifacts`
CI workflow. **Never commit them manually.**

## Building

```bash
# Build everything (profiler binary + WASM viewer + TypeScript bundle)
npm run package

# Build only the Rust profiler
cd profiler && cargo build --release

# Build only the TypeScript action bundle
npx rollup --config rollup.config.ts --configPlugin @rollup/plugin-typescript

# Format code
npm run format:write
```

## Running Locally

The profiler requires root (or `CAP_BPF`):

```bash
# Basic - output events to stdout
sudo ./profiler/target/release/profiler

# Write events to a JSONL file
sudo ./profiler/target/release/profiler --output /tmp/events.jsonl

# With process filtering
sudo PROFILER_IGNORE="sh,node" \
     PROFILER_IGNORE_PATTERN="vscode-server" \
     ./profiler/target/release/profiler --output /tmp/events.jsonl

# Verbose logging
sudo RUST_LOG=debug ./profiler/target/release/profiler
```

## Project Structure

```
action-profiler/
  src/                     TypeScript GitHub Action
    main.ts                  Entry: starts profiler daemon
    post.ts                  Post-job: stops profiler, builds report, uploads artifact
  profiler/                Rust workspace
    profiler/                Userspace daemon (loads eBPF, collects events + metrics)
    profiler-ebpf/           C eBPF programs (compiled with clang, loaded via aya)
    profiler-common/         Shared Rust types (events, constants)
    profiler-viewer/         WASM viewer (processes JSONL into structured data for JS)
  scripts/
    build.sh                 Full build (binary + WASM + viewer assets)
    dev-setup.sh             Mark binaries as skip-worktree for local dev
    release                  Interactive release script (tag + push)
    release-revert.sh        Revert a mistaken release
    inspect-bpf.sh           Debug: inspect compiled .bpf.o
    generate-vmlinux.sh      Generate vmlinux.h from kernel BTF
  .github/workflows/
    check-dist.yml           PR check: verify build outputs + reject binaries
    test-profiler.yml        Integration test: run profiler with real workloads
    update-artifacts.yml     Build and commit compiled artifacts
    release.yml              Create GitHub release on tag push
```

## Workflow

1. Work on a feature branch
2. Open a PR to `master`
3. CI runs `check-dist.yml` (verifies JS/HTML match source, rejects binaries)
4. CI runs `test-profiler.yml` (builds from source, runs workloads, validates output)
5. Merge to `master`
6. If eBPF/Rust/WASM changed: run `Update Compiled Artifacts` workflow, merge the PR it creates
7. Release: `bash scripts/release`

See [docs/RELEASING.md](docs/RELEASING.md) for release details.
