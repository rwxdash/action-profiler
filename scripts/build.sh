#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$REPO_ROOT/profiler/bin"
OUT_DIR="$BIN_DIR/out"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/pkg"

echo "==> Building profiler binary (release)..."
cd "$REPO_ROOT/profiler"
cargo build --release

echo "==> Building WASM viewer..."
cd "$REPO_ROOT/profiler/profiler-viewer"
wasm-pack build --target web --release

echo "==> Copying artifacts..."
cp "$REPO_ROOT/node_modules/echarts/dist/echarts.min.js" "$OUT_DIR/echarts.min.js"
cp "$REPO_ROOT/profiler/target/release/profiler" "$BIN_DIR/profiler"
cp "$REPO_ROOT/profiler/tests/index.html" "$OUT_DIR/index.html"
cp "$REPO_ROOT/profiler/profiler-viewer/pkg/profiler_viewer.js" "$OUT_DIR/pkg/"
cp "$REPO_ROOT/profiler/profiler-viewer/pkg/profiler_viewer_bg.wasm" "$OUT_DIR/pkg/"

chmod +x "$BIN_DIR/profiler"

echo "==> Done. Output:"
ls -lh "$BIN_DIR/profiler"
ls -lh "$OUT_DIR"
ls -lh "$OUT_DIR/pkg"
