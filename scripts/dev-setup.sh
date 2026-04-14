#!/usr/bin/env bash
# Mark compiled binaries as skip-worktree so local builds
# don't show them as modified. These files are only updated
# via the update-artifacts workflow.
set -euo pipefail

FILES=(
  profiler/bin/profiler
  profiler/bin/out/pkg/profiler_viewer_bg.wasm
)

for f in "${FILES[@]}"; do
  if git ls-files --error-unmatch "$f" &>/dev/null; then
    git update-index --skip-worktree "$f"
    echo "  skip-worktree: $f"
  fi
done

echo ""
echo "Done. Local builds won't dirty these files."
echo "To undo: git update-index --no-skip-worktree <file>"
