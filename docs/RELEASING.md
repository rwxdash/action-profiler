# Releasing

## Prerequisites

- All changes merged to `master`
- Compiled artifacts up to date (run `Update Compiled Artifacts` workflow if needed)
- `npm audit` clean
- Local dev setup done (`bash scripts/dev-setup.sh`)

## Steps

1. **Ensure artifacts are current**

   If you changed eBPF code, Rust userspace, WASM viewer, or TypeScript:
   run the `Update Compiled Artifacts` workflow from the Actions tab,
   then merge the resulting PR.

2. **Verify the build**

   ```bash
   git checkout master && git pull
   npm ci
   npm run format:check
   ```

3. **Release**

   ```bash
   bash scripts/release
   ```

   The script will:
   - Show the latest release tag
   - Prompt for the new version (vX.Y.Z)
   - Validate the format
   - Remind you to update `package.json` version
   - Create and push the tag
   - Move the floating major tag (v1, v2, etc.)

   Then `release.yml` triggers in CI and:
   - Validates compiled artifacts exist on the tagged commit
   - Creates a GitHub release with auto-generated notes

## Reverting a Release

If you pushed a tag by mistake:

```bash
bash scripts/release-revert.sh v1.0.0
```

This will:
- Delete the GitHub release
- Delete the remote and local tags
- Reset the floating major tag to the previous release

## Dev Setup (skip-worktree)

Compiled binaries (`profiler/bin/profiler`, WASM blob) are checked into git
for the GitHub Action to work, but you should not commit them from local builds.

Run this once after cloning:

```bash
bash scripts/dev-setup.sh
```

This marks the binaries as skip-worktree so `git status` ignores local changes
to them. The `check-dist.yml` workflow also rejects PRs that include these files.

To undo (e.g., if you need to debug the binary in CI):

```bash
git update-index --no-skip-worktree profiler/bin/profiler
git update-index --no-skip-worktree profiler/bin/out/pkg/profiler_viewer_bg.wasm
```

## Versioning

- **vX.Y.Z** - immutable release tag (semver)
- **vX** - floating major tag, updated automatically by the release script

Users reference the action as:
```yaml
uses: rwxdash/action-profiler@v1       # recommended - gets patches automatically
uses: rwxdash/action-profiler@v1.0.0   # pinned to exact version
```

## What triggers a version bump

- **Patch** (v1.0.1): bug fixes, dependency updates, report improvements
- **Minor** (v1.1.0): new features (inputs, event types, report sections)
- **Major** (v2.0.0): breaking changes (removed inputs, changed output format)
