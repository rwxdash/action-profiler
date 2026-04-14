#!/usr/bin/env bash
# Revert a mistakenly pushed release tag.
# Usage: bash scripts/release-revert.sh v1.0.0
set -euo pipefail

TAG="${1:-}"
if [ -z "$TAG" ]; then
  echo "Usage: $0 <tag>"
  echo "Example: $0 v1.0.0"
  exit 1
fi

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: tag must be vX.Y.Z format (got '$TAG')"
  exit 1
fi

MAJOR="${TAG%%.*}"

echo "This will:"
echo "  - Delete GitHub release for $TAG (if exists)"
echo "  - Delete remote tag $TAG"
echo "  - Delete local tag $TAG"
echo "  - Reset $MAJOR tag to the previous $MAJOR.* release (if any)"
echo ""
read -rp "Continue? [y/N] " confirm
if [[ "$confirm" != [yY] ]]; then
  echo "Aborted."
  exit 0
fi

# Delete GitHub release
if gh release view "$TAG" &>/dev/null; then
  gh release delete "$TAG" --yes
  echo "Deleted GitHub release $TAG"
else
  echo "No GitHub release for $TAG (skipping)"
fi

# Delete remote tag
if git ls-remote --tags origin "refs/tags/$TAG" | grep -q .; then
  git push origin --delete "$TAG"
  echo "Deleted remote tag $TAG"
fi

# Delete local tag
if git tag -l "$TAG" | grep -q .; then
  git tag -d "$TAG"
  echo "Deleted local tag $TAG"
fi

# Find the previous release in this major version and reset the floating tag
PREV=$(git tag -l "$MAJOR.*" --sort=-version:refname | head -1)
if [ -n "$PREV" ]; then
  echo "Resetting $MAJOR tag to $PREV"
  git tag -f "$MAJOR" "$PREV"
  git push -f origin "$MAJOR"
else
  echo "No remaining $MAJOR.* tags -- deleting floating $MAJOR tag"
  git push origin --delete "$MAJOR" 2>/dev/null || true
  git tag -d "$MAJOR" 2>/dev/null || true
fi

echo ""
echo "Done."
