#!/usr/bin/env bash
# release.sh [patch|minor|major] tags HEAD with the next version after the latest v* tag (v0.1.0 when
# there is none) and creates its GitHub Release. It does nothing when HEAD already has a tag. Needs
# GH_TOKEN and the full history (fetch-depth: 0).
set -euo pipefail

bump=${1:-patch}
git fetch --tags --force --quiet

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged $(git tag --points-at HEAD 'v*' | head -1)"
  exit 0
fi

latest=$(git tag --list 'v*' --sort=-version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
if [ -z "$latest" ]; then
  tag=v0.1.0
else
  IFS=. read -r major minor patch <<< "${latest#v}"
  case "$bump" in
    major) tag="v$((major + 1)).0.0" ;;
    minor) tag="v$major.$((minor + 1)).0" ;;
    patch) tag="v$major.$minor.$((patch + 1))" ;;
    *) echo "unknown bump: $bump (patch, minor or major)" >&2; exit 1 ;;
  esac
fi

git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  tag -a "$tag" -m "$tag"
git push origin "$tag"
gh release create "$tag" --verify-tag --title "$tag" --generate-notes
# a tag and Release created with GITHUB_TOKEN do not start other workflows, so start the binaries build
gh workflow run goreleaser.yml -f tag="$tag"
echo "released $tag"
