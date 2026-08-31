#!/usr/bin/env bash
set -euo pipefail

release_sha=${1:-}
[[ $release_sha =~ ^[0-9a-f]{40}$ ]] || {
  echo "release commit must be a full lowercase SHA-1" >&2
  exit 2
}

repository=${2:-${MISE_PROJECT_ROOT:-}}
if [[ -z $repository ]]; then
  repository=$(git rev-parse --show-toplevel)
fi
head_sha=$(git -C "$repository" rev-parse HEAD)
[[ $head_sha == "$release_sha" ]] || {
  echo "release commit does not match the checked out commit" >&2
  exit 1
}

git -C "$repository" fetch origin main --tags
git -C "$repository" merge-base --is-ancestor "$release_sha" origin/main || {
  echo "release commit is not reachable from origin/main" >&2
  exit 1
}

version=$(awk -F '"' '/^version = "/ { print $2; exit }' "$repository/Cargo.toml")
tag="v$version"
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "Cargo package version is not an exact semantic version" >&2
  exit 1
}

subject=$(git -C "$repository" show -s --format=%s "$release_sha")
[[ $subject == "chore: release $tag" ]] || {
  echo "release commit subject does not identify $tag" >&2
  exit 1
}

changelog=$repository/CHANGELOG.md
grep -Fqx "## [Unreleased]" "$changelog" || {
  echo "CHANGELOG.md must contain an Unreleased section" >&2
  exit 1
}
grep -Eq "^## \\[$version\\](\\([^)]*\\))? - [0-9]{4}-[0-9]{2}-[0-9]{2}$" \
  "$changelog" || {
  echo "CHANGELOG.md has no dated section for $version" >&2
  exit 1
}

if git -C "$repository" show-ref --verify --quiet "refs/tags/$tag"; then
  existing_sha=$(git -C "$repository" rev-parse "$tag^{commit}")
  [[ $existing_sha == "$release_sha" ]] || {
    echo "release tag $tag already points at a different commit" >&2
    exit 1
  }
  echo "release tag $tag already points at the prepared commit"
  exit 0
fi

git -C "$repository" config user.name "revoot-release[bot]"
git -C "$repository" config user.email "revoot-release[bot]@users.noreply.github.com"
git -C "$repository" tag -a "$tag" "$release_sha" -m "Revoot $tag"
git -C "$repository" push origin "refs/tags/$tag"

echo "created release tag $tag at $release_sha"
