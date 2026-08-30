#!/usr/bin/env bash
set -euo pipefail

: "${MISE_PROJECT_ROOT:?run through mise}"

tag=${1:-${GITHUB_REF_NAME:-}}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "release tag must be an exact v-prefixed semantic version" >&2
  exit 2
}

version=$(awk -F '"' '/^version = "/ { print $2; exit }' "$MISE_PROJECT_ROOT/Cargo.toml")
[[ -n $version && $tag == "v$version" ]] || {
  echo "release tag $tag does not match Cargo version $version" >&2
  exit 1
}

echo "release tag matches Cargo package version $version"
