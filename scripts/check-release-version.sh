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

tag_commit=$(git -C "$MISE_PROJECT_ROOT" rev-parse --verify "$tag^{commit}") || {
  echo "release tag $tag does not exist" >&2
  exit 1
}
head_commit=$(git -C "$MISE_PROJECT_ROOT" rev-parse HEAD)
[[ $tag_commit == "$head_commit" ]] || {
  echo "release tag $tag does not point at HEAD" >&2
  exit 1
}

changelog="$MISE_PROJECT_ROOT/CHANGELOG.md"
grep -Fqx "## [Unreleased]" "$changelog" || {
  echo "CHANGELOG.md must contain an Unreleased section" >&2
  exit 1
}

versions_file=$(mktemp "${TMPDIR:-/tmp}/revoot-changelog-versions.XXXXXX")
trap 'rm -f "$versions_file"' EXIT
sed -nE 's|^## \[([^]]+)\](\([^)]*\))? - [0-9]{4}-[0-9]{2}-[0-9]{2}$|\1|p' \
  "$changelog" >"$versions_file"
latest_changelog_version=$(sed -n '1p' "$versions_file")
[[ $latest_changelog_version == "$version" ]] || {
  echo "the latest CHANGELOG.md release must be [$version] with an ISO date" >&2
  exit 1
}

while IFS= read -r changelog_version; do
  git -C "$MISE_PROJECT_ROOT" rev-parse --verify --quiet \
    "refs/tags/v$changelog_version^{commit}" >/dev/null || {
      echo "CHANGELOG.md release $changelog_version has no matching v$changelog_version tag" >&2
      exit 1
    }
done <"$versions_file"

while IFS= read -r release_tag; do
  release_version=${release_tag#v}
  grep -Fqx "$release_version" "$versions_file" || {
    echo "release tag $release_tag has no matching CHANGELOG.md section" >&2
    exit 1
  }
done < <(
  git -C "$MISE_PROJECT_ROOT" tag --list 'v*' --sort=version:refname |
    sed -nE '/^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$/p'
)

echo "release tag, Cargo package, and changelog agree on $version"
