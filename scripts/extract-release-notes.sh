#!/usr/bin/env bash
set -euo pipefail

: "${MISE_PROJECT_ROOT:?run through mise}"

tag=${1:-${GITHUB_REF_NAME:-}}
output=${2:-dist/release-notes.md}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "release tag must be an exact v-prefixed semantic version" >&2
  exit 2
}

version=${tag#v}
changelog="$MISE_PROJECT_ROOT/CHANGELOG.md"
mkdir -p "$(dirname "$output")"
temporary=$(mktemp "${TMPDIR:-/tmp}/revoot-release-notes.XXXXXX")
trap 'rm -f "$temporary"' EXIT

awk -v heading="## [$version]" '
  index($0, heading) == 1 && $0 ~ / - / { found = 1; next }
  found && /^## / { exit }
  found {
    lines[++count] = $0
    if ($0 !~ /^[[:space:]]*$/) last_nonempty = count
  }
  END {
    if (!found) exit 1
    first = 1
    while (first <= last_nonempty && lines[first] ~ /^[[:space:]]*$/) first++
    for (line = first; line <= last_nonempty; line++) print lines[line]
  }
' "$changelog" >"$temporary" || {
  echo "CHANGELOG.md has no release section for $version" >&2
  exit 1
}

mv "$temporary" "$output"
[[ -s $output ]] || {
  echo "CHANGELOG.md release section for $version is empty" >&2
  exit 1
}

echo "wrote release notes for $tag to $output"
