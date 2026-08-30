#!/usr/bin/env bash
set -euo pipefail

project_root=${MISE_PROJECT_ROOT:?run through mise}
distribution_root="$project_root/dist"
mkdir -p "$distribution_root"

artifacts=(
  revoot-linux-amd64.tar.gz
  revoot-linux-amd64-debug.tar.gz
  revoot-linux-arm64.tar.gz
  revoot-linux-arm64-debug.tar.gz
  revoot-macos-arm64.tar.gz
)

for artifact in "${artifacts[@]}"; do
  if [[ ! -f "$distribution_root/$artifact" ]]; then
    echo "missing release artifact: dist/$artifact" >&2
    exit 1
  fi
done

staging=$(mktemp -d "${TMPDIR:-/tmp}/revoot-checksums.XXXXXX")
trap 'rm -rf "$staging"' EXIT
(
  cd "$distribution_root"
  shasum -a 256 "${artifacts[@]}"
) >"$staging/SHA256SUMS"
mv "$staging/SHA256SUMS" "$distribution_root/SHA256SUMS"

(
  cd "$distribution_root"
  shasum -a 256 --check SHA256SUMS
)
