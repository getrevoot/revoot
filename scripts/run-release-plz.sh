#!/usr/bin/env bash
set -euo pipefail

: "${MISE_PROJECT_ROOT:?run through mise}"

real_cargo=$(command -v cargo)
[[ -x $real_cargo ]] || {
  echo "could not resolve the pinned Cargo executable" >&2
  exit 1
}

export REVOOT_RELEASE_PLZ_REAL_CARGO=$real_cargo
export CARGO="$MISE_PROJECT_ROOT/scripts/release-plz-cargo.sh"

exec release-plz "$@"
