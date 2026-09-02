#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 TARGET PROFILE OUTPUT" >&2
  exit 2
fi

target=$1
profile=$2
output=$3

case "$target" in
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
  *)
    echo "unsupported package target: $target" >&2
    exit 2
    ;;
esac

case "$profile" in
  release)
    cargo zigbuild --locked --package revoot --bin revoot --release --target "$target"
    ;;
  distribution-debug)
    cargo zigbuild --locked --package revoot --bin revoot \
      --profile distribution-debug --target "$target"
    ;;
  *)
    echo "unsupported package profile: $profile" >&2
    exit 2
    ;;
esac

binary="target/$target/$profile/revoot"
if [[ ! -f "$binary" ]]; then
  echo "expected build output is missing: $binary" >&2
  exit 1
fi

mkdir -p dist "target/package-staging"
staging=$(mktemp -d "target/package-staging/$target-$profile.XXXXXX")
cleanup() {
  find "$staging" -depth -delete
}
trap cleanup EXIT

install -m 0755 "$binary" "$staging/revoot"
install -m 0644 LICENSE "$staging/LICENSE"
install -m 0644 THIRD_PARTY_NOTICES.md "$staging/THIRD_PARTY_NOTICES.md"
mkdir -p "$staging/licenses"
install -m 0644 crates/revoot/assets/review_rules/LICENSE.md \
  "$staging/licenses/embedded-review-rules-LICENSE.md"
mkdir -p "$staging/completions"
install -m 0644 packaging/completions/revoot.bash "$staging/completions/revoot.bash"
install -m 0644 packaging/completions/_revoot "$staging/completions/_revoot"
install -m 0644 packaging/completions/revoot.fish "$staging/completions/revoot.fish"
source_date_epoch=${SOURCE_DATE_EPOCH:-946684800}
if find "$staging" -mindepth 1 -exec touch -d "@$source_date_epoch" {} + 2>/dev/null; then
  :
else
  timestamp=$(date -u -r "$source_date_epoch" '+%Y%m%d%H%M.%S')
  find "$staging" -mindepth 1 -exec touch -t "$timestamp" {} +
fi

if tar --version 2>&1 | grep -q bsdtar; then
  tar --format=ustar --uid 0 --gid 0 --uname root --gname root \
    --no-xattrs -cf "$staging/revoot.tar" -C "$staging" \
    revoot LICENSE THIRD_PARTY_NOTICES.md \
    licenses/embedded-review-rules-LICENSE.md \
    completions/revoot.bash completions/_revoot completions/revoot.fish
else
  tar --format=ustar --owner=0 --group=0 --numeric-owner \
    -cf "$staging/revoot.tar" -C "$staging" \
    revoot LICENSE THIRD_PARTY_NOTICES.md \
    licenses/embedded-review-rules-LICENSE.md \
    completions/revoot.bash completions/_revoot completions/revoot.fish
fi

gzip -n -9 < "$staging/revoot.tar" > "$output"
