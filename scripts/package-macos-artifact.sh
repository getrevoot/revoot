#!/usr/bin/env bash
set -euo pipefail

target=aarch64-apple-darwin
output=${1:-dist/revoot-macos-arm64.tar.gz}

cargo build --locked --release --target "$target"
binary="target/$target/release/revoot"
mkdir -p dist "target/package-staging"
staging=$(mktemp -d "target/package-staging/$target-release.XXXXXX")
cleanup() {
  find "$staging" -depth -delete
}
trap cleanup EXIT

install -m 0755 "$binary" "$staging/revoot"
install -m 0644 LICENSE "$staging/LICENSE"
mkdir -p "$staging/completions"
install -m 0644 packaging/completions/revoot.bash "$staging/completions/revoot.bash"
install -m 0644 packaging/completions/_revoot "$staging/completions/_revoot"
install -m 0644 packaging/completions/revoot.fish "$staging/completions/revoot.fish"

source_date_epoch=${SOURCE_DATE_EPOCH:-946684800}
timestamp=$(date -u -r "$source_date_epoch" '+%Y%m%d%H%M.%S')
find "$staging" -mindepth 1 -exec touch -t "$timestamp" {} +

tar --format=ustar --uid 0 --gid 0 --uname root --gname root --no-xattrs \
  -cf "$staging/revoot.tar" -C "$staging" \
  revoot LICENSE \
  completions/revoot.bash completions/_revoot completions/revoot.fish
gzip -n -9 < "$staging/revoot.tar" > "$output"
