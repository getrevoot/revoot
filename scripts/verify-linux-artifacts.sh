#!/usr/bin/env bash
set -euo pipefail

verify_binary() {
  local binary=$1
  local kind=$2
  local description
  description=$(file "$binary")

  case "$description" in
    *"ELF 64-bit"*"statically linked"*) ;;
    *)
      echo "artifact is not a static 64-bit ELF binary: $description" >&2
      exit 1
      ;;
  esac

  if [[ $kind == release ]]; then
    case "$description" in
      *stripped*) ;;
      *)
        echo "release artifact is not stripped: $description" >&2
        exit 1
        ;;
    esac
  else
    case "$description" in
      *with\ debug_info*not\ stripped*) ;;
      *)
        echo "debug artifact does not retain debug information: $description" >&2
        exit 1
        ;;
    esac
  fi

  if strings "$binary" | grep -Fq "$MISE_PROJECT_ROOT"; then
    echo "artifact leaks the local project path: $binary" >&2
    exit 1
  fi
}

verify_archive() {
  local archive=$1
  local binary=$2
  local listing
  local first_line
  local members
  local gzip_time
  local archived_hash
  local binary_hash

  listing=$(tar -tvzf "$archive")
  first_line=${listing%%$'\n'*}
  case "$first_line" in
    -rwxr-xr-x*root*root*revoot) ;;
    *)
      echo "archive executable mode or normalized ownership is wrong: $first_line" >&2
      exit 1
      ;;
  esac
  while IFS= read -r entry; do
    case "$entry" in
      *root*root*) ;;
      *)
        echo "archive contains non-normalized ownership: $entry" >&2
        exit 1
        ;;
    esac
  done <<< "$listing"

  members=$(tar -tzf "$archive")
  if [[ $members != $'revoot\nLICENSE\ncompletions/revoot.bash\ncompletions/_revoot\ncompletions/revoot.fish' ]]; then
    echo "archive member set or order is wrong: $archive" >&2
    exit 1
  fi

  gzip_time=$(od -An -t u1 -j 4 -N 4 "$archive" | tr -d ' ')
  if [[ $gzip_time != 0000 ]]; then
    echo "gzip timestamp is not normalized: $archive" >&2
    exit 1
  fi

  archived_hash=$(tar -xOzf "$archive" revoot | shasum -a 256 | awk '{print $1}')
  binary_hash=$(shasum -a 256 "$binary" | awk '{print $1}')
  if [[ $archived_hash != "$binary_hash" ]]; then
    echo "archive payload does not match the built binary: $archive" >&2
    exit 1
  fi

  cmp <(tar -xOzf "$archive" LICENSE) LICENSE
  cmp <(tar -xOzf "$archive" completions/revoot.bash) packaging/completions/revoot.bash
  cmp <(tar -xOzf "$archive" completions/_revoot) packaging/completions/_revoot
  cmp <(tar -xOzf "$archive" completions/revoot.fish) packaging/completions/revoot.fish
}

verify_binary target/x86_64-unknown-linux-musl/release/revoot release
verify_binary target/aarch64-unknown-linux-musl/release/revoot release
verify_binary target/x86_64-unknown-linux-musl/distribution-debug/revoot debug
verify_binary target/aarch64-unknown-linux-musl/distribution-debug/revoot debug

verify_archive \
  dist/revoot-linux-amd64.tar.gz \
  target/x86_64-unknown-linux-musl/release/revoot
verify_archive \
  dist/revoot-linux-arm64.tar.gz \
  target/aarch64-unknown-linux-musl/release/revoot
verify_archive \
  dist/revoot-linux-amd64-debug.tar.gz \
  target/x86_64-unknown-linux-musl/distribution-debug/revoot
verify_archive \
  dist/revoot-linux-arm64-debug.tar.gz \
  target/aarch64-unknown-linux-musl/distribution-debug/revoot

echo "Linux artifact verification passed"
