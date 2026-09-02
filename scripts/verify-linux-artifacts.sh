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
  local metadata
  local first_line
  local members
  local gzip_time
  local archived_hash
  local binary_hash

  metadata=$(
    tar --numeric-owner -tvzf "$archive" | awk '
      {
        mode = $1
        if ($2 ~ /^[0-9]+\/[0-9]+$/) {
          split($2, owner, "/")
          uid = owner[1]
          gid = owner[2]
        } else if ($3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/) {
          uid = $3
          gid = $4
        } else {
          exit 1
        }
        print mode, uid, gid, $NF
      }
    '
  ) || {
    echo "could not read numeric archive ownership: $archive" >&2
    exit 1
  }
  first_line=${metadata%%$'\n'*}
  if [[ $first_line != '-rwxr-xr-x 0 0 revoot' ]]; then
    echo "archive executable mode or normalized ownership is wrong: $first_line" >&2
    exit 1
  fi
  while read -r _mode uid gid entry; do
    if [[ $uid != 0 || $gid != 0 ]]; then
      echo "archive contains non-normalized ownership: $entry ($uid:$gid)" >&2
      exit 1
    fi
    if [[ $entry != revoot && $_mode != '-rw-r--r--' ]]; then
      echo "archive documentation has an unsafe mode: $entry ($_mode)" >&2
      exit 1
    fi
  done <<< "$metadata"

  members=$(tar -tzf "$archive")
  if [[ $members != $'revoot\nLICENSE\nTHIRD_PARTY_NOTICES.md\nlicenses/embedded-review-rules-LICENSE.md\ncompletions/revoot.bash\ncompletions/_revoot\ncompletions/revoot.fish' ]]; then
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
  cmp <(tar -xOzf "$archive" THIRD_PARTY_NOTICES.md) THIRD_PARTY_NOTICES.md
  cmp <(tar -xOzf "$archive" licenses/embedded-review-rules-LICENSE.md) \
    crates/revoot/assets/review_rules/LICENSE.md
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
