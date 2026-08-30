#!/usr/bin/env bash
set -euo pipefail

target=aarch64-apple-darwin
project_root=${MISE_PROJECT_ROOT:?run through mise}
binary="target/$target/release/revoot"
archive=dist/revoot-macos-arm64.tar.gz
description=$(file "$binary")
case "$description" in
  *"Mach-O 64-bit executable arm64"*) ;;
  *) echo "artifact is not an ARM64 Mach-O executable: $description" >&2; exit 1 ;;
esac
defined_symbols=$(nm "$binary" | awk '$1 != "U" { print $2 " " $3 }')
if [[ $defined_symbols != 'T __mh_execute_header' ]]; then
  echo "macOS release artifact retains unexpected defined symbols" >&2
  exit 1
fi
if strings "$binary" | grep -Fq "$project_root"; then
  echo "macOS artifact leaks the local project path" >&2
  exit 1
fi

members=$(tar -tzf "$archive")
expected=$'revoot\nLICENSE\ncompletions/revoot.bash\ncompletions/_revoot\ncompletions/revoot.fish'
if [[ $members != "$expected" ]]; then
  echo "macOS archive member set or order is wrong" >&2
  exit 1
fi
first_line=$(tar -tvzf "$archive" | head -n 1)
case "$first_line" in
  -rwxr-xr-x*root*root*revoot) ;;
  *) echo "macOS archive executable mode or ownership is wrong: $first_line" >&2; exit 1 ;;
esac
archived_hash=$(tar -xOzf "$archive" revoot | shasum -a 256 | awk '{print $1}')
built_hash=$(shasum -a 256 "$binary" | awk '{print $1}')
test "$archived_hash" = "$built_hash"
cmp <(tar -xOzf "$archive" LICENSE) LICENSE
cmp <(tar -xOzf "$archive" completions/revoot.bash) packaging/completions/revoot.bash
cmp <(tar -xOzf "$archive" completions/_revoot) packaging/completions/_revoot
cmp <(tar -xOzf "$archive" completions/revoot.fish) packaging/completions/revoot.fish
"$binary" --version >/dev/null
"$binary" doctor --json | grep -Fq '"review_available": true'
echo "macOS artifact verification passed"
