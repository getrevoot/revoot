#!/usr/bin/env bash
set -euo pipefail

real_cargo=${REVOOT_RELEASE_PLZ_REAL_CARGO:?release-plz Cargo path is missing}

if [[ ${1:-} == package ]]; then
  allow_dirty=false
  workspace=false
  no_verify=false
  for argument in "$@"; do
    case "$argument" in
      --allow-dirty) allow_dirty=true ;;
      --workspace) workspace=true ;;
      --no-verify) no_verify=true ;;
    esac
  done
  if [[ $allow_dirty == true && $workspace == true && $no_verify == false ]]; then
    workspace_manifest=$PWD/Cargo.toml
    core_manifest=$PWD/crates/revoot-core/Cargo.toml
    [[ $(grep -Fxc 'publish.workspace = true' "$core_manifest") -eq 1 ]] || {
      echo "revoot-core publication guard has an unexpected shape" >&2
      exit 1
    }
    original_workspace=$(mktemp "${TMPDIR:-/tmp}/revoot-workspace-manifest.XXXXXX")
    original_core=$(mktemp "${TMPDIR:-/tmp}/revoot-core-manifest.XXXXXX")
    rewritten=$(mktemp "${TMPDIR:-/tmp}/revoot-package-manifest.XXXXXX")
    cp "$workspace_manifest" "$original_workspace"
    cp "$core_manifest" "$original_core"
    restore_manifests() {
      cp "$original_workspace" "$workspace_manifest"
      cp "$original_core" "$core_manifest"
      rm -f "$original_workspace" "$original_core" "$rewritten"
    }
    trap restore_manifests EXIT HUP INT TERM

    if [[ $(grep -Fxc 'revoot-core = { path = "crates/revoot-core" }' "$workspace_manifest") -eq 1 ]]; then
      workspace_version=$(awk -F '"' '/^version = "/ { print $2; exit }' "$workspace_manifest")
      [[ $workspace_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        echo "workspace version has an unexpected shape" >&2
        exit 1
      }
      awk -v version="$workspace_version" '
        $0 == "revoot-core = { path = \"crates/revoot-core\" }" {
          print "revoot-core = { version = \"" version "\", path = \"crates/revoot-core\" }"
          next
        }
        { print }
      ' "$workspace_manifest" > "$rewritten"
      cp "$rewritten" "$workspace_manifest"
    fi

    awk '
      $0 == "publish.workspace = true" { print "publish = true"; next }
      { print }
    ' "$core_manifest" > "$rewritten"
    cp "$rewritten" "$core_manifest"

    set +e
    "$real_cargo" "$@" --no-verify
    status=$?
    set -e
    if [[ $status -eq 0 ]]; then
      target_root=${CARGO_TARGET_DIR:-$PWD/target}
      if [[ $target_root != /* ]]; then
        target_root=$PWD/$target_root
      fi
      package_root=$target_root/package
      archives=("$package_root"/*.crate)
      [[ -e ${archives[0]} ]] || {
        echo "Cargo produced no workspace package archives" >&2
        status=1
      }
      if [[ $status -eq 0 ]]; then
        for archive in "${archives[@]}"; do
          tar -xzf "$archive" -C "$package_root"
        done
      fi
    fi
    restore_manifests
    trap - EXIT HUP INT TERM
    exit "$status"
  fi
fi

exec "$real_cargo" "$@"
