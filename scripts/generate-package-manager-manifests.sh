#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 VERSION OUTPUT_DIR" >&2
  exit 2
fi
version=$1
output_dir=$2
github_project=getrevoot/revoot
homepage=https://github.com/getrevoot/revoot
release_base_url="$homepage/releases/download/v$version"
checksums=${REVOOT_CHECKSUM_FILE:-dist/SHA256SUMS}

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || { echo "invalid semantic version" >&2; exit 2; }
[[ -f $checksums ]] || { echo "run mise run release:checksums first" >&2; exit 1; }
if [[ -z ${REVOOT_CHECKSUM_FILE:-} ]]; then
  (cd dist && shasum -a 256 -c SHA256SUMS >/dev/null)
fi

checksum() {
  local asset=$1 value
  value=$(awk -v asset="$asset" '$2 == asset { print $1 }' "$checksums")
  [[ $value =~ ^[0-9a-f]{64}$ ]] || { echo "missing or invalid checksum for $asset" >&2; exit 1; }
  printf '%s' "$value"
}

linux_amd64=$(checksum revoot-linux-amd64.tar.gz)
linux_arm64=$(checksum revoot-linux-arm64.tar.gz)
macos_arm64=$(checksum revoot-macos-arm64.tar.gz)
mkdir -p "$output_dir"

printf '%s\n' \
  '[tools."github:'"$github_project"'"]' \
  'version = "'"$version"'"' \
  '' \
  '[tools."github:'"$github_project"'".platforms]' \
  'linux-x64 = { asset_pattern = "revoot-linux-amd64.tar.gz", checksum = "sha256:'"$linux_amd64"'" }' \
  'linux-arm64 = { asset_pattern = "revoot-linux-arm64.tar.gz", checksum = "sha256:'"$linux_arm64"'" }' \
  'macos-arm64 = { asset_pattern = "revoot-macos-arm64.tar.gz", checksum = "sha256:'"$macos_arm64"'" }' \
  > "$output_dir/revoot.mise.toml"

printf '%s\n' \
  'class Revoot < Formula' \
  '  desc "Independent review for agent-written code"' \
  '  homepage "'"$homepage"'"' \
  '  version "'"$version"'"' \
  '  license "Apache-2.0"' \
  '' \
  '  on_macos do' \
  '    on_arm do' \
  '      url "'"$release_base_url"'/revoot-macos-arm64.tar.gz"' \
  '      sha256 "'"$macos_arm64"'"' \
  '    end' \
  '  end' \
  '' \
  '  on_linux do' \
  '    on_intel do' \
  '      url "'"$release_base_url"'/revoot-linux-amd64.tar.gz"' \
  '      sha256 "'"$linux_amd64"'"' \
  '    end' \
  '    on_arm do' \
  '      url "'"$release_base_url"'/revoot-linux-arm64.tar.gz"' \
  '      sha256 "'"$linux_arm64"'"' \
  '    end' \
  '  end' \
  '' \
  '  def install' \
  '    bin.install "revoot"' \
  '    bash_completion.install "completions/revoot.bash" => "revoot"' \
  '    zsh_completion.install "completions/_revoot"' \
  '    fish_completion.install "completions/revoot.fish"' \
  '  end' \
  '' \
  '  test do' \
  '    assert_match version.to_s, shell_output("#{bin}/revoot --version")' \
  '    system bin/"revoot", "doctor", "--json"' \
  '  end' \
  'end' \
  > "$output_dir/revoot.rb"

echo "generated mise and Homebrew manifests for Revoot $version"
