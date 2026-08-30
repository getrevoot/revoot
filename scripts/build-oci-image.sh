#!/usr/bin/env bash
set -euo pipefail

architecture=${1:?usage: build-oci-image.sh amd64|arm64 [tag]}
tag=${2:-revoot:local-${architecture}}
case "$architecture" in
  amd64) target=x86_64-unknown-linux-musl ;;
  arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported architecture: $architecture" >&2; exit 2 ;;
esac

project_root=${MISE_PROJECT_ROOT:?run through mise}
binary="$project_root/target/$target/release/revoot"
if [[ ! -x "$binary" ]]; then
  echo "missing release binary: run mise run package:linux:release first" >&2
  exit 1
fi

context=$(mktemp -d "${TMPDIR:-/tmp}/revoot-oci.XXXXXX")
trap 'rm -rf "$context"' EXIT
cp "$project_root/packaging/oci/Dockerfile" "$context/Dockerfile"
cp "$binary" "$context/revoot"
DOCKER_BUILDKIT=1 docker build --progress plain \
  --platform "linux/$architecture" --tag "$tag" "$context"

reported_user=$(docker run --rm --platform "linux/$architecture" --entrypoint /usr/local/bin/revoot "$tag" doctor --json)
printf '%s\n' "$reported_user" | grep -q '"review_available": true'

configured_user=$(docker image inspect "$tag" --format '{{.Config.User}}')
test "$configured_user" = "65532:65532"
echo "verified non-root Revoot image: $tag"
