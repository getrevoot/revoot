#!/usr/bin/env bash
set -euo pipefail

architecture=${1:?usage: build-oci-image.sh amd64|arm64 [tag]}
tag=${REVOOT_OCI_TAG:-${2:-revoot:local-${architecture}}}
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
container=
cleanup() {
  if [[ -n $container ]]; then
    docker rm "$container" >/dev/null 2>&1 || true
  fi
  find "$context" -depth -delete
}
trap cleanup EXIT
cp "$project_root/packaging/oci/Dockerfile" "$context/Dockerfile"
cp "$binary" "$context/revoot"
cp "$project_root/LICENSE" "$context/LICENSE"
cp "$project_root/THIRD_PARTY_NOTICES.md" "$context/THIRD_PARTY_NOTICES.md"
cp "$project_root/crates/revoot/assets/review_rules/LICENSE.md" \
  "$context/embedded-review-rules-LICENSE.md"
build_args=(--progress plain --platform "linux/$architecture" --tag "$tag")
if [[ -n ${REVOOT_OCI_SOURCE:-} ]]; then
  build_args+=(--label "org.opencontainers.image.source=$REVOOT_OCI_SOURCE")
fi
if [[ -n ${REVOOT_OCI_REVISION:-} ]]; then
  build_args+=(--label "org.opencontainers.image.revision=$REVOOT_OCI_REVISION")
fi
DOCKER_BUILDKIT=1 docker build "${build_args[@]}" "$context"

reported_user=$(docker run --rm --platform "linux/$architecture" --entrypoint /usr/local/bin/revoot "$tag" doctor --json)
printf '%s\n' "$reported_user" | grep -q '"review_available": true'

configured_user=$(docker image inspect "$tag" --format '{{.Config.User}}')
test "$configured_user" = "65532:65532"
container=$(docker create --platform "linux/$architecture" "$tag")
docker cp "$container:/usr/share/licenses/revoot/LICENSE" "$context/image-LICENSE"
docker cp "$container:/usr/share/licenses/revoot/THIRD_PARTY_NOTICES.md" \
  "$context/image-THIRD_PARTY_NOTICES.md"
docker cp "$container:/usr/share/licenses/revoot/embedded-review-rules-LICENSE.md" \
  "$context/image-embedded-review-rules-LICENSE.md"
cmp "$context/image-LICENSE" "$project_root/LICENSE"
cmp "$context/image-THIRD_PARTY_NOTICES.md" "$project_root/THIRD_PARTY_NOTICES.md"
cmp "$context/image-embedded-review-rules-LICENSE.md" \
  "$project_root/crates/revoot/assets/review_rules/LICENSE.md"
echo "verified non-root Revoot image: $tag"
