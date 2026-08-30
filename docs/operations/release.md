# Releasing Revoot

An exact semantic-version tag runs validation, builds the supported archives
and multi-architecture container image, generates checksums, and creates the
GitHub release.

## Prepare

Update the workspace version and generated CI image tags together, then run:

```sh
mise run ci
mise run package:linux
mise run package:macos
mise run release:checksums
mise run install:cargo:smoke
GITHUB_REF_NAME=v0.1.0 mise run release:version
```

`package:macos` requires an Apple Silicon macOS host.

## Publish

Create and push the tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The workflow publishes Linux AMD64/ARM64 and Apple Silicon macOS archives,
`SHA256SUMS`, and `ghcr.io/getrevoot/revoot` tags with and without the leading
`v`. Stable releases also update `latest`; prereleases do not.

If a job fails, fix it and rerun the workflow. Never move a published version
tag to a different commit.
