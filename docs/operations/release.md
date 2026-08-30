# Releasing Revoot

GitHub is the source, container registry, and release host. Pushing an exact
semantic-version tag runs CI, builds the supported archives and container
images, generates checksums and package-manager metadata, and publishes the
release.

## Prepare a release

Update the workspace version and generated CI image tags together, then run:

```sh
mise run ci
mise run package:linux
mise run package:macos
mise run release:checksums
mise run install:cargo:smoke
GITHUB_REF_NAME=v0.1.0 mise run release:version
```

The archives contain the Revoot binary, Apache-2.0 license, and Bash, Zsh, and
Fish completions. Linux release binaries are static and stripped; diagnostic
archives retain symbols. The macOS archive is a native ARM64 Mach-O.

## Publish

Create and push the version tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow publishes Linux and macOS archives, `SHA256SUMS`, generated
mise and Homebrew metadata, and a multi-architecture image at
`ghcr.io/getrevoot/revoot`. Stable releases also update the `latest` image tag.

If a workflow job fails, correct the problem and rerun it. Do not move an
already-published version tag to a different commit.
