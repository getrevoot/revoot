# Releasing Revoot

Release-plz prepares a pull request from the commits since the previous release.
The pull request updates the workspace version and `CHANGELOG.md`; its changelog
entry is the source for the GitHub release notes. An exact semantic-version tag
then runs validation, builds the supported archives and multi-architecture
container image, generates checksums, and creates the GitHub release.

## Prepare

Run the **Prepare release** workflow and review the resulting pull request.
Release-plz derives the version bump and candidate changelog entries from commit
messages, so edit the pull request when an entry needs clearer user-facing
wording. Merge it after the version, lockfile, generated CI image tags, and
changelog agree.

The workflow uses `RELEASE_PLZ_TOKEN` when that repository secret is available,
falling back to `GITHUB_TOKEN`. Prefer a fine-grained token or GitHub App token
with repository Contents and Pull requests read/write access so the generated
pull request triggers normal CI. With the fallback token, GitHub must allow
Actions to create pull requests, and the generated pull request may need to be
closed and reopened to trigger its checks.

Use Conventional Commit prefixes for changes that affect version selection:
`feat:` for features, `fix:` for fixes, and `!` or a `BREAKING CHANGE:` footer
for incompatible changes. Other commits receive a patch-level default and may
still appear in the generated changelog.

Before tagging, run:

```sh
mise run ci
mise run package:linux
mise run package:macos
mise run release:checksums
mise run install:cargo:smoke
```

`package:macos` requires an Apple Silicon macOS host.

## Publish

Create the tag, validate it locally, and push it:

```sh
git tag -a v0.1.0 -m "Revoot v0.1.0"
mise run release:version v0.1.0
git push origin v0.1.0
```

The workflow publishes Linux AMD64/ARM64 and Apple Silicon macOS archives,
`SHA256SUMS`, and `ghcr.io/getrevoot/revoot` tags with and without the leading
`v`. It uses the matching changelog section as the GitHub release notes. Stable
releases also update `latest`; prereleases do not.

If a job fails, fix it and rerun the workflow. Never move a published version
tag to a different commit.
