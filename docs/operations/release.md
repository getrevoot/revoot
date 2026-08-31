# Releasing Revoot

Release-plz prepares a pull request from the commits since the previous release.
The pull request updates the workspace version and `CHANGELOG.md`; its changelog
entry is the source for the GitHub release notes. Merging that pull request makes
the release bot tag the prepared commit. The exact semantic-version tag then runs
validation, builds the supported archives and multi-architecture container image,
audits dependencies, generates checksums and a CycloneDX SBOM, creates signed
artifact attestations, and creates the GitHub release.

## Prepare

Run the **Prepare release** workflow and review the resulting pull request.
Release-plz derives the version bump and candidate changelog entries from commit
messages, so edit the pull request when an entry needs clearer user-facing
wording. Merge it after the version, lockfile, generated CI image tags, and
changelog agree.

Both release workflows authenticate as the repository's release GitHub App using
the `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` Actions secrets. The App must
be installed only on the repositories it releases and have repository Contents
and Pull requests read/write access. Its separate identity lets a maintainer
review the generated pull request, and its pull request and tag events trigger
the normal protected CI and publishing workflows.

Use Conventional Commit prefixes for changes that affect version selection:
`feat:` for features, `fix:` for fixes, and `!` or a `BREAKING CHANGE:` footer
for incompatible changes. Other commits receive a patch-level default and may
still appear in the generated changelog.

Before merging the release pull request, run:

```sh
mise run verify
mise run package:linux
mise run package:macos
mise run release:checksums
mise run sbom
mise run install:cargo:smoke
```

`package:macos` requires an Apple Silicon macOS host.

## Publish

Approve and merge the generated release pull request with a merge commit. The
**Promote release** workflow validates the merged release pull request and
creates the exact `v<version>` tag at its prepared head commit, rather than at an
unrelated newer commit when merges race. The operation is idempotent. To recover
from an infrastructure failure or bootstrap an already-merged release, dispatch
the workflow manually with the merged release pull request number.

The workflow publishes Linux AMD64/ARM64 and Apple Silicon macOS archives,
`SHA256SUMS`, `revoot.cdx.json`, `image-digest.txt`, and
`ghcr.io/getrevoot/revoot` tags with and without the leading `v`. GitHub
attestations bind the archives and image digest to the release workflow. It uses
the matching changelog section as the GitHub release notes. Stable releases also
update `latest`; prereleases do not. Deployment examples always use the immutable
digest rather than these convenience tags.

If a job fails, fix it and rerun the failed workflow. Never create release tags
by hand or move a published version tag to a different commit.
