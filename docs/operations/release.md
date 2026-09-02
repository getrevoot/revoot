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

The release-plz task uses a narrow Cargo wrapper for its git-only comparison of
the previous tag. For release-plz's workspace-package command only, the wrapper
temporarily makes the unpublished internal crate eligible for Cargo's local
workspace registry, supplies the version missing from the bootstrap tag, and
adds `--no-verify`. It then unpacks Cargo's locally generated archives for
release-plz and restores both manifests with a trap. Normal project packaging
and all other Cargo commands are forwarded unchanged, no crate is published,
and `mise run verify` remains the release build gate.

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
mise run package:oci
mise run release:checksums
mise run sbom
mise run install:cargo:smoke
```

`package:macos` requires an Apple Silicon macOS host. `package:oci` consumes
the Linux release binaries and must run after `package:linux`; it builds and
smoke-tests both non-root image architectures.

For a tool-first engine release, also verify the user-facing contracts before
promotion:

- `revoot review --help`, `revoot scan --help`,
  `revoot rules check --help`, and `revoot delegate --help` match the
  documented CLI, while stdio MCP discovery lists only the documented tools;
- provider conformance covers direct Anthropic Messages and OpenAI Responses,
  batched tools, rebased turns, missing usage, cancellation, and malformed
  responses, with no Bedrock or generic-endpoint fixture;
- the stable JSON golden is `revoot.review-report/v3` with five ordered usage
  phases, and review/scan SARIF 2.1.0 goldens use exact non-zero anchors;
- preview, rule diagnostics, and delegation complete without provider
  credentials or calls; and
- Linux artifacts remain static and stripped, macOS remains ARM64-native and
  stripped, and the shipped executable has no Go, Node, Bun, model CLI, shell,
  or Git runtime dependency.

The OCI image may contain Git for CI checkout compatibility, but Revoot must
not execute it. Packaging smoke tests should continue to assert that repository
hooks and reviewed code are never run and that the image process drops to its
documented non-root identity.

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

If a job fails because of a transient infrastructure problem, rerun the failed
workflow. If a deterministic defect in the tagged source caused the failure,
fix it on `main` and prepare the next patch release. Never create release tags
by hand or move an existing version tag to a different commit.
