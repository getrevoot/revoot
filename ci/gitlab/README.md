# Revoot for GitLab

This directory is the canonical upstream source for Revoot's small GitLab CI
component. The Revoot product repository remains on GitHub and publishes one
multi-architecture image to `ghcr.io/getrevoot/revoot`.

The separate `gitlab.com/getrevoot/revoot-ci` project contains the released copy
of `components/review/template.yml` and deterministic merge-request fixtures.
It tests the published image; it does not mirror or build the Rust source.

For self-managed GitLab, copy the component project to the target instance and
pin the component commit and GHCR image digest as shown under `self-managed/`.
