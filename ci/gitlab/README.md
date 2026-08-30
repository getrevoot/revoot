# Revoot for GitLab

This directory is the canonical upstream source for Revoot's small GitLab CI
component. The Revoot product repository remains on GitHub and publishes one
multi-architecture image to `ghcr.io/getrevoot/revoot`.

The separate `gitlab.com/getrevoot/revoot-ci` project contains the released copy
of `components/review/template.yml` and deterministic merge-request fixtures.
It tests the published image; it does not mirror or build the Rust source.

The review job is grouped in the always-defined `.post` stage but starts
immediately because its `needs` input defaults to an empty list. Pass job names
through `needs` to wait for specific checks. If Revoot is the pipeline's only
job, override `stage` to `test` because GitLab does not run pipelines containing
only `.pre` or `.post` jobs.

For self-managed GitLab, copy the component project to the target instance and
pin the component commit and GHCR image digest as shown under `self-managed/`.
