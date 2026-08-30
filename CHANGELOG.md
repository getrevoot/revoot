# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and
versions follow Semantic Versioning.

## Unreleased

### Added

- Provider-neutral, full-checkout automatic review for GitLab and GitHub.
- Exact host-authoritative diff anchoring and convergent publication.
- Multi-platform packaging, checksums, and container images.
- Multi-language and hostile-repository quality scenarios.
- Strict repository-root `.revoot.toml` policy with base-commit CI loading,
  bounded domain rules, and exact expiring finding suppressions.
- Consequence-first reviewer policy that uses design principles as hypotheses
  while rejecting maintainability-only and conformity-based comments.
- Zero-argument local branch review across committed, staged, unstaged, and
  non-ignored untracked changes, with deterministic base inference, frozen
  local anchors, Git-aware checkout exploration, and stale-state detection.
- GitHub-primary pull-request validation and release automation, including one
  multi-architecture `ghcr.io/getrevoot/revoot` image consumed by both code
  hosts.
- Host-backed finding lineages and semantic prior-discussion review, allowing
  CI runs to carry, suppress, resolve, or reopen findings without an external
  state service or duplicate inline comments.
- Straightforward tag-driven release automation for archives and container
  images.
- Version-lockstep release checks, consistent command-group help, and release
  installation guidance.

### Removed

- The embedded OpenCode runtime-kit, external capsule, and runtime-store
  architecture.
- The unused hosted control-plane, webhook, tenant-governance, and worker-fleet
  implementation.
- Source-repository mirroring and the release-authoritative root GitLab
  pipeline; GitLab support now ships through a thin component and acceptance
  project backed by GitHub release artifacts.

No release has been published yet.
