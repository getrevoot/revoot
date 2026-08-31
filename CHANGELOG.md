# Changelog

All notable changes to Revoot are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/getrevoot/revoot/releases/tag/v0.1.0) - 2026-08-31

### Changed

- Handle benign GitHub review state changes
- skip GitLab forks before external access
- unify sensitive model context filtering
- update GitLab component project links
- harden model and CI security boundaries
- avoid duplicate lineage when reanchoring
- Rename aggregate validation task to verify
- make GitHub thread resolution optional
- Automate release changelog preparation ([#6](https://github.com/getrevoot/revoot/pull/6))
- support full GitHub thread lifecycle auth
- treat bounded file listings as local evidence
- resolve fixed GitHub lineages from review state
- identify GitHub bot comments by account ID
- expose trusted anchors with review diffs
- separate selection and exploration budgets
- report exhausted review budget dimensions
- advance reviewer policy version
- make finding evidence suppression recoverable
- clarify provider rate limit failures
- include provider HTTP status in diagnostics
- report provider failure categories
- ignore unset provider credentials
- support Actions token review inventory
- prepare GitHub container workspace
- support runner-owned GitHub checkouts
- publish green main preview images
- refine README and branding
- add preview image dogfooding channel
- make the container image the primary distribution
- support GitHub variables for provider selection
- default CI to main and automatic provider selection
- start CI reviews alongside other checks
- Initial public release

### Fixed

- fix GitLab component merge request rule
- fix GitHub job container permissions
- fix README logo rendering
