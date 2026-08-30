# AGENTS.md

## Project overview

Revoot is a Rust-based, independent AI code reviewer for pull and merge
requests. It runs in CI, calls Anthropic or OpenAI directly with user-provided
credentials, and publishes line-specific findings plus an evolving review
summary. It has no hosted service or external state store.

The workspace contains the `revoot` CLI and the reusable `revoot-core` crate.
Keep changes portable across the supported distribution targets:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `aarch64-apple-darwin`

## Tooling

- Use `mise` for Rust, Zig, Cargo utilities, and project tasks.
- Respect the versions declared in `mise.toml`; do not introduce an independent
  `rust-toolchain.toml` or require globally installed project tools.
- Pin new stable tools to their major release line. For pre-1.0 tools, pin the
  compatible minor line because minor releases may contain breaking changes.
- Keep `Cargo.lock` committed and use `--locked` for distribution builds.

## Development conventions

- Use stable Rust and the Rust 2024 edition.
- Format with `rustfmt` and keep Clippy clean with warnings denied.
- Prefer pure-Rust dependencies. Avoid system-library dependencies where a
  maintained pure-Rust alternative exists, especially dynamic OpenSSL bindings.
- Add or update tests when behavior changes.
- Keep checkout inspection read-only. Revoot must not execute reviewed code or
  modify the repository being reviewed.
- Keep pull requests and merge requests as the review state store; do not add a
  hosted control plane or database without an explicit architectural decision.
- Provider adapters must follow `docs/provider-conformance.md` and keep provider
  wire types out of the agent and findings domains.
- Keep Linux releases statically linked with musl unless portability or
  operability requires otherwise.
- Never commit or expose credentials, private source, raw prompts, raw model
  responses, or private fixtures. Errors and telemetry must remain
  payload-free.

## Validation

Run the standard suite before considering a change complete:

```sh
mise run ci
```

For packaging-related changes, also run:

```sh
mise run package:linux
mise run package:macos  # on an Apple Silicon macOS host
mise run package:oci
```

Verify Linux release artifacts are static and stripped and Linux debug artifacts
are static and retain debug information. Verify the macOS release is a stripped
ARM64 Mach-O executable and runs on Apple Silicon. When Docker is available,
smoke-test relevant Linux artifacts on musl- and glibc-based images for both
architectures.

## Distribution policy

- Release archives contain stripped, optimized binaries and must not leak local
  build paths or debug symbols.
- Debug archives retain symbols for diagnostics and must be clearly named with
  the `-debug` suffix.
- Preserve executable permissions inside `.tar.gz` archives.
- Write generated archives to `dist/`; do not commit `dist/` or `target/`.
- OCI images must run as a non-root user and support Linux AMD64 and ARM64.
- Keep packaging tasks serialized because concurrent `cargo-zigbuild` processes
  can contend on shared wrapper files.
- Do not describe macOS artifacts as static musl binaries or as providing the
  Linux production containment posture.

## Documentation

- Keep user-facing behavior aligned across `README.md`, `docs/configuration.md`,
  and the GitHub and GitLab operations guides.
- Let release-plz update `CHANGELOG.md` from commits when preparing a release.
  Keep an `Unreleased` section, and ensure every dated version section maps to
  its exact `v<version>` tag.
- Follow `SECURITY.md` for vulnerability reporting and `CONTRIBUTING.md` for
  contribution policy.
