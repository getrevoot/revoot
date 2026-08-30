# AGENTS.md

## Project overview

This repository contains the `revoot` Rust CLI. Keep changes portable across
Linux AMD64/ARM64 and Apple Silicon macOS. The supported distributable targets
are:

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
- Keep Linux releases statically linked with musl unless portability or
  operability requires otherwise.
- Never embed credentials, private keys, tokens, or private secrets in a
  binary. Stripping does not make embedded data secret.

## Validation

Run the standard suite before considering a change complete:

```sh
mise run ci
```

For packaging-related changes, also run:

```sh
mise run package:linux
mise run package:macos  # on an Apple Silicon macOS host
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
- Keep packaging tasks serialized because concurrent `cargo-zigbuild` processes
  can contend on shared wrapper files.
- Do not describe macOS artifacts as static musl binaries or as providing the
  Linux production containment posture.
