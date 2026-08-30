# Contributing to Revoot

Contributions are welcome. Open an issue for significant behavioral changes and
submit code through the canonical GitHub repository. Pull requests are the only
code contribution path; the small GitLab component project is an acceptance and
distribution fixture, not a source mirror.

## Development

Install the pinned toolchain and run the required checks:

```sh
mise install
mise run ci
```

Use stable Rust 2024, keep Clippy clean with warnings denied, prefer maintained
pure-Rust dependencies, and add tests for behavior changes. Keep `Cargo.lock`
committed and do not add a separate Rust toolchain file.

Provider adapters must follow the
[conformance requirements](docs/provider-conformance.md). Packaging changes must
preserve the supported Linux AMD64/ARM64 musl and Apple Silicon targets and pass
the relevant packaging tasks.

Never commit credentials, private repository source, raw prompts, raw model
responses, or private fixtures. By contributing, you agree that your
contribution is licensed under Apache-2.0, as described in section 5 of the
project license.
