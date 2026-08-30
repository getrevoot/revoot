# Revoot

**Independent review for agent-written code.**

**Bring your own keys:** use an Anthropic API key for Claude or an OpenAI API
key for Codex. Revoot calls the provider directly from your machine or CI
runner. There is no Revoot service or hosted control plane.

Revoot is an open-source Rust CLI that reviews local changes, GitHub pull
requests, and GitLab merge requests. It starts with the diff, investigates the
full checkout when needed, and reports actionable findings on the changed
lines. A clean review is a successful result.

> Revoot is pre-1.0. Interfaces may change between minor releases.

## Run with Docker

The versioned container image is the simplest way to run Revoot. Set one
provider key, mount the repository read-only, and start a review:

```sh
export OPENAI_API_KEY=...

docker run --rm \
  --volume "$PWD:/workspace:ro" \
  --workdir /workspace \
  --env OPENAI_API_KEY \
  ghcr.io/getrevoot/revoot:0.1.0 review
```

For Claude, set and pass `ANTHROPIC_API_KEY` instead. The image supports Linux
AMD64 and ARM64; native Linux and Apple Silicon macOS archives are also attached
to each GitHub release.

Revoot reviews committed branch changes, staged and unstaged edits, and
non-ignored untracked files. It infers the default branch; use `--base` to
override it:

```sh
docker run --rm \
  --volume "$PWD:/workspace:ro" \
  --workdir /workspace \
  --env OPENAI_API_KEY \
  ghcr.io/getrevoot/revoot:0.1.0 review --base origin/release
```

Revoot does not modify the checkout or execute repository code. Reviewed code
and selected repository context are sent directly to your configured provider.

## Install a native binary

Each [GitHub release](https://github.com/getrevoot/revoot/releases) includes
archives for Linux AMD64, Linux ARM64, and Apple Silicon macOS, plus a
`SHA256SUMS` file. Download the matching archive:

| System | Release asset |
| --- | --- |
| Linux x86-64 | `revoot-linux-amd64.tar.gz` |
| Linux ARM64 | `revoot-linux-arm64.tar.gz` |
| Apple Silicon macOS | `revoot-macos-arm64.tar.gz` |

Verify the archive against `SHA256SUMS`, then extract and install the binary on
your `PATH`:

```sh
archive=revoot-macos-arm64.tar.gz # choose from the table above

awk -v archive="$archive" '$2 == archive' SHA256SUMS | shasum -a 256 --check -
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 0755 revoot "$HOME/.local/bin/revoot"
revoot --version
```

On Linux, use `sha256sum --check -` if `shasum` is unavailable. Ensure
`$HOME/.local/bin` is on your `PATH`. Native installations can use the shorter
`revoot review` and `revoot init` commands in place of the Docker invocations.

## Run in CI

CI reviews publish each actionable finding as a native review comment anchored
to the relevant changed line. Revoot also maintains one compact summary in the
pull or merge request description, covering the implementation, overall risk,
material concerns, and validation gaps.

The generated review job starts alongside other CI checks by default.

As new commits are pushed, Revoot updates that summary in place and reconciles
the existing line comments with the latest code. The review evolves with the
change instead of appending a disconnected report on every run.

For GitHub Actions:

```sh
mkdir -p .github/workflows
docker run --rm ghcr.io/getrevoot/revoot:0.1.0 init github \
  > .github/workflows/revoot.yml
```

For GitLab CI:

```sh
docker run --rm ghcr.io/getrevoot/revoot:0.1.0 init gitlab \
  > revoot-review.yml
```

Add the generated file to the repository, configure `ANTHROPIC_API_KEY` or
`OPENAI_API_KEY` as a CI secret, and follow the generated instructions. On
GitHub, optional Actions variables named `REVOOT_PROVIDER` and `REVOOT_MODEL`
override the generated `auto` defaults. The
[configuration reference](docs/configuration.md) lists every supported
environment and CI variable, including defaults and precedence. See the
[GitHub](docs/operations/github-actions.md) and
[GitLab](docs/operations/gitlab-component.md) guides for permissions and
self-managed hosts.

Existing pull and merge requests can also be reviewed directly:

```sh
docker run --rm \
  --volume "$PWD:/workspace:ro" \
  --workdir /workspace \
  --env OPENAI_API_KEY \
  --env REVOOT_GITHUB_TOKEN \
  ghcr.io/getrevoot/revoot:0.1.0 review --pr 42
```

For GitLab, pass `REVOOT_GITLAB_TOKEN` and use `review --mr 42` instead.

### No duplicate review threads

Before each CI review, Revoot reads the existing discussion threads. Embedded,
versioned metadata identifies Revoot-owned comments, while the reviewer uses
the text, code context, anchors, replies, and resolution state to interpret
whether a new finding is the same logical issue—not just whether it has the
same fingerprint.

Resolved findings stay resolved unless the reviewer concludes that the issue
has actually recurred. Open findings can be carried forward or re-anchored, and
obsolete findings can be resolved. The pull or merge request is the state
store; no external database is required.

Later commits use the previous completed review as an attention hint, so Revoot
starts with what changed instead of blindly reviewing everything again. The
full pull or merge request remains in scope, and incomplete reviews never
advance that checkpoint.

## Configuration

Configuration is optional. Add `.revoot.toml` at the repository root:

```toml
version = 1

[review]
exclude = ["vendor/**", "dist/**"]
minimum_confidence = 80
max_findings = 12

[[rules]]
paths = ["src/payments/**"]
focus = ["authorization", "idempotency"]
```

The [configuration reference](docs/configuration.md) also covers repository
fields, guidance, budgets, and finding suppressions.

Use `revoot review --help` for command options and `--format json` for
machine-readable output.

## Development

```sh
mise install
mise run ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

[Apache License 2.0](LICENSE)
