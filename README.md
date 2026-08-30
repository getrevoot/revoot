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

## Install

With [mise](https://mise.jdx.dev/):

```sh
mise use --global github:getrevoot/revoot@0.1.0
```

Or install from a checkout:

```sh
mise install
cargo install --locked --path crates/revoot
```

Release archives support Linux AMD64, Linux ARM64, and Apple Silicon macOS. A
multi-architecture image is published at `ghcr.io/getrevoot/revoot`.

## Review local changes

Set one provider key and run the review:

```sh
export ANTHROPIC_API_KEY=...
# or: export OPENAI_API_KEY=...

revoot review
```

Revoot reviews committed branch changes, staged and unstaged edits, and
non-ignored untracked files. It infers the default branch; use `--base` to
override it:

```sh
revoot review --base origin/release
```

Revoot does not modify the checkout or execute repository code. Reviewed code
and selected repository context are sent directly to your configured provider.

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
revoot init github > .github/workflows/revoot.yml
```

For GitLab CI:

```sh
revoot init gitlab > revoot-review.yml
```

Add the generated file to the repository, configure `ANTHROPIC_API_KEY` or
`OPENAI_API_KEY` as a CI secret, and follow the generated instructions. On
GitHub, optional Actions variables named `REVOOT_PROVIDER` and `REVOOT_MODEL`
override the generated `auto` defaults. See the
[GitHub](docs/operations/github-actions.md) and
[GitLab](docs/operations/gitlab-component.md) guides for permissions and
self-managed hosts.

Existing pull and merge requests can also be reviewed directly:

```sh
REVOOT_GITHUB_TOKEN=... revoot review --pr 42
REVOOT_GITLAB_TOKEN=... revoot review --mr 42
```

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

See the [configuration reference](docs/configuration.md) for repository fields,
every supported environment variable, defaults, credentials, and precedence.

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
