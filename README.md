# Revoot

**Independent review for agent-written code.**

**Bring your own keys:** use your Anthropic API key for Claude or your OpenAI
API key for Codex. Revoot calls the model directly from your machine or CI
runner—there is no Revoot service or hosted control plane.

Revoot gives every change a fresh reviewer whose job is to make the
implementation better. It reviews a local branch, GitHub pull request, or
GitLab merge request; investigates the full checked-out repository; and reports
high-value improvements tied to the exact change.

Those improvements may address correctness, maintainability, unnecessary
complexity, reliability, security, performance, compatibility, or missing
tests. Revoot is not limited to proving that code is broken. It asks whether the
change is the best version of itself for the codebase it is joining.

It is an open-source Rust CLI that runs locally or in your CI job.

> Revoot is pre-1.0. The product contract is taking shape, but releases and
> compatibility guarantees are not yet stable.

## Why Revoot exists

AI made writing code dramatically cheaper. It did not make good engineering
judgment automatic, and it did not make an agent good at challenging its own
assumptions.

An implementation agent works inside a context it created: its interpretation
of the task, its plan, and the decisions it has already defended. Asking that
same loop to review its output is still self-review. More iterations can improve
the implementation, but they often preserve the same blind spots and design
choices.

Independent review works for a different reason. A fresh agent starts with a
different objective: assume nothing, inspect the change in its real repository,
and look for ways it can be safer, simpler, clearer, and more durable. The
reviewer does not need to be a larger model than the implementer. It needs
separate context, a narrow role, and enough access to understand the tradeoffs
and consequences of the change.

That is Revoot's job.

## What Revoot does

1. **Captures the real change.** Locally, that includes committed branch work,
   staged and unstaged edits, and non-ignored untracked files. In CI, GitHub or
   GitLab supplies the authoritative diff and inline-comment positions.
2. **Investigates beyond the diff.** Changed files define the review scope, but
   the full checkout supplies context. The reviewer can trace callers, read
   unchanged dependencies, inspect manifests, find violated assumptions, and
   recognize complexity that the surrounding design does not require.
3. **Understands the change narrative.** Revoot reads the bounded commit range
   between the exact base and head, using subjects and selected commit messages
   as untrusted context about intent. Claims in that history still have to be
   verified against the code. Shallow or truncated history is reported rather
   than silently treated as complete.
4. **Returns a review, not more code.** Revoot validates, ranks, deduplicates,
   and anchors actionable findings before reporting them. On a pull or merge
   request it also maintains a compact overview of the implementation, overall
   risk, material risk areas, assumptions or gaps, and any manual validation
   still required. It does not patch the checkout, run a shell, or turn into
   another implementation agent.

The diff tells Revoot where to start. The repository tells it whether the
change fits—and how it can be improved.

Revoot is intentionally not a generic style bot, a general-purpose coding
agent, or a reason to manufacture comments. A clean review is a successful
result.

### Attention is a budget

Revoot classifies changed files before it calls a model. High-signal surfaces
such as authentication, migrations, public interfaces, dependency manifests,
and deployment configuration receive attention first. Ordinary source and test
changes follow. Lockfiles, generated output, snapshots, minified assets, and
documentation receive a small shared low-signal budget. Binary contents are not
sent to the reviewer.

Classification is not a blind extension filter. Cheap local scans can promote
an otherwise noisy artifact when it contains a structural hazard—for example,
a merge-conflict marker or private credential material added to a lockfile.
Selected and deferred counts are included in review output alongside actual
token and cost usage.

This ordering is internal and automatic. Revoot should spend attention where it
can change an engineering decision, not make every repository owner tune an
agent workflow.

## Quick start

### Install

Install the pinned release through mise:

```sh
mise use --global github:getrevoot/revoot@0.1.0
revoot --version
```

Release archives for Linux AMD64, Linux ARM64, and Apple Silicon macOS are also
available from the GitHub release. Verify the selected archive against the
published `SHA256SUMS` before placing `revoot` on `PATH`. Every archive includes
the binary, shell completions, and the project license.

To install from a checkout instead:

```sh
mise install
cargo install --locked --path crates/revoot
```

The release also publishes a checksum-pinned Homebrew formula for downstream
tap installation and one non-root multi-architecture image at
`ghcr.io/getrevoot/revoot`. Production CI configuration should pin the image digest
recorded in the release rather than a mutable tag.

### Review your current work

Provide one supported model-provider credential:

```sh
export ANTHROPIC_API_KEY=...
# or: export OPENAI_API_KEY=...
```

Then run this from any branch with committed or uncommitted work:

```sh
revoot review
```

No pull request, code-host token, Git executable, or review mode is required by
the Revoot process. Revoot infers the
default branch, finds the merge base, captures the complete working state, and
uses the admitted checkout—including non-ignored untracked files—for read-only
investigation. Git repositories and packed objects are read in-process by the
portable binary; repository hooks, filters, diff drivers, and commands are not
executed.

If the intended target is not the default branch, specify only the comparison
base:

```sh
revoot review --base origin/release
```

Revoot never fetches, stages, commits, or modifies the checkout. If the working
state changes during review, the result is marked stale. If there is nothing to
review, it exits successfully without contacting the model provider.

A real review sends the changed code and any repository context the reviewer
chooses to inspect directly to your configured provider. Revoot does not proxy
or retain that content.

## Put Revoot in CI

The same `revoot review` operation runs locally and on both supported code
hosts. CI adds authoritative change-request identity and inline publication.
Before model work it also reads the code host's bounded discussion inventory.
The reviewer interprets open, resolved, human, foreign-bot, and Revoot-owned
threads so an existing logical issue is carried, suppressed, resolved, or
reopened instead of reposted. Revoot embeds lineage metadata in its own comments;
the pull or merge request remains the durable state store and no external state
service is required. Reply authorship, current and original anchors, timestamps,
and resolution history are retained as structured context rather than folded
into an unattributed text blob. The discussion inventory is compared again
immediately before publication so a human action during review stops mutation
instead of racing it.
Existing owned threads are resolved only from an explicit `fixed` disposition
produced by a complete, omission-free review. A missing, partial, failed, or
uncertain result preserves prior findings unchanged.

The owned overview also carries a bounded review checkpoint. On a later commit,
Revoot accepts it only as an attention hint after verifying locally that the old
head is an ancestor and deriving the exact tree delta. The reviewer starts with
those newly changed paths but retains the full pull or merge request as scope.
Incomplete reviews, policy changes, rewritten history, excessive deltas, and
periodic full-attention intervals ignore the hint. This deliberately avoids
treating author-editable metadata as authority to skip code.
The checkpoint is published only after finding comments and thread transitions
converge, so a partial publication cannot advance review state.

### GitHub Actions

Generate and commit the workflow:

```sh
mkdir -p .github/workflows
revoot init github > .github/workflows/revoot.yml
```

The workflow checks out the pull-request head, runs `revoot review --ci`, and
uses the short-lived `GITHUB_TOKEN` to update Revoot's bounded overview in the
pull-request description and publish inline findings. Fork pull requests are
skipped by default so repository secrets are not exposed.

See [GitHub Actions operation](docs/operations/github-actions.md) for enterprise
hosts, token permissions, and safe fork behavior.

### GitLab CI

Generate and commit the component include:

```sh
revoot init gitlab > revoot-review.yml
```

Add the generated include to your pipeline and configure a provider secret. Set
a masked `REVOOT_GITLAB_TOKEN` to update Revoot's bounded overview in the
merge-request description and publish inline findings. A GitLab `CI_JOB_TOKEN`
can acquire review context but cannot update the merge request or create
discussions, so Revoot reports without publishing when write authority is not
available.

The GitLab component is maintained in a small acceptance project and consumes
the same image published by the canonical GitHub release.

### Review an existing pull or merge request

```sh
# GitHub
REVOOT_GITHUB_TOKEN=... revoot review --pr 42

# GitLab
REVOOT_GITLAB_TOKEN=... revoot review --mr 42
```

Provider credentials are still required when the change contains reviewable
work. Use `--format json` for machine-readable output or `--output PATH` to
write the report to a file. Run `revoot review --help` for the complete command
syntax.

### The pull or merge request overview

Revoot preserves the author's description and owns only one hidden,
version-marked `<details>` block. Successive pushes replace that block instead
of appending another report. The collapsed header shows the overall risk; the
body contains a short implementation summary, at most four material risk rows,
assumptions or gaps, and manual validation that automation could not establish.
It deliberately omits status and finding counts because the code host already
shows those.

The footer binds the overview to the tool, provider, model, commit, and—when
running in CI—the exact job:

```text
revoot/0.1.0 reviewed via anthropic/claude-opus-5 at abc123def456
```

`reviewed` is a link to the GitHub Actions run or GitLab CI job. Duplicate or
malformed ownership markers stop publication rather than risking replacement
of author-written content.

## Configuration

Configuration is optional. Add `.revoot.toml` at the repository root to define
review scope, confidence and finding limits, generated-file handling, domain
guidance, path-specific priorities, budgets, and exact expiring suppressions.

```toml
version = 1

[review]
exclude = ["vendor/**", "dist/**"]
minimum_confidence = 80
max_findings = 12

[repository]
guidance = "Every externally retried write must be idempotent."

[[rules]]
paths = ["src/payments/**"]
focus = ["authorization", "idempotency"]
```

Revoot reads this file from the exact base commit in local and CI review, so a
proposed change cannot weaken its own review. See the complete
[configuration reference](docs/configuration.md).

## Deliberate boundaries

The separation between implementation and review is enforced in Revoot's
interfaces, not left to a prompt:

- every review starts from a fresh brief, never an implementer transcript;
- the reviewer receives bounded read, list, search, and diff tools;
- commit subjects and messages are bounded, snapshot-bound, and treated as
  untrusted context rather than instructions;
- the review engine has no write, patch, or shell capability;
- the exact diff remains the authority for scope and finding anchors;
- the full checkout is available when broader context is crucial;
- repository content cannot select credentials, grant network access, add
  tools, or enable publication; and
- deterministic code validates and filters model-generated candidates before
  they become findings.

Principles such as SOLID, DRY, KISS, and YAGNI can suggest questions, but they
are not findings by themselves. A finding must explain the concrete impact or
improvement, not merely cite an acronym or stylistic preference.

There is no hosted Revoot control plane. The binary and credentials run in your
environment, and teams choose their own supported provider and model.

## Providers

Revoot currently includes direct adapters for Anthropic Messages and
OpenAI-compatible Responses APIs. Provider calls are bounded,
cancellation-aware, and made directly from the local process or CI runner.

New adapters must satisfy the
[provider conformance requirements](docs/provider-conformance.md).

## Development

The repository uses pinned tools from `mise.toml`:

```sh
mise install
mise run ci
```

The full suite formats, lints, tests, and checks the supported cross-compilation
targets. See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

Security issues can be reported privately as described in
[SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
