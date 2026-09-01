# GitHub Actions

## Set up

Generate and commit the workflow:

```sh
mkdir -p .github/workflows
REVOOT_IMAGE='ghcr.io/getrevoot/revoot:VERSION@sha256:DIGEST'
revoot init github --image "$REVOOT_IMAGE" > .github/workflows/revoot.yml
```

Copy the digest from the matching release's `image-digest.txt`. Mutable image
tags are rejected. If you use the checked-in workflow template directly, set
the repository variable `REVOOT_IMAGE` to the same immutable reference.

Add either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` as a repository or
organization secret. Optional Actions variables `REVOOT_PROVIDER` and
`REVOOT_MODEL` override the `auto` defaults.

Revoot calls the selected Anthropic or OpenAI API directly. The workflow does
not install or launch a model CLI, Node, Bun, or another agent harness, and
Revoot does not support Bedrock. The binary inspects the checkout through its
embedded Git implementation and does not invoke Git, repository hooks, a
shell, or reviewed code during the review.

## Review execution and report

The generated job runs the tool-first engine with a ten-minute job timeout. It
selects and risk-ranks files deterministically, uses metadata-only semantic
grouping when needed, and runs isolated groups with bounded read/search tools.
Large group diffs are not copied into every model turn. Coverage in the report
is based on hunk pages actually delivered to workers.

The job writes `revoot-review.json` and uploads it for seven days even when a
later publication step fails. The file uses `revoot.review-report/v3` and
contains exact finding coordinates, overview, lineage/publication state,
selection, strategy, risk-adaptive coverage, and five reconciled usage phases.
It contains bounded consumer-facing finding prose and evidence, which may quote
approved source, but no prompts, raw responses, raw tool payloads,
automatically retained source pages, or temporary diff paths.

Budget exhaustion or incomplete required coverage returns verified findings as
an explicitly partial review and stops new group dispatch. A partial review
never resolves an existing lineage automatically. Publication failure remains
exit status 3; a computed partial review is not itself a publication failure.
Set `REVOOT_REVIEW_EFFORT` and `REVOOT_MAX_PARALLEL_GROUPS`, or use the
corresponding local CLI flags, to change operator-owned effort and concurrency.
The repository configuration can only lower resource ceilings.

No extra GitHub token is required to publish comments and the evolving summary.
The generated workflow grants its short-lived `GITHUB_TOKEN` repository read
and pull-request write access; comments appear as `github-actions[bot]`. Revoot
embeds lineage metadata in those comments and the overview, so fixed findings,
duplicate prevention, human resolution, and recurrence tracking do not depend
on GitHub's conversation-resolution mutation.

GitHub does not allow that Actions installation token to resolve or reopen
review threads. Revoot treats that denial as non-fatal: publication and the
checkpoint complete, the report records
`github_thread_resolution_unavailable`, and the conversation remains available
for manual resolution. An outdated conversation is not the same as a resolved
conversation; changing its code does not automatically mark it resolved.

If automatic resolve and reopen behavior is required, use a private GitHub App
installed only on the target repositories with pull-request read/write access.
Generate its short-lived installation token in the workflow and pass that token
as `REVOOT_GITHUB_TOKEN`. Do not use a developer's personal access token for
durable CI automation. GitHub recommends Apps for organization automation and
long-lived integrations; see [deciding when to build a GitHub App][github-app]
and [authenticating as an installation][github-app-token].

[github-app]: https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/deciding-when-to-build-a-github-app
[github-app-token]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation

## Scheduling and forks

The generated workflow starts with the other pull-request workflows. GitHub
has no cross-workflow final stage. To wait for specific checks, put the review
job in the same workflow and reference those jobs with `needs`.

Fork pull requests are skipped because provider secrets and write tokens are
not normally available to them. Do not use `pull_request_target` to run a fork
checkout with secrets. `--fork-behavior report-only` is available only when a
provider credential can be supplied safely.

## Subsequent pushes

Revoot reads existing review threads before each run. It updates one summary
and does not repeat an established finding unless semantic review confirms that
the issue recurred. When GitHub permits thread resolution, Revoot can retire an
old thread and publish the recurrence at its current exact issued anchor. It
never asks the model to relocate an old target. Otherwise it retains the
existing open lineage instead of creating a second active conversation, while
recording the current occurrence in the overview. Human-resolved findings
remain suppressed unless review establishes a materially new occurrence.
Embedded metadata identifies Revoot-owned comments; the pull request remains
the state store.

Revoot checks the pull-request head and discussion state again before writing.
It stops publication if either changed during the review. When ordinary human
review changes the discussion inventory before Revoot has attempted a mutation,
the JSON report records publication state `stopped` with reason
`github_review_state_changed`, retains the computed review artifact, and the
review command exits successfully. A later run reconciles against the new
authoritative state. Changed pull-request identity, ambiguous ownership,
transport failures, and partial or uncertain mutations remain failures. Human
and other bot comments may suppress duplicates but are never modified.

## Manual use

For a manual review, provide a token with repository contents read and pull
request write access:

```sh
REVOOT_GITHUB_TOKEN=... OPENAI_API_KEY=... revoot review --pr 42
```

Use `revoot review --pr 42 --preview --format json` to inspect the immutable
selection, grouping/rule metadata, and budgets without discovering provider
credentials, calling a model, or publishing. SARIF is available only for a
completed review and resolves locations through exact issued anchors.

Credentials are checked in this order: `REVOOT_GITHUB_TOKEN`, `GH_TOKEN`, then
`GITHUB_TOKEN`.

## Revoot repository dogfooding

Pull requests dogfood their own Revoot changes automatically. The review
workflow builds the pull request's AMD64 binary without credentials, publishes
it as `ghcr.io/getrevoot/revoot:pr-N`, and runs the review job from that image.
The PR-scoped tag is replaced on each push, and workflow concurrency prevents
an older review run from continuing after a newer push. A cleanup workflow
deletes the image when the pull request closes and reconciles stale PR images
weekly.

## GitHub Enterprise Server

For GitHub Enterprise Server, provide its HTTPS origin. Revoot derives the
`/api/v3` REST endpoint:

```sh
REVOOT_GITHUB_SERVER_URL=https://github.example.com \
  revoot review --pr 42 --repo platform/project
```
