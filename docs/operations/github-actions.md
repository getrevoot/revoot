# GitHub Actions

## Set up

Generate and commit the workflow:

```sh
mkdir -p .github/workflows
revoot init github > .github/workflows/revoot.yml
```

Add either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` as a repository or
organization secret. Optional Actions variables `REVOOT_PROVIDER` and
`REVOOT_MODEL` override the `auto` defaults.

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

Revoot reads existing review threads before each run. It updates one summary,
re-anchors findings when needed, and does not repeat an established finding
unless semantic review confirms that the issue recurred. Human-resolved
findings remain suppressed unless review establishes a materially new
occurrence. Embedded metadata identifies Revoot-owned comments; the pull
request remains the state store.

Revoot checks the pull-request head and discussion state again before writing.
It stops publication if either changed during the review. Human and other bot
comments may suppress duplicates but are never modified.

## Manual use

For a manual review, provide a token with repository contents read and pull
request write access:

```sh
REVOOT_GITHUB_TOKEN=... OPENAI_API_KEY=... revoot review --pr 42
```

Credentials are checked in this order: `REVOOT_GITHUB_TOKEN`, `GH_TOKEN`, then
`GITHUB_TOKEN`.

## Revoot repository dogfooding

After CI succeeds for a trusted push to `main`, `Publish preview image` publishes
AMD64 `main` and immutable `sha-*` images without creating a GitHub release.
This repository sets `REVOOT_TAG=main` to dogfood the newest green build.

Manual dispatch can publish an RC or branch tag. Point `REVOOT_TAG` at that tag
for testing, set it back to `main` afterward, or clear it to use `latest`.

```sh
gh workflow run preview-image.yml --ref my-branch -f tag=rc-0.2.0-1
gh variable set REVOOT_TAG --body rc-0.2.0-1
gh variable set REVOOT_TAG --body main
```

## GitHub Enterprise Server

For GitHub Enterprise Server, provide its HTTPS origin. Revoot derives the
`/api/v3` REST endpoint:

```sh
REVOOT_GITHUB_SERVER_URL=https://github.example.com \
  revoot review --pr 42 --repo platform/project
```
