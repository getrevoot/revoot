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

No GitHub token setup is required. Each job receives a short-lived
`GITHUB_TOKEN`; the workflow grants it package and repository read access plus
pull-request write access. Comments appear as `github-actions[bot]`. A branded
identity requires a GitHub App or bot-user token supplied as
`REVOOT_GITHUB_TOKEN`.

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
re-anchors open findings when needed, and does not repeat resolved findings
unless semantic review confirms that the issue recurred. Embedded metadata
identifies Revoot-owned comments; the pull request remains the state store.

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

The `Publish preview image` workflow builds an AMD64 image from any selected
branch without creating a GitHub release. Give it an RC or branch tag, then set
the repository variable `REVOOT_TAG` to that tag. Clear the variable to return
reviews to `latest`.

```sh
gh workflow run preview-image.yml --ref my-branch -f tag=rc-0.2.0-1
gh variable set REVOOT_TAG --body rc-0.2.0-1
```

## GitHub Enterprise Server

For GitHub Enterprise Server, provide its HTTPS origin. Revoot derives the
`/api/v3` REST endpoint:

```sh
REVOOT_GITHUB_SERVER_URL=https://github.example.com \
  revoot review --pr 42 --repo platform/project
```
