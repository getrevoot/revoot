# GitHub Actions operation

Revoot uses one full checked-out repository and one authoritative GitHub pull
request snapshot. The GitHub API file patches define changed-file scope and
inline-comment anchors. The checkout supplies broader context: unchanged files,
manifests, call sites, and tests remain available to bounded list/read/search
tools. Checkout content never replaces API identity or position authority.

## Install

Generate the canonical workflow and commit it:

```sh
mkdir -p .github/workflows
revoot init github > .github/workflows/revoot.yml
```

Add `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` as an Actions repository or
organization secret. The workflow gives `GITHUB_TOKEN` only `contents: read`
and `pull-requests: write`, checks out the exact pull-request head with persisted
credentials disabled, and invokes the single `revoot review --ci` operation.
All referenced actions are pinned to full commit IDs.

The default skips fork pull requests because GitHub does not expose ordinary
repository secrets to untrusted fork workflows. `--fork-behavior report-only`
removes the same-repository condition, but the runner still needs a safely
available provider credential; never use `pull_request_target` to expose secrets
while executing an untrusted checkout.

## Local and Enterprise use

On GitHub.com:

```sh
REVOOT_GITHUB_TOKEN=... ANTHROPIC_API_KEY=... revoot review --pr 42
```

When the checkout is a fork, select the upstream target without changing which
files Revoot explores:

```sh
revoot review --pr 42 --repo upstream/project
```

For GitHub Enterprise Server, set the exact HTTPS web origin. Revoot maps it to
the `/api/v3` REST root and rejects an unrelated remote host.

```sh
REVOOT_GITHUB_SERVER_URL=https://github.example.com \
  revoot review --pr 42 --repo platform/project
```

GitHub credentials are selected in this order:
`REVOOT_GITHUB_TOKEN`, `GH_TOKEN`, then `GITHUB_TOKEN`. Use a fine-grained token
or GitHub App installation token with repository contents read and pull-request
write access when inline publication is enabled.

## Publication and convergence

On every successful review, Revoot re-reads the exact open pull request and
updates one bounded, version-marked `<details>` block in its description. Text
outside that block is preserved byte for byte. The block contains the
implementation summary, overall risk, a minimal material-risk table,
assumptions or gaps, manual validation still required, and a footer identifying
the Revoot version, linked Actions run, provider/model, and reviewed commit.
Exact repeats are no-ops; duplicate or malformed ownership markers fail closed.

Before review, Revoot reads the complete bounded review-thread inventory through
GitHub GraphQL, including live resolved and outdated state, current and original
anchors, reply authorship, and timestamps. The reviewer must inspect that
inventory before it can submit findings or its final overview. Comment text
remains untrusted input. Revoot-owned comments carry an embedded lineage and
occurrence marker; semantic review, not that marker, decides whether a current
problem belongs to an existing lineage.

Before publication Revoot reacquires the discussion inventory and aborts if a
reply, edit, resolution, or new thread appeared during review. Before every
comment mutation it also re-reads the pull request and rejects a changed head.
Exact repeats and still-open lineages at the current anchor are no-ops. A moved
or outdated open finding is posted at its current anchor before the old thread
is resolved. Findings omitted after review remain open unless a complete
omission-free review explicitly adjudicates the lineage as fixed. Human-resolved
findings remain suppressed; only a Revoot-resolved finding may be reopened for a
confirmed recurrence. Human and foreign-bot threads can suppress a duplicate
but are never modified. Duplicate or malformed owned markers fail closed. The
pull request and its comments are the durable state store; retained Actions
artifacts are not required for reconciliation.

The owned overview contains a machine-readable review checkpoint for the last
published run. Because pull-request descriptions are author-editable, this
marker is never trusted to exclude code. Revoot verifies that its prior head is
an ancestor in the checked-out commit graph, computes the changed paths between
that head and the current head, and asks the reviewer to inspect those paths
first while keeping the complete pull-request diff available. Incomplete
coverage, a reviewer-policy change, rewritten history, an empty or excessive
delta, or two consecutive incremental passes forces full attention.
Revoot updates the overview checkpoint only after finding publication and
thread reconciliation succeed.

The Actions artifact contains the bounded JSON report. No finding is a normal,
successful terminal result and produces no empty `findings` payload.
