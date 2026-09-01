# CLI and agent integration

Revoot ships one native Rust executable. The review and scan engines call only
the direct Anthropic Messages or OpenAI Responses adapters; there is no
Bedrock, provider-compatible endpoint, model CLI, Node, or Bun runtime. The
binary neither depends on nor invokes a shell or Git executable. The OCI image
may carry Git for CI checkout compatibility, but Revoot does not execute it.
Code-host publication remains a separate deterministic stage.

## Review

```sh
revoot review [--base REF] [--effort low|medium|high] \
  [--max-parallel-groups 1-8] [--format human|json|sarif] [--output PATH]
revoot review --preview [--format human|json]
revoot review --ci [--preview] [--format human|json|sarif] [--output PATH]
revoot review --pr NUMBER [--repo OWNER/REPOSITORY]
revoot review --mr IID
```

`review --preview` is provider-free. It prepares and replay-validates the
immutable snapshot, deterministic selection, grouping inputs, effective rule
identifiers, and resource bounds without sending source to a model or
publishing anything. Preview does not support SARIF because it has no completed
findings.

A normal review uses the tool-first engine:

1. Deterministic selection assigns risk tiers and capacity. Selections of one
   to three files group locally; larger selections make at most one
   metadata-only grouping request.
2. Each group runs in isolation. A complete group diff is inlined once only
   when it is at most 16 KiB and the request stays within the context target.
   Larger groups start from file and hunk manifests, then use bounded reads and
   searches for the evidence they need.
3. Coverage is recorded from content actually delivered by inline context or a
   successful tool call. High-risk hunks require complete delivery; standard
   files require sampling, hazardous hunks, and dispositions; low-risk files
   may remain manifest-only under the fixed policy.
4. Candidate findings must target an assigned file and an exact issued anchor,
   cite delivered evidence, pass deterministic gates, and survive one bounded
   verifier request. A final adjudicator can rank or suppress verified
   candidates but cannot create a finding or move an anchor.
5. GitHub or GitLab publication runs outside the model after freshness and
   ownership checks.

The default effort is `medium` and the default group parallelism is four.
Shared request, token, tool, cost, output, and deadline budgets are reserved
before provider calls. Exhaustion stops new work and preserves verified
results. Incomplete required coverage, worker/tool/provider failure, or failed
verification makes the result partial. Policy-approved low-risk deferral is
reported but does not by itself fail the run. A partial review never marks a
prior finding fixed.

`--format json` emits `revoot.review-report/v3`. The report includes the
immutable snapshot and partition identities, findings with exact changed-side
coordinates, overview, lineage and publication state, deterministic selection,
strategy, risk-adaptive coverage, and exactly five usage phases in this order:
grouping, planning, review, verification, and adjudication. It contains bounded
consumer-facing finding prose and evidence, which may quote approved source,
but no prompts, raw provider responses, raw tool payloads, automatically
retained source pages, or temporary artifact paths.

`--format sarif` emits deterministic SARIF 2.1.0 for completed review results.
Locations resolve through the trusted anchor table: additions use the new
path/line, deletions use the old path/line, and context records retain both
sides. Paths are URI encoded, rules and fingerprints are stable, and an unknown
or line-zero anchor is rejected rather than replaced with a fabricated
location.

## Local scan

```sh
revoot scan [--path PATH]... [--include-untracked] [--preview] \
  [--format human|json|sarif]
```

Scan reviews bounded post-change file chunks and reuses the direct providers,
rules, finding gates, budgets, and exact-anchor SARIF renderer. It is local
output only and never publishes to a pull or merge request. `scan --preview` is
provider-free and supports human or JSON output. A completed scan requires a
provider credential and supports human, JSON, or SARIF output.

Tracked files are the default. `--include-untracked` is accepted only for an
explicit local invocation and is rejected whenever Revoot detects CI. Paths
supplied with `--path` must be safe repository-relative paths.

## Rules and delegation

```sh
revoot rules check <path...> [--json]
revoot delegate manifest
revoot delegate preview
revoot delegate rule <path...>
```

These commands are provider-free and do not discover provider credentials.
`rules check` reports the active rule identifiers and precedence for each path,
without emitting guidance bodies. Precedence is compiled safety, base-commit
repository guidance, matching repository rules, embedded language guidance,
then the generic review rule.

`delegate manifest` emits the canonical `revoot.agent-integration/v1` contract
without reading a repository, environment credentials, or provider settings.
It describes only the fixed provider-free CLI workflows and bounded stdio MCP
surface, and explicitly denies installation, editing, publication, network,
secret, and arbitrary-process authority.

The other delegation commands emit the snapshot-bound
`revoot.delegation/v1` metadata contract.
`delegate preview` covers selected changed paths; `delegate rule` narrows the
manifest to selected paths supplied by the caller. The manifest contains
identities, exclusions, and rule groups—not diffs, source bodies, credentials,
provider instructions, code-edit instructions, or raw Git commands.
Revoot's provider-neutral agent integration contract describes these CLI
workflows and the MCP allowlist; it does not auto-install anything or grant an
agent code-edit authority.

## Stdio MCP server

Start the server from the repository to inspect:

```sh
revoot mcp serve
```

Configure a host agent to launch that exact executable and arguments over
stdio. Revoot writes protocol JSON only to stdout. The server has no network
listener and exposes this fixed surface:

- `revoot_open_review`
- `revoot_list_changed_files`
- `revoot_read_diff`
- `revoot_read_file`
- `revoot_find_files`
- `revoot_search_code`
- `revoot_search_diff`
- `revoot_get_rules`
- `revoot_validate_findings`

`revoot_open_review` returns an opaque process-local handle bound to the
immutable local snapshot. Every other call requires that handle. Results are
bounded to 32 KiB, searches return at most 500 matches, and larger results use
authenticated cursors bound to the handle, snapshot, tool, query, and page.
Stale, tampered, or cross-snapshot handles and cursors fail closed.

MCP grants read and finding-validation authority only. It cannot call a model,
publish, write repository files, run commands, read credentials or arbitrary
environment values, make network requests, or launch another MCP server. Host
agents should use the Revoot tools instead of invoking raw Git or shell commands
for the review workflow.
