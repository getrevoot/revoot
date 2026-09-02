# Tool-First Review Engine Handoff

Last updated: 2026-09-01 (America/Denver)

## Current state

- Repository: `getrevoot/revoot`
- Pull request: [#30](https://github.com/getrevoot/revoot/pull/30)
- Branch: `tool-first-review-engine`
- Current pushed tip: `e9c97538765ad4f25e644464af65ee122f572ab5`
- Version: `0.3.0`
- Active dogfood run: [33577710137](https://github.com/getrevoot/revoot/actions/runs/33577710137)
- Active CI run: [33577710162](https://github.com/getrevoot/revoot/actions/runs/33577710162)
- Every commit in `main..HEAD` has a verified 1Password-backed ED25519 signature.
- The user-owned untracked file `docs/plans/review-engine-benchmarking.md` has not been modified, staged, or committed.

The architectural port and immediate cutover are implemented. The remaining active gate is dogfood quality on this unusually large pull request. A green workflow alone is not sufficient: the canonical report must show meaningful delivered coverage and exercise the finding/verifier path when the model identifies a real issue.

## Implemented architecture

The branch now includes the native Rust tool-first engine described by `docs/plans/opencodereview-port.md`:

- deterministic snapshot, partition, risk, selection, and exact-anchor preparation;
- semantic grouping with deterministic fallback and isolated concurrent group workers;
- private digest-named diff artifacts with bounded paginated reads/searches and RAII cleanup;
- risk-adaptive trusted coverage ledgers;
- planning and effort-based fresh review rounds;
- direct Anthropic and OpenAI adapters with shared aggregate budgets;
- candidate verification, global adjudication, prior-review lineage handling, and publication outside the model;
- provider-free preview, rules, delegation, and agent manifest surfaces;
- tool-first scan mode;
- exact-anchor SARIF and `revoot.review-report/v3` with five-phase usage;
- stdio-only MCP server with the closed read-only tool surface;
- static Rust packaging, third-party notices, provenance, schemas, and golden contracts;
- immediate removal of the legacy single-conversation review engine and fallback.

The complete port, security, distribution, and acceptance scope remains in `docs/plans/opencodereview-port.md`.

## Validation completed

The latest local validation on the current source changes passed:

- `mise run verify`
  - formatting and workspace checks;
  - strict Clippy with warnings denied;
  - dependency audit;
  - 307 `revoot-core` tests;
  - external versioned contract artifacts;
  - 676 nextest tests, with 3 intentional skips;
  - the measured 1 MiB/100-file token-efficiency acceptance test;
  - both supported Linux musl target builds.
- Focused group-worker suite: 33/33.
- macOS ARM64 packaging previously passed with a stripped native executable.
- Linux AMD64/ARM64 release and debug packaging previously passed with the required static/stripped and static/debug properties.
- OCI support and release-workflow smoke enforcement were added. Docker became available later, but final OCI packaging should be rerun after dogfood stabilizes.

All commits added during the dogfood correction cycle were signed and verified before push.

## Dogfood history and findings

### Baseline failure: planning starvation

Run [33570981644](https://github.com/getrevoot/revoot/actions/runs/33570981644) completed successfully at the workflow level but failed the quality bar:

- state: partial;
- findings: 0;
- planning: 34 requests / 218,480 input tokens;
- review: 6 requests / 38,467 input tokens;
- fully read files: 4/64;
- delivered high-risk hunks: 7/9;
- failed groups: 2.

Root cause: a complex group could consume its entire 20-turn medium-effort budget in planning.

Fixes:

- `09386b5` caps planning at two provider turns and deterministically transitions to review;
- phase-specific instructions were added;
- tests prove planning cannot consume the review budget.

### Round lifecycle was invisible

Run [33574143470](https://github.com/getrevoot/revoot/actions/runs/33574143470) proved the planning cap worked, but review rounds still looped:

- planning fell to 10 requests;
- review rose to 33 requests;
- findings remained 0;
- only 3/64 files were fully read;
- failed groups remained 2.

Root cause: packets said only `review_round`; the model was told to complete in the final round but was not given the round number, total rounds, turn number, turn ceiling, or required terminal tool.

Fixes:

- `e4a92aa` exposes round/turn lifecycle explicitly;
- each review round has a bounded fairness ceiling;
- tests prove round 1 requires `checkpoint_review`, round 2/2 requires `complete_group`, and one group cannot monopolize the shared budget.

### Untrusted deferral authority

Run [33575088863](https://github.com/getrevoot/revoot/actions/runs/33575088863) terminated every group but still declared partial coverage with unused capacity:

- planning: 13 requests;
- review: 24 requests;
- explicit deferrals: 15;
- failed groups: 0;
- findings: 0.

Root cause: the model could author `budget_exhausted` and `tool_error` dispositions even when the trusted runtime had observed neither condition.

Fixes:

- `3b1834b` removes those dispositions from the model schema and rejects them defensively;
- final phase turns expose only the required terminal tool;
- provider responses cannot invoke a tool that was not offered;
- critical tool descriptions now explain exact work-unit, anchor, evidence, and completion requirements.

### Opaque and then ambiguous coverage requirements

Run [33576202046](https://github.com/getrevoot/revoot/actions/runs/33576202046) confirmed fabricated deferrals were gone, but the model still could not navigate coverage:

- fully read or sampled files: 3/64;
- delivered high-risk hunks: 4/9;
- explicit deferrals: 0;
- findings: 0.

Root cause: after each tool turn, exact missing requirements were replaced with opaque SHA-256 identifiers. The model could not determine which path/hunk/page remained.

The first correction, `ccdcb7b`, exposed action-prefixed strings. Run [33576970697](https://github.com/getrevoot/revoot/actions/runs/33576970697) showed that encoding was ambiguous: the model treated `read_all_pages:<hunk-id>` as the literal hunk ID, so valid diff delivery fell to zero.

The current correction, `e9c9753`, replaces strings with model-visible structured requirements:

```json
{
  "action": "read_all_pages",
  "path": "src/example.rs",
  "hunk_id": "<exact issued hunk id>",
  "missing_pages": [1, 2]
}
```

The legacy/opaque requirement IDs remain internal to packet integrity and are no longer serialized into the model-visible packet. Focused tests prove exact path/hunk/page projection and prove requirements disappear after successful delivery.

## Active acceptance check

The dogfood run for `e9c9753` is currently active. When it completes:

1. Download the `revoot-review` artifact from run `33577710137`.
2. Inspect the canonical `revoot-review.json`; do not accept the workflow badge alone.
3. Compare against the prior runs using:
   - report state;
   - finding count and finding content;
   - fully read, sampled, and manifest-only files;
   - delivered/required high-risk hunks;
   - explicit deferrals and failed groups;
   - grouping/planning/review/verification/adjudication requests and tokens.
4. Confirm CI run `33577710162` also passes.

For this nearly 1 MiB change, a partial result can be legitimate under the aggregate token ceiling (raised from 300,000 to 2,000,000 after dogfooding showed the pessimistic byte-for-byte reservation estimate left the old ceiling room for only ~3 worst-case requests). It is not acceptable if it again delivers almost no diff bodies, silently loops, uses untrusted deferrals, or produces no candidates because the tool protocol is unusable.

## If the active dogfood run still fails quality

Do not tune budgets or turn ceilings blindly. Add or inspect payload-free operational evidence in this order:

1. Aggregate group schedule statuses by closed reason (`coverage_incomplete`, `budget_exhausted`, `provider_unavailable`, and so on).
2. Count tool calls by tool name and outcome class without logging arguments, source, prompts, responses, or tool bodies.
3. Count candidate submissions and rejection reason codes without retaining finding content.
4. Verify `read_diff` calls use exact structured `path`, raw `hunk_id`, and `missing_pages` values.
5. If reads succeed but candidates remain zero, inspect whether evidence IDs and anchor IDs are visible in the immediately following packet and whether the final-turn tool restriction leaves a candidate-submission opportunity.
6. If coverage is distributed but the aggregate token cap is genuinely reached, wire the existing phase allocator into live dispatch or reserve explicit verification/adjudication capacity rather than increasing the global default again without this evidence.

Raw prompts, raw provider responses, source bodies, and tool payloads must never be logged or persisted during this diagnosis.

## Remaining release work after dogfood quality passes

1. Run `mise run verify` on the final tip.
2. With Docker running, run packaging serially:
   - `mise run package:linux`
   - `mise run package:macos`
   - `mise run package:oci`
3. Run `mise run sbom` and the Cargo-install smoke task required by the release guide.
4. Regenerate `dist/SHA256SUMS` only after the final archive set is assembled; target-specific package tasks intentionally leave it stale.
5. Confirm the PR head still contains only verified signed commits.
6. Confirm all required PR checks and the substantive dogfood review pass.
7. Benchmarking is intentionally deferred to the separate user-owned draft and should be handled in a follow-up.

## Worktree caution

`docs/plans/review-engine-benchmarking.md` is an unrelated untracked user file. Preserve it exactly. Do not include it in cleanup, staging, commits, or rebases unless the user explicitly changes that instruction.
