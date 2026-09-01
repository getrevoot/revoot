# Tool-first review engine redesign

Status: implemented

## Outcome

Revoot uses a native Rust, tool-first review engine instead of a single global
review conversation. The engine keeps Revoot's immutable snapshots,
base-commit configuration, exact anchors, provider adapters, budgets, prior
review lineage, publication controllers, and evaluation corpus. It adds
semantic grouping, isolated group workers, effort-based review rounds,
adaptive diff delivery, explicit coverage, candidate verification, scan and
delegation workflows, SARIF, and a read-only stdio MCP server.

The shipped product remains one Rust binary. It does not require Go, Bun,
Node, a model CLI, a shell, or a Git executable at runtime. OpenAI Responses
and Anthropic Messages remain the only direct model providers.

## Fixed architecture

1. Build the existing deterministic `ReviewPartitionPlan` from the immutable
   review snapshot. It remains the authority for selected files, omissions,
   byte limits, work-unit ownership, and issued anchors.
2. Build `revoot.review-group-plan/v1`. Reviews with at most three files use
   deterministic groups. Larger reviews may use one metadata-only model call;
   malformed or incomplete output falls back deterministically. A group is
   capped at 10 files, 512 KiB of selected diff, and 10,000 anchors.
3. Materialize selected unified diffs in a private per-run artifact directory.
   Artifact names are digests, directory/file modes are `0700`/`0600`, paths
   are never model-visible, and RAII cleanup runs after success, cancellation,
   or failure. An in-memory index records stable hunk IDs, ranges, anchors,
   changed-line counts, and local hazard signals.
4. Inline a group's complete diff only when it is at most 16,384 bytes and the
   request remains below the 32,000-token input target. Larger groups start
   with file and hunk metadata and obtain bodies through bounded tools.
5. Expose `diff_manifest`, `read_diff`, `search_diff`, `read_file`,
   `find_files`, `search_code`, history and prior-review tools,
   `checkpoint_review`, `submit_candidate_finding`, and `complete_group`.
   Implement them in Rust with deterministic pagination. Source reads are
   capped at 500 lines and 32 KiB; diff/search results are capped at 32 KiB;
   search defaults to 200 matches and never exceeds 500.
6. Compute coverage from content actually inlined or returned by successful
   tools. High-risk files require every hunk page. Standard-risk files require
   one hunk plus every locally promoted hazardous hunk and dispositions for
   unread hunks. Low-risk files may be manifest-only unless promoted.
   Incomplete high/standard work makes the review partial. Prior findings may
   be marked fixed only when their current location or deletion was inspected.
7. Complex groups (one 50-line file or 100 aggregate changed lines) receive a
   tool-capable planning pass. Effort controls review rounds and per-group turn
   ceilings: low `1/12`, medium `2/20`, high `3/32`.
8. Rebase worker context instead of summarizing it with another model call.
   Each turn receives immutable policy, a compact group brief, at most 4 KiB
   of structured checkpoint state, and only the latest tool exchange.
9. Apply deterministic candidate validation first. A group verifier receives
   only surviving candidates and cited evidence; it may accept, suppress, or
   lower confidence but cannot create or relocate findings. A final global
   adjudicator receives verified candidates, coverage, omissions, prior state,
   and usage. If it fails, publish deterministically ranked verified findings,
   mark the review partial, and preserve prior lineages.
10. Run at most four groups concurrently, high-signal first, using atomic
    reservations from the review-wide request, token, output, cost, tool, and
    deadline budgets. Stop dispatch on exhaustion and retain verified partial
    results.

## Fixed defaults and interfaces

- Effort: `medium`.
- Parallel groups: 4, operator range 1-8.
- Model requests: 64, range 1-256.
- Combined model tokens: 300,000, range 1-2,000,000.
- Local tool calls: 256, range 1-2,048.
- Deadline: 600 seconds.
- Per-request input target: 32,000 tokens.
- Per-request output maximum: 4,096 tokens.
- Selected diff maximum: 1,000,000 bytes.
- Published findings maximum: 25.

Add CLI surfaces for review preview and effort, scan, rule inspection,
delegation preview/rules, SARIF, and `mcp serve`. Scan reuses the same engine
over bounded source chunks and never publishes to a pull or merge request.
Delegation never calls a model. The stdio MCP server exposes only Revoot's
bounded read-only context and finding-validation tools; it is not an MCP
client and cannot launch tools or access arbitrary network endpoints.

Keep `.revoot.toml` version 1. Add repository-narrowable
`budget.max_model_tokens`, `budget.max_tool_calls`, and
`model_context.max_inline_diff_bytes`. Add trusted operator settings for
effort, parallel groups, model tokens, tool calls, and inline diff bytes.

Bump the public report to `revoot.review-report/v3`. Preserve existing fields
and `revoot.findings/v1`; add strategy, coverage, and per-phase payload-free
usage. Add versioned group-plan, delegation, coverage, and SARIF contracts.

## Port and retention boundary

- Port grouping, complex-group planning, isolated workers, effort rounds,
  tool-loop behavior, useful language rules, candidate filtering, scan,
  preview, rule diagnostics, delegation, and SARIF behavior.
- Adapt diff handling, memory, coverage, tools, MCP, anchors, concurrency,
  configuration, and errors to Revoot's trust model.
- Retain snapshot acquisition, embedded Git, base-commit policy, deterministic
  selection, exact anchors, direct providers, budgets, lineage, publication,
  suppressions, evaluation, and static packaging.
- Omit raw sessions and viewers, persisted reasoning, arbitrary provider
  endpoints, provider/home configuration, generic shell execution, Git
  subprocesses, MCP clients, model relocation, line-zero comments, and default
  test-file exclusion.

Copied or derived Apache-2.0 material retains applicable notices and prominent
modification notices. Product names, symbols, CLI output, and architecture
terminology remain Revoot-native.

## Implementation order

1. Land the plan, legal notices, behavioral port ledger, and synthetic parity
   fixtures.
2. Add group, manifest, coverage, artifact, rule, and tool foundations.
3. Replace orchestration with grouped adaptive workers, verification, global
   adjudication, atomic budgets, and deterministic partial fallback.
4. Add scan, preview, rules, delegation, SARIF, MCP, and the agent skill.
5. Cut `review` over without a legacy flag and delete obsolete orchestration.
6. Update all user/security/operations documentation and distribution checks.

## Acceptance gates

- Ported behavior has deterministic unit and fake-provider coverage, including
  malformed grouping, worker failure, cancellation, verifier/adjudicator
  failure, missing usage, pagination, and budget races.
- No worker can target another group's file or fabricate an anchor. Coverage
  cannot be self-reported or bypassed, and partial coverage cannot resolve a
  prior finding.
- On a deterministic 1 MiB/100-file fixture, grouping and large-group initial
  prompts contain no diff bodies, tool results stay below 32 KiB, no request
  exceeds the 32,000-token target, and medium-effort serialized model input is
  at most 40% of repeatedly inlining each complete group diff.
- Security tests cover path traversal, symlinks, hardlinks, stale handles,
  cursor tampering, prompt injection, binary/invalid text, permissions,
  cleanup, stdout purity, and payload-free diagnostics.
- Existing evaluation gates remain at least 90% precision, 85% recall, and
  75% category recall with clean-case silence and duplicate suppression.
- `mise run verify` passes. Linux, macOS, and OCI packages retain their current
  static-linking, architecture, stripping, non-root, and runtime-dependency
  guarantees.
