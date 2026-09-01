# Port provenance ledger

This document is the legal and engineering provenance record for the Revoot
review-engine port. Upstream identity is intentionally confined to this ledger,
the project-wide third-party notice, adjacent copied-asset notices, and required
headers on directly derived source files. It is not a product name, runtime
concept, configuration key, diagnostic label, or architectural dependency.

## Pinned source

- Upstream project: [Alibaba Open Code Review](https://github.com/alibaba/open-code-review)
- Pinned commit: `8d023aafcec05f8ba5628fca3eaba88078e5d201`
- Upstream license at that commit: Apache License 2.0 (`LICENSE`)
- Upstream `NOTICE` status: no `NOTICE` file exists in the pinned tree
- Local audit checkout: `/Users/scottparadis/workspace/open-code-review`

The commit above is the only source baseline covered by this ledger. Adopting a
later commit is a separate provenance event and requires updating this document,
the copied-file comparison, and notice review.

## Classification

The mapping below uses these terms deliberately:

- **Direct copy** means copyrightable source text or data was copied, allowing
  formatting-only changes such as final-newline normalization.
- **Direct translation** means upstream implementation expression was translated
  into idiomatic Rust and then materially adapted. These files remain derived
  files even when their types or control flow no longer resemble Go closely.
- **Behavioral adaptation** means the Rust implementation was written for
  Revoot's contracts after studying upstream behavior, tests, prompts, or
  interfaces. It is not recorded as a line-level source translation.
- **Informed** means upstream was used as a design or test reference while an
  existing Revoot subsystem remained authoritative.
- **Retained** means the subsystem is Revoot-originated and is not part of the
  port.
- **Omitted** means upstream functionality was deliberately not brought into the
  product.

If later work copies implementation text into a file currently classified as
behavioral adaptation or informed, that file must be reclassified as directly
derived and receive the notice treatment described below.

## Directly derived material

| Class | Exact upstream path(s) | Revoot destination | Port treatment |
|---|---|---|---|
| Direct copy | `internal/config/rules/system_rules.json` | `crates/revoot/assets/review_rules/system_rules.json` | Byte-identical at the pinned commit. Both files have SHA-256 `d9fed1299231c982e65f1250b77c2bcf89228554a60266f08b2228c14da6f5c1`. |
| Direct copy | `internal/config/rules/rule_docs/*.md` (the exact set below) | `crates/revoot/assets/review_rules/rule_docs/*.md` | The full 50-file rule corpus was copied. Forty-eight files are byte-identical; `po.md` and `r.md` differ only in final-newline normalization. |
| Direct translation and substantial adaptation | `internal/agent/grouping.go`, `internal/agent/grouping_test.go`, `internal/agent/coverage_test.go`, `internal/config/template/effort.go` | `crates/revoot-core/src/review_group.rs` | Group shape, effort, validation, and coverage concepts were translated into bounded, snapshot-bound Rust contracts. Revoot adds opaque identities, partition binding, exact anchors, deterministic fallback, fixed capacity limits, and a coverage ledger. The destination retains an upstream SPDX/copyright header and identifies the modification. |

The exact copied rule-document set is:

```text
internal/config/rules/rule_docs/arkts.md
internal/config/rules/rule_docs/astro.md
internal/config/rules/rule_docs/bicep.md
internal/config/rules/rule_docs/build_gradle.md
internal/config/rules/rule_docs/c.md
internal/config/rules/rule_docs/capnp.md
internal/config/rules/rule_docs/cargo_toml.md
internal/config/rules/rule_docs/composer_json.md
internal/config/rules/rule_docs/cpp.md
internal/config/rules/rule_docs/default.md
internal/config/rules/rule_docs/elm.md
internal/config/rules/rule_docs/freemarker.md
internal/config/rules/rule_docs/github_config.md
internal/config/rules/rule_docs/github_workflows.md
internal/config/rules/rule_docs/go.md
internal/config/rules/rule_docs/graphql.md
internal/config/rules/rule_docs/handlebars_mustache.md
internal/config/rules/rule_docs/haskell.md
internal/config/rules/rule_docs/java.md
internal/config/rules/rule_docs/json.md
internal/config/rules/rule_docs/jsonnet.md
internal/config/rules/rule_docs/julia.md
internal/config/rules/rule_docs/kotlin.md
internal/config/rules/rule_docs/mapper_dao_xml.md
internal/config/rules/rule_docs/matlab.md
internal/config/rules/rule_docs/nim.md
internal/config/rules/rule_docs/nix.md
internal/config/rules/rule_docs/objc.md
internal/config/rules/rule_docs/package_json.md
internal/config/rules/rule_docs/php.md
internal/config/rules/rule_docs/po.md
internal/config/rules/rule_docs/pom_xml.md
internal/config/rules/rule_docs/pot.md
internal/config/rules/rule_docs/prisma.md
internal/config/rules/rule_docs/properties.md
internal/config/rules/rule_docs/protobuf.md
internal/config/rules/rule_docs/pug.md
internal/config/rules/rule_docs/python.md
internal/config/rules/rule_docs/r.md
internal/config/rules/rule_docs/rust.md
internal/config/rules/rule_docs/solidity.md
internal/config/rules/rule_docs/swift.md
internal/config/rules/rule_docs/terraform.md
internal/config/rules/rule_docs/thrift.md
internal/config/rules/rule_docs/ts_js_tsx_jsx.md
internal/config/rules/rule_docs/verilog.md
internal/config/rules/rule_docs/vhdl.md
internal/config/rules/rule_docs/vyper.md
internal/config/rules/rule_docs/yaml.md
internal/config/rules/rule_docs/zig.md
```

## Behavioral port mapping

These destinations implement or test corresponding behavior without being
recorded as direct source translations. A destination can appear in more than
one row because Revoot separates contracts, safe handlers, and orchestration.

| Subsystem | Class | Exact upstream path(s) consulted | Current Revoot module(s) | Material Revoot adaptations |
|---|---|---|---|---|
| Semantic grouping and fallback | Behavioral adaptation | `internal/agent/grouping.go`, `internal/agent/grouping_test.go`, `internal/config/template/prompts/grouping_task_system.md`, `internal/config/template/prompts/grouping_task_user.md` | `crates/revoot/src/grouping.rs`, `crates/revoot-core/src/group_metrics.rs` | Metadata-only grouping request, deterministic grouping for at most three files, strict assignment validation, capacity-bounded fallback, body-free metrics, and all-or-nothing initial inlining. |
| Risk-prioritized group dispatch | Behavioral adaptation | `internal/agent/agent.go`, `internal/agent/budget_test.go`, `internal/llmloop/pool.go`, `internal/llmloop/pool_test.go` | `crates/revoot/src/group_scheduler.rs`, `crates/revoot/src/review_group_execution.rs`, `crates/revoot/src/tool_first_engine.rs`, `crates/revoot-core/src/concurrency_trace.rs` | Stable risk/path ordering, bounded parallelism, cancellation-aware dispatch, and deterministic partial/failure bookkeeping. |
| Planning and review rounds | Behavioral adaptation | `internal/agent/agent.go`, `internal/config/template/effort.go`, `internal/config/template/prompts/plan_task_system.md`, `internal/config/template/prompts/plan_task_user.md`, `internal/config/template/prompts/main_task_system.md`, `internal/config/template/prompts/main_task_user.md`, `internal/llmloop/loop.go` | `crates/revoot-core/src/review_worker.rs`, `crates/revoot-core/src/review_packet.rs`, `crates/revoot-core/src/worker_transcript.rs`, `crates/revoot/src/group_worker_engine.rs` | Isolated workers, fixed effort/turn limits, structured fresh-round rebasing, snapshot-bound briefs, and no raw conversation persistence. |
| Structured checkpointing | Behavioral adaptation | `internal/llmloop/compression.go`, `internal/llmloop/compression_test.go`, `internal/config/template/prompts/memory_compression_task_system.md`, `internal/config/template/prompts/memory_compression_task_user.md` | `crates/revoot/src/review_checkpoint.rs`, `crates/revoot-core/src/worker_transcript.rs` | Deterministic 4 KiB structured checkpoints replace provider-authored memory compression and stored conversation history. |
| Read-only review tool contracts | Behavioral adaptation | `internal/tool/definitions.go`, `internal/tool/file_read.go`, `internal/tool/file_find.go`, `internal/tool/file_read_diff.go`, `internal/tool/code_search.go`, `internal/tool/response_message.go`, `internal/config/toolsconfig/tools.json`, `internal/config/toolsconfig/toolsconfig.go` | `crates/revoot-core/src/review_tools.rs`, `crates/revoot/src/diff_artifact.rs`, `crates/revoot-core/src/repository.rs`, `crates/revoot/src/group_worker_engine.rs` | Pure-Rust bounded reads/searches, batching and pagination, no artifact path disclosure, no shell or writes, issued-anchor evidence, and measured coverage effects. |
| Candidate submission and filtering | Behavioral adaptation | `internal/tool/code_comment.go`, `internal/tool/comment_collector.go`, `internal/config/template/prompts/review_filter_task_system.md`, `internal/config/template/prompts/review_filter_task_user.md` | `crates/revoot-core/src/findings.rs`, `crates/revoot-core/src/review_verification.rs`, `crates/revoot/src/group_worker_engine.rs`, `crates/revoot/src/review_verifier.rs` | Deterministic schema/anchor/evidence gates precede a bounded verifier that cannot create findings or relocate targets. |
| Rule loading and matching | Behavioral adaptation plus direct assets above | `internal/config/rules/system_rules.go`, `internal/config/rules/sniffer.go`, `internal/config/rules/system_rules_test.go`, `internal/config/rules/sniffer_test.go`, `cmd/opencodereview/rules_cmd.go`, `cmd/opencodereview/rules_check_test.go` | `crates/revoot/src/review_rules.rs`, `crates/revoot/src/rule_diagnostics.rs` | Deterministic precedence, generic-file support, standard treatment for tests, path-bounded diagnostics, and no provider or content access. |
| Risk and coverage accounting | Behavioral adaptation | `internal/agent/coverage_test.go`, `internal/agent/budget_test.go`, `internal/agent/estimate.go`, `internal/scan/budget_test.go`, `internal/scan/estimate.go` | `crates/revoot-core/src/diff_hazards.rs`, `crates/revoot-core/src/group_metrics.rs`, `crates/revoot-core/src/coverage_gate.rs`, `crates/revoot-core/src/lineage_coverage.rs`, `crates/revoot-core/src/review_budget.rs`, `crates/revoot-core/src/phase_budget.rs`, `crates/revoot-core/src/token_efficiency.rs` | Coverage is based on delivered pages rather than model claims; local hazards promote requirements; global reservations bound requests, tokens, tools, output, cost, and time. |
| Preview | Behavioral adaptation | `internal/agent/preview.go`, `internal/agent/preview_test.go`, `internal/scan/preview.go` | `crates/revoot-core/src/review_preview.rs`, `crates/revoot/src/review_command.rs` | Snapshot- and policy-bound preview contracts disclose selection and strategy without source bodies or provider calls. |
| Scan | Behavioral adaptation | `internal/scan/agent.go`, `internal/scan/batch.go`, `internal/scan/estimate.go`, `internal/scan/preview.go`, `internal/scan/provider.go`, `cmd/opencodereview/scan_cmd.go`, `cmd/opencodereview/scan_cmd_test.go`, `cmd/opencodereview/scan_helpers_test.go` | `crates/revoot-core/src/scan.rs`, `crates/revoot/src/local_review.rs`, `crates/revoot/src/scan_command.rs` | Uses bounded tracked-file chunks, shares review gates, keeps untracked inclusion explicit, and cannot publish to a pull or merge request. |
| Delegation | Behavioral adaptation | `internal/delegate/format.go`, `internal/delegate/rulegroup.go`, `internal/delegate/format_test.go`, `internal/delegate/rulegroup_test.go`, `cmd/opencodereview/delegate_cmd.go`, `cmd/opencodereview/delegate_exec_test.go`, `cmd/opencodereview/delegate_helpers_test.go` | `crates/revoot-core/src/delegation.rs`, `crates/revoot-core/src/agent_manifest.rs`, `crates/revoot/src/delegate_command.rs`, `crates/revoot/src/rules_command.rs` | Provider-neutral, snapshot-bound metadata and rules only; no installation, editing, shell, raw Git, credentials, or provider calls. |
| SARIF output | Behavioral adaptation | `cmd/opencodereview/sarif.go`, `cmd/opencodereview/sarif_test.go` | `crates/revoot-core/src/sarif.rs`, `crates/revoot/src/review_command.rs` | Provider-neutral findings, exact locations, stable ordering, bounded properties, and golden output contracts. |
| Agent-loop and provider protocol behavior | Informed | `internal/llm/client.go`, `internal/llm/protocol.go`, `internal/llm/responses_client.go`, `internal/llmloop/loop.go`, `internal/llmloop/loop_test.go` | `crates/revoot-core/src/provider.rs`, `crates/revoot/src/providers/openai.rs`, `crates/revoot/src/providers/anthropic.rs`, `crates/revoot/src/group_worker_engine.rs`, `crates/revoot/src/tool_first_engine.rs` | Existing hardened direct adapters remain authoritative; tool-call batching, usage accounting, cancellation, and rebased turns are integrated without importing upstream wire types. |

## Revoot-retained subsystems

These parts are intentionally not attributed to the port. Upstream may solve a
related product problem, but Revoot's existing implementation and contracts
remain authoritative.

| Revoot subsystem | Current module(s) | Boundary |
|---|---|---|
| Immutable snapshot acquisition and embedded Git | `crates/revoot-core/src/snapshot.rs`, `crates/revoot-core/src/diff.rs`, `crates/revoot/src/embedded_git.rs`, `crates/revoot/src/github_checkout.rs`, `crates/revoot/src/gitlab_snapshot.rs` | No Git executable or reviewed-code execution. |
| Deterministic selection and partitioning | `crates/revoot-core/src/partition.rs`, `crates/revoot-core/src/config.rs` | Selection remains the authoritative capacity and risk boundary before grouping. |
| Exact opaque anchors | `crates/revoot-core/src/findings.rs`, `crates/revoot-core/src/diff.rs` | Models cannot relocate or synthesize publication coordinates. |
| Hardened network boundary | `crates/revoot-core/src/egress.rs`, GitHub/GitLab transports, direct provider adapters | Allowlisted HTTPS destinations and payload-free diagnostics remain mandatory. |
| Prior-review lineage and publication | `crates/revoot-core/src/review_history.rs`, `crates/revoot/src/prior_review.rs`, `crates/revoot-core/src/publication.rs`, GitHub/GitLab publication modules | Pull/merge-request metadata is the durable state store; publication authority stays outside the model. |
| Evaluation and provider-neutral reporting | `crates/revoot-core/src/evaluation.rs`, `crates/revoot-core/src/review_report.rs` | Existing precision, recall, silence, duplicate, and lineage gates remain release requirements. |

## Deliberately omitted upstream material

| Omitted capability | Exact upstream path(s) | Revoot decision |
|---|---|---|
| Bedrock provider | `internal/llm/client.go`, `internal/llm/providers.go`, `internal/llm/bedrock_test.go`, `cmd/opencodereview/llm_cmd.go`, `cmd/opencodereview/bedrock_config_test.go` | Only direct OpenAI and Anthropic adapters are in this redesign. |
| Raw session logs and stored reasoning | `internal/session/**`, `cmd/opencodereview/session_cmd.go`, `cmd/opencodereview/session_cmd_test.go`, `cmd/opencodereview/session_complete_test.go`, `cmd/opencodereview/session_display_more_test.go` | Prompts, responses, tool payloads, source slices, and model reasoning are not persisted. |
| Session viewer | `internal/viewer/**`, `cmd/opencodereview/viewer_cmd.go` | No local or hosted session viewer is shipped. |
| Telemetry export | `internal/telemetry/**` | No upstream telemetry pipeline is ported. Revoot diagnostics and reports remain payload-free. |
| Arbitrary MCP client and subprocess-launched servers | `internal/mcp/**` | Revoot exposes a bounded stdio MCP server; it does not act as a generic MCP client or launch MCP subprocesses. |
| Generic shell and Git subprocess execution | `internal/gitcmd/**`, `internal/diff/git.go`, `cmd/opencodereview/git.go`, `cmd/opencodereview/shell_unix.go`, `cmd/opencodereview/shell_windows.go` | Safe Rust repository abstractions and embedded Git replace subprocesses. No shell, `awk`, or arbitrary command tool is exposed. |
| Provider TUI, home-directory provider configuration, and API-key commands | `cmd/opencodereview/provider_tui.go`, `cmd/opencodereview/provider_cmd.go`, `cmd/opencodereview/config_cmd.go`, `internal/llm/keycmd.go`, `internal/llm/keycmd_test.go`, `internal/llm/resolver.go` | Trusted environment/CLI configuration and existing direct adapters remain the only provider surface. |
| Arbitrary compatible-provider endpoints | `internal/llm/providers.go`, `internal/llm/resolver.go`, `internal/llm/resolver_test.go` | Provider values remain `auto`, `anthropic`, and `openai`; repository content cannot expand egress. |
| Model-based line relocation | `internal/diff/relocation.go`, `internal/diff/relocation_test.go`, `internal/diff/resolver.go`, `internal/config/template/prompts/re_location_task_system.md`, `internal/config/template/prompts/re_location_task_user.md` | Exact issued anchors fail closed instead of being moved by a model. |
| Suggested code edits | `internal/suggestdiff/**` | Review findings do not grant code-edit authority. |
| Provider-authored memory compression | `internal/llmloop/compression.go`, `internal/config/template/prompts/memory_compression_task_system.md`, `internal/config/template/prompts/memory_compression_task_user.md` | Only bounded structured checkpoints are retained between fresh rounds. |
| VS Code extension, JavaScript launcher, and installer surfaces | `extensions/vscode/**`, `bin/**`, `install.sh`, `install.ps1` | Distribution remains one native Rust binary with no Go, Node, or Bun runtime dependency. |
| Upstream examples and documentation as product assets | `examples/**`, `docs/**`, `README.md` | Revoot documentation and examples are authored for Revoot's own security and runtime contracts. |

## License and notice handling

The following controls apply to this port:

1. `THIRD_PARTY_NOTICES.md` records the upstream project, pinned commit,
   copyright, Apache-2.0 license, modification status, and absence of an
   upstream `NOTICE` at the pin.
2. Copied rule assets carry the adjacent
   `crates/revoot/assets/review_rules/LICENSE.md` notice. The rule bodies are
   kept clean of product branding so they remain usable as review guidance.
3. Directly translated Rust files retain the upstream SPDX/copyright notice,
   add Revoot's copyright, and state that the file was modified for Revoot.
4. Behavioral adaptations and informed implementations are recorded here but
   do not receive an upstream source header merely because behavior or tests
   were consulted.
5. If a future deliberately adopted baseline contains a `NOTICE`, its required
   content must be preserved in the distributed notices. The absence of a
   `NOTICE` at this pin must not be assumed for later revisions.
6. Build output, diagnostics, schemas, module names, runtime identifiers, and
   user-facing text must not use upstream identity except where reproducing a
   legally required notice.

This ledger records engineering provenance and license-preservation procedure;
it is not a substitute for legal advice.
