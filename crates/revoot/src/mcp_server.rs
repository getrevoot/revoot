//! Read-only stdio MCP surface over Revoot's snapshot-bound repository tools.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use revoot_core::{
    AgentBudget, AgentBudgetLimits, CancellationToken, FindingsEnvelope, LineRange,
    LocalSnapshotIdentity, PartitionLimits, RepositoryRelativePath, RepositoryToolLimits,
    RepositoryToolbox, ReviewSelectionPolicy, SearchRequest, UnifiedDiffLimits,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Value, json};

use crate::diff_artifact::{
    DEFAULT_DIFF_PAGE_BYTES, DiffArtifactStore, DiffSearchKind, DiffSearchRequest,
};
use crate::local_review::{
    LocalReviewContextOptions, build_local_review_context, capture_local_git,
};
use crate::review_rules::resolve_embedded_rule;

static HANDLE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct OpenReview {
    root: PathBuf,
    inferred_base: String,
    identity: LocalSnapshotIdentity,
    toolbox: RepositoryToolbox,
    diffs: DiffArtifactStore,
    changed_paths: Vec<RepositoryRelativePath>,
    anchor_ids: BTreeSet<String>,
    snapshot_digest: String,
}

#[derive(Default)]
pub struct RevootMcpServer {
    reviews: Mutex<BTreeMap<String, Arc<OpenReview>>>,
}

impl RevootMcpServer {
    fn open_review(&self, arguments: &JsonObject) -> Result<Value, &'static str> {
        let root = match arguments.get("repository_root").and_then(Value::as_str) {
            Some(root) => PathBuf::from(root),
            None => std::env::current_dir().map_err(|_| "repository unavailable")?,
        };
        let base = arguments.get("base").and_then(Value::as_str);
        let capture = capture_local_git(&root, base).map_err(|_| "review snapshot unavailable")?;
        let context = build_local_review_context(
            capture,
            &LocalReviewContextOptions {
                provider_adapter: "mcp".to_owned(),
                model_id: "host-agent".to_owned(),
                agent_limits: AgentBudgetLimits::default(),
                diff_limits: UnifiedDiffLimits::default(),
                selection_policy: ReviewSelectionPolicy {
                    version: "selection-v1".to_owned(),
                    included_paths: BTreeSet::new(),
                    included_prefixes: Vec::new(),
                    included_suffixes: Vec::new(),
                    excluded_paths: BTreeSet::new(),
                    excluded_prefixes: Vec::new(),
                    excluded_suffixes: Vec::new(),
                    excluded_basename_prefixes: Vec::new(),
                    include_generated: false,
                    max_file_bytes: 2 * 1024 * 1024,
                },
                partition_limits: PartitionLimits {
                    max_files: 100,
                    max_total_bytes: 1_000_000,
                    max_work_units: 128,
                    max_files_per_work_unit: 10,
                    max_bytes_per_work_unit: 512 * 1024,
                    max_anchors_per_work_unit: 10_000,
                },
            },
        )
        .map_err(|_| "review snapshot unavailable")?;
        let cancellation = CancellationToken::default();
        let toolbox = RepositoryToolbox::open_selected(
            &context.root,
            RepositoryToolLimits::default(),
            context.repository_diffs.clone(),
            context.repository_paths.iter().cloned(),
            &cancellation,
        )
        .map_err(|_| "repository inventory unavailable")?;
        let changed_paths = toolbox
            .exact_diffs()
            .map(|(path, _)| path.clone())
            .collect();
        let diffs = DiffArtifactStore::create(toolbox.exact_diffs(), DEFAULT_DIFF_PAGE_BYTES)
            .map_err(|_| "diff artifacts unavailable")?;
        let root = std::fs::canonicalize(&context.root).map_err(|_| "repository unavailable")?;
        let inferred_base = context.inferred_base.clone();
        let identity = context.identity.clone();
        let snapshot_digest = context.partition.plan_sha256.as_str().to_owned();
        let sequence = HANDLE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let handle = revoot_core::Sha256Digest::of_bytes(
            format!(
                "{}:{snapshot_digest}:{sequence}:{}",
                root.display(),
                std::process::id()
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned();
        let anchor_ids = context
            .anchors
            .iter()
            .map(|anchor| anchor.id.as_str().to_owned())
            .collect();
        self.reviews
            .lock()
            .map_err(|_| "server state unavailable")?
            .insert(
                handle.clone(),
                Arc::new(OpenReview {
                    root,
                    inferred_base,
                    identity,
                    toolbox,
                    diffs,
                    changed_paths,
                    anchor_ids,
                    snapshot_digest: snapshot_digest.clone(),
                }),
            );
        Ok(json!({"handle": handle, "snapshot": snapshot_digest}))
    }

    fn review(&self, arguments: &JsonObject) -> Result<Arc<OpenReview>, &'static str> {
        let handle = arguments
            .get("handle")
            .and_then(Value::as_str)
            .ok_or("missing review handle")?;
        let review = self
            .reviews
            .lock()
            .map_err(|_| "server state unavailable")?
            .get(handle)
            .cloned()
            .ok_or("stale or unknown review handle")?;
        let current = capture_local_git(&review.root, Some(&review.inferred_base))
            .map_err(|_| "stale or unknown review handle")?;
        if current.identity != review.identity {
            return Err("stale or unknown review handle");
        }
        Ok(review)
    }

    #[allow(clippy::too_many_lines)]
    fn execute(&self, name: &str, arguments: &JsonObject) -> Result<Value, &'static str> {
        if name == "revoot_open_review" {
            return self.open_review(arguments);
        }
        let review = self.review(arguments)?;
        match name {
            "revoot_list_changed_files" => Ok(json!({
                "snapshot": review.snapshot_digest,
                "files": review.diffs.manifest(&review.changed_paths).map_err(|_| "manifest unavailable")?
            })),
            "revoot_read_diff" => {
                let path = path_argument(arguments)?;
                let hunk = string_argument(arguments, "hunk_id")?;
                let page = u32_argument(arguments, "page")?;
                serde_json::to_value(
                    review
                        .diffs
                        .read_hunk_page(&path, hunk, page)
                        .map_err(|_| "diff page unavailable")?,
                )
                .map_err(|_| "serialization failed")
            }
            "revoot_read_file" => {
                let path = path_argument(arguments)?;
                let start = u32_argument(arguments, "start_line")?;
                let end = u32_argument(arguments, "end_line")?;
                if end.saturating_sub(start) >= 500 {
                    return Err("line range exceeds 500 lines");
                }
                let mut budget = local_budget()?;
                serde_json::to_value(
                    review
                        .toolbox
                        .read_file(
                            &path,
                            LineRange { start, end },
                            &mut budget,
                            &CancellationToken::default(),
                            0,
                        )
                        .map_err(|_| "file read unavailable")?,
                )
                .map_err(|_| "serialization failed")
            }
            "revoot_find_files" => {
                let query = arguments.get("query").and_then(Value::as_str).unwrap_or("");
                let maximum = arguments
                    .get("max_results")
                    .and_then(Value::as_u64)
                    .unwrap_or(200)
                    .min(500);
                let files = review
                    .toolbox
                    .inventory()
                    .files
                    .iter()
                    .filter(|file| file.path.as_str().contains(query))
                    .take(usize::try_from(maximum).unwrap_or(500))
                    .map(|file| &file.path)
                    .collect::<Vec<_>>();
                Ok(
                    json!({"files": files, "truncated": files.len() == usize::try_from(maximum).unwrap_or(500)}),
                )
            }
            "revoot_search_code" => {
                let query = string_argument(arguments, "query")?.to_owned();
                let maximum = u32_argument(arguments, "max_results")?.min(500);
                let mut budget = local_budget()?;
                serde_json::to_value(
                    review
                        .toolbox
                        .search(
                            &SearchRequest {
                                query,
                                paths: Vec::new(),
                                max_results: maximum,
                            },
                            &mut budget,
                            &CancellationToken::default(),
                            0,
                        )
                        .map_err(|_| "code search unavailable")?,
                )
                .map_err(|_| "serialization failed")
            }
            "revoot_search_diff" => {
                let kind = match arguments
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("any")
                {
                    "any" => DiffSearchKind::Any,
                    "added" => DiffSearchKind::Added,
                    "deleted" => DiffSearchKind::Deleted,
                    "context" => DiffSearchKind::Context,
                    _ => return Err("invalid diff search kind"),
                };
                serde_json::to_value(
                    review
                        .diffs
                        .search(&DiffSearchRequest {
                            query: string_argument(arguments, "query")?.to_owned(),
                            regex: arguments
                                .get("regex")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            case_sensitive: arguments
                                .get("case_sensitive")
                                .and_then(Value::as_bool)
                                .unwrap_or(true),
                            paths: Vec::new(),
                            kind,
                            max_results: u32_argument(arguments, "max_results")?.min(500),
                        })
                        .map_err(|_| "diff search unavailable")?,
                )
                .map_err(|_| "serialization failed")
            }
            "revoot_get_rules" => {
                let path = path_argument(arguments)?;
                let rule = resolve_embedded_rule(path.as_str()).map_err(|_| "rule unavailable")?;
                Ok(json!({"id": rule.id, "pattern": rule.pattern, "guidance": rule.guidance}))
            }
            "revoot_validate_findings" => {
                let value = arguments
                    .get("findings")
                    .cloned()
                    .ok_or("missing findings")?;
                let findings: FindingsEnvelope =
                    serde_json::from_value(value).map_err(|_| "invalid findings")?;
                findings.validate().map_err(|_| "invalid findings")?;
                let unknown = findings
                    .findings
                    .iter()
                    .filter(|finding| !review.anchor_ids.contains(finding.anchor_id.as_str()))
                    .map(|finding| finding.anchor_id.as_str())
                    .collect::<Vec<_>>();
                Ok(json!({"valid": unknown.is_empty(), "unknown_anchor_ids": unknown}))
            }
            _ => Err("unknown tool"),
        }
    }
}

impl ServerHandler for RevootMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: tool_definitions(),
            ..ListToolsResult::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let arguments = request.arguments.unwrap_or_default();
        let result = match self.execute(request.name.as_ref(), &arguments) {
            Ok(value) => {
                let text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
                result.structured_content = Some(value);
                result
            }
            Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
        };
        Ok(result.into())
    }
}

fn tool_definitions() -> Vec<Tool> {
    [
        ("revoot_open_review", "Open an immutable local review snapshot", json!({"repository_root":{"type":["string","null"]},"base":{"type":["string","null"]}})),
        ("revoot_list_changed_files", "List changed-file and hunk metadata", json!({"handle":{"type":"string"}})),
        ("revoot_read_diff", "Read one exact diff hunk page", json!({"handle":{"type":"string"},"path":{"type":"string"},"hunk_id":{"type":"string"},"page":{"type":"integer","minimum":1}})),
        ("revoot_read_file", "Read bounded post-change file lines", json!({"handle":{"type":"string"},"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1}})),
        ("revoot_find_files", "Find tracked allowlisted files", json!({"handle":{"type":"string"},"query":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":500}})),
        ("revoot_search_code", "Search allowlisted snapshot code", json!({"handle":{"type":"string"},"query":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":500}})),
        ("revoot_search_diff", "Search exact diff artifacts", json!({"handle":{"type":"string"},"query":{"type":"string"},"regex":{"type":"boolean"},"case_sensitive":{"type":"boolean"},"kind":{"enum":["any","added","deleted","context"]},"max_results":{"type":"integer","minimum":1,"maximum":500}})),
        ("revoot_get_rules", "Get embedded guidance for a path", json!({"handle":{"type":"string"},"path":{"type":"string"}})),
        ("revoot_validate_findings", "Validate findings against issued anchors", json!({"handle":{"type":"string"},"findings":{"type":"object"}})),
    ].into_iter().map(|(name, description, properties)| {
        let schema = json!({"type":"object","additionalProperties":false,"properties":properties});
        Tool::new(name, description, Arc::new(schema.as_object().cloned().unwrap_or_default()))
    }).collect()
}

fn string_argument<'a>(arguments: &'a JsonObject, name: &str) -> Result<&'a str, &'static str> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or("missing string argument")
}

fn u32_argument(arguments: &JsonObject, name: &str) -> Result<u32, &'static str> {
    arguments
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("missing integer argument")
}

fn path_argument(arguments: &JsonObject) -> Result<RepositoryRelativePath, &'static str> {
    RepositoryRelativePath::try_from(string_argument(arguments, "path")?.to_owned())
        .map_err(|_| "invalid repository path")
}

fn local_budget() -> Result<AgentBudget, &'static str> {
    AgentBudget::new(AgentBudgetLimits::default(), 0).map_err(|_| "tool budget unavailable")
}

/// Run the read-only MCP server over standard input and output.
///
/// # Errors
///
/// Returns a payload-free error if the runtime, transport, or protocol service fails.
pub fn serve_stdio(_root: &Path) -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "MCP runtime unavailable")?;
    runtime.block_on(async {
        let service = RevootMcpServer::default()
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|_| "MCP startup failed")?;
        service.waiting().await.map_err(|_| "MCP service failed")?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_only_the_closed_read_only_surface() {
        let names = tool_definitions()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), 9);
        for required in [
            "revoot_open_review",
            "revoot_read_diff",
            "revoot_read_file",
            "revoot_search_code",
            "revoot_search_diff",
            "revoot_validate_findings",
        ] {
            assert!(names.contains(required));
        }
        assert!(names.iter().all(|name| {
            !name.contains("publish") && !name.contains("write") && !name.contains("exec")
        }));
    }
}
