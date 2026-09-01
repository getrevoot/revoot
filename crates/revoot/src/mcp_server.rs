//! Read-only stdio MCP surface over Revoot's snapshot-bound repository tools.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use revoot_core::{
    AgentBudget, AgentBudgetLimits, CancellationToken, CodeSearchRequest, CursorTool,
    FindingsEnvelope, LineRange, LocalSnapshotIdentity, PartitionLimits, RepositoryRelativePath,
    RepositoryToolLimits, RepositoryToolbox, ReviewSelectionPolicy, Sha256Digest,
    ToolCursorBinding, ToolCursorStore, ToolPageRequest, ToolResultLimits, UnifiedDiffLimits,
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
const MCP_RESULT_BYTES: usize = 32 * 1024;
const MCP_PAGE_BYTES: u32 = 30 * 1024;
const MCP_SOURCE_SLICE_BYTES: u64 = 24 * 1024;

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

pub struct RevootMcpServer {
    reviews: Mutex<BTreeMap<String, Arc<OpenReview>>>,
    cursors: ToolCursorStore,
}

impl RevootMcpServer {
    fn new() -> Result<Self, &'static str> {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| "cursor initialization failed")?;
        let cursors = ToolCursorStore::new(
            secret,
            ToolResultLimits {
                max_result_bytes: MCP_PAGE_BYTES,
                ..ToolResultLimits::default()
            },
        )
        .map_err(|_| "cursor initialization failed")?;
        Ok(Self {
            reviews: Mutex::new(BTreeMap::new()),
            cursors,
        })
    }

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
            RepositoryToolLimits {
                max_read_bytes: MCP_SOURCE_SLICE_BYTES,
                ..RepositoryToolLimits::default()
            },
            context.repository_diffs.clone(),
            context.repository_paths.iter().cloned(),
            &cancellation,
        )
        .map_err(|_| "repository inventory unavailable")?;
        let changed_paths = toolbox
            .exact_diffs()
            .map(|(path, _)| path.clone())
            .collect();
        let diffs = DiffArtifactStore::create(
            toolbox.exact_diffs(),
            usize::try_from(MCP_SOURCE_SLICE_BYTES).unwrap_or(DEFAULT_DIFF_PAGE_BYTES),
        )
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
            "revoot_list_changed_files" => {
                let items = review
                    .diffs
                    .manifest(&review.changed_paths)
                    .map_err(|_| "manifest unavailable")?
                    .into_iter()
                    .map(|item| serde_json::to_value(item).map_err(|_| "serialization failed"))
                    .collect::<Result<Vec<_>, _>>()?;
                self.paginate(&review, arguments, CursorTool::ListChangedFiles, &items)
            }
            "revoot_read_diff" => {
                let items = diff_read_arguments(arguments)?
                    .into_iter()
                    .map(|(path, hunk, page)| {
                        review
                            .diffs
                            .read_hunk_page(&path, &hunk, page)
                            .map_err(|_| "diff page unavailable")
                            .and_then(|value| {
                                serde_json::to_value(value).map_err(|_| "serialization failed")
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.paginate(&review, arguments, CursorTool::ReadDiff, &items)
            }
            "revoot_read_file" => {
                let mut budget = local_budget()?;
                let items = file_read_arguments(arguments)?
                    .into_iter()
                    .map(|(path, start, end)| {
                        review
                            .toolbox
                            .read_file(
                                &path,
                                LineRange { start, end },
                                &mut budget,
                                &CancellationToken::default(),
                                0,
                            )
                            .map_err(|_| "file read unavailable")
                            .and_then(|value| {
                                serde_json::to_value(value).map_err(|_| "serialization failed")
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.paginate(&review, arguments, CursorTool::ReadFile, &items)
            }
            "revoot_find_files" => {
                let query = arguments.get("query").and_then(Value::as_str).unwrap_or("");
                let glob = arguments
                    .get("glob")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let glob_matcher = glob
                    .then(|| {
                        globset::Glob::new(query)
                            .map(|pattern| pattern.compile_matcher())
                            .map_err(|_| "invalid file glob")
                    })
                    .transpose()?;
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
                    .filter(|file| {
                        glob_matcher.as_ref().map_or_else(
                            || file.path.as_str().contains(query),
                            |matcher| matcher.is_match(file.path.as_str()),
                        )
                    })
                    .take(usize::try_from(maximum).unwrap_or(500))
                    .map(|file| &file.path)
                    .collect::<Vec<_>>();
                let items = files
                    .into_iter()
                    .map(|path| serde_json::to_value(path).map_err(|_| "serialization failed"))
                    .collect::<Result<Vec<_>, _>>()?;
                self.paginate(&review, arguments, CursorTool::FindFiles, &items)
            }
            "revoot_search_code" => {
                let query = string_argument(arguments, "query")?.to_owned();
                let maximum = u32_argument(arguments, "max_results")?.min(500);
                let mut budget = local_budget()?;
                let result = review
                    .toolbox
                    .search_code(
                        &CodeSearchRequest {
                            query,
                            regex: arguments
                                .get("regex")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            case_sensitive: arguments
                                .get("case_sensitive")
                                .and_then(Value::as_bool)
                                .unwrap_or(true),
                            paths: path_arguments(arguments, "paths")?,
                            max_results: maximum,
                        },
                        &mut budget,
                        &CancellationToken::default(),
                        0,
                    )
                    .map_err(|_| "code search unavailable")?;
                let metadata = json!({
                    "scanned_files": result.scanned_files,
                    "skipped_files": result.skipped_files,
                    "search_truncated": result.truncated,
                });
                let items = result
                    .matches
                    .into_iter()
                    .map(|item| serde_json::to_value(item).map_err(|_| "serialization failed"))
                    .collect::<Result<Vec<_>, _>>()?;
                let page = self.paginate(&review, arguments, CursorTool::SearchCode, &items)?;
                Ok(json!({"metadata": metadata, "page": page}))
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
                let result = review
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
                        paths: path_arguments(arguments, "paths")?,
                        kind,
                        max_results: u32_argument(arguments, "max_results")?.min(500),
                    })
                    .map_err(|_| "diff search unavailable")?;
                let metadata = json!({
                    "scanned_files": result.scanned_files,
                    "search_truncated": result.truncated,
                });
                let items = result
                    .matches
                    .into_iter()
                    .map(|item| serde_json::to_value(item).map_err(|_| "serialization failed"))
                    .collect::<Result<Vec<_>, _>>()?;
                let page = self.paginate(&review, arguments, CursorTool::SearchDiff, &items)?;
                Ok(json!({"metadata": metadata, "page": page}))
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

    fn paginate(
        &self,
        review: &OpenReview,
        arguments: &JsonObject,
        tool: CursorTool,
        items: &[Value],
    ) -> Result<Value, &'static str> {
        let handle = string_argument(arguments, "handle")?;
        let mut query = arguments.clone();
        query.remove("handle");
        query.remove("cursor");
        query.remove("max_result_bytes");
        query.remove("max_matches");
        let query_bytes = serde_json::to_vec(&query).map_err(|_| "cursor unavailable")?;
        let binding = ToolCursorBinding {
            handle_digest: Sha256Digest::of_bytes(handle.as_bytes()),
            snapshot_digest: Sha256Digest::of_bytes(review.snapshot_digest.as_bytes()),
            tool,
            query_digest: Sha256Digest::of_bytes(&query_bytes),
        };
        let cursor = arguments.get("cursor").and_then(Value::as_str);
        let request = ToolPageRequest {
            max_result_bytes: arguments
                .get("max_result_bytes")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            max_matches: arguments
                .get("max_matches")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
        };
        serde_json::to_value(
            self.cursors
                .paginate(&binding, items, cursor, request)
                .map_err(|_| "invalid or stale cursor")?,
        )
        .map_err(|_| "serialization failed")
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
            Ok(value) if encoded_value_len(&value) <= MCP_RESULT_BYTES => {
                let text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned());
                let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
                result.structured_content = Some(value);
                result
            }
            Ok(_) => CallToolResult::error(vec![ContentBlock::text("tool result exceeds limit")]),
            Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
        };
        Ok(result.into())
    }
}

fn tool_definitions() -> Vec<Tool> {
    [
        ("revoot_open_review", "Open an immutable local review snapshot", json!({"repository_root":{"type":["string","null"]},"base":{"type":["string","null"]}})),
        ("revoot_list_changed_files", "List changed-file and hunk metadata", json!({"handle":{"type":"string"},"cursor":{"type":["string","null"]},"max_result_bytes":{"type":["integer","null"],"minimum":1,"maximum":32768},"max_matches":{"type":["integer","null"],"minimum":1,"maximum":500}})),
        ("revoot_read_diff", "Read one or more exact diff hunk pages", json!({"handle":{"type":"string"},"path":{"type":"string"},"hunk_id":{"type":"string"},"page":{"type":"integer","minimum":1},"reads":{"type":"array","maxItems":32,"items":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"hunk_id":{"type":"string"},"page":{"type":"integer","minimum":1}},"required":["path","hunk_id","page"]}},"cursor":{"type":["string","null"]},"max_result_bytes":{"type":["integer","null"],"minimum":1,"maximum":32768},"max_matches":{"type":["integer","null"],"minimum":1,"maximum":32}})),
        ("revoot_read_file", "Read one or more bounded post-change file ranges", json!({"handle":{"type":"string"},"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1},"ranges":{"type":"array","maxItems":32,"items":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1}},"required":["path","start_line","end_line"]}},"cursor":{"type":["string","null"]},"max_result_bytes":{"type":["integer","null"],"minimum":1,"maximum":32768},"max_matches":{"type":["integer","null"],"minimum":1,"maximum":32}})),
        ("revoot_find_files", "Find tracked allowlisted files", json!({"handle":{"type":"string"},"query":{"type":"string"},"glob":{"type":"boolean"},"max_results":{"type":"integer","minimum":1,"maximum":500},"cursor":{"type":["string","null"]},"max_result_bytes":{"type":["integer","null"],"minimum":1,"maximum":32768},"max_matches":{"type":["integer","null"],"minimum":1,"maximum":500}})),
        ("revoot_search_code", "Search allowlisted snapshot code", json!({"handle":{"type":"string"},"query":{"type":"string"},"regex":{"type":"boolean"},"case_sensitive":{"type":"boolean"},"paths":{"type":"array","maxItems":32,"items":{"type":"string"}},"max_results":{"type":"integer","minimum":1,"maximum":500},"cursor":{"type":["string","null"]},"max_result_bytes":{"type":["integer","null"],"minimum":1,"maximum":32768},"max_matches":{"type":["integer","null"],"minimum":1,"maximum":500}})),
        ("revoot_search_diff", "Search exact diff artifacts", json!({"handle":{"type":"string"},"query":{"type":"string"},"regex":{"type":"boolean"},"case_sensitive":{"type":"boolean"},"kind":{"enum":["any","added","deleted","context"]},"paths":{"type":"array","maxItems":32,"items":{"type":"string"}},"max_results":{"type":"integer","minimum":1,"maximum":500},"cursor":{"type":["string","null"]},"max_result_bytes":{"type":["integer","null"],"minimum":1,"maximum":32768},"max_matches":{"type":["integer","null"],"minimum":1,"maximum":500}})),
        ("revoot_get_rules", "Get embedded guidance for a path", json!({"handle":{"type":"string"},"path":{"type":"string"}})),
        ("revoot_validate_findings", "Validate findings against issued anchors", json!({"handle":{"type":"string"},"findings":{"type":"object"}})),
    ].into_iter().map(|(name, description, properties)| {
        let required: &[&str] = match name {
            "revoot_list_changed_files"
            | "revoot_read_diff"
            | "revoot_read_file"
            | "revoot_find_files" => &["handle"],
            "revoot_search_code" => &["handle", "query", "max_results"],
            "revoot_search_diff" => &["handle", "query", "kind", "max_results"],
            "revoot_get_rules" => &["handle", "path"],
            "revoot_validate_findings" => &["handle", "findings"],
            _ => &[],
        };
        let mut schema = json!({"type":"object","additionalProperties":false,"properties":properties,"required":required});
        if name == "revoot_read_diff" {
            schema["oneOf"] = json!([
                {"required":["path", "hunk_id", "page"]},
                {"required":["reads"]}
            ]);
        } else if name == "revoot_read_file" {
            schema["oneOf"] = json!([
                {"required":["path", "start_line", "end_line"]},
                {"required":["ranges"]}
            ]);
        }
        Tool::new(
            name,
            description,
            Arc::new(schema.as_object().cloned().unwrap_or_default()),
        )
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

fn diff_read_arguments(
    arguments: &JsonObject,
) -> Result<Vec<(RepositoryRelativePath, String, u32)>, &'static str> {
    let Some(reads) = arguments.get("reads") else {
        return Ok(vec![(
            path_argument(arguments)?,
            string_argument(arguments, "hunk_id")?.to_owned(),
            u32_argument(arguments, "page")?,
        )]);
    };
    if ["path", "hunk_id", "page"]
        .iter()
        .any(|name| arguments.contains_key(*name))
    {
        return Err("ambiguous diff read arguments");
    }
    let reads = reads.as_array().ok_or("invalid diff reads")?;
    if reads.is_empty() || reads.len() > 32 {
        return Err("invalid diff read count");
    }
    reads
        .iter()
        .map(|value| {
            let item = value.as_object().ok_or("invalid diff read")?;
            Ok((
                path_argument(item)?,
                string_argument(item, "hunk_id")?.to_owned(),
                u32_argument(item, "page")?,
            ))
        })
        .collect()
}

fn file_read_arguments(
    arguments: &JsonObject,
) -> Result<Vec<(RepositoryRelativePath, u32, u32)>, &'static str> {
    if arguments.contains_key("ranges")
        && ["path", "start_line", "end_line"]
            .iter()
            .any(|name| arguments.contains_key(*name))
    {
        return Err("ambiguous file read arguments");
    }
    let values = arguments.get("ranges").map_or_else(
        || Ok(vec![Value::Object(arguments.clone())]),
        |ranges| ranges.as_array().cloned().ok_or("invalid file ranges"),
    )?;
    if values.is_empty() || values.len() > 32 {
        return Err("invalid file range count");
    }
    values
        .iter()
        .map(|value| {
            let item = value.as_object().ok_or("invalid file range")?;
            let path = path_argument(item)?;
            let start = u32_argument(item, "start_line")?;
            let end = u32_argument(item, "end_line")?;
            if end < start || end.saturating_sub(start) >= 500 {
                return Err("line range exceeds 500 lines");
            }
            Ok((path, start, end))
        })
        .collect()
}

fn path_argument(arguments: &JsonObject) -> Result<RepositoryRelativePath, &'static str> {
    RepositoryRelativePath::try_from(string_argument(arguments, "path")?.to_owned())
        .map_err(|_| "invalid repository path")
}

fn path_arguments(
    arguments: &JsonObject,
    name: &str,
) -> Result<Vec<RepositoryRelativePath>, &'static str> {
    let Some(values) = arguments.get(name) else {
        return Ok(Vec::new());
    };
    let values = values.as_array().ok_or("invalid repository paths")?;
    if values.len() > 32 {
        return Err("too many repository paths");
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or("invalid repository path")
                .and_then(|path| {
                    RepositoryRelativePath::try_from(path.to_owned())
                        .map_err(|_| "invalid repository path")
                })
        })
        .collect()
}

fn encoded_value_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
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
        let service = RevootMcpServer::new()?
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
        let tools = tool_definitions();
        let names = tools
            .iter()
            .map(|tool| tool.name.to_string())
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
        for name in [
            "revoot_list_changed_files",
            "revoot_read_diff",
            "revoot_read_file",
            "revoot_find_files",
            "revoot_search_code",
            "revoot_search_diff",
        ] {
            let schema = &tools
                .iter()
                .find(|tool| tool.name.as_ref() == name)
                .expect("paginated tool")
                .input_schema;
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .expect("tool properties");
            assert!(properties.contains_key("cursor"));
            assert_eq!(properties["max_result_bytes"]["maximum"], MCP_RESULT_BYTES);
        }
        assert_eq!(
            tools
                .iter()
                .find(|tool| tool.name.as_ref() == "revoot_read_diff")
                .expect("read diff")
                .input_schema["properties"]["reads"]["maxItems"],
            32
        );
        assert_eq!(
            tools
                .iter()
                .find(|tool| tool.name.as_ref() == "revoot_read_file")
                .expect("read file")
                .input_schema["properties"]["ranges"]["maxItems"],
            32
        );
    }

    #[test]
    fn read_tools_accept_bounded_batches_and_reject_broad_ranges() {
        let diff = json!({
            "reads": [
                {"path": "src/lib.rs", "hunk_id": "h1", "page": 1},
                {"path": "src/main.rs", "hunk_id": "h2", "page": 2}
            ]
        });
        assert_eq!(
            diff_read_arguments(diff.as_object().expect("diff arguments"))
                .expect("diff reads")
                .len(),
            2
        );
        let ambiguous_diff = json!({
            "path": "src/lib.rs",
            "hunk_id": "h1",
            "page": 1,
            "reads": [{"path": "src/lib.rs", "hunk_id": "h1", "page": 1}]
        });
        assert_eq!(
            diff_read_arguments(ambiguous_diff.as_object().expect("diff arguments")),
            Err("ambiguous diff read arguments")
        );

        let files = json!({
            "ranges": [
                {"path": "src/lib.rs", "start_line": 1, "end_line": 500},
                {"path": "src/main.rs", "start_line": 20, "end_line": 25}
            ]
        });
        assert_eq!(
            file_read_arguments(files.as_object().expect("file arguments"))
                .expect("file ranges")
                .len(),
            2
        );
        let broad = json!({"path": "src/lib.rs", "start_line": 1, "end_line": 501});
        assert_eq!(
            file_read_arguments(broad.as_object().expect("broad arguments")),
            Err("line range exceeds 500 lines")
        );
        let ambiguous_file = json!({
            "path": "src/lib.rs",
            "start_line": 1,
            "end_line": 2,
            "ranges": [{"path": "src/lib.rs", "start_line": 1, "end_line": 2}]
        });
        assert_eq!(
            file_read_arguments(ambiguous_file.as_object().expect("file arguments")),
            Err("ambiguous file read arguments")
        );
    }
}
