//! Read-only stdio MCP surface over Revoot's snapshot-bound repository tools.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use revoot_core::{
    AgentBudget, AgentBudgetLimits, AnchorPosition, AnchorTable, CancellationToken,
    CodeSearchRequest, CursorTool, FindingsEnvelope, IssuedWorkUnitAnchors, LineRange,
    LocalSnapshotIdentity, PartitionLimits, ProviderCancellationReason, RepositoryRelativePath,
    RepositoryToolLimits, RepositoryToolbox, ReviewSelectionPolicy, Sha256Digest,
    ToolCursorBinding, ToolCursorStore, ToolPageRequest, ToolResultLimits, UnifiedDiffLimits,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Value, json};

use crate::config::{RepositoryReviewPolicy, resolve_review_configuration};
use crate::diff_artifact::{
    DEFAULT_DIFF_PAGE_BYTES, DiffArtifactStore, DiffHunkManifest, DiffSearchKind, DiffSearchRequest,
};
use crate::local_review::{
    LocalReviewContextOptions, build_local_review_context, capture_local_git,
};
use crate::review_rule_bundle::{ReviewRuleGuidance, resolve_path_rule_guidance};

static HANDLE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const MCP_RESULT_BYTES: usize = 32 * 1024;
const MCP_PAGE_BYTES: u32 = 30 * 1024;
const MCP_SOURCE_SLICE_BYTES: u64 = 24 * 1024;
const MAX_LIVE_REVIEWS: usize = 8;

struct OpenReview {
    root: PathBuf,
    inferred_base: String,
    identity: LocalSnapshotIdentity,
    toolbox: RepositoryToolbox,
    diffs: DiffArtifactStore,
    changed_paths: Vec<RepositoryRelativePath>,
    anchors: AnchorTable,
    issued_anchors: IssuedWorkUnitAnchors,
    work_unit_by_path: BTreeMap<RepositoryRelativePath, String>,
    snapshot_digest: String,
    repository_policy: RepositoryReviewPolicy,
    opened_sequence: u64,
}

#[derive(Clone)]
pub struct RevootMcpServer {
    trusted_root: Arc<PathBuf>,
    reviews: Arc<Mutex<BTreeMap<String, Arc<OpenReview>>>>,
    cursors: Arc<ToolCursorStore>,
}

impl RevootMcpServer {
    fn new(root: &Path) -> Result<Self, &'static str> {
        let trusted_root = std::fs::canonicalize(root).map_err(|_| "repository unavailable")?;
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
            trusted_root: Arc::new(trusted_root),
            reviews: Arc::new(Mutex::new(BTreeMap::new())),
            cursors: Arc::new(cursors),
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "snapshot construction keeps the trusted-root, artifact, and handle bindings visible"
    )]
    fn open_review(
        &self,
        arguments: &JsonObject,
        cancellation: &CancellationToken,
    ) -> Result<Value, &'static str> {
        if cancellation.is_cancelled() {
            return Err("tool call cancelled");
        }
        let requested = arguments
            .get("repository_root")
            .and_then(Value::as_str)
            .map_or_else(|| self.trusted_root.as_ref().clone(), PathBuf::from);
        let root = std::fs::canonicalize(requested).map_err(|_| "repository unavailable")?;
        if !root.starts_with(self.trusted_root.as_ref()) {
            return Err("repository outside server authority");
        }
        let base = arguments.get("base").and_then(Value::as_str);
        let capture = capture_local_git(&root, base).map_err(|_| "review snapshot unavailable")?;
        if cancellation.is_cancelled() {
            return Err("tool call cancelled");
        }
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
        if cancellation.is_cancelled() {
            return Err("tool call cancelled");
        }
        let repository_policy = repository_policy(&context.root, &context.identity.base_sha)?;
        let toolbox = RepositoryToolbox::open_selected(
            &context.root,
            RepositoryToolLimits {
                max_read_bytes: MCP_SOURCE_SLICE_BYTES,
                ..RepositoryToolLimits::default()
            },
            context.repository_diffs.clone(),
            context.repository_paths.iter().cloned(),
            cancellation,
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
        let anchors = context.anchors.clone();
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
        let issued_anchors = context
            .partition
            .work_units
            .iter()
            .map(|unit| {
                (
                    unit.id.as_str().to_owned(),
                    unit.files
                        .iter()
                        .flat_map(|file| file.anchor_ids.iter().cloned())
                        .collect(),
                )
            })
            .collect();
        let work_unit_by_path = context
            .partition
            .work_units
            .iter()
            .flat_map(|unit| {
                unit.files.iter().map(|file| {
                    (
                        RepositoryRelativePath::try_from(file.path.new_path.as_str().to_owned()),
                        unit.id.as_str().to_owned(),
                    )
                })
            })
            .map(|(path, work_unit_id)| {
                path.map(|path| (path, work_unit_id))
                    .map_err(|_| "review partition unavailable")
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut reviews = self
            .reviews
            .lock()
            .map_err(|_| "server state unavailable")?;
        if reviews.len() >= MAX_LIVE_REVIEWS
            && let Some(oldest) = reviews
                .iter()
                .min_by_key(|(_, review)| review.opened_sequence)
                .map(|(handle, _)| handle.clone())
        {
            reviews.remove(&oldest);
        }
        reviews.insert(
            handle.clone(),
            Arc::new(OpenReview {
                root,
                inferred_base,
                identity,
                toolbox,
                diffs,
                changed_paths,
                anchors,
                issued_anchors,
                work_unit_by_path,
                snapshot_digest: snapshot_digest.clone(),
                repository_policy,
                opened_sequence: sequence,
            }),
        );
        Ok(json!({"handle": handle, "snapshot": snapshot_digest}))
    }

    fn review(
        &self,
        arguments: &JsonObject,
        cancellation: &CancellationToken,
    ) -> Result<Arc<OpenReview>, &'static str> {
        if cancellation.is_cancelled() {
            return Err("tool call cancelled");
        }
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
        let current = capture_local_git(&review.root, Some(&review.inferred_base));
        let Ok(current) = current else {
            self.evict_handle(handle)?;
            return Err("stale or unknown review handle");
        };
        if cancellation.is_cancelled() {
            return Err("tool call cancelled");
        }
        if current.identity != review.identity {
            self.evict_handle(handle)?;
            return Err("stale or unknown review handle");
        }
        Ok(review)
    }

    fn evict_handle(&self, handle: &str) -> Result<(), &'static str> {
        self.reviews
            .lock()
            .map_err(|_| "server state unavailable")?
            .remove(handle);
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn execute(
        &self,
        name: &str,
        arguments: &JsonObject,
        cancellation: &CancellationToken,
    ) -> Result<Value, &'static str> {
        if name == "revoot_open_review" {
            return self.open_review(arguments, cancellation);
        }
        let review = self.review(arguments, cancellation)?;
        match name {
            "revoot_list_changed_files" => {
                let items = review
                    .diffs
                    .manifest(&review.changed_paths)
                    .map_err(|_| "manifest unavailable")?
                    .into_iter()
                    .map(|item| {
                        let work_unit_id = review
                            .work_unit_by_path
                            .get(&item.path)
                            .ok_or("manifest unavailable")?;
                        let mut value =
                            serde_json::to_value(item).map_err(|_| "serialization failed")?;
                        value
                            .as_object_mut()
                            .ok_or("serialization failed")?
                            .insert("work_unit_id".to_owned(), json!(work_unit_id));
                        Ok::<Value, &'static str>(value)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.paginate(&review, arguments, CursorTool::ListChangedFiles, &items)
            }
            "revoot_read_diff" => {
                let items = diff_read_arguments(arguments)?
                    .into_iter()
                    .map(|(path, hunk, page)| {
                        let manifest = review
                            .diffs
                            .manifest(std::slice::from_ref(&path))
                            .map_err(|_| "diff page unavailable")?;
                        let indexed_hunk = manifest[0]
                            .hunks
                            .iter()
                            .find(|indexed| indexed.hunk_id == hunk)
                            .ok_or("diff page unavailable")?;
                        let anchors = review
                            .anchors
                            .iter()
                            .filter(|anchor| {
                                anchor.path.old_path.as_str() == path.as_str()
                                    || anchor.path.new_path.as_str() == path.as_str()
                            })
                            .filter(|anchor| anchor_in_hunk(anchor.position, indexed_hunk))
                            .map(|anchor| {
                                json!({
                                    "anchor_id":anchor.id,
                                    "position":anchor.position
                                })
                            })
                            .collect::<Vec<_>>();
                        let mut value = review
                            .diffs
                            .read_hunk_page(&path, &hunk, page)
                            .map_err(|_| "diff page unavailable")
                            .and_then(|value| {
                                serde_json::to_value(value).map_err(|_| "serialization failed")
                            })?;
                        value
                            .as_object_mut()
                            .ok_or("serialization failed")?
                            .insert("anchors".to_owned(), json!(anchors));
                        Ok::<Value, &'static str>(value)
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
                                cancellation,
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
                        cancellation,
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
                let rules = resolve_path_rule_guidance(path.as_str(), &review.repository_policy)
                    .map_err(|_| "rule unavailable")?;
                rule_result(arguments, &path, &rules)
            }
            "revoot_validate_findings" => {
                let value = arguments
                    .get("findings")
                    .cloned()
                    .ok_or("missing findings")?;
                let findings: FindingsEnvelope =
                    serde_json::from_value(value).map_err(|_| "invalid findings")?;
                findings.validate().map_err(|_| "invalid findings")?;
                let issued = review.issued_anchors.get(&findings.work_unit_id);
                let unknown = findings
                    .findings
                    .iter()
                    .filter(|finding| {
                        issued.is_none_or(|anchors| {
                            revoot_core::AnchorId::try_from(finding.anchor_id.clone())
                                .map_or(true, |anchor| !anchors.contains(&anchor))
                        })
                    })
                    .map(|finding| finding.anchor_id.as_str())
                    .collect::<Vec<_>>();
                Ok(json!({
                    "valid": issued.is_some() && unknown.is_empty(),
                    "unknown_anchor_ids": unknown
                }))
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

fn repository_policy(
    root: &Path,
    base: &revoot_core::GitSha,
) -> Result<RepositoryReviewPolicy, &'static str> {
    resolve_review_configuration(
        root,
        Some(base),
        None,
        std::iter::empty::<(std::ffi::OsString, std::ffi::OsString)>(),
    )
    .map(|resolved| resolved.repository)
    .map_err(|_| "review policy unavailable")
}

impl ServerHandler for RevootMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
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
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let arguments = request.arguments.unwrap_or_default();
        let name = request.name.into_owned();
        let cancellation = CancellationToken::default();
        let worker_cancellation = cancellation.clone();
        let server = self.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            server.execute(&name, &arguments, &worker_cancellation)
        });
        let execution = tokio::select! {
            result = &mut worker => result.map_err(|_| "tool execution failed"),
            () = context.ct.cancelled() => {
                cancellation.cancel(ProviderCancellationReason::UserRequested);
                worker.await.map_err(|_| "tool execution failed")
            }
        };
        let result = match execution {
            Ok(Ok(value)) => bounded_success(value),
            Ok(Err(message)) | Err(message) => {
                CallToolResult::error(vec![ContentBlock::text(message)])
            }
        };
        Ok(result.into())
    }
}

fn bounded_success(value: Value) -> CallToolResult {
    if encoded_value_len(&value) > MCP_RESULT_BYTES {
        return CallToolResult::error(vec![ContentBlock::text("tool result exceeds limit")]);
    }
    let mut result = CallToolResult::success(Vec::new());
    result.structured_content = Some(value);
    if serde_json::to_vec(&result).map_or(true, |encoded| encoded.len() > MCP_RESULT_BYTES) {
        CallToolResult::error(vec![ContentBlock::text("tool result exceeds limit")])
    } else {
        result
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
        ("revoot_get_rules", "Resolve effective bounded guidance for a path", json!({"handle":{"type":"string"},"path":{"type":"string"},"rule_ids":{"type":["array","null"],"minItems":1,"maxItems":32,"items":{"type":"string"}},"after_id":{"type":["string","null"]}})),
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

fn anchor_in_hunk(position: AnchorPosition, hunk: &DiffHunkManifest) -> bool {
    match position {
        AnchorPosition::Deletion { old_line } => {
            old_line >= hunk.old_start && old_line < hunk.old_start.saturating_add(hunk.old_count)
        }
        AnchorPosition::Addition { new_line } => {
            new_line >= hunk.new_start && new_line < hunk.new_start.saturating_add(hunk.new_count)
        }
        AnchorPosition::Context { old_line, new_line } => {
            old_line >= hunk.old_start
                && old_line < hunk.old_start.saturating_add(hunk.old_count)
                && new_line >= hunk.new_start
                && new_line < hunk.new_start.saturating_add(hunk.new_count)
        }
    }
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

fn rule_result(
    arguments: &JsonObject,
    path: &RepositoryRelativePath,
    rules: &[ReviewRuleGuidance],
) -> Result<Value, &'static str> {
    let descriptors = rules
        .iter()
        .map(|rule| rule.descriptor.clone())
        .collect::<Vec<_>>();
    let Some(requested) = arguments.get("rule_ids") else {
        if arguments.contains_key("after_id") {
            return Err("invalid rule cursor");
        }
        let value = json!({
            "path": path,
            "rules": descriptors,
            "guidance": [],
            "next_after_id": null,
            "truncated": false,
        });
        return (encoded_value_len(&value) <= MCP_RESULT_BYTES)
            .then_some(value)
            .ok_or("rule result exceeds limit");
    };
    let requested = requested.as_array().ok_or("invalid rule identifiers")?;
    if requested.is_empty() || requested.len() > 32 {
        return Err("invalid rule identifier count");
    }
    let mut requested = requested
        .iter()
        .map(|id| {
            id.as_str()
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .ok_or("invalid rule identifier")
        })
        .collect::<Result<Vec<_>, _>>()?;
    requested.sort();
    if requested.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate rule identifier");
    }
    let by_id = rules
        .iter()
        .map(|rule| (rule.descriptor.id.as_str(), rule))
        .collect::<BTreeMap<_, _>>();
    if requested.iter().any(|id| !by_id.contains_key(id.as_str())) {
        return Err("unknown rule identifier");
    }
    let start = match arguments.get("after_id") {
        Some(Value::String(after)) => requested
            .iter()
            .position(|id| id == after)
            .map(|index| index + 1)
            .ok_or("invalid rule cursor")?,
        Some(Value::Null) | None => 0,
        Some(_) => return Err("invalid rule cursor"),
    };
    let mut guidance = Vec::new();
    for id in &requested[start..] {
        let rule = by_id
            .get(id.as_str())
            .copied()
            .ok_or("unknown rule identifier")?;
        let mut candidate = guidance.clone();
        candidate.push(rule.clone());
        let value = json!({
            "path": path,
            "rules": descriptors,
            "guidance": candidate,
            "next_after_id": id,
            "truncated": true,
        });
        if encoded_value_len(&value) > usize::try_from(MCP_PAGE_BYTES).unwrap_or(MCP_RESULT_BYTES) {
            if guidance.is_empty() {
                return Err("rule result exceeds limit");
            }
            let next_after_id = guidance
                .last()
                .map(|rule: &ReviewRuleGuidance| rule.descriptor.id.clone());
            return Ok(json!({
                "path": path,
                "rules": descriptors,
                "guidance": guidance,
                "next_after_id": next_after_id,
                "truncated": true,
            }));
        }
        guidance = candidate;
    }
    Ok(json!({
        "path": path,
        "rules": descriptors,
        "guidance": guidance,
        "next_after_id": null,
        "truncated": false,
    }))
}

fn local_budget() -> Result<AgentBudget, &'static str> {
    AgentBudget::new(AgentBudgetLimits::default(), 0).map_err(|_| "tool budget unavailable")
}

/// Run the read-only MCP server over standard input and output.
///
/// # Errors
///
/// Returns a payload-free error if the runtime, transport, or protocol service fails.
pub fn serve_stdio(root: &Path) -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "MCP runtime unavailable")?;
    runtime.block_on(async {
        let service = RevootMcpServer::new(root)?
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|_| "MCP startup failed")?;
        service.waiting().await.map_err(|_| "MCP service failed")?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::{Command, Stdio};

    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf};

    use super::*;

    struct ProtocolHarness {
        reader: Lines<BufReader<ReadHalf<tokio::io::DuplexStream>>>,
        writer: WriteHalf<tokio::io::DuplexStream>,
        server: tokio::task::JoinHandle<()>,
    }

    impl ProtocolHarness {
        async fn start() -> Self {
            Self::start_at(Path::new(".")).await
        }

        async fn start_at(root: &Path) -> Self {
            let (server_transport, client_transport) = tokio::io::duplex(256 * 1024);
            let root = root.to_path_buf();
            let server = tokio::spawn(async move {
                let service = RevootMcpServer::new(&root)
                    .expect("server")
                    .serve(server_transport)
                    .await
                    .expect("serve");
                let _ = service.waiting().await;
            });
            let (reader, writer) = tokio::io::split(client_transport);
            let mut harness = Self {
                reader: BufReader::new(reader).lines(),
                writer,
                server,
            };
            harness
                .send(json!({
                    "jsonrpc":"2.0",
                    "id":1,
                    "method":"initialize",
                    "params":{
                        "protocolVersion":"2026-07-28",
                        "capabilities":{},
                        "clientInfo":{"name":"revoot-test","version":"1"}
                    }
                }))
                .await;
            let initialized = harness.receive().await;
            assert_eq!(initialized["id"], 1);
            assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
            assert_eq!(initialized["result"]["capabilities"]["tools"], json!({}));
            harness
                .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .await;
            harness
        }

        async fn start_discover() -> Self {
            let (server_transport, client_transport) = tokio::io::duplex(256 * 1024);
            let server = tokio::spawn(async move {
                let service = RevootMcpServer::new(Path::new("."))
                    .expect("server")
                    .serve(server_transport)
                    .await
                    .expect("serve");
                let _ = service.waiting().await;
            });
            let (reader, writer) = tokio::io::split(client_transport);
            let mut harness = Self {
                reader: BufReader::new(reader).lines(),
                writer,
                server,
            };
            harness
                .send(json!({
                    "jsonrpc":"2.0",
                    "id":1,
                    "method":"server/discover",
                    "params":{
                        "_meta":{
                            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                            "io.modelcontextprotocol/clientInfo":{
                                "name":"revoot-test",
                                "version":"1"
                            },
                            "io.modelcontextprotocol/clientCapabilities":{}
                        }
                    }
                }))
                .await;
            let discovered = harness.receive().await;
            assert_eq!(discovered["id"], 1);
            assert!(
                discovered["result"]["supportedVersions"]
                    .as_array()
                    .expect("supported versions")
                    .iter()
                    .any(|version| version == "2026-07-28")
            );
            harness
        }

        async fn request(&mut self, id: u64, method: &str, mut params: Value) -> Value {
            params.as_object_mut().expect("request params").insert(
                "_meta".to_owned(),
                json!({
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities":{}
                }),
            );
            self.send(json!({
                "jsonrpc":"2.0",
                "id":id,
                "method":method,
                "params":params,
            }))
            .await;
            let response = self.receive().await;
            assert_eq!(response["id"], id);
            response
        }

        async fn send(&mut self, value: Value) {
            let mut encoded = serde_json::to_vec(&value).expect("protocol JSON");
            encoded.push(b'\n');
            self.writer
                .write_all(&encoded)
                .await
                .expect("protocol write");
            self.writer.flush().await.expect("protocol flush");
        }

        async fn receive(&mut self) -> Value {
            let line =
                tokio::time::timeout(std::time::Duration::from_secs(5), self.reader.next_line())
                    .await
                    .expect("protocol response timeout")
                    .expect("protocol read")
                    .expect("protocol closed");
            serde_json::from_str(&line).expect("stdout contains protocol JSON only")
        }
    }

    impl Drop for ProtocolHarness {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    struct RepositoryFixture(TempDir);

    impl RepositoryFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("repository");
            fs::create_dir(directory.path().join("src")).expect("source directory");
            git(directory.path(), &["init", "-b", "main"]);
            git(
                directory.path(),
                &["config", "user.email", "revoot@example.invalid"],
            );
            git(directory.path(), &["config", "user.name", "Revoot Test"]);
            git(directory.path(), &["config", "commit.gpgsign", "false"]);
            fs::write(
                directory.path().join("src/lib.rs"),
                "pub fn value() -> u32 { 1 }\n",
            )
            .expect("base source");
            fs::write(
                directory.path().join(".revoot.toml"),
                "version = 1\n[repository]\nguidance = \"BASE_GUIDANCE_SENTINEL\"\n[[rules]]\npaths = [\"**/*.rs\"]\nfocus = [\"correctness\"]\nguidance = \"REPOSITORY_RULE_SENTINEL\"\n",
            )
            .expect("base policy");
            git(directory.path(), &["add", "."]);
            git(directory.path(), &["commit", "-m", "base"]);
            git(directory.path(), &["checkout", "-b", "feature"]);
            fs::write(
                directory.path().join("src/lib.rs"),
                "pub fn value() -> u32 { 2 }\n",
            )
            .expect("feature source");
            Self(directory)
        }

        fn path(&self) -> &Path {
            self.0.path()
        }
    }

    fn git(root: &Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(arguments)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("Git fixture")
                .success()
        );
    }

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

    #[test]
    fn trusted_root_handle_capacity_and_total_result_bounds_fail_closed() {
        let fixture = RepositoryFixture::new();
        let server = RevootMcpServer::new(fixture.path()).expect("server");
        let outside = RepositoryFixture::new();
        let outside_arguments = json!({
            "repository_root": outside.path(),
            "base": "main"
        });
        assert_eq!(
            server.open_review(
                outside_arguments.as_object().expect("outside arguments"),
                &CancellationToken::default(),
            ),
            Err("repository outside server authority")
        );

        let cancelled = CancellationToken::default();
        cancelled.cancel(ProviderCancellationReason::UserRequested);
        assert_eq!(
            server.open_review(
                outside_arguments.as_object().expect("outside arguments"),
                &cancelled,
            ),
            Err("tool call cancelled")
        );

        let arguments = json!({"repository_root": fixture.path(), "base": "main"});
        let first = server
            .open_review(
                arguments.as_object().expect("open arguments"),
                &CancellationToken::default(),
            )
            .expect("first review");
        let first_handle = first["handle"].as_str().expect("first handle").to_owned();
        let first_directory = server
            .reviews
            .lock()
            .expect("reviews")
            .get(&first_handle)
            .expect("first review")
            .diffs
            .directory_path()
            .to_path_buf();
        for _ in 1..=MAX_LIVE_REVIEWS {
            server
                .open_review(
                    arguments.as_object().expect("open arguments"),
                    &CancellationToken::default(),
                )
                .expect("bounded review");
        }
        assert_eq!(
            server.reviews.lock().expect("reviews").len(),
            MAX_LIVE_REVIEWS
        );
        assert!(
            !server
                .reviews
                .lock()
                .expect("reviews")
                .contains_key(&first_handle)
        );
        assert!(!first_directory.exists());

        let small = bounded_success(json!({"status":"ok"}));
        assert!(serde_json::to_vec(&small).expect("small result").len() <= MCP_RESULT_BYTES);
        assert!(small.content.is_empty());
        let oversized = bounded_success(json!({"body":"x".repeat(MCP_RESULT_BYTES)}));
        assert_eq!(oversized.is_error, Some(true));
    }

    #[tokio::test]
    async fn protocol_negotiates_lists_tools_and_rejects_unknown_handles_cleanly() {
        let mut harness = ProtocolHarness::start().await;
        let listed = harness.request(2, "tools/list", json!({})).await;
        let tools = listed["result"]["tools"].as_array().expect("listed tools");
        assert_eq!(tools.len(), 9);
        assert!(tools.iter().any(|tool| tool["name"] == "revoot_get_rules"));

        let unknown = harness
            .request(
                3,
                "tools/call",
                json!({
                    "name":"revoot_list_changed_files",
                    "arguments":{"handle":"unknown-handle"}
                }),
            )
            .await;
        assert_eq!(unknown["result"]["isError"], true);
        assert!(
            unknown["result"]["content"][0]["text"]
                .as_str()
                .expect("error text")
                .contains("stale or unknown review handle")
        );
        assert!(encoded_value_len(&unknown["result"]) <= MCP_RESULT_BYTES);

        harness
            .send(json!({
                "jsonrpc":"2.0",
                "method":"notifications/cancelled",
                "params":{"requestId":999,"reason":"test cancellation"}
            }))
            .await;
        let after_cancellation = harness.request(4, "tools/list", json!({})).await;
        assert_eq!(after_cancellation["id"], 4);
    }

    #[tokio::test]
    async fn protocol_supports_stateless_discovery_for_2026_clients() {
        let mut harness = ProtocolHarness::start_discover().await;
        let listed = harness.request(2, "tools/list", json!({})).await;
        assert_eq!(
            listed["result"]["tools"]
                .as_array()
                .expect("listed tools")
                .len(),
            9
        );
    }

    #[tokio::test]
    async fn protocol_rejects_repository_roots_outside_server_authority() {
        let trusted = tempfile::tempdir().expect("trusted root");
        let outside = RepositoryFixture::new();
        let mut harness = ProtocolHarness::start_at(trusted.path()).await;
        let response = harness
            .request(
                7,
                "tools/call",
                json!({
                    "name":"revoot_open_review",
                    "arguments":{"repository_root":outside.path(),"base":"main"}
                }),
            )
            .await;
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["content"][0]["text"],
            "repository outside server authority"
        );
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one protocol session demonstrates handle freshness and effective rule reads"
    )]
    async fn protocol_calls_are_bounded_snapshot_bound_and_rules_are_effective() {
        let fixture = RepositoryFixture::new();
        let mut harness = ProtocolHarness::start_at(fixture.path()).await;
        let opened = harness
            .request(
                10,
                "tools/call",
                json!({
                    "name":"revoot_open_review",
                    "arguments":{
                        "repository_root":fixture.path(),
                        "base":"main"
                    }
                }),
            )
            .await;
        assert_ne!(opened["result"]["isError"], true, "{opened}");
        let handle = opened["result"]["structuredContent"]["handle"]
            .as_str()
            .expect("review handle")
            .to_owned();

        let changed = harness
            .request(
                11,
                "tools/call",
                json!({
                    "name":"revoot_list_changed_files",
                    "arguments":{
                        "handle":handle,
                        "max_result_bytes":1024,
                        "max_matches":10
                    }
                }),
            )
            .await;
        assert_ne!(changed["result"]["isError"], true);
        assert!(encoded_value_len(&changed["result"]["structuredContent"]) <= 1024);
        assert_eq!(changed["result"]["content"], json!([]));
        let manifest = &changed["result"]["structuredContent"]["items"][0];
        let work_unit_id = manifest["work_unit_id"]
            .as_str()
            .expect("work-unit ID")
            .to_owned();
        let hunk_id = manifest["hunks"][0]["hunk_id"]
            .as_str()
            .expect("hunk ID")
            .to_owned();
        let diff = harness
            .request(
                15,
                "tools/call",
                json!({
                    "name":"revoot_read_diff",
                    "arguments":{
                        "handle":handle,
                        "path":"src/lib.rs",
                        "hunk_id":hunk_id,
                        "page":1
                    }
                }),
            )
            .await;
        let anchor_id = diff["result"]["structuredContent"]["items"][0]["anchors"][0]["anchor_id"]
            .as_str()
            .unwrap_or_else(|| panic!("issued anchor: {diff}"))
            .to_owned();
        let envelope = |unit: &str| {
            json!({
                "schema_version":"revoot.findings/v1",
                "work_unit_id":unit,
                "findings":[{
                    "anchor_id":anchor_id,
                    "severity":"high",
                    "confidence_percent":90,
                    "category":"correctness",
                    "title":"Exact delivered issue",
                    "explanation":"The delivered line demonstrates a concrete defect.",
                    "evidence":"The exact issued anchor was read through the bounded diff tool."
                }],
                "summary":"One exact finding."
            })
        };
        let valid = harness
            .request(
                16,
                "tools/call",
                json!({
                    "name":"revoot_validate_findings",
                    "arguments":{"handle":handle,"findings":envelope(&work_unit_id)}
                }),
            )
            .await;
        assert_eq!(valid["result"]["structuredContent"]["valid"], true);
        let cross_unit = harness
            .request(
                17,
                "tools/call",
                json!({
                    "name":"revoot_validate_findings",
                    "arguments":{"handle":handle,"findings":envelope("wu1_fabricated")}
                }),
            )
            .await;
        assert_eq!(cross_unit["result"]["structuredContent"]["valid"], false);

        let metadata = harness
            .request(
                12,
                "tools/call",
                json!({
                    "name":"revoot_get_rules",
                    "arguments":{"handle":handle,"path":"src/lib.rs"}
                }),
            )
            .await;
        let rule_metadata = &metadata["result"]["structuredContent"];
        let rule_ids = rule_metadata["rules"]
            .as_array()
            .expect("rule metadata")
            .iter()
            .map(|rule| rule["id"].as_str().expect("rule ID").to_owned())
            .collect::<Vec<_>>();
        for expected in [
            "compiled:safety-invariants",
            "base:repository-guidance",
            "repository:rule-000",
            "rust.md",
            "generic:review",
        ] {
            assert!(rule_ids.iter().any(|id| id == expected));
        }
        assert_eq!(rule_metadata["guidance"], json!([]));

        let guidance = harness
            .request(
                13,
                "tools/call",
                json!({
                    "name":"revoot_get_rules",
                    "arguments":{
                        "handle":handle,
                        "path":"src/lib.rs",
                        "rule_ids":["base:repository-guidance","repository:rule-000"]
                    }
                }),
            )
            .await;
        let guidance = &guidance["result"]["structuredContent"];
        assert!(encoded_value_len(guidance) <= MCP_RESULT_BYTES);
        assert!(
            guidance["guidance"]
                .as_array()
                .expect("guidance")
                .iter()
                .all(|rule| rule["descriptor"]["untrusted_repository_data"] == true)
        );
        let guidance_text = serde_json::to_string(guidance).expect("guidance JSON");
        assert!(guidance_text.contains("BASE_GUIDANCE_SENTINEL"));
        assert!(guidance_text.contains("REPOSITORY_RULE_SENTINEL"));

        fs::write(
            fixture.path().join("src/lib.rs"),
            "pub fn value() -> u32 { 3 }\n",
        )
        .expect("stale mutation");
        let stale = harness
            .request(
                14,
                "tools/call",
                json!({
                    "name":"revoot_list_changed_files",
                    "arguments":{"handle":handle}
                }),
            )
            .await;
        assert_eq!(stale["result"]["isError"], true);
        assert!(
            stale["result"]["content"][0]["text"]
                .as_str()
                .expect("stale error")
                .contains("stale or unknown review handle")
        );
    }
}
