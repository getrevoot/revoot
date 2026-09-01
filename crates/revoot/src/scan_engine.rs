//! Bounded, model-backed execution for immutable local source scans.
//!
//! The model starts from a body-free manifest and can only obtain source through
//! the bounded chunk reader. Scan findings are bound to an exact delivered
//! post-change path and line, retained locally, and never published.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use revoot_core::{
    AnchorId, AnchorPosition, AnchorTable, CancellationToken, ChangedPath, CommentableLine,
    FileChangeKind, Finding, FindingCategory, FindingsEnvelope, ModelContent, ModelFinishReason,
    ModelMessage, ModelRequest, ModelRole, ModelTool, ProviderAdapter, RankedFinding,
    RepositoryPath, ReviewBudgetBroker, ReviewBudgetSnapshot, ReviewModelReservation,
    ReviewModelUsage, ReviewSnapshotIdentity, ScanFileInput, ScanPlan, Severity, Sha256Digest,
    validate_rank_and_render,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_FINDINGS: usize = 25;
const MAX_TOOL_CALLS_PER_TURN: usize = 32;
const MAX_TOOL_RESULT_BYTES: usize = 32 * 1024;
const MAX_SCAN_PAGE_BYTES: usize = 16 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_REQUEST_INPUT_TOKENS: u64 = 32_000;
const MAX_OUTPUT_TOKENS: u32 = 4_096;
const MAX_RULE_IDS: usize = 256;
const MAX_RULE_ID_BYTES: usize = 128;

/// Monotonic clock in the aggregate budget broker's clock domain.
pub trait ScanEngineClock: Send + Sync {
    fn now_millis(&self) -> u64;
}

/// Per-execution limits which may only narrow product-wide bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanEngineLimits {
    pub max_turns: u32,
    pub max_input_tokens: u64,
    pub max_output_tokens: u32,
    pub reserved_cost_microusd: u64,
    pub minimum_confidence_percent: u8,
}

impl Default for ScanEngineLimits {
    fn default() -> Self {
        Self {
            max_turns: 20,
            max_input_tokens: MAX_REQUEST_INPUT_TOKENS,
            max_output_tokens: MAX_OUTPUT_TOKENS,
            reserved_cost_microusd: 500_000,
            minimum_confidence_percent: 85,
        }
    }
}

/// Trusted immutable input for one local scan execution.
pub struct ScanEngineRequest {
    pub model: String,
    pub system_policy: String,
    pub rule_ids: Vec<String>,
    pub plan: ScanPlan,
    pub inputs: Vec<ScanFileInput>,
    pub limits: ScanEngineLimits,
}

impl fmt::Debug for ScanEngineRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanEngineRequest")
            .field("model", &self.model)
            .field("system_policy", &"[redacted]")
            .field("rule_count", &self.rule_ids.len())
            .field("plan_sha256", &self.plan.plan_sha256)
            .field("input_count", &self.inputs.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Body-free progress over the immutable scan plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanEngineCoverage {
    pub selected_files: u32,
    pub omitted_files: u32,
    pub total_chunks: u32,
    pub delivered_chunks: u32,
    pub fully_read_files: u32,
    pub complete: bool,
}

/// Closed reason a scan safely returned verified partial findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanEnginePartialReason {
    InputOmissions,
    Cancelled,
    Budget,
    Provider,
    ProviderContract,
    Context,
    TurnBudget,
}

/// Terminal state for local scan output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum ScanEngineStatus {
    Complete,
    Partial(ScanEnginePartialReason),
}

/// Typed local findings and their trusted post-change anchor table.
#[derive(Serialize)]
pub struct ScanEngineOutput {
    pub schema_version: &'static str,
    pub findings: Vec<RankedFinding>,
    pub anchors: AnchorTable,
    pub status: ScanEngineStatus,
    pub coverage: ScanEngineCoverage,
    pub budget: ReviewBudgetSnapshot,
    pub provider_turns: u32,
    pub tool_calls: u32,
    pub suppressed_candidates: u32,
}

impl fmt::Debug for ScanEngineOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanEngineOutput")
            .field("schema_version", &self.schema_version)
            .field("finding_count", &self.findings.len())
            .field("anchor_count", &self.anchors.len())
            .field("status", &self.status)
            .field("coverage", &self.coverage)
            .field("budget", &self.budget)
            .field("provider_turns", &self.provider_turns)
            .field("tool_calls", &self.tool_calls)
            .field("suppressed_candidates", &self.suppressed_candidates)
            .finish()
    }
}

impl ScanEngineOutput {
    pub const SCHEMA_VERSION: &'static str = "revoot.scan-report/v1";

    /// Render a compact local-only summary without source bodies.
    #[must_use]
    pub fn human(&self) -> String {
        format!(
            "Scan {:?}: {} findings; {}/{} chunks delivered; {} files fully read; {} files omitted\n",
            self.status,
            self.findings.len(),
            self.coverage.delivered_chunks,
            self.coverage.total_chunks,
            self.coverage.fully_read_files,
            self.coverage.omitted_files,
        )
    }
}

/// Payload-free failure for invalid trusted construction or result projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanEngineError {
    Configuration,
    Replay,
    InputBinding,
    FindingProjection,
}

impl fmt::Display for ScanEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "scan engine configuration is invalid",
            Self::Replay => "scan plan replay validation failed",
            Self::InputBinding => "scan inputs do not match the immutable plan",
            Self::FindingProjection => "scan findings could not be projected safely",
        })
    }
}

impl std::error::Error for ScanEngineError {}

#[derive(Clone)]
struct PendingFinding {
    path: RepositoryPath,
    line: u32,
    finding: FindingBody,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingBody {
    severity: Severity,
    confidence_percent: u8,
    category: FindingCategory,
    title: String,
    explanation: String,
    evidence: String,
    #[serde(default)]
    suggested_replacement: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadChunkArgs {
    chunk_id: String,
    page: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitFindingsArgs {
    findings: Vec<SubmittedFinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmittedFinding {
    path: String,
    line: u32,
    chunk_id: String,
    #[serde(flatten)]
    finding: FindingBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteArgs {}

#[derive(Serialize)]
struct ScanManifest<'a> {
    schema_version: &'static str,
    plan_sha256: &'a Sha256Digest,
    snapshot: &'a revoot_core::LocalSnapshotIdentity,
    rule_ids: &'a [String],
    files: Vec<ScanManifestFile<'a>>,
    omissions: &'a [revoot_core::ScanOmission],
    instructions: &'static str,
}

#[derive(Serialize)]
struct ScanManifestFile<'a> {
    path: &'a RepositoryPath,
    content_sha256: &'a Sha256Digest,
    line_count: u32,
    chunks: Vec<ScanManifestChunk<'a>>,
}

#[derive(Serialize)]
struct ScanManifestChunk<'a> {
    id: &'a str,
    start_line: u32,
    end_line: u32,
    body_bytes: u32,
    body_sha256: &'a Sha256Digest,
    pages: u32,
}

struct RecentExchange {
    calls: Vec<(String, String, Value)>,
    results: Vec<(String, String, bool)>,
}

struct Runtime {
    inputs: BTreeMap<RepositoryPath, String>,
    chunks: BTreeMap<String, (RepositoryPath, u32, u32, usize, usize, Sha256Digest)>,
    delivered: BTreeSet<String>,
    delivered_pages: BTreeMap<String, BTreeSet<u32>>,
    pending: Vec<PendingFinding>,
    seen_calls: BTreeSet<String>,
    suppressed: u32,
    provider_turns: u32,
    tool_calls: u32,
}

/// Execute a bounded local scan from a body-free manifest and chunk reads.
///
/// Operational provider, coverage, cancellation, and budget failures return a
/// typed partial result containing any already validated findings. Only invalid
/// trusted construction returns an error.
///
/// # Errors
///
/// Returns a payload-free error when the immutable plan, inputs, configuration,
/// or trusted finding projection is invalid.
#[allow(clippy::too_many_lines)]
pub async fn run_scan_engine(
    adapter: &dyn ProviderAdapter,
    request: ScanEngineRequest,
    budget: &ReviewBudgetBroker,
    cancellation: &CancellationToken,
    clock: &dyn ScanEngineClock,
) -> Result<ScanEngineOutput, ScanEngineError> {
    validate_request(adapter, &request)?;
    request
        .plan
        .validate_replay(&request.inputs)
        .map_err(|_| ScanEngineError::Replay)?;
    let mut runtime = runtime(&request)?;
    if runtime.chunks.is_empty() {
        let status = if request.plan.omissions.is_empty() {
            ScanEngineStatus::Complete
        } else {
            ScanEngineStatus::Partial(ScanEnginePartialReason::InputOmissions)
        };
        return finish(&request, &runtime, status, budget);
    }

    let manifest = render_manifest(&request, &runtime)?;
    let mut recent = None;
    for _ in 0..request.limits.max_turns {
        if cancellation.is_cancelled() {
            return finish(
                &request,
                &runtime,
                ScanEngineStatus::Partial(ScanEnginePartialReason::Cancelled),
                budget,
            );
        }
        let model_request = compose_request(&request, &manifest, recent.as_ref())?;
        let encoded =
            serde_json::to_vec(&model_request).map_err(|_| ScanEngineError::Configuration)?;
        let input_tokens = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        if input_tokens > request.limits.max_input_tokens {
            return finish(
                &request,
                &runtime,
                ScanEngineStatus::Partial(ScanEnginePartialReason::Context),
                budget,
            );
        }
        let reservation = ReviewModelReservation {
            input_tokens,
            output_tokens: u64::from(request.limits.max_output_tokens),
            cost_microusd: request.limits.reserved_cost_microusd,
        };
        let Ok(permit) = budget.reserve_model_request(reservation, clock.now_millis()) else {
            return finish(
                &request,
                &runtime,
                ScanEngineStatus::Partial(ScanEnginePartialReason::Budget),
                budget,
            );
        };
        runtime.provider_turns = runtime.provider_turns.saturating_add(1);
        let Ok(response) = adapter.complete(&model_request, cancellation).await else {
            drop(permit);
            return finish(
                &request,
                &runtime,
                ScanEngineStatus::Partial(ScanEnginePartialReason::Provider),
                budget,
            );
        };
        let reported = (response.usage.input_tokens != 0 || response.usage.output_tokens != 0)
            .then_some(ReviewModelUsage {
                input_tokens: response.usage.input_tokens,
                output_tokens: response.usage.output_tokens,
                cost_microusd: request.limits.reserved_cost_microusd,
            });
        if permit.commit(reported, clock.now_millis()).is_err() {
            return finish(
                &request,
                &runtime,
                ScanEngineStatus::Partial(ScanEnginePartialReason::Budget),
                budget,
            );
        }
        let Some(calls) = response_calls(&response, &request.model) else {
            return finish(
                &request,
                &runtime,
                ScanEngineStatus::Partial(ScanEnginePartialReason::ProviderContract),
                budget,
            );
        };
        if calls
            .iter()
            .enumerate()
            .any(|(index, (_, name, _))| name == "complete_scan" && index + 1 != calls.len())
        {
            return finish(
                &request,
                &runtime,
                ScanEngineStatus::Partial(ScanEnginePartialReason::ProviderContract),
                budget,
            );
        }

        let mut results = Vec::with_capacity(calls.len());
        let mut terminal = None;
        // Batched tool calls are parallel from the model's perspective. A
        // sibling read result cannot authorize a finding or completion until
        // that result has been returned in the next rebased turn.
        let eligible_delivered = runtime.delivered.clone();
        for (id, name, arguments) in &calls {
            if !runtime.seen_calls.insert(id.clone()) {
                terminal = Some(ScanEngineStatus::Partial(
                    ScanEnginePartialReason::ProviderContract,
                ));
                break;
            }
            if budget.charge_tool_calls(1, clock.now_millis()).is_err() {
                terminal = Some(ScanEngineStatus::Partial(ScanEnginePartialReason::Budget));
                break;
            }
            runtime.tool_calls = runtime.tool_calls.saturating_add(1);
            let (body, is_error, completed) = execute_tool(
                name,
                arguments.clone(),
                &request,
                &mut runtime,
                &eligible_delivered,
            );
            results.push((id.clone(), body, is_error));
            if completed {
                terminal = Some(if request.plan.omissions.is_empty() {
                    ScanEngineStatus::Complete
                } else {
                    ScanEngineStatus::Partial(ScanEnginePartialReason::InputOmissions)
                });
            }
        }
        if let Some(status) = terminal {
            return finish(&request, &runtime, status, budget);
        }
        recent = Some(RecentExchange { calls, results });
    }
    finish(
        &request,
        &runtime,
        ScanEngineStatus::Partial(ScanEnginePartialReason::TurnBudget),
        budget,
    )
}

fn validate_request(
    adapter: &dyn ProviderAdapter,
    request: &ScanEngineRequest,
) -> Result<(), ScanEngineError> {
    if adapter.adapter_id().is_empty()
        || request.model.is_empty()
        || request.model.len() > revoot_core::MAX_MODEL_ID_BYTES
        || request.system_policy.is_empty()
        || request.system_policy.len() > 32 * 1024
        || request.rule_ids.len() > MAX_RULE_IDS
        || request.rule_ids.iter().any(|id| {
            id.is_empty()
                || id.len() > MAX_RULE_ID_BYTES
                || id.bytes().any(|byte| byte.is_ascii_control())
        })
        || request.limits.max_turns == 0
        || request.limits.max_input_tokens == 0
        || request.limits.max_input_tokens > MAX_REQUEST_INPUT_TOKENS
        || request.limits.max_output_tokens == 0
        || request.limits.max_output_tokens > MAX_OUTPUT_TOKENS
        || !(1..=100).contains(&request.limits.minimum_confidence_percent)
    {
        return Err(ScanEngineError::Configuration);
    }
    let mut sorted = request.rule_ids.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != request.rule_ids {
        return Err(ScanEngineError::Configuration);
    }
    Ok(())
}

fn runtime(request: &ScanEngineRequest) -> Result<Runtime, ScanEngineError> {
    let inputs = request
        .inputs
        .iter()
        .map(|input| (input.path.clone(), input.content.clone()))
        .collect::<BTreeMap<_, _>>();
    if inputs.len() != request.inputs.len() {
        return Err(ScanEngineError::InputBinding);
    }
    let mut chunks = BTreeMap::new();
    for file in &request.plan.files {
        let content = inputs
            .get(&file.path)
            .ok_or(ScanEngineError::InputBinding)?;
        for chunk in &file.chunks {
            let start =
                usize::try_from(chunk.start_byte).map_err(|_| ScanEngineError::InputBinding)?;
            let end = usize::try_from(chunk.end_byte).map_err(|_| ScanEngineError::InputBinding)?;
            let body = content
                .get(start..end)
                .ok_or(ScanEngineError::InputBinding)?;
            if body.len() > MAX_TOOL_RESULT_BYTES
                || Sha256Digest::of_bytes(body.as_bytes()) != chunk.body_sha256
                || chunks
                    .insert(
                        chunk.id.clone(),
                        (
                            file.path.clone(),
                            chunk.start_line,
                            chunk.end_line,
                            start,
                            end,
                            chunk.body_sha256.clone(),
                        ),
                    )
                    .is_some()
            {
                return Err(ScanEngineError::InputBinding);
            }
        }
    }
    Ok(Runtime {
        inputs,
        chunks,
        delivered: BTreeSet::new(),
        delivered_pages: BTreeMap::new(),
        pending: Vec::new(),
        seen_calls: BTreeSet::new(),
        suppressed: 0,
        provider_turns: 0,
        tool_calls: 0,
    })
}

fn render_manifest(
    request: &ScanEngineRequest,
    runtime: &Runtime,
) -> Result<String, ScanEngineError> {
    serde_json::to_string(&ScanManifest {
        schema_version: "revoot.scan-worker-manifest/v1",
        plan_sha256: &request.plan.plan_sha256,
        snapshot: &request.plan.request.snapshot,
        rule_ids: &request.rule_ids,
        files: request
            .plan
            .files
            .iter()
            .map(|file| ScanManifestFile {
                path: &file.path,
                content_sha256: &file.content_sha256,
                line_count: file.line_count,
                chunks: file
                    .chunks
                    .iter()
                    .map(|chunk| ScanManifestChunk {
                        id: &chunk.id,
                        start_line: chunk.start_line,
                        end_line: chunk.end_line,
                        body_bytes: chunk.body_bytes,
                        body_sha256: &chunk.body_sha256,
                        pages: runtime
                            .chunks
                            .get(&chunk.id)
                            .and_then(|(path, _, _, start, end, _)| {
                                runtime
                                    .inputs
                                    .get(path)
                                    .and_then(|content| content.get(*start..*end))
                            })
                            .map(scan_pages)
                            .and_then(|pages| u32::try_from(pages.len()).ok())
                            .unwrap_or(u32::MAX),
                    })
                    .collect(),
            })
            .collect(),
        omissions: &request.plan.omissions,
        instructions: "Read needed chunks, submit exact path+line findings, then complete only after every chunk was inspected.",
    })
    .map_err(|_| ScanEngineError::Configuration)
}

fn compose_request(
    request: &ScanEngineRequest,
    manifest: &str,
    recent: Option<&RecentExchange>,
) -> Result<ModelRequest, ScanEngineError> {
    let mut messages = vec![ModelMessage {
        role: ModelRole::User,
        content: vec![ModelContent::Text {
            text: manifest.to_owned(),
        }],
    }];
    if let Some(recent) = recent {
        messages.push(ModelMessage {
            role: ModelRole::Assistant,
            content: recent
                .calls
                .iter()
                .map(|(id, name, input)| ModelContent::ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                })
                .collect(),
        });
        messages.push(ModelMessage {
            role: ModelRole::User,
            content: recent
                .results
                .iter()
                .map(|(id, body, is_error)| ModelContent::ToolResult {
                    tool_use_id: id.clone(),
                    content: body.clone(),
                    is_error: *is_error,
                })
                .collect(),
        });
    }
    let model_request = ModelRequest {
        model: request.model.clone(),
        system: Some(request.system_policy.clone()),
        messages,
        tools: scan_tools(),
        max_output_tokens: request.limits.max_output_tokens,
        temperature: Some(0.0),
    };
    model_request
        .validate()
        .map_err(|_| ScanEngineError::Configuration)?;
    Ok(model_request)
}

fn scan_tools() -> Vec<ModelTool> {
    [
        (
            "read_scan_chunk",
            "Read one immutable source chunk page; each result is at most 16 KiB",
            json!({"type":"object","required":["chunk_id","page"],"properties":{"chunk_id":{"type":"string"},"page":{"type":"integer","minimum":1}},"additionalProperties":false}),
        ),
        (
            "submit_scan_findings",
            "Submit bounded findings against exact delivered path and line coordinates",
            json!({"type":"object","required":["findings"],"properties":{"findings":{"type":"array","minItems":1,"maxItems":25,"items":{"type":"object","required":["path","line","chunk_id","severity","confidence_percent","category","title","explanation","evidence"],"properties":{"path":{"type":"string"},"line":{"type":"integer","minimum":1},"chunk_id":{"type":"string"},"severity":{"type":"string","enum":["critical","high","medium","low","info"]},"confidence_percent":{"type":"integer","minimum":0,"maximum":100},"category":{"type":"string","enum":["correctness","security","reliability","performance","maintainability"]},"title":{"type":"string"},"explanation":{"type":"string"},"evidence":{"type":"string"},"suggested_replacement":{"type":["string","null"]}},"additionalProperties":false}}},"additionalProperties":false}),
        ),
        (
            "complete_scan",
            "Complete only after every planned chunk was delivered",
            json!({"type":"object","properties":{},"additionalProperties":false}),
        ),
    ]
    .into_iter()
    .map(|(name, description, input_schema)| ModelTool {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema,
    })
    .collect()
}

fn response_calls(
    response: &revoot_core::ModelResponse,
    model: &str,
) -> Option<Vec<(String, String, Value)>> {
    if response.model != model
        || response.finish_reason != ModelFinishReason::ToolUse
        || response.content.is_empty()
        || serde_json::to_vec(response).ok()?.len() > MAX_PROVIDER_RESPONSE_BYTES
    {
        return None;
    }
    let calls = response
        .content
        .iter()
        .map(|content| match content {
            ModelContent::ToolUse { id, name, input } => {
                Some((id.clone(), name.clone(), input.clone()))
            }
            ModelContent::Text { .. } | ModelContent::ToolResult { .. } => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!calls.is_empty() && calls.len() <= MAX_TOOL_CALLS_PER_TURN).then_some(calls)
}

fn execute_tool(
    name: &str,
    arguments: Value,
    request: &ScanEngineRequest,
    runtime: &mut Runtime,
    eligible_delivered: &BTreeSet<String>,
) -> (String, bool, bool) {
    match name {
        "read_scan_chunk" => match serde_json::from_value::<ReadChunkArgs>(arguments) {
            Ok(args) => read_chunk(&args.chunk_id, args.page, runtime).map_or_else(
                |error| (error.to_owned(), true, false),
                |body| (body, false, false),
            ),
            Err(_) => ("invalid read_scan_chunk input".to_owned(), true, false),
        },
        "submit_scan_findings" => match serde_json::from_value::<SubmitFindingsArgs>(arguments) {
            Ok(args) => submit_findings(args.findings, request, runtime, eligible_delivered)
                .map_or_else(
                    |error| (error.to_owned(), true, false),
                    |body| (body, false, false),
                ),
            Err(_) => ("invalid submit_scan_findings input".to_owned(), true, false),
        },
        "complete_scan" => match serde_json::from_value::<CompleteArgs>(arguments) {
            Ok(CompleteArgs {}) if eligible_delivered.len() == runtime.chunks.len() => {
                ("scan coverage complete".to_owned(), false, true)
            }
            Ok(CompleteArgs {}) => (
                format!(
                    "scan coverage incomplete: {} chunks remain",
                    runtime.chunks.len().saturating_sub(runtime.delivered.len())
                ),
                true,
                false,
            ),
            Err(_) => ("invalid complete_scan input".to_owned(), true, false),
        },
        _ => ("unknown scan tool".to_owned(), true, false),
    }
}

fn read_chunk(chunk_id: &str, page: u32, runtime: &mut Runtime) -> Result<String, &'static str> {
    let (path, _start_line, _end_line, start, end, digest) =
        runtime.chunks.get(chunk_id).ok_or("unknown scan chunk")?;
    let content = runtime.inputs.get(path).ok_or("scan input unavailable")?;
    let body = content.get(*start..*end).ok_or("scan chunk unavailable")?;
    if body.len() > MAX_TOOL_RESULT_BYTES || Sha256Digest::of_bytes(body.as_bytes()) != *digest {
        return Err("scan chunk integrity check failed");
    }
    let pages = scan_pages(body);
    let page_index = usize::try_from(page.saturating_sub(1)).map_err(|_| "invalid scan page")?;
    let (page_start, page_end) = pages.get(page_index).ok_or("invalid scan page")?;
    runtime
        .delivered_pages
        .entry(chunk_id.to_owned())
        .or_default()
        .insert(page);
    if runtime
        .delivered_pages
        .get(chunk_id)
        .is_some_and(|delivered| delivered.len() == pages.len())
    {
        runtime.delivered.insert(chunk_id.to_owned());
    }
    Ok(body[*page_start..*page_end].to_owned())
}

fn scan_pages(body: &str) -> Vec<(usize, usize)> {
    let mut pages = Vec::new();
    let mut start = 0;
    while start < body.len() {
        let mut end = (start + MAX_SCAN_PAGE_BYTES).min(body.len());
        while end > start && !body.is_char_boundary(end) {
            end -= 1;
        }
        // A valid UTF-8 scalar never exceeds four bytes, so this can only be
        // reached for an empty body (which scan plans do not chunk).
        if end == start {
            break;
        }
        pages.push((start, end));
        start = end;
    }
    pages
}

fn submit_findings(
    findings: Vec<SubmittedFinding>,
    request: &ScanEngineRequest,
    runtime: &mut Runtime,
    eligible_delivered: &BTreeSet<String>,
) -> Result<String, &'static str> {
    if findings.is_empty() || findings.len().saturating_add(runtime.pending.len()) > MAX_FINDINGS {
        return Err("scan finding limit exceeded");
    }
    let mut accepted = Vec::new();
    for submitted in findings {
        let path = RepositoryPath::try_from(submitted.path).map_err(|_| "invalid finding path")?;
        let Some((chunk_path, start_line, end_line, ..)) = runtime.chunks.get(&submitted.chunk_id)
        else {
            return Err("unknown finding chunk");
        };
        if !eligible_delivered.contains(&submitted.chunk_id)
            || path != *chunk_path
            || submitted.line == 0
            || submitted.line < *start_line
            || submitted.line > *end_line
        {
            return Err("finding target was not delivered");
        }
        let placeholder = Finding {
            anchor_id: format!("ga1_{}", "0".repeat(64)),
            severity: submitted.finding.severity,
            confidence_percent: submitted.finding.confidence_percent,
            category: submitted.finding.category,
            title: submitted.finding.title.clone(),
            explanation: submitted.finding.explanation.clone(),
            evidence: submitted.finding.evidence.clone(),
            lineage_id: None,
            suggested_replacement: submitted.finding.suggested_replacement.clone(),
        };
        FindingsEnvelope {
            schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
            work_unit_id: scan_work_unit(&request.plan),
            findings: vec![placeholder],
            summary: "Local scan finding.".to_owned(),
        }
        .validate()
        .map_err(|_| "invalid scan finding")?;
        if submitted.finding.confidence_percent < request.limits.minimum_confidence_percent {
            runtime.suppressed = runtime.suppressed.saturating_add(1);
            continue;
        }
        accepted.push(PendingFinding {
            path,
            line: submitted.line,
            finding: submitted.finding,
        });
    }
    runtime.pending.extend(accepted);
    Ok(format!("accepted {} scan findings", runtime.pending.len()))
}

fn finish(
    request: &ScanEngineRequest,
    runtime: &Runtime,
    status: ScanEngineStatus,
    budget: &ReviewBudgetBroker,
) -> Result<ScanEngineOutput, ScanEngineError> {
    let coverage = coverage(&request.plan, runtime);
    let (findings, anchors) = project_findings(request, runtime)?;
    Ok(ScanEngineOutput {
        schema_version: ScanEngineOutput::SCHEMA_VERSION,
        findings,
        anchors,
        status,
        coverage,
        budget: budget.snapshot(),
        provider_turns: runtime.provider_turns,
        tool_calls: runtime.tool_calls,
        suppressed_candidates: runtime.suppressed,
    })
}

fn coverage(plan: &ScanPlan, runtime: &Runtime) -> ScanEngineCoverage {
    let fully_read_files = plan
        .files
        .iter()
        .filter(|file| {
            file.chunks
                .iter()
                .all(|chunk| runtime.delivered.contains(&chunk.id))
        })
        .count();
    let complete = runtime.delivered.len() == runtime.chunks.len() && plan.omissions.is_empty();
    ScanEngineCoverage {
        selected_files: u32::try_from(plan.files.len()).unwrap_or(u32::MAX),
        omitted_files: u32::try_from(plan.omissions.len()).unwrap_or(u32::MAX),
        total_chunks: u32::try_from(runtime.chunks.len()).unwrap_or(u32::MAX),
        delivered_chunks: u32::try_from(runtime.delivered.len()).unwrap_or(u32::MAX),
        fully_read_files: u32::try_from(fully_read_files).unwrap_or(u32::MAX),
        complete,
    }
}

fn project_findings(
    request: &ScanEngineRequest,
    runtime: &Runtime,
) -> Result<(Vec<RankedFinding>, AnchorTable), ScanEngineError> {
    let snapshot = ReviewSnapshotIdentity::Local(request.plan.request.snapshot.clone());
    let mut coordinates = runtime
        .pending
        .iter()
        .map(|finding| (finding.path.clone(), finding.line))
        .collect::<Vec<_>>();
    coordinates.sort();
    coordinates.dedup();
    let lines = coordinates
        .iter()
        .map(|(path, line)| commentable_line(path, *line, runtime))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors =
        AnchorTable::build(snapshot, lines).map_err(|_| ScanEngineError::FindingProjection)?;
    if runtime.pending.is_empty() {
        return Ok((Vec::new(), anchors));
    }
    let by_coordinate = anchors
        .iter()
        .filter_map(|anchor| match anchor.position {
            AnchorPosition::Addition { new_line } => {
                Some(((anchor.path.new_path.clone(), new_line), anchor.id.clone()))
            }
            AnchorPosition::Deletion { .. } | AnchorPosition::Context { .. } => None,
        })
        .collect::<BTreeMap<_, _>>();
    let work_unit_id = scan_work_unit(&request.plan);
    let findings = runtime
        .pending
        .iter()
        .map(|pending| {
            let anchor_id = by_coordinate
                .get(&(pending.path.clone(), pending.line))
                .ok_or(ScanEngineError::FindingProjection)?;
            Ok(Finding {
                anchor_id: anchor_id.as_str().to_owned(),
                severity: pending.finding.severity,
                confidence_percent: pending.finding.confidence_percent,
                category: pending.finding.category,
                title: pending.finding.title.clone(),
                explanation: pending.finding.explanation.clone(),
                evidence: pending.finding.evidence.clone(),
                lineage_id: None,
                suggested_replacement: pending.finding.suggested_replacement.clone(),
            })
        })
        .collect::<Result<Vec<_>, ScanEngineError>>()?;
    let envelope = FindingsEnvelope {
        schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
        work_unit_id: work_unit_id.clone(),
        findings,
        summary: "Local bounded source scan.".to_owned(),
    };
    let issued = BTreeMap::from([(
        work_unit_id,
        anchors
            .iter()
            .map(|anchor| anchor.id.clone())
            .collect::<BTreeSet<AnchorId>>(),
    )]);
    validate_rank_and_render([envelope], &issued, &anchors, MAX_FINDINGS)
        .map(|ranked| (ranked.findings, anchors))
        .map_err(|_| ScanEngineError::FindingProjection)
}

fn commentable_line(
    path: &RepositoryPath,
    line: u32,
    runtime: &Runtime,
) -> Result<CommentableLine, ScanEngineError> {
    let content = runtime
        .inputs
        .get(path)
        .ok_or(ScanEngineError::FindingProjection)?;
    let lines = content.split_inclusive('\n').collect::<Vec<_>>();
    let index =
        usize::try_from(line.saturating_sub(1)).map_err(|_| ScanEngineError::FindingProjection)?;
    let exact = lines.get(index).ok_or(ScanEngineError::FindingProjection)?;
    let context_start = index.saturating_sub(2);
    let context_end = (index + 3).min(lines.len());
    let surrounding_lines = lines[context_start..context_end].concat();
    Ok(CommentableLine {
        path: ChangedPath {
            old_path: path.clone(),
            new_path: path.clone(),
            kind: FileChangeKind::Modified,
        },
        position: AnchorPosition::addition(line).map_err(|_| ScanEngineError::FindingProjection)?,
        exact_line_digest: Sha256Digest::of_bytes(exact.as_bytes()),
        context_digest: Sha256Digest::of_bytes(surrounding_lines.as_bytes()),
    })
}

fn scan_work_unit(plan: &ScanPlan) -> String {
    format!("scan-{}", plan.plan_sha256.as_str())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use revoot_core::{
        DirectProviderErrorKind as ProviderErrorKind, GitSha, LocalSnapshotIdentity, ModelResponse,
        ModelUsage, ProviderError, ProviderFuture, ReviewBudgetLimits, ScanFileTracking,
        ScanLimits, ScanRequestMetadata, ScanUntrackedPolicy, build_scan_plan,
    };

    struct FakeProvider {
        responses: Mutex<VecDeque<Result<ModelResponse, ProviderError>>>,
        requests: Mutex<Vec<ModelRequest>>,
    }

    impl FakeProvider {
        fn new(responses: Vec<Result<ModelResponse, ProviderError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProviderAdapter for FakeProvider {
        fn adapter_id(&self) -> &'static str {
            "fake"
        }

        fn complete<'a>(
            &'a self,
            request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            let response = self.responses.lock().expect("responses").pop_front();
            Box::pin(async move {
                response.unwrap_or_else(|| {
                    Err(ProviderError::new(ProviderErrorKind::Protocol, None, false))
                })
            })
        }
    }

    struct FixedClock;

    impl ScanEngineClock for FixedClock {
        fn now_millis(&self) -> u64 {
            0
        }
    }

    fn sha(marker: char) -> GitSha {
        GitSha::try_from(marker.to_string().repeat(40)).expect("sha")
    }

    fn snapshot() -> LocalSnapshotIdentity {
        LocalSnapshotIdentity {
            repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
            base_sha: sha('a'),
            head_sha: sha('b'),
            working_tree_sha256: Sha256Digest::of_bytes(b"working-tree"),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
        }
    }

    fn fixture() -> (ScanPlan, Vec<ScanFileInput>, String) {
        let inputs = vec![ScanFileInput {
            path: RepositoryPath::try_from("src/lib.rs".to_owned()).expect("path"),
            tracking: ScanFileTracking::Tracked,
            content: "let safe = 1;\nunsafe_call();\n".to_owned(),
        }];
        let plan = build_scan_plan(
            ScanRequestMetadata {
                snapshot: snapshot(),
                requested_paths: Vec::new(),
                untracked_policy: ScanUntrackedPolicy::Exclude,
            },
            ScanLimits::default(),
            inputs.clone(),
        )
        .expect("plan");
        let chunk_id = plan.files[0].chunks[0].id.clone();
        (plan, inputs, chunk_id)
    }

    fn request(plan: ScanPlan, inputs: Vec<ScanFileInput>) -> ScanEngineRequest {
        ScanEngineRequest {
            model: "fake-model".to_owned(),
            system_policy: "Inspect source only through the bounded tools.".to_owned(),
            rule_ids: vec!["generic:review".to_owned()],
            plan,
            inputs,
            limits: ScanEngineLimits::default(),
        }
    }

    fn response(calls: Vec<(&str, &str, Value)>) -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "fake-model".to_owned(),
            content: calls
                .into_iter()
                .map(|(id, name, input)| ModelContent::ToolUse {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    input,
                })
                .collect(),
            finish_reason: ModelFinishReason::ToolUse,
            usage: ModelUsage {
                input_tokens: 100,
                output_tokens: 20,
                cached_input_tokens: 0,
            },
        }
    }

    fn budget(limits: ReviewBudgetLimits) -> ReviewBudgetBroker {
        ReviewBudgetBroker::new(limits, 0).expect("budget")
    }

    #[tokio::test]
    async fn begins_body_free_then_binds_finding_to_delivered_line() {
        let (plan, inputs, chunk_id) = fixture();
        let provider = FakeProvider::new(vec![
            Ok(response(vec![(
                "read-1",
                "read_scan_chunk",
                json!({"chunk_id": chunk_id, "page": 1}),
            )])),
            Ok(response(vec![
                (
                    "submit-1",
                    "submit_scan_findings",
                    json!({"findings":[{
                        "path":"src/lib.rs",
                        "line":2,
                        "chunk_id":chunk_id,
                        "severity":"high",
                        "confidence_percent":95,
                        "category":"security",
                        "title":"Unsafe operation bypasses validation",
                        "explanation":"The operation executes without validating its input.",
                        "evidence":"The delivered line invokes the unsafe operation directly."
                    }]}),
                ),
                ("complete-1", "complete_scan", json!({})),
            ])),
        ]);
        let output = run_scan_engine(
            &provider,
            request(plan, inputs),
            &budget(ReviewBudgetLimits::default()),
            &CancellationToken::default(),
            &FixedClock,
        )
        .await
        .expect("scan");

        assert_eq!(output.status, ScanEngineStatus::Complete);
        assert!(output.coverage.complete);
        assert_eq!(output.findings.len(), 1);
        let anchor = output
            .anchors
            .resolve(output.findings[0].anchor_id.as_str())
            .expect("trusted scan anchor");
        assert_eq!(anchor.path.new_path.as_str(), "src/lib.rs");
        assert_eq!(anchor.position, AnchorPosition::Addition { new_line: 2 });

        let requests = provider.requests.lock().expect("requests");
        let initial = serde_json::to_string(&requests[0]).expect("initial request");
        assert!(!initial.contains("unsafe_call"));
        assert!(initial.contains("revoot.scan-worker-manifest/v1"));
        let rebased = serde_json::to_string(&requests[1]).expect("rebased request");
        assert!(rebased.contains("unsafe_call"));
    }

    #[tokio::test]
    async fn rejects_early_completion_and_accepts_correction_after_read_result() {
        let (plan, inputs, chunk_id) = fixture();
        let provider = FakeProvider::new(vec![
            Ok(response(vec![(
                "complete-early",
                "complete_scan",
                json!({}),
            )])),
            Ok(response(vec![(
                "read-1",
                "read_scan_chunk",
                json!({"chunk_id": chunk_id, "page": 1}),
            )])),
            Ok(response(vec![(
                "complete-final",
                "complete_scan",
                json!({}),
            )])),
        ]);
        let output = run_scan_engine(
            &provider,
            request(plan, inputs),
            &budget(ReviewBudgetLimits::default()),
            &CancellationToken::default(),
            &FixedClock,
        )
        .await
        .expect("scan");
        assert_eq!(output.status, ScanEngineStatus::Complete);
        assert_eq!(output.provider_turns, 3);
        assert_eq!(output.tool_calls, 3);
    }

    #[tokio::test]
    async fn exhausted_budget_returns_redacted_partial_coverage() {
        let (plan, inputs, chunk_id) = fixture();
        let provider = FakeProvider::new(vec![Ok(response(vec![(
            "read-1",
            "read_scan_chunk",
            json!({"chunk_id": chunk_id, "page": 1}),
        )]))]);
        let limits = ReviewBudgetLimits {
            max_model_requests: 1,
            ..ReviewBudgetLimits::default()
        };
        let output = run_scan_engine(
            &provider,
            request(plan, inputs),
            &budget(limits),
            &CancellationToken::default(),
            &FixedClock,
        )
        .await
        .expect("partial scan");
        assert_eq!(
            output.status,
            ScanEngineStatus::Partial(ScanEnginePartialReason::Budget)
        );
        assert_eq!(output.coverage.delivered_chunks, 1);
        assert!(!format!("{output:?}").contains("unsafe_call"));
    }

    #[tokio::test]
    async fn provider_failure_retains_already_validated_local_findings() {
        let (plan, inputs, chunk_id) = fixture();
        let provider = FakeProvider::new(vec![
            Ok(response(vec![(
                "read-1",
                "read_scan_chunk",
                json!({"chunk_id": chunk_id, "page": 1}),
            )])),
            Ok(response(vec![(
                "submit-1",
                "submit_scan_findings",
                json!({"findings":[{
                    "path":"src/lib.rs",
                    "line":2,
                    "chunk_id":chunk_id,
                    "severity":"high",
                    "confidence_percent":95,
                    "category":"reliability",
                    "title":"Unchecked operation can fail",
                    "explanation":"The operation has no visible failure handling.",
                    "evidence":"The delivered line calls the operation without a guard."
                }]}),
            )])),
            Err(ProviderError::new(
                ProviderErrorKind::Unavailable,
                Some(503),
                true,
            )),
        ]);
        let output = run_scan_engine(
            &provider,
            request(plan, inputs),
            &budget(ReviewBudgetLimits::default()),
            &CancellationToken::default(),
            &FixedClock,
        )
        .await
        .expect("partial scan");
        assert_eq!(
            output.status,
            ScanEngineStatus::Partial(ScanEnginePartialReason::Provider)
        );
        assert_eq!(output.findings.len(), 1);
        assert!(
            output
                .anchors
                .resolve(output.findings[0].anchor_id.as_str())
                .is_some()
        );
    }

    #[tokio::test]
    async fn cancellation_stops_before_provider_dispatch() {
        let (plan, inputs, _) = fixture();
        let provider = FakeProvider::new(Vec::new());
        let cancellation = CancellationToken::default();
        cancellation.cancel(revoot_core::ProviderCancellationReason::UserRequested);
        let output = run_scan_engine(
            &provider,
            request(plan, inputs),
            &budget(ReviewBudgetLimits::default()),
            &cancellation,
            &FixedClock,
        )
        .await
        .expect("cancelled scan");
        assert_eq!(
            output.status,
            ScanEngineStatus::Partial(ScanEnginePartialReason::Cancelled)
        );
        assert!(provider.requests.lock().expect("requests").is_empty());
    }
}
