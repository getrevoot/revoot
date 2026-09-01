//! Isolated, bounded provider loop for one review group.
//!
//! The worker owns planning and effort rounds, fresh-turn packet composition,
//! assigned-path tool authority, trusted coverage accounting, and deterministic
//! candidate preparation. Verification and global adjudication are separate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use revoot_core::review_packet::{
    ReviewPacket, ReviewPacketComposer, ReviewPacketComposition, ReviewPacketDiffContext,
    ReviewPacketFindingSummary, ReviewPacketInput, ReviewPacketPlanSummary, ReviewPacketPurpose,
    ReviewPacketRecentExchange, ReviewPacketToolCall, ReviewPacketToolResult,
};
use revoot_core::{
    AgentBudget, AgentBudgetLimits, AgentBudgetUsage, AnchorId, AnchorTable, CancellationToken,
    CandidateForVerification, CodeSearchRequest, CompleteGroupRejection, CoverageCompletionGate,
    GroupCompletion, GroupCoverageLedger, GroupPartialCause, LineRange, ModelContent,
    ModelFinishReason, ModelMessage, ModelRequest, ModelRole, ModelTool, PreparedVerificationBatch,
    PriorReviewContext, ProviderAdapter, RepositoryPath, RepositoryRelativePath, RepositoryToolbox,
    ReviewBudgetBroker, ReviewModelReservation, ReviewModelSettlement, ReviewModelUsage,
    ReviewWorkerCheckpoint, ReviewWorkerError, ReviewWorkerPhase, ReviewWorkerPlan,
    ReviewWorkerState, Sha256Digest, UnreadHunkDisposition, WorkUnitId, prepare_verification_batch,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::diff_artifact::{DiffArtifactStore, DiffSearchKind, DiffSearchRequest};
use crate::git_history::GitHistoryToolbox;
use crate::review_rule_bundle::ReviewRuleBundle;

#[cfg(test)]
use crate::diff_artifact::MAX_INLINE_GROUP_DIFF_BYTES;
#[cfg(test)]
use revoot_core::review_packet::ReviewPacketCompleteDiff;

const MAX_TOOL_CALLS_PER_TURN: usize = 32;
const MAX_TOOL_RESULT_BYTES: usize = 32 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_REQUEST_BYTES: usize = 32_000;
const MAX_REQUEST_INPUT_TOKENS: u64 = 32_000;
const MAX_SUMMARY_BYTES: usize = 4 * 1024;
const MAX_SUMMARY_ASSUMPTIONS: usize = 64;
const MAX_SUMMARY_ASSUMPTION_BYTES: usize = 512;
const MAX_CANDIDATES: usize = 25;

/// Monotonic clock supplied by the review controller.
pub trait GroupWorkerClock: Send + Sync {
    fn now_millis(&self) -> u64;
}

/// Provider and local-resource limits for one isolated worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupWorkerLimits {
    pub max_output_tokens: u32,
    pub max_input_tokens: u64,
    pub reserved_cost_microusd: u64,
    pub max_request_bytes: usize,
    pub local_tool_budget: AgentBudgetLimits,
}

impl Default for GroupWorkerLimits {
    fn default() -> Self {
        Self {
            max_output_tokens: 4_096,
            max_input_tokens: MAX_REQUEST_INPUT_TOKENS,
            reserved_cost_microusd: 500_000,
            max_request_bytes: MAX_REQUEST_BYTES,
            local_tool_budget: AgentBudgetLimits::default(),
        }
    }
}

/// Complete trusted input for one group. Payload-bearing fields have no Debug
/// surface and are consumed by the worker.
pub struct GroupWorkerRequest {
    pub model: String,
    pub system_policy: String,
    pub plan: ReviewWorkerPlan,
    pub initial_packet: ReviewPacketInput,
    /// Trusted candidate-target path to originating partition work-unit ID.
    /// Both old-side deletion targets and new-side addition/context targets
    /// are represented when the group spans multiple work units.
    pub work_unit_ids_by_path: BTreeMap<RepositoryPath, WorkUnitId>,
    pub assigned_paths: BTreeSet<RepositoryRelativePath>,
    pub issued_anchors: BTreeSet<AnchorId>,
    pub anchor_table: AnchorTable,
    pub coverage_gate: CoverageCompletionGate,
    pub rule_bundle: ReviewRuleBundle,
    pub history: Option<Arc<GitHistoryToolbox>>,
    pub prior_review: PriorReviewContext,
    pub limits: GroupWorkerLimits,
}

impl fmt::Debug for GroupWorkerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupWorkerRequest")
            .field("model", &self.model)
            .field("system_policy", &"[redacted]")
            .field("group_id", &self.plan.group_id)
            .field("assigned_path_count", &self.assigned_paths.len())
            .field("work_unit_binding_count", &self.work_unit_ids_by_path.len())
            .field("issued_anchor_count", &self.issued_anchors.len())
            .field("rule_count", &self.rule_bundle.rule_count())
            .field("history_available", &self.history.is_some())
            .field("prior_review_count", &self.prior_review.discussions().len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Narrow evidence delivered by a successful read tool and eligible for the
/// verifier request.
#[derive(Clone, Eq, PartialEq)]
pub struct GroupWorkerEvidence {
    pub evidence_id: String,
    pub content: String,
}

impl fmt::Debug for GroupWorkerEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupWorkerEvidence")
            .field("evidence_id", &self.evidence_id)
            .field("content", &"[redacted]")
            .field("bytes", &self.content.len())
            .finish()
    }
}

/// Bounded model-authored group summary returned to global adjudication.
#[derive(Clone, Eq, PartialEq)]
pub struct GroupWorkerSummary {
    pub text: String,
    pub assumptions: Vec<String>,
}

impl fmt::Debug for GroupWorkerSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupWorkerSummary")
            .field("text", &"[redacted]")
            .field("assumption_count", &self.assumptions.len())
            .finish()
    }
}

impl GroupWorkerSummary {
    fn partial() -> Self {
        Self {
            text: "Group review incomplete.".to_owned(),
            assumptions: vec![
                "The group stopped before its coverage contract completed.".to_owned(),
            ],
        }
    }
}

/// Closed reason a valid worker stopped with retained partial results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupWorkerPartialReason {
    Cancelled,
    Budget,
    Provider,
    ProviderContract,
    Tool,
    Coverage,
    Context,
    TurnBudget,
}

/// Terminal coverage and worker status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupWorkerStatus {
    Complete(GroupCompletion),
    Partial(GroupWorkerPartialReason),
}

/// Prepared group output consumed by the existing verifier boundary.
pub struct GroupWorkerOutput {
    pub candidates: PreparedVerificationBatch,
    pub evidence: Vec<GroupWorkerEvidence>,
    pub summary: GroupWorkerSummary,
    pub status: GroupWorkerStatus,
    pub coverage: GroupCoverageLedger,
    pub usage: AgentBudgetUsage,
    pub provider_turns: u32,
    pub tool_calls: u32,
}

impl fmt::Debug for GroupWorkerOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupWorkerOutput")
            .field("candidate_count", &self.candidates.candidates.len())
            .field("evidence_count", &self.evidence.len())
            .field("summary", &self.summary)
            .field("status", &self.status)
            .field("coverage", &self.coverage)
            .field("usage", &self.usage)
            .field("provider_turns", &self.provider_turns)
            .field("tool_calls", &self.tool_calls)
            .finish()
    }
}

/// Payload-free invalid worker construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupWorkerError {
    Configuration,
    GroupBinding,
    PathBinding,
    ArtifactBinding,
    CoverageBinding,
    Packet,
    LocalBudget,
    Candidate,
}

struct WorkerRuntime<'a> {
    toolbox: &'a RepositoryToolbox,
    diff_store: &'a DiffArtifactStore,
    assigned_paths: &'a BTreeSet<RepositoryRelativePath>,
    assigned_provider_paths: BTreeSet<RepositoryPath>,
    issued_anchors: &'a BTreeSet<AnchorId>,
    anchor_table: &'a AnchorTable,
    work_unit_ids_by_path: &'a BTreeMap<RepositoryPath, WorkUnitId>,
    candidate_target_paths: BTreeSet<RepositoryPath>,
    cancellation: &'a CancellationToken,
    clock: &'a dyn GroupWorkerClock,
    history: Option<&'a GitHistoryToolbox>,
    prior_review: &'a PriorReviewContext,
    rule_bundle: &'a ReviewRuleBundle,
    prior_review_cursor: usize,
    local_budget: AgentBudget,
    coverage_gate: Option<CoverageCompletionGate>,
    final_coverage: Option<GroupCoverageLedger>,
    provider_usage: AgentBudgetUsage,
    started_at_millis: u64,
    candidates: Vec<CandidateForVerification>,
    delivered_evidence_ids: BTreeSet<String>,
    evidence: Vec<GroupWorkerEvidence>,
    summary: Option<GroupWorkerSummary>,
    completion: Option<GroupCompletion>,
    checkpoint: ReviewWorkerCheckpoint,
    plan_summary: Option<ReviewPacketPlanSummary>,
    tool_calls: u32,
}

/// Run one isolated planning/review worker to completion or a bounded partial
/// result. Operational failures retain already prepared candidates and narrow
/// evidence; malformed trusted construction fails before provider dispatch.
///
/// # Errors
///
/// Returns only for invalid trusted input or an internal candidate-preparation
/// invariant. Provider, budget, tool, cancellation, and coverage failures are
/// returned as [`GroupWorkerStatus::Partial`].
#[allow(clippy::too_many_lines)]
pub async fn run_group_worker(
    adapter: &dyn ProviderAdapter,
    request: GroupWorkerRequest,
    toolbox: &RepositoryToolbox,
    diff_store: &DiffArtifactStore,
    aggregate_budget: &ReviewBudgetBroker,
    cancellation: &CancellationToken,
    clock: &dyn GroupWorkerClock,
) -> Result<GroupWorkerOutput, GroupWorkerError> {
    validate_request(adapter, &request, diff_store)?;
    let started_at = clock.now_millis();
    let local_budget = AgentBudget::new(request.limits.local_tool_budget, started_at)
        .map_err(|_| GroupWorkerError::LocalBudget)?;
    let assigned_provider_paths = request
        .assigned_paths
        .iter()
        .map(|path| {
            RepositoryPath::try_from(path.as_str().to_owned())
                .map_err(|_| GroupWorkerError::PathBinding)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let candidate_target_paths = request
        .issued_anchors
        .iter()
        .filter_map(|anchor_id| request.anchor_table.resolve(anchor_id.as_str()))
        .filter(|anchor| assigned_provider_paths.contains(&anchor.path.new_path))
        .map(|anchor| match anchor.position {
            revoot_core::AnchorPosition::Deletion { .. } => anchor.path.old_path.clone(),
            revoot_core::AnchorPosition::Addition { .. }
            | revoot_core::AnchorPosition::Context { .. } => anchor.path.new_path.clone(),
        })
        .collect::<BTreeSet<_>>();
    let mut runtime = WorkerRuntime {
        toolbox,
        diff_store,
        assigned_paths: &request.assigned_paths,
        assigned_provider_paths,
        issued_anchors: &request.issued_anchors,
        anchor_table: &request.anchor_table,
        work_unit_ids_by_path: &request.work_unit_ids_by_path,
        candidate_target_paths,
        cancellation,
        clock,
        history: request.history.as_deref(),
        prior_review: &request.prior_review,
        rule_bundle: &request.rule_bundle,
        prior_review_cursor: 0,
        local_budget,
        coverage_gate: Some(request.coverage_gate),
        final_coverage: None,
        provider_usage: AgentBudgetUsage::default(),
        started_at_millis: started_at,
        candidates: Vec::new(),
        delivered_evidence_ids: BTreeSet::new(),
        evidence: Vec::new(),
        summary: None,
        completion: None,
        checkpoint: request.initial_packet.checkpoint.clone(),
        plan_summary: None,
        tool_calls: 0,
    };
    mark_initial_manifest(&mut runtime)?;

    let mut state = ReviewWorkerState::new(request.plan.clone());
    let mut composer = ReviewPacketComposer::new(
        request.plan.group_id.clone(),
        request.initial_packet.group_brief.group_plan_sha256.clone(),
    );
    let mut base_packet = request.initial_packet;
    let mut initial = true;
    let mut recent_exchange = None;
    let mut seen_tool_call_ids = BTreeSet::new();

    loop {
        if cancellation.is_cancelled() {
            return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Cancelled);
        }
        if let Err(error) = state.reserve_provider_turn() {
            let reason = if error == ReviewWorkerError::TurnBudget {
                GroupWorkerPartialReason::TurnBudget
            } else {
                GroupWorkerPartialReason::ProviderContract
            };
            return partial_output(&mut state, &runtime, reason);
        }
        let purpose = if initial {
            ReviewPacketPurpose::GroupInitial
        } else {
            packet_purpose(state.phase()).ok_or(GroupWorkerError::Packet)?
        };
        let packet_input = if initial {
            base_packet.purpose = ReviewPacketPurpose::GroupInitial;
            base_packet.recent_exchange = None;
            base_packet.clone()
        } else {
            rebase_packet(&base_packet, purpose, &runtime, recent_exchange.take())?
        };
        let packet = match composer
            .compose(packet_input)
            .map_err(|_error| GroupWorkerError::Packet)?
        {
            ReviewPacketComposition::Ready(packet) => packet,
            ReviewPacketComposition::Partial(_) => {
                return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Context);
            }
        };
        if initial {
            mark_inline_coverage(&mut runtime, &packet)?;
        }
        initial = false;

        let model_request = compose_model_request(
            &request.model,
            &request.system_policy,
            &packet,
            state.phase(),
            request.limits.max_output_tokens,
        )
        .map_err(|()| GroupWorkerError::Packet)?;
        let encoded_request =
            serde_json::to_vec(&model_request).map_err(|_| GroupWorkerError::Packet)?;
        if encoded_request.len() > request.limits.max_request_bytes {
            return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Context);
        }
        let estimated_input_tokens = packet
            .estimated_input_tokens
            .max(estimate_wire_tokens(encoded_request.len()));
        if estimated_input_tokens > request.limits.max_input_tokens {
            return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Context);
        }
        let reservation = ReviewModelReservation {
            input_tokens: estimated_input_tokens,
            output_tokens: u64::from(request.limits.max_output_tokens),
            cost_microusd: request.limits.reserved_cost_microusd,
        };
        let Ok(permit) = aggregate_budget.reserve_model_request(reservation, clock.now_millis())
        else {
            return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Budget);
        };
        runtime.provider_usage.turns = runtime.provider_usage.turns.saturating_add(1);
        runtime.provider_usage.model_requests =
            runtime.provider_usage.model_requests.saturating_add(1);
        let Ok(response) = adapter.complete(&model_request, cancellation).await else {
            drop(permit);
            record_provider_usage(&mut runtime, reservation);
            return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Provider);
        };
        let reported = (response.usage.input_tokens != 0 || response.usage.output_tokens != 0)
            .then_some(ReviewModelUsage {
                input_tokens: response.usage.input_tokens,
                output_tokens: response.usage.output_tokens,
                cost_microusd: request.limits.reserved_cost_microusd,
            });
        let settlement = permit.commit(reported, clock.now_millis());
        let Ok(settlement) = settlement else {
            record_provider_usage(&mut runtime, reservation);
            return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Budget);
        };
        record_provider_settlement(&mut runtime, settlement);
        let Ok(tool_calls) = validate_provider_response(&response, &request.model) else {
            return partial_output(
                &mut state,
                &runtime,
                GroupWorkerPartialReason::ProviderContract,
            );
        };
        if tool_calls.is_empty() {
            return partial_output(
                &mut state,
                &runtime,
                GroupWorkerPartialReason::ProviderContract,
            );
        }
        if terminal_tool_is_not_last(&tool_calls) {
            return partial_output(
                &mut state,
                &runtime,
                GroupWorkerPartialReason::ProviderContract,
            );
        }

        let mut exchange_calls = Vec::with_capacity(tool_calls.len());
        let mut exchange_results = Vec::with_capacity(tool_calls.len());
        let phase_before = state.phase();
        for (id, name, input) in tool_calls {
            if cancellation.is_cancelled() {
                return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Cancelled);
            }
            if !seen_tool_call_ids.insert(id.clone()) {
                return partial_output(
                    &mut state,
                    &runtime,
                    GroupWorkerPartialReason::ProviderContract,
                );
            }
            if aggregate_budget
                .charge_tool_calls(1, clock.now_millis())
                .is_err()
            {
                return partial_output(&mut state, &runtime, GroupWorkerPartialReason::Budget);
            }
            runtime.tool_calls = runtime.tool_calls.saturating_add(1);
            let body = match execute_tool(
                &name,
                input.clone(),
                &mut state,
                &request.plan,
                &mut runtime,
            ) {
                Ok(body) | Err(ToolExecutionError::Recoverable(body)) => body,
                Err(ToolExecutionError::Partial(reason)) => {
                    return partial_output(&mut state, &runtime, reason);
                }
            };
            exchange_calls.push(ReviewPacketToolCall {
                call_id: id.clone(),
                tool_name: name.clone(),
                arguments: input,
            });
            exchange_results.push(ReviewPacketToolResult {
                call_id: id,
                tool_name: name,
                body,
                truncated: false,
            });
            if runtime.completion.is_some() {
                break;
            }
        }
        if let Some(completion) = runtime.completion.clone() {
            return complete_output(&state, &runtime, completion);
        }
        recent_exchange = if phase_before == state.phase() {
            Some(ReviewPacketRecentExchange {
                assistant_calls: exchange_calls,
                tool_results: exchange_results,
            })
        } else {
            None
        };
    }
}

fn validate_request(
    adapter: &dyn ProviderAdapter,
    request: &GroupWorkerRequest,
    diff_store: &DiffArtifactStore,
) -> Result<(), GroupWorkerError> {
    if request.model.is_empty()
        || request.system_policy.trim().is_empty()
        || request.system_policy.contains('\0')
        || adapter.adapter_id().is_empty()
        || request.limits.max_output_tokens == 0
        || request.limits.max_output_tokens > 4_096
        || request.limits.max_input_tokens == 0
        || request.limits.max_input_tokens > MAX_REQUEST_INPUT_TOKENS
        || request.limits.max_request_bytes == 0
        || request.limits.max_request_bytes > MAX_REQUEST_BYTES
    {
        return Err(GroupWorkerError::Configuration);
    }
    if request.plan.group_id != request.initial_packet.group_brief.group_id
        || request.rule_bundle.group_id().as_str() != request.plan.group_id
        || request.initial_packet.purpose != ReviewPacketPurpose::GroupInitial
        || request.assigned_paths.is_empty()
        || request.assigned_paths.len() != request.initial_packet.group_brief.files.len()
    {
        return Err(GroupWorkerError::GroupBinding);
    }
    validate_rule_bundle_binding(request)?;
    let brief_paths = request
        .initial_packet
        .group_brief
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    if request
        .assigned_paths
        .iter()
        .map(RepositoryRelativePath::as_str)
        .collect::<BTreeSet<_>>()
        != brief_paths
    {
        return Err(GroupWorkerError::PathBinding);
    }
    let assigned = request.assigned_paths.iter().cloned().collect::<Vec<_>>();
    let manifest = diff_store
        .manifest(&assigned)
        .map_err(|_| GroupWorkerError::ArtifactBinding)?;
    let bytes = manifest.iter().map(|file| file.size_bytes).sum::<u64>();
    let hunks = manifest
        .iter()
        .map(|file| u32::try_from(file.hunks.len()).unwrap_or(u32::MAX))
        .fold(0_u32, u32::saturating_add);
    if bytes != request.initial_packet.diff_manifest.complete_diff_bytes
        || hunks != request.initial_packet.diff_manifest.hunk_count
        || u32::try_from(manifest.len()).unwrap_or(u32::MAX)
            != request.initial_packet.diff_manifest.file_count
    {
        return Err(GroupWorkerError::ArtifactBinding);
    }
    if request.coverage_gate.ledger().files.len() != request.assigned_paths.len()
        || request.assigned_paths.iter().any(|path| {
            RepositoryPath::try_from(path.as_str().to_owned())
                .ok()
                .is_none_or(|path| !request.coverage_gate.ledger().files.contains_key(&path))
        })
    {
        return Err(GroupWorkerError::CoverageBinding);
    }
    let assigned_provider_paths = request
        .assigned_paths
        .iter()
        .map(|path| RepositoryPath::try_from(path.as_str().to_owned()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| GroupWorkerError::PathBinding)?;
    let mut candidate_targets = BTreeSet::new();
    for anchor_id in &request.issued_anchors {
        let anchor = request
            .anchor_table
            .resolve(anchor_id.as_str())
            .ok_or(GroupWorkerError::PathBinding)?;
        if !assigned_provider_paths.contains(&anchor.path.new_path) {
            return Err(GroupWorkerError::PathBinding);
        }
        candidate_targets.insert(match anchor.position {
            revoot_core::AnchorPosition::Deletion { .. } => anchor.path.old_path.clone(),
            revoot_core::AnchorPosition::Addition { .. }
            | revoot_core::AnchorPosition::Context { .. } => anchor.path.new_path.clone(),
        });
    }
    let allowed_binding_paths = assigned_provider_paths
        .union(&candidate_targets)
        .cloned()
        .collect::<BTreeSet<_>>();
    if allowed_binding_paths.iter().any(|path| {
        request
            .work_unit_ids_by_path
            .get(path)
            .is_none_or(|id| !valid_work_unit_id(id.as_str()))
    }) || request
        .work_unit_ids_by_path
        .iter()
        .any(|(path, id)| !allowed_binding_paths.contains(path) || !valid_work_unit_id(id.as_str()))
    {
        return Err(GroupWorkerError::GroupBinding);
    }
    Ok(())
}

fn validate_rule_bundle_binding(request: &GroupWorkerRequest) -> Result<(), GroupWorkerError> {
    let packet_rule_ids = request
        .initial_packet
        .policy
        .rule_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let bundle_rule_ids = request.rule_bundle.rule_ids().collect::<BTreeSet<_>>();
    if packet_rule_ids.len() != request.initial_packet.policy.rule_ids.len()
        || packet_rule_ids != bundle_rule_ids
    {
        return Err(GroupWorkerError::GroupBinding);
    }
    Ok(())
}

fn valid_work_unit_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn mark_initial_manifest(runtime: &mut WorkerRuntime<'_>) -> Result<(), GroupWorkerError> {
    let gate = runtime
        .coverage_gate
        .as_mut()
        .ok_or(GroupWorkerError::CoverageBinding)?;
    for path in &runtime.assigned_provider_paths {
        gate.mark_manifested(path)
            .map_err(|_| GroupWorkerError::CoverageBinding)?;
    }
    Ok(())
}

fn mark_inline_coverage(
    runtime: &mut WorkerRuntime<'_>,
    packet: &ReviewPacket,
) -> Result<(), GroupWorkerError> {
    if !matches!(
        packet.diff_context,
        ReviewPacketDiffContext::InlineComplete { .. }
    ) {
        return Ok(());
    }
    let assigned = runtime.assigned_paths.iter().cloned().collect::<Vec<_>>();
    let manifest = runtime
        .diff_store
        .manifest(&assigned)
        .map_err(|_| GroupWorkerError::ArtifactBinding)?;
    let gate = runtime
        .coverage_gate
        .as_mut()
        .ok_or(GroupWorkerError::CoverageBinding)?;
    for file in manifest {
        let path = RepositoryPath::try_from(file.path.as_str().to_owned())
            .map_err(|_| GroupWorkerError::PathBinding)?;
        for hunk in file.hunks {
            for page in 1..=hunk.pages {
                gate.record_hunk_page(&path, &hunk.hunk_id, page)
                    .map_err(|_| GroupWorkerError::CoverageBinding)?;
            }
        }
    }
    Ok(())
}

fn packet_purpose(phase: ReviewWorkerPhase) -> Option<ReviewPacketPurpose> {
    match phase {
        ReviewWorkerPhase::Planning => Some(ReviewPacketPurpose::Planning),
        ReviewWorkerPhase::Reviewing { round } => Some(ReviewPacketPurpose::ReviewRound { round }),
        ReviewWorkerPhase::Verifying => Some(ReviewPacketPurpose::Verification),
        ReviewWorkerPhase::Complete | ReviewWorkerPhase::Partial => None,
    }
}

fn estimate_wire_tokens(encoded_bytes: usize) -> u64 {
    u64::try_from(encoded_bytes).unwrap_or(u64::MAX)
}

fn rebase_packet(
    base: &ReviewPacketInput,
    purpose: ReviewPacketPurpose,
    runtime: &WorkerRuntime<'_>,
    recent_exchange: Option<ReviewPacketRecentExchange>,
) -> Result<ReviewPacketInput, GroupWorkerError> {
    let mut input = base.clone();
    input.purpose = purpose;
    input.checkpoint = runtime.checkpoint.clone();
    input.plan_summary.clone_from(&runtime.plan_summary);
    input.accepted_findings = runtime
        .candidates
        .iter()
        .map(|candidate| {
            Ok(ReviewPacketFindingSummary {
                candidate_id: candidate.candidate_id.clone(),
                anchor_id: AnchorId::try_from(candidate.finding.anchor_id.clone())
                    .map_err(|_| GroupWorkerError::Candidate)?,
                severity: candidate.finding.severity,
                confidence_percent: candidate.finding.confidence_percent,
                category: candidate.finding.category,
                evidence_ids: candidate.evidence_references.clone(),
            })
        })
        .collect::<Result<Vec<_>, GroupWorkerError>>()?;
    input.unresolved_coverage_ids = runtime
        .coverage_gate
        .as_ref()
        .map(|gate| gate.ledger().missing_requirements())
        .unwrap_or_default()
        .into_iter()
        .map(|requirement| {
            let encoded = serde_json::to_vec(&requirement).unwrap_or_default();
            format!("coverage:{}", Sha256Digest::of_bytes(&encoded).as_str())
        })
        .collect();
    input.recent_exchange = recent_exchange;
    input.complete_diff = None;
    input.token_estimates.inline_request_tokens = None;
    Ok(input)
}

fn compose_model_request(
    model: &str,
    system_policy: &str,
    packet: &ReviewPacket,
    phase: ReviewWorkerPhase,
    max_output_tokens: u32,
) -> Result<ModelRequest, ()> {
    let message = render_packet(packet, phase)?;
    let request = ModelRequest {
        model: model.to_owned(),
        system: Some(system_policy.to_owned()),
        messages: vec![ModelMessage {
            role: ModelRole::User,
            content: vec![ModelContent::Text { text: message }],
        }],
        tools: model_tools(),
        max_output_tokens,
        temperature: None,
    };
    request.validate().map_err(|_| ())?;
    Ok(request)
}

#[derive(Serialize)]
struct PacketWire<'a> {
    purpose: &'static str,
    worker_phase: &'static str,
    group_id: &'a str,
    snapshot_sha256: &'a Sha256Digest,
    partition_sha256: &'a Sha256Digest,
    group_plan_sha256: &'a Sha256Digest,
    system_policy_id: &'a str,
    system_policy_sha256: &'a Sha256Digest,
    rule_ids: &'a [String],
    checkpoint: &'a ReviewWorkerCheckpoint,
    plan_summary: Option<PlanSummaryWire<'a>>,
    accepted_findings: Vec<FindingSummaryWire<'a>>,
    unresolved_coverage_ids: &'a [String],
    files: Vec<FileBriefWire<'a>>,
    diff: DiffContextWire<'a>,
    recent_exchange: Option<ExchangeWire<'a>>,
}

#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct PlanSummaryWire<'a> {
    focus_area_ids: &'a [String],
    hunk_ids: &'a [String],
    dependency_question_ids: &'a [String],
    risk_hypothesis_ids: &'a [String],
}

#[derive(Serialize)]
struct FindingSummaryWire<'a> {
    candidate_id: &'a str,
    anchor_id: &'a AnchorId,
    severity: revoot_core::Severity,
    confidence_percent: u8,
    category: revoot_core::FindingCategory,
    evidence_ids: &'a [String],
}

#[derive(Serialize)]
struct FileBriefWire<'a> {
    path: &'a RepositoryPath,
    tier: revoot_core::ReviewValueTier,
    changed_lines: u32,
    hunk_ids: &'a [String],
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum DiffContextWire<'a> {
    InlineComplete {
        body: &'a str,
        sha256: &'a Sha256Digest,
    },
    ManifestOnly {
        sha256: &'a Sha256Digest,
        bytes: u64,
        file_count: u32,
        hunk_count: u32,
    },
}

#[derive(Serialize)]
struct ExchangeWire<'a> {
    assistant_calls: Vec<ToolCallWire<'a>>,
    tool_results: Vec<ToolResultWire<'a>>,
}

#[derive(Serialize)]
struct ToolCallWire<'a> {
    call_id: &'a str,
    tool_name: &'a str,
    arguments: &'a Value,
}

#[derive(Serialize)]
struct ToolResultWire<'a> {
    call_id: &'a str,
    tool_name: &'a str,
    body: &'a str,
    truncated: bool,
}

fn render_packet(packet: &ReviewPacket, phase: ReviewWorkerPhase) -> Result<String, ()> {
    let purpose = match packet.purpose {
        ReviewPacketPurpose::GroupInitial => "group_initial",
        ReviewPacketPurpose::Planning => "planning",
        ReviewPacketPurpose::ReviewRound { .. } => "review_round",
        ReviewPacketPurpose::Verification => "verification",
        ReviewPacketPurpose::Adjudication => "adjudication",
    };
    let worker_phase = match phase {
        ReviewWorkerPhase::Planning => "planning",
        ReviewWorkerPhase::Reviewing { .. } => "reviewing",
        ReviewWorkerPhase::Verifying => "verifying",
        ReviewWorkerPhase::Complete => "complete",
        ReviewWorkerPhase::Partial => "partial",
    };
    let plan_summary = packet.plan_summary.as_ref().map(|plan| PlanSummaryWire {
        focus_area_ids: &plan.focus_area_ids,
        hunk_ids: &plan.hunk_ids,
        dependency_question_ids: &plan.dependency_question_ids,
        risk_hypothesis_ids: &plan.risk_hypothesis_ids,
    });
    let accepted_findings = packet
        .accepted_findings
        .iter()
        .map(|finding| FindingSummaryWire {
            candidate_id: &finding.candidate_id,
            anchor_id: &finding.anchor_id,
            severity: finding.severity,
            confidence_percent: finding.confidence_percent,
            category: finding.category,
            evidence_ids: &finding.evidence_ids,
        })
        .collect();
    let files = packet
        .group_brief
        .files
        .iter()
        .map(|file| FileBriefWire {
            path: &file.path,
            tier: file.tier,
            changed_lines: file.changed_lines,
            hunk_ids: &file.hunk_ids,
        })
        .collect();
    let diff = match &packet.diff_context {
        ReviewPacketDiffContext::InlineComplete { body, sha256 } => {
            DiffContextWire::InlineComplete { body, sha256 }
        }
        ReviewPacketDiffContext::ManifestOnly(manifest) => DiffContextWire::ManifestOnly {
            sha256: &manifest.complete_diff_sha256,
            bytes: manifest.complete_diff_bytes,
            file_count: manifest.file_count,
            hunk_count: manifest.hunk_count,
        },
    };
    let recent_exchange = packet
        .recent_exchange
        .as_ref()
        .map(|exchange| ExchangeWire {
            assistant_calls: exchange
                .assistant_calls
                .iter()
                .map(|call| ToolCallWire {
                    call_id: &call.call_id,
                    tool_name: &call.tool_name,
                    arguments: &call.arguments,
                })
                .collect(),
            tool_results: exchange
                .tool_results
                .iter()
                .map(|result| ToolResultWire {
                    call_id: &result.call_id,
                    tool_name: &result.tool_name,
                    body: &result.body,
                    truncated: result.truncated,
                })
                .collect(),
        });
    serde_json::to_string(&PacketWire {
        purpose,
        worker_phase,
        group_id: &packet.group_brief.group_id,
        snapshot_sha256: &packet.group_brief.snapshot_sha256,
        partition_sha256: &packet.group_brief.partition_sha256,
        group_plan_sha256: &packet.group_brief.group_plan_sha256,
        system_policy_id: &packet.policy.system_policy_id,
        system_policy_sha256: &packet.policy.system_policy_sha256,
        rule_ids: &packet.policy.rule_ids,
        checkpoint: &packet.checkpoint,
        plan_summary,
        accepted_findings,
        unresolved_coverage_ids: &packet.unresolved_coverage_ids,
        files,
        diff,
        recent_exchange,
    })
    .map_err(|_| ())
}

fn model_tools() -> Vec<ModelTool> {
    [
        ("diff_manifest", json!({"type":"object","properties":{},"additionalProperties":false})),
        ("read_diff", json!({"type":"object","required":["reads"],"properties":{"reads":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"object","required":["path","hunk_id","page"],"properties":{"path":{"type":"string"},"hunk_id":{"type":"string"},"page":{"type":"integer","minimum":1}},"additionalProperties":false}}},"additionalProperties":false})),
        ("search_diff", search_schema()),
        ("read_file", json!({"type":"object","required":["reads"],"properties":{"reads":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"object","required":["path","start_line","end_line"],"properties":{"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1}},"additionalProperties":false}}},"additionalProperties":false})),
        ("find_files", json!({"type":"object","required":["query","glob","max_results"],"properties":{"query":{"type":"string"},"glob":{"type":"boolean"},"max_results":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false})),
        ("search_code", search_schema()),
        ("list_change_commits", json!({"type":"object","required":["max_results"],"properties":{"max_results":{"type":"integer","minimum":1,"maximum":256}},"additionalProperties":false})),
        ("show_commit_context", json!({"type":"object","required":["commit"],"properties":{"commit":{"type":"string"}},"additionalProperties":false})),
        ("get_existing_revoot_findings", json!({"type":"object","required":["cursor","max_results"],"properties":{"cursor":{"type":"integer","minimum":0},"max_results":{"type":"integer","minimum":1,"maximum":10}},"additionalProperties":false})),
        ("get_rules", json!({"type":"object","required":["rule_ids"],"properties":{"rule_ids":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"string"}},"after_id":{"type":["string","null"]}},"additionalProperties":false})),
        ("checkpoint_review", json!({"type":"object","required":["checkpoint"],"properties":{"checkpoint":{"type":"object"},"plan_summary":{"type":["object","null"]}},"additionalProperties":false})),
        ("submit_candidate_finding", json!({"type":"object","required":["candidate"],"properties":{"candidate":{"type":"object"}},"additionalProperties":false})),
        ("complete_group", json!({"type":"object","required":["checkpoint","summary"],"properties":{"checkpoint":{"type":"object"},"summary":{"type":"object"},"dispositions":{"type":"array","maxItems":10000}},"additionalProperties":false})),
    ]
    .into_iter()
    .map(|(name, input_schema)| ModelTool {
        name: name.to_owned(),
        description: format!("Bounded internal {name} operation"),
        input_schema,
    })
    .collect()
}

fn search_schema() -> Value {
    json!({"type":"object","required":["query","regex","case_sensitive","paths","max_results"],"properties":{"query":{"type":"string"},"regex":{"type":"boolean"},"case_sensitive":{"type":"boolean"},"paths":{"type":"array","maxItems":32,"items":{"type":"string"}},"kind":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":500}},"additionalProperties":false})
}

fn validate_provider_response(
    response: &revoot_core::ModelResponse,
    expected_model: &str,
) -> Result<Vec<(String, String, Value)>, ()> {
    if response.model != expected_model
        || response.finish_reason != ModelFinishReason::ToolUse
        || response.content.is_empty()
        || serde_json::to_vec(response)
            .map_or(true, |bytes| bytes.len() > MAX_PROVIDER_RESPONSE_BYTES)
    {
        return Err(());
    }
    let calls = response
        .content
        .iter()
        .filter_map(|content| match content {
            ModelContent::ToolUse { id, name, input } => {
                Some((id.clone(), name.clone(), input.clone()))
            }
            ModelContent::Text { .. } | ModelContent::ToolResult { .. } => None,
        })
        .collect::<Vec<_>>();
    if calls.is_empty() || calls.len() > MAX_TOOL_CALLS_PER_TURN {
        return Err(());
    }
    Ok(calls)
}

fn terminal_tool_is_not_last(calls: &[(String, String, Value)]) -> bool {
    calls.iter().enumerate().any(|(index, (_, name, _))| {
        matches!(name.as_str(), "checkpoint_review" | "complete_group") && index + 1 != calls.len()
    })
}

enum ToolExecutionError {
    Recoverable(String),
    Partial(GroupWorkerPartialReason),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadDiffArgs {
    reads: Vec<ReadDiffItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadDiffItem {
    path: String,
    hunk_id: String,
    page: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    regex: bool,
    case_sensitive: bool,
    paths: Vec<String>,
    #[serde(default)]
    kind: Option<String>,
    max_results: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFileArgs {
    reads: Vec<ReadFileItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFileItem {
    path: String,
    start_line: u32,
    end_line: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindFilesArgs {
    query: String,
    glob: bool,
    max_results: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListCommitsArgs {
    max_results: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitContextArgs {
    commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PriorReviewArgs {
    cursor: usize,
    max_results: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRulesArgs {
    rule_ids: Vec<String>,
    #[serde(default)]
    after_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointArgs {
    checkpoint: ReviewWorkerCheckpoint,
    #[serde(default)]
    plan_summary: Option<ReviewPacketPlanSummaryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct ReviewPacketPlanSummaryWire {
    focus_area_ids: Vec<String>,
    hunk_ids: Vec<String>,
    dependency_question_ids: Vec<String>,
    risk_hypothesis_ids: Vec<String>,
}

impl From<ReviewPacketPlanSummaryWire> for ReviewPacketPlanSummary {
    fn from(value: ReviewPacketPlanSummaryWire) -> Self {
        Self {
            focus_area_ids: value.focus_area_ids,
            hunk_ids: value.hunk_ids,
            dependency_question_ids: value.dependency_question_ids,
            risk_hypothesis_ids: value.risk_hypothesis_ids,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateArgs {
    candidate: CandidateForVerification,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteArgs {
    checkpoint: ReviewWorkerCheckpoint,
    summary: SummaryWire,
    #[serde(default)]
    dispositions: Vec<DispositionWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SummaryWire {
    text: String,
    #[serde(default)]
    assumptions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DispositionWire {
    path: String,
    hunk_id: String,
    disposition: UnreadHunkDisposition,
}

fn execute_tool(
    name: &str,
    input: Value,
    state: &mut ReviewWorkerState,
    plan: &ReviewWorkerPlan,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<String, ToolExecutionError> {
    let result = match name {
        "diff_manifest" => execute_manifest(input, runtime),
        "read_diff" => execute_read_diff(input, runtime),
        "search_diff" => execute_search_diff(input, runtime),
        "read_file" => execute_read_file(input, runtime),
        "find_files" => execute_find_files(input, runtime),
        "search_code" => execute_search_code(input, runtime),
        "list_change_commits" => execute_list_commits(input, runtime),
        "show_commit_context" => execute_commit_context(input, runtime),
        "get_existing_revoot_findings" => execute_prior_review(input, runtime),
        "get_rules" => execute_get_rules(input, runtime),
        "checkpoint_review" => execute_checkpoint(input, state, plan, runtime),
        "submit_candidate_finding" => execute_candidate(input, runtime),
        "complete_group" => execute_complete(input, state, plan, runtime),
        _ => Err(ToolExecutionError::Recoverable(tool_error("unknown_tool"))),
    }?;
    encode_result(result)
}

fn execute_manifest(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    strict_input::<EmptyArgs>(input)?;
    let paths = runtime.assigned_paths.iter().cloned().collect::<Vec<_>>();
    let manifest = runtime
        .diff_store
        .manifest(&paths)
        .map_err(|_| recoverable("artifact"))?;
    serde_json::to_value(manifest).map_err(|_| recoverable("serialization"))
}

fn execute_read_diff(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<ReadDiffArgs>(input)?;
    if args.reads.is_empty() || args.reads.len() > 32 {
        return Err(recoverable("bounds"));
    }
    let manifests = runtime
        .diff_store
        .manifest(&runtime.assigned_paths.iter().cloned().collect::<Vec<_>>())
        .map_err(|_| recoverable("artifact"))?;
    let manifest_by_path = manifests
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut pages = Vec::with_capacity(args.reads.len());
    for read in args.reads {
        let path = assigned_path(&read.path, runtime)?;
        let page = runtime
            .diff_store
            .read_hunk_page(&path, &read.hunk_id, read.page)
            .map_err(|_| recoverable("diff_read"))?;
        let provider_path =
            RepositoryPath::try_from(path.as_str().to_owned()).map_err(|_| recoverable("path"))?;
        runtime
            .coverage_gate
            .as_mut()
            .ok_or_else(|| recoverable("coverage"))?
            .record_hunk_page(&provider_path, &page.hunk_id, page.page)
            .map_err(|_| recoverable("coverage"))?;
        let hunk = manifest_by_path
            .get(path.as_str())
            .and_then(|file| file.hunks.iter().find(|hunk| hunk.hunk_id == page.hunk_id))
            .ok_or_else(|| recoverable("artifact"))?;
        let anchors = runtime
            .anchor_table
            .iter()
            .filter(|anchor| runtime.issued_anchors.contains(&anchor.id))
            .filter(|anchor| {
                anchor.path.old_path.as_str() == path.as_str()
                    || anchor.path.new_path.as_str() == path.as_str()
            })
            .filter(|anchor| anchor_in_hunk(anchor.position, hunk))
            .map(|anchor| json!({"anchor_id": anchor.id, "position": anchor.position}))
            .collect::<Vec<_>>();
        pages.push(json!({
            "path": page.path,
            "hunk_id": page.hunk_id,
            "page": page.page,
            "total_pages": page.total_pages,
            "content": page.content,
            "anchors": anchors,
        }));
    }
    let value = json!({"pages": pages});
    record_evidence(&value, runtime)?;
    Ok(value)
}

fn anchor_in_hunk(
    position: revoot_core::AnchorPosition,
    hunk: &crate::diff_artifact::DiffHunkManifest,
) -> bool {
    match position {
        revoot_core::AnchorPosition::Addition { new_line } => {
            new_line >= hunk.new_start && new_line < hunk.new_start.saturating_add(hunk.new_count)
        }
        revoot_core::AnchorPosition::Deletion { old_line } => {
            old_line >= hunk.old_start && old_line < hunk.old_start.saturating_add(hunk.old_count)
        }
        revoot_core::AnchorPosition::Context { old_line, new_line } => {
            old_line >= hunk.old_start
                && old_line < hunk.old_start.saturating_add(hunk.old_count)
                && new_line >= hunk.new_start
                && new_line < hunk.new_start.saturating_add(hunk.new_count)
        }
    }
}

fn execute_search_diff(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<SearchArgs>(input)?;
    let paths = assigned_search_paths(args.paths, runtime)?;
    let kind = match args.kind.as_deref().unwrap_or("any") {
        "any" => DiffSearchKind::Any,
        "added" => DiffSearchKind::Added,
        "deleted" => DiffSearchKind::Deleted,
        "context" => DiffSearchKind::Context,
        _ => return Err(recoverable("search_kind")),
    };
    let result = runtime
        .diff_store
        .search(&DiffSearchRequest {
            query: args.query,
            regex: args.regex,
            case_sensitive: args.case_sensitive,
            paths,
            kind,
            max_results: args.max_results,
        })
        .map_err(|_| recoverable("diff_search"))?;
    let value = serde_json::to_value(result).map_err(|_| recoverable("serialization"))?;
    record_evidence(&value, runtime)?;
    Ok(value)
}

fn execute_read_file(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<ReadFileArgs>(input)?;
    if args.reads.is_empty() || args.reads.len() > 32 {
        return Err(recoverable("bounds"));
    }
    let mut reads = Vec::with_capacity(args.reads.len());
    for read in args.reads {
        if read.start_line == 0
            || read.end_line < read.start_line
            || read.end_line.saturating_sub(read.start_line) >= 500
        {
            return Err(recoverable("range"));
        }
        let path = repository_path(&read.path)?;
        let result = runtime
            .toolbox
            .read_file(
                &path,
                LineRange {
                    start: read.start_line,
                    end: read.end_line,
                },
                &mut runtime.local_budget,
                runtime.cancellation,
                runtime.clock.now_millis(),
            )
            .map_err(|_| repository_partial(runtime))?;
        reads.push(result);
    }
    let value = serde_json::to_value(reads).map_err(|_| recoverable("serialization"))?;
    record_evidence(&value, runtime)?;
    Ok(value)
}

fn execute_find_files(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<FindFilesArgs>(input)?;
    if args.query.is_empty()
        || args.query.len() > 512
        || args.query.contains(['\0', '\n', '\r'])
        || args.max_results == 0
        || args.max_results > 500
    {
        return Err(recoverable("find_files"));
    }
    let matcher = args
        .glob
        .then(|| globset::Glob::new(&args.query).map(|glob| glob.compile_matcher()))
        .transpose()
        .map_err(|_| recoverable("find_files"))?;
    let limit = usize::try_from(args.max_results).unwrap_or(usize::MAX);
    let mut matching = runtime
        .toolbox
        .inventory()
        .files
        .iter()
        .filter(|file| {
            matcher.as_ref().map_or_else(
                || file.path.as_str().contains(&args.query),
                |matcher| matcher.is_match(file.path.as_str()),
            )
        })
        .map(|file| file.path.clone())
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    let truncated = matching.len() > limit;
    matching.truncate(limit);
    runtime
        .local_budget
        .charge_tool(
            1,
            u64::try_from(matching.len()).unwrap_or(u64::MAX),
            0,
            runtime.clock.now_millis(),
        )
        .map_err(|_| ToolExecutionError::Partial(GroupWorkerPartialReason::Budget))?;
    Ok(json!({"paths":matching,"truncated":truncated}))
}

fn execute_search_code(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<SearchArgs>(input)?;
    let paths = repository_search_paths(args.paths, runtime)?;
    let result = runtime
        .toolbox
        .search_code(
            &CodeSearchRequest {
                query: args.query,
                regex: args.regex,
                case_sensitive: args.case_sensitive,
                paths,
                max_results: args.max_results,
            },
            &mut runtime.local_budget,
            runtime.cancellation,
            runtime.clock.now_millis(),
        )
        .map_err(|_| repository_partial(runtime))?;
    let value = serde_json::to_value(result).map_err(|_| recoverable("serialization"))?;
    record_evidence(&value, runtime)?;
    Ok(value)
}

fn execute_list_commits(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<ListCommitsArgs>(input)?;
    let history = runtime
        .history
        .ok_or_else(|| recoverable("history_unavailable"))?;
    let result = history
        .list_change_commits(
            args.max_results,
            &mut runtime.local_budget,
            runtime.cancellation,
            runtime.clock.now_millis(),
        )
        .map_err(|_| repository_partial(runtime))?;
    let value = serde_json::to_value(result).map_err(|_| recoverable("serialization"))?;
    record_evidence(&value, runtime)?;
    Ok(value)
}

fn execute_commit_context(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<CommitContextArgs>(input)?;
    let commit = revoot_core::GitSha::try_from(args.commit).map_err(|_| recoverable("commit"))?;
    let history = runtime
        .history
        .ok_or_else(|| recoverable("history_unavailable"))?;
    let result = history
        .show_commit_context(
            &commit,
            &mut runtime.local_budget,
            runtime.cancellation,
            runtime.clock.now_millis(),
        )
        .map_err(|_| repository_partial(runtime))?;
    let value = serde_json::to_value(result).map_err(|_| recoverable("serialization"))?;
    record_evidence(&value, runtime)?;
    Ok(value)
}

fn execute_prior_review(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<PriorReviewArgs>(input)?;
    if args.cursor != runtime.prior_review_cursor || args.max_results == 0 || args.max_results > 10
    {
        return Err(recoverable("prior_review_cursor"));
    }
    let discussions = runtime.prior_review.discussions();
    if args.cursor > discussions.len() {
        return Err(recoverable("prior_review_cursor"));
    }
    let end = args
        .cursor
        .saturating_add(args.max_results)
        .min(discussions.len());
    let value = json!({
        "discussions": &discussions[args.cursor..end],
        "next_cursor": (end < discussions.len()).then_some(end),
    });
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| recoverable("serialization"))?
        .len();
    runtime
        .local_budget
        .charge_tool(
            1,
            u64::try_from(end.saturating_sub(args.cursor)).unwrap_or(u64::MAX),
            u64::try_from(bytes).unwrap_or(u64::MAX),
            runtime.clock.now_millis(),
        )
        .map_err(|_| ToolExecutionError::Partial(GroupWorkerPartialReason::Budget))?;
    runtime.prior_review_cursor = end;
    record_evidence(&value, runtime)?;
    Ok(value)
}

fn execute_get_rules(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<GetRulesArgs>(input)?;
    let page = runtime
        .rule_bundle
        .read_rules(&args.rule_ids, args.after_id.as_deref())
        .map_err(|_| recoverable("rules"))?;
    runtime
        .local_budget
        .charge_tool(1, 0, 0, runtime.clock.now_millis())
        .map_err(|_| ToolExecutionError::Partial(GroupWorkerPartialReason::Budget))?;
    serde_json::to_value(page).map_err(|_| recoverable("serialization"))
}

fn execute_checkpoint(
    input: Value,
    state: &mut ReviewWorkerState,
    plan: &ReviewWorkerPlan,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<CheckpointArgs>(input)?;
    args.checkpoint
        .validate()
        .map_err(|_| recoverable("checkpoint"))?;
    match state.phase() {
        ReviewWorkerPhase::Planning => {
            let plan_summary = args
                .plan_summary
                .ok_or_else(|| recoverable("plan_summary"))?;
            runtime.plan_summary = Some(plan_summary.into());
            state
                .finish_planning(args.checkpoint.clone())
                .map_err(|_| recoverable("transition"))?;
        }
        ReviewWorkerPhase::Reviewing { round } if usize::from(round) < plan.rounds.len() => {
            if args.plan_summary.is_some() {
                return Err(recoverable("plan_summary"));
            }
            state
                .finish_round(args.checkpoint.clone())
                .map_err(|_| recoverable("transition"))?;
        }
        ReviewWorkerPhase::Reviewing { .. }
        | ReviewWorkerPhase::Verifying
        | ReviewWorkerPhase::Complete
        | ReviewWorkerPhase::Partial => return Err(recoverable("transition")),
    }
    runtime.checkpoint = args.checkpoint;
    Ok(json!({"status":"accepted"}))
}

fn execute_candidate(
    input: Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<CandidateArgs>(input)?;
    if runtime.candidates.len() >= MAX_CANDIDATES
        || runtime
            .candidates
            .iter()
            .any(|candidate| candidate.candidate_id == args.candidate.candidate_id)
    {
        return Err(recoverable("candidate"));
    }
    let anchor = runtime
        .anchor_table
        .resolve(&args.candidate.finding.anchor_id)
        .ok_or_else(|| recoverable("candidate"))?;
    let target_path = match anchor.position {
        revoot_core::AnchorPosition::Deletion { .. } => anchor.path.old_path.clone(),
        revoot_core::AnchorPosition::Addition { .. }
        | revoot_core::AnchorPosition::Context { .. } => anchor.path.new_path.clone(),
    };
    let expected_work_unit_id = runtime
        .work_unit_ids_by_path
        .get(&target_path)
        .ok_or_else(|| recoverable("candidate"))?;
    if args.candidate.work_unit_id != expected_work_unit_id.as_str() {
        return Err(recoverable("candidate"));
    }
    prepare_verification_batch(
        [args.candidate.clone()],
        expected_work_unit_id.as_str(),
        &runtime.candidate_target_paths,
        runtime.issued_anchors,
        &runtime.delivered_evidence_ids,
        runtime.anchor_table,
    )
    .map_err(|_| recoverable("candidate"))?;
    runtime.candidates.push(args.candidate);
    Ok(json!({"status":"accepted"}))
}

fn execute_complete(
    input: Value,
    state: &mut ReviewWorkerState,
    plan: &ReviewWorkerPlan,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<Value, ToolExecutionError> {
    let args = strict_input::<CompleteArgs>(input)?;
    let ReviewWorkerPhase::Reviewing { round } = state.phase() else {
        return Err(recoverable("transition"));
    };
    if usize::from(round) != plan.rounds.len() || !valid_summary(&args.summary) {
        return Err(recoverable("transition"));
    }
    args.checkpoint
        .validate()
        .map_err(|_| recoverable("checkpoint"))?;
    let gate = runtime
        .coverage_gate
        .as_mut()
        .ok_or_else(|| recoverable("coverage"))?;
    for disposition in args.dispositions {
        let path =
            RepositoryPath::try_from(disposition.path).map_err(|_| recoverable("disposition"))?;
        if !runtime.assigned_provider_paths.contains(&path) {
            return Err(recoverable("path_authority"));
        }
        gate.set_unread_disposition(&path, &disposition.hunk_id, disposition.disposition)
            .map_err(|_| recoverable("disposition"))?;
    }
    let missing = gate.ledger().missing_requirements();
    if !missing.is_empty() {
        return Err(ToolExecutionError::Recoverable(encode_missing(
            &CompleteGroupRejection {
                missing_requirements: missing,
                partial_causes: BTreeSet::new(),
            },
        )?));
    }
    state
        .finish_round(args.checkpoint.clone())
        .map_err(|_| recoverable("transition"))?;
    let completion = runtime
        .coverage_gate
        .as_ref()
        .map(|gate| gate.ledger().clone())
        .ok_or_else(|| recoverable("coverage"))?;
    runtime.final_coverage = Some(completion);
    let completion = runtime
        .coverage_gate
        .take()
        .ok_or_else(|| recoverable("coverage"))?
        .complete_group()
        .map_err(|rejection| {
            ToolExecutionError::Recoverable(
                encode_missing(&rejection).unwrap_or_else(|_| tool_error("coverage")),
            )
        })?;
    state
        .finish_verification()
        .map_err(|_| recoverable("transition"))?;
    runtime.checkpoint = args.checkpoint;
    runtime.summary = Some(GroupWorkerSummary {
        text: args.summary.text,
        assumptions: args.summary.assumptions,
    });
    runtime.completion = Some(completion);
    Ok(json!({"status":"accepted"}))
}

fn valid_summary(summary: &SummaryWire) -> bool {
    !summary.text.trim().is_empty()
        && summary.text.len() <= MAX_SUMMARY_BYTES
        && !summary.text.contains('\0')
        && summary.assumptions.len() <= MAX_SUMMARY_ASSUMPTIONS
        && summary.assumptions.iter().all(|assumption| {
            !assumption.trim().is_empty()
                && assumption.len() <= MAX_SUMMARY_ASSUMPTION_BYTES
                && !assumption.contains('\0')
        })
}

fn strict_input<T: for<'de> Deserialize<'de>>(input: Value) -> Result<T, ToolExecutionError> {
    serde_json::from_value(input).map_err(|_| recoverable("schema"))
}

fn assigned_path(
    value: &str,
    runtime: &WorkerRuntime<'_>,
) -> Result<RepositoryRelativePath, ToolExecutionError> {
    let path =
        RepositoryRelativePath::try_from(value.to_owned()).map_err(|_| recoverable("path"))?;
    if !runtime.assigned_paths.contains(&path) {
        return Err(recoverable("path_authority"));
    }
    Ok(path)
}

fn repository_path(value: &str) -> Result<RepositoryRelativePath, ToolExecutionError> {
    RepositoryRelativePath::try_from(value.to_owned()).map_err(|_| recoverable("path"))
}

fn assigned_search_paths(
    values: Vec<String>,
    runtime: &WorkerRuntime<'_>,
) -> Result<Vec<RepositoryRelativePath>, ToolExecutionError> {
    if values.len() > 32 {
        return Err(recoverable("bounds"));
    }
    let paths = if values.is_empty() {
        runtime.assigned_paths.iter().cloned().collect()
    } else {
        values
            .into_iter()
            .map(|path| assigned_path(&path, runtime))
            .collect::<Result<Vec<_>, _>>()?
    };
    if paths.iter().collect::<BTreeSet<_>>().len() != paths.len() {
        return Err(recoverable("duplicate_path"));
    }
    Ok(paths)
}

fn repository_search_paths(
    values: Vec<String>,
    _runtime: &WorkerRuntime<'_>,
) -> Result<Vec<RepositoryRelativePath>, ToolExecutionError> {
    if values.len() > 32 {
        return Err(recoverable("bounds"));
    }
    let paths = values
        .into_iter()
        .map(|path| repository_path(&path))
        .collect::<Result<Vec<_>, _>>()?;
    if paths.iter().collect::<BTreeSet<_>>().len() != paths.len() {
        return Err(recoverable("duplicate_path"));
    }
    Ok(paths)
}

fn record_evidence(
    value: &Value,
    runtime: &mut WorkerRuntime<'_>,
) -> Result<(), ToolExecutionError> {
    let content = serde_json::to_string(value).map_err(|_| recoverable("serialization"))?;
    if content.len() > MAX_TOOL_RESULT_BYTES {
        return Err(recoverable("result_too_large"));
    }
    let evidence_id = format!("evidence:{:04}", runtime.tool_calls);
    runtime.delivered_evidence_ids.insert(evidence_id.clone());
    runtime.evidence.push(GroupWorkerEvidence {
        evidence_id,
        content,
    });
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn encode_result(value: Value) -> Result<String, ToolExecutionError> {
    let encoded = serde_json::to_string(&value).map_err(|_| recoverable("serialization"))?;
    if encoded.len() > MAX_TOOL_RESULT_BYTES {
        return Err(recoverable("result_too_large"));
    }
    Ok(encoded)
}

fn encode_missing(rejection: &CompleteGroupRejection) -> Result<String, ToolExecutionError> {
    encode_result(json!({
        "error":"coverage_incomplete",
        "retryable":true,
        "missing_requirements":rejection.missing_requirements,
        "partial_causes":rejection.partial_causes,
    }))
}

fn repository_partial(runtime: &mut WorkerRuntime<'_>) -> ToolExecutionError {
    if runtime.cancellation.is_cancelled() {
        ToolExecutionError::Partial(GroupWorkerPartialReason::Cancelled)
    } else {
        if let Some(gate) = runtime.coverage_gate.as_mut() {
            gate.record_partial_cause(GroupPartialCause::ToolError);
        }
        ToolExecutionError::Recoverable(tool_error("repository"))
    }
}

fn recoverable(code: &str) -> ToolExecutionError {
    ToolExecutionError::Recoverable(tool_error(code))
}

fn tool_error(code: &str) -> String {
    json!({"error":code,"retryable":true}).to_string()
}

fn prepare_candidates(
    runtime: &WorkerRuntime<'_>,
) -> Result<PreparedVerificationBatch, GroupWorkerError> {
    if runtime.candidates.is_empty() {
        return Ok(PreparedVerificationBatch {
            candidates: Vec::new(),
        });
    }
    let mut prepared = Vec::with_capacity(runtime.candidates.len());
    for candidate in &runtime.candidates {
        let anchor = runtime
            .anchor_table
            .resolve(&candidate.finding.anchor_id)
            .ok_or(GroupWorkerError::Candidate)?;
        let target_path = match anchor.position {
            revoot_core::AnchorPosition::Deletion { .. } => anchor.path.old_path.clone(),
            revoot_core::AnchorPosition::Addition { .. }
            | revoot_core::AnchorPosition::Context { .. } => anchor.path.new_path.clone(),
        };
        let expected_work_unit_id = runtime
            .work_unit_ids_by_path
            .get(&target_path)
            .ok_or(GroupWorkerError::Candidate)?;
        let mut one = prepare_verification_batch(
            [candidate.clone()],
            expected_work_unit_id.as_str(),
            &runtime.candidate_target_paths,
            runtime.issued_anchors,
            &runtime.delivered_evidence_ids,
            runtime.anchor_table,
        )
        .map_err(|_| GroupWorkerError::Candidate)?;
        prepared.append(&mut one.candidates);
    }
    Ok(PreparedVerificationBatch {
        candidates: prepared,
    })
}

fn complete_output(
    state: &ReviewWorkerState,
    runtime: &WorkerRuntime<'_>,
    completion: GroupCompletion,
) -> Result<GroupWorkerOutput, GroupWorkerError> {
    Ok(GroupWorkerOutput {
        candidates: prepare_candidates(runtime)?,
        evidence: runtime.evidence.clone(),
        summary: runtime
            .summary
            .clone()
            .unwrap_or_else(GroupWorkerSummary::partial),
        status: GroupWorkerStatus::Complete(completion),
        coverage: output_coverage(runtime)?,
        usage: output_usage(runtime),
        provider_turns: state.provider_turns(),
        tool_calls: runtime.tool_calls,
    })
}

fn partial_output(
    state: &mut ReviewWorkerState,
    runtime: &WorkerRuntime<'_>,
    reason: GroupWorkerPartialReason,
) -> Result<GroupWorkerOutput, GroupWorkerError> {
    if !matches!(
        state.phase(),
        ReviewWorkerPhase::Partial | ReviewWorkerPhase::Complete
    ) {
        let _ = state.mark_partial();
    }
    Ok(GroupWorkerOutput {
        candidates: prepare_candidates(runtime)?,
        evidence: runtime.evidence.clone(),
        summary: runtime
            .summary
            .clone()
            .unwrap_or_else(GroupWorkerSummary::partial),
        status: GroupWorkerStatus::Partial(reason),
        coverage: output_coverage(runtime)?,
        usage: output_usage(runtime),
        provider_turns: state.provider_turns(),
        tool_calls: runtime.tool_calls,
    })
}

fn record_provider_settlement(runtime: &mut WorkerRuntime<'_>, settlement: ReviewModelSettlement) {
    let usage = match settlement {
        ReviewModelSettlement::Reported(usage)
        | ReviewModelSettlement::Conservative { charged: usage, .. } => usage,
    };
    record_provider_usage(
        runtime,
        ReviewModelReservation {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cost_microusd: usage.cost_microusd,
        },
    );
}

fn record_provider_usage(runtime: &mut WorkerRuntime<'_>, usage: ReviewModelReservation) {
    runtime.provider_usage.input_tokens = runtime
        .provider_usage
        .input_tokens
        .saturating_add(usage.input_tokens);
    runtime.provider_usage.output_tokens = runtime
        .provider_usage
        .output_tokens
        .saturating_add(usage.output_tokens);
    runtime.provider_usage.cost_microusd = runtime
        .provider_usage
        .cost_microusd
        .saturating_add(usage.cost_microusd);
}

fn output_coverage(runtime: &WorkerRuntime<'_>) -> Result<GroupCoverageLedger, GroupWorkerError> {
    runtime
        .final_coverage
        .clone()
        .or_else(|| {
            runtime
                .coverage_gate
                .as_ref()
                .map(|gate| gate.ledger().clone())
        })
        .ok_or(GroupWorkerError::CoverageBinding)
}

fn output_usage(runtime: &WorkerRuntime<'_>) -> AgentBudgetUsage {
    let local = runtime.local_budget.usage();
    AgentBudgetUsage {
        turns: runtime.provider_usage.turns,
        model_requests: runtime.provider_usage.model_requests,
        tool_calls: runtime.tool_calls,
        repository_files: local.repository_files,
        repository_bytes: local.repository_bytes,
        input_tokens: runtime.provider_usage.input_tokens,
        output_tokens: runtime.provider_usage.output_tokens,
        cost_microusd: runtime.provider_usage.cost_microusd,
        candidate_findings: u32::try_from(runtime.candidates.len()).unwrap_or(u32::MAX),
        elapsed_millis: runtime
            .clock
            .now_millis()
            .saturating_sub(runtime.started_at_millis),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use revoot_core::provider::ProviderErrorKind;
    use revoot_core::review_packet::{
        ReviewPacketDiffManifest, ReviewPacketFileBrief, ReviewPacketGroupBrief,
        ReviewPacketPolicy, ReviewPacketTokenEstimates,
    };
    use revoot_core::{
        FileChangeKind, FileCoverageLedger, GitSha, GroupCoverageLedger, GroupFileManifest,
        GroupHunkManifest, HunkCoverage, LocalSnapshotIdentity, ModelResponse, ModelUsage,
        ProviderError, ProviderFuture, RepositoryDiff, RepositoryToolLimits, ReviewEffort,
        ReviewGroup, ReviewGroupMetrics, ReviewSnapshotIdentity, ReviewValueTier,
    };
    use tempfile::TempDir;

    use crate::config::RepositoryReviewPolicy;
    use crate::review_group_inputs::{TrustedGroupFileInput, TrustedReviewGroupInput};
    use crate::review_rule_bundle::build_review_rule_bundle;

    const DIFF: &str = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";

    struct FakeProvider {
        responses: Mutex<VecDeque<ModelResponse>>,
        requests: Mutex<Vec<ModelRequest>>,
        calls: AtomicUsize,
    }

    impl FakeProvider {
        fn new(responses: Vec<ModelResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
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
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            let response = self.responses.lock().expect("responses").pop_front();
            Box::pin(async move {
                response.ok_or_else(|| ProviderError::new(ProviderErrorKind::Protocol, None, false))
            })
        }
    }

    struct FixedClock;

    impl GroupWorkerClock for FixedClock {
        fn now_millis(&self) -> u64 {
            0
        }
    }

    struct Fixture {
        _directory: TempDir,
        toolbox: RepositoryToolbox,
        store: DiffArtifactStore,
        request: GroupWorkerRequest,
        budget: ReviewBudgetBroker,
        cancellation: CancellationToken,
    }

    fn sha(marker: char) -> GitSha {
        GitSha::try_from(marker.to_string().repeat(40)).expect("SHA")
    }

    fn snapshot() -> ReviewSnapshotIdentity {
        ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
            repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
            base_sha: sha('a'),
            head_sha: sha('b'),
            working_tree_sha256: Sha256Digest::of_bytes(b"working-tree"),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
        })
    }

    fn provider_path() -> RepositoryPath {
        RepositoryPath::try_from("src/lib.rs".to_owned()).expect("provider path")
    }

    fn relative_path() -> RepositoryRelativePath {
        RepositoryRelativePath::try_from("src/lib.rs".to_owned()).expect("relative path")
    }

    fn work_unit_id() -> String {
        format!("wu-{}", "b".repeat(64))
    }

    fn group(tier: ReviewValueTier) -> ReviewGroup {
        serde_json::from_value(json!({
            "id": format!("rg-{}", "a".repeat(64)),
            "files": [{
                "path": {
                    "old_path": "src/lib.rs",
                    "new_path": "src/lib.rs",
                    "kind": "modified"
                },
                "tier": tier,
                "input_bytes": DIFF.len(),
                "anchor_ids": [],
                "work_unit_id": work_unit_id()
            }],
            "input_bytes": DIFF.len(),
            "anchor_count": 0
        }))
        .expect("group")
    }

    #[allow(clippy::too_many_lines)]
    fn fixture(
        effort: ReviewEffort,
        changed_lines: u32,
        tier: ReviewValueTier,
        inline: bool,
        budget_limits: revoot_core::ReviewBudgetLimits,
    ) -> Fixture {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(directory.path().join("src")).expect("src directory");
        fs::write(directory.path().join("src/lib.rs"), "new\n").expect("source");
        fs::write(
            directory.path().join("src/helper.rs"),
            "pub fn helper() {}\n",
        )
        .expect("helper source");
        let cancellation = CancellationToken::default();
        let path = relative_path();
        let toolbox = RepositoryToolbox::open_selected(
            directory.path(),
            RepositoryToolLimits::default(),
            [RepositoryDiff {
                path: path.clone(),
                text: DIFF.to_owned(),
            }],
            [
                path.clone(),
                RepositoryRelativePath::try_from("src/helper.rs".to_owned()).expect("helper path"),
            ],
            &cancellation,
        )
        .expect("toolbox");
        let store = DiffArtifactStore::create([(&path, DIFF)], 32 * 1024).expect("artifact store");
        let file_manifest = store
            .manifest(std::slice::from_ref(&path))
            .expect("manifest")
            .pop()
            .expect("file manifest");
        let group = group(tier);
        let trusted_work_unit_id = group.files[0].work_unit_id.clone();
        let trusted_group_input = TrustedReviewGroupInput {
            partition_sha256: Sha256Digest::of_bytes(b"partition"),
            group_plan_sha256: Sha256Digest::of_bytes(b"group-plan"),
            selected_input_sha256: Sha256Digest::of_bytes(b"selected-input"),
            group: group.clone(),
            file_count: 1,
            exact_diff_bytes: file_manifest.size_bytes,
            changed_line_count: changed_lines,
            hunk_count: u32::try_from(file_manifest.hunks.len()).expect("hunk count"),
            files: vec![TrustedGroupFileInput {
                artifact_sha256: file_manifest.sha256.clone(),
                work_unit_id: trusted_work_unit_id.clone(),
                rule_ids: vec![
                    "compiled:safety-invariants".to_owned(),
                    "generic:review".to_owned(),
                    "rust.md".to_owned(),
                ],
                manifest: GroupFileManifest {
                    path: provider_path(),
                    status: FileChangeKind::Modified,
                    exact_diff_bytes: file_manifest.size_bytes,
                    metadata_only: false,
                    hunks: file_manifest
                        .hunks
                        .iter()
                        .map(|hunk| GroupHunkManifest {
                            hunk_id: hunk.hunk_id.clone(),
                            changed_lines: hunk.changed_lines,
                            pages: hunk.pages,
                        })
                        .collect(),
                },
            }],
        };
        let rule_bundle =
            build_review_rule_bundle(&trusted_group_input, &RepositoryReviewPolicy::default())
                .expect("rule bundle");
        let metrics = ReviewGroupMetrics {
            changed_lines_by_path: BTreeMap::from([(provider_path(), changed_lines)]),
        };
        let plan = ReviewWorkerPlan::build(&group, effort, &metrics).expect("worker plan");
        let identity = snapshot();
        let anchors = AnchorTable::build(identity, []).expect("anchor table");
        let coverage = GroupCoverageLedger::new([FileCoverageLedger {
            path: provider_path(),
            tier,
            manifested: false,
            metadata_only: false,
            hunks: file_manifest
                .hunks
                .iter()
                .map(|hunk| HunkCoverage {
                    hunk_id: hunk.hunk_id.clone(),
                    total_pages: hunk.pages,
                    delivered_pages: BTreeSet::new(),
                    hazardous: hunk.hazardous,
                })
                .collect(),
            unread_dispositions: BTreeMap::new(),
        }])
        .expect("coverage ledger");
        let diff_sha = Sha256Digest::of_bytes(DIFF.as_bytes());
        let plan_sha = Sha256Digest::of_bytes(b"group-plan");
        let initial_packet = ReviewPacketInput {
            purpose: ReviewPacketPurpose::GroupInitial,
            group_brief: ReviewPacketGroupBrief {
                group_id: plan.group_id.clone(),
                snapshot_sha256: Sha256Digest::of_bytes(b"snapshot"),
                partition_sha256: Sha256Digest::of_bytes(b"partition"),
                group_plan_sha256: plan_sha,
                files: vec![ReviewPacketFileBrief {
                    path: provider_path(),
                    tier,
                    changed_lines,
                    hunk_ids: file_manifest
                        .hunks
                        .iter()
                        .map(|hunk| hunk.hunk_id.clone())
                        .collect(),
                }],
            },
            policy: ReviewPacketPolicy {
                system_policy_id: "policy-v1".to_owned(),
                system_policy_sha256: Sha256Digest::of_bytes(b"policy"),
                rule_ids: rule_bundle.rule_ids().map(str::to_owned).collect(),
            },
            checkpoint: ReviewWorkerCheckpoint::default(),
            plan_summary: None,
            accepted_findings: Vec::new(),
            unresolved_coverage_ids: Vec::new(),
            recent_exchange: None,
            diff_manifest: ReviewPacketDiffManifest {
                complete_diff_sha256: diff_sha.clone(),
                complete_diff_bytes: u64::try_from(DIFF.len()).expect("diff bytes"),
                file_count: 1,
                hunk_count: u32::try_from(file_manifest.hunks.len()).expect("hunk count"),
            },
            complete_diff: Some(ReviewPacketCompleteDiff::SmallComplete {
                body: DIFF.to_owned(),
                sha256: diff_sha,
            }),
            token_estimates: ReviewPacketTokenEstimates {
                manifest_request_tokens: 400,
                inline_request_tokens: Some(if inline { 600 } else { 32_001 }),
            },
        };
        let request = GroupWorkerRequest {
            model: "model-v1".to_owned(),
            system_policy: "Use bounded tools and complete the assigned review group.".to_owned(),
            plan,
            initial_packet,
            work_unit_ids_by_path: BTreeMap::from([(provider_path(), trusted_work_unit_id)]),
            assigned_paths: BTreeSet::from([path]),
            issued_anchors: BTreeSet::new(),
            anchor_table: anchors,
            coverage_gate: CoverageCompletionGate::new(coverage, &BTreeSet::new())
                .expect("coverage gate"),
            rule_bundle,
            history: None,
            prior_review: PriorReviewContext::default(),
            limits: GroupWorkerLimits::default(),
        };
        Fixture {
            _directory: directory,
            toolbox,
            store,
            request,
            budget: ReviewBudgetBroker::new(budget_limits, 0).expect("aggregate budget"),
            cancellation,
        }
    }

    fn tool_response(id: usize, name: &str, input: Value) -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "model-v1".to_owned(),
            content: vec![ModelContent::ToolUse {
                id: format!("call-{id}"),
                name: name.to_owned(),
                input,
            }],
            finish_reason: ModelFinishReason::ToolUse,
            usage: ModelUsage::default(),
        }
    }

    fn batched_response(calls: Vec<(usize, &str, Value)>) -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "model-v1".to_owned(),
            content: calls
                .into_iter()
                .map(|(id, name, input)| ModelContent::ToolUse {
                    id: format!("call-{id}"),
                    name: name.to_owned(),
                    input,
                })
                .collect(),
            finish_reason: ModelFinishReason::ToolUse,
            usage: ModelUsage::default(),
        }
    }

    fn checkpoint() -> Value {
        json!({
            "hypotheses": [],
            "evidence_references": [],
            "unresolved_coverage": []
        })
    }

    fn checkpoint_call(planning: bool) -> Value {
        let mut value = json!({"checkpoint": checkpoint()});
        if planning {
            value["plan_summary"] = json!({
                "focus_area_ids": ["focus-1"],
                "hunk_ids": [],
                "dependency_question_ids": [],
                "risk_hypothesis_ids": []
            });
        }
        value
    }

    fn complete_call() -> Value {
        json!({
            "checkpoint": checkpoint(),
            "summary": {"text":"reviewed","assumptions":[]}
        })
    }

    fn generous_budget() -> revoot_core::ReviewBudgetLimits {
        revoot_core::ReviewBudgetLimits::default()
    }

    async fn run(fixture: Fixture, provider: &FakeProvider) -> GroupWorkerOutput {
        run_group_worker(
            provider,
            fixture.request,
            &fixture.toolbox,
            &fixture.store,
            &fixture.budget,
            &fixture.cancellation,
            &FixedClock,
        )
        .await
        .expect("worker output")
    }

    #[tokio::test]
    async fn simple_low_effort_completes_one_round_and_reads_cross_group_context() {
        let budgeted = fixture(
            ReviewEffort::Low,
            10,
            ReviewValueTier::High,
            true,
            generous_budget(),
        );
        let provider = FakeProvider::new(vec![batched_response(vec![
            (
                1,
                "read_file",
                json!({"reads":[{"path":"src/helper.rs","start_line":1,"end_line":1}]}),
            ),
            (2, "complete_group", complete_call()),
        ])]);
        let output = run(budgeted, &provider).await;
        assert!(matches!(output.status, GroupWorkerStatus::Complete(_)));
        assert_eq!(output.provider_turns, 1);
        assert_eq!(output.tool_calls, 2);
        assert_eq!(output.evidence.len(), 1);
        assert_eq!(output.coverage.files.len(), 1);
        assert_eq!(output.usage.model_requests, 1);
        assert_eq!(output.usage.tool_calls, 2);
        assert!(output.usage.repository_files >= 1);
        assert!(output.usage.input_tokens > 0);
        assert_eq!(output.usage.output_tokens, 4_096);
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn medium_effort_runs_two_fresh_review_rounds() {
        let budgeted = fixture(
            ReviewEffort::Medium,
            10,
            ReviewValueTier::High,
            true,
            generous_budget(),
        );
        let provider = FakeProvider::new(vec![
            tool_response(1, "checkpoint_review", checkpoint_call(false)),
            tool_response(2, "complete_group", complete_call()),
        ]);
        let output = run(budgeted, &provider).await;
        assert!(matches!(output.status, GroupWorkerStatus::Complete(_)));
        assert_eq!(output.provider_turns, 2);
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn rule_guidance_is_ids_only_initially_and_delivered_once_by_tool() {
        let budgeted = fixture(
            ReviewEffort::Medium,
            10,
            ReviewValueTier::High,
            true,
            generous_budget(),
        );
        let provider = FakeProvider::new(vec![
            tool_response(1, "get_rules", json!({"rule_ids":["generic:review"]})),
            tool_response(2, "checkpoint_review", checkpoint_call(false)),
            tool_response(3, "complete_group", complete_call()),
        ]);
        let output = run(budgeted, &provider).await;
        assert!(matches!(output.status, GroupWorkerStatus::Complete(_)));
        assert_eq!(output.tool_calls, 3);
        assert_eq!(output.usage.tool_calls, 3);

        let requests = provider.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        let rendered = requests
            .iter()
            .map(|request| serde_json::to_string(request).expect("request JSON"))
            .collect::<Vec<_>>();
        let guidance_marker = "Test files are normal reviewable code";
        assert!(rendered[0].contains("generic:review"));
        assert!(!rendered[0].contains(guidance_marker));
        assert_eq!(rendered[1].matches(guidance_marker).count(), 1);
        assert!(!rendered[2].contains(guidance_marker));
        assert_eq!(
            rendered
                .iter()
                .map(|request| request.matches(guidance_marker).count())
                .sum::<usize>(),
            1
        );
    }

    #[tokio::test]
    async fn complex_high_effort_plans_then_runs_three_rounds_under_shared_budget() {
        let limits = revoot_core::ReviewBudgetLimits {
            max_model_requests: 4,
            max_model_tokens: 100_000,
            max_output_tokens: 4 * 4_096,
            max_tool_calls: 16,
            max_cost_microusd: 5_000_000,
            max_elapsed_millis: 60_000,
        };
        let fixture = fixture(ReviewEffort::High, 50, ReviewValueTier::High, true, limits);
        let provider = FakeProvider::new(vec![
            tool_response(1, "checkpoint_review", checkpoint_call(true)),
            tool_response(2, "checkpoint_review", checkpoint_call(false)),
            tool_response(3, "checkpoint_review", checkpoint_call(false)),
            tool_response(4, "complete_group", complete_call()),
        ]);
        let output = run(fixture, &provider).await;
        assert!(matches!(output.status, GroupWorkerStatus::Complete(_)));
        assert_eq!(output.provider_turns, 4);
        assert_eq!(provider.calls(), 4);
    }

    #[tokio::test]
    async fn coverage_rejection_can_be_corrected_with_batched_diff_read_and_completion() {
        let fixture = fixture(
            ReviewEffort::Low,
            10,
            ReviewValueTier::High,
            false,
            generous_budget(),
        );
        let manifest = fixture
            .store
            .manifest(&[relative_path()])
            .expect("manifest");
        let hunk_id = manifest[0].hunks[0].hunk_id.clone();
        let provider = FakeProvider::new(vec![
            tool_response(1, "complete_group", complete_call()),
            batched_response(vec![
                (
                    2,
                    "read_diff",
                    json!({"reads":[{"path":"src/lib.rs","hunk_id":hunk_id,"page":1}]}),
                ),
                (3, "complete_group", complete_call()),
            ]),
        ]);
        let output = run(fixture, &provider).await;
        assert!(matches!(output.status, GroupWorkerStatus::Complete(_)));
        assert_eq!(output.provider_turns, 2);
        assert_eq!(output.tool_calls, 3);
        assert_eq!(output.evidence.len(), 1);
    }

    #[tokio::test]
    async fn aggregate_budget_and_cancellation_return_payload_free_partial_results() {
        let limits = revoot_core::ReviewBudgetLimits {
            max_model_requests: 1,
            ..generous_budget()
        };
        let budgeted = fixture(
            ReviewEffort::Medium,
            50,
            ReviewValueTier::High,
            true,
            limits,
        );
        let provider = FakeProvider::new(vec![tool_response(
            1,
            "checkpoint_review",
            checkpoint_call(true),
        )]);
        let output = run(budgeted, &provider).await;
        assert_eq!(
            output.status,
            GroupWorkerStatus::Partial(GroupWorkerPartialReason::Budget)
        );
        assert_eq!(provider.calls(), 1);

        let cancelled = fixture(
            ReviewEffort::Low,
            10,
            ReviewValueTier::Low,
            true,
            generous_budget(),
        );
        cancelled
            .cancellation
            .cancel(revoot_core::ProviderCancellationReason::UserRequested);
        let provider = FakeProvider::new(Vec::new());
        let output = run(cancelled, &provider).await;
        assert_eq!(
            output.status,
            GroupWorkerStatus::Partial(GroupWorkerPartialReason::Cancelled)
        );
        assert_eq!(provider.calls(), 0);
    }

    #[test]
    fn conservative_wire_estimate_has_no_fixed_thirty_two_thousand_token_floor() {
        assert_eq!(estimate_wire_tokens(1_024), 1_024);
        assert!(estimate_wire_tokens(1_024) < MAX_REQUEST_INPUT_TOKENS);
        assert_eq!(estimate_wire_tokens(32_001), 32_001);
    }

    #[test]
    fn tool_surface_is_closed_and_read_only() {
        assert_eq!(
            model_tools()
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            [
                "diff_manifest",
                "read_diff",
                "search_diff",
                "read_file",
                "find_files",
                "search_code",
                "list_change_commits",
                "show_commit_context",
                "get_existing_revoot_findings",
                "get_rules",
                "checkpoint_review",
                "submit_candidate_finding",
                "complete_group",
            ]
        );
    }

    #[test]
    fn phase_rebasing_uses_fixed_packet_purposes() {
        assert_eq!(
            packet_purpose(ReviewWorkerPhase::Planning),
            Some(ReviewPacketPurpose::Planning)
        );
        assert_eq!(
            packet_purpose(ReviewWorkerPhase::Reviewing { round: 3 }),
            Some(ReviewPacketPurpose::ReviewRound { round: 3 })
        );
        assert_eq!(packet_purpose(ReviewWorkerPhase::Complete), None);
    }

    #[test]
    fn terminal_state_tools_must_end_a_provider_batch() {
        let call = |name: &str| ("id".to_owned(), name.to_owned(), json!({}));
        assert!(terminal_tool_is_not_last(&[
            call("complete_group"),
            call("read_diff")
        ]));
        assert!(!terminal_tool_is_not_last(&[
            call("read_diff"),
            call("complete_group")
        ]));
    }

    #[test]
    fn summary_and_tool_results_are_bounded() {
        assert!(valid_summary(&SummaryWire {
            text: "reviewed".to_owned(),
            assumptions: Vec::new(),
        }));
        assert!(!valid_summary(&SummaryWire {
            text: "x".repeat(MAX_SUMMARY_BYTES + 1),
            assumptions: Vec::new(),
        }));
        assert!(encode_result(json!({"ok":true})).is_ok());
        assert!(encode_result(json!({"body":"x".repeat(MAX_TOOL_RESULT_BYTES)})).is_err());
    }

    #[test]
    fn large_diff_constant_matches_artifact_policy() {
        assert_eq!(MAX_INLINE_GROUP_DIFF_BYTES, 16_384);
        let complete = ReviewPacketCompleteDiff::LargeManifestOnly {
            sha256: Sha256Digest::of_bytes(b"diff"),
            bytes: MAX_INLINE_GROUP_DIFF_BYTES + 1,
        };
        assert!(matches!(
            complete,
            ReviewPacketCompleteDiff::LargeManifestOnly { .. }
        ));
    }
}
