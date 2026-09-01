//! Native composition for the tool-first review pipeline.
//!
//! This module sequences already-bounded preparation, isolated group
//! execution, verification, global adjudication, and deterministic reduction.
//! It does not implement a second model loop and does not retain artifacts,
//! prompts, responses, tool payloads, or source slices in its report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use revoot_core::provider::ProviderAdapter;
use revoot_core::{
    AdjudicationFallbackCoverage, AgentBudgetUsage, AgentOmission, AgentOmissionReason, AnchorId,
    AnchorPosition, AnchorTable, AuthorizedLineageAction, AuthorizedLineageDecision,
    CancellationToken, DeliveredAnchorEvidence, GroupCoverageLedger, LineageCoverageEvidence,
    LineageDecisionResponse, PriorLineageRecord, PriorLineageTarget, PriorReviewContext,
    PriorReviewSource, PriorReviewState, ProposedLineageDecision, ProposedLineageDisposition,
    RepositoryRelativePath, RepositoryToolbox, ReviewBudgetBroker, ReviewBudgetUsage, ReviewEffort,
    ReviewGroupId, ReviewOutcome, ReviewPartitionPlan, ReviewReportPhase, ReviewReportPhaseUsage,
    Sha256Digest, VerifiedCandidate, WorkUnitFile, authorize_lineage_decisions,
};

use crate::config::RepositoryReviewPolicy;
use crate::diff_artifact::{DEFAULT_DIFF_PAGE_BYTES, DiffArtifactStore, DiffHunkManifest};
use crate::git_history::GitHistoryToolbox;
use crate::group_runtime::GroupRuntimeStopReason;
use crate::group_scheduler::{GroupScheduleSnapshot, GroupScheduleStatus};
use crate::group_worker_engine::{GroupWorkerClock, GroupWorkerLimits, GroupWorkerStatus};
use crate::review_adjudicator::{
    AdjudicationGroupSummary, AdjudicationLineage, AdjudicationLineageState,
    GlobalAdjudicationContext, ReviewAdjudicationMode, ReviewAdjudicatorClock,
    ReviewAdjudicatorConfig, ReviewAdjudicatorError, ReviewAdjudicatorFallbackReason,
    run_review_adjudicator,
};
use crate::review_group_execution::{
    ExecutedReviewGroup, GroupVerificationStatus, PreparedReviewGroupExecution,
    ReviewGroupExecutionConfig, ReviewGroupExecutionError, execute_review_groups,
};
use crate::review_group_inputs::derive_review_group_inputs;
use crate::review_grouper::{ReviewGrouperClock, ReviewGrouperConfig, ReviewGrouperMode};
use crate::review_preparation::{
    ReviewPreparationBindings, ReviewPreparationError, ToolFirstPreparationInput,
    ToolFirstPreparedReview, prepare_tool_first_review,
};
use crate::review_result_reducer::{
    GroupResultAccounting, ReducedReviewResult, ReviewResultReducerError, reduce_review_result,
};
use crate::review_rule_bundle::build_review_rule_bundle;
use crate::review_verifier::{ReviewVerifierClock, ReviewVerifierConfig};
use crate::rule_diagnostics::{RepositoryRuleMetadata, RuleDiagnosticPolicy};

const MAX_SYSTEM_POLICY_BYTES: usize = 16 * 1024;
const MAX_SYSTEM_POLICY_ID_BYTES: usize = 128;

/// Bounded phase configuration for one tool-first invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolFirstEngineLimits {
    pub model: String,
    pub effort: ReviewEffort,
    pub max_parallel_groups: usize,
    pub diff_page_bytes: usize,
    pub max_inline_diff_bytes: u64,
    pub grouper: ReviewGrouperConfig,
    pub worker: GroupWorkerLimits,
    pub verifier: ReviewVerifierConfig,
    pub adjudicator: ReviewAdjudicatorConfig,
}

impl ToolFirstEngineLimits {
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        let model = model.into();
        Self {
            grouper: ReviewGrouperConfig::new(model.clone()),
            worker: GroupWorkerLimits::default(),
            verifier: ReviewVerifierConfig::new(model.clone()),
            adjudicator: ReviewAdjudicatorConfig::new(model.clone()),
            model,
            effort: ReviewEffort::Medium,
            max_parallel_groups: 4,
            diff_page_bytes: DEFAULT_DIFF_PAGE_BYTES,
            max_inline_diff_bytes: crate::diff_artifact::MAX_INLINE_GROUP_DIFF_BYTES,
        }
    }
}

/// Owned trusted state for one end-to-end tool-first review.
pub struct ToolFirstEngineRequest<C> {
    pub provider: Arc<dyn ProviderAdapter>,
    pub toolbox: Arc<RepositoryToolbox>,
    pub history: Option<Arc<GitHistoryToolbox>>,
    pub prior_review: PriorReviewContext,
    pub anchor_table: AnchorTable,
    pub partition: ReviewPartitionPlan,
    pub rule_policy: RepositoryReviewPolicy,
    pub budget: ReviewBudgetBroker,
    pub cancellation: CancellationToken,
    pub clock: Arc<C>,
    pub limits: ToolFirstEngineLimits,
    pub system_policy_id: String,
    pub system_policy: String,
    pub initial_omissions: Vec<AgentOmission>,
}

impl<C> fmt::Debug for ToolFirstEngineRequest<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolFirstEngineRequest")
            .field("provider", &self.provider.adapter_id())
            .field("history_available", &self.history.is_some())
            .field("prior_review_count", &self.prior_review.discussions().len())
            .field("partition_sha256", &self.partition.plan_sha256)
            .field("limits", &self.limits)
            .field("system_policy_id", &self.system_policy_id)
            .field("system_policy", &"[redacted]")
            .field("initial_omission_count", &self.initial_omissions.len())
            .finish_non_exhaustive()
    }
}

/// Payload-free terminal report from the native tool-first pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolFirstEngineReport {
    pub result: ReducedReviewResult,
    /// Final trusted coverage ledgers in stable review-group identity order.
    pub group_coverage: Vec<GroupCoverageLedger>,
    pub grouping_mode: ReviewGrouperMode,
    pub group_plan_sha256: Sha256Digest,
    pub group_count: u32,
    pub schedule: GroupScheduleSnapshot,
    pub adjudication_mode: ReviewAdjudicationMode,
    pub verified_candidates: u32,
    pub verification_suppressions: u32,
    pub budget_usage: ReviewBudgetUsage,
    pub phase_usage: Vec<ReviewReportPhaseUsage>,
}

/// Closed phase failure without provider or repository payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolFirstEngineError {
    Configuration,
    Serialization,
    Preparation(ReviewPreparationError),
    Execution(ReviewGroupExecutionError),
    ExecutionAccounting,
    CandidateAccounting,
    GroupAccounting,
    LineageAccounting,
    CoverageAccounting,
    BudgetAccounting,
    Adjudication(ReviewAdjudicatorError),
    Reduction(ReviewResultReducerError),
}

impl fmt::Display for ToolFirstEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "tool-first review configuration is invalid",
            Self::Serialization => "tool-first review identity cannot be encoded",
            Self::Preparation(_) => "tool-first review preparation failed",
            Self::Execution(_) => "tool-first review group execution failed",
            Self::ExecutionAccounting => "tool-first review execution accounting is invalid",
            Self::CandidateAccounting => "tool-first candidate accounting is invalid",
            Self::GroupAccounting => "tool-first group accounting is invalid",
            Self::LineageAccounting => "tool-first lineage accounting is invalid",
            Self::CoverageAccounting => "tool-first coverage accounting is invalid",
            Self::BudgetAccounting => "tool-first phase budget accounting is invalid",
            Self::Adjudication(_) => "tool-first review adjudication failed",
            Self::Reduction(_) => "tool-first review reduction failed",
        })
    }
}

impl std::error::Error for ToolFirstEngineError {}

/// Run the native tool-first review pipeline to a deterministic final report.
///
/// # Errors
///
/// Returns a phase-specific, payload-free failure for invalid trusted input or
/// an internal accounting contradiction. Provider failures inside grouping,
/// workers, verification, or adjudication follow their bounded partial or
/// deterministic fallback paths.
pub async fn run_tool_first_engine<C>(
    request: ToolFirstEngineRequest<C>,
) -> Result<ToolFirstEngineReport, ToolFirstEngineError>
where
    C: ReviewGrouperClock
        + GroupWorkerClock
        + ReviewVerifierClock
        + ReviewAdjudicatorClock
        + Send
        + Sync
        + 'static,
{
    validate_request(&request)?;
    let bindings = preparation_bindings(&request)?;
    let diagnostic_policy = diagnostic_rule_policy(&request.rule_policy);
    let preparation_input = ToolFirstPreparationInput {
        repository: request.toolbox.as_ref(),
        partition: &request.partition,
        anchor_table: request.anchor_table.clone(),
        rule_policy: &diagnostic_policy,
        bindings,
        grouper: request.limits.grouper.clone(),
        effort: request.limits.effort,
        diff_page_bytes: request.limits.diff_page_bytes,
        max_inline_diff_bytes: request.limits.max_inline_diff_bytes,
    };
    let prepared = prepare_tool_first_review(
        preparation_input,
        request.provider.as_ref(),
        &request.budget,
        &request.cancellation,
        request.clock.as_ref(),
    )
    .await
    .map_err(ToolFirstEngineError::Preparation)?;
    execute_and_reduce(request, prepared).await
}

#[allow(
    clippy::too_many_lines,
    reason = "the top-level phase sequence keeps artifact lifetime and accounting reconciliation visible"
)]
async fn execute_and_reduce<C>(
    request: ToolFirstEngineRequest<C>,
    prepared: ToolFirstPreparedReview,
) -> Result<ToolFirstEngineReport, ToolFirstEngineError>
where
    C: GroupWorkerClock + ReviewVerifierClock + ReviewAdjudicatorClock + Send + Sync + 'static,
{
    let ToolFirstPreparedReview {
        artifacts,
        selected_inputs,
        group_plan,
        grouping_mode,
        grouping_usage: _,
        packets,
    } = prepared;
    let group_inputs =
        derive_review_group_inputs(&request.partition, &group_plan, &selected_inputs)
            .map_err(|_| ToolFirstEngineError::ExecutionAccounting)?;
    let mut rule_bundles = group_inputs
        .iter()
        .map(|group| {
            build_review_rule_bundle(group, &request.rule_policy)
                .map(|bundle| (group.group.id.clone(), bundle))
                .map_err(|_| ToolFirstEngineError::ExecutionAccounting)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if rule_bundles.len() != group_plan.groups.len() {
        return Err(ToolFirstEngineError::ExecutionAccounting);
    }
    let initial_coverage = packets
        .iter()
        .map(|(group_id, packet)| (group_id.clone(), packet.coverage_gate.ledger().clone()))
        .collect::<BTreeMap<_, _>>();
    let prepared_groups = packets
        .into_iter()
        .map(|(group_id, packet)| {
            Ok(PreparedReviewGroupExecution {
                rule_bundle: rule_bundles
                    .remove(&group_id)
                    .ok_or(ToolFirstEngineError::ExecutionAccounting)?,
                group_id,
                packet,
                prior_review: request.prior_review.clone(),
            })
        })
        .collect::<Result<Vec<_>, ToolFirstEngineError>>()?;
    if !rule_bundles.is_empty() {
        return Err(ToolFirstEngineError::ExecutionAccounting);
    }
    let artifacts = Arc::new(artifacts);
    let execution = execute_review_groups(
        &group_plan,
        prepared_groups,
        Arc::clone(&request.provider),
        Arc::clone(&request.toolbox),
        Arc::clone(&artifacts),
        request.history.clone(),
        request.budget.clone(),
        request.cancellation.clone(),
        Arc::clone(&request.clock),
        ReviewGroupExecutionConfig {
            model: request.limits.model.clone(),
            system_policy: request.system_policy.clone(),
            max_parallel_groups: request.limits.max_parallel_groups,
            worker_limits: request.limits.worker.clone(),
            verifier: request.limits.verifier.clone(),
        },
    )
    .await
    .map_err(ToolFirstEngineError::Execution)?;
    let verified = verified_candidates(&execution.groups)
        .map_err(|_| ToolFirstEngineError::CandidateAccounting)?;
    let verification_suppressions = verification_suppression_count(&execution.groups)
        .map_err(|_| ToolFirstEngineError::CandidateAccounting)?;
    let mut group_accounting = group_accounting(&execution, initial_coverage)
        .map_err(|_| ToolFirstEngineError::GroupAccounting)?;
    let adjudication_context = adjudication_context(
        &execution,
        &group_accounting,
        &request.partition,
        &request.prior_review,
        request.budget.snapshot().usage,
    )
    .map_err(|_| ToolFirstEngineError::GroupAccounting)?;
    let adjudication = run_review_adjudicator(
        request.provider.as_ref(),
        &request.limits.adjudicator,
        &verified,
        &adjudication_context,
        &request.budget,
        &request.cancellation,
        request.clock.as_ref(),
    )
    .await
    .map_err(ToolFirstEngineError::Adjudication)?;
    let lineage_authorizations = authorize_review_lineages(
        &request.prior_review,
        &request.anchor_table,
        &request.partition,
        artifacts.as_ref(),
        &group_accounting,
        !adjudication.partial
            && !adjudication_context.coverage.partial
            && request.initial_omissions.is_empty(),
        adjudication.lineage_response.clone(),
    )
    .map_err(|_| ToolFirstEngineError::LineageAccounting)?;
    attach_lineage_authorizations(&mut group_accounting, lineage_authorizations)
        .map_err(|_| ToolFirstEngineError::LineageAccounting)?;
    let mut ordered_group_coverage = execution
        .groups
        .iter()
        .map(|group| (group.group_id.clone(), group.coverage.clone()))
        .collect::<Vec<_>>();
    ordered_group_coverage.sort_by(|left, right| left.0.cmp(&right.0));
    if ordered_group_coverage
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(ToolFirstEngineError::CoverageAccounting);
    }
    let group_coverage = ordered_group_coverage
        .into_iter()
        .map(|(_, coverage)| coverage)
        .collect();
    let mut initial_omissions = request.initial_omissions;
    if let ReviewAdjudicationMode::DeterministicFallback(reason) = adjudication.mode {
        initial_omissions.push(adjudication_fallback_omission(reason));
    }
    let mut result = reduce_review_result(
        &adjudication.outcome,
        &request.partition,
        &execution.schedule,
        &group_accounting,
        &initial_omissions,
        &request.prior_review,
    )
    .map_err(ToolFirstEngineError::Reduction)?;
    let budget_snapshot = request.budget.snapshot();
    if budget_snapshot.outstanding != revoot_core::OutstandingReviewReservations::default() {
        return Err(ToolFirstEngineError::BudgetAccounting);
    }
    let budget_usage = budget_snapshot.usage;
    let phase_usage = ordered_phase_usage(
        request
            .budget
            .phase_usage(revoot_core::ReviewBudgetPhase::Grouping),
        request
            .budget
            .phase_usage(revoot_core::ReviewBudgetPhase::Planning),
        request
            .budget
            .phase_usage(revoot_core::ReviewBudgetPhase::Review),
        request
            .budget
            .phase_usage(revoot_core::ReviewBudgetPhase::Verification),
        request
            .budget
            .phase_usage(revoot_core::ReviewBudgetPhase::Adjudication),
    );
    reconcile_phase_usage(&phase_usage, budget_usage)
        .map_err(|_| ToolFirstEngineError::BudgetAccounting)?;
    apply_aggregate_usage(&mut result.outcome, budget_usage, verified.len())
        .map_err(|_| ToolFirstEngineError::BudgetAccounting)?;
    Ok(ToolFirstEngineReport {
        result,
        group_coverage,
        grouping_mode,
        group_plan_sha256: group_plan.plan_sha256,
        group_count: u32::try_from(group_plan.groups.len())
            .map_err(|_| ToolFirstEngineError::ExecutionAccounting)?,
        schedule: execution.schedule,
        adjudication_mode: adjudication.mode,
        verified_candidates: u32::try_from(verified.len())
            .map_err(|_| ToolFirstEngineError::ExecutionAccounting)?,
        verification_suppressions,
        budget_usage,
        phase_usage,
    })
}

fn ordered_phase_usage(
    grouping: ReviewBudgetUsage,
    planning: ReviewBudgetUsage,
    review: ReviewBudgetUsage,
    verification: ReviewBudgetUsage,
    adjudication: ReviewBudgetUsage,
) -> Vec<ReviewReportPhaseUsage> {
    [
        (ReviewReportPhase::Grouping, grouping),
        (ReviewReportPhase::Planning, planning),
        (ReviewReportPhase::Review, review),
        (ReviewReportPhase::Verification, verification),
        (ReviewReportPhase::Adjudication, adjudication),
    ]
    .into_iter()
    .map(|(phase, usage)| ReviewReportPhaseUsage {
        phase,
        model_requests: usage.model_requests,
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        tool_calls: usage.tool_calls,
        cost_microusd: usage.cost_microusd,
    })
    .collect()
}

fn reconcile_phase_usage(
    phases: &[ReviewReportPhaseUsage],
    aggregate: ReviewBudgetUsage,
) -> Result<(), ToolFirstEngineError> {
    let totals = phases
        .iter()
        .try_fold(
            (0_u32, 0_u64, 0_u64, 0_u32, 0_u64),
            |(requests, input, output, tools, cost), phase| {
                Some((
                    requests.checked_add(phase.model_requests)?,
                    input.checked_add(phase.input_tokens)?,
                    output.checked_add(phase.output_tokens)?,
                    tools.checked_add(phase.tool_calls)?,
                    cost.checked_add(phase.cost_microusd)?,
                ))
            },
        )
        .ok_or(ToolFirstEngineError::ExecutionAccounting)?;
    if totals
        != (
            aggregate.model_requests,
            aggregate.input_tokens,
            aggregate.output_tokens,
            aggregate.tool_calls,
            aggregate.cost_microusd,
        )
    {
        return Err(ToolFirstEngineError::ExecutionAccounting);
    }
    Ok(())
}

fn validate_request<C>(request: &ToolFirstEngineRequest<C>) -> Result<(), ToolFirstEngineError> {
    let limits = &request.limits;
    if limits.model.trim().is_empty()
        || limits.model != limits.grouper.model
        || limits.model != limits.verifier.model
        || limits.model != limits.adjudicator.model
        || !(1..=8).contains(&limits.max_parallel_groups)
        || limits.diff_page_bytes == 0
        || limits.max_inline_diff_bytes == 0
        || limits.max_inline_diff_bytes > crate::diff_artifact::MAX_INLINE_GROUP_DIFF_BYTES
        || request.system_policy.trim().is_empty()
        || request.system_policy.len() > MAX_SYSTEM_POLICY_BYTES
        || request.system_policy.contains('\0')
        || !valid_identifier(&request.system_policy_id, MAX_SYSTEM_POLICY_ID_BYTES)
        || request.provider.adapter_id().trim().is_empty()
        || request.anchor_table.identity() != &request.partition.snapshot
        || request.partition.validate_replay().is_err()
        || request.partition.work_units.is_empty()
    {
        return Err(ToolFirstEngineError::Configuration);
    }
    Ok(())
}

fn preparation_bindings<C>(
    request: &ToolFirstEngineRequest<C>,
) -> Result<ReviewPreparationBindings, ToolFirstEngineError> {
    let snapshot = serde_json::to_vec(&request.partition.snapshot)
        .map_err(|_| ToolFirstEngineError::Serialization)?;
    Ok(ReviewPreparationBindings {
        snapshot_sha256: Sha256Digest::of_bytes(&snapshot),
        partition_sha256: request.partition.plan_sha256.clone(),
        system_policy_id: request.system_policy_id.clone(),
        system_policy_sha256: Sha256Digest::of_bytes(request.system_policy.as_bytes()),
    })
}

fn diagnostic_rule_policy(policy: &RepositoryReviewPolicy) -> RuleDiagnosticPolicy {
    RuleDiagnosticPolicy {
        base_guidance_present: policy.guidance.is_some(),
        repository_rules: policy
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| RepositoryRuleMetadata {
                id: format!("repository:rule-{index:03}"),
                path_patterns: rule.paths.clone(),
            })
            .collect(),
    }
}

fn verified_candidates(
    groups: &[ExecutedReviewGroup],
) -> Result<Vec<VerifiedCandidate>, ToolFirstEngineError> {
    let mut identifiers = BTreeSet::new();
    let mut verified = Vec::new();
    for group in groups {
        if let GroupVerificationStatus::Verified { accepted, .. } = &group.verification {
            for candidate in accepted {
                if !identifiers.insert(candidate.candidate_id.as_str()) {
                    return Err(ToolFirstEngineError::ExecutionAccounting);
                }
                verified.push(candidate.clone());
            }
        }
    }
    Ok(verified)
}

fn verification_suppression_count(
    groups: &[ExecutedReviewGroup],
) -> Result<u32, ToolFirstEngineError> {
    groups.iter().try_fold(0_u32, |total, group| {
        let count = match &group.verification {
            GroupVerificationStatus::Verified { suppressed, .. } => suppressed.len(),
            GroupVerificationStatus::UnverifiedPartial { candidate_ids, .. } => candidate_ids.len(),
            GroupVerificationStatus::NoCandidates => 0,
        };
        total
            .checked_add(
                u32::try_from(count).map_err(|_| ToolFirstEngineError::ExecutionAccounting)?,
            )
            .ok_or(ToolFirstEngineError::ExecutionAccounting)
    })
}

fn group_accounting(
    execution: &crate::review_group_execution::ReviewGroupExecutionReport,
    mut initial_coverage: BTreeMap<ReviewGroupId, GroupCoverageLedger>,
) -> Result<Vec<GroupResultAccounting>, ToolFirstEngineError> {
    let executed = execution
        .groups
        .iter()
        .map(|group| (group.group_id.clone(), group))
        .collect::<BTreeMap<_, _>>();
    let scheduled = execution
        .schedule
        .records
        .iter()
        .map(|record| record.group_id.clone())
        .collect::<BTreeSet<_>>();
    if executed
        .keys()
        .any(|group_id| !scheduled.contains(group_id))
        || initial_coverage
            .keys()
            .any(|group_id| !scheduled.contains(group_id))
    {
        return Err(ToolFirstEngineError::ExecutionAccounting);
    }
    let mut accounting = Vec::with_capacity(execution.schedule.records.len());
    for record in &execution.schedule.records {
        let initial = initial_coverage
            .remove(&record.group_id)
            .ok_or(ToolFirstEngineError::ExecutionAccounting)?;
        let (coverage, usage) = executed.get(&record.group_id).map_or_else(
            || (initial, AgentBudgetUsage::default()),
            |group| (group.coverage.clone(), group.usage),
        );
        accounting.push(GroupResultAccounting {
            group_id: record.group_id.clone(),
            usage,
            coverage,
            lineage: Vec::new(),
        });
    }
    if !initial_coverage.is_empty() {
        return Err(ToolFirstEngineError::ExecutionAccounting);
    }
    Ok(accounting)
}

#[allow(
    clippy::too_many_arguments,
    reason = "lineage authorization explicitly receives each trusted input boundary"
)]
fn authorize_review_lineages(
    prior_review: &PriorReviewContext,
    anchor_table: &AnchorTable,
    partition: &ReviewPartitionPlan,
    artifacts: &DiffArtifactStore,
    accounting: &[GroupResultAccounting],
    coverage_complete: bool,
    response: LineageDecisionResponse,
) -> Result<Vec<AuthorizedLineageDecision>, ToolFirstEngineError> {
    let selected_inputs = partition
        .work_units
        .iter()
        .flat_map(|unit| unit.files.iter())
        .collect::<Vec<_>>();
    let issued_anchors = selected_inputs
        .iter()
        .flat_map(|input| input.anchor_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let artifact_paths = selected_inputs
        .iter()
        .map(|input| {
            RepositoryRelativePath::try_from(input.path.new_path.as_str().to_owned())
                .map_err(|_| ToolFirstEngineError::ExecutionAccounting)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifests = artifacts
        .manifest(&artifact_paths)
        .map_err(|_| ToolFirstEngineError::ExecutionAccounting)?;
    let manifests = manifests
        .into_iter()
        .map(|manifest| (manifest.path.as_str().to_owned(), manifest.hunks))
        .collect::<BTreeMap<_, _>>();
    let records = prior_review
        .discussions()
        .iter()
        .filter_map(|discussion| {
            discussion
                .lineage
                .as_ref()
                .map(|lineage| PriorLineageRecord {
                    lineage_id: lineage.lineage_sha256.clone(),
                    discussion_source: discussion.source,
                    state: discussion.state,
                    resolution_source: discussion.resolution.as_ref().map(|value| value.source),
                    target: derive_lineage_target(
                        discussion,
                        anchor_table,
                        &selected_inputs,
                        &manifests,
                        &issued_anchors,
                    ),
                })
        })
        .collect::<Vec<_>>();
    let (delivered_anchors, delivered_deletion_hunks) = delivered_lineage_evidence(
        accounting,
        anchor_table,
        &manifests,
        artifacts,
        &issued_anchors,
    )?;
    let coverage = LineageCoverageEvidence::new(
        coverage_complete,
        delivered_anchors,
        delivered_deletion_hunks,
        &issued_anchors,
        anchor_table,
    )
    .map_err(|_| ToolFirstEngineError::ExecutionAccounting)?;
    authorize_lineage_decisions(
        records.clone(),
        response,
        &coverage,
        &issued_anchors,
        anchor_table,
    )
    .or_else(|_| {
        authorize_lineage_decisions(
            records.clone(),
            preserve_lineage_response(&records),
            &coverage,
            &issued_anchors,
            anchor_table,
        )
    })
    .map(|authorization| authorization.decisions)
    .map_err(|_| ToolFirstEngineError::ExecutionAccounting)
}

fn derive_lineage_target(
    discussion: &revoot_core::PriorReviewDiscussion,
    anchor_table: &AnchorTable,
    selected_inputs: &[&WorkUnitFile],
    manifests: &BTreeMap<String, Vec<DiffHunkManifest>>,
    issued_anchors: &BTreeSet<AnchorId>,
) -> PriorLineageTarget {
    let Some(path) = discussion.path.as_deref() else {
        return PriorLineageTarget::Unavailable;
    };
    if let Some(line) = discussion.line {
        let mut matches = anchor_table.iter().filter(|anchor| {
            issued_anchors.contains(&anchor.id)
                && anchor.path.new_path.as_str() == path
                && current_line(anchor.position) == Some(line)
        });
        if let Some(anchor) = matches.next()
            && matches.next().is_none()
            && let Some(hunk) = manifests
                .get(anchor.path.new_path.as_str())
                .and_then(|hunks| {
                    hunks
                        .iter()
                        .find(|hunk| anchor_in_hunk(anchor.position, hunk))
                })
        {
            return PriorLineageTarget::CurrentLocation {
                anchor_id: anchor.id.clone(),
                evidence_id: hunk.hunk_id.clone(),
            };
        }
    }
    let Some(old_line) = discussion.original_line.or(discussion.line) else {
        return PriorLineageTarget::Unavailable;
    };
    let mut matches = selected_inputs.iter().filter_map(|input| {
        (input.path.old_path.as_str() == path || input.path.new_path.as_str() == path)
            .then_some(input.path.new_path.as_str())
    });
    let Some(new_path) = matches.next() else {
        return PriorLineageTarget::Unavailable;
    };
    if matches.next().is_some() {
        return PriorLineageTarget::Unavailable;
    }
    let mut hunks = manifests
        .get(new_path)
        .into_iter()
        .flatten()
        .filter(|hunk| line_in_range(old_line, hunk.old_start, hunk.old_count));
    let Some(hunk) = hunks.next() else {
        return PriorLineageTarget::Unavailable;
    };
    if hunks.next().is_some() {
        return PriorLineageTarget::Unavailable;
    }
    PriorLineageTarget::DeletionHunk {
        hunk_evidence_id: hunk.hunk_id.clone(),
    }
}

fn delivered_lineage_evidence(
    accounting: &[GroupResultAccounting],
    anchor_table: &AnchorTable,
    manifests: &BTreeMap<String, Vec<DiffHunkManifest>>,
    artifacts: &DiffArtifactStore,
    issued_anchors: &BTreeSet<AnchorId>,
) -> Result<(Vec<DeliveredAnchorEvidence>, Vec<String>), ToolFirstEngineError> {
    let mut anchors = BTreeSet::new();
    let mut deletion_hunks = BTreeSet::new();
    for account in accounting {
        for file in account.coverage.files.values() {
            let hunks = manifests
                .get(file.path.as_str())
                .ok_or(ToolFirstEngineError::ExecutionAccounting)?;
            for coverage in &file.hunks {
                let manifest = hunks
                    .iter()
                    .find(|hunk| hunk.hunk_id == coverage.hunk_id)
                    .ok_or(ToolFirstEngineError::ExecutionAccounting)?;
                if coverage.total_pages != manifest.pages {
                    return Err(ToolFirstEngineError::ExecutionAccounting);
                }
                if !coverage.delivered_pages.is_empty() {
                    let path = RepositoryRelativePath::try_from(file.path.as_str().to_owned())
                        .map_err(|_| ToolFirstEngineError::ExecutionAccounting)?;
                    let positions = coverage
                        .delivered_pages
                        .iter()
                        .map(|page| {
                            artifacts
                                .read_hunk_page(&path, &manifest.hunk_id, *page)
                                .map(|page| page.positions)
                                .map_err(|_| ToolFirstEngineError::ExecutionAccounting)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flatten()
                        .collect::<BTreeSet<_>>();
                    for anchor in anchor_table.iter().filter(|anchor| {
                        issued_anchors.contains(&anchor.id)
                            && anchor.path.new_path == file.path
                            && positions.contains(&anchor.position)
                    }) {
                        anchors.insert((anchor.id.clone(), manifest.hunk_id.clone()));
                    }
                }
                if coverage.delivered_pages.len()
                    == usize::try_from(coverage.total_pages).unwrap_or(usize::MAX)
                    && (1..=coverage.total_pages)
                        .all(|page| coverage.delivered_pages.contains(&page))
                {
                    deletion_hunks.insert(manifest.hunk_id.clone());
                }
            }
        }
    }
    Ok((
        anchors
            .into_iter()
            .map(|(anchor_id, evidence_id)| DeliveredAnchorEvidence {
                anchor_id,
                evidence_id,
            })
            .collect(),
        deletion_hunks.into_iter().collect(),
    ))
}

fn current_line(position: AnchorPosition) -> Option<u32> {
    match position {
        AnchorPosition::Addition { new_line } | AnchorPosition::Context { new_line, .. } => {
            Some(new_line)
        }
        AnchorPosition::Deletion { .. } => None,
    }
}

fn anchor_in_hunk(position: AnchorPosition, hunk: &DiffHunkManifest) -> bool {
    match position {
        AnchorPosition::Addition { new_line } => {
            line_in_range(new_line, hunk.new_start, hunk.new_count)
        }
        AnchorPosition::Deletion { old_line } => {
            line_in_range(old_line, hunk.old_start, hunk.old_count)
        }
        AnchorPosition::Context { old_line, new_line } => {
            line_in_range(old_line, hunk.old_start, hunk.old_count)
                && line_in_range(new_line, hunk.new_start, hunk.new_count)
        }
    }
}

fn line_in_range(line: u32, start: u32, count: u32) -> bool {
    count > 0 && line >= start && line < start.saturating_add(count)
}

fn preserve_lineage_response(records: &[PriorLineageRecord]) -> LineageDecisionResponse {
    LineageDecisionResponse {
        schema_version: LineageDecisionResponse::SCHEMA_VERSION.to_owned(),
        decisions: records
            .iter()
            .map(|record| ProposedLineageDecision {
                lineage_id: record.lineage_id.clone(),
                disposition: ProposedLineageDisposition::Preserve,
            })
            .collect(),
    }
}

fn attach_lineage_authorizations(
    accounting: &mut [GroupResultAccounting],
    mut decisions: Vec<AuthorizedLineageDecision>,
) -> Result<(), ToolFirstEngineError> {
    decisions.retain(|decision| {
        matches!(
            decision.action,
            AuthorizedLineageAction::ResolveFixed { .. }
        )
    });
    if decisions.is_empty() {
        return Ok(());
    }
    let Some(first) = accounting.first_mut() else {
        return Err(ToolFirstEngineError::ExecutionAccounting);
    };
    first.lineage = decisions;
    Ok(())
}

fn adjudication_context(
    execution: &crate::review_group_execution::ReviewGroupExecutionReport,
    accounting: &[GroupResultAccounting],
    partition: &ReviewPartitionPlan,
    prior_review: &PriorReviewContext,
    budget_usage: ReviewBudgetUsage,
) -> Result<GlobalAdjudicationContext, ToolFirstEngineError> {
    let groups = execution
        .groups
        .iter()
        .map(|group| (group.group_id.clone(), group))
        .collect::<BTreeMap<_, _>>();
    let group_summaries = execution
        .schedule
        .records
        .iter()
        .map(|record| {
            let group = groups.get(&record.group_id);
            AdjudicationGroupSummary {
                group_id: record.group_id.as_str().to_owned(),
                summary: group.map_or_else(
                    || "Group review did not produce a completed summary.".to_owned(),
                    |group| group.summary.text.clone(),
                ),
                partial: !matches!(record.status, GroupScheduleStatus::Complete)
                    || group.is_none_or(|group| {
                        !matches!(
                            group.worker_status,
                            GroupWorkerStatus::Complete(
                                revoot_core::GroupCompletion::Complete { .. }
                            )
                        ) || matches!(
                            group.verification,
                            GroupVerificationStatus::UnverifiedPartial { .. }
                        )
                    }),
            }
        })
        .collect();
    let deferred_files = accounting.iter().try_fold(0_u32, |total, account| {
        let count = account
            .coverage
            .files
            .values()
            .filter(|file| !file.unread_dispositions.is_empty())
            .count();
        total
            .checked_add(
                u32::try_from(count).map_err(|_| ToolFirstEngineError::ExecutionAccounting)?,
            )
            .ok_or(ToolFirstEngineError::ExecutionAccounting)
    })?;
    let failed_groups = execution
        .schedule
        .failed_groups
        .checked_add(execution.schedule.cancelled_groups)
        .ok_or(ToolFirstEngineError::ExecutionAccounting)?;
    let partial = execution.schedule.partial
        || execution
            .schedule
            .records
            .iter()
            .any(|record| !matches!(record.status, GroupScheduleStatus::Complete))
        || accounting
            .iter()
            .any(|account| !account.coverage.is_complete())
        || !partition.coverage.complete;
    let coverage = AdjudicationFallbackCoverage {
        partial,
        failed_groups,
        deferred_files,
        budget_exhausted: matches!(
            execution.stop_reason,
            Some(GroupRuntimeStopReason::BudgetExhausted)
        ),
    };
    Ok(GlobalAdjudicationContext {
        group_summaries,
        coverage,
        prior_lineages: adjudication_lineages(prior_review)?,
        selection_omissions: partition.coverage.omitted_files,
        budget_usage,
    })
}

fn adjudication_lineages(
    prior_review: &PriorReviewContext,
) -> Result<Vec<AdjudicationLineage>, ToolFirstEngineError> {
    let mut lineages = BTreeMap::new();
    for discussion in prior_review.discussions() {
        let Some(marker) = &discussion.lineage else {
            continue;
        };
        let state = if discussion.source != PriorReviewSource::Revoot {
            AdjudicationLineageState::Foreign
        } else if discussion.state == PriorReviewState::Resolved {
            AdjudicationLineageState::HumanResolved
        } else {
            AdjudicationLineageState::Active
        };
        if lineages
            .insert(marker.lineage_sha256.as_str().to_owned(), state)
            .is_some()
        {
            return Err(ToolFirstEngineError::ExecutionAccounting);
        }
    }
    Ok(lineages
        .into_iter()
        .map(|(lineage_id, state)| AdjudicationLineage { lineage_id, state })
        .collect())
}

fn adjudication_fallback_omission(reason: ReviewAdjudicatorFallbackReason) -> AgentOmission {
    let reason = match reason {
        ReviewAdjudicatorFallbackReason::BudgetUnavailable
        | ReviewAdjudicatorFallbackReason::BudgetSettlement => AgentOmissionReason::BudgetExhausted,
        ReviewAdjudicatorFallbackReason::Cancelled => AgentOmissionReason::CoverageIncomplete,
        ReviewAdjudicatorFallbackReason::InputTooLarge
        | ReviewAdjudicatorFallbackReason::ProviderFailure
        | ReviewAdjudicatorFallbackReason::InvalidResponse => AgentOmissionReason::ProviderLimited,
    };
    AgentOmission {
        subject_id: "global-adjudication".to_owned(),
        reason,
    }
}

fn apply_aggregate_usage(
    outcome: &mut ReviewOutcome,
    aggregate: ReviewBudgetUsage,
    verified_candidates: usize,
) -> Result<(), ToolFirstEngineError> {
    let usage = match outcome {
        ReviewOutcome::Complete { usage, .. }
        | ReviewOutcome::Partial { usage, .. }
        | ReviewOutcome::NoFindings { usage, .. }
        | ReviewOutcome::Stale { usage }
        | ReviewOutcome::Blocked { usage, .. }
        | ReviewOutcome::Failed { usage, .. }
        | ReviewOutcome::Cancelled { usage } => usage,
    };
    usage.turns = aggregate.model_requests;
    usage.model_requests = aggregate.model_requests;
    usage.input_tokens = aggregate.input_tokens;
    usage.output_tokens = aggregate.output_tokens;
    usage.tool_calls = aggregate.tool_calls;
    usage.cost_microusd = aggregate.cost_microusd;
    usage.elapsed_millis = aggregate.elapsed_millis;
    usage.candidate_findings = u32::try_from(verified_candidates)
        .map_err(|_| ToolFirstEngineError::ExecutionAccounting)?;
    Ok(())
}

fn valid_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use revoot_core::provider::{ProviderError, ProviderErrorKind, ProviderFuture};
    use revoot_core::{
        AdjudicatorResponse, AnchorPosition, ChangedPath, CommentableLine, FileChangeKind,
        FindingLineageMarker, GitSha, LocalSnapshotIdentity, ModelContent, ModelFinishReason,
        ModelRequest, ModelResponse, ModelUsage, PartitionLimits, PriorReviewDiscussion,
        PriorReviewResolution, RepositoryDiff, RepositoryPath, RepositoryRelativePath,
        RepositoryToolLimits, ReviewBudgetLimits, ReviewFileClass, ReviewFileInput, ReviewObject,
        ReviewObjectRole, ReviewSelectionPolicy, ReviewSnapshotIdentity, ReviewValue,
        ReviewValueReason, ReviewValueTier, build_partition_plan,
    };
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    const DIFF_A: &str = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1 +1 @@\n-old\n+new\n";
    const DIFF_B: &str = "diff --git a/src/b.rs b/src/b.rs\n--- a/src/b.rs\n+++ b/src/b.rs\n@@ -1 +1 @@\n-old\n+new\n";
    const DIFF_C: &str = "diff --git a/src/c.rs b/src/c.rs\n--- a/src/c.rs\n+++ b/src/c.rs\n@@ -1 +1 @@\n-old\n+new\n";
    const DIFF_D: &str = "diff --git a/src/d.rs b/src/d.rs\n--- a/src/d.rs\n+++ b/src/d.rs\n@@ -1 +1 @@\n-old\n+new\n";

    struct FixedClock;

    impl ReviewGrouperClock for FixedClock {
        fn now_millis(&self) -> u64 {
            0
        }
    }

    impl GroupWorkerClock for FixedClock {
        fn now_millis(&self) -> u64 {
            0
        }
    }

    impl ReviewVerifierClock for FixedClock {
        fn now_millis(&self) -> u64 {
            0
        }
    }

    impl ReviewAdjudicatorClock for FixedClock {
        fn now_millis(&self) -> u64 {
            0
        }
    }

    struct CompletingProvider {
        calls: AtomicUsize,
    }

    impl ProviderAdapter for CompletingProvider {
        fn adapter_id(&self) -> &'static str {
            "completing-fake"
        }

        fn complete<'a>(
            &'a self,
            request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let grouping = request.tools.is_empty();
            Box::pin(async move {
                Ok(if grouping {
                    grouping_response()
                } else {
                    complete_group_response()
                })
            })
        }
    }

    struct FailingProvider {
        calls: AtomicUsize,
    }

    impl ProviderAdapter for FailingProvider {
        fn adapter_id(&self) -> &'static str {
            "failing-fake"
        }

        fn complete<'a>(
            &'a self,
            request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let grouping = request.tools.is_empty();
            Box::pin(async move {
                if grouping {
                    Ok(grouping_response())
                } else {
                    Err(ProviderError::new(
                        ProviderErrorKind::Unavailable,
                        None,
                        true,
                    ))
                }
            })
        }
    }

    struct LineageProvider {
        worker_stage: AtomicUsize,
        lineage_id: Sha256Digest,
        malformed_lineage_response: bool,
    }

    impl ProviderAdapter for LineageProvider {
        fn adapter_id(&self) -> &'static str {
            "lineage-fake"
        }

        fn complete<'a>(
            &'a self,
            request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            let response = if request.tools.is_empty() {
                lineage_adjudication_response(&self.lineage_id, self.malformed_lineage_response)
            } else if self.worker_stage.fetch_add(1, Ordering::Relaxed) == 0 {
                let packet = request
                    .messages
                    .iter()
                    .flat_map(|message| &message.content)
                    .find_map(|content| match content {
                        ModelContent::Text { text } => {
                            serde_json::from_str::<serde_json::Value>(text).ok()
                        }
                        ModelContent::ToolUse { .. } | ModelContent::ToolResult { .. } => None,
                    })
                    .expect("worker packet");
                let file = &packet["files"][0];
                ModelResponse {
                    provider_response_id: None,
                    model: "model-v1".to_owned(),
                    content: vec![ModelContent::ToolUse {
                        id: "lineage-read".to_owned(),
                        name: "read_diff".to_owned(),
                        input: json!({"reads":[{
                            "path": file["path"],
                            "hunk_id": file["hunk_ids"][0],
                            "page": 1
                        }]}),
                    }],
                    finish_reason: ModelFinishReason::ToolUse,
                    usage: ModelUsage::default(),
                }
            } else {
                complete_group_response()
            };
            Box::pin(async move { Ok(response) })
        }
    }

    struct EngineSetup {
        _directory: TempDir,
        toolbox: Arc<RepositoryToolbox>,
        partition: ReviewPartitionPlan,
        anchors: AnchorTable,
    }

    fn setup() -> EngineSetup {
        let directory = tempfile::tempdir().expect("temporary repository");
        fs::create_dir(directory.path().join("src")).expect("source directory");
        fs::write(directory.path().join("src/a.rs"), "new\n").expect("source A");
        fs::write(directory.path().join("src/b.rs"), "new\n").expect("source B");
        fs::write(directory.path().join("src/c.rs"), "new\n").expect("source C");
        fs::write(directory.path().join("src/d.rs"), "new\n").expect("source D");
        let repository_paths = [
            repository_path("src/a.rs"),
            repository_path("src/b.rs"),
            repository_path("src/c.rs"),
            repository_path("src/d.rs"),
        ];
        let relative_paths = [
            relative_path("src/a.rs"),
            relative_path("src/b.rs"),
            relative_path("src/c.rs"),
            relative_path("src/d.rs"),
        ];
        let diffs = [DIFF_A, DIFF_B, DIFF_C, DIFF_D];
        let snapshot = snapshot();
        let anchors = AnchorTable::build(snapshot.clone(), []).expect("anchor table");
        let inputs = repository_paths
            .iter()
            .zip(diffs)
            .map(|(path, diff)| ReviewFileInput {
                path: ChangedPath {
                    old_path: path.clone(),
                    new_path: path.clone(),
                    kind: FileChangeKind::Modified,
                },
                class: ReviewFileClass::Text,
                review_value: ReviewValue {
                    tier: ReviewValueTier::Low,
                    score: 1,
                    reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                },
                objects: vec![ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: Sha256Digest::of_bytes(diff.as_bytes()),
                    size_bytes: u64::try_from(diff.len()).expect("diff bytes"),
                }],
                anchor_ids: Vec::new(),
            })
            .collect::<Vec<_>>();
        let partition = build_partition_plan(
            snapshot,
            &ReviewSelectionPolicy {
                version: "selection-v1".to_owned(),
                included_paths: BTreeSet::new(),
                included_prefixes: Vec::new(),
                included_suffixes: Vec::new(),
                excluded_paths: BTreeSet::new(),
                excluded_prefixes: Vec::new(),
                excluded_suffixes: Vec::new(),
                excluded_basename_prefixes: Vec::new(),
                include_generated: false,
                max_file_bytes: 100_000,
            },
            PartitionLimits {
                max_files: 100,
                max_total_bytes: 1_000_000,
                max_work_units: 100,
                max_files_per_work_unit: 1,
                max_bytes_per_work_unit: 100_000,
                max_anchors_per_work_unit: 100,
            },
            inputs,
        )
        .expect("partition");
        let cancellation = CancellationToken::default();
        let toolbox = Arc::new(
            RepositoryToolbox::open_selected(
                directory.path(),
                RepositoryToolLimits::default(),
                relative_paths
                    .iter()
                    .cloned()
                    .zip(diffs)
                    .map(|(path, text)| RepositoryDiff {
                        path,
                        text: text.to_owned(),
                    }),
                relative_paths.iter().cloned(),
                &cancellation,
            )
            .expect("toolbox"),
        );
        EngineSetup {
            _directory: directory,
            toolbox,
            partition,
            anchors,
        }
    }

    fn lineage_setup(
        discussion_source: PriorReviewSource,
        discussion_state: PriorReviewState,
        current_anchor: bool,
    ) -> (EngineSetup, PriorReviewContext, Sha256Digest) {
        let directory = tempfile::tempdir().expect("temporary repository");
        fs::create_dir(directory.path().join("src")).expect("source directory");
        fs::write(directory.path().join("src/lineage.rs"), "new\n").expect("source");
        let path = repository_path("src/lineage.rs");
        let changed_path = ChangedPath {
            old_path: path.clone(),
            new_path: path.clone(),
            kind: FileChangeKind::Modified,
        };
        let mut diff = "diff --git a/src/lineage.rs b/src/lineage.rs\n--- a/src/lineage.rs\n+++ b/src/lineage.rs\n@@ -1 +1 @@\n-old\n+new\n ".to_owned();
        diff.push_str(&"x".repeat(17_000));
        diff.push('\n');
        let snapshot = snapshot();
        let anchors = AnchorTable::build(
            snapshot.clone(),
            current_anchor.then(|| CommentableLine {
                path: changed_path.clone(),
                position: AnchorPosition::addition(1).expect("anchor"),
                exact_line_digest: Sha256Digest::of_bytes(b"new"),
                context_digest: Sha256Digest::of_bytes(b"context"),
            }),
        )
        .expect("anchor table");
        let anchor_ids = anchors.iter().map(|anchor| anchor.id.clone()).collect();
        let partition = build_partition_plan(
            snapshot,
            &ReviewSelectionPolicy {
                version: "selection-v1".to_owned(),
                included_paths: BTreeSet::new(),
                included_prefixes: Vec::new(),
                included_suffixes: Vec::new(),
                excluded_paths: BTreeSet::new(),
                excluded_prefixes: Vec::new(),
                excluded_suffixes: Vec::new(),
                excluded_basename_prefixes: Vec::new(),
                include_generated: false,
                max_file_bytes: 100_000,
            },
            PartitionLimits {
                max_files: 1,
                max_total_bytes: 100_000,
                max_work_units: 1,
                max_files_per_work_unit: 1,
                max_bytes_per_work_unit: 100_000,
                max_anchors_per_work_unit: 10,
            },
            [ReviewFileInput {
                path: changed_path,
                class: ReviewFileClass::Text,
                review_value: ReviewValue {
                    tier: ReviewValueTier::High,
                    score: 220,
                    reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                },
                objects: vec![ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: Sha256Digest::of_bytes(diff.as_bytes()),
                    size_bytes: u64::try_from(diff.len()).expect("diff bytes"),
                }],
                anchor_ids,
            }],
        )
        .expect("partition");
        let cancellation = CancellationToken::default();
        let toolbox = Arc::new(
            RepositoryToolbox::open_selected(
                directory.path(),
                RepositoryToolLimits::default(),
                [RepositoryDiff {
                    path: relative_path("src/lineage.rs"),
                    text: diff,
                }],
                [relative_path("src/lineage.rs")],
                &cancellation,
            )
            .expect("toolbox"),
        );
        let (prior_review, lineage_id) =
            lineage_prior_review(discussion_source, discussion_state, current_anchor);
        (
            EngineSetup {
                _directory: directory,
                toolbox,
                partition,
                anchors,
            },
            prior_review,
            lineage_id,
        )
    }

    fn lineage_prior_review(
        source: PriorReviewSource,
        state: PriorReviewState,
        current_anchor: bool,
    ) -> (PriorReviewContext, Sha256Digest) {
        let lineage_id = Sha256Digest::of_bytes(b"prior-lineage");
        let resolution = (state == PriorReviewState::Resolved).then_some(PriorReviewResolution {
            source: PriorReviewSource::Other,
            resolved_at: None,
        });
        let prior_review = PriorReviewContext::try_new(vec![PriorReviewDiscussion {
            thread_id: "thread-lineage".to_owned(),
            comment_id: "comment-lineage".to_owned(),
            source,
            state,
            path: Some("src/lineage.rs".to_owned()),
            line: current_anchor.then_some(1),
            original_line: Some(1),
            body: "Prior finding".to_owned(),
            replies: Vec::new(),
            resolution,
            lineage: Some(FindingLineageMarker::new(
                lineage_id.clone(),
                GitSha::try_from("9".repeat(40)).expect("prior head"),
                Sha256Digest::of_bytes(b"prior evidence"),
            )),
        }])
        .expect("prior review");
        (prior_review, lineage_id)
    }

    fn request<P>(setup: EngineSetup, provider: Arc<P>) -> ToolFirstEngineRequest<FixedClock>
    where
        P: ProviderAdapter + 'static,
    {
        let mut limits = ToolFirstEngineLimits::new("model-v1");
        limits.effort = ReviewEffort::Low;
        limits.max_parallel_groups = 2;
        ToolFirstEngineRequest {
            provider,
            toolbox: setup.toolbox,
            history: None,
            prior_review: PriorReviewContext::default(),
            anchor_table: setup.anchors,
            partition: setup.partition,
            rule_policy: RepositoryReviewPolicy::default(),
            budget: ReviewBudgetBroker::new(ReviewBudgetLimits::default(), 0).expect("budget"),
            cancellation: CancellationToken::default(),
            clock: Arc::new(FixedClock),
            limits,
            system_policy_id: "tool-first-policy-v1".to_owned(),
            system_policy: "Use only bounded tools and complete the assigned review group."
                .to_owned(),
            initial_omissions: Vec::new(),
        }
    }

    #[tokio::test]
    async fn two_groups_complete_through_the_full_native_pipeline() {
        let provider = Arc::new(CompletingProvider {
            calls: AtomicUsize::new(0),
        });
        let result = run_tool_first_engine(request(setup(), Arc::clone(&provider)))
            .await
            .expect("tool-first result");
        assert!(result.group_count >= 2);
        assert_eq!(result.schedule.complete_groups, result.group_count);
        assert_eq!(result.verified_candidates, 0);
        assert!(matches!(
            result.adjudication_mode,
            ReviewAdjudicationMode::NoVerifiedCandidates
        ));
        assert!(matches!(
            result.result.outcome,
            ReviewOutcome::NoFindings { .. }
        ));
        assert_eq!(
            result
                .phase_usage
                .iter()
                .map(|usage| usage.phase)
                .collect::<Vec<_>>(),
            vec![
                ReviewReportPhase::Grouping,
                ReviewReportPhase::Planning,
                ReviewReportPhase::Review,
                ReviewReportPhase::Verification,
                ReviewReportPhase::Adjudication,
            ]
        );
        reconcile_phase_usage(&result.phase_usage, result.budget_usage)
            .expect("phase totals reconcile");
        assert_eq!(
            provider.calls.load(Ordering::Relaxed),
            usize::try_from(result.group_count).expect("group count") + 1
        );
    }

    #[tokio::test]
    async fn two_group_provider_failure_returns_a_deterministic_partial_result() {
        let provider = Arc::new(FailingProvider {
            calls: AtomicUsize::new(0),
        });
        let result = run_tool_first_engine(request(setup(), Arc::clone(&provider)))
            .await
            .expect("partial tool-first result");
        assert!(result.group_count >= 2);
        assert_eq!(result.schedule.partial_groups, result.group_count);
        assert!(result.schedule.partial);
        assert!(matches!(
            result.result.outcome,
            ReviewOutcome::Partial { .. }
        ));
        assert_eq!(result.result.coverage.failed_groups, 0);
        assert_eq!(
            provider.calls.load(Ordering::Relaxed),
            usize::try_from(result.group_count).expect("group count") + 1
        );
    }

    #[tokio::test]
    async fn full_engine_cancellation_and_provider_failure_clean_artifacts() {
        let completing = Arc::new(CompletingProvider {
            calls: AtomicUsize::new(0),
        });
        let cancelled_request = request(setup(), completing);
        let cancelled_prepared = prepare_for_execution(&cancelled_request).await;
        let cancelled_directory = cancelled_prepared.artifacts.directory_path().to_path_buf();
        cancelled_request
            .cancellation
            .cancel(revoot_core::ProviderCancellationReason::UserRequested);
        let _cancelled_result = execute_and_reduce(cancelled_request, cancelled_prepared).await;
        assert!(!cancelled_directory.exists());

        let failing = Arc::new(FailingProvider {
            calls: AtomicUsize::new(0),
        });
        let failed_request = request(setup(), failing);
        let failed_prepared = prepare_for_execution(&failed_request).await;
        let failed_directory = failed_prepared.artifacts.directory_path().to_path_buf();
        let failed_result = execute_and_reduce(failed_request, failed_prepared)
            .await
            .expect("provider failure produces a partial review");
        assert!(matches!(
            failed_result.result.outcome,
            ReviewOutcome::Partial { .. }
        ));
        assert!(!failed_directory.exists());
    }

    #[tokio::test]
    async fn delivered_current_anchor_and_complete_deletion_hunk_authorize_fixed() {
        for current_anchor in [true, false] {
            let (setup, prior_review, lineage_id) = lineage_setup(
                PriorReviewSource::Revoot,
                PriorReviewState::Open,
                current_anchor,
            );
            let provider = Arc::new(LineageProvider {
                worker_stage: AtomicUsize::new(0),
                lineage_id: lineage_id.clone(),
                malformed_lineage_response: false,
            });
            let mut review = request(setup, Arc::clone(&provider));
            review.prior_review = prior_review;
            let result = run_tool_first_engine(review).await.expect("lineage review");
            assert_eq!(provider.worker_stage.load(Ordering::Relaxed), 2);
            assert_eq!(result.result.prior_finding_dispositions.len(), 1);
            assert_eq!(
                result.result.prior_finding_dispositions[0].lineage_id,
                lineage_id
            );
            assert_eq!(
                result.result.prior_finding_dispositions[0].disposition,
                crate::review_contracts::PriorFindingDispositionKind::Fixed
            );
        }
    }

    #[tokio::test]
    async fn partial_coverage_and_missing_lineage_decision_preserve_prior_finding() {
        for (malformed, add_partial_omission) in [(false, true), (true, false)] {
            let (setup, prior_review, lineage_id) =
                lineage_setup(PriorReviewSource::Revoot, PriorReviewState::Open, true);
            let provider = Arc::new(LineageProvider {
                worker_stage: AtomicUsize::new(0),
                lineage_id,
                malformed_lineage_response: malformed,
            });
            let mut review = request(setup, provider);
            review.prior_review = prior_review;
            if add_partial_omission {
                review.initial_omissions.push(AgentOmission {
                    subject_id: "trusted-selection-omission".to_owned(),
                    reason: AgentOmissionReason::CoverageIncomplete,
                });
            }
            let result = run_tool_first_engine(review).await.expect("partial review");
            assert!(matches!(
                result.result.outcome,
                ReviewOutcome::Partial { .. }
            ));
            assert_eq!(
                result.result.prior_finding_dispositions[0].disposition,
                crate::review_contracts::PriorFindingDispositionKind::Uncertain
            );
            if malformed {
                assert!(matches!(
                    result.adjudication_mode,
                    ReviewAdjudicationMode::DeterministicFallback(
                        ReviewAdjudicatorFallbackReason::InvalidResponse
                    )
                ));
            }
        }
    }

    #[tokio::test]
    async fn foreign_and_already_resolved_lineages_remain_outside_resolution_actions() {
        for (source, state) in [
            (PriorReviewSource::Other, PriorReviewState::Open),
            (PriorReviewSource::Revoot, PriorReviewState::Resolved),
        ] {
            let (setup, prior_review, lineage_id) = lineage_setup(source, state, true);
            let provider = Arc::new(LineageProvider {
                worker_stage: AtomicUsize::new(0),
                lineage_id,
                malformed_lineage_response: false,
            });
            let mut review = request(setup, provider);
            review.prior_review = prior_review;
            let result = run_tool_first_engine(review)
                .await
                .expect("preserved review");
            assert!(result.result.prior_finding_dispositions.is_empty());
        }
    }

    async fn prepare_for_execution(
        request: &ToolFirstEngineRequest<FixedClock>,
    ) -> ToolFirstPreparedReview {
        let bindings = preparation_bindings(request).expect("preparation bindings");
        let diagnostic_policy = diagnostic_rule_policy(&request.rule_policy);
        prepare_tool_first_review(
            ToolFirstPreparationInput {
                repository: request.toolbox.as_ref(),
                partition: &request.partition,
                anchor_table: request.anchor_table.clone(),
                rule_policy: &diagnostic_policy,
                bindings,
                grouper: request.limits.grouper.clone(),
                effort: request.limits.effort,
                diff_page_bytes: request.limits.diff_page_bytes,
                max_inline_diff_bytes: request.limits.max_inline_diff_bytes,
            },
            request.provider.as_ref(),
            &request.budget,
            &request.cancellation,
            request.clock.as_ref(),
        )
        .await
        .expect("tool-first preparation")
    }

    fn complete_group_response() -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "model-v1".to_owned(),
            content: vec![ModelContent::ToolUse {
                id: "call-1".to_owned(),
                name: "complete_group".to_owned(),
                input: json!({
                    "checkpoint": {
                        "hypotheses": [],
                        "evidence_references": [],
                        "unresolved_coverage": []
                    },
                    "summary": {"text":"reviewed","assumptions":[]}
                }),
            }],
            finish_reason: ModelFinishReason::ToolUse,
            usage: ModelUsage::default(),
        }
    }

    fn lineage_adjudication_response(lineage_id: &Sha256Digest, malformed: bool) -> ModelResponse {
        let mut response = json!({
            "schema_version": AdjudicatorResponse::SCHEMA_VERSION,
            "publish": [],
            "suppress": [],
            "overview": {
                "summary": "No current findings remain.",
                "assumptions": []
            }
        });
        if !malformed {
            response["lineage_decisions"] = json!([{
                "lineage_id": lineage_id,
                "disposition": "fixed"
            }]);
        }
        ModelResponse {
            provider_response_id: None,
            model: "model-v1".to_owned(),
            content: vec![ModelContent::Text {
                text: response.to_string(),
            }],
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage::default(),
        }
    }

    fn grouping_response() -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "model-v1".to_owned(),
            content: vec![ModelContent::Text {
                text: json!({
                    "schema_version": "revoot.grouping-proposal/v1",
                    "groups": [
                        {"paths": ["src/a.rs"]},
                        {"paths": ["src/b.rs"]},
                        {"paths": ["src/c.rs"]},
                        {"paths": ["src/d.rs"]}
                    ]
                })
                .to_string(),
            }],
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage::default(),
        }
    }

    fn snapshot() -> ReviewSnapshotIdentity {
        ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
            repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
            base_sha: GitSha::try_from("a".repeat(40)).expect("base SHA"),
            head_sha: GitSha::try_from("b".repeat(40)).expect("head SHA"),
            working_tree_sha256: Sha256Digest::of_bytes(b"working tree"),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
        })
    }

    fn repository_path(path: &str) -> RepositoryPath {
        RepositoryPath::try_from(path.to_owned()).expect("repository path")
    }

    fn relative_path(path: &str) -> RepositoryRelativePath {
        RepositoryRelativePath::try_from(path.to_owned()).expect("relative path")
    }
}
