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
    AdjudicationFallbackCoverage, AgentBudgetUsage, AgentOmission, AgentOmissionReason,
    AnchorTable, AuthorizedLineageDecision, CancellationToken, GroupCoverageLedger,
    PriorReviewContext, PriorReviewSource, PriorReviewState, RepositoryToolbox, ReviewBudgetBroker,
    ReviewBudgetUsage, ReviewEffort, ReviewGroupId, ReviewOutcome, ReviewPartitionPlan,
    ReviewReportPhase, ReviewReportPhaseUsage, Sha256Digest, VerifiedCandidate,
};

use crate::config::RepositoryReviewPolicy;
use crate::diff_artifact::DEFAULT_DIFF_PAGE_BYTES;
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
    /// Optional exact-evidence decisions produced by the trusted lineage
    /// authorization layer. Absence can preserve or mark still-present
    /// lineages, but can never mark one fixed.
    pub lineage_authorizations: Vec<AuthorizedLineageDecision>,
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
            .field(
                "lineage_authorization_count",
                &self.lineage_authorizations.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Payload-free terminal report from the native tool-first pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolFirstEngineReport {
    pub result: ReducedReviewResult,
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
        grouping_usage,
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
    let verified = verified_candidates(&execution.groups)?;
    let verification_suppressions = verification_suppression_count(&execution.groups)?;
    let group_accounting =
        group_accounting(&execution, initial_coverage, request.lineage_authorizations)?;
    let adjudication_context = adjudication_context(
        &execution,
        &group_accounting,
        &request.partition,
        &request.prior_review,
        request.budget.snapshot().usage,
    )?;
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
        return Err(ToolFirstEngineError::ExecutionAccounting);
    }
    let budget_usage = budget_snapshot.usage;
    let phase_usage = ordered_phase_usage(
        grouping_usage,
        execution.phase_usage.planning,
        execution.phase_usage.review,
        execution.phase_usage.verification,
        adjudication.usage,
    );
    reconcile_phase_usage(&phase_usage, budget_usage)?;
    apply_aggregate_usage(&mut result.outcome, budget_usage, verified.len())?;
    Ok(ToolFirstEngineReport {
        result,
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
    lineage: Vec<AuthorizedLineageDecision>,
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
    let mut lineage = Some(lineage);
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
            // The authorization is review-wide. Its exact-evidence authority
            // is carried by the closed decision type; deterministic placement
            // in one per-group reducer record must not duplicate it.
            lineage: lineage.take().unwrap_or_default(),
        });
    }
    if !initial_coverage.is_empty() || lineage.is_some_and(|lineage| !lineage.is_empty()) {
        return Err(ToolFirstEngineError::ExecutionAccounting);
    }
    Ok(accounting)
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
        ChangedPath, FileChangeKind, GitSha, LocalSnapshotIdentity, ModelContent,
        ModelFinishReason, ModelRequest, ModelResponse, ModelUsage, PartitionLimits,
        RepositoryDiff, RepositoryPath, RepositoryRelativePath, RepositoryToolLimits,
        ReviewBudgetLimits, ReviewFileClass, ReviewFileInput, ReviewObject, ReviewObjectRole,
        ReviewSelectionPolicy, ReviewSnapshotIdentity, ReviewValue, ReviewValueReason,
        ReviewValueTier, build_partition_plan,
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
            lineage_authorizations: Vec::new(),
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
