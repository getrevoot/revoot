//! Deterministic projection of globally adjudicated review results.
//!
//! This module performs no provider, tool, publication, filesystem, or
//! execution work. It validates final accounting against immutable plans and
//! projects only already-verified candidates into the existing result types.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use revoot_core::{
    AdjudicationOutcome, AgentBudgetUsage, AgentOmission, AgentOmissionReason,
    AuthorizedLineageAction, FindingsEnvelope, GroupCoverageLedger, PriorReviewContext,
    PriorReviewSource, PriorReviewState, RepositoryPath, ReviewGroupId, ReviewPartitionPlan,
    ReviewValueTier, Sha256Digest,
};

use crate::group_scheduler::{
    GroupFailureReason, GroupPartialReason, GroupScheduleSnapshot, GroupScheduleStatus,
};
use crate::review_contracts::{
    PriorFindingDisposition, PriorFindingDispositionKind, ReviewCoverage,
};
use crate::review_overview::{ReviewOverview, ReviewRisk, RiskLevel};

const MAX_PUBLISHED_FINDINGS: usize = 25;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_OVERVIEW_SUMMARY_BYTES: usize = 1_200;
const MAX_OVERVIEW_ITEM_BYTES: usize = 400;
const MAX_OVERVIEW_ITEMS: usize = 6;

/// Trusted accounting returned for one scheduled review group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupResultAccounting {
    pub group_id: ReviewGroupId,
    pub usage: AgentBudgetUsage,
    pub coverage: GroupCoverageLedger,
    /// Coverage-gated lineage decisions created by the trusted lineage
    /// authorization layer. The reducer never treats a model proposal as an
    /// authorization.
    pub lineage: Vec<revoot_core::AuthorizedLineageDecision>,
}

/// Existing result contracts produced by one deterministic reduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReducedReviewResult {
    pub outcome: revoot_core::ReviewOutcome,
    pub overview: ReviewOverview,
    pub coverage: ReviewCoverage,
    pub prior_finding_dispositions: Vec<PriorFindingDisposition>,
}

/// Closed, payload-free reduction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewResultReducerError {
    Partition,
    Schedule,
    DuplicateGroupAccounting,
    MissingGroupAccounting,
    UnknownGroupAccounting,
    CoveragePath,
    DuplicateCoveragePath,
    CoverageIncompleteForCompleteGroup,
    CandidateCount,
    CandidateIdentifier,
    DuplicateCandidate,
    DuplicateFinding,
    UnknownWorkUnit,
    CandidateTarget,
    CandidateAnchor,
    FindingsEnvelope,
    UsageOverflow,
    Omission,
    DuplicateLineage,
    UnknownLineage,
    Overview,
}

impl fmt::Display for ReviewResultReducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Partition => "review partition is invalid",
            Self::Schedule => "group schedule accounting is invalid",
            Self::DuplicateGroupAccounting => "group accounting is duplicated",
            Self::MissingGroupAccounting => "scheduled group accounting is missing",
            Self::UnknownGroupAccounting => "group accounting is outside the schedule",
            Self::CoveragePath => "coverage does not account for the selected paths",
            Self::DuplicateCoveragePath => "selected path coverage is duplicated",
            Self::CoverageIncompleteForCompleteGroup => "a complete group has incomplete coverage",
            Self::CandidateCount => "published finding count exceeds the product limit",
            Self::CandidateIdentifier => "candidate identity is invalid",
            Self::DuplicateCandidate => "candidate identity is duplicated",
            Self::DuplicateFinding => "published finding is duplicated",
            Self::UnknownWorkUnit => "published finding targets an unknown work unit",
            Self::CandidateTarget => "published finding targets a path outside its work unit",
            Self::CandidateAnchor => "published finding targets an unissued work-unit anchor",
            Self::FindingsEnvelope => "projected findings envelope is invalid",
            Self::UsageOverflow => "group usage cannot be aggregated",
            Self::Omission => "review omission accounting is invalid",
            Self::DuplicateLineage => "prior lineage accounting is duplicated",
            Self::UnknownLineage => "published or authorized lineage is not active and owned",
            Self::Overview => "adjudicated overview cannot be projected safely",
        })
    }
}

impl std::error::Error for ReviewResultReducerError {}

/// Validate accounting and project final verified results.
///
/// Findings retain adjudicator rank within each original work unit. Work-unit
/// envelopes retain immutable partition order. A prior lineage becomes
/// `still_present` only when a published finding carries it. It becomes
/// `fixed` only when the overall result is complete and trusted exact-evidence
/// authorization exists; all other active owned lineages remain uncertain.
///
/// # Errors
///
/// Rejects contradictory plans, schedules, coverage, usage, findings,
/// omissions, over-capacity results, or lineage authority.
pub fn reduce_review_result(
    adjudication: &AdjudicationOutcome,
    partition: &ReviewPartitionPlan,
    schedule: &GroupScheduleSnapshot,
    group_accounting: &[GroupResultAccounting],
    initial_omissions: &[AgentOmission],
    prior_review: &PriorReviewContext,
) -> Result<ReducedReviewResult, ReviewResultReducerError> {
    partition
        .validate_replay()
        .map_err(|_| ReviewResultReducerError::Partition)?;
    validate_schedule(schedule)?;
    let accounts = validate_group_accounting(schedule, group_accounting)?;
    let selected = selected_paths(partition);
    let coverage = reduce_coverage(partition, schedule, &accounts, &selected)?;
    let usage = reduce_usage(group_accounting)?;
    let mut omissions = validate_omissions(initial_omissions)?;
    omissions.extend(schedule_omissions(schedule));
    omissions.sort_by(|left, right| {
        left.subject_id
            .cmp(&right.subject_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    omissions.dedup_by(|left, right| left == right);

    let schedule_incomplete = schedule
        .records
        .iter()
        .any(|record| !matches!(record.status, GroupScheduleStatus::Complete));
    let coverage_incomplete = accounts
        .values()
        .any(|account| !account.coverage.is_complete());
    let partial = schedule.partial
        || schedule_incomplete
        || !partition.coverage.complete
        || coverage_incomplete
        || !omissions.is_empty();

    let active_lineages = active_owned_lineages(prior_review)?;
    let fixed_authorizations = fixed_lineage_authorizations(&accounts, prior_review)?;
    let findings = project_findings(adjudication, partition, &active_lineages)?;
    let dispositions = project_lineages(
        adjudication,
        &active_lineages,
        &fixed_authorizations,
        !partial,
    )?;
    let overview = project_overview(adjudication, partial, &findings, &coverage)?;
    let summary = overview.summary.clone();
    let outcome = if partial {
        revoot_core::ReviewOutcome::Partial {
            findings,
            summary,
            omissions,
            usage,
        }
    } else if findings.is_empty() {
        revoot_core::ReviewOutcome::NoFindings {
            summary,
            omissions,
            usage,
        }
    } else {
        revoot_core::ReviewOutcome::Complete {
            findings,
            summary,
            usage,
        }
    };
    Ok(ReducedReviewResult {
        outcome,
        overview,
        coverage,
        prior_finding_dispositions: dispositions,
    })
}

fn validate_schedule(schedule: &GroupScheduleSnapshot) -> Result<(), ReviewResultReducerError> {
    if schedule.max_parallel_groups == 0 || schedule.max_parallel_groups > 8 {
        return Err(ReviewResultReducerError::Schedule);
    }
    let mut ids = BTreeSet::new();
    let mut positions = BTreeSet::new();
    let mut counts = [0_u32; 6];
    for record in &schedule.records {
        if record.priority_position == 0
            || !ids.insert(record.group_id.clone())
            || !positions.insert(record.priority_position)
        {
            return Err(ReviewResultReducerError::Schedule);
        }
        let index = match record.status {
            GroupScheduleStatus::Queued => 0,
            GroupScheduleStatus::Running => 1,
            GroupScheduleStatus::Complete => 2,
            GroupScheduleStatus::Partial(_) => 3,
            GroupScheduleStatus::Failed(_) => 4,
            GroupScheduleStatus::CancelledBeforeDispatch
            | GroupScheduleStatus::CancelledWhileRunning => 5,
        };
        counts[index] = counts[index]
            .checked_add(1)
            .ok_or(ReviewResultReducerError::Schedule)?;
    }
    if counts
        != [
            schedule.queued_groups,
            schedule.running_groups,
            schedule.complete_groups,
            schedule.partial_groups,
            schedule.failed_groups,
            schedule.cancelled_groups,
        ]
        || schedule.partial
            != schedule.records.iter().any(|record| {
                !matches!(
                    record.status,
                    GroupScheduleStatus::Queued
                        | GroupScheduleStatus::Running
                        | GroupScheduleStatus::Complete
                )
            })
    {
        return Err(ReviewResultReducerError::Schedule);
    }
    let expected_positions = (1..=u32::try_from(schedule.records.len())
        .map_err(|_| ReviewResultReducerError::Schedule)?)
        .collect::<BTreeSet<_>>();
    if positions != expected_positions {
        return Err(ReviewResultReducerError::Schedule);
    }
    Ok(())
}

fn validate_group_accounting<'a>(
    schedule: &GroupScheduleSnapshot,
    accounting: &'a [GroupResultAccounting],
) -> Result<BTreeMap<ReviewGroupId, &'a GroupResultAccounting>, ReviewResultReducerError> {
    let scheduled = schedule
        .records
        .iter()
        .map(|record| record.group_id.clone())
        .collect::<BTreeSet<_>>();
    let mut accounts = BTreeMap::new();
    for account in accounting {
        if !scheduled.contains(&account.group_id) {
            return Err(ReviewResultReducerError::UnknownGroupAccounting);
        }
        if accounts.insert(account.group_id.clone(), account).is_some() {
            return Err(ReviewResultReducerError::DuplicateGroupAccounting);
        }
    }
    if accounts.len() != scheduled.len() {
        return Err(ReviewResultReducerError::MissingGroupAccounting);
    }
    for record in &schedule.records {
        if matches!(record.status, GroupScheduleStatus::Complete)
            && !accounts
                .get(&record.group_id)
                .expect("all scheduled groups accounted")
                .coverage
                .is_complete()
        {
            return Err(ReviewResultReducerError::CoverageIncompleteForCompleteGroup);
        }
    }
    Ok(accounts)
}

fn selected_paths(partition: &ReviewPartitionPlan) -> BTreeMap<RepositoryPath, ReviewValueTier> {
    partition
        .work_units
        .iter()
        .flat_map(|unit| unit.files.iter())
        .map(|file| (file.path.new_path.clone(), file.review_value.tier))
        .collect()
}

fn reduce_coverage(
    partition: &ReviewPartitionPlan,
    schedule: &GroupScheduleSnapshot,
    accounts: &BTreeMap<ReviewGroupId, &GroupResultAccounting>,
    selected: &BTreeMap<RepositoryPath, ReviewValueTier>,
) -> Result<ReviewCoverage, ReviewResultReducerError> {
    let mut result = ReviewCoverage {
        policy_version: GroupCoverageLedger::POLICY_VERSION,
        high_risk_files: 0,
        standard_risk_files: 0,
        low_risk_files: 0,
        fully_read_files: 0,
        sampled_files: 0,
        manifest_only_files: 0,
        delivered_high_risk_hunks: 0,
        required_high_risk_hunks: 0,
        explicit_deferrals: 0,
        failed_groups: schedule
            .failed_groups
            .checked_add(schedule.cancelled_groups)
            .ok_or(ReviewResultReducerError::CoveragePath)?,
    };
    for tier in selected.values() {
        match tier {
            ReviewValueTier::High => increment(&mut result.high_risk_files)?,
            ReviewValueTier::Standard => increment(&mut result.standard_risk_files)?,
            ReviewValueTier::Low => increment(&mut result.low_risk_files)?,
        }
    }
    let mut accounted_paths = BTreeSet::new();
    for account in accounts.values() {
        if account.coverage.policy_version != GroupCoverageLedger::POLICY_VERSION {
            return Err(ReviewResultReducerError::CoveragePath);
        }
        for (path, file) in &account.coverage.files {
            if selected.get(path) != Some(&file.tier) {
                return Err(ReviewResultReducerError::CoveragePath);
            }
            if !accounted_paths.insert(path.clone()) {
                return Err(ReviewResultReducerError::DuplicateCoveragePath);
            }
            let fully_read = file.metadata_only || file.hunks.iter().all(hunk_fully_delivered);
            let sampled = file
                .hunks
                .iter()
                .any(|hunk| !hunk.delivered_pages.is_empty());
            if fully_read {
                increment(&mut result.fully_read_files)?;
            } else if sampled {
                increment(&mut result.sampled_files)?;
            } else {
                increment(&mut result.manifest_only_files)?;
            }
            result.explicit_deferrals = result
                .explicit_deferrals
                .checked_add(
                    u32::try_from(file.unread_dispositions.len())
                        .map_err(|_| ReviewResultReducerError::CoveragePath)?,
                )
                .ok_or(ReviewResultReducerError::CoveragePath)?;
            if file.tier == ReviewValueTier::High {
                result.required_high_risk_hunks = result
                    .required_high_risk_hunks
                    .checked_add(
                        u32::try_from(file.hunks.len())
                            .map_err(|_| ReviewResultReducerError::CoveragePath)?,
                    )
                    .ok_or(ReviewResultReducerError::CoveragePath)?;
                result.delivered_high_risk_hunks = result
                    .delivered_high_risk_hunks
                    .checked_add(
                        u32::try_from(
                            file.hunks
                                .iter()
                                .filter(|hunk| hunk_fully_delivered(hunk))
                                .count(),
                        )
                        .map_err(|_| ReviewResultReducerError::CoveragePath)?,
                    )
                    .ok_or(ReviewResultReducerError::CoveragePath)?;
            }
        }
    }
    if accounted_paths != selected.keys().cloned().collect() {
        return Err(ReviewResultReducerError::CoveragePath);
    }
    let counted_files = result
        .fully_read_files
        .checked_add(result.sampled_files)
        .and_then(|value| value.checked_add(result.manifest_only_files))
        .ok_or(ReviewResultReducerError::CoveragePath)?;
    if counted_files != partition.coverage.included_files {
        return Err(ReviewResultReducerError::CoveragePath);
    }
    Ok(result)
}

fn hunk_fully_delivered(hunk: &revoot_core::HunkCoverage) -> bool {
    hunk.total_pages > 0
        && hunk.delivered_pages.len() == usize::try_from(hunk.total_pages).unwrap_or(usize::MAX)
        && (1..=hunk.total_pages).all(|page| hunk.delivered_pages.contains(&page))
}

fn increment(value: &mut u32) -> Result<(), ReviewResultReducerError> {
    *value = value
        .checked_add(1)
        .ok_or(ReviewResultReducerError::CoveragePath)?;
    Ok(())
}

fn reduce_usage(
    accounting: &[GroupResultAccounting],
) -> Result<AgentBudgetUsage, ReviewResultReducerError> {
    let mut total = AgentBudgetUsage::default();
    for account in accounting {
        total.turns = add_u32(total.turns, account.usage.turns)?;
        total.model_requests = add_u32(total.model_requests, account.usage.model_requests)?;
        total.tool_calls = add_u32(total.tool_calls, account.usage.tool_calls)?;
        total.repository_files = add_u64(total.repository_files, account.usage.repository_files)?;
        total.repository_bytes = add_u64(total.repository_bytes, account.usage.repository_bytes)?;
        total.input_tokens = add_u64(total.input_tokens, account.usage.input_tokens)?;
        total.output_tokens = add_u64(total.output_tokens, account.usage.output_tokens)?;
        total.cost_microusd = add_u64(total.cost_microusd, account.usage.cost_microusd)?;
        total.candidate_findings =
            add_u32(total.candidate_findings, account.usage.candidate_findings)?;
        total.elapsed_millis = total.elapsed_millis.max(account.usage.elapsed_millis);
    }
    Ok(total)
}

fn add_u32(left: u32, right: u32) -> Result<u32, ReviewResultReducerError> {
    left.checked_add(right)
        .ok_or(ReviewResultReducerError::UsageOverflow)
}

fn add_u64(left: u64, right: u64) -> Result<u64, ReviewResultReducerError> {
    left.checked_add(right)
        .ok_or(ReviewResultReducerError::UsageOverflow)
}

fn validate_omissions(
    omissions: &[AgentOmission],
) -> Result<Vec<AgentOmission>, ReviewResultReducerError> {
    let mut seen = BTreeSet::new();
    for omission in omissions {
        if !valid_identifier(&omission.subject_id)
            || !seen.insert((omission.subject_id.clone(), omission.reason))
        {
            return Err(ReviewResultReducerError::Omission);
        }
    }
    Ok(omissions.to_vec())
}

fn schedule_omissions(schedule: &GroupScheduleSnapshot) -> Vec<AgentOmission> {
    schedule
        .records
        .iter()
        .filter_map(|record| {
            let reason = match record.status {
                GroupScheduleStatus::Partial(reason) => match reason {
                    GroupPartialReason::BudgetExhausted | GroupPartialReason::DeadlineExceeded => {
                        AgentOmissionReason::BudgetExhausted
                    }
                    GroupPartialReason::ProviderUnavailable
                    | GroupPartialReason::VerificationFailed => {
                        AgentOmissionReason::ProviderLimited
                    }
                    GroupPartialReason::CoverageIncomplete | GroupPartialReason::ToolError => {
                        AgentOmissionReason::CoverageIncomplete
                    }
                },
                GroupScheduleStatus::Failed(reason) => match reason {
                    GroupFailureReason::ProviderFailed => AgentOmissionReason::ProviderLimited,
                    GroupFailureReason::InvalidOutput
                    | GroupFailureReason::PreparationFailed
                    | GroupFailureReason::RuntimeFailure => AgentOmissionReason::CoverageIncomplete,
                },
                GroupScheduleStatus::CancelledBeforeDispatch
                | GroupScheduleStatus::CancelledWhileRunning => {
                    AgentOmissionReason::BudgetExhausted
                }
                GroupScheduleStatus::Queued | GroupScheduleStatus::Running => {
                    AgentOmissionReason::CoverageIncomplete
                }
                GroupScheduleStatus::Complete => return None,
            };
            Some(AgentOmission {
                subject_id: record.group_id.as_str().to_owned(),
                reason,
            })
        })
        .collect()
}

fn active_owned_lineages(
    prior_review: &PriorReviewContext,
) -> Result<BTreeSet<Sha256Digest>, ReviewResultReducerError> {
    let mut lineages = BTreeSet::new();
    for discussion in prior_review
        .discussions()
        .iter()
        .filter(|discussion| discussion.source == PriorReviewSource::Revoot)
        .filter(|discussion| discussion.state != PriorReviewState::Resolved)
    {
        if let Some(lineage) = &discussion.lineage
            && !lineages.insert(lineage.lineage_sha256.clone())
        {
            return Err(ReviewResultReducerError::DuplicateLineage);
        }
    }
    Ok(lineages)
}

fn fixed_lineage_authorizations(
    accounts: &BTreeMap<ReviewGroupId, &GroupResultAccounting>,
    prior_review: &PriorReviewContext,
) -> Result<BTreeSet<Sha256Digest>, ReviewResultReducerError> {
    let owned = prior_review.owned_lineages();
    let mut seen = BTreeSet::new();
    let mut fixed = BTreeSet::new();
    for account in accounts.values() {
        for decision in &account.lineage {
            if !owned.contains(&decision.lineage_id) {
                return Err(ReviewResultReducerError::UnknownLineage);
            }
            if !seen.insert(decision.lineage_id.clone()) {
                return Err(ReviewResultReducerError::DuplicateLineage);
            }
            if matches!(
                decision.action,
                AuthorizedLineageAction::ResolveFixed { .. }
            ) {
                fixed.insert(decision.lineage_id.clone());
            }
        }
    }
    Ok(fixed)
}

fn project_findings(
    adjudication: &AdjudicationOutcome,
    partition: &ReviewPartitionPlan,
    active_lineages: &BTreeSet<Sha256Digest>,
) -> Result<Vec<FindingsEnvelope>, ReviewResultReducerError> {
    if adjudication.publish.len() > MAX_PUBLISHED_FINDINGS {
        return Err(ReviewResultReducerError::CandidateCount);
    }
    let work_units = partition
        .work_units
        .iter()
        .map(|unit| (unit.id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();
    let mut candidate_ids = BTreeSet::new();
    let mut finding_keys = BTreeSet::new();
    let mut published_lineages = BTreeSet::new();
    let mut grouped = BTreeMap::<&str, Vec<revoot_core::Finding>>::new();
    for candidate in &adjudication.publish {
        if !valid_identifier(&candidate.candidate_id)
            || !candidate_ids.insert(candidate.candidate_id.as_str())
        {
            return Err(if valid_identifier(&candidate.candidate_id) {
                ReviewResultReducerError::DuplicateCandidate
            } else {
                ReviewResultReducerError::CandidateIdentifier
            });
        }
        let unit = work_units
            .get(candidate.work_unit_id.as_str())
            .ok_or(ReviewResultReducerError::UnknownWorkUnit)?;
        let file = unit
            .files
            .iter()
            .find(|file| {
                file.path.new_path == candidate.target_path
                    || file.path.old_path == candidate.target_path
            })
            .ok_or(ReviewResultReducerError::CandidateTarget)?;
        if !file
            .anchor_ids
            .iter()
            .any(|anchor| anchor.as_str() == candidate.finding.anchor_id)
        {
            return Err(ReviewResultReducerError::CandidateAnchor);
        }
        let finding_key = (
            candidate.work_unit_id.as_str(),
            candidate.finding.anchor_id.as_str(),
            candidate.finding.category,
            candidate.finding.title.as_str(),
        );
        if !finding_keys.insert(finding_key) {
            return Err(ReviewResultReducerError::DuplicateFinding);
        }
        if let Some(lineage) = &candidate.finding.lineage_id {
            if !active_lineages.contains(lineage) {
                return Err(ReviewResultReducerError::UnknownLineage);
            }
            if !published_lineages.insert(lineage.clone()) {
                return Err(ReviewResultReducerError::DuplicateLineage);
            }
        }
        grouped
            .entry(unit.id.as_str())
            .or_default()
            .push(candidate.finding.clone());
    }
    for suppression in &adjudication.suppressed {
        if !valid_identifier(&suppression.candidate_id) {
            return Err(ReviewResultReducerError::CandidateIdentifier);
        }
        if !candidate_ids.insert(suppression.candidate_id.as_str()) {
            return Err(ReviewResultReducerError::DuplicateCandidate);
        }
    }
    let summary = bounded_line(&adjudication.overview.summary, MAX_OVERVIEW_SUMMARY_BYTES)
        .ok_or(ReviewResultReducerError::Overview)?;
    let mut envelopes = Vec::new();
    for unit in &partition.work_units {
        let Some(findings) = grouped.remove(unit.id.as_str()) else {
            continue;
        };
        let envelope = FindingsEnvelope {
            schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
            work_unit_id: unit.id.as_str().to_owned(),
            findings,
            summary: summary.clone(),
        };
        envelope
            .validate()
            .map_err(|_| ReviewResultReducerError::FindingsEnvelope)?;
        envelopes.push(envelope);
    }
    Ok(envelopes)
}

fn project_lineages(
    adjudication: &AdjudicationOutcome,
    active: &BTreeSet<Sha256Digest>,
    fixed: &BTreeSet<Sha256Digest>,
    complete: bool,
) -> Result<Vec<PriorFindingDisposition>, ReviewResultReducerError> {
    let published = adjudication
        .publish
        .iter()
        .filter_map(|candidate| candidate.finding.lineage_id.clone())
        .collect::<BTreeSet<_>>();
    if !published.is_subset(active) || !fixed.is_subset(active) {
        return Err(ReviewResultReducerError::UnknownLineage);
    }
    Ok(active
        .iter()
        .map(|lineage_id| {
            let (disposition, evidence) = if published.contains(lineage_id) {
                (
                    PriorFindingDispositionKind::StillPresent,
                    "a published verified finding retained this lineage",
                )
            } else if complete && fixed.contains(lineage_id) {
                (
                    PriorFindingDispositionKind::Fixed,
                    "trusted exact-location or deletion-hunk evidence authorized resolution",
                )
            } else {
                (
                    PriorFindingDispositionKind::Uncertain,
                    "resolution was not authorized by complete exact evidence",
                )
            };
            PriorFindingDisposition {
                lineage_id: lineage_id.clone(),
                disposition,
                evidence: evidence.to_owned(),
            }
        })
        .collect())
}

fn project_overview(
    adjudication: &AdjudicationOutcome,
    partial: bool,
    findings: &[FindingsEnvelope],
    coverage: &ReviewCoverage,
) -> Result<ReviewOverview, ReviewResultReducerError> {
    let summary = bounded_line(&adjudication.overview.summary, MAX_OVERVIEW_SUMMARY_BYTES)
        .ok_or(ReviewResultReducerError::Overview)?;
    let maximum_severity = findings
        .iter()
        .flat_map(|envelope| envelope.findings.iter())
        .map(|finding| finding.severity)
        .min();
    let mut risk = match maximum_severity {
        Some(revoot_core::Severity::Critical) => RiskLevel::Critical,
        Some(revoot_core::Severity::High) => RiskLevel::High,
        Some(revoot_core::Severity::Medium) => RiskLevel::Moderate,
        Some(revoot_core::Severity::Low | revoot_core::Severity::Info) | None => RiskLevel::Low,
    };
    if partial && risk < RiskLevel::Moderate {
        risk = RiskLevel::Moderate;
    }
    let basis = if partial {
        "The review is partial, so uninspected work may contain additional issues."
    } else if findings.is_empty() {
        "The completed review produced no verified findings."
    } else {
        "Overall risk reflects the highest-severity published verified finding."
    }
    .to_owned();
    let mut assumptions = Vec::new();
    let mut seen = BTreeSet::new();
    if partial {
        let total_selected = coverage
            .fully_read_files
            .checked_add(coverage.sampled_files)
            .and_then(|value| value.checked_add(coverage.manifest_only_files))
            .ok_or(ReviewResultReducerError::Overview)?;
        let coverage_gap = format!(
            "Read {} of {total_selected} selected files in full ({} sampled, {} manifest-only); delivered {} of {} required high-risk hunks; {} review group(s) failed; {} hunks explicitly deferred.",
            coverage.fully_read_files,
            coverage.sampled_files,
            coverage.manifest_only_files,
            coverage.delivered_high_risk_hunks,
            coverage.required_high_risk_hunks,
            coverage.failed_groups,
            coverage.explicit_deferrals,
        );
        let coverage_gap = bounded_line(&coverage_gap, MAX_OVERVIEW_ITEM_BYTES)
            .ok_or(ReviewResultReducerError::Overview)?;
        seen.insert(coverage_gap.to_ascii_lowercase());
        assumptions.push(coverage_gap);
        let lineage_gap =
            "No prior lineage was auto-resolved without complete exact evidence.".to_owned();
        seen.insert(lineage_gap.to_ascii_lowercase());
        assumptions.push(lineage_gap);
    }
    for assumption in &adjudication.overview.assumptions {
        if assumptions.len() == MAX_OVERVIEW_ITEMS {
            break;
        }
        let Some(assumption) = bounded_line(assumption, MAX_OVERVIEW_ITEM_BYTES) else {
            return Err(ReviewResultReducerError::Overview);
        };
        if seen.insert(assumption.to_ascii_lowercase()) {
            assumptions.push(assumption);
        }
    }
    let risks = if risk == RiskLevel::Low {
        Vec::new()
    } else {
        vec![ReviewRisk {
            area: "Published review result".to_owned(),
            risk,
            basis: basis.clone(),
        }]
    };
    let overview = ReviewOverview {
        summary,
        overall_risk: risk,
        overall_basis: basis,
        risks,
        assumptions_and_gaps: assumptions,
        manual_validations: if partial {
            vec!["Inspect deferred or failed review groups before merging.".to_owned()]
        } else {
            Vec::new()
        },
    };
    overview
        .validate()
        .map_err(|_| ReviewResultReducerError::Overview)?;
    Ok(overview)
}

fn bounded_line(value: &str, maximum_bytes: usize) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    if normalized.len() <= maximum_bytes {
        return Some(normalized);
    }
    let mut end = maximum_bytes;
    while !normalized.is_char_boundary(end) {
        end = end.checked_sub(1)?;
    }
    let shortened = normalized[..end].trim_end().to_owned();
    (!shortened.is_empty()).then_some(shortened)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use revoot_core::{
        AdjudicatedOverview, ChangedPath, FileChangeKind, Finding, FindingCategory,
        FindingLineageMarker, GitSha, GroupCoverageLedger, HunkCoverage, LocalSnapshotIdentity,
        PartitionLimits, PriorReviewDiscussion, ReviewFileClass, ReviewFileInput, ReviewObject,
        ReviewObjectRole, ReviewSelectionPolicy, ReviewValue, ReviewValueReason, Severity,
        build_partition_plan,
    };
    use serde_json::json;

    use super::*;
    use crate::group_scheduler::GroupScheduleRecord;

    fn anchor(index: usize) -> revoot_core::AnchorId {
        serde_json::from_value(json!(format!("ga1_{index:064x}"))).expect("anchor")
    }

    fn partition(count: usize) -> ReviewPartitionPlan {
        let files = (0..count)
            .map(|index| {
                let path = RepositoryPath::try_from(format!("src/file-{index}.rs")).expect("path");
                ReviewFileInput {
                    path: ChangedPath {
                        old_path: path.clone(),
                        new_path: path,
                        kind: FileChangeKind::Modified,
                    },
                    class: ReviewFileClass::Text,
                    review_value: ReviewValue {
                        tier: if index == 0 {
                            ReviewValueTier::High
                        } else {
                            ReviewValueTier::Standard
                        },
                        score: if index == 0 { 220 } else { 100 },
                        reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                    },
                    objects: vec![ReviewObject {
                        role: ReviewObjectRole::ExactDiff,
                        content_sha256: Sha256Digest::of_bytes(format!("diff-{index}").as_bytes()),
                        size_bytes: 100,
                    }],
                    anchor_ids: vec![anchor(index)],
                }
            })
            .collect::<Vec<_>>();
        let sha = |marker: char| GitSha::try_from(marker.to_string().repeat(40)).expect("sha");
        build_partition_plan(
            revoot_core::ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
                repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
                base_sha: sha('a'),
                head_sha: sha('b'),
                working_tree_sha256: Sha256Digest::of_bytes(b"working-tree"),
                exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
            }),
            &ReviewSelectionPolicy {
                version: "policy-v1".to_owned(),
                included_paths: BTreeSet::new(),
                included_prefixes: Vec::new(),
                included_suffixes: Vec::new(),
                excluded_paths: BTreeSet::new(),
                excluded_prefixes: Vec::new(),
                excluded_suffixes: Vec::new(),
                excluded_basename_prefixes: Vec::new(),
                include_generated: false,
                max_file_bytes: 1_000,
            },
            PartitionLimits {
                max_files: 100,
                max_total_bytes: 1_000_000,
                max_work_units: 100,
                max_files_per_work_unit: 1,
                max_bytes_per_work_unit: 512 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
            files,
        )
        .expect("partition")
    }

    fn group_id(index: usize) -> ReviewGroupId {
        serde_json::from_value(json!(format!("rg-{index}"))).expect("group id")
    }

    fn schedule(count: usize, partial_index: Option<usize>) -> GroupScheduleSnapshot {
        let records = (0..count)
            .map(|index| GroupScheduleRecord {
                group_id: group_id(index),
                priority_position: u32::try_from(index + 1).expect("position"),
                status: if partial_index == Some(index) {
                    GroupScheduleStatus::Partial(GroupPartialReason::BudgetExhausted)
                } else {
                    GroupScheduleStatus::Complete
                },
            })
            .collect::<Vec<_>>();
        GroupScheduleSnapshot {
            plan_sha256: Sha256Digest::of_bytes(b"group-plan"),
            max_parallel_groups: 4,
            cancellation_requested: false,
            queued_groups: 0,
            running_groups: 0,
            complete_groups: u32::try_from(count - usize::from(partial_index.is_some()))
                .expect("count"),
            partial_groups: u32::from(partial_index.is_some()),
            failed_groups: 0,
            cancelled_groups: 0,
            partial: partial_index.is_some(),
            records,
        }
    }

    fn accounting(
        partition: &ReviewPartitionPlan,
        partial_index: Option<usize>,
    ) -> Vec<GroupResultAccounting> {
        partition
            .work_units
            .iter()
            .enumerate()
            .map(|(index, unit)| {
                let file = &unit.files[0];
                let delivered_pages = if partial_index == Some(index) {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([1])
                };
                let ledger = revoot_core::FileCoverageLedger {
                    path: file.path.new_path.clone(),
                    tier: file.review_value.tier,
                    manifested: true,
                    metadata_only: false,
                    hunks: vec![HunkCoverage {
                        hunk_id: format!("hunk-{index}"),
                        total_pages: 1,
                        delivered_pages,
                        hazardous: false,
                    }],
                    unread_dispositions: BTreeMap::new(),
                };
                GroupResultAccounting {
                    group_id: group_id(index),
                    usage: AgentBudgetUsage {
                        model_requests: 1,
                        input_tokens: 100,
                        output_tokens: 10,
                        elapsed_millis: 20 + u64::try_from(index).expect("index"),
                        ..AgentBudgetUsage::default()
                    },
                    coverage: GroupCoverageLedger::new([ledger]).expect("coverage"),
                    lineage: Vec::new(),
                }
            })
            .collect()
    }

    fn candidate(
        partition: &ReviewPartitionPlan,
        unit_index: usize,
        id: &str,
    ) -> revoot_core::VerifiedCandidate {
        let unit = &partition.work_units[unit_index];
        let file = &unit.files[0];
        revoot_core::VerifiedCandidate {
            candidate_id: id.to_owned(),
            work_unit_id: unit.id.as_str().to_owned(),
            target_path: file.path.new_path.clone(),
            finding: Finding {
                anchor_id: file.anchor_ids[0].as_str().to_owned(),
                severity: Severity::High,
                confidence_percent: 95,
                category: FindingCategory::Correctness,
                title: format!("Finding {id}"),
                explanation: "A verified explanation.".to_owned(),
                evidence: "Delivered exact evidence.".to_owned(),
                lineage_id: None,
                suggested_replacement: None,
            },
            evidence_references: vec![format!("evidence-{id}")],
        }
    }

    fn adjudication(publish: Vec<revoot_core::VerifiedCandidate>) -> AdjudicationOutcome {
        AdjudicationOutcome {
            publish,
            suppressed: Vec::new(),
            overview: AdjudicatedOverview {
                summary: "Verified findings were globally ranked.".to_owned(),
                assumptions: Vec::new(),
            },
        }
    }

    #[test]
    fn complete_multi_work_unit_result_groups_findings_and_usage() {
        let plan = partition(2);
        let result = reduce_review_result(
            &adjudication(vec![
                candidate(&plan, 1, "candidate-2"),
                candidate(&plan, 0, "candidate-1"),
            ]),
            &plan,
            &schedule(2, None),
            &accounting(&plan, None),
            &[],
            &PriorReviewContext::default(),
        )
        .expect("reduced");
        let revoot_core::ReviewOutcome::Complete {
            findings, usage, ..
        } = result.outcome
        else {
            panic!("complete outcome");
        };
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].work_unit_id, plan.work_units[0].id.as_str());
        assert_eq!(findings[1].work_unit_id, plan.work_units[1].id.as_str());
        assert_eq!(usage.model_requests, 2);
        assert_eq!(usage.elapsed_millis, 21);
        assert_eq!(result.coverage.fully_read_files, 2);
    }

    #[test]
    fn complete_empty_result_is_no_findings() {
        let plan = partition(1);
        let result = reduce_review_result(
            &adjudication(Vec::new()),
            &plan,
            &schedule(1, None),
            &accounting(&plan, None),
            &[],
            &PriorReviewContext::default(),
        )
        .expect("reduced");
        assert!(matches!(
            result.outcome,
            revoot_core::ReviewOutcome::NoFindings { .. }
        ));
        assert_eq!(result.overview.overall_risk, RiskLevel::Low);
    }

    #[test]
    fn partial_result_retains_verified_findings_and_never_fixes_lineage() {
        let plan = partition(1);
        let lineage_id = Sha256Digest::of_bytes(b"lineage");
        let marker = FindingLineageMarker::new(
            lineage_id.clone(),
            GitSha::try_from("c".repeat(40)).expect("sha"),
            Sha256Digest::of_bytes(b"evidence"),
        );
        let prior = PriorReviewContext::try_new(vec![PriorReviewDiscussion {
            thread_id: "thread-1".to_owned(),
            comment_id: "comment-1".to_owned(),
            source: PriorReviewSource::Revoot,
            state: PriorReviewState::Open,
            path: Some("src/file-0.rs".to_owned()),
            line: Some(1),
            original_line: Some(1),
            body: "Prior finding".to_owned(),
            replies: Vec::new(),
            resolution: None,
            lineage: Some(marker),
        }])
        .expect("prior review");
        let mut accounts = accounting(&plan, Some(0));
        accounts[0]
            .lineage
            .push(revoot_core::AuthorizedLineageDecision {
                lineage_id: lineage_id.clone(),
                action: AuthorizedLineageAction::ResolveFixed {
                    evidence: revoot_core::LineageResolutionEvidence::DeletionHunk {
                        hunk_evidence_id: "deletion-1".to_owned(),
                    },
                },
            });
        let result = reduce_review_result(
            &adjudication(vec![candidate(&plan, 0, "candidate-1")]),
            &plan,
            &schedule(1, Some(0)),
            &accounts,
            &[],
            &prior,
        )
        .expect("partial reduction");
        assert!(matches!(
            result.outcome,
            revoot_core::ReviewOutcome::Partial { .. }
        ));
        assert_eq!(
            result.prior_finding_dispositions[0].disposition,
            PriorFindingDispositionKind::Uncertain
        );
        assert_eq!(result.overview.overall_risk, RiskLevel::High);
    }

    #[test]
    fn published_matching_lineage_is_the_only_still_present_authority() {
        let plan = partition(1);
        let lineage_id = Sha256Digest::of_bytes(b"lineage");
        let marker = FindingLineageMarker::new(
            lineage_id.clone(),
            GitSha::try_from("c".repeat(40)).expect("sha"),
            Sha256Digest::of_bytes(b"evidence"),
        );
        let prior = PriorReviewContext::try_new(vec![PriorReviewDiscussion {
            thread_id: "thread-1".to_owned(),
            comment_id: "comment-1".to_owned(),
            source: PriorReviewSource::Revoot,
            state: PriorReviewState::Open,
            path: None,
            line: None,
            original_line: None,
            body: "Prior finding".to_owned(),
            replies: Vec::new(),
            resolution: None,
            lineage: Some(marker),
        }])
        .expect("prior review");
        let mut finding = candidate(&plan, 0, "candidate-1");
        finding.finding.lineage_id = Some(lineage_id);
        let result = reduce_review_result(
            &adjudication(vec![finding]),
            &plan,
            &schedule(1, None),
            &accounting(&plan, None),
            &[],
            &prior,
        )
        .expect("reduced");
        assert_eq!(
            result.prior_finding_dispositions[0].disposition,
            PriorFindingDispositionKind::StillPresent
        );
    }

    #[test]
    fn complete_exact_authorization_can_mark_unpublished_lineage_fixed() {
        let plan = partition(1);
        let lineage_id = Sha256Digest::of_bytes(b"lineage");
        let marker = FindingLineageMarker::new(
            lineage_id.clone(),
            GitSha::try_from("c".repeat(40)).expect("sha"),
            Sha256Digest::of_bytes(b"evidence"),
        );
        let prior = PriorReviewContext::try_new(vec![PriorReviewDiscussion {
            thread_id: "thread-1".to_owned(),
            comment_id: "comment-1".to_owned(),
            source: PriorReviewSource::Revoot,
            state: PriorReviewState::Open,
            path: Some("src/file-0.rs".to_owned()),
            line: Some(1),
            original_line: Some(1),
            body: "Prior finding".to_owned(),
            replies: Vec::new(),
            resolution: None,
            lineage: Some(marker),
        }])
        .expect("prior review");
        let mut accounts = accounting(&plan, None);
        accounts[0]
            .lineage
            .push(revoot_core::AuthorizedLineageDecision {
                lineage_id,
                action: AuthorizedLineageAction::ResolveFixed {
                    evidence: revoot_core::LineageResolutionEvidence::DeletionHunk {
                        hunk_evidence_id: "deletion-1".to_owned(),
                    },
                },
            });
        let result = reduce_review_result(
            &adjudication(Vec::new()),
            &plan,
            &schedule(1, None),
            &accounts,
            &[],
            &prior,
        )
        .expect("reduced");
        assert_eq!(
            result.prior_finding_dispositions[0].disposition,
            PriorFindingDispositionKind::Fixed
        );
    }

    #[test]
    fn duplicate_and_max_finding_gates_fail_closed() {
        let plan = partition(1);
        let duplicate = candidate(&plan, 0, "candidate-1");
        let error = reduce_review_result(
            &adjudication(vec![duplicate.clone(), duplicate]),
            &plan,
            &schedule(1, None),
            &accounting(&plan, None),
            &[],
            &PriorReviewContext::default(),
        )
        .expect_err("duplicate candidate");
        assert_eq!(error, ReviewResultReducerError::DuplicateCandidate);

        let oversized = (0..=MAX_PUBLISHED_FINDINGS)
            .map(|index| candidate(&plan, 0, &format!("candidate-{index}")))
            .collect();
        let error = reduce_review_result(
            &adjudication(oversized),
            &plan,
            &schedule(1, None),
            &accounting(&plan, None),
            &[],
            &PriorReviewContext::default(),
        )
        .expect_err("finding cap");
        assert_eq!(error, ReviewResultReducerError::CandidateCount);
    }
}
