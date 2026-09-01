//! Canonical version-3 reporting for the native tool-first engine.
//!
//! The adapter consumes only trusted identities, deterministic accounting,
//! verified finding envelopes, and the bounded overview. It never accepts or
//! emits prompts, responses, source slices, diff bodies, tool payloads, or
//! temporary artifact locations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use revoot_core::{
    AgentBudgetUsage, AnchorId, AnchorPosition, AnchorTable, Finding, FindingsEnvelope,
    IssuedWorkUnitAnchors, ReviewEffort, ReviewGroupingSource, ReviewOutcome, ReviewPartitionPlan,
    ReviewReportCoverage, ReviewReportError, ReviewReportFinding, ReviewReportFindingCoordinate,
    ReviewReportFindingSide, ReviewReportLineage, ReviewReportLineageDisposition,
    ReviewReportOverview, ReviewReportPhase, ReviewReportPhaseUsage, ReviewReportPublication,
    ReviewReportSelection, ReviewReportState, ReviewReportStrategy, ReviewReportUsage,
    ReviewReportUsageTotals, ReviewReportV3, Sha256Digest, validate_rank_and_render,
};

use crate::group_scheduler::GroupScheduleStatus;
use crate::review_engine::PriorFindingDispositionKind;
use crate::review_grouper::ReviewGrouperMode;
use crate::review_overview::{ReviewOverview, RiskLevel};
use crate::tool_first_engine::ToolFirstEngineReport;

const MAX_FINDINGS: usize = 25;

/// Trusted inputs not derivable from the payload-free engine report.
pub struct ToolFirstReportInput<'a> {
    pub engine: &'a ToolFirstEngineReport,
    pub partition: &'a ReviewPartitionPlan,
    pub anchors: &'a AnchorTable,
    pub snapshot_sha256: Sha256Digest,
    pub selection: ReviewReportSelection,
    pub publication: ReviewReportPublication,
    pub effort: ReviewEffort,
    /// Exact trusted per-phase accounting. `None` is distinct from a real
    /// phase whose counters are all zero.
    pub phase_usage: Option<Vec<ReviewReportPhaseUsage>>,
}

impl fmt::Debug for ToolFirstReportInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolFirstReportInput")
            .field("partition_sha256", &self.partition.plan_sha256)
            .field("snapshot_sha256", &self.snapshot_sha256)
            .field("selection", &self.selection)
            .field("publication", &self.publication)
            .field("effort", &self.effort)
            .field(
                "phase_usage_available",
                &self.phase_usage.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}

/// Stable, payload-free adapter failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolFirstReportError {
    EngineAccounting,
    Partition,
    Snapshot,
    Selection,
    Findings,
    Overview,
    MissingPhaseUsage,
    PhaseUsage,
    PhaseUsageMismatch,
    Report(ReviewReportError),
    Serialization,
}

impl fmt::Display for ToolFirstReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EngineAccounting => "tool-first engine accounting is inconsistent",
            Self::Partition => "review partition cannot be replayed",
            Self::Snapshot => "trusted snapshot identity does not match the partition",
            Self::Selection => "trusted selection accounting does not match the partition",
            Self::Findings => "verified findings cannot be projected into report identities",
            Self::Overview => "bounded review overview cannot be rendered",
            Self::MissingPhaseUsage => {
                "tool-first engine report has only aggregate usage; five trusted phase records are required"
            }
            Self::PhaseUsage => "trusted phase usage is incomplete, duplicated, or overflowed",
            Self::PhaseUsageMismatch => {
                "trusted phase usage does not reconcile to tool-first aggregate usage"
            }
            Self::Report(_) => "canonical review report validation failed",
            Self::Serialization => "trusted snapshot identity cannot be encoded",
        })
    }
}

impl std::error::Error for ToolFirstReportError {}

/// Construct and revalidate a canonical `revoot.review-report/v3`.
///
/// # Errors
///
/// Fails closed when trusted identities or accounting disagree, when phase
/// usage is unavailable, or when the core version-3 contract rejects the
/// projection.
pub fn build_tool_first_report(
    input: ToolFirstReportInput<'_>,
) -> Result<ReviewReportV3, ToolFirstReportError> {
    input
        .partition
        .validate_replay()
        .map_err(|_| ToolFirstReportError::Partition)?;
    validate_engine(input.engine, input.partition)?;
    validate_snapshot(&input)?;
    let expected_selection = selection_from_partition(input.partition);
    if input.selection != expected_selection {
        return Err(ToolFirstReportError::Selection);
    }
    let issued = issued_anchors(input.partition);
    let findings = project_findings(
        outcome_findings(&input.engine.result.outcome),
        &issued,
        input.anchors,
    )?;
    let overview_text = render_overview(&input.engine.result.overview)?;
    let overview = ReviewReportOverview {
        content_sha256: Sha256Digest::of_bytes(overview_text.as_bytes()),
        text: overview_text,
    };
    let lineage = input
        .engine
        .result
        .prior_finding_dispositions
        .iter()
        .map(|disposition| ReviewReportLineage {
            lineage_id: disposition.lineage_id.clone(),
            disposition: match disposition.disposition {
                PriorFindingDispositionKind::StillPresent => {
                    ReviewReportLineageDisposition::StillPresent
                }
                PriorFindingDispositionKind::Fixed => ReviewReportLineageDisposition::Fixed,
                PriorFindingDispositionKind::Uncertain => ReviewReportLineageDisposition::Uncertain,
            },
            evidence_sha256: Sha256Digest::of_bytes(disposition.evidence.as_bytes()),
        })
        .collect();
    let provided_phase_usage = input
        .phase_usage
        .as_ref()
        .ok_or(ToolFirstReportError::MissingPhaseUsage)?;
    if provided_phase_usage != &input.engine.phase_usage {
        return Err(ToolFirstReportError::PhaseUsageMismatch);
    }
    let usage = phase_usage(input.phase_usage, input.engine.budget_usage)?;
    let report = ReviewReportV3::new(
        report_state(&input.engine.result.outcome),
        input.snapshot_sha256,
        input.partition.plan_sha256.clone(),
        findings,
        overview,
        lineage,
        input.publication,
        input.selection,
        ReviewReportStrategy {
            effort: input.effort,
            grouping_source: grouping_source(input.engine.grouping_mode),
            group_count: input.engine.group_count,
            max_parallel_groups: input.engine.schedule.max_parallel_groups,
        },
        coverage(&input.engine.result.coverage),
        usage,
    )
    .map_err(ToolFirstReportError::Report)?;
    report.validate().map_err(ToolFirstReportError::Report)?;
    report
        .validate_against_anchors(input.anchors)
        .map_err(ToolFirstReportError::Report)?;
    report
        .canonical_json()
        .map_err(ToolFirstReportError::Report)?;
    Ok(report)
}

type FindingSourceKey = (String, AnchorId, Sha256Digest, Sha256Digest);

fn project_findings(
    envelopes: &[FindingsEnvelope],
    issued: &IssuedWorkUnitAnchors,
    anchors: &AnchorTable,
) -> Result<Vec<ReviewReportFinding>, ToolFirstReportError> {
    let ranked = validate_rank_and_render(envelopes.to_vec(), issued, anchors, MAX_FINDINGS)
        .map_err(|_| ToolFirstReportError::Findings)?;
    let sources = finding_sources(envelopes, issued, anchors)?;
    ranked
        .findings
        .into_iter()
        .map(|ranked| {
            let key = (
                ranked.work_unit_id.clone(),
                ranked.anchor_id.clone(),
                ranked.finding_key.clone(),
                ranked.content_digest.clone(),
            );
            let source = sources.get(&key).ok_or(ToolFirstReportError::Findings)?;
            let anchor = anchors
                .resolve(ranked.anchor_id.as_str())
                .ok_or(ToolFirstReportError::Findings)?;
            Ok(ReviewReportFinding {
                work_unit_id: ranked.work_unit_id,
                anchor_id: ranked.anchor_id,
                coordinate: report_coordinate(&anchor.path, anchor.position),
                finding_key: ranked.finding_key,
                content_sha256: ranked.content_digest,
                severity: ranked.severity,
                confidence_percent: ranked.confidence_percent,
                category: ranked.category,
                title: source.title.clone(),
                explanation: source.explanation.clone(),
                evidence: source.evidence.clone(),
                suggested_replacement: source.suggested_replacement.clone(),
                rendered_body: ranked.rendered_body,
                lineage_id: ranked.lineage_id,
            })
        })
        .collect()
}

fn finding_sources(
    envelopes: &[FindingsEnvelope],
    issued: &IssuedWorkUnitAnchors,
    anchors: &AnchorTable,
) -> Result<BTreeMap<FindingSourceKey, Finding>, ToolFirstReportError> {
    let mut sources = BTreeMap::new();
    for envelope in envelopes {
        for finding in &envelope.findings {
            let singleton = FindingsEnvelope {
                schema_version: envelope.schema_version.clone(),
                work_unit_id: envelope.work_unit_id.clone(),
                findings: vec![finding.clone()],
                summary: envelope.summary.clone(),
            };
            let ranked = validate_rank_and_render([singleton], issued, anchors, 1)
                .map_err(|_| ToolFirstReportError::Findings)?
                .findings
                .into_iter()
                .next()
                .ok_or(ToolFirstReportError::Findings)?;
            let key = (
                ranked.work_unit_id,
                ranked.anchor_id,
                ranked.finding_key,
                ranked.content_digest,
            );
            if sources
                .insert(key, finding.clone())
                .is_some_and(|existing| existing != *finding)
            {
                return Err(ToolFirstReportError::Findings);
            }
        }
    }
    Ok(sources)
}

fn report_coordinate(
    path: &revoot_core::ChangedPath,
    position: AnchorPosition,
) -> ReviewReportFindingCoordinate {
    match position {
        AnchorPosition::Deletion { old_line } => ReviewReportFindingCoordinate {
            path: path.old_path.clone(),
            side: ReviewReportFindingSide::Old,
            line: old_line,
        },
        AnchorPosition::Addition { new_line } | AnchorPosition::Context { new_line, .. } => {
            ReviewReportFindingCoordinate {
                path: path.new_path.clone(),
                side: ReviewReportFindingSide::New,
                line: new_line,
            }
        }
    }
}

fn validate_engine(
    engine: &ToolFirstEngineReport,
    partition: &ReviewPartitionPlan,
) -> Result<(), ToolFirstReportError> {
    validate_schedule(engine)?;
    if engine.group_count
        != u32::try_from(engine.schedule.records.len())
            .map_err(|_| ToolFirstReportError::EngineAccounting)?
        || engine.group_count == 0
        || engine.schedule.plan_sha256 != engine.group_plan_sha256
        || engine.verified_candidates
            < u32::try_from(outcome_findings(&engine.result.outcome).len())
                .map_err(|_| ToolFirstReportError::EngineAccounting)?
        || engine
            .result
            .coverage
            .high_risk_files
            .checked_add(engine.result.coverage.standard_risk_files)
            .and_then(|value| value.checked_add(engine.result.coverage.low_risk_files))
            != Some(partition.coverage.included_files)
    {
        return Err(ToolFirstReportError::EngineAccounting);
    }
    let usage = outcome_usage(&engine.result.outcome);
    if usage.model_requests != engine.budget_usage.model_requests
        || usage.input_tokens != engine.budget_usage.input_tokens
        || usage.output_tokens != engine.budget_usage.output_tokens
        || usage.tool_calls != engine.budget_usage.tool_calls
        || usage.cost_microusd != engine.budget_usage.cost_microusd
        || usage.elapsed_millis != engine.budget_usage.elapsed_millis
    {
        return Err(ToolFirstReportError::EngineAccounting);
    }
    Ok(())
}

fn validate_schedule(engine: &ToolFirstEngineReport) -> Result<(), ToolFirstReportError> {
    let schedule = &engine.schedule;
    if schedule.max_parallel_groups == 0 || schedule.max_parallel_groups > 8 {
        return Err(ToolFirstReportError::EngineAccounting);
    }
    let mut ids = BTreeSet::new();
    let mut positions = BTreeSet::new();
    let mut counts = [0_u32; 6];
    for record in &schedule.records {
        if record.priority_position == 0
            || !ids.insert(record.group_id.clone())
            || !positions.insert(record.priority_position)
        {
            return Err(ToolFirstReportError::EngineAccounting);
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
            .ok_or(ToolFirstReportError::EngineAccounting)?;
    }
    let expected_positions = (1..=u32::try_from(schedule.records.len())
        .map_err(|_| ToolFirstReportError::EngineAccounting)?)
        .collect::<BTreeSet<_>>();
    if counts
        != [
            schedule.queued_groups,
            schedule.running_groups,
            schedule.complete_groups,
            schedule.partial_groups,
            schedule.failed_groups,
            schedule.cancelled_groups,
        ]
        || positions != expected_positions
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
        return Err(ToolFirstReportError::EngineAccounting);
    }
    Ok(())
}

fn validate_snapshot(input: &ToolFirstReportInput<'_>) -> Result<(), ToolFirstReportError> {
    if input.anchors.identity() != &input.partition.snapshot {
        return Err(ToolFirstReportError::Snapshot);
    }
    let snapshot = serde_json::to_vec(&input.partition.snapshot)
        .map_err(|_| ToolFirstReportError::Serialization)?;
    if Sha256Digest::of_bytes(&snapshot) != input.snapshot_sha256 {
        return Err(ToolFirstReportError::Snapshot);
    }
    Ok(())
}

fn selection_from_partition(partition: &ReviewPartitionPlan) -> ReviewReportSelection {
    ReviewReportSelection {
        changed_files: partition.coverage.input_files,
        selected_files: partition.coverage.included_files,
        omitted_files: partition.coverage.omitted_files,
        selected_diff_bytes: partition.coverage.included_bytes,
        omission_reasons: partition.coverage.omission_reasons.clone(),
    }
}

fn issued_anchors(partition: &ReviewPartitionPlan) -> IssuedWorkUnitAnchors {
    partition
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
        .collect()
}

fn report_state(outcome: &ReviewOutcome) -> ReviewReportState {
    match outcome {
        ReviewOutcome::Complete { .. } => ReviewReportState::Complete,
        ReviewOutcome::Partial { .. } => ReviewReportState::Partial,
        ReviewOutcome::NoFindings { .. } => ReviewReportState::NoFindings,
        ReviewOutcome::Blocked { .. } => ReviewReportState::Blocked,
        ReviewOutcome::Failed { .. } | ReviewOutcome::Stale { .. } => ReviewReportState::Failed,
        ReviewOutcome::Cancelled { .. } => ReviewReportState::Cancelled,
    }
}

fn outcome_findings(outcome: &ReviewOutcome) -> &[revoot_core::FindingsEnvelope] {
    match outcome {
        ReviewOutcome::Complete { findings, .. } | ReviewOutcome::Partial { findings, .. } => {
            findings
        }
        ReviewOutcome::NoFindings { .. }
        | ReviewOutcome::Stale { .. }
        | ReviewOutcome::Blocked { .. }
        | ReviewOutcome::Failed { .. }
        | ReviewOutcome::Cancelled { .. } => &[],
    }
}

fn outcome_usage(outcome: &ReviewOutcome) -> AgentBudgetUsage {
    match outcome {
        ReviewOutcome::Complete { usage, .. }
        | ReviewOutcome::Partial { usage, .. }
        | ReviewOutcome::NoFindings { usage, .. }
        | ReviewOutcome::Stale { usage }
        | ReviewOutcome::Blocked { usage, .. }
        | ReviewOutcome::Failed { usage, .. }
        | ReviewOutcome::Cancelled { usage } => *usage,
    }
}

fn grouping_source(mode: ReviewGrouperMode) -> ReviewGroupingSource {
    match mode {
        ReviewGrouperMode::DeterministicSmallSelection => ReviewGroupingSource::Deterministic,
        ReviewGrouperMode::Semantic => ReviewGroupingSource::Semantic,
        ReviewGrouperMode::DeterministicFallback(_) => ReviewGroupingSource::DeterministicFallback,
    }
}

fn coverage(value: &crate::review_engine::ReviewCoverage) -> ReviewReportCoverage {
    ReviewReportCoverage {
        policy_version: value.policy_version.to_owned(),
        high_risk_files: value.high_risk_files,
        standard_risk_files: value.standard_risk_files,
        low_risk_files: value.low_risk_files,
        fully_read_files: value.fully_read_files,
        sampled_files: value.sampled_files,
        manifest_only_files: value.manifest_only_files,
        delivered_high_risk_hunks: value.delivered_high_risk_hunks,
        required_high_risk_hunks: value.required_high_risk_hunks,
        explicit_deferrals: value.explicit_deferrals,
        failed_groups: value.failed_groups,
    }
}

fn phase_usage(
    phases: Option<Vec<ReviewReportPhaseUsage>>,
    aggregate: revoot_core::ReviewBudgetUsage,
) -> Result<ReviewReportUsage, ToolFirstReportError> {
    let phases = phases.ok_or(ToolFirstReportError::MissingPhaseUsage)?;
    let expected = BTreeSet::from([
        ReviewReportPhase::Grouping,
        ReviewReportPhase::Planning,
        ReviewReportPhase::Review,
        ReviewReportPhase::Verification,
        ReviewReportPhase::Adjudication,
    ]);
    if phases.len() != expected.len()
        || phases
            .iter()
            .map(|usage| usage.phase)
            .collect::<BTreeSet<_>>()
            != expected
    {
        return Err(ToolFirstReportError::PhaseUsage);
    }
    let totals = phases
        .iter()
        .try_fold(ReviewReportUsageTotals::default(), |mut totals, phase| {
            totals.model_requests = totals.model_requests.checked_add(phase.model_requests)?;
            totals.input_tokens = totals.input_tokens.checked_add(phase.input_tokens)?;
            totals.output_tokens = totals.output_tokens.checked_add(phase.output_tokens)?;
            totals.tool_calls = totals.tool_calls.checked_add(phase.tool_calls)?;
            totals.cost_microusd = totals.cost_microusd.checked_add(phase.cost_microusd)?;
            Some(totals)
        })
        .ok_or(ToolFirstReportError::PhaseUsage)?;
    if totals.model_requests != aggregate.model_requests
        || totals.input_tokens != aggregate.input_tokens
        || totals.output_tokens != aggregate.output_tokens
        || totals.tool_calls != aggregate.tool_calls
        || totals.cost_microusd != aggregate.cost_microusd
    {
        return Err(ToolFirstReportError::PhaseUsageMismatch);
    }
    Ok(ReviewReportUsage { phases, totals })
}

fn render_overview(overview: &ReviewOverview) -> Result<String, ToolFirstReportError> {
    overview
        .validate()
        .map_err(|_| ToolFirstReportError::Overview)?;
    let mut output = String::new();
    writeln!(output, "{}", overview.summary).map_err(|_| ToolFirstReportError::Overview)?;
    writeln!(
        output,
        "Overall risk: {}",
        risk_label(overview.overall_risk)
    )
    .map_err(|_| ToolFirstReportError::Overview)?;
    writeln!(output, "Basis: {}", overview.overall_basis)
        .map_err(|_| ToolFirstReportError::Overview)?;
    for risk in &overview.risks {
        writeln!(
            output,
            "Risk — {} ({}): {}",
            risk.area,
            risk_label(risk.risk),
            risk.basis
        )
        .map_err(|_| ToolFirstReportError::Overview)?;
    }
    for assumption in &overview.assumptions_and_gaps {
        writeln!(output, "Assumption or gap: {assumption}")
            .map_err(|_| ToolFirstReportError::Overview)?;
    }
    for validation in &overview.manual_validations {
        writeln!(output, "Manual validation: {validation}")
            .map_err(|_| ToolFirstReportError::Overview)?;
    }
    let output = output.trim_end().to_owned();
    if output.is_empty() || output.len() > 8 * 1024 || output.contains('\0') {
        return Err(ToolFirstReportError::Overview);
    }
    Ok(output)
}

const fn risk_label(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Moderate => "moderate",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use revoot_core::{
        AgentBudgetUsage, AnchorPosition, ChangedPath, CommentableLine, FileChangeKind, Finding,
        FindingCategory, FindingsEnvelope, GitSha, LocalSnapshotIdentity, PartitionLimits,
        ReviewFileClass, ReviewFileInput, ReviewObject, ReviewObjectRole, ReviewSelectionPolicy,
        ReviewSnapshotIdentity, ReviewValue, ReviewValueReason, ReviewValueTier, Severity,
        build_partition_plan,
    };
    use serde_json::json;

    use super::*;
    use crate::group_scheduler::{GroupScheduleRecord, GroupScheduleStatus};
    use crate::review_adjudicator::ReviewAdjudicationMode;
    use crate::review_engine::{PriorFindingDisposition, ReviewCoverage};
    use crate::review_result_reducer::ReducedReviewResult;

    struct Fixture {
        partition: ReviewPartitionPlan,
        anchors: AnchorTable,
        engine: ToolFirstEngineReport,
        snapshot_sha256: Sha256Digest,
    }

    fn fixture() -> Fixture {
        let snapshot = snapshot();
        let path = repository_path("src/lib.rs");
        let changed = ChangedPath {
            old_path: path.clone(),
            new_path: path,
            kind: FileChangeKind::Modified,
        };
        let anchors = AnchorTable::build(
            snapshot.clone(),
            [CommentableLine {
                path: changed.clone(),
                position: AnchorPosition::Addition { new_line: 1 },
                exact_line_digest: Sha256Digest::of_bytes(b"line"),
                context_digest: Sha256Digest::of_bytes(b"context"),
            }],
        )
        .expect("anchors");
        let anchor_id = anchors.iter().next().expect("anchor").id.clone();
        let partition = build_partition_plan(
            snapshot.clone(),
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
                max_file_bytes: 1_000,
            },
            PartitionLimits {
                max_files: 10,
                max_total_bytes: 10_000,
                max_work_units: 10,
                max_files_per_work_unit: 10,
                max_bytes_per_work_unit: 10_000,
                max_anchors_per_work_unit: 100,
            },
            [ReviewFileInput {
                path: changed,
                class: ReviewFileClass::Text,
                review_value: ReviewValue {
                    tier: ReviewValueTier::High,
                    score: 220,
                    reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                },
                objects: vec![ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: Sha256Digest::of_bytes(b"diff"),
                    size_bytes: 100,
                }],
                anchor_ids: vec![anchor_id.clone()],
            }],
        )
        .expect("partition");
        let work_unit_id = partition.work_units[0].id.as_str().to_owned();
        let overview = ReviewOverview {
            summary: "One verified issue requires attention.".to_owned(),
            overall_risk: RiskLevel::High,
            overall_basis: "A high-severity verified finding remains.".to_owned(),
            risks: Vec::new(),
            assumptions_and_gaps: Vec::new(),
            manual_validations: Vec::new(),
        };
        let aggregate = aggregate_usage();
        let agent_usage = AgentBudgetUsage {
            turns: aggregate.model_requests,
            model_requests: aggregate.model_requests,
            tool_calls: aggregate.tool_calls,
            input_tokens: aggregate.input_tokens,
            output_tokens: aggregate.output_tokens,
            cost_microusd: aggregate.cost_microusd,
            candidate_findings: 1,
            elapsed_millis: aggregate.elapsed_millis,
            ..AgentBudgetUsage::default()
        };
        let result = ReducedReviewResult {
            outcome: ReviewOutcome::Complete {
                findings: vec![FindingsEnvelope {
                    schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
                    work_unit_id,
                    findings: vec![Finding {
                        anchor_id: anchor_id.as_str().to_owned(),
                        severity: Severity::High,
                        confidence_percent: 95,
                        category: FindingCategory::Correctness,
                        title: "Incorrect state transition".to_owned(),
                        explanation: "The transition can leave state inconsistent.".to_owned(),
                        evidence: "The added line performs the transition without a guard."
                            .to_owned(),
                        lineage_id: None,
                        suggested_replacement: None,
                    }],
                    summary: overview.summary.clone(),
                }],
                summary: overview.summary.clone(),
                usage: agent_usage,
            },
            overview,
            coverage: ReviewCoverage {
                policy_version: "revoot.risk-adaptive-coverage/v1",
                high_risk_files: 1,
                standard_risk_files: 0,
                low_risk_files: 0,
                fully_read_files: 1,
                sampled_files: 0,
                manifest_only_files: 0,
                delivered_high_risk_hunks: 1,
                required_high_risk_hunks: 1,
                explicit_deferrals: 0,
                failed_groups: 0,
            },
            prior_finding_dispositions: Vec::<PriorFindingDisposition>::new(),
        };
        let group_plan_sha256 = Sha256Digest::of_bytes(b"group-plan");
        let group_id =
            serde_json::from_value(json!(format!("rg-{}", "1".repeat(64)))).expect("group id");
        let engine = ToolFirstEngineReport {
            result,
            grouping_mode: ReviewGrouperMode::Semantic,
            group_plan_sha256: group_plan_sha256.clone(),
            group_count: 1,
            schedule: crate::group_scheduler::GroupScheduleSnapshot {
                plan_sha256: group_plan_sha256,
                max_parallel_groups: 4,
                cancellation_requested: false,
                queued_groups: 0,
                running_groups: 0,
                complete_groups: 1,
                partial_groups: 0,
                failed_groups: 0,
                cancelled_groups: 0,
                partial: false,
                records: vec![GroupScheduleRecord {
                    group_id,
                    priority_position: 1,
                    status: GroupScheduleStatus::Complete,
                }],
            },
            adjudication_mode: ReviewAdjudicationMode::Model,
            verified_candidates: 1,
            verification_suppressions: 0,
            budget_usage: aggregate,
            phase_usage: phases(),
        };
        let snapshot_sha256 =
            Sha256Digest::of_bytes(&serde_json::to_vec(&snapshot).expect("snapshot encoding"));
        Fixture {
            partition,
            anchors,
            engine,
            snapshot_sha256,
        }
    }

    #[test]
    fn builds_canonical_v3_with_findings_strategy_coverage_and_phase_usage() {
        let fixture = fixture();
        let mut report =
            build_tool_first_report(input(&fixture, Some(phases()))).expect("canonical report");
        assert_eq!(report.schema_version, ReviewReportV3::SCHEMA_VERSION);
        assert_eq!(report.state, ReviewReportState::Complete);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.strategy.grouping_source,
            ReviewGroupingSource::Semantic
        );
        assert_eq!(report.strategy.group_count, 1);
        assert_eq!(report.coverage.high_risk_files, 1);
        assert_eq!(report.coverage.delivered_high_risk_hunks, 1);
        assert_eq!(report.usage.phases.len(), 5);
        assert_eq!(report.usage.totals.model_requests, 5);
        report.validate().expect("report validates");
        report.report_sha256 = Sha256Digest::of_bytes(b"tampered report");
        assert_eq!(report.validate(), Err(ReviewReportError::ReportDigest));
    }

    #[test]
    fn missing_phase_data_fails_instead_of_fabricating_a_split() {
        let fixture = fixture();
        assert_eq!(
            build_tool_first_report(input(&fixture, None)),
            Err(ToolFirstReportError::MissingPhaseUsage)
        );
    }

    #[test]
    fn phase_totals_must_reconcile_to_engine_aggregate() {
        let fixture = fixture();
        let mut usage = phases();
        usage[0].input_tokens += 1;
        assert_eq!(
            build_tool_first_report(input(&fixture, Some(usage))),
            Err(ToolFirstReportError::PhaseUsageMismatch)
        );
    }

    #[test]
    fn selection_and_snapshot_mismatches_fail_closed() {
        let fixture = fixture();
        let mut selection_mismatch = input(&fixture, Some(phases()));
        selection_mismatch.selection.selected_diff_bytes += 1;
        assert_eq!(
            build_tool_first_report(selection_mismatch),
            Err(ToolFirstReportError::Selection)
        );

        let mut snapshot_mismatch = input(&fixture, Some(phases()));
        snapshot_mismatch.snapshot_sha256 = Sha256Digest::of_bytes(b"wrong snapshot");
        assert_eq!(
            build_tool_first_report(snapshot_mismatch),
            Err(ToolFirstReportError::Snapshot)
        );
    }

    #[test]
    fn inconsistent_schedule_accounting_fails_closed() {
        let mut fixture = fixture();
        fixture.engine.schedule.complete_groups = 0;
        assert_eq!(
            build_tool_first_report(input(&fixture, Some(phases()))),
            Err(ToolFirstReportError::EngineAccounting)
        );
    }

    #[test]
    fn canonical_json_has_no_payload_source_or_artifact_fields() {
        let fixture = fixture();
        let report =
            build_tool_first_report(input(&fixture, Some(phases()))).expect("canonical report");
        let json = String::from_utf8(report.canonical_json().expect("canonical JSON"))
            .expect("UTF-8 JSON");
        for forbidden in [
            "artifact_path",
            "diff_body",
            "prompt",
            "provider_response",
            "raw_response",
            "source_body",
            "tool_payload",
        ] {
            assert!(!json.contains(forbidden));
        }
    }

    fn input(
        fixture: &Fixture,
        phase_usage: Option<Vec<ReviewReportPhaseUsage>>,
    ) -> ToolFirstReportInput<'_> {
        ToolFirstReportInput {
            engine: &fixture.engine,
            partition: &fixture.partition,
            anchors: &fixture.anchors,
            snapshot_sha256: fixture.snapshot_sha256.clone(),
            selection: selection_from_partition(&fixture.partition),
            publication: ReviewReportPublication {
                planned_findings: 1,
                published_findings: 0,
                suppressed_findings: 0,
                publication_complete: false,
            },
            effort: ReviewEffort::Medium,
            phase_usage,
        }
    }

    fn phases() -> Vec<ReviewReportPhaseUsage> {
        [
            ReviewReportPhase::Grouping,
            ReviewReportPhase::Planning,
            ReviewReportPhase::Review,
            ReviewReportPhase::Verification,
            ReviewReportPhase::Adjudication,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, phase)| ReviewReportPhaseUsage {
            phase,
            model_requests: 1,
            input_tokens: 10,
            output_tokens: 2,
            tool_calls: u32::from(index == 2),
            cost_microusd: 5,
        })
        .collect()
    }

    fn aggregate_usage() -> revoot_core::ReviewBudgetUsage {
        revoot_core::ReviewBudgetUsage {
            model_requests: 5,
            input_tokens: 50,
            output_tokens: 10,
            tool_calls: 1,
            cost_microusd: 25,
            elapsed_millis: 50,
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

    fn repository_path(path: &str) -> revoot_core::RepositoryPath {
        revoot_core::RepositoryPath::try_from(path.to_owned()).expect("repository path")
    }
}
