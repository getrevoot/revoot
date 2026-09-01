//! Local scan adapter over the shared tool-first review pipeline.
//!
//! Scan chunks are represented as bounded, synthetic addition hunks with their
//! real repository path and post-change line coordinates. The adapter does not
//! implement a model loop: grouping, planning, review rounds, repository tools,
//! coverage, verification, and adjudication all run through the same engine as
//! change review. Results remain local and carry no publication authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::path::PathBuf;
use std::sync::Arc;

use revoot_core::{
    AgentOmission, AgentOmissionReason, AnchorTable, CancellationToken, ChangedPath,
    FileChangeKind, FindingsEnvelope, IssuedWorkUnitAnchors, PartitionLimits, PriorReviewContext,
    ProviderAdapter, RankedFinding, RepositoryDiff, RepositoryRelativePath, RepositoryToolLimits,
    RepositoryToolbox, ReviewBudgetBroker, ReviewBudgetSnapshot, ReviewFileClass, ReviewFileInput,
    ReviewObject, ReviewObjectRole, ReviewOutcome, ReviewPartitionPlan, ReviewSelectionPolicy,
    ReviewSnapshotIdentity, ScanFile, ScanFileInput, ScanOmissionReason, ScanPlan, Sha256Digest,
    UnifiedDiffLimits, build_partition_plan, classify_review_value, parse_gitlab_file_diff,
    validate_rank_and_render,
};
use serde::Serialize;

use crate::config::RepositoryReviewPolicy;
use crate::group_worker_engine::GroupWorkerClock;
use crate::review_adjudicator::ReviewAdjudicatorClock;
use crate::review_grouper::ReviewGrouperClock;
use crate::review_verifier::ReviewVerifierClock;
use crate::tool_first_engine::{
    ToolFirstEngineLimits, ToolFirstEngineRequest, run_tool_first_engine,
};

const MAX_FINDINGS: usize = 25;

/// Clock accepted by every phase of the shared tool-first engine.
pub trait ScanEngineClock:
    ReviewGrouperClock
    + GroupWorkerClock
    + ReviewVerifierClock
    + ReviewAdjudicatorClock
    + Send
    + Sync
    + 'static
{
}

impl<T> ScanEngineClock for T where
    T: ReviewGrouperClock
        + GroupWorkerClock
        + ReviewVerifierClock
        + ReviewAdjudicatorClock
        + Send
        + Sync
        + 'static
{
}

/// Trusted immutable input for one local scan execution.
pub struct ScanEngineRequest<C> {
    pub provider: Arc<dyn ProviderAdapter>,
    pub repository_root: PathBuf,
    pub repository_paths: BTreeSet<RepositoryRelativePath>,
    pub model: String,
    pub plan: ScanPlan,
    pub inputs: Vec<ScanFileInput>,
    pub selection_policy: ReviewSelectionPolicy,
    pub partition_limits: PartitionLimits,
    pub rule_policy: RepositoryReviewPolicy,
    pub limits: ToolFirstEngineLimits,
    pub minimum_confidence_percent: u8,
    pub max_findings: usize,
    pub budget: ReviewBudgetBroker,
    pub cancellation: CancellationToken,
    pub clock: Arc<C>,
    pub system_policy_id: String,
    pub system_policy: String,
}

impl<C> fmt::Debug for ScanEngineRequest<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanEngineRequest")
            .field("provider", &self.provider.adapter_id())
            .field("repository_path_count", &self.repository_paths.len())
            .field("model", &self.model)
            .field("plan_sha256", &self.plan.plan_sha256)
            .field("input_count", &self.inputs.len())
            .field("limits", &self.limits)
            .field("system_policy_id", &self.system_policy_id)
            .field("system_policy", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Body-free progress over the immutable scan plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanEngineCoverage {
    pub policy_version: &'static str,
    pub selected_files: u32,
    pub omitted_files: u32,
    pub total_chunks: u32,
    pub delivered_chunks: u32,
    pub fully_read_files: u32,
    pub sampled_files: u32,
    pub manifest_only_files: u32,
    pub delivered_high_risk_hunks: u32,
    pub required_high_risk_hunks: u32,
    pub explicit_deferrals: u32,
    pub failed_groups: u32,
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
    Diff,
    Anchor,
    Partition,
    Repository,
    Engine,
    FindingProjection,
}

impl fmt::Display for ScanEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "scan engine configuration is invalid",
            Self::Replay => "scan plan replay validation failed",
            Self::InputBinding => "scan inputs do not match the immutable plan",
            Self::Diff => "scan chunks could not be represented safely",
            Self::Anchor => "scan anchors could not be constructed safely",
            Self::Partition => "scan partition could not be constructed safely",
            Self::Repository => "scan repository tools could not be bound safely",
            Self::Engine => "shared tool-first scan execution failed",
            Self::FindingProjection => "scan findings could not be projected safely",
        })
    }
}

impl std::error::Error for ScanEngineError {}

struct ScanReviewInput {
    partition: ReviewPartitionPlan,
    anchors: AnchorTable,
    issued: IssuedWorkUnitAnchors,
    diffs: Vec<RepositoryDiff>,
    manifest_only_files: u32,
}

struct ScanProjection<'a> {
    plan: &'a ScanPlan,
    anchors: AnchorTable,
    issued: &'a IssuedWorkUnitAnchors,
    minimum_confidence_percent: u8,
    max_findings: usize,
    rule_policy: &'a RepositoryReviewPolicy,
    cancelled: bool,
    budget_limits: revoot_core::ReviewBudgetLimits,
    manifest_only_files: u32,
}

/// Execute a local scan through the native tool-first review engine.
///
/// Each [`ScanPlan`] chunk becomes exactly one bounded addition hunk. Initial
/// packets remain manifest-only, so source reaches the model only through the
/// shared bounded diff and repository tools. The returned result is local-only.
///
/// # Errors
///
/// Returns a payload-free failure for replay divergence, unsafe repository
/// binding, malformed synthetic diffs, invalid shared-engine configuration, or
/// contradictory final finding/coverage accounting.
pub async fn run_scan_engine<C>(
    mut request: ScanEngineRequest<C>,
) -> Result<ScanEngineOutput, ScanEngineError>
where
    C: ScanEngineClock,
{
    validate_request(&request)?;
    request
        .plan
        .validate_replay(&request.inputs)
        .map_err(|_| ScanEngineError::Replay)?;
    let scan_review = build_scan_review_input(
        &request.plan,
        &request.inputs,
        &request.selection_policy,
        request.partition_limits,
    )?;
    if scan_review.partition.work_units.is_empty() {
        return Ok(empty_partition_output(
            &request,
            &scan_review,
            request.plan.coverage.chunks != 0,
        ));
    }
    let (allowed_paths, selected_diffs) = toolbox_bindings(
        &scan_review,
        &request.repository_paths,
        &request.rule_policy,
    )?;
    let toolbox = Arc::new(
        RepositoryToolbox::open_selected(
            &request.repository_root,
            RepositoryToolLimits::default(),
            selected_diffs,
            allowed_paths,
            &request.cancellation,
        )
        .map_err(|_| ScanEngineError::Repository)?,
    );
    // Scan never sends a whole file automatically. Even the smallest valid
    // synthetic diff is larger than this all-or-nothing inline threshold.
    request.limits.max_inline_diff_bytes = 1;
    request.limits.model.clone_from(&request.model);
    let initial_omissions = scan_omissions(&request.plan);
    let budget_limits = request.budget.snapshot().limits;
    let engine = run_tool_first_engine(ToolFirstEngineRequest {
        provider: request.provider,
        toolbox,
        history: None,
        prior_review: PriorReviewContext::default(),
        anchor_table: scan_review.anchors.clone(),
        partition: scan_review.partition,
        rule_policy: request.rule_policy.clone(),
        budget: request.budget,
        cancellation: request.cancellation.clone(),
        clock: request.clock,
        limits: request.limits,
        system_policy_id: request.system_policy_id,
        system_policy: request.system_policy,
        initial_omissions,
    })
    .await
    .map_err(|_| ScanEngineError::Engine)?;

    project_output(
        &engine,
        ScanProjection {
            plan: &request.plan,
            anchors: scan_review.anchors,
            issued: &scan_review.issued,
            minimum_confidence_percent: request.minimum_confidence_percent,
            max_findings: request.max_findings,
            rule_policy: &request.rule_policy,
            cancelled: request.cancellation.is_cancelled(),
            budget_limits,
            manifest_only_files: scan_review.manifest_only_files,
        },
    )
}

fn toolbox_bindings(
    scan_review: &ScanReviewInput,
    repository_paths: &BTreeSet<RepositoryRelativePath>,
    rule_policy: &RepositoryReviewPolicy,
) -> Result<(BTreeSet<RepositoryRelativePath>, Vec<RepositoryDiff>), ScanEngineError> {
    let allowed_paths = repository_paths
        .iter()
        .filter(|path| rule_policy.allows_model_context(path.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let selected_paths = scan_review
        .partition
        .work_units
        .iter()
        .flat_map(|unit| &unit.files)
        .map(|file| RepositoryRelativePath::try_from(file.path.new_path.as_str().to_owned()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| ScanEngineError::Partition)?;
    if !selected_paths.is_subset(&allowed_paths) {
        return Err(ScanEngineError::Repository);
    }
    let selected_diffs = scan_review
        .diffs
        .iter()
        .filter(|diff| {
            selected_paths.contains(&diff.path)
                && rule_policy.allows_model_context(diff.path.as_str())
        })
        .cloned()
        .collect();
    Ok((allowed_paths, selected_diffs))
}

fn validate_request<C>(request: &ScanEngineRequest<C>) -> Result<(), ScanEngineError> {
    if request.provider.adapter_id().is_empty()
        || request.model.is_empty()
        || request.model.len() > revoot_core::MAX_MODEL_ID_BYTES
        || request.limits.model != request.model
        || request.repository_paths.is_empty() && !request.plan.files.is_empty()
        || !(1..=100).contains(&request.minimum_confidence_percent)
        || request.max_findings == 0
        || request.max_findings > MAX_FINDINGS
        || request.system_policy_id.is_empty()
        || request.system_policy.is_empty()
    {
        return Err(ScanEngineError::Configuration);
    }
    request
        .selection_policy
        .validate()
        .map_err(|_| ScanEngineError::Configuration)?;
    request
        .partition_limits
        .validate()
        .map_err(|_| ScanEngineError::Configuration)
}

fn build_scan_review_input(
    plan: &ScanPlan,
    inputs: &[ScanFileInput],
    selection_policy: &ReviewSelectionPolicy,
    partition_limits: PartitionLimits,
) -> Result<ScanReviewInput, ScanEngineError> {
    let source = inputs
        .iter()
        .map(|input| (input.path.clone(), input))
        .collect::<BTreeMap<_, _>>();
    if source.len() != inputs.len() {
        return Err(ScanEngineError::InputBinding);
    }
    let snapshot = ReviewSnapshotIdentity::Local(plan.request.snapshot.clone());
    let mut diffs = Vec::with_capacity(plan.files.len());
    let mut review_files = Vec::with_capacity(plan.files.len());
    let mut commentable = Vec::new();
    let mut expected_anchors = Vec::with_capacity(plan.files.len());
    let mut manifest_only_files = 0_u32;
    for file in &plan.files {
        let input = source
            .get(&file.path)
            .ok_or(ScanEngineError::InputBinding)?;
        if file.chunks.is_empty() {
            manifest_only_files = manifest_only_files.saturating_add(1);
            continue;
        }
        let changed = ChangedPath {
            old_path: file.path.clone(),
            new_path: file.path.clone(),
            kind: FileChangeKind::Added,
        };
        let diff = render_scan_diff(file, input)?;
        let parsed = parse_gitlab_file_diff(
            &changed,
            diff.as_bytes(),
            scan_diff_limits(file, diff.len())?,
        )
        .map_err(|_| ScanEngineError::Diff)?;
        if parsed.hunk_count != u32::try_from(file.chunks.len()).unwrap_or(u32::MAX)
            || parsed.commentable_lines.len()
                != usize::try_from(file.line_count).unwrap_or(usize::MAX)
        {
            return Err(ScanEngineError::Diff);
        }
        expected_anchors.push(parsed.commentable_lines.len());
        commentable.extend(parsed.commentable_lines);
        let relative = RepositoryRelativePath::try_from(file.path.as_str().to_owned())
            .map_err(|_| ScanEngineError::InputBinding)?;
        diffs.push(RepositoryDiff {
            path: relative,
            text: diff.clone(),
        });
        review_files.push(ReviewFileInput {
            path: changed.clone(),
            class: ReviewFileClass::Text,
            review_value: classify_review_value(&changed, ReviewFileClass::Text, Some(&diff)),
            objects: vec![ReviewObject {
                role: ReviewObjectRole::ExactDiff,
                content_sha256: parsed.input_sha256,
                size_bytes: u64::try_from(diff.len()).map_err(|_| ScanEngineError::Diff)?,
            }],
            anchor_ids: Vec::new(),
        });
    }
    let anchors =
        AnchorTable::build(snapshot.clone(), commentable).map_err(|_| ScanEngineError::Anchor)?;
    issue_anchors(&anchors, &mut review_files, &expected_anchors)?;
    let partition =
        build_partition_plan(snapshot, selection_policy, partition_limits, review_files)
            .map_err(|_| ScanEngineError::Partition)?;
    let issued = partition
        .work_units
        .iter()
        .map(|unit| {
            (
                unit.id.as_str().to_owned(),
                unit.files
                    .iter()
                    .flat_map(|file| file.anchor_ids.iter().cloned())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect();
    Ok(ScanReviewInput {
        partition,
        anchors,
        issued,
        diffs,
        manifest_only_files,
    })
}

fn scan_diff_limits(
    file: &ScanFile,
    diff_bytes: usize,
) -> Result<UnifiedDiffLimits, ScanEngineError> {
    let mut limits = UnifiedDiffLimits::default();
    limits.max_input_bytes = diff_bytes.max(1);
    limits.max_input_lines = file.line_count.saturating_add(
        u32::try_from(file.chunks.len())
            .unwrap_or(u32::MAX)
            .saturating_add(8),
    );
    limits.max_hunks = u32::try_from(file.chunks.len()).map_err(|_| ScanEngineError::Diff)?;
    limits.max_lines_per_hunk = file
        .chunks
        .iter()
        .map(|chunk| {
            chunk
                .end_line
                .saturating_sub(chunk.start_line)
                .saturating_add(1)
        })
        .max()
        .unwrap_or(1);
    limits.max_commentable_lines = file.line_count.max(1);
    limits.context_radius_lines = limits.context_radius_lines.min(limits.max_lines_per_hunk);
    Ok(limits)
}

fn render_scan_diff(file: &ScanFile, input: &ScanFileInput) -> Result<String, ScanEngineError> {
    if input.path != file.path
        || Sha256Digest::of_bytes(input.content.as_bytes()) != file.content_sha256
    {
        return Err(ScanEngineError::InputBinding);
    }
    let mut output = format!(
        "diff --git a/{0} b/{0}\nnew file mode 100644\n--- /dev/null\n+++ b/{0}\n",
        file.path.as_str()
    );
    for chunk in &file.chunks {
        let start = usize::try_from(chunk.start_byte).map_err(|_| ScanEngineError::InputBinding)?;
        let end = usize::try_from(chunk.end_byte).map_err(|_| ScanEngineError::InputBinding)?;
        let body = input
            .content
            .get(start..end)
            .ok_or(ScanEngineError::InputBinding)?;
        if Sha256Digest::of_bytes(body.as_bytes()) != chunk.body_sha256 {
            return Err(ScanEngineError::InputBinding);
        }
        let count = chunk
            .end_line
            .saturating_sub(chunk.start_line)
            .saturating_add(1);
        writeln!(output, "@@ -0,0 +{},{} @@", chunk.start_line, count)
            .map_err(|_| ScanEngineError::Diff)?;
        for line in body.split_inclusive('\n') {
            output.push('+');
            if let Some(content) = line.strip_suffix('\n') {
                output.push_str(content);
                output.push('\n');
            } else {
                output.push_str(line);
                output.push('\n');
                output.push_str("\\ No newline at end of file\n");
            }
        }
    }
    Ok(output)
}

fn issue_anchors(
    anchors: &AnchorTable,
    files: &mut [ReviewFileInput],
    expected: &[usize],
) -> Result<(), ScanEngineError> {
    let indices = files
        .iter()
        .enumerate()
        .map(|(index, file)| (file.path.clone(), index))
        .collect::<BTreeMap<_, _>>();
    if indices.len() != files.len() {
        return Err(ScanEngineError::Anchor);
    }
    let mut observed = vec![0_usize; files.len()];
    for anchor in anchors.iter() {
        let index = *indices.get(&anchor.path).ok_or(ScanEngineError::Anchor)?;
        files[index].anchor_ids.push(anchor.id.clone());
        observed[index] = observed[index].saturating_add(1);
    }
    if observed != expected {
        return Err(ScanEngineError::Anchor);
    }
    Ok(())
}

fn scan_omissions(plan: &ScanPlan) -> Vec<AgentOmission> {
    plan.omissions
        .iter()
        .map(|omission| AgentOmission {
            subject_id: format!(
                "scan:{}",
                Sha256Digest::of_bytes(omission.path.as_str().as_bytes()).as_str()
            ),
            reason: match omission.reason {
                ScanOmissionReason::BinaryLikeContent => AgentOmissionReason::BinaryFile,
                ScanOmissionReason::FileTooLarge | ScanOmissionReason::LineTooLarge => {
                    AgentOmissionReason::FileTooLarge
                }
                ScanOmissionReason::NotRequested | ScanOmissionReason::UntrackedNotAuthorized => {
                    AgentOmissionReason::PolicyExcluded
                }
                ScanOmissionReason::FileBudget
                | ScanOmissionReason::TotalByteBudget
                | ScanOmissionReason::ChunkBudget => AgentOmissionReason::BudgetExhausted,
            },
        })
        .collect()
}

fn project_output(
    engine: &crate::tool_first_engine::ToolFirstEngineReport,
    projection: ScanProjection<'_>,
) -> Result<ScanEngineOutput, ScanEngineError> {
    let ScanProjection {
        plan,
        anchors,
        issued,
        minimum_confidence_percent,
        max_findings,
        rule_policy,
        cancelled,
        budget_limits,
        manifest_only_files,
    } = projection;
    let envelopes = outcome_findings(&engine.result.outcome);
    let ranked = validate_rank_and_render(envelopes, issued, &anchors, max_findings)
        .map_err(|_| ScanEngineError::FindingProjection)?;
    let mut suppressed = engine.verification_suppressions;
    let findings = ranked
        .findings
        .into_iter()
        .filter(|finding| {
            let retain = finding.confidence_percent >= minimum_confidence_percent
                && !rule_policy.suppresses(&finding.finding_key);
            if !retain {
                suppressed = suppressed.saturating_add(1);
            }
            retain
        })
        .collect::<Vec<_>>();
    let review_coverage = &engine.result.coverage;
    let selected_files = review_coverage
        .high_risk_files
        .saturating_add(review_coverage.standard_risk_files)
        .saturating_add(review_coverage.low_risk_files)
        .saturating_add(manifest_only_files);
    let partition_omissions = plan.coverage.included_files.saturating_sub(selected_files);
    let delivered_chunks = engine
        .group_coverage
        .iter()
        .flat_map(|ledger| ledger.files.values())
        .flat_map(|file| &file.hunks)
        .filter(|hunk| {
            hunk.total_pages > 0
                && hunk.delivered_pages.len()
                    == usize::try_from(hunk.total_pages).unwrap_or(usize::MAX)
                && (1..=hunk.total_pages).all(|page| hunk.delivered_pages.contains(&page))
        })
        .count();
    let status = scan_status(
        &engine.result.outcome,
        &engine.schedule,
        cancelled,
        plan,
        partition_omissions,
    );
    let omitted_files = plan
        .coverage
        .omitted_files
        .saturating_add(partition_omissions);
    let coverage = ScanEngineCoverage {
        policy_version: review_coverage.policy_version,
        selected_files,
        omitted_files,
        total_chunks: plan.coverage.chunks,
        delivered_chunks: u32::try_from(delivered_chunks).unwrap_or(u32::MAX),
        fully_read_files: review_coverage
            .fully_read_files
            .saturating_add(manifest_only_files),
        sampled_files: review_coverage.sampled_files,
        manifest_only_files: review_coverage
            .manifest_only_files
            .saturating_add(manifest_only_files),
        delivered_high_risk_hunks: review_coverage.delivered_high_risk_hunks,
        required_high_risk_hunks: review_coverage.required_high_risk_hunks,
        explicit_deferrals: review_coverage.explicit_deferrals,
        failed_groups: review_coverage.failed_groups,
        complete: status == ScanEngineStatus::Complete,
    };
    Ok(ScanEngineOutput {
        schema_version: ScanEngineOutput::SCHEMA_VERSION,
        findings,
        anchors,
        status,
        coverage,
        budget: ReviewBudgetSnapshot {
            limits: budget_limits,
            usage: engine.budget_usage,
            outstanding: revoot_core::OutstandingReviewReservations::default(),
        },
        provider_turns: engine.budget_usage.model_requests,
        tool_calls: engine.budget_usage.tool_calls,
        suppressed_candidates: suppressed,
    })
}

fn empty_partition_output<C>(
    request: &ScanEngineRequest<C>,
    scan_review: &ScanReviewInput,
    omitted_nonempty_content: bool,
) -> ScanEngineOutput {
    let omitted_files = request.plan.coverage.omitted_files.saturating_add(
        request
            .plan
            .coverage
            .included_files
            .saturating_sub(scan_review.manifest_only_files),
    );
    let complete = !omitted_nonempty_content && request.plan.coverage.complete;
    ScanEngineOutput {
        schema_version: ScanEngineOutput::SCHEMA_VERSION,
        findings: Vec::new(),
        anchors: scan_review.anchors.clone(),
        status: if complete {
            ScanEngineStatus::Complete
        } else {
            ScanEngineStatus::Partial(ScanEnginePartialReason::InputOmissions)
        },
        coverage: ScanEngineCoverage {
            policy_version: revoot_core::GroupCoverageLedger::POLICY_VERSION,
            selected_files: scan_review.manifest_only_files,
            omitted_files,
            total_chunks: request.plan.coverage.chunks,
            delivered_chunks: 0,
            fully_read_files: scan_review.manifest_only_files,
            sampled_files: 0,
            manifest_only_files: scan_review.manifest_only_files,
            delivered_high_risk_hunks: 0,
            required_high_risk_hunks: 0,
            explicit_deferrals: 0,
            failed_groups: 0,
            complete,
        },
        budget: request.budget.snapshot(),
        provider_turns: 0,
        tool_calls: 0,
        suppressed_candidates: 0,
    }
}

fn outcome_findings(outcome: &ReviewOutcome) -> Vec<FindingsEnvelope> {
    match outcome {
        ReviewOutcome::Complete { findings, .. } | ReviewOutcome::Partial { findings, .. } => {
            findings.clone()
        }
        ReviewOutcome::NoFindings { .. }
        | ReviewOutcome::Stale { .. }
        | ReviewOutcome::Blocked { .. }
        | ReviewOutcome::Failed { .. }
        | ReviewOutcome::Cancelled { .. } => Vec::new(),
    }
}

fn scan_status(
    outcome: &ReviewOutcome,
    schedule: &crate::group_scheduler::GroupScheduleSnapshot,
    cancelled: bool,
    plan: &ScanPlan,
    partition_omissions: u32,
) -> ScanEngineStatus {
    if cancelled || matches!(outcome, ReviewOutcome::Cancelled { .. }) {
        return ScanEngineStatus::Partial(ScanEnginePartialReason::Cancelled);
    }
    if !plan.coverage.complete || partition_omissions != 0 {
        return ScanEngineStatus::Partial(ScanEnginePartialReason::InputOmissions);
    }
    if schedule.records.iter().any(|record| {
        matches!(
            record.status,
            crate::group_scheduler::GroupScheduleStatus::Partial(
                crate::group_scheduler::GroupPartialReason::BudgetExhausted
                    | crate::group_scheduler::GroupPartialReason::DeadlineExceeded
            )
        )
    }) {
        return ScanEngineStatus::Partial(ScanEnginePartialReason::Budget);
    }
    if matches!(outcome, ReviewOutcome::Partial { .. }) || schedule.partial {
        return ScanEngineStatus::Partial(ScanEnginePartialReason::Provider);
    }
    ScanEngineStatus::Complete
}

#[cfg(test)]
mod tests {
    use std::fs;

    use revoot_core::{
        GitSha, LocalSnapshotIdentity, RepositoryPath, ReviewValueTier, ScanFileTracking,
        ScanLimits, ScanRequestMetadata, ScanUntrackedPolicy, build_scan_plan,
    };
    use tempfile::TempDir;

    use crate::config::ModelContextPolicy;

    use super::*;

    fn repository_path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).expect("repository path")
    }

    fn scan_plan(content: &str) -> (ScanPlan, Vec<ScanFileInput>) {
        let input = ScanFileInput {
            path: repository_path("src/lib.rs"),
            tracking: ScanFileTracking::Tracked,
            content: content.to_owned(),
        };
        let plan = build_scan_plan(
            ScanRequestMetadata {
                snapshot: LocalSnapshotIdentity {
                    repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
                    base_sha: GitSha::try_from("1".repeat(40)).expect("base"),
                    head_sha: GitSha::try_from("2".repeat(40)).expect("head"),
                    working_tree_sha256: Sha256Digest::of_bytes(b"tree"),
                    exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"diffs"),
                },
                requested_paths: Vec::new(),
                untracked_policy: ScanUntrackedPolicy::Exclude,
            },
            ScanLimits {
                max_chunk_lines: 2,
                ..ScanLimits::default()
            },
            [input.clone()],
        )
        .expect("scan plan");
        (plan, vec![input])
    }

    fn selection() -> ReviewSelectionPolicy {
        ReviewSelectionPolicy {
            version: "scan-selection-v1".to_owned(),
            included_paths: BTreeSet::new(),
            included_prefixes: Vec::new(),
            included_suffixes: Vec::new(),
            excluded_paths: BTreeSet::new(),
            excluded_prefixes: Vec::new(),
            excluded_suffixes: Vec::new(),
            excluded_basename_prefixes: Vec::new(),
            include_generated: true,
            max_file_bytes: 2 * 1024 * 1024,
        }
    }

    #[test]
    fn chunks_become_real_line_anchored_hunks_without_whole_file_context() {
        let (plan, inputs) = scan_plan("one\ntwo\nthree\n");
        let built = build_scan_review_input(
            &plan,
            &inputs,
            &selection(),
            PartitionLimits {
                max_files: 10,
                max_total_bytes: 1_000_000,
                max_work_units: 10,
                max_files_per_work_unit: 10,
                max_bytes_per_work_unit: 512 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
        )
        .expect("scan review input");
        let diff = &built.diffs[0].text;
        assert!(diff.contains("@@ -0,0 +1,2 @@"));
        assert!(diff.contains("@@ -0,0 +3,1 @@"));
        assert_eq!(built.anchors.len(), 3);
        assert_eq!(
            built
                .anchors
                .iter()
                .map(|anchor| match anchor.position {
                    revoot_core::AnchorPosition::Addition { new_line } => new_line,
                    _ => panic!("scan anchors are additions"),
                })
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2, 3])
        );
        assert_eq!(
            built.partition.work_units[0].files[0].review_value.tier,
            ReviewValueTier::Standard
        );
    }

    #[test]
    fn replay_or_content_tampering_fails_closed() {
        let (plan, mut inputs) = scan_plan("one\ntwo\n");
        inputs[0].content.push_str("changed\n");
        assert_eq!(
            build_scan_review_input(
                &plan,
                &inputs,
                &selection(),
                PartitionLimits {
                    max_files: 10,
                    max_total_bytes: 1_000_000,
                    max_work_units: 10,
                    max_files_per_work_unit: 10,
                    max_bytes_per_work_unit: 512 * 1024,
                    max_anchors_per_work_unit: 10_000,
                },
            )
            .err(),
            Some(ScanEngineError::InputBinding)
        );
    }

    #[test]
    fn no_newline_is_preserved_in_the_synthetic_diff() {
        let (plan, inputs) = scan_plan("last line");
        let rendered = render_scan_diff(&plan.files[0], &inputs[0]).expect("diff");
        assert!(rendered.ends_with("+last line\n\\ No newline at end of file\n"));
        let changed = ChangedPath {
            old_path: repository_path("src/lib.rs"),
            new_path: repository_path("src/lib.rs"),
            kind: FileChangeKind::Added,
        };
        assert!(
            parse_gitlab_file_diff(&changed, rendered.as_bytes(), UnifiedDiffLimits::default())
                .is_ok()
        );
    }

    #[test]
    fn empty_files_are_manifest_only_and_require_no_synthetic_hunk() {
        let (plan, inputs) = scan_plan("");
        let built = build_scan_review_input(
            &plan,
            &inputs,
            &selection(),
            PartitionLimits {
                max_files: 10,
                max_total_bytes: 1_000_000,
                max_work_units: 10,
                max_files_per_work_unit: 10,
                max_bytes_per_work_unit: 512 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
        )
        .expect("empty scan input");
        assert_eq!(built.manifest_only_files, 1);
        assert!(built.diffs.is_empty());
        assert!(built.partition.work_units.is_empty());
        assert!(built.anchors.is_empty());
    }

    #[test]
    fn repository_toolbox_accepts_the_synthetic_diff_for_real_paths() {
        let directory = TempDir::new().expect("directory");
        fs::create_dir(directory.path().join("src")).expect("src");
        fs::write(directory.path().join("src/lib.rs"), "one\ntwo\n").expect("source");
        let (plan, inputs) = scan_plan("one\ntwo\n");
        let built = build_scan_review_input(
            &plan,
            &inputs,
            &selection(),
            PartitionLimits {
                max_files: 10,
                max_total_bytes: 1_000_000,
                max_work_units: 10,
                max_files_per_work_unit: 10,
                max_bytes_per_work_unit: 512 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
        )
        .expect("scan review input");
        let toolbox = RepositoryToolbox::open_selected(
            directory.path(),
            RepositoryToolLimits::default(),
            built.diffs,
            [RepositoryRelativePath::try_from("src/lib.rs".to_owned()).expect("path")],
            &CancellationToken::default(),
        );
        assert!(toolbox.is_ok());
    }

    #[test]
    fn model_context_exclusion_rejects_selected_paths_and_diffs_before_toolbox_open() {
        let (plan, inputs) = scan_plan("one\ntwo\n");
        let built = build_scan_review_input(
            &plan,
            &inputs,
            &selection(),
            PartitionLimits {
                max_files: 10,
                max_total_bytes: 1_000_000,
                max_work_units: 10,
                max_files_per_work_unit: 10,
                max_bytes_per_work_unit: 512 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
        )
        .expect("scan review input");
        let path = RepositoryRelativePath::try_from("src/lib.rs".to_owned()).expect("path");
        let policy = RepositoryReviewPolicy {
            model_context: ModelContextPolicy {
                exclude: vec!["src/lib.rs".to_owned()],
            },
            ..RepositoryReviewPolicy::default()
        };
        assert_eq!(
            toolbox_bindings(&built, &BTreeSet::from([path]), &policy).err(),
            Some(ScanEngineError::Repository)
        );
    }
}
