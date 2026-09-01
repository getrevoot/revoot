//! Concurrent execution and verification for prepared isolated review groups.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use revoot_core::{
    AgentBudgetUsage, CancellationToken, GroupCoverageLedger, ProviderAdapter, ReviewBudgetBroker,
    ReviewGroupId, ReviewGroupPlan, SuppressedVerificationCandidate, VerifiedCandidate,
};

use crate::diff_artifact::DiffArtifactStore;
use crate::git_history::GitHistoryToolbox;
use crate::group_runtime::{
    GroupRuntimeError, GroupRuntimeReport, GroupRuntimeStopReason, GroupWorkerResult,
    run_group_runtime,
};
use crate::group_scheduler::{
    GroupFailureReason, GroupPartialReason, GroupScheduleSnapshot, ScheduledReviewGroup,
};
use crate::group_worker_engine::{
    GroupWorkerClock, GroupWorkerLimits, GroupWorkerOutput, GroupWorkerPartialReason,
    GroupWorkerRequest, GroupWorkerStatus, GroupWorkerSummary, run_group_worker,
};
use crate::review_group_packet::PreparedReviewGroupPacket;
use crate::review_verifier::{
    PartialVerifierSuppression, ReviewVerifierClock, ReviewVerifierConfig,
    ReviewVerifierFailureReason, ReviewVerifierOutcome, VerifierEvidence, run_review_verifier,
};

/// One prepared group and its host-backed discussion context.
pub struct PreparedReviewGroupExecution {
    pub group_id: ReviewGroupId,
    pub packet: PreparedReviewGroupPacket,
    pub prior_review: revoot_core::PriorReviewContext,
}

impl fmt::Debug for PreparedReviewGroupExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedReviewGroupExecution")
            .field("group_id", &self.group_id)
            .field("prior_review_count", &self.prior_review.discussions().len())
            .finish_non_exhaustive()
    }
}

/// Fixed execution configuration shared by every group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewGroupExecutionConfig {
    pub model: String,
    pub system_policy: String,
    pub max_parallel_groups: usize,
    pub worker_limits: GroupWorkerLimits,
    pub verifier: ReviewVerifierConfig,
}

/// Verification disposition for one completed worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupVerificationStatus {
    NoCandidates,
    Verified {
        accepted: Vec<VerifiedCandidate>,
        suppressed: Vec<SuppressedVerificationCandidate>,
    },
    UnverifiedPartial {
        reason: ReviewVerifierFailureReason,
        candidate_ids: Vec<String>,
    },
}

/// Deterministic source-free result for one scheduled group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedReviewGroup {
    pub group_id: ReviewGroupId,
    pub summary: GroupWorkerSummary,
    pub worker_status: GroupWorkerStatus,
    pub verification: GroupVerificationStatus,
    pub coverage: GroupCoverageLedger,
    pub usage: AgentBudgetUsage,
    pub provider_turns: u32,
    pub tool_calls: u32,
}

/// Complete concurrent execution reduction in scheduler priority order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewGroupExecutionReport {
    pub groups: Vec<ExecutedReviewGroup>,
    pub schedule: GroupScheduleSnapshot,
    pub stop_reason: Option<GroupRuntimeStopReason>,
}

/// Payload-free orchestration construction or runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewGroupExecutionError {
    Configuration,
    GroupCount,
    DuplicateGroup,
    GroupBinding,
    Runtime(GroupRuntimeError),
    ResultBookkeeping,
}

impl fmt::Display for ReviewGroupExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "group execution configuration is invalid",
            Self::GroupCount => "prepared group count does not match the group plan",
            Self::DuplicateGroup => "prepared group identities are duplicated",
            Self::GroupBinding => "prepared group identity does not match its packet or plan",
            Self::Runtime(_) => "concurrent group runtime failed",
            Self::ResultBookkeeping => "group execution result bookkeeping failed",
        })
    }
}

impl std::error::Error for ReviewGroupExecutionError {}

impl From<GroupRuntimeError> for ReviewGroupExecutionError {
    fn from(error: GroupRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

struct GroupTaskInput {
    packet: PreparedReviewGroupPacket,
    prior_review: revoot_core::PriorReviewContext,
}

/// Execute prepared groups with true bounded concurrency, then verify every
/// non-empty candidate batch before retaining it as publishable output.
///
/// Verifier failures retain only source-free group metadata and candidate IDs;
/// unverified findings are never returned as verified candidates.
///
/// # Errors
///
/// Rejects invalid configuration, incomplete/duplicated preparation, packet
/// identity mismatches, or runtime bookkeeping failures.
#[allow(clippy::too_many_arguments)]
pub async fn execute_review_groups<C>(
    plan: &ReviewGroupPlan,
    prepared: Vec<PreparedReviewGroupExecution>,
    provider: Arc<dyn ProviderAdapter>,
    toolbox: Arc<revoot_core::RepositoryToolbox>,
    artifacts: Arc<DiffArtifactStore>,
    history: Option<Arc<GitHistoryToolbox>>,
    budget: ReviewBudgetBroker,
    cancellation: CancellationToken,
    clock: Arc<C>,
    config: ReviewGroupExecutionConfig,
) -> Result<ReviewGroupExecutionReport, ReviewGroupExecutionError>
where
    C: GroupWorkerClock + ReviewVerifierClock + Send + Sync + 'static,
{
    validate_config(&config)?;
    let inputs = validate_prepared(plan, prepared)?;
    let inputs = Arc::new(Mutex::new(inputs));
    let results = Arc::new(Mutex::new(
        BTreeMap::<ReviewGroupId, ExecutedReviewGroup>::new(),
    ));
    let worker_inputs = Arc::clone(&inputs);
    let worker_results = Arc::clone(&results);
    let worker_provider = Arc::clone(&provider);
    let worker_toolbox = Arc::clone(&toolbox);
    let worker_artifacts = Arc::clone(&artifacts);
    let worker_history = history.clone();
    let worker_budget = budget.clone();
    let worker_clock = Arc::clone(&clock);
    let dispatch_clock = Arc::clone(&clock);
    let worker_config = config.clone();
    let dispatch_budget = budget.clone();

    let runtime = run_group_runtime(
        plan,
        config.max_parallel_groups,
        cancellation.clone(),
        move || {
            has_dispatch_capacity(
                &dispatch_budget,
                GroupWorkerClock::now_millis(dispatch_clock.as_ref()),
            )
        },
        move |scheduled, task_cancellation| {
            let inputs = Arc::clone(&worker_inputs);
            let results = Arc::clone(&worker_results);
            let provider = Arc::clone(&worker_provider);
            let toolbox = Arc::clone(&worker_toolbox);
            let artifacts = Arc::clone(&worker_artifacts);
            let history = worker_history.clone();
            let budget = worker_budget.clone();
            let clock = Arc::clone(&worker_clock);
            let config = worker_config.clone();
            async move {
                let Some(input) = take_group_input(&inputs, &scheduled.group.id) else {
                    return GroupWorkerResult::Failed(GroupFailureReason::PreparationFailed);
                };
                let worker_request = worker_request(input, history, &config);
                let Ok(worker) = run_group_worker(
                    provider.as_ref(),
                    worker_request,
                    toolbox.as_ref(),
                    artifacts.as_ref(),
                    &budget,
                    &task_cancellation,
                    clock.as_ref(),
                )
                .await
                else {
                    return GroupWorkerResult::Failed(GroupFailureReason::PreparationFailed);
                };
                finish_worker(
                    scheduled,
                    worker,
                    provider.as_ref(),
                    &config.verifier,
                    &budget,
                    &task_cancellation,
                    clock.as_ref(),
                    &results,
                )
                .await
            }
        },
    )
    .await?;
    reduce_report(runtime, &results)
}

fn validate_config(config: &ReviewGroupExecutionConfig) -> Result<(), ReviewGroupExecutionError> {
    if config.model.is_empty()
        || config.system_policy.trim().is_empty()
        || config.system_policy.contains('\0')
        || !(1..=8).contains(&config.max_parallel_groups)
        || config.verifier.model != config.model
    {
        return Err(ReviewGroupExecutionError::Configuration);
    }
    Ok(())
}

fn validate_prepared(
    plan: &ReviewGroupPlan,
    prepared: Vec<PreparedReviewGroupExecution>,
) -> Result<BTreeMap<ReviewGroupId, GroupTaskInput>, ReviewGroupExecutionError> {
    if prepared.len() != plan.groups.len() {
        return Err(ReviewGroupExecutionError::GroupCount);
    }
    let planned = plan
        .groups
        .iter()
        .map(|group| group.id.clone())
        .collect::<BTreeSet<_>>();
    let mut inputs = BTreeMap::new();
    for item in prepared {
        if !planned.contains(&item.group_id)
            || item.packet.worker_plan.group_id != item.group_id.as_str()
            || item.packet.initial_packet.group_brief.group_id != item.group_id.as_str()
        {
            return Err(ReviewGroupExecutionError::GroupBinding);
        }
        if inputs
            .insert(
                item.group_id,
                GroupTaskInput {
                    packet: item.packet,
                    prior_review: item.prior_review,
                },
            )
            .is_some()
        {
            return Err(ReviewGroupExecutionError::DuplicateGroup);
        }
    }
    Ok(inputs)
}

fn take_group_input(
    inputs: &Mutex<BTreeMap<ReviewGroupId, GroupTaskInput>>,
    group_id: &ReviewGroupId,
) -> Option<GroupTaskInput> {
    lock(inputs).remove(group_id)
}

fn worker_request(
    input: GroupTaskInput,
    history: Option<Arc<GitHistoryToolbox>>,
    config: &ReviewGroupExecutionConfig,
) -> GroupWorkerRequest {
    let packet = input.packet;
    GroupWorkerRequest {
        model: config.model.clone(),
        system_policy: config.system_policy.clone(),
        plan: packet.worker_plan,
        initial_packet: packet.initial_packet,
        work_unit_ids_by_path: packet.work_unit_ids_by_path,
        assigned_paths: packet.assigned_paths,
        issued_anchors: packet.issued_anchors,
        anchor_table: packet.anchor_table,
        coverage_gate: packet.coverage_gate,
        history,
        prior_review: input.prior_review,
        limits: config.worker_limits.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_worker<C>(
    scheduled: ScheduledReviewGroup,
    worker: GroupWorkerOutput,
    provider: &dyn ProviderAdapter,
    verifier_config: &ReviewVerifierConfig,
    budget: &ReviewBudgetBroker,
    cancellation: &CancellationToken,
    clock: &C,
    results: &Mutex<BTreeMap<ReviewGroupId, ExecutedReviewGroup>>,
) -> GroupWorkerResult<()>
where
    C: ReviewVerifierClock,
{
    let evidence = required_verifier_evidence(&worker);
    let verification = run_review_verifier(
        provider,
        verifier_config,
        &worker.candidates,
        evidence,
        budget,
        cancellation,
        clock,
    )
    .await;
    let (verification, verifier_failed) = verification_status(verification);
    let worker_outcome = scheduler_outcome(&worker.status);
    let result = ExecutedReviewGroup {
        group_id: scheduled.group.id.clone(),
        summary: worker.summary,
        worker_status: worker.status,
        verification,
        coverage: worker.coverage,
        usage: worker.usage,
        provider_turns: worker.provider_turns,
        tool_calls: worker.tool_calls,
    };
    lock(results).insert(scheduled.group.id, result);
    if verifier_failed {
        return GroupWorkerResult::Partial {
            reason: GroupPartialReason::VerificationFailed,
            verified_result: None,
        };
    }
    match worker_outcome {
        SchedulerOutcome::Complete => GroupWorkerResult::Complete(()),
        SchedulerOutcome::Partial(reason) => GroupWorkerResult::Partial {
            reason,
            verified_result: Some(()),
        },
        SchedulerOutcome::Cancelled => GroupWorkerResult::Cancelled,
    }
}

fn required_verifier_evidence(worker: &GroupWorkerOutput) -> Vec<VerifierEvidence> {
    let required = worker
        .candidates
        .candidates
        .iter()
        .flat_map(|candidate| candidate.evidence_references.iter().cloned())
        .collect::<BTreeSet<_>>();
    worker
        .evidence
        .iter()
        .filter(|evidence| required.contains(&evidence.evidence_id))
        .map(|evidence| VerifierEvidence {
            evidence_id: evidence.evidence_id.clone(),
            content: evidence.content.clone(),
        })
        .collect()
}

fn verification_status(outcome: ReviewVerifierOutcome) -> (GroupVerificationStatus, bool) {
    match outcome {
        ReviewVerifierOutcome::NoCandidates => (GroupVerificationStatus::NoCandidates, false),
        ReviewVerifierOutcome::Verified(outcome) => (
            GroupVerificationStatus::Verified {
                accepted: outcome.accepted,
                suppressed: outcome.suppressed,
            },
            false,
        ),
        ReviewVerifierOutcome::Partial(PartialVerifierSuppression {
            reason,
            suppressed_candidate_ids,
        }) => (
            GroupVerificationStatus::UnverifiedPartial {
                reason,
                candidate_ids: suppressed_candidate_ids,
            },
            true,
        ),
    }
}

enum SchedulerOutcome {
    Complete,
    Partial(GroupPartialReason),
    Cancelled,
}

fn scheduler_outcome(status: &GroupWorkerStatus) -> SchedulerOutcome {
    match status {
        GroupWorkerStatus::Complete(revoot_core::GroupCompletion::Complete { .. }) => {
            SchedulerOutcome::Complete
        }
        GroupWorkerStatus::Complete(revoot_core::GroupCompletion::Partial { causes, .. }) => {
            if causes.contains(&revoot_core::GroupPartialCause::BudgetExhausted) {
                SchedulerOutcome::Partial(GroupPartialReason::BudgetExhausted)
            } else {
                SchedulerOutcome::Partial(GroupPartialReason::ToolError)
            }
        }
        GroupWorkerStatus::Partial(GroupWorkerPartialReason::Cancelled) => {
            SchedulerOutcome::Cancelled
        }
        GroupWorkerStatus::Partial(
            GroupWorkerPartialReason::Budget | GroupWorkerPartialReason::TurnBudget,
        ) => SchedulerOutcome::Partial(GroupPartialReason::BudgetExhausted),
        GroupWorkerStatus::Partial(GroupWorkerPartialReason::Provider) => {
            SchedulerOutcome::Partial(GroupPartialReason::ProviderUnavailable)
        }
        GroupWorkerStatus::Partial(GroupWorkerPartialReason::Tool) => {
            SchedulerOutcome::Partial(GroupPartialReason::ToolError)
        }
        GroupWorkerStatus::Partial(
            GroupWorkerPartialReason::Coverage
            | GroupWorkerPartialReason::Context
            | GroupWorkerPartialReason::ProviderContract,
        ) => SchedulerOutcome::Partial(GroupPartialReason::CoverageIncomplete),
    }
}

fn has_dispatch_capacity(budget: &ReviewBudgetBroker, now_millis: u64) -> bool {
    if budget.ensure_dispatch_deadline(now_millis).is_err() {
        return false;
    }
    let snapshot = budget.snapshot();
    snapshot
        .usage
        .model_requests
        .saturating_add(snapshot.outstanding.model_requests)
        < snapshot.limits.max_model_requests
        && snapshot
            .usage
            .input_tokens
            .saturating_add(snapshot.usage.output_tokens)
            .saturating_add(snapshot.outstanding.input_tokens)
            .saturating_add(snapshot.outstanding.output_tokens)
            < snapshot.limits.max_model_tokens
        && snapshot
            .usage
            .output_tokens
            .saturating_add(snapshot.outstanding.output_tokens)
            < snapshot.limits.max_output_tokens
        && snapshot.usage.tool_calls < snapshot.limits.max_tool_calls
        && (snapshot.limits.max_cost_microusd == 0
            || snapshot
                .usage
                .cost_microusd
                .saturating_add(snapshot.outstanding.cost_microusd)
                < snapshot.limits.max_cost_microusd)
}

fn reduce_report(
    runtime: GroupRuntimeReport<()>,
    results: &Mutex<BTreeMap<ReviewGroupId, ExecutedReviewGroup>>,
) -> Result<ReviewGroupExecutionReport, ReviewGroupExecutionError> {
    let mut results = lock(results);
    let mut groups = Vec::with_capacity(results.len());
    for record in &runtime.schedule.records {
        if let Some(result) = results.remove(&record.group_id) {
            groups.push(result);
        }
    }
    if !results.is_empty() {
        return Err(ReviewGroupExecutionError::ResultBookkeeping);
    }
    Ok(ReviewGroupExecutionReport {
        groups,
        schedule: runtime.schedule,
        stop_reason: runtime.stop_reason,
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use revoot_core::provider::{ProviderErrorKind, ProviderFuture};
    use revoot_core::{
        AnchorTable, ChangedPath, FileChangeKind, Finding, FindingCategory, GitSha,
        GroupCompletion, LocalSnapshotIdentity, ModelContent, ModelFinishReason, ModelRequest,
        ModelResponse, ModelUsage, PartitionLimits, PreparedVerificationBatch,
        PreparedVerificationCandidate, ProposedReviewGroup, RepositoryDiff, RepositoryPath,
        RepositoryRelativePath, RepositoryToolLimits, ReviewEffort, ReviewFileClass,
        ReviewFileInput, ReviewGroupingSource, ReviewObject, ReviewObjectRole,
        ReviewSelectionPolicy, ReviewSnapshotIdentity, ReviewValue, ReviewValueReason,
        ReviewValueTier, Severity, Sha256Digest, VerifierSuppressionReason, build_partition_plan,
        build_review_group_plan,
    };
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::sync::Barrier;

    use crate::review_group_inputs::{derive_review_group_inputs, derive_selected_review_inputs};
    use crate::review_group_packet::{ReviewGroupPacketBindings, prepare_review_group_packet};
    use crate::rule_diagnostics::RuleDiagnosticPolicy;

    use super::*;

    const DIFF_A: &str = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1 +1 @@\n-old\n+new\n";
    const DIFF_B: &str = "diff --git a/src/b.rs b/src/b.rs\n--- a/src/b.rs\n+++ b/src/b.rs\n@@ -1 +1 @@\n-old\n+new\n";

    struct FixedClock;

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

    struct ConcurrentProvider {
        barrier: Arc<Barrier>,
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }

    impl ProviderAdapter for ConcurrentProvider {
        fn adapter_id(&self) -> &'static str {
            "concurrent-fake"
        }

        fn complete<'a>(
            &'a self,
            _request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            let barrier = Arc::clone(&self.barrier);
            let active = Arc::clone(&self.active);
            let maximum = Arc::clone(&self.maximum);
            Box::pin(async move {
                let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                maximum.fetch_max(current, Ordering::AcqRel);
                barrier.wait().await;
                active.fetch_sub(1, Ordering::AcqRel);
                Ok(tool_response("complete_group", complete_input()))
            })
        }
    }

    enum VerifierBehavior {
        Suppress,
        Fail,
    }

    struct VerifierProvider(VerifierBehavior);

    impl ProviderAdapter for VerifierProvider {
        fn adapter_id(&self) -> &'static str {
            "verifier-fake"
        }

        fn complete<'a>(
            &'a self,
            _request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            match self.0 {
                VerifierBehavior::Suppress => Box::pin(async {
                    Ok(text_response(
                        json!({
                            "schema_version":"revoot.verifier-decisions/v1",
                            "decisions":[{
                                "decision":"suppress",
                                "candidate_id":"candidate-1",
                                "reason":"insufficient_evidence"
                            }]
                        })
                        .to_string(),
                    ))
                }),
                VerifierBehavior::Fail => Box::pin(async {
                    Err(revoot_core::ProviderError::new(
                        ProviderErrorKind::Unavailable,
                        None,
                        true,
                    ))
                }),
            }
        }
    }

    struct IntegrationSetup {
        _directory: TempDir,
        plan: ReviewGroupPlan,
        prepared: Vec<PreparedReviewGroupExecution>,
        toolbox: Arc<revoot_core::RepositoryToolbox>,
        artifacts: Arc<DiffArtifactStore>,
    }

    #[allow(clippy::too_many_lines)]
    fn two_group_setup() -> IntegrationSetup {
        let directory = tempfile::tempdir().expect("temporary repository");
        fs::create_dir(directory.path().join("src")).expect("source directory");
        fs::write(directory.path().join("src/a.rs"), "new\n").expect("source A");
        fs::write(directory.path().join("src/b.rs"), "new\n").expect("source B");
        let paths = [repository_path("src/a.rs"), repository_path("src/b.rs")];
        let relative = [relative_path("src/a.rs"), relative_path("src/b.rs")];
        let diffs = [DIFF_A, DIFF_B];
        let snapshot = snapshot();
        let anchors = AnchorTable::build(snapshot.clone(), []).expect("anchor table");
        let inputs = paths
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
        let artifacts = Arc::new(
            DiffArtifactStore::create(relative.iter().zip(diffs), 32 * 1024)
                .expect("artifact store"),
        );
        let selected = derive_selected_review_inputs(
            &partition,
            artifacts.as_ref(),
            &RuleDiagnosticPolicy::default(),
        )
        .expect("selected inputs");
        let proposals = paths
            .iter()
            .cloned()
            .map(|path| ProposedReviewGroup { paths: vec![path] })
            .collect::<Vec<_>>();
        let plan =
            build_review_group_plan(&partition, Some(&proposals), ReviewGroupingSource::Semantic)
                .expect("group plan");
        let group_inputs =
            derive_review_group_inputs(&partition, &plan, &selected).expect("group inputs");
        let snapshot_sha256 =
            Sha256Digest::of_bytes(&serde_json::to_vec(&snapshot).expect("snapshot JSON"));
        let prepared = group_inputs
            .into_iter()
            .map(|input| {
                let bindings = ReviewGroupPacketBindings {
                    snapshot: snapshot.clone(),
                    snapshot_sha256: snapshot_sha256.clone(),
                    partition_sha256: input.partition_sha256.clone(),
                    group_plan_sha256: input.group_plan_sha256.clone(),
                    selected_input_sha256: input.selected_input_sha256.clone(),
                    system_policy_id: "policy-v1".to_owned(),
                    system_policy_sha256: Sha256Digest::of_bytes(b"policy"),
                };
                let packet = prepare_review_group_packet(
                    &input,
                    artifacts.as_ref(),
                    anchors.clone(),
                    &bindings,
                    ReviewEffort::Low,
                )
                .expect("prepared packet");
                PreparedReviewGroupExecution {
                    group_id: input.group.id,
                    packet,
                    prior_review: revoot_core::PriorReviewContext::default(),
                }
            })
            .collect();
        let cancellation = CancellationToken::default();
        let toolbox = Arc::new(
            revoot_core::RepositoryToolbox::open_selected(
                directory.path(),
                RepositoryToolLimits::default(),
                relative
                    .iter()
                    .cloned()
                    .zip(diffs)
                    .map(|(path, text)| RepositoryDiff {
                        path,
                        text: text.to_owned(),
                    }),
                relative.iter().cloned(),
                &cancellation,
            )
            .expect("repository toolbox"),
        );
        IntegrationSetup {
            _directory: directory,
            plan,
            prepared,
            toolbox,
            artifacts,
        }
    }

    fn execution_config() -> ReviewGroupExecutionConfig {
        ReviewGroupExecutionConfig {
            model: "model-v1".to_owned(),
            system_policy: "Use bounded tools and complete the assigned group.".to_owned(),
            max_parallel_groups: 2,
            worker_limits: GroupWorkerLimits::default(),
            verifier: ReviewVerifierConfig::new("model-v1"),
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

    fn complete_input() -> serde_json::Value {
        json!({
            "checkpoint": {
                "hypotheses": [],
                "evidence_references": [],
                "unresolved_coverage": []
            },
            "summary": {"text":"reviewed","assumptions":[]}
        })
    }

    fn tool_response(name: &str, input: serde_json::Value) -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "model-v1".to_owned(),
            content: vec![ModelContent::ToolUse {
                id: "call-1".to_owned(),
                name: name.to_owned(),
                input,
            }],
            finish_reason: ModelFinishReason::ToolUse,
            usage: ModelUsage::default(),
        }
    }

    fn text_response(text: String) -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "model-v1".to_owned(),
            content: vec![ModelContent::Text { text }],
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage::default(),
        }
    }

    fn scheduled_group() -> ScheduledReviewGroup {
        ScheduledReviewGroup {
            priority_position: 0,
            group: serde_json::from_value(json!({
                "id": format!("rg-{}", "a".repeat(64)),
                "files": [{
                    "path": {
                        "old_path": "src/a.rs",
                        "new_path": "src/a.rs",
                        "kind": "modified"
                    },
                    "tier": "low",
                    "input_bytes": DIFF_A.len(),
                    "anchor_ids": [],
                    "work_unit_id": format!("wu-{}", "b".repeat(64))
                }],
                "input_bytes": DIFF_A.len(),
                "anchor_count": 0
            }))
            .expect("review group"),
        }
    }

    fn candidate_worker_output(status: GroupWorkerStatus) -> GroupWorkerOutput {
        GroupWorkerOutput {
            candidates: PreparedVerificationBatch {
                candidates: vec![PreparedVerificationCandidate {
                    candidate_id: "candidate-1".to_owned(),
                    work_unit_id: format!("wu-{}", "b".repeat(64)),
                    target_path: repository_path("src/a.rs"),
                    finding: Finding {
                        anchor_id: format!("anchor-{}", "c".repeat(64)),
                        severity: Severity::Medium,
                        confidence_percent: 90,
                        category: FindingCategory::Correctness,
                        title: "Bounded title".to_owned(),
                        explanation: "Bounded explanation".to_owned(),
                        evidence: "Bounded evidence".to_owned(),
                        lineage_id: None,
                        suggested_replacement: None,
                    },
                    evidence_references: vec!["evidence:0001".to_owned()],
                }],
            },
            evidence: vec![crate::group_worker_engine::GroupWorkerEvidence {
                evidence_id: "evidence:0001".to_owned(),
                content: "bounded evidence".to_owned(),
            }],
            summary: GroupWorkerSummary {
                text: "reviewed".to_owned(),
                assumptions: Vec::new(),
            },
            status,
            coverage: GroupCoverageLedger::new([]).expect("coverage"),
            usage: AgentBudgetUsage {
                turns: 2,
                model_requests: 2,
                tool_calls: 3,
                candidate_findings: 1,
                ..AgentBudgetUsage::default()
            },
            provider_turns: 2,
            tool_calls: 3,
        }
    }

    #[tokio::test]
    async fn executes_two_groups_with_real_parallel_fanout() {
        let setup = two_group_setup();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let provider: Arc<dyn ProviderAdapter> = Arc::new(ConcurrentProvider {
            barrier: Arc::new(Barrier::new(2)),
            active,
            maximum: Arc::clone(&maximum),
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            execute_review_groups(
                &setup.plan,
                setup.prepared,
                provider,
                setup.toolbox,
                setup.artifacts,
                None,
                ReviewBudgetBroker::new(revoot_core::ReviewBudgetLimits::default(), 0)
                    .expect("budget"),
                CancellationToken::default(),
                Arc::new(FixedClock),
                execution_config(),
            ),
        )
        .await
        .expect("parallel execution did not deadlock")
        .expect("execution report");
        assert_eq!(maximum.load(Ordering::Acquire), 2);
        assert_eq!(result.groups.len(), 2);
        assert!(
            result
                .groups
                .iter()
                .all(|group| matches!(group.verification, GroupVerificationStatus::NoCandidates))
        );
        assert!(result.groups.iter().all(|group| group.provider_turns == 1));
        assert!(result.groups.iter().all(|group| group.tool_calls == 1));
        assert!(
            result
                .groups
                .iter()
                .all(|group| group.coverage.files.len() == 1)
        );
        assert!(result.groups.iter().all(|group| {
            group.usage.model_requests == 1
                && group.usage.tool_calls == 1
                && group.usage.input_tokens > 0
                && group.usage.output_tokens == 4_096
        }));
        assert_eq!(result.schedule.records.len(), 2);
        assert_eq!(result.stop_reason, None);
    }

    #[tokio::test]
    async fn verifier_suppression_is_retained_as_verified_accounting() {
        let results = Mutex::new(BTreeMap::new());
        let result = finish_worker(
            scheduled_group(),
            candidate_worker_output(GroupWorkerStatus::Complete(GroupCompletion::Complete {
                policy_version: "coverage-v1".to_owned(),
                low_risk_deferrals: 0,
            })),
            &VerifierProvider(VerifierBehavior::Suppress),
            &ReviewVerifierConfig::new("model-v1"),
            &ReviewBudgetBroker::new(revoot_core::ReviewBudgetLimits::default(), 0)
                .expect("budget"),
            &CancellationToken::default(),
            &FixedClock,
            &results,
        )
        .await;
        assert!(matches!(result, GroupWorkerResult::Complete(())));
        let stored = lock(&results);
        let group = stored.values().next().expect("stored group");
        let GroupVerificationStatus::Verified {
            accepted,
            suppressed,
        } = &group.verification
        else {
            panic!("expected verified suppression accounting")
        };
        assert!(accepted.is_empty());
        assert_eq!(suppressed.len(), 1);
        assert_eq!(
            suppressed[0].reason,
            VerifierSuppressionReason::InsufficientEvidence
        );
    }

    #[tokio::test]
    async fn verifier_failure_retains_metadata_but_no_verified_result() {
        let results = Mutex::new(BTreeMap::new());
        let result = finish_worker(
            scheduled_group(),
            candidate_worker_output(GroupWorkerStatus::Partial(
                GroupWorkerPartialReason::Provider,
            )),
            &VerifierProvider(VerifierBehavior::Fail),
            &ReviewVerifierConfig::new("model-v1"),
            &ReviewBudgetBroker::new(revoot_core::ReviewBudgetLimits::default(), 0)
                .expect("budget"),
            &CancellationToken::default(),
            &FixedClock,
            &results,
        )
        .await;
        assert!(matches!(
            result,
            GroupWorkerResult::Partial {
                reason: GroupPartialReason::VerificationFailed,
                verified_result: None
            }
        ));
        let stored = lock(&results);
        let group = stored.values().next().expect("metadata retained");
        assert_eq!(group.provider_turns, 2);
        assert_eq!(group.tool_calls, 3);
        assert!(matches!(
            group.verification,
            GroupVerificationStatus::UnverifiedPartial {
                reason: ReviewVerifierFailureReason::ProviderFailure,
                ..
            }
        ));
    }

    #[test]
    fn verifier_failure_is_never_classified_as_verified() {
        let (status, failed) =
            verification_status(ReviewVerifierOutcome::Partial(PartialVerifierSuppression {
                reason: ReviewVerifierFailureReason::ProviderFailure,
                suppressed_candidate_ids: vec!["candidate-1".to_owned()],
            }));
        assert!(failed);
        assert!(matches!(
            status,
            GroupVerificationStatus::UnverifiedPartial { .. }
        ));
    }

    #[test]
    fn dispatch_capacity_accounts_for_outstanding_reservations() {
        let budget =
            ReviewBudgetBroker::new(revoot_core::ReviewBudgetLimits::default(), 0).expect("budget");
        assert!(has_dispatch_capacity(&budget, 0));
        let _permit = budget
            .reserve_model_request(
                revoot_core::ReviewModelReservation {
                    input_tokens: 299_000,
                    output_tokens: 1_000,
                    cost_microusd: 0,
                },
                0,
            )
            .expect("permit");
        assert!(!has_dispatch_capacity(&budget, 0));
    }

    #[test]
    fn dispatch_capacity_closes_at_aggregate_deadline() {
        let limits = revoot_core::ReviewBudgetLimits {
            max_elapsed_millis: 10,
            ..revoot_core::ReviewBudgetLimits::default()
        };
        let budget = ReviewBudgetBroker::new(limits, 5).expect("budget");
        assert!(has_dispatch_capacity(&budget, 15));
        assert!(!has_dispatch_capacity(&budget, 16));
    }
}
