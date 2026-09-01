//! End-to-end trusted preparation for the tool-first review engine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use revoot_core::provider::ProviderAdapter;
use revoot_core::{
    AnchorTable, CancellationToken, RepositoryRelativePath, RepositoryToolbox, ReviewBudgetBroker,
    ReviewEffort, ReviewGroupId, ReviewGroupPlan, ReviewPartitionPlan, Sha256Digest,
};

use crate::diff_artifact::{DEFAULT_DIFF_PAGE_BYTES, DiffArtifactStore};
use crate::review_group_inputs::{
    TrustedSelectedReviewInputs, derive_review_group_inputs, derive_selected_review_inputs,
};
use crate::review_group_packet::{
    PreparedReviewGroupPacket, ReviewGroupPacketBindings, prepare_review_group_packet,
};
use crate::review_grouper::{
    ReviewGrouperClock, ReviewGrouperConfig, ReviewGrouperMode, run_review_grouper,
};
use crate::rule_diagnostics::RuleDiagnosticPolicy;

/// Trusted run-wide identities copied into every isolated packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPreparationBindings {
    pub snapshot_sha256: Sha256Digest,
    pub partition_sha256: Sha256Digest,
    pub system_policy_id: String,
    pub system_policy_sha256: Sha256Digest,
}

/// Complete trusted input to one preparation invocation.
pub struct ToolFirstPreparationInput<'a> {
    pub repository: &'a RepositoryToolbox,
    pub partition: &'a ReviewPartitionPlan,
    pub anchor_table: AnchorTable,
    pub rule_policy: &'a RuleDiagnosticPolicy,
    pub bindings: ReviewPreparationBindings,
    pub grouper: ReviewGrouperConfig,
    pub effort: ReviewEffort,
    pub diff_page_bytes: usize,
}

impl<'a> ToolFirstPreparationInput<'a> {
    #[must_use]
    pub fn with_defaults(
        repository: &'a RepositoryToolbox,
        partition: &'a ReviewPartitionPlan,
        anchor_table: AnchorTable,
        rule_policy: &'a RuleDiagnosticPolicy,
        bindings: ReviewPreparationBindings,
        model: impl Into<String>,
    ) -> Self {
        Self {
            repository,
            partition,
            anchor_table,
            rule_policy,
            bindings,
            grouper: ReviewGrouperConfig::new(model),
            effort: ReviewEffort::Medium,
            diff_page_bytes: DEFAULT_DIFF_PAGE_BYTES,
        }
    }
}

/// Owning preparation output. The private artifact directory remains alive for
/// exactly as long as this value and is removed by its RAII drop path.
pub struct ToolFirstPreparedReview {
    pub artifacts: DiffArtifactStore,
    pub selected_inputs: TrustedSelectedReviewInputs,
    pub group_plan: ReviewGroupPlan,
    pub grouping_mode: ReviewGrouperMode,
    pub packets: BTreeMap<ReviewGroupId, PreparedReviewGroupPacket>,
}

impl fmt::Debug for ToolFirstPreparedReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolFirstPreparedReview")
            .field("artifact_count", &self.artifacts.artifact_count())
            .field("group_count", &self.group_plan.groups.len())
            .field("grouping_mode", &self.grouping_mode)
            .field("packet_count", &self.packets.len())
            .finish_non_exhaustive()
    }
}

/// Payload-free preparation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewPreparationError {
    Cancelled,
    PartitionBinding,
    SnapshotBinding,
    RepositoryDiff,
    Artifact,
    SelectedInputs,
    Grouping,
    GroupInputs,
    Packet,
    GroupAssignment,
    Serialization,
}

/// Prepare private artifacts, metadata-only grouping, and every group packet.
///
/// # Errors
///
/// Fails closed on stale snapshot/partition identities, missing selected diffs,
/// invalid trusted metadata, cancellation, or any group packet that cannot be
/// prepared completely. Provider and grouping-response failures are handled by
/// the grouper's deterministic fallback and are not preparation errors.
pub async fn prepare_tool_first_review(
    input: ToolFirstPreparationInput<'_>,
    adapter: &dyn ProviderAdapter,
    budget: &ReviewBudgetBroker,
    cancellation: &CancellationToken,
    clock: &dyn ReviewGrouperClock,
) -> Result<ToolFirstPreparedReview, ReviewPreparationError> {
    validate_run_bindings(&input)?;
    if cancellation.is_cancelled() {
        return Err(ReviewPreparationError::Cancelled);
    }
    let selected_paths = selected_paths(input.partition)?;
    let exact_diffs = input
        .repository
        .exact_diffs()
        .map(|(path, text)| (path.clone(), text))
        .collect::<BTreeMap<_, _>>();
    let selected_diffs = selected_paths
        .iter()
        .map(|path| {
            exact_diffs
                .get(path)
                .copied()
                .map(|text| (path, text))
                .ok_or(ReviewPreparationError::RepositoryDiff)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let artifacts = DiffArtifactStore::create(selected_diffs, input.diff_page_bytes)
        .map_err(|_| ReviewPreparationError::Artifact)?;
    finish_preparation(input, artifacts, adapter, budget, cancellation, clock).await
}

async fn finish_preparation(
    input: ToolFirstPreparationInput<'_>,
    artifacts: DiffArtifactStore,
    adapter: &dyn ProviderAdapter,
    budget: &ReviewBudgetBroker,
    cancellation: &CancellationToken,
    clock: &dyn ReviewGrouperClock,
) -> Result<ToolFirstPreparedReview, ReviewPreparationError> {
    let selected_inputs =
        derive_selected_review_inputs(input.partition, &artifacts, input.rule_policy)
            .map_err(|_| ReviewPreparationError::SelectedInputs)?;
    let grouping = run_review_grouper(
        adapter,
        &input.grouper,
        input.partition,
        Some(selected_inputs.grouping_facts()),
        budget,
        cancellation,
        clock,
    )
    .await
    .map_err(|_| ReviewPreparationError::Grouping)?;
    let group_inputs =
        derive_review_group_inputs(input.partition, &grouping.plan, &selected_inputs)
            .map_err(|_| ReviewPreparationError::GroupInputs)?;
    if group_inputs.len() != grouping.plan.groups.len() {
        return Err(ReviewPreparationError::GroupAssignment);
    }
    let mut packets = BTreeMap::new();
    for group_input in group_inputs {
        let group_id = group_input.group.id.clone();
        let packet = prepare_review_group_packet(
            &group_input,
            &artifacts,
            input.anchor_table.clone(),
            &ReviewGroupPacketBindings {
                snapshot: input.partition.snapshot.clone(),
                snapshot_sha256: input.bindings.snapshot_sha256.clone(),
                partition_sha256: input.bindings.partition_sha256.clone(),
                group_plan_sha256: grouping.plan.plan_sha256.clone(),
                selected_input_sha256: selected_inputs.input_sha256().clone(),
                system_policy_id: input.bindings.system_policy_id.clone(),
                system_policy_sha256: input.bindings.system_policy_sha256.clone(),
            },
            input.effort,
        )
        .map_err(|_| ReviewPreparationError::Packet)?;
        if packets.insert(group_id, packet).is_some() {
            return Err(ReviewPreparationError::GroupAssignment);
        }
    }
    if packets.len() != grouping.plan.groups.len()
        || grouping
            .plan
            .groups
            .iter()
            .any(|group| !packets.contains_key(&group.id))
    {
        return Err(ReviewPreparationError::GroupAssignment);
    }
    Ok(ToolFirstPreparedReview {
        artifacts,
        selected_inputs,
        group_plan: grouping.plan,
        grouping_mode: grouping.mode,
        packets,
    })
}

fn validate_run_bindings(
    input: &ToolFirstPreparationInput<'_>,
) -> Result<(), ReviewPreparationError> {
    input
        .partition
        .validate_replay()
        .map_err(|_| ReviewPreparationError::PartitionBinding)?;
    if input.partition.work_units.is_empty()
        || input.partition.plan_sha256 != input.bindings.partition_sha256
    {
        return Err(ReviewPreparationError::PartitionBinding);
    }
    if input.anchor_table.identity() != &input.partition.snapshot {
        return Err(ReviewPreparationError::SnapshotBinding);
    }
    let snapshot = serde_json::to_vec(&input.partition.snapshot)
        .map_err(|_| ReviewPreparationError::Serialization)?;
    if Sha256Digest::of_bytes(&snapshot) != input.bindings.snapshot_sha256 {
        return Err(ReviewPreparationError::SnapshotBinding);
    }
    Ok(())
}

fn selected_paths(
    partition: &ReviewPartitionPlan,
) -> Result<BTreeSet<RepositoryRelativePath>, ReviewPreparationError> {
    let paths = partition
        .work_units
        .iter()
        .flat_map(|unit| &unit.files)
        .map(|file| {
            RepositoryRelativePath::try_from(file.path.new_path.as_str().to_owned())
                .map_err(|_| ReviewPreparationError::RepositoryDiff)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let file_count = partition
        .work_units
        .iter()
        .map(|unit| unit.files.len())
        .sum::<usize>();
    if paths.len() != file_count || paths.is_empty() {
        return Err(ReviewPreparationError::RepositoryDiff);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use revoot_core::provider::{ProviderError, ProviderErrorKind, ProviderFuture};
    use revoot_core::{
        AnchorPosition, ChangedPath, CommentableLine, FileChangeKind, LocalSnapshotIdentity,
        ModelContent, ModelFinishReason, ModelRequest, ModelResponse, ModelUsage, PartitionLimits,
        RepositoryDiff, RepositoryPath, RepositoryToolLimits, ReviewFileClass, ReviewFileInput,
        ReviewObject, ReviewObjectRole, ReviewSelectionPolicy, ReviewValue, ReviewValueReason,
        ReviewValueTier, build_partition_plan,
    };
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    struct TestClock(AtomicU64);

    impl Default for TestClock {
        fn default() -> Self {
            Self(AtomicU64::new(1))
        }
    }

    impl ReviewGrouperClock for TestClock {
        fn now_millis(&self) -> u64 {
            self.0.fetch_add(1, Ordering::Relaxed)
        }
    }

    struct FakeAdapter {
        results: Mutex<VecDeque<Result<ModelResponse, ProviderError>>>,
        requests: Mutex<Vec<ModelRequest>>,
    }

    impl FakeAdapter {
        fn new(results: Vec<Result<ModelResponse, ProviderError>>) -> Self {
            Self {
                results: Mutex::new(results.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().expect("requests").len()
        }
    }

    impl ProviderAdapter for FakeAdapter {
        fn adapter_id(&self) -> &'static str {
            "fake"
        }

        fn complete<'a>(
            &'a self,
            request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("requests")
                    .push(request.clone());
                self.results
                    .lock()
                    .expect("results")
                    .pop_front()
                    .unwrap_or_else(|| {
                        Err(ProviderError::new(ProviderErrorKind::Protocol, None, false))
                    })
            })
        }
    }

    #[tokio::test]
    async fn small_selection_uses_zero_grouping_calls() {
        let context = fixture_context(3, false);
        let adapter = FakeAdapter::new(Vec::new());
        let mut input = context.input("");
        input.effort = ReviewEffort::Low;
        let prepared = prepare_tool_first_review(
            input,
            &adapter,
            &budget(),
            &CancellationToken::default(),
            &TestClock::default(),
        )
        .await
        .expect("prepared");
        assert_eq!(adapter.request_count(), 0);
        assert_eq!(
            prepared.grouping_mode,
            ReviewGrouperMode::DeterministicSmallSelection
        );
        assert_eq!(prepared.artifacts.artifact_count(), 3);
        assert_eq!(prepared.packets.len(), prepared.group_plan.groups.len());
    }

    #[tokio::test]
    async fn larger_selection_groups_on_metadata_and_falls_back_safely() {
        let context = fixture_context(4, false);
        let paths = context.paths();
        let adapter = FakeAdapter::new(vec![Ok(grouping_response(&paths))]);
        let prepared = prepare_tool_first_review(
            context.input("fixture-model"),
            &adapter,
            &budget(),
            &CancellationToken::default(),
            &TestClock::default(),
        )
        .await
        .expect("semantic preparation");
        assert_eq!(prepared.grouping_mode, ReviewGrouperMode::Semantic);
        assert_eq!(adapter.request_count(), 1);
        assert_metadata_only_request(&adapter);

        let context = fixture_context(4, false);
        let adapter = FakeAdapter::new(vec![Err(ProviderError::new(
            ProviderErrorKind::Unavailable,
            Some(503),
            true,
        ))]);
        let prepared = prepare_tool_first_review(
            context.input("fixture-model"),
            &adapter,
            &budget(),
            &CancellationToken::default(),
            &TestClock::default(),
        )
        .await
        .expect("fallback preparation");
        assert_eq!(
            prepared.grouping_mode,
            ReviewGrouperMode::DeterministicFallback(
                crate::review_grouper::ReviewGrouperFallbackReason::ProviderFailure
            )
        );
        assert_eq!(prepared.packets.len(), prepared.group_plan.groups.len());
    }

    fn assert_metadata_only_request(adapter: &FakeAdapter) {
        let requests = adapter.requests.lock().expect("requests");
        assert!(requests[0].tools.is_empty());
        let ModelContent::Text { text } = &requests[0].messages[0].content[0] else {
            panic!("metadata request expected")
        };
        assert!(!text.contains("PRIVATE_DIFF_SENTINEL"));
        let value: serde_json::Value = serde_json::from_str(text).expect("metadata JSON");
        assert_eq!(
            value
                .as_object()
                .expect("object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["files", "partition_sha256", "schema_version"])
        );
    }

    #[tokio::test]
    async fn large_selected_diff_stays_manifest_only() {
        let context = fixture_context(1, true);
        let adapter = FakeAdapter::new(Vec::new());
        let prepared = prepare_tool_first_review(
            context.input(""),
            &adapter,
            &budget(),
            &CancellationToken::default(),
            &TestClock::default(),
        )
        .await
        .expect("large preparation");
        let packet = &prepared
            .packets
            .values()
            .next()
            .expect("packet")
            .initial_packet;
        assert!(matches!(
            &packet.complete_diff,
            Some(revoot_core::review_packet::ReviewPacketCompleteDiff::LargeManifestOnly { .. })
        ));
        assert_eq!(packet.token_estimates.inline_request_tokens, None);
    }

    #[tokio::test]
    async fn artifact_directory_cleans_on_drop_and_error() {
        let context = fixture_context(1, false);
        let prepared = prepare_tool_first_review(
            context.input(""),
            &FakeAdapter::new(Vec::new()),
            &budget(),
            &CancellationToken::default(),
            &TestClock::default(),
        )
        .await
        .expect("prepared");
        let directory = prepared.artifacts.directory_path().to_path_buf();
        assert!(directory.is_dir());
        drop(prepared);
        assert!(!directory.exists());

        let context = fixture_context(4, false);
        let artifacts = materialize(&context);
        let directory = artifacts.directory_path().to_path_buf();
        let error = finish_preparation(
            context.input(""),
            artifacts,
            &FakeAdapter::new(Vec::new()),
            &budget(),
            &CancellationToken::default(),
            &TestClock::default(),
        )
        .await
        .expect_err("invalid grouping config");
        assert_eq!(error, ReviewPreparationError::Grouping);
        assert!(!directory.exists());
    }

    struct TestContext {
        _root: TempDir,
        repository: RepositoryToolbox,
        partition: ReviewPartitionPlan,
        anchors: AnchorTable,
        bindings: ReviewPreparationBindings,
        diffs: Vec<RepositoryDiff>,
        rule_policy: RuleDiagnosticPolicy,
    }

    impl TestContext {
        fn input(&self, model: &str) -> ToolFirstPreparationInput<'_> {
            ToolFirstPreparationInput {
                repository: &self.repository,
                partition: &self.partition,
                anchor_table: self.anchors.clone(),
                rule_policy: &self.rule_policy,
                bindings: self.bindings.clone(),
                grouper: ReviewGrouperConfig::new(model),
                effort: ReviewEffort::Medium,
                diff_page_bytes: 8 * 1024,
            }
        }

        fn paths(&self) -> Vec<&str> {
            self.diffs.iter().map(|diff| diff.path.as_str()).collect()
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps all cryptographically bound review inputs visibly consistent"
    )]
    fn fixture_context(count: usize, large: bool) -> TestContext {
        let root = TempDir::new().expect("root");
        let snapshot = revoot_core::ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
            repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
            base_sha: "a".repeat(40).try_into().expect("base"),
            head_sha: "b".repeat(40).try_into().expect("head"),
            working_tree_sha256: Sha256Digest::of_bytes(b"tree"),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
        });
        let changed = (0..count)
            .map(|index| {
                let path = RepositoryPath::try_from(format!("src/file-{index}.rs")).expect("path");
                ChangedPath {
                    old_path: path.clone(),
                    new_path: path,
                    kind: FileChangeKind::Modified,
                }
            })
            .collect::<Vec<_>>();
        let anchors = AnchorTable::build(
            snapshot.clone(),
            changed.iter().map(|path| CommentableLine {
                path: path.clone(),
                position: AnchorPosition::addition(1).expect("anchor"),
                exact_line_digest: Sha256Digest::of_bytes(path.new_path.as_str().as_bytes()),
                context_digest: Sha256Digest::of_bytes(b"context"),
            }),
        )
        .expect("anchors");
        let diffs = changed
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let added = if large {
                    format!("+{}\n", "x".repeat(17_000))
                } else {
                    "+PRIVATE_DIFF_SENTINEL\n".to_owned()
                };
                RepositoryDiff {
                    path: RepositoryRelativePath::try_from(path.new_path.as_str().to_owned())
                        .expect("relative path"),
                    text: format!(
                        "diff --git a/{0} b/{0}\n--- a/{0}\n+++ b/{0}\n@@ -1 +1 @@\n-old-{index}\n{added}",
                        path.new_path.as_str()
                    ),
                }
            })
            .collect::<Vec<_>>();
        for diff in &diffs {
            let file = root.path().join(diff.path.as_str());
            fs::create_dir_all(file.parent().expect("parent")).expect("directory");
            fs::write(file, b"post-change\n").expect("file");
        }
        let inputs = changed
            .iter()
            .zip(&diffs)
            .map(|(path, diff)| ReviewFileInput {
                path: path.clone(),
                class: ReviewFileClass::Text,
                review_value: ReviewValue {
                    tier: ReviewValueTier::Standard,
                    score: 100,
                    reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                },
                objects: vec![ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: Sha256Digest::of_bytes(diff.text.as_bytes()),
                    size_bytes: u64::try_from(diff.text.len()).expect("diff bytes"),
                }],
                anchor_ids: anchors
                    .iter()
                    .filter(|anchor| anchor.path == *path)
                    .map(|anchor| anchor.id.clone())
                    .collect(),
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
                max_files_per_work_unit: 20,
                max_bytes_per_work_unit: 100_000,
                max_anchors_per_work_unit: 100,
            },
            inputs,
        )
        .expect("partition");
        let repository = RepositoryToolbox::open_selected(
            root.path(),
            RepositoryToolLimits::default(),
            diffs.clone(),
            diffs.iter().map(|diff| diff.path.clone()),
            &CancellationToken::default(),
        )
        .expect("repository");
        let bindings = ReviewPreparationBindings {
            snapshot_sha256: Sha256Digest::of_bytes(
                &serde_json::to_vec(&snapshot).expect("snapshot JSON"),
            ),
            partition_sha256: partition.plan_sha256.clone(),
            system_policy_id: "review-policy-v1".to_owned(),
            system_policy_sha256: Sha256Digest::of_bytes(b"policy"),
        };
        TestContext {
            _root: root,
            repository,
            partition,
            anchors,
            bindings,
            diffs,
            rule_policy: RuleDiagnosticPolicy::default(),
        }
    }

    fn materialize(context: &TestContext) -> DiffArtifactStore {
        let paths = selected_paths(&context.partition).expect("selected paths");
        let exact = context
            .repository
            .exact_diffs()
            .map(|(path, text)| (path.clone(), text))
            .collect::<BTreeMap<_, _>>();
        DiffArtifactStore::create(
            paths
                .iter()
                .map(|path| (path, *exact.get(path).expect("selected diff"))),
            8 * 1024,
        )
        .expect("artifacts")
    }

    fn grouping_response(paths: &[&str]) -> ModelResponse {
        ModelResponse {
            provider_response_id: None,
            model: "fixture-model".to_owned(),
            content: vec![ModelContent::Text {
                text: serde_json::to_string(&json!({
                    "schema_version": "revoot.grouping-proposal/v1",
                    "groups": [
                        {"paths": &paths[..2]},
                        {"paths": &paths[2..]},
                    ]
                }))
                .expect("response"),
            }],
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage {
                input_tokens: 100,
                output_tokens: 30,
                cached_input_tokens: 0,
            },
        }
    }

    fn budget() -> ReviewBudgetBroker {
        ReviewBudgetBroker::new(revoot_core::ReviewBudgetLimits::default(), 0).expect("budget")
    }
}
