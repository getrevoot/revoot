//! End-to-end token-efficiency acceptance over captured native model requests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::{Arc, Mutex};

use revoot::config::RepositoryReviewPolicy;
use revoot::group_worker_engine::GroupWorkerClock;
use revoot::review_adjudicator::ReviewAdjudicatorClock;
use revoot::review_grouper::ReviewGrouperClock;
use revoot::review_verifier::ReviewVerifierClock;
use revoot::tool_first_engine::{
    ToolFirstEngineLimits, ToolFirstEngineRequest, run_tool_first_engine,
};
use revoot_core::provider::{ProviderAdapter, ProviderFuture};
use revoot_core::{
    AnchorPosition, AnchorTable, CancellationToken, ChangedPath, CommentableLine, EfficiencyGroup,
    EfficiencyHunkDelivery, EfficiencyPhase, EfficiencyRequest, EfficiencyToolResult,
    FileChangeKind, GitSha, LocalSnapshotIdentity, ModelContent, ModelFinishReason, ModelRequest,
    ModelResponse, ModelUsage, PartitionLimits, PriorReviewContext, RepositoryDiff, RepositoryPath,
    RepositoryRelativePath, RepositoryToolLimits, RepositoryToolbox, ReviewBudgetBroker,
    ReviewBudgetLimits, ReviewEffort, ReviewFileClass, ReviewFileInput, ReviewObject,
    ReviewObjectRole, ReviewReportPhase, ReviewSelectionPolicy, ReviewSnapshotIdentity,
    ReviewValue, ReviewValueReason, ReviewValueTier, Sha256Digest, build_partition_plan,
    measure_token_efficiency,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const FILE_COUNT: usize = 100;
const SELECTED_DIFF_BYTES: usize = 1024 * 1024;
const REQUEST_TOKEN_TARGET: usize = 32_000;
const TOOL_RESULT_LIMIT: usize = 32 * 1024;
const DIFF_MARKER: &str = "REVOOT_EFFICIENCY_DIFF_BODY_MARKER";

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

struct CapturingProvider {
    paths: Vec<String>,
    requests: Mutex<Vec<ModelRequest>>,
    stages: Mutex<BTreeMap<String, u8>>,
}

impl CapturingProvider {
    fn new(paths: Vec<String>) -> Self {
        Self {
            paths,
            requests: Mutex::new(Vec::new()),
            stages: Mutex::new(BTreeMap::new()),
        }
    }

    fn captured(&self) -> Vec<ModelRequest> {
        self.requests.lock().expect("requests").clone()
    }

    fn response(&self, request: &ModelRequest) -> ModelResponse {
        let usage = ModelUsage {
            input_tokens: u64::try_from(serde_json::to_vec(request).expect("request JSON").len())
                .expect("input tokens"),
            output_tokens: 64,
            cached_input_tokens: 0,
        };
        if request.tools.is_empty() {
            let groups = self
                .paths
                .chunks(10)
                .map(|paths| json!({"paths": paths}))
                .collect::<Vec<_>>();
            return text_response(
                json!({
                    "schema_version": "revoot.grouping-proposal/v1",
                    "groups": groups,
                })
                .to_string(),
                usage,
            );
        }

        let packet = packet(request);
        let group_id = packet["group_id"].as_str().expect("group ID").to_owned();
        let mut stages = self.stages.lock().expect("stages");
        let stage = stages.entry(group_id.clone()).or_default();
        let call_id = format!("call-{}-{}", *stage, &group_id[group_id.len() - 8..]);
        let response = match *stage {
            0 => {
                assert_eq!(packet["purpose"], "group_initial");
                assert_eq!(packet["diff"]["mode"], "manifest_only");
                let files = packet["files"].as_array().expect("file briefs");
                if let Some(file) = files
                    .iter()
                    .find(|file| !file["hunk_ids"].as_array().expect("hunks").is_empty())
                {
                    tool_response(
                        call_id,
                        "read_diff",
                        json!({"reads":[{
                            "path": file["path"],
                            "hunk_id": file["hunk_ids"][0],
                            "page": 1
                        }]}),
                        usage,
                    )
                } else {
                    tool_response(call_id, "diff_manifest", json!({}), usage)
                }
            }
            1 => tool_response(
                call_id,
                "checkpoint_review",
                json!({"checkpoint": empty_checkpoint()}),
                usage,
            ),
            2 => tool_response(
                call_id,
                "complete_group",
                json!({
                    "checkpoint": empty_checkpoint(),
                    "summary": {"text": "reviewed", "assumptions": []}
                }),
                usage,
            ),
            _ => panic!("unexpected provider stage"),
        };
        *stage += 1;
        response
    }
}

impl ProviderAdapter for CapturingProvider {
    fn adapter_id(&self) -> &'static str {
        "capturing-efficiency"
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
        let response = self.response(request);
        Box::pin(async move { Ok(response) })
    }
}

fn empty_checkpoint() -> Value {
    json!({"hypotheses":[], "evidence_references":[], "unresolved_coverage":[]})
}

fn text_response(text: String, usage: ModelUsage) -> ModelResponse {
    ModelResponse {
        provider_response_id: None,
        model: "efficiency-model".to_owned(),
        content: vec![ModelContent::Text { text }],
        finish_reason: ModelFinishReason::Stop,
        usage,
    }
}

fn tool_response(id: String, name: &str, input: Value, usage: ModelUsage) -> ModelResponse {
    ModelResponse {
        provider_response_id: None,
        model: "efficiency-model".to_owned(),
        content: vec![ModelContent::ToolUse {
            id,
            name: name.to_owned(),
            input,
        }],
        finish_reason: ModelFinishReason::ToolUse,
        usage,
    }
}

fn packet(request: &ModelRequest) -> Value {
    let text = request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .find_map(|content| match content {
            ModelContent::Text { text } => Some(text),
            ModelContent::ToolUse { .. } | ModelContent::ToolResult { .. } => None,
        })
        .expect("packet text");
    serde_json::from_str(text).expect("packet JSON")
}

struct Setup {
    _directory: TempDir,
    toolbox: Arc<RepositoryToolbox>,
    partition: revoot_core::ReviewPartitionPlan,
    anchors: AnchorTable,
    paths: Vec<String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete immutable 100-file fixture is kept together so every measured request derives from one preparation"
)]
fn setup() -> Setup {
    let directory = tempfile::tempdir().expect("repository");
    let paths = (0..FILE_COUNT)
        .map(|index| format!("d{index:03}/f{index:03}"))
        .collect::<Vec<_>>();
    let base = SELECTED_DIFF_BYTES / FILE_COUNT;
    let remainder = SELECTED_DIFF_BYTES % FILE_COUNT;
    let diffs = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let target = base + usize::from(index < remainder);
            if index == 0 {
                changed_diff(path, target)
            } else {
                metadata_rename_diff(path, target)
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        diffs.iter().map(String::len).sum::<usize>(),
        SELECTED_DIFF_BYTES
    );
    for path in &paths {
        fs::create_dir_all(directory.path().join(path).parent().expect("source parent"))
            .expect("source directory");
        fs::write(directory.path().join(path), "new\n").expect("source file");
    }

    let changed_paths = paths
        .iter()
        .map(|path| ChangedPath {
            old_path: RepositoryPath::try_from(format!("{path}.old")).expect("old path"),
            new_path: RepositoryPath::try_from(path.clone()).expect("new path"),
            kind: FileChangeKind::Renamed,
        })
        .collect::<Vec<_>>();
    let snapshot = snapshot();
    let anchors = AnchorTable::build(
        snapshot.clone(),
        changed_paths.iter().map(|path| CommentableLine {
            path: path.clone(),
            position: AnchorPosition::deletion(1).expect("deletion anchor"),
            exact_line_digest: Sha256Digest::of_bytes(path.old_path.as_str().as_bytes()),
            context_digest: Sha256Digest::of_bytes(b"efficiency-context"),
        }),
    )
    .expect("anchors");
    let anchor_ids = anchors
        .iter()
        .map(|anchor| (anchor.path.new_path.clone(), anchor.id.clone()))
        .collect::<BTreeMap<_, _>>();
    let inputs = changed_paths
        .iter()
        .zip(&diffs)
        .map(|(path, diff)| ReviewFileInput {
            path: path.clone(),
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
            anchor_ids: vec![anchor_ids[&path.new_path].clone()],
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
            max_file_bytes: 20_000,
        },
        PartitionLimits {
            max_files: 100,
            max_total_bytes: u64::try_from(SELECTED_DIFF_BYTES).expect("selected bytes"),
            max_work_units: 100,
            max_files_per_work_unit: 10,
            max_bytes_per_work_unit: 120_000,
            max_anchors_per_work_unit: 100,
        },
        inputs,
    )
    .expect("partition");
    assert_eq!(partition.coverage.included_files, 100);
    assert_eq!(
        partition.coverage.included_bytes,
        u64::try_from(SELECTED_DIFF_BYTES).expect("selected bytes")
    );
    let cancellation = CancellationToken::default();
    let toolbox = Arc::new(
        RepositoryToolbox::open_selected(
            directory.path(),
            RepositoryToolLimits::default(),
            paths.iter().zip(&diffs).map(|(path, text)| RepositoryDiff {
                path: RepositoryRelativePath::try_from(path.clone()).expect("relative path"),
                text: text.clone(),
            }),
            paths
                .iter()
                .map(|path| RepositoryRelativePath::try_from(path.clone()).expect("relative path")),
            &cancellation,
        )
        .expect("toolbox"),
    );
    Setup {
        _directory: directory,
        toolbox,
        partition,
        anchors,
        paths,
    }
}

fn changed_diff(path: &str, target: usize) -> String {
    padded_diff(
        format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n {DIFF_MARKER} "
        ),
        target,
    )
}

fn metadata_rename_diff(path: &str, target: usize) -> String {
    padded_diff(
        format!(
            "diff --git a/{path}.old b/{path}\nsimilarity index 100%\nrename from {path}.old\nrename to {path}\n{DIFF_MARKER} "
        ),
        target,
    )
}

fn padded_diff(mut value: String, target: usize) -> String {
    assert!(value.len() < target);
    value.push_str(&"x".repeat(target - value.len() - 1));
    value.push('\n');
    assert_eq!(value.len(), target);
    value
}

fn snapshot() -> ReviewSnapshotIdentity {
    ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
        repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
        base_sha: GitSha::try_from("a".repeat(40)).expect("base"),
        head_sha: GitSha::try_from("b".repeat(40)).expect("head"),
        working_tree_sha256: Sha256Digest::of_bytes(b"working-tree"),
        exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
    })
}

fn engine_request(
    setup: Setup,
    provider: Arc<CapturingProvider>,
) -> ToolFirstEngineRequest<FixedClock> {
    let mut limits = ToolFirstEngineLimits::new("efficiency-model");
    limits.effort = ReviewEffort::Medium;
    limits.max_parallel_groups = 4;
    limits.diff_page_bytes = 24 * 1024;
    ToolFirstEngineRequest {
        provider,
        toolbox: setup.toolbox,
        history: None,
        prior_review: PriorReviewContext::default(),
        anchor_table: setup.anchors,
        partition: setup.partition,
        rule_policy: RepositoryReviewPolicy::default(),
        budget: ReviewBudgetBroker::new(
            ReviewBudgetLimits {
                max_model_requests: 256,
                max_model_tokens: 2_000_000,
                max_output_tokens: 1_000_000,
                max_tool_calls: 2_048,
                max_cost_microusd: 100_000_000,
                max_elapsed_millis: 600_000,
            },
            0,
        )
        .expect("budget"),
        cancellation: CancellationToken::default(),
        clock: Arc::new(FixedClock),
        limits,
        system_policy_id: "efficiency-policy-v1".to_owned(),
        system_policy: "Use bounded tools and complete every assigned review group.".to_owned(),
        initial_omissions: Vec::new(),
    }
}

#[allow(clippy::too_many_lines)]
fn derive_efficiency(requests: &[ModelRequest]) -> revoot_core::TokenEfficiencyReport {
    let mut groups = BTreeMap::new();
    for request in requests.iter().filter(|request| !request.tools.is_empty()) {
        let packet = packet(request);
        if packet["purpose"] != "group_initial" {
            continue;
        }
        let group_id = packet["group_id"].as_str().expect("group ID").to_owned();
        assert_eq!(packet["diff"]["mode"], "manifest_only");
        groups.insert(
            group_id.clone(),
            EfficiencyGroup {
                group_id,
                file_count: u32::try_from(packet["files"].as_array().expect("files").len())
                    .expect("file count"),
                full_diff_bytes: packet["diff"]["bytes"].as_u64().expect("diff bytes"),
                full_diff_estimated_tokens: packet["diff"]["bytes"].as_u64().expect("diff tokens"),
                max_inline_diff_bytes: 16_384,
            },
        );
    }

    let mut review_rounds = BTreeMap::<String, u8>::new();
    let measured = requests
        .iter()
        .enumerate()
        .map(|(index, request)| {
            let payload_bytes = u64::try_from(
                serde_json::to_vec(request)
                    .expect("request serialization")
                    .len(),
            )
            .expect("payload bytes");
            assert!(payload_bytes <= REQUEST_TOKEN_TARGET as u64);
            if request.tools.is_empty() {
                let wire = serde_json::to_string(request).expect("grouping request");
                assert!(!wire.contains(DIFF_MARKER));
                return EfficiencyRequest {
                    request_id: format!("request-{index:03}"),
                    phase: EfficiencyPhase::Grouping,
                    group_id: None,
                    round: None,
                    payload_bytes,
                    estimated_input_tokens: payload_bytes,
                    diff_body_bytes: 0,
                    diff_body_estimated_tokens: 0,
                    tool_results: Vec::new(),
                    hunk_deliveries: Vec::new(),
                };
            }

            let packet = packet(request);
            let group_id = packet["group_id"].as_str().expect("group ID").to_owned();
            let initial = packet["purpose"] == "group_initial";
            if initial {
                assert_eq!(packet["diff"]["mode"], "manifest_only");
                assert!(
                    !serde_json::to_string(request)
                        .expect("initial request")
                        .contains(DIFF_MARKER)
                );
            }
            let round = if initial {
                None
            } else {
                let round = review_rounds.entry(group_id.clone()).or_default();
                *round += 1;
                Some(*round)
            };
            let mut diff_body_bytes = 0_u64;
            let mut tool_results = Vec::new();
            let mut hunk_deliveries = Vec::new();
            if let Some(results) = packet["recent_exchange"]["tool_results"].as_array() {
                for result in results {
                    let body = result["body"].as_str().expect("tool result body");
                    assert!(body.len() <= TOOL_RESULT_LIMIT);
                    tool_results.push(EfficiencyToolResult {
                        result_id: result["call_id"].as_str().expect("call ID").to_owned(),
                        bytes: u32::try_from(body.len()).expect("tool result bytes"),
                    });
                    let body: Value = serde_json::from_str(body).expect("tool result JSON");
                    if result["tool_name"] != "read_diff" {
                        continue;
                    }
                    assert!(
                        body["evidence_id"]
                            .as_str()
                            .is_some_and(|evidence_id| evidence_id.starts_with("evidence:")),
                        "successful diff delivery exposes its citeable evidence ID"
                    );
                    let delivered = body["result"]
                        .as_object()
                        .expect("bounded read_diff result envelope");
                    let pages = delivered["pages"]
                        .as_array()
                        .expect("read_diff result pages");
                    assert!(!pages.is_empty(), "read_diff delivery cannot be empty");
                    for page in pages {
                        let content = page["content"].as_str().expect("page content");
                        let bytes = u32::try_from(content.len()).expect("page bytes");
                        diff_body_bytes += u64::from(bytes);
                        hunk_deliveries.push(EfficiencyHunkDelivery {
                            delivery_id: format!(
                                "{}:{}:{}",
                                page["path"].as_str().expect("page path"),
                                page["hunk_id"].as_str().expect("hunk ID"),
                                page["page"].as_u64().expect("page number")
                            ),
                            bytes,
                        });
                    }
                }
            }
            EfficiencyRequest {
                request_id: format!("request-{index:03}"),
                phase: if initial {
                    EfficiencyPhase::GroupInitial
                } else {
                    EfficiencyPhase::ReviewRound
                },
                group_id: Some(group_id),
                round,
                payload_bytes,
                estimated_input_tokens: payload_bytes,
                diff_body_bytes,
                diff_body_estimated_tokens: diff_body_bytes,
                tool_results,
                hunk_deliveries,
            }
        })
        .collect::<Vec<_>>();
    measure_token_efficiency(
        ReviewEffort::Medium,
        REQUEST_TOKEN_TARGET as u64,
        groups.into_values().collect(),
        measured,
    )
    .expect("efficiency report")
}

#[tokio::test]
async fn native_one_mib_hundred_file_review_meets_token_efficiency_gates() {
    let setup = setup();
    let provider = Arc::new(CapturingProvider::new(setup.paths.clone()));
    let result = run_tool_first_engine(engine_request(setup, Arc::clone(&provider)))
        .await
        .expect("native review");
    assert_eq!(
        result.grouping_mode,
        revoot::review_grouper::ReviewGrouperMode::Semantic
    );
    assert_eq!(result.group_count, 10);
    assert_eq!(
        result.schedule.complete_groups, 10,
        "schedule: {:?}",
        result.schedule
    );
    let phase_requests = result
        .phase_usage
        .iter()
        .map(|usage| (usage.phase, usage.model_requests))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(phase_requests[&ReviewReportPhase::Grouping], 1);
    // Ten-file groups stay below the complexity threshold, so planning is
    // deterministically skipped. The scripted review emits no candidates, so
    // verifier and adjudicator calls are also deterministically unnecessary.
    assert_eq!(phase_requests[&ReviewReportPhase::Planning], 0);
    assert_eq!(phase_requests[&ReviewReportPhase::Review], 30);
    assert_eq!(phase_requests[&ReviewReportPhase::Verification], 0);
    assert_eq!(phase_requests[&ReviewReportPhase::Adjudication], 0);

    let requests = provider.captured();
    assert_eq!(requests.len(), 31);
    let report = derive_efficiency(&requests);
    assert_eq!(report.selected_files, 100);
    assert_eq!(
        report.selected_diff_bytes,
        u64::try_from(SELECTED_DIFF_BYTES).expect("selected bytes")
    );
    assert!(report.actual_percent_of_baseline <= 40);
    let deliveries = report
        .requests
        .iter()
        .flat_map(|request| {
            request
                .hunk_deliveries
                .iter()
                .map(move |delivery| (request.group_id.as_deref(), &delivery.delivery_id))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(deliveries.len(), 1);
    report.validate().expect("efficiency gates");
}
