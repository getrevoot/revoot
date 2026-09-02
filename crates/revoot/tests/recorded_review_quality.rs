//! Non-credentialed end-to-end quality gate over the checked-in scenario corpus.
//!
//! A deterministic protocol adapter supplies recorded review decisions, but it
//! learns opaque work-unit, hunk, evidence, and anchor identities only from the
//! real model requests and tool results. Production preparation, tools,
//! coverage, candidate admission, verification, adjudication, and reduction
//! remain authoritative.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use revoot::config::RepositoryReviewPolicy;
use revoot::group_worker_engine::GroupWorkerClock;
use revoot::review_adjudicator::ReviewAdjudicatorClock;
use revoot::review_grouper::{ReviewGrouperClock, ReviewGrouperMode};
use revoot::review_verifier::ReviewVerifierClock;
use revoot::reviewer_policy::{REVIEWER_POLICY_VERSION, tool_first_reviewer_system_policy};
use revoot::tool_first_engine::{
    ToolFirstEngineLimits, ToolFirstEngineRequest, run_tool_first_engine,
};
use revoot_core::provider::ProviderErrorKind;
use revoot_core::{
    AnchorPosition, AnchorTable, CancellationToken, ChangedPath, DiffRefs, DiffVersionId,
    DiffVersionRecord, EvaluationCase, EvaluationThresholds, ExpectedDefect, FileChangeKind,
    Finding, FindingCategory, GitLabDiffVersionIdentity, GitSha, MergeRequestIid, ModelContent,
    ModelFinishReason, ModelRequest, ModelResponse, ModelUsage, PartitionLimits, ProjectId,
    ProviderAdapter, ProviderError, ProviderFuture, RepositoryDiff, RepositoryPath,
    RepositoryRelativePath, RepositoryToolLimits, RepositoryToolbox, ReviewBudgetBroker,
    ReviewBudgetLimits, ReviewEffort, ReviewFileClass, ReviewFileInput, ReviewObject,
    ReviewObjectRole, ReviewOutcome, ReviewSelectionPolicy, ReviewValue, ReviewValueReason,
    ReviewValueTier, Sha256Digest, SnapshotScope, UnifiedDiffLimits, build_partition_plan,
    evaluate_corpus, parse_gitlab_file_diff,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::TempDir;

const MODEL: &str = "recorded-quality-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationScenario {
    schema_version: String,
    case_id: String,
    #[serde(rename = "sequence_id")]
    _sequence_id: Option<String>,
    revision: u64,
    clean_change: bool,
    base_sha: String,
    start_sha: String,
    head_sha: String,
    old_path: String,
    new_path: String,
    change_kind: FileChangeKind,
    exact_diff: String,
    checkout_files: BTreeMap<String, String>,
    expected_defects: Vec<ExpectedScenarioDefect>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedScenarioDefect {
    side: ExpectedSide,
    line: u32,
    category: FindingCategory,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedSide {
    Old,
    New,
}

#[derive(Clone, Copy)]
struct RecordedDiagnosis {
    line: u32,
    category: FindingCategory,
}

#[derive(Default)]
struct ProviderTrace {
    worker_requests: u32,
    diff_reads: u32,
    candidate_submissions: u32,
    verifier_requests: u32,
    adjudicator_requests: u32,
}

struct RecordedProvider {
    diagnosis: Option<RecordedDiagnosis>,
    next_call: AtomicU64,
    trace: Mutex<ProviderTrace>,
}

impl RecordedProvider {
    fn new(diagnosis: Option<RecordedDiagnosis>) -> Self {
        Self {
            diagnosis,
            next_call: AtomicU64::new(1),
            trace: Mutex::new(ProviderTrace::default()),
        }
    }

    fn respond(&self, request: &ModelRequest) -> Result<ModelResponse, ProviderError> {
        request.validate().map_err(|_| protocol_error())?;
        if request.tools.is_empty() {
            return self.respond_without_tools(request);
        }
        self.respond_to_worker(request)
    }

    fn respond_to_worker(&self, request: &ModelRequest) -> Result<ModelResponse, ProviderError> {
        self.trace.lock().expect("trace").worker_requests += 1;
        let packet = request_json(request)?;
        let recent = packet
            .get("recent_exchange")
            .filter(|value| !value.is_null());
        if recent.is_none() {
            let mut reads = Vec::new();
            for file in packet["files"].as_array().ok_or_else(protocol_error)? {
                let path = file["path"].as_str().ok_or_else(protocol_error)?;
                for hunk in file["hunk_ids"].as_array().ok_or_else(protocol_error)? {
                    reads.push(json!({
                        "path": path,
                        "hunk_id": hunk.as_str().ok_or_else(protocol_error)?,
                        "page": 1
                    }));
                }
            }
            if reads.is_empty() {
                return Err(protocol_error());
            }
            self.trace.lock().expect("trace").diff_reads +=
                u32::try_from(reads.len()).unwrap_or(u32::MAX);
            return Ok(tool_response(vec![(
                self.call_id(),
                "read_diff",
                json!({"reads": reads}),
            )]));
        }

        let delivered = recent
            .and_then(|value| value["tool_results"].as_array())
            .and_then(|results| {
                results.iter().find_map(|result| {
                    (result["tool_name"] == "read_diff")
                        .then(|| result["body"].as_str())
                        .flatten()
                })
            })
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
            .ok_or_else(protocol_error)?;
        let evidence_id = delivered["evidence_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(protocol_error)?;
        let mut calls = Vec::new();
        if let Some(diagnosis) = self.diagnosis {
            let (work_unit_id, anchor_id) =
                visible_target(&packet, &delivered["result"], diagnosis.line)?;
            calls.push((
                self.call_id(),
                "submit_candidate_finding",
                json!({"candidate": {
                    "candidate_id": "recorded-candidate-1",
                    "work_unit_id": work_unit_id,
                    "finding": {
                        "anchor_id": anchor_id,
                        "severity": "high",
                        "confidence_percent": 99,
                        "category": category_name(diagnosis.category),
                        "title": "Recorded material defect",
                        "explanation": "The delivered changed line demonstrates the recorded failure mode.",
                        "evidence": "The cited bounded diff page contains the defective changed line.",
                        "lineage_id": null,
                        "suggested_replacement": null
                    },
                    "evidence_references": [evidence_id]
                }}),
            ));
            self.trace.lock().expect("trace").candidate_submissions += 1;
        }
        calls.push((self.call_id(), "complete_group", completion_input()));
        Ok(tool_response(calls))
    }

    fn respond_without_tools(
        &self,
        request: &ModelRequest,
    ) -> Result<ModelResponse, ProviderError> {
        let input = request_json(request)?;
        if let Some(candidates) = input.get("candidates").and_then(Value::as_array) {
            self.trace.lock().expect("trace").verifier_requests += 1;
            let decisions = candidates
                .iter()
                .map(|candidate| {
                    Ok(json!({
                        "candidate_id": candidate["candidate_id"]
                            .as_str()
                            .ok_or_else(protocol_error)?,
                        "decision": "accept"
                    }))
                })
                .collect::<Result<Vec<_>, ProviderError>>()?;
            return Ok(text_response(&json!({
                "schema_version": "revoot.verifier-decisions/v1",
                "decisions": decisions
            })));
        }
        let candidates = input["verified_candidates"]
            .as_array()
            .ok_or_else(protocol_error)?;
        self.trace.lock().expect("trace").adjudicator_requests += 1;
        let publish = candidates
            .iter()
            .map(|candidate| {
                candidate["candidate_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(protocol_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(text_response(&json!({
            "schema_version": "revoot.adjudicator-decisions/v1",
            "publish": publish,
            "suppress": [],
            "overview": {
                "summary": "Recorded verified findings were retained.",
                "assumptions": []
            },
            "lineage_decisions": []
        })))
    }

    fn call_id(&self) -> String {
        format!(
            "recorded-call-{}",
            self.next_call.fetch_add(1, Ordering::Relaxed)
        )
    }
}

impl ProviderAdapter for RecordedProvider {
    fn adapter_id(&self) -> &'static str {
        "recorded-quality"
    }

    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
        _cancellation: &'a CancellationToken,
    ) -> ProviderFuture<'a> {
        let response = self.respond(request);
        Box::pin(async move { response })
    }
}

#[derive(Default)]
struct RecordedClock(AtomicU64);

impl RecordedClock {
    fn tick(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

impl ReviewGrouperClock for RecordedClock {
    fn now_millis(&self) -> u64 {
        self.tick()
    }
}

impl GroupWorkerClock for RecordedClock {
    fn now_millis(&self) -> u64 {
        self.tick()
    }
}

impl ReviewVerifierClock for RecordedClock {
    fn now_millis(&self) -> u64 {
        self.tick()
    }
}

impl ReviewAdjudicatorClock for RecordedClock {
    fn now_millis(&self) -> u64 {
        self.tick()
    }
}

fn protocol_error() -> ProviderError {
    ProviderError::new(ProviderErrorKind::Protocol, None, false)
}

fn request_json(request: &ModelRequest) -> Result<Value, ProviderError> {
    let [ModelContent::Text { text }] = request.messages[0].content.as_slice() else {
        return Err(protocol_error());
    };
    serde_json::from_str(text).map_err(|_| protocol_error())
}

fn tool_response(calls: Vec<(String, &'static str, Value)>) -> ModelResponse {
    ModelResponse {
        provider_response_id: None,
        model: MODEL.to_owned(),
        content: calls
            .into_iter()
            .map(|(id, name, input)| ModelContent::ToolUse {
                id,
                name: name.to_owned(),
                input,
            })
            .collect(),
        finish_reason: ModelFinishReason::ToolUse,
        usage: ModelUsage {
            input_tokens: 100,
            output_tokens: 50,
            cached_input_tokens: 0,
        },
    }
}

fn text_response(value: &Value) -> ModelResponse {
    ModelResponse {
        provider_response_id: None,
        model: MODEL.to_owned(),
        content: vec![ModelContent::Text {
            text: serde_json::to_string(value).expect("recorded response JSON"),
        }],
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: 100,
            output_tokens: 50,
            cached_input_tokens: 0,
        },
    }
}

fn completion_input() -> Value {
    json!({
        "checkpoint": {
            "hypotheses": [],
            "evidence_references": [],
            "unresolved_coverage": []
        },
        "summary": {"text": "Recorded review completed.", "assumptions": []}
    })
}

fn visible_target(
    packet: &Value,
    delivered_result: &Value,
    new_line: u32,
) -> Result<(String, String), ProviderError> {
    let files = packet["files"].as_array().ok_or_else(protocol_error)?;
    for page in delivered_result["pages"]
        .as_array()
        .ok_or_else(protocol_error)?
    {
        let path = page["path"].as_str().ok_or_else(protocol_error)?;
        let work_unit_id = files
            .iter()
            .find(|file| file["path"].as_str() == Some(path))
            .and_then(|file| file["work_unit_id"].as_str())
            .ok_or_else(protocol_error)?;
        for anchor in page["anchors"].as_array().ok_or_else(protocol_error)? {
            if anchor["position"]["kind"] == "addition"
                && anchor["position"]["new_line"].as_u64() == Some(u64::from(new_line))
            {
                return Ok((
                    work_unit_id.to_owned(),
                    anchor["anchor_id"]
                        .as_str()
                        .ok_or_else(protocol_error)?
                        .to_owned(),
                ));
            }
        }
    }
    Err(protocol_error())
}

const fn category_name(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Correctness => "correctness",
        FindingCategory::Security => "security",
        FindingCategory::Reliability => "reliability",
        FindingCategory::Performance => "performance",
        FindingCategory::Maintainability => "maintainability",
    }
}

fn recorded_diagnosis(case_id: &str) -> Option<RecordedDiagnosis> {
    let (line, category) = match case_id {
        "go/reliability-double-close" => (3, FindingCategory::Reliability),
        "java/correctness-reference-equality"
        | "adversarial/repository-instruction-hidden-defect" => (3, FindingCategory::Correctness),
        "python/security-shell-injection" | "terraform/security-public-database-ingress" => {
            (3, FindingCategory::Security)
        }
        "rust/correctness-divide-by-zero" | "typescript/cross-file-timeout-units" => {
            (2, FindingCategory::Correctness)
        }
        "principles/duplication-with-security-consequence" => (2, FindingCategory::Security),
        "rust/session-units-r1" => (2, FindingCategory::Reliability),
        "sql/reliability-unbounded-delete" => (1, FindingCategory::Reliability),
        "rust/clean-refactor"
        | "principles/dry-duplication-without-consequence"
        | "adversarial/repository-instruction-clean"
        | "rust/session-units-r2"
        | "principles/solid-responsibility-without-consequence" => return None,
        unknown => panic!("scenario {unknown} lacks a recorded quality decision"),
    };
    Some(RecordedDiagnosis { line, category })
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_owned()
}

fn scenarios() -> Vec<EvaluationScenario> {
    let directory = workspace_root().join("tests/fixtures/evaluation/scenarios");
    let mut paths = fs::read_dir(directory)
        .expect("scenario directory")
        .map(|entry| entry.expect("scenario entry").path())
        .filter(|path| path.extension().is_some_and(|value| value == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            serde_json::from_str(&fs::read_to_string(path).expect("scenario input"))
                .expect("valid scenario")
        })
        .collect()
}

fn snapshot(scenario: &EvaluationScenario) -> revoot_core::GitLabSnapshotIdentity {
    GitLabDiffVersionIdentity {
        scope: SnapshotScope {
            instance_origin_digest: Sha256Digest::of_bytes(b"recorded-quality.invalid"),
            project_id: ProjectId::try_from(1).unwrap(),
            merge_request_iid: MergeRequestIid::try_from(1).unwrap(),
        },
        diff_version: DiffVersionRecord {
            id: DiffVersionId::try_from(scenario.revision).unwrap(),
            refs: DiffRefs {
                base_sha: GitSha::try_from(scenario.base_sha.clone()).unwrap(),
                start_sha: GitSha::try_from(scenario.start_sha.clone()).unwrap(),
                head_sha: GitSha::try_from(scenario.head_sha.clone()).unwrap(),
            },
        },
    }
    .freeze(Sha256Digest::of_bytes(scenario.exact_diff.as_bytes()))
}

fn expected_position(defect: &ExpectedScenarioDefect) -> AnchorPosition {
    match defect.side {
        ExpectedSide::Old => AnchorPosition::Deletion {
            old_line: defect.line,
        },
        ExpectedSide::New => AnchorPosition::Addition {
            new_line: defect.line,
        },
    }
}

struct PreparedCase {
    _checkout: TempDir,
    request: ToolFirstEngineRequest<RecordedClock>,
    evaluation: EvaluationCase,
}

#[allow(clippy::too_many_lines)]
fn prepare_case(scenario: &EvaluationScenario, provider: Arc<dyn ProviderAdapter>) -> PreparedCase {
    assert_eq!(scenario.schema_version, "revoot.evaluation-scenario/v1");
    let changed_path = ChangedPath {
        old_path: RepositoryPath::try_from(scenario.old_path.clone()).unwrap(),
        new_path: RepositoryPath::try_from(scenario.new_path.clone()).unwrap(),
        kind: scenario.change_kind,
    };
    let parsed = parse_gitlab_file_diff(
        &changed_path,
        scenario.exact_diff.as_bytes(),
        UnifiedDiffLimits::default(),
    )
    .expect("strict scenario diff");
    let snapshot = snapshot(scenario);
    let anchors = AnchorTable::build(snapshot.clone(), parsed.commentable_lines)
        .expect("snapshot-bound anchors");
    let expected_defects = scenario
        .expected_defects
        .iter()
        .map(|defect| {
            let position = expected_position(defect);
            let anchor = anchors
                .iter()
                .find(|anchor| anchor.position == position)
                .expect("expected exact anchor");
            ExpectedDefect {
                anchor_id: anchor.id.as_str().to_owned(),
                category: defect.category,
            }
        })
        .collect();
    let checkout = tempfile::tempdir().expect("checkout");
    for (path, content) in &scenario.checkout_files {
        let path = RepositoryRelativePath::try_from(path.clone()).expect("normalized path");
        let destination = checkout.path().join(path.as_str());
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).expect("checkout directory");
        }
        fs::write(destination, content).expect("checkout file");
    }
    let cancellation = CancellationToken::default();
    let path = RepositoryRelativePath::try_from(scenario.new_path.clone()).unwrap();
    let toolbox = RepositoryToolbox::open_selected(
        checkout.path(),
        RepositoryToolLimits::default(),
        [RepositoryDiff {
            path: path.clone(),
            text: scenario.exact_diff.clone(),
        }],
        [path],
        &cancellation,
    )
    .expect("scenario toolbox");
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
            max_file_bytes: 2 * 1024 * 1024,
        },
        PartitionLimits {
            max_files: 10,
            max_total_bytes: 2 * 1024 * 1024,
            max_work_units: 10,
            max_files_per_work_unit: 10,
            max_bytes_per_work_unit: 2 * 1024 * 1024,
            max_anchors_per_work_unit: 10_000,
        },
        [ReviewFileInput {
            path: changed_path,
            class: ReviewFileClass::Text,
            review_value: ReviewValue {
                tier: ReviewValueTier::Standard,
                score: 100,
                reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
            },
            objects: vec![ReviewObject {
                role: ReviewObjectRole::ExactDiff,
                content_sha256: Sha256Digest::of_bytes(scenario.exact_diff.as_bytes()),
                size_bytes: u64::try_from(scenario.exact_diff.len()).unwrap_or(u64::MAX),
            }],
            anchor_ids: anchors.iter().map(|anchor| anchor.id.clone()).collect(),
        }],
    )
    .expect("scenario partition");
    let mut limits = ToolFirstEngineLimits::new(MODEL);
    limits.effort = ReviewEffort::Low;
    limits.max_inline_diff_bytes = 1;
    let request = ToolFirstEngineRequest {
        provider,
        toolbox: Arc::new(toolbox),
        history: None,
        prior_review: revoot_core::PriorReviewContext::default(),
        anchor_table: anchors,
        partition,
        rule_policy: RepositoryReviewPolicy::default(),
        budget: ReviewBudgetBroker::new(ReviewBudgetLimits::default(), 0).expect("budget"),
        cancellation,
        clock: Arc::new(RecordedClock::default()),
        limits,
        system_policy_id: format!("{REVIEWER_POLICY_VERSION}.recorded-quality"),
        system_policy: tool_first_reviewer_system_policy(),
        initial_omissions: Vec::new(),
    };
    PreparedCase {
        _checkout: checkout,
        request,
        evaluation: EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: scenario.case_id.clone(),
            clean_change: scenario.clean_change,
            expected_defects,
        },
    }
}

fn findings(outcome: ReviewOutcome) -> Vec<Finding> {
    match outcome {
        ReviewOutcome::Complete { findings, .. } | ReviewOutcome::Partial { findings, .. } => {
            findings
                .into_iter()
                .flat_map(|envelope| envelope.findings)
                .collect()
        }
        ReviewOutcome::NoFindings { .. } => Vec::new(),
        other => panic!("recorded review did not complete: {other:?}"),
    }
}

#[tokio::test]
async fn recorded_tool_first_engine_meets_release_quality_thresholds() {
    let mut observations = Vec::new();
    let mut total_diff_reads = 0_u32;
    let mut defect_cases = 0_u32;
    for scenario in scenarios() {
        let diagnosis = recorded_diagnosis(&scenario.case_id);
        let provider = Arc::new(RecordedProvider::new(diagnosis));
        let adapter: Arc<dyn ProviderAdapter> = provider.clone();
        let prepared = prepare_case(&scenario, adapter);
        let report = run_tool_first_engine(prepared.request)
            .await
            .unwrap_or_else(|error| panic!("{} engine failure: {error}", scenario.case_id));
        assert_eq!(
            report.grouping_mode,
            ReviewGrouperMode::DeterministicSmallSelection
        );
        assert_eq!(report.group_count, 1);
        let produced = findings(report.result.outcome);
        let case_score = prepared
            .evaluation
            .score(&produced)
            .expect("valid case score");
        assert_eq!(case_score.false_positive, 0, "{}", scenario.case_id);
        assert_eq!(case_score.false_negative, 0, "{}", scenario.case_id);
        assert_eq!(case_score.duplicate_reports, 0, "{}", scenario.case_id);
        if scenario.clean_change {
            assert!(case_score.clean_change_silent, "{}", scenario.case_id);
        }
        let trace = provider.trace.lock().expect("trace");
        assert_eq!(trace.worker_requests, 2, "{}", scenario.case_id);
        assert!(trace.diff_reads >= 1, "{}", scenario.case_id);
        total_diff_reads = total_diff_reads.saturating_add(trace.diff_reads);
        if diagnosis.is_some() {
            defect_cases += 1;
            assert_eq!(trace.candidate_submissions, 1, "{}", scenario.case_id);
            assert_eq!(trace.verifier_requests, 1, "{}", scenario.case_id);
            assert_eq!(trace.adjudicator_requests, 1, "{}", scenario.case_id);
        } else {
            assert_eq!(trace.candidate_submissions, 0, "{}", scenario.case_id);
            assert_eq!(trace.verifier_requests, 0, "{}", scenario.case_id);
            assert_eq!(trace.adjudicator_requests, 0, "{}", scenario.case_id);
        }
        drop(trace);
        observations.push((prepared.evaluation, produced));
    }
    assert_eq!(defect_cases, 10);
    assert!(total_diff_reads >= u32::try_from(observations.len()).unwrap_or(u32::MAX));
    let scored = observations
        .iter()
        .map(|(case, findings)| (case, findings.as_slice()))
        .collect::<Vec<_>>();
    let gate =
        evaluate_corpus(&scored, EvaluationThresholds::default()).expect("bounded recorded corpus");
    assert!(gate.passed, "quality gate failed: {:?}", gate.failures);
    assert_eq!(gate.score.precision_basis_points, 10_000);
    assert_eq!(gate.score.recall_basis_points, 10_000);
    assert_eq!(gate.score.noisy_clean_cases, 0);
    assert_eq!(gate.score.duplicate_reports, 0);
    assert!(
        gate.score
            .category_recall_basis_points
            .values()
            .all(|score| *score == 10_000)
    );
}
