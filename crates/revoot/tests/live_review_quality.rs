//! Credentialed end-to-end quality evaluation over full checkout scenarios.
//! Ignored by default because it makes billable provider requests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use revoot::egress_setup::authorize_standard_provider;
use revoot::providers::ApiKey;
use revoot::providers::anthropic::{AnthropicAdapter, AnthropicConfig};
use revoot::providers::openai::{OpenAiAdapter, OpenAiConfig};
use revoot::review_engine::{
    IndependentReviewBrief, MonotonicClock, ReviewAnchor, ReviewEngineLimits, ReviewEngineRequest,
    run_review,
};
use revoot_core::{
    AgentBudgetLimits, AgentBudgetUsage, AgentTool, AnchorPosition, AnchorTable, CancellationToken,
    ChangedPath, DiffRefs, DiffVersionId, DiffVersionRecord, EvaluationCase, EvaluationThresholds,
    ExpectedDefect, FileChangeKind, Finding, FindingCategory, GitLabDiffVersionIdentity, GitSha,
    MergeRequestIid, ProjectId, ProviderAdapter, RepositoryDiff, RepositoryPath,
    RepositoryRelativePath, RepositoryToolLimits, RepositoryToolbox, ReviewInvocation,
    ReviewOutcome, Sha256Digest, SnapshotScope, UnifiedDiffLimits, evaluate_corpus,
    parse_gitlab_file_diff,
};
use serde::{Deserialize, Serialize};

static CHECKOUT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Deserialize, Serialize)]
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedScenarioDefect {
    side: ExpectedSide,
    line: u32,
    category: FindingCategory,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedSide {
    Old,
    New,
}

struct MaterializedCheckout(PathBuf);

impl MaterializedCheckout {
    fn create(files: &BTreeMap<String, String>) -> Self {
        let suffix = CHECKOUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "revoot-live-evaluation-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("evaluation checkout root");
        for (path, content) in files {
            let path = RepositoryRelativePath::try_from(path.clone()).expect("normalized path");
            let destination = root.join(path.as_str());
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).expect("evaluation checkout directory");
            }
            fs::write(destination, content).expect("evaluation checkout file");
        }
        Self(root)
    }
}

impl Drop for MaterializedCheckout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct CaseClock(Instant);

impl MonotonicClock for CaseClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
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
            instance_origin_digest: Sha256Digest::of_bytes(b"evaluation.invalid"),
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

fn tools() -> BTreeSet<AgentTool> {
    BTreeSet::from([
        AgentTool::ListFiles,
        AgentTool::ReadFile,
        AgentTool::Search,
        AgentTool::ShowDiff,
        AgentTool::SubmitCandidateFinding,
        AgentTool::SubmitReviewSummary,
    ])
}

fn prepare_case(
    scenario: &EvaluationScenario,
    adapter: &dyn ProviderAdapter,
    model: &str,
    cancellation: &CancellationToken,
) -> (MaterializedCheckout, ReviewEngineRequest, EvaluationCase) {
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
        .expect("snapshot-bound scenario anchors");
    let expected_defects = scenario
        .expected_defects
        .iter()
        .map(|defect| {
            let position = expected_position(defect);
            let anchor = anchors
                .iter()
                .find(|anchor| anchor.position == position)
                .expect("expected line has exact anchor");
            ExpectedDefect {
                anchor_id: anchor.id.as_str().to_owned(),
                category: defect.category,
            }
        })
        .collect();
    let checkout = MaterializedCheckout::create(&scenario.checkout_files);
    let toolbox = RepositoryToolbox::open(
        &checkout.0,
        RepositoryToolLimits::default(),
        [RepositoryDiff {
            path: RepositoryRelativePath::try_from(scenario.new_path.clone()).unwrap(),
            text: scenario.exact_diff.clone(),
        }],
        cancellation,
    )
    .expect("full scenario checkout inventory");
    let anchor_catalog = anchors
        .iter()
        .map(|anchor| {
            format!(
                "{} => {} {:?}",
                anchor.id.as_str(),
                anchor.path.new_path.as_str(),
                anchor.position
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let prompt = format!(
        "Review work unit evaluation for changed path {}. Start with show_diff, then inspect the full checkout as needed. Use only these exact anchors for candidate findings:\n{}",
        scenario.new_path, anchor_catalog
    );
    let request = ReviewEngineRequest {
        invocation: ReviewInvocation {
            review_id: format!("live-evaluation-{}", scenario.case_id.replace('/', "-")),
            snapshot: snapshot.into(),
            work_unit_ids: BTreeSet::from(["evaluation".to_owned()]),
            provider_adapter: adapter.adapter_id().to_owned(),
            model_id: model.to_owned(),
            allowed_tools: tools(),
            limits: AgentBudgetLimits::default(),
        },
        toolbox,
        history: None,
        prior_review: revoot_core::PriorReviewContext::default(),
        anchors: anchors
            .iter()
            .map(|anchor| {
                (
                    anchor.id.as_str().to_owned(),
                    ReviewAnchor {
                        path: RepositoryRelativePath::try_from(
                            anchor.path.new_path.as_str().to_owned(),
                        )
                        .expect("anchor checkout path"),
                        position: anchor.position,
                    },
                )
            })
            .collect(),
        review_brief: IndependentReviewBrief::try_new(prompt)
            .expect("valid independent evaluation brief"),
        repository_guidance: None,
        initial_omissions: Vec::new(),
        limits: ReviewEngineLimits::default(),
    };
    let case = EvaluationCase {
        schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
        case_id: scenario.case_id.clone(),
        clean_change: scenario.clean_change,
        expected_defects,
    };
    (checkout, request, case)
}

fn outcome_parts(outcome: ReviewOutcome) -> (&'static str, Vec<Finding>, AgentBudgetUsage) {
    match outcome {
        ReviewOutcome::Complete {
            findings, usage, ..
        } => (
            "complete",
            findings
                .into_iter()
                .flat_map(|envelope| envelope.findings)
                .collect(),
            usage,
        ),
        ReviewOutcome::Partial {
            findings, usage, ..
        } => (
            "partial",
            findings
                .into_iter()
                .flat_map(|envelope| envelope.findings)
                .collect(),
            usage,
        ),
        ReviewOutcome::NoFindings { usage, .. } => ("no_findings", Vec::new(), usage),
        ReviewOutcome::Stale { usage } => ("stale", Vec::new(), usage),
        ReviewOutcome::Blocked { usage, .. } => ("blocked", Vec::new(), usage),
        ReviewOutcome::Failed { usage, .. } => ("failed", Vec::new(), usage),
        ReviewOutcome::Cancelled { usage } => ("cancelled", Vec::new(), usage),
    }
}

fn required(name: &str) -> Vec<u8> {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("{name} is required for live quality evaluation"))
        .into_encoded_bytes()
}

fn required_model(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for live quality evaluation"))
}

fn adapter() -> (Box<dyn ProviderAdapter>, String, String) {
    match std::env::var("REVOOT_LIVE_EVALUATION_PROVIDER").as_deref() {
        Ok("anthropic") => {
            let model = required_model("REVOOT_LIVE_ANTHROPIC_MODEL");
            let authorization =
                authorize_standard_provider("anthropic", "https://api.anthropic.com/v1/messages")
                    .expect("Anthropic egress");
            let adapter = AnthropicAdapter::new(
                &AnthropicConfig::default(),
                ApiKey::new(required("ANTHROPIC_API_KEY")).expect("Anthropic key"),
                &authorization,
            )
            .expect("Anthropic adapter");
            (Box::new(adapter), "anthropic".to_owned(), model)
        }
        Ok("openai") => {
            let model = required_model("REVOOT_LIVE_OPENAI_MODEL");
            let authorization =
                authorize_standard_provider("openai", "https://api.openai.com/v1/responses")
                    .expect("OpenAI egress");
            let adapter = OpenAiAdapter::new(
                &OpenAiConfig::default(),
                ApiKey::new(required("OPENAI_API_KEY")).expect("OpenAI key"),
                &authorization,
            )
            .expect("OpenAI adapter");
            (Box::new(adapter), "openai".to_owned(), model)
        }
        _ => panic!("REVOOT_LIVE_EVALUATION_PROVIDER must be anthropic or openai"),
    }
}

#[tokio::test]
#[ignore = "requires an explicit provider, credential, and model"]
async fn live_full_checkout_quality() {
    let (adapter, _provider, model) = adapter();
    let scenarios = scenarios();
    let mut observations = Vec::new();
    for scenario in scenarios {
        let cancellation = CancellationToken::default();
        let (_checkout, request, evaluation) =
            prepare_case(&scenario, adapter.as_ref(), &model, &cancellation);
        let clock = CaseClock(Instant::now());
        let report = run_review(adapter.as_ref(), request, cancellation, &clock)
            .await
            .unwrap_or_else(|error| panic!("{} review failed: {error}", scenario.case_id));
        let elapsed_millis = clock.now_millis();
        let (outcome, findings, _usage) = outcome_parts(report.outcome);
        let score = evaluation.score(&findings).expect("valid quality score");
        observations.push((evaluation, findings));
        assert!(
            matches!(outcome, "complete" | "no_findings"),
            "quality case did not complete"
        );
        assert!(
            elapsed_millis <= 600_000,
            "quality case exceeded ten minutes"
        );
        assert_eq!(score.false_positive, 0, "quality false positive");
        assert_eq!(score.false_negative, 0, "quality false negative");
        assert_eq!(score.duplicate_reports, 0, "quality duplicate");
        if scenario.clean_change {
            assert!(score.clean_change_silent, "clean case was noisy");
        }
    }
    let observation_refs = observations
        .iter()
        .map(|(case, findings)| (case, findings.as_slice()))
        .collect::<Vec<_>>();
    let gate = evaluate_corpus(&observation_refs, EvaluationThresholds::default())
        .expect("bounded quality corpus");
    assert!(
        gate.passed,
        "aggregate quality gate failed: {:?}",
        gate.failures
    );
}
