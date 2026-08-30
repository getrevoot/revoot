use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use revoot_core::{
    AnchorPosition, AnchorTable, CancellationToken, ChangedPath, DiffRefs, DiffVersionId,
    DiffVersionRecord, EvaluationCase, ExpectedDefect, FileChangeKind, FindingCategory,
    GitLabDiffVersionIdentity, GitSha, MergeRequestIid, ProjectId, RepositoryDiff, RepositoryPath,
    RepositoryRelativePath, RepositoryToolLimits, RepositoryToolbox, Sha256Digest, SnapshotScope,
    UnifiedDiffLimits, parse_gitlab_file_diff,
};
use serde::Deserialize;

static CHECKOUT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationScenario {
    schema_version: String,
    case_id: String,
    sequence_id: Option<String>,
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

struct MaterializedCheckout(PathBuf);

impl MaterializedCheckout {
    fn create(files: &BTreeMap<String, String>) -> Self {
        let suffix = CHECKOUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("revoot-evaluation-{}-{suffix}", std::process::id()));
        fs::create_dir(&root).expect("scenario checkout root must be creatable");
        for (path, content) in files {
            let path = RepositoryRelativePath::try_from(path.clone())
                .expect("scenario path must be normalized");
            let destination = root.join(path.as_str());
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).expect("scenario directory must be creatable");
            }
            fs::write(destination, content).expect("scenario file must be writable");
        }
        Self(root)
    }
}

impl Drop for MaterializedCheckout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("revoot crate must live below the workspace root")
        .to_owned()
}

fn scenarios() -> Vec<EvaluationScenario> {
    let directory = workspace_root().join("tests/fixtures/evaluation/scenarios");
    let mut paths = fs::read_dir(directory)
        .expect("scenario directory must be readable")
        .map(|entry| entry.expect("scenario entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let input = fs::read_to_string(&path).expect("scenario must be readable");
            serde_json::from_str(&input)
                .unwrap_or_else(|error| panic!("{} is invalid: {error}", path.display()))
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

#[test]
fn executable_scenarios_bind_real_diffs_full_checkouts_and_expected_anchors() {
    let root = workspace_root();
    let schema_input =
        fs::read_to_string(root.join("contracts/evaluation-scenario-v1.schema.json"))
            .expect("scenario schema must be readable");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_input).expect("scenario schema must be JSON");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        "revoot.evaluation-scenario/v1"
    );

    let scenarios = scenarios();
    assert!(scenarios.len() >= 4);
    let mut case_ids = BTreeSet::new();
    let mut categories = BTreeSet::new();
    for scenario in &scenarios {
        assert_eq!(scenario.schema_version, "revoot.evaluation-scenario/v1");
        assert!(case_ids.insert(scenario.case_id.as_str()));
        assert_eq!(scenario.clean_change, scenario.expected_defects.is_empty());

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
        .expect("scenario exact diff must parse strictly");
        let anchors = AnchorTable::build(snapshot(scenario), parsed.commentable_lines)
            .expect("scenario anchors must bind");
        let expected_defects = scenario
            .expected_defects
            .iter()
            .map(|defect| {
                categories.insert(defect.category);
                let position = expected_position(defect);
                let anchor = anchors
                    .iter()
                    .find(|anchor| anchor.position == position)
                    .unwrap_or_else(|| {
                        panic!("{} has no anchor at {position:?}", scenario.case_id)
                    });
                ExpectedDefect {
                    anchor_id: anchor.id.as_str().to_owned(),
                    category: defect.category,
                }
            })
            .collect();
        let case = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: scenario.case_id.clone(),
            clean_change: scenario.clean_change,
            expected_defects,
        };
        case.score(&[])
            .expect("derived score contract must be valid");

        let checkout = MaterializedCheckout::create(&scenario.checkout_files);
        let diff_path = RepositoryRelativePath::try_from(scenario.new_path.clone()).unwrap();
        let toolbox = RepositoryToolbox::open(
            &checkout.0,
            RepositoryToolLimits::default(),
            [RepositoryDiff {
                path: diff_path,
                text: scenario.exact_diff.clone(),
            }],
            &CancellationToken::default(),
        )
        .expect("scenario full checkout must inventory");
        assert_eq!(
            toolbox.inventory().files.len(),
            scenario.checkout_files.len(),
            "{} must expose every full-checkout file",
            scenario.case_id
        );
    }
    assert!(categories.contains(&FindingCategory::Correctness));
    assert!(categories.contains(&FindingCategory::Reliability));
}

#[test]
fn principle_scenarios_distinguish_conformity_from_consequence() {
    let scenarios = scenarios();
    for case_id in [
        "principles/dry-duplication-without-consequence",
        "principles/solid-responsibility-without-consequence",
    ] {
        let scenario = scenarios
            .iter()
            .find(|scenario| scenario.case_id == case_id)
            .unwrap_or_else(|| panic!("missing principle silence case {case_id}"));
        assert!(scenario.clean_change);
        assert!(scenario.expected_defects.is_empty());
    }

    let consequential = scenarios
        .iter()
        .find(|scenario| scenario.case_id == "principles/duplication-with-security-consequence")
        .expect("missing consequential duplication case");
    assert!(!consequential.clean_change);
    assert_eq!(consequential.expected_defects.len(), 1);
    assert_eq!(
        consequential.expected_defects[0].category,
        FindingCategory::Security
    );
}

#[test]
fn incremental_sequence_is_contiguous_and_resolves_the_known_defect() {
    let scenarios = scenarios();
    let mut sequence = scenarios
        .iter()
        .filter(|scenario| scenario.sequence_id.as_deref() == Some("rust/session-units"))
        .collect::<Vec<_>>();
    sequence.sort_by_key(|scenario| scenario.revision);
    assert_eq!(sequence.len(), 2);
    assert_eq!(sequence[0].revision, 1);
    assert_eq!(sequence[1].revision, 2);
    assert_eq!(sequence[1].base_sha, sequence[0].head_sha);
    assert!(!sequence[0].clean_change);
    assert!(sequence[1].clean_change);
}
