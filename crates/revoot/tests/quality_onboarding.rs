use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use revoot::github_init::{GitHubInitOptions, render_github_actions};
use revoot::gitlab_init::{GitLabInitOptions, render_gitlab_ci};
use revoot_core::{EvaluationCase, Finding, FindingCategory, Severity};

const TEN_MINUTES: Duration = Duration::from_mins(10);

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("revoot crate must live below the workspace root")
        .to_owned()
}

fn evaluation_cases() -> Vec<(PathBuf, EvaluationCase)> {
    let fixture_directory = workspace_root().join("tests/fixtures/evaluation/public");
    let mut paths: Vec<_> = fs::read_dir(&fixture_directory)
        .expect("evaluation fixture directory must be readable")
        .map(|entry| {
            entry
                .expect("evaluation fixture entry must be readable")
                .path()
        })
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let input = fs::read_to_string(&path).expect("evaluation fixture must be readable");
            let case = serde_json::from_str(&input).expect("evaluation fixture must match v1");
            (path, case)
        })
        .collect()
}

fn finding(anchor_id: &str, category: FindingCategory) -> Finding {
    Finding {
        anchor_id: anchor_id.to_owned(),
        severity: Severity::High,
        confidence_percent: 95,
        category,
        title: "Material defect".to_owned(),
        explanation: "The changed behavior violates the stated invariant.".to_owned(),
        evidence: "The issued anchor identifies the affected changed line.".to_owned(),
        lineage_id: None,
        suggested_replacement: None,
    }
}

fn case_by_id<'a>(cases: &'a [(PathBuf, EvaluationCase)], case_id: &str) -> &'a EvaluationCase {
    &cases
        .iter()
        .find(|(_, case)| case.case_id == case_id)
        .unwrap_or_else(|| panic!("missing required evaluation case {case_id}"))
        .1
}

#[test]
fn public_corpus_matches_the_versioned_schema_contract() {
    let root = workspace_root();
    let schema_input = fs::read_to_string(root.join("contracts/evaluation-case-v1.schema.json"))
        .expect("evaluation schema must be readable");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_input).expect("evaluation schema must be valid JSON");

    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        EvaluationCase::SCHEMA_VERSION
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["required"],
        serde_json::json!([
            "schema_version",
            "case_id",
            "clean_change",
            "expected_defects"
        ])
    );

    let cases = evaluation_cases();
    assert!(!cases.is_empty(), "the public corpus must not be empty");
    let mut case_ids = BTreeSet::new();
    for (path, case) in &cases {
        assert_eq!(
            case.schema_version,
            EvaluationCase::SCHEMA_VERSION,
            "{} has an unexpected schema version",
            path.display()
        );
        assert!(
            case_ids.insert(case.case_id.as_str()),
            "duplicate case id {}",
            case.case_id
        );
        case.score(&[])
            .unwrap_or_else(|error| panic!("{} violates {error:?}", path.display()));
    }

    for required in [
        "rust/clean-001",
        "rust/correctness-001",
        "rust/incremental-001",
    ] {
        assert!(
            case_ids.contains(required),
            "missing required case {required}"
        );
    }
}

#[test]
fn public_corpus_records_clean_defect_and_incremental_scoring() {
    let cases = evaluation_cases();

    let clean = case_by_id(&cases, "rust/clean-001");
    let silent = clean.score(&[]).expect("clean case must score");
    assert!(silent.clean_change_silent);
    assert_eq!(silent.false_positive, 0);

    let noisy = clean
        .score(&[finding("src/lib.rs:new:12", FindingCategory::Correctness)])
        .expect("clean case with an observation must still score");
    assert!(!noisy.clean_change_silent);
    assert_eq!(noisy.false_positive, 1);

    let defect = case_by_id(&cases, "rust/correctness-001");
    let expected = &defect.expected_defects[0];
    let exact = finding(&expected.anchor_id, expected.category);
    let detected = defect
        .score(std::slice::from_ref(&exact))
        .expect("defect case must score");
    assert_eq!(detected.true_positive, 1);
    assert_eq!(detected.false_positive, 0);
    assert_eq!(detected.false_negative, 0);

    let wrong_category = defect
        .score(&[finding(
            &expected.anchor_id,
            FindingCategory::Maintainability,
        )])
        .expect("wrong-category observation must score");
    assert_eq!(wrong_category.true_positive, 0);
    assert_eq!(wrong_category.false_positive, 1);
    assert_eq!(wrong_category.false_negative, 1);

    let incremental = case_by_id(&cases, "rust/incremental-001");
    let incremental_expected = &incremental.expected_defects[0];
    let stable = finding(
        &incremental_expected.anchor_id,
        incremental_expected.category,
    );
    let missed = incremental.score(&[]).expect("incremental case must score");
    assert_eq!(missed.false_negative, 1);

    let first_run = incremental
        .score(std::slice::from_ref(&stable))
        .expect("first incremental run must score");
    let repeated_run = incremental
        .score(std::slice::from_ref(&stable))
        .expect("repeated incremental run must score");
    assert_eq!(
        first_run, repeated_run,
        "stable anchors must score identically"
    );
    assert_eq!(repeated_run.true_positive, 1);

    let duplicated = incremental
        .score(&[stable.clone(), stable])
        .expect("duplicate incremental observations must score");
    assert_eq!(duplicated.true_positive, 1);
    assert_eq!(duplicated.duplicate_reports, 1);
}

#[test]
fn generated_gitlab_onboarding_contract_is_bounded_and_matches_ci_assets() {
    let started = Instant::now();
    let options = GitLabInitOptions {
        component: "gitlab.com/getrevoot/revoot-ci/review".to_owned(),
        version: "0.1.0".to_owned(),
        provider: "anthropic".to_owned(),
        model: "claude-sonnet-5".to_owned(),
        fork_behavior: "skip".to_owned(),
    };
    let generated = render_gitlab_ci(&options).expect("safe onboarding input must render");

    assert_eq!(generated.matches("include:").count(), 1);
    assert!(generated.contains("component: gitlab.com/getrevoot/revoot-ci/review@0.1.0"));
    assert!(generated.contains("provider: anthropic"));
    assert!(generated.contains("model: claude-sonnet-5"));
    assert!(generated.contains("fork_behavior: skip"));
    assert!(!generated.to_ascii_lowercase().contains("token"));
    assert!(!generated.to_ascii_lowercase().contains("secret"));

    let root = workspace_root();
    let component_path = root.join("ci/gitlab/components/review/template.yml");
    if component_path.is_file() {
        let component = fs::read_to_string(component_path).expect("component must be readable");
        assert!(component.contains("provider:"));
        assert!(component.contains("model:"));
        assert!(component.contains("fork_behavior:"));
        assert!(component.contains("skip"));
        assert!(component.contains("default: .post"));
        assert!(component.contains("needs: $[[ inputs.needs ]]"));
        assert!(component.contains("$CI_PIPELINE_SOURCE == \"merge_request_event\""));
        assert!(component.contains("revoot review --ci"));
        assert!(component.contains("revoot-review.json"));
    }

    let self_managed_example_path = root.join("ci/gitlab/self-managed/example.gitlab-ci.yml");
    if self_managed_example_path.is_file() {
        let example = fs::read_to_string(self_managed_example_path)
            .expect("self-managed example must be readable");
        assert!(example.contains("0123456789abcdef0123456789abcdef01234567"));
        assert!(example.contains("@sha256:REPLACE_ME"));
        assert!(example.contains("provider: auto"));
        assert!(example.contains("fork_behavior: skip"));
    }

    let elapsed = started.elapsed();
    eprintln!(
        "automated_onboarding_record elapsed_ms={} budget_ms={}",
        elapsed.as_millis(),
        TEN_MINUTES.as_millis()
    );
    assert!(
        elapsed < TEN_MINUTES,
        "configuration generation exceeded the ten-minute onboarding budget"
    );
}

#[test]
fn generated_github_onboarding_contract_is_bounded_and_matches_ci_asset() {
    let started = Instant::now();
    let generated =
        render_github_actions(&GitHubInitOptions::default()).expect("safe workflow inputs");
    let canonical = fs::read_to_string(workspace_root().join("ci/github/revoot-review.yml"))
        .expect("canonical GitHub workflow");

    assert_eq!(generated, canonical);
    assert_eq!(generated.matches("revoot review --ci").count(), 1);
    assert!(generated.contains("contents: read"));
    assert!(generated.contains("pull-requests: write"));
    assert!(generated.contains("persist-credentials: false"));
    assert!(generated.contains("github.event.pull_request.head.sha"));
    assert!(generated.contains("head.repo.full_name == github.repository"));
    assert!(generated.contains("REVOOT_PROVIDER: ${{ vars.REVOOT_PROVIDER || 'auto' }}"));
    assert!(generated.contains("REVOOT_MODEL: ${{ vars.REVOOT_MODEL || 'auto' }}"));
    assert!(!generated.contains("pull_request_target"));
    assert!(!generated.contains("workflow_run"));
    assert!(!generated.contains("@main"));

    let elapsed = started.elapsed();
    eprintln!(
        "automated_github_onboarding_record elapsed_ms={} budget_ms={}",
        elapsed.as_millis(),
        TEN_MINUTES.as_millis()
    );
    assert!(
        elapsed < TEN_MINUTES,
        "GitHub workflow generation exceeded the ten-minute onboarding budget"
    );
}
