use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use revoot::gitlab_init::{GitLabInitOptions, render_gitlab_ci};
use revoot_core::{
    AgentBudget, AgentBudgetLimits, AgentRun, AgentTool, AnchorTable, CancellationToken,
    ChangedPath, InventoryCoverage, LineRange, RepositoryDiff, RepositoryRelativePath,
    RepositoryToolError, RepositoryToolLimits, RepositoryToolbox, ReviewInvocation, ReviewOutcome,
    SearchRequest, UnifiedDiffLimits, parse_gitlab_file_diff,
};
use serde_json::json;

static CHECKOUT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn immutable_image(version: &str) -> String {
    format!(
        "ghcr.io/getrevoot/revoot:{version}@sha256:{}",
        "a".repeat(64)
    )
}

struct CheckoutFixture {
    root: PathBuf,
}

impl CheckoutFixture {
    fn new() -> Self {
        let sequence = CHECKOUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "revoot-product-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("src")).expect("fixture source directory must be created");
        fs::write(
            root.join("src/changed.rs"),
            "pub fn run() {\n    dependency_contract_v1();\n}\n",
        )
        .expect("changed fixture must be written");
        fs::write(
            root.join("src/dependency.rs"),
            "pub fn dependency_contract_v1() -> bool { true }\n",
        )
        .expect("unchanged dependency fixture must be written");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("dependency manifest fixture must be written");
        Self { root }
    }
}

impl Drop for CheckoutFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn repository_path(value: &str) -> RepositoryRelativePath {
    RepositoryRelativePath::try_from(value.to_owned()).expect("fixture path must be valid")
}

fn command(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_revoot"))
        .args(arguments)
        .env_clear()
        .output()
        .expect("revoot command must run")
}

fn successful_stdout(arguments: &[&str]) -> String {
    let output = command(arguments);
    assert!(
        output.status.success(),
        "revoot {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("command output must be UTF-8")
}

fn invocation() -> ReviewInvocation {
    ReviewInvocation {
        review_id: "product-contract-review".to_owned(),
        snapshot: serde_json::from_value(json!({
            "version": {
                "scope": {
                    "instance_origin_digest": "11".repeat(32),
                    "project_id": 7,
                    "merge_request_iid": 9
                },
                "diff_version": {
                    "id": 3,
                    "refs": {
                        "base_sha": "aa".repeat(20),
                        "start_sha": "bb".repeat(20),
                        "head_sha": "cc".repeat(20)
                    }
                }
            },
            "exact_diff_manifest_sha256": "22".repeat(32)
        }))
        .expect("fixture snapshot must be valid"),
        work_unit_ids: BTreeSet::from(["unit-1".to_owned()]),
        provider_adapter: "fixture".to_owned(),
        model_id: "fixture-v1".to_owned(),
        allowed_tools: BTreeSet::from([
            AgentTool::ReadFile,
            AgentTool::Search,
            AgentTool::ListFiles,
            AgentTool::InspectChangedFile,
            AgentTool::InspectTests,
            AgentTool::ShowDiff,
            AgentTool::SubmitCandidateFinding,
            AgentTool::SubmitReviewSummary,
        ]),
        limits: AgentBudgetLimits::default(),
    }
}

#[test]
fn cli_exposes_one_review_operation_without_internal_modes() {
    let root_help = successful_stdout(&["--help"]);
    let review_operations: Vec<_> = root_help
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("revoot review"))
        .collect();
    assert_eq!(review_operations, ["revoot review"]);

    let config_help = successful_stdout(&["config", "explain", "--help"]);
    let init_help = successful_stdout(&["init", "gitlab", "--help"]);
    let public_surface = format!("{root_help}\n{config_help}\n{init_help}");
    for internal_control in [
        "--depth",
        "--review-mode",
        "--risk",
        "--thoroughness",
        "--agent-turns",
        "--investigation-mode",
        "--checkout-mode",
        "--context-mode",
        "--changed-files-only",
        "--full-repository",
    ] {
        assert!(
            !public_surface.contains(internal_control),
            "internal review control leaked into the public CLI: {internal_control}"
        );
    }

    let explained = successful_stdout(&["config", "explain", "--json"]);
    let report: serde_json::Value =
        serde_json::from_str(&explained).expect("config report must be JSON");
    let keys: BTreeSet<_> = report["fields"]
        .as_array()
        .expect("config report fields must be an array")
        .iter()
        .map(|field| field["key"].as_str().expect("config key must be a string"))
        .collect();
    for internal_key in [
        "review.depth",
        "review.mode",
        "review.risk",
        "review.thoroughness",
        "review.turn_strategy",
        "review.checkout_mode",
        "review.context_mode",
    ] {
        assert!(
            !keys.contains(internal_key),
            "risk-adaptive strategy must remain internal: {internal_key}"
        );
    }
}

#[test]
fn command_group_help_is_successful_and_side_effect_free() {
    for (arguments, expected) in [
        (&["init", "--help"][..], "revoot init github"),
        (&["config", "--help"][..], "revoot config explain"),
        (&["completions", "--help"][..], "revoot completions bash"),
        (&["doctor", "--help"][..], "revoot doctor [--json]"),
    ] {
        let stdout = successful_stdout(arguments);
        assert!(stdout.contains(expected), "missing help for {arguments:?}");
        if arguments[0] == "doctor" {
            assert!(
                !stdout.contains("Host:"),
                "doctor help executed the command"
            );
        }
    }
}

#[test]
fn exact_diff_seeds_anchors_while_full_checkout_context_remains_internal() {
    const EXACT_DIFF: &str = "@@ -1,3 +1,3 @@\n pub fn run() {\n-    old_behavior();\n+    dependency_contract_v1();\n }\n";
    let fixture = CheckoutFixture::new();
    let cancellation = CancellationToken::default();
    let changed_repository_path = repository_path("src/changed.rs");
    let changed_gitlab_path: ChangedPath = serde_json::from_value(json!({
        "old_path": "src/changed.rs",
        "new_path": "src/changed.rs",
        "kind": "modified"
    }))
    .expect("changed GitLab path must be valid");

    let parsed = parse_gitlab_file_diff(
        &changed_gitlab_path,
        EXACT_DIFF.as_bytes(),
        UnifiedDiffLimits::default(),
    )
    .expect("exact diff must seed trusted commentable lines");
    let anchors = AnchorTable::build(invocation().snapshot, parsed.commentable_lines)
        .expect("exact diff lines must bind to the immutable snapshot");
    assert!(!anchors.is_empty());
    assert!(
        anchors
            .iter()
            .all(|anchor| anchor.path == changed_gitlab_path)
    );

    let toolbox = RepositoryToolbox::open(
        &fixture.root,
        RepositoryToolLimits::default(),
        [RepositoryDiff {
            path: changed_repository_path.clone(),
            text: EXACT_DIFF.to_owned(),
        }],
        &cancellation,
    )
    .expect("full checkout must open without a user-selected mode");
    assert_eq!(toolbox.inventory().coverage, InventoryCoverage::Complete);
    let inventoried_paths: BTreeSet<_> = toolbox
        .inventory()
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(
        inventoried_paths,
        BTreeSet::from(["Cargo.toml", "src/changed.rs", "src/dependency.rs"])
    );

    let mut budget = AgentBudget::new(AgentBudgetLimits::default(), 0)
        .expect("repository tools must share a valid review budget");
    let diff = toolbox
        .show_diff(&changed_repository_path, &mut budget, &cancellation, 1)
        .expect("changed file must expose its exact diff");
    assert_eq!(diff.content, EXACT_DIFF);
    assert_eq!(
        toolbox.show_diff(
            &repository_path("src/dependency.rs"),
            &mut budget,
            &cancellation,
            2,
        ),
        Err(RepositoryToolError::DiffUnavailable),
        "unchanged files must not gain synthetic diff anchors"
    );

    let dependency = toolbox
        .read_file(
            &repository_path("src/dependency.rs"),
            LineRange { start: 1, end: 1 },
            &mut budget,
            &cancellation,
            3,
        )
        .expect("unchanged dependency must remain readable internally");
    assert!(dependency.content.contains("dependency_contract_v1"));

    let search = toolbox
        .search(
            &SearchRequest {
                query: "dependency_contract_v1".to_owned(),
                paths: Vec::new(),
                max_results: 10,
            },
            &mut budget,
            &cancellation,
            4,
        )
        .expect("empty search scope must cover the complete checkout inventory");
    assert!(
        search
            .matches
            .iter()
            .any(|item| item.path == repository_path("src/dependency.rs"))
    );
}

#[test]
fn a_silent_review_is_a_successful_terminal_outcome() {
    let mut run = AgentRun::new(invocation(), CancellationToken::default(), 1_000)
        .expect("review invocation must start");
    let outcome = run
        .finish("No material findings.".to_owned(), Vec::new())
        .expect("silence must be a successful review result");

    let ReviewOutcome::NoFindings {
        summary,
        omissions,
        usage,
    } = outcome
    else {
        panic!("a review without admitted findings must finish as no_findings")
    };
    assert_eq!(summary, "No material findings.");
    assert!(omissions.is_empty());
    assert_eq!(usage.candidate_findings, 0);

    let encoded = serde_json::to_value(ReviewOutcome::NoFindings {
        summary,
        omissions,
        usage,
    })
    .expect("successful outcome must serialize");
    assert_eq!(encoded["state"], "no_findings");
    assert!(encoded.get("findings").is_none());
}

#[test]
fn generated_gitlab_include_is_minimal_and_selects_no_review_strategy() {
    let generated = render_gitlab_ci(&GitLabInitOptions {
        image: immutable_image("1.2.3"),
        component: "gitlab.com/revoot/revoot-ci/review".to_owned(),
        version: "1.2.3".to_owned(),
        provider: "anthropic".to_owned(),
        model: "auto".to_owned(),
        fork_behavior: "skip".to_owned(),
    })
    .expect("default GitLab onboarding must render");

    let lines: Vec<_> = generated.lines().collect();
    assert_eq!(
        lines,
        [
            "include:",
            "  - component: gitlab.com/revoot/revoot-ci/review@1.2.3",
            "    inputs:",
            "      image: ghcr.io/getrevoot/revoot:1.2.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "      provider: anthropic",
            "      model: auto",
            "      fork_behavior: skip",
        ]
    );
    assert_eq!(generated.matches("component:").count(), 1);
    assert!(!generated.contains("script:"));
    assert!(generated.contains("image:") && generated.contains("@sha256:"));
    assert!(!generated.contains("variables:"));
    for internal_input in ["depth:", "review_mode:", "risk:", "thoroughness:", "turns:"] {
        assert!(
            !generated.contains(internal_input),
            "generated onboarding exposed internal strategy: {internal_input}"
        );
    }
}
