use std::collections::{BTreeMap, BTreeSet};

use revoot::review_sarif::render_review_sarif;
use revoot_core::{
    AnchorId, AnchorPosition, AnchorTable, ChangedPath, CommentableLine, DelegationManifest,
    DelegationRuleGroupInput, FileChangeKind, Finding, FindingCategory, FindingsEnvelope, GitSha,
    LocalSnapshotIdentity, PartitionLimits, RankedFinding, RepositoryPath, ReviewEffort,
    ReviewFileClass, ReviewFileInput, ReviewGroupPlan, ReviewGroupingSource, ReviewObject,
    ReviewObjectRole, ReviewOmissionReason, ReviewPartitionPlan, ReviewReportCoverage,
    ReviewReportFinding, ReviewReportFindingCoordinate, ReviewReportFindingSide,
    ReviewReportOverview, ReviewReportPhase, ReviewReportPhaseUsage, ReviewReportPublication,
    ReviewReportSelection, ReviewReportState, ReviewReportStrategy, ReviewReportUsage,
    ReviewReportUsageTotals, ReviewReportV3, ReviewSelectionPolicy, ReviewSnapshotIdentity,
    ReviewValue, ReviewValueReason, ReviewValueTier, SarifCoverageMetadata, SarifLog,
    SarifRunMetadata, Severity, Sha256Digest, build_delegation_manifest, build_partition_plan,
    build_review_group_plan, render_sarif, validate_rank_and_render,
};
use serde::Serialize;
use serde_json::Value;

#[path = "support/contract_schema.rs"]
mod contract_schema;

const REPORT_SCHEMA: &str = include_str!("../../../contracts/review-report-v3.schema.json");
const GROUP_SCHEMA: &str = include_str!("../../../contracts/review-group-plan-v1.schema.json");
const DELEGATION_SCHEMA: &str = include_str!("../../../contracts/delegation-v1.schema.json");
const COVERAGE_SCHEMA: &str = include_str!("../../../contracts/coverage-v1.schema.json");
const SARIF_SCHEMA: &str = include_str!("../../../contracts/sarif-2.1.0.schema.json");

const REPORT_GOLDEN: &str = include_str!("../../../contracts/golden/review-report-v3.valid.json");
const GROUP_GOLDEN: &str =
    include_str!("../../../contracts/golden/review-group-plan-v1.valid.json");
const DELEGATION_GOLDEN: &str = include_str!("../../../contracts/golden/delegation-v1.valid.json");
const COVERAGE_GOLDEN: &str = include_str!("../../../contracts/golden/coverage-v1.valid.json");
const REVIEW_SARIF_GOLDEN: &str =
    include_str!("../../../contracts/golden/review-sarif-2.1.0.valid.json");
const SCAN_SARIF_GOLDEN: &str =
    include_str!("../../../contracts/golden/scan-sarif-2.1.0.valid.json");

fn digest(marker: char) -> Sha256Digest {
    Sha256Digest::try_from(marker.to_string().repeat(64)).expect("valid digest")
}

fn anchor(marker: char) -> AnchorId {
    AnchorId::try_from(format!("ga1_{}", marker.to_string().repeat(64))).expect("valid anchor")
}

fn path(value: &str) -> RepositoryPath {
    RepositoryPath::try_from(value.to_owned()).expect("valid repository path")
}

fn changed(value: &str) -> ChangedPath {
    let path = path(value);
    ChangedPath {
        old_path: path.clone(),
        new_path: path,
        kind: FileChangeKind::Modified,
    }
}

fn snapshot() -> ReviewSnapshotIdentity {
    ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
        repository_identity_sha256: digest('a'),
        base_sha: GitSha::try_from("b".repeat(40)).expect("valid base SHA"),
        head_sha: GitSha::try_from("c".repeat(40)).expect("valid head SHA"),
        working_tree_sha256: digest('d'),
        exact_diff_manifest_sha256: digest('e'),
    })
}

fn partition() -> ReviewPartitionPlan {
    let files = [
        ("src/high.rs", ReviewValueTier::High, 220, '1'),
        ("tests/standard.rs", ReviewValueTier::Standard, 90, '2'),
    ]
    .into_iter()
    .map(|(name, tier, score, marker)| ReviewFileInput {
        path: changed(name),
        class: ReviewFileClass::Text,
        review_value: ReviewValue {
            tier,
            score,
            reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
        },
        objects: vec![ReviewObject {
            role: ReviewObjectRole::ExactDiff,
            content_sha256: digest(marker),
            size_bytes: 40,
        }],
        anchor_ids: vec![anchor(marker)],
    });
    build_partition_plan(
        snapshot(),
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
            max_file_bytes: 100,
        },
        PartitionLimits {
            max_files: 10,
            max_total_bytes: 1_000,
            max_work_units: 10,
            max_files_per_work_unit: 10,
            max_bytes_per_work_unit: 1_000,
            max_anchors_per_work_unit: 10,
        },
        files,
    )
    .expect("partition fixture")
}

fn group_plan(partition: &ReviewPartitionPlan) -> ReviewGroupPlan {
    build_review_group_plan(partition, None, ReviewGroupingSource::Deterministic)
        .expect("group plan fixture")
}

fn delegation(partition: &ReviewPartitionPlan) -> DelegationManifest {
    build_delegation_manifest(
        partition,
        digest('f'),
        digest('0'),
        [
            DelegationRuleGroupInput {
                id: "rust".to_owned(),
                rule_ids: vec!["correctness".to_owned()],
                matched_paths: vec![path("src/high.rs"), path("tests/standard.rs")],
            },
            DelegationRuleGroupInput {
                id: "tests".to_owned(),
                rule_ids: vec!["test-quality".to_owned()],
                matched_paths: vec![path("tests/standard.rs")],
            },
        ],
    )
    .expect("delegation fixture")
}

fn anchors() -> AnchorTable {
    let renamed = ChangedPath {
        old_path: path("src/old name.rs"),
        new_path: path("src/new #name.rs"),
        kind: FileChangeKind::Renamed,
    };
    AnchorTable::build(
        snapshot(),
        [
            CommentableLine {
                path: renamed.clone(),
                position: AnchorPosition::deletion(4).expect("deletion"),
                exact_line_digest: digest('1'),
                context_digest: digest('2'),
            },
            CommentableLine {
                path: renamed.clone(),
                position: AnchorPosition::addition(7).expect("addition"),
                exact_line_digest: digest('3'),
                context_digest: digest('4'),
            },
            CommentableLine {
                path: renamed,
                position: AnchorPosition::context(8, 9).expect("context"),
                exact_line_digest: digest('5'),
                context_digest: digest('6'),
            },
        ],
    )
    .expect("anchor table fixture")
}

fn coverage() -> ReviewReportCoverage {
    ReviewReportCoverage {
        policy_version: "revoot.risk-adaptive-coverage/v1".to_owned(),
        high_risk_files: 1,
        standard_risk_files: 1,
        low_risk_files: 1,
        fully_read_files: 1,
        sampled_files: 1,
        manifest_only_files: 1,
        delivered_high_risk_hunks: 2,
        required_high_risk_hunks: 2,
        explicit_deferrals: 1,
        failed_groups: 0,
    }
}

fn ranked_finding(
    anchor_id: AnchorId,
    category: FindingCategory,
    severity: Severity,
    marker: char,
) -> RankedFinding {
    RankedFinding {
        work_unit_id: "wu-contract".to_owned(),
        anchor_id,
        severity,
        confidence_percent: 91,
        category,
        finding_key: digest(marker),
        content_digest: digest(
            char::from_digit(marker.to_digit(16).expect("hex marker") + 1, 16)
                .expect("next hex marker"),
        ),
        lineage_id: None,
        rendered_body: format!("Finding {marker}: exact verified evidence."),
    }
}

fn sarif_findings(anchors: &AnchorTable) -> Vec<RankedFinding> {
    let deletion = anchors
        .iter()
        .find(|item| matches!(item.position, AnchorPosition::Deletion { .. }))
        .expect("deletion anchor");
    let addition = anchors
        .iter()
        .find(|item| matches!(item.position, AnchorPosition::Addition { .. }))
        .expect("addition anchor");
    let context = anchors
        .iter()
        .find(|item| matches!(item.position, AnchorPosition::Context { .. }))
        .expect("context anchor");
    vec![
        ranked_finding(
            context.id.clone(),
            FindingCategory::Reliability,
            Severity::Low,
            '3',
        ),
        ranked_finding(
            deletion.id.clone(),
            FindingCategory::Correctness,
            Severity::Medium,
            '1',
        ),
        ranked_finding(
            addition.id.clone(),
            FindingCategory::Security,
            Severity::Critical,
            '2',
        ),
    ]
}

fn usage() -> ReviewReportUsage {
    ReviewReportUsage {
        phases: [
            ReviewReportPhase::Grouping,
            ReviewReportPhase::Planning,
            ReviewReportPhase::Review,
            ReviewReportPhase::Verification,
            ReviewReportPhase::Adjudication,
        ]
        .into_iter()
        .map(|phase| ReviewReportPhaseUsage {
            phase,
            model_requests: 0,
            input_tokens: 0,
            output_tokens: 0,
            tool_calls: 0,
            cost_microusd: 0,
        })
        .collect(),
        totals: ReviewReportUsageTotals::default(),
    }
}

fn report(anchors: &AnchorTable) -> ReviewReportV3 {
    let issued_anchor = anchors
        .iter()
        .find(|item| matches!(item.position, AnchorPosition::Addition { .. }))
        .expect("addition anchor");
    let source = Finding {
        anchor_id: issued_anchor.id.as_str().to_owned(),
        severity: Severity::High,
        confidence_percent: 95,
        category: FindingCategory::Security,
        title: "Validation can be bypassed".to_owned(),
        explanation: "The changed operation runs before the required validation.".to_owned(),
        evidence: "The issued addition anchor identifies the unguarded operation.".to_owned(),
        lineage_id: None,
        suggested_replacement: None,
    };
    let envelope = FindingsEnvelope {
        schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
        work_unit_id: "wu-contract".to_owned(),
        findings: vec![source.clone()],
        summary: "One exact-anchor finding.".to_owned(),
    };
    let issued = BTreeMap::from([(
        "wu-contract".to_owned(),
        BTreeSet::from([issued_anchor.id.clone()]),
    )]);
    let ranked = validate_rank_and_render([envelope], &issued, anchors, 25)
        .expect("ranked finding")
        .findings
        .remove(0);
    let overview_text = "Review completed with one verified finding.".to_owned();
    let snapshot_identity = serde_json::to_vec(anchors.identity()).expect("snapshot JSON");
    ReviewReportV3::new(
        ReviewReportState::Complete,
        Sha256Digest::of_bytes(&snapshot_identity),
        digest('f'),
        vec![ReviewReportFinding {
            work_unit_id: ranked.work_unit_id,
            anchor_id: ranked.anchor_id,
            coordinate: ReviewReportFindingCoordinate {
                path: issued_anchor.path.new_path.clone(),
                side: ReviewReportFindingSide::New,
                line: 7,
            },
            finding_key: ranked.finding_key,
            content_sha256: ranked.content_digest,
            severity: source.severity,
            confidence_percent: source.confidence_percent,
            category: source.category,
            title: source.title,
            explanation: source.explanation,
            evidence: source.evidence,
            suggested_replacement: source.suggested_replacement,
            rendered_body: ranked.rendered_body,
            lineage_id: source.lineage_id,
        }],
        ReviewReportOverview {
            content_sha256: Sha256Digest::of_bytes(overview_text.as_bytes()),
            text: overview_text,
        },
        Vec::new(),
        ReviewReportPublication {
            planned_findings: 1,
            published_findings: 1,
            suppressed_findings: 0,
            publication_complete: true,
        },
        ReviewReportSelection {
            changed_files: 3,
            selected_files: 3,
            omitted_files: 0,
            selected_diff_bytes: 128,
            omission_reasons: BTreeMap::<ReviewOmissionReason, u32>::new(),
        },
        ReviewReportStrategy {
            effort: ReviewEffort::Medium,
            grouping_source: ReviewGroupingSource::Deterministic,
            group_count: 1,
            max_parallel_groups: 4,
        },
        coverage(),
        usage(),
    )
    .expect("report fixture")
}

fn scan_sarif(anchors: &AnchorTable, findings: &[RankedFinding]) -> SarifLog {
    render_sarif(
        &findings[..1],
        anchors,
        SarifRunMetadata {
            partial: true,
            coverage: SarifCoverageMetadata {
                selected_files: 3,
                fully_read_files: 1,
                sampled_files: 1,
                manifest_only_files: 0,
                delivered_high_risk_hunks: 1,
                required_high_risk_hunks: 2,
                explicit_deferrals: 1,
                failed_groups: 1,
                policy_version: "revoot.risk-adaptive-coverage/v1".to_owned(),
            },
        },
    )
    .expect("scan SARIF fixture")
}

fn pretty<T: Serialize>(value: &T) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(value).expect("serialize contract fixture")
    )
}

fn assert_schema(schema: &str, id: &str, required: &[&str]) {
    let value: Value = serde_json::from_str(schema).expect("valid JSON schema");
    assert_eq!(
        value["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(value["$id"], id);
    assert_eq!(value["type"], "object");
    assert_eq!(value["additionalProperties"], false);
    let declared = value["required"]
        .as_array()
        .expect("required array")
        .iter()
        .map(|item| item.as_str().expect("required field"))
        .collect::<BTreeSet<_>>();
    assert_eq!(declared, required.iter().copied().collect());
}

fn assert_body_free(value: &str) {
    for field in [
        "artifact_path",
        "diff_body",
        "prompt",
        "provider_response",
        "raw_response",
        "source_body",
        "tool_payload",
    ] {
        assert!(!value.contains(&format!("\"{field}\"")));
    }
}

#[test]
fn schemas_are_strict_versioned_contracts() {
    assert_schema(
        REPORT_SCHEMA,
        "https://schemas.revoot.dev/review-report-v3.schema.json",
        &[
            "schema_version",
            "state",
            "snapshot_sha256",
            "partition_sha256",
            "findings",
            "overview",
            "lineage",
            "publication",
            "selection",
            "strategy",
            "coverage",
            "usage",
            "report_sha256",
        ],
    );
    assert_schema(
        GROUP_SCHEMA,
        "https://schemas.revoot.dev/review-group-plan-v1.schema.json",
        &[
            "schema_version",
            "partition_sha256",
            "source",
            "limits",
            "groups",
            "plan_sha256",
        ],
    );
    assert_schema(
        DELEGATION_SCHEMA,
        "https://schemas.revoot.dev/delegation-v1.schema.json",
        &[
            "schema_version",
            "snapshot",
            "partition_sha256",
            "policy_digests",
            "files",
            "exclusions",
            "rule_groups",
            "manifest_sha256",
        ],
    );
    assert_schema(
        COVERAGE_SCHEMA,
        "https://schemas.revoot.dev/coverage-v1.schema.json",
        &[
            "policy_version",
            "high_risk_files",
            "standard_risk_files",
            "low_risk_files",
            "fully_read_files",
            "sampled_files",
            "manifest_only_files",
            "delivered_high_risk_hunks",
            "required_high_risk_hunks",
            "explicit_deferrals",
            "failed_groups",
        ],
    );
    assert_schema(
        SARIF_SCHEMA,
        "https://schemas.revoot.dev/sarif-2.1.0.schema.json",
        &["version", "$schema", "runs"],
    );

    let report_schema: Value = serde_json::from_str(REPORT_SCHEMA).expect("report schema");
    let group_schema: Value = serde_json::from_str(GROUP_SCHEMA).expect("group schema");
    let delegation_schema: Value =
        serde_json::from_str(DELEGATION_SCHEMA).expect("delegation schema");
    let coverage_schema: Value = serde_json::from_str(COVERAGE_SCHEMA).expect("coverage schema");
    let sarif_schema: Value = serde_json::from_str(SARIF_SCHEMA).expect("SARIF schema");
    let external_schemas = BTreeMap::from([("coverage-v1.schema.json", coverage_schema.clone())]);
    for (schema, golden) in [
        (&report_schema, REPORT_GOLDEN),
        (&group_schema, GROUP_GOLDEN),
        (&delegation_schema, DELEGATION_GOLDEN),
        (&coverage_schema, COVERAGE_GOLDEN),
        (&sarif_schema, REVIEW_SARIF_GOLDEN),
        (&sarif_schema, SCAN_SARIF_GOLDEN),
    ] {
        let instance = serde_json::from_str(golden).expect("valid golden JSON");
        contract_schema::assert_valid(schema, &instance, &external_schemas);
    }
}

#[test]
fn checked_in_goldens_match_public_serializers() {
    let partition = partition();
    let group = group_plan(&partition);
    let delegation = delegation(&partition);
    let anchors = anchors();
    let coverage = coverage();
    let report = report(&anchors);
    let findings = sarif_findings(&anchors);
    let review_sarif =
        render_review_sarif(&findings, &anchors, ReviewReportState::Complete, &coverage)
            .expect("review SARIF fixture");
    let scan_sarif = scan_sarif(&anchors, &findings);

    assert_eq!(pretty(&report), REPORT_GOLDEN);
    assert_eq!(pretty(&group), GROUP_GOLDEN);
    assert_eq!(pretty(&delegation), DELEGATION_GOLDEN);
    assert_eq!(pretty(&coverage), COVERAGE_GOLDEN);
    assert_eq!(pretty(&review_sarif), REVIEW_SARIF_GOLDEN);
    assert_eq!(pretty(&scan_sarif), SCAN_SARIF_GOLDEN);

    let report_round_trip: ReviewReportV3 =
        serde_json::from_str(REPORT_GOLDEN).expect("report golden");
    report_round_trip.validate().expect("valid report golden");
    let group_round_trip: ReviewGroupPlan =
        serde_json::from_str(GROUP_GOLDEN).expect("group golden");
    group_round_trip
        .validate_against(&partition)
        .expect("valid group golden");
    let delegation_round_trip: DelegationManifest =
        serde_json::from_str(DELEGATION_GOLDEN).expect("delegation golden");
    delegation_round_trip
        .validate_against(&partition)
        .expect("valid delegation golden");
    let _: ReviewReportCoverage = serde_json::from_str(COVERAGE_GOLDEN).expect("coverage golden");
    let _: SarifLog = serde_json::from_str(REVIEW_SARIF_GOLDEN).expect("review SARIF golden");
    let _: SarifLog = serde_json::from_str(SCAN_SARIF_GOLDEN).expect("scan SARIF golden");

    for golden in [
        REPORT_GOLDEN,
        GROUP_GOLDEN,
        DELEGATION_GOLDEN,
        COVERAGE_GOLDEN,
        REVIEW_SARIF_GOLDEN,
        SCAN_SARIF_GOLDEN,
    ] {
        assert_body_free(golden);
    }
}
