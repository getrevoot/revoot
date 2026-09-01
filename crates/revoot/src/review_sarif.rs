//! Exact-anchor SARIF rendering for completed review results.
//!
//! This adapter only translates trusted review state and aggregate coverage.
//! Finding coordinates, paths, sides, rules, and fingerprints remain derived
//! by the core SARIF renderer from the immutable anchor table.

use revoot_core::{
    AnchorTable, RankedFinding, ReviewReportCoverage, ReviewReportError, ReviewReportState,
    ReviewReportV3, SarifCoverageMetadata, SarifError, SarifLog, SarifRunMetadata, render_sarif,
};

/// Fail-closed error for canonical report or SARIF validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewSarifError {
    Report(ReviewReportError),
    Sarif(SarifError),
}

impl std::fmt::Display for ReviewSarifError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Report(_) => "canonical review report is not bound to the trusted anchors",
            Self::Sarif(_) => "review SARIF rendering failed",
        })
    }
}

impl std::error::Error for ReviewSarifError {}

/// Render a canonical version-3 report through its trusted anchor table.
///
/// The report is replay-validated against `anchors` before any SARIF result is
/// emitted. Report coordinates are never used as an independent or fallback
/// location source.
///
/// # Errors
///
/// Fails closed for an invalid report, snapshot mismatch, unknown anchor,
/// coordinate mismatch, line zero, or invalid SARIF coverage/content.
pub fn render_report_v3_sarif(
    report: &ReviewReportV3,
    anchors: &AnchorTable,
) -> Result<SarifLog, ReviewSarifError> {
    report
        .validate_against_anchors(anchors)
        .map_err(ReviewSarifError::Report)?;
    let findings = report
        .findings
        .iter()
        .map(|finding| RankedFinding {
            work_unit_id: finding.work_unit_id.clone(),
            anchor_id: finding.anchor_id.clone(),
            severity: finding.severity,
            confidence_percent: finding.confidence_percent,
            category: finding.category,
            finding_key: finding.finding_key.clone(),
            content_digest: finding.content_sha256.clone(),
            lineage_id: finding.lineage_id.clone(),
            rendered_body: finding.rendered_body.clone(),
        })
        .collect::<Vec<_>>();
    render_review_sarif(&findings, anchors, report.state, &report.coverage)
        .map_err(ReviewSarifError::Sarif)
}

/// Render ranked review findings as deterministic SARIF 2.1.0.
///
/// The adapter never substitutes a fallback location. Every finding must
/// resolve to a non-zero coordinate in `anchors`; the core renderer preserves
/// old-side deletions, new-side additions, and both-side context coordinates.
///
/// # Errors
///
/// Returns [`SarifError::InvalidCoverage`] for overflowing or contradictory
/// aggregate coverage. All exact-anchor, duplicate, path, text, and result
/// bounds are enforced by the core renderer.
pub fn render_review_sarif(
    findings: &[RankedFinding],
    anchors: &AnchorTable,
    state: ReviewReportState,
    coverage: &ReviewReportCoverage,
) -> Result<SarifLog, SarifError> {
    let selected_files = coverage
        .high_risk_files
        .checked_add(coverage.standard_risk_files)
        .and_then(|value| value.checked_add(coverage.low_risk_files))
        .ok_or(SarifError::InvalidCoverage)?;
    if matches!(
        state,
        ReviewReportState::Complete | ReviewReportState::NoFindings
    ) && (coverage.failed_groups != 0
        || coverage.delivered_high_risk_hunks != coverage.required_high_risk_hunks)
    {
        return Err(SarifError::InvalidCoverage);
    }
    if state == ReviewReportState::NoFindings && !findings.is_empty() {
        return Err(SarifError::InvalidCoverage);
    }
    render_sarif(
        findings,
        anchors,
        SarifRunMetadata {
            partial: !matches!(
                state,
                ReviewReportState::Complete | ReviewReportState::NoFindings
            ),
            coverage: SarifCoverageMetadata {
                selected_files,
                fully_read_files: coverage.fully_read_files,
                sampled_files: coverage.sampled_files,
                manifest_only_files: coverage.manifest_only_files,
                delivered_high_risk_hunks: coverage.delivered_high_risk_hunks,
                required_high_risk_hunks: coverage.required_high_risk_hunks,
                explicit_deferrals: coverage.explicit_deferrals,
                failed_groups: coverage.failed_groups,
                policy_version: coverage.policy_version.clone(),
            },
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::json;

    use super::*;
    use revoot_core::{
        AnchorPosition, ChangedPath, CommentableLine, FileChangeKind, Finding, FindingCategory,
        FindingsEnvelope, GitSha, LocalSnapshotIdentity, RepositoryPath, ReviewEffort,
        ReviewGroupingSource, ReviewReportFinding, ReviewReportFindingCoordinate,
        ReviewReportFindingSide, ReviewReportOverview, ReviewReportPhase, ReviewReportPhaseUsage,
        ReviewReportPublication, ReviewReportSelection, ReviewReportStrategy, ReviewReportUsage,
        ReviewReportUsageTotals, ReviewSnapshotIdentity, Severity, Sha256Digest,
        validate_rank_and_render,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).expect("digest")
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).expect("path")
    }

    fn anchors() -> AnchorTable {
        let snapshot = ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
            repository_identity_sha256: digest('a'),
            base_sha: GitSha::try_from("b".repeat(40)).expect("base SHA"),
            head_sha: GitSha::try_from("c".repeat(40)).expect("head SHA"),
            working_tree_sha256: digest('d'),
            exact_diff_manifest_sha256: digest('e'),
        });
        let renamed = ChangedPath {
            old_path: path("src/old name.rs"),
            new_path: path("src/new #name.rs"),
            kind: FileChangeKind::Renamed,
        };
        AnchorTable::build(
            snapshot,
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
        .expect("anchor table")
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

    fn finding(
        anchor_id: revoot_core::AnchorId,
        category: FindingCategory,
        severity: Severity,
        marker: char,
    ) -> RankedFinding {
        RankedFinding {
            work_unit_id: "wu2_fixture".to_owned(),
            anchor_id,
            severity,
            confidence_percent: 91,
            category,
            finding_key: digest(marker),
            content_digest: digest(
                char::from_digit(marker.to_digit(16).expect("hex") + 1, 16).expect("next hex"),
            ),
            lineage_id: None,
            rendered_body: format!("Finding {marker}: exact verified evidence."),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn report(anchors: &AnchorTable) -> ReviewReportV3 {
        let anchor = anchors
            .iter()
            .find(|anchor| matches!(anchor.position, AnchorPosition::Addition { .. }))
            .expect("addition anchor");
        let source = Finding {
            anchor_id: anchor.id.as_str().to_owned(),
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
            work_unit_id: "wu2_fixture".to_owned(),
            findings: vec![source.clone()],
            summary: "One exact-anchor finding.".to_owned(),
        };
        let issued = BTreeMap::from([(
            "wu2_fixture".to_owned(),
            BTreeSet::from([anchor.id.clone()]),
        )]);
        let ranked = validate_rank_and_render([envelope], &issued, anchors, 25)
            .expect("ranked finding")
            .findings
            .remove(0);
        let overview_text = "Review completed with one verified finding.".to_owned();
        let phases = [
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
        .collect();
        let snapshot_identity = serde_json::to_vec(anchors.identity()).expect("snapshot identity");
        ReviewReportV3::new(
            ReviewReportState::Complete,
            Sha256Digest::of_bytes(&snapshot_identity),
            digest('f'),
            vec![ReviewReportFinding {
                work_unit_id: ranked.work_unit_id,
                anchor_id: ranked.anchor_id,
                coordinate: ReviewReportFindingCoordinate {
                    path: anchor.path.new_path.clone(),
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
                omission_reasons: BTreeMap::new(),
            },
            ReviewReportStrategy {
                effort: ReviewEffort::Medium,
                grouping_source: ReviewGroupingSource::Deterministic,
                group_count: 1,
                max_parallel_groups: 4,
            },
            coverage(),
            ReviewReportUsage {
                phases,
                totals: ReviewReportUsageTotals::default(),
            },
        )
        .expect("report")
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn golden_review_sarif_preserves_exact_sides_and_uri_safe_paths() {
        let anchors = anchors();
        let deletion = anchors
            .iter()
            .find(|anchor| matches!(anchor.position, AnchorPosition::Deletion { .. }))
            .expect("deletion anchor");
        let addition = anchors
            .iter()
            .find(|anchor| matches!(anchor.position, AnchorPosition::Addition { .. }))
            .expect("addition anchor");
        let context = anchors
            .iter()
            .find(|anchor| matches!(anchor.position, AnchorPosition::Context { .. }))
            .expect("context anchor");
        let findings = [
            finding(
                context.id.clone(),
                FindingCategory::Reliability,
                Severity::Low,
                '3',
            ),
            finding(
                deletion.id.clone(),
                FindingCategory::Correctness,
                Severity::Medium,
                '1',
            ),
            finding(
                addition.id.clone(),
                FindingCategory::Security,
                Severity::Critical,
                '2',
            ),
        ];
        let log = render_review_sarif(
            &findings,
            &anchors,
            ReviewReportState::Complete,
            &coverage(),
        )
        .expect("SARIF");
        let value = serde_json::to_value(&log).expect("SARIF JSON");
        let results = value["runs"][0]["results"].as_array().expect("results");
        assert_eq!(results.len(), 3);
        let expected_fingerprints = [digest('1'), digest('2'), digest('3')];
        assert_eq!(
            results
                .iter()
                .map(|result| result["properties"]["diffSide"].as_str().expect("side"))
                .collect::<Vec<_>>(),
            vec!["old", "new", "both"]
        );
        assert_eq!(results[0]["properties"]["oldLine"], 4);
        assert!(results[0]["properties"].get("newLine").is_none());
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/old%20name.rs"
        );
        assert_eq!(results[1]["properties"]["newLine"], 7);
        assert!(results[1]["properties"].get("oldLine").is_none());
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/new%20%23name.rs"
        );
        assert_eq!(results[2]["properties"]["oldLine"], 8);
        assert_eq!(results[2]["properties"]["newLine"], 9);
        assert_eq!(
            results
                .iter()
                .map(|result| result["ruleId"].as_str().expect("rule ID"))
                .collect::<Vec<_>>(),
            vec![
                "revoot.correctness",
                "revoot.security",
                "revoot.reliability"
            ]
        );
        assert_eq!(
            results
                .iter()
                .map(|result| {
                    result["partialFingerprints"]["revootFindingKey/v1"]
                        .as_str()
                        .expect("fingerprint")
                })
                .collect::<Vec<_>>(),
            expected_fingerprints
                .iter()
                .map(Sha256Digest::as_str)
                .collect::<Vec<_>>()
        );
        assert!(
            !String::from_utf8(log.canonical_json().expect("canonical JSON"))
                .expect("UTF-8")
                .contains("unknown:1")
        );
        assert_eq!(
            value["runs"][0]["properties"]["coverage"],
            json!({
                "selectedFiles": 3,
                "fullyReadFiles": 1,
                "sampledFiles": 1,
                "manifestOnlyFiles": 1,
                "deliveredHighRiskHunks": 2,
                "requiredHighRiskHunks": 2,
                "explicitDeferrals": 1,
                "failedGroups": 0,
                "policyVersion": "revoot.risk-adaptive-coverage/v1"
            })
        );
    }

    #[test]
    fn report_v3_sarif_requires_the_matching_trusted_anchor_table() {
        let anchors = anchors();
        let report = report(&anchors);
        let log = render_report_v3_sarif(&report, &anchors).expect("exact-anchor SARIF");
        let value = serde_json::to_value(log).expect("SARIF JSON");
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/new%20%23name.rs"
        );
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        assert!(!value.to_string().contains("unknown:1"));

        let empty = AnchorTable::build(
            anchors.identity().clone(),
            std::iter::empty::<CommentableLine>(),
        )
        .expect("empty anchor table");
        assert_eq!(
            render_report_v3_sarif(&report, &empty),
            Err(ReviewSarifError::Report(ReviewReportError::AnchorBinding))
        );
    }

    #[test]
    fn unknown_anchor_and_invalid_complete_coverage_fail_closed() {
        let anchors = anchors();
        let item = finding(
            anchors.iter().next().expect("anchor").id.clone(),
            FindingCategory::Correctness,
            Severity::High,
            '1',
        );
        let empty = AnchorTable::build(
            anchors.identity().clone(),
            std::iter::empty::<CommentableLine>(),
        )
        .expect("empty anchors");
        assert_eq!(
            render_review_sarif(
                std::slice::from_ref(&item),
                &empty,
                ReviewReportState::Partial,
                &coverage(),
            ),
            Err(SarifError::UnknownAnchor)
        );
        let mut incomplete = coverage();
        incomplete.delivered_high_risk_hunks = 1;
        assert_eq!(
            render_review_sarif(
                std::slice::from_ref(&item),
                &anchors,
                ReviewReportState::Complete,
                &incomplete,
            ),
            Err(SarifError::InvalidCoverage)
        );
        assert!(AnchorPosition::addition(0).is_err());
        assert!(AnchorPosition::deletion(0).is_err());
    }

    #[test]
    fn partial_state_is_explicit_and_output_is_order_stable() {
        let anchors = anchors();
        let selected = anchors.iter().take(2).collect::<Vec<_>>();
        let findings = vec![
            finding(
                selected[0].id.clone(),
                FindingCategory::Performance,
                Severity::Info,
                '1',
            ),
            finding(
                selected[1].id.clone(),
                FindingCategory::Maintainability,
                Severity::Low,
                '2',
            ),
        ];
        let mut partial_coverage = coverage();
        partial_coverage.failed_groups = 1;
        let left = render_review_sarif(
            &findings,
            &anchors,
            ReviewReportState::Partial,
            &partial_coverage,
        )
        .expect("left");
        let right = render_review_sarif(
            &findings.iter().cloned().rev().collect::<Vec<_>>(),
            &anchors,
            ReviewReportState::Partial,
            &partial_coverage,
        )
        .expect("right");
        assert_eq!(left, right);
        assert!(left.runs[0].properties.partial);
        assert_eq!(left.runs[0].properties.coverage.failed_groups, 1);
    }
}
