//! Deterministic SARIF 2.1.0 rendering for verified findings.
//!
//! Rendering resolves only trusted anchors. Coverage properties contain counts
//! and policy identity, never source or diff bodies.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AnchorPosition, AnchorTable, FindingCategory, RankedFinding, RepositoryPath, Severity,
    Sha256Digest,
};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const MAX_RESULTS: usize = 250;
const MAX_MESSAGE_BYTES: usize = 8 * 1024;
const MAX_POLICY_VERSION_BYTES: usize = 128;
const TRUNCATED_MESSAGE_SUFFIX: &str = "\n\n[message truncated]";

/// Body-free aggregate coverage included in SARIF run properties.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifCoverageMetadata {
    pub selected_files: u32,
    pub fully_read_files: u32,
    pub sampled_files: u32,
    pub manifest_only_files: u32,
    pub delivered_high_risk_hunks: u32,
    pub required_high_risk_hunks: u32,
    pub explicit_deferrals: u32,
    pub failed_groups: u32,
    pub policy_version: String,
}

/// Review completion state attached to one SARIF run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifRunMetadata {
    pub partial: bool,
    pub coverage: SarifCoverageMetadata,
}

/// SARIF 2.1.0 log emitted by Revoot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SarifLog {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub invocations: Vec<SarifInvocation>,
    pub results: Vec<SarifResult>,
    pub properties: SarifRunProperties,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifDriver {
    pub name: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifInvocation {
    pub execution_successful: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifResult {
    pub rule_id: String,
    pub level: SarifLevel,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub partial_fingerprints: SarifFingerprints,
    pub properties: SarifResultProperties,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SarifLevel {
    Error,
    Warning,
    Note,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifArtifactLocation {
    pub uri: String,
    pub uri_base_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifRegion {
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifFingerprints {
    #[serde(rename = "revootFindingKey/v1")]
    pub finding_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SarifDiffSide {
    Old,
    New,
    Both,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifResultProperties {
    pub anchor_id: String,
    pub work_unit_id: String,
    pub confidence_percent: u8,
    pub diff_side: SarifDiffSide,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line: Option<u32>,
    pub content_sha256: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_sha256: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SarifRunProperties {
    pub snapshot_sha256: Sha256Digest,
    pub partial: bool,
    pub coverage: SarifCoverageMetadata,
}

/// Failure while converting verified findings to SARIF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SarifError {
    TooManyResults,
    InvalidCoverage,
    UnknownAnchor,
    DuplicateFinding,
    LineZero,
    InvalidPath,
    InvalidText,
    Serialization,
}

impl fmt::Display for SarifError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyResults => "the SARIF result limit was exceeded",
            Self::InvalidCoverage => "the SARIF coverage metadata is invalid",
            Self::UnknownAnchor => "a SARIF result does not resolve to a trusted anchor",
            Self::DuplicateFinding => "the SARIF input contains a duplicate verified finding",
            Self::LineZero => "SARIF locations cannot use line zero",
            Self::InvalidPath => "a SARIF artifact path cannot be represented safely",
            Self::InvalidText => "a SARIF message contains invalid text",
            Self::Serialization => "SARIF serialization failed",
        })
    }
}

impl std::error::Error for SarifError {}

impl SarifLog {
    /// Serialize this typed SARIF log without adding source content.
    ///
    /// # Errors
    ///
    /// Returns an error only if typed JSON serialization unexpectedly fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>, SarifError> {
        serde_json::to_vec(self).map_err(|_| SarifError::Serialization)
    }
}

/// Render verified, ranked findings against their exact trusted anchors.
///
/// Input order does not affect output order. Finding messages are bounded to
/// 8 KiB at a UTF-8 boundary; their full verified content digest is retained.
///
/// # Errors
///
/// Rejects excessive or duplicate results, unknown anchors, invalid coverage,
/// unsafe paths, line zero, invalid message controls, or serialization failure.
#[allow(clippy::too_many_lines)]
pub fn render_sarif(
    findings: &[RankedFinding],
    anchors: &AnchorTable,
    metadata: SarifRunMetadata,
) -> Result<SarifLog, SarifError> {
    if findings.len() > MAX_RESULTS {
        return Err(SarifError::TooManyResults);
    }
    validate_coverage(&metadata.coverage)?;
    let mut findings = findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.finding_key
            .cmp(&right.finding_key)
            .then_with(|| left.anchor_id.cmp(&right.anchor_id))
            .then_with(|| left.content_digest.cmp(&right.content_digest))
    });
    if findings
        .windows(2)
        .any(|pair| pair[0].finding_key == pair[1].finding_key)
    {
        return Err(SarifError::DuplicateFinding);
    }

    let mut categories = BTreeSet::new();
    let mut results = Vec::with_capacity(findings.len());
    for finding in findings {
        let anchor = anchors
            .resolve(finding.anchor_id.as_str())
            .ok_or(SarifError::UnknownAnchor)?;
        categories.insert(finding.category);
        let (path, physical_line, diff_side, old_line, new_line) = match anchor.position {
            AnchorPosition::Addition { new_line } => (
                &anchor.path.new_path,
                new_line,
                SarifDiffSide::New,
                None,
                Some(new_line),
            ),
            AnchorPosition::Deletion { old_line } => (
                &anchor.path.old_path,
                old_line,
                SarifDiffSide::Old,
                Some(old_line),
                None,
            ),
            AnchorPosition::Context { old_line, new_line } => (
                &anchor.path.new_path,
                new_line,
                SarifDiffSide::Both,
                Some(old_line),
                Some(new_line),
            ),
        };
        if physical_line == 0 || old_line == Some(0) || new_line == Some(0) {
            return Err(SarifError::LineZero);
        }
        validate_message(&finding.rendered_body)?;
        results.push(SarifResult {
            rule_id: rule_id(finding.category).to_owned(),
            level: level(finding.severity),
            message: SarifMessage {
                text: bounded_message(&finding.rendered_body),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: artifact_uri(path)?,
                        uri_base_id: "%SRCROOT%".to_owned(),
                    },
                    region: SarifRegion {
                        start_line: physical_line,
                        end_line: physical_line,
                    },
                },
            }],
            partial_fingerprints: SarifFingerprints {
                finding_key: finding.finding_key.as_str().to_owned(),
            },
            properties: SarifResultProperties {
                anchor_id: finding.anchor_id.as_str().to_owned(),
                work_unit_id: finding.work_unit_id.clone(),
                confidence_percent: finding.confidence_percent,
                diff_side,
                old_line,
                new_line,
                content_sha256: finding.content_digest.clone(),
                lineage_sha256: finding.lineage_id.clone(),
            },
        });
    }
    let rules = categories.into_iter().map(sarif_rule).collect();
    let snapshot_sha256 = Sha256Digest::of_bytes(
        &serde_json::to_vec(anchors.identity()).map_err(|_| SarifError::Serialization)?,
    );
    Ok(SarifLog {
        version: SARIF_VERSION.to_owned(),
        schema: SARIF_SCHEMA.to_owned(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Revoot".to_owned(),
                    information_uri: "https://github.com/getrevoot/revoot".to_owned(),
                    rules,
                },
            },
            invocations: vec![SarifInvocation {
                // SARIF construction succeeded even when review coverage was
                // partial; the review state is carried separately below.
                execution_successful: true,
            }],
            results,
            properties: SarifRunProperties {
                snapshot_sha256,
                partial: metadata.partial,
                coverage: metadata.coverage,
            },
        }],
    })
}

fn validate_coverage(coverage: &SarifCoverageMetadata) -> Result<(), SarifError> {
    let represented = coverage
        .fully_read_files
        .checked_add(coverage.sampled_files)
        .and_then(|value| value.checked_add(coverage.manifest_only_files));
    if represented.is_none_or(|value| value > coverage.selected_files)
        || coverage.delivered_high_risk_hunks > coverage.required_high_risk_hunks
        || !valid_label(&coverage.policy_version, MAX_POLICY_VERSION_BYTES)
    {
        return Err(SarifError::InvalidCoverage);
    }
    Ok(())
}

fn validate_message(message: &str) -> Result<(), SarifError> {
    if message.trim().is_empty()
        || message
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(SarifError::InvalidText);
    }
    Ok(())
}

fn bounded_message(message: &str) -> String {
    if message.len() <= MAX_MESSAGE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_MESSAGE_BYTES - TRUNCATED_MESSAGE_SUFFIX.len();
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = message[..end].to_owned();
    bounded.push_str(TRUNCATED_MESSAGE_SUFFIX);
    bounded
}

fn artifact_uri(path: &RepositoryPath) -> Result<String, SarifError> {
    if path.as_str().starts_with('/') || path.as_str().is_empty() {
        return Err(SarifError::InvalidPath);
    }
    let mut uri = String::new();
    for (index, segment) in path.as_str().split('/').enumerate() {
        if segment.is_empty() {
            return Err(SarifError::InvalidPath);
        }
        if index != 0 {
            uri.push('/');
        }
        if matches!(segment, "." | "..") {
            for _ in segment.bytes() {
                uri.push_str("%2E");
            }
            continue;
        }
        for byte in segment.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                uri.push(char::from(byte));
            } else {
                use std::fmt::Write as _;
                write!(&mut uri, "%{byte:02X}").map_err(|_| SarifError::Serialization)?;
            }
        }
    }
    Ok(uri)
}

const fn level(severity: Severity) -> SarifLevel {
    match severity {
        Severity::Critical | Severity::High => SarifLevel::Error,
        Severity::Medium => SarifLevel::Warning,
        Severity::Low | Severity::Info => SarifLevel::Note,
    }
}

const fn rule_id(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Correctness => "revoot.correctness",
        FindingCategory::Security => "revoot.security",
        FindingCategory::Reliability => "revoot.reliability",
        FindingCategory::Performance => "revoot.performance",
        FindingCategory::Maintainability => "revoot.maintainability",
    }
}

fn sarif_rule(category: FindingCategory) -> SarifRule {
    let name = match category {
        FindingCategory::Correctness => "Correctness",
        FindingCategory::Security => "Security",
        FindingCategory::Reliability => "Reliability",
        FindingCategory::Performance => "Performance",
        FindingCategory::Maintainability => "Maintainability",
    };
    SarifRule {
        id: rule_id(category).to_owned(),
        name: name.to_owned(),
        short_description: SarifMessage {
            text: format!("Revoot {name} finding"),
        },
    }
}

fn valid_label(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ChangedPath, CommentableLine, FileChangeKind, GitSha, LocalSnapshotIdentity,
        ReviewSnapshotIdentity,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn anchors() -> AnchorTable {
        let snapshot = ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
            repository_identity_sha256: digest('a'),
            base_sha: GitSha::try_from("b".repeat(40)).unwrap(),
            head_sha: GitSha::try_from("c".repeat(40)).unwrap(),
            working_tree_sha256: digest('d'),
            exact_diff_manifest_sha256: digest('e'),
        });
        let modified = ChangedPath {
            old_path: path("src/old name.rs"),
            new_path: path("src/new name.rs"),
            kind: FileChangeKind::Renamed,
        };
        AnchorTable::build(
            snapshot,
            [
                CommentableLine {
                    path: modified.clone(),
                    position: AnchorPosition::deletion(4).unwrap(),
                    exact_line_digest: digest('1'),
                    context_digest: digest('2'),
                },
                CommentableLine {
                    path: modified.clone(),
                    position: AnchorPosition::addition(7).unwrap(),
                    exact_line_digest: digest('3'),
                    context_digest: digest('4'),
                },
                CommentableLine {
                    path: modified,
                    position: AnchorPosition::context(8, 9).unwrap(),
                    exact_line_digest: digest('5'),
                    context_digest: digest('6'),
                },
            ],
        )
        .unwrap()
    }

    fn finding(
        anchor_id: crate::AnchorId,
        category: FindingCategory,
        severity: Severity,
        marker: char,
    ) -> RankedFinding {
        RankedFinding {
            work_unit_id: "wu2_test".to_owned(),
            anchor_id,
            severity,
            confidence_percent: 91,
            category,
            finding_key: digest(marker),
            content_digest: digest(char::from_digit(marker.to_digit(16).unwrap() + 1, 16).unwrap()),
            lineage_id: None,
            rendered_body: format!("Finding {marker}: exact verified evidence."),
        }
    }

    fn metadata(partial: bool) -> SarifRunMetadata {
        SarifRunMetadata {
            partial,
            coverage: SarifCoverageMetadata {
                selected_files: 3,
                fully_read_files: 1,
                sampled_files: 1,
                manifest_only_files: 1,
                delivered_high_risk_hunks: 2,
                required_high_risk_hunks: 2,
                explicit_deferrals: 1,
                failed_groups: u32::from(partial),
                policy_version: "coverage-v1".to_owned(),
            },
        }
    }

    #[test]
    fn golden_sarif_preserves_changed_side_coordinates() {
        let anchors = anchors();
        let deletion = anchors
            .iter()
            .find(|anchor| matches!(anchor.position, AnchorPosition::Deletion { .. }))
            .unwrap();
        let context = anchors
            .iter()
            .find(|anchor| matches!(anchor.position, AnchorPosition::Context { .. }))
            .unwrap();
        let findings = vec![
            finding(
                context.id.clone(),
                FindingCategory::Security,
                Severity::Critical,
                '2',
            ),
            finding(
                deletion.id.clone(),
                FindingCategory::Correctness,
                Severity::Medium,
                '1',
            ),
        ];
        let log = render_sarif(&findings, &anchors, metadata(true)).unwrap();
        let json = String::from_utf8(log.canonical_json().unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(
            value["runs"][0]["results"][0]["properties"]["diffSide"],
            "old"
        );
        assert_eq!(value["runs"][0]["results"][0]["properties"]["oldLine"], 4);
        assert!(
            value["runs"][0]["results"][0]["properties"]
                .get("newLine")
                .is_none()
        );
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            4
        );
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/old%20name.rs"
        );
        assert_eq!(
            value["runs"][0]["results"][1]["properties"]["diffSide"],
            "both"
        );
        assert_eq!(value["runs"][0]["results"][1]["properties"]["oldLine"], 8);
        assert_eq!(value["runs"][0]["results"][1]["properties"]["newLine"], 9);
        assert_eq!(value["runs"][0]["properties"]["partial"], true);
        assert_eq!(
            value["runs"][0]["properties"]["coverage"]["failedGroups"],
            1
        );
        assert!(json.len() < 10_000);
    }

    #[test]
    fn rendering_is_independent_of_input_order() {
        let anchors = anchors();
        let selected = anchors.iter().take(2).collect::<Vec<_>>();
        let left = vec![
            finding(
                selected[0].id.clone(),
                FindingCategory::Reliability,
                Severity::High,
                '1',
            ),
            finding(
                selected[1].id.clone(),
                FindingCategory::Performance,
                Severity::Low,
                '2',
            ),
        ];
        let right = left.iter().cloned().rev().collect::<Vec<_>>();
        assert_eq!(
            render_sarif(&left, &anchors, metadata(false)).unwrap(),
            render_sarif(&right, &anchors, metadata(false)).unwrap()
        );
    }

    #[test]
    fn messages_are_utf8_safely_bounded() {
        let anchors = anchors();
        let mut finding = finding(
            anchors.iter().next().unwrap().id.clone(),
            FindingCategory::Maintainability,
            Severity::Info,
            '1',
        );
        finding.rendered_body = "é".repeat(MAX_MESSAGE_BYTES);
        let log = render_sarif(&[finding], &anchors, metadata(false)).unwrap();
        let message = &log.runs[0].results[0].message.text;
        assert!(message.len() <= MAX_MESSAGE_BYTES);
        assert!(message.ends_with("[message truncated]"));
    }

    #[test]
    fn unknown_anchors_duplicates_and_bad_coverage_fail_closed() {
        let anchors = anchors();
        let first = anchors.iter().next().unwrap();
        let item = finding(
            first.id.clone(),
            FindingCategory::Correctness,
            Severity::High,
            '1',
        );
        assert_eq!(
            render_sarif(&[item.clone(), item], &anchors, metadata(false)),
            Err(SarifError::DuplicateFinding)
        );

        let mut coverage = metadata(false);
        coverage.coverage.fully_read_files = 4;
        assert_eq!(
            render_sarif(&[], &anchors, coverage),
            Err(SarifError::InvalidCoverage)
        );

        let other_anchors = AnchorTable::build(
            anchors.identity().clone(),
            std::iter::empty::<CommentableLine>(),
        )
        .unwrap();
        let item = finding(
            first.id.clone(),
            FindingCategory::Correctness,
            Severity::High,
            '1',
        );
        assert_eq!(
            render_sarif(&[item], &other_anchors, metadata(false)),
            Err(SarifError::UnknownAnchor)
        );
    }

    #[test]
    fn coverage_properties_contain_no_source_body_fields() {
        let anchors = anchors();
        let log = render_sarif(&[], &anchors, metadata(true)).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&log.canonical_json().unwrap()).unwrap();
        let coverage = &value["runs"][0]["properties"]["coverage"];
        for forbidden in ["body", "content", "diff", "prompt", "response", "source"] {
            assert!(coverage.get(forbidden).is_none());
        }
    }
}
