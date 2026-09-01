//! Canonical payload-free accounting contract for review report version 3.
//!
//! The report retains finding identities and bounded overview text, but no raw
//! source, prompts, responses, tool payloads, or temporary artifact locations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AnchorId, FindingCategory, ReviewEffort, ReviewGroupingSource, ReviewOmissionReason, Severity,
    Sha256Digest,
};

const MAX_FINDINGS: usize = 25;
const MAX_OVERVIEW_BYTES: usize = 8 * 1024;
const MAX_POLICY_VERSION_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReportState {
    Complete,
    Partial,
    NoFindings,
    Blocked,
    Failed,
    Cancelled,
}

/// Stable reference to one verified finding; prose stays in the existing
/// findings/publication contract rather than being copied into this report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportFinding {
    pub anchor_id: AnchorId,
    pub finding_key: Sha256Digest,
    pub content_sha256: Sha256Digest,
    pub severity: Severity,
    pub confidence_percent: u8,
    pub category: FindingCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportOverview {
    pub text: String,
    pub content_sha256: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReportLineageDisposition {
    StillPresent,
    Fixed,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportLineage {
    pub lineage_id: Sha256Digest,
    pub disposition: ReviewReportLineageDisposition,
    pub evidence_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportPublication {
    pub planned_findings: u32,
    pub published_findings: u32,
    pub suppressed_findings: u32,
    pub publication_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportSelection {
    pub changed_files: u32,
    pub selected_files: u32,
    pub omitted_files: u32,
    pub selected_diff_bytes: u64,
    pub omission_reasons: BTreeMap<ReviewOmissionReason, u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportStrategy {
    pub effort: ReviewEffort,
    pub grouping_source: ReviewGroupingSource,
    pub group_count: u32,
    pub max_parallel_groups: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportCoverage {
    pub policy_version: String,
    pub high_risk_files: u32,
    pub standard_risk_files: u32,
    pub low_risk_files: u32,
    pub fully_read_files: u32,
    pub sampled_files: u32,
    pub manifest_only_files: u32,
    pub delivered_high_risk_hunks: u32,
    pub required_high_risk_hunks: u32,
    pub explicit_deferrals: u32,
    pub failed_groups: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReportPhase {
    Grouping,
    Planning,
    Review,
    Verification,
    Adjudication,
}

impl ReviewReportPhase {
    const ALL: [Self; 5] = [
        Self::Grouping,
        Self::Planning,
        Self::Review,
        Self::Verification,
        Self::Adjudication,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportPhaseUsage {
    pub phase: ReviewReportPhase,
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tool_calls: u32,
    pub cost_microusd: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportUsageTotals {
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tool_calls: u32,
    pub cost_microusd: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportUsage {
    pub phases: Vec<ReviewReportPhaseUsage>,
    pub totals: ReviewReportUsageTotals,
}

/// Stable `revoot.review-report/v3` contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportV3 {
    pub schema_version: String,
    pub state: ReviewReportState,
    pub snapshot_sha256: Sha256Digest,
    pub partition_sha256: Sha256Digest,
    pub findings: Vec<ReviewReportFinding>,
    pub overview: ReviewReportOverview,
    pub lineage: Vec<ReviewReportLineage>,
    pub publication: ReviewReportPublication,
    pub selection: ReviewReportSelection,
    pub strategy: ReviewReportStrategy,
    pub coverage: ReviewReportCoverage,
    pub usage: ReviewReportUsage,
    pub report_sha256: Sha256Digest,
}

impl ReviewReportV3 {
    pub const SCHEMA_VERSION: &'static str = "revoot.review-report/v3";

    /// Construct and validate a report while deriving its canonical digest.
    ///
    /// # Errors
    ///
    /// Returns the first schema invariant or accounting contradiction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: ReviewReportState,
        snapshot_sha256: Sha256Digest,
        partition_sha256: Sha256Digest,
        findings: Vec<ReviewReportFinding>,
        overview: ReviewReportOverview,
        lineage: Vec<ReviewReportLineage>,
        publication: ReviewReportPublication,
        selection: ReviewReportSelection,
        strategy: ReviewReportStrategy,
        coverage: ReviewReportCoverage,
        usage: ReviewReportUsage,
    ) -> Result<Self, ReviewReportError> {
        let mut report = Self {
            schema_version: Self::SCHEMA_VERSION.to_owned(),
            state,
            snapshot_sha256,
            partition_sha256,
            findings,
            overview,
            lineage,
            publication,
            selection,
            strategy,
            coverage,
            usage,
            report_sha256: Sha256Digest::of_bytes(&[]),
        };
        canonicalize(&mut report);
        report.report_sha256 = report_digest(&report)?;
        report.validate()?;
        Ok(report)
    }

    /// Validate canonical ordering, cross-field counts, phase totals, partial
    /// state, bounded text, and the report digest.
    ///
    /// # Errors
    ///
    /// Returns the first invalid field or contradiction.
    pub fn validate(&self) -> Result<(), ReviewReportError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ReviewReportError::SchemaVersion);
        }
        validate_findings(&self.findings)?;
        validate_overview(&self.overview)?;
        validate_lineage(&self.lineage)?;
        validate_selection(&self.selection)?;
        validate_strategy_coverage(&self.strategy, &self.coverage, &self.selection, self.state)?;
        validate_publication(&self.publication, self.findings.len(), self.state)?;
        validate_usage(&self.usage)?;
        if self.report_sha256 != report_digest(self)? {
            return Err(ReviewReportError::ReportDigest);
        }
        Ok(())
    }

    /// Serialize only after full schema and accounting validation.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed JSON serialization error.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ReviewReportError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ReviewReportError::Serialization)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewReportError {
    SchemaVersion,
    Findings,
    Overview,
    Lineage,
    Publication,
    Selection,
    Strategy,
    Coverage,
    PhaseOrder,
    UsageOverflow,
    UsageTotals,
    ReportDigest,
    Serialization,
}

impl fmt::Display for ReviewReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "the review report schema version is invalid",
            Self::Findings => "the review report findings are invalid",
            Self::Overview => "the review report overview is invalid",
            Self::Lineage => "the review report lineage records are invalid",
            Self::Publication => "the review report publication metadata is invalid",
            Self::Selection => "the review report selection metadata is invalid",
            Self::Strategy => "the review report strategy metadata is invalid",
            Self::Coverage => "the review report coverage metadata is invalid",
            Self::PhaseOrder => "the review report phase usage is incomplete or unordered",
            Self::UsageOverflow => "review report phase usage overflowed",
            Self::UsageTotals => "review report phase totals do not match",
            Self::ReportDigest => "the review report digest is invalid",
            Self::Serialization => "the review report could not be serialized",
        })
    }
}

impl std::error::Error for ReviewReportError {}

fn canonicalize(report: &mut ReviewReportV3) {
    report.findings.sort_by(|left, right| {
        left.finding_key
            .cmp(&right.finding_key)
            .then_with(|| left.anchor_id.cmp(&right.anchor_id))
    });
    report
        .lineage
        .sort_by(|left, right| left.lineage_id.cmp(&right.lineage_id));
    report.usage.phases.sort_by_key(|phase| phase.phase);
}

fn validate_findings(findings: &[ReviewReportFinding]) -> Result<(), ReviewReportError> {
    if findings.len() > MAX_FINDINGS
        || findings
            .iter()
            .any(|finding| finding.confidence_percent > 100)
        || findings.windows(2).any(|pair| {
            (&pair[0].finding_key, &pair[0].anchor_id) >= (&pair[1].finding_key, &pair[1].anchor_id)
        })
        || findings
            .iter()
            .map(|finding| &finding.finding_key)
            .collect::<BTreeSet<_>>()
            .len()
            != findings.len()
    {
        return Err(ReviewReportError::Findings);
    }
    Ok(())
}

fn validate_overview(overview: &ReviewReportOverview) -> Result<(), ReviewReportError> {
    if overview.text.trim().is_empty()
        || overview.text.len() > MAX_OVERVIEW_BYTES
        || overview
            .text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        || Sha256Digest::of_bytes(overview.text.as_bytes()) != overview.content_sha256
    {
        return Err(ReviewReportError::Overview);
    }
    Ok(())
}

fn validate_lineage(lineage: &[ReviewReportLineage]) -> Result<(), ReviewReportError> {
    if lineage
        .windows(2)
        .any(|pair| pair[0].lineage_id >= pair[1].lineage_id)
    {
        return Err(ReviewReportError::Lineage);
    }
    Ok(())
}

fn validate_publication(
    publication: &ReviewReportPublication,
    findings: usize,
    state: ReviewReportState,
) -> Result<(), ReviewReportError> {
    let findings = u32::try_from(findings).map_err(|_| ReviewReportError::Publication)?;
    if publication.planned_findings > findings
        || publication.published_findings > publication.planned_findings
        || publication
            .published_findings
            .checked_add(publication.suppressed_findings)
            .is_none_or(|count| count > findings)
        || (publication.publication_complete
            && publication.published_findings != publication.planned_findings)
        || (matches!(
            state,
            ReviewReportState::Blocked | ReviewReportState::Failed | ReviewReportState::Cancelled
        ) && publication.published_findings != 0)
    {
        return Err(ReviewReportError::Publication);
    }
    Ok(())
}

fn validate_selection(selection: &ReviewReportSelection) -> Result<(), ReviewReportError> {
    let omitted = selection
        .omission_reasons
        .values()
        .try_fold(0_u32, |sum, value| sum.checked_add(*value));
    if selection
        .selected_files
        .checked_add(selection.omitted_files)
        != Some(selection.changed_files)
        || omitted != Some(selection.omitted_files)
    {
        return Err(ReviewReportError::Selection);
    }
    Ok(())
}

fn validate_strategy_coverage(
    strategy: &ReviewReportStrategy,
    coverage: &ReviewReportCoverage,
    selection: &ReviewReportSelection,
    state: ReviewReportState,
) -> Result<(), ReviewReportError> {
    if strategy.max_parallel_groups == 0
        || strategy.max_parallel_groups > 8
        || (selection.selected_files > 0) != (strategy.group_count > 0)
        || coverage.failed_groups > strategy.group_count
    {
        return Err(ReviewReportError::Strategy);
    }
    let tier_files = coverage
        .high_risk_files
        .checked_add(coverage.standard_risk_files)
        .and_then(|value| value.checked_add(coverage.low_risk_files));
    let read_files = coverage
        .fully_read_files
        .checked_add(coverage.sampled_files)
        .and_then(|value| value.checked_add(coverage.manifest_only_files));
    let incomplete_required =
        coverage.delivered_high_risk_hunks < coverage.required_high_risk_hunks;
    if tier_files != Some(selection.selected_files)
        || read_files.is_none_or(|files| files > selection.selected_files)
        || coverage.delivered_high_risk_hunks > coverage.required_high_risk_hunks
        || !valid_label(&coverage.policy_version, MAX_POLICY_VERSION_BYTES)
        || (matches!(
            state,
            ReviewReportState::Complete | ReviewReportState::NoFindings
        ) && (coverage.failed_groups != 0 || incomplete_required))
        || (state == ReviewReportState::Complete && selection.omitted_files != 0)
    {
        return Err(ReviewReportError::Coverage);
    }
    Ok(())
}

fn validate_usage(usage: &ReviewReportUsage) -> Result<(), ReviewReportError> {
    if usage.phases.len() != ReviewReportPhase::ALL.len()
        || usage
            .phases
            .iter()
            .map(|phase| phase.phase)
            .ne(ReviewReportPhase::ALL)
    {
        return Err(ReviewReportError::PhaseOrder);
    }
    let mut totals = ReviewReportUsageTotals::default();
    for phase in &usage.phases {
        totals.model_requests = totals
            .model_requests
            .checked_add(phase.model_requests)
            .ok_or(ReviewReportError::UsageOverflow)?;
        totals.input_tokens = totals
            .input_tokens
            .checked_add(phase.input_tokens)
            .ok_or(ReviewReportError::UsageOverflow)?;
        totals.output_tokens = totals
            .output_tokens
            .checked_add(phase.output_tokens)
            .ok_or(ReviewReportError::UsageOverflow)?;
        totals.tool_calls = totals
            .tool_calls
            .checked_add(phase.tool_calls)
            .ok_or(ReviewReportError::UsageOverflow)?;
        totals.cost_microusd = totals
            .cost_microusd
            .checked_add(phase.cost_microusd)
            .ok_or(ReviewReportError::UsageOverflow)?;
    }
    if totals != usage.totals {
        return Err(ReviewReportError::UsageTotals);
    }
    Ok(())
}

fn report_digest(report: &ReviewReportV3) -> Result<Sha256Digest, ReviewReportError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        state: ReviewReportState,
        snapshot_sha256: &'a Sha256Digest,
        partition_sha256: &'a Sha256Digest,
        findings: &'a [ReviewReportFinding],
        overview: &'a ReviewReportOverview,
        lineage: &'a [ReviewReportLineage],
        publication: &'a ReviewReportPublication,
        selection: &'a ReviewReportSelection,
        strategy: &'a ReviewReportStrategy,
        coverage: &'a ReviewReportCoverage,
        usage: &'a ReviewReportUsage,
    }
    serde_json::to_vec(&DigestInput {
        schema_version: &report.schema_version,
        state: report.state,
        snapshot_sha256: &report.snapshot_sha256,
        partition_sha256: &report.partition_sha256,
        findings: &report.findings,
        overview: &report.overview,
        lineage: &report.lineage,
        publication: &report.publication,
        selection: &report.selection,
        strategy: &report.strategy,
        coverage: &report.coverage,
        usage: &report.usage,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| ReviewReportError::Serialization)
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

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn anchor(marker: char) -> AnchorId {
        AnchorId::try_from(format!("ga1_{}", marker.to_string().repeat(64))).unwrap()
    }

    fn phases() -> ReviewReportUsage {
        let phases = ReviewReportPhase::ALL
            .into_iter()
            .enumerate()
            .map(|(index, phase)| ReviewReportPhaseUsage {
                phase,
                model_requests: u32::try_from(index).unwrap(),
                input_tokens: u64::try_from(index * 10).unwrap(),
                output_tokens: u64::try_from(index * 2).unwrap(),
                tool_calls: u32::try_from(index * 3).unwrap(),
                cost_microusd: u64::try_from(index * 5).unwrap(),
            })
            .collect::<Vec<_>>();
        ReviewReportUsage {
            phases,
            totals: ReviewReportUsageTotals {
                model_requests: 10,
                input_tokens: 100,
                output_tokens: 20,
                tool_calls: 30,
                cost_microusd: 50,
            },
        }
    }

    fn report() -> ReviewReportV3 {
        let overview_text = "Review completed with one verified finding.".to_owned();
        ReviewReportV3::new(
            ReviewReportState::Complete,
            digest('a'),
            digest('b'),
            vec![ReviewReportFinding {
                anchor_id: anchor('1'),
                finding_key: digest('1'),
                content_sha256: digest('2'),
                severity: Severity::High,
                confidence_percent: 95,
                category: FindingCategory::Correctness,
                lineage_id: None,
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
                changed_files: 2,
                selected_files: 2,
                omitted_files: 0,
                selected_diff_bytes: 100,
                omission_reasons: BTreeMap::new(),
            },
            ReviewReportStrategy {
                effort: ReviewEffort::Medium,
                grouping_source: ReviewGroupingSource::Deterministic,
                group_count: 1,
                max_parallel_groups: 4,
            },
            ReviewReportCoverage {
                policy_version: "coverage-v1".to_owned(),
                high_risk_files: 1,
                standard_risk_files: 1,
                low_risk_files: 0,
                fully_read_files: 2,
                sampled_files: 0,
                manifest_only_files: 0,
                delivered_high_risk_hunks: 2,
                required_high_risk_hunks: 2,
                explicit_deferrals: 0,
                failed_groups: 0,
            },
            phases(),
        )
        .unwrap()
    }

    #[test]
    fn report_v3_is_canonical_and_contains_strict_phase_totals() {
        let report = report();
        report.validate().unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&report.canonical_json().unwrap()).unwrap();
        assert_eq!(value["schema_version"], ReviewReportV3::SCHEMA_VERSION);
        assert_eq!(value["usage"]["phases"].as_array().unwrap().len(), 5);
        assert_eq!(value["usage"]["totals"]["input_tokens"], 100);
        assert_eq!(value["coverage"]["fully_read_files"], 2);
    }

    #[test]
    fn phase_total_tampering_fails_closed() {
        let mut total_tampered = report();
        total_tampered.usage.totals.tool_calls += 1;
        assert_eq!(
            total_tampered.validate(),
            Err(ReviewReportError::UsageTotals)
        );

        let mut order_tampered = report();
        order_tampered.usage.phases.swap(0, 1);
        assert_eq!(
            order_tampered.validate(),
            Err(ReviewReportError::PhaseOrder)
        );
    }

    #[test]
    fn coverage_selection_and_partial_state_are_cross_checked() {
        let mut coverage_tampered = report();
        coverage_tampered.coverage.delivered_high_risk_hunks = 1;
        assert_eq!(
            coverage_tampered.validate(),
            Err(ReviewReportError::Coverage)
        );

        let mut selection_tampered = report();
        selection_tampered.selection.omitted_files = 1;
        assert_eq!(
            selection_tampered.validate(),
            Err(ReviewReportError::Selection)
        );
    }

    #[test]
    fn report_has_no_payload_or_artifact_path_fields() {
        let json = String::from_utf8(report().canonical_json().unwrap()).unwrap();
        for forbidden in [
            "artifact_path",
            "diff_body",
            "prompt",
            "provider_response",
            "raw_response",
            "source_body",
            "tool_payload",
        ] {
            assert!(!json.contains(forbidden));
        }
    }

    #[test]
    fn constructor_normalizes_finding_lineage_and_phase_order() {
        let mut usage = phases();
        usage.phases.reverse();
        let overview_text = "No findings after bounded review.".to_owned();
        let result = ReviewReportV3::new(
            ReviewReportState::NoFindings,
            digest('a'),
            digest('b'),
            Vec::new(),
            ReviewReportOverview {
                content_sha256: Sha256Digest::of_bytes(overview_text.as_bytes()),
                text: overview_text,
            },
            vec![
                ReviewReportLineage {
                    lineage_id: digest('2'),
                    disposition: ReviewReportLineageDisposition::Uncertain,
                    evidence_sha256: digest('3'),
                },
                ReviewReportLineage {
                    lineage_id: digest('1'),
                    disposition: ReviewReportLineageDisposition::Fixed,
                    evidence_sha256: digest('4'),
                },
            ],
            ReviewReportPublication {
                planned_findings: 0,
                published_findings: 0,
                suppressed_findings: 0,
                publication_complete: true,
            },
            ReviewReportSelection {
                changed_files: 1,
                selected_files: 1,
                omitted_files: 0,
                selected_diff_bytes: 1,
                omission_reasons: BTreeMap::new(),
            },
            ReviewReportStrategy {
                effort: ReviewEffort::Low,
                grouping_source: ReviewGroupingSource::Deterministic,
                group_count: 1,
                max_parallel_groups: 1,
            },
            ReviewReportCoverage {
                policy_version: "coverage-v1".to_owned(),
                high_risk_files: 0,
                standard_risk_files: 0,
                low_risk_files: 1,
                fully_read_files: 0,
                sampled_files: 0,
                manifest_only_files: 1,
                delivered_high_risk_hunks: 0,
                required_high_risk_hunks: 0,
                explicit_deferrals: 1,
                failed_groups: 0,
            },
            usage,
        )
        .unwrap();
        assert_eq!(result.lineage[0].lineage_id, digest('1'));
        assert_eq!(result.usage.phases[0].phase, ReviewReportPhase::Grouping);
    }
}
