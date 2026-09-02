//! Deterministic global-adjudication fallback for already verified findings.
//!
//! This path cannot create or mutate findings. It ranks the immutable verified
//! set, suppresses exact logical duplicates, applies the product finding cap,
//! and emits a conservative overview when a model adjudicator is unavailable.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AdjudicatedOverview, AdjudicationOutcome, AdjudicationSuppressionReason, FindingCategory,
    GloballySuppressedCandidate, Severity, VerifiedCandidate,
};

const MAX_INPUT_CANDIDATES: usize = 256;
const MAX_PUBLISHED_FINDINGS: usize = 25;

/// Trusted aggregate state used to make fallback limitations explicit.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicationFallbackCoverage {
    pub partial: bool,
    pub failed_groups: u32,
    pub deferred_files: u32,
    pub budget_exhausted: bool,
}

/// Stable, payload-free fallback failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjudicationFallbackError {
    CandidateCount,
    DuplicateCandidateId,
}

/// Rank and deduplicate verified candidates without model authority.
///
/// Every returned finding is copied exactly from `verified`. Existing lineage
/// state is deliberately absent from this contract, so this fallback cannot
/// resolve or otherwise mutate prior review discussions.
///
/// # Errors
///
/// Rejects an unbounded input or duplicate candidate identifiers.
pub fn deterministic_adjudication_fallback(
    verified: &[VerifiedCandidate],
    coverage: AdjudicationFallbackCoverage,
) -> Result<AdjudicationOutcome, AdjudicationFallbackError> {
    if verified.len() > MAX_INPUT_CANDIDATES {
        return Err(AdjudicationFallbackError::CandidateCount);
    }
    let mut candidate_ids = BTreeSet::new();
    if verified
        .iter()
        .any(|candidate| !candidate_ids.insert(candidate.candidate_id.as_str()))
    {
        return Err(AdjudicationFallbackError::DuplicateCandidateId);
    }

    let mut groups: BTreeMap<LogicalFindingKey<'_>, Vec<&VerifiedCandidate>> = BTreeMap::new();
    for candidate in verified {
        groups
            .entry(LogicalFindingKey::from(candidate))
            .or_default()
            .push(candidate);
    }
    for candidates in groups.values_mut() {
        candidates.sort_by(|left, right| candidate_order(left, right));
    }

    let mut canonical = groups
        .values()
        .filter_map(|candidates| candidates.first().copied())
        .collect::<Vec<_>>();
    canonical.sort_by(|left, right| candidate_order(left, right));
    let published_ids = canonical
        .iter()
        .take(MAX_PUBLISHED_FINDINGS)
        .map(|candidate| candidate.candidate_id.as_str())
        .collect::<BTreeSet<_>>();
    let publish = canonical
        .iter()
        .take(MAX_PUBLISHED_FINDINGS)
        .map(|candidate| (*candidate).clone())
        .collect();

    let mut suppressed = Vec::new();
    for candidates in groups.values() {
        let Some(canonical) = candidates.first() else {
            continue;
        };
        if !published_ids.contains(canonical.candidate_id.as_str()) {
            suppressed.push(lower_priority(canonical));
        }
        for duplicate in candidates.iter().skip(1) {
            let reason = if published_ids.contains(canonical.candidate_id.as_str()) {
                AdjudicationSuppressionReason::Duplicate {
                    canonical_candidate_id: canonical.candidate_id.clone(),
                }
            } else {
                AdjudicationSuppressionReason::LowerPriority
            };
            suppressed.push(GloballySuppressedCandidate {
                candidate_id: duplicate.candidate_id.clone(),
                reason,
            });
        }
    }
    suppressed.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));

    Ok(AdjudicationOutcome {
        publish,
        suppressed,
        overview: conservative_overview(coverage),
    })
}

fn lower_priority(candidate: &VerifiedCandidate) -> GloballySuppressedCandidate {
    GloballySuppressedCandidate {
        candidate_id: candidate.candidate_id.clone(),
        reason: AdjudicationSuppressionReason::LowerPriority,
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct LogicalFindingKey<'a> {
    anchor_id: &'a str,
    category: FindingCategory,
    title: &'a str,
}

impl<'a> From<&'a VerifiedCandidate> for LogicalFindingKey<'a> {
    fn from(candidate: &'a VerifiedCandidate) -> Self {
        Self {
            anchor_id: &candidate.finding.anchor_id,
            category: candidate.finding.category,
            title: &candidate.finding.title,
        }
    }
}

fn candidate_order(left: &VerifiedCandidate, right: &VerifiedCandidate) -> Ordering {
    severity_priority(right.finding.severity)
        .cmp(&severity_priority(left.finding.severity))
        .then_with(|| {
            right
                .finding
                .confidence_percent
                .cmp(&left.finding.confidence_percent)
        })
        .then_with(|| left.target_path.cmp(&right.target_path))
        .then_with(|| left.finding.anchor_id.cmp(&right.finding.anchor_id))
        .then_with(|| left.candidate_id.cmp(&right.candidate_id))
}

const fn severity_priority(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

fn conservative_overview(coverage: AdjudicationFallbackCoverage) -> AdjudicatedOverview {
    let mut assumptions = vec![
        "Global model adjudication was unavailable; verified findings were ranked deterministically."
            .to_owned(),
        "Prior review lineages were preserved because fallback ranking has no resolution authority."
            .to_owned(),
    ];
    if coverage.partial {
        assumptions.push("Review coverage is partial.".to_owned());
    }
    if coverage.failed_groups > 0 {
        assumptions.push(format!("Failed review groups: {}.", coverage.failed_groups));
    }
    if coverage.deferred_files > 0 {
        assumptions.push(format!(
            "Adaptively deferred files: {}.",
            coverage.deferred_files
        ));
    }
    if coverage.budget_exhausted {
        assumptions.push("The aggregate review budget was exhausted.".to_owned());
    }
    AdjudicatedOverview {
        summary: if coverage.partial {
            "Verified findings are available from a partial review; deterministic fallback ranking was used."
                .to_owned()
        } else {
            "Verified findings were ranked with the deterministic adjudication fallback.".to_owned()
        },
        assumptions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, RepositoryPath};

    fn candidate(id: &str, anchor: &str, severity: Severity, confidence: u8) -> VerifiedCandidate {
        VerifiedCandidate {
            candidate_id: id.to_owned(),
            work_unit_id: "group-1".to_owned(),
            target_path: RepositoryPath::try_from("src/lib.rs".to_owned()).expect("path"),
            finding: Finding {
                anchor_id: anchor.to_owned(),
                severity,
                confidence_percent: confidence,
                category: FindingCategory::Correctness,
                title: "Broken state transition".to_owned(),
                explanation: "The transition can leave invalid state.".to_owned(),
                evidence: "Delivered evidence demonstrates the invalid ordering.".to_owned(),
                lineage_id: None,
                suggested_replacement: None,
            },
            evidence_references: vec!["diff:h1:page:1".to_owned()],
        }
    }

    #[test]
    fn ranking_is_severity_confidence_then_stable_identity() {
        let outcome = deterministic_adjudication_fallback(
            &[
                candidate("medium", "anchor-2", Severity::Medium, 99),
                candidate("high-low", "anchor-3", Severity::High, 85),
                candidate("high-high", "anchor-1", Severity::High, 95),
            ],
            AdjudicationFallbackCoverage::default(),
        )
        .expect("fallback");
        assert_eq!(
            outcome
                .publish
                .iter()
                .map(|candidate| candidate.candidate_id.as_str())
                .collect::<Vec<_>>(),
            ["high-high", "high-low", "medium"]
        );
    }

    #[test]
    fn exact_duplicates_reference_a_published_canonical_candidate() {
        let outcome = deterministic_adjudication_fallback(
            &[
                candidate("preferred", "anchor-1", Severity::High, 95),
                candidate("duplicate", "anchor-1", Severity::High, 90),
            ],
            AdjudicationFallbackCoverage::default(),
        )
        .expect("fallback");
        assert_eq!(outcome.publish[0].candidate_id, "preferred");
        assert!(matches!(
            &outcome.suppressed[0].reason,
            AdjudicationSuppressionReason::Duplicate { canonical_candidate_id }
                if canonical_candidate_id == "preferred"
        ));
    }

    #[test]
    fn finding_cap_suppresses_lower_priority_candidates() {
        let candidates = (0..30)
            .map(|index| {
                candidate(
                    &format!("candidate-{index:02}"),
                    &format!("anchor-{index:02}"),
                    Severity::Medium,
                    90,
                )
            })
            .collect::<Vec<_>>();
        let outcome = deterministic_adjudication_fallback(
            &candidates,
            AdjudicationFallbackCoverage::default(),
        )
        .expect("fallback");
        assert_eq!(outcome.publish.len(), MAX_PUBLISHED_FINDINGS);
        assert_eq!(outcome.suppressed.len(), 5);
        assert!(
            outcome.suppressed.iter().all(|candidate| {
                candidate.reason == AdjudicationSuppressionReason::LowerPriority
            })
        );
    }

    #[test]
    fn partial_overview_is_conservative_and_preserves_lineages() {
        let outcome = deterministic_adjudication_fallback(
            &[],
            AdjudicationFallbackCoverage {
                partial: true,
                failed_groups: 2,
                deferred_files: 3,
                budget_exhausted: true,
            },
        )
        .expect("fallback");
        assert!(outcome.overview.summary.contains("partial"));
        assert!(
            outcome
                .overview
                .assumptions
                .iter()
                .any(|assumption| assumption.contains("preserved"))
        );
    }

    #[test]
    fn duplicate_candidate_ids_fail_closed() {
        let candidate = candidate("same", "anchor-1", Severity::High, 90);
        assert_eq!(
            deterministic_adjudication_fallback(
                &[candidate.clone(), candidate],
                AdjudicationFallbackCoverage::default(),
            ),
            Err(AdjudicationFallbackError::DuplicateCandidateId)
        );
    }
}
