//! Deterministic scoring for the versioned review-quality corpus.
//!
//! The scorer deliberately knows nothing about prompts or providers. A held-out
//! case declares which anchor/category pairs are material defects; observations
//! are matched exactly so prompt tuning cannot quietly redefine success.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Finding, FindingCategory};

/// One material defect expected in a review-quality case.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDefect {
    pub anchor_id: String,
    pub category: FindingCategory,
}

/// A versioned evaluation case independent of any provider transcript.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCase {
    pub schema_version: String,
    pub case_id: String,
    pub clean_change: bool,
    pub expected_defects: Vec<ExpectedDefect>,
}

/// Aggregate exact-match quality evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvaluationScore {
    pub expected: u32,
    pub reported: u32,
    pub true_positive: u32,
    pub false_positive: u32,
    pub false_negative: u32,
    pub duplicate_reports: u32,
    pub clean_change_silent: bool,
}

/// Aggregate corpus evidence used by release-quality gates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvaluationCorpusScore {
    pub cases: u32,
    pub clean_cases: u32,
    pub noisy_clean_cases: u32,
    pub expected: u32,
    pub reported: u32,
    pub true_positive: u32,
    pub false_positive: u32,
    pub false_negative: u32,
    pub duplicate_reports: u32,
    /// Precision in basis points. A corpus with no reports has 10,000 only
    /// when it also has no expected defects; otherwise it has zero precision.
    pub precision_basis_points: u16,
    /// Recall in basis points. A corpus without expected defects has 10,000.
    pub recall_basis_points: u16,
    pub category_recall_basis_points: BTreeMap<FindingCategory, u16>,
}

/// Explicit release thresholds; changing these is a reviewable policy event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvaluationThresholds {
    pub minimum_precision_basis_points: u16,
    pub minimum_recall_basis_points: u16,
    pub minimum_category_recall_basis_points: u16,
    pub maximum_noisy_clean_cases: u32,
    pub maximum_duplicate_reports: u32,
}

impl Default for EvaluationThresholds {
    fn default() -> Self {
        Self {
            minimum_precision_basis_points: 9_000,
            minimum_recall_basis_points: 8_500,
            minimum_category_recall_basis_points: 7_500,
            maximum_noisy_clean_cases: 0,
            maximum_duplicate_reports: 0,
        }
    }
}

/// Deterministic pass/fail evidence for a corpus and threshold policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvaluationGate {
    pub passed: bool,
    pub score: EvaluationCorpusScore,
    pub thresholds: EvaluationThresholds,
    pub failures: Vec<EvaluationGateFailure>,
}

/// A stable reason why review quality did not meet release policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationGateFailure {
    Precision,
    Recall,
    CategoryRecall,
    CleanChangeNoise,
    DuplicateReports,
}

/// Corpus or observation violated a deterministic scoring invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationError {
    SchemaVersion,
    CaseId,
    ContradictoryCleanCase,
    DuplicateExpectedDefect,
    InvalidThreshold,
    CountOverflow,
}

/// Combine exact case scores and enforce a release policy.
///
/// # Errors
///
/// Returns [`EvaluationError::CountOverflow`] when aggregate evidence cannot
/// be represented by the versioned score type.
pub fn evaluate_corpus(
    cases: &[(&EvaluationCase, &[Finding])],
    thresholds: EvaluationThresholds,
) -> Result<EvaluationGate, EvaluationError> {
    if thresholds.minimum_precision_basis_points > 10_000
        || thresholds.minimum_recall_basis_points > 10_000
        || thresholds.minimum_category_recall_basis_points > 10_000
    {
        return Err(EvaluationError::InvalidThreshold);
    }

    let mut score = EvaluationCorpusScore {
        cases: as_u32(cases.len())?,
        clean_cases: 0,
        noisy_clean_cases: 0,
        expected: 0,
        reported: 0,
        true_positive: 0,
        false_positive: 0,
        false_negative: 0,
        duplicate_reports: 0,
        precision_basis_points: 0,
        recall_basis_points: 0,
        category_recall_basis_points: BTreeMap::new(),
    };
    let mut category_expected = BTreeMap::<FindingCategory, u32>::new();
    let mut category_true_positive = BTreeMap::<FindingCategory, u32>::new();

    for (case, findings) in cases {
        let case_score = case.score(findings)?;
        score.expected = checked_add(score.expected, case_score.expected)?;
        score.reported = checked_add(score.reported, case_score.reported)?;
        score.true_positive = checked_add(score.true_positive, case_score.true_positive)?;
        score.false_positive = checked_add(score.false_positive, case_score.false_positive)?;
        score.false_negative = checked_add(score.false_negative, case_score.false_negative)?;
        score.duplicate_reports =
            checked_add(score.duplicate_reports, case_score.duplicate_reports)?;
        if case.clean_change {
            score.clean_cases = checked_add(score.clean_cases, 1)?;
            if !case_score.clean_change_silent {
                score.noisy_clean_cases = checked_add(score.noisy_clean_cases, 1)?;
            }
        }
        for defect in &case.expected_defects {
            let count = category_expected.entry(defect.category).or_default();
            *count = checked_add(*count, 1)?;
        }
        let observed = findings
            .iter()
            .map(|finding| ExpectedDefect {
                anchor_id: finding.anchor_id.clone(),
                category: finding.category,
            })
            .collect::<BTreeSet<_>>();
        for defect in case
            .expected_defects
            .iter()
            .filter(|defect| observed.contains(*defect))
        {
            let category = defect.category;
            let count = category_true_positive.entry(category).or_default();
            *count = checked_add(*count, 1)?;
        }
    }

    score.precision_basis_points = ratio_basis_points(
        score.true_positive,
        score.true_positive.saturating_add(score.false_positive),
        score.expected == 0,
    );
    score.recall_basis_points = ratio_basis_points(score.true_positive, score.expected, true);
    for (category, expected) in category_expected {
        let observed = category_true_positive.get(&category).copied().unwrap_or(0);
        score
            .category_recall_basis_points
            .insert(category, ratio_basis_points(observed, expected, true));
    }

    let mut failures = Vec::new();
    if score.precision_basis_points < thresholds.minimum_precision_basis_points {
        failures.push(EvaluationGateFailure::Precision);
    }
    if score.recall_basis_points < thresholds.minimum_recall_basis_points {
        failures.push(EvaluationGateFailure::Recall);
    }
    if score
        .category_recall_basis_points
        .values()
        .any(|recall| *recall < thresholds.minimum_category_recall_basis_points)
    {
        failures.push(EvaluationGateFailure::CategoryRecall);
    }
    if score.noisy_clean_cases > thresholds.maximum_noisy_clean_cases {
        failures.push(EvaluationGateFailure::CleanChangeNoise);
    }
    if score.duplicate_reports > thresholds.maximum_duplicate_reports {
        failures.push(EvaluationGateFailure::DuplicateReports);
    }
    Ok(EvaluationGate {
        passed: failures.is_empty(),
        score,
        thresholds,
        failures,
    })
}

fn checked_add(left: u32, right: u32) -> Result<u32, EvaluationError> {
    left.checked_add(right)
        .ok_or(EvaluationError::CountOverflow)
}

fn ratio_basis_points(numerator: u32, denominator: u32, empty_is_perfect: bool) -> u16 {
    if denominator == 0 {
        return if empty_is_perfect { 10_000 } else { 0 };
    }
    let scaled = u64::from(numerator)
        .saturating_mul(10_000)
        .checked_div(u64::from(denominator))
        .unwrap_or(0)
        .min(10_000);
    u16::try_from(scaled).unwrap_or(10_000)
}

impl EvaluationCase {
    pub const SCHEMA_VERSION: &'static str = "revoot.evaluation-case/v1";

    /// Validate and score findings using exact anchor/category identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed case metadata, duplicate expectations, contradictory
    /// clean cases, and counts that cannot be represented in the evidence.
    pub fn score(&self, findings: &[Finding]) -> Result<EvaluationScore, EvaluationError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(EvaluationError::SchemaVersion);
        }
        if self.case_id.is_empty()
            || self.case_id.len() > 128
            || !self.case_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')
            })
        {
            return Err(EvaluationError::CaseId);
        }
        if self.clean_change != self.expected_defects.is_empty() {
            return Err(EvaluationError::ContradictoryCleanCase);
        }

        let expected: BTreeSet<_> = self.expected_defects.iter().cloned().collect();
        if expected.len() != self.expected_defects.len() {
            return Err(EvaluationError::DuplicateExpectedDefect);
        }

        let observed: BTreeSet<_> = findings
            .iter()
            .map(|finding| ExpectedDefect {
                anchor_id: finding.anchor_id.clone(),
                category: finding.category,
            })
            .collect();
        let true_positive = expected.intersection(&observed).count();
        let false_positive = observed.difference(&expected).count();
        let false_negative = expected.difference(&observed).count();
        let duplicate_reports = findings.len().saturating_sub(observed.len());

        Ok(EvaluationScore {
            expected: as_u32(expected.len())?,
            reported: as_u32(findings.len())?,
            true_positive: as_u32(true_positive)?,
            false_positive: as_u32(false_positive)?,
            false_negative: as_u32(false_negative)?,
            duplicate_reports: as_u32(duplicate_reports)?,
            clean_change_silent: self.clean_change && findings.is_empty(),
        })
    }
}

fn as_u32(value: usize) -> Result<u32, EvaluationError> {
    u32::try_from(value).map_err(|_| EvaluationError::CountOverflow)
}

#[cfg(test)]
mod tests {
    use super::{
        EvaluationCase, EvaluationError, EvaluationGateFailure, EvaluationThresholds,
        ExpectedDefect, evaluate_corpus,
    };
    use crate::{Finding, FindingCategory, Severity};

    fn finding(anchor: &str, category: FindingCategory) -> Finding {
        Finding {
            anchor_id: anchor.to_owned(),
            severity: Severity::High,
            confidence_percent: 91,
            category,
            title: "A material defect".to_owned(),
            explanation: "This behavior violates the case invariant.".to_owned(),
            evidence: "The changed line demonstrates the failure.".to_owned(),
            lineage_id: None,
            suggested_replacement: None,
        }
    }

    #[test]
    fn scores_exact_matches_false_positives_and_duplicates() {
        let case = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: "rust/correctness-001".to_owned(),
            clean_change: false,
            expected_defects: vec![ExpectedDefect {
                anchor_id: "anchor-a".to_owned(),
                category: FindingCategory::Correctness,
            }],
        };
        let score = case
            .score(&[
                finding("anchor-a", FindingCategory::Correctness),
                finding("anchor-a", FindingCategory::Correctness),
                finding("anchor-b", FindingCategory::Maintainability),
            ])
            .expect("valid case");
        assert_eq!(score.true_positive, 1);
        assert_eq!(score.false_positive, 1);
        assert_eq!(score.false_negative, 0);
        assert_eq!(score.duplicate_reports, 1);
    }

    #[test]
    fn clean_change_requires_silence() {
        let case = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: "rust/clean-001".to_owned(),
            clean_change: true,
            expected_defects: Vec::new(),
        };
        assert!(case.score(&[]).expect("valid case").clean_change_silent);
        assert!(
            !case
                .score(&[finding("anchor-a", FindingCategory::Correctness)])
                .expect("valid case")
                .clean_change_silent
        );
    }

    #[test]
    fn rejects_contradictory_and_duplicate_expectations() {
        let defect = ExpectedDefect {
            anchor_id: "anchor-a".to_owned(),
            category: FindingCategory::Reliability,
        };
        let contradictory = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: "bad-clean".to_owned(),
            clean_change: true,
            expected_defects: vec![defect.clone()],
        };
        assert_eq!(
            contradictory.score(&[]),
            Err(EvaluationError::ContradictoryCleanCase)
        );
        let duplicate = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: "duplicate".to_owned(),
            clean_change: false,
            expected_defects: vec![defect.clone(), defect],
        };
        assert_eq!(
            duplicate.score(&[]),
            Err(EvaluationError::DuplicateExpectedDefect)
        );
    }

    #[test]
    fn corpus_gate_tracks_precision_recall_categories_and_clean_noise() {
        let correctness = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: "rust/correctness".to_owned(),
            clean_change: false,
            expected_defects: vec![ExpectedDefect {
                anchor_id: "anchor-a".to_owned(),
                category: FindingCategory::Correctness,
            }],
        };
        let security = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: "python/security".to_owned(),
            clean_change: false,
            expected_defects: vec![ExpectedDefect {
                anchor_id: "anchor-b".to_owned(),
                category: FindingCategory::Security,
            }],
        };
        let clean = EvaluationCase {
            schema_version: EvaluationCase::SCHEMA_VERSION.to_owned(),
            case_id: "typescript/clean".to_owned(),
            clean_change: true,
            expected_defects: Vec::new(),
        };
        let noisy = finding("anchor-c", FindingCategory::Maintainability);
        let correct = [finding("anchor-a", FindingCategory::Correctness)];
        let observations: Vec<(&EvaluationCase, &[Finding])> = vec![
            (&correctness, &correct),
            (&security, &[]),
            (&clean, std::slice::from_ref(&noisy)),
        ];
        let gate = evaluate_corpus(&observations, EvaluationThresholds::default())
            .expect("bounded corpus");
        assert!(!gate.passed);
        assert_eq!(gate.score.precision_basis_points, 5_000);
        assert_eq!(gate.score.recall_basis_points, 5_000);
        assert_eq!(gate.score.noisy_clean_cases, 1);
        assert_eq!(
            gate.score
                .category_recall_basis_points
                .get(&FindingCategory::Correctness),
            Some(&10_000)
        );
        assert_eq!(
            gate.score
                .category_recall_basis_points
                .get(&FindingCategory::Security),
            Some(&0)
        );
        assert!(gate.failures.contains(&EvaluationGateFailure::Precision));
        assert!(gate.failures.contains(&EvaluationGateFailure::Recall));
        assert!(
            gate.failures
                .contains(&EvaluationGateFailure::CategoryRecall)
        );
        assert!(
            gate.failures
                .contains(&EvaluationGateFailure::CleanChangeNoise)
        );
    }
}
