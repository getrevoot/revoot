//! Deterministic candidate verification and adjudication boundaries.
//!
//! Model-authored decisions can only reference candidates admitted by trusted
//! code. Findings, anchors, target paths, and evidence references are copied
//! from that admission set and cannot be replaced by verifier output.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AnchorId, AnchorPosition, AnchorTable, Finding, FindingsEnvelope, FindingsValidationError,
    RepositoryPath,
};

const MAX_CANDIDATES: usize = 25;
const MAX_CANDIDATE_ID_BYTES: usize = 128;
const MAX_WORK_UNIT_ID_BYTES: usize = 128;
const MAX_EVIDENCE_REFERENCES: usize = 32;
const MAX_EVIDENCE_ID_BYTES: usize = 128;
const MAX_OVERVIEW_BYTES: usize = 4 * 1024;
const MAX_OVERVIEW_ASSUMPTIONS: usize = 64;
const MAX_OVERVIEW_ASSUMPTION_BYTES: usize = 512;

/// One untrusted worker candidate and its cited, opaque evidence references.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateForVerification {
    pub candidate_id: String,
    pub work_unit_id: String,
    pub finding: Finding,
    pub evidence_references: Vec<String>,
}

/// Trusted verifier payload produced after deterministic candidate gates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedVerificationCandidate {
    pub candidate_id: String,
    pub work_unit_id: String,
    pub target_path: RepositoryPath,
    pub finding: Finding,
    pub evidence_references: Vec<String>,
}

/// A complete, bounded verifier request domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedVerificationBatch {
    pub candidates: Vec<PreparedVerificationCandidate>,
}

/// Stable, payload-free failure from deterministic candidate admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateVerificationError {
    CandidateCount,
    CandidateId,
    DuplicateCandidateId,
    WorkUnitId,
    WorkUnitMismatch,
    Finding(FindingsValidationError),
    AnchorShape,
    AnchorNotIssued,
    AnchorNotTrusted,
    TargetNotAssigned,
    EvidenceReferenceCount,
    EvidenceReferenceId,
    DuplicateEvidenceReference,
    EvidenceNotDelivered,
}

/// Validate worker candidates and bind them to trusted paths and evidence.
///
/// # Errors
///
/// Returns a stable reason without embedding candidate, path, source, or model
/// payloads in the error.
pub fn prepare_verification_batch(
    candidates: impl IntoIterator<Item = CandidateForVerification>,
    expected_work_unit_id: &str,
    assigned_paths: &BTreeSet<RepositoryPath>,
    issued_anchors: &BTreeSet<AnchorId>,
    delivered_evidence: &BTreeSet<String>,
    anchor_table: &AnchorTable,
) -> Result<PreparedVerificationBatch, CandidateVerificationError> {
    if !valid_identifier(expected_work_unit_id, MAX_WORK_UNIT_ID_BYTES) {
        return Err(CandidateVerificationError::WorkUnitId);
    }
    let candidates: Vec<_> = candidates.into_iter().collect();
    if candidates.is_empty() || candidates.len() > MAX_CANDIDATES {
        return Err(CandidateVerificationError::CandidateCount);
    }
    let mut seen_candidates = BTreeSet::new();
    let mut prepared = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if !valid_identifier(&candidate.candidate_id, MAX_CANDIDATE_ID_BYTES) {
            return Err(CandidateVerificationError::CandidateId);
        }
        if !seen_candidates.insert(candidate.candidate_id.clone()) {
            return Err(CandidateVerificationError::DuplicateCandidateId);
        }
        if !valid_identifier(&candidate.work_unit_id, MAX_WORK_UNIT_ID_BYTES) {
            return Err(CandidateVerificationError::WorkUnitId);
        }
        if candidate.work_unit_id != expected_work_unit_id {
            return Err(CandidateVerificationError::WorkUnitMismatch);
        }
        validate_finding(&candidate).map_err(CandidateVerificationError::Finding)?;
        let anchor_id = AnchorId::try_from(candidate.finding.anchor_id.clone())
            .map_err(|_| CandidateVerificationError::AnchorShape)?;
        if !issued_anchors.contains(&anchor_id) {
            return Err(CandidateVerificationError::AnchorNotIssued);
        }
        let anchor = anchor_table
            .resolve(anchor_id.as_str())
            .ok_or(CandidateVerificationError::AnchorNotTrusted)?;
        let target_path = match anchor.position {
            AnchorPosition::Deletion { .. } => anchor.path.old_path.clone(),
            AnchorPosition::Addition { .. } | AnchorPosition::Context { .. } => {
                anchor.path.new_path.clone()
            }
        };
        if !assigned_paths.contains(&target_path) {
            return Err(CandidateVerificationError::TargetNotAssigned);
        }
        if candidate.evidence_references.is_empty()
            || candidate.evidence_references.len() > MAX_EVIDENCE_REFERENCES
        {
            return Err(CandidateVerificationError::EvidenceReferenceCount);
        }
        let mut seen_evidence = BTreeSet::new();
        for evidence_id in &candidate.evidence_references {
            if !valid_identifier(evidence_id, MAX_EVIDENCE_ID_BYTES) {
                return Err(CandidateVerificationError::EvidenceReferenceId);
            }
            if !seen_evidence.insert(evidence_id.clone()) {
                return Err(CandidateVerificationError::DuplicateEvidenceReference);
            }
            if !delivered_evidence.contains(evidence_id) {
                return Err(CandidateVerificationError::EvidenceNotDelivered);
            }
        }
        prepared.push(PreparedVerificationCandidate {
            candidate_id: candidate.candidate_id,
            work_unit_id: candidate.work_unit_id,
            target_path,
            finding: candidate.finding,
            evidence_references: candidate.evidence_references,
        });
    }
    Ok(PreparedVerificationBatch {
        candidates: prepared,
    })
}

fn validate_finding(candidate: &CandidateForVerification) -> Result<(), FindingsValidationError> {
    FindingsEnvelope {
        schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
        work_unit_id: candidate.work_unit_id.clone(),
        findings: vec![candidate.finding.clone()],
        summary: "Candidate prepared for verification.".to_owned(),
    }
    .validate()
}

/// A bounded suppression reason available to the verifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierSuppressionReason {
    Incorrect,
    InsufficientEvidence,
    NotActionable,
    Duplicate,
    Policy,
}

/// The only changes a verifier may request for an admitted candidate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifierDecisionKind {
    Accept,
    Suppress { reason: VerifierSuppressionReason },
    LowerConfidence { confidence_percent: u8 },
}

/// One verifier decision referencing an existing candidate by opaque ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierDecision {
    pub candidate_id: String,
    #[serde(flatten)]
    pub kind: VerifierDecisionKind,
}

/// Complete verifier output. No finding, anchor, path, or evidence fields are
/// accepted by this schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierResponse {
    pub schema_version: String,
    pub decisions: Vec<VerifierDecision>,
}

impl VerifierResponse {
    pub const SCHEMA_VERSION: &'static str = "revoot.verifier-decisions/v1";
}

/// An admitted candidate accepted by deterministic verifier application.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCandidate {
    pub candidate_id: String,
    pub work_unit_id: String,
    pub target_path: RepositoryPath,
    pub finding: Finding,
    pub evidence_references: Vec<String>,
}

/// A candidate intentionally removed by verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressedVerificationCandidate {
    pub candidate_id: String,
    pub reason: VerifierSuppressionReason,
}

/// Fully accounted verifier result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationOutcome {
    pub accepted: Vec<VerifiedCandidate>,
    pub suppressed: Vec<SuppressedVerificationCandidate>,
}

/// Stable, payload-free verifier-output failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierResponseError {
    SchemaVersion,
    DecisionCount,
    CandidateId,
    UnknownCandidate,
    DuplicateCandidate,
    MissingCandidate,
    ConfidenceNotLowered,
}

/// Apply verifier decisions without permitting candidate mutation or creation.
///
/// # Errors
///
/// Rejects malformed, missing, duplicate, unknown, or confidence-raising
/// decisions with a stable reason that contains no model payload.
pub fn apply_verifier_response(
    batch: &PreparedVerificationBatch,
    response: VerifierResponse,
) -> Result<VerificationOutcome, VerifierResponseError> {
    if response.schema_version != VerifierResponse::SCHEMA_VERSION {
        return Err(VerifierResponseError::SchemaVersion);
    }
    if response.decisions.len() != batch.candidates.len() {
        return Err(VerifierResponseError::DecisionCount);
    }
    let candidates: BTreeMap<_, _> = batch
        .candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.as_str(), candidate))
        .collect();
    let mut decisions = BTreeMap::new();
    for decision in response.decisions {
        if !valid_identifier(&decision.candidate_id, MAX_CANDIDATE_ID_BYTES) {
            return Err(VerifierResponseError::CandidateId);
        }
        let candidate = candidates
            .get(decision.candidate_id.as_str())
            .ok_or(VerifierResponseError::UnknownCandidate)?;
        if let VerifierDecisionKind::LowerConfidence { confidence_percent } = decision.kind
            && confidence_percent >= candidate.finding.confidence_percent
        {
            return Err(VerifierResponseError::ConfidenceNotLowered);
        }
        if decisions
            .insert(decision.candidate_id, decision.kind)
            .is_some()
        {
            return Err(VerifierResponseError::DuplicateCandidate);
        }
    }
    if decisions.len() != batch.candidates.len() {
        return Err(VerifierResponseError::MissingCandidate);
    }

    let mut accepted = Vec::new();
    let mut suppressed = Vec::new();
    for candidate in &batch.candidates {
        let decision = decisions
            .remove(&candidate.candidate_id)
            .ok_or(VerifierResponseError::MissingCandidate)?;
        match decision {
            VerifierDecisionKind::Accept => accepted.push(copy_verified(candidate)),
            VerifierDecisionKind::LowerConfidence { confidence_percent } => {
                let mut verified = copy_verified(candidate);
                verified.finding.confidence_percent = confidence_percent;
                accepted.push(verified);
            }
            VerifierDecisionKind::Suppress { reason } => {
                suppressed.push(SuppressedVerificationCandidate {
                    candidate_id: candidate.candidate_id.clone(),
                    reason,
                });
            }
        }
    }
    Ok(VerificationOutcome {
        accepted,
        suppressed,
    })
}

fn copy_verified(candidate: &PreparedVerificationCandidate) -> VerifiedCandidate {
    VerifiedCandidate {
        candidate_id: candidate.candidate_id.clone(),
        work_unit_id: candidate.work_unit_id.clone(),
        target_path: candidate.target_path.clone(),
        finding: candidate.finding.clone(),
        evidence_references: candidate.evidence_references.clone(),
    }
}

/// Why the global adjudicator suppressed an already verified candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdjudicationSuppressionReason {
    Duplicate { canonical_candidate_id: String },
    Superseded,
    LowerPriority,
    Policy,
}

/// One suppressed candidate in a global adjudication response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicationSuppression {
    pub candidate_id: String,
    #[serde(flatten)]
    pub reason: AdjudicationSuppressionReason,
}

/// Structured overview authored from verified candidates and aggregate state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicatedOverview {
    pub summary: String,
    pub assumptions: Vec<String>,
}

/// Global adjudicator output. Candidate ranking is the order of `publish`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicatorResponse {
    pub schema_version: String,
    pub publish: Vec<String>,
    pub suppress: Vec<AdjudicationSuppression>,
    pub overview: AdjudicatedOverview,
}

impl AdjudicatorResponse {
    pub const SCHEMA_VERSION: &'static str = "revoot.adjudicator-decisions/v1";
}

/// A suppressed verified candidate and its bounded global reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GloballySuppressedCandidate {
    pub candidate_id: String,
    pub reason: AdjudicationSuppressionReason,
}

/// Ranked, immutable candidates after global adjudication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicationOutcome {
    pub publish: Vec<VerifiedCandidate>,
    pub suppressed: Vec<GloballySuppressedCandidate>,
    pub overview: AdjudicatedOverview,
}

/// Stable, payload-free global adjudicator failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdjudicatorResponseError {
    SchemaVersion,
    CandidateCount,
    CandidateId,
    UnknownCandidate,
    DuplicateCandidate,
    MissingCandidate,
    DuplicateTargetNotPublished,
    Overview,
    AssumptionCount,
    Assumption,
}

/// Apply global ranking and suppression without accepting new or modified
/// findings.
///
/// # Errors
///
/// Every verified candidate must appear exactly once in `publish` or
/// `suppress`; duplicate canonical targets must be present in `publish`.
pub fn apply_adjudicator_response(
    verified: &[VerifiedCandidate],
    response: AdjudicatorResponse,
) -> Result<AdjudicationOutcome, AdjudicatorResponseError> {
    if response.schema_version != AdjudicatorResponse::SCHEMA_VERSION {
        return Err(AdjudicatorResponseError::SchemaVersion);
    }
    if response
        .publish
        .len()
        .saturating_add(response.suppress.len())
        != verified.len()
    {
        return Err(AdjudicatorResponseError::CandidateCount);
    }
    validate_overview(&response.overview)?;
    let by_id: BTreeMap<_, _> = verified
        .iter()
        .map(|candidate| (candidate.candidate_id.as_str(), candidate))
        .collect();
    if by_id.len() != verified.len() {
        return Err(AdjudicatorResponseError::DuplicateCandidate);
    }
    let mut accounted = BTreeSet::new();
    let mut publish = Vec::with_capacity(response.publish.len());
    let published_ids: BTreeSet<_> = response.publish.iter().map(String::as_str).collect();
    if published_ids.len() != response.publish.len() {
        return Err(AdjudicatorResponseError::DuplicateCandidate);
    }
    for candidate_id in &response.publish {
        validate_adjudication_candidate_id(candidate_id)?;
        let candidate = by_id
            .get(candidate_id.as_str())
            .ok_or(AdjudicatorResponseError::UnknownCandidate)?;
        if !accounted.insert(candidate_id.clone()) {
            return Err(AdjudicatorResponseError::DuplicateCandidate);
        }
        publish.push((*candidate).clone());
    }
    let mut suppressed = Vec::with_capacity(response.suppress.len());
    for suppression in response.suppress {
        validate_adjudication_candidate_id(&suppression.candidate_id)?;
        if !by_id.contains_key(suppression.candidate_id.as_str()) {
            return Err(AdjudicatorResponseError::UnknownCandidate);
        }
        if !accounted.insert(suppression.candidate_id.clone()) {
            return Err(AdjudicatorResponseError::DuplicateCandidate);
        }
        if let AdjudicationSuppressionReason::Duplicate {
            canonical_candidate_id,
        } = &suppression.reason
        {
            validate_adjudication_candidate_id(canonical_candidate_id)?;
            if canonical_candidate_id == &suppression.candidate_id
                || !published_ids.contains(canonical_candidate_id.as_str())
            {
                return Err(AdjudicatorResponseError::DuplicateTargetNotPublished);
            }
        }
        suppressed.push(GloballySuppressedCandidate {
            candidate_id: suppression.candidate_id,
            reason: suppression.reason,
        });
    }
    if accounted.len() != verified.len() {
        return Err(AdjudicatorResponseError::MissingCandidate);
    }
    Ok(AdjudicationOutcome {
        publish,
        suppressed,
        overview: response.overview,
    })
}

fn validate_adjudication_candidate_id(candidate_id: &str) -> Result<(), AdjudicatorResponseError> {
    if valid_identifier(candidate_id, MAX_CANDIDATE_ID_BYTES) {
        Ok(())
    } else {
        Err(AdjudicatorResponseError::CandidateId)
    }
}

fn validate_overview(overview: &AdjudicatedOverview) -> Result<(), AdjudicatorResponseError> {
    if !valid_bounded_text(&overview.summary, MAX_OVERVIEW_BYTES) {
        return Err(AdjudicatorResponseError::Overview);
    }
    if overview.assumptions.len() > MAX_OVERVIEW_ASSUMPTIONS {
        return Err(AdjudicatorResponseError::AssumptionCount);
    }
    if overview
        .assumptions
        .iter()
        .any(|assumption| !valid_bounded_text(assumption, MAX_OVERVIEW_ASSUMPTION_BYTES))
    {
        return Err(AdjudicatorResponseError::Assumption);
    }
    Ok(())
}

fn valid_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_bounded_text(value: &str, maximum_bytes: usize) -> bool {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return false;
    }
    let lowercase = value.to_ascii_lowercase();
    !lowercase.contains("<!-- revoot:")
        && !["http://", "https://", "javascript:", "data:", "file:"]
            .into_iter()
            .any(|needle| lowercase.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ChangedPath, CommentableLine, DiffRefs, DiffVersionId, DiffVersionRecord, FileChangeKind,
        FindingCategory, GitLabDiffVersionIdentity, MergeRequestIid, ProjectId, Severity,
        Sha256Digest, SnapshotScope,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).expect("valid digest")
    }

    fn anchor_table() -> AnchorTable {
        let identity = GitLabDiffVersionIdentity {
            scope: SnapshotScope {
                instance_origin_digest: digest('a'),
                project_id: ProjectId::try_from(1).expect("project ID"),
                merge_request_iid: MergeRequestIid::try_from(2).expect("merge request ID"),
            },
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(3).expect("diff version ID"),
                refs: DiffRefs {
                    base_sha: "b".repeat(40).try_into().expect("base SHA"),
                    start_sha: "c".repeat(40).try_into().expect("start SHA"),
                    head_sha: "d".repeat(40).try_into().expect("head SHA"),
                },
            },
        }
        .freeze(digest('e'));
        AnchorTable::build(
            identity,
            [
                CommentableLine {
                    path: ChangedPath {
                        old_path: path("src/lib.rs"),
                        new_path: path("src/lib.rs"),
                        kind: FileChangeKind::Modified,
                    },
                    position: AnchorPosition::addition(10).expect("line"),
                    exact_line_digest: digest('1'),
                    context_digest: digest('2'),
                },
                CommentableLine {
                    path: ChangedPath {
                        old_path: path("src/other.rs"),
                        new_path: path("src/other.rs"),
                        kind: FileChangeKind::Modified,
                    },
                    position: AnchorPosition::addition(20).expect("line"),
                    exact_line_digest: digest('3'),
                    context_digest: digest('4'),
                },
            ],
        )
        .expect("anchor table")
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).expect("path")
    }

    fn candidate(anchor_id: &str, candidate_id: &str) -> CandidateForVerification {
        CandidateForVerification {
            candidate_id: candidate_id.to_owned(),
            work_unit_id: "group-1".to_owned(),
            finding: Finding {
                anchor_id: anchor_id.to_owned(),
                severity: Severity::High,
                confidence_percent: 90,
                category: FindingCategory::Correctness,
                title: "Unchecked state transition".to_owned(),
                explanation: "The state changes before validation.".to_owned(),
                evidence: "The delivered hunk shows the mutation first.".to_owned(),
                lineage_id: None,
                suggested_replacement: None,
            },
            evidence_references: vec!["diff:hunk-1:page-1".to_owned()],
        }
    }

    fn prepared() -> PreparedVerificationBatch {
        let table = anchor_table();
        let anchor = table
            .iter()
            .find(|anchor| anchor.path.new_path == path("src/lib.rs"))
            .expect("library anchor")
            .id
            .clone();
        prepare_verification_batch(
            [candidate(anchor.as_str(), "candidate-1")],
            "group-1",
            &BTreeSet::from([path("src/lib.rs"), path("src/other.rs")]),
            &BTreeSet::from([anchor]),
            &BTreeSet::from(["diff:hunk-1:page-1".to_owned()]),
            &table,
        )
        .expect("prepared")
    }

    #[test]
    fn preparation_binds_anchor_to_trusted_assigned_path() {
        let batch = prepared();
        assert_eq!(batch.candidates[0].target_path, path("src/lib.rs"));
        assert_eq!(batch.candidates[0].evidence_references.len(), 1);
    }

    #[test]
    fn preparation_rejects_cross_group_anchor() {
        let table = anchor_table();
        let other = table
            .iter()
            .find(|anchor| anchor.path.new_path == path("src/other.rs"))
            .expect("other anchor")
            .id
            .clone();
        assert_eq!(
            prepare_verification_batch(
                [candidate(other.as_str(), "candidate-1")],
                "group-1",
                &BTreeSet::from([path("src/lib.rs")]),
                &BTreeSet::from([other]),
                &BTreeSet::from(["diff:hunk-1:page-1".to_owned()]),
                &table,
            ),
            Err(CandidateVerificationError::TargetNotAssigned)
        );
    }

    #[test]
    fn preparation_rejects_unissued_or_undelivered_evidence() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        assert_eq!(
            prepare_verification_batch(
                [candidate(anchor.as_str(), "candidate-1")],
                "group-1",
                &BTreeSet::from([path("src/lib.rs"), path("src/other.rs")]),
                &BTreeSet::new(),
                &BTreeSet::from(["diff:hunk-1:page-1".to_owned()]),
                &table,
            ),
            Err(CandidateVerificationError::AnchorNotIssued)
        );
        assert_eq!(
            prepare_verification_batch(
                [candidate(anchor.as_str(), "candidate-1")],
                "group-1",
                &BTreeSet::from([path("src/lib.rs"), path("src/other.rs")]),
                &BTreeSet::from([anchor]),
                &BTreeSet::new(),
                &table,
            ),
            Err(CandidateVerificationError::EvidenceNotDelivered)
        );
    }

    #[test]
    fn verifier_accept_preserves_candidate_exactly() {
        let batch = prepared();
        let expected = copy_verified(&batch.candidates[0]);
        let outcome = apply_verifier_response(
            &batch,
            VerifierResponse {
                schema_version: VerifierResponse::SCHEMA_VERSION.to_owned(),
                decisions: vec![VerifierDecision {
                    candidate_id: "candidate-1".to_owned(),
                    kind: VerifierDecisionKind::Accept,
                }],
            },
        )
        .expect("accepted");
        assert_eq!(outcome.accepted, vec![expected]);
    }

    #[test]
    fn verifier_can_only_lower_confidence() {
        let batch = prepared();
        for confidence in [90, 91, 100] {
            assert_eq!(
                apply_verifier_response(
                    &batch,
                    VerifierResponse {
                        schema_version: VerifierResponse::SCHEMA_VERSION.to_owned(),
                        decisions: vec![VerifierDecision {
                            candidate_id: "candidate-1".to_owned(),
                            kind: VerifierDecisionKind::LowerConfidence {
                                confidence_percent: confidence,
                            },
                        }],
                    },
                ),
                Err(VerifierResponseError::ConfidenceNotLowered)
            );
        }
        let lowered = apply_verifier_response(
            &batch,
            VerifierResponse {
                schema_version: VerifierResponse::SCHEMA_VERSION.to_owned(),
                decisions: vec![VerifierDecision {
                    candidate_id: "candidate-1".to_owned(),
                    kind: VerifierDecisionKind::LowerConfidence {
                        confidence_percent: 75,
                    },
                }],
            },
        )
        .expect("lowered");
        assert_eq!(lowered.accepted[0].finding.confidence_percent, 75);
        assert_eq!(
            lowered.accepted[0].finding.anchor_id,
            batch.candidates[0].finding.anchor_id
        );
    }

    #[test]
    fn verifier_cannot_create_duplicate_or_omit_candidates() {
        let mut batch = prepared();
        let mut second = batch.candidates[0].clone();
        second.candidate_id = "candidate-2".to_owned();
        batch.candidates.push(second);
        let accept_one = VerifierDecision {
            candidate_id: "candidate-1".to_owned(),
            kind: VerifierDecisionKind::Accept,
        };
        assert_eq!(
            apply_verifier_response(
                &batch,
                VerifierResponse {
                    schema_version: VerifierResponse::SCHEMA_VERSION.to_owned(),
                    decisions: vec![accept_one.clone()],
                },
            ),
            Err(VerifierResponseError::DecisionCount)
        );
        assert_eq!(
            apply_verifier_response(
                &batch,
                VerifierResponse {
                    schema_version: VerifierResponse::SCHEMA_VERSION.to_owned(),
                    decisions: vec![accept_one.clone(), accept_one],
                },
            ),
            Err(VerifierResponseError::DuplicateCandidate)
        );
        assert_eq!(
            apply_verifier_response(
                &batch,
                VerifierResponse {
                    schema_version: VerifierResponse::SCHEMA_VERSION.to_owned(),
                    decisions: vec![
                        VerifierDecision {
                            candidate_id: "candidate-1".to_owned(),
                            kind: VerifierDecisionKind::Accept,
                        },
                        VerifierDecision {
                            candidate_id: "candidate-new".to_owned(),
                            kind: VerifierDecisionKind::Accept,
                        },
                    ],
                },
            ),
            Err(VerifierResponseError::UnknownCandidate)
        );
    }

    fn verified(candidate_id: &str) -> VerifiedCandidate {
        let mut value = copy_verified(&prepared().candidates[0]);
        value.candidate_id = candidate_id.to_owned();
        value
    }

    fn overview() -> AdjudicatedOverview {
        AdjudicatedOverview {
            summary: "Two candidates were globally compared.".to_owned(),
            assumptions: vec!["Coverage remained partial for one low-risk file.".to_owned()],
        }
    }

    #[test]
    fn adjudication_ranks_and_deduplicates_only_verified_candidates() {
        let candidates = vec![verified("candidate-1"), verified("candidate-2")];
        let outcome = apply_adjudicator_response(
            &candidates,
            AdjudicatorResponse {
                schema_version: AdjudicatorResponse::SCHEMA_VERSION.to_owned(),
                publish: vec!["candidate-1".to_owned()],
                suppress: vec![AdjudicationSuppression {
                    candidate_id: "candidate-2".to_owned(),
                    reason: AdjudicationSuppressionReason::Duplicate {
                        canonical_candidate_id: "candidate-1".to_owned(),
                    },
                }],
                overview: overview(),
            },
        )
        .expect("adjudicated");
        assert_eq!(outcome.publish, vec![verified("candidate-1")]);
        assert_eq!(outcome.suppressed.len(), 1);
    }

    #[test]
    fn adjudication_rejects_invented_and_unaccounted_candidates() {
        let verified = vec![verified("candidate-1"), verified("candidate-2")];
        assert_eq!(
            apply_adjudicator_response(
                &verified,
                AdjudicatorResponse {
                    schema_version: AdjudicatorResponse::SCHEMA_VERSION.to_owned(),
                    publish: vec!["candidate-new".to_owned()],
                    suppress: vec![AdjudicationSuppression {
                        candidate_id: "candidate-2".to_owned(),
                        reason: AdjudicationSuppressionReason::Policy,
                    }],
                    overview: overview(),
                },
            ),
            Err(AdjudicatorResponseError::UnknownCandidate)
        );
        assert_eq!(
            apply_adjudicator_response(
                &verified,
                AdjudicatorResponse {
                    schema_version: AdjudicatorResponse::SCHEMA_VERSION.to_owned(),
                    publish: vec!["candidate-1".to_owned()],
                    suppress: Vec::new(),
                    overview: overview(),
                },
            ),
            Err(AdjudicatorResponseError::CandidateCount)
        );
    }

    #[test]
    fn duplicate_suppression_must_target_a_published_candidate() {
        let verified = vec![verified("candidate-1"), verified("candidate-2")];
        assert_eq!(
            apply_adjudicator_response(
                &verified,
                AdjudicatorResponse {
                    schema_version: AdjudicatorResponse::SCHEMA_VERSION.to_owned(),
                    publish: vec!["candidate-1".to_owned()],
                    suppress: vec![AdjudicationSuppression {
                        candidate_id: "candidate-2".to_owned(),
                        reason: AdjudicationSuppressionReason::Duplicate {
                            canonical_candidate_id: "candidate-2".to_owned(),
                        },
                    }],
                    overview: overview(),
                },
            ),
            Err(AdjudicatorResponseError::DuplicateTargetNotPublished)
        );
    }

    #[test]
    fn model_decision_schemas_reject_mutation_fields() {
        let verifier = serde_json::from_value::<VerifierResponse>(serde_json::json!({
            "schema_version": VerifierResponse::SCHEMA_VERSION,
            "decisions": [{
                "candidate_id": "candidate-1",
                "decision": "accept",
                "anchor_id": "invented"
            }]
        }));
        assert!(verifier.is_err());
        let adjudicator = serde_json::from_value::<AdjudicatorResponse>(serde_json::json!({
            "schema_version": AdjudicatorResponse::SCHEMA_VERSION,
            "publish": ["candidate-1"],
            "suppress": [],
            "overview": {"summary": "ok", "assumptions": []},
            "findings": []
        }));
        assert!(adjudicator.is_err());
    }
}
