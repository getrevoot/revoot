//! Coverage-gated authorization for prior-finding lineage resolution.
//!
//! A model may propose that an owned prior finding is fixed, but trusted code
//! authorizes resolution only from complete review coverage and delivery of
//! the exact current anchor or exact deletion-hunk evidence.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{AnchorId, AnchorTable, PriorReviewSource, PriorReviewState, Sha256Digest};

const MAX_LINEAGES: usize = 500;
const MAX_DELIVERED_ANCHORS: usize = 10_000;
const MAX_DELETION_HUNKS: usize = 10_000;
const MAX_EVIDENCE_ID_BYTES: usize = 128;

/// The exact current evidence needed to resolve one prior lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PriorLineageTarget {
    CurrentLocation {
        anchor_id: AnchorId,
        evidence_id: String,
    },
    DeletionHunk {
        hunk_evidence_id: String,
    },
    Unavailable,
}

/// Trusted host state and current target for one prior lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorLineageRecord {
    pub lineage_id: Sha256Digest,
    pub discussion_source: PriorReviewSource,
    pub state: PriorReviewState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_source: Option<PriorReviewSource>,
    pub target: PriorLineageTarget,
}

/// One exact anchor delivery recorded from model-visible tool output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredAnchorEvidence {
    pub anchor_id: AnchorId,
    pub evidence_id: String,
}

/// Trusted coverage evidence assembled from actual successful deliveries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageCoverageEvidence {
    coverage_complete: bool,
    delivered_anchors: BTreeMap<AnchorId, BTreeSet<String>>,
    delivered_deletion_hunks: BTreeSet<String>,
}

impl LineageCoverageEvidence {
    /// Validate and retain exact evidence delivery identities.
    ///
    /// `coverage_complete` must represent overall policy completeness. A false
    /// value always prevents automatic lineage resolution.
    ///
    /// # Errors
    ///
    /// Rejects excessive, malformed, duplicate, unissued, or untrusted
    /// evidence without including its payload in the error.
    pub fn new(
        coverage_complete: bool,
        delivered_anchors: impl IntoIterator<Item = DeliveredAnchorEvidence>,
        delivered_deletion_hunks: impl IntoIterator<Item = String>,
        issued_anchors: &BTreeSet<AnchorId>,
        anchor_table: &AnchorTable,
    ) -> Result<Self, LineageCoverageError> {
        let mut anchors: BTreeMap<AnchorId, BTreeSet<String>> = BTreeMap::new();
        let mut anchor_count = 0_usize;
        for delivery in delivered_anchors {
            anchor_count = anchor_count
                .checked_add(1)
                .ok_or(LineageCoverageError::EvidenceCount)?;
            if anchor_count > MAX_DELIVERED_ANCHORS {
                return Err(LineageCoverageError::EvidenceCount);
            }
            if !valid_evidence_id(&delivery.evidence_id) {
                return Err(LineageCoverageError::EvidenceId);
            }
            if !issued_anchors.contains(&delivery.anchor_id) {
                return Err(LineageCoverageError::AnchorNotIssued);
            }
            if anchor_table.resolve(delivery.anchor_id.as_str()).is_none() {
                return Err(LineageCoverageError::AnchorNotTrusted);
            }
            if !anchors
                .entry(delivery.anchor_id)
                .or_default()
                .insert(delivery.evidence_id)
            {
                return Err(LineageCoverageError::DuplicateEvidence);
            }
        }

        let mut deletion_hunks = BTreeSet::new();
        for hunk_id in delivered_deletion_hunks {
            if deletion_hunks.len() >= MAX_DELETION_HUNKS {
                return Err(LineageCoverageError::EvidenceCount);
            }
            if !valid_evidence_id(&hunk_id) {
                return Err(LineageCoverageError::EvidenceId);
            }
            if !deletion_hunks.insert(hunk_id) {
                return Err(LineageCoverageError::DuplicateEvidence);
            }
        }
        Ok(Self {
            coverage_complete,
            delivered_anchors: anchors,
            delivered_deletion_hunks: deletion_hunks,
        })
    }

    /// Whether aggregate policy coverage is complete enough for resolution.
    #[must_use]
    pub const fn coverage_complete(&self) -> bool {
        self.coverage_complete
    }
}

/// A model-authored lineage disposition. It cannot identify replacement
/// anchors, hunks, paths, host state, or resolution provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposedLineageDisposition {
    Preserve,
    Fixed,
}

/// One proposed disposition for an existing lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedLineageDecision {
    pub lineage_id: Sha256Digest,
    pub disposition: ProposedLineageDisposition,
}

/// Complete model-authored lineage response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageDecisionResponse {
    pub schema_version: String,
    pub decisions: Vec<ProposedLineageDecision>,
}

impl LineageDecisionResponse {
    pub const SCHEMA_VERSION: &'static str = "revoot.lineage-decisions/v1";
}

/// Exact trusted evidence authorizing one fixed disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LineageResolutionEvidence {
    CurrentLocation {
        anchor_id: AnchorId,
        evidence_id: String,
    },
    DeletionHunk {
        hunk_evidence_id: String,
    },
}

/// Why an existing host state is preserved instead of being auto-resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineagePreservationReason {
    ProposedPreserve,
    ForeignDiscussion,
    AlreadyResolved,
    ExternallyResolved,
    PartialCoverage,
    TargetUnavailable,
    CurrentLocationNotDelivered,
    DeletionHunkNotDelivered,
}

/// Trusted resolution action after coverage and host-state authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizedLineageAction {
    Preserve {
        state: PriorReviewState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolution_source: Option<PriorReviewSource>,
        reason: LineagePreservationReason,
    },
    ResolveFixed {
        evidence: LineageResolutionEvidence,
    },
}

/// One fully authorized lineage result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedLineageDecision {
    pub lineage_id: Sha256Digest,
    pub action: AuthorizedLineageAction,
}

/// Deterministic authorization result in trusted record order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageAuthorization {
    pub decisions: Vec<AuthorizedLineageDecision>,
}

/// Stable, payload-free lineage coverage or response failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineageCoverageError {
    SchemaVersion,
    LineageCount,
    DuplicateLineage,
    UnknownLineage,
    MissingLineage,
    InvalidHostState,
    EvidenceCount,
    EvidenceId,
    DuplicateEvidence,
    AnchorNotIssued,
    AnchorNotTrusted,
}

/// Authorize proposed fixed dispositions from exact delivered coverage.
///
/// Foreign discussions and any already-resolved state are always preserved.
/// A partial run never authorizes resolution, even if the target evidence was
/// delivered before the run became partial.
///
/// # Errors
///
/// Rejects malformed records or proposals with stable reasons containing no
/// discussion, path, source, or model payload.
pub fn authorize_lineage_decisions(
    records: impl IntoIterator<Item = PriorLineageRecord>,
    response: LineageDecisionResponse,
    coverage: &LineageCoverageEvidence,
    issued_anchors: &BTreeSet<AnchorId>,
    anchor_table: &AnchorTable,
) -> Result<LineageAuthorization, LineageCoverageError> {
    if response.schema_version != LineageDecisionResponse::SCHEMA_VERSION {
        return Err(LineageCoverageError::SchemaVersion);
    }
    let records: Vec<_> = records.into_iter().collect();
    if records.len() > MAX_LINEAGES || response.decisions.len() != records.len() {
        return Err(LineageCoverageError::LineageCount);
    }
    let mut by_lineage = BTreeMap::new();
    for record in records {
        validate_record(&record, issued_anchors, anchor_table)?;
        if by_lineage
            .insert(record.lineage_id.clone(), record)
            .is_some()
        {
            return Err(LineageCoverageError::DuplicateLineage);
        }
    }
    let mut proposals = BTreeMap::new();
    for decision in response.decisions {
        if !by_lineage.contains_key(&decision.lineage_id) {
            return Err(LineageCoverageError::UnknownLineage);
        }
        if proposals
            .insert(decision.lineage_id, decision.disposition)
            .is_some()
        {
            return Err(LineageCoverageError::DuplicateLineage);
        }
    }
    if proposals.len() != by_lineage.len() {
        return Err(LineageCoverageError::MissingLineage);
    }

    let mut decisions = Vec::with_capacity(by_lineage.len());
    for (lineage_id, record) in by_lineage {
        let proposal = proposals
            .remove(&lineage_id)
            .ok_or(LineageCoverageError::MissingLineage)?;
        decisions.push(AuthorizedLineageDecision {
            lineage_id,
            action: authorize_one(&record, proposal, coverage),
        });
    }
    Ok(LineageAuthorization { decisions })
}

fn validate_record(
    record: &PriorLineageRecord,
    issued_anchors: &BTreeSet<AnchorId>,
    anchor_table: &AnchorTable,
) -> Result<(), LineageCoverageError> {
    if (record.state == PriorReviewState::Resolved) != record.resolution_source.is_some() {
        return Err(LineageCoverageError::InvalidHostState);
    }
    match &record.target {
        PriorLineageTarget::CurrentLocation {
            anchor_id,
            evidence_id,
        } => {
            if !valid_evidence_id(evidence_id) {
                return Err(LineageCoverageError::EvidenceId);
            }
            if !issued_anchors.contains(anchor_id) {
                return Err(LineageCoverageError::AnchorNotIssued);
            }
            if anchor_table.resolve(anchor_id.as_str()).is_none() {
                return Err(LineageCoverageError::AnchorNotTrusted);
            }
        }
        PriorLineageTarget::DeletionHunk { hunk_evidence_id } => {
            if !valid_evidence_id(hunk_evidence_id) {
                return Err(LineageCoverageError::EvidenceId);
            }
        }
        PriorLineageTarget::Unavailable => {}
    }
    Ok(())
}

fn authorize_one(
    record: &PriorLineageRecord,
    proposal: ProposedLineageDisposition,
    coverage: &LineageCoverageEvidence,
) -> AuthorizedLineageAction {
    let preserve = |reason| AuthorizedLineageAction::Preserve {
        state: record.state,
        resolution_source: record.resolution_source,
        reason,
    };
    if record.discussion_source != PriorReviewSource::Revoot {
        return preserve(LineagePreservationReason::ForeignDiscussion);
    }
    if record.state == PriorReviewState::Resolved {
        return preserve(
            if record.resolution_source == Some(PriorReviewSource::Other) {
                LineagePreservationReason::ExternallyResolved
            } else {
                LineagePreservationReason::AlreadyResolved
            },
        );
    }
    if proposal == ProposedLineageDisposition::Preserve {
        return preserve(LineagePreservationReason::ProposedPreserve);
    }
    if !coverage.coverage_complete {
        return preserve(LineagePreservationReason::PartialCoverage);
    }
    match &record.target {
        PriorLineageTarget::CurrentLocation {
            anchor_id,
            evidence_id,
        } if coverage
            .delivered_anchors
            .get(anchor_id)
            .is_some_and(|evidence| evidence.contains(evidence_id)) =>
        {
            AuthorizedLineageAction::ResolveFixed {
                evidence: LineageResolutionEvidence::CurrentLocation {
                    anchor_id: anchor_id.clone(),
                    evidence_id: evidence_id.clone(),
                },
            }
        }
        PriorLineageTarget::CurrentLocation { .. } => {
            preserve(LineagePreservationReason::CurrentLocationNotDelivered)
        }
        PriorLineageTarget::DeletionHunk { hunk_evidence_id }
            if coverage.delivered_deletion_hunks.contains(hunk_evidence_id) =>
        {
            AuthorizedLineageAction::ResolveFixed {
                evidence: LineageResolutionEvidence::DeletionHunk {
                    hunk_evidence_id: hunk_evidence_id.clone(),
                },
            }
        }
        PriorLineageTarget::DeletionHunk { .. } => {
            preserve(LineagePreservationReason::DeletionHunkNotDelivered)
        }
        PriorLineageTarget::Unavailable => preserve(LineagePreservationReason::TargetUnavailable),
    }
}

fn valid_evidence_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVIDENCE_ID_BYTES
        && !value.contains("..")
        && !value.starts_with('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnchorPosition, ChangedPath, CommentableLine, DiffRefs, DiffVersionId, DiffVersionRecord,
        FileChangeKind, GitLabDiffVersionIdentity, MergeRequestIid, ProjectId, RepositoryPath,
        SnapshotScope,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).expect("digest")
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
            [CommentableLine {
                path: ChangedPath {
                    old_path: RepositoryPath::try_from("src/lib.rs".to_owned()).expect("path"),
                    new_path: RepositoryPath::try_from("src/lib.rs".to_owned()).expect("path"),
                    kind: FileChangeKind::Modified,
                },
                position: AnchorPosition::addition(10).expect("line"),
                exact_line_digest: digest('1'),
                context_digest: digest('2'),
            }],
        )
        .expect("anchor table")
    }

    fn current_record(anchor_id: AnchorId) -> PriorLineageRecord {
        PriorLineageRecord {
            lineage_id: digest('f'),
            discussion_source: PriorReviewSource::Revoot,
            state: PriorReviewState::Open,
            resolution_source: None,
            target: PriorLineageTarget::CurrentLocation {
                anchor_id,
                evidence_id: "diff:hunk-1:page-1".to_owned(),
            },
        }
    }

    fn response(
        lineage_id: Sha256Digest,
        disposition: ProposedLineageDisposition,
    ) -> LineageDecisionResponse {
        LineageDecisionResponse {
            schema_version: LineageDecisionResponse::SCHEMA_VERSION.to_owned(),
            decisions: vec![ProposedLineageDecision {
                lineage_id,
                disposition,
            }],
        }
    }

    fn coverage(
        complete: bool,
        anchor: Option<AnchorId>,
        evidence_id: &str,
        deletion_hunks: Vec<String>,
        issued: &BTreeSet<AnchorId>,
        table: &AnchorTable,
    ) -> LineageCoverageEvidence {
        LineageCoverageEvidence::new(
            complete,
            anchor.into_iter().map(|anchor_id| DeliveredAnchorEvidence {
                anchor_id,
                evidence_id: evidence_id.to_owned(),
            }),
            deletion_hunks,
            issued,
            table,
        )
        .expect("coverage")
    }

    #[test]
    fn exact_current_anchor_and_evidence_authorize_fixed() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let issued = BTreeSet::from([anchor.clone()]);
        let record = current_record(anchor.clone());
        let authorization = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Fixed),
            &coverage(
                true,
                Some(anchor.clone()),
                "diff:hunk-1:page-1",
                Vec::new(),
                &issued,
                &table,
            ),
            &issued,
            &table,
        )
        .expect("authorization");
        assert!(matches!(
            &authorization.decisions[0].action,
            AuthorizedLineageAction::ResolveFixed {
                evidence: LineageResolutionEvidence::CurrentLocation { anchor_id, .. }
            } if anchor_id == &anchor
        ));
    }

    #[test]
    fn different_evidence_for_same_anchor_does_not_authorize() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let issued = BTreeSet::from([anchor.clone()]);
        let record = current_record(anchor.clone());
        let authorization = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Fixed),
            &coverage(
                true,
                Some(anchor),
                "diff:hunk-1:page-2",
                Vec::new(),
                &issued,
                &table,
            ),
            &issued,
            &table,
        )
        .expect("authorization");
        assert!(matches!(
            authorization.decisions[0].action,
            AuthorizedLineageAction::Preserve {
                reason: LineagePreservationReason::CurrentLocationNotDelivered,
                ..
            }
        ));
    }

    #[test]
    fn exact_deletion_hunk_authorizes_fixed() {
        let table = anchor_table();
        let issued = BTreeSet::new();
        let record = PriorLineageRecord {
            lineage_id: digest('f'),
            discussion_source: PriorReviewSource::Revoot,
            state: PriorReviewState::Outdated,
            resolution_source: None,
            target: PriorLineageTarget::DeletionHunk {
                hunk_evidence_id: "diff:deleted-hunk-1".to_owned(),
            },
        };
        let authorization = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Fixed),
            &coverage(
                true,
                None,
                "unused",
                vec!["diff:deleted-hunk-1".to_owned()],
                &issued,
                &table,
            ),
            &issued,
            &table,
        )
        .expect("authorization");
        assert!(matches!(
            authorization.decisions[0].action,
            AuthorizedLineageAction::ResolveFixed {
                evidence: LineageResolutionEvidence::DeletionHunk { .. }
            }
        ));
    }

    #[test]
    fn partial_coverage_never_authorizes_resolution() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let issued = BTreeSet::from([anchor.clone()]);
        let record = current_record(anchor.clone());
        let authorization = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Fixed),
            &coverage(
                false,
                Some(anchor),
                "diff:hunk-1:page-1",
                Vec::new(),
                &issued,
                &table,
            ),
            &issued,
            &table,
        )
        .expect("authorization");
        assert!(matches!(
            authorization.decisions[0].action,
            AuthorizedLineageAction::Preserve {
                reason: LineagePreservationReason::PartialCoverage,
                ..
            }
        ));
    }

    #[test]
    fn external_resolution_state_is_preserved() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let issued = BTreeSet::from([anchor.clone()]);
        let mut record = current_record(anchor.clone());
        record.state = PriorReviewState::Resolved;
        record.resolution_source = Some(PriorReviewSource::Other);
        let authorization = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Fixed),
            &coverage(
                true,
                Some(anchor),
                "diff:hunk-1:page-1",
                Vec::new(),
                &issued,
                &table,
            ),
            &issued,
            &table,
        )
        .expect("authorization");
        assert!(matches!(
            authorization.decisions[0].action,
            AuthorizedLineageAction::Preserve {
                state: PriorReviewState::Resolved,
                resolution_source: Some(PriorReviewSource::Other),
                reason: LineagePreservationReason::ExternallyResolved,
            }
        ));
    }

    #[test]
    fn foreign_discussion_is_never_mutated() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let issued = BTreeSet::from([anchor.clone()]);
        let mut record = current_record(anchor.clone());
        record.discussion_source = PriorReviewSource::Other;
        let authorization = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Fixed),
            &coverage(
                true,
                Some(anchor),
                "diff:hunk-1:page-1",
                Vec::new(),
                &issued,
                &table,
            ),
            &issued,
            &table,
        )
        .expect("authorization");
        assert!(matches!(
            authorization.decisions[0].action,
            AuthorizedLineageAction::Preserve {
                reason: LineagePreservationReason::ForeignDiscussion,
                ..
            }
        ));
    }

    #[test]
    fn preserve_proposal_never_resolves_even_with_exact_coverage() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let issued = BTreeSet::from([anchor.clone()]);
        let record = current_record(anchor.clone());
        let authorization = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Preserve),
            &coverage(
                true,
                Some(anchor),
                "diff:hunk-1:page-1",
                Vec::new(),
                &issued,
                &table,
            ),
            &issued,
            &table,
        )
        .expect("authorization");
        assert!(matches!(
            authorization.decisions[0].action,
            AuthorizedLineageAction::Preserve {
                reason: LineagePreservationReason::ProposedPreserve,
                ..
            }
        ));
    }

    #[test]
    fn missing_duplicate_and_unknown_proposals_fail_closed() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let issued = BTreeSet::from([anchor.clone()]);
        let first = current_record(anchor.clone());
        let mut second = current_record(anchor.clone());
        second.lineage_id = digest('9');
        let evidence = coverage(
            true,
            Some(anchor),
            "diff:hunk-1:page-1",
            Vec::new(),
            &issued,
            &table,
        );
        assert_eq!(
            authorize_lineage_decisions(
                [first.clone(), second.clone()],
                response(first.lineage_id.clone(), ProposedLineageDisposition::Fixed),
                &evidence,
                &issued,
                &table,
            ),
            Err(LineageCoverageError::LineageCount)
        );
        assert_eq!(
            authorize_lineage_decisions(
                [first.clone(), second],
                LineageDecisionResponse {
                    schema_version: LineageDecisionResponse::SCHEMA_VERSION.to_owned(),
                    decisions: vec![
                        ProposedLineageDecision {
                            lineage_id: first.lineage_id.clone(),
                            disposition: ProposedLineageDisposition::Fixed,
                        },
                        ProposedLineageDecision {
                            lineage_id: first.lineage_id,
                            disposition: ProposedLineageDisposition::Preserve,
                        },
                    ],
                },
                &evidence,
                &issued,
                &table,
            ),
            Err(LineageCoverageError::DuplicateLineage)
        );
        assert_eq!(
            authorize_lineage_decisions(
                [current_record(
                    table.iter().next().expect("anchor").id.clone()
                )],
                response(digest('8'), ProposedLineageDisposition::Fixed),
                &evidence,
                &issued,
                &table,
            ),
            Err(LineageCoverageError::UnknownLineage)
        );
    }

    #[test]
    fn unissued_anchor_and_malformed_hunk_are_payload_free_errors() {
        let table = anchor_table();
        let anchor = table.iter().next().expect("anchor").id.clone();
        let record = current_record(anchor);
        let empty_coverage = coverage(true, None, "unused", Vec::new(), &BTreeSet::new(), &table);
        let error = authorize_lineage_decisions(
            [record.clone()],
            response(record.lineage_id, ProposedLineageDisposition::Fixed),
            &empty_coverage,
            &BTreeSet::new(),
            &table,
        )
        .expect_err("unissued anchor");
        assert_eq!(error, LineageCoverageError::AnchorNotIssued);
        assert_eq!(format!("{error:?}"), "AnchorNotIssued");

        let malformed = PriorLineageRecord {
            lineage_id: digest('f'),
            discussion_source: PriorReviewSource::Revoot,
            state: PriorReviewState::Open,
            resolution_source: None,
            target: PriorLineageTarget::DeletionHunk {
                hunk_evidence_id: "../../src/private.rs".to_owned(),
            },
        };
        assert_eq!(
            authorize_lineage_decisions(
                [malformed.clone()],
                response(malformed.lineage_id, ProposedLineageDisposition::Fixed),
                &empty_coverage,
                &BTreeSet::new(),
                &table,
            ),
            Err(LineageCoverageError::EvidenceId)
        );
    }

    #[test]
    fn model_schema_cannot_supply_resolution_evidence_or_host_state() {
        let response = serde_json::from_value::<LineageDecisionResponse>(serde_json::json!({
            "schema_version": LineageDecisionResponse::SCHEMA_VERSION,
            "decisions": [{
                "lineage_id": digest('f'),
                "disposition": "fixed",
                "anchor_id": "invented",
                "state": "resolved"
            }]
        }));
        assert!(response.is_err());
    }
}
