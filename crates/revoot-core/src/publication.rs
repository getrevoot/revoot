//! Pure, create/no-op publication planning and recovery journal.
//!
//! This module performs no SCM calls and contains no credentials. A controller
//! must independently acquire a complete discussion inventory and re-check the
//! immutable snapshot before each mutation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AnchorId, GitLabSnapshotIdentity, ReviewSnapshotIdentity, Sha256Digest};

const MARKER_PREFIX: &str = "<!-- revoot:v1 ";
const MARKER_SUFFIX: &str = " -->";
const LINEAGE_MARKER_PREFIX: &str = "<!-- revoot:lineage-v1 ";
const MAX_COMMENT_BYTES: usize = 16 * 1024;
const MAX_CANDIDATES: usize = 1_000;
const MAX_EXISTING_NOTES: usize = 100_000;

/// Intended location of a publication candidate.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "anchor_id")]
pub enum PublicationTarget {
    Inline(AnchorId),
    Summary,
}

/// A deterministic rendered comment before marker/fingerprint binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationCandidate {
    pub target: PublicationTarget,
    pub body: String,
}

/// Marker attached only to Revoot-created comments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationMarker {
    pub scope_sha256: Sha256Digest,
    pub fingerprint_sha256: Sha256Digest,
    pub target_kind: PublicationTargetKind,
}

/// Marker target class. The anchor remains bound through the fingerprint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationTargetKind {
    Inline,
    Summary,
}

/// Host-backed identity for one semantically adjudicated finding lineage.
///
/// The lineage is assigned when a finding is first published. Later findings
/// may reuse it only after review interprets them as the same logical issue.
/// The evidence digest describes the observed occurrence and is not itself an
/// issue fingerprint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingLineageMarker {
    pub lineage_sha256: Sha256Digest,
    pub occurrence_sha256: Sha256Digest,
    pub reviewed_head: crate::GitSha,
    pub evidence_sha256: Sha256Digest,
}

impl FindingLineageMarker {
    /// Construct one occurrence marker for a semantically assigned lineage.
    ///
    /// # Panics
    ///
    /// Panics only if the standard lowercase SHA-256 formatter stops producing
    /// a valid digest, which is an internal invariant.
    #[must_use]
    pub fn new(
        lineage_sha256: Sha256Digest,
        reviewed_head: crate::GitSha,
        evidence_sha256: Sha256Digest,
    ) -> Self {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, b"revoot-finding-occurrence-v1");
        hash_field(&mut hasher, lineage_sha256.as_str().as_bytes());
        hash_field(&mut hasher, reviewed_head.as_str().as_bytes());
        hash_field(&mut hasher, evidence_sha256.as_str().as_bytes());
        Self {
            lineage_sha256,
            occurrence_sha256: Sha256Digest::try_from(format!("{:x}", hasher.finalize()))
                .expect("SHA-256 formatting is valid"),
            reviewed_head,
            evidence_sha256,
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{LINEAGE_MARKER_PREFIX}lineage={} occurrence={} head={} evidence={}{MARKER_SUFFIX}",
            self.lineage_sha256.as_str(),
            self.occurrence_sha256.as_str(),
            self.reviewed_head.as_str(),
            self.evidence_sha256.as_str(),
        )
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let content = value
            .strip_prefix(LINEAGE_MARKER_PREFIX)?
            .strip_suffix(MARKER_SUFFIX)?;
        let mut parts = content.split(' ');
        let lineage = parts.next()?.strip_prefix("lineage=")?;
        let occurrence = parts.next()?.strip_prefix("occurrence=")?;
        let head = parts.next()?.strip_prefix("head=")?;
        let evidence = parts.next()?.strip_prefix("evidence=")?;
        if parts.next().is_some() {
            return None;
        }
        let marker = Self {
            lineage_sha256: Sha256Digest::try_from(lineage.to_owned()).ok()?,
            occurrence_sha256: Sha256Digest::try_from(occurrence.to_owned()).ok()?,
            reviewed_head: crate::GitSha::try_from(head.to_owned()).ok()?,
            evidence_sha256: Sha256Digest::try_from(evidence.to_owned()).ok()?,
        };
        let expected = Self::new(
            marker.lineage_sha256.clone(),
            marker.reviewed_head.clone(),
            marker.evidence_sha256.clone(),
        );
        (marker.occurrence_sha256 == expected.occurrence_sha256).then_some(marker)
    }

    /// Extract the sole lineage marker from a comment body.
    ///
    /// `None` is returned for legacy comments and for ambiguous/malformed
    /// marker inventories so callers never infer lineage from a lookalike.
    #[must_use]
    pub fn from_body(body: &str) -> Option<Self> {
        let mut markers = body.lines().filter_map(Self::parse);
        let marker = markers.next()?;
        markers.next().is_none().then_some(marker)
    }
}

impl PublicationMarker {
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{MARKER_PREFIX}scope={} fingerprint={} kind={}{MARKER_SUFFIX}",
            self.scope_sha256.as_str(),
            self.fingerprint_sha256.as_str(),
            match self.target_kind {
                PublicationTargetKind::Inline => "inline",
                PublicationTargetKind::Summary => "summary",
            }
        )
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let content = value
            .strip_prefix(MARKER_PREFIX)?
            .strip_suffix(MARKER_SUFFIX)?;
        let mut parts = content.split(' ');
        let scope = parts.next()?.strip_prefix("scope=")?;
        let fingerprint = parts.next()?.strip_prefix("fingerprint=")?;
        let kind = parts.next()?.strip_prefix("kind=")?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            scope_sha256: Sha256Digest::try_from(scope.to_owned()).ok()?,
            fingerprint_sha256: Sha256Digest::try_from(fingerprint.to_owned()).ok()?,
            target_kind: match kind {
                "inline" => PublicationTargetKind::Inline,
                "summary" => PublicationTargetKind::Summary,
                _ => return None,
            },
        })
    }
}

/// One existing GitLab note from a completely acquired inventory.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingPublicationNote {
    pub note_id: u64,
    pub author_user_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_username: Option<String>,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discussion_id: Option<String>,
    #[serde(default)]
    pub resolvable: bool,
    #[serde(default)]
    pub resolved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by_user_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_line: Option<u32>,
}

impl ExistingPublicationNote {
    #[must_use]
    pub fn terminal_marker(&self) -> Option<PublicationMarker> {
        let marker_line = self
            .body
            .rsplit_once('\n')
            .map_or(self.body.as_str(), |(_, tail)| tail);
        PublicationMarker::parse(marker_line)
    }
}

/// Complete or incomplete pre-publication discussion inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationInventory {
    pub complete: bool,
    pub notes: Vec<ExistingPublicationNote>,
}

/// Comment content after immutable scope, fingerprint, and marker binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPublication {
    pub target: PublicationTarget,
    pub body: String,
    pub marker: PublicationMarker,
    pub marked_body: String,
}

/// The only MVP decisions: create a new note or perform no mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum PublicationDecision {
    Create,
    NoOp { existing_note_id: u64 },
}

/// One ordered publication action. Summary actions are always last.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationAction {
    pub publication: PreparedPublication,
    pub decision: PublicationDecision,
}

/// Immutable publication plan derived from a complete inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPlan {
    pub schema_version: String,
    pub snapshot: GitLabSnapshotIdentity,
    pub bot_user_id: u64,
    pub actions: Vec<PublicationAction>,
    pub plan_sha256: Sha256Digest,
}

impl PublicationPlan {
    pub const SCHEMA_VERSION: &'static str = "revoot.publication-plan/v1";

    /// Recompute ordering, markers, fingerprints, decisions, and plan digest.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for a tampered or malformed retained plan.
    pub fn validate_replay(&self) -> Result<(), PublicationReplayError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(PublicationReplayError::SchemaVersion);
        }
        if self.bot_user_id == 0 {
            return Err(PublicationReplayError::BotIdentity);
        }
        if self.actions.len() > MAX_CANDIDATES {
            return Err(PublicationReplayError::ActionCount);
        }
        let scope = publication_scope_digest(&self.snapshot);
        let mut previous: Option<&PreparedPublication> = None;
        let mut fingerprints = BTreeSet::new();
        let mut saw_summary = false;
        for action in &self.actions {
            validate_candidate(&PublicationCandidate {
                target: action.publication.target.clone(),
                body: action.publication.body.clone(),
            })
            .map_err(PublicationReplayError::Candidate)?;
            if saw_summary {
                return Err(PublicationReplayError::SummaryNotLast);
            }
            if matches!(action.publication.target, PublicationTarget::Summary) {
                saw_summary = true;
            }
            if previous.is_some_and(|prior| {
                publication_order(prior, &action.publication) != std::cmp::Ordering::Less
            }) {
                return Err(PublicationReplayError::ActionOrder);
            }
            previous = Some(&action.publication);
            let expected = prepare_publication(
                &self.snapshot,
                &action.publication.target,
                &action.publication.body,
            );
            if expected.marked_body.len() > MAX_COMMENT_BYTES {
                return Err(PublicationReplayError::Candidate(
                    PublicationCandidateError::BodyTooLarge,
                ));
            }
            if expected != action.publication || action.publication.marker.scope_sha256 != scope {
                return Err(PublicationReplayError::MarkerOrFingerprint);
            }
            if !fingerprints.insert(action.publication.marker.fingerprint_sha256.clone()) {
                return Err(PublicationReplayError::DuplicateFingerprint);
            }
            match action.decision {
                PublicationDecision::Create => {}
                PublicationDecision::NoOp { existing_note_id } if existing_note_id != 0 => {}
                PublicationDecision::NoOp { .. } => {
                    return Err(PublicationReplayError::NoteIdentity);
                }
            }
        }
        if derive_plan_digest(self) != self.plan_sha256 {
            return Err(PublicationReplayError::PlanDigest);
        }
        Ok(())
    }
}

/// Publication-plan construction error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationPlanError {
    InventoryIncomplete,
    InventoryTooLarge,
    BotIdentity,
    DuplicateNoteId,
    CandidateCount,
    Candidate(PublicationCandidateError),
    DuplicateFingerprint,
    MultipleSummaries,
    AmbiguousOwnedMatch,
    InternalReplay(PublicationReplayError),
}

/// Invalid candidate body or target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationCandidateError {
    EmptyBody,
    BodyTooLarge,
    ControlCharacter,
    MarkerInjection,
}

/// Retained-plan validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationReplayError {
    SchemaVersion,
    BotIdentity,
    ActionCount,
    Candidate(PublicationCandidateError),
    SummaryNotLast,
    ActionOrder,
    MarkerOrFingerprint,
    DuplicateFingerprint,
    NoteIdentity,
    PlanDigest,
}

/// Build a create/no-op plan from a complete discussion inventory.
///
/// Only a note authored by the configured bot with an exact valid terminal
/// marker can produce `NoOp`. Human, foreign, malformed, and forged-marker
/// notes are never modified and never suppress creation.
///
/// # Errors
///
/// Rejects incomplete/ambiguous inventories, invalid candidates, duplicate
/// fingerprints, multiple summaries, and invalid bot identity.
pub fn build_publication_plan(
    snapshot: GitLabSnapshotIdentity,
    bot_user_id: u64,
    candidates: impl IntoIterator<Item = PublicationCandidate>,
    inventory: &PublicationInventory,
) -> Result<PublicationPlan, PublicationPlanError> {
    if bot_user_id == 0 {
        return Err(PublicationPlanError::BotIdentity);
    }
    validate_inventory(inventory)?;
    let candidates: Vec<_> = candidates.into_iter().collect();
    if candidates.len() > MAX_CANDIDATES {
        return Err(PublicationPlanError::CandidateCount);
    }
    let mut prepared = Vec::with_capacity(candidates.len());
    let mut fingerprints = BTreeSet::new();
    let mut summary_count = 0_usize;
    for candidate in candidates {
        validate_candidate(&candidate).map_err(PublicationPlanError::Candidate)?;
        summary_count += usize::from(matches!(candidate.target, PublicationTarget::Summary));
        let publication = prepare_publication(&snapshot, &candidate.target, &candidate.body);
        if publication.marked_body.len() > MAX_COMMENT_BYTES {
            return Err(PublicationPlanError::Candidate(
                PublicationCandidateError::BodyTooLarge,
            ));
        }
        if !fingerprints.insert(publication.marker.fingerprint_sha256.clone()) {
            return Err(PublicationPlanError::DuplicateFingerprint);
        }
        prepared.push(publication);
    }
    if summary_count > 1 {
        return Err(PublicationPlanError::MultipleSummaries);
    }
    prepared.sort_by(publication_order);

    let mut actions = Vec::with_capacity(prepared.len());
    for publication in prepared {
        let exact_matches: Vec<_> = inventory
            .notes
            .iter()
            .filter(|note| note.author_user_id == bot_user_id)
            .filter(|note| note.terminal_marker().as_ref() == Some(&publication.marker))
            .collect();
        let lineage_matches = if exact_matches.is_empty() {
            finding_lineage_id(&publication.body).map_or_else(Vec::new, |lineage| {
                inventory
                    .notes
                    .iter()
                    .filter(|note| note.author_user_id == bot_user_id)
                    .filter(|note| finding_lineage_id(&note.body).as_ref() == Some(&lineage))
                    .collect()
            })
        } else {
            Vec::new()
        };
        let matches = if exact_matches.is_empty() {
            lineage_matches
        } else {
            exact_matches
        };
        let decision = match matches.as_slice() {
            [] => PublicationDecision::Create,
            [note] => PublicationDecision::NoOp {
                existing_note_id: note.note_id,
            },
            _ => return Err(PublicationPlanError::AmbiguousOwnedMatch),
        };
        actions.push(PublicationAction {
            publication,
            decision,
        });
    }
    let mut plan = PublicationPlan {
        schema_version: PublicationPlan::SCHEMA_VERSION.to_owned(),
        snapshot,
        bot_user_id,
        actions,
        plan_sha256: Sha256Digest::of_bytes(&[]),
    };
    plan.plan_sha256 = derive_plan_digest(&plan);
    plan.validate_replay()
        .map_err(PublicationPlanError::InternalReplay)?;
    Ok(plan)
}

/// Return an embedded semantic lineage, including a deterministic compatibility
/// identity for legacy v1 Revoot publications.
#[must_use]
pub fn finding_lineage_id(body: &str) -> Option<Sha256Digest> {
    if let Some(marker) = FindingLineageMarker::from_body(body) {
        return Some(marker.lineage_sha256);
    }
    let mut markers = body.lines().filter_map(PublicationMarker::parse);
    let marker = markers.next()?;
    if markers.next().is_some() {
        return None;
    }
    Some(Sha256Digest::of_bytes(
        marker.fingerprint_sha256.as_str().as_bytes(),
    ))
}

fn validate_inventory(inventory: &PublicationInventory) -> Result<(), PublicationPlanError> {
    if !inventory.complete {
        return Err(PublicationPlanError::InventoryIncomplete);
    }
    if inventory.notes.len() > MAX_EXISTING_NOTES {
        return Err(PublicationPlanError::InventoryTooLarge);
    }
    let mut note_ids = BTreeSet::new();
    for note in &inventory.notes {
        if note.note_id == 0 || note.author_user_id == 0 || !note_ids.insert(note.note_id) {
            return Err(PublicationPlanError::DuplicateNoteId);
        }
    }
    Ok(())
}

fn validate_candidate(candidate: &PublicationCandidate) -> Result<(), PublicationCandidateError> {
    if candidate.body.trim().is_empty() {
        return Err(PublicationCandidateError::EmptyBody);
    }
    if candidate.body.len() > MAX_COMMENT_BYTES {
        return Err(PublicationCandidateError::BodyTooLarge);
    }
    if candidate
        .body
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(PublicationCandidateError::ControlCharacter);
    }
    if candidate.body.contains(MARKER_PREFIX) {
        return Err(PublicationCandidateError::MarkerInjection);
    }
    Ok(())
}

fn prepare_publication(
    snapshot: &GitLabSnapshotIdentity,
    target: &PublicationTarget,
    body: &str,
) -> PreparedPublication {
    prepare_review_publication(
        &ReviewSnapshotIdentity::GitLab(snapshot.clone()),
        target,
        body,
    )
    .expect("validated publication candidate prepares infallibly")
}

/// Bind one validated comment body and target to any supported immutable review snapshot.
///
/// # Errors
///
/// Rejects the same malformed or oversized candidate bodies as the publication planner.
///
/// # Panics
///
/// Panics only if an internally defined, infallible publication target cannot serialize.
pub fn prepare_review_publication(
    snapshot: &ReviewSnapshotIdentity,
    target: &PublicationTarget,
    body: &str,
) -> Result<PreparedPublication, PublicationCandidateError> {
    validate_candidate(&PublicationCandidate {
        target: target.clone(),
        body: body.to_owned(),
    })?;
    let scope_sha256 = review_publication_scope_digest(snapshot);
    let target_kind = match target {
        PublicationTarget::Inline(_) => PublicationTargetKind::Inline,
        PublicationTarget::Summary => PublicationTargetKind::Summary,
    };
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"revoot-publication-fingerprint-v1");
    hash_field(&mut hasher, scope_sha256.as_str().as_bytes());
    let target_bytes =
        serde_json::to_vec(target).expect("publication target serializes infallibly");
    hash_field(&mut hasher, &target_bytes);
    hash_field(&mut hasher, body.as_bytes());
    let marker = PublicationMarker {
        scope_sha256,
        fingerprint_sha256: Sha256Digest::try_from(format!("{:x}", hasher.finalize()))
            .expect("SHA-256 formatting is valid"),
        target_kind,
    };
    let marked_body = format!("{body}\n{}", marker.render());
    let prepared = PreparedPublication {
        target: target.clone(),
        body: body.to_owned(),
        marker,
        marked_body,
    };
    if prepared.marked_body.len() > MAX_COMMENT_BYTES {
        return Err(PublicationCandidateError::BodyTooLarge);
    }
    Ok(prepared)
}

fn publication_scope_digest(snapshot: &GitLabSnapshotIdentity) -> Sha256Digest {
    review_publication_scope_digest(&ReviewSnapshotIdentity::GitLab(snapshot.clone()))
}

#[must_use]
/// Return the deterministic publication scope for a supported snapshot identity.
///
/// # Panics
///
/// Panics only if an internally defined, infallible snapshot identity cannot serialize.
pub fn review_publication_scope_digest(snapshot: &ReviewSnapshotIdentity) -> Sha256Digest {
    let bytes = match snapshot {
        ReviewSnapshotIdentity::GitLab(identity) => serde_json::to_vec(identity),
        ReviewSnapshotIdentity::GitHub(identity) => serde_json::to_vec(identity),
        ReviewSnapshotIdentity::Local(identity) => serde_json::to_vec(identity),
    }
    .expect("review snapshot identity serializes infallibly");
    Sha256Digest::of_bytes(&bytes)
}

fn publication_order(
    left: &PreparedPublication,
    right: &PreparedPublication,
) -> std::cmp::Ordering {
    let left_summary = matches!(left.target, PublicationTarget::Summary);
    let right_summary = matches!(right.target, PublicationTarget::Summary);
    left_summary.cmp(&right_summary).then_with(|| {
        left.marker
            .fingerprint_sha256
            .cmp(&right.marker.fingerprint_sha256)
    })
}

#[derive(Serialize)]
struct PublicationPlanDigestView<'a> {
    schema_version: &'a str,
    snapshot: &'a GitLabSnapshotIdentity,
    bot_user_id: u64,
    actions: &'a [PublicationAction],
}

fn derive_plan_digest(plan: &PublicationPlan) -> Sha256Digest {
    let view = PublicationPlanDigestView {
        schema_version: &plan.schema_version,
        snapshot: &plan.snapshot,
        bot_user_id: plan.bot_user_id,
        actions: &plan.actions,
    };
    Sha256Digest::of_bytes(
        &serde_json::to_vec(&view).expect("publication plan serializes infallibly"),
    )
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

/// Durable journal state for one publication plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum PublicationJournalState {
    Ready { next_action: u32 },
    AwaitingOutcome { action: u32 },
    AmbiguousOutcome { action: u32 },
    Completed,
    StoppedStale { before_action: u32 },
    Failed { action: u32 },
}

/// Confirmed journal entry. No request or response payload is retained.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum PublicationJournalOutcome {
    Created { note_id: u64 },
    NoOp { note_id: u64 },
    Reconciled { note_id: u64 },
}

/// One durable completed action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationJournalEntry {
    pub action: u32,
    pub fingerprint_sha256: Sha256Digest,
    pub outcome: PublicationJournalOutcome,
}

/// Pure state machine for freshness and ambiguous-response recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationJournal {
    pub schema_version: String,
    pub plan_sha256: Sha256Digest,
    pub snapshot: GitLabSnapshotIdentity,
    pub bot_user_id: u64,
    pub actions: Vec<PublicationAction>,
    pub state: PublicationJournalState,
    pub entries: Vec<PublicationJournalEntry>,
}

impl PublicationJournal {
    pub const SCHEMA_VERSION: &'static str = "revoot.publication-journal/v1";

    /// Create a journal only from an intact retained plan.
    ///
    /// # Errors
    ///
    /// Rejects any plan that fails canonical replay validation.
    pub fn try_new(plan: &PublicationPlan) -> Result<Self, PublicationReplayError> {
        plan.validate_replay()?;
        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_owned(),
            plan_sha256: plan.plan_sha256.clone(),
            snapshot: plan.snapshot.clone(),
            bot_user_id: plan.bot_user_id,
            actions: plan.actions.clone(),
            state: if plan.actions.is_empty() {
                PublicationJournalState::Completed
            } else {
                PublicationJournalState::Ready { next_action: 0 }
            },
            entries: Vec::new(),
        })
    }

    /// Validate a deserialized journal before resuming any publication work.
    ///
    /// # Errors
    ///
    /// Rejects plan tampering, non-contiguous entries, impossible outcomes,
    /// and state/index combinations that cannot arise from this state machine.
    pub fn validate_replay(&self) -> Result<(), PublicationJournalReplayError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(PublicationJournalReplayError::SchemaVersion);
        }
        PublicationPlan {
            schema_version: PublicationPlan::SCHEMA_VERSION.to_owned(),
            snapshot: self.snapshot.clone(),
            bot_user_id: self.bot_user_id,
            actions: self.actions.clone(),
            plan_sha256: self.plan_sha256.clone(),
        }
        .validate_replay()
        .map_err(PublicationJournalReplayError::Plan)?;

        if self.entries.len() > self.actions.len() {
            return Err(PublicationJournalReplayError::EntryCount);
        }
        for (index, entry) in self.entries.iter().enumerate() {
            let expected_index =
                u32::try_from(index).map_err(|_| PublicationJournalReplayError::EntryIndex)?;
            let action = self
                .actions
                .get(index)
                .ok_or(PublicationJournalReplayError::EntryIndex)?;
            if entry.action != expected_index
                || entry.fingerprint_sha256 != action.publication.marker.fingerprint_sha256
            {
                return Err(PublicationJournalReplayError::EntryIndex);
            }
            let valid_outcome = match (action.decision.clone(), entry.outcome) {
                (
                    PublicationDecision::Create,
                    PublicationJournalOutcome::Created { note_id }
                    | PublicationJournalOutcome::Reconciled { note_id },
                ) => note_id != 0,
                (
                    PublicationDecision::NoOp { existing_note_id },
                    PublicationJournalOutcome::NoOp { note_id },
                ) => note_id == existing_note_id,
                _ => false,
            };
            if !valid_outcome {
                return Err(PublicationJournalReplayError::EntryOutcome);
            }
        }

        let completed =
            u32::try_from(self.entries.len()).map_err(|_| PublicationJournalReplayError::State)?;
        let action_count =
            u32::try_from(self.actions.len()).map_err(|_| PublicationJournalReplayError::State)?;
        let valid_state = match self.state {
            PublicationJournalState::Ready { next_action } => {
                next_action == completed && next_action < action_count
            }
            PublicationJournalState::AwaitingOutcome { action } => {
                action == completed && action < action_count
            }
            PublicationJournalState::AmbiguousOutcome { action } => {
                action == completed
                    && action < action_count
                    && matches!(
                        self.actions[usize::try_from(action)
                            .map_err(|_| PublicationJournalReplayError::State)?]
                        .decision,
                        PublicationDecision::Create
                    )
            }
            PublicationJournalState::Completed => completed == action_count,
            PublicationJournalState::StoppedStale { before_action }
            | PublicationJournalState::Failed {
                action: before_action,
            } => before_action == completed && before_action < action_count,
        };
        if !valid_state {
            return Err(PublicationJournalReplayError::State);
        }
        Ok(())
    }

    /// Re-check exact snapshot freshness and record intent before an action.
    ///
    /// # Errors
    ///
    /// Rejects stale identity, invalid state, or index drift. Staleness is
    /// terminal and occurs before any caller-authorized mutation.
    pub fn begin_next(
        &mut self,
        observed: &GitLabSnapshotIdentity,
    ) -> Result<&PublicationAction, PublicationJournalError> {
        self.validate_replay()
            .map_err(|_| PublicationJournalError::RetainedState)?;
        let PublicationJournalState::Ready { next_action } = self.state else {
            return Err(PublicationJournalError::InvalidState);
        };
        if observed != &self.snapshot {
            self.state = PublicationJournalState::StoppedStale {
                before_action: next_action,
            };
            return Err(PublicationJournalError::StaleSnapshot);
        }
        let index = usize::try_from(next_action).map_err(|_| PublicationJournalError::Index)?;
        let action = self
            .actions
            .get(index)
            .ok_or(PublicationJournalError::Index)?;
        self.state = PublicationJournalState::AwaitingOutcome {
            action: next_action,
        };
        Ok(action)
    }

    /// Confirm the expected create or no-op outcome.
    ///
    /// # Errors
    ///
    /// Rejects zero/mismatched note identities or invalid state.
    pub fn confirm(&mut self, note_id: u64) -> Result<(), PublicationJournalError> {
        self.validate_replay()
            .map_err(|_| PublicationJournalError::RetainedState)?;
        if note_id == 0 {
            return self.fail_current(PublicationJournalError::NoteIdentity);
        }
        let action_index = self.awaiting_index()?;
        let action = &self.actions[action_index];
        let outcome = match action.decision {
            PublicationDecision::Create => PublicationJournalOutcome::Created { note_id },
            PublicationDecision::NoOp { existing_note_id } if existing_note_id == note_id => {
                PublicationJournalOutcome::NoOp { note_id }
            }
            PublicationDecision::NoOp { .. } => {
                return self.fail_current(PublicationJournalError::NoteIdentity);
            }
        };
        self.complete_current(outcome)
    }

    /// Mark a lost/ambiguous create response for inventory reconciliation.
    ///
    /// # Errors
    ///
    /// Only a create action awaiting an outcome may become ambiguous.
    pub fn mark_ambiguous(&mut self) -> Result<(), PublicationJournalError> {
        self.validate_replay()
            .map_err(|_| PublicationJournalError::RetainedState)?;
        let index = self.awaiting_index()?;
        if !matches!(self.actions[index].decision, PublicationDecision::Create) {
            return self.fail_current(PublicationJournalError::InvalidState);
        }
        self.state = PublicationJournalState::AmbiguousOutcome {
            action: u32::try_from(index).map_err(|_| PublicationJournalError::Index)?,
        };
        Ok(())
    }

    /// Reconcile a lost create response using a fresh complete inventory.
    ///
    /// Zero exact owned matches authorizes retry of the same action; one records
    /// success; multiple matches fail closed.
    ///
    /// # Errors
    ///
    /// Rejects incomplete inventory, invalid state, or ambiguous ownership.
    pub fn reconcile_ambiguous(
        &mut self,
        inventory: &PublicationInventory,
    ) -> Result<PublicationReconciliation, PublicationJournalError> {
        self.validate_replay()
            .map_err(|_| PublicationJournalError::RetainedState)?;
        let PublicationJournalState::AmbiguousOutcome { action } = self.state else {
            return Err(PublicationJournalError::InvalidState);
        };
        validate_inventory(inventory).map_err(|_| PublicationJournalError::Inventory)?;
        let index = usize::try_from(action).map_err(|_| PublicationJournalError::Index)?;
        let expected = &self
            .actions
            .get(index)
            .ok_or(PublicationJournalError::Index)?
            .publication
            .marker;
        let matches: Vec<_> = inventory
            .notes
            .iter()
            .filter(|note| note.author_user_id == self.bot_user_id)
            .filter(|note| note.terminal_marker().as_ref() == Some(expected))
            .collect();
        match matches.as_slice() {
            [] => {
                self.state = PublicationJournalState::Ready {
                    next_action: action,
                };
                Ok(PublicationReconciliation::RetryAuthorized)
            }
            [note] => {
                let note_id = note.note_id;
                self.complete_current(PublicationJournalOutcome::Reconciled { note_id })?;
                Ok(PublicationReconciliation::Recovered { note_id })
            }
            _ => self.fail_current(PublicationJournalError::AmbiguousOwnedMatch),
        }
    }

    /// Stop before the next action when the controller cannot prove that the
    /// authoritative merge-request identity is still exact.
    ///
    /// # Errors
    ///
    /// Rejects invalid retained state or a transition outside `Ready`.
    pub fn stop_stale(&mut self) -> Result<(), PublicationJournalError> {
        self.validate_replay()
            .map_err(|_| PublicationJournalError::RetainedState)?;
        let PublicationJournalState::Ready { next_action } = self.state else {
            return Err(PublicationJournalError::InvalidState);
        };
        self.state = PublicationJournalState::StoppedStale {
            before_action: next_action,
        };
        Ok(())
    }

    /// Retain a terminal failure at the current action without payload data.
    ///
    /// # Errors
    ///
    /// Rejects invalid retained state or an already terminal journal.
    pub fn fail(&mut self) -> Result<(), PublicationJournalError> {
        self.validate_replay()
            .map_err(|_| PublicationJournalError::RetainedState)?;
        let (PublicationJournalState::AwaitingOutcome { action }
        | PublicationJournalState::AmbiguousOutcome { action }
        | PublicationJournalState::Ready {
            next_action: action,
        }) = self.state
        else {
            return Err(PublicationJournalError::InvalidState);
        };
        self.state = PublicationJournalState::Failed { action };
        Ok(())
    }

    fn awaiting_index(&self) -> Result<usize, PublicationJournalError> {
        let PublicationJournalState::AwaitingOutcome { action } = self.state else {
            return Err(PublicationJournalError::InvalidState);
        };
        usize::try_from(action).map_err(|_| PublicationJournalError::Index)
    }

    fn complete_current(
        &mut self,
        outcome: PublicationJournalOutcome,
    ) -> Result<(), PublicationJournalError> {
        let (PublicationJournalState::AwaitingOutcome { action }
        | PublicationJournalState::AmbiguousOutcome { action }) = self.state
        else {
            return Err(PublicationJournalError::InvalidState);
        };
        let index = usize::try_from(action).map_err(|_| PublicationJournalError::Index)?;
        let fingerprint_sha256 = self
            .actions
            .get(index)
            .ok_or(PublicationJournalError::Index)?
            .publication
            .marker
            .fingerprint_sha256
            .clone();
        self.entries.push(PublicationJournalEntry {
            action,
            fingerprint_sha256,
            outcome,
        });
        let next_action = action
            .checked_add(1)
            .ok_or(PublicationJournalError::Index)?;
        self.state = if usize::try_from(next_action).ok() == Some(self.actions.len()) {
            PublicationJournalState::Completed
        } else {
            PublicationJournalState::Ready { next_action }
        };
        Ok(())
    }

    fn fail_current<T>(
        &mut self,
        error: PublicationJournalError,
    ) -> Result<T, PublicationJournalError> {
        let (PublicationJournalState::AwaitingOutcome { action }
        | PublicationJournalState::AmbiguousOutcome { action }
        | PublicationJournalState::Ready {
            next_action: action,
        }) = self.state
        else {
            return Err(error);
        };
        self.state = PublicationJournalState::Failed { action };
        Err(error)
    }
}

/// Result of ambiguous-response reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationReconciliation {
    RetryAuthorized,
    Recovered { note_id: u64 },
}

/// Stable journal transition error without SCM payload text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationJournalError {
    RetainedState,
    InvalidState,
    StaleSnapshot,
    Index,
    NoteIdentity,
    Inventory,
    AmbiguousOwnedMatch,
}

/// Persisted-journal validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationJournalReplayError {
    SchemaVersion,
    Plan(PublicationReplayError),
    EntryCount,
    EntryIndex,
    EntryOutcome,
    State,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DiffRefs, DiffVersionId, DiffVersionRecord, GitLabDiffVersionIdentity, GitSha,
        MergeRequestIid, ProjectId, SnapshotScope,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn snapshot(marker: char) -> GitLabSnapshotIdentity {
        GitLabDiffVersionIdentity {
            scope: SnapshotScope {
                instance_origin_digest: digest('a'),
                project_id: ProjectId::try_from(1).unwrap(),
                merge_request_iid: MergeRequestIid::try_from(2).unwrap(),
            },
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(3).unwrap(),
                refs: DiffRefs {
                    base_sha: "b".repeat(40).try_into().unwrap(),
                    start_sha: "c".repeat(40).try_into().unwrap(),
                    head_sha: marker.to_string().repeat(40).try_into().unwrap(),
                },
            },
        }
        .freeze(digest('e'))
    }

    fn inline(marker: char, body: &str) -> PublicationCandidate {
        PublicationCandidate {
            target: PublicationTarget::Inline(
                AnchorId::try_from(format!("ga1_{}", marker.to_string().repeat(64))).unwrap(),
            ),
            body: body.to_owned(),
        }
    }

    fn empty_inventory() -> PublicationInventory {
        PublicationInventory {
            complete: true,
            notes: Vec::new(),
        }
    }

    #[test]
    fn plan_is_deterministic_and_summary_is_last() {
        let candidates = [
            PublicationCandidate {
                target: PublicationTarget::Summary,
                body: "Summary".to_owned(),
            },
            inline('1', "First"),
            inline('2', "Second"),
        ];
        let first =
            build_publication_plan(snapshot('d'), 7, candidates.clone(), &empty_inventory())
                .unwrap();
        let second = build_publication_plan(
            snapshot('d'),
            7,
            candidates.into_iter().rev(),
            &empty_inventory(),
        )
        .unwrap();
        assert_eq!(first, second);
        assert!(matches!(
            first.actions.last().unwrap().publication.target,
            PublicationTarget::Summary
        ));
        assert!(first.validate_replay().is_ok());
    }

    #[test]
    fn only_exact_owned_terminal_marker_produces_noop() {
        let initial = build_publication_plan(
            snapshot('d'),
            7,
            [inline('1', "Finding")],
            &empty_inventory(),
        )
        .unwrap();
        let marker = initial.actions[0].publication.marker.render();
        let inventory = PublicationInventory {
            complete: true,
            notes: vec![
                ExistingPublicationNote {
                    note_id: 1,
                    author_user_id: 8,
                    body: format!("foreign\n{marker}"),
                    discussion_id: None,
                    resolvable: false,
                    resolved: false,
                    ..ExistingPublicationNote::default()
                },
                ExistingPublicationNote {
                    note_id: 2,
                    author_user_id: 7,
                    body: format!("owned\n{marker}"),
                    discussion_id: None,
                    resolvable: false,
                    resolved: false,
                    ..ExistingPublicationNote::default()
                },
            ],
        };
        let plan =
            build_publication_plan(snapshot('d'), 7, [inline('1', "Finding")], &inventory).unwrap();
        assert_eq!(
            plan.actions[0].decision,
            PublicationDecision::NoOp {
                existing_note_id: 2
            }
        );
    }

    #[test]
    fn incomplete_or_ambiguous_inventory_fails_closed() {
        let incomplete = PublicationInventory {
            complete: false,
            notes: Vec::new(),
        };
        assert_eq!(
            build_publication_plan(snapshot('d'), 7, [inline('1', "Finding")], &incomplete),
            Err(PublicationPlanError::InventoryIncomplete)
        );

        let initial = build_publication_plan(
            snapshot('d'),
            7,
            [inline('1', "Finding")],
            &empty_inventory(),
        )
        .unwrap();
        let body = initial.actions[0].publication.marked_body.clone();
        let ambiguous = PublicationInventory {
            complete: true,
            notes: vec![
                ExistingPublicationNote {
                    note_id: 1,
                    author_user_id: 7,
                    body: body.clone(),
                    discussion_id: None,
                    resolvable: false,
                    resolved: false,
                    ..ExistingPublicationNote::default()
                },
                ExistingPublicationNote {
                    note_id: 2,
                    author_user_id: 7,
                    body,
                    discussion_id: None,
                    resolvable: false,
                    resolved: false,
                    ..ExistingPublicationNote::default()
                },
            ],
        };
        assert_eq!(
            build_publication_plan(snapshot('d'), 7, [inline('1', "Finding")], &ambiguous),
            Err(PublicationPlanError::AmbiguousOwnedMatch)
        );
    }

    #[test]
    fn stale_before_first_or_later_action_stops_before_mutation() {
        let plan = build_publication_plan(
            snapshot('d'),
            7,
            [inline('1', "First"), inline('2', "Second")],
            &empty_inventory(),
        )
        .unwrap();
        let mut journal = PublicationJournal::try_new(&plan).unwrap();
        assert_eq!(
            journal.begin_next(&snapshot('f')),
            Err(PublicationJournalError::StaleSnapshot)
        );
        assert_eq!(journal.entries.len(), 0);

        let mut journal = PublicationJournal::try_new(&plan).unwrap();
        journal.begin_next(&snapshot('d')).unwrap();
        journal.confirm(10).unwrap();
        assert_eq!(
            journal.begin_next(&snapshot('f')),
            Err(PublicationJournalError::StaleSnapshot)
        );
        assert_eq!(journal.entries.len(), 1);
    }

    #[test]
    fn lost_response_reconciles_or_authorizes_exact_retry() {
        let plan = build_publication_plan(
            snapshot('d'),
            7,
            [inline('1', "Finding")],
            &empty_inventory(),
        )
        .unwrap();
        let mut journal = PublicationJournal::try_new(&plan).unwrap();
        journal.begin_next(&snapshot('d')).unwrap();
        journal.mark_ambiguous().unwrap();
        assert_eq!(
            journal.reconcile_ambiguous(&empty_inventory()).unwrap(),
            PublicationReconciliation::RetryAuthorized
        );
        journal.begin_next(&snapshot('d')).unwrap();
        journal.mark_ambiguous().unwrap();
        let inventory = PublicationInventory {
            complete: true,
            notes: vec![ExistingPublicationNote {
                note_id: 42,
                author_user_id: 7,
                body: plan.actions[0].publication.marked_body.clone(),
                discussion_id: None,
                resolvable: false,
                resolved: false,
                ..ExistingPublicationNote::default()
            }],
        };
        assert_eq!(
            journal.reconcile_ambiguous(&inventory).unwrap(),
            PublicationReconciliation::Recovered { note_id: 42 }
        );
        assert_eq!(journal.state, PublicationJournalState::Completed);
    }

    #[test]
    fn marker_injection_and_plan_tampering_are_rejected() {
        let injected = PublicationCandidate {
            target: PublicationTarget::Summary,
            body: "text <!-- revoot:v1 fake -->".to_owned(),
        };
        assert_eq!(
            build_publication_plan(snapshot('d'), 7, [injected], &empty_inventory()),
            Err(PublicationPlanError::Candidate(
                PublicationCandidateError::MarkerInjection
            ))
        );

        let mut plan = build_publication_plan(
            snapshot('d'),
            7,
            [inline('1', "Finding")],
            &empty_inventory(),
        )
        .unwrap();
        plan.actions[0].publication.body.push('!');
        assert_eq!(
            plan.validate_replay(),
            Err(PublicationReplayError::MarkerOrFingerprint)
        );
    }

    #[test]
    fn lineage_marker_round_trips_and_rejects_ambiguous_bodies() {
        let marker = FindingLineageMarker::new(
            Sha256Digest::of_bytes(b"semantic-lineage"),
            GitSha::try_from("a".repeat(40)).unwrap(),
            Sha256Digest::of_bytes(b"observed-evidence"),
        );
        let rendered = marker.render();
        assert_eq!(FindingLineageMarker::parse(&rendered), Some(marker.clone()));
        assert_eq!(
            FindingLineageMarker::from_body(&format!("finding\n{rendered}")),
            Some(marker.clone())
        );
        assert!(
            FindingLineageMarker::from_body(&format!("finding\n{rendered}\n{rendered}")).is_none()
        );
        let tampered = rendered.replacen(marker.occurrence_sha256.as_str(), &"f".repeat(64), 1);
        assert!(FindingLineageMarker::parse(&tampered).is_none());
    }

    #[test]
    fn journal_replay_rejects_tampering_and_impossible_state() {
        let plan = build_publication_plan(
            snapshot('d'),
            7,
            [inline('1', "Finding")],
            &empty_inventory(),
        )
        .unwrap();
        let mut journal = PublicationJournal::try_new(&plan).unwrap();
        journal.state = PublicationJournalState::Completed;
        assert_eq!(
            journal.validate_replay(),
            Err(PublicationJournalReplayError::State)
        );

        let mut tampered = plan;
        tampered.plan_sha256 = digest('f');
        assert_eq!(
            PublicationJournal::try_new(&tampered),
            Err(PublicationReplayError::PlanDigest)
        );
    }
}
