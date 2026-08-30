//! Incremental GitLab publication planning over the preserved marker protocol.
//!
//! Existing human and foreign-bot notes are never treated as Revoot state.
//! Notes from older snapshot scopes are selected for explicit resolution. The
//! transport cannot edit bodies or delete user-visible data.

use std::collections::BTreeSet;

use revoot_core::{
    GitLabSnapshotIdentity, PublicationCandidate, PublicationInventory, PublicationPlan,
    PublicationPlanError, Sha256Digest, build_publication_plan, finding_lineage_id,
};

/// Complete create/no-op plan plus prior-head notes visible to the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabIncrementalPublicationPlan {
    pub publication: PublicationPlan,
    /// Revoot-owned notes from another immutable snapshot scope.
    pub stale_discussions: Vec<GitLabDiscussionResolution>,
    /// Current-scope Revoot notes not represented by this run's candidates.
    pub superseded_discussions: Vec<GitLabDiscussionResolution>,
    /// Resolved Revoot lineages explicitly resubmitted as current recurrences.
    pub reopened_discussions: Vec<GitLabDiscussionResolution>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitLabDiscussionResolution {
    pub discussion_id: String,
    pub note_id: u64,
}

/// Bind stable finding fingerprints to a complete discussion inventory.
///
/// Exact current-scope matches become no-ops in `publication`. Older-scope and
/// no-longer-produced current-scope notes are surfaced explicitly for the
/// readiness-gated publication controller to resolve after current findings converge.
///
/// # Errors
///
/// Returns the preserved publication planner's validation error for incomplete
/// inventories, invalid bot identity, invalid candidates, or ambiguous markers.
pub fn build_incremental_publication_plan(
    snapshot: GitLabSnapshotIdentity,
    bot_user_id: u64,
    candidates: impl IntoIterator<Item = PublicationCandidate>,
    inventory: &PublicationInventory,
    fixed_lineages: &BTreeSet<Sha256Digest>,
) -> Result<GitLabIncrementalPublicationPlan, PublicationPlanError> {
    let publication = build_publication_plan(snapshot, bot_user_id, candidates, inventory)?;
    let current_scope = publication
        .actions
        .first()
        .map(|action| action.publication.marker.scope_sha256.clone());
    let current_fingerprints = publication
        .actions
        .iter()
        .map(|action| action.publication.marker.fingerprint_sha256.clone())
        .collect::<BTreeSet<Sha256Digest>>();
    let current_lineages = publication
        .actions
        .iter()
        .filter_map(|action| finding_lineage_id(&action.publication.body))
        .collect::<BTreeSet<_>>();
    let mut stale_discussions = Vec::new();
    let mut superseded_discussions = Vec::new();
    let mut reopened_discussions = Vec::new();
    for note in inventory
        .notes
        .iter()
        .filter(|note| note.author_user_id == bot_user_id)
    {
        let Some(marker) = note.terminal_marker() else {
            continue;
        };
        let Some(discussion_id) = note.discussion_id.as_ref().filter(|_| note.resolvable) else {
            continue;
        };
        let resolution = GitLabDiscussionResolution {
            discussion_id: discussion_id.clone(),
            note_id: note.note_id,
        };
        if finding_lineage_id(&note.body).is_some_and(|lineage| current_lineages.contains(&lineage))
        {
            if note.resolved && note.resolved_by_user_id == Some(bot_user_id) {
                reopened_discussions.push(resolution);
            }
            continue;
        }
        if note.resolved {
            continue;
        }
        if !finding_lineage_id(&note.body).is_some_and(|lineage| fixed_lineages.contains(&lineage))
        {
            continue;
        }
        if current_scope
            .as_ref()
            .is_some_and(|scope| scope == &marker.scope_sha256)
        {
            if !current_fingerprints.contains(&marker.fingerprint_sha256) {
                superseded_discussions.push(resolution);
            }
        } else {
            stale_discussions.push(resolution);
        }
    }
    stale_discussions.sort_unstable();
    superseded_discussions.sort_unstable();
    reopened_discussions.sort_unstable();
    Ok(GitLabIncrementalPublicationPlan {
        publication,
        stale_discussions,
        superseded_discussions,
        reopened_discussions,
    })
}

#[cfg(test)]
mod tests {
    use revoot_core::{
        DiffRefs, DiffVersionId, DiffVersionRecord, ExistingPublicationNote,
        GitLabDiffVersionIdentity, MergeRequestIid, ProjectId, PublicationDecision,
        PublicationTarget, Sha256Digest, SnapshotScope,
    };

    use super::*;

    fn snapshot(manifest: u8) -> GitLabSnapshotIdentity {
        GitLabDiffVersionIdentity {
            scope: SnapshotScope {
                instance_origin_digest: Sha256Digest::of_bytes(b"origin"),
                project_id: ProjectId::try_from(1).unwrap(),
                merge_request_iid: MergeRequestIid::try_from(2).unwrap(),
            },
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(u64::from(manifest) + 1).unwrap(),
                refs: DiffRefs {
                    base_sha: revoot_core::GitSha::try_from("a".repeat(40)).unwrap(),
                    start_sha: revoot_core::GitSha::try_from("b".repeat(40)).unwrap(),
                    head_sha: revoot_core::GitSha::try_from(format!("{manifest:x}").repeat(40))
                        .unwrap(),
                },
            },
        }
        .freeze(Sha256Digest::of_bytes(&[manifest]))
    }

    fn candidate(body: &str) -> PublicationCandidate {
        PublicationCandidate {
            target: PublicationTarget::Summary,
            body: body.to_owned(),
        }
    }

    fn lineage_candidate(
        snapshot: &GitLabSnapshotIdentity,
        lineage: &Sha256Digest,
    ) -> PublicationCandidate {
        let marker = revoot_core::FindingLineageMarker::new(
            lineage.clone(),
            snapshot.version.diff_version.refs.head_sha.clone(),
            Sha256Digest::of_bytes(
                snapshot
                    .version
                    .diff_version
                    .refs
                    .head_sha
                    .as_str()
                    .as_bytes(),
            ),
        );
        candidate(&format!("finding\n{}", marker.render()))
    }

    #[test]
    fn exact_repeat_is_a_no_op_and_prior_head_is_stale() {
        let first = build_incremental_publication_plan(
            snapshot(1),
            9,
            [candidate("finding")],
            &PublicationInventory {
                complete: true,
                notes: Vec::new(),
            },
            &BTreeSet::new(),
        )
        .unwrap();
        let current_body = first.publication.actions[0].publication.marked_body.clone();
        let prior = build_incremental_publication_plan(
            snapshot(2),
            9,
            [candidate("finding")],
            &PublicationInventory {
                complete: true,
                notes: Vec::new(),
            },
            &BTreeSet::new(),
        )
        .unwrap();
        let inventory = PublicationInventory {
            complete: true,
            notes: vec![
                ExistingPublicationNote {
                    note_id: 10,
                    author_user_id: 9,
                    body: current_body,
                    discussion_id: Some("discussion-current".to_owned()),
                    resolvable: true,
                    resolved: false,
                    ..ExistingPublicationNote::default()
                },
                ExistingPublicationNote {
                    note_id: 11,
                    author_user_id: 9,
                    body: prior.publication.actions[0].publication.marked_body.clone(),
                    discussion_id: Some("discussion-prior".to_owned()),
                    resolvable: true,
                    resolved: false,
                    ..ExistingPublicationNote::default()
                },
            ],
        };
        let fixed_lineages = BTreeSet::from([
            finding_lineage_id(&inventory.notes[1].body).expect("owned prior lineage")
        ]);
        let repeated = build_incremental_publication_plan(
            snapshot(1),
            9,
            [candidate("finding")],
            &inventory,
            &fixed_lineages,
        )
        .unwrap();
        assert!(matches!(
            repeated.publication.actions[0].decision,
            PublicationDecision::NoOp {
                existing_note_id: 10
            }
        ));
        assert_eq!(
            repeated.stale_discussions,
            vec![GitLabDiscussionResolution {
                discussion_id: "discussion-prior".to_owned(),
                note_id: 11,
            }]
        );
    }

    #[test]
    fn incomplete_review_never_resolves_an_absent_lineage() {
        let first_snapshot = snapshot(1);
        let next_snapshot = snapshot(2);
        let lineage = Sha256Digest::of_bytes(b"preserved-lineage");
        let first = build_incremental_publication_plan(
            first_snapshot.clone(),
            9,
            [lineage_candidate(&first_snapshot, &lineage)],
            &PublicationInventory {
                complete: true,
                notes: Vec::new(),
            },
            &BTreeSet::new(),
        )
        .unwrap();
        let inventory = PublicationInventory {
            complete: true,
            notes: vec![ExistingPublicationNote {
                note_id: 10,
                author_user_id: 9,
                body: first.publication.actions[0].publication.marked_body.clone(),
                discussion_id: Some("discussion-lineage".to_owned()),
                resolvable: true,
                resolved: false,
                ..ExistingPublicationNote::default()
            }],
        };
        let incomplete =
            build_incremental_publication_plan(next_snapshot, 9, [], &inventory, &BTreeSet::new())
                .unwrap();
        assert!(incomplete.stale_discussions.is_empty());
        assert!(incomplete.superseded_discussions.is_empty());
        assert!(incomplete.reopened_discussions.is_empty());
    }

    #[test]
    fn semantic_lineage_carries_open_thread_and_reopens_resolved_recurrence() {
        let first_snapshot = snapshot(1);
        let next_snapshot = snapshot(2);
        let lineage = Sha256Digest::of_bytes(b"semantic-lineage");
        let first = build_incremental_publication_plan(
            first_snapshot.clone(),
            9,
            [lineage_candidate(&first_snapshot, &lineage)],
            &PublicationInventory {
                complete: true,
                notes: Vec::new(),
            },
            &BTreeSet::new(),
        )
        .unwrap();
        let note = ExistingPublicationNote {
            note_id: 10,
            author_user_id: 9,
            body: first.publication.actions[0].publication.marked_body.clone(),
            discussion_id: Some("discussion-lineage".to_owned()),
            resolvable: true,
            resolved: false,
            ..ExistingPublicationNote::default()
        };
        let carried = build_incremental_publication_plan(
            next_snapshot.clone(),
            9,
            [lineage_candidate(&next_snapshot, &lineage)],
            &PublicationInventory {
                complete: true,
                notes: vec![note.clone()],
            },
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(matches!(
            carried.publication.actions[0].decision,
            PublicationDecision::NoOp {
                existing_note_id: 10
            }
        ));
        assert!(carried.stale_discussions.is_empty());
        assert!(carried.reopened_discussions.is_empty());

        let recurrence = build_incremental_publication_plan(
            next_snapshot.clone(),
            9,
            [lineage_candidate(&next_snapshot, &lineage)],
            &PublicationInventory {
                complete: true,
                notes: vec![ExistingPublicationNote {
                    resolved: true,
                    resolved_by_user_id: Some(9),
                    ..note.clone()
                }],
            },
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            recurrence.reopened_discussions,
            vec![GitLabDiscussionResolution {
                discussion_id: "discussion-lineage".to_owned(),
                note_id: 10,
            }]
        );

        let human_resolved = build_incremental_publication_plan(
            next_snapshot.clone(),
            9,
            [lineage_candidate(&next_snapshot, &lineage)],
            &PublicationInventory {
                complete: true,
                notes: vec![ExistingPublicationNote {
                    resolved: true,
                    resolved_by_user_id: Some(8),
                    ..note
                }],
            },
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(human_resolved.reopened_discussions.is_empty());
    }
}
