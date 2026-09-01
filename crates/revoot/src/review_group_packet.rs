//! Trusted construction of one isolated worker's initial packet and authority.

use std::collections::{BTreeMap, BTreeSet};

use revoot_core::review_packet::{
    ReviewPacketCompleteDiff, ReviewPacketComposer, ReviewPacketComposition,
    ReviewPacketDiffManifest, ReviewPacketFileBrief, ReviewPacketGroupBrief, ReviewPacketInput,
    ReviewPacketPolicy, ReviewPacketPurpose, ReviewPacketTokenEstimates,
};
use revoot_core::{
    AnchorId, AnchorPosition, AnchorTable, ChangedPath, CoverageCompletionGate, RepositoryPath,
    RepositoryRelativePath, ReviewEffort, ReviewGroupMetrics, ReviewSnapshotIdentity,
    ReviewWorkerCheckpoint, ReviewWorkerPlan, Sha256Digest, WorkUnitId,
};
use serde::Serialize;

use crate::diff_artifact::{
    DiffArtifactError, DiffArtifactStore, DiffFileManifest, MAX_INLINE_GROUP_DIFF_BYTES,
};
use crate::review_group_inputs::{TrustedGroupFileInput, TrustedReviewGroupInput};

const MAX_REQUEST_INPUT_TOKENS: u64 = 32_000;
const CONSERVATIVE_PACKET_OVERHEAD_TOKENS: u64 = 1_024;

/// Trusted snapshot, plan, and policy identities expected by packet assembly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewGroupPacketBindings {
    pub snapshot: ReviewSnapshotIdentity,
    pub snapshot_sha256: Sha256Digest,
    pub partition_sha256: Sha256Digest,
    pub group_plan_sha256: Sha256Digest,
    pub selected_input_sha256: Sha256Digest,
    pub system_policy_id: String,
    pub system_policy_sha256: Sha256Digest,
    pub max_inline_diff_bytes: u64,
}

/// Stable prepared state for later conversion into a provider worker request.
///
/// The initial packet may hold one complete small diff. It deliberately has no
/// serialization or ordinary debug surface beyond the packet's redacted one.
pub struct PreparedReviewGroupPacket {
    pub worker_plan: ReviewWorkerPlan,
    pub initial_packet: ReviewPacketInput,
    pub anchor_table: AnchorTable,
    pub coverage_gate: CoverageCompletionGate,
    pub assigned_paths: BTreeSet<RepositoryRelativePath>,
    /// Exact trusted old/new path pairs for every assigned file.
    pub assigned_file_paths: BTreeSet<ChangedPath>,
    pub issued_anchors: BTreeSet<AnchorId>,
    pub work_unit_ids_by_path: BTreeMap<RepositoryPath, WorkUnitId>,
}

/// Payload-free packet construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewGroupPacketError {
    Binding,
    SnapshotBinding,
    Artifact,
    PathBinding,
    DigestBinding,
    CountBinding,
    RuleBinding,
    HunkBinding,
    AnchorBinding,
    WorkUnitBinding,
    WorkerPlan,
    Coverage,
    ContextCapacity,
    Packet,
    Serialization,
}

/// Assemble and validate one complete worker-ready trusted packet.
///
/// Small groups expose the complete concatenated diff only when the exact group
/// is at most 16 KiB. Larger groups retain only its exact digest and byte count.
/// Every initial packet is replayed through `ReviewPacketComposer` before being
/// returned, proving its mandatory context remains within the 32,000-token cap.
///
/// # Errors
///
/// Rejects stale snapshot/plan bindings, artifact or manifest mismatches,
/// incomplete anchors, ambiguous work-unit targets, invalid coverage state, or
/// mandatory packet context beyond the fixed request limit.
#[allow(
    clippy::too_many_lines,
    reason = "artifact, anchor, coverage, and packet bindings remain visible in one linear gate"
)]
pub fn prepare_review_group_packet(
    group_input: &TrustedReviewGroupInput,
    artifacts: &DiffArtifactStore,
    anchor_table: AnchorTable,
    bindings: &ReviewGroupPacketBindings,
    effort: ReviewEffort,
) -> Result<PreparedReviewGroupPacket, ReviewGroupPacketError> {
    validate_bindings(group_input, &anchor_table, bindings)?;
    let indexed_files = validate_group_files(group_input, artifacts)?;
    let assigned_paths = assigned_paths(group_input)?;
    let assigned_file_paths = assigned_file_paths(group_input)?;
    let work_unit_ids_by_path = work_unit_bindings(group_input)?;
    let issued_anchors = validate_anchors(group_input, &anchor_table, &work_unit_ids_by_path)?;
    let metrics = worker_metrics(group_input)?;
    let worker_plan = ReviewWorkerPlan::build(&group_input.group, effort, &metrics)
        .map_err(|_| ReviewGroupPacketError::WorkerPlan)?;
    let coverage = artifacts
        .coverage_for_group(&group_input.group)
        .map_err(map_artifact_error)?;
    let metadata_only_renames = group_input
        .files
        .iter()
        .filter(|file| {
            file.manifest.metadata_only
                && file.manifest.status == revoot_core::FileChangeKind::Renamed
        })
        .map(|file| file.manifest.path.clone())
        .collect();
    let coverage_gate = CoverageCompletionGate::new(coverage, &metadata_only_renames)
        .map_err(|_| ReviewGroupPacketError::Coverage)?;
    let initial_packet = build_initial_packet(group_input, artifacts, bindings, &indexed_files)?;
    let mut composer = ReviewPacketComposer::new(
        group_input.group.id.as_str().to_owned(),
        group_input.group_plan_sha256.clone(),
    );
    match composer
        .compose(initial_packet.clone())
        .map_err(|_| ReviewGroupPacketError::Packet)?
    {
        ReviewPacketComposition::Ready(packet)
            if packet.estimated_input_tokens <= MAX_REQUEST_INPUT_TOKENS => {}
        ReviewPacketComposition::Ready(_) | ReviewPacketComposition::Partial(_) => {
            return Err(ReviewGroupPacketError::ContextCapacity);
        }
    }
    Ok(PreparedReviewGroupPacket {
        worker_plan,
        initial_packet,
        anchor_table,
        coverage_gate,
        assigned_paths,
        assigned_file_paths,
        issued_anchors,
        work_unit_ids_by_path,
    })
}

fn validate_bindings(
    input: &TrustedReviewGroupInput,
    anchors: &AnchorTable,
    bindings: &ReviewGroupPacketBindings,
) -> Result<(), ReviewGroupPacketError> {
    if input.partition_sha256 != bindings.partition_sha256
        || input.group_plan_sha256 != bindings.group_plan_sha256
        || input.selected_input_sha256 != bindings.selected_input_sha256
        || bindings.max_inline_diff_bytes == 0
        || bindings.max_inline_diff_bytes > MAX_INLINE_GROUP_DIFF_BYTES
    {
        return Err(ReviewGroupPacketError::Binding);
    }
    if anchors.identity() != &bindings.snapshot {
        return Err(ReviewGroupPacketError::SnapshotBinding);
    }
    let snapshot_bytes = serde_json::to_vec(&bindings.snapshot)
        .map_err(|_| ReviewGroupPacketError::Serialization)?;
    if Sha256Digest::of_bytes(&snapshot_bytes) != bindings.snapshot_sha256 {
        return Err(ReviewGroupPacketError::SnapshotBinding);
    }
    Ok(())
}

fn validate_group_files(
    input: &TrustedReviewGroupInput,
    artifacts: &DiffArtifactStore,
) -> Result<BTreeMap<RepositoryPath, DiffFileManifest>, ReviewGroupPacketError> {
    if input.group.files.is_empty()
        || usize::try_from(input.file_count).ok() != Some(input.group.files.len())
        || input.files.len() != input.group.files.len()
    {
        return Err(ReviewGroupPacketError::CountBinding);
    }
    let mut group_files = BTreeMap::new();
    for file in &input.group.files {
        if group_files
            .insert(file.path.new_path.clone(), file)
            .is_some()
        {
            return Err(ReviewGroupPacketError::PathBinding);
        }
    }
    let paths = group_files
        .keys()
        .map(|path| {
            RepositoryRelativePath::try_from(path.as_str().to_owned())
                .map_err(|_| ReviewGroupPacketError::PathBinding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifests = artifacts.manifest(&paths).map_err(map_artifact_error)?;
    let indexed_artifacts = manifests
        .into_iter()
        .map(|manifest| {
            let path = RepositoryPath::try_from(manifest.path.as_str().to_owned())
                .map_err(|_| ReviewGroupPacketError::PathBinding)?;
            Ok((path, manifest))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if indexed_artifacts.len() != group_files.len() {
        return Err(ReviewGroupPacketError::PathBinding);
    }
    let mut exact_diff_bytes = 0_u64;
    let mut changed_line_count = 0_u32;
    let mut hunk_count = 0_u32;
    let mut input_paths = BTreeSet::new();
    for file in &input.files {
        let path = &file.manifest.path;
        if !input_paths.insert(path.clone()) {
            return Err(ReviewGroupPacketError::PathBinding);
        }
        let group_file = group_files
            .get(path)
            .ok_or(ReviewGroupPacketError::PathBinding)?;
        if file.manifest.status != group_file.path.kind
            || file.work_unit_id != group_file.work_unit_id
        {
            return Err(ReviewGroupPacketError::WorkUnitBinding);
        }
        validate_file_manifest(
            file,
            indexed_artifacts
                .get(path)
                .ok_or(ReviewGroupPacketError::PathBinding)?,
        )?;
        exact_diff_bytes = exact_diff_bytes
            .checked_add(file.manifest.exact_diff_bytes)
            .ok_or(ReviewGroupPacketError::CountBinding)?;
        changed_line_count = file
            .manifest
            .hunks
            .iter()
            .try_fold(changed_line_count, |total, hunk| {
                total.checked_add(hunk.changed_lines)
            })
            .ok_or(ReviewGroupPacketError::CountBinding)?;
        hunk_count = hunk_count
            .checked_add(
                u32::try_from(file.manifest.hunks.len())
                    .map_err(|_| ReviewGroupPacketError::CountBinding)?,
            )
            .ok_or(ReviewGroupPacketError::CountBinding)?;
    }
    if input_paths != group_files.keys().cloned().collect()
        || input.exact_diff_bytes != exact_diff_bytes
        || input.changed_line_count != changed_line_count
        || input.hunk_count != hunk_count
    {
        return Err(ReviewGroupPacketError::CountBinding);
    }
    Ok(indexed_artifacts)
}

fn validate_file_manifest(
    file: &TrustedGroupFileInput,
    artifact: &DiffFileManifest,
) -> Result<(), ReviewGroupPacketError> {
    if file.artifact_sha256 != artifact.sha256 {
        return Err(ReviewGroupPacketError::DigestBinding);
    }
    if file.manifest.exact_diff_bytes != artifact.size_bytes
        || file.manifest.metadata_only != artifact.hunks.is_empty()
        || file.manifest.hunks.len() != artifact.hunks.len()
    {
        return Err(ReviewGroupPacketError::CountBinding);
    }
    if file.rule_ids.is_empty() || !file.rule_ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ReviewGroupPacketError::RuleBinding);
    }
    for (expected, actual) in file.manifest.hunks.iter().zip(&artifact.hunks) {
        if expected.hunk_id != actual.hunk_id
            || expected.changed_lines != actual.changed_lines
            || expected.pages != actual.pages
        {
            return Err(ReviewGroupPacketError::HunkBinding);
        }
    }
    Ok(())
}

fn assigned_paths(
    input: &TrustedReviewGroupInput,
) -> Result<BTreeSet<RepositoryRelativePath>, ReviewGroupPacketError> {
    input
        .group
        .files
        .iter()
        .map(|file| {
            RepositoryRelativePath::try_from(file.path.new_path.as_str().to_owned())
                .map_err(|_| ReviewGroupPacketError::PathBinding)
        })
        .collect()
}

fn assigned_file_paths(
    input: &TrustedReviewGroupInput,
) -> Result<BTreeSet<ChangedPath>, ReviewGroupPacketError> {
    let paths = input
        .group
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    if paths.len() != input.group.files.len()
        || paths.iter().any(|path| path.semantic_issue().is_some())
    {
        return Err(ReviewGroupPacketError::PathBinding);
    }
    Ok(paths)
}

fn work_unit_bindings(
    input: &TrustedReviewGroupInput,
) -> Result<BTreeMap<RepositoryPath, WorkUnitId>, ReviewGroupPacketError> {
    let files = input
        .files
        .iter()
        .map(|file| (file.manifest.path.clone(), &file.work_unit_id))
        .collect::<BTreeMap<_, _>>();
    if files.len() != input.files.len() {
        return Err(ReviewGroupPacketError::WorkUnitBinding);
    }
    let mut bindings = BTreeMap::new();
    for group_file in &input.group.files {
        let work_unit_id = files
            .get(&group_file.path.new_path)
            .ok_or(ReviewGroupPacketError::WorkUnitBinding)?;
        insert_unique_binding(
            &mut bindings,
            group_file.path.new_path.clone(),
            (*work_unit_id).clone(),
        )?;
        if group_file.path.old_path != group_file.path.new_path {
            insert_unique_binding(
                &mut bindings,
                group_file.path.old_path.clone(),
                (*work_unit_id).clone(),
            )?;
        }
    }
    Ok(bindings)
}

fn insert_unique_binding(
    bindings: &mut BTreeMap<RepositoryPath, WorkUnitId>,
    path: RepositoryPath,
    work_unit_id: WorkUnitId,
) -> Result<(), ReviewGroupPacketError> {
    if bindings.insert(path, work_unit_id).is_some() {
        return Err(ReviewGroupPacketError::WorkUnitBinding);
    }
    Ok(())
}

fn validate_anchors(
    input: &TrustedReviewGroupInput,
    table: &AnchorTable,
    work_units: &BTreeMap<RepositoryPath, WorkUnitId>,
) -> Result<BTreeSet<AnchorId>, ReviewGroupPacketError> {
    let group_files = input
        .group
        .files
        .iter()
        .map(|file| (file.path.new_path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    let mut issued = BTreeSet::new();
    for group_file in &input.group.files {
        for anchor_id in &group_file.anchor_ids {
            if !issued.insert(anchor_id.clone()) {
                return Err(ReviewGroupPacketError::AnchorBinding);
            }
            let anchor = table
                .resolve(anchor_id.as_str())
                .ok_or(ReviewGroupPacketError::AnchorBinding)?;
            if anchor.path != group_file.path {
                return Err(ReviewGroupPacketError::AnchorBinding);
            }
            let target = match anchor.position {
                AnchorPosition::Deletion { .. } => &anchor.path.old_path,
                AnchorPosition::Addition { .. } | AnchorPosition::Context { .. } => {
                    &anchor.path.new_path
                }
            };
            if work_units.get(target) != Some(&group_file.work_unit_id) {
                return Err(ReviewGroupPacketError::WorkUnitBinding);
            }
        }
    }
    if u32::try_from(issued.len()).ok() != Some(input.group.anchor_count)
        || group_files.len() != input.group.files.len()
    {
        return Err(ReviewGroupPacketError::AnchorBinding);
    }
    Ok(issued)
}

fn worker_metrics(
    input: &TrustedReviewGroupInput,
) -> Result<ReviewGroupMetrics, ReviewGroupPacketError> {
    let changed_lines_by_path = input
        .files
        .iter()
        .map(|file| {
            let changed = file
                .manifest
                .hunks
                .iter()
                .try_fold(0_u32, |total, hunk| total.checked_add(hunk.changed_lines))
                .ok_or(ReviewGroupPacketError::CountBinding)?;
            // The lifecycle contract requires a positive planning metric. A
            // metadata-only rename uses one solely to represent its presence;
            // the packet brief retains its exact changed-line count of zero.
            Ok((file.manifest.path.clone(), changed.max(1)))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(ReviewGroupMetrics {
        changed_lines_by_path,
    })
}

fn build_initial_packet(
    input: &TrustedReviewGroupInput,
    artifacts: &DiffArtifactStore,
    bindings: &ReviewGroupPacketBindings,
    indexed_artifacts: &BTreeMap<RepositoryPath, DiffFileManifest>,
) -> Result<ReviewPacketInput, ReviewGroupPacketError> {
    let files = packet_file_briefs(input)?;
    let mut rule_ids = input
        .files
        .iter()
        .flat_map(|file| file.rule_ids.iter().cloned())
        .collect::<Vec<_>>();
    rule_ids.sort();
    rule_ids.dedup();
    let mut unresolved_coverage_ids = files
        .iter()
        .flat_map(|file| file.hunk_ids.iter().cloned())
        .collect::<Vec<_>>();
    unresolved_coverage_ids.sort();
    if unresolved_coverage_ids
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ReviewGroupPacketError::HunkBinding);
    }
    let complete = complete_group_diff(
        input,
        artifacts,
        indexed_artifacts,
        bindings.max_inline_diff_bytes,
    )?;
    let manifest_tokens = estimate_manifest_tokens(input, bindings)?;
    if manifest_tokens == 0 || manifest_tokens > MAX_REQUEST_INPUT_TOKENS {
        return Err(ReviewGroupPacketError::ContextCapacity);
    }
    let inline_request_tokens = complete
        .inline_bytes
        .map(|bytes| {
            manifest_tokens
                .checked_add(bytes)
                .ok_or(ReviewGroupPacketError::ContextCapacity)
        })
        .transpose()?;
    Ok(ReviewPacketInput {
        purpose: ReviewPacketPurpose::GroupInitial,
        group_brief: ReviewPacketGroupBrief {
            group_id: input.group.id.as_str().to_owned(),
            snapshot_sha256: bindings.snapshot_sha256.clone(),
            partition_sha256: input.partition_sha256.clone(),
            group_plan_sha256: input.group_plan_sha256.clone(),
            files,
        },
        policy: ReviewPacketPolicy {
            system_policy_id: bindings.system_policy_id.clone(),
            system_policy_sha256: bindings.system_policy_sha256.clone(),
            rule_ids,
        },
        checkpoint: ReviewWorkerCheckpoint::default(),
        plan_summary: None,
        accepted_findings: Vec::new(),
        unresolved_coverage_ids,
        recent_exchange: None,
        diff_manifest: ReviewPacketDiffManifest {
            complete_diff_sha256: complete.sha256,
            complete_diff_bytes: complete.bytes,
            file_count: input.file_count,
            hunk_count: input.hunk_count,
        },
        complete_diff: Some(complete.value),
        token_estimates: ReviewPacketTokenEstimates {
            manifest_request_tokens: manifest_tokens,
            inline_request_tokens,
        },
    })
}

fn packet_file_briefs(
    input: &TrustedReviewGroupInput,
) -> Result<Vec<ReviewPacketFileBrief>, ReviewGroupPacketError> {
    let mut files = input
        .files
        .iter()
        .map(|file| {
            let mut hunk_ids = file
                .manifest
                .hunks
                .iter()
                .map(|hunk| hunk.hunk_id.clone())
                .collect::<Vec<_>>();
            hunk_ids.sort();
            let changed_lines = file
                .manifest
                .hunks
                .iter()
                .try_fold(0_u32, |total, hunk| total.checked_add(hunk.changed_lines))
                .ok_or(ReviewGroupPacketError::CountBinding)?;
            let tier = input
                .group
                .files
                .iter()
                .find(|group_file| group_file.path.new_path == file.manifest.path)
                .ok_or(ReviewGroupPacketError::PathBinding)?
                .tier;
            Ok(ReviewPacketFileBrief {
                path: file.manifest.path.clone(),
                tier,
                changed_lines,
                hunk_ids,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

struct CompleteGroupDiff {
    value: ReviewPacketCompleteDiff,
    sha256: Sha256Digest,
    bytes: u64,
    inline_bytes: Option<u64>,
}

fn complete_group_diff(
    input: &TrustedReviewGroupInput,
    artifacts: &DiffArtifactStore,
    indexed_artifacts: &BTreeMap<RepositoryPath, DiffFileManifest>,
    max_inline_diff_bytes: u64,
) -> Result<CompleteGroupDiff, ReviewGroupPacketError> {
    let relative_paths = indexed_artifacts
        .keys()
        .map(|path| {
            RepositoryRelativePath::try_from(path.as_str().to_owned())
                .map_err(|_| ReviewGroupPacketError::PathBinding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let complete_body = artifacts
        .inline_group_diff(&relative_paths, u64::MAX)
        .map_err(map_artifact_error)?
        .ok_or(ReviewGroupPacketError::Artifact)?;
    let complete_bytes =
        u64::try_from(complete_body.len()).map_err(|_| ReviewGroupPacketError::CountBinding)?;
    if complete_bytes != input.exact_diff_bytes {
        return Err(ReviewGroupPacketError::CountBinding);
    }
    let complete_sha256 = Sha256Digest::of_bytes(complete_body.as_bytes());
    let (value, inline_bytes) = if complete_bytes <= max_inline_diff_bytes {
        (
            ReviewPacketCompleteDiff::SmallComplete {
                body: complete_body,
                sha256: complete_sha256.clone(),
            },
            Some(complete_bytes),
        )
    } else {
        (
            ReviewPacketCompleteDiff::LargeManifestOnly {
                sha256: complete_sha256.clone(),
                bytes: complete_bytes,
            },
            None,
        )
    };
    Ok(CompleteGroupDiff {
        value,
        sha256: complete_sha256,
        bytes: complete_bytes,
        inline_bytes,
    })
}

fn estimate_manifest_tokens(
    input: &TrustedReviewGroupInput,
    bindings: &ReviewGroupPacketBindings,
) -> Result<u64, ReviewGroupPacketError> {
    #[derive(Serialize)]
    struct EstimateBasis<'a> {
        input: &'a TrustedReviewGroupInput,
        snapshot_sha256: &'a Sha256Digest,
        system_policy_id: &'a str,
        system_policy_sha256: &'a Sha256Digest,
    }
    let bytes = serde_json::to_vec(&EstimateBasis {
        input,
        snapshot_sha256: &bindings.snapshot_sha256,
        system_policy_id: &bindings.system_policy_id,
        system_policy_sha256: &bindings.system_policy_sha256,
    })
    .map_err(|_| ReviewGroupPacketError::Serialization)?;
    u64::try_from(bytes.len())
        .ok()
        .and_then(|bytes| bytes.checked_add(CONSERVATIVE_PACKET_OVERHEAD_TOKENS))
        .ok_or(ReviewGroupPacketError::ContextCapacity)
}

const fn map_artifact_error(_: DiffArtifactError) -> ReviewGroupPacketError {
    ReviewGroupPacketError::Artifact
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use revoot_core::review_packet::{ReviewPacketCompleteDiff, ReviewPacketDiffContext};
    use revoot_core::{
        AnchorPosition, ChangedPath, CommentableLine, FileChangeKind, LocalSnapshotIdentity,
        PartitionLimits, ReviewFileClass, ReviewFileInput, ReviewGroupingSource, ReviewObject,
        ReviewObjectRole, ReviewPartitionPlan, ReviewSelectionPolicy, ReviewValue,
        ReviewValueReason, ReviewValueTier, build_partition_plan, build_review_group_plan,
    };

    use crate::review_group_inputs::{derive_review_group_inputs, derive_selected_review_inputs};
    use crate::rule_diagnostics::RuleDiagnosticPolicy;

    use super::*;

    #[test]
    fn builds_small_inline_packet_with_exact_authority() {
        let setup = setup(&[small_fixture("src/a.rs"), small_fixture("src/b.rs")], 1);
        let expected_body = setup
            .fixtures
            .iter()
            .map(|fixture| fixture.diff.as_str())
            .collect::<String>();
        let prepared = prepare_review_group_packet(
            &setup.group_input,
            &setup.store,
            setup.anchor_table,
            &setup.bindings,
            ReviewEffort::Medium,
        )
        .expect("prepared packet");
        assert_eq!(prepared.assigned_paths.len(), 2);
        assert_eq!(prepared.assigned_file_paths.len(), 2);
        assert_eq!(prepared.issued_anchors.len(), 2);
        assert_eq!(prepared.work_unit_ids_by_path.len(), 2);
        assert_eq!(
            prepared
                .work_unit_ids_by_path
                .values()
                .map(WorkUnitId::as_str)
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
        assert_eq!(prepared.coverage_gate.ledger().files.len(), 2);
        assert_eq!(prepared.worker_plan.effort, ReviewEffort::Medium);
        assert_eq!(prepared.worker_plan.rounds.len(), 2);
        let Some(ReviewPacketCompleteDiff::SmallComplete { body, sha256 }) =
            &prepared.initial_packet.complete_diff
        else {
            panic!("small group must carry the complete diff")
        };
        assert_eq!(body, &expected_body);
        assert_eq!(*sha256, Sha256Digest::of_bytes(expected_body.as_bytes()));
        assert_eq!(
            prepared.initial_packet.diff_manifest.complete_diff_sha256,
            *sha256
        );
        assert!(
            prepared
                .initial_packet
                .token_estimates
                .manifest_request_tokens
                <= MAX_REQUEST_INPUT_TOKENS
        );
        let mut composer = ReviewPacketComposer::new(
            prepared.worker_plan.group_id.clone(),
            prepared
                .initial_packet
                .group_brief
                .group_plan_sha256
                .clone(),
        );
        let ReviewPacketComposition::Ready(packet) = composer
            .compose(prepared.initial_packet.clone())
            .expect("valid initial packet")
        else {
            panic!("expected ready packet")
        };
        assert!(matches!(
            packet.diff_context,
            ReviewPacketDiffContext::InlineComplete { .. }
        ));
        assert_eq!(prepared.initial_packet.group_brief.files.len(), 2);
        assert_eq!(prepared.initial_packet.unresolved_coverage_ids.len(), 2);
        assert!(
            prepared
                .initial_packet
                .policy
                .rule_ids
                .contains(&"rust.md".to_owned())
        );
    }

    #[test]
    fn metadata_only_rename_preserves_exact_old_and_new_authority() {
        let fixture = metadata_only_rename_fixture("src/legacy.rs", "src/current.rs");
        let expected_path = fixture.path.clone();
        let setup = setup(&[fixture], 1);
        assert_eq!(setup.group_input.group.anchor_count, 0);
        assert!(setup.group_input.files[0].manifest.metadata_only);
        let prepared = prepare_review_group_packet(
            &setup.group_input,
            &setup.store,
            setup.anchor_table,
            &setup.bindings,
            ReviewEffort::Low,
        )
        .expect("metadata-only rename packet");
        assert!(prepared.issued_anchors.is_empty());
        assert_eq!(
            prepared.assigned_file_paths,
            BTreeSet::from([expected_path.clone()])
        );
        let old_binding = prepared
            .work_unit_ids_by_path
            .get(&expected_path.old_path)
            .expect("old-path binding");
        let new_binding = prepared
            .work_unit_ids_by_path
            .get(&expected_path.new_path)
            .expect("new-path binding");
        assert_eq!(old_binding, new_binding);
        assert_eq!(prepared.work_unit_ids_by_path.len(), 2);
    }

    #[test]
    fn trusted_narrower_inline_limit_keeps_complete_diff_manifest_only() {
        let mut setup = setup(&[small_fixture("src/a.rs")], 1);
        setup.bindings.max_inline_diff_bytes = 1;
        let expected_bytes = setup.group_input.exact_diff_bytes;
        let prepared = prepare_review_group_packet(
            &setup.group_input,
            &setup.store,
            setup.anchor_table,
            &setup.bindings,
            ReviewEffort::Low,
        )
        .expect("manifest-only packet");
        assert!(matches!(
            prepared.initial_packet.complete_diff,
            Some(ReviewPacketCompleteDiff::LargeManifestOnly { bytes, .. }) if bytes == expected_bytes
        ));
        assert_eq!(
            prepared
                .initial_packet
                .token_estimates
                .inline_request_tokens,
            None
        );
    }

    #[test]
    fn large_group_is_manifest_only_with_complete_digest() {
        let fixture = large_fixture("src/large.rs");
        let expected_sha = Sha256Digest::of_bytes(fixture.diff.as_bytes());
        let expected_bytes = u64::try_from(fixture.diff.len()).expect("bytes");
        let setup = setup(&[fixture], 1);
        let prepared = prepare_review_group_packet(
            &setup.group_input,
            &setup.store,
            setup.anchor_table,
            &setup.bindings,
            ReviewEffort::Low,
        )
        .expect("large packet");
        assert!(expected_bytes > MAX_INLINE_GROUP_DIFF_BYTES);
        assert_eq!(
            prepared.initial_packet.complete_diff,
            Some(ReviewPacketCompleteDiff::LargeManifestOnly {
                sha256: expected_sha.clone(),
                bytes: expected_bytes,
            })
        );
        assert_eq!(
            prepared.initial_packet.diff_manifest.complete_diff_sha256,
            expected_sha
        );
        assert_eq!(
            prepared.initial_packet.diff_manifest.complete_diff_bytes,
            expected_bytes
        );
        assert_eq!(
            prepared
                .initial_packet
                .token_estimates
                .inline_request_tokens,
            None
        );
        assert!(
            prepared
                .initial_packet
                .token_estimates
                .manifest_request_tokens
                <= MAX_REQUEST_INPUT_TOKENS
        );
        assert_eq!(
            prepared.initial_packet.group_brief.files[0].hunk_ids.len(),
            1
        );
    }

    #[test]
    fn rejects_snapshot_anchor_path_and_digest_mismatches() {
        let mut binding_setup = setup(&[small_fixture("src/a.rs")], 1);
        binding_setup.bindings.group_plan_sha256 = Sha256Digest::of_bytes(b"wrong plan");
        assert_eq!(
            prepare_review_group_packet(
                &binding_setup.group_input,
                &binding_setup.store,
                binding_setup.anchor_table,
                &binding_setup.bindings,
                ReviewEffort::Low,
            )
            .err(),
            Some(ReviewGroupPacketError::Binding)
        );

        let mut digest_setup = setup(&[small_fixture("src/a.rs")], 1);
        digest_setup.group_input.files[0].artifact_sha256 =
            Sha256Digest::of_bytes(b"wrong artifact");
        assert_eq!(
            prepare_review_group_packet(
                &digest_setup.group_input,
                &digest_setup.store,
                digest_setup.anchor_table,
                &digest_setup.bindings,
                ReviewEffort::Low,
            )
            .err(),
            Some(ReviewGroupPacketError::DigestBinding)
        );

        let mut path_setup = setup(&[small_fixture("src/a.rs")], 1);
        path_setup.group_input.files[0].manifest.path =
            RepositoryPath::try_from("outside.rs".to_owned()).expect("path");
        assert_eq!(
            prepare_review_group_packet(
                &path_setup.group_input,
                &path_setup.store,
                path_setup.anchor_table,
                &path_setup.bindings,
                ReviewEffort::Low,
            )
            .err(),
            Some(ReviewGroupPacketError::PathBinding)
        );

        let mut snapshot_digest_setup = setup(&[small_fixture("src/a.rs")], 1);
        snapshot_digest_setup.bindings.snapshot_sha256 = Sha256Digest::of_bytes(b"forged snapshot");
        assert_eq!(
            prepare_review_group_packet(
                &snapshot_digest_setup.group_input,
                &snapshot_digest_setup.store,
                snapshot_digest_setup.anchor_table,
                &snapshot_digest_setup.bindings,
                ReviewEffort::Low,
            )
            .err(),
            Some(ReviewGroupPacketError::SnapshotBinding)
        );

        let snapshot_setup = setup(&[small_fixture("src/a.rs")], 1);
        let other_snapshot = snapshot(b'x');
        let empty_table = AnchorTable::build(other_snapshot, Vec::<CommentableLine>::new())
            .expect("other anchors");
        assert_eq!(
            prepare_review_group_packet(
                &snapshot_setup.group_input,
                &snapshot_setup.store,
                empty_table,
                &snapshot_setup.bindings,
                ReviewEffort::Low,
            )
            .err(),
            Some(ReviewGroupPacketError::SnapshotBinding)
        );

        let anchor_setup = setup(&[small_fixture("src/a.rs")], 1);
        let empty_table = AnchorTable::build(
            anchor_setup.bindings.snapshot.clone(),
            Vec::<CommentableLine>::new(),
        )
        .expect("empty anchors");
        assert_eq!(
            prepare_review_group_packet(
                &anchor_setup.group_input,
                &anchor_setup.store,
                empty_table,
                &anchor_setup.bindings,
                ReviewEffort::Low,
            )
            .err(),
            Some(ReviewGroupPacketError::AnchorBinding)
        );
    }

    struct Setup {
        fixtures: Vec<Fixture>,
        store: DiffArtifactStore,
        group_input: TrustedReviewGroupInput,
        anchor_table: AnchorTable,
        bindings: ReviewGroupPacketBindings,
    }

    #[derive(Clone)]
    struct Fixture {
        path: ChangedPath,
        diff: String,
    }

    fn small_fixture(path: &str) -> Fixture {
        fixture(path, "+new\n")
    }

    fn large_fixture(path: &str) -> Fixture {
        fixture(path, &format!("+{}\n", "x".repeat(17_000)))
    }

    fn metadata_only_rename_fixture(old_path: &str, new_path: &str) -> Fixture {
        let old_path = RepositoryPath::try_from(old_path.to_owned()).expect("old path");
        let new_path = RepositoryPath::try_from(new_path.to_owned()).expect("new path");
        Fixture {
            diff: format!(
                "diff --git a/{old} b/{new}\nsimilarity index 100%\nrename from {old}\nrename to {new}\n",
                old = old_path.as_str(),
                new = new_path.as_str()
            ),
            path: ChangedPath {
                old_path,
                new_path,
                kind: FileChangeKind::Renamed,
            },
        }
    }

    fn fixture(path: &str, added: &str) -> Fixture {
        let repository_path = RepositoryPath::try_from(path.to_owned()).expect("path");
        let changed = ChangedPath {
            old_path: repository_path.clone(),
            new_path: repository_path,
            kind: FileChangeKind::Modified,
        };
        Fixture {
            diff: format!(
                "diff --git a/{0} b/{0}\n--- a/{0}\n+++ b/{0}\n@@ -1 +1 @@\n-old\n{added}",
                changed.new_path.as_str()
            ),
            path: changed,
        }
    }

    fn setup(fixtures: &[Fixture], max_files_per_work_unit: u32) -> Setup {
        let snapshot = snapshot(b's');
        let anchor_table = AnchorTable::build(
            snapshot.clone(),
            fixtures
                .iter()
                .filter(|fixture| fixture.diff.contains("@@"))
                .map(|fixture| CommentableLine {
                    path: fixture.path.clone(),
                    position: AnchorPosition::addition(1).expect("position"),
                    exact_line_digest: Sha256Digest::of_bytes(
                        fixture.path.new_path.as_str().as_bytes(),
                    ),
                    context_digest: Sha256Digest::of_bytes(fixture.diff.as_bytes()),
                }),
        )
        .expect("anchors");
        let partition = partition(
            fixtures,
            &anchor_table,
            snapshot.clone(),
            max_files_per_work_unit,
        );
        let paths = fixtures
            .iter()
            .map(|fixture| {
                RepositoryRelativePath::try_from(fixture.path.new_path.as_str().to_owned())
                    .expect("relative path")
            })
            .collect::<Vec<_>>();
        let store = DiffArtifactStore::create(
            paths
                .iter()
                .zip(fixtures)
                .map(|(path, fixture)| (path, fixture.diff.as_str())),
            8 * 1024,
        )
        .expect("store");
        let selected =
            derive_selected_review_inputs(&partition, &store, &RuleDiagnosticPolicy::default())
                .expect("selected inputs");
        let plan = build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic)
            .expect("group plan");
        let mut group_inputs =
            derive_review_group_inputs(&partition, &plan, &selected).expect("group inputs");
        assert_eq!(group_inputs.len(), 1);
        let group_input = group_inputs.remove(0);
        let bindings = ReviewGroupPacketBindings {
            snapshot: snapshot.clone(),
            snapshot_sha256: Sha256Digest::of_bytes(
                &serde_json::to_vec(&snapshot).expect("snapshot JSON"),
            ),
            partition_sha256: group_input.partition_sha256.clone(),
            group_plan_sha256: group_input.group_plan_sha256.clone(),
            selected_input_sha256: group_input.selected_input_sha256.clone(),
            system_policy_id: "review-policy-v1".to_owned(),
            system_policy_sha256: Sha256Digest::of_bytes(b"review policy"),
            max_inline_diff_bytes: MAX_INLINE_GROUP_DIFF_BYTES,
        };
        Setup {
            fixtures: fixtures.to_vec(),
            store,
            group_input,
            anchor_table,
            bindings,
        }
    }

    fn partition(
        fixtures: &[Fixture],
        anchors: &AnchorTable,
        snapshot: ReviewSnapshotIdentity,
        max_files_per_work_unit: u32,
    ) -> ReviewPartitionPlan {
        let inputs: Vec<ReviewFileInput> = fixtures
            .iter()
            .map(|fixture| ReviewFileInput {
                path: fixture.path.clone(),
                class: ReviewFileClass::Text,
                review_value: ReviewValue {
                    tier: ReviewValueTier::Standard,
                    score: 100,
                    reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                },
                objects: vec![ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: Sha256Digest::of_bytes(fixture.diff.as_bytes()),
                    size_bytes: u64::try_from(fixture.diff.len()).expect("diff bytes"),
                }],
                anchor_ids: anchors
                    .iter()
                    .filter(|anchor| anchor.path == fixture.path)
                    .map(|anchor| anchor.id.clone())
                    .collect(),
            })
            .collect();
        build_partition_plan(
            snapshot,
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
                max_file_bytes: 100_000,
            },
            PartitionLimits {
                max_files: 100,
                max_total_bytes: 1_000_000,
                max_work_units: 100,
                max_files_per_work_unit,
                max_bytes_per_work_unit: 100_000,
                max_anchors_per_work_unit: 100,
            },
            inputs,
        )
        .expect("partition")
    }

    fn snapshot(marker: u8) -> ReviewSnapshotIdentity {
        ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
            repository_identity_sha256: Sha256Digest::of_bytes(&[marker, b'r']),
            base_sha: "a".repeat(40).try_into().expect("base"),
            head_sha: "b".repeat(40).try_into().expect("head"),
            working_tree_sha256: Sha256Digest::of_bytes(&[marker, b'w']),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(&[marker, b'm']),
        })
    }
}
