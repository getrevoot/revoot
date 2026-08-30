//! Composition bridge from an authoritative GitLab snapshot to review-engine inputs.
//!
//! GitLab remains authoritative for changed paths, exact diff bytes, commentable
//! lines, and snapshot identity. The bound checkout contributes only the repository
//! root and exact reviewed HEAD used by the read-only repository tools.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::str;

use revoot_core::{
    AgentBudgetLimits, AgentTool, AnchorId, AnchorTable, AnchorTableError, DiffAvailability,
    GitLabSnapshotIdentity, IssuedWorkUnitAnchors, PartitionBuildError, PartitionLimits,
    RepositoryDiff, RepositoryPathError, RepositoryRelativePath, ReviewFileClass, ReviewFileInput,
    ReviewInvocation, ReviewInvocationError, ReviewObject, ReviewObjectRole, ReviewPartitionPlan,
    ReviewSelectionPolicy, Sha256Digest, SnapshotReadiness, UnifiedDiffError, UnifiedDiffLimits,
    ValidatedChangedFile, build_partition_plan, classify_review_value, parse_gitlab_file_diff,
};

use crate::gitlab_checkout::{BoundGitLabCheckout, GitLabCheckoutError, bind_checkout_to_snapshot};
use crate::gitlab_snapshot::{AcquiredGitLabSnapshot, GitLabSnapshotReplayError};

/// Explicit bounded inputs that vary by provider or repository policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabReviewContextOptions {
    pub provider_adapter: String,
    pub model_id: String,
    pub agent_limits: AgentBudgetLimits,
    pub diff_limits: UnifiedDiffLimits,
    pub selection_policy: ReviewSelectionPolicy,
    pub partition_limits: PartitionLimits,
}

/// Complete immutable inputs for the automatic review controller.
#[derive(Clone, Eq, PartialEq)]
pub struct GitLabReviewContext {
    /// Full verified checkout root used for broad unchanged-file and dependency exploration.
    /// It never expands or changes the API-authoritative review scope.
    pub checkout: BoundGitLabCheckout,
    pub snapshot_readiness: SnapshotReadiness,
    /// Exact per-file diff text supplied by the bound GitLab diff-version API.
    pub repository_diffs: Vec<RepositoryDiff>,
    /// Commentable positions derived only from strict parsing of those exact API diffs.
    pub anchors: AnchorTable,
    pub partition: ReviewPartitionPlan,
    pub issued_anchors: IssuedWorkUnitAnchors,
    pub invocation: Option<ReviewInvocation>,
}

impl fmt::Debug for GitLabReviewContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let readiness = match &self.snapshot_readiness {
            SnapshotReadiness::Complete => "complete",
            SnapshotReadiness::Partial { .. } => "partial",
            SnapshotReadiness::Blocked { .. } => "blocked",
        };
        formatter
            .debug_struct("GitLabReviewContext")
            .field("snapshot_readiness", &readiness)
            .field("repository_diff_count", &self.repository_diffs.len())
            .field("anchor_count", &self.anchors.len())
            .field("work_unit_count", &self.partition.work_units.len())
            .finish_non_exhaustive()
    }
}

/// A redaction-safe bridge failure. No diff, blob, path, or checkout content is retained.
#[derive(Clone, Eq, PartialEq)]
pub enum GitLabReviewContextError {
    SnapshotReplay(GitLabSnapshotReplayError),
    SnapshotBlocked,
    Checkout(GitLabCheckoutError),
    RepositoryPath(RepositoryPathError),
    Diff(UnifiedDiffError),
    DiffIdentityMismatch,
    DiffEncoding,
    ObjectSize,
    Anchor(AnchorTableError),
    Partition(PartitionBuildError),
    Invocation(ReviewInvocationError),
}

impl fmt::Debug for GitLabReviewContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SnapshotReplay(_) => "SnapshotReplay",
            Self::SnapshotBlocked => "SnapshotBlocked",
            Self::Checkout(_) => "Checkout",
            Self::RepositoryPath(_) => "RepositoryPath",
            Self::Diff(_) => "Diff",
            Self::DiffIdentityMismatch => "DiffIdentityMismatch",
            Self::DiffEncoding => "DiffEncoding",
            Self::ObjectSize => "ObjectSize",
            Self::Anchor(_) => "Anchor",
            Self::Partition(_) => "Partition",
            Self::Invocation(_) => "Invocation",
        })
    }
}

impl fmt::Display for GitLabReviewContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SnapshotReplay(_) => "GitLab snapshot replay validation failed",
            Self::SnapshotBlocked => "GitLab snapshot is blocked and cannot be reviewed",
            Self::Checkout(_) => "checkout does not match the authoritative GitLab snapshot",
            Self::RepositoryPath(_) => "GitLab path cannot be represented by repository tools",
            Self::Diff(_) => "GitLab exact diff failed strict parsing",
            Self::DiffIdentityMismatch => "GitLab exact diff identity is contradictory",
            Self::DiffEncoding => "GitLab exact diff is not UTF-8",
            Self::ObjectSize => "GitLab review object size exceeds supported bounds",
            Self::Anchor(_) => "GitLab comment anchor construction failed",
            Self::Partition(_) => "GitLab review partition construction failed",
            Self::Invocation(_) => "GitLab review invocation validation failed",
        })
    }
}

impl Error for GitLabReviewContextError {}

/// Revalidate and compose one acquired snapshot and bound checkout for review.
///
/// Partial snapshots remain reviewable when at least one exact diff survives
/// policy and partition limits. Their original readiness evidence is preserved
/// in the returned context. Blocked or internally inconsistent snapshots fail.
///
/// # Errors
///
/// Returns a closed error for snapshot replay/binding failure, malformed exact
/// diffs, invalid paths or anchors, partition failure, an empty plan, or an
/// invalid invocation skeleton.
pub fn build_gitlab_review_context(
    snapshot: &AcquiredGitLabSnapshot,
    checkout: BoundGitLabCheckout,
    options: &GitLabReviewContextOptions,
) -> Result<GitLabReviewContext, GitLabReviewContextError> {
    let readiness = snapshot
        .replay()
        .map_err(GitLabReviewContextError::SnapshotReplay)?
        .readiness;
    if matches!(readiness, SnapshotReadiness::Blocked { .. }) {
        return Err(GitLabReviewContextError::SnapshotBlocked);
    }
    let checkout = bind_checkout_to_snapshot(checkout.repository, snapshot)
        .map_err(GitLabReviewContextError::Checkout)?;
    let materials = build_review_materials(
        &snapshot.evidence().identity,
        snapshot.exact_files(),
        options,
    )?;
    Ok(GitLabReviewContext {
        checkout,
        snapshot_readiness: readiness,
        repository_diffs: materials.repository_diffs,
        anchors: materials.anchors,
        partition: materials.partition,
        issued_anchors: materials.issued_anchors,
        invocation: materials.invocation,
    })
}

struct ReviewMaterials {
    repository_diffs: Vec<RepositoryDiff>,
    anchors: AnchorTable,
    partition: ReviewPartitionPlan,
    issued_anchors: IssuedWorkUnitAnchors,
    invocation: Option<ReviewInvocation>,
}

fn build_review_materials(
    identity: &GitLabSnapshotIdentity,
    exact_files: &[ValidatedChangedFile],
    options: &GitLabReviewContextOptions,
) -> Result<ReviewMaterials, GitLabReviewContextError> {
    let mut repository_diffs = Vec::new();
    let mut review_files = Vec::with_capacity(exact_files.len());
    let mut commentable_lines = Vec::new();
    let mut file_line_counts = Vec::with_capacity(exact_files.len());
    for file in exact_files {
        let class = classify_file(file);
        let exact_diff = file
            .unified_diff
            .as_deref()
            .and_then(|bytes| str::from_utf8(bytes).ok());
        let review_value = classify_review_value(&file.file.path, class, exact_diff);
        let repository_path =
            RepositoryRelativePath::try_from(file.file.path.new_path.as_str().to_owned())
                .map_err(GitLabReviewContextError::RepositoryPath)?;
        let (exact_object, line_count) = exact_diff_material(
            file,
            repository_path.clone(),
            options.diff_limits,
            &mut repository_diffs,
            &mut commentable_lines,
        )?;
        let mut objects = Vec::new();
        if let Some(object) = exact_object {
            objects.push(object);
        }
        review_files.push(ReviewFileInput {
            path: file.file.path.clone(),
            class,
            review_value,
            objects,
            anchor_ids: Vec::new(),
        });
        file_line_counts.push(line_count);
    }

    let anchors = AnchorTable::build(identity.clone(), commentable_lines)
        .map_err(GitLabReviewContextError::Anchor)?;
    issue_file_anchors(&anchors, &mut review_files, &file_line_counts)?;
    let partition = build_partition_plan(
        identity.clone(),
        &options.selection_policy,
        options.partition_limits,
        review_files,
    )
    .map_err(GitLabReviewContextError::Partition)?;
    let issued_anchors = issued_anchors(&partition);
    let invocation = if partition.work_units.is_empty() {
        None
    } else {
        let invocation = ReviewInvocation {
            review_id: review_id(identity),
            snapshot: identity.clone().into(),
            work_unit_ids: partition
                .work_units
                .iter()
                .map(|unit| unit.id.as_str().to_owned())
                .collect(),
            provider_adapter: options.provider_adapter.clone(),
            model_id: options.model_id.clone(),
            allowed_tools: automatic_review_tools(),
            limits: options.agent_limits,
        };
        invocation
            .validate()
            .map_err(GitLabReviewContextError::Invocation)?;
        Some(invocation)
    };
    Ok(ReviewMaterials {
        repository_diffs,
        anchors,
        partition,
        issued_anchors,
        invocation,
    })
}

fn exact_diff_material(
    file: &ValidatedChangedFile,
    path: RepositoryRelativePath,
    limits: UnifiedDiffLimits,
    repository_diffs: &mut Vec<RepositoryDiff>,
    commentable_lines: &mut Vec<revoot_core::CommentableLine>,
) -> Result<(Option<ReviewObject>, usize), GitLabReviewContextError> {
    match (&file.file.diff, &file.unified_diff) {
        (DiffAvailability::Available(expected), Some(bytes)) => {
            let parsed = parse_gitlab_file_diff(&file.file.path, bytes, limits)
                .map_err(GitLabReviewContextError::Diff)?;
            if &parsed.input_sha256 != expected {
                return Err(GitLabReviewContextError::DiffIdentityMismatch);
            }
            let text = str::from_utf8(bytes)
                .map_err(|_| GitLabReviewContextError::DiffEncoding)?
                .to_owned();
            let size_bytes =
                u64::try_from(bytes.len()).map_err(|_| GitLabReviewContextError::ObjectSize)?;
            let line_count = parsed.commentable_lines.len();
            commentable_lines.extend(parsed.commentable_lines);
            repository_diffs.push(RepositoryDiff { path, text });
            Ok((
                Some(ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: parsed.input_sha256,
                    size_bytes,
                }),
                line_count,
            ))
        }
        (DiffAvailability::Available(_), None) | (_, Some(_)) => {
            Err(GitLabReviewContextError::DiffIdentityMismatch)
        }
        (
            DiffAvailability::Collapsed
            | DiffAvailability::TooLarge
            | DiffAvailability::Binary
            | DiffAvailability::Missing
            | DiffAvailability::Unknown,
            None,
        ) => Ok((None, 0)),
    }
}

fn classify_file(file: &ValidatedChangedFile) -> ReviewFileClass {
    if matches!(file.file.diff, DiffAvailability::Binary) {
        ReviewFileClass::Binary
    } else if file.generated == Some(true) {
        ReviewFileClass::Generated
    } else {
        ReviewFileClass::Text
    }
}

fn issue_file_anchors(
    anchors: &AnchorTable,
    files: &mut [ReviewFileInput],
    expected_line_counts: &[usize],
) -> Result<(), GitLabReviewContextError> {
    let mut indices = BTreeMap::new();
    for (index, file) in files.iter().enumerate() {
        if indices.insert(file.path.clone(), index).is_some() {
            return Err(GitLabReviewContextError::DiffIdentityMismatch);
        }
    }
    let mut observed = vec![0_usize; files.len()];
    for anchor in anchors.iter() {
        let Some(index) = indices.get(&anchor.path).copied() else {
            return Err(GitLabReviewContextError::DiffIdentityMismatch);
        };
        files[index].anchor_ids.push(anchor.id.clone());
        observed[index] = observed[index].saturating_add(1);
    }
    if observed != expected_line_counts {
        return Err(GitLabReviewContextError::DiffIdentityMismatch);
    }
    Ok(())
}

fn issued_anchors(partition: &ReviewPartitionPlan) -> IssuedWorkUnitAnchors {
    partition
        .work_units
        .iter()
        .map(|unit| {
            let anchors = unit
                .files
                .iter()
                .flat_map(|file| file.anchor_ids.iter().cloned())
                .collect::<BTreeSet<AnchorId>>();
            (unit.id.as_str().to_owned(), anchors)
        })
        .collect::<BTreeMap<_, _>>()
}

fn automatic_review_tools() -> BTreeSet<AgentTool> {
    BTreeSet::from([
        AgentTool::ReadFile,
        AgentTool::Search,
        AgentTool::ListFiles,
        AgentTool::InspectChangedFile,
        AgentTool::InspectTests,
        AgentTool::ShowDiff,
        AgentTool::GetMergeRequestMetadata,
        AgentTool::GetExistingRevootFindings,
        AgentTool::ListChangeCommits,
        AgentTool::ShowCommitContext,
        AgentTool::SubmitCandidateFinding,
        AgentTool::SubmitReviewSummary,
    ])
}

fn review_id(identity: &GitLabSnapshotIdentity) -> String {
    let scope = &identity.version.scope;
    let binding = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        scope.instance_origin_digest.as_str(),
        scope.project_id.get(),
        scope.merge_request_iid.get(),
        identity.version.diff_version.id.get(),
        identity.version.diff_version.refs.base_sha.as_str(),
        identity.version.diff_version.refs.start_sha.as_str(),
        identity.version.diff_version.refs.head_sha.as_str(),
        identity.exact_diff_manifest_sha256.as_str(),
    );
    format!(
        "gitlab:{}",
        Sha256Digest::of_bytes(binding.as_bytes()).as_str()
    )
}

#[cfg(test)]
mod tests {
    use revoot_core::{
        ChangedFile, ChangedPath, DiffRefs, DiffVersionId, DiffVersionRecord, FileChangeKind,
        GitLabDiffVersionIdentity, MergeRequestIid, ProjectId, RepositoryPath, SnapshotScope,
    };

    use super::*;

    fn identity() -> GitLabSnapshotIdentity {
        GitLabDiffVersionIdentity {
            scope: SnapshotScope {
                instance_origin_digest: revoot_core::Sha256Digest::of_bytes(b"origin"),
                project_id: ProjectId::try_from(42).unwrap(),
                merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
            },
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(9).unwrap(),
                refs: DiffRefs {
                    base_sha: revoot_core::GitSha::try_from("a".repeat(40)).unwrap(),
                    start_sha: revoot_core::GitSha::try_from("b".repeat(40)).unwrap(),
                    head_sha: revoot_core::GitSha::try_from("c".repeat(40)).unwrap(),
                },
            },
        }
        .freeze(revoot_core::Sha256Digest::of_bytes(b"manifest"))
    }

    fn changed_file(diff: Option<&[u8]>) -> ValidatedChangedFile {
        let path = RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap();
        ValidatedChangedFile {
            file: ChangedFile {
                path: ChangedPath {
                    old_path: path.clone(),
                    new_path: path,
                    kind: FileChangeKind::Modified,
                },
                diff: diff.map_or(DiffAvailability::Missing, |bytes| {
                    DiffAvailability::Available(revoot_core::Sha256Digest::of_bytes(bytes))
                }),
            },
            generated: Some(false),
            unified_diff: diff.map(<[u8]>::to_vec),
        }
    }

    fn options() -> GitLabReviewContextOptions {
        GitLabReviewContextOptions {
            provider_adapter: "anthropic".to_owned(),
            model_id: "claude-sonnet".to_owned(),
            agent_limits: AgentBudgetLimits::default(),
            diff_limits: UnifiedDiffLimits::default(),
            selection_policy: ReviewSelectionPolicy {
                version: "selection-v1".to_owned(),
                included_paths: BTreeSet::new(),
                included_prefixes: Vec::new(),
                included_suffixes: Vec::new(),
                excluded_paths: BTreeSet::new(),
                excluded_prefixes: Vec::new(),
                excluded_suffixes: Vec::new(),
                include_generated: false,
                max_file_bytes: 1024 * 1024,
            },
            partition_limits: PartitionLimits {
                max_files: 100,
                max_total_bytes: 2 * 1024 * 1024,
                max_work_units: 10,
                max_files_per_work_unit: 20,
                max_bytes_per_work_unit: 1024 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
        }
    }

    #[test]
    fn api_exact_diff_derives_repository_anchor_partition_and_invocation_identity() {
        let diff = b"@@ -1 +1 @@\n-old\n+new\n";
        let materials =
            build_review_materials(&identity(), &[changed_file(Some(diff))], &options()).unwrap();
        assert_eq!(materials.repository_diffs.len(), 1);
        assert_eq!(materials.repository_diffs[0].path.as_str(), "src/lib.rs");
        assert_eq!(materials.repository_diffs[0].text.as_bytes(), diff);
        assert_eq!(materials.anchors.len(), 2);
        assert_eq!(materials.partition.work_units.len(), 1);
        let unit = &materials.partition.work_units[0];
        assert_eq!(unit.anchor_count, 2);
        assert_eq!(
            materials.issued_anchors[unit.id.as_str()].len(),
            materials.anchors.len()
        );
        let invocation = materials
            .invocation
            .as_ref()
            .expect("reviewable invocation");
        assert_eq!(invocation.snapshot, identity());
        assert!(invocation.work_unit_ids.contains(unit.id.as_str()));
        assert!(invocation.allows(AgentTool::ShowDiff));
        assert!(invocation.allows(AgentTool::SubmitCandidateFinding));
        invocation.validate().unwrap();
    }

    #[test]
    fn automatic_tools_explore_full_checkout_without_expanding_gitlab_diff_scope() {
        let tools = automatic_review_tools();
        assert!(tools.contains(&AgentTool::ReadFile));
        assert!(tools.contains(&AgentTool::Search));
        assert!(tools.contains(&AgentTool::ListFiles));
        assert!(tools.contains(&AgentTool::ShowDiff));
        assert!(tools.contains(&AgentTool::GetExistingRevootFindings));
    }

    #[test]
    fn unavailable_diff_never_becomes_checkout_derived_review_input() {
        let materials = build_review_materials(&identity(), &[changed_file(None)], &options())
            .expect("empty authoritative scope");
        assert!(materials.repository_diffs.is_empty());
        assert!(materials.partition.work_units.is_empty());
        assert!(materials.invocation.is_none());
    }

    #[test]
    fn availability_digest_must_match_exact_bytes() {
        let diff = b"@@ -1 +1 @@\n-old\n+new\n";
        let mut file = changed_file(Some(diff));
        file.file.diff = DiffAvailability::Available(revoot_core::Sha256Digest::of_bytes(b"other"));
        assert_eq!(
            build_review_materials(&identity(), &[file], &options()).map(|_| ()),
            Err(GitLabReviewContextError::DiffIdentityMismatch)
        );
    }
}
