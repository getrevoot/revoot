//! Authoritative GitHub pull-request acquisition, review context, and publication.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use revoot_core::{
    AgentBudgetLimits, AgentTool, AnchorId, AnchorPosition, AnchorTable, ChangedPath,
    FileChangeKind, GitHubSnapshotIdentity, GitSha, IssuedWorkUnitAnchors, PartitionLimits,
    PriorReviewContext, PriorReviewSource, PriorReviewState, PublicationCandidate,
    PublicationMarker, PublicationTarget, RepositoryDiff, RepositoryPath, RepositoryRelativePath,
    ReviewFileClass, ReviewFileInput, ReviewInvocation, ReviewObject, ReviewObjectRole,
    ReviewPartitionPlan, ReviewSelectionPolicy, ReviewSnapshotIdentity, Sha256Digest,
    UnifiedDiffLimits, build_partition_plan, classify_review_value, finding_lineage_id,
    parse_gitlab_file_diff, prepare_review_publication, review_publication_scope_digest,
};
use serde::{Deserialize, Serialize};

use crate::github_checkout::{DiscoveredGitHubRepository, GitHubCiContext, GitHubRepositorySlug};
use crate::github_transport::{GitHubClient, GitHubTransportError};
use crate::prior_review::acquire_github_prior_review;
use crate::review_overview::{ReviewOverviewError, update_description};

const MAX_PAGES: u32 = 30;
const PER_PAGE: u32 = 100;
const MAX_COMMENTS: usize = 10_000;

#[derive(Clone, Debug)]
pub struct GitHubReviewContextOptions {
    pub provider_adapter: String,
    pub model_id: String,
    pub agent_limits: AgentBudgetLimits,
    pub diff_limits: UnifiedDiffLimits,
    pub selection_policy: ReviewSelectionPolicy,
    pub partition_limits: PartitionLimits,
}

pub struct GitHubReviewContext {
    pub repository: DiscoveredGitHubRepository,
    pub target_repository: GitHubRepositorySlug,
    pub identity: GitHubSnapshotIdentity,
    pub description: String,
    pub repository_diffs: Vec<RepositoryDiff>,
    pub anchors: AnchorTable,
    pub partition: ReviewPartitionPlan,
    pub issued_anchors: IssuedWorkUnitAnchors,
    pub invocation: Option<ReviewInvocation>,
    pub omitted_patch_count: u32,
}

impl fmt::Debug for GitHubReviewContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubReviewContext")
            .field("repository_diff_count", &self.repository_diffs.len())
            .field("anchor_count", &self.anchors.len())
            .field("work_unit_count", &self.partition.work_units.len())
            .field("omitted_patch_count", &self.omitted_patch_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubReviewError {
    Transport,
    InvalidPullRequest,
    PullRequestClosed,
    IdentityMismatch,
    CheckoutHeadMismatch,
    PaginationLimit,
    InvalidFile,
    DuplicateFile,
    Diff,
    Anchor,
    Partition,
    EmptyReview,
    Invocation,
    PublicationInventory,
    PublicationAmbiguous,
    PublicationStale,
    PublicationMutation,
    Overview,
}

impl fmt::Display for GitHubReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Transport => "GitHub REST operation failed",
            Self::InvalidPullRequest => "GitHub returned an invalid pull request",
            Self::PullRequestClosed => "the GitHub pull request is not open",
            Self::IdentityMismatch => "GitHub pull-request identity changed during acquisition",
            Self::CheckoutHeadMismatch => "checkout HEAD does not match GitHub pull-request HEAD",
            Self::PaginationLimit => "GitHub pull-request file pagination reached its hard limit",
            Self::InvalidFile => "GitHub returned an invalid changed file",
            Self::DuplicateFile => "GitHub returned duplicate changed paths",
            Self::Diff => "GitHub returned a malformed exact patch",
            Self::Anchor => "GitHub comment anchors could not be constructed",
            Self::Partition => "GitHub review partition construction failed",
            Self::EmptyReview => "GitHub pull request has no reviewable exact patches",
            Self::Invocation => "GitHub review invocation is invalid",
            Self::PublicationInventory => {
                "GitHub review-comment inventory is incomplete or invalid"
            }
            Self::PublicationAmbiguous => "GitHub contains ambiguous Revoot-owned comments",
            Self::PublicationStale => "GitHub pull-request HEAD changed before publication",
            Self::PublicationMutation => "GitHub review-comment publication failed",
            Self::Overview => "GitHub pull-request overview update failed",
        })
    }
}

/// Replace Revoot's owned overview block in the latest PR body.
///
/// Returns `true` when a mutation was required and `false` for an exact no-op.
///
/// # Errors
///
/// Rejects transport failures, stale pull-request identity, ambiguous ownership
/// markers, invalid descriptions, and unconfirmed mutations.
pub async fn update_github_overview(
    client: &GitHubClient,
    context: &GitHubReviewContext,
    overview_block: &str,
) -> Result<bool, GitHubReviewError> {
    let pull = get_pull(
        client,
        &context.target_repository,
        context.identity.pull_request_number,
    )
    .await?;
    if pull.state != "open"
        || pull.base.repo.id != context.identity.repository_id.get()
        || pull.base.sha != context.identity.base_sha.as_str()
        || pull.head.sha != context.identity.head_sha.as_str()
    {
        return Err(GitHubReviewError::PublicationStale);
    }
    let current = pull.body.as_deref().unwrap_or_default();
    let updated = update_description(current, overview_block).map_err(map_overview_error)?;
    if updated == current {
        return Ok(false);
    }
    let response = client
        .patch(
            &context.target_repository,
            &[
                "pulls",
                &context.identity.pull_request_number.get().to_string(),
            ],
            &UpdatePullRequestBody { body: &updated },
        )
        .await?;
    let observed: GitHubPull =
        serde_json::from_slice(&response.body).map_err(|_| GitHubReviewError::Overview)?;
    if observed.state != "open"
        || observed.base.repo.id != context.identity.repository_id.get()
        || observed.base.sha != context.identity.base_sha.as_str()
        || observed.head.sha != context.identity.head_sha.as_str()
        || observed.body.as_deref() != Some(updated.as_str())
    {
        return Err(GitHubReviewError::Overview);
    }
    Ok(true)
}

fn map_overview_error(error: ReviewOverviewError) -> GitHubReviewError {
    match error {
        ReviewOverviewError::AmbiguousMarkers => GitHubReviewError::PublicationAmbiguous,
        ReviewOverviewError::InvalidOverview
        | ReviewOverviewError::InvalidMetadata
        | ReviewOverviewError::InvalidDescription
        | ReviewOverviewError::DescriptionTooLarge => GitHubReviewError::Overview,
    }
}

impl Error for GitHubReviewError {}

impl From<GitHubTransportError> for GitHubReviewError {
    fn from(_: GitHubTransportError) -> Self {
        Self::Transport
    }
}

/// Double-read an open PR around bounded file pagination and build exact review anchors.
///
/// # Errors
///
/// Rejects transport failures, identity changes, malformed patches, and empty review scope.
pub async fn acquire_github_review_context(
    client: &GitHubClient,
    repository: DiscoveredGitHubRepository,
    target_repository: GitHubRepositorySlug,
    pull_number: revoot_core::PullRequestNumber,
    ci: Option<&GitHubCiContext>,
    options: &GitHubReviewContextOptions,
) -> Result<GitHubReviewContext, GitHubReviewError> {
    let initial = get_pull(client, &target_repository, pull_number).await?;
    validate_pull(&initial, &target_repository, pull_number, ci)?;
    if initial.state != "open" {
        return Err(GitHubReviewError::PullRequestClosed);
    }
    let (files, capped) = list_files(client, &target_repository, pull_number).await?;
    let final_pull = get_pull(client, &target_repository, pull_number).await?;
    if initial != final_pull {
        return Err(GitHubReviewError::IdentityMismatch);
    }
    if repository.head_sha.as_str() != initial.head.sha {
        return Err(GitHubReviewError::CheckoutHeadMismatch);
    }
    let represented = u64::try_from(files.len()).map_err(|_| GitHubReviewError::InvalidFile)?;
    if (initial.changed_files <= u64::from(MAX_PAGES * PER_PAGE)
        && (capped || represented != initial.changed_files))
        || (initial.changed_files > u64::from(MAX_PAGES * PER_PAGE)
            && (!capped || represented != u64::from(MAX_PAGES * PER_PAGE)))
    {
        return Err(GitHubReviewError::IdentityMismatch);
    }
    let identity = GitHubSnapshotIdentity {
        api_origin_digest: Sha256Digest::of_bytes(repository.remote.server.api_root.as_bytes()),
        repository_id: revoot_core::GitHubRepositoryId::try_from(initial.base.repo.id)
            .map_err(|_| GitHubReviewError::InvalidPullRequest)?,
        pull_request_number: pull_number,
        base_sha: GitSha::try_from(initial.base.sha.clone())
            .map_err(|_| GitHubReviewError::InvalidPullRequest)?,
        head_sha: GitSha::try_from(initial.head.sha.clone())
            .map_err(|_| GitHubReviewError::InvalidPullRequest)?,
        exact_diff_manifest_sha256: manifest_digest(&files)?,
    };
    build_context(
        repository,
        target_repository,
        identity,
        initial.body.unwrap_or_default(),
        files,
        capped,
        options,
    )
}

#[allow(clippy::too_many_lines)]
fn build_context(
    repository: DiscoveredGitHubRepository,
    target_repository: GitHubRepositorySlug,
    identity: GitHubSnapshotIdentity,
    description: String,
    mut files: Vec<GitHubFile>,
    capped: bool,
    options: &GitHubReviewContextOptions,
) -> Result<GitHubReviewContext, GitHubReviewError> {
    files.sort_by(|left, right| left.filename.cmp(&right.filename));
    let mut paths = BTreeSet::new();
    let mut repository_diffs = Vec::new();
    let mut commentable = Vec::new();
    let mut inputs = Vec::with_capacity(files.len());
    let mut expected_anchor_counts = Vec::with_capacity(files.len());
    let mut omitted_patch_count = u32::from(capped);
    for file in files {
        let changed_path = changed_path(&file)?;
        if !paths.insert(changed_path.clone()) {
            return Err(GitHubReviewError::DuplicateFile);
        }
        let repository_path =
            RepositoryRelativePath::try_from(changed_path.new_path.as_str().to_owned())
                .map_err(|_| GitHubReviewError::InvalidFile)?;
        let mut objects = Vec::new();
        let class = if file.patch.is_some() {
            ReviewFileClass::Text
        } else {
            ReviewFileClass::Binary
        };
        let review_value = classify_review_value(&changed_path, class, file.patch.as_deref());
        let anchor_count = if let Some(mut patch) = file.patch {
            if !patch.ends_with('\n') {
                patch.push('\n');
            }
            let parsed =
                parse_gitlab_file_diff(&changed_path, patch.as_bytes(), options.diff_limits)
                    .map_err(|_| GitHubReviewError::Diff)?;
            let additions = parsed
                .commentable_lines
                .iter()
                .filter(|line| matches!(line.position, AnchorPosition::Addition { .. }))
                .count();
            let deletions = parsed
                .commentable_lines
                .iter()
                .filter(|line| matches!(line.position, AnchorPosition::Deletion { .. }))
                .count();
            if u64::try_from(additions).unwrap_or(u64::MAX) != file.additions
                || u64::try_from(deletions).unwrap_or(u64::MAX) != file.deletions
                || file.changes != file.additions.saturating_add(file.deletions)
            {
                omitted_patch_count = omitted_patch_count.saturating_add(1);
                inputs.push(ReviewFileInput {
                    path: changed_path,
                    class,
                    review_value,
                    objects,
                    anchor_ids: Vec::new(),
                });
                expected_anchor_counts.push(0);
                continue;
            }
            let size_bytes = u64::try_from(patch.len()).map_err(|_| GitHubReviewError::Diff)?;
            let anchor_count = parsed.commentable_lines.len();
            commentable.extend(parsed.commentable_lines);
            repository_diffs.push(RepositoryDiff {
                path: repository_path,
                text: patch,
            });
            objects.push(ReviewObject {
                role: ReviewObjectRole::ExactDiff,
                content_sha256: parsed.input_sha256,
                size_bytes,
            });
            anchor_count
        } else {
            omitted_patch_count = omitted_patch_count.saturating_add(1);
            0
        };
        inputs.push(ReviewFileInput {
            path: changed_path,
            class,
            review_value,
            objects,
            anchor_ids: Vec::new(),
        });
        expected_anchor_counts.push(anchor_count);
    }
    let review_identity = ReviewSnapshotIdentity::GitHub(identity.clone());
    let anchors = AnchorTable::build(review_identity.clone(), commentable)
        .map_err(|_| GitHubReviewError::Anchor)?;
    issue_anchors(&anchors, &mut inputs, &expected_anchor_counts)?;
    let partition = build_partition_plan(
        review_identity.clone(),
        &options.selection_policy,
        options.partition_limits,
        inputs,
    )
    .map_err(|_| GitHubReviewError::Partition)?;
    let issued_anchors = issued_anchors(&partition);
    let invocation = if partition.work_units.is_empty() {
        None
    } else {
        let invocation = ReviewInvocation {
            review_id: format!(
                "github:{}",
                Sha256Digest::of_bytes(
                    &serde_json::to_vec(&identity).expect("identity serializes infallibly")
                )
                .as_str()
            ),
            snapshot: review_identity,
            work_unit_ids: partition
                .work_units
                .iter()
                .map(|unit| unit.id.as_str().to_owned())
                .collect(),
            provider_adapter: options.provider_adapter.clone(),
            model_id: options.model_id.clone(),
            allowed_tools: automatic_tools(),
            limits: options.agent_limits,
        };
        invocation
            .validate()
            .map_err(|_| GitHubReviewError::Invocation)?;
        Some(invocation)
    };
    Ok(GitHubReviewContext {
        repository,
        target_repository,
        identity,
        description,
        repository_diffs,
        anchors,
        partition,
        issued_anchors,
        invocation,
        omitted_patch_count,
    })
}

fn validate_pull(
    pull: &GitHubPull,
    repository: &GitHubRepositorySlug,
    number: revoot_core::PullRequestNumber,
    ci: Option<&GitHubCiContext>,
) -> Result<(), GitHubReviewError> {
    if pull.number != number.get()
        || pull.base.repo.full_name != repository.as_str()
        || pull.base.repo.id == 0
        || pull.head.repo.id == 0
        || GitSha::try_from(pull.base.sha.clone()).is_err()
        || GitSha::try_from(pull.head.sha.clone()).is_err()
    {
        return Err(GitHubReviewError::InvalidPullRequest);
    }
    if ci.is_some_and(|ci| {
        ci.pull_request_number != number
            || ci.target_repository != *repository
            || ci.target_repository_id.get() != pull.base.repo.id
            || ci.base_sha.as_str() != pull.base.sha
            || ci.head_sha.as_str() != pull.head.sha
    }) {
        return Err(GitHubReviewError::IdentityMismatch);
    }
    Ok(())
}

async fn get_pull(
    client: &GitHubClient,
    repository: &GitHubRepositorySlug,
    number: revoot_core::PullRequestNumber,
) -> Result<GitHubPull, GitHubReviewError> {
    let response = client
        .get(Some(repository), &["pulls", &number.get().to_string()], &[])
        .await?;
    serde_json::from_slice(&response.body).map_err(|_| GitHubReviewError::InvalidPullRequest)
}

async fn list_files(
    client: &GitHubClient,
    repository: &GitHubRepositorySlug,
    number: revoot_core::PullRequestNumber,
) -> Result<(Vec<GitHubFile>, bool), GitHubReviewError> {
    let mut files = Vec::new();
    for page in 1..=MAX_PAGES {
        let response = client
            .get(
                Some(repository),
                &["pulls", &number.get().to_string(), "files"],
                &[
                    ("per_page", PER_PAGE.to_string()),
                    ("page", page.to_string()),
                ],
            )
            .await?;
        let page_files: Vec<GitHubFile> =
            serde_json::from_slice(&response.body).map_err(|_| GitHubReviewError::InvalidFile)?;
        if page_files.len() > PER_PAGE as usize {
            return Err(GitHubReviewError::InvalidFile);
        }
        let terminal = page_files.len() < PER_PAGE as usize;
        files.extend(page_files);
        if terminal {
            return Ok((files, false));
        }
    }
    Ok((files, true))
}

fn manifest_digest(files: &[GitHubFile]) -> Result<Sha256Digest, GitHubReviewError> {
    let mut files = files.to_vec();
    files.sort_by(|left, right| left.filename.cmp(&right.filename));
    serde_json::to_vec(&files)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| GitHubReviewError::InvalidFile)
}

fn changed_path(file: &GitHubFile) -> Result<ChangedPath, GitHubReviewError> {
    let new = RepositoryPath::try_from(file.filename.clone())
        .map_err(|_| GitHubReviewError::InvalidFile)?;
    let (old, kind) = match file.status.as_str() {
        "added" | "copied" => (new.clone(), FileChangeKind::Added),
        "removed" => (new.clone(), FileChangeKind::Deleted),
        "modified" | "changed" => (new.clone(), FileChangeKind::Modified),
        "renamed" => (
            RepositoryPath::try_from(
                file.previous_filename
                    .clone()
                    .ok_or(GitHubReviewError::InvalidFile)?,
            )
            .map_err(|_| GitHubReviewError::InvalidFile)?,
            FileChangeKind::Renamed,
        ),
        _ => return Err(GitHubReviewError::InvalidFile),
    };
    let path = ChangedPath {
        old_path: old,
        new_path: new,
        kind,
    };
    if path.semantic_issue().is_some() {
        return Err(GitHubReviewError::InvalidFile);
    }
    Ok(path)
}

fn issue_anchors(
    anchors: &AnchorTable,
    files: &mut [ReviewFileInput],
    expected: &[usize],
) -> Result<(), GitHubReviewError> {
    let mut indices = BTreeMap::new();
    for (index, file) in files.iter().enumerate() {
        if indices.insert(file.path.clone(), index).is_some() {
            return Err(GitHubReviewError::DuplicateFile);
        }
    }
    let mut observed = vec![0_usize; files.len()];
    for anchor in anchors.iter() {
        let index = *indices.get(&anchor.path).ok_or(GitHubReviewError::Anchor)?;
        files[index].anchor_ids.push(anchor.id.clone());
        observed[index] = observed[index].saturating_add(1);
    }
    if observed != expected {
        return Err(GitHubReviewError::Anchor);
    }
    Ok(())
}

fn issued_anchors(partition: &ReviewPartitionPlan) -> IssuedWorkUnitAnchors {
    partition
        .work_units
        .iter()
        .map(|unit| {
            (
                unit.id.as_str().to_owned(),
                unit.files
                    .iter()
                    .flat_map(|file| file.anchor_ids.iter().cloned())
                    .collect::<BTreeSet<AnchorId>>(),
            )
        })
        .collect()
}

fn automatic_tools() -> BTreeSet<AgentTool> {
    BTreeSet::from([
        AgentTool::ReadFile,
        AgentTool::Search,
        AgentTool::ListFiles,
        AgentTool::InspectChangedFile,
        AgentTool::InspectTests,
        AgentTool::ShowDiff,
        AgentTool::GetPullRequestMetadata,
        AgentTool::GetExistingRevootFindings,
        AgentTool::ListChangeCommits,
        AgentTool::ShowCommitContext,
        AgentTool::SubmitCandidateFinding,
        AgentTool::SubmitReviewSummary,
    ])
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitHubPublicationEvidence {
    pub actions_confirmed: u32,
    pub mutation_attempts: u32,
    pub superseded_comments: u32,
    pub reopened_threads: u32,
}

/// Reconcile and publish Revoot-owned GitHub review comments.
///
/// # Errors
///
/// Rejects incomplete inventories, stale PR heads, ambiguous markers, and mutations.
#[allow(clippy::too_many_lines)]
pub async fn publish_github_findings(
    client: &GitHubClient,
    context: &GitHubReviewContext,
    candidates: &[PublicationCandidate],
    prior_review: &PriorReviewContext,
    fixed_lineages: &BTreeSet<Sha256Digest>,
) -> Result<GitHubPublicationEvidence, GitHubReviewError> {
    let current = acquire_github_prior_review(
        client,
        &context.target_repository,
        context.identity.pull_request_number,
        &context.identity.head_sha,
    )
    .await
    .map_err(|_| GitHubReviewError::PublicationAmbiguous)?;
    if current != *prior_review {
        return Err(GitHubReviewError::PublicationAmbiguous);
    }
    let bot = authenticated_user(client).await?;
    let comments = list_comments(
        client,
        &context.target_repository,
        context.identity.pull_request_number,
    )
    .await?;
    let snapshot = ReviewSnapshotIdentity::GitHub(context.identity.clone());
    let scope = review_publication_scope_digest(&snapshot);
    let prepared = candidates
        .iter()
        .map(|candidate| {
            prepare_review_publication(&snapshot, &candidate.target, &candidate.body)
                .map_err(|_| GitHubReviewError::PublicationMutation)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fingerprints = prepared
        .iter()
        .map(|item| item.marker.fingerprint_sha256.clone())
        .collect::<BTreeSet<_>>();
    let lineages = prepared
        .iter()
        .filter_map(|item| finding_lineage_id(&item.body))
        .collect::<BTreeSet<_>>();
    let mut evidence = GitHubPublicationEvidence::default();
    for publication in &prepared {
        let exact_matches = comments
            .iter()
            .filter(|comment| comment.user.id == bot.id)
            .filter(|comment| comment.marker().as_ref() == Some(&publication.marker))
            .collect::<Vec<_>>();
        let lineage_discussion = finding_lineage_id(&publication.body).and_then(|lineage| {
            prior_review.discussions().iter().find(|discussion| {
                discussion.source == PriorReviewSource::Revoot
                    && discussion
                        .lineage
                        .as_ref()
                        .is_some_and(|marker| marker.lineage_sha256 == lineage)
            })
        });
        if let Some(thread) = lineage_discussion
            && exact_matches.is_empty()
            && occurrence_needs_current_anchor(context, publication, thread)
            && (thread.state != PriorReviewState::Resolved
                || thread
                    .resolution
                    .as_ref()
                    .is_some_and(|resolution| resolution.source == PriorReviewSource::Revoot))
        {
            ensure_fresh(client, context).await?;
            create_comment(client, context, publication).await?;
            evidence.mutation_attempts = evidence.mutation_attempts.saturating_add(1);
            evidence.actions_confirmed = evidence.actions_confirmed.saturating_add(1);
            if thread.state != PriorReviewState::Resolved {
                ensure_fresh(client, context).await?;
                set_thread_resolved(client, &thread.thread_id, true).await?;
                evidence.mutation_attempts = evidence.mutation_attempts.saturating_add(1);
                evidence.superseded_comments = evidence.superseded_comments.saturating_add(1);
            }
            continue;
        }
        let lineage_matches = if exact_matches.is_empty() {
            finding_lineage_id(&publication.body).map_or_else(Vec::new, |lineage| {
                comments
                    .iter()
                    .filter(|comment| comment.user.id == bot.id)
                    .filter(|comment| comment.lineage_id().as_ref() == Some(&lineage))
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
        match matches.as_slice() {
            [_] => {
                if let Some(lineage) = finding_lineage_id(&publication.body)
                    && let Some(thread) = prior_review.discussions().iter().find(|discussion| {
                        discussion.source == PriorReviewSource::Revoot
                            && discussion.state == PriorReviewState::Resolved
                            && discussion.resolution.as_ref().is_some_and(|resolution| {
                                resolution.source == PriorReviewSource::Revoot
                            })
                            && discussion
                                .lineage
                                .as_ref()
                                .is_some_and(|marker| marker.lineage_sha256 == lineage)
                    })
                {
                    ensure_fresh(client, context).await?;
                    set_thread_resolved(client, &thread.thread_id, false).await?;
                    evidence.mutation_attempts = evidence.mutation_attempts.saturating_add(1);
                    evidence.reopened_threads = evidence.reopened_threads.saturating_add(1);
                }
                evidence.actions_confirmed = evidence.actions_confirmed.saturating_add(1);
            }
            [] => {
                ensure_fresh(client, context).await?;
                create_comment(client, context, publication).await?;
                evidence.mutation_attempts = evidence.mutation_attempts.saturating_add(1);
                evidence.actions_confirmed = evidence.actions_confirmed.saturating_add(1);
            }
            _ => return Err(GitHubReviewError::PublicationAmbiguous),
        }
    }
    for comment in comments.iter().filter(|comment| comment.user.id == bot.id) {
        if comment.lineage_id().is_some_and(|lineage| {
            prior_review.discussions().iter().any(|discussion| {
                discussion.source == PriorReviewSource::Revoot
                    && discussion.state == PriorReviewState::Resolved
                    && discussion
                        .lineage
                        .as_ref()
                        .is_some_and(|marker| marker.lineage_sha256 == lineage)
            })
        }) {
            continue;
        }
        if comment
            .lineage_id()
            .is_some_and(|lineage| lineages.contains(&lineage))
        {
            continue;
        }
        if let Some(lineage) = comment.lineage_id()
            && fixed_lineages.contains(&lineage)
            && let Some(thread) = prior_review.discussions().iter().find(|discussion| {
                discussion.source == PriorReviewSource::Revoot
                    && discussion.state != PriorReviewState::Resolved
                    && discussion
                        .lineage
                        .as_ref()
                        .is_some_and(|marker| marker.lineage_sha256 == lineage)
            })
        {
            ensure_fresh(client, context).await?;
            set_thread_resolved(client, &thread.thread_id, true).await?;
            evidence.mutation_attempts = evidence.mutation_attempts.saturating_add(1);
            evidence.superseded_comments = evidence.superseded_comments.saturating_add(1);
            continue;
        }
        let Some(marker) = comment.marker() else {
            continue;
        };
        if marker.scope_sha256 == scope && fingerprints.contains(&marker.fingerprint_sha256) {
            continue;
        }
        ensure_fresh(client, context).await?;
        supersede_comment(client, &context.target_repository, comment).await?;
        evidence.mutation_attempts = evidence.mutation_attempts.saturating_add(1);
        evidence.superseded_comments = evidence.superseded_comments.saturating_add(1);
    }
    Ok(evidence)
}

fn occurrence_needs_current_anchor(
    context: &GitHubReviewContext,
    publication: &revoot_core::PreparedPublication,
    discussion: &revoot_core::PriorReviewDiscussion,
) -> bool {
    if discussion.state == PriorReviewState::Outdated {
        return true;
    }
    let PublicationTarget::Inline(anchor_id) = &publication.target else {
        return false;
    };
    let Some(anchor) = context.anchors.resolve(anchor_id.as_str()) else {
        return true;
    };
    let (path, line) = match anchor.position {
        revoot_core::AnchorPosition::Deletion { old_line } => {
            (anchor.path.old_path.as_str(), old_line)
        }
        revoot_core::AnchorPosition::Addition { new_line }
        | revoot_core::AnchorPosition::Context { new_line, .. } => {
            (anchor.path.new_path.as_str(), new_line)
        }
    };
    discussion.path.as_deref() != Some(path) || discussion.line != Some(line)
}

async fn set_thread_resolved(
    client: &GitHubClient,
    thread_id: &str,
    resolved: bool,
) -> Result<(), GitHubReviewError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Envelope {
        data: Option<Data>,
        errors: Option<Vec<serde_json::Value>>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Data {
        resolve_review_thread: Option<Payload>,
        unresolve_review_thread: Option<Payload>,
    }
    #[derive(Deserialize)]
    struct Payload {
        thread: Thread,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Thread {
        id: String,
        is_resolved: bool,
    }

    let query = if resolved {
        "mutation RevootResolveThread($threadId: ID!) { resolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } } }"
    } else {
        "mutation RevootReopenThread($threadId: ID!) { unresolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } } }"
    };
    let response = client
        .graphql(&serde_json::json!({
            "query": query,
            "variables": {"threadId": thread_id},
        }))
        .await?;
    let envelope: Envelope = serde_json::from_slice(&response.body)
        .map_err(|_| GitHubReviewError::PublicationMutation)?;
    let thread = envelope
        .errors
        .is_none()
        .then_some(envelope.data)
        .flatten()
        .and_then(|data| {
            if resolved {
                data.resolve_review_thread
            } else {
                data.unresolve_review_thread
            }
        })
        .map(|payload| payload.thread)
        .ok_or(GitHubReviewError::PublicationMutation)?;
    if thread.id != thread_id || thread.is_resolved != resolved {
        return Err(GitHubReviewError::PublicationMutation);
    }
    Ok(())
}

async fn authenticated_user(client: &GitHubClient) -> Result<GitHubUser, GitHubReviewError> {
    let response = client.get(None, &["user"], &[]).await?;
    serde_json::from_slice(&response.body).map_err(|_| GitHubReviewError::PublicationInventory)
}

async fn list_comments(
    client: &GitHubClient,
    repository: &GitHubRepositorySlug,
    number: revoot_core::PullRequestNumber,
) -> Result<Vec<GitHubComment>, GitHubReviewError> {
    let mut comments = Vec::new();
    for page in 1..=100_u32 {
        let response = client
            .get(
                Some(repository),
                &["pulls", &number.get().to_string(), "comments"],
                &[
                    ("per_page", PER_PAGE.to_string()),
                    ("page", page.to_string()),
                ],
            )
            .await?;
        let items: Vec<GitHubComment> = serde_json::from_slice(&response.body)
            .map_err(|_| GitHubReviewError::PublicationInventory)?;
        if items.len() > PER_PAGE as usize
            || comments.len().saturating_add(items.len()) > MAX_COMMENTS
        {
            return Err(GitHubReviewError::PublicationInventory);
        }
        let terminal = items.len() < PER_PAGE as usize;
        comments.extend(items);
        if terminal {
            return Ok(comments);
        }
    }
    Err(GitHubReviewError::PublicationInventory)
}

async fn ensure_fresh(
    client: &GitHubClient,
    context: &GitHubReviewContext,
) -> Result<(), GitHubReviewError> {
    let pull = get_pull(
        client,
        &context.target_repository,
        context.identity.pull_request_number,
    )
    .await?;
    if pull.state != "open"
        || pull.base.repo.id != context.identity.repository_id.get()
        || pull.base.sha != context.identity.base_sha.as_str()
        || pull.head.sha != context.identity.head_sha.as_str()
    {
        return Err(GitHubReviewError::PublicationStale);
    }
    Ok(())
}

async fn create_comment(
    client: &GitHubClient,
    context: &GitHubReviewContext,
    publication: &revoot_core::PreparedPublication,
) -> Result<(), GitHubReviewError> {
    let PublicationTarget::Inline(anchor_id) = &publication.target else {
        return Err(GitHubReviewError::PublicationMutation);
    };
    let anchor = context
        .anchors
        .resolve(anchor_id.as_str())
        .ok_or(GitHubReviewError::Anchor)?;
    let (line, side) = match anchor.position {
        AnchorPosition::Deletion { old_line } => (old_line, "LEFT"),
        AnchorPosition::Addition { new_line } | AnchorPosition::Context { new_line, .. } => {
            (new_line, "RIGHT")
        }
    };
    let body = CreateReviewComment {
        body: &publication.marked_body,
        commit_id: context.identity.head_sha.as_str(),
        path: anchor.path.new_path.as_str(),
        line,
        side,
    };
    let response = client
        .post(
            &context.target_repository,
            &[
                "pulls",
                &context.identity.pull_request_number.get().to_string(),
                "comments",
            ],
            &body,
        )
        .await?;
    let created: GitHubComment = serde_json::from_slice(&response.body)
        .map_err(|_| GitHubReviewError::PublicationMutation)?;
    if created.body != publication.marked_body {
        return Err(GitHubReviewError::PublicationMutation);
    }
    Ok(())
}

async fn supersede_comment(
    client: &GitHubClient,
    repository: &GitHubRepositorySlug,
    comment: &GitHubComment,
) -> Result<(), GitHubReviewError> {
    let body = format!(
        "{}\n\n_This finding was superseded by a later Revoot review._\n<!-- revoot:superseded -->",
        comment.body
    );
    let response = client
        .patch(
            repository,
            &["pulls", "comments", &comment.id.to_string()],
            &UpdateReviewComment { body: &body },
        )
        .await?;
    let updated: GitHubComment = serde_json::from_slice(&response.body)
        .map_err(|_| GitHubReviewError::PublicationMutation)?;
    if updated.body != body {
        return Err(GitHubReviewError::PublicationMutation);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct GitHubPull {
    number: u64,
    state: String,
    changed_files: u64,
    #[serde(default)]
    body: Option<String>,
    base: GitHubBranch,
    head: GitHubBranch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct GitHubBranch {
    sha: String,
    repo: GitHubRepository,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct GitHubRepository {
    id: u64,
    full_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GitHubFile {
    sha: String,
    filename: String,
    status: String,
    additions: u64,
    deletions: u64,
    changes: u64,
    #[serde(default)]
    previous_filename: Option<String>,
    #[serde(default)]
    patch: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubUser {
    id: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubComment {
    id: u64,
    user: GitHubUser,
    body: String,
}

impl GitHubComment {
    fn marker(&self) -> Option<PublicationMarker> {
        let terminal = self
            .body
            .rsplit_once('\n')
            .map_or(self.body.as_str(), |(_, tail)| tail);
        PublicationMarker::parse(terminal)
    }

    fn lineage_id(&self) -> Option<Sha256Digest> {
        finding_lineage_id(&self.body)
    }
}

#[derive(Serialize)]
struct CreateReviewComment<'a> {
    body: &'a str,
    commit_id: &'a str,
    path: &'a str,
    line: u32,
    side: &'a str,
}

#[derive(Serialize)]
struct UpdateReviewComment<'a> {
    body: &'a str,
}

#[derive(Serialize)]
struct UpdatePullRequestBody<'a> {
    body: &'a str,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::github_checkout::{DiscoveredGitHubRemote, GitHubServer};
    use crate::github_transport::GitHubToken;

    use super::*;

    fn file(status: &str, name: &str, previous: Option<&str>) -> GitHubFile {
        GitHubFile {
            sha: "a".repeat(40),
            filename: name.to_owned(),
            status: status.to_owned(),
            additions: 1,
            deletions: 1,
            changes: 2,
            previous_filename: previous.map(str::to_owned),
            patch: Some("@@ -1 +1 @@\n-old\n+new\n".to_owned()),
        }
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let count = stream.read(&mut buffer).await.expect("read request");
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(head_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let head_end = head_end + 4;
                let head = std::str::from_utf8(&request[..head_end]).expect("request head");
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= head_end + length {
                    break;
                }
            }
        }
        request
    }

    fn request_json(request: &[u8]) -> serde_json::Value {
        let start = request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("request head")
            + 4;
        serde_json::from_slice(&request[start..]).expect("request JSON")
    }

    async fn write_json(stream: &mut tokio::net::TcpStream, value: &serde_json::Value) {
        let body = serde_json::to_vec(value).expect("response JSON");
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.expect("head");
        stream.write_all(&body).await.expect("body");
    }

    fn pull_body(body: &str) -> serde_json::Value {
        serde_json::json!({
            "number": 7,
            "state": "open",
            "changed_files": 1,
            "body": body,
            "base": {"sha": "a".repeat(40), "repo": {"id": 42, "full_name": "acme/widgets"}},
            "head": {"sha": "b".repeat(40), "repo": {"id": 43, "full_name": "acme/widgets"}}
        })
    }

    fn review_context() -> GitHubReviewContext {
        let server = GitHubServer::from_web_origin("https://github.com").unwrap();
        let slug = GitHubRepositorySlug::parse("acme/widgets").unwrap();
        let repository = DiscoveredGitHubRepository {
            root: PathBuf::from("/checkout"),
            head_sha: GitSha::try_from("b".repeat(40)).unwrap(),
            remote: DiscoveredGitHubRemote {
                name: "origin".to_owned(),
                server,
                repository: slug.clone(),
            },
        };
        let identity = GitHubSnapshotIdentity {
            api_origin_digest: Sha256Digest::of_bytes(b"api"),
            repository_id: revoot_core::GitHubRepositoryId::try_from(42).unwrap(),
            pull_request_number: revoot_core::PullRequestNumber::try_from(7).unwrap(),
            base_sha: GitSha::try_from("a".repeat(40)).unwrap(),
            head_sha: repository.head_sha.clone(),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
        };
        build_context(
            repository,
            slug,
            identity,
            String::new(),
            vec![file("modified", "src/lib.rs", None)],
            false,
            &GitHubReviewContextOptions {
                provider_adapter: "anthropic".to_owned(),
                model_id: "model".to_owned(),
                agent_limits: AgentBudgetLimits::default(),
                diff_limits: UnifiedDiffLimits::default(),
                selection_policy: ReviewSelectionPolicy {
                    version: "automatic-v1".to_owned(),
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
                    max_total_bytes: 4 * 1024 * 1024,
                    max_work_units: 10,
                    max_files_per_work_unit: 20,
                    max_bytes_per_work_unit: 512 * 1024,
                    max_anchors_per_work_unit: 10_000,
                },
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn overview_updates_latest_pull_body_without_replacing_author_text() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().unwrap();
        let overview = concat!(
            "<!-- revoot:overview:v1:start -->\n",
            "<details>overview</details>\n",
            "<!-- revoot:overview:v1:end -->"
        );
        let expected = format!("author text\n\n{overview}");
        let expected_for_server = expected.clone();
        let server = tokio::spawn(async move {
            let (mut get, _) = listener.accept().await.unwrap();
            let get_request = read_request(&mut get).await;
            assert!(get_request.starts_with(b"GET /repos/acme/widgets/pulls/7 "));
            write_json(&mut get, &pull_body("author text")).await;

            let (mut patch, _) = listener.accept().await.unwrap();
            let patch_request = read_request(&mut patch).await;
            assert!(patch_request.starts_with(b"PATCH /repos/acme/widgets/pulls/7 "));
            assert_eq!(request_json(&patch_request)["body"], expected_for_server);
            write_json(&mut patch, &pull_body(&expected_for_server)).await;
        });
        let client = GitHubClient::new_for_loopback(
            GitHubToken::new(b"test-token".to_vec()).unwrap(),
            address,
        )
        .unwrap();
        assert!(
            update_github_overview(&client, &review_context(), overview)
                .await
                .unwrap()
        );
        server.await.unwrap();
        assert!(expected.ends_with(overview));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn clean_review_resolves_owned_open_lineage_without_reposting() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().unwrap();
        let context = review_context();
        let lineage = Sha256Digest::of_bytes(b"lineage");
        let lineage_marker = revoot_core::FindingLineageMarker::new(
            lineage.clone(),
            context.identity.head_sha.clone(),
            Sha256Digest::of_bytes(b"evidence"),
        );
        let body = format!(
            "finding\n{}\n<!-- revoot:v1 scope={} fingerprint={} kind=inline -->",
            lineage_marker.render(),
            "a".repeat(64),
            "b".repeat(64)
        );
        let prior = PriorReviewContext::try_new(vec![revoot_core::PriorReviewDiscussion {
            thread_id: "PRRT_thread".to_owned(),
            comment_id: "41".to_owned(),
            source: PriorReviewSource::Revoot,
            state: PriorReviewState::Open,
            path: Some("src/lib.rs".to_owned()),
            line: Some(1),
            original_line: Some(1),
            body: body.clone(),
            replies: Vec::new(),
            resolution: None,
            lineage: Some(lineage_marker),
        }])
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut inventory_user, _) = listener.accept().await.unwrap();
            assert!(
                read_request(&mut inventory_user)
                    .await
                    .starts_with(b"GET /user ")
            );
            write_json(
                &mut inventory_user,
                &serde_json::json!({"id": 7, "login": "revoot-bot"}),
            )
            .await;

            let (mut inventory, _) = listener.accept().await.unwrap();
            assert!(
                read_request(&mut inventory)
                    .await
                    .starts_with(b"POST /graphql ")
            );
            write_json(
                &mut inventory,
                &serde_json::json!({"data": {"repository": {"pullRequest": {
                    "reviewThreads": {
                        "nodes": [{
                            "id": "PRRT_thread",
                            "isResolved": false,
                            "isOutdated": false,
                            "path": "src/lib.rs",
                            "line": 1,
                            "originalLine": 1,
                            "resolvedBy": null,
                            "comments": {
                                "nodes": [{
                                    "databaseId": 41,
                                    "body": body,
                                    "author": {"login": "revoot-bot", "databaseId": 7},
                                    "originalCommit": {"oid": "d".repeat(40)},
                                    "createdAt": null,
                                    "updatedAt": null
                                }],
                                "pageInfo": {"hasNextPage": false}
                            }
                        }],
                        "pageInfo": {"hasNextPage": false, "endCursor": null}
                    }
                }}}}),
            )
            .await;

            let (mut user, _) = listener.accept().await.unwrap();
            assert!(read_request(&mut user).await.starts_with(b"GET /user "));
            write_json(&mut user, &serde_json::json!({"id": 7})).await;

            let (mut comments, _) = listener.accept().await.unwrap();
            let request = read_request(&mut comments).await;
            assert!(request.starts_with(b"GET /repos/acme/widgets/pulls/7/comments?"));
            write_json(
                &mut comments,
                &serde_json::json!([{"id": 41, "user": {"id": 7}, "body": body}]),
            )
            .await;

            let (mut fresh, _) = listener.accept().await.unwrap();
            assert!(
                read_request(&mut fresh)
                    .await
                    .starts_with(b"GET /repos/acme/widgets/pulls/7 ")
            );
            write_json(&mut fresh, &pull_body("author text")).await;

            let (mut resolve, _) = listener.accept().await.unwrap();
            let request = read_request(&mut resolve).await;
            assert!(request.starts_with(b"POST /graphql "));
            assert!(
                request_json(&request)["query"]
                    .as_str()
                    .unwrap()
                    .contains("resolveReviewThread")
            );
            write_json(
                &mut resolve,
                &serde_json::json!({"data": {"resolveReviewThread": {"thread": {
                    "id": "PRRT_thread", "isResolved": true
                }}}}),
            )
            .await;
        });
        let client = GitHubClient::new_for_loopback(
            GitHubToken::new(b"test-token".to_vec()).unwrap(),
            address,
        )
        .unwrap();
        let evidence =
            publish_github_findings(&client, &context, &[], &prior, &BTreeSet::from([lineage]))
                .await
                .unwrap();
        server.await.unwrap();
        assert_eq!(evidence.superseded_comments, 1);
        assert_eq!(evidence.mutation_attempts, 1);
    }

    #[tokio::test]
    async fn new_discussion_during_review_stops_before_publication() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut user, _) = listener.accept().await.unwrap();
            assert!(read_request(&mut user).await.starts_with(b"GET /user "));
            write_json(&mut user, &serde_json::json!({"login": "revoot-bot"})).await;

            let (mut inventory, _) = listener.accept().await.unwrap();
            assert!(
                read_request(&mut inventory)
                    .await
                    .starts_with(b"POST /graphql ")
            );
            write_json(
                &mut inventory,
                &serde_json::json!({"data": {"repository": {"pullRequest": {
                    "reviewThreads": {
                        "nodes": [{
                            "id": "PRRT_human",
                            "isResolved": false,
                            "isOutdated": false,
                            "path": "src/lib.rs",
                            "line": 1,
                            "originalLine": 1,
                            "resolvedBy": null,
                            "comments": {
                                "nodes": [{
                                    "databaseId": 50,
                                    "body": "A human comment added while Revoot was reviewing.",
                                    "author": {"login": "reviewer"},
                                    "originalCommit": {"oid": "b".repeat(40)},
                                    "createdAt": "2026-08-29T10:00:00Z",
                                    "updatedAt": "2026-08-29T10:00:00Z"
                                }],
                                "pageInfo": {"hasNextPage": false}
                            }
                        }],
                        "pageInfo": {"hasNextPage": false, "endCursor": null}
                    }
                }}}}),
            )
            .await;
        });
        let client = GitHubClient::new_for_loopback(
            GitHubToken::new(b"test-token".to_vec()).unwrap(),
            address,
        )
        .unwrap();
        let error = publish_github_findings(
            &client,
            &review_context(),
            &[],
            &PriorReviewContext::default(),
            &BTreeSet::new(),
        )
        .await
        .expect_err("changed inventory must stop publication");
        assert_eq!(error, GitHubReviewError::PublicationAmbiguous);
        server.await.unwrap();
    }

    #[test]
    fn github_statuses_map_to_strict_changed_paths() {
        let renamed =
            changed_path(&file("renamed", "src/new.rs", Some("src/old.rs"))).expect("renamed");
        assert_eq!(renamed.kind, FileChangeKind::Renamed);
        assert_eq!(renamed.old_path.as_str(), "src/old.rs");
        assert_eq!(
            changed_path(&file("added", "src/new.rs", None))
                .unwrap()
                .kind,
            FileChangeKind::Added
        );
        assert!(changed_path(&file("mystery", "src/new.rs", None)).is_err());
    }

    #[test]
    fn outdated_occurrence_requires_a_current_anchor() {
        let context = review_context();
        let anchor_id = context
            .issued_anchors
            .values()
            .flat_map(|anchors| anchors.iter())
            .next()
            .expect("issued anchor")
            .clone();
        let snapshot = ReviewSnapshotIdentity::GitHub(context.identity.clone());
        let publication =
            prepare_review_publication(&snapshot, &PublicationTarget::Inline(anchor_id), "finding")
                .unwrap();
        let discussion = revoot_core::PriorReviewDiscussion {
            thread_id: "thread".to_owned(),
            comment_id: "1".to_owned(),
            source: PriorReviewSource::Revoot,
            state: PriorReviewState::Outdated,
            path: Some("src/lib.rs".to_owned()),
            line: None,
            original_line: Some(1),
            body: "finding".to_owned(),
            replies: Vec::new(),
            resolution: None,
            lineage: None,
        };
        assert!(occurrence_needs_current_anchor(
            &context,
            &publication,
            &discussion
        ));
    }

    #[test]
    fn superseded_marker_is_no_longer_terminal() {
        let identity = ReviewSnapshotIdentity::GitHub(GitHubSnapshotIdentity {
            api_origin_digest: Sha256Digest::of_bytes(b"api"),
            repository_id: revoot_core::GitHubRepositoryId::try_from(1).unwrap(),
            pull_request_number: revoot_core::PullRequestNumber::try_from(2).unwrap(),
            base_sha: GitSha::try_from("a".repeat(40)).unwrap(),
            head_sha: GitSha::try_from("b".repeat(40)).unwrap(),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"diff"),
        });
        let prepared =
            prepare_review_publication(&identity, &PublicationTarget::Summary, "finding").unwrap();
        let comment = GitHubComment {
            id: 1,
            user: GitHubUser { id: 2 },
            body: format!("{}\n<!-- revoot:superseded -->", prepared.marked_body),
        };
        assert!(comment.marker().is_none());
    }

    #[test]
    fn exact_github_patch_builds_native_snapshot_anchors_and_partition() {
        let server = GitHubServer::from_web_origin("https://github.com").unwrap();
        let slug = GitHubRepositorySlug::parse("acme/widgets").unwrap();
        let repository = DiscoveredGitHubRepository {
            root: PathBuf::from("/checkout"),
            head_sha: GitSha::try_from("b".repeat(40)).unwrap(),
            remote: DiscoveredGitHubRemote {
                name: "origin".to_owned(),
                server,
                repository: slug.clone(),
            },
        };
        let identity = GitHubSnapshotIdentity {
            api_origin_digest: Sha256Digest::of_bytes(b"api"),
            repository_id: revoot_core::GitHubRepositoryId::try_from(42).unwrap(),
            pull_request_number: revoot_core::PullRequestNumber::try_from(7).unwrap(),
            base_sha: GitSha::try_from("a".repeat(40)).unwrap(),
            head_sha: repository.head_sha.clone(),
            exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
        };
        let mut truncated = file("modified", "src/truncated.rs", None);
        truncated.additions = 2;
        truncated.changes = 3;
        let context = build_context(
            repository,
            slug,
            identity.clone(),
            String::new(),
            vec![file("modified", "src/lib.rs", None), truncated],
            false,
            &GitHubReviewContextOptions {
                provider_adapter: "anthropic".to_owned(),
                model_id: "model".to_owned(),
                agent_limits: AgentBudgetLimits::default(),
                diff_limits: UnifiedDiffLimits::default(),
                selection_policy: ReviewSelectionPolicy {
                    version: "automatic-v1".to_owned(),
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
                    max_total_bytes: 4 * 1024 * 1024,
                    max_work_units: 10,
                    max_files_per_work_unit: 20,
                    max_bytes_per_work_unit: 512 * 1024,
                    max_anchors_per_work_unit: 10_000,
                },
            },
        )
        .expect("context");
        assert_eq!(context.identity, identity);
        assert_eq!(context.repository_diffs.len(), 1);
        assert_eq!(context.anchors.len(), 2);
        assert_eq!(context.omitted_patch_count, 1);
        assert_eq!(context.partition.work_units.len(), 1);
        assert!(matches!(
            context
                .invocation
                .as_ref()
                .expect("reviewable invocation")
                .snapshot,
            ReviewSnapshotIdentity::GitHub(_)
        ));
    }
}
