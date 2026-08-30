//! Read-only local Git acquisition for a synthetic change request.
//!
//! Local review compares the merge base of the inferred target branch with the
//! complete current state: committed branch changes, staged changes, unstaged
//! changes, and non-ignored untracked files. Repository metadata and objects are
//! read in-process; no Git executable, hook, diff driver, or text converter runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use revoot_core::{
    AgentBudgetLimits, AgentTool, AnchorId, AnchorTable, ChangedPath, FileChangeKind, GitSha,
    IssuedWorkUnitAnchors, LocalSnapshotIdentity, PartitionLimits, RepositoryDiff, RepositoryPath,
    RepositoryRelativePath, ReviewFileClass, ReviewFileInput, ReviewInvocation, ReviewObject,
    ReviewObjectRole, ReviewPartitionPlan, ReviewSelectionPolicy, ReviewSnapshotIdentity,
    Sha256Digest, UnifiedDiffLimits, build_partition_plan, classify_review_value,
    parse_gitlab_file_diff,
};
use serde::Serialize;
use sha1::{Digest as Sha1Digest, Sha1};
use similar::TextDiff;

use crate::embedded_git::{EmbeddedGitError, EmbeddedRepository};

const MAX_FILE_DIFF_BYTES: usize = 2 * 1024 * 1024;
const MAX_BASE_REF_BYTES: usize = 1_024;

/// Engine and partition limits supplied after configuration is resolved.
#[derive(Clone, Debug)]
pub struct LocalReviewContextOptions {
    pub provider_adapter: String,
    pub model_id: String,
    pub agent_limits: AgentBudgetLimits,
    pub diff_limits: UnifiedDiffLimits,
    pub selection_policy: ReviewSelectionPolicy,
    pub partition_limits: PartitionLimits,
}

/// One read-only capture of the local synthetic change request.
pub struct LocalGitCapture {
    pub root: PathBuf,
    pub inferred_base: String,
    pub identity: LocalSnapshotIdentity,
    pub changed_file_count: u32,
    pub omitted_diff_count: u32,
    changed: Vec<CapturedChange>,
    repository_paths: BTreeSet<RepositoryRelativePath>,
}

impl fmt::Debug for LocalGitCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalGitCapture")
            .field("changed_file_count", &self.changed_file_count)
            .field("omitted_diff_count", &self.omitted_diff_count)
            .finish_non_exhaustive()
    }
}

impl LocalGitCapture {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty()
    }

    #[must_use]
    pub const fn repository_paths(&self) -> &BTreeSet<RepositoryRelativePath> {
        &self.repository_paths
    }
}

/// Local context consumed by the shared automatic review engine.
pub struct LocalReviewContext {
    pub root: PathBuf,
    pub inferred_base: String,
    pub identity: LocalSnapshotIdentity,
    pub repository_paths: BTreeSet<RepositoryRelativePath>,
    pub repository_diffs: Vec<RepositoryDiff>,
    pub anchors: AnchorTable,
    pub partition: ReviewPartitionPlan,
    pub issued_anchors: IssuedWorkUnitAnchors,
    pub invocation: Option<ReviewInvocation>,
    pub omitted_diff_count: u32,
}

impl fmt::Debug for LocalReviewContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalReviewContext")
            .field("repository_path_count", &self.repository_paths.len())
            .field("repository_diff_count", &self.repository_diffs.len())
            .field("anchor_count", &self.anchors.len())
            .field("work_unit_count", &self.partition.work_units.len())
            .field("omitted_diff_count", &self.omitted_diff_count)
            .finish_non_exhaustive()
    }
}

/// Redaction-safe local acquisition and composition failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalReviewError {
    NotRepository,
    InvalidBase,
    BaseAmbiguous,
    HistoryUnavailable,
    InvalidPath,
    Conflict,
    Diff,
    Anchor,
    Partition,
    EmptyReview,
    Invocation,
}

impl fmt::Display for LocalReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotRepository => "the current directory is not inside a Git repository",
            Self::InvalidBase => "the selected local review base is invalid",
            Self::BaseAmbiguous => "the local review base could not be inferred unambiguously",
            Self::HistoryUnavailable => "the local review base history is unavailable",
            Self::InvalidPath => "Git returned a path that cannot be reviewed safely",
            Self::Conflict => "the working tree contains unresolved merge conflicts",
            Self::Diff => "a local exact diff could not be parsed",
            Self::Anchor => "local review anchors could not be constructed",
            Self::Partition => "local review partition construction failed",
            Self::EmptyReview => "the local changes contain no reviewable exact diff",
            Self::Invocation => "the local review invocation is invalid",
        })
    }
}

impl std::error::Error for LocalReviewError {}

#[derive(Clone)]
struct CapturedChange {
    path: ChangedPath,
    diff: Option<String>,
}

struct ClassifiedChange {
    path: ChangedPath,
    old_id: Option<gix::ObjectId>,
    new_id: Option<gix::ObjectId>,
}

#[derive(Serialize)]
struct ManifestEntry<'a> {
    path: &'a ChangedPath,
    diff: &'a str,
}

/// Capture the current repository as a synthetic local change request.
///
/// # Errors
///
/// Fails closed on ambiguous history, unsafe paths, unresolved conflicts, or
/// bounded Git output violations.
#[allow(clippy::too_many_lines)]
pub fn capture_local_git(
    directory: &Path,
    explicit_base: Option<&str>,
) -> Result<LocalGitCapture, LocalReviewError> {
    let repository = EmbeddedRepository::discover(directory).map_err(map_embedded_open_error)?;
    let root = repository.root().to_path_buf();
    let head_sha = repository
        .head()
        .map_err(|_| LocalReviewError::HistoryUnavailable)?;
    let inferred_base = match explicit_base {
        Some(value) => {
            validate_base_ref(value)?;
            value.to_owned()
        }
        None => infer_base_ref(&repository)?,
    };
    let selected_base = repository
        .resolve_commit(&inferred_base)
        .map_err(|_| LocalReviewError::HistoryUnavailable)?;
    let base_sha = repository
        .merge_base(&selected_base, &head_sha)
        .map_err(|_| LocalReviewError::HistoryUnavailable)?;
    let base_files = repository
        .base_files(&base_sha)
        .map_err(map_embedded_error)?;
    let repository_paths = repository.working_paths().map_err(map_embedded_error)?;
    let current_ids = repository_paths
        .iter()
        .map(|path| hash_worktree_blob(&root, path).map(|id| (path.clone(), id)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let changes = classify_changes(&base_files, &current_ids)?;
    let mut captured = Vec::with_capacity(changes.len());
    let mut omitted_diff_count = 0_u32;
    let mut state_material = Vec::new();
    for change in changes {
        append_field(
            &mut state_material,
            change.path.old_path.as_str().as_bytes(),
        );
        append_field(
            &mut state_material,
            change.path.new_path.as_str().as_bytes(),
        );
        append_field(
            &mut state_material,
            format!("{:?}", change.path.kind).as_bytes(),
        );
        append_field(
            &mut state_material,
            change
                .old_id
                .map_or_else(|| "missing".to_owned(), |id| id.to_string())
                .as_bytes(),
        );
        append_field(
            &mut state_material,
            change
                .new_id
                .map_or_else(|| "missing".to_owned(), |id| id.to_string())
                .as_bytes(),
        );
        let diff = render_file_diff(&repository, &root, &change)?;
        let diff_identity = diff.as_deref().map_or_else(
            || "omitted".to_owned(),
            |text| Sha256Digest::of_bytes(text.as_bytes()).as_str().to_owned(),
        );
        append_field(&mut state_material, diff_identity.as_bytes());
        if diff.is_none() {
            omitted_diff_count = omitted_diff_count.saturating_add(1);
        }
        captured.push(CapturedChange {
            path: change.path,
            diff,
        });
    }
    let manifest = captured
        .iter()
        .filter_map(|change| {
            change.diff.as_deref().map(|diff| ManifestEntry {
                path: &change.path,
                diff,
            })
        })
        .collect::<Vec<_>>();
    let exact_diff_manifest_sha256 =
        Sha256Digest::of_bytes(&serde_json::to_vec(&manifest).map_err(|_| LocalReviewError::Diff)?);
    let identity = LocalSnapshotIdentity {
        repository_identity_sha256: repository_identity(&repository, &head_sha)?,
        base_sha,
        head_sha,
        working_tree_sha256: Sha256Digest::of_bytes(&state_material),
        exact_diff_manifest_sha256,
    };
    Ok(LocalGitCapture {
        root,
        inferred_base,
        identity,
        changed_file_count: u32::try_from(captured.len()).unwrap_or(u32::MAX),
        omitted_diff_count,
        changed: captured,
        repository_paths,
    })
}

/// Turn a captured local Git state into the shared review-engine contracts.
///
/// # Errors
///
/// Rejects malformed diffs, inconsistent anchors, an invalid partition policy,
/// or an invalid invocation. A valid empty partition is preserved so callers
/// can return a successful zero-model review.
pub fn build_local_review_context(
    capture: LocalGitCapture,
    options: &LocalReviewContextOptions,
) -> Result<LocalReviewContext, LocalReviewError> {
    let review_identity = ReviewSnapshotIdentity::Local(capture.identity.clone());
    let mut repository_diffs = Vec::new();
    let mut commentable = Vec::new();
    let mut inputs = Vec::with_capacity(capture.changed.len());
    let mut expected_anchor_counts = Vec::with_capacity(capture.changed.len());
    for change in capture.changed {
        let mut objects = Vec::new();
        let class = if change.diff.is_some() {
            ReviewFileClass::Text
        } else {
            ReviewFileClass::Binary
        };
        let review_value = classify_review_value(&change.path, class, change.diff.as_deref());
        let anchor_count = if let Some(diff) = change.diff {
            let parsed = parse_gitlab_file_diff(&change.path, diff.as_bytes(), options.diff_limits)
                .map_err(|_| LocalReviewError::Diff)?;
            let size_bytes = u64::try_from(diff.len()).map_err(|_| LocalReviewError::Diff)?;
            let count = parsed.commentable_lines.len();
            commentable.extend(parsed.commentable_lines);
            repository_diffs.push(RepositoryDiff {
                path: RepositoryRelativePath::try_from(change.path.new_path.as_str().to_owned())
                    .map_err(|_| LocalReviewError::InvalidPath)?,
                text: diff,
            });
            objects.push(ReviewObject {
                role: ReviewObjectRole::ExactDiff,
                content_sha256: parsed.input_sha256,
                size_bytes,
            });
            count
        } else {
            0
        };
        inputs.push(ReviewFileInput {
            path: change.path,
            class,
            review_value,
            objects,
            anchor_ids: Vec::new(),
        });
        expected_anchor_counts.push(anchor_count);
    }
    let anchors = AnchorTable::build(review_identity.clone(), commentable)
        .map_err(|_| LocalReviewError::Anchor)?;
    issue_anchors(&anchors, &mut inputs, &expected_anchor_counts)?;
    let partition = build_partition_plan(
        review_identity.clone(),
        &options.selection_policy,
        options.partition_limits,
        inputs,
    )
    .map_err(|_| LocalReviewError::Partition)?;
    let issued_anchors = issued_anchors(&partition);
    let identity_bytes =
        serde_json::to_vec(&capture.identity).map_err(|_| LocalReviewError::Invocation)?;
    let invocation = if partition.work_units.is_empty() {
        None
    } else {
        let invocation = ReviewInvocation {
            review_id: format!("local:{}", Sha256Digest::of_bytes(&identity_bytes).as_str()),
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
            .map_err(|_| LocalReviewError::Invocation)?;
        Some(invocation)
    };
    Ok(LocalReviewContext {
        root: capture.root,
        inferred_base: capture.inferred_base,
        identity: capture.identity,
        repository_paths: capture.repository_paths,
        repository_diffs,
        anchors,
        partition,
        issued_anchors,
        invocation,
        omitted_diff_count: capture.omitted_diff_count,
    })
}

/// Re-capture against the frozen merge base and compare every identity field.
#[must_use]
pub fn local_snapshot_is_fresh(context: &LocalReviewContext) -> bool {
    capture_local_git(&context.root, Some(context.identity.base_sha.as_str()))
        .is_ok_and(|capture| capture.identity == context.identity)
}

fn issue_anchors(
    anchors: &AnchorTable,
    files: &mut [ReviewFileInput],
    expected: &[usize],
) -> Result<(), LocalReviewError> {
    let mut indices = BTreeMap::new();
    for (index, file) in files.iter().enumerate() {
        if indices.insert(file.path.clone(), index).is_some() {
            return Err(LocalReviewError::Anchor);
        }
    }
    let mut observed = vec![0_usize; files.len()];
    for anchor in anchors.iter() {
        let index = *indices.get(&anchor.path).ok_or(LocalReviewError::Anchor)?;
        files[index].anchor_ids.push(anchor.id.clone());
        observed[index] = observed[index].saturating_add(1);
    }
    if observed != expected {
        return Err(LocalReviewError::Anchor);
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

fn infer_base_ref(repository: &EmbeddedRepository) -> Result<String, LocalReviewError> {
    if let Some(origin) = symbolic_remote_head(repository, "origin") {
        return Ok(origin);
    }
    let remotes = repository
        .remote_urls()
        .map_err(|_| LocalReviewError::HistoryUnavailable)?;
    let mut candidates = remotes
        .keys()
        .filter(|remote| remote.as_str() != "origin")
        .filter_map(|remote| symbolic_remote_head(repository, remote))
        .collect::<BTreeSet<_>>();
    if candidates.len() == 1 {
        return Ok(candidates.pop_first().expect("one candidate"));
    }
    let local = ["main", "master"]
        .into_iter()
        .filter(|name| repository.resolve_commit(name).is_ok())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    match local.as_slice() {
        [only] => Ok(only.clone()),
        _ => Err(LocalReviewError::BaseAmbiguous),
    }
}

fn symbolic_remote_head(repository: &EmbeddedRepository, remote: &str) -> Option<String> {
    if !valid_remote_name(remote) {
        return None;
    }
    let reference = format!("refs/remotes/{remote}/HEAD");
    repository.symbolic_reference(&reference)
}

fn valid_remote_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_base_ref(value: &str) -> Result<(), LocalReviewError> {
    if value.is_empty()
        || value.len() > MAX_BASE_REF_BYTES
        || value.starts_with('-')
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("..")
        || value.contains("@{")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
    {
        return Err(LocalReviewError::InvalidBase);
    }
    Ok(())
}

fn repository_identity(
    repository: &EmbeddedRepository,
    head: &GitSha,
) -> Result<Sha256Digest, LocalReviewError> {
    let roots = repository
        .root_commits(head)
        .map_err(|_| LocalReviewError::HistoryUnavailable)?;
    let material = roots
        .iter()
        .map(GitSha::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Sha256Digest::of_bytes(material.as_bytes()))
}

fn classify_changes(
    base: &BTreeMap<RepositoryRelativePath, gix::ObjectId>,
    current: &BTreeMap<RepositoryRelativePath, gix::ObjectId>,
) -> Result<Vec<ClassifiedChange>, LocalReviewError> {
    let mut removed = base
        .iter()
        .filter(|(path, _)| !current.contains_key(*path))
        .map(|(path, id)| (path.clone(), *id))
        .collect::<BTreeMap<_, _>>();
    let mut added = current
        .iter()
        .filter(|(path, _)| !base.contains_key(*path))
        .map(|(path, id)| (path.clone(), *id))
        .collect::<BTreeMap<_, _>>();
    let mut changes = Vec::new();

    let mut removed_by_id = BTreeMap::<String, Vec<RepositoryRelativePath>>::new();
    for (path, id) in &removed {
        removed_by_id
            .entry(id.to_string())
            .or_default()
            .push(path.clone());
    }
    let mut added_by_id = BTreeMap::<String, Vec<RepositoryRelativePath>>::new();
    for (path, id) in &added {
        added_by_id
            .entry(id.to_string())
            .or_default()
            .push(path.clone());
    }
    for (id, old_paths) in removed_by_id {
        let Some(new_paths) = added_by_id.get(&id) else {
            continue;
        };
        if let ([old], [new]) = (old_paths.as_slice(), new_paths.as_slice()) {
            let old_id = removed.remove(old).ok_or(LocalReviewError::Diff)?;
            let new_id = added.remove(new).ok_or(LocalReviewError::Diff)?;
            changes.push(classified_change(
                old,
                new,
                FileChangeKind::Renamed,
                Some(old_id),
                Some(new_id),
            )?);
        }
    }

    for (path, old_id) in removed {
        changes.push(classified_change(
            &path,
            &path,
            FileChangeKind::Deleted,
            Some(old_id),
            None,
        )?);
    }
    for (path, new_id) in added {
        changes.push(classified_change(
            &path,
            &path,
            FileChangeKind::Added,
            None,
            Some(new_id),
        )?);
    }
    for (path, old_id) in base {
        let Some(new_id) = current.get(path) else {
            continue;
        };
        if old_id != new_id {
            changes.push(classified_change(
                path,
                path,
                FileChangeKind::Modified,
                Some(*old_id),
                Some(*new_id),
            )?);
        }
    }
    changes.sort_by(|left, right| left.path.new_path.cmp(&right.path.new_path));
    Ok(changes)
}

fn classified_change(
    old: &RepositoryRelativePath,
    new: &RepositoryRelativePath,
    kind: FileChangeKind,
    old_id: Option<gix::ObjectId>,
    new_id: Option<gix::ObjectId>,
) -> Result<ClassifiedChange, LocalReviewError> {
    let path = ChangedPath {
        old_path: RepositoryPath::try_from(old.as_str().to_owned())
            .map_err(|_| LocalReviewError::InvalidPath)?,
        new_path: RepositoryPath::try_from(new.as_str().to_owned())
            .map_err(|_| LocalReviewError::InvalidPath)?,
        kind,
    };
    if path.semantic_issue().is_some() {
        return Err(LocalReviewError::InvalidPath);
    }
    Ok(ClassifiedChange {
        path,
        old_id,
        new_id,
    })
}

fn hash_worktree_blob(
    root: &Path,
    path: &RepositoryRelativePath,
) -> Result<gix::ObjectId, LocalReviewError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(path.as_str()))
        .map_err(|_| LocalReviewError::InvalidPath)?;
    let metadata = file.metadata().map_err(|_| LocalReviewError::InvalidPath)?;
    if !metadata.is_file() {
        return Err(LocalReviewError::InvalidPath);
    }
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", metadata.len()).as_bytes());
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| LocalReviewError::InvalidPath)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| LocalReviewError::Diff)?)
            .ok_or(LocalReviewError::Diff)?;
        hasher.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err(LocalReviewError::Diff);
    }
    gix::ObjectId::from_hex(format!("{:x}", hasher.finalize()).as_bytes())
        .map_err(|_| LocalReviewError::Diff)
}

fn render_file_diff(
    repository: &EmbeddedRepository,
    root: &Path,
    change: &ClassifiedChange,
) -> Result<Option<String>, LocalReviewError> {
    let old = if let Some(id) = change.old_id {
        match repository.object_bytes(
            id,
            u64::try_from(MAX_FILE_DIFF_BYTES).expect("diff bound fits u64"),
        ) {
            Ok(bytes) => bytes,
            Err(EmbeddedGitError::ObjectTooLarge) => return Ok(None),
            Err(_) => return Err(LocalReviewError::Diff),
        }
    } else {
        Vec::new()
    };
    let new = if change.new_id.is_some() {
        let Some(bytes) = read_worktree_bounded(root, &change.path.new_path)? else {
            return Ok(None);
        };
        bytes
    } else {
        Vec::new()
    };
    if old.contains(&0) || new.contains(&0) {
        return Ok(None);
    }
    let (Ok(old), Ok(new)) = (std::str::from_utf8(&old), std::str::from_utf8(&new)) else {
        return Ok(None);
    };
    let diff = TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .to_string();
    if diff.is_empty() || diff.len() > MAX_FILE_DIFF_BYTES {
        return Ok(None);
    }
    Ok(Some(diff))
}

fn read_worktree_bounded(
    root: &Path,
    path: &RepositoryPath,
) -> Result<Option<Vec<u8>>, LocalReviewError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(path.as_str()))
        .map_err(|_| LocalReviewError::InvalidPath)?;
    let metadata = file.metadata().map_err(|_| LocalReviewError::InvalidPath)?;
    if !metadata.is_file()
        || metadata.len() > u64::try_from(MAX_FILE_DIFF_BYTES).expect("diff bound fits u64")
    {
        return Ok(None);
    }
    let maximum = u64::try_from(MAX_FILE_DIFF_BYTES).expect("diff bound fits u64");
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| LocalReviewError::InvalidPath)?;
    if bytes.len() > MAX_FILE_DIFF_BYTES {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn map_embedded_open_error(_error: EmbeddedGitError) -> LocalReviewError {
    LocalReviewError::NotRepository
}

fn map_embedded_error(error: EmbeddedGitError) -> LocalReviewError {
    match error {
        EmbeddedGitError::Conflict => LocalReviewError::Conflict,
        EmbeddedGitError::InvalidPath => LocalReviewError::InvalidPath,
        EmbeddedGitError::PathLimit | EmbeddedGitError::ObjectTooLarge => LocalReviewError::Diff,
        _ => LocalReviewError::HistoryUnavailable,
    }
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "revoot-local-review-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("src")).expect("fixture root");
            git(&root, &["init", "-b", "main"]);
            git(&root, &["config", "user.email", "revoot@example.invalid"]);
            git(&root, &["config", "user.name", "Revoot Test"]);
            git(&root, &["config", "commit.gpgsign", "false"]);
            fs::write(root.join("src/lib.rs"), "pub fn value() -> u32 { 1 }\n").unwrap();
            fs::write(root.join("Cargo.toml"), "[package]\nname = \"fixture\"\n").unwrap();
            fs::write(root.join(".gitignore"), "target/\n").unwrap();
            git(&root, &["add", "."]);
            git(&root, &["commit", "-m", "base"]);
            git(&root, &["checkout", "-b", "feature"]);
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn git(root: &Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(arguments)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("git")
                .success()
        );
    }

    #[test]
    fn embedded_capture_child_without_git_on_path() {
        let Some(root) = std::env::var_os("REVOOT_EMBEDDED_GIT_TEST_ROOT") else {
            return;
        };
        let capture = capture_local_git(Path::new(&root), Some("main"))
            .expect("embedded capture does not need the Git executable");
        assert_eq!(capture.changed_file_count, 1);
    }

    #[test]
    fn local_capture_runs_with_git_absent_from_path() {
        let fixture = Fixture::new();
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 2 }\n",
        )
        .unwrap();
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "local_review::tests::embedded_capture_child_without_git_on_path",
                "--nocapture",
            ])
            .env("REVOOT_EMBEDDED_GIT_TEST_ROOT", &fixture.0)
            .env("PATH", fixture.0.join("no-git-here"))
            .status()
            .expect("launch isolated test process");
        assert!(status.success());
    }

    #[test]
    fn repository_filters_are_never_executed() {
        let fixture = Fixture::new();
        let filter = fixture.0.join("malicious-filter");
        let sentinel = fixture.0.join("filter-was-executed");
        fs::write(
            &filter,
            format!("#!/bin/sh\ntouch '{}'\ncat\n", sentinel.display()),
        )
        .unwrap();
        let mut permissions = fs::metadata(&filter).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&filter, permissions).unwrap();
        fs::write(
            fixture.0.join(".git/info/exclude"),
            "malicious-filter\nfilter-was-executed\n",
        )
        .unwrap();
        git(
            &fixture.0,
            &[
                "config",
                "filter.revoot-review.clean",
                filter.to_str().unwrap(),
            ],
        );
        fs::write(
            fixture.0.join(".gitattributes"),
            "src/lib.rs filter=revoot-review\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 2 }\n",
        )
        .unwrap();

        let capture = capture_local_git(&fixture.0, Some("main")).expect("local capture");
        assert_eq!(capture.changed_file_count, 2);
        assert!(!sentinel.exists());
    }

    #[test]
    fn captures_committed_staged_unstaged_and_untracked_but_not_ignored_files() {
        let fixture = Fixture::new();
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 2 }\n",
        )
        .unwrap();
        git(&fixture.0, &["add", "src/lib.rs"]);
        git(&fixture.0, &["commit", "-m", "committed change"]);
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 3 }\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("src/staged.rs"),
            "pub fn staged_value() -> u32 { 5 }\n",
        )
        .unwrap();
        git(&fixture.0, &["add", "src/staged.rs"]);
        fs::write(
            fixture.0.join("src/new.rs"),
            "pub fn new_value() -> u32 { 4 }\n",
        )
        .unwrap();
        fs::create_dir_all(fixture.0.join("target")).unwrap();
        fs::write(fixture.0.join("target/cache"), "ignored").unwrap();

        let capture = capture_local_git(&fixture.0, Some("main")).expect("local capture");
        assert_eq!(capture.changed_file_count, 3);
        assert_eq!(capture.omitted_diff_count, 0);
        assert!(
            capture
                .repository_paths
                .contains(&RepositoryRelativePath::try_from("src/new.rs".to_owned()).unwrap())
        );
        assert!(
            !capture
                .repository_paths
                .iter()
                .any(|path| path.as_str().starts_with("target/"))
        );
        assert_ne!(capture.identity.base_sha, capture.identity.head_sha);
    }

    #[test]
    fn inferred_local_main_and_snapshot_freshness_are_deterministic() {
        let fixture = Fixture::new();
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 2 }\n",
        )
        .unwrap();
        let capture = capture_local_git(&fixture.0, None).expect("inferred main");
        assert_eq!(capture.inferred_base, "main");
        let options = LocalReviewContextOptions {
            provider_adapter: "fixture".to_owned(),
            model_id: "fixture-model".to_owned(),
            agent_limits: AgentBudgetLimits::default(),
            diff_limits: UnifiedDiffLimits::default(),
            selection_policy: ReviewSelectionPolicy {
                version: "fixture-v1".to_owned(),
                included_paths: BTreeSet::new(),
                included_prefixes: Vec::new(),
                included_suffixes: Vec::new(),
                excluded_paths: BTreeSet::new(),
                excluded_prefixes: Vec::new(),
                excluded_suffixes: Vec::new(),
                include_generated: true,
                max_file_bytes: 2 * 1024 * 1024,
            },
            partition_limits: PartitionLimits {
                max_files: 100,
                max_total_bytes: 8 * 1024 * 1024,
                max_work_units: 10,
                max_files_per_work_unit: 20,
                max_bytes_per_work_unit: 2 * 1024 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
        };
        let context = build_local_review_context(capture, &options).expect("local context");
        assert!(local_snapshot_is_fresh(&context));
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 3 }\n",
        )
        .unwrap();
        assert!(!local_snapshot_is_fresh(&context));
    }

    #[test]
    fn low_signal_only_change_can_finish_without_a_model_invocation() {
        let fixture = Fixture::new();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let capture = capture_local_git(&fixture.0, Some("main")).expect("local capture");
        let context = build_local_review_context(
            capture,
            &LocalReviewContextOptions {
                provider_adapter: "fixture".to_owned(),
                model_id: "fixture-model".to_owned(),
                agent_limits: AgentBudgetLimits::default(),
                diff_limits: UnifiedDiffLimits::default(),
                selection_policy: ReviewSelectionPolicy {
                    version: "fixture-v1".to_owned(),
                    included_paths: BTreeSet::new(),
                    included_prefixes: Vec::new(),
                    included_suffixes: Vec::new(),
                    excluded_paths: BTreeSet::new(),
                    excluded_prefixes: Vec::new(),
                    excluded_suffixes: Vec::new(),
                    include_generated: true,
                    max_file_bytes: 1_024,
                },
                partition_limits: PartitionLimits {
                    max_files: 10,
                    max_total_bytes: 100,
                    max_work_units: 2,
                    max_files_per_work_unit: 10,
                    max_bytes_per_work_unit: 100,
                    max_anchors_per_work_unit: 100,
                },
            },
        )
        .expect("low-signal context");

        assert!(context.partition.work_units.is_empty());
        assert!(context.invocation.is_none());
        assert_eq!(
            context.partition.omitted[0].reason,
            revoot_core::ReviewOmissionReason::LowSignalBudget
        );
    }

    #[test]
    fn unsafe_base_and_unresolved_conflict_fail_closed() {
        let fixture = Fixture::new();
        assert_eq!(
            capture_local_git(&fixture.0, Some("--upload-pack=bad")).unwrap_err(),
            LocalReviewError::InvalidBase
        );
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 2 }\n",
        )
        .unwrap();
        git(&fixture.0, &["add", "src/lib.rs"]);
        git(&fixture.0, &["commit", "-m", "feature"]);
        git(&fixture.0, &["checkout", "main"]);
        fs::write(
            fixture.0.join("src/lib.rs"),
            "pub fn value() -> u32 { 9 }\n",
        )
        .unwrap();
        git(&fixture.0, &["add", "src/lib.rs"]);
        git(&fixture.0, &["commit", "-m", "main"]);
        let status = Command::new("git")
            .arg("-C")
            .arg(&fixture.0)
            .args(["merge", "feature"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
        assert_eq!(
            capture_local_git(&fixture.0, Some("main")).unwrap_err(),
            LocalReviewError::Conflict
        );
    }
}
