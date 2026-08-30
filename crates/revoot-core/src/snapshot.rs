//! Pure contracts for binding and assessing immutable code-host review snapshots.
//!
//! This module deliberately contains no HTTP, credential, checkout, process, or publication code.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const GIT_SHA_MIN_LEN: usize = 40;
const GIT_SHA_MAX_LEN: usize = 64;
const SHA256_HEX_LEN: usize = 64;
const ANCHOR_PREFIX: &str = "ga1_";

/// A rejected positive numeric identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPositiveId;

impl fmt::Display for InvalidPositiveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identifier must be greater than zero")
    }
}

macro_rules! positive_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(try_from = "u64", into = "u64")]
        pub struct $name(u64);

        impl $name {
            /// Return the provider numeric identifier.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl TryFrom<u64> for $name {
            type Error = InvalidPositiveId;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                if value == 0 {
                    Err(InvalidPositiveId)
                } else {
                    Ok(Self(value))
                }
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

positive_id!(ProjectId);
positive_id!(MergeRequestIid);
positive_id!(DiffVersionId);
positive_id!(GitHubRepositoryId);
positive_id!(PullRequestNumber);

/// Error returned for a malformed hexadecimal identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HexIdentityError {
    Length,
    Character,
}

impl fmt::Display for HexIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => formatter.write_str("hexadecimal identity has an invalid length"),
            Self::Character => {
                formatter.write_str("hexadecimal identity must contain lowercase ASCII hex")
            }
        }
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// An exact Git object or commit identifier accepted by supported GitLab repositories.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitSha(String);

impl GitSha {
    /// Return the lowercase hexadecimal value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GitSha {
    type Error = HexIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != GIT_SHA_MIN_LEN && value.len() != GIT_SHA_MAX_LEN {
            return Err(HexIdentityError::Length);
        }
        if !is_lower_hex(&value) {
            return Err(HexIdentityError::Character);
        }
        Ok(Self(value))
    }
}

impl From<GitSha> for String {
    fn from(value: GitSha) -> Self {
        value.0
    }
}

/// A lowercase SHA-256 digest used for content and identity binding.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Return the lowercase hexadecimal value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash bytes into the canonical lowercase representation.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = HexIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != SHA256_HEX_LEN {
            return Err(HexIdentityError::Length);
        }
        if !is_lower_hex(&value) {
            return Err(HexIdentityError::Character);
        }
        Ok(Self(value))
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

/// An exact UTF-8 repository path returned by GitLab.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepositoryPath(String);

/// Error returned for a repository path that cannot be represented safely in the contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryPathError {
    Empty,
    Nul,
}

impl fmt::Display for RepositoryPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("repository path must not be empty"),
            Self::Nul => formatter.write_str("repository path must not contain NUL"),
        }
    }
}

impl RepositoryPath {
    /// Return the exact provider path without normalization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RepositoryPath {
    type Error = RepositoryPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(RepositoryPathError::Empty);
        }
        if value.contains('\0') {
            return Err(RepositoryPathError::Nul);
        }
        Ok(Self(value))
    }
}

impl From<RepositoryPath> for String {
    fn from(value: RepositoryPath) -> Self {
        value.0
    }
}

/// The immutable SHA triple GitLab uses for one merge-request diff version.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffRefs {
    pub base_sha: GitSha,
    pub start_sha: GitSha,
    pub head_sha: GitSha,
}

/// One diff-version identity returned by GitLab's versions endpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffVersionRecord {
    pub id: DiffVersionId,
    pub refs: DiffRefs,
}

/// Scope which prevents the same provider IDs on different GitLab instances from colliding.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotScope {
    pub instance_origin_digest: Sha256Digest,
    pub project_id: ProjectId,
    pub merge_request_iid: MergeRequestIid,
}

/// Provider identity selected before exact diff content has been acquired and hashed.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitLabDiffVersionIdentity {
    pub scope: SnapshotScope,
    pub diff_version: DiffVersionRecord,
}

/// Fully frozen identity for exact diff content from one GitLab merge-request version.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitLabSnapshotIdentity {
    pub version: GitLabDiffVersionIdentity,
    pub exact_diff_manifest_sha256: Sha256Digest,
}

/// Fully frozen identity for one GitHub pull-request head and exact diff manifest.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSnapshotIdentity {
    pub api_origin_digest: Sha256Digest,
    pub repository_id: GitHubRepositoryId,
    pub pull_request_number: PullRequestNumber,
    pub base_sha: GitSha,
    pub head_sha: GitSha,
    pub exact_diff_manifest_sha256: Sha256Digest,
}

/// Fully frozen identity for a local branch plus its staged, unstaged, and
/// non-ignored untracked changes.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSnapshotIdentity {
    /// Stable repository scope derived from the root commit set.
    pub repository_identity_sha256: Sha256Digest,
    /// Merge base against which the synthetic change request was captured.
    pub base_sha: GitSha,
    /// Committed `HEAD` observed during capture.
    pub head_sha: GitSha,
    /// Digest covering every changed path and its observed local state.
    pub working_tree_sha256: Sha256Digest,
    /// Digest covering the exact reviewable per-file diffs.
    pub exact_diff_manifest_sha256: Sha256Digest,
}

/// Provider-specific immutable identity used by the shared review engine.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum ReviewSnapshotIdentity {
    GitLab(GitLabSnapshotIdentity),
    GitHub(GitHubSnapshotIdentity),
    Local(LocalSnapshotIdentity),
}

impl From<GitLabSnapshotIdentity> for ReviewSnapshotIdentity {
    fn from(value: GitLabSnapshotIdentity) -> Self {
        Self::GitLab(value)
    }
}

impl From<GitHubSnapshotIdentity> for ReviewSnapshotIdentity {
    fn from(value: GitHubSnapshotIdentity) -> Self {
        Self::GitHub(value)
    }
}

impl From<LocalSnapshotIdentity> for ReviewSnapshotIdentity {
    fn from(value: LocalSnapshotIdentity) -> Self {
        Self::Local(value)
    }
}

impl PartialEq<GitLabSnapshotIdentity> for ReviewSnapshotIdentity {
    fn eq(&self, other: &GitLabSnapshotIdentity) -> bool {
        matches!(self, Self::GitLab(identity) if identity == other)
    }
}

impl PartialEq<ReviewSnapshotIdentity> for GitLabSnapshotIdentity {
    fn eq(&self, other: &ReviewSnapshotIdentity) -> bool {
        other == self
    }
}

impl GitLabDiffVersionIdentity {
    /// Bind a trusted canonical exact-version diff manifest to this provider identity.
    #[must_use]
    pub fn freeze(self, exact_diff_manifest_sha256: Sha256Digest) -> GitLabSnapshotIdentity {
        GitLabSnapshotIdentity {
            version: self,
            exact_diff_manifest_sha256,
        }
    }
}

/// Evidence that one numbered page was fetched.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PageReceipt {
    pub page_number: u32,
    pub item_count: u32,
    pub has_next_page: bool,
}

/// Ordered items plus evidence for every page used to acquire them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaginatedAcquisition<T> {
    pub items: Vec<T>,
    pub pages: Vec<PageReceipt>,
}

/// A reason a paginated acquisition cannot be proved complete.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PaginationIssue {
    NoPages,
    PageNumberZero,
    FirstPageMissing { observed: u32 },
    NonSequentialPage { expected: u32, observed: u32 },
    PageAfterTerminal { page_number: u32 },
    ContinuationNotFetched { after_page: u32 },
    ItemCountMismatch { receipts: u64, observed: u64 },
}

/// Deterministically evaluated pagination status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum PaginationCompleteness {
    Complete {
        pages: u32,
        items: u64,
    },
    Partial {
        pages: u32,
        items: u64,
        reasons: Vec<PaginationIssue>,
    },
}

impl<T> PaginatedAcquisition<T> {
    /// Check sequence, terminal-page, and aggregate item-count evidence.
    #[must_use]
    pub fn completeness(&self) -> PaginationCompleteness {
        let mut reasons = BTreeSet::new();
        if self.pages.is_empty() {
            reasons.insert(PaginationIssue::NoPages);
        }

        for (index, page) in self.pages.iter().enumerate() {
            if page.page_number == 0 {
                reasons.insert(PaginationIssue::PageNumberZero);
            }
            if index == 0 && page.page_number != 1 {
                reasons.insert(PaginationIssue::FirstPageMissing {
                    observed: page.page_number,
                });
            }
            if index > 0 {
                let previous = self.pages[index - 1];
                if !previous.has_next_page {
                    reasons.insert(PaginationIssue::PageAfterTerminal {
                        page_number: page.page_number,
                    });
                }
                let expected = previous.page_number.saturating_add(1);
                if page.page_number != expected {
                    reasons.insert(PaginationIssue::NonSequentialPage {
                        expected,
                        observed: page.page_number,
                    });
                }
            }
        }

        if let Some(last) = self.pages.last()
            && last.has_next_page
        {
            reasons.insert(PaginationIssue::ContinuationNotFetched {
                after_page: last.page_number,
            });
        }

        let receipt_items = self
            .pages
            .iter()
            .map(|page| u64::from(page.item_count))
            .sum::<u64>();
        let observed_items = u64::try_from(self.items.len()).unwrap_or(u64::MAX);
        if receipt_items != observed_items {
            reasons.insert(PaginationIssue::ItemCountMismatch {
                receipts: receipt_items,
                observed: observed_items,
            });
        }

        let page_count = u32::try_from(self.pages.len()).unwrap_or(u32::MAX);
        if reasons.is_empty() {
            PaginationCompleteness::Complete {
                pages: page_count,
                items: observed_items,
            }
        } else {
            PaginationCompleteness::Partial {
                pages: page_count,
                items: observed_items,
                reasons: reasons.into_iter().collect(),
            }
        }
    }
}

/// A reason immutable snapshot identity cannot be established.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum IdentityBlocker {
    MergeRequestDiffRefsNotPrepared,
    DiffVersionsPaginationIncomplete {
        reasons: Vec<PaginationIssue>,
    },
    NoDiffVersions,
    DiffVersionsNotNewestFirst {
        previous: DiffVersionId,
        observed: DiffVersionId,
    },
    LatestDiffRefsMismatch {
        merge_request: DiffRefs,
        latest_version: DiffRefs,
    },
}

/// Result of binding MR refs to the newest completely acquired diff version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SnapshotBinding {
    Bound { identity: GitLabDiffVersionIdentity },
    Blocked { reasons: Vec<IdentityBlocker> },
}

/// Bind only when pagination is complete and the newest version matches all three MR refs.
#[must_use]
pub fn bind_latest_snapshot(
    scope: SnapshotScope,
    merge_request_refs: Option<&DiffRefs>,
    versions: &PaginatedAcquisition<DiffVersionRecord>,
) -> SnapshotBinding {
    let mut blockers = BTreeSet::new();
    if merge_request_refs.is_none() {
        blockers.insert(IdentityBlocker::MergeRequestDiffRefsNotPrepared);
    }
    if let PaginationCompleteness::Partial { reasons, .. } = versions.completeness() {
        blockers.insert(IdentityBlocker::DiffVersionsPaginationIncomplete { reasons });
    }
    if versions.items.is_empty() {
        blockers.insert(IdentityBlocker::NoDiffVersions);
    }
    for pair in versions.items.windows(2) {
        if pair[0].id <= pair[1].id {
            blockers.insert(IdentityBlocker::DiffVersionsNotNewestFirst {
                previous: pair[0].id,
                observed: pair[1].id,
            });
        }
    }
    if let (Some(mr_refs), Some(latest)) = (merge_request_refs, versions.items.first())
        && *mr_refs != latest.refs
    {
        blockers.insert(IdentityBlocker::LatestDiffRefsMismatch {
            merge_request: mr_refs.clone(),
            latest_version: latest.refs.clone(),
        });
    }

    if !blockers.is_empty() {
        return SnapshotBinding::Blocked {
            reasons: blockers.into_iter().collect(),
        };
    }

    let Some(latest) = versions.items.first().cloned() else {
        return SnapshotBinding::Blocked {
            reasons: vec![IdentityBlocker::NoDiffVersions],
        };
    };
    SnapshotBinding::Bound {
        identity: GitLabDiffVersionIdentity {
            scope,
            diff_version: latest,
        },
    }
}

/// GitLab's collection state for an exact diff version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "value")]
pub enum DiffVersionState {
    Collected,
    Overflow,
    WithoutFiles,
    Unknown(String),
}

/// Independent count evidence exposed by GitLab.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum ChangedFileCount {
    Exact(u32),
    CappedAt(u32),
    Unavailable,
}

/// What can be proved about changed paths absent from the exact-version response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum UnrepresentedFileCount {
    Exact(u32),
    AtLeast(u32),
    Unknown,
}

/// GitLab's structural classification for a changed path.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Modified,
    Renamed,
    Added,
    Deleted,
}

/// Exact old/new provider paths and their structural relationship.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedPath {
    pub old_path: RepositoryPath,
    pub new_path: RepositoryPath,
    pub kind: FileChangeKind,
}

/// A structural contradiction between provider paths and a file-change classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangedPathIssue {
    SamePathRequired,
    DistinctPathsRequired,
}

/// Which immutable side of a changed path a blob belongs to.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobSide {
    Old,
    New,
}

/// The exact path and commit at which a repository blob must be acquired.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRequest {
    pub side: BlobSide,
    pub path: RepositoryPath,
    pub commit_sha: GitSha,
}

impl ChangedPath {
    /// Return a structural contradiction without normalizing provider paths.
    #[must_use]
    pub fn semantic_issue(&self) -> Option<ChangedPathIssue> {
        match self.kind {
            FileChangeKind::Renamed if self.old_path == self.new_path => {
                Some(ChangedPathIssue::DistinctPathsRequired)
            }
            FileChangeKind::Modified | FileChangeKind::Added | FileChangeKind::Deleted
                if self.old_path != self.new_path =>
            {
                Some(ChangedPathIssue::SamePathRequired)
            }
            FileChangeKind::Modified
            | FileChangeKind::Renamed
            | FileChangeKind::Added
            | FileChangeKind::Deleted => None,
        }
    }

    /// Derive the only valid full-blob requests for this change.
    ///
    /// Old content is always bound to `base_sha`; new content is always bound to
    /// `head_sha`. `start_sha` is intentionally not used for blob acquisition.
    #[must_use]
    pub fn expected_blobs(&self, refs: &DiffRefs) -> Vec<BlobRequest> {
        let old = BlobRequest {
            side: BlobSide::Old,
            path: self.old_path.clone(),
            commit_sha: refs.base_sha.clone(),
        };
        let new = BlobRequest {
            side: BlobSide::New,
            path: self.new_path.clone(),
            commit_sha: refs.head_sha.clone(),
        };
        match self.kind {
            FileChangeKind::Modified | FileChangeKind::Renamed => vec![old, new],
            FileChangeKind::Added => vec![new],
            FileChangeKind::Deleted => vec![old],
        }
    }
}

/// Availability of the exact GitLab diff text for one represented file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "digest")]
pub enum DiffAvailability {
    Available(Sha256Digest),
    Collapsed,
    TooLarge,
    Binary,
    Missing,
    Unknown,
}

/// A changed path and its exact-version diff availability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedFile {
    pub path: ChangedPath,
    pub diff: DiffAvailability,
}

/// Whether acquired bytes are the Git blob itself or an intentionally unexpanded LFS pointer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobRepresentation {
    FileContent,
    LfsPointer,
}

/// Identity of exact bytes retrieved for one expected old/new blob request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobIdentity {
    pub request: BlobRequest,
    pub blob_sha: GitSha,
    pub content_sha256: Sha256Digest,
    pub size_bytes: u64,
    pub representation: BlobRepresentation,
}

/// Why an exact expected blob was not made reviewable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobUnavailableReason {
    Missing,
    UnauthorizedPrivateFork,
    TooLarge,
    UnsupportedEncoding,
    SkippedByPolicy,
    FetchFailed,
}

/// Outcome for one exact old/new blob request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum BlobAcquisition {
    Acquired {
        identity: BlobIdentity,
    },
    Unavailable {
        request: BlobRequest,
        reason: BlobUnavailableReason,
    },
}

impl BlobAcquisition {
    fn request(&self) -> &BlobRequest {
        match self {
            Self::Acquired { identity } => &identity.request,
            Self::Unavailable { request, .. } => request,
        }
    }
}

/// A coverage loss that permits an honest partial snapshot but forbids a complete claim.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CoverageGap {
    DiffVersionOverflow,
    ReportedChangedFilesCapped {
        lower_bound: u32,
    },
    ReportedChangedFilesUnavailable,
    ReportedChangedFilesMismatch {
        reported: u32,
        represented: u32,
    },
    CurrentDiffPaginationIncomplete {
        reasons: Vec<PaginationIssue>,
    },
    CurrentDiffCountMismatch {
        current: u32,
        exact_version: u32,
    },
    CurrentDiffPathMismatch {
        only_current: u32,
        only_exact: u32,
    },
    DiffUnavailable {
        path: ChangedPath,
        reason: DiffUnavailableReason,
    },
    BlobNotObserved {
        request: BlobRequest,
    },
    BlobUnavailable {
        request: BlobRequest,
        reason: BlobUnavailableReason,
    },
    LfsPointerNotExpanded {
        request: BlobRequest,
    },
}

/// Stable classification for unavailable file diff text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffUnavailableReason {
    Collapsed,
    TooLarge,
    Binary,
    Missing,
    Unknown,
}

impl DiffAvailability {
    const fn unavailable_reason(&self) -> Option<DiffUnavailableReason> {
        match self {
            Self::Available(_) => None,
            Self::Collapsed => Some(DiffUnavailableReason::Collapsed),
            Self::TooLarge => Some(DiffUnavailableReason::TooLarge),
            Self::Binary => Some(DiffUnavailableReason::Binary),
            Self::Missing => Some(DiffUnavailableReason::Missing),
            Self::Unknown => Some(DiffUnavailableReason::Unknown),
        }
    }
}

/// A contradiction or state that prevents a trustworthy snapshot from existing.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SnapshotBlocker {
    DiffVersionWithoutFiles,
    UnknownDiffVersionState {
        value: String,
    },
    DuplicateExactChangedPath {
        path: ChangedPath,
    },
    DuplicateCurrentChangedPath {
        path: ChangedPath,
    },
    InvalidChangedPath {
        path: ChangedPath,
        reason: ChangedPathIssue,
    },
    DuplicateBlobEvidence {
        request: BlobRequest,
    },
    UnexpectedBlobEvidence {
        request: BlobRequest,
    },
    IncludedByteCountOverflow,
}

/// Pure evidence needed to determine whether an immutable snapshot is complete.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEvidence {
    pub identity: GitLabSnapshotIdentity,
    pub diff_version_state: DiffVersionState,
    pub reported_changed_files: ChangedFileCount,
    pub exact_version_files: Vec<ChangedFile>,
    pub current_diffs: PaginatedAcquisition<ChangedPath>,
    pub blobs: Vec<BlobAcquisition>,
}

/// Explicit result: complete, reviewable only as partial, or blocked by contradictions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SnapshotReadiness {
    Complete,
    Partial {
        reasons: Vec<CoverageGap>,
    },
    Blocked {
        reasons: Vec<SnapshotBlocker>,
        coverage_gaps: Vec<CoverageGap>,
    },
}

/// Deterministic counts and readiness derived from snapshot evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAssessment {
    pub readiness: SnapshotReadiness,
    pub files_represented: u32,
    pub files_reviewable: u32,
    pub represented_files_unreviewable: u32,
    pub unrepresented_files: UnrepresentedFileCount,
    pub blobs_expected: u32,
    pub blobs_included: u32,
    pub bytes_included: u64,
}

impl SnapshotEvidence {
    /// Assess independent identity, pagination, file, diff-limit, and blob evidence.
    #[must_use]
    pub fn assess(&self) -> SnapshotAssessment {
        let mut blockers = BTreeSet::new();
        let mut gaps = BTreeSet::new();
        let exact_count = self.assess_diff_evidence(&mut blockers, &mut gaps);
        let exact_paths = self.assess_exact_paths(&mut blockers, &mut gaps);
        self.assess_current_paths(exact_count, &exact_paths, &mut blockers, &mut gaps);
        let (expected_requests, observed) = self.assess_blobs(&mut blockers, &mut gaps);
        let (files_reviewable, blobs_included, bytes_included) =
            self.included_counts(&observed, &mut blockers);

        let files_represented = exact_count;
        let represented_files_unreviewable = files_represented.saturating_sub(files_reviewable);
        let unrepresented_files = self.unrepresented_files(exact_count);
        let blobs_expected = u32::try_from(expected_requests.len()).unwrap_or(u32::MAX);
        let readiness = if !blockers.is_empty() {
            SnapshotReadiness::Blocked {
                reasons: blockers.into_iter().collect(),
                coverage_gaps: gaps.into_iter().collect(),
            }
        } else if gaps.is_empty() {
            SnapshotReadiness::Complete
        } else {
            SnapshotReadiness::Partial {
                reasons: gaps.into_iter().collect(),
            }
        };

        SnapshotAssessment {
            readiness,
            files_represented,
            files_reviewable,
            represented_files_unreviewable,
            unrepresented_files,
            blobs_expected,
            blobs_included,
            bytes_included,
        }
    }

    fn assess_diff_evidence(
        &self,
        blockers: &mut BTreeSet<SnapshotBlocker>,
        gaps: &mut BTreeSet<CoverageGap>,
    ) -> u32 {
        match &self.diff_version_state {
            DiffVersionState::Collected => {}
            DiffVersionState::Overflow => {
                gaps.insert(CoverageGap::DiffVersionOverflow);
            }
            DiffVersionState::WithoutFiles => {
                blockers.insert(SnapshotBlocker::DiffVersionWithoutFiles);
            }
            DiffVersionState::Unknown(value) => {
                blockers.insert(SnapshotBlocker::UnknownDiffVersionState {
                    value: value.clone(),
                });
            }
        }

        let exact_count = u32::try_from(self.exact_version_files.len()).unwrap_or(u32::MAX);
        match self.reported_changed_files {
            ChangedFileCount::Exact(reported) if reported != exact_count => {
                gaps.insert(CoverageGap::ReportedChangedFilesMismatch {
                    reported,
                    represented: exact_count,
                });
            }
            ChangedFileCount::Exact(_) => {}
            ChangedFileCount::CappedAt(lower_bound) => {
                gaps.insert(CoverageGap::ReportedChangedFilesCapped { lower_bound });
            }
            ChangedFileCount::Unavailable => {
                gaps.insert(CoverageGap::ReportedChangedFilesUnavailable);
            }
        }

        if let PaginationCompleteness::Partial { reasons, .. } = self.current_diffs.completeness() {
            gaps.insert(CoverageGap::CurrentDiffPaginationIncomplete { reasons });
        }
        exact_count
    }

    fn assess_exact_paths(
        &self,
        blockers: &mut BTreeSet<SnapshotBlocker>,
        gaps: &mut BTreeSet<CoverageGap>,
    ) -> BTreeSet<ChangedPath> {
        let mut exact_paths = BTreeSet::new();
        for file in &self.exact_version_files {
            if let Some(reason) = file.path.semantic_issue() {
                blockers.insert(SnapshotBlocker::InvalidChangedPath {
                    path: file.path.clone(),
                    reason,
                });
            }
            if !exact_paths.insert(file.path.clone()) {
                blockers.insert(SnapshotBlocker::DuplicateExactChangedPath {
                    path: file.path.clone(),
                });
            }
            if let Some(reason) = file.diff.unavailable_reason() {
                gaps.insert(CoverageGap::DiffUnavailable {
                    path: file.path.clone(),
                    reason,
                });
            }
        }
        exact_paths
    }

    fn assess_current_paths(
        &self,
        exact_count: u32,
        exact_paths: &BTreeSet<ChangedPath>,
        blockers: &mut BTreeSet<SnapshotBlocker>,
        gaps: &mut BTreeSet<CoverageGap>,
    ) {
        let mut current_paths = BTreeSet::new();
        for path in &self.current_diffs.items {
            if let Some(reason) = path.semantic_issue() {
                blockers.insert(SnapshotBlocker::InvalidChangedPath {
                    path: path.clone(),
                    reason,
                });
            }
            if !current_paths.insert(path.clone()) {
                blockers
                    .insert(SnapshotBlocker::DuplicateCurrentChangedPath { path: path.clone() });
            }
        }
        let current_count = u32::try_from(self.current_diffs.items.len()).unwrap_or(u32::MAX);
        if current_count != exact_count {
            gaps.insert(CoverageGap::CurrentDiffCountMismatch {
                current: current_count,
                exact_version: exact_count,
            });
        }
        let only_current =
            u32::try_from(current_paths.difference(exact_paths).count()).unwrap_or(u32::MAX);
        let only_exact =
            u32::try_from(exact_paths.difference(&current_paths).count()).unwrap_or(u32::MAX);
        if only_current != 0 || only_exact != 0 {
            gaps.insert(CoverageGap::CurrentDiffPathMismatch {
                only_current,
                only_exact,
            });
        }
    }

    fn assess_blobs<'a>(
        &'a self,
        blockers: &mut BTreeSet<SnapshotBlocker>,
        gaps: &mut BTreeSet<CoverageGap>,
    ) -> (
        BTreeSet<BlobRequest>,
        BTreeMap<BlobRequest, &'a BlobAcquisition>,
    ) {
        let refs = &self.identity.version.diff_version.refs;
        let mut expected_requests = BTreeSet::new();
        for file in &self.exact_version_files {
            expected_requests.extend(file.path.expected_blobs(refs));
        }

        let mut observed = BTreeMap::new();
        for acquisition in &self.blobs {
            let request = acquisition.request().clone();
            if !expected_requests.contains(&request) {
                blockers.insert(SnapshotBlocker::UnexpectedBlobEvidence { request });
            } else if observed.insert(request.clone(), acquisition).is_some() {
                blockers.insert(SnapshotBlocker::DuplicateBlobEvidence { request });
            }
        }

        for request in &expected_requests {
            match observed.get(request) {
                None => {
                    gaps.insert(CoverageGap::BlobNotObserved {
                        request: request.clone(),
                    });
                }
                Some(BlobAcquisition::Unavailable { reason, .. }) => {
                    gaps.insert(CoverageGap::BlobUnavailable {
                        request: request.clone(),
                        reason: *reason,
                    });
                }
                Some(BlobAcquisition::Acquired { identity })
                    if identity.representation == BlobRepresentation::LfsPointer =>
                {
                    gaps.insert(CoverageGap::LfsPointerNotExpanded {
                        request: request.clone(),
                    });
                }
                Some(BlobAcquisition::Acquired { .. }) => {}
            }
        }
        (expected_requests, observed)
    }

    fn included_counts(
        &self,
        observed: &BTreeMap<BlobRequest, &BlobAcquisition>,
        blockers: &mut BTreeSet<SnapshotBlocker>,
    ) -> (u32, u32, u64) {
        let refs = &self.identity.version.diff_version.refs;
        let mut files_reviewable = 0_u32;
        for file in &self.exact_version_files {
            let requests = file.path.expected_blobs(refs);
            let diff_available = matches!(file.diff, DiffAvailability::Available(_));
            let all_blobs_reviewable = requests.iter().all(|request| {
                matches!(
                    observed.get(request),
                    Some(BlobAcquisition::Acquired { identity })
                        if identity.representation == BlobRepresentation::FileContent
                )
            });
            if diff_available && all_blobs_reviewable {
                files_reviewable = files_reviewable.saturating_add(1);
            }
        }

        let mut blobs_included = 0_u32;
        let mut bytes_included = 0_u64;
        for acquisition in observed.values() {
            if let BlobAcquisition::Acquired { identity } = acquisition {
                blobs_included = blobs_included.saturating_add(1);
                if let Some(total) = bytes_included.checked_add(identity.size_bytes) {
                    bytes_included = total;
                } else {
                    blockers.insert(SnapshotBlocker::IncludedByteCountOverflow);
                    bytes_included = u64::MAX;
                }
            }
        }
        (files_reviewable, blobs_included, bytes_included)
    }

    const fn unrepresented_files(&self, represented: u32) -> UnrepresentedFileCount {
        match self.reported_changed_files {
            ChangedFileCount::Exact(reported) if reported >= represented => {
                UnrepresentedFileCount::Exact(reported - represented)
            }
            ChangedFileCount::Exact(_) | ChangedFileCount::Unavailable => {
                UnrepresentedFileCount::Unknown
            }
            ChangedFileCount::CappedAt(lower_bound) => {
                UnrepresentedFileCount::AtLeast(lower_bound.saturating_sub(represented))
            }
        }
    }
}

/// A valid single-line GitLab text-diff position.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AnchorPosition {
    Addition { new_line: u32 },
    Deletion { old_line: u32 },
    Context { old_line: u32, new_line: u32 },
}

/// Error returned when a purported commentable position uses line zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAnchorPosition;

impl AnchorPosition {
    /// Construct an addition position.
    ///
    /// # Errors
    ///
    /// Rejects GitLab's invalid line number zero.
    pub const fn addition(new_line: u32) -> Result<Self, InvalidAnchorPosition> {
        if new_line == 0 {
            Err(InvalidAnchorPosition)
        } else {
            Ok(Self::Addition { new_line })
        }
    }

    /// Construct a deletion position.
    ///
    /// # Errors
    ///
    /// Rejects GitLab's invalid line number zero.
    pub const fn deletion(old_line: u32) -> Result<Self, InvalidAnchorPosition> {
        if old_line == 0 {
            Err(InvalidAnchorPosition)
        } else {
            Ok(Self::Deletion { old_line })
        }
    }

    /// Construct an unchanged context position.
    ///
    /// # Errors
    ///
    /// Rejects either GitLab line number when it is zero.
    pub const fn context(old_line: u32, new_line: u32) -> Result<Self, InvalidAnchorPosition> {
        if old_line == 0 || new_line == 0 {
            Err(InvalidAnchorPosition)
        } else {
            Ok(Self::Context { old_line, new_line })
        }
    }

    const fn valid(self) -> bool {
        match self {
            Self::Addition { new_line } => new_line != 0,
            Self::Deletion { old_line } => old_line != 0,
            Self::Context { old_line, new_line } => old_line != 0 && new_line != 0,
        }
    }
}

/// Trusted parser output for one commentable hunk line.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommentableLine {
    pub path: ChangedPath,
    pub position: AnchorPosition,
    pub exact_line_digest: Sha256Digest,
    pub context_digest: Sha256Digest,
}

/// A deterministic opaque ID. It carries no path or line coordinate in plaintext.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AnchorId(String);

impl AnchorId {
    /// Return the opaque identifier for schema output and allowlist lookup.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for AnchorId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AnchorId {
    type Error = HexIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let Some(digest) = value.strip_prefix(ANCHOR_PREFIX) else {
            return Err(HexIdentityError::Length);
        };
        if digest.len() != SHA256_HEX_LEN {
            return Err(HexIdentityError::Length);
        }
        if !is_lower_hex(digest) {
            return Err(HexIdentityError::Character);
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for AnchorId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// One allowlisted opaque anchor and the exact trusted GitLab position it resolves to.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedAnchor {
    pub id: AnchorId,
    pub path: ChangedPath,
    pub position: AnchorPosition,
    pub exact_line_digest: Sha256Digest,
    pub context_digest: Sha256Digest,
}

impl TrustedAnchor {
    fn line(&self) -> CommentableLine {
        CommentableLine {
            path: self.path.clone(),
            position: self.position,
            exact_line_digest: self.exact_line_digest.clone(),
            context_digest: self.context_digest.clone(),
        }
    }
}

/// Why a trusted anchor table cannot be constructed or replayed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnchorTableError {
    InvalidPosition,
    InvalidChangedPath,
    PositionIncompatibleWithFileChange,
    DuplicateCoordinate,
    DuplicateAnchorId,
    IdentityMismatch,
}

impl fmt::Display for AnchorTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPosition => formatter.write_str("anchor position contains line zero"),
            Self::InvalidChangedPath => {
                formatter.write_str("anchor contains contradictory changed-path semantics")
            }
            Self::PositionIncompatibleWithFileChange => {
                formatter.write_str("anchor position is incompatible with the file change")
            }
            Self::DuplicateCoordinate => {
                formatter.write_str("anchor table contains a duplicate coordinate")
            }
            Self::DuplicateAnchorId => {
                formatter.write_str("anchor table contains a duplicate identifier")
            }
            Self::IdentityMismatch => {
                formatter.write_str("anchor identifier does not match its snapshot identity")
            }
        }
    }
}

/// Complete allowlist from opaque IDs to trusted positions for one immutable snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorTable {
    identity: ReviewSnapshotIdentity,
    anchors: Vec<TrustedAnchor>,
}

impl AnchorTable {
    /// Build one anchor for every trusted commentable-line record.
    ///
    /// # Errors
    ///
    /// Rejects zero lines, duplicate coordinates, or the cryptographically improbable
    /// duplicate identifier instead of silently dropping an anchor.
    pub fn build(
        identity: impl Into<ReviewSnapshotIdentity>,
        lines: impl IntoIterator<Item = CommentableLine>,
    ) -> Result<Self, AnchorTableError> {
        let identity = identity.into();
        let anchors = lines
            .into_iter()
            .map(|line| TrustedAnchor {
                id: derive_anchor_id(&identity, &line),
                path: line.path,
                position: line.position,
                exact_line_digest: line.exact_line_digest,
                context_digest: line.context_digest,
            })
            .collect();
        Self::from_anchors(identity, anchors)
    }

    /// Validate and restore a serialized trusted anchor table.
    ///
    /// # Errors
    ///
    /// Rejects invalid positions, duplicate coordinates or IDs, and any ID which does
    /// not recompute from the supplied immutable snapshot identity and anchor content.
    pub fn from_anchors(
        identity: impl Into<ReviewSnapshotIdentity>,
        mut anchors: Vec<TrustedAnchor>,
    ) -> Result<Self, AnchorTableError> {
        let identity = identity.into();
        let mut coordinates = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for anchor in &anchors {
            if !anchor.position.valid() {
                return Err(AnchorTableError::InvalidPosition);
            }
            if anchor.path.semantic_issue().is_some() {
                return Err(AnchorTableError::InvalidChangedPath);
            }
            let compatible = match (anchor.path.kind, anchor.position) {
                (FileChangeKind::Added, AnchorPosition::Addition { .. })
                | (FileChangeKind::Deleted, AnchorPosition::Deletion { .. })
                | (FileChangeKind::Modified | FileChangeKind::Renamed, _) => true,
                (
                    FileChangeKind::Added,
                    AnchorPosition::Deletion { .. } | AnchorPosition::Context { .. },
                )
                | (
                    FileChangeKind::Deleted,
                    AnchorPosition::Addition { .. } | AnchorPosition::Context { .. },
                ) => false,
            };
            if !compatible {
                return Err(AnchorTableError::PositionIncompatibleWithFileChange);
            }
            if !coordinates.insert((anchor.path.clone(), anchor.position)) {
                return Err(AnchorTableError::DuplicateCoordinate);
            }
            if !ids.insert(anchor.id.clone()) {
                return Err(AnchorTableError::DuplicateAnchorId);
            }
            if anchor.id != derive_anchor_id(&identity, &anchor.line()) {
                return Err(AnchorTableError::IdentityMismatch);
            }
        }
        anchors.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Self { identity, anchors })
    }

    /// Return the immutable snapshot identity to which every anchor is bound.
    #[must_use]
    pub const fn identity(&self) -> &ReviewSnapshotIdentity {
        &self.identity
    }

    /// Resolve only an allowlisted opaque anchor ID.
    #[must_use]
    pub fn resolve(&self, id: &str) -> Option<&TrustedAnchor> {
        self.anchors
            .binary_search_by(|anchor| anchor.id.as_str().cmp(id))
            .ok()
            .map(|index| &self.anchors[index])
    }

    /// Iterate in deterministic opaque-ID order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &TrustedAnchor> {
        self.anchors.iter()
    }

    /// Return the number of allowlisted positions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Return whether the snapshot contains no commentable positions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorTableWire {
    identity: ReviewSnapshotIdentity,
    anchors: Vec<TrustedAnchor>,
}

impl<'de> Deserialize<'de> for AnchorTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AnchorTableWire::deserialize(deserializer)?;
        Self::from_anchors(wire.identity, wire.anchors).map_err(serde::de::Error::custom)
    }
}

fn derive_anchor_id(identity: &ReviewSnapshotIdentity, line: &CommentableLine) -> AnchorId {
    let mut hasher = Sha256::new();
    hash_snapshot_identity(&mut hasher, identity);
    hash_field(&mut hasher, line.path.old_path.as_str().as_bytes());
    hash_field(&mut hasher, line.path.new_path.as_str().as_bytes());
    let change_kind = match line.path.kind {
        FileChangeKind::Modified => b"modified".as_slice(),
        FileChangeKind::Renamed => b"renamed".as_slice(),
        FileChangeKind::Added => b"added".as_slice(),
        FileChangeKind::Deleted => b"deleted".as_slice(),
    };
    hash_field(&mut hasher, change_kind);
    match line.position {
        AnchorPosition::Addition { new_line } => {
            hash_field(&mut hasher, b"addition");
            hash_field(&mut hasher, &new_line.to_be_bytes());
        }
        AnchorPosition::Deletion { old_line } => {
            hash_field(&mut hasher, b"deletion");
            hash_field(&mut hasher, &old_line.to_be_bytes());
        }
        AnchorPosition::Context { old_line, new_line } => {
            hash_field(&mut hasher, b"context");
            hash_field(&mut hasher, &old_line.to_be_bytes());
            hash_field(&mut hasher, &new_line.to_be_bytes());
        }
    }
    hash_field(&mut hasher, line.exact_line_digest.as_str().as_bytes());
    hash_field(&mut hasher, line.context_digest.as_str().as_bytes());
    AnchorId(format!("{ANCHOR_PREFIX}{:x}", hasher.finalize()))
}

fn hash_snapshot_identity(hasher: &mut Sha256, identity: &ReviewSnapshotIdentity) {
    match identity {
        ReviewSnapshotIdentity::GitLab(identity) => {
            hash_field(hasher, b"revoot-gitlab-anchor-v1");
            hash_field(
                hasher,
                identity
                    .version
                    .scope
                    .instance_origin_digest
                    .as_str()
                    .as_bytes(),
            );
            hash_field(
                hasher,
                &identity.version.scope.project_id.get().to_be_bytes(),
            );
            hash_field(
                hasher,
                &identity.version.scope.merge_request_iid.get().to_be_bytes(),
            );
            hash_field(
                hasher,
                &identity.version.diff_version.id.get().to_be_bytes(),
            );
            let refs = &identity.version.diff_version.refs;
            hash_field(hasher, refs.base_sha.as_str().as_bytes());
            hash_field(hasher, refs.start_sha.as_str().as_bytes());
            hash_field(hasher, refs.head_sha.as_str().as_bytes());
            hash_field(
                hasher,
                identity.exact_diff_manifest_sha256.as_str().as_bytes(),
            );
        }
        ReviewSnapshotIdentity::GitHub(identity) => {
            hash_field(hasher, b"revoot-github-anchor-v1");
            hash_field(hasher, identity.api_origin_digest.as_str().as_bytes());
            hash_field(hasher, &identity.repository_id.get().to_be_bytes());
            hash_field(hasher, &identity.pull_request_number.get().to_be_bytes());
            hash_field(hasher, identity.base_sha.as_str().as_bytes());
            hash_field(hasher, identity.head_sha.as_str().as_bytes());
            hash_field(
                hasher,
                identity.exact_diff_manifest_sha256.as_str().as_bytes(),
            );
        }
        ReviewSnapshotIdentity::Local(identity) => {
            hash_field(hasher, b"revoot-local-anchor-v1");
            hash_field(
                hasher,
                identity.repository_identity_sha256.as_str().as_bytes(),
            );
            hash_field(hasher, identity.base_sha.as_str().as_bytes());
            hash_field(hasher, identity.head_sha.as_str().as_bytes());
            hash_field(hasher, identity.working_tree_sha256.as_str().as_bytes());
            hash_field(
                hasher,
                identity.exact_diff_manifest_sha256.as_str().as_bytes(),
            );
        }
    }
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(character: char) -> GitSha {
        GitSha::try_from(character.to_string().repeat(40)).unwrap()
    }

    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::try_from(character.to_string().repeat(64)).unwrap()
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn refs() -> DiffRefs {
        DiffRefs {
            base_sha: sha('a'),
            start_sha: sha('b'),
            head_sha: sha('c'),
        }
    }

    fn scope() -> SnapshotScope {
        SnapshotScope {
            instance_origin_digest: digest('d'),
            project_id: ProjectId::try_from(42).unwrap(),
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
        }
    }

    fn version_identity() -> GitLabDiffVersionIdentity {
        GitLabDiffVersionIdentity {
            scope: scope(),
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(9).unwrap(),
                refs: refs(),
            },
        }
    }

    fn identity() -> GitLabSnapshotIdentity {
        version_identity().freeze(digest('0'))
    }

    fn changed_path(kind: FileChangeKind, old: &str, new: &str) -> ChangedPath {
        ChangedPath {
            old_path: path(old),
            new_path: path(new),
            kind,
        }
    }

    fn available_file(path: ChangedPath, marker: char) -> ChangedFile {
        ChangedFile {
            path,
            diff: DiffAvailability::Available(digest(marker)),
        }
    }

    fn acquired(request: BlobRequest, marker: char, size_bytes: u64) -> BlobAcquisition {
        BlobAcquisition::Acquired {
            identity: BlobIdentity {
                request,
                blob_sha: sha(marker),
                content_sha256: digest(marker),
                size_bytes,
                representation: BlobRepresentation::FileContent,
            },
        }
    }

    #[test]
    fn strict_identity_scalars_reject_ambiguous_values_during_deserialization() {
        assert!(GitSha::try_from("A".repeat(40)).is_err());
        assert!(GitSha::try_from("a".repeat(39)).is_err());
        assert!(Sha256Digest::try_from("a".repeat(63)).is_err());
        assert!(ProjectId::try_from(0).is_err());
        assert!(RepositoryPath::try_from(String::new()).is_err());
        assert!(serde_json::from_str::<GitSha>(&format!("\"{}\"", "z".repeat(40))).is_err());
        assert!(serde_json::from_str::<ProjectId>("0").is_err());
    }

    #[test]
    fn pagination_requires_a_contiguous_sequence_and_observed_terminal_page() {
        let complete = PaginatedAcquisition {
            items: vec![1, 2, 3],
            pages: vec![
                PageReceipt {
                    page_number: 1,
                    item_count: 2,
                    has_next_page: true,
                },
                PageReceipt {
                    page_number: 2,
                    item_count: 1,
                    has_next_page: false,
                },
            ],
        };
        assert_eq!(
            complete.completeness(),
            PaginationCompleteness::Complete { pages: 2, items: 3 }
        );

        let partial = PaginatedAcquisition {
            items: vec![1],
            pages: vec![PageReceipt {
                page_number: 1,
                item_count: 2,
                has_next_page: true,
            }],
        };
        let PaginationCompleteness::Partial { reasons, .. } = partial.completeness() else {
            panic!("pagination must be partial");
        };
        assert!(reasons.contains(&PaginationIssue::ContinuationNotFetched { after_page: 1 }));
        assert!(reasons.contains(&PaginationIssue::ItemCountMismatch {
            receipts: 2,
            observed: 1,
        }));
    }

    #[test]
    fn binding_requires_full_pagination_newest_order_and_exact_triple() {
        let versions = PaginatedAcquisition {
            items: vec![
                DiffVersionRecord {
                    id: DiffVersionId::try_from(9).unwrap(),
                    refs: refs(),
                },
                DiffVersionRecord {
                    id: DiffVersionId::try_from(8).unwrap(),
                    refs: DiffRefs {
                        base_sha: sha('1'),
                        start_sha: sha('2'),
                        head_sha: sha('3'),
                    },
                },
            ],
            pages: vec![PageReceipt {
                page_number: 1,
                item_count: 2,
                has_next_page: false,
            }],
        };
        assert_eq!(
            bind_latest_snapshot(scope(), Some(&refs()), &versions),
            SnapshotBinding::Bound {
                identity: version_identity()
            }
        );

        let stale_refs = DiffRefs {
            head_sha: sha('f'),
            ..refs()
        };
        let SnapshotBinding::Blocked { reasons } =
            bind_latest_snapshot(scope(), Some(&stale_refs), &versions)
        else {
            panic!("mismatched head must block binding");
        };
        assert!(matches!(
            reasons.as_slice(),
            [IdentityBlocker::LatestDiffRefsMismatch { .. }]
        ));
    }

    #[test]
    fn binding_blocks_unprepared_refs_and_unfinished_version_pagination() {
        let versions = PaginatedAcquisition {
            items: vec![DiffVersionRecord {
                id: DiffVersionId::try_from(9).unwrap(),
                refs: refs(),
            }],
            pages: vec![PageReceipt {
                page_number: 1,
                item_count: 1,
                has_next_page: true,
            }],
        };
        let SnapshotBinding::Blocked { reasons } = bind_latest_snapshot(scope(), None, &versions)
        else {
            panic!("unprepared refs must block binding");
        };
        assert!(reasons.contains(&IdentityBlocker::MergeRequestDiffRefsNotPrepared));
        assert!(reasons.iter().any(|reason| matches!(
            reason,
            IdentityBlocker::DiffVersionsPaginationIncomplete { .. }
        )));
    }

    #[test]
    fn blob_requests_use_base_for_old_head_for_new_and_never_start() {
        let cases = [
            (
                changed_path(FileChangeKind::Modified, "old.rs", "new.rs"),
                vec![BlobSide::Old, BlobSide::New],
            ),
            (
                changed_path(FileChangeKind::Renamed, "before.rs", "after.rs"),
                vec![BlobSide::Old, BlobSide::New],
            ),
            (
                changed_path(FileChangeKind::Added, "added.rs", "added.rs"),
                vec![BlobSide::New],
            ),
            (
                changed_path(FileChangeKind::Deleted, "gone.rs", "gone.rs"),
                vec![BlobSide::Old],
            ),
        ];

        for (changed, expected_sides) in cases {
            let requests = changed.expected_blobs(&refs());
            assert_eq!(
                requests
                    .iter()
                    .map(|request| request.side)
                    .collect::<Vec<_>>(),
                expected_sides
            );
            for request in requests {
                match request.side {
                    BlobSide::Old => assert_eq!(request.commit_sha, refs().base_sha),
                    BlobSide::New => assert_eq!(request.commit_sha, refs().head_sha),
                }
                assert_ne!(request.commit_sha, refs().start_sha);
            }
        }
    }

    #[test]
    fn complete_snapshot_requires_matching_inventory_and_every_exact_blob() {
        let modified = changed_path(FileChangeKind::Modified, "src/lib.rs", "src/lib.rs");
        let added = changed_path(FileChangeKind::Added, "src/new.rs", "src/new.rs");
        let files = vec![
            available_file(modified.clone(), '1'),
            available_file(added.clone(), '2'),
        ];
        let requests = files
            .iter()
            .flat_map(|file| file.path.expected_blobs(&refs()))
            .collect::<Vec<_>>();
        let evidence = SnapshotEvidence {
            identity: identity(),
            diff_version_state: DiffVersionState::Collected,
            reported_changed_files: ChangedFileCount::Exact(2),
            exact_version_files: files,
            current_diffs: PaginatedAcquisition {
                items: vec![modified, added],
                pages: vec![PageReceipt {
                    page_number: 1,
                    item_count: 2,
                    has_next_page: false,
                }],
            },
            blobs: requests
                .into_iter()
                .zip(['3', '4', '5'])
                .map(|(request, marker)| acquired(request, marker, 10))
                .collect(),
        };

        assert_eq!(
            evidence.assess(),
            SnapshotAssessment {
                readiness: SnapshotReadiness::Complete,
                files_represented: 2,
                files_reviewable: 2,
                represented_files_unreviewable: 0,
                unrepresented_files: UnrepresentedFileCount::Exact(0),
                blobs_expected: 3,
                blobs_included: 3,
                bytes_included: 30,
            }
        );
    }

    #[test]
    fn overflow_collapsed_and_missing_blob_are_explicit_partial_coverage() {
        let modified = changed_path(FileChangeKind::Modified, "src/lib.rs", "src/lib.rs");
        let requests = modified.expected_blobs(&refs());
        let evidence = SnapshotEvidence {
            identity: identity(),
            diff_version_state: DiffVersionState::Overflow,
            reported_changed_files: ChangedFileCount::CappedAt(1_000),
            exact_version_files: vec![ChangedFile {
                path: modified.clone(),
                diff: DiffAvailability::Collapsed,
            }],
            current_diffs: PaginatedAcquisition {
                items: vec![modified],
                pages: vec![PageReceipt {
                    page_number: 1,
                    item_count: 1,
                    has_next_page: true,
                }],
            },
            blobs: vec![acquired(requests[0].clone(), '4', 10)],
        };

        let assessment = evidence.assess();
        let SnapshotReadiness::Partial { reasons } = assessment.readiness else {
            panic!("limited evidence must remain explicitly partial");
        };
        assert!(reasons.contains(&CoverageGap::DiffVersionOverflow));
        assert!(reasons.contains(&CoverageGap::ReportedChangedFilesCapped { lower_bound: 1_000 }));
        assert!(
            reasons.iter().any(|reason| matches!(
                reason,
                CoverageGap::CurrentDiffPaginationIncomplete { .. }
            ))
        );
        assert!(reasons.contains(&CoverageGap::DiffUnavailable {
            path: evidence.exact_version_files[0].path.clone(),
            reason: DiffUnavailableReason::Collapsed,
        }));
        assert!(reasons.contains(&CoverageGap::BlobNotObserved {
            request: requests[1].clone(),
        }));
        assert_eq!(assessment.files_reviewable, 0);
        assert_eq!(assessment.represented_files_unreviewable, 1);
        assert_eq!(
            assessment.unrepresented_files,
            UnrepresentedFileCount::AtLeast(999)
        );
        assert_eq!(assessment.blobs_included, 1);
        assert_eq!(assessment.bytes_included, 10);
    }

    #[test]
    fn contradictory_blob_evidence_blocks_instead_of_overstating_coverage() {
        let added = changed_path(FileChangeKind::Added, "new.rs", "new.rs");
        let expected = added.expected_blobs(&refs())[0].clone();
        let unexpected = BlobRequest {
            path: path("other.rs"),
            ..expected.clone()
        };
        let evidence = SnapshotEvidence {
            identity: identity(),
            diff_version_state: DiffVersionState::Collected,
            reported_changed_files: ChangedFileCount::Exact(1),
            exact_version_files: vec![available_file(added.clone(), '5')],
            current_diffs: PaginatedAcquisition {
                items: vec![added],
                pages: vec![PageReceipt {
                    page_number: 1,
                    item_count: 1,
                    has_next_page: false,
                }],
            },
            blobs: vec![
                acquired(expected.clone(), '6', 20),
                acquired(unexpected.clone(), '7', 20),
            ],
        };

        let SnapshotReadiness::Blocked { reasons, .. } = evidence.assess().readiness else {
            panic!("unexpected blob evidence must block");
        };
        assert!(reasons.contains(&SnapshotBlocker::UnexpectedBlobEvidence {
            request: unexpected,
        }));
    }

    #[test]
    fn contradictory_changed_path_blocks_snapshot_and_anchor_construction() {
        let invalid = changed_path(FileChangeKind::Renamed, "same.rs", "same.rs");
        assert_eq!(
            invalid.semantic_issue(),
            Some(ChangedPathIssue::DistinctPathsRequired)
        );
        let request = invalid.expected_blobs(&refs())[0].clone();
        let evidence = SnapshotEvidence {
            identity: identity(),
            diff_version_state: DiffVersionState::Collected,
            reported_changed_files: ChangedFileCount::Exact(1),
            exact_version_files: vec![available_file(invalid.clone(), '8')],
            current_diffs: PaginatedAcquisition {
                items: vec![invalid.clone()],
                pages: vec![PageReceipt {
                    page_number: 1,
                    item_count: 1,
                    has_next_page: false,
                }],
            },
            blobs: vec![acquired(request, '9', 10)],
        };
        let SnapshotReadiness::Blocked { reasons, .. } = evidence.assess().readiness else {
            panic!("contradictory path semantics must block");
        };
        assert!(reasons.contains(&SnapshotBlocker::InvalidChangedPath {
            path: invalid.clone(),
            reason: ChangedPathIssue::DistinctPathsRequired,
        }));

        let line = CommentableLine {
            path: invalid,
            position: AnchorPosition::addition(1).unwrap(),
            exact_line_digest: digest('a'),
            context_digest: digest('b'),
        };
        assert_eq!(
            AnchorTable::build(identity(), vec![line]),
            Err(AnchorTableError::InvalidChangedPath)
        );
    }

    #[test]
    fn anchor_position_must_be_possible_for_the_file_change() {
        let line = CommentableLine {
            path: changed_path(FileChangeKind::Added, "new.rs", "new.rs"),
            position: AnchorPosition::deletion(1).unwrap(),
            exact_line_digest: digest('a'),
            context_digest: digest('b'),
        };
        assert_eq!(
            AnchorTable::build(identity(), vec![line]),
            Err(AnchorTableError::PositionIncompatibleWithFileChange)
        );
    }

    #[test]
    fn opaque_anchors_are_deterministic_bound_and_shape_preserving() {
        let changed = changed_path(FileChangeKind::Modified, "src/lib.rs", "src/lib.rs");
        let lines = vec![
            CommentableLine {
                path: changed.clone(),
                position: AnchorPosition::addition(14).unwrap(),
                exact_line_digest: digest('8'),
                context_digest: digest('9'),
            },
            CommentableLine {
                path: changed,
                position: AnchorPosition::context(12, 13).unwrap(),
                exact_line_digest: digest('a'),
                context_digest: digest('b'),
            },
        ];
        let first = AnchorTable::build(identity(), lines.clone()).unwrap();
        let second = AnchorTable::build(identity(), lines).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_eq!(
            first.iter().next().unwrap().id.as_str(),
            "ga1_71e9c05e50fe6e97fb17d246f7a3b59ce4582fc9ebcde334e038c282cdb7a435"
        );

        for anchor in first.iter() {
            assert!(anchor.id.as_str().starts_with(ANCHOR_PREFIX));
            assert!(!anchor.id.as_str().contains("src"));
            assert_eq!(first.resolve(anchor.id.as_str()), Some(anchor));
        }

        let serialized = serde_json::to_vec(&first).unwrap();
        let replayed: AnchorTable = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(first, replayed);
    }

    #[test]
    fn anchor_identity_changes_with_snapshot_or_line_context() {
        let changed = changed_path(FileChangeKind::Added, "src/new.rs", "src/new.rs");
        let line = CommentableLine {
            path: changed,
            position: AnchorPosition::addition(3).unwrap(),
            exact_line_digest: digest('c'),
            context_digest: digest('d'),
        };
        let original = AnchorTable::build(identity(), vec![line.clone()]).unwrap();
        let mut other_identity = identity();
        other_identity.version.diff_version.refs.head_sha = sha('e');
        let other_snapshot = AnchorTable::build(other_identity, vec![line.clone()]).unwrap();
        assert_ne!(
            original.iter().next().unwrap().id,
            other_snapshot.iter().next().unwrap().id
        );

        let mut other_manifest = identity();
        other_manifest.exact_diff_manifest_sha256 = digest('e');
        let other_manifest = AnchorTable::build(other_manifest, vec![line.clone()]).unwrap();
        assert_ne!(
            original.iter().next().unwrap().id,
            other_manifest.iter().next().unwrap().id
        );

        let mut other_line = line;
        other_line.context_digest = digest('f');
        let other_context = AnchorTable::build(identity(), vec![other_line]).unwrap();
        assert_ne!(
            original.iter().next().unwrap().id,
            other_context.iter().next().unwrap().id
        );
    }

    #[test]
    fn local_snapshot_round_trip_and_working_state_bind_anchor_identity() {
        let local = LocalSnapshotIdentity {
            repository_identity_sha256: digest('1'),
            base_sha: sha('a'),
            head_sha: sha('b'),
            working_tree_sha256: digest('2'),
            exact_diff_manifest_sha256: digest('3'),
        };
        let identity = ReviewSnapshotIdentity::Local(local.clone());
        let replayed: ReviewSnapshotIdentity =
            serde_json::from_slice(&serde_json::to_vec(&identity).unwrap()).unwrap();
        assert_eq!(replayed, identity);

        let line = CommentableLine {
            path: changed_path(FileChangeKind::Modified, "src/lib.rs", "src/lib.rs"),
            position: AnchorPosition::addition(2).unwrap(),
            exact_line_digest: digest('4'),
            context_digest: digest('5'),
        };
        let first = AnchorTable::build(local.clone(), [line.clone()]).unwrap();
        let mut changed_state = local;
        changed_state.working_tree_sha256 = digest('6');
        let second = AnchorTable::build(changed_state, [line]).unwrap();
        assert_ne!(
            first.iter().next().unwrap().id,
            second.iter().next().unwrap().id
        );
    }

    #[test]
    fn anchor_table_rejects_duplicate_coordinates_and_tampered_replay() {
        let line = CommentableLine {
            path: changed_path(FileChangeKind::Added, "src/new.rs", "src/new.rs"),
            position: AnchorPosition::addition(3).unwrap(),
            exact_line_digest: digest('1'),
            context_digest: digest('2'),
        };
        assert_eq!(
            AnchorTable::build(identity(), vec![line.clone(), line]),
            Err(AnchorTableError::DuplicateCoordinate)
        );

        let table = AnchorTable::build(
            identity(),
            vec![CommentableLine {
                path: changed_path(FileChangeKind::Deleted, "gone.rs", "gone.rs"),
                position: AnchorPosition::deletion(4).unwrap(),
                exact_line_digest: digest('3'),
                context_digest: digest('4'),
            }],
        )
        .unwrap();
        let mut value = serde_json::to_value(table).unwrap();
        value["identity"]["version"]["diff_version"]["refs"]["head_sha"] =
            serde_json::Value::String("f".repeat(40));
        assert!(serde_json::from_value::<AnchorTable>(value).is_err());
    }
}
