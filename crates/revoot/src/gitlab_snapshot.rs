//! Authenticated, read-only GitLab merge-request snapshot acquisition.
//!
//! This controller composes the hardened GET-only transport with strict wire
//! validation and the pure snapshot domain. It performs no Git execution,
//! filesystem access, publication, mutation, or credential discovery. The
//! controller owns bounded preparation polling and retry of transport failures
//! that the read adapter explicitly classifies as safe to replay.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::time::Duration;

use revoot_core::{
    AuthoritativeGitLabMergeRequest, BlobAcquisition, BlobSide, BlobUnavailableReason, ChangedFile,
    ChangedFileCount, ChangedPath, DiffVersionRecord, GitLabPage, GitLabSnapshotIdentity,
    GitLabVerificationInput, GitLabVerificationMismatch, GitLabVerificationResult, GitLabWireError,
    GitLabWireLimits, IdentityBlocker, PaginatedAcquisition, ProjectId, Sha256Digest,
    SnapshotAssessment, SnapshotBinding, SnapshotEvidence, SnapshotReadiness, SnapshotScope,
    ValidatedChangedFile, ValidatedDiffVersion, ValidatedMergeRequestMetadata, ValidatedRawBlob,
    VerifiedGitLabContext, bind_latest_snapshot, collect_complete_pages, parse_changed_files_page,
    parse_diff_versions_page, parse_exact_diff_version_response, parse_merge_request_response,
    parse_project_response, parse_raw_blob_response,
};
use serde::Serialize;

use crate::gitlab_transport::{
    GitLabEndpointError, GitLabFailureKind, GitLabPagination, GitLabReadClient, GitLabReadEndpoint,
    GitLabRetryMetadata, GitLabTransportError,
};

const MAX_PER_PAGE: u32 = 100;
const HARD_MAX_BLOB_REQUESTS: u32 = 1_000_000;
const HARD_MAX_TOTAL_BLOB_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_MAX_TOTAL_REQUESTS: u32 = 1_100_000;
const HARD_MAX_ACQUISITION_TIMEOUT: Duration = Duration::from_hours(24);
const HARD_MAX_READ_ATTEMPTS: u8 = 16;
const HARD_MAX_PREPARATION_POLLS: u8 = 64;
const HARD_MAX_RETRY_DELAY: Duration = Duration::from_mins(5);
const EXACT_DIFF_MANIFEST_SCHEMA: &str = "revoot.gitlab-exact-diff-manifest.v1";

/// Bounded controller-owned policy for safe GET replay and async preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabSnapshotRetryPolicy {
    /// Total attempts for one GET, including the first attempt.
    pub max_read_attempts: u8,
    /// Total observations of an asynchronously prepared resource.
    pub max_preparation_polls: u8,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_retry_after: Duration,
}

impl Default for GitLabSnapshotRetryPolicy {
    fn default() -> Self {
        Self {
            max_read_attempts: 3,
            max_preparation_polls: 8,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(30),
        }
    }
}

/// Controller-level request and retained-content limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabSnapshotAcquisitionLimits {
    pub wire: GitLabWireLimits,
    pub per_page: u32,
    pub max_blob_requests: u32,
    pub max_total_blob_bytes: u64,
    pub max_total_requests: u32,
    pub acquisition_timeout: Duration,
    pub retry: GitLabSnapshotRetryPolicy,
}

impl Default for GitLabSnapshotAcquisitionLimits {
    fn default() -> Self {
        Self {
            wire: GitLabWireLimits::default(),
            per_page: MAX_PER_PAGE,
            max_blob_requests: 128,
            max_total_blob_bytes: 16 * 1024 * 1024,
            max_total_requests: 512,
            acquisition_timeout: Duration::from_mins(10),
            retry: GitLabSnapshotRetryPolicy::default(),
        }
    }
}

/// Rejected controller limits. Invalid limits never initiate a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabSnapshotControllerBuildError {
    InvalidWireLimits,
    InvalidPerPage,
    InvalidBlobRequestLimit,
    InvalidTotalBlobBytes,
    InvalidTotalRequestLimit,
    InvalidAcquisitionTimeout,
    InvalidRetryPolicy,
}

impl fmt::Display for GitLabSnapshotControllerBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitLab snapshot controller limits rejected")
    }
}

impl Error for GitLabSnapshotControllerBuildError {}

/// Safe operation label. It never contains a project path, SHA, URL, or body.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GitLabSnapshotStage {
    InitialMergeRequest,
    TargetProject,
    SourceProject,
    DiffVersions,
    ExactDiffVersion,
    CurrentDiffs,
    RawBlob,
    FinalMergeRequest,
}

/// Which authenticated project projection contradicted the requested identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabProjectRole {
    Target,
    Source,
}

/// Identity contradictions are distinct from transport and untrusted-wire failures.
#[derive(Clone, Eq, PartialEq)]
pub enum GitLabSnapshotIdentityFailure {
    OriginMismatch,
    MergeRequestSelectionMismatch,
    SourceProjectUnavailable,
    ProjectProjectionMismatch {
        role: GitLabProjectRole,
    },
    VerificationMismatch {
        mismatches: BTreeSet<GitLabVerificationMismatch>,
    },
    DiffVersionMergeRequestMismatch,
    LatestVersionBinding {
        reasons: Vec<IdentityBlocker>,
    },
    ExactVersionMismatch,
    ChangedFileCountConflict,
    SnapshotChangedDuringAcquisition,
    PaginationInvariant,
}

impl fmt::Debug for GitLabSnapshotIdentityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OriginMismatch => formatter.write_str("OriginMismatch"),
            Self::MergeRequestSelectionMismatch => {
                formatter.write_str("MergeRequestSelectionMismatch")
            }
            Self::SourceProjectUnavailable => formatter.write_str("SourceProjectUnavailable"),
            Self::ProjectProjectionMismatch { role } => formatter
                .debug_struct("ProjectProjectionMismatch")
                .field("role", role)
                .finish(),
            Self::VerificationMismatch { mismatches } => formatter
                .debug_struct("VerificationMismatch")
                .field("mismatches", mismatches)
                .finish(),
            Self::DiffVersionMergeRequestMismatch => {
                formatter.write_str("DiffVersionMergeRequestMismatch")
            }
            Self::LatestVersionBinding { reasons } => formatter
                .debug_struct("LatestVersionBinding")
                .field("reason_count", &reasons.len())
                .finish(),
            Self::ExactVersionMismatch => formatter.write_str("ExactVersionMismatch"),
            Self::ChangedFileCountConflict => formatter.write_str("ChangedFileCountConflict"),
            Self::SnapshotChangedDuringAcquisition => {
                formatter.write_str("SnapshotChangedDuringAcquisition")
            }
            Self::PaginationInvariant => formatter.write_str("PaginationInvariant"),
        }
    }
}

/// Redaction-safe facts retained for one transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabSnapshotTransportFailure {
    pub stage: GitLabSnapshotStage,
    pub kind: GitLabFailureKind,
    pub status: Option<u16>,
    pub retry: GitLabRetryMetadata,
    pub evidence: GitLabSnapshotAcquisitionEvidence,
}

/// Which controller-wide budget stopped acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabSnapshotBudgetFailureKind {
    RequestLimit,
    Deadline,
}

/// Redaction-safe acquisition-wide budget exhaustion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabSnapshotBudgetFailure {
    pub stage: GitLabSnapshotStage,
    pub kind: GitLabSnapshotBudgetFailureKind,
    pub requests_started: u32,
    pub evidence: GitLabSnapshotAcquisitionEvidence,
}

/// Safe controller-wide counters retained for every terminal outcome.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitLabSnapshotAcquisitionEvidence {
    pub requests_started: u32,
    pub safe_read_retry_attempts: u32,
    pub preparation_poll_observations: u32,
}

/// An asynchronously generated GitLab projection did not become authoritative
/// within the configured poll bound. The caller may retry the whole acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabSnapshotPreparationFailure {
    pub stage: GitLabSnapshotStage,
    pub polls_completed: u8,
    pub evidence: GitLabSnapshotAcquisitionEvidence,
}

/// A failed acquisition before trustworthy snapshot evidence could be completed.
#[derive(Clone, Eq, PartialEq)]
pub enum GitLabSnapshotAcquisitionFailure {
    Transport(GitLabSnapshotTransportFailure),
    Budget(GitLabSnapshotBudgetFailure),
    Preparation(GitLabSnapshotPreparationFailure),
    Wire {
        stage: GitLabSnapshotStage,
        error: GitLabWireError,
        evidence: GitLabSnapshotAcquisitionEvidence,
    },
    Identity {
        failure: GitLabSnapshotIdentityFailure,
        evidence: GitLabSnapshotAcquisitionEvidence,
    },
}

impl GitLabSnapshotAcquisitionFailure {
    #[must_use]
    pub const fn evidence(&self) -> GitLabSnapshotAcquisitionEvidence {
        match self {
            Self::Transport(failure) => failure.evidence,
            Self::Budget(failure) => failure.evidence,
            Self::Preparation(failure) => failure.evidence,
            Self::Wire { evidence, .. } | Self::Identity { evidence, .. } => *evidence,
        }
    }

    fn with_evidence(mut self, evidence: GitLabSnapshotAcquisitionEvidence) -> Self {
        match &mut self {
            Self::Transport(failure) => failure.evidence = evidence,
            Self::Budget(failure) => failure.evidence = evidence,
            Self::Preparation(failure) => failure.evidence = evidence,
            Self::Wire {
                evidence: retained, ..
            }
            | Self::Identity {
                evidence: retained, ..
            } => *retained = evidence,
        }
        self
    }
}

impl fmt::Debug for GitLabSnapshotAcquisitionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(failure) => formatter.debug_tuple("Transport").field(failure).finish(),
            Self::Budget(failure) => formatter.debug_tuple("Budget").field(failure).finish(),
            Self::Preparation(failure) => {
                formatter.debug_tuple("Preparation").field(failure).finish()
            }
            Self::Wire {
                stage,
                error,
                evidence,
            } => formatter
                .debug_struct("Wire")
                .field("stage", stage)
                .field("error", error)
                .field("evidence", evidence)
                .finish(),
            Self::Identity { failure, evidence } => formatter
                .debug_struct("Identity")
                .field("failure", failure)
                .field("evidence", evidence)
                .finish(),
        }
    }
}

impl fmt::Display for GitLabSnapshotAcquisitionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Transport(_) => "GitLab snapshot acquisition transport failure",
            Self::Budget(_) => "GitLab snapshot acquisition budget exhausted",
            Self::Preparation(_) => "GitLab snapshot preparation did not complete",
            Self::Wire { .. } => "GitLab snapshot acquisition wire rejection",
            Self::Identity { .. } => "GitLab snapshot acquisition identity rejection",
        })
    }
}

impl Error for GitLabSnapshotAcquisitionFailure {}

/// Replay validation failures for a retained acquired snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabSnapshotReplayError {
    ContextIdentity,
    ExactDiffManifest,
    ExactFiles,
    BlobContent,
    BlobEvidence,
    Assessment,
}

impl fmt::Display for GitLabSnapshotReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("retained GitLab snapshot evidence failed replay")
    }
}

impl Error for GitLabSnapshotReplayError {}

/// Exact retained snapshot inputs. Accessors expose content deliberately; debug output does not.
#[derive(Clone, Eq, PartialEq)]
pub struct AcquiredGitLabSnapshot {
    verified_context: VerifiedGitLabContext,
    exact_files: Vec<ValidatedChangedFile>,
    blob_contents: Vec<ValidatedRawBlob>,
    evidence: SnapshotEvidence,
    assessment: SnapshotAssessment,
    acquisition_evidence: GitLabSnapshotAcquisitionEvidence,
}

impl AcquiredGitLabSnapshot {
    #[must_use]
    pub const fn verified_context(&self) -> &VerifiedGitLabContext {
        &self.verified_context
    }

    #[must_use]
    pub fn exact_files(&self) -> &[ValidatedChangedFile] {
        &self.exact_files
    }

    #[must_use]
    pub fn blob_contents(&self) -> &[ValidatedRawBlob] {
        &self.blob_contents
    }

    #[must_use]
    pub const fn evidence(&self) -> &SnapshotEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn assessment(&self) -> &SnapshotAssessment {
        &self.assessment
    }

    #[must_use]
    pub const fn acquisition_evidence(&self) -> GitLabSnapshotAcquisitionEvidence {
        self.acquisition_evidence
    }

    /// Recompute all controller-owned bindings without network access.
    ///
    /// # Errors
    ///
    /// Rejects context, manifest, file, blob, or assessment tampering.
    pub fn replay(&self) -> Result<SnapshotAssessment, GitLabSnapshotReplayError> {
        validate_context_identity(&self.verified_context, &self.evidence.identity)?;
        let manifest = exact_diff_manifest_digest(
            &self.evidence.identity.version.diff_version,
            &self.exact_files,
        );
        if manifest != self.evidence.identity.exact_diff_manifest_sha256 {
            return Err(GitLabSnapshotReplayError::ExactDiffManifest);
        }
        let exact_files = self
            .exact_files
            .iter()
            .map(|file| file.file.clone())
            .collect::<Vec<_>>();
        if exact_files != self.evidence.exact_version_files {
            return Err(GitLabSnapshotReplayError::ExactFiles);
        }
        validate_blob_replay(&self.blob_contents, &self.evidence.blobs)?;
        let assessment = self.evidence.assess();
        if assessment != self.assessment {
            return Err(GitLabSnapshotReplayError::Assessment);
        }
        Ok(assessment)
    }
}

impl fmt::Debug for AcquiredGitLabSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let readiness = match &self.assessment.readiness {
            SnapshotReadiness::Complete => "complete",
            SnapshotReadiness::Partial { .. } => "partial",
            SnapshotReadiness::Blocked { .. } => "blocked",
        };
        formatter
            .debug_struct("AcquiredGitLabSnapshot")
            .field("exact_file_count", &self.exact_files.len())
            .field("retained_blob_count", &self.blob_contents.len())
            .field("readiness", &readiness)
            .field("acquisition_evidence", &self.acquisition_evidence)
            .finish_non_exhaustive()
    }
}

/// Acquisition results preserve complete, honest partial, and blocked states separately.
#[derive(Eq, PartialEq)]
pub enum GitLabSnapshotAcquisitionOutcome {
    Complete(AcquiredGitLabSnapshot),
    Partial(AcquiredGitLabSnapshot),
    Blocked(AcquiredGitLabSnapshot),
    Failed(GitLabSnapshotAcquisitionFailure),
}

impl fmt::Debug for GitLabSnapshotAcquisitionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete(snapshot) => formatter.debug_tuple("Complete").field(snapshot).finish(),
            Self::Partial(snapshot) => formatter.debug_tuple("Partial").field(snapshot).finish(),
            Self::Blocked(snapshot) => formatter.debug_tuple("Blocked").field(snapshot).finish(),
            Self::Failed(failure) => formatter.debug_tuple("Failed").field(failure).finish(),
        }
    }
}

/// One configured read-only acquisition controller.
pub struct GitLabSnapshotController<'client> {
    client: &'client GitLabReadClient,
    limits: GitLabSnapshotAcquisitionLimits,
}

impl<'client> GitLabSnapshotController<'client> {
    /// Validate limits before creating a controller.
    ///
    /// # Errors
    ///
    /// Rejects unusable or hard-cap-exceeding request and retention bounds.
    pub fn new(
        client: &'client GitLabReadClient,
        limits: GitLabSnapshotAcquisitionLimits,
    ) -> Result<Self, GitLabSnapshotControllerBuildError> {
        limits
            .wire
            .validate()
            .map_err(|_| GitLabSnapshotControllerBuildError::InvalidWireLimits)?;
        if limits.per_page == 0
            || limits.per_page > MAX_PER_PAGE
            || limits.per_page > limits.wire.max_items_per_page
        {
            return Err(GitLabSnapshotControllerBuildError::InvalidPerPage);
        }
        if limits.max_blob_requests == 0
            || limits.max_blob_requests > HARD_MAX_BLOB_REQUESTS
            || limits.max_blob_requests > limits.wire.max_total_items.saturating_mul(2)
        {
            return Err(GitLabSnapshotControllerBuildError::InvalidBlobRequestLimit);
        }
        if limits.max_total_blob_bytes == 0
            || limits.max_total_blob_bytes > HARD_MAX_TOTAL_BLOB_BYTES
        {
            return Err(GitLabSnapshotControllerBuildError::InvalidTotalBlobBytes);
        }
        if limits.max_total_requests == 0 || limits.max_total_requests > HARD_MAX_TOTAL_REQUESTS {
            return Err(GitLabSnapshotControllerBuildError::InvalidTotalRequestLimit);
        }
        if limits.acquisition_timeout.is_zero()
            || limits.acquisition_timeout > HARD_MAX_ACQUISITION_TIMEOUT
        {
            return Err(GitLabSnapshotControllerBuildError::InvalidAcquisitionTimeout);
        }
        let retry = limits.retry;
        if retry.max_read_attempts == 0
            || retry.max_read_attempts > HARD_MAX_READ_ATTEMPTS
            || retry.max_preparation_polls == 0
            || retry.max_preparation_polls > HARD_MAX_PREPARATION_POLLS
            || retry.initial_backoff.is_zero()
            || retry.initial_backoff > retry.max_backoff
            || retry.max_backoff > HARD_MAX_RETRY_DELAY
            || retry.max_retry_after.is_zero()
            || retry.max_retry_after > HARD_MAX_RETRY_DELAY
        {
            return Err(GitLabSnapshotControllerBuildError::InvalidRetryPolicy);
        }
        Ok(Self { client, limits })
    }

    /// Acquire one exact merge-request snapshot without retries or mutations.
    #[must_use]
    pub async fn acquire(
        &self,
        verification: GitLabVerificationInput,
    ) -> GitLabSnapshotAcquisitionOutcome {
        let mut budget = AcquisitionBudget::new(
            self.limits.max_total_requests,
            self.limits.acquisition_timeout,
        );
        match self.try_acquire(verification, &mut budget).await {
            Ok(snapshot) => match snapshot.assessment.readiness {
                SnapshotReadiness::Complete => GitLabSnapshotAcquisitionOutcome::Complete(snapshot),
                SnapshotReadiness::Partial { .. } => {
                    GitLabSnapshotAcquisitionOutcome::Partial(snapshot)
                }
                SnapshotReadiness::Blocked { .. } => {
                    GitLabSnapshotAcquisitionOutcome::Blocked(snapshot)
                }
            },
            Err(failure) => {
                GitLabSnapshotAcquisitionOutcome::Failed(failure.with_evidence(budget.evidence()))
            }
        }
    }

    async fn try_acquire(
        &self,
        verification: GitLabVerificationInput,
        budget: &mut AcquisitionBudget,
    ) -> Result<AcquiredGitLabSnapshot, GitLabSnapshotAcquisitionFailure> {
        let (merge_request, verified_context) =
            self.acquire_verified_context(verification, budget).await?;
        let target_id = verified_context.target_project().id;
        let merge_request_iid = verified_context.merge_request_iid();

        let scope = SnapshotScope {
            instance_origin_digest: Sha256Digest::of_bytes(
                verified_context.origin().as_str().as_bytes(),
            ),
            project_id: target_id,
            merge_request_iid,
        };
        let bound = self
            .acquire_bound_version(target_id, merge_request_iid, &merge_request, scope, budget)
            .await?;

        let exact = self
            .acquire_exact_version(target_id, merge_request_iid, bound.diff_version.id, budget)
            .await?;
        if exact.version.record != bound.diff_version
            || exact
                .version
                .merge_request_id
                .is_some_and(|id| id != merge_request.merge_request_id)
        {
            return Err(identity(
                GitLabSnapshotIdentityFailure::ExactVersionMismatch,
            ));
        }
        let reported_changed_files = reconcile_changed_file_counts(
            merge_request.changed_files,
            exact.version.reported_files,
        )?;
        let mut exact_files = exact.files;
        exact_files.sort_by(|left, right| left.file.path.cmp(&right.file.path));

        let current_diffs = self
            .acquire_current_diffs(target_id, merge_request_iid, budget)
            .await?;
        let (blobs, blob_contents) = self
            .acquire_blobs(
                verified_context.target_project().id,
                verified_context.source_project().id,
                &bound.diff_version,
                &exact_files,
                budget,
            )
            .await?;

        let final_merge_request = self
            .acquire_merge_request(
                target_id,
                merge_request_iid,
                GitLabSnapshotStage::FinalMergeRequest,
                budget,
            )
            .await?;
        if final_merge_request != merge_request {
            return Err(identity(
                GitLabSnapshotIdentityFailure::SnapshotChangedDuringAcquisition,
            ));
        }

        let manifest_sha256 = exact_diff_manifest_digest(&bound.diff_version, &exact_files);
        let identity = bound.freeze(manifest_sha256);
        let evidence = SnapshotEvidence {
            identity,
            diff_version_state: exact.version.state,
            reported_changed_files,
            exact_version_files: exact_files.iter().map(|file| file.file.clone()).collect(),
            current_diffs,
            blobs,
        };
        let assessment = evidence.assess();
        budget.ensure_deadline(GitLabSnapshotStage::FinalMergeRequest)?;
        Ok(AcquiredGitLabSnapshot {
            verified_context,
            exact_files,
            blob_contents,
            evidence,
            assessment,
            acquisition_evidence: budget.evidence(),
        })
    }

    async fn acquire_verified_context(
        &self,
        verification: GitLabVerificationInput,
        budget: &mut AcquisitionBudget,
    ) -> Result<
        (ValidatedMergeRequestMetadata, VerifiedGitLabContext),
        GitLabSnapshotAcquisitionFailure,
    > {
        if verification.origin != *self.client.origin() {
            return Err(identity(GitLabSnapshotIdentityFailure::OriginMismatch));
        }
        let target_id = verification.project.id;
        let merge_request_iid = verification.merge_request_iid;
        let merge_request = self
            .acquire_prepared_merge_request(target_id, merge_request_iid, budget)
            .await?;
        let source_id = merge_request
            .source_project_id
            .ok_or_else(|| identity(GitLabSnapshotIdentityFailure::SourceProjectUnavailable))?;
        let target_project = self
            .acquire_project(target_id, GitLabSnapshotStage::TargetProject, budget)
            .await?;
        if target_project.id != target_id {
            return Err(identity(
                GitLabSnapshotIdentityFailure::ProjectProjectionMismatch {
                    role: GitLabProjectRole::Target,
                },
            ));
        }
        let source_project = self
            .acquire_project(source_id, GitLabSnapshotStage::SourceProject, budget)
            .await?;
        if source_project.id != source_id {
            return Err(identity(
                GitLabSnapshotIdentityFailure::ProjectProjectionMismatch {
                    role: GitLabProjectRole::Source,
                },
            ));
        }
        let authoritative = AuthoritativeGitLabMergeRequest {
            target_project,
            source_project,
            merge_request_iid: merge_request.iid,
            source_ref: merge_request.source_ref.clone(),
            target_ref: merge_request.target_ref.clone(),
            head_sha: merge_request.head_sha.clone(),
        };
        match verification.verify(authoritative) {
            GitLabVerificationResult::Verified(context) => Ok((merge_request, context)),
            GitLabVerificationResult::Mismatch { mismatches } => Err(identity(
                GitLabSnapshotIdentityFailure::VerificationMismatch { mismatches },
            )),
        }
    }

    async fn acquire_prepared_merge_request(
        &self,
        project_id: ProjectId,
        merge_request_iid: revoot_core::MergeRequestIid,
        budget: &mut AcquisitionBudget,
    ) -> Result<ValidatedMergeRequestMetadata, GitLabSnapshotAcquisitionFailure> {
        for poll in 1..=self.limits.retry.max_preparation_polls {
            let merge_request = self
                .acquire_merge_request(
                    project_id,
                    merge_request_iid,
                    GitLabSnapshotStage::InitialMergeRequest,
                    budget,
                )
                .await?;
            budget.record_preparation_poll();
            if merge_request.project_id != project_id
                || merge_request.target_project_id != project_id
                || merge_request.iid != merge_request_iid
            {
                return Err(identity(
                    GitLabSnapshotIdentityFailure::MergeRequestSelectionMismatch,
                ));
            }
            if merge_request.diff_refs.is_some() {
                return Ok(merge_request);
            }
            if poll == self.limits.retry.max_preparation_polls {
                return Err(preparation(GitLabSnapshotStage::InitialMergeRequest, poll));
            }
            budget
                .wait_backoff(
                    GitLabSnapshotStage::InitialMergeRequest,
                    self.limits.retry,
                    poll - 1,
                    None,
                )
                .await?;
        }
        Err(preparation(
            GitLabSnapshotStage::InitialMergeRequest,
            self.limits.retry.max_preparation_polls,
        ))
    }

    async fn acquire_bound_version(
        &self,
        project_id: ProjectId,
        merge_request_iid: revoot_core::MergeRequestIid,
        merge_request: &ValidatedMergeRequestMetadata,
        scope: SnapshotScope,
        budget: &mut AcquisitionBudget,
    ) -> Result<revoot_core::GitLabDiffVersionIdentity, GitLabSnapshotAcquisitionFailure> {
        for poll in 1..=self.limits.retry.max_preparation_polls {
            let versions = self
                .acquire_diff_versions(project_id, merge_request_iid, budget)
                .await?;
            budget.record_preparation_poll();
            if versions.items.iter().any(|version| {
                version
                    .merge_request_id
                    .is_some_and(|id| id != merge_request.merge_request_id)
            }) {
                return Err(identity(
                    GitLabSnapshotIdentityFailure::DiffVersionMergeRequestMismatch,
                ));
            }
            let version_records = PaginatedAcquisition {
                items: versions
                    .items
                    .iter()
                    .map(|version| version.record.clone())
                    .collect(),
                pages: versions.pages,
            };
            match bind_latest_snapshot(
                scope.clone(),
                merge_request.diff_refs.as_ref(),
                &version_records,
            ) {
                SnapshotBinding::Bound { identity } => return Ok(identity),
                SnapshotBinding::Blocked { reasons }
                    if preparation_only_binding_failure(&reasons) =>
                {
                    if poll == self.limits.retry.max_preparation_polls {
                        return Err(preparation(GitLabSnapshotStage::DiffVersions, poll));
                    }
                }
                SnapshotBinding::Blocked { reasons } => {
                    return Err(identity(
                        GitLabSnapshotIdentityFailure::LatestVersionBinding { reasons },
                    ));
                }
            }
            budget
                .wait_backoff(
                    GitLabSnapshotStage::DiffVersions,
                    self.limits.retry,
                    poll - 1,
                    None,
                )
                .await?;
            let refreshed = self
                .acquire_merge_request(
                    project_id,
                    merge_request_iid,
                    GitLabSnapshotStage::InitialMergeRequest,
                    budget,
                )
                .await?;
            if refreshed != *merge_request {
                return Err(identity(
                    GitLabSnapshotIdentityFailure::SnapshotChangedDuringAcquisition,
                ));
            }
        }
        Err(preparation(
            GitLabSnapshotStage::DiffVersions,
            self.limits.retry.max_preparation_polls,
        ))
    }

    async fn acquire_project(
        &self,
        project_id: ProjectId,
        stage: GitLabSnapshotStage,
        budget: &mut AcquisitionBudget,
    ) -> Result<revoot_core::GitLabProjectIdentity, GitLabSnapshotAcquisitionFailure> {
        let response = self
            .read(&GitLabReadEndpoint::Project { project_id }, stage, budget)
            .await?;
        parse_project_response(&response, self.limits.wire).map_err(|error| wire(stage, error))
    }

    async fn acquire_merge_request(
        &self,
        project_id: ProjectId,
        merge_request_iid: revoot_core::MergeRequestIid,
        stage: GitLabSnapshotStage,
        budget: &mut AcquisitionBudget,
    ) -> Result<ValidatedMergeRequestMetadata, GitLabSnapshotAcquisitionFailure> {
        let response = self
            .read(
                &GitLabReadEndpoint::MergeRequest {
                    project_id,
                    merge_request_iid,
                },
                stage,
                budget,
            )
            .await?;
        parse_merge_request_response(&response, self.limits.wire)
            .map_err(|error| wire(stage, error))
    }

    async fn acquire_diff_versions(
        &self,
        project_id: ProjectId,
        merge_request_iid: revoot_core::MergeRequestIid,
        budget: &mut AcquisitionBudget,
    ) -> Result<PaginatedAcquisition<ValidatedDiffVersion>, GitLabSnapshotAcquisitionFailure> {
        let mut pages = Vec::new();
        let mut requested_page = 1_u32;
        loop {
            self.validate_page_bound(requested_page, GitLabSnapshotStage::DiffVersions)?;
            let pagination = self.pagination(requested_page)?;
            let response = self
                .read(
                    &GitLabReadEndpoint::DiffVersions {
                        project_id,
                        merge_request_iid,
                        pagination,
                    },
                    GitLabSnapshotStage::DiffVersions,
                    budget,
                )
                .await?;
            let page = parse_diff_versions_page(
                &response,
                requested_page,
                self.limits.per_page,
                self.limits.wire,
            )
            .map_err(|error| wire(GitLabSnapshotStage::DiffVersions, error))?;
            let next = page.metadata.next_page;
            pages.push(page);
            let Some(next) = next else {
                break;
            };
            requested_page = next;
        }
        collect_complete_pages(pages, self.limits.wire)
            .map_err(|error| wire(GitLabSnapshotStage::DiffVersions, error))
    }

    async fn acquire_exact_version(
        &self,
        project_id: ProjectId,
        merge_request_iid: revoot_core::MergeRequestIid,
        version_id: revoot_core::DiffVersionId,
        budget: &mut AcquisitionBudget,
    ) -> Result<revoot_core::ValidatedExactDiffVersion, GitLabSnapshotAcquisitionFailure> {
        let response = self
            .read(
                &GitLabReadEndpoint::ExactDiffVersion {
                    project_id,
                    merge_request_iid,
                    version_id,
                },
                GitLabSnapshotStage::ExactDiffVersion,
                budget,
            )
            .await?;
        parse_exact_diff_version_response(&response, self.limits.wire)
            .map_err(|error| wire(GitLabSnapshotStage::ExactDiffVersion, error))
    }

    async fn acquire_current_diffs(
        &self,
        project_id: ProjectId,
        merge_request_iid: revoot_core::MergeRequestIid,
        budget: &mut AcquisitionBudget,
    ) -> Result<PaginatedAcquisition<ChangedPath>, GitLabSnapshotAcquisitionFailure> {
        let mut pages = Vec::new();
        let mut requested_page = 1_u32;
        loop {
            self.validate_page_bound(requested_page, GitLabSnapshotStage::CurrentDiffs)?;
            let pagination = self.pagination(requested_page)?;
            let response = self
                .read(
                    &GitLabReadEndpoint::ChangedFiles {
                        project_id,
                        merge_request_iid,
                        pagination,
                    },
                    GitLabSnapshotStage::CurrentDiffs,
                    budget,
                )
                .await?;
            let page = parse_changed_files_page(
                &response,
                requested_page,
                self.limits.per_page,
                self.limits.wire,
            )
            .map_err(|error| wire(GitLabSnapshotStage::CurrentDiffs, error))?;
            let next = page.metadata.next_page;
            pages.push(GitLabPage {
                metadata: page.metadata,
                items: page.items.into_iter().map(|file| file.file.path).collect(),
            });
            let Some(next) = next else {
                break;
            };
            requested_page = next;
        }
        let mut acquisition = collect_complete_pages(pages, self.limits.wire)
            .map_err(|error| wire(GitLabSnapshotStage::CurrentDiffs, error))?;
        acquisition.items.sort();
        Ok(acquisition)
    }

    async fn acquire_blobs(
        &self,
        target_project_id: ProjectId,
        source_project_id: ProjectId,
        version: &DiffVersionRecord,
        files: &[ValidatedChangedFile],
        budget: &mut AcquisitionBudget,
    ) -> Result<(Vec<BlobAcquisition>, Vec<ValidatedRawBlob>), GitLabSnapshotAcquisitionFailure>
    {
        let requests = files
            .iter()
            .flat_map(|file| file.file.path.expected_blobs(&version.refs))
            .collect::<BTreeSet<_>>();
        let mut evidence = Vec::with_capacity(requests.len());
        let retained_capacity = requests
            .len()
            .min(usize::try_from(self.limits.max_blob_requests).unwrap_or(usize::MAX));
        let mut retained = Vec::with_capacity(retained_capacity);
        let mut retained_bytes = 0_u64;
        for (index, request) in requests.into_iter().enumerate() {
            if index >= usize::try_from(self.limits.max_blob_requests).unwrap_or(usize::MAX) {
                evidence.push(BlobAcquisition::Unavailable {
                    request,
                    reason: BlobUnavailableReason::SkippedByPolicy,
                });
                continue;
            }
            let project_id = match request.side {
                BlobSide::Old => target_project_id,
                BlobSide::New => source_project_id,
            };
            let endpoint = GitLabReadEndpoint::RawRepositoryFile {
                project_id,
                file_path: request.path.clone(),
                revision: request.commit_sha.clone(),
            };
            let response = match budget
                .get(
                    self.client,
                    &endpoint,
                    GitLabSnapshotStage::RawBlob,
                    self.limits.retry,
                )
                .await
            {
                Ok(response) => response,
                Err(GitLabSnapshotAcquisitionFailure::Transport(failure)) => {
                    if let Some(reason) = recoverable_blob_failure(failure.kind) {
                        evidence.push(BlobAcquisition::Unavailable { request, reason });
                        continue;
                    }
                    return Err(GitLabSnapshotAcquisitionFailure::Transport(failure));
                }
                Err(error) => {
                    return Err(error);
                }
            };
            let blob = parse_raw_blob_response(&request, &response, self.limits.wire)
                .map_err(|error| wire(GitLabSnapshotStage::RawBlob, error))?;
            let Some(next_bytes) = retained_bytes.checked_add(blob.identity.size_bytes) else {
                evidence.push(BlobAcquisition::Unavailable {
                    request,
                    reason: BlobUnavailableReason::SkippedByPolicy,
                });
                continue;
            };
            if next_bytes > self.limits.max_total_blob_bytes {
                evidence.push(BlobAcquisition::Unavailable {
                    request,
                    reason: BlobUnavailableReason::SkippedByPolicy,
                });
                continue;
            }
            retained_bytes = next_bytes;
            evidence.push(BlobAcquisition::Acquired {
                identity: blob.identity.clone(),
            });
            retained.push(blob);
        }
        Ok((evidence, retained))
    }

    async fn read(
        &self,
        endpoint: &GitLabReadEndpoint,
        stage: GitLabSnapshotStage,
        budget: &mut AcquisitionBudget,
    ) -> Result<revoot_core::GitLabResponseObservation, GitLabSnapshotAcquisitionFailure> {
        budget
            .get(self.client, endpoint, stage, self.limits.retry)
            .await
    }

    fn pagination(&self, page: u32) -> Result<GitLabPagination, GitLabSnapshotAcquisitionFailure> {
        GitLabPagination::new(page, self.limits.per_page).map_err(|error| match error {
            GitLabEndpointError::InvalidPagination
            | GitLabEndpointError::UrlConstruction
            | GitLabEndpointError::OriginBinding => {
                identity(GitLabSnapshotIdentityFailure::PaginationInvariant)
            }
        })
    }

    fn validate_page_bound(
        &self,
        page: u32,
        stage: GitLabSnapshotStage,
    ) -> Result<(), GitLabSnapshotAcquisitionFailure> {
        if page == 0 || page > self.limits.wire.max_pages {
            Err(wire(stage, GitLabWireError::TooManyPages))
        } else {
            Ok(())
        }
    }
}

struct AcquisitionBudget {
    deadline: tokio::time::Instant,
    max_requests: u32,
    requests_started: u32,
    safe_read_retry_attempts: u32,
    preparation_poll_observations: u32,
}

impl AcquisitionBudget {
    fn new(max_requests: u32, timeout: Duration) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + timeout,
            max_requests,
            requests_started: 0,
            safe_read_retry_attempts: 0,
            preparation_poll_observations: 0,
        }
    }

    async fn get(
        &mut self,
        client: &GitLabReadClient,
        endpoint: &GitLabReadEndpoint,
        stage: GitLabSnapshotStage,
        retry_policy: GitLabSnapshotRetryPolicy,
    ) -> Result<revoot_core::GitLabResponseObservation, GitLabSnapshotAcquisitionFailure> {
        for attempt in 1..=retry_policy.max_read_attempts {
            if attempt > 1 {
                self.safe_read_retry_attempts = self.safe_read_retry_attempts.saturating_add(1);
            }
            self.ensure_deadline(stage)?;
            if self.requests_started >= self.max_requests {
                return Err(self.failure(stage, GitLabSnapshotBudgetFailureKind::RequestLimit));
            }
            self.requests_started += 1;
            match tokio::time::timeout_at(self.deadline, client.get(endpoint)).await {
                Ok(Ok(response)) => return Ok(response.into_observation()),
                Ok(Err(error)) => {
                    let retry = error.retry();
                    if attempt == retry_policy.max_read_attempts || !retry.eligible_read {
                        return Err(transport(stage, &error));
                    }
                    let retry_after = retry
                        .after_seconds
                        .map(Duration::from_secs)
                        .filter(|delay| *delay <= retry_policy.max_retry_after);
                    if retry.after_seconds.is_some() && retry_after.is_none() {
                        return Err(transport(stage, &error));
                    }
                    self.wait_backoff(stage, retry_policy, attempt - 1, retry_after)
                        .await?;
                }
                Err(_) => {
                    return Err(self.failure(stage, GitLabSnapshotBudgetFailureKind::Deadline));
                }
            }
        }
        Err(self.failure(stage, GitLabSnapshotBudgetFailureKind::RequestLimit))
    }

    async fn wait_backoff(
        &self,
        stage: GitLabSnapshotStage,
        policy: GitLabSnapshotRetryPolicy,
        exponent: u8,
        retry_after: Option<Duration>,
    ) -> Result<(), GitLabSnapshotAcquisitionFailure> {
        self.ensure_deadline(stage)?;
        let delay = retry_after.unwrap_or_else(|| {
            let multiplier = 1_u32
                .checked_shl(u32::from(exponent).min(31))
                .unwrap_or(u32::MAX);
            let base = policy
                .initial_backoff
                .saturating_mul(multiplier)
                .min(policy.max_backoff);
            deterministic_jitter(base, self.requests_started).min(policy.max_backoff)
        });
        let Some(wake) = tokio::time::Instant::now().checked_add(delay) else {
            return Err(self.failure(stage, GitLabSnapshotBudgetFailureKind::Deadline));
        };
        if wake >= self.deadline {
            return Err(self.failure(stage, GitLabSnapshotBudgetFailureKind::Deadline));
        }
        tokio::time::sleep_until(wake).await;
        self.ensure_deadline(stage)
    }

    fn ensure_deadline(
        &self,
        stage: GitLabSnapshotStage,
    ) -> Result<(), GitLabSnapshotAcquisitionFailure> {
        if tokio::time::Instant::now() >= self.deadline {
            Err(self.failure(stage, GitLabSnapshotBudgetFailureKind::Deadline))
        } else {
            Ok(())
        }
    }

    fn record_preparation_poll(&mut self) {
        self.preparation_poll_observations = self.preparation_poll_observations.saturating_add(1);
    }

    const fn evidence(&self) -> GitLabSnapshotAcquisitionEvidence {
        GitLabSnapshotAcquisitionEvidence {
            requests_started: self.requests_started,
            safe_read_retry_attempts: self.safe_read_retry_attempts,
            preparation_poll_observations: self.preparation_poll_observations,
        }
    }

    const fn failure(
        &self,
        stage: GitLabSnapshotStage,
        kind: GitLabSnapshotBudgetFailureKind,
    ) -> GitLabSnapshotAcquisitionFailure {
        GitLabSnapshotAcquisitionFailure::Budget(GitLabSnapshotBudgetFailure {
            stage,
            kind,
            requests_started: self.requests_started,
            evidence: self.evidence(),
        })
    }
}

fn deterministic_jitter(base: Duration, request_ordinal: u32) -> Duration {
    let slot = u128::from(
        request_ordinal
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223)
            % 5,
    );
    let jitter_nanos = base.as_nanos().saturating_mul(slot) / 20;
    base.saturating_add(Duration::from_nanos(
        u64::try_from(jitter_nanos).unwrap_or(u64::MAX),
    ))
}

fn preparation_only_binding_failure(reasons: &[IdentityBlocker]) -> bool {
    !reasons.is_empty()
        && reasons.iter().all(|reason| {
            matches!(
                reason,
                IdentityBlocker::NoDiffVersions | IdentityBlocker::LatestDiffRefsMismatch { .. }
            )
        })
}

fn reconcile_changed_file_counts(
    merge_request: ChangedFileCount,
    exact_version: ChangedFileCount,
) -> Result<ChangedFileCount, GitLabSnapshotAcquisitionFailure> {
    match (merge_request, exact_version) {
        (ChangedFileCount::Exact(left), ChangedFileCount::Exact(right)) if left == right => {
            Ok(ChangedFileCount::Exact(left))
        }
        (ChangedFileCount::Exact(_), ChangedFileCount::Exact(_)) => Err(identity(
            GitLabSnapshotIdentityFailure::ChangedFileCountConflict,
        )),
        (ChangedFileCount::CappedAt(left), ChangedFileCount::Exact(right))
        | (ChangedFileCount::Exact(right), ChangedFileCount::CappedAt(left)) => {
            if right < left {
                Err(identity(
                    GitLabSnapshotIdentityFailure::ChangedFileCountConflict,
                ))
            } else {
                Ok(ChangedFileCount::CappedAt(left))
            }
        }
        (ChangedFileCount::CappedAt(left), ChangedFileCount::CappedAt(right)) => {
            Ok(ChangedFileCount::CappedAt(left.max(right)))
        }
        (ChangedFileCount::Unavailable, _) | (_, ChangedFileCount::Unavailable) => {
            Ok(ChangedFileCount::Unavailable)
        }
    }
}

fn recoverable_blob_failure(kind: GitLabFailureKind) -> Option<BlobUnavailableReason> {
    match kind {
        GitLabFailureKind::NotFound => Some(BlobUnavailableReason::Missing),
        GitLabFailureKind::Forbidden => Some(BlobUnavailableReason::UnauthorizedPrivateFork),
        GitLabFailureKind::BodyTooLarge => Some(BlobUnavailableReason::TooLarge),
        GitLabFailureKind::MissingContentType
        | GitLabFailureKind::UnsupportedContentType
        | GitLabFailureKind::UnsupportedContentEncoding => {
            Some(BlobUnavailableReason::UnsupportedEncoding)
        }
        GitLabFailureKind::Authentication
        | GitLabFailureKind::Conflict
        | GitLabFailureKind::RateLimited
        | GitLabFailureKind::RedirectDenied
        | GitLabFailureKind::ServerUnavailable
        | GitLabFailureKind::UnexpectedStatus
        | GitLabFailureKind::MalformedContentLength
        | GitLabFailureKind::TooManyHeaders
        | GitLabFailureKind::ObservedHeaderTooLarge
        | GitLabFailureKind::ConnectTimeout
        | GitLabFailureKind::RequestTimeout
        | GitLabFailureKind::BodyTimeout
        | GitLabFailureKind::Connection
        | GitLabFailureKind::Protocol
        | GitLabFailureKind::Endpoint => None,
    }
}

#[derive(Serialize)]
struct ExactDiffManifest<'a> {
    schema: &'static str,
    version: &'a DiffVersionRecord,
    files: Vec<ExactDiffManifestFile<'a>>,
}

#[derive(Serialize)]
struct ExactDiffManifestFile<'a> {
    file: &'a ChangedFile,
    generated: Option<bool>,
    unified_diff_bytes: Option<u64>,
}

fn exact_diff_manifest_digest(
    version: &DiffVersionRecord,
    files: &[ValidatedChangedFile],
) -> Sha256Digest {
    let manifest = ExactDiffManifest {
        schema: EXACT_DIFF_MANIFEST_SCHEMA,
        version,
        files: files
            .iter()
            .map(|file| ExactDiffManifestFile {
                file: &file.file,
                generated: file.generated,
                unified_diff_bytes: file
                    .unified_diff
                    .as_ref()
                    .map(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            })
            .collect(),
    };
    Sha256Digest::of_bytes(
        &serde_json::to_vec(&manifest).expect("validated diff manifest serializes infallibly"),
    )
}

fn validate_context_identity(
    context: &VerifiedGitLabContext,
    identity: &GitLabSnapshotIdentity,
) -> Result<(), GitLabSnapshotReplayError> {
    let scope = &identity.version.scope;
    if scope.instance_origin_digest != Sha256Digest::of_bytes(context.origin().as_str().as_bytes())
        || scope.project_id != context.target_project().id
        || scope.merge_request_iid != context.merge_request_iid()
        || identity.version.diff_version.refs.head_sha != *context.head_sha()
    {
        return Err(GitLabSnapshotReplayError::ContextIdentity);
    }
    Ok(())
}

fn validate_blob_replay(
    contents: &[ValidatedRawBlob],
    evidence: &[BlobAcquisition],
) -> Result<(), GitLabSnapshotReplayError> {
    let mut retained = BTreeMap::new();
    for blob in contents {
        if blob.identity.size_bytes != u64::try_from(blob.body.len()).unwrap_or(u64::MAX)
            || blob.identity.content_sha256 != Sha256Digest::of_bytes(&blob.body)
            || retained
                .insert(blob.identity.request.clone(), blob.identity.clone())
                .is_some()
        {
            return Err(GitLabSnapshotReplayError::BlobContent);
        }
    }
    let mut acquired = BTreeMap::new();
    for blob in evidence {
        if let BlobAcquisition::Acquired { identity } = blob
            && acquired
                .insert(identity.request.clone(), identity.clone())
                .is_some()
        {
            return Err(GitLabSnapshotReplayError::BlobEvidence);
        }
    }
    if retained != acquired {
        return Err(GitLabSnapshotReplayError::BlobEvidence);
    }
    Ok(())
}

fn transport(
    stage: GitLabSnapshotStage,
    error: &GitLabTransportError,
) -> GitLabSnapshotAcquisitionFailure {
    GitLabSnapshotAcquisitionFailure::Transport(GitLabSnapshotTransportFailure {
        stage,
        kind: error.kind(),
        status: error.status(),
        retry: error.retry(),
        evidence: GitLabSnapshotAcquisitionEvidence::default(),
    })
}

fn wire(stage: GitLabSnapshotStage, error: GitLabWireError) -> GitLabSnapshotAcquisitionFailure {
    GitLabSnapshotAcquisitionFailure::Wire {
        stage,
        error,
        evidence: GitLabSnapshotAcquisitionEvidence::default(),
    }
}

fn identity(failure: GitLabSnapshotIdentityFailure) -> GitLabSnapshotAcquisitionFailure {
    GitLabSnapshotAcquisitionFailure::Identity {
        failure,
        evidence: GitLabSnapshotAcquisitionEvidence::default(),
    }
}

fn preparation(
    stage: GitLabSnapshotStage,
    polls_completed: u8,
) -> GitLabSnapshotAcquisitionFailure {
    GitLabSnapshotAcquisitionFailure::Preparation(GitLabSnapshotPreparationFailure {
        stage,
        polls_completed,
        evidence: GitLabSnapshotAcquisitionEvidence::default(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    use revoot_core::{
        CoverageGap, GitLabOrigin, GitLabOriginPolicy, GitLabProjectIdentity, GitLabProjectPath,
        GitRefName, GitSha, MergeRequestIid, RepositoryPath, SnapshotBlocker,
        UntrustedGitLabCiHint,
    };
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::gitlab_transport::{
        GitLabAccessToken, GitLabCaMode, GitLabTransportConfig, GitLabTransportLimits,
    };

    struct MockResponse {
        status: &'static str,
        content_type: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        delay: Option<Duration>,
    }

    async fn serve_sequence(
        responses: Vec<MockResponse>,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind numeric-loopback fixture server");
        let address = listener.local_addr().expect("read fixture address");
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut responses = VecDeque::from(responses);
            while let Some(response) = responses.pop_front() {
                let accepted =
                    tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
                let Ok(Ok((mut stream, _))) = accepted else {
                    break;
                };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while request.len() < 16 * 1024
                    && !request.windows(4).any(|part| part == b"\r\n\r\n")
                {
                    let count = stream
                        .read(&mut buffer)
                        .await
                        .expect("read fixture request");
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                }
                let mut head = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
                    response.status,
                    response.content_type,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    head.push_str(&name);
                    head.push_str(": ");
                    head.push_str(&value);
                    head.push_str("\r\n");
                }
                head.push_str("Connection: close\r\n\r\n");
                if let Some(delay) = response.delay {
                    tokio::time::sleep(delay).await;
                }
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&response.body).await;
                requests.push(request);
            }
            requests
        });
        (address, task)
    }

    fn json_response(value: impl serde::Serialize) -> MockResponse {
        MockResponse {
            status: "200 OK",
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
            body: serde_json::to_vec(&value).unwrap(),
            delay: None,
        }
    }

    fn json_status(status: &'static str) -> MockResponse {
        MockResponse {
            status,
            content_type: "application/json",
            headers: Vec::new(),
            body: b"{}".to_vec(),
            delay: None,
        }
    }

    fn page_response(
        value: Value,
        page: u32,
        per_page: u32,
        next: Option<u32>,
        total: u32,
        total_pages: u32,
    ) -> MockResponse {
        let mut response = json_response(value);
        response.headers = vec![
            ("X-Page".to_owned(), page.to_string()),
            ("X-Per-Page".to_owned(), per_page.to_string()),
            (
                "X-Prev-Page".to_owned(),
                page.checked_sub(1)
                    .filter(|_| page > 1)
                    .map_or_else(String::new, |value| value.to_string()),
            ),
            (
                "X-Next-Page".to_owned(),
                next.map_or_else(String::new, |value| value.to_string()),
            ),
            ("X-Total".to_owned(), total.to_string()),
            ("X-Total-Pages".to_owned(), total_pages.to_string()),
        ];
        response
    }

    fn raw_response(request: &revoot_core::BlobRequest, marker: char, body: &[u8]) -> MockResponse {
        MockResponse {
            status: "200 OK",
            content_type: "application/octet-stream",
            headers: vec![
                ("X-Gitlab-Blob-Id".to_owned(), sha(marker)),
                (
                    "X-Gitlab-Commit-Id".to_owned(),
                    request.commit_sha.as_str().to_owned(),
                ),
                (
                    "X-Gitlab-Content-Sha256".to_owned(),
                    Sha256Digest::of_bytes(body).as_str().to_owned(),
                ),
                ("X-Gitlab-Encoding".to_owned(), "base64".to_owned()),
                ("X-Gitlab-Execute-Filemode".to_owned(), "false".to_owned()),
                (
                    "X-Gitlab-File-Path".to_owned(),
                    request.path.as_str().to_owned(),
                ),
                (
                    "X-Gitlab-Ref".to_owned(),
                    request.commit_sha.as_str().to_owned(),
                ),
                ("X-Gitlab-Size".to_owned(), body.len().to_string()),
            ],
            body: body.to_vec(),
            delay: None,
        }
    }

    fn sha(marker: char) -> String {
        marker.to_string().repeat(40)
    }

    fn project(id: u64, path: &str) -> Value {
        json!({"id": id, "path_with_namespace": path})
    }

    fn merge_request(head: char) -> Value {
        json!({
            "id": 99,
            "iid": 7,
            "project_id": 42,
            "source_project_id": 41,
            "target_project_id": 42,
            "state": "opened",
            "source_branch": "feature/review",
            "target_branch": "main",
            "sha": sha(head),
            "diff_refs": {
                "base_sha": sha('a'),
                "start_sha": sha('b'),
                "head_sha": sha(head)
            },
            "changes_count": "1"
        })
    }

    fn version(id: u64, head: char) -> Value {
        json!({
            "id": id,
            "head_commit_sha": sha(head),
            "base_commit_sha": sha('a'),
            "start_commit_sha": sha('b'),
            "state": "collected",
            "real_size": "1",
            "created_at": "2026-08-20T00:00:00Z",
            "merge_request_id": 99,
            "patch_id_sha": sha('e')
        })
    }

    fn changed_file(path: &str) -> Value {
        json!({
            "old_path": path,
            "new_path": path,
            "a_mode": "100644",
            "b_mode": "100644",
            "diff": "@@ -1 +1 @@\n-old\n+new\n",
            "new_file": false,
            "renamed_file": false,
            "deleted_file": false,
            "generated_file": false,
            "collapsed": false,
            "too_large": false
        })
    }

    fn exact_version(files: Vec<Value>) -> Value {
        let mut value = version(9, 'c');
        value
            .as_object_mut()
            .expect("version object")
            .insert("diffs".to_owned(), Value::Array(files));
        value
    }

    fn origin() -> GitLabOrigin {
        GitLabOrigin::parse(
            "https://gitlab.example.test",
            &GitLabOriginPolicy::default(),
        )
        .unwrap()
    }

    fn project_identity(id: u64, path: &str) -> GitLabProjectIdentity {
        GitLabProjectIdentity {
            id: ProjectId::try_from(id).unwrap(),
            path: GitLabProjectPath::try_from(path.to_owned()).unwrap(),
        }
    }

    fn verification() -> GitLabVerificationInput {
        let origin = origin();
        let target_project = project_identity(42, "group/target");
        let source_project = project_identity(41, "fork/source");
        GitLabVerificationInput {
            origin: origin.clone(),
            project: target_project.clone(),
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
            ci_hint: Some(UntrustedGitLabCiHint {
                origin,
                pipeline_project: source_project.clone(),
                target_project,
                source_project,
                merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
                source_ref: GitRefName::try_from("feature/review".to_owned()).unwrap(),
                target_ref: GitRefName::try_from("main".to_owned()).unwrap(),
                head_sha: GitSha::try_from(sha('c')).unwrap(),
            }),
        }
    }

    fn build_client(address: SocketAddr) -> GitLabReadClient {
        let config = GitLabTransportConfig::new(
            origin(),
            GitLabCaMode::BundledWebPki,
            GitLabTransportLimits::default(),
        );
        GitLabReadClient::new_for_loopback(
            &config,
            GitLabAccessToken::new(b"fixture-token".to_vec()).unwrap(),
            address,
        )
        .unwrap()
    }

    fn limits() -> GitLabSnapshotAcquisitionLimits {
        GitLabSnapshotAcquisitionLimits {
            per_page: 1,
            ..GitLabSnapshotAcquisitionLimits::default()
        }
    }

    const fn acquisition_evidence(
        requests_started: u32,
        safe_read_retry_attempts: u32,
        preparation_poll_observations: u32,
    ) -> GitLabSnapshotAcquisitionEvidence {
        GitLabSnapshotAcquisitionEvidence {
            requests_started,
            safe_read_retry_attempts,
            preparation_poll_observations,
        }
    }

    fn blob_requests() -> [revoot_core::BlobRequest; 2] {
        let path = RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap();
        [
            revoot_core::BlobRequest {
                side: BlobSide::Old,
                path: path.clone(),
                commit_sha: GitSha::try_from(sha('a')).unwrap(),
            },
            revoot_core::BlobRequest {
                side: BlobSide::New,
                path,
                commit_sha: GitSha::try_from(sha('c')).unwrap(),
            },
        ]
    }

    fn complete_responses() -> Vec<MockResponse> {
        let [old, new] = blob_requests();
        vec![
            json_response(merge_request('c')),
            json_response(project(42, "group/target")),
            json_response(project(41, "fork/source")),
            page_response(json!([version(9, 'c')]), 1, 1, Some(2), 2, 2),
            page_response(json!([version(8, 'd')]), 2, 1, None, 2, 2),
            json_response(exact_version(vec![changed_file("src/lib.rs")])),
            page_response(json!([changed_file("src/lib.rs")]), 1, 1, None, 1, 1),
            raw_response(&old, 'f', b"old\n"),
            raw_response(&new, 'd', b"new\n"),
            json_response(merge_request('c')),
        ]
    }

    #[tokio::test]
    async fn recorded_fork_projection_acquires_complete_replayable_snapshot() {
        let (address, server) = serve_sequence(complete_responses()).await;
        let client = build_client(address);
        let controller = GitLabSnapshotController::new(&client, limits()).unwrap();
        let GitLabSnapshotAcquisitionOutcome::Complete(snapshot) =
            controller.acquire(verification()).await
        else {
            panic!("expected complete snapshot")
        };
        assert_eq!(snapshot.assessment().files_represented, 1);
        assert_eq!(snapshot.assessment().blobs_expected, 2);
        assert_eq!(snapshot.assessment().blobs_included, 2);
        assert_eq!(snapshot.blob_contents().len(), 2);
        assert_eq!(
            snapshot.acquisition_evidence(),
            acquisition_evidence(10, 0, 2)
        );
        assert_eq!(snapshot.replay().unwrap(), snapshot.assessment().clone());
        let mut tampered = snapshot.clone();
        tampered.blob_contents[0].body.push(b'!');
        assert_eq!(
            tampered.replay(),
            Err(GitLabSnapshotReplayError::BlobContent)
        );
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("src/lib.rs"));
        assert!(!debug.contains(&sha('a')));

        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 10);
        let request_lines = requests
            .iter()
            .map(|request| {
                String::from_utf8_lossy(request)
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert!(request_lines.iter().all(|line| line.starts_with("GET ")));
        assert_eq!(request_lines[1], "GET /api/v4/projects/42 HTTP/1.1");
        assert_eq!(request_lines[2], "GET /api/v4/projects/41 HTTP/1.1");
        assert!(request_lines[3].contains("versions?page=1&per_page=1"));
        assert!(request_lines[4].contains("versions?page=2&per_page=1"));
        assert!(request_lines[7].contains("/projects/42/repository/files/"));
        assert!(request_lines[7].contains("ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(request_lines[8].contains("/projects/41/repository/files/"));
        assert!(request_lines[8].contains("ref=cccccccccccccccccccccccccccccccccccccccc"));
    }

    #[tokio::test]
    async fn missing_blob_is_an_honest_partial_snapshot() {
        let [old, new] = blob_requests();
        let responses = vec![
            json_response(merge_request('c')),
            json_response(project(42, "group/target")),
            json_response(project(41, "fork/source")),
            page_response(json!([version(9, 'c')]), 1, 1, None, 1, 1),
            json_response(exact_version(vec![changed_file("src/lib.rs")])),
            page_response(json!([changed_file("src/lib.rs")]), 1, 1, None, 1, 1),
            raw_response(&old, 'f', b"old\n"),
            json_status("404 Not Found"),
            json_response(merge_request('c')),
        ];
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let controller = GitLabSnapshotController::new(&client, limits()).unwrap();
        let GitLabSnapshotAcquisitionOutcome::Partial(snapshot) =
            controller.acquire(verification()).await
        else {
            panic!("expected partial snapshot")
        };
        let SnapshotReadiness::Partial { reasons } = &snapshot.assessment().readiness else {
            panic!("expected partial assessment")
        };
        assert!(reasons.contains(&CoverageGap::BlobUnavailable {
            request: new,
            reason: BlobUnavailableReason::Missing,
        }));
        assert_eq!(snapshot.replay().unwrap(), snapshot.assessment().clone());
        assert_eq!(server.await.unwrap().len(), 9);
    }

    #[tokio::test]
    async fn duplicate_current_projection_is_blocked_not_complete() {
        let [old, new] = blob_requests();
        let responses = vec![
            json_response(merge_request('c')),
            json_response(project(42, "group/target")),
            json_response(project(41, "fork/source")),
            page_response(json!([version(9, 'c')]), 1, 2, None, 1, 1),
            json_response(exact_version(vec![changed_file("src/lib.rs")])),
            page_response(
                json!([changed_file("src/lib.rs"), changed_file("src/lib.rs")]),
                1,
                2,
                None,
                2,
                1,
            ),
            raw_response(&old, 'f', b"old\n"),
            raw_response(&new, 'd', b"new\n"),
            json_response(merge_request('c')),
        ];
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let mut limits = limits();
        limits.per_page = 2;
        let controller = GitLabSnapshotController::new(&client, limits).unwrap();
        let GitLabSnapshotAcquisitionOutcome::Blocked(snapshot) =
            controller.acquire(verification()).await
        else {
            panic!("expected blocked snapshot")
        };
        let SnapshotReadiness::Blocked { reasons, .. } = &snapshot.assessment().readiness else {
            panic!("expected blocked assessment")
        };
        assert!(
            reasons.contains(&SnapshotBlocker::DuplicateCurrentChangedPath {
                path: ChangedPath {
                    old_path: RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap(),
                    new_path: RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap(),
                    kind: revoot_core::FileChangeKind::Modified,
                },
            })
        );
        assert_eq!(snapshot.replay().unwrap(), snapshot.assessment().clone());
        assert_eq!(server.await.unwrap().len(), 9);
    }

    #[tokio::test]
    async fn transport_wire_and_identity_failures_remain_distinct_and_safe() {
        let (address, server) = serve_sequence(vec![json_status("401 Unauthorized")]).await;
        let client = build_client(address);
        let controller = GitLabSnapshotController::new(&client, limits()).unwrap();
        assert_eq!(
            controller.acquire(verification()).await,
            GitLabSnapshotAcquisitionOutcome::Failed(GitLabSnapshotAcquisitionFailure::Transport(
                GitLabSnapshotTransportFailure {
                    stage: GitLabSnapshotStage::InitialMergeRequest,
                    kind: GitLabFailureKind::Authentication,
                    status: Some(401),
                    retry: GitLabRetryMetadata::default(),
                    evidence: acquisition_evidence(1, 0, 0),
                }
            ))
        );
        server.await.unwrap();

        let mut malformed = merge_request('c');
        malformed
            .as_object_mut()
            .unwrap()
            .insert("iid".to_owned(), Value::String("7".to_owned()));
        let (address, server) = serve_sequence(vec![json_response(malformed)]).await;
        let client = build_client(address);
        let controller = GitLabSnapshotController::new(&client, limits()).unwrap();
        assert_eq!(
            controller.acquire(verification()).await,
            GitLabSnapshotAcquisitionOutcome::Failed(GitLabSnapshotAcquisitionFailure::Wire {
                stage: GitLabSnapshotStage::InitialMergeRequest,
                error: GitLabWireError::MalformedJson,
                evidence: acquisition_evidence(1, 0, 0),
            })
        );
        server.await.unwrap();

        let responses = vec![
            json_response(merge_request('c')),
            json_response(project(7, "group/target")),
        ];
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let controller = GitLabSnapshotController::new(&client, limits()).unwrap();
        let outcome = controller.acquire(verification()).await;
        let debug = format!("{outcome:?}");
        assert_eq!(
            outcome,
            GitLabSnapshotAcquisitionOutcome::Failed(GitLabSnapshotAcquisitionFailure::Identity {
                failure: GitLabSnapshotIdentityFailure::ProjectProjectionMismatch {
                    role: GitLabProjectRole::Target,
                },
                evidence: acquisition_evidence(2, 0, 1),
            })
        );
        assert!(!debug.contains("fixture-token"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pagination_gap_and_final_freshness_change_fail_closed() {
        let mut gap_page = page_response(json!([version(9, 'c')]), 1, 1, Some(3), 2, 2);
        gap_page.headers.truncate(4);
        let responses = vec![
            json_response(merge_request('c')),
            json_response(project(42, "group/target")),
            json_response(project(41, "fork/source")),
            gap_page,
        ];
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let controller = GitLabSnapshotController::new(&client, limits()).unwrap();
        assert!(matches!(
            controller.acquire(verification()).await,
            GitLabSnapshotAcquisitionOutcome::Failed(GitLabSnapshotAcquisitionFailure::Wire {
                stage: GitLabSnapshotStage::DiffVersions,
                error: GitLabWireError::PaginationGap,
                ..
            })
        ));
        server.await.unwrap();

        let mut responses = complete_responses();
        *responses.last_mut().unwrap() = json_response(merge_request('d'));
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let controller = GitLabSnapshotController::new(&client, limits()).unwrap();
        assert_eq!(
            controller.acquire(verification()).await,
            GitLabSnapshotAcquisitionOutcome::Failed(GitLabSnapshotAcquisitionFailure::Identity {
                failure: GitLabSnapshotIdentityFailure::SnapshotChangedDuringAcquisition,
                evidence: acquisition_evidence(10, 0, 2),
            })
        );
        assert_eq!(server.await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn controller_wide_request_and_deadline_budgets_are_terminal() {
        let responses = vec![
            json_response(merge_request('c')),
            json_response(project(42, "group/target")),
            json_response(project(41, "fork/source")),
        ];
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let mut bounded = limits();
        bounded.max_total_requests = 3;
        let controller = GitLabSnapshotController::new(&client, bounded).unwrap();
        assert_eq!(
            controller.acquire(verification()).await,
            GitLabSnapshotAcquisitionOutcome::Failed(GitLabSnapshotAcquisitionFailure::Budget(
                GitLabSnapshotBudgetFailure {
                    stage: GitLabSnapshotStage::DiffVersions,
                    kind: GitLabSnapshotBudgetFailureKind::RequestLimit,
                    requests_started: 3,
                    evidence: acquisition_evidence(3, 0, 1),
                }
            ))
        );
        assert_eq!(server.await.unwrap().len(), 3);

        let mut delayed = json_response(merge_request('c'));
        delayed.delay = Some(Duration::from_millis(100));
        let (address, server) = serve_sequence(vec![delayed]).await;
        let client = build_client(address);
        let mut bounded = limits();
        bounded.acquisition_timeout = Duration::from_millis(20);
        let controller = GitLabSnapshotController::new(&client, bounded).unwrap();
        assert_eq!(
            controller.acquire(verification()).await,
            GitLabSnapshotAcquisitionOutcome::Failed(GitLabSnapshotAcquisitionFailure::Budget(
                GitLabSnapshotBudgetFailure {
                    stage: GitLabSnapshotStage::InitialMergeRequest,
                    kind: GitLabSnapshotBudgetFailureKind::Deadline,
                    requests_started: 1,
                    evidence: acquisition_evidence(1, 0, 0),
                }
            ))
        );
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bounded_preparation_poll_and_retry_are_visible_and_deadline_dominated() {
        let mut unprepared = merge_request('c');
        unprepared
            .as_object_mut()
            .unwrap()
            .insert("diff_refs".to_owned(), Value::Null);
        let mut responses = complete_responses();
        responses.insert(0, json_response(unprepared.clone()));
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let mut bounded = limits();
        bounded.retry.initial_backoff = Duration::from_millis(1);
        bounded.retry.max_backoff = Duration::from_millis(2);
        let controller = GitLabSnapshotController::new(&client, bounded).unwrap();
        let GitLabSnapshotAcquisitionOutcome::Complete(snapshot) =
            controller.acquire(verification()).await
        else {
            panic!("expected prepared complete snapshot")
        };
        assert_eq!(
            snapshot.acquisition_evidence(),
            acquisition_evidence(11, 0, 3)
        );
        assert_eq!(server.await.unwrap().len(), 11);

        let mut responses = complete_responses();
        responses.insert(0, json_status("503 Service Unavailable"));
        let (address, server) = serve_sequence(responses).await;
        let client = build_client(address);
        let mut bounded = limits();
        bounded.retry.initial_backoff = Duration::from_millis(1);
        bounded.retry.max_backoff = Duration::from_millis(2);
        let controller = GitLabSnapshotController::new(&client, bounded).unwrap();
        let GitLabSnapshotAcquisitionOutcome::Complete(snapshot) =
            controller.acquire(verification()).await
        else {
            panic!("expected retry-complete snapshot")
        };
        assert_eq!(
            snapshot.acquisition_evidence(),
            acquisition_evidence(11, 1, 2)
        );
        assert_eq!(server.await.unwrap().len(), 11);

        let (address, server) = serve_sequence(vec![
            json_response(unprepared.clone()),
            json_response(unprepared),
        ])
        .await;
        let client = build_client(address);
        let mut bounded = limits();
        bounded.retry.max_preparation_polls = 2;
        bounded.retry.initial_backoff = Duration::from_millis(1);
        bounded.retry.max_backoff = Duration::from_millis(2);
        let controller = GitLabSnapshotController::new(&client, bounded).unwrap();
        assert_eq!(
            controller.acquire(verification()).await,
            GitLabSnapshotAcquisitionOutcome::Failed(
                GitLabSnapshotAcquisitionFailure::Preparation(GitLabSnapshotPreparationFailure {
                    stage: GitLabSnapshotStage::InitialMergeRequest,
                    polls_completed: 2,
                    evidence: acquisition_evidence(2, 0, 2),
                })
            )
        );
        assert_eq!(server.await.unwrap().len(), 2);
    }

    #[test]
    fn invalid_limits_are_rejected_before_controller_construction() {
        let client = build_client(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9).into());
        let limits = GitLabSnapshotAcquisitionLimits {
            per_page: 101,
            ..GitLabSnapshotAcquisitionLimits::default()
        };
        assert_eq!(
            GitLabSnapshotController::new(&client, limits).err(),
            Some(GitLabSnapshotControllerBuildError::InvalidPerPage)
        );

        let limits = GitLabSnapshotAcquisitionLimits {
            max_total_requests: 0,
            ..GitLabSnapshotAcquisitionLimits::default()
        };
        assert_eq!(
            GitLabSnapshotController::new(&client, limits).err(),
            Some(GitLabSnapshotControllerBuildError::InvalidTotalRequestLimit)
        );

        let limits = GitLabSnapshotAcquisitionLimits {
            acquisition_timeout: Duration::ZERO,
            ..GitLabSnapshotAcquisitionLimits::default()
        };
        assert_eq!(
            GitLabSnapshotController::new(&client, limits).err(),
            Some(GitLabSnapshotControllerBuildError::InvalidAcquisitionTimeout)
        );

        let limits = GitLabSnapshotAcquisitionLimits {
            retry: GitLabSnapshotRetryPolicy {
                max_read_attempts: 0,
                ..GitLabSnapshotRetryPolicy::default()
            },
            ..GitLabSnapshotAcquisitionLimits::default()
        };
        assert_eq!(
            GitLabSnapshotController::new(&client, limits).err(),
            Some(GitLabSnapshotControllerBuildError::InvalidRetryPolicy)
        );
    }
}
