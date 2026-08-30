//! Strict, bounded GitLab REST wire parsing and deterministic pagination.
//!
//! The caller supplies already-authenticated response observations. This module
//! performs no HTTP, DNS, credential, filesystem, process, or publication work.

use std::collections::{BTreeMap, BTreeSet};
use std::str;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::publication::{ExistingPublicationNote, PublicationInventory};
use crate::snapshot::{
    BlobIdentity, BlobRepresentation, BlobRequest, ChangedFile, ChangedFileCount, ChangedPath,
    DiffAvailability, DiffRefs, DiffVersionId, DiffVersionRecord, DiffVersionState, FileChangeKind,
    GitSha, MergeRequestIid, PageReceipt, PaginatedAcquisition, ProjectId, RepositoryPath,
    Sha256Digest,
};
use crate::{GitLabProjectIdentity, GitLabProjectPath, GitRefName};

const HARD_MAX_JSON_BODY_BYTES: usize = 32 * 1024 * 1024;
const HARD_MAX_BLOB_BODY_BYTES: usize = 32 * 1024 * 1024;
const HARD_MAX_ITEMS_PER_PAGE: u32 = 1_000;
const HARD_MAX_PAGES: u32 = 10_000;
const HARD_MAX_TOTAL_ITEMS: u32 = 1_000_000;
const HARD_MAX_HEADER_COUNT: u32 = 512;
const HARD_MAX_HEADER_BYTES: usize = 64 * 1024;

/// Bounds applied before allocating or converting untrusted GitLab responses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitLabWireLimits {
    pub max_json_body_bytes: usize,
    pub max_blob_body_bytes: usize,
    pub max_items_per_page: u32,
    pub max_pages: u32,
    pub max_total_items: u32,
    pub max_diff_bytes: usize,
    pub max_note_body_bytes: usize,
    pub max_string_bytes: usize,
    pub max_notes_per_discussion: u32,
    pub max_header_count: u32,
    pub max_header_name_bytes: usize,
    pub max_header_value_bytes: usize,
}

impl Default for GitLabWireLimits {
    fn default() -> Self {
        Self {
            max_json_body_bytes: 8 * 1024 * 1024,
            max_blob_body_bytes: 4 * 1024 * 1024,
            max_items_per_page: 100,
            max_pages: 1_000,
            max_total_items: 100_000,
            max_diff_bytes: 2 * 1024 * 1024,
            max_note_body_bytes: 128 * 1024,
            max_string_bytes: 4_096,
            max_notes_per_discussion: 1_000,
            max_header_count: 128,
            max_header_name_bytes: 128,
            max_header_value_bytes: 16 * 1024,
        }
    }
}

impl GitLabWireLimits {
    /// Validate nonzero hard bounds and their internal relationships.
    ///
    /// # Errors
    ///
    /// Returns [`GitLabWireError::InvalidLimits`] for an unusable dimension.
    pub fn validate(self) -> Result<(), GitLabWireError> {
        let valid = self.max_json_body_bytes > 0
            && self.max_json_body_bytes <= HARD_MAX_JSON_BODY_BYTES
            && self.max_blob_body_bytes > 0
            && self.max_blob_body_bytes <= HARD_MAX_BLOB_BODY_BYTES
            && self.max_items_per_page > 0
            && self.max_items_per_page <= HARD_MAX_ITEMS_PER_PAGE
            && self.max_pages > 0
            && self.max_pages <= HARD_MAX_PAGES
            && self.max_total_items > 0
            && self.max_total_items <= HARD_MAX_TOTAL_ITEMS
            && self.max_diff_bytes > 0
            && self.max_diff_bytes <= self.max_json_body_bytes
            && self.max_note_body_bytes > 0
            && self.max_note_body_bytes <= self.max_json_body_bytes
            && self.max_string_bytes > 0
            && self.max_string_bytes <= self.max_json_body_bytes
            && self.max_notes_per_discussion > 0
            && self.max_notes_per_discussion <= self.max_total_items
            && self.max_header_count > 0
            && self.max_header_count <= HARD_MAX_HEADER_COUNT
            && self.max_header_name_bytes > 0
            && self.max_header_name_bytes <= HARD_MAX_HEADER_BYTES
            && self.max_header_value_bytes > 0
            && self.max_header_value_bytes <= HARD_MAX_HEADER_BYTES;
        if valid {
            Ok(())
        } else {
            Err(GitLabWireError::InvalidLimits)
        }
    }
}

/// One raw response header observed by the transport adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabResponseHeader {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// One complete response observation with no transport or credential capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabResponseObservation {
    pub status: u16,
    pub headers: Vec<GitLabResponseHeader>,
    pub body: Vec<u8>,
}

/// Bounded response metadata retained without copying arbitrary headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabResponseMetadata {
    pub status: u16,
    pub content_length: Option<u64>,
    pub request_id: Option<String>,
}

/// Closed failure taxonomy for untrusted GitLab response data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitLabWireError {
    InvalidLimits,
    UnexpectedStatus(u16),
    BodyTooLarge { observed: usize, maximum: usize },
    EmptyBody,
    InvalidUtf8 { valid_up_to: usize },
    MalformedJson,
    WrongContentType,
    TooManyHeaders { observed: usize, maximum: u32 },
    InvalidHeaderName,
    HeaderNameTooLong,
    HeaderValueTooLong,
    InvalidHeaderValue,
    DuplicateHeader(String),
    InvalidHeaderNumber(String),
    ContentLengthMismatch { declared: u64, observed: usize },
    StringTooLong,
    InvalidIdentifier,
    InvalidProject,
    InvalidRef,
    InvalidSha,
    InvalidPath,
    InvalidMergeRequestState,
    InvalidChangedFileCount,
    DiffRefsHeadMismatch,
    InvalidDiffVersionState,
    TooManyPageItems { observed: usize, maximum: u32 },
    InvalidRequestedPage,
    PaginationPageMismatch,
    PaginationPerPageMismatch,
    PaginationPreviousMismatch,
    PaginationNextMismatch,
    PaginationCycle,
    PaginationGap,
    PaginationAfterTerminal,
    PaginationContinuationMissing,
    PaginationAmbiguousContinuation,
    PaginationTotalMismatch,
    PaginationOverflow,
    MalformedLinkHeader,
    TooManyPages,
    TooManyTotalItems,
    InvalidChangedPath,
    ContradictoryDiffFlags,
    DiffTooLarge { observed: usize, maximum: usize },
    InvalidExactVersion,
    TooManyDiscussionNotes,
    InvalidDiscussion,
    DuplicateDiscussionId,
    DuplicateNoteId,
    CreatedResponseMismatch,
    NoteBodyTooLarge,
    BlobMetadataMissing(String),
    BlobMetadataMismatch(String),
    BlobDigestMismatch,
    BlobSizeMismatch,
}

/// Narrow project identity response used to authenticate configured and fork paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabProjectWire {
    pub id: u64,
    pub path_with_namespace: String,
}

/// Raw merge-request SHA triple.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabDiffRefsWire {
    pub base_sha: String,
    pub start_sha: String,
    pub head_sha: String,
}

/// Narrow merge-request metadata response used by snapshot binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabMergeRequestWire {
    pub id: u64,
    pub iid: u64,
    pub project_id: u64,
    pub source_project_id: Option<u64>,
    pub target_project_id: u64,
    pub state: String,
    pub source_branch: String,
    pub target_branch: String,
    pub sha: String,
    pub diff_refs: Option<GitLabDiffRefsWire>,
    pub changes_count: Option<String>,
}

/// Validated MR state needed by the deterministic controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabMergeRequestState {
    Opened,
    Closed,
    Merged,
    Locked,
}

/// Trusted conversion of the narrow merge-request metadata response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMergeRequestMetadata {
    pub merge_request_id: u64,
    pub iid: MergeRequestIid,
    pub project_id: ProjectId,
    pub source_project_id: Option<ProjectId>,
    pub target_project_id: ProjectId,
    pub state: GitLabMergeRequestState,
    pub source_ref: GitRefName,
    pub target_ref: GitRefName,
    pub head_sha: GitSha,
    pub diff_refs: Option<DiffRefs>,
    pub changed_files: ChangedFileCount,
}

/// Raw item from the merge-request diff-versions endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabDiffVersionWire {
    pub id: u64,
    pub head_commit_sha: String,
    pub base_commit_sha: String,
    pub start_commit_sha: String,
    pub state: String,
    pub real_size: Option<String>,
    pub created_at: Option<String>,
    pub merge_request_id: Option<u64>,
    pub patch_id_sha: Option<String>,
}

/// Validated diff-version identity plus completeness signals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDiffVersion {
    pub record: DiffVersionRecord,
    pub state: DiffVersionState,
    pub reported_files: ChangedFileCount,
    pub merge_request_id: Option<u64>,
}

/// Raw file-diff item returned by current or exact-version endpoints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabChangedFileWire {
    pub old_path: String,
    pub new_path: String,
    pub a_mode: Option<String>,
    pub b_mode: Option<String>,
    pub diff: Option<String>,
    pub new_file: bool,
    pub renamed_file: bool,
    pub deleted_file: bool,
    pub generated_file: Option<bool>,
    pub collapsed: Option<bool>,
    pub too_large: Option<bool>,
}

/// Validated changed-file metadata and available unified-diff bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedChangedFile {
    pub file: ChangedFile,
    pub generated: Option<bool>,
    pub unified_diff: Option<Vec<u8>>,
}

/// Raw exact diff-version response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabExactDiffVersionWire {
    pub id: u64,
    pub head_commit_sha: String,
    pub base_commit_sha: String,
    pub start_commit_sha: String,
    pub state: String,
    pub real_size: Option<String>,
    pub created_at: Option<String>,
    pub merge_request_id: Option<u64>,
    pub patch_id_sha: Option<String>,
    pub diffs: Vec<GitLabChangedFileWire>,
}

/// Exact-version response after strict identity and file conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedExactDiffVersion {
    pub version: ValidatedDiffVersion,
    pub files: Vec<ValidatedChangedFile>,
}

/// Raw user identity nested in a discussion note.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabDiscussionAuthorWire {
    pub id: u64,
    pub username: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabDiscussionPositionWire {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub old_line: Option<u32>,
    pub new_line: Option<u32>,
}

/// Raw note inventory entry. The narrow response contract intentionally retains
/// only fields used for ownership and deterministic marker reconciliation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabDiscussionNoteWire {
    pub id: u64,
    #[serde(rename = "type")]
    pub note_type: Option<String>,
    pub body: String,
    pub author: GitLabDiscussionAuthorWire,
    pub system: bool,
    #[serde(default)]
    pub resolvable: bool,
    #[serde(default)]
    pub resolved: bool,
    pub resolved_by: Option<GitLabDiscussionAuthorWire>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub resolved_at: Option<String>,
    pub position: Option<GitLabDiscussionPositionWire>,
}

/// Raw discussion and its bounded notes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GitLabDiscussionWire {
    pub id: String,
    pub individual_note: bool,
    pub notes: Vec<GitLabDiscussionNoteWire>,
}

/// Validated discussion entry retained before flattening publication inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDiscussion {
    pub id: String,
    pub individual_note: bool,
    pub notes: Vec<ExistingPublicationNote>,
}

/// Identity retained from a validated create-only publication response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedCreatedPublication {
    pub note_id: u64,
}

/// Validated raw blob bytes and exact immutable identity metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRawBlob {
    pub identity: BlobIdentity,
    pub execute_filemode: bool,
    pub body: Vec<u8>,
}

/// One offset-pagination response proven internally consistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabPaginationMetadata {
    pub page_number: u32,
    pub per_page: u32,
    pub item_count: u32,
    pub next_page: Option<u32>,
    pub total_items: Option<u64>,
    pub total_pages: Option<u32>,
}

/// One typed page paired with validated response pagination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabPage<T> {
    pub metadata: GitLabPaginationMetadata,
    pub items: Vec<T>,
}

/// Parse bounded common response metadata without interpreting a response body.
///
/// # Errors
///
/// Rejects invalid limits, malformed/duplicate observed headers, content-length
/// mismatch, or an overlong request identifier.
pub fn parse_response_metadata(
    response: &GitLabResponseObservation,
    limits: GitLabWireLimits,
) -> Result<GitLabResponseMetadata, GitLabWireError> {
    limits.validate()?;
    let headers = ParsedHeaders::parse(&response.headers, limits)?;
    headers.validate_content_length(response.body.len())?;
    let content_length = headers.optional_u64("content-length")?;
    let request_id = headers.get("x-request-id").map(str::to_owned);
    if request_id
        .as_ref()
        .is_some_and(|value| value.len() > limits.max_string_bytes)
    {
        return Err(GitLabWireError::StringTooLong);
    }
    Ok(GitLabResponseMetadata {
        status: response.status,
        content_length,
        request_id,
    })
}

/// Parse and validate the narrow merge-request response.
///
/// # Errors
///
/// Rejects response, JSON, identifier, SHA, state, and count ambiguity.
pub fn parse_merge_request_response(
    response: &GitLabResponseObservation,
    limits: GitLabWireLimits,
) -> Result<ValidatedMergeRequestMetadata, GitLabWireError> {
    let wire: GitLabMergeRequestWire = parse_json_response(response, limits)?;
    validate_merge_request(wire, limits)
}

/// Parse and validate the narrow authenticated project identity response.
///
/// # Errors
///
/// Rejects response, JSON, identifier, and namespace-path ambiguity.
pub fn parse_project_response(
    response: &GitLabResponseObservation,
    limits: GitLabWireLimits,
) -> Result<GitLabProjectIdentity, GitLabWireError> {
    let wire: GitLabProjectWire = parse_json_response(response, limits)?;
    validate_bounded_string(&wire.path_with_namespace, limits)?;
    Ok(GitLabProjectIdentity {
        id: ProjectId::try_from(wire.id).map_err(|_| GitLabWireError::InvalidProject)?,
        path: GitLabProjectPath::try_from(wire.path_with_namespace)
            .map_err(|_| GitLabWireError::InvalidProject)?,
    })
}

/// Parse one diff-version collection page.
///
/// # Errors
///
/// Rejects malformed bodies/items or inconsistent pagination metadata.
pub fn parse_diff_versions_page(
    response: &GitLabResponseObservation,
    requested_page: u32,
    requested_per_page: u32,
    limits: GitLabWireLimits,
) -> Result<GitLabPage<ValidatedDiffVersion>, GitLabWireError> {
    let wire: Vec<GitLabDiffVersionWire> = parse_json_response(response, limits)?;
    validate_item_count(wire.len(), limits)?;
    let metadata = parse_pagination(
        response,
        requested_page,
        requested_per_page,
        wire.len(),
        limits,
    )?;
    let items = wire
        .into_iter()
        .map(|item| validate_diff_version(item, limits))
        .collect::<Result<_, _>>()?;
    Ok(GitLabPage { metadata, items })
}

/// Parse one current changed-file collection page.
///
/// # Errors
///
/// Rejects malformed bodies, structural flag contradictions, unsafe paths,
/// oversized diffs, or inconsistent pagination.
pub fn parse_changed_files_page(
    response: &GitLabResponseObservation,
    requested_page: u32,
    requested_per_page: u32,
    limits: GitLabWireLimits,
) -> Result<GitLabPage<ValidatedChangedFile>, GitLabWireError> {
    let wire: Vec<GitLabChangedFileWire> = parse_json_response(response, limits)?;
    validate_item_count(wire.len(), limits)?;
    let metadata = parse_pagination(
        response,
        requested_page,
        requested_per_page,
        wire.len(),
        limits,
    )?;
    let items = wire
        .into_iter()
        .map(|item| validate_changed_file(item, limits))
        .collect::<Result<_, _>>()?;
    Ok(GitLabPage { metadata, items })
}

/// Parse one exact diff-version response.
///
/// # Errors
///
/// Rejects malformed identity, count/state ambiguity, excessive files, and any
/// changed-file contradiction that could overstate exact-version coverage.
pub fn parse_exact_diff_version_response(
    response: &GitLabResponseObservation,
    limits: GitLabWireLimits,
) -> Result<ValidatedExactDiffVersion, GitLabWireError> {
    let wire: GitLabExactDiffVersionWire = parse_json_response(response, limits)?;
    validate_item_count(wire.diffs.len(), limits)?;
    let version = validate_diff_version(
        GitLabDiffVersionWire {
            id: wire.id,
            head_commit_sha: wire.head_commit_sha,
            base_commit_sha: wire.base_commit_sha,
            start_commit_sha: wire.start_commit_sha,
            state: wire.state,
            real_size: wire.real_size,
            created_at: wire.created_at,
            merge_request_id: wire.merge_request_id,
            patch_id_sha: wire.patch_id_sha,
        },
        limits,
    )?;
    let files = wire
        .diffs
        .into_iter()
        .map(|item| validate_changed_file(item, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let unique: BTreeSet<_> = files.iter().map(|file| &file.file.path).collect();
    if unique.len() != files.len() {
        return Err(GitLabWireError::InvalidExactVersion);
    }
    if matches!(version.state, DiffVersionState::WithoutFiles) && !files.is_empty() {
        return Err(GitLabWireError::InvalidExactVersion);
    }
    if let ChangedFileCount::Exact(reported) = version.reported_files
        && usize::try_from(reported).unwrap_or(usize::MAX) < files.len()
    {
        return Err(GitLabWireError::InvalidExactVersion);
    }
    Ok(ValidatedExactDiffVersion { version, files })
}

/// Parse one discussion collection page.
///
/// # Errors
///
/// Rejects malformed or oversized discussion/note data and inconsistent pagination.
pub fn parse_discussions_page(
    response: &GitLabResponseObservation,
    requested_page: u32,
    requested_per_page: u32,
    limits: GitLabWireLimits,
) -> Result<GitLabPage<ValidatedDiscussion>, GitLabWireError> {
    let wire: Vec<GitLabDiscussionWire> = parse_json_response(response, limits)?;
    validate_item_count(wire.len(), limits)?;
    let metadata = parse_pagination(
        response,
        requested_page,
        requested_per_page,
        wire.len(),
        limits,
    )?;
    let items = wire
        .into_iter()
        .map(|item| validate_discussion(item, limits))
        .collect::<Result<_, _>>()?;
    Ok(GitLabPage { metadata, items })
}

/// Validate the response to a create-discussion request against the exact body
/// and authenticated bot identity that the caller authorized.
///
/// Unknown GitLab response fields remain forward-compatible, while duplicate
/// known fields, missing fields, invalid types, and identity/body mismatches are
/// rejected by the narrow wire contract.
///
/// # Errors
///
/// Rejects any non-201, malformed, oversized, ambiguous, system-generated, or
/// body/author-mismatched response.
pub fn parse_created_discussion_response(
    response: &GitLabResponseObservation,
    expected_body: &str,
    expected_bot_user_id: u64,
    limits: GitLabWireLimits,
) -> Result<ValidatedCreatedPublication, GitLabWireError> {
    let wire: GitLabDiscussionWire = parse_json_response_with_status(response, limits, 201)?;
    if wire.individual_note
        || wire.notes.len() != 1
        || wire.notes[0].system
        || wire.notes[0].note_type.as_deref() != Some("DiffNote")
    {
        return Err(GitLabWireError::CreatedResponseMismatch);
    }
    let discussion = validate_discussion(wire, limits)?;
    validate_created_note(&discussion.notes[0], expected_body, expected_bot_user_id)
}

/// Validate the response to a create-note request against the exact body and
/// authenticated bot identity that the caller authorized.
///
/// # Errors
///
/// Rejects any non-201, malformed, oversized, ambiguous, system-generated, or
/// body/author-mismatched response.
pub fn parse_created_note_response(
    response: &GitLabResponseObservation,
    expected_body: &str,
    expected_bot_user_id: u64,
    limits: GitLabWireLimits,
) -> Result<ValidatedCreatedPublication, GitLabWireError> {
    let wire: GitLabDiscussionNoteWire = parse_json_response_with_status(response, limits, 201)?;
    if wire.system || wire.note_type.is_some() {
        return Err(GitLabWireError::CreatedResponseMismatch);
    }
    let discussion = validate_discussion(
        GitLabDiscussionWire {
            id: "created-note".to_owned(),
            individual_note: true,
            notes: vec![wire],
        },
        limits,
    )?;
    validate_created_note(&discussion.notes[0], expected_body, expected_bot_user_id)
}

/// Validate a discussion resolution-state response against the exact discussion, note,
/// and authenticated bot identity selected by reconciliation.
///
/// # Errors
///
/// Rejects a non-200, malformed, mismatched, non-resolvable, or wrong-state response.
pub fn parse_discussion_resolution_response(
    response: &GitLabResponseObservation,
    expected_discussion_id: &str,
    expected_note_id: u64,
    expected_bot_user_id: u64,
    expected_resolved: bool,
    limits: GitLabWireLimits,
) -> Result<(), GitLabWireError> {
    let wire: GitLabDiscussionWire = parse_json_response_with_status(response, limits, 200)?;
    if wire.id != expected_discussion_id || wire.individual_note {
        return Err(GitLabWireError::CreatedResponseMismatch);
    }
    let discussion = validate_discussion(wire, limits)?;
    let Some(note) = discussion.notes.iter().find(|note| {
        note.note_id == expected_note_id && note.author_user_id == expected_bot_user_id
    }) else {
        return Err(GitLabWireError::CreatedResponseMismatch);
    };
    if !note.resolvable || note.resolved != expected_resolved {
        return Err(GitLabWireError::CreatedResponseMismatch);
    }
    Ok(())
}

/// Validate raw repository-file bytes against exact request and GitLab metadata headers.
///
/// # Errors
///
/// Rejects missing/inconsistent headers, status, byte bounds, digest, size, path,
/// ref, commit, or blob identity mismatches.
pub fn parse_raw_blob_response(
    request: &BlobRequest,
    response: &GitLabResponseObservation,
    limits: GitLabWireLimits,
) -> Result<ValidatedRawBlob, GitLabWireError> {
    limits.validate()?;
    validate_success_status(response.status)?;
    if response.body.len() > limits.max_blob_body_bytes {
        return Err(GitLabWireError::BodyTooLarge {
            observed: response.body.len(),
            maximum: limits.max_blob_body_bytes,
        });
    }
    let headers = ParsedHeaders::parse(&response.headers, limits)?;
    headers.validate_content_length(response.body.len())?;
    let blob_sha = parse_required_sha_header(&headers, "x-gitlab-blob-id")?;
    let commit_sha = parse_required_sha_header(&headers, "x-gitlab-commit-id")?;
    if commit_sha != request.commit_sha {
        return Err(GitLabWireError::BlobMetadataMismatch(
            "x-gitlab-commit-id".to_owned(),
        ));
    }
    let ref_value = headers.required("x-gitlab-ref")?;
    if ref_value != request.commit_sha.as_str() {
        return Err(GitLabWireError::BlobMetadataMismatch(
            "x-gitlab-ref".to_owned(),
        ));
    }
    let path = RepositoryPath::try_from(headers.required("x-gitlab-file-path")?.to_owned())
        .map_err(|_| GitLabWireError::InvalidPath)?;
    if path != request.path {
        return Err(GitLabWireError::BlobMetadataMismatch(
            "x-gitlab-file-path".to_owned(),
        ));
    }
    if headers.required("x-gitlab-encoding")? != "base64" {
        return Err(GitLabWireError::BlobMetadataMismatch(
            "x-gitlab-encoding".to_owned(),
        ));
    }
    let declared_size = headers.required_u64("x-gitlab-size")?;
    if declared_size != u64::try_from(response.body.len()).unwrap_or(u64::MAX) {
        return Err(GitLabWireError::BlobSizeMismatch);
    }
    let declared_digest = Sha256Digest::try_from(
        headers.required("x-gitlab-content-sha256")?.to_owned(),
    )
    .map_err(|_| GitLabWireError::BlobMetadataMismatch("x-gitlab-content-sha256".to_owned()))?;
    let actual_digest = Sha256Digest::of_bytes(&response.body);
    if declared_digest != actual_digest {
        return Err(GitLabWireError::BlobDigestMismatch);
    }
    let execute_filemode =
        parse_bool(headers.required("x-gitlab-execute-filemode")?).ok_or_else(|| {
            GitLabWireError::BlobMetadataMismatch("x-gitlab-execute-filemode".to_owned())
        })?;
    let representation = if is_lfs_pointer(&response.body) {
        BlobRepresentation::LfsPointer
    } else {
        BlobRepresentation::FileContent
    };
    Ok(ValidatedRawBlob {
        identity: BlobIdentity {
            request: request.clone(),
            blob_sha,
            content_sha256: actual_digest,
            size_bytes: declared_size,
            representation,
        },
        execute_filemode,
        body: response.body.clone(),
    })
}

/// Validate a complete ordered offset-pagination acquisition.
///
/// # Errors
///
/// Rejects empty, gapped, cyclic, reordered, over-limit, inconsistent-total,
/// post-terminal, or unfinished page sequences.
pub fn collect_complete_pages<T>(
    pages: Vec<GitLabPage<T>>,
    limits: GitLabWireLimits,
) -> Result<PaginatedAcquisition<T>, GitLabWireError> {
    limits.validate()?;
    if pages.is_empty() {
        return Err(GitLabWireError::PaginationContinuationMissing);
    }
    if pages.len() > usize::try_from(limits.max_pages).unwrap_or(usize::MAX) {
        return Err(GitLabWireError::TooManyPages);
    }
    let expected_per_page = pages[0].metadata.per_page;
    if expected_per_page == 0 || expected_per_page > limits.max_items_per_page {
        return Err(GitLabWireError::PaginationPerPageMismatch);
    }
    let expected_total = pages[0].metadata.total_items;
    let expected_total_pages = pages[0].metadata.total_pages;
    let mut items = Vec::new();
    let mut receipts = Vec::new();
    let mut previous_next = Some(1_u32);
    for (index, page) in pages.into_iter().enumerate() {
        let expected_page = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(GitLabWireError::PaginationOverflow)?;
        if page.metadata.page_number != expected_page {
            return Err(if page.metadata.page_number < expected_page {
                GitLabWireError::PaginationCycle
            } else {
                GitLabWireError::PaginationGap
            });
        }
        if previous_next != Some(expected_page) {
            return Err(GitLabWireError::PaginationAfterTerminal);
        }
        if page.metadata.per_page != expected_per_page
            || page.metadata.total_items != expected_total
            || page.metadata.total_pages != expected_total_pages
            || usize::try_from(page.metadata.item_count).unwrap_or(usize::MAX) != page.items.len()
        {
            return Err(GitLabWireError::PaginationTotalMismatch);
        }
        if page.metadata.item_count > expected_per_page
            || page.metadata.item_count > limits.max_items_per_page
        {
            return Err(GitLabWireError::TooManyPageItems {
                observed: page.items.len(),
                maximum: limits.max_items_per_page,
            });
        }
        if let (Some(total), Some(total_pages)) = (expected_total, expected_total_pages) {
            let expected_next = validate_pagination_totals(
                total,
                total_pages,
                expected_page,
                expected_per_page,
                page.items.len(),
            )?;
            if page.metadata.next_page != expected_next.next_page() {
                return Err(GitLabWireError::PaginationNextMismatch);
            }
        }
        let item_count = page.metadata.item_count;
        previous_next = page.metadata.next_page;
        receipts.push(PageReceipt {
            page_number: expected_page,
            item_count,
            has_next_page: previous_next.is_some(),
        });
        items.extend(page.items);
        if items.len() > usize::try_from(limits.max_total_items).unwrap_or(usize::MAX) {
            return Err(GitLabWireError::TooManyTotalItems);
        }
    }
    if previous_next.is_some() {
        return Err(GitLabWireError::PaginationContinuationMissing);
    }
    if expected_total.is_some_and(|total| total != u64::try_from(items.len()).unwrap_or(u64::MAX)) {
        return Err(GitLabWireError::PaginationTotalMismatch);
    }
    Ok(PaginatedAcquisition {
        items,
        pages: receipts,
    })
}

/// Flatten a completely acquired discussion set into deterministic publication inventory.
///
/// # Errors
///
/// Rejects page-sequence errors and duplicate discussion or note identities.
pub fn collect_discussion_inventory(
    pages: Vec<GitLabPage<ValidatedDiscussion>>,
    limits: GitLabWireLimits,
) -> Result<PublicationInventory, GitLabWireError> {
    let acquisition = collect_complete_pages(pages, limits)?;
    let mut discussions = BTreeSet::new();
    let mut notes = BTreeMap::new();
    for discussion in acquisition.items {
        if !discussions.insert(discussion.id.clone()) {
            return Err(GitLabWireError::DuplicateDiscussionId);
        }
        for mut note in discussion.notes {
            if !discussion.individual_note {
                note.discussion_id = Some(discussion.id.clone());
            }
            if notes.insert(note.note_id, note).is_some() {
                return Err(GitLabWireError::DuplicateNoteId);
            }
            if notes.len() > usize::try_from(limits.max_total_items).unwrap_or(usize::MAX) {
                return Err(GitLabWireError::TooManyTotalItems);
            }
        }
    }
    Ok(PublicationInventory {
        complete: true,
        notes: notes.into_values().collect(),
    })
}

fn parse_json_response<T: DeserializeOwned>(
    response: &GitLabResponseObservation,
    limits: GitLabWireLimits,
) -> Result<T, GitLabWireError> {
    parse_json_response_with_status(response, limits, 200)
}

fn parse_json_response_with_status<T: DeserializeOwned>(
    response: &GitLabResponseObservation,
    limits: GitLabWireLimits,
    expected_status: u16,
) -> Result<T, GitLabWireError> {
    limits.validate()?;
    if response.status != expected_status {
        return Err(GitLabWireError::UnexpectedStatus(response.status));
    }
    if response.body.is_empty() {
        return Err(GitLabWireError::EmptyBody);
    }
    if response.body.len() > limits.max_json_body_bytes {
        return Err(GitLabWireError::BodyTooLarge {
            observed: response.body.len(),
            maximum: limits.max_json_body_bytes,
        });
    }
    let headers = ParsedHeaders::parse(&response.headers, limits)?;
    headers.validate_content_length(response.body.len())?;
    if let Some(content_type) = headers.get("content-type")
        && !valid_json_content_type(content_type)
    {
        return Err(GitLabWireError::WrongContentType);
    }
    let text = str::from_utf8(&response.body).map_err(|error| GitLabWireError::InvalidUtf8 {
        valid_up_to: error.valid_up_to(),
    })?;
    serde_json::from_str(text).map_err(|_| GitLabWireError::MalformedJson)
}

fn validate_created_note(
    note: &ExistingPublicationNote,
    expected_body: &str,
    expected_bot_user_id: u64,
) -> Result<ValidatedCreatedPublication, GitLabWireError> {
    if expected_bot_user_id == 0
        || note.author_user_id != expected_bot_user_id
        || note.body != expected_body
    {
        return Err(GitLabWireError::CreatedResponseMismatch);
    }
    Ok(ValidatedCreatedPublication {
        note_id: note.note_id,
    })
}

fn validate_merge_request(
    wire: GitLabMergeRequestWire,
    limits: GitLabWireLimits,
) -> Result<ValidatedMergeRequestMetadata, GitLabWireError> {
    validate_bounded_string(&wire.state, limits)?;
    let state = match wire.state.as_str() {
        "opened" => GitLabMergeRequestState::Opened,
        "closed" => GitLabMergeRequestState::Closed,
        "merged" => GitLabMergeRequestState::Merged,
        "locked" => GitLabMergeRequestState::Locked,
        _ => return Err(GitLabWireError::InvalidMergeRequestState),
    };
    if wire.id == 0 {
        return Err(GitLabWireError::InvalidIdentifier);
    }
    validate_bounded_string(&wire.source_branch, limits)?;
    validate_bounded_string(&wire.target_branch, limits)?;
    let iid =
        MergeRequestIid::try_from(wire.iid).map_err(|_| GitLabWireError::InvalidIdentifier)?;
    let project_id =
        ProjectId::try_from(wire.project_id).map_err(|_| GitLabWireError::InvalidIdentifier)?;
    let source_project_id = wire
        .source_project_id
        .map(ProjectId::try_from)
        .transpose()
        .map_err(|_| GitLabWireError::InvalidIdentifier)?;
    let target_project_id = ProjectId::try_from(wire.target_project_id)
        .map_err(|_| GitLabWireError::InvalidIdentifier)?;
    if project_id != target_project_id {
        return Err(GitLabWireError::InvalidIdentifier);
    }
    let head_sha = parse_sha(wire.sha, limits)?;
    let source_ref =
        GitRefName::try_from(wire.source_branch).map_err(|_| GitLabWireError::InvalidRef)?;
    let target_ref =
        GitRefName::try_from(wire.target_branch).map_err(|_| GitLabWireError::InvalidRef)?;
    let diff_refs = wire
        .diff_refs
        .map(|refs| validate_diff_refs(refs, limits))
        .transpose()?;
    if diff_refs
        .as_ref()
        .is_some_and(|refs| refs.head_sha != head_sha)
    {
        return Err(GitLabWireError::DiffRefsHeadMismatch);
    }
    let changed_files = parse_changed_file_count(wire.changes_count.as_deref(), limits)?;
    Ok(ValidatedMergeRequestMetadata {
        merge_request_id: wire.id,
        iid,
        project_id,
        source_project_id,
        target_project_id,
        state,
        source_ref,
        target_ref,
        head_sha,
        diff_refs,
        changed_files,
    })
}

fn validate_diff_refs(
    wire: GitLabDiffRefsWire,
    limits: GitLabWireLimits,
) -> Result<DiffRefs, GitLabWireError> {
    Ok(DiffRefs {
        base_sha: parse_sha(wire.base_sha, limits)?,
        start_sha: parse_sha(wire.start_sha, limits)?,
        head_sha: parse_sha(wire.head_sha, limits)?,
    })
}

fn validate_diff_version(
    wire: GitLabDiffVersionWire,
    limits: GitLabWireLimits,
) -> Result<ValidatedDiffVersion, GitLabWireError> {
    let reported_files = parse_changed_file_count(wire.real_size.as_deref(), limits)?;
    validate_optional_string(wire.created_at.as_deref(), limits)?;
    validate_optional_string(wire.patch_id_sha.as_deref(), limits)?;
    if wire.merge_request_id == Some(0) {
        return Err(GitLabWireError::InvalidIdentifier);
    }
    validate_bounded_string(&wire.state, limits)?;
    let mut state = match wire.state.as_str() {
        "collected" => DiffVersionState::Collected,
        "overflow" => DiffVersionState::Overflow,
        "without_files" => DiffVersionState::WithoutFiles,
        value if !value.is_empty() => DiffVersionState::Unknown(value.to_owned()),
        _ => return Err(GitLabWireError::InvalidDiffVersionState),
    };
    if matches!(reported_files, ChangedFileCount::CappedAt(_)) {
        state = DiffVersionState::Overflow;
    }
    Ok(ValidatedDiffVersion {
        record: DiffVersionRecord {
            id: DiffVersionId::try_from(wire.id).map_err(|_| GitLabWireError::InvalidIdentifier)?,
            refs: DiffRefs {
                base_sha: parse_sha(wire.base_commit_sha, limits)?,
                start_sha: parse_sha(wire.start_commit_sha, limits)?,
                head_sha: parse_sha(wire.head_commit_sha, limits)?,
            },
        },
        state,
        reported_files,
        merge_request_id: wire.merge_request_id,
    })
}

fn validate_changed_file(
    wire: GitLabChangedFileWire,
    limits: GitLabWireLimits,
) -> Result<ValidatedChangedFile, GitLabWireError> {
    for value in [
        wire.old_path.as_str(),
        wire.new_path.as_str(),
        wire.a_mode.as_deref().unwrap_or(""),
        wire.b_mode.as_deref().unwrap_or(""),
    ] {
        validate_bounded_string(value, limits)?;
    }
    let flag_count =
        u8::from(wire.new_file) + u8::from(wire.renamed_file) + u8::from(wire.deleted_file);
    if flag_count > 1 || (wire.collapsed == Some(true) && wire.too_large == Some(true)) {
        return Err(GitLabWireError::ContradictoryDiffFlags);
    }
    let kind = if wire.new_file {
        FileChangeKind::Added
    } else if wire.renamed_file {
        FileChangeKind::Renamed
    } else if wire.deleted_file {
        FileChangeKind::Deleted
    } else {
        FileChangeKind::Modified
    };
    let path = ChangedPath {
        old_path: RepositoryPath::try_from(wire.old_path)
            .map_err(|_| GitLabWireError::InvalidPath)?,
        new_path: RepositoryPath::try_from(wire.new_path)
            .map_err(|_| GitLabWireError::InvalidPath)?,
        kind,
    };
    if path.semantic_issue().is_some() {
        return Err(GitLabWireError::InvalidChangedPath);
    }
    let diff = wire.diff.unwrap_or_default();
    if diff.len() > limits.max_diff_bytes {
        return Err(GitLabWireError::DiffTooLarge {
            observed: diff.len(),
            maximum: limits.max_diff_bytes,
        });
    }
    let collapsed = wire.collapsed == Some(true);
    let too_large = wire.too_large == Some(true);
    if (collapsed || too_large) && !diff.is_empty() {
        return Err(GitLabWireError::ContradictoryDiffFlags);
    }
    let binary_line = diff.strip_suffix('\n').unwrap_or(&diff);
    let binary = diff.contains('\0')
        || binary_line == "GIT binary patch"
        || (binary_line.starts_with("Binary files ") && binary_line.ends_with(" differ"));
    let availability = if too_large {
        DiffAvailability::TooLarge
    } else if collapsed {
        DiffAvailability::Collapsed
    } else if binary {
        DiffAvailability::Binary
    } else if !diff.is_empty() {
        DiffAvailability::Available(Sha256Digest::of_bytes(diff.as_bytes()))
    } else if wire.collapsed.is_none() || wire.too_large.is_none() {
        DiffAvailability::Unknown
    } else {
        DiffAvailability::Missing
    };
    let unified_diff =
        matches!(availability, DiffAvailability::Available(_)).then(|| diff.into_bytes());
    Ok(ValidatedChangedFile {
        file: ChangedFile {
            path,
            diff: availability,
        },
        generated: wire.generated_file,
        unified_diff,
    })
}

fn validate_discussion(
    wire: GitLabDiscussionWire,
    limits: GitLabWireLimits,
) -> Result<ValidatedDiscussion, GitLabWireError> {
    validate_bounded_string(&wire.id, limits)?;
    if wire.id.is_empty() {
        return Err(GitLabWireError::InvalidDiscussion);
    }
    if wire.notes.is_empty()
        || wire.notes.len() > usize::try_from(limits.max_notes_per_discussion).unwrap_or(usize::MAX)
    {
        return Err(GitLabWireError::TooManyDiscussionNotes);
    }
    let mut note_ids = BTreeSet::new();
    let mut notes = Vec::with_capacity(wire.notes.len());
    for note in wire.notes {
        if note.id == 0 || note.author.id == 0 || !note_ids.insert(note.id) {
            return Err(GitLabWireError::DuplicateNoteId);
        }
        validate_bounded_string(&note.author.username, limits)?;
        validate_optional_string(note.note_type.as_deref(), limits)?;
        validate_optional_string(note.created_at.as_deref(), limits)?;
        validate_optional_string(note.updated_at.as_deref(), limits)?;
        validate_optional_string(note.resolved_at.as_deref(), limits)?;
        if let Some(resolved_by) = &note.resolved_by {
            if resolved_by.id == 0 {
                return Err(GitLabWireError::InvalidDiscussion);
            }
            validate_bounded_string(&resolved_by.username, limits)?;
        }
        if let Some(position) = &note.position {
            validate_optional_string(position.old_path.as_deref(), limits)?;
            validate_optional_string(position.new_path.as_deref(), limits)?;
        }
        if note.body.len() > limits.max_note_body_bytes {
            return Err(GitLabWireError::NoteBodyTooLarge);
        }
        if note.body.contains('\0') {
            return Err(GitLabWireError::InvalidDiscussion);
        }
        notes.push(ExistingPublicationNote {
            note_id: note.id,
            author_user_id: note.author.id,
            author_username: Some(note.author.username),
            body: note.body,
            discussion_id: None,
            resolvable: note.resolvable,
            resolved: note.resolved,
            resolved_by_user_id: note.resolved_by.map(|author| author.id),
            created_at: note.created_at,
            updated_at: note.updated_at,
            resolved_at: note.resolved_at,
            path: note.position.as_ref().and_then(|position| {
                if position.new_line.is_some() {
                    position
                        .new_path
                        .clone()
                        .or_else(|| position.old_path.clone())
                } else {
                    position
                        .old_path
                        .clone()
                        .or_else(|| position.new_path.clone())
                }
            }),
            line: note
                .position
                .as_ref()
                .and_then(|position| position.new_line.or(position.old_line)),
            original_line: note
                .position
                .as_ref()
                .and_then(|position| position.old_line),
        });
    }
    Ok(ValidatedDiscussion {
        id: wire.id,
        individual_note: wire.individual_note,
        notes,
    })
}

fn validate_item_count(observed: usize, limits: GitLabWireLimits) -> Result<(), GitLabWireError> {
    if observed > usize::try_from(limits.max_items_per_page).unwrap_or(usize::MAX) {
        Err(GitLabWireError::TooManyPageItems {
            observed,
            maximum: limits.max_items_per_page,
        })
    } else {
        Ok(())
    }
}

fn validate_success_status(status: u16) -> Result<(), GitLabWireError> {
    if status == 200 {
        Ok(())
    } else {
        Err(GitLabWireError::UnexpectedStatus(status))
    }
}

fn validate_bounded_string(value: &str, limits: GitLabWireLimits) -> Result<(), GitLabWireError> {
    if value.len() > limits.max_string_bytes {
        Err(GitLabWireError::StringTooLong)
    } else {
        Ok(())
    }
}

fn validate_optional_string(
    value: Option<&str>,
    limits: GitLabWireLimits,
) -> Result<(), GitLabWireError> {
    value.map_or(Ok(()), |value| validate_bounded_string(value, limits))
}

fn parse_sha(value: String, limits: GitLabWireLimits) -> Result<GitSha, GitLabWireError> {
    validate_bounded_string(&value, limits)?;
    GitSha::try_from(value).map_err(|_| GitLabWireError::InvalidSha)
}

fn parse_changed_file_count(
    value: Option<&str>,
    limits: GitLabWireLimits,
) -> Result<ChangedFileCount, GitLabWireError> {
    let Some(value) = value else {
        return Ok(ChangedFileCount::Unavailable);
    };
    validate_bounded_string(value, limits)?;
    if value.is_empty() {
        return Ok(ChangedFileCount::Unavailable);
    }
    let (digits, capped) = value
        .strip_suffix('+')
        .map_or((value, false), |digits| (digits, true));
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(GitLabWireError::InvalidChangedFileCount);
    }
    let count = digits
        .parse::<u32>()
        .map_err(|_| GitLabWireError::InvalidChangedFileCount)?;
    if capped {
        if count == 0 {
            return Err(GitLabWireError::InvalidChangedFileCount);
        }
        Ok(ChangedFileCount::CappedAt(count))
    } else {
        Ok(ChangedFileCount::Exact(count))
    }
}

fn parse_pagination(
    response: &GitLabResponseObservation,
    requested_page: u32,
    requested_per_page: u32,
    item_count: usize,
    limits: GitLabWireLimits,
) -> Result<GitLabPaginationMetadata, GitLabWireError> {
    if requested_page == 0
        || requested_per_page == 0
        || requested_per_page > limits.max_items_per_page
    {
        return Err(GitLabWireError::InvalidRequestedPage);
    }
    let headers = ParsedHeaders::parse(&response.headers, limits)?;
    validate_pagination_echoes(&headers, requested_page, requested_per_page)?;
    let total_items = headers.optional_u64("x-total")?;
    let total_pages = headers.optional_u32("x-total-pages")?;
    if total_items.is_some() != total_pages.is_some() {
        return Err(GitLabWireError::PaginationTotalMismatch);
    }
    if item_count > usize::try_from(requested_per_page).unwrap_or(usize::MAX) {
        return Err(GitLabWireError::TooManyPageItems {
            observed: item_count,
            maximum: requested_per_page,
        });
    }
    let header_next = headers.page_signal("x-next-page")?;
    let link_next = headers
        .get("link")
        .map_or(Ok(PageSignal::Unobserved), parse_link_next)?;
    let explicit_next = combine_next_signals(header_next, link_next)?;
    let resolved = if let (Some(total), Some(pages)) = (total_items, total_pages) {
        let expected = validate_pagination_totals(
            total,
            pages,
            requested_page,
            requested_per_page,
            item_count,
        )?;
        if explicit_next != PageSignal::Unobserved && explicit_next != expected {
            return Err(GitLabWireError::PaginationNextMismatch);
        }
        expected
    } else {
        match explicit_next {
            PageSignal::Unobserved
                if item_count < usize::try_from(requested_per_page).unwrap_or(usize::MAX) =>
            {
                PageSignal::Terminal
            }
            PageSignal::Unobserved => {
                return Err(GitLabWireError::PaginationAmbiguousContinuation);
            }
            observed => observed,
        }
    };
    let next_page = resolved.next_page();
    if let Some(next) = next_page {
        if next <= requested_page {
            return Err(GitLabWireError::PaginationCycle);
        }
        if next != requested_page.saturating_add(1) {
            return Err(GitLabWireError::PaginationGap);
        }
        if item_count == 0 {
            return Err(GitLabWireError::PaginationNextMismatch);
        }
    }
    Ok(GitLabPaginationMetadata {
        page_number: requested_page,
        per_page: requested_per_page,
        item_count: u32::try_from(item_count).map_err(|_| GitLabWireError::PaginationOverflow)?,
        next_page,
        total_items,
        total_pages,
    })
}

fn validate_pagination_echoes(
    headers: &ParsedHeaders,
    requested_page: u32,
    requested_per_page: u32,
) -> Result<(), GitLabWireError> {
    if headers
        .optional_u32("x-page")?
        .is_some_and(|page| page != requested_page)
    {
        return Err(GitLabWireError::PaginationPageMismatch);
    }
    if headers
        .optional_u32("x-per-page")?
        .is_some_and(|per_page| per_page != requested_per_page)
    {
        return Err(GitLabWireError::PaginationPerPageMismatch);
    }
    let expected_previous = requested_page
        .checked_sub(1)
        .filter(|_| requested_page > 1)
        .map_or(PageSignal::Terminal, PageSignal::Page);
    let observed_previous = headers.page_signal("x-prev-page")?;
    if observed_previous != PageSignal::Unobserved && observed_previous != expected_previous {
        return Err(GitLabWireError::PaginationPreviousMismatch);
    }
    Ok(())
}

fn validate_pagination_totals(
    total: u64,
    pages: u32,
    requested_page: u32,
    requested_per_page: u32,
    item_count: usize,
) -> Result<PageSignal, GitLabWireError> {
    let calculated = total
        .checked_add(u64::from(requested_per_page) - 1)
        .map(|value| value / u64::from(requested_per_page))
        .ok_or(GitLabWireError::PaginationOverflow)?;
    let calculated =
        u32::try_from(calculated.max(1)).map_err(|_| GitLabWireError::PaginationOverflow)?;
    if pages != calculated || requested_page > pages {
        return Err(GitLabWireError::PaginationTotalMismatch);
    }
    let consumed_before = u64::from(requested_page - 1)
        .checked_mul(u64::from(requested_per_page))
        .ok_or(GitLabWireError::PaginationOverflow)?;
    let expected_items = total
        .saturating_sub(consumed_before)
        .min(u64::from(requested_per_page));
    if expected_items != u64::try_from(item_count).unwrap_or(u64::MAX) {
        return Err(GitLabWireError::PaginationTotalMismatch);
    }
    if requested_page < pages {
        requested_page
            .checked_add(1)
            .map(PageSignal::Page)
            .ok_or(GitLabWireError::PaginationOverflow)
    } else {
        Ok(PageSignal::Terminal)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageSignal {
    Unobserved,
    Terminal,
    Page(u32),
}

impl PageSignal {
    const fn next_page(self) -> Option<u32> {
        match self {
            Self::Page(page) => Some(page),
            Self::Unobserved | Self::Terminal => None,
        }
    }
}

fn combine_next_signals(
    header: PageSignal,
    link: PageSignal,
) -> Result<PageSignal, GitLabWireError> {
    match (header, link) {
        (PageSignal::Unobserved, value) | (value, PageSignal::Unobserved) => Ok(value),
        (left, right) if left == right => Ok(left),
        (_, _) => Err(GitLabWireError::PaginationNextMismatch),
    }
}

fn parse_link_next(value: &str) -> Result<PageSignal, GitLabWireError> {
    let mut next = None;
    for entry in value.split(',') {
        let entry = entry.trim();
        let Some((target, parameters)) = entry.split_once('>') else {
            return Err(GitLabWireError::MalformedLinkHeader);
        };
        let Some(target) = target.strip_prefix('<') else {
            return Err(GitLabWireError::MalformedLinkHeader);
        };
        let relations = parameters.split(';').map(str::trim).find_map(|parameter| {
            parameter
                .strip_prefix("rel=")
                .map(|value| value.trim_matches('"'))
        });
        if relations
            .is_some_and(|relations| relations.split_ascii_whitespace().any(|rel| rel == "next"))
        {
            if next.is_some() {
                return Err(GitLabWireError::MalformedLinkHeader);
            }
            let query = target
                .split_once('?')
                .map(|(_, query)| query)
                .ok_or(GitLabWireError::MalformedLinkHeader)?;
            let mut page = None;
            for parameter in query.split('&') {
                if let Some(value) = parameter.strip_prefix("page=") {
                    if page.is_some() {
                        return Err(GitLabWireError::MalformedLinkHeader);
                    }
                    page = Some(parse_strict_u32(value, "link")?);
                }
            }
            next = Some(page.ok_or(GitLabWireError::MalformedLinkHeader)?);
        }
    }
    Ok(next.map_or(PageSignal::Terminal, PageSignal::Page))
}

struct ParsedHeaders {
    values: BTreeMap<String, String>,
}

impl ParsedHeaders {
    fn parse(
        input: &[GitLabResponseHeader],
        limits: GitLabWireLimits,
    ) -> Result<Self, GitLabWireError> {
        if input.len() > usize::try_from(limits.max_header_count).unwrap_or(usize::MAX) {
            return Err(GitLabWireError::TooManyHeaders {
                observed: input.len(),
                maximum: limits.max_header_count,
            });
        }
        let mut values = BTreeMap::new();
        for header in input {
            if header.name.len() > limits.max_header_name_bytes {
                return Err(GitLabWireError::HeaderNameTooLong);
            }
            if header.value.len() > limits.max_header_value_bytes {
                return Err(GitLabWireError::HeaderValueTooLong);
            }
            if header.name.is_empty()
                || !header
                    .name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                return Err(GitLabWireError::InvalidHeaderName);
            }
            let name = str::from_utf8(&header.name)
                .map_err(|_| GitLabWireError::InvalidHeaderName)?
                .to_ascii_lowercase();
            let value =
                str::from_utf8(&header.value).map_err(|_| GitLabWireError::InvalidHeaderValue)?;
            if value.contains(['\r', '\n', '\0']) {
                return Err(GitLabWireError::InvalidHeaderValue);
            }
            if observed_header(&name)
                && values
                    .insert(name.clone(), value.trim().to_owned())
                    .is_some()
            {
                return Err(GitLabWireError::DuplicateHeader(name));
            }
        }
        Ok(Self { values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn required(&self, name: &str) -> Result<&str, GitLabWireError> {
        self.get(name)
            .ok_or_else(|| GitLabWireError::BlobMetadataMissing(name.to_owned()))
    }

    fn required_u64(&self, name: &str) -> Result<u64, GitLabWireError> {
        parse_strict_u64(self.required(name)?, name)
    }

    fn optional_u64(&self, name: &str) -> Result<Option<u64>, GitLabWireError> {
        self.get(name)
            .map(|value| parse_strict_u64(value, name))
            .transpose()
    }

    fn optional_u32(&self, name: &str) -> Result<Option<u32>, GitLabWireError> {
        self.get(name)
            .map(|value| parse_strict_u32(value, name))
            .transpose()
    }

    fn page_signal(&self, name: &str) -> Result<PageSignal, GitLabWireError> {
        match self.get(name) {
            None => Ok(PageSignal::Unobserved),
            Some("") => Ok(PageSignal::Terminal),
            Some(value) => parse_strict_u32(value, name).map(PageSignal::Page),
        }
    }

    fn validate_content_length(&self, observed: usize) -> Result<(), GitLabWireError> {
        if let Some(declared) = self.optional_u64("content-length")?
            && declared != u64::try_from(observed).unwrap_or(u64::MAX)
        {
            return Err(GitLabWireError::ContentLengthMismatch { declared, observed });
        }
        Ok(())
    }
}

fn observed_header(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "content-type"
            | "link"
            | "x-page"
            | "x-next-page"
            | "x-prev-page"
            | "x-per-page"
            | "x-total"
            | "x-total-pages"
            | "x-request-id"
            | "x-gitlab-blob-id"
            | "x-gitlab-commit-id"
            | "x-gitlab-content-sha256"
            | "x-gitlab-encoding"
            | "x-gitlab-execute-filemode"
            | "x-gitlab-file-name"
            | "x-gitlab-file-path"
            | "x-gitlab-last-commit-id"
            | "x-gitlab-ref"
            | "x-gitlab-size"
    )
}

fn parse_required_sha_header(
    headers: &ParsedHeaders,
    name: &str,
) -> Result<GitSha, GitLabWireError> {
    GitSha::try_from(headers.required(name)?.to_owned())
        .map_err(|_| GitLabWireError::BlobMetadataMismatch(name.to_owned()))
}

fn parse_strict_u64(value: &str, name: &str) -> Result<u64, GitLabWireError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(GitLabWireError::InvalidHeaderNumber(name.to_owned()));
    }
    value
        .parse()
        .map_err(|_| GitLabWireError::InvalidHeaderNumber(name.to_owned()))
}

fn parse_strict_u32(value: &str, name: &str) -> Result<u32, GitLabWireError> {
    let parsed = parse_strict_u64(value, name)?;
    u32::try_from(parsed).map_err(|_| GitLabWireError::InvalidHeaderNumber(name.to_owned()))
}

fn valid_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    parts
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        && parts.all(|parameter| parameter.trim().eq_ignore_ascii_case("charset=utf-8"))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn is_lfs_pointer(bytes: &[u8]) -> bool {
    bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::BlobSide;
    use serde_json::{Value, json};

    fn sha(marker: char) -> String {
        marker.to_string().repeat(40)
    }

    fn header(name: &str, value: impl std::fmt::Display) -> GitLabResponseHeader {
        GitLabResponseHeader {
            name: name.as_bytes().to_vec(),
            value: format!("{value}").into_bytes(),
        }
    }

    fn json_response(
        value: &Value,
        headers: Vec<GitLabResponseHeader>,
    ) -> GitLabResponseObservation {
        GitLabResponseObservation {
            status: 200,
            headers,
            body: serde_json::to_vec(value).unwrap(),
        }
    }

    fn page_headers(
        page: u32,
        per_page: u32,
        next: Option<u32>,
        total: u64,
        total_pages: u32,
    ) -> Vec<GitLabResponseHeader> {
        vec![
            header("X-Page", page),
            header("X-Per-Page", per_page),
            header(
                "X-Prev-Page",
                page.checked_sub(1)
                    .filter(|_| page > 1)
                    .map_or_else(String::new, |value| value.to_string()),
            ),
            header(
                "X-Next-Page",
                next.map_or_else(String::new, |value| value.to_string()),
            ),
            header("X-Total", total),
            header("X-Total-Pages", total_pages),
        ]
    }

    fn version(id: u64, marker: char, state: &str, real_size: &str) -> Value {
        json!({
            "id": id,
            "head_commit_sha": sha(marker),
            "base_commit_sha": sha('a'),
            "start_commit_sha": sha('b'),
            "state": state,
            "real_size": real_size,
            "created_at": "2026-08-19T00:00:00Z",
            "merge_request_id": 99,
            "patch_id_sha": sha('c')
        })
    }

    fn changed_file(path: &str, diff: &str) -> Value {
        json!({
            "old_path": path,
            "new_path": path,
            "a_mode": "100644",
            "b_mode": "100644",
            "diff": diff,
            "new_file": false,
            "renamed_file": false,
            "deleted_file": false,
            "generated_file": false,
            "collapsed": false,
            "too_large": false
        })
    }

    fn discussion(id: &str, note_id: u64, author: u64, body: &str) -> Value {
        json!({
            "id": id,
            "individual_note": false,
            "notes": [{
                "id": note_id,
                "type": "DiscussionNote",
                "body": body,
                "author": {"id": author, "username": format!("user{author}")},
                "system": false
            }]
        })
    }

    fn blob_request() -> BlobRequest {
        BlobRequest {
            side: BlobSide::Old,
            path: RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap(),
            commit_sha: GitSha::try_from(sha('a')).unwrap(),
        }
    }

    fn blob_response(body: &[u8]) -> GitLabResponseObservation {
        GitLabResponseObservation {
            status: 200,
            headers: vec![
                header("Content-Length", body.len()),
                header("X-Gitlab-Blob-Id", sha('d')),
                header("X-Gitlab-Commit-Id", sha('a')),
                header(
                    "X-Gitlab-Content-Sha256",
                    Sha256Digest::of_bytes(body).as_str(),
                ),
                header("X-Gitlab-Encoding", "base64"),
                header("X-Gitlab-Execute-Filemode", "true"),
                header("X-Gitlab-File-Path", "src/lib.rs"),
                header("X-Gitlab-Ref", sha('a')),
                header("X-Gitlab-Size", body.len()),
            ],
            body: body.to_vec(),
        }
    }

    #[test]
    fn merge_request_golden_converts_exact_types_and_capped_count() {
        let response = json_response(
            &json!({
                "id": 99,
                "iid": 7,
                "project_id": 42,
                "source_project_id": 41,
                "target_project_id": 42,
                "state": "opened",
                "source_branch": "feature/review",
                "target_branch": "main",
                "sha": sha('c'),
                "diff_refs": {
                    "base_sha": sha('a'),
                    "start_sha": sha('b'),
                    "head_sha": sha('c')
                },
                "changes_count": "1000+"
            }),
            vec![header("Content-Type", "application/json; charset=utf-8")],
        );
        let parsed = parse_merge_request_response(&response, GitLabWireLimits::default()).unwrap();
        assert_eq!(parsed.merge_request_id, 99);
        assert_eq!(parsed.iid.get(), 7);
        assert_eq!(parsed.project_id.get(), 42);
        assert_eq!(parsed.source_project_id.unwrap().get(), 41);
        assert_eq!(parsed.state, GitLabMergeRequestState::Opened);
        assert_eq!(parsed.source_ref.as_str(), "feature/review");
        assert_eq!(parsed.target_ref.as_str(), "main");
        assert_eq!(parsed.changed_files, ChangedFileCount::CappedAt(1_000));
        assert_eq!(parsed.diff_refs.unwrap().head_sha.as_str(), sha('c'));
    }

    #[test]
    fn project_projection_is_tolerant_but_strictly_typed() {
        let response = json_response(
            &json!({
                "id": 42,
                "path_with_namespace": "group/project",
                "name": "ignored provider decoration"
            }),
            vec![],
        );
        let project = parse_project_response(&response, GitLabWireLimits::default()).unwrap();
        assert_eq!(project.id.get(), 42);
        assert_eq!(project.path.as_str(), "group/project");

        for value in [
            json!({"id": 0, "path_with_namespace": "group/project"}),
            json!({"id": 42, "path_with_namespace": "project"}),
            json!({"id": "42", "path_with_namespace": "group/project"}),
        ] {
            assert!(
                parse_project_response(&json_response(&value, vec![]), GitLabWireLimits::default())
                    .is_err()
            );
        }
    }

    #[test]
    fn json_boundary_tolerates_unknown_but_rejects_duplicate_ambiguous_and_invalid_bytes() {
        let unknown = json_response(
            &json!({
                "id": 1, "iid": 1, "project_id": 1, "source_project_id": 1,
                "target_project_id": 1, "state": "opened",
                "source_branch": "feature", "target_branch": "main", "sha": sha('a'),
                "diff_refs": null, "changes_count": "1", "surprise": true
            }),
            vec![],
        );
        assert!(parse_merge_request_response(&unknown, GitLabWireLimits::default()).is_ok());

        let duplicate = GitLabResponseObservation {
            status: 200,
            headers: vec![],
            body: format!(
                "{{\"id\":1,\"id\":2,\"iid\":1,\"project_id\":1,\"source_project_id\":1,\"target_project_id\":1,\"state\":\"opened\",\"source_branch\":\"feature\",\"target_branch\":\"main\",\"sha\":\"{}\",\"diff_refs\":null,\"changes_count\":\"1\"}}",
                sha('a')
            )
            .into_bytes(),
        };
        assert_eq!(
            parse_merge_request_response(&duplicate, GitLabWireLimits::default()),
            Err(GitLabWireError::MalformedJson)
        );

        let ambiguous = json_response(
            &json!({
                "id": 1, "iid": "1", "project_id": 1, "source_project_id": 1,
                "target_project_id": 1, "state": "opened",
                "source_branch": "feature", "target_branch": "main", "sha": sha('a'),
                "diff_refs": null, "changes_count": 1
            }),
            vec![],
        );
        assert_eq!(
            parse_merge_request_response(&ambiguous, GitLabWireLimits::default()),
            Err(GitLabWireError::MalformedJson)
        );

        let invalid_utf8 = GitLabResponseObservation {
            status: 200,
            headers: vec![],
            body: vec![0xff],
        };
        assert_eq!(
            parse_merge_request_response(&invalid_utf8, GitLabWireLimits::default()),
            Err(GitLabWireError::InvalidUtf8 { valid_up_to: 0 })
        );
    }

    #[test]
    fn merge_request_rejects_count_and_head_identity_ambiguity() {
        for count in ["01", "0+", "1++", "-1"] {
            let response = json_response(
                &json!({
                    "id": 1, "iid": 1, "project_id": 1, "source_project_id": 1,
                    "target_project_id": 1, "state": "opened",
                    "source_branch": "feature", "target_branch": "main", "sha": sha('c'),
                    "diff_refs": null, "changes_count": count
                }),
                vec![],
            );
            assert_eq!(
                parse_merge_request_response(&response, GitLabWireLimits::default()),
                Err(GitLabWireError::InvalidChangedFileCount)
            );
        }

        let mismatch = json_response(
            &json!({
                "id": 1, "iid": 1, "project_id": 1, "source_project_id": 1,
                "target_project_id": 1, "state": "opened",
                "source_branch": "feature", "target_branch": "main", "sha": sha('c'),
                "diff_refs": {
                    "base_sha": sha('a'), "start_sha": sha('b'), "head_sha": sha('d')
                },
                "changes_count": "1"
            }),
            vec![],
        );
        assert_eq!(
            parse_merge_request_response(&mismatch, GitLabWireLimits::default()),
            Err(GitLabWireError::DiffRefsHeadMismatch)
        );
    }

    #[test]
    fn response_envelope_rejects_status_type_length_and_body_limits() {
        let metadata_response = GitLabResponseObservation {
            status: 206,
            headers: vec![
                header("Content-Length", 3),
                header("X-Request-Id", "request-1"),
            ],
            body: b"abc".to_vec(),
        };
        assert_eq!(
            parse_response_metadata(&metadata_response, GitLabWireLimits::default()).unwrap(),
            GitLabResponseMetadata {
                status: 206,
                content_length: Some(3),
                request_id: Some("request-1".to_owned()),
            }
        );

        let mut response = json_response(&json!([]), vec![]);
        response.status = 404;
        assert_eq!(
            parse_changed_files_page(&response, 1, 20, GitLabWireLimits::default()),
            Err(GitLabWireError::UnexpectedStatus(404))
        );

        response.status = 200;
        response.headers = vec![header("Content-Type", "text/html")];
        assert_eq!(
            parse_changed_files_page(&response, 1, 20, GitLabWireLimits::default()),
            Err(GitLabWireError::WrongContentType)
        );

        response.headers = vec![header("Content-Length", response.body.len() + 1)];
        assert!(matches!(
            parse_changed_files_page(&response, 1, 20, GitLabWireLimits::default()),
            Err(GitLabWireError::ContentLengthMismatch { .. })
        ));

        response.headers.clear();
        let limits = GitLabWireLimits {
            max_json_body_bytes: 1,
            max_diff_bytes: 1,
            max_note_body_bytes: 1,
            max_string_bytes: 1,
            ..GitLabWireLimits::default()
        };
        assert!(matches!(
            parse_changed_files_page(&response, 1, 20, limits),
            Err(GitLabWireError::BodyTooLarge { .. })
        ));

        let injection = GitLabResponseObservation {
            status: 200,
            headers: vec![header("X-Request-Id", "safe\r\ninjected")],
            body: vec![],
        };
        assert_eq!(
            parse_response_metadata(&injection, GitLabWireLimits::default()),
            Err(GitLabWireError::InvalidHeaderValue)
        );
    }

    #[test]
    fn paginated_diff_versions_golden_collects_only_complete_sequence() {
        let mut first_headers = page_headers(1, 2, Some(2), 3, 2);
        first_headers.push(header(
            "Link",
            "<https://gitlab.example/api/v4/versions?per_page=2&page=2>; rel=\"next\"",
        ));
        let first = parse_diff_versions_page(
            &json_response(
                &json!([
                    version(3, 'c', "collected", "2"),
                    version(2, 'd', "collected", "1")
                ]),
                first_headers,
            ),
            1,
            2,
            GitLabWireLimits::default(),
        )
        .unwrap();
        let second = parse_diff_versions_page(
            &json_response(
                &json!([version(1, 'e', "collected", "1000+")]),
                page_headers(2, 2, None, 3, 2),
            ),
            2,
            2,
            GitLabWireLimits::default(),
        )
        .unwrap();
        assert_eq!(second.items[0].state, DiffVersionState::Overflow);
        let acquired =
            collect_complete_pages(vec![first, second], GitLabWireLimits::default()).unwrap();
        assert_eq!(acquired.items.len(), 3);
        assert_eq!(acquired.pages.len(), 2);
        assert!(!acquired.pages[1].has_next_page);
    }

    #[test]
    fn pagination_rejects_ambiguous_cycles_gaps_and_signal_conflicts() {
        let full_without_headers = json_response(
            &json!([changed_file("a", "x"), changed_file("b", "y")]),
            vec![],
        );
        assert_eq!(
            parse_changed_files_page(&full_without_headers, 1, 2, GitLabWireLimits::default(),),
            Err(GitLabWireError::PaginationAmbiguousContinuation)
        );

        let short_without_headers = json_response(&json!([changed_file("a", "x")]), vec![]);
        assert!(
            parse_changed_files_page(&short_without_headers, 1, 2, GitLabWireLimits::default(),)
                .unwrap()
                .metadata
                .next_page
                .is_none()
        );

        for (next, expected) in [
            (1, GitLabWireError::PaginationCycle),
            (3, GitLabWireError::PaginationGap),
        ] {
            let response = json_response(
                &json!([changed_file("a", "x"), changed_file("b", "y")]),
                vec![header("X-Next-Page", next)],
            );
            assert_eq!(
                parse_changed_files_page(&response, 1, 2, GitLabWireLimits::default()),
                Err(expected)
            );
        }

        let conflicting = json_response(
            &json!([changed_file("a", "x"), changed_file("b", "y")]),
            vec![
                header("X-Next-Page", 2),
                header(
                    "Link",
                    "<https://gitlab.example/api?per_page=2&page=3>; rel=\"next\"",
                ),
            ],
        );
        assert_eq!(
            parse_changed_files_page(&conflicting, 1, 2, GitLabWireLimits::default()),
            Err(GitLabWireError::PaginationNextMismatch)
        );
    }

    #[test]
    fn pagination_rejects_inconsistent_totals_headers_and_sequences() {
        let inconsistent_total =
            json_response(&json!([changed_file("a", "x")]), vec![header("X-Total", 1)]);
        assert_eq!(
            parse_changed_files_page(&inconsistent_total, 1, 2, GitLabWireLimits::default()),
            Err(GitLabWireError::PaginationTotalMismatch)
        );

        let duplicate_header = json_response(
            &json!([changed_file("a", "x")]),
            vec![header("X-Page", 1), header("x-page", 1)],
        );
        assert_eq!(
            parse_changed_files_page(&duplicate_header, 1, 2, GitLabWireLimits::default()),
            Err(GitLabWireError::DuplicateHeader("x-page".to_owned()))
        );

        let overflowing_total = json_response(
            &json!([]),
            vec![
                header("X-Total", u64::MAX),
                header("X-Total-Pages", 1),
                header("X-Next-Page", ""),
            ],
        );
        assert_eq!(
            parse_changed_files_page(&overflowing_total, 1, 2, GitLabWireLimits::default()),
            Err(GitLabWireError::PaginationOverflow)
        );

        let terminal = GitLabPage {
            metadata: GitLabPaginationMetadata {
                page_number: 1,
                per_page: 2,
                item_count: 1,
                next_page: None,
                total_items: None,
                total_pages: None,
            },
            items: vec![1_u8],
        };
        let after = GitLabPage {
            metadata: GitLabPaginationMetadata {
                page_number: 2,
                per_page: 2,
                item_count: 1,
                next_page: None,
                total_items: None,
                total_pages: None,
            },
            items: vec![2_u8],
        };
        assert_eq!(
            collect_complete_pages(vec![terminal, after], GitLabWireLimits::default()),
            Err(GitLabWireError::PaginationAfterTerminal)
        );

        let unfinished = GitLabPage {
            metadata: GitLabPaginationMetadata {
                page_number: 1,
                per_page: 2,
                item_count: 2,
                next_page: Some(2),
                total_items: None,
                total_pages: None,
            },
            items: vec![1_u8, 2],
        };
        assert_eq!(
            collect_complete_pages(vec![unfinished], GitLabWireLimits::default()),
            Err(GitLabWireError::PaginationContinuationMissing)
        );
    }

    #[test]
    fn changed_files_preserve_available_bytes_and_fail_closed_on_omissions() {
        let values = json!([
            changed_file("src/lib.rs", "@@ -1 +1 @@\n-old\n+new\n"),
            {
                "old_path": "large.rs", "new_path": "large.rs", "a_mode": "100644",
                "b_mode": "100644", "diff": "", "new_file": false,
                "renamed_file": false, "deleted_file": false, "generated_file": null,
                "collapsed": true, "too_large": false
            },
            {
                "old_path": "old.bin", "new_path": "old.bin", "a_mode": "100644",
                "b_mode": "100644", "diff": "Binary files a and b differ", "new_file": false,
                "renamed_file": false, "deleted_file": false, "generated_file": false,
                "collapsed": false, "too_large": false
            },
            {
                "old_path": "legacy.rs", "new_path": "legacy.rs", "a_mode": "100644",
                "b_mode": "100644", "diff": "", "new_file": false,
                "renamed_file": false, "deleted_file": false, "generated_file": null,
                "collapsed": null, "too_large": null
            }
        ]);
        let page = parse_changed_files_page(
            &json_response(&values, page_headers(1, 4, None, 4, 1)),
            1,
            4,
            GitLabWireLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            page.items[0].file.diff,
            DiffAvailability::Available(_)
        ));
        assert!(page.items[0].unified_diff.is_some());
        assert_eq!(page.items[1].file.diff, DiffAvailability::Collapsed);
        assert_eq!(page.items[2].file.diff, DiffAvailability::Binary);
        assert_eq!(page.items[3].file.diff, DiffAvailability::Unknown);
    }

    #[test]
    fn changed_files_reject_flag_path_and_diff_contradictions() {
        let mut value = changed_file("a.rs", "x");
        value["new_file"] = json!(true);
        value["deleted_file"] = json!(true);
        assert_eq!(
            parse_changed_files_page(
                &json_response(&json!([value]), page_headers(1, 1, None, 1, 1)),
                1,
                1,
                GitLabWireLimits::default(),
            ),
            Err(GitLabWireError::ContradictoryDiffFlags)
        );

        let limits = GitLabWireLimits {
            max_diff_bytes: 1,
            ..GitLabWireLimits::default()
        };
        assert_eq!(
            parse_changed_files_page(
                &json_response(
                    &json!([changed_file("a.rs", "too long")]),
                    page_headers(1, 1, None, 1, 1),
                ),
                1,
                1,
                limits,
            ),
            Err(GitLabWireError::DiffTooLarge {
                observed: 8,
                maximum: 1,
            })
        );

        let mut value = changed_file("a.rs", "x");
        value["new_path"] = json!("b.rs");
        assert_eq!(
            parse_changed_files_page(
                &json_response(&json!([value]), page_headers(1, 1, None, 1, 1)),
                1,
                1,
                GitLabWireLimits::default(),
            ),
            Err(GitLabWireError::InvalidChangedPath)
        );

        let mut value = changed_file("a.rs", "x");
        value["collapsed"] = json!(true);
        assert_eq!(
            parse_changed_files_page(
                &json_response(&json!([value]), page_headers(1, 1, None, 1, 1)),
                1,
                1,
                GitLabWireLimits::default(),
            ),
            Err(GitLabWireError::ContradictoryDiffFlags)
        );
    }

    #[test]
    fn exact_version_preserves_overflow_and_rejects_duplicate_files() {
        let exact = json!({
            "id": 9,
            "head_commit_sha": sha('c'),
            "base_commit_sha": sha('a'),
            "start_commit_sha": sha('b'),
            "state": "collected",
            "real_size": "1000+",
            "created_at": null,
            "merge_request_id": 99,
            "patch_id_sha": null,
            "diffs": [changed_file("a.rs", "x")]
        });
        let parsed = parse_exact_diff_version_response(
            &json_response(&exact, vec![]),
            GitLabWireLimits::default(),
        )
        .unwrap();
        assert_eq!(parsed.version.state, DiffVersionState::Overflow);

        let mut duplicate = exact;
        duplicate["real_size"] = json!("2");
        duplicate["diffs"] = json!([changed_file("a.rs", "x"), changed_file("a.rs", "y")]);
        assert_eq!(
            parse_exact_diff_version_response(
                &json_response(&duplicate, vec![]),
                GitLabWireLimits::default(),
            ),
            Err(GitLabWireError::InvalidExactVersion)
        );
    }

    #[test]
    fn raw_blob_golden_binds_headers_body_request_and_lfs_representation() {
        let body = b"hello exact blob";
        let parsed = parse_raw_blob_response(
            &blob_request(),
            &blob_response(body),
            GitLabWireLimits::default(),
        )
        .unwrap();
        assert_eq!(parsed.body, body);
        assert!(parsed.execute_filemode);
        assert_eq!(parsed.identity.request, blob_request());
        assert_eq!(parsed.identity.size_bytes, 16);
        assert_eq!(
            parsed.identity.representation,
            BlobRepresentation::FileContent
        );

        let lfs = b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1\n";
        let parsed = parse_raw_blob_response(
            &blob_request(),
            &blob_response(lfs),
            GitLabWireLimits::default(),
        )
        .unwrap();
        assert_eq!(
            parsed.identity.representation,
            BlobRepresentation::LfsPointer
        );
    }

    #[test]
    fn raw_blob_rejects_missing_duplicate_and_inconsistent_metadata() {
        let request = blob_request();
        let mut response = blob_response(b"hello");
        response
            .headers
            .retain(|header| !header.name.eq_ignore_ascii_case(b"x-gitlab-content-sha256"));
        assert_eq!(
            parse_raw_blob_response(&request, &response, GitLabWireLimits::default()),
            Err(GitLabWireError::BlobMetadataMissing(
                "x-gitlab-content-sha256".to_owned()
            ))
        );

        let mut response = blob_response(b"hello");
        response.headers.push(header("x-gitlab-size", 5));
        assert_eq!(
            parse_raw_blob_response(&request, &response, GitLabWireLimits::default()),
            Err(GitLabWireError::DuplicateHeader("x-gitlab-size".to_owned()))
        );

        let mut response = blob_response(b"hello");
        let digest = response
            .headers
            .iter_mut()
            .find(|header| header.name.eq_ignore_ascii_case(b"x-gitlab-content-sha256"))
            .unwrap();
        digest.value = "f".repeat(64).into_bytes();
        assert_eq!(
            parse_raw_blob_response(&request, &response, GitLabWireLimits::default()),
            Err(GitLabWireError::BlobDigestMismatch)
        );

        let mut response = blob_response(b"hello");
        let path = response
            .headers
            .iter_mut()
            .find(|header| header.name.eq_ignore_ascii_case(b"x-gitlab-file-path"))
            .unwrap();
        path.value = b"other.rs".to_vec();
        assert_eq!(
            parse_raw_blob_response(&request, &response, GitLabWireLimits::default()),
            Err(GitLabWireError::BlobMetadataMismatch(
                "x-gitlab-file-path".to_owned()
            ))
        );
    }

    #[test]
    fn discussion_pages_flatten_deterministically_and_reject_duplicates() {
        let first = parse_discussions_page(
            &json_response(
                &json!([discussion("d2", 20, 2, "later")]),
                page_headers(1, 1, Some(2), 2, 2),
            ),
            1,
            1,
            GitLabWireLimits::default(),
        )
        .unwrap();
        let second = parse_discussions_page(
            &json_response(
                &json!([discussion("d1", 10, 1, "earlier")]),
                page_headers(2, 1, None, 2, 2),
            ),
            2,
            1,
            GitLabWireLimits::default(),
        )
        .unwrap();
        let inventory = collect_discussion_inventory(
            vec![first.clone(), second.clone()],
            GitLabWireLimits::default(),
        )
        .unwrap();
        assert!(inventory.complete);
        assert_eq!(
            inventory
                .notes
                .iter()
                .map(|note| note.note_id)
                .collect::<Vec<_>>(),
            vec![10, 20]
        );

        let mut duplicate_note = second;
        duplicate_note.items[0].notes[0].note_id = 20;
        assert_eq!(
            collect_discussion_inventory(vec![first, duplicate_note], GitLabWireLimits::default(),),
            Err(GitLabWireError::DuplicateNoteId)
        );
    }

    #[test]
    fn discussion_wire_tolerates_unknown_but_rejects_empty_and_oversized_notes() {
        let unknown = json!([{
            "id": "d1", "individual_note": false,
            "notes": [discussion("ignored", 1, 1, "body")["notes"][0].clone()],
            "extra": true
        }]);
        assert!(
            parse_discussions_page(
                &json_response(&unknown, page_headers(1, 1, None, 1, 1)),
                1,
                1,
                GitLabWireLimits::default(),
            )
            .is_ok()
        );

        let empty = json!([{"id": "d1", "individual_note": false, "notes": []}]);
        assert_eq!(
            parse_discussions_page(
                &json_response(&empty, page_headers(1, 1, None, 1, 1)),
                1,
                1,
                GitLabWireLimits::default(),
            ),
            Err(GitLabWireError::TooManyDiscussionNotes)
        );

        let oversized = json!([discussion("d1", 1, 1, "too long")]);
        let limits = GitLabWireLimits {
            max_note_body_bytes: 1,
            ..GitLabWireLimits::default()
        };
        assert_eq!(
            parse_discussions_page(
                &json_response(&oversized, page_headers(1, 1, None, 1, 1)),
                1,
                1,
                limits,
            ),
            Err(GitLabWireError::NoteBodyTooLarge)
        );

        let mut positioned = discussion("d2", 2, 7, "finding");
        let root = &mut positioned["notes"][0];
        root["resolved"] = json!(true);
        root["resolved_by"] = json!({"id": 9, "username": "reviewer"});
        root["resolved_at"] = json!("2026-08-29T10:00:00Z");
        root["position"] = json!({
            "old_path": "src/old.rs", "new_path": "src/new.rs",
            "old_line": 14, "new_line": null
        });
        let page = parse_discussions_page(
            &json_response(&json!([positioned]), page_headers(1, 1, None, 1, 1)),
            1,
            1,
            GitLabWireLimits::default(),
        )
        .expect("positioned discussion");
        let note = &page.items[0].notes[0];
        assert_eq!(note.resolved_by_user_id, Some(9));
        assert_eq!(note.path.as_deref(), Some("src/old.rs"));
        assert_eq!(note.line, Some(14));
        assert_eq!(note.original_line, Some(14));
    }

    #[test]
    fn created_responses_bind_exact_body_author_and_single_note() {
        let body = "finding\n<!-- marker -->";
        let value = json!({
            "id": "discussion-1",
            "individual_note": false,
            "notes": [{
                "id": 41,
                "type": "DiffNote",
                "body": body,
                "author": {"id": 7, "username": "bot", "future": true},
                "system": false,
                "future": {"nested": true}
            }],
            "future": 1
        });
        let mut response = json_response(&value, Vec::new());
        response.status = 201;
        assert_eq!(
            parse_created_discussion_response(&response, body, 7, GitLabWireLimits::default()),
            Ok(ValidatedCreatedPublication { note_id: 41 })
        );
        assert_eq!(
            parse_created_discussion_response(
                &response,
                "different",
                7,
                GitLabWireLimits::default()
            ),
            Err(GitLabWireError::CreatedResponseMismatch)
        );

        let mut note_value = value["notes"][0].clone();
        note_value["type"] = Value::Null;
        let mut note = json_response(&note_value, Vec::new());
        note.status = 201;
        assert_eq!(
            parse_created_note_response(&note, body, 7, GitLabWireLimits::default()),
            Ok(ValidatedCreatedPublication { note_id: 41 })
        );
        assert_eq!(
            parse_created_note_response(&note, body, 8, GitLabWireLimits::default()),
            Err(GitLabWireError::CreatedResponseMismatch)
        );
    }

    #[test]
    fn created_responses_reject_recursive_duplicate_known_fields() {
        let body = br#"{"id":"d1","individual_note":false,"notes":[{"id":1,"type":"DiffNote","body":"x","author":{"id":7,"id":8,"username":"bot"},"system":false}]}"#;
        let response = GitLabResponseObservation {
            status: 201,
            headers: Vec::new(),
            body: body.to_vec(),
        };
        assert_eq!(
            parse_created_discussion_response(&response, "x", 7, GitLabWireLimits::default()),
            Err(GitLabWireError::MalformedJson)
        );
    }
}
