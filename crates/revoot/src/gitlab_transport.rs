//! Hardened, read-only GitLab REST transport.
//!
//! The public constructor requires a previously authorized direct egress route.
//! Requests are assembled from a closed endpoint enum, pinned to the authorized
//! DNS answers, and sent with an explicit rustls/ring trust configuration.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING, USER_AGENT,
};
use reqwest::{StatusCode, Url};
use revoot_core::{
    AllowedProviderEgress, CertificateAuthorityMode, DiffVersionId, EgressRouteKind, GitLabOrigin,
    GitLabResponseHeader, GitLabResponseObservation, GitSha, MergeRequestIid, ProjectId,
    RepositoryPath,
};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::retry::{
    RetryJitter, RetryPolicy, retry_after as parse_retry_after, retryable_server_status,
};

const ADAPTER_ID: &str = "gitlab-rest";
const API_ROOT_PATH: &str = "/api/v4";
const MAX_TOKEN_BYTES: usize = 4_096;
const MAX_CUSTOM_CA_CERTIFICATES: usize = 64;
const MAX_CUSTOM_CA_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_CUSTOM_CA_BUNDLE_BYTES: usize = 1024 * 1024;
const HARD_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const HARD_MAX_RESPONSE_HEADERS: usize = 256;
const HARD_MAX_OBSERVED_HEADER_BYTES: usize = 16 * 1024;
const HARD_MAX_TOTAL_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;
const MAX_PAGE: u32 = 10_000;
const MAX_PER_PAGE: u32 = 100;
const MAX_REPOSITORY_PATH_BYTES: usize = 4_096;
const USER_AGENT_VALUE: &str = concat!("revoot/", env!("CARGO_PKG_VERSION"));

static PRIVATE_TOKEN: HeaderName = HeaderName::from_static("private-token");
static JOB_TOKEN: HeaderName = HeaderName::from_static("job-token");

/// GitLab authentication schemes supported by the direct REST transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabAuthenticationKind {
    /// Project, group, or personal access token sent as `PRIVATE-TOKEN`.
    PrivateToken,
    /// GitLab CI job token sent as `JOB-TOKEN`. This is read-only in Revoot.
    JobToken,
    /// OAuth or other GitLab-supported bearer credential.
    Bearer,
}

/// Secret GitLab access token. Its value is never formatted or serialized.
pub struct GitLabAccessToken {
    value: Box<[u8]>,
    kind: GitLabAuthenticationKind,
}

impl GitLabAccessToken {
    /// Validate and take ownership of a token suitable for one HTTP header.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, whitespace, and control-containing values.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, GitLabClientBuildError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || !value.iter().all(|byte| (b'!'..=b'~').contains(byte))
        {
            return Err(GitLabClientBuildError::InvalidAccessToken);
        }
        Ok(Self {
            value: value.into_boxed_slice(),
            kind: GitLabAuthenticationKind::PrivateToken,
        })
    }

    /// Construct a read credential from a GitLab CI job token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, whitespace, and control-containing values.
    pub fn job_token(value: impl Into<Vec<u8>>) -> Result<Self, GitLabClientBuildError> {
        Self::with_kind(value, GitLabAuthenticationKind::JobToken)
    }

    /// Construct a read credential using `Authorization: Bearer`.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, whitespace, and control-containing values.
    pub fn bearer(value: impl Into<Vec<u8>>) -> Result<Self, GitLabClientBuildError> {
        Self::with_kind(value, GitLabAuthenticationKind::Bearer)
    }

    fn with_kind(
        value: impl Into<Vec<u8>>,
        kind: GitLabAuthenticationKind,
    ) -> Result<Self, GitLabClientBuildError> {
        let mut credential = Self::new(value)?;
        credential.kind = kind;
        Ok(credential)
    }

    fn header_value(&self) -> Result<HeaderValue, GitLabClientBuildError> {
        let mut value = HeaderValue::from_bytes(&self.value)
            .map_err(|_| GitLabClientBuildError::InvalidAccessToken)?;
        value.set_sensitive(true);
        Ok(value)
    }

    fn authorization_header(&self) -> Result<HeaderValue, GitLabClientBuildError> {
        bearer_header(&self.value)
    }

    #[must_use]
    pub const fn kind(&self) -> GitLabAuthenticationKind {
        self.kind
    }
}

impl Drop for GitLabAccessToken {
    fn drop(&mut self) {
        self.value.fill(0);
    }
}

impl fmt::Debug for GitLabAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitLabAccessToken(<redacted>)")
    }
}

/// Secret credential dedicated to the closed publication mutation surface.
///
/// This type is intentionally not interchangeable with [`GitLabAccessToken`],
/// so a read capability cannot silently acquire mutation authority.
pub struct GitLabWriteAccessToken {
    value: Box<[u8]>,
    kind: GitLabAuthenticationKind,
}

impl GitLabWriteAccessToken {
    /// Validate and take ownership of a write-scoped token.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, whitespace, or control-containing
    /// token bytes.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, GitLabClientBuildError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || !value.iter().all(|byte| (b'!'..=b'~').contains(byte))
        {
            return Err(GitLabClientBuildError::InvalidAccessToken);
        }
        Ok(Self {
            value: value.into_boxed_slice(),
            kind: GitLabAuthenticationKind::PrivateToken,
        })
    }

    /// Construct a write credential using `Authorization: Bearer`.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-ASCII, whitespace, and control-containing values.
    pub fn bearer(value: impl Into<Vec<u8>>) -> Result<Self, GitLabClientBuildError> {
        let mut credential = Self::new(value)?;
        credential.kind = GitLabAuthenticationKind::Bearer;
        Ok(credential)
    }

    fn header_value(&self) -> Result<HeaderValue, GitLabClientBuildError> {
        let mut value = HeaderValue::from_bytes(&self.value)
            .map_err(|_| GitLabClientBuildError::InvalidAccessToken)?;
        value.set_sensitive(true);
        Ok(value)
    }

    fn authorization_header(&self) -> Result<HeaderValue, GitLabClientBuildError> {
        bearer_header(&self.value)
    }

    #[must_use]
    pub const fn kind(&self) -> GitLabAuthenticationKind {
        self.kind
    }
}

impl Drop for GitLabWriteAccessToken {
    fn drop(&mut self) {
        self.value.fill(0);
    }
}

impl fmt::Debug for GitLabWriteAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitLabWriteAccessToken(<redacted>)")
    }
}

fn bearer_header(value: &[u8]) -> Result<HeaderValue, GitLabClientBuildError> {
    let mut bytes = [0_u8; MAX_TOKEN_BYTES + 7];
    let length = value
        .len()
        .checked_add(7)
        .ok_or(GitLabClientBuildError::InvalidAccessToken)?;
    if length > bytes.len() {
        return Err(GitLabClientBuildError::InvalidAccessToken);
    }
    bytes[..7].copy_from_slice(b"Bearer ");
    bytes[7..length].copy_from_slice(value);
    let result = HeaderValue::from_bytes(&bytes[..length])
        .map_err(|_| GitLabClientBuildError::InvalidAccessToken)
        .map(|mut header| {
            header.set_sensitive(true);
            header
        });
    bytes.fill(0);
    result
}

/// Exact DER roots and their configuration identity.
pub struct GitLabCustomCaBundle {
    certificates: Vec<Vec<u8>>,
    sha256: [u8; 32],
}

impl GitLabCustomCaBundle {
    /// Build a bounded custom-root bundle and bind it to the expected digest.
    ///
    /// The digest is SHA-256 over the exact DER certificates in order, with each
    /// certificate prefixed by its unsigned 64-bit big-endian length.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized bundles, empty/oversized certificates, and a
    /// digest mismatch. Certificate syntax is checked when the client is built.
    pub fn from_der(
        certificates: Vec<Vec<u8>>,
        expected_sha256: [u8; 32],
    ) -> Result<Self, GitLabClientBuildError> {
        if certificates.is_empty() || certificates.len() > MAX_CUSTOM_CA_CERTIFICATES {
            return Err(GitLabClientBuildError::InvalidCustomCaBundle);
        }
        let mut total = 0_usize;
        let mut hasher = Sha256::new();
        for certificate in &certificates {
            if certificate.is_empty() || certificate.len() > MAX_CUSTOM_CA_CERTIFICATE_BYTES {
                return Err(GitLabClientBuildError::InvalidCustomCaBundle);
            }
            total = total
                .checked_add(certificate.len())
                .ok_or(GitLabClientBuildError::InvalidCustomCaBundle)?;
            if total > MAX_CUSTOM_CA_BUNDLE_BYTES {
                return Err(GitLabClientBuildError::InvalidCustomCaBundle);
            }
            let length = u64::try_from(certificate.len())
                .map_err(|_| GitLabClientBuildError::InvalidCustomCaBundle)?;
            hasher.update(length.to_be_bytes());
            hasher.update(certificate);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_sha256 {
            return Err(GitLabClientBuildError::CustomCaIdentityMismatch);
        }
        Ok(Self {
            certificates,
            sha256: actual,
        })
    }

    /// Return the exact bundle identity for policy binding.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

impl fmt::Debug for GitLabCustomCaBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabCustomCaBundle")
            .field("certificate_count", &self.certificates.len())
            .field("sha256", &"<redacted>")
            .finish()
    }
}

/// Explicit trust-root choices. Platform/root discovery is not representable.
pub enum GitLabCaMode {
    /// The Mozilla roots compiled into the pinned `webpki-roots` dependency.
    BundledWebPki,
    /// Only the exact custom DER roots are trusted.
    CustomBundle(GitLabCustomCaBundle),
}

impl fmt::Debug for GitLabCaMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundledWebPki => formatter.write_str("BundledWebPki"),
            Self::CustomBundle(bundle) => {
                formatter.debug_tuple("CustomBundle").field(bundle).finish()
            }
        }
    }
}

/// Network and allocation limits for one read-only request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabTransportLimits {
    connect_timeout: Duration,
    request_timeout: Duration,
    read_idle_timeout: Duration,
    connection_pool_idle_timeout: Duration,
    max_body_bytes: usize,
}

impl GitLabTransportLimits {
    /// Construct bounded time and body limits.
    ///
    /// # Errors
    ///
    /// Rejects zero durations/body size, a phase timeout greater than the total
    /// request deadline, or a body cap above 32 MiB.
    pub fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        read_idle_timeout: Duration,
        connection_pool_idle_timeout: Duration,
        max_body_bytes: usize,
    ) -> Result<Self, GitLabClientBuildError> {
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || read_idle_timeout.is_zero()
            || connection_pool_idle_timeout.is_zero()
            || connect_timeout > request_timeout
            || read_idle_timeout > request_timeout
            || max_body_bytes == 0
            || max_body_bytes > HARD_MAX_BODY_BYTES
        {
            return Err(GitLabClientBuildError::InvalidLimits);
        }
        Ok(Self {
            connect_timeout,
            request_timeout,
            read_idle_timeout,
            connection_pool_idle_timeout,
            max_body_bytes,
        })
    }

    #[must_use]
    pub const fn max_body_bytes(self) -> usize {
        self.max_body_bytes
    }
}

impl Default for GitLabTransportLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            read_idle_timeout: Duration::from_secs(10),
            connection_pool_idle_timeout: Duration::from_secs(15),
            max_body_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Complete transport configuration, excluding the credential and egress grant.
pub struct GitLabTransportConfig {
    origin: GitLabOrigin,
    ca_mode: GitLabCaMode,
    limits: GitLabTransportLimits,
}

impl GitLabTransportConfig {
    #[must_use]
    pub const fn new(
        origin: GitLabOrigin,
        ca_mode: GitLabCaMode,
        limits: GitLabTransportLimits,
    ) -> Self {
        Self {
            origin,
            ca_mode,
            limits,
        }
    }
}

impl fmt::Debug for GitLabTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabTransportConfig")
            .field("origin", &"<redacted>")
            .field("ca_mode", &self.ca_mode)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Validated offset pagination accepted by GitLab collection endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabPagination {
    page: u32,
    per_page: u32,
}

impl GitLabPagination {
    /// Construct a bounded page request.
    ///
    /// # Errors
    ///
    /// Rejects page zero, pages above 10,000, and per-page values outside 1..=100.
    pub const fn new(page: u32, per_page: u32) -> Result<Self, GitLabEndpointError> {
        if page == 0 || page > MAX_PAGE || per_page == 0 || per_page > MAX_PER_PAGE {
            Err(GitLabEndpointError::InvalidPagination)
        } else {
            Ok(Self { page, per_page })
        }
    }

    #[must_use]
    pub const fn page(self) -> u32 {
        self.page
    }

    #[must_use]
    pub const fn per_page(self) -> u32 {
        self.per_page
    }
}

/// Closed set of GitLab REST reads used by snapshot and publication inventory.
pub enum GitLabReadEndpoint {
    CurrentUser,
    Project {
        project_id: ProjectId,
    },
    ProjectByPath {
        project_path: revoot_core::GitLabProjectPath,
    },
    MergeRequest {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
    },
    DiffVersions {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        pagination: GitLabPagination,
    },
    ExactDiffVersion {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        version_id: DiffVersionId,
    },
    ChangedFiles {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        pagination: GitLabPagination,
    },
    RawRepositoryFile {
        project_id: ProjectId,
        file_path: RepositoryPath,
        revision: GitSha,
    },
    Discussions {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        pagination: GitLabPagination,
    },
}

impl GitLabReadEndpoint {
    const fn kind(&self) -> GitLabReadEndpointKind {
        match self {
            Self::CurrentUser => GitLabReadEndpointKind::CurrentUser,
            Self::Project { .. } | Self::ProjectByPath { .. } => GitLabReadEndpointKind::Project,
            Self::MergeRequest { .. } => GitLabReadEndpointKind::MergeRequest,
            Self::DiffVersions { .. } => GitLabReadEndpointKind::DiffVersions,
            Self::ExactDiffVersion { .. } => GitLabReadEndpointKind::ExactDiffVersion,
            Self::ChangedFiles { .. } => GitLabReadEndpointKind::ChangedFiles,
            Self::RawRepositoryFile { .. } => GitLabReadEndpointKind::RawRepositoryFile,
            Self::Discussions { .. } => GitLabReadEndpointKind::Discussions,
        }
    }

    const fn expected_content(&self) -> ExpectedContent {
        match self {
            Self::RawRepositoryFile { .. } => ExpectedContent::Raw,
            _ => ExpectedContent::Json,
        }
    }
}

impl fmt::Debug for GitLabReadEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("GitLabReadEndpoint")
            .field(&self.kind())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabReadEndpointKind {
    CurrentUser,
    Project,
    MergeRequest,
    DiffVersions,
    ExactDiffVersion,
    ChangedFiles,
    RawRepositoryFile,
    Discussions,
}

/// Exact GitLab text position used by the closed discussion-create endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct GitLabTextPosition {
    pub position_type: &'static str,
    pub base_sha: String,
    pub start_sha: String,
    pub head_sha: String,
    pub old_path: String,
    pub new_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line: Option<u32>,
}

#[derive(Serialize)]
struct GitLabDiscussionCreateBody<'a> {
    body: &'a str,
    position: &'a GitLabTextPosition,
}

#[derive(Serialize)]
struct GitLabNoteCreateBody<'a> {
    body: &'a str,
}

#[derive(Serialize)]
struct GitLabDiscussionResolveBody {
    resolved: bool,
}

#[derive(Serialize)]
struct GitLabMergeRequestDescriptionBody<'a> {
    description: &'a str,
}

/// Closed mutation surface: replace the bounded MR description, create a Revoot
/// comment, or resolve one exact Revoot-owned discussion selected by
/// reconciliation. General note edits, deletion, and arbitrary GitLab mutation
/// are not representable.
pub(crate) enum GitLabWriteEndpoint<'a> {
    Discussion {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        body: &'a str,
        position: &'a GitLabTextPosition,
    },
    SummaryNote {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        body: &'a str,
    },
    SetDiscussionResolved {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        discussion_id: &'a str,
        resolved: bool,
    },
    UpdateMergeRequestDescription {
        project_id: ProjectId,
        merge_request_iid: MergeRequestIid,
        description: &'a str,
    },
}

/// Safe rate-limit fields retained from a response.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitLabRateLimitMetadata {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_epoch_seconds: Option<u64>,
    pub malformed: bool,
}

/// Safe response metadata. Raw URLs, bodies, credentials, and arbitrary headers are excluded.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitLabResponseMetadata {
    pub request_id: Option<String>,
    pub request_id_malformed: bool,
    pub rate_limit: GitLabRateLimitMetadata,
    pub retry_after_seconds: Option<u64>,
    pub retry_after_malformed: bool,
}

/// Retry facts only; the adapter never performs an automatic replay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitLabRetryMetadata {
    pub eligible_read: bool,
    pub after_seconds: Option<u64>,
}

/// Successful, bounded response ready for the strict wire parser.
pub struct GitLabReadResponse {
    observation: GitLabResponseObservation,
    metadata: GitLabResponseMetadata,
}

impl GitLabReadResponse {
    #[must_use]
    pub const fn metadata(&self) -> &GitLabResponseMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn observation(&self) -> &GitLabResponseObservation {
        &self.observation
    }

    #[must_use]
    pub fn into_observation(self) -> GitLabResponseObservation {
        self.observation
    }
}

impl fmt::Debug for GitLabReadResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabReadResponse")
            .field("status", &self.observation.status)
            .field("header_count", &self.observation.headers.len())
            .field("body_bytes", &self.observation.body.len())
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Safe client-construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabClientBuildError {
    InvalidAccessToken,
    InvalidCustomCaBundle,
    CustomCaIdentityMismatch,
    InvalidCustomCaCertificate,
    InvalidLimits,
    InvalidOrigin,
    WrongAdapter,
    WrongAuthorizedOrigin,
    WrongAuthorizedPath,
    ProxyNotSupported,
    CertificateAuthorityMismatch,
    DnsPinMismatch,
    TlsConfiguration,
    HttpClientConfiguration,
}

impl fmt::Display for GitLabClientBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GitLab client configuration rejected: {self:?}")
    }
}

impl Error for GitLabClientBuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabEndpointError {
    InvalidPagination,
    UrlConstruction,
    OriginBinding,
}

impl fmt::Display for GitLabEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GitLab read endpoint rejected: {self:?}")
    }
}

impl Error for GitLabEndpointError {}

/// Closed failure taxonomy containing no URL, credential, raw header, or body text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabFailureKind {
    Authentication,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    RedirectDenied,
    ServerUnavailable,
    UnexpectedStatus,
    MissingContentType,
    UnsupportedContentType,
    UnsupportedContentEncoding,
    MalformedContentLength,
    BodyTooLarge,
    TooManyHeaders,
    ObservedHeaderTooLarge,
    ConnectTimeout,
    RequestTimeout,
    BodyTimeout,
    Connection,
    Protocol,
    Endpoint,
}

/// One failed request with safe classification and retry metadata.
pub struct GitLabTransportError {
    kind: GitLabFailureKind,
    status: Option<u16>,
    metadata: Box<GitLabResponseMetadata>,
    retry: GitLabRetryMetadata,
}

impl GitLabTransportError {
    #[must_use]
    pub const fn kind(&self) -> GitLabFailureKind {
        self.kind
    }

    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    #[must_use]
    pub const fn metadata(&self) -> &GitLabResponseMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn retry(&self) -> GitLabRetryMetadata {
        self.retry
    }
}

impl fmt::Debug for GitLabTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabTransportError")
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("metadata", &self.metadata)
            .field("retry", &self.retry)
            .finish()
    }
}

impl fmt::Display for GitLabTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GitLab read failed: {:?}", self.kind)
    }
}

impl Error for GitLabTransportError {}

/// Whether a failed mutation is proven not to have committed or must be
/// reconciled against a fresh, complete inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabWriteFailureEffect {
    NoEffect,
    Ambiguous,
}

/// Safe failure observation for a closed publication mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabWriteError {
    pub kind: GitLabFailureKind,
    pub status: Option<u16>,
    pub metadata: GitLabResponseMetadata,
    pub effect: GitLabWriteFailureEffect,
    pub retryable_after_reconciliation: bool,
}

impl fmt::Display for GitLabWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitLab publication mutation failed: {:?}",
            self.kind
        )
    }
}

impl Error for GitLabWriteError {}

/// Bounded successful response to a closed publication mutation.
pub(crate) struct GitLabWriteResponse {
    pub observation: GitLabResponseObservation,
}

impl fmt::Debug for GitLabWriteResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabWriteResponse")
            .field("status", &self.observation.status)
            .field("header_count", &self.observation.headers.len())
            .field("body_bytes", &self.observation.body.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
enum ExpectedContent {
    Json,
    Raw,
}

struct RoutePins {
    hostname: String,
    addresses: Vec<SocketAddr>,
}

/// Direct, pinned and read-only GitLab client.
pub struct GitLabReadClient {
    http: reqwest::Client,
    origin: GitLabOrigin,
    request_base: Url,
    #[cfg(test)]
    loopback_host: Option<HeaderValue>,
    expected_origin: Url,
    max_body_bytes: usize,
    token: GitLabAccessToken,
}

impl GitLabReadClient {
    /// Construct a client from a pure-policy egress authorization.
    ///
    /// # Errors
    ///
    /// Fails closed unless the grant is for the exact adapter, origin,
    /// `/api/v4` root, direct route, CA kind, and canonical hostname.
    pub fn new(
        config: &GitLabTransportConfig,
        token: GitLabAccessToken,
        authorization: &AllowedProviderEgress,
    ) -> Result<Self, GitLabClientBuildError> {
        validate_authorization(config, authorization)?;
        let resolution = authorization.resolution();
        let addresses = resolution
            .pinned_addresses()
            .iter()
            .map(|address| SocketAddr::new(*address, config.origin.port()))
            .collect();
        let pins = RoutePins {
            hostname: resolution.hostname().as_str().to_owned(),
            addresses,
        };
        Self::build(config, token, &pins, None)
    }

    fn build(
        config: &GitLabTransportConfig,
        token: GitLabAccessToken,
        pins: &RoutePins,
        #[cfg(test)] loopback: Option<SocketAddr>,
        #[cfg(not(test))] _loopback: Option<SocketAddr>,
    ) -> Result<Self, GitLabClientBuildError> {
        if config.origin.host().parse::<IpAddr>().is_ok()
            || config.origin.host().starts_with('[')
            || pins.hostname != config.origin.host()
            || pins.addresses.is_empty()
        {
            return Err(GitLabClientBuildError::InvalidOrigin);
        }

        let expected_origin = parse_and_validate_origin(&config.origin)?;
        let tls = build_tls_config(&config.ca_mode)?;
        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        default_headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));

        let https_only = {
            #[cfg(test)]
            {
                loopback.is_none()
            }
            #[cfg(not(test))]
            {
                true
            }
        };
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(https_only)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(default_headers)
            .connect_timeout(config.limits.connect_timeout)
            .timeout(config.limits.request_timeout)
            .read_timeout(config.limits.read_idle_timeout)
            .pool_idle_timeout(Some(config.limits.connection_pool_idle_timeout))
            .pool_max_idle_per_host(1)
            .http1_only();
        for address in &pins.addresses {
            if address.ip().is_unspecified() {
                return Err(GitLabClientBuildError::DnsPinMismatch);
            }
        }
        builder = builder.resolve_to_addrs(&pins.hostname, &pins.addresses);
        let http = builder
            .build()
            .map_err(|_| GitLabClientBuildError::HttpClientConfiguration)?;

        #[cfg(test)]
        let (request_base, loopback_host) = if let Some(loopback) = loopback {
            let url = Url::parse(&format!("http://{loopback}"))
                .map_err(|_| GitLabClientBuildError::InvalidOrigin)?;
            let authority = config
                .origin
                .as_str()
                .strip_prefix("https://")
                .ok_or(GitLabClientBuildError::InvalidOrigin)?;
            let host = HeaderValue::from_str(authority)
                .map_err(|_| GitLabClientBuildError::InvalidOrigin)?;
            (url, Some(host))
        } else {
            (expected_origin.clone(), None)
        };
        #[cfg(not(test))]
        let request_base = expected_origin.clone();

        Ok(Self {
            http,
            origin: config.origin.clone(),
            request_base,
            #[cfg(test)]
            loopback_host,
            expected_origin,
            max_body_bytes: config.limits.max_body_bytes,
            token,
        })
    }

    /// Execute exactly one GET. No status or transport failure is retried here.
    ///
    /// # Errors
    ///
    /// Returns a safe classified error for endpoint construction, transport,
    /// status, content metadata, or body-limit failures.
    pub async fn get(
        &self,
        endpoint: &GitLabReadEndpoint,
    ) -> Result<GitLabReadResponse, GitLabTransportError> {
        let url = self.build_url(endpoint).map_err(|_| {
            failure(
                GitLabFailureKind::Endpoint,
                None,
                GitLabResponseMetadata::default(),
                false,
            )
        })?;
        let mut request = self
            .authenticate(self.http.get(url))
            .map_err(|_| endpoint_transport_failure())?;
        request = request.header(
            ACCEPT,
            match endpoint.expected_content() {
                ExpectedContent::Json => HeaderValue::from_static("application/json"),
                ExpectedContent::Raw => HeaderValue::from_static("application/octet-stream"),
            },
        );
        #[cfg(test)]
        if let Some(host) = &self.loopback_host {
            request = request.header(reqwest::header::HOST, host.clone());
        }

        let mut response = request
            .send()
            .await
            .map_err(|error| classify_send_error(&error))?;
        let status = response.status();
        let metadata = extract_metadata(response.headers());
        if status != StatusCode::OK {
            return Err(classify_status(status, metadata));
        }
        validate_response_headers(response.headers(), endpoint.expected_content(), &metadata)?;
        let declared_length = parse_content_length(response.headers(), &metadata)?;
        if declared_length.is_some_and(|length| length > self.max_body_bytes) {
            return Err(failure(
                GitLabFailureKind::BodyTooLarge,
                Some(status.as_u16()),
                metadata,
                false,
            ));
        }
        let headers = retain_wire_headers(response.headers(), &metadata)?;
        let capacity = declared_length.unwrap_or(0).min(self.max_body_bytes);
        let mut body = Vec::with_capacity(capacity);
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|error| classify_body_error(&error, status.as_u16(), metadata.clone()))?;
            let Some(chunk) = chunk else {
                break;
            };
            let Some(next_length) = body.len().checked_add(chunk.len()) else {
                return Err(failure(
                    GitLabFailureKind::BodyTooLarge,
                    Some(status.as_u16()),
                    metadata,
                    false,
                ));
            };
            if next_length > self.max_body_bytes {
                return Err(failure(
                    GitLabFailureKind::BodyTooLarge,
                    Some(status.as_u16()),
                    metadata,
                    false,
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(GitLabReadResponse {
            observation: GitLabResponseObservation {
                status: status.as_u16(),
                headers,
                body,
            },
            metadata,
        })
    }

    /// Execute a safe GET with one bounded logical-operation retry budget.
    /// Controllers that already own a broader budget call [`Self::get`]
    /// directly so retry loops cannot multiply.
    ///
    /// # Errors
    ///
    /// Returns the final safe classified error when the operation is permanent
    /// or its attempt or elapsed-time budget is exhausted.
    pub async fn get_with_retry(
        &self,
        endpoint: &GitLabReadEndpoint,
    ) -> Result<GitLabReadResponse, GitLabTransportError> {
        let policy = RetryPolicy::default();
        let deadline = tokio::time::Instant::now() + policy.total_budget;
        let mut jitter = RetryJitter::for_operation();
        for attempt in 1..=policy.max_attempts {
            let result = tokio::time::timeout_at(deadline, self.get(endpoint)).await;
            let error = match result {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(error)) => error,
                Err(_) => {
                    return Err(failure(
                        GitLabFailureKind::RequestTimeout,
                        None,
                        GitLabResponseMetadata::default(),
                        false,
                    ));
                }
            };
            let retry = error.retry();
            if !retry.eligible_read || attempt == policy.max_attempts {
                return Err(error);
            }
            let delay = policy.delay(
                attempt,
                retry.after_seconds.map(Duration::from_secs),
                &mut jitter,
            );
            let Some(wake) = tokio::time::Instant::now().checked_add(delay) else {
                return Err(error);
            };
            if wake > deadline {
                return Err(error);
            }
            eprintln!(
                "revoot: platform=gitlab operation=safe_read attempt={} retry_reason={:?} delay_ms={} outcome=retrying",
                attempt,
                error.kind(),
                delay.as_millis()
            );
            tokio::time::sleep_until(wake).await;
        }
        unreachable!("validated retry policy always performs at least one attempt")
    }

    /// Return the exact canonical origin bound into this client.
    #[must_use]
    pub const fn origin(&self) -> &GitLabOrigin {
        &self.origin
    }

    fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, GitLabClientBuildError> {
        Ok(match self.token.kind {
            GitLabAuthenticationKind::PrivateToken => {
                request.header(PRIVATE_TOKEN.clone(), self.token.header_value()?)
            }
            GitLabAuthenticationKind::JobToken => {
                request.header(JOB_TOKEN.clone(), self.token.header_value()?)
            }
            GitLabAuthenticationKind::Bearer => {
                request.header(AUTHORIZATION, self.token.authorization_header()?)
            }
        })
    }

    fn build_url(&self, endpoint: &GitLabReadEndpoint) -> Result<Url, GitLabEndpointError> {
        let mut url = self.request_base.clone();
        let endpoint_segments = endpoint_segments(endpoint)?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| GitLabEndpointError::UrlConstruction)?;
            segments.clear();
            for segment in &endpoint_segments {
                segments.push(segment);
            }
        }
        add_endpoint_query(&mut url, endpoint);
        #[cfg(test)]
        let production = self.loopback_host.is_none();
        #[cfg(not(test))]
        let production = true;
        if production && !same_origin(&url, &self.expected_origin) {
            return Err(GitLabEndpointError::OriginBinding);
        }
        Ok(url)
    }

    #[cfg(test)]
    pub(crate) fn new_for_loopback(
        config: &GitLabTransportConfig,
        token: GitLabAccessToken,
        address: SocketAddr,
    ) -> Result<Self, GitLabClientBuildError> {
        let pins = RoutePins {
            hostname: config.origin.host().to_owned(),
            addresses: vec![address],
        };
        Self::build(config, token, &pins, Some(address))
    }
}

impl fmt::Debug for GitLabReadClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabReadClient")
            .field("origin", &"<redacted>")
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

/// Direct, pinned GitLab client whose only request method is crate-private and
/// accepts the closed publication endpoint enum.
pub struct GitLabWriteClient {
    http: reqwest::Client,
    origin: GitLabOrigin,
    request_base: Url,
    #[cfg(test)]
    loopback_host: Option<HeaderValue>,
    expected_origin: Url,
    max_body_bytes: usize,
    token: GitLabWriteAccessToken,
}

impl GitLabWriteClient {
    /// Construct an inert publication capability. Actual mutation execution remains
    /// crate-private and is additionally guarded by the publication controller.
    ///
    /// # Errors
    ///
    /// Rejects invalid credentials, transport configuration, or an egress
    /// authorization that does not exactly bind the configured GitLab origin.
    pub fn new(
        config: &GitLabTransportConfig,
        token: GitLabWriteAccessToken,
        authorization: &AllowedProviderEgress,
    ) -> Result<Self, GitLabClientBuildError> {
        validate_authorization(config, authorization)?;
        let resolution = authorization.resolution();
        let pins = RoutePins {
            hostname: resolution.hostname().as_str().to_owned(),
            addresses: resolution
                .pinned_addresses()
                .iter()
                .map(|address| SocketAddr::new(*address, config.origin.port()))
                .collect(),
        };
        Self::build(config, token, &pins, None)
    }

    fn build(
        config: &GitLabTransportConfig,
        token: GitLabWriteAccessToken,
        pins: &RoutePins,
        #[cfg(test)] loopback: Option<SocketAddr>,
        #[cfg(not(test))] _loopback: Option<SocketAddr>,
    ) -> Result<Self, GitLabClientBuildError> {
        if config.origin.host().parse::<IpAddr>().is_ok()
            || config.origin.host().starts_with('[')
            || pins.hostname != config.origin.host()
            || pins.addresses.is_empty()
            || pins
                .addresses
                .iter()
                .any(|address| address.ip().is_unspecified())
        {
            return Err(GitLabClientBuildError::InvalidOrigin);
        }
        let expected_origin = parse_and_validate_origin(&config.origin)?;
        let tls = build_tls_config(&config.ca_mode)?;
        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        default_headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        let https_only = {
            #[cfg(test)]
            {
                loopback.is_none()
            }
            #[cfg(not(test))]
            {
                true
            }
        };
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(https_only)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(default_headers)
            .connect_timeout(config.limits.connect_timeout)
            .timeout(config.limits.request_timeout)
            .read_timeout(config.limits.read_idle_timeout)
            .pool_idle_timeout(Some(config.limits.connection_pool_idle_timeout))
            .pool_max_idle_per_host(1)
            .http1_only();
        builder = builder.resolve_to_addrs(&pins.hostname, &pins.addresses);
        let http = builder
            .build()
            .map_err(|_| GitLabClientBuildError::HttpClientConfiguration)?;
        #[cfg(test)]
        let (request_base, loopback_host) = if let Some(loopback) = loopback {
            let url = Url::parse(&format!("http://{loopback}"))
                .map_err(|_| GitLabClientBuildError::InvalidOrigin)?;
            let authority = config
                .origin
                .as_str()
                .strip_prefix("https://")
                .ok_or(GitLabClientBuildError::InvalidOrigin)?;
            let host = HeaderValue::from_str(authority)
                .map_err(|_| GitLabClientBuildError::InvalidOrigin)?;
            (url, Some(host))
        } else {
            (expected_origin.clone(), None)
        };
        #[cfg(not(test))]
        let request_base = expected_origin.clone();
        Ok(Self {
            http,
            origin: config.origin.clone(),
            request_base,
            #[cfg(test)]
            loopback_host,
            expected_origin,
            max_body_bytes: config.limits.max_body_bytes,
            token,
        })
    }

    #[must_use]
    pub(crate) const fn origin(&self) -> &GitLabOrigin {
        &self.origin
    }

    pub(crate) async fn mutate(
        &self,
        endpoint: &GitLabWriteEndpoint<'_>,
    ) -> Result<GitLabWriteResponse, GitLabWriteError> {
        let url = self
            .build_url(endpoint)
            .map_err(|_| write_endpoint_failure())?;
        let body = serialize_write_body(endpoint, self.max_body_bytes)?;
        let builder = if matches!(
            endpoint,
            GitLabWriteEndpoint::SetDiscussionResolved { .. }
                | GitLabWriteEndpoint::UpdateMergeRequestDescription { .. }
        ) {
            self.http.put(url)
        } else {
            self.http.post(url)
        };
        let request = self
            .authenticate(builder)
            .map_err(|_| write_endpoint_failure())?;
        let request = request
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(body);
        #[cfg(test)]
        let request = if let Some(host) = &self.loopback_host {
            request.header(reqwest::header::HOST, host.clone())
        } else {
            request
        };
        let response = request
            .send()
            .await
            .map_err(|error| classify_write_send_error(&error))?;
        let status = response.status();
        let metadata = extract_metadata(response.headers());
        let expected_status = if matches!(
            endpoint,
            GitLabWriteEndpoint::SetDiscussionResolved { .. }
                | GitLabWriteEndpoint::UpdateMergeRequestDescription { .. }
        ) {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        if status != expected_status {
            return Err(classify_write_status(status, metadata));
        }
        collect_write_response(response, metadata, self.max_body_bytes).await
    }

    fn build_url(&self, endpoint: &GitLabWriteEndpoint<'_>) -> Result<Url, GitLabEndpointError> {
        let mut url = self.request_base.clone();
        let (project_id, iid, final_segment) = match endpoint {
            GitLabWriteEndpoint::Discussion {
                project_id,
                merge_request_iid,
                ..
            }
            | GitLabWriteEndpoint::SetDiscussionResolved {
                project_id,
                merge_request_iid,
                ..
            } => (*project_id, *merge_request_iid, Some("discussions")),
            GitLabWriteEndpoint::SummaryNote {
                project_id,
                merge_request_iid,
                ..
            } => (*project_id, *merge_request_iid, Some("notes")),
            GitLabWriteEndpoint::UpdateMergeRequestDescription {
                project_id,
                merge_request_iid,
                ..
            } => (*project_id, *merge_request_iid, None),
        };
        let mut segments = vec!["api".to_owned(), "v4".to_owned()];
        push_merge_request_segments(&mut segments, project_id, iid);
        if let Some(final_segment) = final_segment {
            segments.push(final_segment.to_owned());
        }
        if let GitLabWriteEndpoint::SetDiscussionResolved { discussion_id, .. } = endpoint {
            if discussion_id.is_empty()
                || discussion_id.len() > 128
                || !discussion_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(GitLabEndpointError::UrlConstruction);
            }
            segments.push((*discussion_id).to_owned());
        }
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| GitLabEndpointError::UrlConstruction)?;
            path.clear();
            for segment in &segments {
                path.push(segment);
            }
        }
        #[cfg(test)]
        let production = self.loopback_host.is_none();
        #[cfg(not(test))]
        let production = true;
        if production && !same_origin(&url, &self.expected_origin) {
            return Err(GitLabEndpointError::OriginBinding);
        }
        Ok(url)
    }

    fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, GitLabClientBuildError> {
        Ok(match self.token.kind {
            GitLabAuthenticationKind::PrivateToken => {
                request.header(PRIVATE_TOKEN.clone(), self.token.header_value()?)
            }
            GitLabAuthenticationKind::Bearer => {
                request.header(AUTHORIZATION, self.token.authorization_header()?)
            }
            GitLabAuthenticationKind::JobToken => {
                return Err(GitLabClientBuildError::InvalidAccessToken);
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_loopback(
        config: &GitLabTransportConfig,
        token: GitLabWriteAccessToken,
        address: SocketAddr,
    ) -> Result<Self, GitLabClientBuildError> {
        let pins = RoutePins {
            hostname: config.origin.host().to_owned(),
            addresses: vec![address],
        };
        Self::build(config, token, &pins, Some(address))
    }
}

fn write_endpoint_failure() -> GitLabWriteError {
    write_failure(
        GitLabFailureKind::Endpoint,
        None,
        GitLabResponseMetadata::default(),
        GitLabWriteFailureEffect::NoEffect,
        false,
    )
}

fn endpoint_transport_failure() -> GitLabTransportError {
    failure(
        GitLabFailureKind::Endpoint,
        None,
        GitLabResponseMetadata::default(),
        false,
    )
}

fn serialize_write_body(
    endpoint: &GitLabWriteEndpoint<'_>,
    max_body_bytes: usize,
) -> Result<Vec<u8>, GitLabWriteError> {
    let body = match endpoint {
        GitLabWriteEndpoint::Discussion { body, position, .. } => {
            serde_json::to_vec(&GitLabDiscussionCreateBody { body, position })
        }
        GitLabWriteEndpoint::SummaryNote { body, .. } => {
            serde_json::to_vec(&GitLabNoteCreateBody { body })
        }
        GitLabWriteEndpoint::SetDiscussionResolved { resolved, .. } => {
            serde_json::to_vec(&GitLabDiscussionResolveBody {
                resolved: *resolved,
            })
        }
        GitLabWriteEndpoint::UpdateMergeRequestDescription { description, .. } => {
            serde_json::to_vec(&GitLabMergeRequestDescriptionBody { description })
        }
    }
    .map_err(|_| write_endpoint_failure())?;
    if body.len() > max_body_bytes {
        return Err(write_failure(
            GitLabFailureKind::BodyTooLarge,
            None,
            GitLabResponseMetadata::default(),
            GitLabWriteFailureEffect::NoEffect,
            false,
        ));
    }
    Ok(body)
}

fn classify_write_status(status: StatusCode, metadata: GitLabResponseMetadata) -> GitLabWriteError {
    let read = classify_status(status, metadata.clone());
    let effect = if matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::CONFLICT
            | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        GitLabWriteFailureEffect::NoEffect
    } else {
        GitLabWriteFailureEffect::Ambiguous
    };
    let retryable = matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
    ) || retryable_server_status(status.as_u16());
    write_failure(
        read.kind(),
        Some(status.as_u16()),
        metadata,
        effect,
        retryable,
    )
}

async fn collect_write_response(
    mut response: reqwest::Response,
    metadata: GitLabResponseMetadata,
    max_body_bytes: usize,
) -> Result<GitLabWriteResponse, GitLabWriteError> {
    let status = response.status().as_u16();
    validate_write_response_headers(response.headers(), &metadata)?;
    let declared_length = parse_write_content_length(response.headers(), &metadata)?;
    if declared_length.is_some_and(|length| length > max_body_bytes) {
        return Err(write_failure(
            GitLabFailureKind::BodyTooLarge,
            Some(status),
            metadata,
            GitLabWriteFailureEffect::Ambiguous,
            false,
        ));
    }
    let headers = retain_write_wire_headers(response.headers(), &metadata)?;
    let mut body = Vec::with_capacity(declared_length.unwrap_or_default().min(max_body_bytes));
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        let read = classify_body_error(&error, status, metadata.clone());
        write_failure(
            read.kind(),
            Some(status),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        )
    })? {
        let Some(total) = body.len().checked_add(chunk.len()) else {
            return Err(write_failure(
                GitLabFailureKind::BodyTooLarge,
                Some(status),
                metadata,
                GitLabWriteFailureEffect::Ambiguous,
                false,
            ));
        };
        if total > max_body_bytes {
            return Err(write_failure(
                GitLabFailureKind::BodyTooLarge,
                Some(status),
                metadata,
                GitLabWriteFailureEffect::Ambiguous,
                false,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    if declared_length.is_some_and(|length| length != body.len()) {
        return Err(write_failure(
            GitLabFailureKind::MalformedContentLength,
            Some(status),
            metadata,
            GitLabWriteFailureEffect::Ambiguous,
            false,
        ));
    }
    Ok(GitLabWriteResponse {
        observation: GitLabResponseObservation {
            status,
            headers,
            body,
        },
    })
}

fn validate_authorization(
    config: &GitLabTransportConfig,
    authorization: &AllowedProviderEgress,
) -> Result<(), GitLabClientBuildError> {
    if authorization.adapter_id() != ADAPTER_ID {
        return Err(GitLabClientBuildError::WrongAdapter);
    }
    if authorization.route_kind() != EgressRouteKind::Direct {
        return Err(GitLabClientBuildError::ProxyNotSupported);
    }
    match (&config.ca_mode, authorization.certificate_authorities()) {
        (GitLabCaMode::BundledWebPki, CertificateAuthorityMode::BundledWebPki) => {}
        (GitLabCaMode::CustomBundle(bundle), CertificateAuthorityMode::CustomBundle { sha256 })
            if bundle.sha256 == *sha256 => {}
        (GitLabCaMode::CustomBundle(_), CertificateAuthorityMode::CustomBundle { .. }) => {
            return Err(GitLabClientBuildError::CustomCaIdentityMismatch);
        }
        _ => return Err(GitLabClientBuildError::CertificateAuthorityMismatch),
    }
    let authorized_origin = authorization.endpoint().origin();
    if authorized_origin.hostname().as_str() != config.origin.host()
        || authorized_origin.port() != config.origin.port()
    {
        return Err(GitLabClientBuildError::WrongAuthorizedOrigin);
    }
    if authorization.endpoint().path() != API_ROOT_PATH {
        return Err(GitLabClientBuildError::WrongAuthorizedPath);
    }
    let resolution = authorization.resolution();
    if resolution.hostname().as_str() != config.origin.host()
        || resolution.pinned_addresses().is_empty()
    {
        return Err(GitLabClientBuildError::DnsPinMismatch);
    }
    Ok(())
}

fn parse_and_validate_origin(origin: &GitLabOrigin) -> Result<Url, GitLabClientBuildError> {
    let url = Url::parse(origin.as_str()).map_err(|_| GitLabClientBuildError::InvalidOrigin)?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.host_str() != Some(origin.host())
        || url.port_or_known_default() != Some(origin.port())
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GitLabClientBuildError::InvalidOrigin);
    }
    Ok(url)
}

fn build_tls_config(ca_mode: &GitLabCaMode) -> Result<ClientConfig, GitLabClientBuildError> {
    let roots = match ca_mode {
        GitLabCaMode::BundledWebPki => RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        },
        GitLabCaMode::CustomBundle(bundle) => {
            let mut roots = RootCertStore::empty();
            for certificate in &bundle.certificates {
                roots
                    .add(CertificateDer::from(certificate.as_slice()))
                    .map_err(|_| GitLabClientBuildError::InvalidCustomCaCertificate)?;
            }
            roots
        }
    };
    if roots.is_empty() {
        return Err(GitLabClientBuildError::InvalidCustomCaBundle);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| GitLabClientBuildError::TlsConfiguration)?;
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
        && left.username().is_empty()
        && left.password().is_none()
}

fn endpoint_segments(endpoint: &GitLabReadEndpoint) -> Result<Vec<String>, GitLabEndpointError> {
    let mut segments = vec!["api".to_owned(), "v4".to_owned()];
    match endpoint {
        GitLabReadEndpoint::CurrentUser => {
            segments.push("user".to_owned());
        }
        GitLabReadEndpoint::Project { project_id } => {
            segments.push("projects".to_owned());
            segments.push(project_id.get().to_string());
        }
        GitLabReadEndpoint::ProjectByPath { project_path } => {
            segments.push("projects".to_owned());
            segments.push(project_path.as_str().to_owned());
        }
        GitLabReadEndpoint::MergeRequest {
            project_id,
            merge_request_iid,
        } => push_merge_request_segments(&mut segments, *project_id, *merge_request_iid),
        GitLabReadEndpoint::DiffVersions {
            project_id,
            merge_request_iid,
            ..
        } => {
            push_merge_request_segments(&mut segments, *project_id, *merge_request_iid);
            segments.push("versions".to_owned());
        }
        GitLabReadEndpoint::ExactDiffVersion {
            project_id,
            merge_request_iid,
            version_id,
        } => {
            push_merge_request_segments(&mut segments, *project_id, *merge_request_iid);
            segments.push("versions".to_owned());
            segments.push(version_id.get().to_string());
        }
        GitLabReadEndpoint::ChangedFiles {
            project_id,
            merge_request_iid,
            ..
        } => {
            push_merge_request_segments(&mut segments, *project_id, *merge_request_iid);
            segments.push("diffs".to_owned());
        }
        GitLabReadEndpoint::RawRepositoryFile {
            project_id,
            file_path,
            ..
        } => {
            if file_path.as_str().len() > MAX_REPOSITORY_PATH_BYTES {
                return Err(GitLabEndpointError::UrlConstruction);
            }
            segments.push("projects".to_owned());
            segments.push(project_id.get().to_string());
            segments.push("repository".to_owned());
            segments.push("files".to_owned());
            segments.push(file_path.as_str().to_owned());
            segments.push("raw".to_owned());
        }
        GitLabReadEndpoint::Discussions {
            project_id,
            merge_request_iid,
            ..
        } => {
            push_merge_request_segments(&mut segments, *project_id, *merge_request_iid);
            segments.push("discussions".to_owned());
        }
    }
    Ok(segments)
}

fn push_merge_request_segments(
    segments: &mut Vec<String>,
    project_id: ProjectId,
    merge_request_iid: MergeRequestIid,
) {
    segments.push("projects".to_owned());
    segments.push(project_id.get().to_string());
    segments.push("merge_requests".to_owned());
    segments.push(merge_request_iid.get().to_string());
}

fn add_endpoint_query(url: &mut Url, endpoint: &GitLabReadEndpoint) {
    match endpoint {
        GitLabReadEndpoint::DiffVersions { pagination, .. }
        | GitLabReadEndpoint::ChangedFiles { pagination, .. }
        | GitLabReadEndpoint::Discussions { pagination, .. } => {
            url.query_pairs_mut()
                .append_pair("page", &pagination.page().to_string())
                .append_pair("per_page", &pagination.per_page().to_string());
            if matches!(endpoint, GitLabReadEndpoint::ChangedFiles { .. }) {
                url.query_pairs_mut().append_pair("unidiff", "true");
            }
        }
        GitLabReadEndpoint::ExactDiffVersion { .. } => {
            url.query_pairs_mut().append_pair("unidiff", "true");
        }
        GitLabReadEndpoint::RawRepositoryFile { revision, .. } => {
            url.query_pairs_mut().append_pair("ref", revision.as_str());
        }
        GitLabReadEndpoint::CurrentUser
        | GitLabReadEndpoint::Project { .. }
        | GitLabReadEndpoint::ProjectByPath { .. }
        | GitLabReadEndpoint::MergeRequest { .. } => {}
    }
}

fn validate_response_headers(
    headers: &HeaderMap,
    expected: ExpectedContent,
    metadata: &GitLabResponseMetadata,
) -> Result<(), GitLabTransportError> {
    if headers.len() > HARD_MAX_RESPONSE_HEADERS {
        return Err(failure(
            GitLabFailureKind::TooManyHeaders,
            Some(StatusCode::OK.as_u16()),
            metadata.clone(),
            false,
        ));
    }
    let content_type = unique_header(headers, CONTENT_TYPE).map_err(|()| {
        failure(
            GitLabFailureKind::UnsupportedContentType,
            Some(StatusCode::OK.as_u16()),
            metadata.clone(),
            false,
        )
    })?;
    let Some(content_type) = content_type else {
        return Err(failure(
            GitLabFailureKind::MissingContentType,
            Some(StatusCode::OK.as_u16()),
            metadata.clone(),
            false,
        ));
    };
    if content_type.as_bytes().len() > HARD_MAX_OBSERVED_HEADER_BYTES
        || !content_type_allowed(content_type.as_bytes(), expected)
    {
        return Err(failure(
            GitLabFailureKind::UnsupportedContentType,
            Some(StatusCode::OK.as_u16()),
            metadata.clone(),
            false,
        ));
    }

    let content_encoding = unique_header(headers, CONTENT_ENCODING).map_err(|()| {
        failure(
            GitLabFailureKind::UnsupportedContentEncoding,
            Some(StatusCode::OK.as_u16()),
            metadata.clone(),
            false,
        )
    })?;
    if content_encoding.is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity")) {
        return Err(failure(
            GitLabFailureKind::UnsupportedContentEncoding,
            Some(StatusCode::OK.as_u16()),
            metadata.clone(),
            false,
        ));
    }
    Ok(())
}

fn validate_write_response_headers(
    headers: &HeaderMap,
    metadata: &GitLabResponseMetadata,
) -> Result<(), GitLabWriteError> {
    if headers.len() > HARD_MAX_RESPONSE_HEADERS {
        return Err(write_failure(
            GitLabFailureKind::TooManyHeaders,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        ));
    }
    let total_header_bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())?
            .checked_add(value.as_bytes().len())
    });
    if total_header_bytes.is_none_or(|bytes| bytes > HARD_MAX_TOTAL_RESPONSE_HEADER_BYTES) {
        return Err(write_failure(
            GitLabFailureKind::ObservedHeaderTooLarge,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        ));
    }
    let content_type = unique_header(headers, CONTENT_TYPE).map_err(|()| {
        write_failure(
            GitLabFailureKind::UnsupportedContentType,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        )
    })?;
    if content_type.is_none_or(|value| {
        value.as_bytes().len() > HARD_MAX_OBSERVED_HEADER_BYTES
            || !content_type_allowed(value.as_bytes(), ExpectedContent::Json)
    }) {
        return Err(write_failure(
            if content_type.is_none() {
                GitLabFailureKind::MissingContentType
            } else {
                GitLabFailureKind::UnsupportedContentType
            },
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        ));
    }
    let encoding = unique_header(headers, CONTENT_ENCODING).map_err(|()| {
        write_failure(
            GitLabFailureKind::UnsupportedContentEncoding,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        )
    })?;
    if encoding.is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity")) {
        return Err(write_failure(
            GitLabFailureKind::UnsupportedContentEncoding,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        ));
    }
    let transfer_encoding = unique_header(headers, TRANSFER_ENCODING).map_err(|()| {
        write_failure(
            GitLabFailureKind::MalformedContentLength,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        )
    })?;
    if transfer_encoding.is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"chunked"))
        || (transfer_encoding.is_some() && headers.contains_key(CONTENT_LENGTH))
    {
        return Err(write_failure(
            GitLabFailureKind::MalformedContentLength,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        ));
    }
    Ok(())
}

fn parse_write_content_length(
    headers: &HeaderMap,
    metadata: &GitLabResponseMetadata,
) -> Result<Option<usize>, GitLabWriteError> {
    let value = unique_header(headers, CONTENT_LENGTH).map_err(|()| {
        write_failure(
            GitLabFailureKind::MalformedContentLength,
            Some(StatusCode::CREATED.as_u16()),
            metadata.clone(),
            GitLabWriteFailureEffect::Ambiguous,
            false,
        )
    })?;
    value
        .map(|value| {
            let bytes = value.as_bytes();
            let parsed = std::str::from_utf8(bytes)
                .ok()
                .filter(|_| !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit))
                .and_then(|text| text.parse::<usize>().ok());
            parsed.ok_or_else(|| {
                write_failure(
                    GitLabFailureKind::MalformedContentLength,
                    Some(StatusCode::CREATED.as_u16()),
                    metadata.clone(),
                    GitLabWriteFailureEffect::Ambiguous,
                    false,
                )
            })
        })
        .transpose()
}

fn retain_write_wire_headers(
    headers: &HeaderMap,
    metadata: &GitLabResponseMetadata,
) -> Result<Vec<GitLabResponseHeader>, GitLabWriteError> {
    let mut retained = Vec::new();
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "content-length" | "content-type" | "x-request-id"
        ) {
            if value.as_bytes().len() > HARD_MAX_OBSERVED_HEADER_BYTES {
                return Err(write_failure(
                    GitLabFailureKind::ObservedHeaderTooLarge,
                    Some(StatusCode::CREATED.as_u16()),
                    metadata.clone(),
                    GitLabWriteFailureEffect::Ambiguous,
                    false,
                ));
            }
            retained.push(GitLabResponseHeader {
                name: name.as_str().as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            });
        }
    }
    Ok(retained)
}

fn content_type_allowed(value: &[u8], expected: ExpectedContent) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let mut parts = text.split(';');
    let media_type = parts.next().map(str::trim).unwrap_or_default();
    let media_allowed = match expected {
        ExpectedContent::Json => media_type.eq_ignore_ascii_case("application/json"),
        ExpectedContent::Raw => {
            media_type.eq_ignore_ascii_case("application/octet-stream")
                || media_type.eq_ignore_ascii_case("text/plain")
        }
    };
    if !media_allowed {
        return false;
    }
    let mut saw_charset = false;
    for parameter in parts {
        let parameter = parameter.trim();
        let Some((name, value)) = parameter.split_once('=') else {
            return false;
        };
        if saw_charset || !name.trim().eq_ignore_ascii_case("charset") {
            return false;
        }
        let value = value.trim().trim_matches('"');
        if !value.eq_ignore_ascii_case("utf-8") {
            return false;
        }
        saw_charset = true;
    }
    true
}

fn parse_content_length(
    headers: &HeaderMap,
    metadata: &GitLabResponseMetadata,
) -> Result<Option<usize>, GitLabTransportError> {
    let value = unique_header(headers, CONTENT_LENGTH).map_err(|()| {
        failure(
            GitLabFailureKind::MalformedContentLength,
            Some(StatusCode::OK.as_u16()),
            metadata.clone(),
            false,
        )
    })?;
    value
        .map(|value| {
            let bytes = value.as_bytes();
            if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                return Err(failure(
                    GitLabFailureKind::MalformedContentLength,
                    Some(StatusCode::OK.as_u16()),
                    metadata.clone(),
                    false,
                ));
            }
            let text = std::str::from_utf8(bytes).map_err(|_| {
                failure(
                    GitLabFailureKind::MalformedContentLength,
                    Some(StatusCode::OK.as_u16()),
                    metadata.clone(),
                    false,
                )
            })?;
            text.parse::<usize>().map_err(|_| {
                failure(
                    GitLabFailureKind::MalformedContentLength,
                    Some(StatusCode::OK.as_u16()),
                    metadata.clone(),
                    false,
                )
            })
        })
        .transpose()
}

fn unique_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&HeaderValue>, ()> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        Err(())
    } else {
        Ok(first)
    }
}

fn extract_metadata(headers: &HeaderMap) -> GitLabResponseMetadata {
    let (request_id, request_id_malformed) = safe_request_id(headers);
    let (limit, limit_bad) = strict_u64_header(headers, HeaderName::from_static("ratelimit-limit"));
    let (remaining, remaining_bad) =
        strict_u64_header(headers, HeaderName::from_static("ratelimit-remaining"));
    let (reset_epoch_seconds, reset_bad) =
        strict_u64_header(headers, HeaderName::from_static("ratelimit-reset"));
    let retry_after_value = parse_retry_after(headers, SystemTime::now());
    let retry_after_present = headers.contains_key(HeaderName::from_static("retry-after"));
    let retry_after_seconds = retry_after_value.map(|delay| {
        delay
            .as_secs()
            .saturating_add(u64::from(delay.subsec_nanos() > 0))
    });
    let retry_after_malformed = retry_after_present && retry_after_value.is_none();
    let retry_after_too_large =
        retry_after_seconds.is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS);
    GitLabResponseMetadata {
        request_id,
        request_id_malformed,
        rate_limit: GitLabRateLimitMetadata {
            limit,
            remaining,
            reset_epoch_seconds,
            malformed: limit_bad || remaining_bad || reset_bad,
        },
        retry_after_seconds: retry_after_seconds.filter(|value| *value <= MAX_RETRY_AFTER_SECONDS),
        retry_after_malformed: retry_after_malformed || retry_after_too_large,
    }
}

fn safe_request_id(headers: &HeaderMap) -> (Option<String>, bool) {
    let name = HeaderName::from_static("x-request-id");
    let Ok(value) = unique_header(headers, name) else {
        return (None, true);
    };
    let Some(value) = value else {
        return (None, false);
    };
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_REQUEST_ID_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return (None, true);
    }
    match std::str::from_utf8(bytes) {
        Ok(value) => (Some(value.to_owned()), false),
        Err(_) => (None, true),
    }
}

fn strict_u64_header(headers: &HeaderMap, name: HeaderName) -> (Option<u64>, bool) {
    let Ok(value) = unique_header(headers, name) else {
        return (None, true);
    };
    let Some(value) = value else {
        return (None, false);
    };
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return (None, true);
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return (None, true);
    };
    match text.parse::<u64>() {
        Ok(number) => (Some(number), false),
        Err(_) => (None, true),
    }
}

fn retain_wire_headers(
    headers: &HeaderMap,
    metadata: &GitLabResponseMetadata,
) -> Result<Vec<GitLabResponseHeader>, GitLabTransportError> {
    let mut retained = Vec::new();
    for (name, value) in headers {
        if observed_wire_header(name.as_str()) {
            if value.as_bytes().len() > HARD_MAX_OBSERVED_HEADER_BYTES {
                return Err(failure(
                    GitLabFailureKind::ObservedHeaderTooLarge,
                    Some(StatusCode::OK.as_u16()),
                    metadata.clone(),
                    false,
                ));
            }
            retained.push(GitLabResponseHeader {
                name: name.as_str().as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            });
        }
    }
    Ok(retained)
}

fn observed_wire_header(name: &str) -> bool {
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

fn classify_status(status: StatusCode, metadata: GitLabResponseMetadata) -> GitLabTransportError {
    let kind = match status {
        StatusCode::UNAUTHORIZED => GitLabFailureKind::Authentication,
        StatusCode::FORBIDDEN => GitLabFailureKind::Forbidden,
        StatusCode::NOT_FOUND => GitLabFailureKind::NotFound,
        StatusCode::CONFLICT => GitLabFailureKind::Conflict,
        StatusCode::REQUEST_TIMEOUT => GitLabFailureKind::RequestTimeout,
        StatusCode::TOO_MANY_REQUESTS => GitLabFailureKind::RateLimited,
        status if status.is_redirection() => GitLabFailureKind::RedirectDenied,
        status if status.is_server_error() => GitLabFailureKind::ServerUnavailable,
        _ => GitLabFailureKind::UnexpectedStatus,
    };
    let retryable = matches!(
        kind,
        GitLabFailureKind::RateLimited | GitLabFailureKind::RequestTimeout
    ) || matches!(kind, GitLabFailureKind::ServerUnavailable)
        && retryable_server_status(status.as_u16());
    failure(kind, Some(status.as_u16()), metadata, retryable)
}

fn classify_send_error(error: &reqwest::Error) -> GitLabTransportError {
    let kind = if error.is_timeout() && error.is_connect() {
        GitLabFailureKind::ConnectTimeout
    } else if error.is_timeout() {
        GitLabFailureKind::RequestTimeout
    } else if error.is_connect() {
        GitLabFailureKind::Connection
    } else {
        GitLabFailureKind::Protocol
    };
    let retryable = !matches!(kind, GitLabFailureKind::Protocol);
    failure(kind, None, GitLabResponseMetadata::default(), retryable)
}

fn classify_write_send_error(error: &reqwest::Error) -> GitLabWriteError {
    let read = classify_send_error(error);
    let no_effect = error.is_connect();
    write_failure(
        read.kind(),
        None,
        GitLabResponseMetadata::default(),
        if no_effect {
            GitLabWriteFailureEffect::NoEffect
        } else {
            GitLabWriteFailureEffect::Ambiguous
        },
        !matches!(read.kind(), GitLabFailureKind::Protocol),
    )
}

fn classify_body_error(
    error: &reqwest::Error,
    status: u16,
    metadata: GitLabResponseMetadata,
) -> GitLabTransportError {
    let kind = if error.is_timeout() {
        GitLabFailureKind::BodyTimeout
    } else if error.is_body() || error.is_connect() {
        GitLabFailureKind::Connection
    } else {
        GitLabFailureKind::Protocol
    };
    let retryable = !matches!(kind, GitLabFailureKind::Protocol);
    failure(kind, Some(status), metadata, retryable)
}

fn failure(
    kind: GitLabFailureKind,
    status: Option<u16>,
    metadata: GitLabResponseMetadata,
    retryable: bool,
) -> GitLabTransportError {
    GitLabTransportError {
        kind,
        status,
        retry: GitLabRetryMetadata {
            eligible_read: retryable,
            after_seconds: retryable.then_some(metadata.retry_after_seconds).flatten(),
        },
        metadata: Box::new(metadata),
    }
}

fn write_failure(
    kind: GitLabFailureKind,
    status: Option<u16>,
    metadata: GitLabResponseMetadata,
    effect: GitLabWriteFailureEffect,
    retryable_after_reconciliation: bool,
) -> GitLabWriteError {
    GitLabWriteError {
        kind,
        status,
        metadata,
        effect,
        retryable_after_reconciliation,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use revoot_core::{
        AllowedProviderOrigin, CanonicalHostname, CanonicalHttpsEndpoint, CanonicalHttpsOrigin,
        CertificateAuthorityMode, DnsAnswer, DnsObservation, DnsPolicy, EndpointPathRule,
        GitLabOriginPolicy, ProviderAdapterEgressPolicy, ProviderEgressDecision,
        ProviderEgressPolicy, ProviderProxyMode, ProviderRouteObservation, RepositoryPath,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    struct MockResponse {
        head: Vec<u8>,
        body: Vec<u8>,
        body_delay: Option<Duration>,
    }

    async fn serve_once(response: MockResponse) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind numeric-loopback mock server");
        let address = listener.local_addr().expect("read mock address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept mock request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while request.len() < 16 * 1024 && !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.expect("read mock request");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
            }
            stream
                .write_all(&response.head)
                .await
                .expect("write response head");
            if let Some(delay) = response.body_delay {
                tokio::time::sleep(delay).await;
            }
            let _ = stream.write_all(&response.body).await;
            request
        });
        (address, task)
    }

    async fn serve_sequence(
        responses: Vec<MockResponse>,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind numeric-loopback mock server");
        let address = listener.local_addr().expect("read mock address");
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.expect("accept mock request");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while request.len() < 16 * 1024
                    && !request.windows(4).any(|part| part == b"\r\n\r\n")
                {
                    let count = stream.read(&mut buffer).await.expect("read mock request");
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                }
                stream.write_all(&response.head).await.expect("write head");
                if let Some(delay) = response.body_delay {
                    tokio::time::sleep(delay).await;
                }
                let _ = stream.write_all(&response.body).await;
                requests.push(request);
            }
            requests
        });
        (address, task)
    }

    fn json_response(status: &str, extra_headers: &str, body: &[u8]) -> MockResponse {
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        MockResponse {
            head,
            body: body.to_vec(),
            body_delay: None,
        }
    }

    fn origin() -> GitLabOrigin {
        GitLabOrigin::parse(
            "https://gitlab.example.test",
            &GitLabOriginPolicy::default(),
        )
        .expect("valid test origin")
    }

    fn token() -> GitLabAccessToken {
        GitLabAccessToken::new(b"top-secret-token".to_vec()).expect("valid token")
    }

    fn write_token() -> GitLabWriteAccessToken {
        GitLabWriteAccessToken::new(b"write-only-secret".to_vec()).expect("valid write token")
    }

    fn config(limits: GitLabTransportLimits) -> GitLabTransportConfig {
        GitLabTransportConfig::new(origin(), GitLabCaMode::BundledWebPki, limits)
    }

    fn custom_authorization(sha256: [u8; 32]) -> AllowedProviderEgress {
        let allowed_origin = AllowedProviderOrigin::try_new(
            CanonicalHttpsOrigin::parse("https://gitlab.example.test")
                .expect("valid policy origin"),
            vec![EndpointPathRule::prefix(API_ROOT_PATH).expect("valid API root")],
        )
        .expect("valid allowed origin");
        let adapter = ProviderAdapterEgressPolicy::try_new(ADAPTER_ID, vec![allowed_origin])
            .expect("valid adapter");
        let policy = ProviderEgressPolicy::try_new(
            vec![adapter],
            ProviderProxyMode::Direct,
            CertificateAuthorityMode::CustomBundle { sha256 },
            DnsPolicy::default(),
            DnsPolicy::default(),
        )
        .expect("valid policy");
        let endpoint = CanonicalHttpsEndpoint::parse("https://gitlab.example.test/api/v4")
            .expect("valid endpoint");
        let route = ProviderRouteObservation::Direct {
            upstream_dns: DnsObservation::new(
                CanonicalHostname::parse("gitlab.example.test").expect("valid hostname"),
                vec![DnsAnswer {
                    address: "1.1.1.1".parse().expect("valid public address"),
                    ttl_seconds: 60,
                }],
            ),
        };
        match policy.authorize(ADAPTER_ID, &endpoint, &route) {
            ProviderEgressDecision::Allowed(authorization) => authorization,
            ProviderEgressDecision::Denied(denial) => {
                panic!("test authorization unexpectedly denied: {denial:?}")
            }
        }
    }

    #[tokio::test]
    async fn sends_only_get_with_pinned_path_and_sensitive_headers() {
        let (address, server) = serve_once(json_response(
            "200 OK",
            "X-Request-Id: request-123\r\n",
            br#"{"ok":true}"#,
        ))
        .await;
        let client = GitLabReadClient::new_for_loopback(
            &config(GitLabTransportLimits::default()),
            token(),
            address,
        )
        .expect("build test client");
        let response = client
            .get(&GitLabReadEndpoint::MergeRequest {
                project_id: ProjectId::try_from(42).expect("positive id"),
                merge_request_iid: MergeRequestIid::try_from(7).expect("positive iid"),
            })
            .await
            .expect("successful response");
        assert_eq!(response.observation().body, br#"{"ok":true}"#);
        assert_eq!(
            response.metadata().request_id.as_deref(),
            Some("request-123")
        );

        let request = server.await.expect("mock task");
        let request = String::from_utf8(request).expect("ASCII request");
        assert!(request.starts_with("GET /api/v4/projects/42/merge_requests/7 HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("host: gitlab.example.test\r\n")
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("private-token: top-secret-token\r\n")
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("accept-encoding: identity\r\n")
        );
    }

    #[tokio::test]
    async fn sends_job_and_bearer_auth_using_their_exact_schemes() {
        for (token, expected_header) in [
            (
                GitLabAccessToken::job_token(b"ci-job-secret".to_vec()).unwrap(),
                "job-token: ci-job-secret\r\n",
            ),
            (
                GitLabAccessToken::bearer(b"oauth-secret".to_vec()).unwrap(),
                "authorization: Bearer oauth-secret\r\n",
            ),
        ] {
            let (address, server) = serve_once(json_response("200 OK", "", br#"{"id":1}"#)).await;
            let client = GitLabReadClient::new_for_loopback(
                &config(GitLabTransportLimits::default()),
                token,
                address,
            )
            .unwrap();
            client.get(&GitLabReadEndpoint::CurrentUser).await.unwrap();
            let request = String::from_utf8(server.await.unwrap()).unwrap();
            assert!(request.contains(expected_header));
            assert!(!request.to_ascii_lowercase().contains("private-token:"));
        }
    }

    #[tokio::test]
    async fn percent_encodes_repository_path_and_binds_immutable_ref() {
        let (address, server) = serve_once(json_response("200 OK", "", b"{}")).await;
        let client = GitLabReadClient::new_for_loopback(
            &config(GitLabTransportLimits::default()),
            token(),
            address,
        )
        .expect("build test client");
        let endpoint = GitLabReadEndpoint::RawRepositoryFile {
            project_id: ProjectId::try_from(9).expect("positive id"),
            file_path: RepositoryPath::try_from("src/a b.rs".to_owned()).expect("valid path"),
            revision: GitSha::try_from("a".repeat(40)).expect("valid sha"),
        };
        let error = client
            .get(&endpoint)
            .await
            .expect_err("JSON is invalid raw content type");
        assert_eq!(error.kind(), GitLabFailureKind::UnsupportedContentType);
        let request = String::from_utf8(server.await.expect("mock task")).expect("ASCII request");
        assert!(request.starts_with(
            "GET /api/v4/projects/9/repository/files/src%2Fa%20b.rs/raw?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n"
        ));
    }

    #[tokio::test]
    async fn project_path_lookup_is_one_percent_encoded_segment() {
        let (address, server) = serve_once(json_response(
            "200 OK",
            "",
            br#"{"id":9,"path_with_namespace":"group/project"}"#,
        ))
        .await;
        let client = GitLabReadClient::new_for_loopback(
            &config(GitLabTransportLimits::default()),
            token(),
            address,
        )
        .expect("build test client");
        client
            .get(&GitLabReadEndpoint::ProjectByPath {
                project_path: revoot_core::GitLabProjectPath::try_from("group/project".to_owned())
                    .expect("project path"),
            })
            .await
            .expect("project response");
        let request = String::from_utf8(server.await.expect("mock task")).expect("ASCII request");
        assert!(request.starts_with("GET /api/v4/projects/group%2Fproject HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn does_not_follow_redirects_or_retain_location() {
        let response = MockResponse {
            head: b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/credential-sink\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            body: Vec::new(),
            body_delay: None,
        };
        let (address, server) = serve_once(response).await;
        let client = GitLabReadClient::new_for_loopback(
            &config(GitLabTransportLimits::default()),
            token(),
            address,
        )
        .expect("build test client");
        let error = client
            .get(&GitLabReadEndpoint::CurrentUser)
            .await
            .expect_err("redirect must be returned, not followed");
        assert_eq!(error.kind(), GitLabFailureKind::RedirectDenied);
        assert_eq!(error.status(), Some(302));
        assert!(!format!("{error:?}").contains("credential-sink"));
        let request = server.await.expect("mock task");
        assert!(!request.is_empty());
    }

    #[tokio::test]
    async fn classifies_rate_limit_without_replaying() {
        let (address, server) = serve_once(json_response(
            "429 Too Many Requests",
            "Retry-After: 17\r\nRateLimit-Limit: 100\r\nRateLimit-Remaining: 0\r\nRateLimit-Reset: 123456\r\nX-Request-Id: rate-1\r\n",
            b"{}",
        ))
        .await;
        let client = GitLabReadClient::new_for_loopback(
            &config(GitLabTransportLimits::default()),
            token(),
            address,
        )
        .expect("build test client");
        let error = client
            .get(&GitLabReadEndpoint::CurrentUser)
            .await
            .expect_err("rate limit is a classified failure");
        assert_eq!(error.kind(), GitLabFailureKind::RateLimited);
        assert_eq!(error.retry().after_seconds, Some(17));
        assert!(error.retry().eligible_read);
        assert_eq!(error.metadata().rate_limit.remaining, Some(0));
        assert_eq!(error.metadata().request_id.as_deref(), Some("rate-1"));
        let request = server.await.expect("single request");
        assert_eq!(
            request.windows(4).filter(|part| *part == b"GET ").count(),
            1
        );
    }

    #[tokio::test]
    async fn standalone_safe_read_retries_without_nesting_transport_attempts() {
        let (address, server) = serve_sequence(vec![
            json_response("503 Service Unavailable", "Retry-After: 0\r\n", b"{}"),
            json_response("200 OK", "", br#"{"id":7}"#),
        ])
        .await;
        let client = GitLabReadClient::new_for_loopback(
            &config(GitLabTransportLimits::default()),
            token(),
            address,
        )
        .expect("build test client");
        let response = client
            .get_with_retry(&GitLabReadEndpoint::CurrentUser)
            .await
            .expect("transient read succeeds");
        assert_eq!(response.observation().status, 200);
        let requests = server.await.expect("mock task");
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.starts_with(b"GET ")));
    }

    #[tokio::test]
    async fn rejects_encoded_and_oversized_bodies_before_retention() {
        let response = MockResponse {
            head: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\n".to_vec(),
            body: b"nope".to_vec(),
            body_delay: None,
        };
        let (address, server) = serve_once(response).await;
        let client = GitLabReadClient::new_for_loopback(
            &config(GitLabTransportLimits::default()),
            token(),
            address,
        )
        .expect("build test client");
        let error = client
            .get(&GitLabReadEndpoint::CurrentUser)
            .await
            .expect_err("compressed response is forbidden");
        assert_eq!(error.kind(), GitLabFailureKind::UnsupportedContentEncoding);
        server.await.expect("mock task");

        let limits = GitLabTransportLimits::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            3,
        )
        .expect("valid limits");
        let (address, server) = serve_once(json_response("200 OK", "", b"1234")).await;
        let client = GitLabReadClient::new_for_loopback(&config(limits), token(), address)
            .expect("build test client");
        let error = client
            .get(&GitLabReadEndpoint::CurrentUser)
            .await
            .expect_err("declared body exceeds cap");
        assert_eq!(error.kind(), GitLabFailureKind::BodyTooLarge);
        server.await.expect("mock task");
    }

    #[tokio::test]
    async fn enforces_body_idle_timeout() {
        let response = MockResponse {
            head: b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n".to_vec(),
            body: b"{}".to_vec(),
            body_delay: Some(Duration::from_millis(250)),
        };
        let (address, server) = serve_once(response).await;
        let limits = GitLabTransportLimits::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_millis(50),
            Duration::from_secs(1),
            32,
        )
        .expect("valid limits");
        let client = GitLabReadClient::new_for_loopback(&config(limits), token(), address)
            .expect("build test client");
        let error = client
            .get(&GitLabReadEndpoint::CurrentUser)
            .await
            .expect_err("idle body read must time out");
        assert_eq!(error.kind(), GitLabFailureKind::BodyTimeout);
        assert!(error.retry().eligible_read);
        server.await.expect("mock task");
    }

    #[test]
    fn credentials_and_sensitive_endpoint_values_are_redacted() {
        let token =
            GitLabAccessToken::new(b"never-print-this-token".to_vec()).expect("valid token");
        assert_eq!(format!("{token:?}"), "GitLabAccessToken(<redacted>)");
        let header = token.header_value().expect("valid sensitive header");
        assert!(!format!("{header:?}").contains("never-print"));
        let endpoint = GitLabReadEndpoint::RawRepositoryFile {
            project_id: ProjectId::try_from(1).expect("positive id"),
            file_path: RepositoryPath::try_from("private/secret.txt".to_owned())
                .expect("valid path"),
            revision: GitSha::try_from("b".repeat(40)).expect("valid sha"),
        };
        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("private"));
        assert!(!debug.contains(&"b".repeat(40)));
    }

    #[test]
    fn request_timeout_status_is_a_retryable_safe_read() {
        let error = classify_status(
            StatusCode::REQUEST_TIMEOUT,
            GitLabResponseMetadata::default(),
        );
        assert_eq!(error.kind(), GitLabFailureKind::RequestTimeout);
        assert_eq!(error.status(), Some(408));
        assert!(error.retry().eligible_read);
    }

    #[test]
    fn pagination_and_custom_ca_identity_are_bounded() {
        assert_eq!(
            GitLabPagination::new(0, 100),
            Err(GitLabEndpointError::InvalidPagination)
        );
        assert_eq!(
            GitLabPagination::new(1, 101),
            Err(GitLabEndpointError::InvalidPagination)
        );
        let certificate = vec![1_u8, 2, 3];
        assert_eq!(
            GitLabCustomCaBundle::from_der(vec![certificate], [0_u8; 32])
                .expect_err("digest mismatch"),
            GitLabClientBuildError::CustomCaIdentityMismatch
        );
    }

    #[test]
    fn custom_ca_must_match_exact_egress_authorization_digest() {
        let certificate = vec![1_u8, 2, 3];
        let mut hasher = Sha256::new();
        hasher.update(3_u64.to_be_bytes());
        hasher.update(&certificate);
        let digest: [u8; 32] = hasher.finalize().into();
        let bundle = GitLabCustomCaBundle::from_der(vec![certificate], digest)
            .expect("identity-bound test bundle");
        let config = GitLabTransportConfig::new(
            origin(),
            GitLabCaMode::CustomBundle(bundle),
            GitLabTransportLimits::default(),
        );

        assert_eq!(
            validate_authorization(&config, &custom_authorization([9_u8; 32])),
            Err(GitLabClientBuildError::CustomCaIdentityMismatch)
        );
        assert_eq!(
            validate_authorization(&config, &custom_authorization(digest)),
            Ok(())
        );
    }

    #[tokio::test]
    async fn write_statuses_are_conservatively_classified() {
        for (status, expected_kind, retryable) in [
            ("200 OK", GitLabFailureKind::UnexpectedStatus, false),
            ("202 Accepted", GitLabFailureKind::UnexpectedStatus, false),
            ("204 No Content", GitLabFailureKind::UnexpectedStatus, false),
            ("302 Found", GitLabFailureKind::RedirectDenied, false),
            (
                "503 Service Unavailable",
                GitLabFailureKind::ServerUnavailable,
                true,
            ),
            (
                "408 Request Timeout",
                GitLabFailureKind::RequestTimeout,
                true,
            ),
            (
                "501 Not Implemented",
                GitLabFailureKind::ServerUnavailable,
                false,
            ),
        ] {
            let (address, server) = serve_once(json_response(status, "", b"{}")).await;
            let client = GitLabWriteClient::new_for_loopback(
                &config(GitLabTransportLimits::default()),
                write_token(),
                address,
            )
            .expect("build write client");
            let error = client
                .mutate(&GitLabWriteEndpoint::SummaryNote {
                    project_id: ProjectId::try_from(1).expect("project"),
                    merge_request_iid: MergeRequestIid::try_from(2).expect("iid"),
                    body: "summary",
                })
                .await
                .expect_err("non-201 must not be accepted");
            assert_eq!(error.kind, expected_kind);
            assert_eq!(error.effect, GitLabWriteFailureEffect::Ambiguous);
            assert_eq!(error.retryable_after_reconciliation, retryable);
            let request = server.await.expect("mock server");
            assert!(
                request.starts_with(b"POST /api/v4/projects/1/merge_requests/2/notes HTTP/1.1\r\n")
            );
        }
    }

    #[test]
    fn write_credentials_are_separately_redacted() {
        let token = write_token();
        assert_eq!(format!("{token:?}"), "GitLabWriteAccessToken(<redacted>)");
        assert!(!format!("{:?}", token.header_value().expect("header")).contains("write-only"));
    }
}
