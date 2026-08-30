//! Canonical GitLab identity and untrusted CI-context contracts.
//!
//! This module performs no environment access, network I/O, credential access,
//! or URL resolution. Callers pass environment entries explicitly. CI-derived
//! values remain hints until they match a separately supplied authoritative
//! merge-request observation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::{GitSha, MergeRequestIid, ProjectId};

const HTTPS_PREFIX: &str = "https://";
const DEFAULT_HTTPS_PORT: u16 = 443;
const MAX_HOST_BYTES: usize = 253;
const MAX_HOST_LABEL_BYTES: usize = 63;
const MAX_PROJECT_PATH_BYTES: usize = 1_024;
const MAX_PROJECT_PATH_COMPONENT_BYTES: usize = 255;
const MAX_PROJECT_PATH_COMPONENTS: usize = 20;
const MAX_REF_BYTES: usize = 1_024;
const MAX_REF_COMPONENT_BYTES: usize = 255;

/// Trusted policy for explicitly supported non-default GitLab HTTPS ports.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitLabOriginPolicy {
    supported_non_default_ports: BTreeSet<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitLabOriginPolicyError {
    ZeroPort,
    DefaultPort,
}

impl GitLabOriginPolicy {
    /// Construct a normalized allowlist of explicitly supported non-default
    /// HTTPS ports.
    ///
    /// # Errors
    ///
    /// Returns an error when zero or the implicit default HTTPS port is listed.
    pub fn new(ports: impl IntoIterator<Item = u16>) -> Result<Self, GitLabOriginPolicyError> {
        let mut supported_non_default_ports = BTreeSet::new();
        for port in ports {
            if port == 0 {
                return Err(GitLabOriginPolicyError::ZeroPort);
            }
            if port == DEFAULT_HTTPS_PORT {
                return Err(GitLabOriginPolicyError::DefaultPort);
            }
            supported_non_default_ports.insert(port);
        }
        Ok(Self {
            supported_non_default_ports,
        })
    }

    #[must_use]
    pub fn supports(&self, port: u16) -> bool {
        port == DEFAULT_HTTPS_PORT || self.supported_non_default_ports.contains(&port)
    }
}

/// Canonical HTTPS origin with no path, userinfo, query, or fragment.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitLabOrigin {
    canonical: String,
    host: String,
    non_default_port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "error", content = "port", rename_all = "snake_case")]
pub enum GitLabOriginError {
    Scheme,
    UserInfo,
    Path,
    Query,
    Fragment,
    Host,
    Port,
    UnsupportedPort(u16),
}

impl GitLabOrigin {
    /// Parse and canonicalize an HTTPS origin under trusted port policy.
    /// Hostnames are lowercased, IP literals are normalized, one trailing slash
    /// is removed, and an explicit `:443` is omitted.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-HTTPS scheme, URL components beyond the
    /// authority, malformed or ambiguous hosts/ports, or a non-default port not
    /// explicitly supported by policy.
    pub fn parse(value: &str, policy: &GitLabOriginPolicy) -> Result<Self, GitLabOriginError> {
        let Some(authority) = value.strip_prefix(HTTPS_PREFIX) else {
            return Err(GitLabOriginError::Scheme);
        };
        if authority.contains('@') {
            return Err(GitLabOriginError::UserInfo);
        }
        if authority.contains('?') {
            return Err(GitLabOriginError::Query);
        }
        if authority.contains('#') {
            return Err(GitLabOriginError::Fragment);
        }
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.contains('/') {
            return Err(GitLabOriginError::Path);
        }

        let (host, port) = parse_authority(authority)?;
        if !policy.supports(port) {
            return Err(GitLabOriginError::UnsupportedPort(port));
        }
        let non_default_port = (port != DEFAULT_HTTPS_PORT).then_some(port);
        let canonical = non_default_port.map_or_else(
            || format!("{HTTPS_PREFIX}{host}"),
            |port| format!("{HTTPS_PREFIX}{host}:{port}"),
        );
        Ok(Self {
            canonical,
            host,
            non_default_port,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        match self.non_default_port {
            Some(port) => port,
            None => DEFAULT_HTTPS_PORT,
        }
    }

    #[must_use]
    pub const fn non_default_port(&self) -> Option<u16> {
        self.non_default_port
    }
}

impl fmt::Debug for GitLabOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("GitLabOrigin")
            .field(&self.canonical)
            .finish()
    }
}

impl fmt::Display for GitLabOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical)
    }
}

impl Serialize for GitLabOrigin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.canonical)
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16), GitLabOriginError> {
    if authority.is_empty() {
        return Err(GitLabOriginError::Host);
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return Err(GitLabOriginError::Host);
        };
        let (literal, suffix_with_bracket) = bracketed.split_at(close);
        let address = literal
            .parse::<Ipv6Addr>()
            .map_err(|_| GitLabOriginError::Host)?;
        let suffix = suffix_with_bracket
            .strip_prefix(']')
            .ok_or(GitLabOriginError::Host)?;
        let port = parse_port_suffix(suffix)?;
        return Ok((format!("[{address}]"), port));
    }
    if authority.contains('[') || authority.contains(']') || authority.matches(':').count() > 1 {
        return Err(GitLabOriginError::Host);
    }
    let (raw_host, port) = match authority.rsplit_once(':') {
        Some((host, raw_port)) => (host, parse_port(raw_port)?),
        None => (authority, DEFAULT_HTTPS_PORT),
    };
    Ok((canonical_host(raw_host)?, port))
}

fn parse_port_suffix(suffix: &str) -> Result<u16, GitLabOriginError> {
    if suffix.is_empty() {
        return Ok(DEFAULT_HTTPS_PORT);
    }
    let raw_port = suffix.strip_prefix(':').ok_or(GitLabOriginError::Port)?;
    parse_port(raw_port)
}

fn parse_port(raw_port: &str) -> Result<u16, GitLabOriginError> {
    if raw_port.is_empty()
        || !raw_port.bytes().all(|byte| byte.is_ascii_digit())
        || (raw_port.len() > 1 && raw_port.starts_with('0'))
    {
        return Err(GitLabOriginError::Port);
    }
    let port = raw_port
        .parse::<u16>()
        .map_err(|_| GitLabOriginError::Port)?;
    if port == 0 {
        return Err(GitLabOriginError::Port);
    }
    Ok(port)
}

fn canonical_host(raw_host: &str) -> Result<String, GitLabOriginError> {
    if raw_host.is_empty()
        || raw_host.len() > MAX_HOST_BYTES
        || !raw_host.is_ascii()
        || raw_host.ends_with('.')
        || raw_host.contains('%')
    {
        return Err(GitLabOriginError::Host);
    }
    if raw_host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return raw_host
            .parse::<Ipv4Addr>()
            .map(|address| address.to_string())
            .map_err(|_| GitLabOriginError::Host);
    }
    for label in raw_host.split('.') {
        if label.is_empty()
            || label.len() > MAX_HOST_LABEL_BYTES
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(GitLabOriginError::Host);
        }
    }
    Ok(raw_host.to_ascii_lowercase())
}

/// Exact GitLab namespace/project path under the supported ASCII subset.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitLabProjectPath(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitLabProjectPathError {
    Empty,
    Length,
    Depth,
    Component,
    Character,
}

impl fmt::Display for GitLabProjectPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "project path is empty",
            Self::Length => "project path exceeds the supported length",
            Self::Depth => "project path has an unsupported namespace depth",
            Self::Component => "project path contains an invalid component",
            Self::Character => "project path contains an unsupported character",
        })
    }
}

impl GitLabProjectPath {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GitLabProjectPath {
    type Error = GitLabProjectPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(GitLabProjectPathError::Empty);
        }
        if value.len() > MAX_PROJECT_PATH_BYTES {
            return Err(GitLabProjectPathError::Length);
        }
        let components = value.split('/').collect::<Vec<_>>();
        if components.len() < 2 || components.len() > MAX_PROJECT_PATH_COMPONENTS {
            return Err(GitLabProjectPathError::Depth);
        }
        for component in components {
            if component.is_empty()
                || component.len() > MAX_PROJECT_PATH_COMPONENT_BYTES
                || matches!(component, "." | "..")
            {
                return Err(GitLabProjectPathError::Component);
            }
            if !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(GitLabProjectPathError::Character);
            }
        }
        Ok(Self(value))
    }
}

impl From<GitLabProjectPath> for String {
    fn from(value: GitLabProjectPath) -> Self {
        value.0
    }
}

/// Bounded branch/ref name using a deliberately narrow Git-compatible subset.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitRefName(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitRefNameError {
    Empty,
    Length,
    Component,
    Character,
    Ambiguous,
}

impl fmt::Display for GitRefNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "ref name is empty",
            Self::Length => "ref name exceeds the supported length",
            Self::Component => "ref name contains an invalid component",
            Self::Character => "ref name contains an unsupported character",
            Self::Ambiguous => "ref name contains an ambiguous sequence",
        })
    }
}

impl GitRefName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GitRefName {
    type Error = GitRefNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(GitRefNameError::Empty);
        }
        if value.len() > MAX_REF_BYTES {
            return Err(GitRefNameError::Length);
        }
        if value.starts_with('/')
            || value.starts_with('-')
            || value.ends_with('/')
            || value.ends_with('.')
            || value.contains("//")
            || value.contains("..")
            || value.contains("@{")
        {
            return Err(GitRefNameError::Ambiguous);
        }
        for component in value.split('/') {
            if component.is_empty()
                || component.len() > MAX_REF_COMPONENT_BYTES
                || component.starts_with('.')
                || component
                    .get(component.len().saturating_sub(5)..)
                    .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".lock"))
            {
                return Err(GitRefNameError::Component);
            }
            if !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(GitRefNameError::Character);
            }
        }
        Ok(Self(value))
    }
}

impl From<GitRefName> for String {
    fn from(value: GitRefName) -> Self {
        value.0
    }
}

/// Numeric and path identity for one GitLab project.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitLabProjectIdentity {
    pub id: ProjectId,
    pub path: GitLabProjectPath,
}

/// The only CI variables examined by [`classify_gitlab_ci_environment`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitLabCiField {
    ServerUrl,
    PipelineSource,
    PipelineProjectId,
    PipelineProjectPath,
    MergeRequestProjectId,
    MergeRequestProjectPath,
    MergeRequestIid,
    MergeRequestSourceProjectId,
    MergeRequestSourceProjectPath,
    MergeRequestSourceBranch,
    MergeRequestTargetBranch,
    MergeRequestEventType,
    CommitSha,
    MergeRequestSourceBranchSha,
}

impl GitLabCiField {
    #[must_use]
    pub const fn environment_name(self) -> &'static str {
        match self {
            Self::ServerUrl => "CI_SERVER_URL",
            Self::PipelineSource => "CI_PIPELINE_SOURCE",
            Self::PipelineProjectId => "CI_PROJECT_ID",
            Self::PipelineProjectPath => "CI_PROJECT_PATH",
            Self::MergeRequestProjectId => "CI_MERGE_REQUEST_PROJECT_ID",
            Self::MergeRequestProjectPath => "CI_MERGE_REQUEST_PROJECT_PATH",
            Self::MergeRequestIid => "CI_MERGE_REQUEST_IID",
            Self::MergeRequestSourceProjectId => "CI_MERGE_REQUEST_SOURCE_PROJECT_ID",
            Self::MergeRequestSourceProjectPath => "CI_MERGE_REQUEST_SOURCE_PROJECT_PATH",
            Self::MergeRequestSourceBranch => "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
            Self::MergeRequestTargetBranch => "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
            Self::MergeRequestEventType => "CI_MERGE_REQUEST_EVENT_TYPE",
            Self::CommitSha => "CI_COMMIT_SHA",
            Self::MergeRequestSourceBranchSha => "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA",
        }
    }
}

const REQUIRED_CI_FIELDS: [GitLabCiField; 13] = [
    GitLabCiField::ServerUrl,
    GitLabCiField::PipelineSource,
    GitLabCiField::PipelineProjectId,
    GitLabCiField::PipelineProjectPath,
    GitLabCiField::MergeRequestProjectId,
    GitLabCiField::MergeRequestProjectPath,
    GitLabCiField::MergeRequestIid,
    GitLabCiField::MergeRequestSourceProjectId,
    GitLabCiField::MergeRequestSourceProjectPath,
    GitLabCiField::MergeRequestSourceBranch,
    GitLabCiField::MergeRequestTargetBranch,
    GitLabCiField::MergeRequestEventType,
    GitLabCiField::CommitSha,
];

fn ci_field(name: &str) -> Option<GitLabCiField> {
    REQUIRED_CI_FIELDS
        .into_iter()
        .chain([GitLabCiField::MergeRequestSourceBranchSha])
        .find(|field| field.environment_name() == name)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "reason", content = "field", rename_all = "snake_case")]
pub enum GitLabCiAmbiguity {
    DuplicateVariable(GitLabCiField),
    InvalidValue(GitLabCiField),
    UnsupportedPipelineSource,
    UnsupportedMergeRequestEventType,
    ConflictingHeadSha,
    InconsistentProjectIdentity,
    UnrelatedPipelineProject,
}

/// Typed but untrusted merge-request context derived only from allowlisted CI
/// variables.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedGitLabCiHint {
    pub origin: GitLabOrigin,
    pub pipeline_project: GitLabProjectIdentity,
    pub target_project: GitLabProjectIdentity,
    pub source_project: GitLabProjectIdentity,
    pub merge_request_iid: MergeRequestIid,
    pub source_ref: GitRefName,
    pub target_ref: GitRefName,
    pub head_sha: GitSha,
}

impl UntrustedGitLabCiHint {
    #[must_use]
    pub fn is_fork(&self) -> bool {
        self.source_project != self.target_project
    }
}

/// Deterministic classification of an untrusted CI environment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "classification", content = "details", rename_all = "snake_case")]
pub enum GitLabCiContext {
    Ready(UntrustedGitLabCiHint),
    Missing {
        fields: BTreeSet<GitLabCiField>,
    },
    Ambiguous {
        reasons: BTreeSet<GitLabCiAmbiguity>,
    },
    ForkMismatch {
        hint: UntrustedGitLabCiHint,
    },
}

impl GitLabCiContext {
    #[must_use]
    pub const fn hint(&self) -> Option<&UntrustedGitLabCiHint> {
        match self {
            Self::Ready(hint) | Self::ForkMismatch { hint } => Some(hint),
            Self::Missing { .. } | Self::Ambiguous { .. } => None,
        }
    }
}

/// Parse only an explicit allowlist of GitLab predefined CI variables.
/// Unknown entries—including secret/token variables—are ignored and never
/// retained in the result. Duplicate allowlisted names are ambiguous even when
/// their values are identical.
#[must_use]
pub fn classify_gitlab_ci_environment(
    variables: impl IntoIterator<Item = (String, String)>,
    origin_policy: &GitLabOriginPolicy,
) -> GitLabCiContext {
    let (selected, mut reasons) = collect_ci_variables(variables);
    let missing = missing_ci_fields(&selected);
    let projects = parse_ci_projects(&selected, &mut reasons);
    let review = parse_ci_review(&selected, origin_policy, &mut reasons);
    validate_ci_execution(&selected, review.head_sha.as_ref(), &mut reasons);

    if !reasons.is_empty() {
        return GitLabCiContext::Ambiguous { reasons };
    }
    if !missing.is_empty() {
        return GitLabCiContext::Missing { fields: missing };
    }
    let Some(hint) = assemble_ci_hint(projects, review) else {
        return GitLabCiContext::Ambiguous {
            reasons: BTreeSet::from([GitLabCiAmbiguity::InconsistentProjectIdentity]),
        };
    };
    classify_project_relationship(hint)
}

fn collect_ci_variables(
    variables: impl IntoIterator<Item = (String, String)>,
) -> (BTreeMap<GitLabCiField, String>, BTreeSet<GitLabCiAmbiguity>) {
    let mut selected = BTreeMap::new();
    let mut reasons = BTreeSet::new();
    for (name, value) in variables {
        let Some(field) = ci_field(&name) else {
            continue;
        };
        if selected.insert(field, value).is_some() {
            reasons.insert(GitLabCiAmbiguity::DuplicateVariable(field));
        }
    }
    (selected, reasons)
}

fn missing_ci_fields(selected: &BTreeMap<GitLabCiField, String>) -> BTreeSet<GitLabCiField> {
    REQUIRED_CI_FIELDS
        .into_iter()
        .filter(|field| selected.get(field).is_none_or(String::is_empty))
        .collect()
}

struct ParsedCiProjects {
    pipeline_id: Option<ProjectId>,
    pipeline_path: Option<GitLabProjectPath>,
    target_id: Option<ProjectId>,
    target_path: Option<GitLabProjectPath>,
    source_id: Option<ProjectId>,
    source_path: Option<GitLabProjectPath>,
}

fn parse_ci_projects(
    selected: &BTreeMap<GitLabCiField, String>,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
) -> ParsedCiProjects {
    ParsedCiProjects {
        pipeline_id: parse_ci_positive_id(selected, GitLabCiField::PipelineProjectId, reasons),
        pipeline_path: parse_ci_project_path(selected, GitLabCiField::PipelineProjectPath, reasons),
        target_id: parse_ci_positive_id(selected, GitLabCiField::MergeRequestProjectId, reasons),
        target_path: parse_ci_project_path(
            selected,
            GitLabCiField::MergeRequestProjectPath,
            reasons,
        ),
        source_id: parse_ci_positive_id(
            selected,
            GitLabCiField::MergeRequestSourceProjectId,
            reasons,
        ),
        source_path: parse_ci_project_path(
            selected,
            GitLabCiField::MergeRequestSourceProjectPath,
            reasons,
        ),
    }
}

struct ParsedCiReview {
    origin: Option<GitLabOrigin>,
    merge_request_iid: Option<MergeRequestIid>,
    source_ref: Option<GitRefName>,
    target_ref: Option<GitRefName>,
    head_sha: Option<GitSha>,
}

fn parse_ci_review(
    selected: &BTreeMap<GitLabCiField, String>,
    origin_policy: &GitLabOriginPolicy,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
) -> ParsedCiReview {
    let origin = parse_ci_value(selected, GitLabCiField::ServerUrl, reasons, |value| {
        GitLabOrigin::parse(value, origin_policy)
    });
    let merge_request_iid =
        parse_ci_positive_number(selected, GitLabCiField::MergeRequestIid, reasons)
            .and_then(|value| MergeRequestIid::try_from(value).ok());
    let source_ref = parse_ci_ref(selected, GitLabCiField::MergeRequestSourceBranch, reasons);
    let target_ref = parse_ci_ref(selected, GitLabCiField::MergeRequestTargetBranch, reasons);
    let head_sha = parse_ci_value(selected, GitLabCiField::CommitSha, reasons, |value| {
        GitSha::try_from(value.to_owned())
    });
    ParsedCiReview {
        origin,
        merge_request_iid,
        source_ref,
        target_ref,
        head_sha,
    }
}

fn validate_ci_execution(
    selected: &BTreeMap<GitLabCiField, String>,
    head_sha: Option<&GitSha>,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
) {
    if selected
        .get(&GitLabCiField::PipelineSource)
        .is_some_and(|value| !value.is_empty() && value != "merge_request_event")
    {
        reasons.insert(GitLabCiAmbiguity::UnsupportedPipelineSource);
    }
    if selected
        .get(&GitLabCiField::MergeRequestEventType)
        .is_some_and(|value| !value.is_empty() && value != "detached")
    {
        reasons.insert(GitLabCiAmbiguity::UnsupportedMergeRequestEventType);
    }
    if let Some(source_sha) = parse_optional_ci_value(
        selected,
        GitLabCiField::MergeRequestSourceBranchSha,
        reasons,
        |value| GitSha::try_from(value.to_owned()),
    ) && head_sha.is_some_and(|head| head != &source_sha)
    {
        reasons.insert(GitLabCiAmbiguity::ConflictingHeadSha);
    }
}

fn assemble_ci_hint(
    projects: ParsedCiProjects,
    review: ParsedCiReview,
) -> Option<UntrustedGitLabCiHint> {
    Some(UntrustedGitLabCiHint {
        origin: review.origin?,
        pipeline_project: GitLabProjectIdentity {
            id: projects.pipeline_id?,
            path: projects.pipeline_path?,
        },
        target_project: GitLabProjectIdentity {
            id: projects.target_id?,
            path: projects.target_path?,
        },
        source_project: GitLabProjectIdentity {
            id: projects.source_id?,
            path: projects.source_path?,
        },
        merge_request_iid: review.merge_request_iid?,
        source_ref: review.source_ref?,
        target_ref: review.target_ref?,
        head_sha: review.head_sha?,
    })
}

fn classify_project_relationship(hint: UntrustedGitLabCiHint) -> GitLabCiContext {
    let pipeline_is_target = identity_matches(&hint.pipeline_project, &hint.target_project);
    let pipeline_is_source = identity_matches(&hint.pipeline_project, &hint.source_project);
    let source_is_target = identity_matches(&hint.source_project, &hint.target_project);
    if !(identities_consistent(&hint.pipeline_project, &hint.target_project)
        && identities_consistent(&hint.pipeline_project, &hint.source_project)
        && identities_consistent(&hint.source_project, &hint.target_project))
    {
        return GitLabCiContext::Ambiguous {
            reasons: BTreeSet::from([GitLabCiAmbiguity::InconsistentProjectIdentity]),
        };
    }
    if !pipeline_is_target && !pipeline_is_source {
        return GitLabCiContext::Ambiguous {
            reasons: BTreeSet::from([GitLabCiAmbiguity::UnrelatedPipelineProject]),
        };
    }
    if !source_is_target {
        return GitLabCiContext::ForkMismatch { hint };
    }
    GitLabCiContext::Ready(hint)
}

fn parse_ci_project_path(
    selected: &BTreeMap<GitLabCiField, String>,
    field: GitLabCiField,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
) -> Option<GitLabProjectPath> {
    parse_ci_value(selected, field, reasons, |value| {
        GitLabProjectPath::try_from(value.to_owned())
    })
}

fn parse_ci_ref(
    selected: &BTreeMap<GitLabCiField, String>,
    field: GitLabCiField,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
) -> Option<GitRefName> {
    parse_ci_value(selected, field, reasons, |value| {
        GitRefName::try_from(value.to_owned())
    })
}

fn parse_ci_positive_id(
    selected: &BTreeMap<GitLabCiField, String>,
    field: GitLabCiField,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
) -> Option<ProjectId> {
    parse_ci_positive_number(selected, field, reasons).and_then(|id| ProjectId::try_from(id).ok())
}

fn parse_ci_positive_number(
    selected: &BTreeMap<GitLabCiField, String>,
    field: GitLabCiField,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
) -> Option<u64> {
    parse_ci_value(selected, field, reasons, |value| {
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value.starts_with('0')
        {
            return Err(());
        }
        value
            .parse::<u64>()
            .map_err(|_| ())
            .and_then(|id| (id > 0).then_some(id).ok_or(()))
    })
}

fn parse_ci_value<T, E>(
    selected: &BTreeMap<GitLabCiField, String>,
    field: GitLabCiField,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
    parser: impl FnOnce(&str) -> Result<T, E>,
) -> Option<T> {
    let value = selected.get(&field)?;
    if value.is_empty() {
        return None;
    }
    if let Ok(parsed) = parser(value) {
        Some(parsed)
    } else {
        reasons.insert(GitLabCiAmbiguity::InvalidValue(field));
        None
    }
}

fn parse_optional_ci_value<T, E>(
    selected: &BTreeMap<GitLabCiField, String>,
    field: GitLabCiField,
    reasons: &mut BTreeSet<GitLabCiAmbiguity>,
    parser: impl FnOnce(&str) -> Result<T, E>,
) -> Option<T> {
    selected.get(&field).and_then(|value| {
        if value.is_empty() {
            None
        } else if let Ok(parsed) = parser(value) {
            Some(parsed)
        } else {
            reasons.insert(GitLabCiAmbiguity::InvalidValue(field));
            None
        }
    })
}

fn identity_matches(left: &GitLabProjectIdentity, right: &GitLabProjectIdentity) -> bool {
    left.id == right.id && left.path == right.path
}

fn identities_consistent(left: &GitLabProjectIdentity, right: &GitLabProjectIdentity) -> bool {
    (left.id == right.id) == (left.path == right.path)
}

/// Trusted controller selection plus an optional untrusted CI hint. This is an
/// input to authoritative verification, not a verified context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabVerificationInput {
    pub origin: GitLabOrigin,
    pub project: GitLabProjectIdentity,
    pub merge_request_iid: MergeRequestIid,
    pub ci_hint: Option<UntrustedGitLabCiHint>,
}

/// Typed merge-request identity supplied by the authenticated GitLab adapter.
/// Constructing this value does not perform network I/O or imply verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeGitLabMergeRequest {
    pub target_project: GitLabProjectIdentity,
    pub source_project: GitLabProjectIdentity,
    pub merge_request_iid: MergeRequestIid,
    pub source_ref: GitRefName,
    pub target_ref: GitRefName,
    pub head_sha: GitSha,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitLabVerificationMismatch {
    ConfiguredProjectId,
    ConfiguredProjectPath,
    ConfiguredMergeRequestIid,
    CiOrigin,
    CiPipelineProjectId,
    CiPipelineProjectPath,
    CiTargetProjectId,
    CiTargetProjectPath,
    CiSourceProjectId,
    CiSourceProjectPath,
    CiMergeRequestIid,
    CiSourceRef,
    CiTargetRef,
    CiHeadSha,
}

/// Context that crossed the authoritative verification boundary. Fields are
/// private so the value can only be constructed by [`GitLabVerificationInput::verify`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedGitLabContext {
    origin: GitLabOrigin,
    target_project: GitLabProjectIdentity,
    source_project: GitLabProjectIdentity,
    merge_request_iid: MergeRequestIid,
    source_ref: GitRefName,
    target_ref: GitRefName,
    head_sha: GitSha,
}

impl VerifiedGitLabContext {
    #[must_use]
    pub const fn origin(&self) -> &GitLabOrigin {
        &self.origin
    }

    #[must_use]
    pub const fn target_project(&self) -> &GitLabProjectIdentity {
        &self.target_project
    }

    #[must_use]
    pub const fn source_project(&self) -> &GitLabProjectIdentity {
        &self.source_project
    }

    #[must_use]
    pub const fn merge_request_iid(&self) -> MergeRequestIid {
        self.merge_request_iid
    }

    #[must_use]
    pub const fn source_ref(&self) -> &GitRefName {
        &self.source_ref
    }

    #[must_use]
    pub const fn target_ref(&self) -> &GitRefName {
        &self.target_ref
    }

    #[must_use]
    pub const fn head_sha(&self) -> &GitSha {
        &self.head_sha
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "details", rename_all = "snake_case")]
pub enum GitLabVerificationResult {
    Verified(VerifiedGitLabContext),
    Mismatch {
        mismatches: BTreeSet<GitLabVerificationMismatch>,
    },
}

impl GitLabVerificationInput {
    /// Compare trusted selection and untrusted hints with an authenticated,
    /// authoritative merge-request observation.
    #[must_use]
    pub fn verify(
        self,
        authoritative: AuthoritativeGitLabMergeRequest,
    ) -> GitLabVerificationResult {
        let mut mismatches = BTreeSet::new();
        compare(
            self.project.id == authoritative.target_project.id,
            GitLabVerificationMismatch::ConfiguredProjectId,
            &mut mismatches,
        );
        compare(
            self.project.path == authoritative.target_project.path,
            GitLabVerificationMismatch::ConfiguredProjectPath,
            &mut mismatches,
        );
        compare(
            self.merge_request_iid == authoritative.merge_request_iid,
            GitLabVerificationMismatch::ConfiguredMergeRequestIid,
            &mut mismatches,
        );

        if let Some(hint) = self.ci_hint {
            compare(
                hint.origin == self.origin,
                GitLabVerificationMismatch::CiOrigin,
                &mut mismatches,
            );
            let authoritative_pipeline_project =
                if identity_matches(&hint.pipeline_project, &hint.source_project) {
                    Some(&authoritative.source_project)
                } else if identity_matches(&hint.pipeline_project, &hint.target_project) {
                    Some(&authoritative.target_project)
                } else {
                    None
                };
            if let Some(project) = authoritative_pipeline_project {
                compare_project(
                    &hint.pipeline_project,
                    project,
                    GitLabVerificationMismatch::CiPipelineProjectId,
                    GitLabVerificationMismatch::CiPipelineProjectPath,
                    &mut mismatches,
                );
            } else {
                mismatches.insert(GitLabVerificationMismatch::CiPipelineProjectId);
                mismatches.insert(GitLabVerificationMismatch::CiPipelineProjectPath);
            }
            compare_project(
                &hint.target_project,
                &authoritative.target_project,
                GitLabVerificationMismatch::CiTargetProjectId,
                GitLabVerificationMismatch::CiTargetProjectPath,
                &mut mismatches,
            );
            compare_project(
                &hint.source_project,
                &authoritative.source_project,
                GitLabVerificationMismatch::CiSourceProjectId,
                GitLabVerificationMismatch::CiSourceProjectPath,
                &mut mismatches,
            );
            compare(
                hint.merge_request_iid == authoritative.merge_request_iid,
                GitLabVerificationMismatch::CiMergeRequestIid,
                &mut mismatches,
            );
            compare(
                hint.source_ref == authoritative.source_ref,
                GitLabVerificationMismatch::CiSourceRef,
                &mut mismatches,
            );
            compare(
                hint.target_ref == authoritative.target_ref,
                GitLabVerificationMismatch::CiTargetRef,
                &mut mismatches,
            );
            compare(
                hint.head_sha == authoritative.head_sha,
                GitLabVerificationMismatch::CiHeadSha,
                &mut mismatches,
            );
        }

        if !mismatches.is_empty() {
            return GitLabVerificationResult::Mismatch { mismatches };
        }
        GitLabVerificationResult::Verified(VerifiedGitLabContext {
            origin: self.origin,
            target_project: authoritative.target_project,
            source_project: authoritative.source_project,
            merge_request_iid: authoritative.merge_request_iid,
            source_ref: authoritative.source_ref,
            target_ref: authoritative.target_ref,
            head_sha: authoritative.head_sha,
        })
    }
}

fn compare(
    matches: bool,
    mismatch: GitLabVerificationMismatch,
    mismatches: &mut BTreeSet<GitLabVerificationMismatch>,
) {
    if !matches {
        mismatches.insert(mismatch);
    }
}

fn compare_project(
    left: &GitLabProjectIdentity,
    right: &GitLabProjectIdentity,
    id_mismatch: GitLabVerificationMismatch,
    path_mismatch: GitLabVerificationMismatch,
    mismatches: &mut BTreeSet<GitLabVerificationMismatch>,
) {
    compare(left.id == right.id, id_mismatch, mismatches);
    compare(left.path == right.path, path_mismatch, mismatches);
}

#[cfg(test)]
mod tests {
    use super::{
        AuthoritativeGitLabMergeRequest, GitLabCiAmbiguity, GitLabCiContext, GitLabCiField,
        GitLabOrigin, GitLabOriginError, GitLabOriginPolicy, GitLabProjectIdentity,
        GitLabProjectPath, GitLabProjectPathError, GitLabVerificationInput,
        GitLabVerificationMismatch, GitLabVerificationResult, GitRefName, GitRefNameError,
        classify_gitlab_ci_environment,
    };
    use crate::{GitSha, MergeRequestIid, ProjectId};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER_SHA: &str = "1123456789abcdef0123456789abcdef01234567";

    fn policy() -> GitLabOriginPolicy {
        GitLabOriginPolicy::new([8443]).unwrap()
    }

    fn same_project_environment() -> Vec<(String, String)> {
        [
            ("CI_SERVER_URL", "https://GitLab.Example.com:443/"),
            ("CI_PIPELINE_SOURCE", "merge_request_event"),
            ("CI_PROJECT_ID", "42"),
            ("CI_PROJECT_PATH", "group/project"),
            ("CI_MERGE_REQUEST_PROJECT_ID", "42"),
            ("CI_MERGE_REQUEST_PROJECT_PATH", "group/project"),
            ("CI_MERGE_REQUEST_IID", "7"),
            ("CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "42"),
            ("CI_MERGE_REQUEST_SOURCE_PROJECT_PATH", "group/project"),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "feature/strict-ci"),
            ("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main"),
            ("CI_MERGE_REQUEST_EVENT_TYPE", "detached"),
            ("CI_COMMIT_SHA", SHA),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", ""),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
    }

    fn ready_hint() -> super::UntrustedGitLabCiHint {
        match classify_gitlab_ci_environment(same_project_environment(), &policy()) {
            GitLabCiContext::Ready(hint) => hint,
            other => panic!("unexpected classification: {other:?}"),
        }
    }

    fn project(id: u64, path: &str) -> GitLabProjectIdentity {
        GitLabProjectIdentity {
            id: ProjectId::try_from(id).unwrap(),
            path: GitLabProjectPath::try_from(path.to_owned()).unwrap(),
        }
    }

    fn authoritative() -> AuthoritativeGitLabMergeRequest {
        AuthoritativeGitLabMergeRequest {
            target_project: project(42, "group/project"),
            source_project: project(42, "group/project"),
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
            source_ref: GitRefName::try_from("feature/strict-ci".to_owned()).unwrap(),
            target_ref: GitRefName::try_from("main".to_owned()).unwrap(),
            head_sha: GitSha::try_from(SHA.to_owned()).unwrap(),
        }
    }

    #[test]
    fn origin_is_https_only_and_canonical() {
        let origin = GitLabOrigin::parse("https://GitLab.Example.COM:443/", &policy()).unwrap();
        assert_eq!(origin.as_str(), "https://gitlab.example.com");
        assert_eq!(origin.host(), "gitlab.example.com");
        assert_eq!(origin.port(), 443);
        assert_eq!(origin.non_default_port(), None);

        let ipv6 = GitLabOrigin::parse("https://[2001:0db8::1]:8443", &policy()).unwrap();
        assert_eq!(ipv6.as_str(), "https://[2001:db8::1]:8443");
        assert_eq!(ipv6.non_default_port(), Some(8443));
    }

    #[test]
    fn origin_rejects_extra_url_components_and_ambiguous_authorities() {
        for (value, expected) in [
            ("http://gitlab.example.com", GitLabOriginError::Scheme),
            (
                "https://user@gitlab.example.com",
                GitLabOriginError::UserInfo,
            ),
            ("https://gitlab.example.com/api", GitLabOriginError::Path),
            ("https://gitlab.example.com?q=1", GitLabOriginError::Query),
            ("https://gitlab.example.com#x", GitLabOriginError::Fragment),
            ("https://gitlab.example.com:0443", GitLabOriginError::Port),
            ("https://127.0.0.999", GitLabOriginError::Host),
        ] {
            assert_eq!(GitLabOrigin::parse(value, &policy()), Err(expected));
        }
        assert_eq!(
            GitLabOrigin::parse("https://gitlab.example.com:9443", &policy()),
            Err(GitLabOriginError::UnsupportedPort(9443))
        );
    }

    #[test]
    fn project_paths_are_namespace_qualified_and_bounded() {
        assert!(GitLabProjectPath::try_from("group/sub/project_1".to_owned()).is_ok());
        assert_eq!(
            GitLabProjectPath::try_from("project".to_owned()),
            Err(GitLabProjectPathError::Depth)
        );
        assert_eq!(
            GitLabProjectPath::try_from("group/../project".to_owned()),
            Err(GitLabProjectPathError::Component)
        );
        assert_eq!(
            GitLabProjectPath::try_from("group/proj%2Fect".to_owned()),
            Err(GitLabProjectPathError::Character)
        );
    }

    #[test]
    fn ref_names_reject_git_ambiguities_and_broad_characters() {
        assert!(GitRefName::try_from("feature/safe-1.2".to_owned()).is_ok());
        for value in [
            "../main",
            "feature//x",
            "feature/@{x",
            "feature/x.lock",
            "feature with space",
            "feature/~x",
        ] {
            assert!(GitRefName::try_from(value.to_owned()).is_err(), "{value}");
        }
        assert_eq!(
            GitRefName::try_from("feature//x".to_owned()),
            Err(GitRefNameError::Ambiguous)
        );
    }

    #[test]
    fn allowlisted_same_project_ci_context_is_ready() {
        let hint = ready_hint();
        assert_eq!(hint.origin.as_str(), "https://gitlab.example.com");
        assert_eq!(hint.target_project.id.get(), 42);
        assert_eq!(hint.merge_request_iid.get(), 7);
        assert_eq!(hint.head_sha.as_str(), SHA);
        assert!(!hint.is_fork());
    }

    #[test]
    fn ci_classification_is_input_order_independent() {
        let forward = same_project_environment();
        let mut reverse = forward.clone();
        reverse.reverse();
        assert_eq!(
            classify_gitlab_ci_environment(forward, &policy()),
            classify_gitlab_ci_environment(reverse, &policy())
        );
    }

    #[test]
    fn unknown_secret_environment_entries_are_ignored_and_not_retained() {
        let mut environment = same_project_environment();
        environment.push(("GITLAB_TOKEN".to_owned(), "super-secret-value".to_owned()));
        environment.push(("CI_JOB_TOKEN".to_owned(), "another-secret".to_owned()));
        let context = classify_gitlab_ci_environment(environment, &policy());
        let debug = format!("{context:?}");
        let report = serde_json::to_string(&context).unwrap();
        assert!(matches!(context, GitLabCiContext::Ready(_)));
        assert!(!debug.contains("super-secret-value"));
        assert!(!debug.contains("another-secret"));
        assert!(!report.contains("super-secret-value"));
        assert!(!report.contains("another-secret"));
        assert!(report.contains("\"classification\":\"ready\""));
    }

    #[test]
    fn missing_fields_are_named_without_copying_values() {
        let mut environment = same_project_environment();
        environment.retain(|(name, _)| name != "CI_MERGE_REQUEST_IID");
        assert_eq!(
            classify_gitlab_ci_environment(environment, &policy()),
            GitLabCiContext::Missing {
                fields: [GitLabCiField::MergeRequestIid].into_iter().collect()
            }
        );
    }

    #[test]
    fn duplicate_allowlisted_names_are_ambiguous_even_when_identical() {
        let mut environment = same_project_environment();
        environment.push(("CI_PROJECT_ID".to_owned(), "42".to_owned()));
        assert_eq!(
            classify_gitlab_ci_environment(environment, &policy()),
            GitLabCiContext::Ambiguous {
                reasons: [GitLabCiAmbiguity::DuplicateVariable(
                    GitLabCiField::PipelineProjectId
                )]
                .into_iter()
                .collect()
            }
        );
    }

    #[test]
    fn invalid_and_unsupported_ci_values_are_ambiguous() {
        let mut environment = same_project_environment();
        for (name, value) in &mut environment {
            if name == "CI_PROJECT_ID" {
                *value = "042".to_owned();
            }
            if name == "CI_MERGE_REQUEST_EVENT_TYPE" {
                *value = "merged_result".to_owned();
            }
        }
        let GitLabCiContext::Ambiguous { reasons } =
            classify_gitlab_ci_environment(environment, &policy())
        else {
            panic!("expected ambiguity");
        };
        assert!(reasons.contains(&GitLabCiAmbiguity::InvalidValue(
            GitLabCiField::PipelineProjectId
        )));
        assert!(reasons.contains(&GitLabCiAmbiguity::UnsupportedMergeRequestEventType));
    }

    #[test]
    fn fork_project_relationship_is_explicitly_classified() {
        let mut environment = same_project_environment();
        for (name, value) in &mut environment {
            match name.as_str() {
                "CI_PROJECT_ID" | "CI_MERGE_REQUEST_SOURCE_PROJECT_ID" => {
                    *value = "99".to_owned();
                }
                "CI_PROJECT_PATH" | "CI_MERGE_REQUEST_SOURCE_PROJECT_PATH" => {
                    *value = "contributor/project".to_owned();
                }
                _ => {}
            }
        }
        let context = classify_gitlab_ci_environment(environment, &policy());
        let GitLabCiContext::ForkMismatch { hint } = context else {
            panic!("expected fork mismatch");
        };
        assert!(hint.is_fork());
        assert_eq!(hint.pipeline_project, hint.source_project);
        assert_ne!(hint.source_project, hint.target_project);
    }

    #[test]
    fn target_project_fork_pipeline_can_be_authoritatively_verified() {
        let mut environment = same_project_environment();
        for (name, value) in &mut environment {
            match name.as_str() {
                "CI_MERGE_REQUEST_SOURCE_PROJECT_ID" => *value = "99".to_owned(),
                "CI_MERGE_REQUEST_SOURCE_PROJECT_PATH" => {
                    *value = "contributor/project".to_owned();
                }
                _ => {}
            }
        }
        let GitLabCiContext::ForkMismatch { hint } =
            classify_gitlab_ci_environment(environment, &policy())
        else {
            panic!("expected fork mismatch");
        };
        let input = GitLabVerificationInput {
            origin: GitLabOrigin::parse("https://gitlab.example.com", &policy()).unwrap(),
            project: project(42, "group/project"),
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
            ci_hint: Some(hint),
        };
        let mut observation = authoritative();
        observation.source_project = project(99, "contributor/project");
        assert!(matches!(
            input.verify(observation),
            GitLabVerificationResult::Verified(_)
        ));
    }

    #[test]
    fn crossed_project_id_and_path_pairs_are_ambiguous() {
        let mut environment = same_project_environment();
        for (name, value) in &mut environment {
            if name == "CI_PROJECT_PATH" {
                *value = "other/project".to_owned();
            }
        }
        assert_eq!(
            classify_gitlab_ci_environment(environment, &policy()),
            GitLabCiContext::Ambiguous {
                reasons: [GitLabCiAmbiguity::InconsistentProjectIdentity]
                    .into_iter()
                    .collect()
            }
        );
    }

    #[test]
    fn conflicting_optional_source_sha_is_ambiguous() {
        let mut environment = same_project_environment();
        for (name, value) in &mut environment {
            if name == "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA" {
                *value = OTHER_SHA.to_owned();
            }
        }
        assert_eq!(
            classify_gitlab_ci_environment(environment, &policy()),
            GitLabCiContext::Ambiguous {
                reasons: [GitLabCiAmbiguity::ConflictingHeadSha]
                    .into_iter()
                    .collect()
            }
        );
    }

    #[test]
    fn noncanonical_sha_is_an_ambiguous_ci_value() {
        let mut environment = same_project_environment();
        for (name, value) in &mut environment {
            if name == "CI_COMMIT_SHA" {
                *value = SHA.to_ascii_uppercase();
            }
        }
        assert_eq!(
            classify_gitlab_ci_environment(environment, &policy()),
            GitLabCiContext::Ambiguous {
                reasons: [GitLabCiAmbiguity::InvalidValue(GitLabCiField::CommitSha)]
                    .into_iter()
                    .collect()
            }
        );
    }

    #[test]
    fn authoritative_match_is_the_only_verified_boundary() {
        let input = GitLabVerificationInput {
            origin: GitLabOrigin::parse("https://gitlab.example.com", &policy()).unwrap(),
            project: project(42, "group/project"),
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
            ci_hint: Some(ready_hint()),
        };
        let GitLabVerificationResult::Verified(verified) = input.verify(authoritative()) else {
            panic!("expected verified context");
        };
        assert_eq!(verified.origin().as_str(), "https://gitlab.example.com");
        assert_eq!(verified.target_project().id.get(), 42);
        assert_eq!(verified.merge_request_iid().get(), 7);
        assert_eq!(verified.head_sha().as_str(), SHA);
    }

    #[test]
    fn authoritative_mismatches_are_complete_and_deterministic() {
        let input = GitLabVerificationInput {
            origin: GitLabOrigin::parse("https://other.example.com", &policy()).unwrap(),
            project: project(43, "other/project"),
            merge_request_iid: MergeRequestIid::try_from(8).unwrap(),
            ci_hint: Some(ready_hint()),
        };
        let GitLabVerificationResult::Mismatch { mismatches } = input.verify(authoritative())
        else {
            panic!("expected mismatch");
        };
        assert_eq!(
            mismatches,
            [
                GitLabVerificationMismatch::ConfiguredProjectId,
                GitLabVerificationMismatch::ConfiguredProjectPath,
                GitLabVerificationMismatch::ConfiguredMergeRequestIid,
                GitLabVerificationMismatch::CiOrigin,
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn manually_constructed_unrelated_pipeline_hint_cannot_verify() {
        let mut hint = ready_hint();
        hint.pipeline_project = project(88, "unrelated/project");
        let input = GitLabVerificationInput {
            origin: GitLabOrigin::parse("https://gitlab.example.com", &policy()).unwrap(),
            project: project(42, "group/project"),
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
            ci_hint: Some(hint),
        };
        let GitLabVerificationResult::Mismatch { mismatches } = input.verify(authoritative())
        else {
            panic!("expected mismatch");
        };
        assert!(mismatches.contains(&GitLabVerificationMismatch::CiPipelineProjectId));
        assert!(mismatches.contains(&GitLabVerificationMismatch::CiPipelineProjectPath));
    }
}
