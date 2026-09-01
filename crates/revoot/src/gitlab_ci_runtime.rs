//! GitLab CI authentication, fork policy, readiness, and report-only behavior.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use revoot_core::GitLabCiContext;
use serde::Deserialize;

use crate::gitlab_publication::GitLabPublicationAuthorization;
use crate::gitlab_transport::{
    GitLabAccessToken, GitLabFailureKind, GitLabReadClient, GitLabReadEndpoint,
    GitLabTransportError, GitLabWriteAccessToken,
};

const MAX_ENVIRONMENT_ENTRIES: usize = 16_384;

/// Environment variable selected for GitLab authentication. Values are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabCredentialSource {
    RevootPrivateToken,
    GitLabPrivateToken,
    RevootBearerToken,
    CiJobToken,
}

impl GitLabCredentialSource {
    #[must_use]
    pub const fn environment_name(self) -> &'static str {
        match self {
            Self::RevootPrivateToken => "REVOOT_GITLAB_TOKEN",
            Self::GitLabPrivateToken => "GITLAB_TOKEN",
            Self::RevootBearerToken => "REVOOT_GITLAB_BEARER_TOKEN",
            Self::CiJobToken => "CI_JOB_TOKEN",
        }
    }
}

/// Read and optional write credentials derived from an explicit environment allowlist.
pub struct GitLabCredentialSet {
    pub read: GitLabAccessToken,
    pub write: Option<GitLabWriteAccessToken>,
    pub source: GitLabCredentialSource,
}

impl fmt::Debug for GitLabCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitLabCredentialSet")
            .field("source", &self.source)
            .field("write_available", &self.write.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabCredentialError {
    EnvironmentTooLarge,
    DuplicateVariable,
    Missing,
    Invalid,
}

impl fmt::Display for GitLabCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EnvironmentTooLarge => "too many environment entries",
            Self::DuplicateVariable => "a GitLab credential variable was supplied more than once",
            Self::Missing => "no supported GitLab credential is configured",
            Self::Invalid => "the selected GitLab credential is invalid",
        })
    }
}

impl Error for GitLabCredentialError {}

/// Load only documented GitLab credential variables, in deterministic precedence order.
///
/// # Errors
///
/// Rejects oversized input, duplicate credential names, missing credentials,
/// and values that are unsafe for an HTTP header.
pub fn load_gitlab_credentials(
    variables: impl IntoIterator<Item = (String, String)>,
) -> Result<GitLabCredentialSet, GitLabCredentialError> {
    let mut selected = BTreeMap::new();
    for (index, (name, value)) in variables.into_iter().enumerate() {
        if index >= MAX_ENVIRONMENT_ENTRIES {
            return Err(GitLabCredentialError::EnvironmentTooLarge);
        }
        let source = match name.as_str() {
            "REVOOT_GITLAB_TOKEN" => Some(GitLabCredentialSource::RevootPrivateToken),
            "GITLAB_TOKEN" => Some(GitLabCredentialSource::GitLabPrivateToken),
            "REVOOT_GITLAB_BEARER_TOKEN" => Some(GitLabCredentialSource::RevootBearerToken),
            "CI_JOB_TOKEN" => Some(GitLabCredentialSource::CiJobToken),
            _ => None,
        };
        if let Some(source) = source
            && selected.insert(source.environment_name(), value).is_some()
        {
            return Err(GitLabCredentialError::DuplicateVariable);
        }
    }
    let (source, value) = [
        GitLabCredentialSource::RevootPrivateToken,
        GitLabCredentialSource::GitLabPrivateToken,
        GitLabCredentialSource::RevootBearerToken,
        GitLabCredentialSource::CiJobToken,
    ]
    .into_iter()
    .find_map(|source| {
        selected
            .get(source.environment_name())
            .filter(|value| !value.is_empty())
            .map(|value| (source, value.as_bytes()))
    })
    .ok_or(GitLabCredentialError::Missing)?;

    let read = match source {
        GitLabCredentialSource::RevootPrivateToken | GitLabCredentialSource::GitLabPrivateToken => {
            GitLabAccessToken::new(value.to_vec())
        }
        GitLabCredentialSource::RevootBearerToken => GitLabAccessToken::bearer(value.to_vec()),
        GitLabCredentialSource::CiJobToken => GitLabAccessToken::job_token(value.to_vec()),
    }
    .map_err(|_| GitLabCredentialError::Invalid)?;
    let write = match source {
        GitLabCredentialSource::RevootPrivateToken | GitLabCredentialSource::GitLabPrivateToken => {
            Some(GitLabWriteAccessToken::new(value.to_vec()))
        }
        GitLabCredentialSource::RevootBearerToken => {
            Some(GitLabWriteAccessToken::bearer(value.to_vec()))
        }
        GitLabCredentialSource::CiJobToken => None,
    }
    .transpose()
    .map_err(|_| GitLabCredentialError::Invalid)?;
    Ok(GitLabCredentialSet {
        read,
        write,
        source,
    })
}

/// Configured behavior when merge-request code comes from a fork.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GitLabForkBehavior {
    /// Emit reports/artifacts without publication credentials or GitLab mutations.
    #[default]
    ReportOnly,
    /// Do no provider or publication work in the source-controlled pipeline.
    Skip,
    /// Publish only when a separately trusted target-side pipeline is established.
    TrustedTargetPipeline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabExecutionMode {
    Publish,
    ReportOnly,
    Skip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabCheckoutBinding {
    Bound,
    Unbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabProviderReadiness {
    Ready,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabPublicationPreference {
    Publish,
    ReportOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabTargetPipelineTrust {
    Trusted,
    Untrusted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabReadinessCode {
    Ready,
    MissingCiContext,
    AmbiguousCiContext,
    ForkReportOnly,
    ForkSkipped,
    ForkTargetPipelineRequired,
    MissingCredential,
    JobTokenCannotPublish,
    GitLabAuthenticationFailed,
    GitLabAuthorizationFailed,
    GitLabUnavailable,
    CheckoutUnbound,
    ProviderUnavailable,
    BotIdentityUnavailable,
}

/// One payload-free, actionable diagnostic suitable for terminal or JSON output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabReadinessDiagnostic {
    pub code: GitLabReadinessCode,
    pub blocking: bool,
    pub action: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabReadiness {
    pub mode: GitLabExecutionMode,
    pub diagnostics: Vec<GitLabReadinessDiagnostic>,
    pub bot_user_id: Option<u64>,
}

impl GitLabReadiness {
    /// Consume publication authority only after readiness selected publish mode.
    #[must_use]
    pub fn publication_authorization(&self) -> Option<GitLabPublicationAuthorization> {
        (matches!(self.mode, GitLabExecutionMode::Publish) && self.is_ready())
            .then(GitLabPublicationAuthorization::accepted)
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.blocking)
    }
}

/// Facts gathered by checkout, provider, and authenticated GitLab probes.
#[derive(Clone, Copy, Debug)]
pub struct GitLabReadinessInput<'a> {
    pub ci: &'a GitLabCiContext,
    pub credential_source: Option<GitLabCredentialSource>,
    pub authenticated_user: Result<u64, GitLabProbeFailure>,
    pub checkout: GitLabCheckoutBinding,
    pub provider: GitLabProviderReadiness,
    pub publication: GitLabPublicationPreference,
    pub fork_behavior: GitLabForkBehavior,
    /// True only for a trusted target-side pipeline not controlled by fork code.
    pub target_pipeline: GitLabTargetPipelineTrust,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabProbeFailure {
    Authentication,
    Authorization,
    Unavailable,
    InvalidResponse,
}

/// Determine publish/report/skip behavior without silently weakening expected publication.
#[must_use]
pub fn diagnose_gitlab_readiness(input: GitLabReadinessInput<'_>) -> GitLabReadiness {
    let mut diagnostics = Vec::new();
    let mut mode = if matches!(input.publication, GitLabPublicationPreference::Publish) {
        GitLabExecutionMode::Publish
    } else {
        GitLabExecutionMode::ReportOnly
    };
    match input.ci {
        GitLabCiContext::Missing { .. } => diagnostics.push(diagnostic(
            GitLabReadinessCode::MissingCiContext,
            true,
            "run in a merge-request pipeline or supply an explicit project and MR IID",
        )),
        GitLabCiContext::Ambiguous { .. } => diagnostics.push(diagnostic(
            GitLabReadinessCode::AmbiguousCiContext,
            true,
            "remove conflicting GitLab CI variables and use a detached MR pipeline",
        )),
        GitLabCiContext::ForkMismatch { .. } => match input.fork_behavior {
            GitLabForkBehavior::ReportOnly => {
                mode = GitLabExecutionMode::ReportOnly;
                diagnostics.push(diagnostic(
                    GitLabReadinessCode::ForkReportOnly,
                    false,
                    "review output will be written only to CI reports/artifacts",
                ));
            }
            GitLabForkBehavior::Skip => {
                mode = GitLabExecutionMode::Skip;
                diagnostics.push(diagnostic(
                    GitLabReadinessCode::ForkSkipped,
                    false,
                    "configure a trusted target-side pipeline to review forks",
                ));
            }
            GitLabForkBehavior::TrustedTargetPipeline
                if matches!(input.target_pipeline, GitLabTargetPipelineTrust::Trusted) => {}
            GitLabForkBehavior::TrustedTargetPipeline => diagnostics.push(diagnostic(
                GitLabReadinessCode::ForkTargetPipelineRequired,
                true,
                "run this fork review from an approved target-side pipeline",
            )),
        },
        GitLabCiContext::Ready(_) => {}
    }

    if matches!(input.checkout, GitLabCheckoutBinding::Unbound)
        && !matches!(mode, GitLabExecutionMode::Skip)
    {
        diagnostics.push(diagnostic(
            GitLabReadinessCode::CheckoutUnbound,
            true,
            "check out the exact MR head SHA reported by the GitLab API",
        ));
    }
    if matches!(input.provider, GitLabProviderReadiness::Unavailable)
        && !matches!(mode, GitLabExecutionMode::Skip)
    {
        diagnostics.push(diagnostic(
            GitLabReadinessCode::ProviderUnavailable,
            true,
            "configure a supported model provider and its credential",
        ));
    }
    if input.credential_source.is_none() && matches!(mode, GitLabExecutionMode::Publish) {
        diagnostics.push(diagnostic(
            GitLabReadinessCode::MissingCredential,
            true,
            "set masked REVOOT_GITLAB_TOKEN with API permission, or use report-only mode",
        ));
    }
    if input.credential_source == Some(GitLabCredentialSource::CiJobToken)
        && matches!(mode, GitLabExecutionMode::Publish)
    {
        diagnostics.push(diagnostic(
            GitLabReadinessCode::JobTokenCannotPublish,
            true,
            "CI_JOB_TOKEN can read MR data but cannot create MR discussions; configure a bot token",
        ));
    }
    let bot_user_id = diagnose_authenticated_user(mode, input.authenticated_user, &mut diagnostics);
    if diagnostics.is_empty() {
        diagnostics.push(diagnostic(
            GitLabReadinessCode::Ready,
            false,
            "GitLab review prerequisites are ready",
        ));
    }
    GitLabReadiness {
        mode,
        diagnostics,
        bot_user_id,
    }
}

fn diagnose_authenticated_user(
    mode: GitLabExecutionMode,
    user: Result<u64, GitLabProbeFailure>,
    diagnostics: &mut Vec<GitLabReadinessDiagnostic>,
) -> Option<u64> {
    if !matches!(mode, GitLabExecutionMode::Publish) {
        return user.ok().filter(|id| *id > 0);
    }
    match user {
        Ok(id) if id > 0 => Some(id),
        Ok(_) | Err(GitLabProbeFailure::InvalidResponse) => {
            diagnostics.push(diagnostic(
                GitLabReadinessCode::BotIdentityUnavailable,
                true,
                "verify the GitLab token resolves to an active bot user",
            ));
            None
        }
        Err(failure) => {
            let (code, action) = match failure {
                GitLabProbeFailure::Authentication => (
                    GitLabReadinessCode::GitLabAuthenticationFailed,
                    "replace the expired or invalid GitLab credential",
                ),
                GitLabProbeFailure::Authorization => (
                    GitLabReadinessCode::GitLabAuthorizationFailed,
                    "grant the bot the minimum project API access required for this MR",
                ),
                GitLabProbeFailure::Unavailable => (
                    GitLabReadinessCode::GitLabUnavailable,
                    "check GitLab connectivity, CA configuration, and service health",
                ),
                GitLabProbeFailure::InvalidResponse => unreachable!(),
            };
            diagnostics.push(diagnostic(code, true, action));
            None
        }
    }
}

/// Verify the configured credential and acquire the immutable bot user ID.
///
/// # Errors
///
/// Classifies authentication, authorization, connectivity, and malformed-user
/// responses without retaining the response body.
pub async fn probe_gitlab_user(client: &GitLabReadClient) -> Result<u64, GitLabProbeFailure> {
    #[derive(Deserialize)]
    struct UserProjection {
        id: u64,
    }

    let response = client
        .get_with_retry(&GitLabReadEndpoint::CurrentUser)
        .await
        .map_err(|error| classify_probe_transport(&error))?;
    let user: UserProjection = serde_json::from_slice(response.observation().body.as_slice())
        .map_err(|_| GitLabProbeFailure::InvalidResponse)?;
    (user.id > 0)
        .then_some(user.id)
        .ok_or(GitLabProbeFailure::InvalidResponse)
}

fn classify_probe_transport(error: &GitLabTransportError) -> GitLabProbeFailure {
    match error.kind() {
        GitLabFailureKind::Authentication => GitLabProbeFailure::Authentication,
        GitLabFailureKind::Forbidden | GitLabFailureKind::NotFound => {
            GitLabProbeFailure::Authorization
        }
        _ => GitLabProbeFailure::Unavailable,
    }
}

const fn diagnostic(
    code: GitLabReadinessCode,
    blocking: bool,
    action: &'static str,
) -> GitLabReadinessDiagnostic {
    GitLabReadinessDiagnostic {
        code,
        blocking,
        action,
    }
}

#[cfg(test)]
mod tests {
    use revoot_core::{
        GitLabCiContext, GitLabOrigin, GitLabOriginPolicy, GitLabProjectIdentity,
        GitLabProjectPath, GitRefName, GitSha, MergeRequestIid, ProjectId, UntrustedGitLabCiHint,
    };

    use super::*;
    use crate::gitlab_transport::GitLabAuthenticationKind;

    fn hint(fork: bool) -> UntrustedGitLabCiHint {
        let source_id = if fork { 2 } else { 1 };
        let source_path = if fork {
            "fork/project"
        } else {
            "group/project"
        };
        UntrustedGitLabCiHint {
            origin: GitLabOrigin::parse(
                "https://gitlab.example.com",
                &GitLabOriginPolicy::default(),
            )
            .unwrap(),
            pipeline_project: GitLabProjectIdentity {
                id: ProjectId::try_from(source_id).unwrap(),
                path: GitLabProjectPath::try_from(source_path.to_owned()).unwrap(),
            },
            target_project: GitLabProjectIdentity {
                id: ProjectId::try_from(1).unwrap(),
                path: GitLabProjectPath::try_from("group/project".to_owned()).unwrap(),
            },
            source_project: GitLabProjectIdentity {
                id: ProjectId::try_from(source_id).unwrap(),
                path: GitLabProjectPath::try_from(source_path.to_owned()).unwrap(),
            },
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
            source_ref: GitRefName::try_from("feature".to_owned()).unwrap(),
            target_ref: GitRefName::try_from("main".to_owned()).unwrap(),
            head_sha: GitSha::try_from("a".repeat(40)).unwrap(),
        }
    }

    #[test]
    fn job_token_is_read_only_and_never_debugged() {
        let credentials = load_gitlab_credentials([
            ("UNRELATED_SECRET".to_owned(), "ignore".to_owned()),
            ("CI_JOB_TOKEN".to_owned(), "job-secret".to_owned()),
        ])
        .unwrap();
        assert_eq!(credentials.read.kind(), GitLabAuthenticationKind::JobToken);
        assert!(credentials.write.is_none());
        assert!(!format!("{credentials:?}").contains("job-secret"));
    }

    #[test]
    fn fork_defaults_to_non_blocking_report_only() {
        let ci = GitLabCiContext::ForkMismatch { hint: hint(true) };
        let readiness = diagnose_gitlab_readiness(GitLabReadinessInput {
            ci: &ci,
            credential_source: None,
            authenticated_user: Ok(99),
            checkout: GitLabCheckoutBinding::Bound,
            provider: GitLabProviderReadiness::Ready,
            publication: GitLabPublicationPreference::Publish,
            fork_behavior: GitLabForkBehavior::ReportOnly,
            target_pipeline: GitLabTargetPipelineTrust::Untrusted,
        });
        assert_eq!(readiness.mode, GitLabExecutionMode::ReportOnly);
        assert!(readiness.is_ready());
        assert!(readiness.publication_authorization().is_none());
    }

    #[test]
    fn job_token_publish_has_an_actionable_blocker() {
        let ci = GitLabCiContext::Ready(hint(false));
        let readiness = diagnose_gitlab_readiness(GitLabReadinessInput {
            ci: &ci,
            credential_source: Some(GitLabCredentialSource::CiJobToken),
            authenticated_user: Ok(99),
            checkout: GitLabCheckoutBinding::Bound,
            provider: GitLabProviderReadiness::Ready,
            publication: GitLabPublicationPreference::Publish,
            fork_behavior: GitLabForkBehavior::ReportOnly,
            target_pipeline: GitLabTargetPipelineTrust::Untrusted,
        });
        assert!(!readiness.is_ready());
        assert!(
            readiness.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == GitLabReadinessCode::JobTokenCannotPublish
            })
        );
    }
}
