//! Discovery and authoritative binding for a local Git checkout.
//!
//! The checkout supplies repository context only. GitLab API snapshot identity
//! remains authoritative for the merge request, diff version, and head SHA.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use reqwest::Url;
use revoot_core::{
    GitLabCiContext, GitLabOrigin, GitLabOriginPolicy, GitLabProjectIdentity, GitLabProjectPath,
    GitLabVerificationInput, GitSha, MergeRequestIid,
};

use crate::embedded_git::EmbeddedRepository;
use crate::gitlab_snapshot::AcquiredGitLabSnapshot;

/// One canonical GitLab remote discovered from the checkout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredGitLabRemote {
    pub name: String,
    pub origin: GitLabOrigin,
    pub project_path: GitLabProjectPath,
}

/// Context supplied by the checked-out repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredGitRepository {
    pub root: PathBuf,
    pub head_sha: GitSha,
    pub remote: DiscoveredGitLabRemote,
}

/// A checkout proven to match the authoritative GitLab snapshot head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundGitLabCheckout {
    pub repository: DiscoveredGitRepository,
    pub source_project: revoot_core::GitLabProjectIdentity,
}

/// Trusted local selection supplied by explicit configuration or CLI input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitGitLabMergeRequest {
    pub origin: GitLabOrigin,
    pub target_project: GitLabProjectIdentity,
    pub merge_request_iid: MergeRequestIid,
}

/// Safe discovery/binding failures. Remote URLs are not retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabCheckoutError {
    NotRepository,
    InvalidHead,
    NoRemote,
    AmbiguousRemote,
    UnsupportedRemote,
    RemoteOriginMismatch,
    RemoteProjectMismatch,
    CheckoutHeadMismatch,
    MergeRequestSelectionMissing,
    MergeRequestSelectionMismatch,
}

impl fmt::Display for GitLabCheckoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotRepository => "the checkout is not a Git repository",
            Self::InvalidHead => "the checkout HEAD is not a supported full Git object ID",
            Self::NoRemote => "the checkout has no GitLab remote",
            Self::AmbiguousRemote => "the checkout has multiple possible GitLab remotes",
            Self::UnsupportedRemote => "the Git remote is not a supported GitLab URL",
            Self::RemoteOriginMismatch => "the checkout remote and GitLab API origins differ",
            Self::RemoteProjectMismatch => {
                "the checkout remote does not identify the authoritative source project"
            }
            Self::CheckoutHeadMismatch => {
                "the checkout HEAD does not match the authoritative merge-request head"
            }
            Self::MergeRequestSelectionMissing => {
                "no merge request was selected by CI context or explicit input"
            }
            Self::MergeRequestSelectionMismatch => {
                "explicit merge-request input conflicts with GitLab CI context"
            }
        })
    }
}

/// Select the target project and MR IID while preserving CI data as untrusted hints.
///
/// CI context can supply a selection by itself. Explicit input is required outside
/// GitLab CI and, when both are present, must exactly match the CI target selection.
/// The resulting input still requires authenticated API verification.
///
/// # Errors
///
/// Returns an error for missing selection, unusable CI classification, origin or
/// source-remote mismatch, and conflicts between explicit and CI selections.
pub fn select_gitlab_merge_request(
    repository: &DiscoveredGitRepository,
    ci: Option<&GitLabCiContext>,
    explicit: Option<&ExplicitGitLabMergeRequest>,
) -> Result<GitLabVerificationInput, GitLabCheckoutError> {
    let hint = match ci {
        Some(GitLabCiContext::Ready(hint) | GitLabCiContext::ForkMismatch { hint }) => Some(hint),
        Some(GitLabCiContext::Missing { .. } | GitLabCiContext::Ambiguous { .. }) => {
            return Err(GitLabCheckoutError::MergeRequestSelectionMismatch);
        }
        None => None,
    };
    if let Some(hint) = hint {
        if repository.remote.origin != hint.origin {
            return Err(GitLabCheckoutError::RemoteOriginMismatch);
        }
        if repository.remote.project_path != hint.source_project.path {
            return Err(GitLabCheckoutError::RemoteProjectMismatch);
        }
        if explicit.is_some_and(|selection| {
            selection.origin != hint.origin
                || selection.target_project != hint.target_project
                || selection.merge_request_iid != hint.merge_request_iid
        }) {
            return Err(GitLabCheckoutError::MergeRequestSelectionMismatch);
        }
        return Ok(GitLabVerificationInput {
            origin: hint.origin.clone(),
            project: hint.target_project.clone(),
            merge_request_iid: hint.merge_request_iid,
            ci_hint: Some(hint.clone()),
        });
    }
    let explicit = explicit.ok_or(GitLabCheckoutError::MergeRequestSelectionMissing)?;
    if explicit.origin != repository.remote.origin {
        return Err(GitLabCheckoutError::RemoteOriginMismatch);
    }
    Ok(GitLabVerificationInput {
        origin: explicit.origin.clone(),
        project: explicit.target_project.clone(),
        merge_request_iid: explicit.merge_request_iid,
        ci_hint: None,
    })
}

impl Error for GitLabCheckoutError {}

/// Discover the repository root, exact checkout HEAD, and canonical GitLab remote.
///
/// `origin` is preferred when present. Without it, discovery succeeds only when
/// every supported remote resolves to the same GitLab project identity.
///
/// # Errors
///
/// Returns a bounded, payload-free error when Git is unavailable, repository
/// metadata is malformed, or no unambiguous supported GitLab remote exists.
pub fn discover_gitlab_repository(
    start: &Path,
    origin_policy: &GitLabOriginPolicy,
    expected_origin: Option<&GitLabOrigin>,
) -> Result<DiscoveredGitRepository, GitLabCheckoutError> {
    let repository =
        EmbeddedRepository::discover(start).map_err(|_| GitLabCheckoutError::NotRepository)?;
    let root = repository.root().to_path_buf();
    let head = repository
        .head()
        .map_err(|_| GitLabCheckoutError::InvalidHead)?;
    let mut remotes = BTreeMap::new();
    for (name, url) in repository
        .remote_urls()
        .map_err(|_| GitLabCheckoutError::NotRepository)?
    {
        if !valid_remote_name(&name) {
            return Err(GitLabCheckoutError::UnsupportedRemote);
        }
        let parsed = parse_gitlab_remote_url(&url, origin_policy, expected_origin);
        if let Ok((origin, project_path)) = parsed {
            remotes.insert(
                name.clone(),
                DiscoveredGitLabRemote {
                    name,
                    origin,
                    project_path,
                },
            );
        }
    }
    let remote = select_remote(remotes)?;
    Ok(DiscoveredGitRepository {
        root,
        head_sha: head,
        remote,
    })
}

/// Parse HTTPS, `ssh://git@host/path`, and `git@host:path` GitLab remotes.
///
/// # Errors
///
/// Rejects malformed URLs, unsupported origins, encoded paths, and invalid
/// GitLab project paths. GitLab Runner's `gitlab-ci-token` credential form is
/// accepted only when CI supplied the expected origin; the credential is never
/// retained.
pub fn parse_gitlab_remote_url(
    value: &str,
    origin_policy: &GitLabOriginPolicy,
    expected_origin: Option<&GitLabOrigin>,
) -> Result<(GitLabOrigin, GitLabProjectPath), GitLabCheckoutError> {
    if value.is_empty() || value.len() > 8 * 1024 || value.contains(['\n', '\r', '\0']) {
        return Err(GitLabCheckoutError::UnsupportedRemote);
    }
    let (host, project, explicit_https_origin) = if value.starts_with("https://") {
        let url = Url::parse(value).map_err(|_| GitLabCheckoutError::UnsupportedRemote)?;
        let runner_credentials = expected_origin.is_some()
            && url.username() == "gitlab-ci-token"
            && url.password().is_some_and(|password| !password.is_empty());
        let has_credentials = !url.username().is_empty() || url.password().is_some();
        if (has_credentials && !runner_credentials)
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(GitLabCheckoutError::UnsupportedRemote);
        }
        let host = url
            .host_str()
            .ok_or(GitLabCheckoutError::UnsupportedRemote)?;
        let port = url.port_or_known_default().unwrap_or(443);
        let authority = if port == 443 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        (
            host.to_owned(),
            url.path().to_owned(),
            Some(format!("https://{authority}")),
        )
    } else if value.starts_with("ssh://") {
        let url = Url::parse(value).map_err(|_| GitLabCheckoutError::UnsupportedRemote)?;
        if url.username() != "git"
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(GitLabCheckoutError::UnsupportedRemote);
        }
        (
            url.host_str()
                .ok_or(GitLabCheckoutError::UnsupportedRemote)?
                .to_owned(),
            url.path().to_owned(),
            None,
        )
    } else {
        let Some(rest) = value.strip_prefix("git@") else {
            return Err(GitLabCheckoutError::UnsupportedRemote);
        };
        let Some((host, path)) = rest.split_once(':') else {
            return Err(GitLabCheckoutError::UnsupportedRemote);
        };
        if host.is_empty() || host.contains(['@', '/', ':']) {
            return Err(GitLabCheckoutError::UnsupportedRemote);
        }
        (host.to_owned(), path.to_owned(), None)
    };

    let origin = if let Some(expected) = expected_origin {
        if !host.eq_ignore_ascii_case(expected.host()) {
            return Err(GitLabCheckoutError::RemoteOriginMismatch);
        }
        if let Some(explicit) = explicit_https_origin {
            let parsed = GitLabOrigin::parse(&explicit, origin_policy)
                .map_err(|_| GitLabCheckoutError::UnsupportedRemote)?;
            if &parsed != expected {
                return Err(GitLabCheckoutError::RemoteOriginMismatch);
            }
        }
        expected.clone()
    } else {
        let inferred_origin = explicit_https_origin.unwrap_or_else(|| format!("https://{host}"));
        GitLabOrigin::parse(&inferred_origin, origin_policy)
            .map_err(|_| GitLabCheckoutError::UnsupportedRemote)?
    };
    let project = project.trim_start_matches('/');
    let project = project.strip_suffix(".git").unwrap_or(project);
    if project.contains('%') || project.ends_with('/') {
        return Err(GitLabCheckoutError::UnsupportedRemote);
    }
    let project_path = GitLabProjectPath::try_from(project.to_owned())
        .map_err(|_| GitLabCheckoutError::UnsupportedRemote)?;
    Ok((origin, project_path))
}

/// Bind checkout-derived repository context to one API-authoritative snapshot.
///
/// # Errors
///
/// Returns an error unless origin, source project path, checkout HEAD, and exact
/// snapshot head agree.
pub fn bind_checkout_to_snapshot(
    repository: DiscoveredGitRepository,
    snapshot: &AcquiredGitLabSnapshot,
) -> Result<BoundGitLabCheckout, GitLabCheckoutError> {
    let context = snapshot.verified_context();
    if repository.remote.origin != *context.origin() {
        return Err(GitLabCheckoutError::RemoteOriginMismatch);
    }
    if repository.remote.project_path != context.source_project().path {
        return Err(GitLabCheckoutError::RemoteProjectMismatch);
    }
    if &repository.head_sha != context.head_sha()
        || repository.head_sha
            != snapshot
                .evidence()
                .identity
                .version
                .diff_version
                .refs
                .head_sha
    {
        return Err(GitLabCheckoutError::CheckoutHeadMismatch);
    }
    Ok(BoundGitLabCheckout {
        repository,
        source_project: context.source_project().clone(),
    })
}

fn valid_remote_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn select_remote(
    mut remotes: BTreeMap<String, DiscoveredGitLabRemote>,
) -> Result<DiscoveredGitLabRemote, GitLabCheckoutError> {
    if let Some(origin) = remotes.remove("origin") {
        return Ok(origin);
    }
    let Some(first) = remotes.values().next().cloned() else {
        return Err(GitLabCheckoutError::NoRemote);
    };
    if remotes
        .values()
        .any(|remote| remote.origin != first.origin || remote.project_path != first.project_path)
    {
        return Err(GitLabCheckoutError::AmbiguousRemote);
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use revoot_core::{GitLabProjectIdentity, MergeRequestIid, ProjectId};

    use super::*;

    fn policy() -> GitLabOriginPolicy {
        GitLabOriginPolicy::new([8443]).expect("valid test policy")
    }

    #[test]
    fn parses_supported_remote_forms_to_one_identity() {
        let expected = GitLabOrigin::parse("https://gitlab.example.com", &policy()).unwrap();
        for value in [
            "https://gitlab.example.com/group/project.git",
            "ssh://git@gitlab.example.com/group/project.git",
            "git@gitlab.example.com:group/project.git",
        ] {
            let (origin, project) =
                parse_gitlab_remote_url(value, &policy(), Some(&expected)).unwrap();
            assert_eq!(origin, expected);
            assert_eq!(project.as_str(), "group/project");
        }
    }

    #[test]
    fn rejects_credentials_and_origin_ambiguity() {
        assert_eq!(
            parse_gitlab_remote_url(
                "https://token@gitlab.example.com/group/project.git",
                &policy(),
                None,
            ),
            Err(GitLabCheckoutError::UnsupportedRemote)
        );
        let expected = GitLabOrigin::parse("https://gitlab.example.com:8443", &policy()).unwrap();
        assert_eq!(
            parse_gitlab_remote_url(
                "https://gitlab.example.com/group/project.git",
                &policy(),
                Some(&expected),
            ),
            Err(GitLabCheckoutError::RemoteOriginMismatch)
        );
    }

    #[test]
    fn accepts_only_gitlab_runner_credentials_with_an_expected_origin() {
        let expected = GitLabOrigin::parse("https://gitlab.example.com", &policy()).unwrap();
        let runner_url = "https://gitlab-ci-token:job-secret@gitlab.example.com/group/project.git";
        let (origin, project) =
            parse_gitlab_remote_url(runner_url, &policy(), Some(&expected)).unwrap();
        assert_eq!(origin, expected);
        assert_eq!(project.as_str(), "group/project");

        assert_eq!(
            parse_gitlab_remote_url(runner_url, &policy(), None),
            Err(GitLabCheckoutError::UnsupportedRemote)
        );
        assert_eq!(
            parse_gitlab_remote_url(
                "https://other:job-secret@gitlab.example.com/group/project.git",
                &policy(),
                Some(&expected),
            ),
            Err(GitLabCheckoutError::UnsupportedRemote)
        );
    }

    #[test]
    fn explicit_local_selection_remains_unverified() {
        let origin = GitLabOrigin::parse("https://gitlab.example.com", &policy()).unwrap();
        let repository = DiscoveredGitRepository {
            root: PathBuf::from("/checkout"),
            head_sha: GitSha::try_from("a".repeat(40)).unwrap(),
            remote: DiscoveredGitLabRemote {
                name: "origin".to_owned(),
                origin: origin.clone(),
                project_path: GitLabProjectPath::try_from("group/project".to_owned()).unwrap(),
            },
        };
        let selection = ExplicitGitLabMergeRequest {
            origin: origin.clone(),
            target_project: GitLabProjectIdentity {
                id: ProjectId::try_from(42).unwrap(),
                path: GitLabProjectPath::try_from("group/project".to_owned()).unwrap(),
            },
            merge_request_iid: MergeRequestIid::try_from(7).unwrap(),
        };
        let verification =
            select_gitlab_merge_request(&repository, None, Some(&selection)).unwrap();
        assert_eq!(verification.origin, origin);
        assert_eq!(verification.project, selection.target_project);
        assert_eq!(verification.merge_request_iid, selection.merge_request_iid);
        assert!(verification.ci_hint.is_none());
    }
}
