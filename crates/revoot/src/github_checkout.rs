//! GitHub repository discovery, Actions event classification, and head binding.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use reqwest::Url;
use revoot_core::{GitHubRepositoryId, GitSha, PullRequestNumber};
use serde::Deserialize;

use crate::embedded_git::EmbeddedRepository;

const MAX_EVENT_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitHubRepositorySlug(String);

impl GitHubRepositorySlug {
    /// Parse one exact `owner/repository` identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, or unsafe components.
    pub fn parse(value: impl Into<String>) -> Result<Self, GitHubCheckoutError> {
        let value = value.into();
        let mut parts = value.split('/');
        let (Some(owner), Some(repository), None) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(GitHubCheckoutError::InvalidRepository);
        };
        if !valid_component(owner) || !valid_component(repository) || value.len() > 256 {
            return Err(GitHubCheckoutError::InvalidRepository);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    /// Return the owner component.
    ///
    /// # Panics
    ///
    /// Cannot panic for values constructed through [`Self::parse`].
    pub fn owner(&self) -> &str {
        self.0.split_once('/').expect("validated slug").0
    }

    #[must_use]
    /// Return the repository component.
    ///
    /// # Panics
    ///
    /// Cannot panic for values constructed through [`Self::parse`].
    pub fn repository(&self) -> &str {
        self.0.split_once('/').expect("validated slug").1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubServer {
    pub web_origin: String,
    pub api_root: String,
}

impl GitHubServer {
    /// Map a canonical GitHub web origin to its REST API root.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS, credentialed, or non-origin URLs.
    pub fn from_web_origin(value: &str) -> Result<Self, GitHubCheckoutError> {
        let url = Url::parse(value).map_err(|_| GitHubCheckoutError::InvalidServer)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(GitHubCheckoutError::InvalidServer);
        }
        let host = url.host_str().ok_or(GitHubCheckoutError::InvalidServer)?;
        let port = url.port_or_known_default().unwrap_or(443);
        let authority = if port == 443 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        let web_origin = format!("https://{authority}");
        let api_root = if host.eq_ignore_ascii_case("github.com") && port == 443 {
            "https://api.github.com".to_owned()
        } else {
            format!("{web_origin}/api/v3")
        };
        Ok(Self {
            web_origin,
            api_root,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredGitHubRemote {
    pub name: String,
    pub server: GitHubServer,
    pub repository: GitHubRepositorySlug,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredGitHubRepository {
    pub root: PathBuf,
    pub head_sha: GitSha,
    pub remote: DiscoveredGitHubRemote,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubCiContext {
    pub server: GitHubServer,
    pub target_repository: GitHubRepositorySlug,
    pub target_repository_id: GitHubRepositoryId,
    pub source_repository: GitHubRepositorySlug,
    pub pull_request_number: PullRequestNumber,
    pub base_sha: GitSha,
    pub head_sha: GitSha,
    pub fork: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubCheckoutError {
    NotRepository,
    InvalidHead,
    NoRemote,
    AmbiguousRemote,
    UnsupportedRemote,
    InvalidRepository,
    InvalidServer,
    MissingActionsContext,
    UnsupportedActionsEvent,
    EventUnavailable,
    EventTooLarge,
    InvalidEvent,
    ContextMismatch,
    CheckoutHeadMismatch,
}

impl fmt::Display for GitHubCheckoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotRepository => "the checkout is not a Git repository",
            Self::InvalidHead => "the checkout HEAD is not a full Git object ID",
            Self::NoRemote => "the checkout has no supported GitHub remote",
            Self::AmbiguousRemote => "the checkout has multiple possible GitHub remotes",
            Self::UnsupportedRemote => "the Git remote is not a supported GitHub URL",
            Self::InvalidRepository => "the GitHub owner/repository identity is invalid",
            Self::InvalidServer => "the GitHub server origin is invalid",
            Self::MissingActionsContext => "GitHub Actions pull-request context is unavailable",
            Self::UnsupportedActionsEvent => "the GitHub Actions event is not a pull request",
            Self::EventUnavailable => "the GitHub Actions event payload is unavailable",
            Self::EventTooLarge => "the GitHub Actions event payload exceeds the limit",
            Self::InvalidEvent => "the GitHub Actions event payload is invalid",
            Self::ContextMismatch => "the checkout and GitHub Actions context disagree",
            Self::CheckoutHeadMismatch => "checkout HEAD does not match the pull-request head",
        })
    }
}

impl Error for GitHubCheckoutError {}

/// Load a bounded pull-request identity from the GitHub Actions event file.
///
/// # Errors
///
/// Rejects duplicate/missing variables, unsupported events, and invalid payloads.
pub fn classify_github_actions(
    environment: &[(String, String)],
) -> Result<Option<GitHubCiContext>, GitHubCheckoutError> {
    let values = unique_environment(environment)?;
    if values.get("GITHUB_ACTIONS").map(String::as_str) != Some("true") {
        return Ok(None);
    }
    let event_name = values
        .get("GITHUB_EVENT_NAME")
        .ok_or(GitHubCheckoutError::MissingActionsContext)?;
    if event_name != "pull_request" {
        return Err(GitHubCheckoutError::UnsupportedActionsEvent);
    }
    let event_path = values
        .get("GITHUB_EVENT_PATH")
        .ok_or(GitHubCheckoutError::MissingActionsContext)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(event_path)
        .map_err(|_| GitHubCheckoutError::EventUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| GitHubCheckoutError::EventUnavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_EVENT_BYTES {
        return Err(GitHubCheckoutError::EventTooLarge);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_EVENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| GitHubCheckoutError::EventUnavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_EVENT_BYTES {
        return Err(GitHubCheckoutError::EventTooLarge);
    }
    parse_github_event(&bytes, values.get("GITHUB_SERVER_URL").map(String::as_str)).map(Some)
}

/// Parse the selected identity fields from one bounded Actions event payload.
///
/// # Errors
///
/// Rejects malformed or contradictory repository and pull-request identities.
pub fn parse_github_event(
    bytes: &[u8],
    server_url: Option<&str>,
) -> Result<GitHubCiContext, GitHubCheckoutError> {
    if bytes.len() as u64 > MAX_EVENT_BYTES {
        return Err(GitHubCheckoutError::EventTooLarge);
    }
    let event: PullRequestEvent =
        serde_json::from_slice(bytes).map_err(|_| GitHubCheckoutError::InvalidEvent)?;
    if event.action.is_empty() || event.pull_request.state != "open" {
        return Err(GitHubCheckoutError::InvalidEvent);
    }
    let target_repository = GitHubRepositorySlug::parse(event.repository.full_name)?;
    let source_repository = GitHubRepositorySlug::parse(event.pull_request.head.repo.full_name)?;
    let target_from_pr = GitHubRepositorySlug::parse(event.pull_request.base.repo.full_name)?;
    if target_repository != target_from_pr
        || event.repository.id != event.pull_request.base.repo.id
        || event.number != event.pull_request.number
    {
        return Err(GitHubCheckoutError::ContextMismatch);
    }
    let server = GitHubServer::from_web_origin(server_url.unwrap_or("https://github.com"))?;
    Ok(GitHubCiContext {
        server,
        target_repository,
        target_repository_id: GitHubRepositoryId::try_from(event.repository.id)
            .map_err(|_| GitHubCheckoutError::InvalidEvent)?,
        source_repository,
        pull_request_number: PullRequestNumber::try_from(event.number)
            .map_err(|_| GitHubCheckoutError::InvalidEvent)?,
        base_sha: GitSha::try_from(event.pull_request.base.sha)
            .map_err(|_| GitHubCheckoutError::InvalidEvent)?,
        head_sha: GitSha::try_from(event.pull_request.head.sha)
            .map_err(|_| GitHubCheckoutError::InvalidEvent)?,
        fork: event.pull_request.head.repo.id != event.pull_request.base.repo.id,
    })
}

/// Discover a Git checkout, exact HEAD, and unambiguous GitHub remote.
///
/// # Errors
///
/// Rejects unavailable Git metadata and unsupported or ambiguous remotes.
pub fn discover_github_repository(
    start: &Path,
    expected_server: Option<&GitHubServer>,
) -> Result<DiscoveredGitHubRepository, GitHubCheckoutError> {
    let repository =
        EmbeddedRepository::discover(start).map_err(|_| GitHubCheckoutError::NotRepository)?;
    let root = repository.root().to_path_buf();
    let head_sha = repository
        .head()
        .map_err(|_| GitHubCheckoutError::InvalidHead)?;
    let mut remotes = BTreeMap::new();
    for (name, value) in repository
        .remote_urls()
        .map_err(|_| GitHubCheckoutError::NotRepository)?
    {
        if !valid_remote_name(&name) {
            return Err(GitHubCheckoutError::UnsupportedRemote);
        }
        if let Ok((server, repository)) = parse_github_remote(&value, expected_server) {
            remotes.insert(
                name.clone(),
                DiscoveredGitHubRemote {
                    name,
                    server,
                    repository,
                },
            );
        }
    }
    let remote = if let Some(origin) = remotes.remove("origin") {
        origin
    } else {
        let mut values = remotes.into_values();
        let first = values.next().ok_or(GitHubCheckoutError::NoRemote)?;
        if values.any(|candidate| {
            candidate.server != first.server || candidate.repository != first.repository
        }) {
            return Err(GitHubCheckoutError::AmbiguousRemote);
        }
        first
    };
    Ok(DiscoveredGitHubRepository {
        root,
        head_sha,
        remote,
    })
}

/// Bind the checked-out HEAD and target remote to Actions context.
///
/// # Errors
///
/// Rejects any head, server, or repository mismatch.
pub fn bind_github_checkout(
    repository: DiscoveredGitHubRepository,
    context: &GitHubCiContext,
) -> Result<DiscoveredGitHubRepository, GitHubCheckoutError> {
    if repository.head_sha != context.head_sha
        || repository.remote.server != context.server
        || repository.remote.repository != context.target_repository
    {
        return Err(GitHubCheckoutError::CheckoutHeadMismatch);
    }
    Ok(repository)
}

/// Parse a public GitHub or explicitly selected Enterprise remote.
///
/// # Errors
///
/// Rejects credentials, malformed paths, and unselected arbitrary hosts.
pub fn parse_github_remote(
    value: &str,
    expected_server: Option<&GitHubServer>,
) -> Result<(GitHubServer, GitHubRepositorySlug), GitHubCheckoutError> {
    if value.is_empty() || value.len() > 8 * 1024 || value.contains(['\n', '\r', '\0']) {
        return Err(GitHubCheckoutError::UnsupportedRemote);
    }
    let (host, path) = if value.starts_with("https://") || value.starts_with("ssh://") {
        let url = Url::parse(value).map_err(|_| GitHubCheckoutError::UnsupportedRemote)?;
        if url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            return Err(GitHubCheckoutError::UnsupportedRemote);
        }
        if url.scheme() == "https" && !url.username().is_empty() {
            return Err(GitHubCheckoutError::UnsupportedRemote);
        }
        if url.scheme() == "ssh" && url.username() != "git" {
            return Err(GitHubCheckoutError::UnsupportedRemote);
        }
        (
            url.host_str()
                .ok_or(GitHubCheckoutError::UnsupportedRemote)?
                .to_owned(),
            url.path().to_owned(),
        )
    } else {
        let rest = value
            .strip_prefix("git@")
            .ok_or(GitHubCheckoutError::UnsupportedRemote)?;
        let (host, path) = rest
            .split_once(':')
            .ok_or(GitHubCheckoutError::UnsupportedRemote)?;
        (host.to_owned(), path.to_owned())
    };
    let server = if let Some(expected) = expected_server {
        let expected_host = Url::parse(&expected.web_origin)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or(GitHubCheckoutError::InvalidServer)?;
        if !host.eq_ignore_ascii_case(&expected_host) {
            return Err(GitHubCheckoutError::UnsupportedRemote);
        }
        expected.clone()
    } else if host.eq_ignore_ascii_case("github.com") {
        GitHubServer::from_web_origin("https://github.com")?
    } else {
        return Err(GitHubCheckoutError::UnsupportedRemote);
    };
    let repository = path
        .trim_start_matches('/')
        .strip_suffix(".git")
        .unwrap_or_else(|| path.trim_start_matches('/'));
    Ok((server, GitHubRepositorySlug::parse(repository.to_owned())?))
}

fn unique_environment(
    environment: &[(String, String)],
) -> Result<BTreeMap<String, String>, GitHubCheckoutError> {
    let mut selected = BTreeMap::new();
    for (name, value) in environment.iter().filter(|(name, _)| {
        matches!(
            name.as_str(),
            "GITHUB_ACTIONS" | "GITHUB_EVENT_NAME" | "GITHUB_EVENT_PATH" | "GITHUB_SERVER_URL"
        )
    }) {
        if selected.insert(name.clone(), value.clone()).is_some() {
            return Err(GitHubCheckoutError::ContextMismatch);
        }
    }
    Ok(selected)
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_remote_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Deserialize)]
struct PullRequestEvent {
    action: String,
    number: u64,
    pull_request: EventPullRequest,
    repository: EventRepository,
}

#[derive(Deserialize)]
struct EventPullRequest {
    number: u64,
    state: String,
    base: EventBranch,
    head: EventBranch,
}

#[derive(Deserialize)]
struct EventBranch {
    sha: String,
    repo: EventRepository,
}

#[derive(Deserialize)]
struct EventRepository {
    id: u64,
    full_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_public_and_enterprise_remotes_without_confusing_arbitrary_hosts() {
        let (server, repository) =
            parse_github_remote("git@github.com:acme/widgets.git", None).expect("github remote");
        assert_eq!(server.api_root, "https://api.github.com");
        assert_eq!(repository.as_str(), "acme/widgets");
        assert!(parse_github_remote("git@gitlab.example:acme/widgets.git", None).is_err());

        let enterprise = GitHubServer::from_web_origin("https://github.acme.test").unwrap();
        let (_, repository) = parse_github_remote(
            "ssh://git@github.acme.test/acme/widgets.git",
            Some(&enterprise),
        )
        .expect("enterprise remote");
        assert_eq!(repository.as_str(), "acme/widgets");
    }

    #[test]
    fn event_identity_is_strict_and_classifies_forks() {
        let event = br#"{
          "action":"synchronize","number":7,
          "pull_request":{"number":7,"state":"open",
            "base":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"id":42,"full_name":"acme/widgets"}},
            "head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"id":99,"full_name":"contributor/widgets"}}},
          "repository":{"id":42,"full_name":"acme/widgets"}
        }"#;
        let context = parse_github_event(event, Some("https://github.com")).expect("event");
        assert!(context.fork);
        assert_eq!(context.pull_request_number.get(), 7);
        assert_eq!(context.target_repository.as_str(), "acme/widgets");
    }
}
