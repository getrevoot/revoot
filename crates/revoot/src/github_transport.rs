//! Direct, bounded GitHub REST transport for pull-request review.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    HeaderMap, HeaderValue, USER_AGENT,
};
use reqwest::{Method, StatusCode, Url};
use revoot_core::{AllowedProviderEgress, CertificateAuthorityMode, EgressRouteKind};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::github_checkout::GitHubRepositorySlug;

const ADAPTER_ID: &str = "github-rest";
const MAX_TOKEN_BYTES: usize = 4_096;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_CUSTOM_CA_CERTIFICATES: usize = 64;
const MAX_CUSTOM_CA_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_CUSTOM_CA_BUNDLE_BYTES: usize = 1024 * 1024;
const USER_AGENT_VALUE: &str = concat!("revoot/", env!("CARGO_PKG_VERSION"));

pub struct GitHubToken(Box<[u8]>);

impl GitHubToken {
    /// Construct an owned, zeroized bearer credential.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, whitespace, and control-containing values.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, GitHubTransportError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || !value.iter().all(|byte| (b'!'..=b'~').contains(byte))
        {
            return Err(GitHubTransportError::INVALID_CREDENTIAL);
        }
        Ok(Self(value.into_boxed_slice()))
    }

    fn authorization(&self) -> Result<HeaderValue, GitHubTransportError> {
        let mut bytes = [0_u8; MAX_TOKEN_BYTES + 7];
        let length = self
            .0
            .len()
            .checked_add(7)
            .ok_or(GitHubTransportError::INVALID_CREDENTIAL)?;
        bytes[..7].copy_from_slice(b"Bearer ");
        bytes[7..length].copy_from_slice(&self.0);
        let result = HeaderValue::from_bytes(&bytes[..length])
            .map_err(|_| GitHubTransportError::INVALID_CREDENTIAL)
            .map(|mut value| {
                value.set_sensitive(true);
                value
            });
        bytes.fill(0);
        result
    }
}

impl Drop for GitHubToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for GitHubToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHubToken(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubCredentialSource {
    RevootToken,
    GhToken,
    ActionsToken,
}

impl GitHubCredentialSource {
    const fn name(self) -> &'static str {
        match self {
            Self::RevootToken => "REVOOT_GITHUB_TOKEN",
            Self::GhToken => "GH_TOKEN",
            Self::ActionsToken => "GITHUB_TOKEN",
        }
    }
}

/// Select a GitHub credential through deterministic environment precedence.
///
/// # Errors
///
/// Rejects duplicates, missing values, and invalid header bytes.
pub fn load_github_token(
    environment: &[(String, String)],
) -> Result<(GitHubToken, GitHubCredentialSource), GitHubTransportError> {
    let mut selected = BTreeMap::new();
    for (name, value) in environment.iter().filter(|(name, _)| {
        matches!(
            name.as_str(),
            "REVOOT_GITHUB_TOKEN" | "GH_TOKEN" | "GITHUB_TOKEN"
        )
    }) {
        if selected.insert(name.as_str(), value.as_str()).is_some() {
            return Err(GitHubTransportError::DUPLICATE_CREDENTIAL);
        }
    }
    for source in [
        GitHubCredentialSource::RevootToken,
        GitHubCredentialSource::GhToken,
        GitHubCredentialSource::ActionsToken,
    ] {
        if let Some(value) = selected
            .get(source.name())
            .filter(|value| !value.is_empty())
        {
            return Ok((GitHubToken::new(value.as_bytes().to_vec())?, source));
        }
    }
    Err(GitHubTransportError::MISSING_CREDENTIAL)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubFailureKind {
    InvalidConfiguration,
    InvalidCredential,
    MissingCredential,
    DuplicateCredential,
    Transport,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unprocessable,
    RateLimited,
    Server,
    UnexpectedStatus,
    ResponseTooLarge,
    InvalidResponse,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GitHubTransportError {
    pub kind: GitHubFailureKind,
    pub status: Option<u16>,
}

impl GitHubTransportError {
    const INVALID_CREDENTIAL: Self = Self::new(GitHubFailureKind::InvalidCredential, None);
    const MISSING_CREDENTIAL: Self = Self::new(GitHubFailureKind::MissingCredential, None);
    const DUPLICATE_CREDENTIAL: Self = Self::new(GitHubFailureKind::DuplicateCredential, None);

    const fn new(kind: GitHubFailureKind, status: Option<u16>) -> Self {
        Self { kind, status }
    }
}

impl fmt::Debug for GitHubTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubTransportError")
            .field("kind", &self.kind)
            .field("status", &self.status)
            .finish()
    }
}

impl fmt::Display for GitHubTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub REST operation failed")
    }
}

impl Error for GitHubTransportError {}

pub struct GitHubResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Exact custom roots bound to the egress policy by a deterministic digest.
pub struct GitHubCustomCaBundle {
    certificates: Vec<Vec<u8>>,
    sha256: [u8; 32],
}

impl GitHubCustomCaBundle {
    /// Construct a bounded DER bundle and verify its configured identity.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized certificates or a digest mismatch.
    pub fn from_der(
        certificates: Vec<Vec<u8>>,
        expected_sha256: [u8; 32],
    ) -> Result<Self, GitHubTransportError> {
        if certificates.is_empty() || certificates.len() > MAX_CUSTOM_CA_CERTIFICATES {
            return Err(invalid_configuration());
        }
        let mut total = 0_usize;
        let mut hasher = Sha256::new();
        for certificate in &certificates {
            if certificate.is_empty() || certificate.len() > MAX_CUSTOM_CA_CERTIFICATE_BYTES {
                return Err(invalid_configuration());
            }
            total = total
                .checked_add(certificate.len())
                .ok_or_else(invalid_configuration)?;
            if total > MAX_CUSTOM_CA_BUNDLE_BYTES {
                return Err(invalid_configuration());
            }
            let length = u64::try_from(certificate.len()).map_err(|_| invalid_configuration())?;
            hasher.update(length.to_be_bytes());
            hasher.update(certificate);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_sha256 {
            return Err(invalid_configuration());
        }
        Ok(Self {
            certificates,
            sha256: actual,
        })
    }
}

impl fmt::Debug for GitHubCustomCaBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubCustomCaBundle")
            .field("certificate_count", &self.certificates.len())
            .field("sha256", &"<redacted>")
            .finish()
    }
}

/// Explicit GitHub trust-root selection. Insecure TLS is not representable.
pub enum GitHubCaMode {
    BundledWebPki,
    CustomBundle(GitHubCustomCaBundle),
}

pub struct GitHubClient {
    http: reqwest::Client,
    api_root: Url,
    token: GitHubToken,
    #[cfg(test)]
    loopback_host: Option<HeaderValue>,
}

impl GitHubClient {
    /// Construct a direct, DNS-pinned GitHub REST client.
    ///
    /// # Errors
    ///
    /// Rejects invalid API roots, credentials, or mismatched egress authorization.
    pub fn new(
        api_root: &str,
        token: GitHubToken,
        authorization: &AllowedProviderEgress,
    ) -> Result<Self, GitHubTransportError> {
        Self::new_with_ca(api_root, token, authorization, &GitHubCaMode::BundledWebPki)
    }

    /// Construct with an explicit custom trust-root policy for Enterprise Server.
    ///
    /// # Errors
    ///
    /// Rejects invalid roots or any mismatch with the egress authorization.
    pub fn new_with_ca(
        api_root: &str,
        token: GitHubToken,
        authorization: &AllowedProviderEgress,
        ca_mode: &GitHubCaMode,
    ) -> Result<Self, GitHubTransportError> {
        let api_root = parse_api_root(api_root)?;
        validate_authorization(&api_root, authorization, ca_mode)?;
        let resolution = authorization.resolution();
        let host = api_root
            .host_str()
            .ok_or_else(invalid_configuration)?
            .to_owned();
        let port = api_root.port_or_known_default().unwrap_or(443);
        let addresses = resolution
            .pinned_addresses()
            .iter()
            .map(|address| SocketAddr::new(*address, port))
            .collect::<Vec<_>>();
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| address.ip().is_unspecified())
        {
            return Err(invalid_configuration());
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid_configuration())?;
        let roots = match ca_mode {
            GitHubCaMode::BundledWebPki => RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
            GitHubCaMode::CustomBundle(bundle) => {
                let mut roots = RootCertStore::empty();
                for certificate in &bundle.certificates {
                    roots
                        .add(CertificateDer::from(certificate.as_slice()))
                        .map_err(|_| invalid_configuration())?;
                }
                roots
            }
        };
        if roots.is_empty() {
            return Err(invalid_configuration());
        }
        let mut tls = builder.with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static("2022-11-28"),
        );
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_mins(1))
            .read_timeout(Duration::from_secs(30))
            .pool_idle_timeout(Some(Duration::from_secs(30)))
            .pool_max_idle_per_host(1)
            .http1_only();
        builder = builder.resolve_to_addrs(&host, &addresses);
        let http = builder.build().map_err(|_| invalid_configuration())?;
        Ok(Self {
            http,
            api_root,
            token,
            #[cfg(test)]
            loopback_host: None,
        })
    }

    /// Execute one bounded GET against the closed API-root/repository surface.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe transport, status, or response-bound failure.
    pub async fn get(
        &self,
        repository: Option<&GitHubRepositorySlug>,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<GitHubResponse, GitHubTransportError> {
        self.request(Method::GET, repository, segments, query, None)
            .await
    }

    /// Execute one bounded JSON POST.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe serialization, transport, status, or response failure.
    pub async fn post<T: Serialize + ?Sized>(
        &self,
        repository: &GitHubRepositorySlug,
        segments: &[&str],
        body: &T,
    ) -> Result<GitHubResponse, GitHubTransportError> {
        let body = serde_json::to_vec(body).map_err(|_| invalid_response())?;
        self.request(Method::POST, Some(repository), segments, &[], Some(body))
            .await
    }

    /// Execute one bounded JSON PATCH.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe serialization, transport, status, or response failure.
    pub async fn patch<T: Serialize + ?Sized>(
        &self,
        repository: &GitHubRepositorySlug,
        segments: &[&str],
        body: &T,
    ) -> Result<GitHubResponse, GitHubTransportError> {
        let body = serde_json::to_vec(body).map_err(|_| invalid_response())?;
        self.request(Method::PATCH, Some(repository), segments, &[], Some(body))
            .await
    }

    /// Execute one bounded GraphQL POST against the GitHub or GHES sibling endpoint.
    ///
    /// # Errors
    ///
    /// Returns the same redaction-safe transport and response failures as REST.
    pub async fn graphql<T: Serialize + ?Sized>(
        &self,
        body: &T,
    ) -> Result<GitHubResponse, GitHubTransportError> {
        let mut url = self.api_root.clone();
        url.set_path(if self.api_root.path() == "/api/v3" {
            "/api/graphql"
        } else {
            "/graphql"
        });
        let body = serde_json::to_vec(body).map_err(|_| invalid_response())?;
        self.send(Method::POST, url, Some(body)).await
    }

    async fn request(
        &self,
        method: Method,
        repository: Option<&GitHubRepositorySlug>,
        segments: &[&str],
        query: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Result<GitHubResponse, GitHubTransportError> {
        let mut url = self.api_root.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| invalid_configuration())?;
            path.pop_if_empty();
            if let Some(repository) = repository {
                path.push("repos");
                path.push(repository.owner());
                path.push(repository.repository());
            }
            for segment in segments {
                if segment.is_empty() || segment.contains(['/', '\0']) {
                    return Err(invalid_configuration());
                }
                path.push(segment);
            }
        }
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(name, value)| (*name, value.as_str())));
        }
        self.send(method, url, body).await
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
    ) -> Result<GitHubResponse, GitHubTransportError> {
        let mut request = self
            .http
            .request(method, url)
            .header(AUTHORIZATION, self.token.authorization()?);
        #[cfg(test)]
        if let Some(host) = &self.loopback_host {
            request = request.header(reqwest::header::HOST, host.clone());
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| GitHubTransportError::new(GitHubFailureKind::Transport, None))?;
        let status = response.status();
        if response
            .headers()
            .get(CONTENT_ENCODING)
            .is_some_and(|value| {
                value
                    .to_str()
                    .map_or(true, |encoding| !encoding.eq_ignore_ascii_case("identity"))
            })
        {
            return Err(invalid_response());
        }
        if response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_BODY_BYTES)
        {
            return Err(GitHubTransportError::new(
                GitHubFailureKind::ResponseTooLarge,
                Some(status.as_u16()),
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| GitHubTransportError::new(GitHubFailureKind::Transport, None))?
        {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > MAX_BODY_BYTES)
            {
                return Err(GitHubTransportError::new(
                    GitHubFailureKind::ResponseTooLarge,
                    Some(status.as_u16()),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(status_error(status));
        }
        Ok(GitHubResponse {
            status: status.as_u16(),
            body: bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_loopback(
        token: GitHubToken,
        address: SocketAddr,
    ) -> Result<Self, GitHubTransportError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid_configuration())?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(false)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| invalid_configuration())?;
        Ok(Self {
            http,
            api_root: Url::parse(&format!("http://{address}"))
                .map_err(|_| invalid_configuration())?,
            token,
            loopback_host: Some(HeaderValue::from_static("api.github.com")),
        })
    }
}

fn parse_api_root(value: &str) -> Result<Url, GitHubTransportError> {
    let url = Url::parse(value).map_err(|_| invalid_configuration())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url
            .host_str()
            .is_some_and(|host| host.parse::<IpAddr>().is_ok())
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/" | "/api/v3")
    {
        return Err(invalid_configuration());
    }
    Ok(url)
}

fn validate_authorization(
    api_root: &Url,
    authorization: &AllowedProviderEgress,
    ca_mode: &GitHubCaMode,
) -> Result<(), GitHubTransportError> {
    let ca_matches = match (ca_mode, authorization.certificate_authorities()) {
        (GitHubCaMode::BundledWebPki, CertificateAuthorityMode::BundledWebPki) => true,
        (GitHubCaMode::CustomBundle(bundle), CertificateAuthorityMode::CustomBundle { sha256 }) => {
            bundle.sha256 == *sha256
        }
        _ => false,
    };
    if authorization.adapter_id() != ADAPTER_ID
        || authorization.route_kind() != EgressRouteKind::Direct
        || !ca_matches
        || authorization.endpoint().origin().hostname().as_str()
            != api_root.host_str().unwrap_or("")
        || authorization.endpoint().origin().port()
            != api_root.port_or_known_default().unwrap_or(443)
        || authorization.endpoint().path() != api_root.path()
        || authorization.resolution().hostname().as_str() != api_root.host_str().unwrap_or("")
    {
        return Err(invalid_configuration());
    }
    Ok(())
}

fn status_error(status: StatusCode) -> GitHubTransportError {
    let kind = match status {
        StatusCode::UNAUTHORIZED => GitHubFailureKind::Unauthorized,
        StatusCode::FORBIDDEN if status.as_u16() == 403 => GitHubFailureKind::Forbidden,
        StatusCode::NOT_FOUND => GitHubFailureKind::NotFound,
        StatusCode::CONFLICT => GitHubFailureKind::Conflict,
        StatusCode::UNPROCESSABLE_ENTITY => GitHubFailureKind::Unprocessable,
        value if value == StatusCode::TOO_MANY_REQUESTS => GitHubFailureKind::RateLimited,
        value if value.is_server_error() => GitHubFailureKind::Server,
        _ => GitHubFailureKind::UnexpectedStatus,
    };
    GitHubTransportError::new(kind, Some(status.as_u16()))
}

const fn invalid_configuration() -> GitHubTransportError {
    GitHubTransportError::new(GitHubFailureKind::InvalidConfiguration, None)
}

const fn invalid_response() -> GitHubTransportError {
    GitHubTransportError::new(GitHubFailureKind::InvalidResponse, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_precedence_is_explicit_and_debug_is_redacted() {
        let (token, source) = load_github_token(&[
            ("GITHUB_TOKEN".to_owned(), "actions-secret".to_owned()),
            ("REVOOT_GITHUB_TOKEN".to_owned(), "bot-secret".to_owned()),
        ])
        .expect("credential");
        assert_eq!(source, GitHubCredentialSource::RevootToken);
        assert_eq!(format!("{token:?}"), "GitHubToken(<redacted>)");
    }

    #[test]
    fn api_roots_are_closed_to_github_shapes() {
        assert!(parse_api_root("https://api.github.com").is_ok());
        assert!(parse_api_root("https://github.acme.test/api/v3").is_ok());
        assert!(parse_api_root("http://api.github.com").is_err());
        assert!(parse_api_root("https://api.github.com/other").is_err());
    }

    #[test]
    fn custom_ca_identity_is_exact_bounded_and_redacted() {
        let certificate = vec![1, 2, 3];
        let mut hasher = Sha256::new();
        hasher.update(3_u64.to_be_bytes());
        hasher.update(&certificate);
        let digest: [u8; 32] = hasher.finalize().into();
        let bundle = GitHubCustomCaBundle::from_der(vec![certificate.clone()], digest)
            .expect("matching identity");
        let debug = format!("{bundle:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("1, 2, 3"));
        assert!(GitHubCustomCaBundle::from_der(vec![certificate], [9; 32]).is_err());
    }
}
