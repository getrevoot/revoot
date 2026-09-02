//! Direct model-provider adapters.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap,
    HeaderValue, USER_AGENT,
};
use reqwest::{StatusCode, Url};
use revoot_core::provider::{CancellationToken, ProviderError, ProviderErrorKind};
use revoot_core::{AllowedProviderEgress, CertificateAuthorityMode, EgressRouteKind};
use rustls::{ClientConfig, RootCertStore};
use tokio::time::{Instant, sleep, timeout_at};

pub mod anthropic;
pub mod openai;

const USER_AGENT_VALUE: &str = concat!("revoot/", env!("CARGO_PKG_VERSION"));
const MAX_CREDENTIAL_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderHttpLimits {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub read_idle_timeout: Duration,
    pub max_response_body_bytes: usize,
    pub max_response_headers: usize,
    pub max_response_header_bytes: usize,
}

impl Default for ProviderHttpLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_mins(2),
            read_idle_timeout: Duration::from_secs(30),
            max_response_body_bytes: 4 * 1024 * 1024,
            max_response_headers: 64,
            max_response_header_bytes: 32 * 1024,
        }
    }
}

impl ProviderHttpLimits {
    fn valid(self) -> bool {
        !self.connect_timeout.is_zero()
            && !self.request_timeout.is_zero()
            && !self.read_idle_timeout.is_zero()
            && (1..=16 * 1024 * 1024).contains(&self.max_response_body_bytes)
            && (1..=256).contains(&self.max_response_headers)
            && (1..=256 * 1024).contains(&self.max_response_header_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderBuildError {
    InvalidCredential,
    InvalidLimits,
    WrongAdapter,
    WrongRoute,
    UnsupportedCertificateAuthorities,
    InvalidEndpoint,
    DnsPinMismatch,
    HttpClientConfiguration,
}

impl fmt::Display for ProviderBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "provider adapter configuration failed: {self:?}")
    }
}

impl std::error::Error for ProviderBuildError {}

/// Secret API key whose debug surface and destructor never expose the value.
pub struct ApiKey(Vec<u8>);

impl ApiKey {
    /// Copy a validated credential into adapter-owned memory.
    ///
    /// # Errors
    ///
    /// Rejects empty, overlong, or HTTP-header-unsafe credentials.
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, ProviderBuildError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_CREDENTIAL_BYTES
            || value
                .iter()
                .any(|byte| byte.is_ascii_control() || *byte > 0x7e)
        {
            return Err(ProviderBuildError::InvalidCredential);
        }
        Ok(Self(value.to_vec()))
    }

    fn header_value(&self, prefix: &[u8]) -> Result<HeaderValue, ProviderBuildError> {
        let mut encoded = Vec::with_capacity(prefix.len() + self.0.len());
        encoded.extend_from_slice(prefix);
        encoded.extend_from_slice(&self.0);
        let result = HeaderValue::from_bytes(&encoded);
        encoded.fill(0);
        let mut header = result.map_err(|_| ProviderBuildError::InvalidCredential)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey(<redacted>)")
    }
}

impl Drop for ApiKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub(crate) struct DirectHttp {
    client: reqwest::Client,
    endpoint: Url,
    limits: ProviderHttpLimits,
}

pub(crate) struct HttpResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl DirectHttp {
    pub(crate) fn build(
        expected_adapter: &str,
        authorization: &AllowedProviderEgress,
        limits: ProviderHttpLimits,
    ) -> Result<Self, ProviderBuildError> {
        if authorization.adapter_id() != expected_adapter {
            return Err(ProviderBuildError::WrongAdapter);
        }
        if authorization.route_kind() != EgressRouteKind::Direct {
            return Err(ProviderBuildError::WrongRoute);
        }
        if authorization.certificate_authorities() != &CertificateAuthorityMode::BundledWebPki {
            return Err(ProviderBuildError::UnsupportedCertificateAuthorities);
        }
        if !limits.valid() {
            return Err(ProviderBuildError::InvalidLimits);
        }

        let authorized = authorization.endpoint();
        let hostname = authorized.origin().hostname().as_str();
        let port = authorized.origin().port();
        let authority = if port == 443 {
            hostname.to_owned()
        } else {
            format!("{hostname}:{port}")
        };
        let endpoint = Url::parse(&format!("https://{authority}{}", authorized.path()))
            .map_err(|_| ProviderBuildError::InvalidEndpoint)?;
        let pins: Vec<_> = authorization
            .resolution()
            .pinned_addresses()
            .iter()
            .map(|address| SocketAddr::new(*address, port))
            .collect();
        if pins.is_empty() || pins.iter().any(|address| address.ip().is_unspecified()) {
            return Err(ProviderBuildError::DnsPinMismatch);
        }

        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| ProviderBuildError::HttpClientConfiguration)?;
        let mut tls = builder.with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        default_headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .default_headers(default_headers)
            .connect_timeout(limits.connect_timeout)
            .timeout(limits.request_timeout)
            .read_timeout(limits.read_idle_timeout)
            .pool_max_idle_per_host(1)
            .http1_only()
            .resolve_to_addrs(hostname, &pins)
            .build()
            .map_err(|_| ProviderBuildError::HttpClientConfiguration)?;

        Ok(Self {
            client,
            endpoint,
            limits,
        })
    }

    pub(crate) async fn post_json(
        &self,
        headers: HeaderMap,
        body: Vec<u8>,
        cancellation: &CancellationToken,
    ) -> Result<HttpResponse, ProviderError> {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let request = self
            .client
            .post(self.endpoint.clone())
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body);
        let deadline = Instant::now() + self.limits.request_timeout;
        let response = tokio::select! {
            result = timeout_at(deadline, request.send()) => {
                match result {
                    Ok(Ok(response)) => response,
                    Ok(Err(_)) => return Err(ProviderError::new(ProviderErrorKind::Unavailable, None, true)),
                    Err(_) => return Err(ProviderError::new(ProviderErrorKind::Timeout, None, true)),
                }
            }
            () = wait_for_cancellation(cancellation) => return Err(cancelled()),
        };
        let expected_length = validate_headers(response.headers(), self.limits)?;
        let status = response.status();
        if !status.is_success() {
            return Err(classify_status(status));
        }
        validate_json_content_type(response.headers())?;

        let mut response = response;
        let mut body = Vec::new();
        loop {
            let chunk = tokio::select! {
                result = timeout_at(deadline, response.chunk()) => {
                    match result {
                        Ok(Ok(chunk)) => chunk,
                        Ok(Err(_)) => return Err(ProviderError::new(ProviderErrorKind::Unavailable, None, true)),
                        Err(_) => return Err(ProviderError::new(ProviderErrorKind::Timeout, None, true)),
                    }
                }
                () = wait_for_cancellation(cancellation) => return Err(cancelled()),
            };
            let Some(chunk) = chunk else { break };
            append_bounded_body(&mut body, &chunk, self.limits.max_response_body_bytes)?;
        }
        if expected_length.is_some_and(|expected| expected != body.len()) {
            return Err(json_error());
        }
        Ok(HttpResponse { status, body })
    }
}

fn append_bounded_body(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
) -> Result<(), ProviderError> {
    let next = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(response_too_large)?;
    if next > max_bytes {
        return Err(response_too_large());
    }
    body.extend_from_slice(chunk);
    Ok(())
}

async fn wait_for_cancellation(cancellation: &CancellationToken) {
    while !cancellation.is_cancelled() {
        sleep(Duration::from_millis(10)).await;
    }
}

fn validate_headers(
    headers: &HeaderMap,
    limits: ProviderHttpLimits,
) -> Result<Option<usize>, ProviderError> {
    if headers.len() > limits.max_response_headers {
        return Err(ProviderError::new(ProviderErrorKind::Protocol, None, false));
    }
    let bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total.checked_add(name.as_str().len() + value.as_bytes().len())
    });
    if bytes.is_none_or(|bytes| bytes > limits.max_response_header_bytes) {
        return Err(ProviderError::new(ProviderErrorKind::Protocol, None, false));
    }
    if headers
        .get(CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(ProviderError::new(ProviderErrorKind::Protocol, None, false));
    }
    let lengths = headers.get_all(CONTENT_LENGTH);
    let mut lengths = lengths.iter();
    let content_length = match (lengths.next(), lengths.next()) {
        (None, None) => None,
        (Some(value), None) => Some(
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(json_error)?,
        ),
        _ => return Err(json_error()),
    };
    if content_length.is_some_and(|length| length > limits.max_response_body_bytes) {
        return Err(response_too_large());
    }
    Ok(content_length)
}

fn validate_json_content_type(headers: &HeaderMap) -> Result<(), ProviderError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(json_error)?;
    let mime = content_type
        .split_once(';')
        .map_or(content_type, |(mime, _)| mime)
        .trim();
    if mime.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(json_error())
    }
}

fn classify_status(status: StatusCode) -> ProviderError {
    let code = status.as_u16();
    let (kind, retryable) = match code {
        401 => (ProviderErrorKind::Authentication, false),
        403 => (ProviderErrorKind::PermissionDenied, false),
        408 => (ProviderErrorKind::Timeout, true),
        429 => (ProviderErrorKind::RateLimited, true),
        500..=599 => (ProviderErrorKind::Unavailable, true),
        _ => (ProviderErrorKind::InvalidRequest, false),
    };
    ProviderError::new(kind, Some(code), retryable)
}

fn cancelled() -> ProviderError {
    ProviderError::new(ProviderErrorKind::Cancelled, None, false)
}

fn response_too_large() -> ProviderError {
    ProviderError::new(ProviderErrorKind::ResponseTooLarge, None, false)
}

pub(crate) fn json_error() -> ProviderError {
    ProviderError::new(ProviderErrorKind::Protocol, None, false)
}

pub(crate) fn credential_header(
    credential: &ApiKey,
    prefix: &[u8],
) -> Result<HeaderValue, ProviderBuildError> {
    credential.header_value(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_debug_is_redacted() {
        let key = ApiKey::new("top-secret-value").expect("valid key");
        assert_eq!(format!("{key:?}"), "ApiKey(<redacted>)");
        assert!(!format!("{key:?}").contains("top-secret"));
    }

    #[test]
    fn credential_rejects_header_injection() {
        assert_eq!(
            ApiKey::new("secret\r\nx-injected: yes").expect_err("must reject"),
            ProviderBuildError::InvalidCredential
        );
    }

    #[test]
    fn status_errors_are_payload_free_and_classified() {
        let error = classify_status(StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.kind(), ProviderErrorKind::RateLimited);
        assert!(error.retryable());
        assert_eq!(error.status_code(), Some(429));
    }

    #[test]
    fn response_metadata_is_strictly_bounded() {
        let limits = ProviderHttpLimits::default();
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("12"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert_eq!(validate_headers(&headers, limits), Ok(Some(12)));
        assert_eq!(validate_json_content_type(&headers), Ok(()));

        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("not-a-number"));
        assert_eq!(
            validate_headers(&headers, limits)
                .expect_err("invalid length")
                .kind(),
            ProviderErrorKind::Protocol
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        assert_eq!(
            validate_json_content_type(&headers)
                .expect_err("invalid media type")
                .kind(),
            ProviderErrorKind::Protocol
        );
    }

    #[test]
    fn oversized_and_ambiguous_response_metadata_fail_payload_free() {
        let limits = ProviderHttpLimits {
            max_response_body_bytes: 16,
            max_response_headers: 2,
            max_response_header_bytes: 128,
            ..ProviderHttpLimits::default()
        };
        let mut oversized = HeaderMap::new();
        oversized.insert(CONTENT_LENGTH, HeaderValue::from_static("17"));
        let error = validate_headers(&oversized, limits).expect_err("body limit");
        assert_eq!(error.kind(), ProviderErrorKind::ResponseTooLarge);

        let mut excessive = HeaderMap::new();
        excessive.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        excessive.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        excessive.insert("x-extra", HeaderValue::from_static("SENSITIVE_MARKER"));
        let error = validate_headers(&excessive, limits).expect_err("header count");
        assert_eq!(error.kind(), ProviderErrorKind::Protocol);
        assert!(!format!("{error:?}").contains("SENSITIVE_MARKER"));

        let mut ambiguous = HeaderMap::new();
        ambiguous.append(CONTENT_LENGTH, HeaderValue::from_static("1"));
        ambiguous.append(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert_eq!(
            validate_headers(&ambiguous, limits)
                .expect_err("duplicate content lengths")
                .kind(),
            ProviderErrorKind::Protocol
        );
    }

    #[test]
    fn chunked_response_body_is_bounded_without_content_length() {
        let mut body = Vec::new();
        append_bounded_body(&mut body, b"12345678", 12).expect("first chunk");
        let error = append_bounded_body(&mut body, b"SENSITIVE", 12).expect_err("body limit");
        assert_eq!(error.kind(), ProviderErrorKind::ResponseTooLarge);
        assert_eq!(body, b"12345678");
        assert!(!format!("{error:?}").contains("SENSITIVE"));
    }

    #[test]
    fn timeout_cancellation_and_response_loss_are_classified_without_payloads() {
        let timeout = classify_status(StatusCode::REQUEST_TIMEOUT);
        assert_eq!(timeout.kind(), ProviderErrorKind::Timeout);
        assert!(timeout.retryable());

        let cancellation = cancelled();
        assert_eq!(cancellation.kind(), ProviderErrorKind::Cancelled);
        assert!(!cancellation.retryable());

        // A transport loss after dispatch cannot prove whether the provider
        // accepted the request. It is retryable but carries no response body;
        // the engine conservatively settles the corresponding reservation.
        let response_loss = ProviderError::new(ProviderErrorKind::Unavailable, None, true);
        assert!(response_loss.retryable());
        assert_eq!(response_loss.status_code(), None);
        assert_eq!(
            response_loss.to_string(),
            "provider request failed: Unavailable"
        );
    }
}
