//! Direct model-provider adapters.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap,
    HeaderValue, USER_AGENT,
};
use reqwest::{StatusCode, Url};
use revoot_core::provider::{CancellationToken, ProviderError, ProviderErrorKind};
use revoot_core::{AllowedProviderEgress, CertificateAuthorityMode, EgressRouteKind};
use rustls::{ClientConfig, RootCertStore};
use tokio::time::{Instant, sleep, timeout_at};

use crate::retry::{RetryJitter, RetryPolicy, retry_after};

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
    /// Total attempts for one logical model request, including the first.
    pub retry_max_attempts: u8,
    pub retry_initial_delay: Duration,
    pub retry_max_delay: Duration,
    pub retry_total_budget: Duration,
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
            retry_max_attempts: 4,
            retry_initial_delay: Duration::from_secs(1),
            retry_max_delay: Duration::from_secs(30),
            retry_total_budget: Duration::from_mins(1),
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
            && self.retry_policy().valid()
            && self.retry_max_attempts <= 16
            && self.retry_max_delay <= Duration::from_mins(5)
            && self.retry_total_budget <= self.request_timeout
    }

    const fn retry_policy(self) -> RetryPolicy {
        RetryPolicy {
            max_attempts: self.retry_max_attempts,
            initial_delay: self.retry_initial_delay,
            max_delay: self.retry_max_delay,
            max_retry_after: self.retry_max_delay,
            total_budget: self.retry_total_budget,
        }
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
    adapter_id: &'static str,
}

pub(crate) struct HttpResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl DirectHttp {
    pub(crate) fn build(
        expected_adapter: &'static str,
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
            adapter_id: expected_adapter,
        })
    }

    pub(crate) async fn post_json(
        &self,
        headers: HeaderMap,
        body: Vec<u8>,
        cancellation: &CancellationToken,
    ) -> Result<HttpResponse, ProviderError> {
        let policy = self.limits.retry_policy();
        let started = Instant::now();
        let request_deadline = started + self.limits.request_timeout;
        let retry_deadline = started + policy.total_budget;
        let mut jitter = RetryJitter::for_operation();
        for attempt in 1..=policy.max_attempts {
            if cancellation.is_cancelled() {
                return Err(cancelled());
            }
            if Instant::now() >= request_deadline {
                return Err(ProviderError::new(ProviderErrorKind::Timeout, None, false));
            }
            let result = self
                .send_once(
                    headers.clone(),
                    body.clone(),
                    cancellation,
                    request_deadline,
                )
                .await;
            let error = match result {
                Ok(response) => return Ok(response),
                Err(error) => error,
            };
            if !error.retryable() || attempt == policy.max_attempts {
                if error.cost_ambiguous() {
                    eprintln!(
                        "revoot: provider={} operation=model_request attempt={} retry_reason={:?} outcome=terminal cost_ambiguous=true",
                        self.adapter_id,
                        attempt,
                        error.kind()
                    );
                }
                return Err(error);
            }
            let delay = policy.delay(attempt, error.retry_after(), &mut jitter);
            let now = Instant::now();
            let Some(wake) = now.checked_add(delay) else {
                return Err(error);
            };
            if wake > retry_deadline || wake >= request_deadline {
                return Err(error);
            }
            eprintln!(
                "revoot: provider={} operation=model_request attempt={} retry_reason={:?} delay_ms={} outcome=retrying",
                self.adapter_id,
                attempt,
                error.kind(),
                delay.as_millis()
            );
            tokio::select! {
                () = sleep(delay) => {}
                () = wait_for_cancellation(cancellation) => return Err(cancelled()),
            }
        }
        unreachable!("validated retry policy always performs at least one attempt")
    }

    async fn send_once(
        &self,
        headers: HeaderMap,
        body: Vec<u8>,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> Result<HttpResponse, ProviderError> {
        let request = self
            .client
            .post(self.endpoint.clone())
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body);
        let mut response = tokio::select! {
            result = timeout_at(deadline, request.send()) => {
                match result {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => return Err(classify_send_error(&error)),
                    Err(_) => return Err(ProviderError::new(ProviderErrorKind::Timeout, None, false).with_cost_ambiguous()),
                }
            }
            () = wait_for_cancellation(cancellation) => return Err(cancelled()),
        };
        let expected_length = validate_headers(response.headers(), self.limits)?;
        let status = response.status();
        if !status.is_success() {
            let retry_after = retry_after(response.headers(), SystemTime::now());
            let permanent_quota = if status == StatusCode::TOO_MANY_REQUESTS {
                collect_body(
                    &mut response,
                    self.limits.max_response_body_bytes,
                    deadline,
                    cancellation,
                    false,
                )
                .await
                .is_ok_and(|body| permanent_quota_error(&body))
            } else {
                false
            };
            return Err(classify_status(status, permanent_quota).with_retry_after(retry_after));
        }
        validate_json_content_type(response.headers())?;
        let body = collect_body(
            &mut response,
            self.limits.max_response_body_bytes,
            deadline,
            cancellation,
            true,
        )
        .await?;
        if expected_length.is_some_and(|expected| expected != body.len()) {
            return Err(json_error().with_cost_ambiguous());
        }
        Ok(HttpResponse { status, body })
    }

    #[cfg(test)]
    fn new_for_loopback(
        adapter_id: &'static str,
        address: SocketAddr,
        limits: ProviderHttpLimits,
    ) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(false)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .expect("loopback client");
        Self {
            client,
            endpoint: Url::parse(&format!("http://{address}/v1/messages")).unwrap(),
            limits,
            adapter_id,
        }
    }
}

async fn collect_body(
    response: &mut reqwest::Response,
    max_bytes: usize,
    deadline: Instant,
    cancellation: &CancellationToken,
    accepted_model_request: bool,
) -> Result<Vec<u8>, ProviderError> {
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {
            result = timeout_at(deadline, response.chunk()) => {
                match result {
                    Ok(Ok(chunk)) => chunk,
                    Ok(Err(_)) => {
                        let error = ProviderError::new(ProviderErrorKind::Unavailable, None, !accepted_model_request);
                        return Err(if accepted_model_request { error.with_cost_ambiguous() } else { error });
                    }
                    Err(_) => {
                        let error = ProviderError::new(ProviderErrorKind::Timeout, None, !accepted_model_request);
                        return Err(if accepted_model_request { error.with_cost_ambiguous() } else { error });
                    }
                }
            }
            () = wait_for_cancellation(cancellation) => return Err(cancelled()),
        };
        let Some(chunk) = chunk else { break };
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(response_too_large)?;
        if next > max_bytes {
            return Err(response_too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn classify_send_error(error: &reqwest::Error) -> ProviderError {
    let kind = if error.is_timeout() {
        ProviderErrorKind::Timeout
    } else {
        ProviderErrorKind::Unavailable
    };
    // Only connection-establishment failures prove the provider did not accept
    // the model request. Other send failures are cost-ambiguous and terminal.
    let failure = ProviderError::new(kind, None, error.is_connect());
    if error.is_connect() {
        failure
    } else {
        failure.with_cost_ambiguous()
    }
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

fn classify_status(status: StatusCode, permanent_quota: bool) -> ProviderError {
    let code = status.as_u16();
    let (kind, retryable) = match code {
        401 => (ProviderErrorKind::Authentication, false),
        403 => (ProviderErrorKind::PermissionDenied, false),
        408 => (ProviderErrorKind::Timeout, false),
        429 => (ProviderErrorKind::RateLimited, !permanent_quota),
        500..=599 => (ProviderErrorKind::Unavailable, false),
        _ => (ProviderErrorKind::InvalidRequest, false),
    };
    let error = ProviderError::new(kind, Some(code), retryable);
    if code == 408 || (500..=599).contains(&code) {
        error.with_cost_ambiguous()
    } else {
        error
    }
}

fn permanent_quota_error(body: &[u8]) -> bool {
    const PERMANENT_CODES: [&str; 4] = [
        "insufficient_quota",
        "billing_hard_limit_reached",
        "billing_not_active",
        "credit_balance_too_low",
    ];
    fn contains(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(value) => PERMANENT_CODES.contains(&value.as_str()),
            serde_json::Value::Array(values) => values.iter().any(contains),
            serde_json::Value::Object(values) => values.values().any(contains),
            _ => false,
        }
    }
    serde_json::from_slice(body).is_ok_and(|value| contains(&value))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_limits() -> ProviderHttpLimits {
        ProviderHttpLimits {
            request_timeout: Duration::from_secs(10),
            retry_initial_delay: Duration::from_millis(10),
            retry_max_delay: Duration::from_millis(20),
            retry_total_budget: Duration::from_secs(1),
            ..ProviderHttpLimits::default()
        }
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) {
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&chunk[..read]);
            let Some(head_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let head = std::str::from_utf8(&bytes[..head_end]).unwrap();
            let content_length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= head_end + 4 + content_length {
                return;
            }
        }
    }

    async fn write_response(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        extra: &str,
        body: &[u8],
    ) {
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    }

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
        let error = classify_status(StatusCode::TOO_MANY_REQUESTS, false);
        assert_eq!(error.kind(), ProviderErrorKind::RateLimited);
        assert!(error.retryable());
        assert_eq!(error.status_code(), Some(429));
        let timeout = classify_status(StatusCode::REQUEST_TIMEOUT, false);
        assert!(!timeout.retryable());
        assert!(timeout.cost_ambiguous());
        let unavailable = classify_status(StatusCode::SERVICE_UNAVAILABLE, false);
        assert!(!unavailable.retryable());
        assert!(unavailable.cost_ambiguous());
        assert!(!classify_status(StatusCode::NOT_IMPLEMENTED, false).retryable());
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

    #[tokio::test(start_paused = true)]
    async fn retries_transient_429_then_succeeds_with_one_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (status, extra) in [
                ("429 Too Many Requests", "Retry-After: 0\r\n"),
                ("429 Too Many Requests", ""),
                ("200 OK", ""),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                write_response(&mut stream, status, extra, b"{}").await;
            }
        });
        let http = DirectHttp::new_for_loopback("fixture", address, test_limits());
        let response = http
            .post_json(
                HeaderMap::new(),
                b"{}".to_vec(),
                &CancellationToken::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn received_408_is_cost_ambiguous_and_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            write_response(&mut stream, "408 Request Timeout", "", b"{}").await;
        });
        let http = DirectHttp::new_for_loopback("fixture", address, test_limits());
        let result = http
            .post_json(
                HeaderMap::new(),
                b"{}".to_vec(),
                &CancellationToken::default(),
            )
            .await;
        let Err(error) = result else {
            panic!("408 response must be terminal")
        };
        assert_eq!(error.kind(), ProviderErrorKind::Timeout);
        assert!(!error.retryable());
        assert!(error.cost_ambiguous());
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn received_503_is_cost_ambiguous_and_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            write_response(&mut stream, "503 Service Unavailable", "", b"{}").await;
        });
        let http = DirectHttp::new_for_loopback("fixture", address, test_limits());
        let result = http
            .post_json(
                HeaderMap::new(),
                b"{}".to_vec(),
                &CancellationToken::default(),
            )
            .await;
        let Err(error) = result else {
            panic!("503 response must be terminal")
        };
        assert_eq!(error.kind(), ProviderErrorKind::Unavailable);
        assert!(!error.retryable());
        assert!(error.cost_ambiguous());
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn retries_connection_establishment_failure_then_succeeds() {
        let placeholder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = placeholder.local_addr().unwrap();
        drop(placeholder);
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let listener = TcpListener::bind(address).await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            write_response(&mut stream, "200 OK", "", b"{}").await;
        });
        let http = DirectHttp::new_for_loopback("fixture", address, test_limits());
        assert!(
            http.post_json(
                HeaderMap::new(),
                b"{}".to_vec(),
                &CancellationToken::default()
            )
            .await
            .is_ok()
        );
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_quota_429_is_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            write_response(
                &mut stream,
                "429 Too Many Requests",
                "",
                br#"{"error":{"code":"insufficient_quota"}}"#,
            )
            .await;
        });
        let http = DirectHttp::new_for_loopback("fixture", address, test_limits());
        let result = http
            .post_json(
                HeaderMap::new(),
                b"{}".to_vec(),
                &CancellationToken::default(),
            )
            .await;
        let Err(error) = result else {
            panic!("permanent quota must fail")
        };
        assert_eq!(error.kind(), ProviderErrorKind::RateLimited);
        assert!(!error.retryable());
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_retry_backoff() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            write_response(&mut stream, "429 Too Many Requests", "", b"{}").await;
        });
        let mut limits = test_limits();
        limits.retry_initial_delay = Duration::from_secs(30);
        limits.retry_max_delay = Duration::from_secs(30);
        limits.retry_total_budget = Duration::from_mins(1);
        limits.request_timeout = Duration::from_mins(1);
        let http = DirectHttp::new_for_loopback("fixture", address, limits);
        let cancellation = CancellationToken::default();
        let cancel = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            cancel.cancel(revoot_core::provider::ProviderCancellationReason::UserRequested);
        });
        let result = http
            .post_json(HeaderMap::new(), b"{}".to_vec(), &cancellation)
            .await;
        let Err(error) = result else {
            panic!("cancellation must fail")
        };
        assert_eq!(error.kind(), ProviderErrorKind::Cancelled);
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn interrupted_success_body_is_cost_ambiguous_and_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{}",
                )
                .await
                .unwrap();
        });
        let http = DirectHttp::new_for_loopback("fixture", address, test_limits());
        let result = http
            .post_json(
                HeaderMap::new(),
                b"{}".to_vec(),
                &CancellationToken::default(),
            )
            .await;
        let Err(error) = result else {
            panic!("partial body must fail")
        };
        assert!(error.cost_ambiguous());
        assert!(!error.retryable());
        server.await.unwrap();
    }
}
