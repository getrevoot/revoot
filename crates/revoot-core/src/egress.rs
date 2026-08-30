//! Pure provider endpoint and egress-policy contracts.
//!
//! This module deliberately performs no DNS, socket, HTTP, proxy discovery, or
//! credential work.  Adapters supply observations; the policy validates those
//! observations and returns the exact addresses a trusted connector may pin.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_HOSTNAME_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 1024;
const MAX_DNS_ANSWERS: usize = 32;
const MAX_DNS_TTL_SECONDS: u32 = 86_400;

/// A canonical ASCII DNS hostname.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalHostname(String);

impl CanonicalHostname {
    /// Parses and lowercases a DNS hostname.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError::InvalidHostname`] when the input is not the
    /// supported canonical DNS-name grammar or is an IP-literal-like value.
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        if input.is_empty()
            || input.len() > MAX_HOSTNAME_BYTES
            || !input.is_ascii()
            || input.ends_with('.')
            || input.parse::<IpAddr>().is_ok()
            || input.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(EndpointError::InvalidHostname);
        }

        let canonical = input.to_ascii_lowercase();
        for label in canonical.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(EndpointError::InvalidHostname);
            }
        }

        Ok(Self(canonical))
    }

    /// Returns the canonical hostname for trusted connector code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalHostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalHostname(<redacted>)")
    }
}

/// A canonical HTTPS origin. Port 443 is represented canonically as `None`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalHttpsOrigin {
    hostname: CanonicalHostname,
    explicit_port: Option<u16>,
}

impl CanonicalHttpsOrigin {
    /// Parses an HTTPS origin with no userinfo, query, fragment, or non-root path.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] when the input is not a canonicalizable HTTPS
    /// origin or contains a non-root path.
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        let endpoint = CanonicalHttpsEndpoint::parse(input)?;
        if endpoint.path != "/" {
            return Err(EndpointError::OriginHasPath);
        }
        Ok(endpoint.origin)
    }

    /// Constructs an origin from a validated hostname and nonzero port.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError::InvalidPort`] when `port` is zero.
    pub fn try_new(hostname: CanonicalHostname, port: u16) -> Result<Self, EndpointError> {
        if port == 0 {
            return Err(EndpointError::InvalidPort);
        }
        Ok(Self {
            hostname,
            explicit_port: (port != 443).then_some(port),
        })
    }

    /// Returns the canonical hostname.
    #[must_use]
    pub fn hostname(&self) -> &CanonicalHostname {
        &self.hostname
    }

    /// Returns the effective TCP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.explicit_port.unwrap_or(443)
    }
}

impl fmt::Debug for CanonicalHttpsOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalHttpsOrigin")
            .field("hostname", &"<redacted>")
            .field("port", &self.port())
            .finish()
    }
}

/// A canonical HTTPS endpoint with an absolute, unescaped path.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalHttpsEndpoint {
    origin: CanonicalHttpsOrigin,
    path: String,
}

impl CanonicalHttpsEndpoint {
    /// Parses the intentionally small endpoint grammar accepted by Revoot.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] when the input falls outside the closed HTTPS
    /// endpoint grammar.
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        if !input.is_ascii() || input.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(EndpointError::InvalidCharacter);
        }
        let remainder = input
            .strip_prefix("https://")
            .ok_or(EndpointError::HttpsRequired)?;
        if remainder.contains('@') {
            return Err(EndpointError::UserinfoNotAllowed);
        }
        if remainder.contains('?') {
            return Err(EndpointError::QueryNotAllowed);
        }
        if remainder.contains('#') {
            return Err(EndpointError::FragmentNotAllowed);
        }
        if remainder.contains('%') || remainder.contains('\\') || remainder.contains(' ') {
            return Err(EndpointError::InvalidCharacter);
        }

        let (authority, path) = remainder
            .split_once('/')
            .map_or((remainder, "/"), |(authority, _)| {
                (authority, &remainder[authority.len()..])
            });
        if authority.is_empty() {
            return Err(EndpointError::MissingAuthority);
        }
        if authority.starts_with('[') || authority.ends_with(']') {
            return Err(EndpointError::IpLiteralNotAllowed);
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                if host.contains(':') || port.is_empty() {
                    return Err(EndpointError::InvalidPort);
                }
                let port = port
                    .parse::<u16>()
                    .map_err(|_| EndpointError::InvalidPort)?;
                if port == 0 {
                    return Err(EndpointError::InvalidPort);
                }
                (host, port)
            }
            None => (authority, 443),
        };
        let hostname = CanonicalHostname::parse(host)?;
        validate_path(path)?;

        Ok(Self {
            origin: CanonicalHttpsOrigin::try_new(hostname, port)?,
            path: path.to_owned(),
        })
    }

    /// Returns the canonical origin.
    #[must_use]
    pub fn origin(&self) -> &CanonicalHttpsOrigin {
        &self.origin
    }

    /// Returns the exact canonical path for trusted adapter code.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Debug for CanonicalHttpsEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalHttpsEndpoint")
            .field("origin", &self.origin)
            .field("path", &"<redacted>")
            .finish()
    }
}

fn validate_path(path: &str) -> Result<(), EndpointError> {
    if !path.starts_with('/') || path.len() > MAX_PATH_BYTES {
        return Err(EndpointError::InvalidPath);
    }
    if path == "/" {
        return Ok(());
    }
    if path.ends_with('/')
        || path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(EndpointError::InvalidPath);
    }
    if !path.bytes().all(|byte| {
        byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    }) {
        return Err(EndpointError::InvalidPath);
    }
    Ok(())
}

/// Why endpoint canonicalization failed. Values contain no attacker-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    HttpsRequired,
    MissingAuthority,
    UserinfoNotAllowed,
    QueryNotAllowed,
    FragmentNotAllowed,
    IpLiteralNotAllowed,
    InvalidHostname,
    InvalidPort,
    InvalidPath,
    InvalidCharacter,
    OriginHasPath,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid provider endpoint: {self:?}")
    }
}

impl Error for EndpointError {}

/// A path allowlist entry for one provider origin.
#[derive(Clone, PartialEq, Eq)]
pub enum EndpointPathRule {
    Exact(String),
    Prefix(String),
}

impl EndpointPathRule {
    /// Builds an exact canonical-path rule.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError::InvalidPath`] when `path` is not canonical.
    pub fn exact(path: &str) -> Result<Self, EndpointError> {
        validate_path(path)?;
        Ok(Self::Exact(path.to_owned()))
    }

    /// Builds a segment-boundary prefix rule over a canonical path.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError::InvalidPath`] when `path` is not canonical.
    pub fn prefix(path: &str) -> Result<Self, EndpointError> {
        validate_path(path)?;
        Ok(Self::Prefix(path.to_owned()))
    }

    fn permits(&self, candidate: &str) -> bool {
        match self {
            Self::Exact(path) => candidate == path,
            Self::Prefix(path) if path == "/" => true,
            Self::Prefix(path) => {
                candidate == path
                    || candidate
                        .strip_prefix(path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
        }
    }
}

impl fmt::Debug for EndpointPathRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(_) => formatter.write_str("Exact(<redacted>)"),
            Self::Prefix(_) => formatter.write_str("Prefix(<redacted>)"),
        }
    }
}

/// One exact origin and its allowed endpoint paths.
#[derive(Clone, PartialEq, Eq)]
pub struct AllowedProviderOrigin {
    origin: CanonicalHttpsOrigin,
    paths: Vec<EndpointPathRule>,
}

impl AllowedProviderOrigin {
    /// Builds the nonempty path allowlist for one exact origin.
    ///
    /// # Errors
    ///
    /// Returns [`EgressPolicyError`] when the path allowlist is empty or
    /// contains duplicate rules.
    pub fn try_new(
        origin: CanonicalHttpsOrigin,
        paths: Vec<EndpointPathRule>,
    ) -> Result<Self, EgressPolicyError> {
        if paths.is_empty() {
            return Err(EgressPolicyError::EmptyPathAllowlist);
        }
        if paths
            .iter()
            .enumerate()
            .any(|(index, path)| paths[..index].contains(path))
        {
            return Err(EgressPolicyError::DuplicatePathRule);
        }
        Ok(Self { origin, paths })
    }

    fn permits(&self, endpoint: &CanonicalHttpsEndpoint) -> bool {
        self.origin == endpoint.origin
            && self.paths.iter().any(|rule| rule.permits(endpoint.path()))
    }
}

impl fmt::Debug for AllowedProviderOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllowedProviderOrigin")
            .field("origin", &self.origin)
            .field("path_rule_count", &self.paths.len())
            .finish()
    }
}

/// The complete origin allowlist for one provider adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderAdapterEgressPolicy {
    adapter_id: String,
    origins: Vec<AllowedProviderOrigin>,
}

impl ProviderAdapterEgressPolicy {
    /// Builds a closed, nonempty origin allowlist for one adapter.
    ///
    /// # Errors
    ///
    /// Returns [`EgressPolicyError`] when the adapter ID or origin allowlist is
    /// invalid.
    pub fn try_new(
        adapter_id: &str,
        origins: Vec<AllowedProviderOrigin>,
    ) -> Result<Self, EgressPolicyError> {
        if !valid_adapter_id(adapter_id) {
            return Err(EgressPolicyError::InvalidAdapterId);
        }
        if origins.is_empty() {
            return Err(EgressPolicyError::EmptyOriginAllowlist);
        }
        if origins.iter().enumerate().any(|(index, candidate)| {
            origins[..index]
                .iter()
                .any(|prior| prior.origin == candidate.origin)
        }) {
            return Err(EgressPolicyError::DuplicateOrigin);
        }
        Ok(Self {
            adapter_id: adapter_id.to_owned(),
            origins,
        })
    }

    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    fn permits(&self, endpoint: &CanonicalHttpsEndpoint) -> Result<(), EgressDenial> {
        let Some(origin) = self
            .origins
            .iter()
            .find(|allowed| allowed.origin == endpoint.origin)
        else {
            return Err(EgressDenial::OriginNotAllowed);
        };
        if !origin.permits(endpoint) {
            return Err(EgressDenial::PathNotAllowed);
        }
        Ok(())
    }
}

impl fmt::Debug for ProviderAdapterEgressPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAdapterEgressPolicy")
            .field("adapter_id", &self.adapter_id)
            .field("origin_count", &self.origins.len())
            .finish()
    }
}

fn valid_adapter_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Security-relevant classification of a resolved address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddressClass {
    Public,
    Private,
    Shared,
    Loopback,
    LinkLocal,
    Metadata,
    Documentation,
    Benchmark,
    Multicast,
    Unspecified,
    Transition,
    Reserved,
}

/// Classifies an address without consulting platform networking state.
#[must_use]
pub fn classify_ip_address(address: IpAddr) -> IpAddressClass {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

fn classify_ipv4(address: Ipv4Addr) -> IpAddressClass {
    let octets = address.octets();
    if address.is_unspecified() {
        IpAddressClass::Unspecified
    } else if matches!(octets, [169, 254, 169, 254 | 123] | [169, 254, 170, 2 | 23])
        || address == Ipv4Addr::new(100, 100, 100, 200)
        || address == Ipv4Addr::new(168, 63, 129, 16)
    {
        IpAddressClass::Metadata
    } else if octets[0] == 127 {
        IpAddressClass::Loopback
    } else if octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || matches!(octets[..2], [192, 168])
    {
        IpAddressClass::Private
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        IpAddressClass::Shared
    } else if matches!(octets[..2], [169, 254]) {
        IpAddressClass::LinkLocal
    } else if matches!(octets[..3], [192, 0, 2] | [198, 51, 100] | [203, 0, 113]) {
        IpAddressClass::Documentation
    } else if octets[0] == 198 && matches!(octets[1], 18 | 19) {
        IpAddressClass::Benchmark
    } else if matches!(octets[..3], [192, 88, 99]) {
        IpAddressClass::Transition
    } else if octets[0] >= 224 && octets[0] <= 239 {
        IpAddressClass::Multicast
    } else if octets[0] == 0 || octets[0] >= 240 || matches!(octets[..3], [192, 0, 0]) {
        IpAddressClass::Reserved
    } else {
        IpAddressClass::Public
    }
}

fn classify_ipv6(address: Ipv6Addr) -> IpAddressClass {
    let segments = address.segments();
    if address.is_unspecified() {
        IpAddressClass::Unspecified
    } else if address.is_loopback() {
        IpAddressClass::Loopback
    } else if address == "fd00:ec2::254".parse::<Ipv6Addr>().expect("static IPv6")
        || address == "fe80::a9fe:a9fe".parse::<Ipv6Addr>().expect("static IPv6")
    {
        IpAddressClass::Metadata
    } else if segments[..6] == [0, 0, 0, 0, 0, 0xffff]
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || segments[0] == 0x2002
    {
        IpAddressClass::Transition
    } else if segments[0] & 0xfe00 == 0xfc00 {
        IpAddressClass::Private
    } else if segments[0] & 0xffc0 == 0xfe80 {
        IpAddressClass::LinkLocal
    } else if segments[0] & 0xff00 == 0xff00 {
        IpAddressClass::Multicast
    } else if segments[0] == 0x2001 && segments[1] == 0x0db8
        || segments[0] == 0x3fff && segments[1] & 0xf000 == 0
    {
        IpAddressClass::Documentation
    } else if segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0 {
        IpAddressClass::Benchmark
    } else if segments[0] == 0x2001 && segments[1] <= 0x01ff
        || segments[0] == 0x0100 && segments[1..4] == [0, 0, 0]
    {
        IpAddressClass::Reserved
    } else if segments[0] & 0xe000 == 0x2000 {
        IpAddressClass::Public
    } else {
        IpAddressClass::Reserved
    }
}

/// A canonical, explicitly approved private CIDR.
#[derive(Clone, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix_length: u8,
}

impl IpCidr {
    /// Builds a CIDR contained wholly within RFC 1918 or RFC 4193 private space.
    ///
    /// # Errors
    ///
    /// Returns [`IpCidrError`] for an invalid prefix, noncanonical network
    /// address, or range not contained wholly within supported private space.
    pub fn private(network: IpAddr, prefix_length: u8) -> Result<Self, IpCidrError> {
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix_length > max {
            return Err(IpCidrError::InvalidPrefixLength);
        }
        if masked_address(network, prefix_length) != network {
            return Err(IpCidrError::HostBitsSet);
        }
        if !private_cidr_supported(network, prefix_length) {
            return Err(IpCidrError::NotPrivate);
        }
        Ok(Self {
            network,
            prefix_length,
        })
    }

    fn contains(&self, candidate: IpAddr) -> bool {
        self.network.is_ipv4() == candidate.is_ipv4()
            && masked_address(candidate, self.prefix_length) == self.network
    }
}

impl fmt::Debug for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpCidr")
            .field("network", &"<redacted>")
            .field("prefix_length", &self.prefix_length)
            .finish()
    }
}

fn private_cidr_supported(network: IpAddr, prefix_length: u8) -> bool {
    match network {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            [
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
            ]
            .into_iter()
            .any(|(base, base_prefix)| {
                prefix_length >= base_prefix && masked_v4(value, base_prefix) == u32::from(base)
            })
        }
        IpAddr::V6(address) => {
            prefix_length >= 7
                && masked_v6(u128::from(address), 7)
                    == u128::from(Ipv6Addr::from(0xfc00_u128 << 112))
        }
    }
}

fn masked_address(address: IpAddr, prefix_length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            IpAddr::V4(Ipv4Addr::from(masked_v4(u32::from(address), prefix_length)))
        }
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(masked_v6(
            u128::from(address),
            prefix_length,
        ))),
    }
}

fn masked_v4(value: u32, prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else {
        value & (u32::MAX << (32 - prefix_length))
    }
}

fn masked_v6(value: u128, prefix_length: u8) -> u128 {
    if prefix_length == 0 {
        0
    } else {
        value & (u128::MAX << (128 - prefix_length))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCidrError {
    InvalidPrefixLength,
    HostBitsSet,
    NotPrivate,
}

impl fmt::Display for IpCidrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid private CIDR: {self:?}")
    }
}

impl Error for IpCidrError {}

/// One DNS answer supplied by a resolver adapter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DnsAnswer {
    pub address: IpAddr,
    pub ttl_seconds: u32,
}

impl fmt::Debug for DnsAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsAnswer")
            .field("address", &"<redacted>")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

/// A complete A/AAAA lookup observation for one hostname.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsObservation {
    hostname: CanonicalHostname,
    answers: Vec<DnsAnswer>,
}

impl DnsObservation {
    #[must_use]
    pub fn new(hostname: CanonicalHostname, answers: Vec<DnsAnswer>) -> Self {
        Self { hostname, answers }
    }
}

impl fmt::Debug for DnsObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsObservation")
            .field("hostname", &"<redacted>")
            .field("answer_count", &self.answers.len())
            .finish()
    }
}

/// Bounds and private-network exceptions applied to a DNS answer set.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsPolicy {
    max_answers: usize,
    min_ttl_seconds: u32,
    max_ttl_seconds: u32,
    allowed_private_cidrs: Vec<IpCidr>,
}

impl DnsPolicy {
    /// Builds a bounded DNS policy. Every non-public class remains denied except
    /// `Private` addresses inside an explicitly supplied private CIDR.
    ///
    /// # Errors
    ///
    /// Returns [`DnsPolicyError`] when answer or TTL bounds are unsafe, or when
    /// private CIDR entries are duplicated.
    pub fn try_new(
        max_answers: usize,
        min_ttl_seconds: u32,
        max_ttl_seconds: u32,
        allowed_private_cidrs: Vec<IpCidr>,
    ) -> Result<Self, DnsPolicyError> {
        if !(1..=MAX_DNS_ANSWERS).contains(&max_answers) {
            return Err(DnsPolicyError::InvalidAnswerBound);
        }
        if min_ttl_seconds == 0
            || max_ttl_seconds < min_ttl_seconds
            || max_ttl_seconds > MAX_DNS_TTL_SECONDS
        {
            return Err(DnsPolicyError::InvalidTtlBounds);
        }
        if allowed_private_cidrs
            .iter()
            .enumerate()
            .any(|(index, cidr)| allowed_private_cidrs[..index].contains(cidr))
        {
            return Err(DnsPolicyError::DuplicatePrivateCidr);
        }
        Ok(Self {
            max_answers,
            min_ttl_seconds,
            max_ttl_seconds,
            allowed_private_cidrs,
        })
    }

    fn validate(&self, observation: &DnsObservation) -> Result<ValidatedDnsResolution, DnsDenial> {
        if observation.answers.is_empty() {
            return Err(DnsDenial::NoAnswers);
        }
        if observation.answers.len() > self.max_answers {
            return Err(DnsDenial::TooManyAnswers);
        }

        let mut addresses = Vec::with_capacity(observation.answers.len());
        let mut minimum_ttl = u32::MAX;
        for answer in &observation.answers {
            if !(self.min_ttl_seconds..=self.max_ttl_seconds).contains(&answer.ttl_seconds) {
                return Err(DnsDenial::TtlOutOfBounds);
            }
            if addresses.contains(&answer.address) {
                return Err(DnsDenial::DuplicateAddress);
            }
            let class = classify_ip_address(answer.address);
            if class != IpAddressClass::Public
                && !(class == IpAddressClass::Private
                    && self
                        .allowed_private_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(answer.address)))
            {
                return Err(DnsDenial::AddressClassDenied(class));
            }
            addresses.push(answer.address);
            minimum_ttl = minimum_ttl.min(answer.ttl_seconds);
        }
        addresses.sort_unstable();

        Ok(ValidatedDnsResolution {
            hostname: observation.hostname.clone(),
            addresses,
            minimum_ttl_seconds: minimum_ttl,
        })
    }
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            max_answers: 8,
            min_ttl_seconds: 1,
            max_ttl_seconds: 3_600,
            allowed_private_cidrs: Vec::new(),
        }
    }
}

impl fmt::Debug for DnsPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsPolicy")
            .field("max_answers", &self.max_answers)
            .field("min_ttl_seconds", &self.min_ttl_seconds)
            .field("max_ttl_seconds", &self.max_ttl_seconds)
            .field("private_cidr_count", &self.allowed_private_cidrs.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicyError {
    InvalidAnswerBound,
    InvalidTtlBounds,
    DuplicatePrivateCidr,
}

impl fmt::Display for DnsPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid DNS policy: {self:?}")
    }
}

impl Error for DnsPolicyError {}

/// DNS denials never include a hostname or address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDenial {
    HostnameMismatch,
    NoAnswers,
    TooManyAnswers,
    TtlOutOfBounds,
    DuplicateAddress,
    AddressClassDenied(IpAddressClass),
}

/// A validated set of addresses that a connector must pin for this request.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedDnsResolution {
    hostname: CanonicalHostname,
    addresses: Vec<IpAddr>,
    minimum_ttl_seconds: u32,
}

impl ValidatedDnsResolution {
    /// Returns the exact canonical hostname this resolution is bound to.
    #[must_use]
    pub fn hostname(&self) -> &CanonicalHostname {
        &self.hostname
    }

    /// Returns the complete validated address set for connection pinning.
    #[must_use]
    pub fn pinned_addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    #[must_use]
    pub fn minimum_ttl_seconds(&self) -> u32 {
        self.minimum_ttl_seconds
    }
}

impl fmt::Debug for ValidatedDnsResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedDnsResolution")
            .field("hostname", &"<redacted>")
            .field("address_count", &self.addresses.len())
            .field("minimum_ttl_seconds", &self.minimum_ttl_seconds)
            .finish()
    }
}

/// Result of comparing a fresh DNS answer set with a previously pinned set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRebindingDecision {
    Unchanged,
    Denied(DnsDenial),
    AddressSetChanged,
}

/// Revalidates a fresh observation and requires exact set equality with the pin.
#[must_use]
pub fn compare_dns_rebinding(
    pinned: &ValidatedDnsResolution,
    fresh: &DnsObservation,
    policy: &DnsPolicy,
) -> DnsRebindingDecision {
    if fresh.hostname != pinned.hostname {
        return DnsRebindingDecision::Denied(DnsDenial::HostnameMismatch);
    }
    match policy.validate(fresh) {
        Ok(validated) if validated.addresses == pinned.addresses => DnsRebindingDecision::Unchanged,
        Ok(_) => DnsRebindingDecision::AddressSetChanged,
        Err(denial) => DnsRebindingDecision::Denied(denial),
    }
}

/// Proxy selection is explicit. Environment and platform proxy discovery are
/// intentionally not representable.
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderProxyMode {
    Direct,
    ExplicitHttps { proxy_origin: CanonicalHttpsOrigin },
}

impl fmt::Debug for ProviderProxyMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("Direct"),
            Self::ExplicitHttps { .. } => {
                formatter.write_str("ExplicitHttps { proxy_origin: <redacted> }")
            }
        }
    }
}

/// Explicitly selected trust-root policy. An insecure TLS mode is not representable.
#[derive(Clone, PartialEq, Eq)]
pub enum CertificateAuthorityMode {
    BundledWebPki,
    SystemRoots,
    CustomBundle { sha256: [u8; 32] },
    SystemAndCustom { sha256: [u8; 32] },
}

impl CertificateAuthorityMode {
    const fn kind(&self) -> CertificateAuthorityKind {
        match self {
            Self::BundledWebPki => CertificateAuthorityKind::BundledWebPki,
            Self::SystemRoots => CertificateAuthorityKind::SystemRoots,
            Self::CustomBundle { .. } => CertificateAuthorityKind::CustomBundle,
            Self::SystemAndCustom { .. } => CertificateAuthorityKind::SystemAndCustom,
        }
    }

    fn has_valid_bundle_identity(&self) -> bool {
        match self {
            Self::BundledWebPki | Self::SystemRoots => true,
            Self::CustomBundle { sha256 } | Self::SystemAndCustom { sha256 } => {
                sha256.iter().any(|byte| *byte != 0)
            }
        }
    }
}

impl fmt::Debug for CertificateAuthorityMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BundledWebPki => "BundledWebPki",
            Self::SystemRoots => "SystemRoots",
            Self::CustomBundle { .. } => "CustomBundle { sha256: <redacted> }",
            Self::SystemAndCustom { .. } => "SystemAndCustom { sha256: <redacted> }",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateAuthorityKind {
    BundledWebPki,
    SystemRoots,
    CustomBundle,
    SystemAndCustom,
}

/// Resolver and route evidence observed for a request.
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderRouteObservation {
    Direct {
        upstream_dns: DnsObservation,
    },
    ExplicitProxy {
        proxy_origin: CanonicalHttpsOrigin,
        proxy_dns: DnsObservation,
    },
}

impl fmt::Debug for ProviderRouteObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct { upstream_dns } => formatter
                .debug_struct("Direct")
                .field("upstream_dns", upstream_dns)
                .finish(),
            Self::ExplicitProxy { proxy_dns, .. } => formatter
                .debug_struct("ExplicitProxy")
                .field("proxy_origin", &"<redacted>")
                .field("proxy_dns", proxy_dns)
                .finish(),
        }
    }
}

/// Closed, pure provider-egress policy.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderEgressPolicy {
    adapters: Vec<ProviderAdapterEgressPolicy>,
    proxy_mode: ProviderProxyMode,
    certificate_authorities: CertificateAuthorityMode,
    upstream_dns_policy: DnsPolicy,
    proxy_dns_policy: DnsPolicy,
}

impl ProviderEgressPolicy {
    /// Builds a closed policy from adapter, route, CA, and DNS policy choices.
    ///
    /// # Errors
    ///
    /// Returns [`EgressPolicyError`] for empty or duplicate adapters, or an
    /// unidentified custom CA bundle.
    pub fn try_new(
        adapters: Vec<ProviderAdapterEgressPolicy>,
        proxy_mode: ProviderProxyMode,
        certificate_authorities: CertificateAuthorityMode,
        upstream_dns_policy: DnsPolicy,
        proxy_dns_policy: DnsPolicy,
    ) -> Result<Self, EgressPolicyError> {
        if adapters.is_empty() {
            return Err(EgressPolicyError::EmptyAdapterAllowlist);
        }
        if adapters.iter().enumerate().any(|(index, candidate)| {
            adapters[..index]
                .iter()
                .any(|prior| prior.adapter_id == candidate.adapter_id)
        }) {
            return Err(EgressPolicyError::DuplicateAdapter);
        }
        if !certificate_authorities.has_valid_bundle_identity() {
            return Err(EgressPolicyError::InvalidCaBundleIdentity);
        }
        Ok(Self {
            adapters,
            proxy_mode,
            certificate_authorities,
            upstream_dns_policy,
            proxy_dns_policy,
        })
    }

    /// Authorizes a single adapter endpoint against supplied route evidence.
    #[must_use]
    pub fn authorize(
        &self,
        adapter_id: &str,
        endpoint: &CanonicalHttpsEndpoint,
        route: &ProviderRouteObservation,
    ) -> ProviderEgressDecision {
        let Some(adapter) = self
            .adapters
            .iter()
            .find(|adapter| adapter.adapter_id == adapter_id)
        else {
            return ProviderEgressDecision::Denied(EgressDenial::UnknownAdapter);
        };
        if let Err(denial) = adapter.permits(endpoint) {
            return ProviderEgressDecision::Denied(denial);
        }

        let (route_kind, resolution) = match (&self.proxy_mode, route) {
            (ProviderProxyMode::Direct, ProviderRouteObservation::Direct { upstream_dns }) => {
                if upstream_dns.hostname != *endpoint.origin.hostname() {
                    return ProviderEgressDecision::Denied(EgressDenial::Dns(
                        DnsDenial::HostnameMismatch,
                    ));
                }
                match self.upstream_dns_policy.validate(upstream_dns) {
                    Ok(resolution) => (EgressRouteKind::Direct, resolution),
                    Err(denial) => {
                        return ProviderEgressDecision::Denied(EgressDenial::Dns(denial));
                    }
                }
            }
            (
                ProviderProxyMode::ExplicitHttps {
                    proxy_origin: configured,
                },
                ProviderRouteObservation::ExplicitProxy {
                    proxy_origin: observed,
                    proxy_dns,
                },
            ) => {
                if configured != observed {
                    return ProviderEgressDecision::Denied(EgressDenial::ProxyMismatch);
                }
                if proxy_dns.hostname != *configured.hostname() {
                    return ProviderEgressDecision::Denied(EgressDenial::Dns(
                        DnsDenial::HostnameMismatch,
                    ));
                }
                match self.proxy_dns_policy.validate(proxy_dns) {
                    Ok(resolution) => (EgressRouteKind::ExplicitProxy, resolution),
                    Err(denial) => {
                        return ProviderEgressDecision::Denied(EgressDenial::Dns(denial));
                    }
                }
            }
            _ => return ProviderEgressDecision::Denied(EgressDenial::RouteMismatch),
        };

        ProviderEgressDecision::Allowed(AllowedProviderEgress {
            adapter_id: adapter_id.to_owned(),
            endpoint: endpoint.clone(),
            route_kind,
            certificate_authorities: self.certificate_authorities.clone(),
            resolution,
        })
    }

    /// Redirects are disabled and denied before any target is followed.
    #[must_use]
    pub const fn authorize_redirect(
        &self,
        _target: &CanonicalHttpsEndpoint,
    ) -> ProviderEgressDecision {
        ProviderEgressDecision::Denied(EgressDenial::RedirectDisabled)
    }
}

impl fmt::Debug for ProviderEgressPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEgressPolicy")
            .field("adapter_count", &self.adapters.len())
            .field("proxy_mode", &self.proxy_mode)
            .field("certificate_authorities", &self.certificate_authorities)
            .field("upstream_dns_policy", &self.upstream_dns_policy)
            .field("proxy_dns_policy", &self.proxy_dns_policy)
            .finish()
    }
}

/// An authorization result safe to include in diagnostic debug output.
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderEgressDecision {
    Allowed(AllowedProviderEgress),
    Denied(EgressDenial),
}

impl fmt::Debug for ProviderEgressDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed(allowed) => formatter.debug_tuple("Allowed").field(allowed).finish(),
            Self::Denied(denial) => formatter.debug_tuple("Denied").field(denial).finish(),
        }
    }
}

/// A connector-ready request authorization. Debug output redacts target data.
#[derive(Clone, PartialEq, Eq)]
pub struct AllowedProviderEgress {
    adapter_id: String,
    endpoint: CanonicalHttpsEndpoint,
    route_kind: EgressRouteKind,
    certificate_authorities: CertificateAuthorityMode,
    resolution: ValidatedDnsResolution,
}

impl AllowedProviderEgress {
    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    #[must_use]
    pub fn endpoint(&self) -> &CanonicalHttpsEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub const fn route_kind(&self) -> EgressRouteKind {
        self.route_kind
    }

    #[must_use]
    pub const fn certificate_authority_kind(&self) -> CertificateAuthorityKind {
        self.certificate_authorities.kind()
    }

    /// Return the exact trust-root authorization, including a custom bundle's
    /// configuration identity. Its debug representation redacts the digest.
    #[must_use]
    pub const fn certificate_authorities(&self) -> &CertificateAuthorityMode {
        &self.certificate_authorities
    }

    #[must_use]
    pub fn resolution(&self) -> &ValidatedDnsResolution {
        &self.resolution
    }
}

impl fmt::Debug for AllowedProviderEgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllowedProviderEgress")
            .field("adapter_id", &self.adapter_id)
            .field("endpoint", &"<redacted>")
            .field("route_kind", &self.route_kind)
            .field(
                "certificate_authority_kind",
                &self.certificate_authorities.kind(),
            )
            .field("address_count", &self.resolution.addresses.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRouteKind {
    Direct,
    ExplicitProxy,
}

/// A deny reason containing no host, path, address, credential, or CA material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDenial {
    UnknownAdapter,
    OriginNotAllowed,
    PathNotAllowed,
    RouteMismatch,
    ProxyMismatch,
    Dns(DnsDenial),
    RedirectDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicyError {
    InvalidAdapterId,
    EmptyAdapterAllowlist,
    DuplicateAdapter,
    EmptyOriginAllowlist,
    DuplicateOrigin,
    EmptyPathAllowlist,
    DuplicatePathRule,
    InvalidCaBundleIdentity,
}

impl fmt::Display for EgressPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid provider egress policy: {self:?}")
    }
}

impl Error for EgressPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> CanonicalHostname {
        CanonicalHostname::parse(value).expect("valid test hostname")
    }

    fn endpoint(value: &str) -> CanonicalHttpsEndpoint {
        CanonicalHttpsEndpoint::parse(value).expect("valid test endpoint")
    }

    fn answer(value: &str, ttl_seconds: u32) -> DnsAnswer {
        DnsAnswer {
            address: value.parse().expect("valid test address"),
            ttl_seconds,
        }
    }

    fn observation(hostname: &str, answers: Vec<DnsAnswer>) -> DnsObservation {
        DnsObservation::new(host(hostname), answers)
    }

    fn adapter() -> ProviderAdapterEgressPolicy {
        ProviderAdapterEgressPolicy::try_new(
            "openai",
            vec![
                AllowedProviderOrigin::try_new(
                    CanonicalHttpsOrigin::parse("https://api.example.com")
                        .expect("valid test origin"),
                    vec![EndpointPathRule::prefix("/v1").expect("valid test path")],
                )
                .expect("valid origin policy"),
            ],
        )
        .expect("valid adapter policy")
    }

    fn direct_policy() -> ProviderEgressPolicy {
        ProviderEgressPolicy::try_new(
            vec![adapter()],
            ProviderProxyMode::Direct,
            CertificateAuthorityMode::BundledWebPki,
            DnsPolicy::default(),
            DnsPolicy::default(),
        )
        .expect("valid egress policy")
    }

    #[test]
    fn canonicalizes_hostname_and_default_https_port() {
        let endpoint = endpoint("https://API.Example.COM:443/v1/models");
        assert_eq!(endpoint.origin().hostname().as_str(), "api.example.com");
        assert_eq!(endpoint.origin().port(), 443);
        assert_eq!(endpoint.origin.explicit_port, None);
        assert_eq!(endpoint.path(), "/v1/models");
        assert_eq!(
            CanonicalHttpsOrigin::parse("https://api.example.com/"),
            CanonicalHttpsOrigin::parse("https://API.EXAMPLE.COM:443")
        );
    }

    #[test]
    fn rejects_ambiguous_or_expansive_endpoint_forms() {
        let cases = [
            ("http://api.example.com/v1", EndpointError::HttpsRequired),
            (
                "https://user@api.example.com/v1",
                EndpointError::UserinfoNotAllowed,
            ),
            (
                "https://api.example.com/v1?q=x",
                EndpointError::QueryNotAllowed,
            ),
            (
                "https://api.example.com/v1#x",
                EndpointError::FragmentNotAllowed,
            ),
            (
                "https://api.example.com/v1%2fadmin",
                EndpointError::InvalidCharacter,
            ),
            (
                "https://api.example.com/v1//models",
                EndpointError::InvalidPath,
            ),
            (
                "https://api.example.com/v1/./admin",
                EndpointError::InvalidPath,
            ),
            (
                "https://api.example.com/v1/../admin",
                EndpointError::InvalidPath,
            ),
            ("https://api.example.com/v1/", EndpointError::InvalidPath),
            (
                "https://[2001:db8::1]/v1",
                EndpointError::IpLiteralNotAllowed,
            ),
            ("https://api.example.com:0/v1", EndpointError::InvalidPort),
            (
                "https://api.example.com/not-an-origin",
                EndpointError::OriginHasPath,
            ),
        ];
        for (input, expected) in cases {
            let result = if expected == EndpointError::OriginHasPath {
                CanonicalHttpsOrigin::parse(input).map(|_| ())
            } else {
                CanonicalHttpsEndpoint::parse(input).map(|_| ())
            };
            assert_eq!(result, Err(expected), "input must be rejected");
        }
    }

    #[test]
    fn enforces_dns_hostname_syntax() {
        for invalid in [
            "",
            ".example.com",
            "example.com.",
            "-api.example.com",
            "api-.example.com",
            "api_example.com",
            "127.0.0.1",
            "2130706433",
            "éxample.com",
        ] {
            assert_eq!(
                CanonicalHostname::parse(invalid),
                Err(EndpointError::InvalidHostname)
            );
        }
        assert_eq!(host("API-2.Example.COM").as_str(), "api-2.example.com");
    }

    #[test]
    fn origin_constructor_rejects_port_zero() {
        assert_eq!(
            CanonicalHttpsOrigin::try_new(host("api.example.com"), 0),
            Err(EndpointError::InvalidPort)
        );
        assert_eq!(
            CanonicalHttpsOrigin::try_new(host("api.example.com"), 443)
                .unwrap()
                .port(),
            443
        );
    }

    #[test]
    fn path_rules_reject_normalization_bypasses() {
        for path in ["/v1/.", "/v1/..", "/v1/../admin", "/v1//admin"] {
            assert_eq!(
                EndpointPathRule::exact(path),
                Err(EndpointError::InvalidPath)
            );
            assert_eq!(
                EndpointPathRule::prefix(path),
                Err(EndpointError::InvalidPath)
            );
        }
        let rule = EndpointPathRule::prefix("/v1").unwrap();
        assert!(rule.permits("/v1/admin"));
        assert!(!rule.permits("/v10/admin"));
    }

    #[test]
    fn adapter_allowlist_is_exact_for_origin_port_and_path_boundary() {
        let policy = direct_policy();
        let direct = |hostname: &str| ProviderRouteObservation::Direct {
            upstream_dns: observation(hostname, vec![answer("93.184.216.34", 60)]),
        };
        assert!(matches!(
            policy.authorize(
                "openai",
                &endpoint("https://api.example.com/v1/models"),
                &direct("api.example.com")
            ),
            ProviderEgressDecision::Allowed(_)
        ));
        assert_eq!(
            policy.authorize(
                "other",
                &endpoint("https://api.example.com/v1/models"),
                &direct("api.example.com")
            ),
            ProviderEgressDecision::Denied(EgressDenial::UnknownAdapter)
        );
        assert_eq!(
            policy.authorize(
                "openai",
                &endpoint("https://api.example.com:8443/v1/models"),
                &direct("api.example.com")
            ),
            ProviderEgressDecision::Denied(EgressDenial::OriginNotAllowed)
        );
        assert_eq!(
            policy.authorize(
                "openai",
                &endpoint("https://api.example.com/v10/models"),
                &direct("api.example.com")
            ),
            ProviderEgressDecision::Denied(EgressDenial::PathNotAllowed)
        );
    }

    #[test]
    fn redirects_are_unconditionally_denied() {
        assert_eq!(
            direct_policy().authorize_redirect(&endpoint("https://api.example.com/v1/other")),
            ProviderEgressDecision::Denied(EgressDenial::RedirectDisabled)
        );
    }

    #[test]
    fn classifies_ipv4_public_private_and_special_ranges() {
        let cases = [
            ("8.8.8.8", IpAddressClass::Public),
            ("10.0.0.1", IpAddressClass::Private),
            ("100.64.0.1", IpAddressClass::Shared),
            ("127.0.0.1", IpAddressClass::Loopback),
            ("169.254.1.2", IpAddressClass::LinkLocal),
            ("169.254.169.254", IpAddressClass::Metadata),
            ("100.100.100.200", IpAddressClass::Metadata),
            ("192.0.2.1", IpAddressClass::Documentation),
            ("198.18.0.1", IpAddressClass::Benchmark),
            ("224.0.0.1", IpAddressClass::Multicast),
            ("0.0.0.0", IpAddressClass::Unspecified),
            ("192.88.99.1", IpAddressClass::Transition),
            ("240.0.0.1", IpAddressClass::Reserved),
        ];
        for (address, expected) in cases {
            assert_eq!(classify_ip_address(address.parse().unwrap()), expected);
        }
    }

    #[test]
    fn classifies_ipv6_public_private_and_special_ranges() {
        let cases = [
            ("2606:4700:4700::1111", IpAddressClass::Public),
            ("fd12::1", IpAddressClass::Private),
            ("::1", IpAddressClass::Loopback),
            ("fe80::1", IpAddressClass::LinkLocal),
            ("fd00:ec2::254", IpAddressClass::Metadata),
            ("2001:db8::1", IpAddressClass::Documentation),
            ("3fff::1", IpAddressClass::Documentation),
            ("3ffe::1", IpAddressClass::Public),
            ("2001:2::1", IpAddressClass::Benchmark),
            ("ff02::1", IpAddressClass::Multicast),
            ("::", IpAddressClass::Unspecified),
            ("::ffff:8.8.8.8", IpAddressClass::Transition),
            ("64:ff9b::808:808", IpAddressClass::Transition),
            ("2002:0808:0808::1", IpAddressClass::Transition),
            ("100::1", IpAddressClass::Reserved),
        ];
        for (address, expected) in cases {
            assert_eq!(classify_ip_address(address.parse().unwrap()), expected);
        }
    }

    #[test]
    fn dns_policy_enforces_cardinality_ttl_uniqueness_and_address_class() {
        let policy = DnsPolicy::try_new(2, 10, 300, Vec::new()).unwrap();
        assert_eq!(
            policy.validate(&observation("api.example.com", Vec::new())),
            Err(DnsDenial::NoAnswers)
        );
        assert_eq!(
            policy.validate(&observation(
                "api.example.com",
                vec![
                    answer("1.1.1.1", 60),
                    answer("8.8.8.8", 60),
                    answer("9.9.9.9", 60)
                ]
            )),
            Err(DnsDenial::TooManyAnswers)
        );
        assert_eq!(
            policy.validate(&observation("api.example.com", vec![answer("1.1.1.1", 9)])),
            Err(DnsDenial::TtlOutOfBounds)
        );
        assert_eq!(
            policy.validate(&observation(
                "api.example.com",
                vec![answer("1.1.1.1", 60), answer("1.1.1.1", 60)]
            )),
            Err(DnsDenial::DuplicateAddress)
        );
        assert_eq!(
            policy.validate(&observation(
                "api.example.com",
                vec![answer("127.0.0.1", 60)]
            )),
            Err(DnsDenial::AddressClassDenied(IpAddressClass::Loopback))
        );
    }

    #[test]
    fn explicit_private_cidr_allows_only_private_addresses_inside_it() {
        let cidr = IpCidr::private("10.20.0.0".parse().unwrap(), 16).unwrap();
        let policy = DnsPolicy::try_new(4, 1, 300, vec![cidr.clone()]).unwrap();
        assert!(
            policy
                .validate(&observation(
                    "internal.example.com",
                    vec![answer("10.20.4.5", 60)]
                ))
                .is_ok()
        );
        assert_eq!(
            policy.validate(&observation(
                "internal.example.com",
                vec![answer("10.21.4.5", 60)]
            )),
            Err(DnsDenial::AddressClassDenied(IpAddressClass::Private))
        );
        assert_eq!(
            policy.validate(&observation(
                "internal.example.com",
                vec![answer("169.254.169.254", 60)]
            )),
            Err(DnsDenial::AddressClassDenied(IpAddressClass::Metadata))
        );
        assert_eq!(
            IpCidr::private("10.0.0.1".parse().unwrap(), 8),
            Err(IpCidrError::HostBitsSet)
        );
        assert_eq!(
            IpCidr::private("10.0.0.0".parse().unwrap(), 7),
            Err(IpCidrError::NotPrivate)
        );
        assert!(cidr.contains("10.20.255.255".parse().unwrap()));
    }

    #[test]
    fn ipv6_private_cidr_is_exact_and_cannot_expand_outside_ula() {
        let cidr = IpCidr::private("fd12:3456::".parse().unwrap(), 32).unwrap();
        assert!(cidr.contains("fd12:3456::1".parse().unwrap()));
        assert!(!cidr.contains("fd12:3457::1".parse().unwrap()));
        assert_eq!(
            IpCidr::private("fc00::".parse().unwrap(), 6),
            Err(IpCidrError::NotPrivate)
        );
    }

    #[test]
    fn rebinding_requires_same_hostname_and_exact_address_set() {
        let policy = DnsPolicy::default();
        let pinned = policy
            .validate(&observation(
                "api.example.com",
                vec![answer("8.8.8.8", 60), answer("1.1.1.1", 60)],
            ))
            .unwrap();
        assert_eq!(
            compare_dns_rebinding(
                &pinned,
                &observation(
                    "api.example.com",
                    vec![answer("1.1.1.1", 30), answer("8.8.8.8", 30)]
                ),
                &policy
            ),
            DnsRebindingDecision::Unchanged
        );
        assert_eq!(
            compare_dns_rebinding(
                &pinned,
                &observation("api.example.com", vec![answer("9.9.9.9", 60)]),
                &policy
            ),
            DnsRebindingDecision::AddressSetChanged
        );
        assert_eq!(
            compare_dns_rebinding(
                &pinned,
                &observation("other.example.com", vec![answer("8.8.8.8", 60)]),
                &policy
            ),
            DnsRebindingDecision::Denied(DnsDenial::HostnameMismatch)
        );
    }

    #[test]
    fn direct_mode_validates_and_returns_complete_upstream_pin() {
        let decision = direct_policy().authorize(
            "openai",
            &endpoint("https://api.example.com/v1/models"),
            &ProviderRouteObservation::Direct {
                upstream_dns: observation(
                    "api.example.com",
                    vec![answer("8.8.8.8", 60), answer("1.1.1.1", 30)],
                ),
            },
        );
        let ProviderEgressDecision::Allowed(allowed) = decision else {
            panic!("expected allowed request")
        };
        assert_eq!(allowed.route_kind(), EgressRouteKind::Direct);
        assert_eq!(allowed.resolution().pinned_addresses().len(), 2);
        assert_eq!(allowed.resolution().minimum_ttl_seconds(), 30);
        assert_eq!(
            allowed.certificate_authority_kind(),
            CertificateAuthorityKind::BundledWebPki
        );
    }

    #[test]
    fn explicit_proxy_mode_validates_only_the_configured_proxy_route() {
        let proxy = CanonicalHttpsOrigin::parse("https://proxy.corp.example:8443").unwrap();
        let policy = ProviderEgressPolicy::try_new(
            vec![adapter()],
            ProviderProxyMode::ExplicitHttps {
                proxy_origin: proxy.clone(),
            },
            CertificateAuthorityMode::SystemAndCustom { sha256: [7; 32] },
            DnsPolicy::default(),
            DnsPolicy::try_new(
                4,
                1,
                300,
                vec![IpCidr::private("10.4.0.0".parse().unwrap(), 16).unwrap()],
            )
            .unwrap(),
        )
        .unwrap();
        let decision = policy.authorize(
            "openai",
            &endpoint("https://api.example.com/v1/models"),
            &ProviderRouteObservation::ExplicitProxy {
                proxy_origin: proxy,
                proxy_dns: observation("proxy.corp.example", vec![answer("10.4.2.3", 60)]),
            },
        );
        let ProviderEgressDecision::Allowed(allowed) = decision else {
            panic!("expected explicit proxy to be allowed")
        };
        assert_eq!(allowed.route_kind(), EgressRouteKind::ExplicitProxy);
        assert_eq!(
            allowed.certificate_authority_kind(),
            CertificateAuthorityKind::SystemAndCustom
        );
        assert_eq!(
            policy.authorize(
                "openai",
                &endpoint("https://api.example.com/v1/models"),
                &ProviderRouteObservation::Direct {
                    upstream_dns: observation("api.example.com", vec![answer("8.8.8.8", 60)])
                }
            ),
            ProviderEgressDecision::Denied(EgressDenial::RouteMismatch)
        );
    }

    #[test]
    fn rejects_an_unidentified_custom_ca_bundle() {
        assert_eq!(
            ProviderEgressPolicy::try_new(
                vec![adapter()],
                ProviderProxyMode::Direct,
                CertificateAuthorityMode::CustomBundle { sha256: [0; 32] },
                DnsPolicy::default(),
                DnsPolicy::default(),
            ),
            Err(EgressPolicyError::InvalidCaBundleIdentity)
        );
    }

    #[test]
    fn debug_output_redacts_targets_addresses_paths_and_bundle_identity() {
        let policy = ProviderEgressPolicy::try_new(
            vec![adapter()],
            ProviderProxyMode::Direct,
            CertificateAuthorityMode::CustomBundle { sha256: [9; 32] },
            DnsPolicy::default(),
            DnsPolicy::default(),
        )
        .unwrap();
        let decision = policy.authorize(
            "openai",
            &endpoint("https://api.example.com/v1/secret"),
            &ProviderRouteObservation::Direct {
                upstream_dns: observation("api.example.com", vec![answer("93.184.216.34", 60)]),
            },
        );
        let ProviderEgressDecision::Allowed(allowed) = &decision else {
            panic!("expected allowed egress");
        };
        assert_eq!(
            allowed.certificate_authorities(),
            &CertificateAuthorityMode::CustomBundle { sha256: [9; 32] }
        );
        let output = format!("{policy:?} {decision:?}");
        for sensitive in ["api.example.com", "/v1/secret", "93.184.216.34", "09090909"] {
            assert!(!output.contains(sensitive));
        }
        assert!(output.contains("<redacted>"));
    }
}
