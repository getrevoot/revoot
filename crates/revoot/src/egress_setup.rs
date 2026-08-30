//! Frictionless construction of the existing strict direct-egress contract.

use std::net::{IpAddr, ToSocketAddrs};

use revoot_core::{
    AllowedProviderEgress, AllowedProviderOrigin, CanonicalHttpsEndpoint, CertificateAuthorityMode,
    DnsAnswer, DnsObservation, DnsPolicy, EndpointPathRule, IpCidr, ProviderAdapterEgressPolicy,
    ProviderEgressDecision, ProviderEgressPolicy, ProviderProxyMode, ProviderRouteObservation,
};

const STANDARD_PIN_LIFETIME_SECONDS: u32 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardEgressError {
    Endpoint,
    Resolution,
    Policy,
    Denied,
}

/// Resolve and authorize one exact public HTTPS provider endpoint.
///
/// The standard mode pins the complete address set returned by the platform
/// resolver for the lifetime of the constructed request client. Adapters still
/// disable redirects and proxies and connect only to the returned authorization.
///
/// # Errors
///
/// Returns only redaction-safe setup classes; hostnames and addresses are not
/// copied into errors.
pub fn authorize_standard_provider(
    adapter_id: &str,
    endpoint: &str,
) -> Result<AllowedProviderEgress, StandardEgressError> {
    let endpoint =
        CanonicalHttpsEndpoint::parse(endpoint).map_err(|_| StandardEgressError::Endpoint)?;
    let addresses: Vec<IpAddr> = (
        endpoint.origin().hostname().as_str(),
        endpoint.origin().port(),
    )
        .to_socket_addrs()
        .map_err(|_| StandardEgressError::Resolution)?
        .map(|address| address.ip())
        .collect();
    authorize_resolved_provider(
        adapter_id,
        &endpoint,
        addresses,
        CertificateAuthorityMode::BundledWebPki,
        Vec::new(),
    )
}

/// Authorize a caller-supplied complete platform-resolution result.
///
/// This split makes standard-mode policy independently testable without live
/// DNS and gives future resolvers a stable construction boundary.
///
/// # Errors
///
/// Rejects missing or excessive answers, invalid policy inputs, and resolution
/// sets containing private or special-purpose addresses.
pub fn authorize_resolved_standard_provider(
    adapter_id: &str,
    endpoint: &CanonicalHttpsEndpoint,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Result<AllowedProviderEgress, StandardEgressError> {
    authorize_resolved_provider(
        adapter_id,
        endpoint,
        addresses,
        CertificateAuthorityMode::BundledWebPki,
        Vec::new(),
    )
}

/// Resolve and authorize one exact HTTPS endpoint with explicit private-network
/// and trust-root exceptions. This is intended for operator-controlled
/// self-managed code-host configuration; public provider endpoints should use
/// [`authorize_standard_provider`].
///
/// # Errors
///
/// Rejects invalid endpoints, DNS failures, denied address classes, invalid
/// policy inputs, or unidentified custom trust roots.
pub fn authorize_configured_provider(
    adapter_id: &str,
    endpoint: &str,
    certificate_authorities: CertificateAuthorityMode,
    allowed_private_cidrs: Vec<IpCidr>,
) -> Result<AllowedProviderEgress, StandardEgressError> {
    let endpoint =
        CanonicalHttpsEndpoint::parse(endpoint).map_err(|_| StandardEgressError::Endpoint)?;
    let addresses: Vec<IpAddr> = (
        endpoint.origin().hostname().as_str(),
        endpoint.origin().port(),
    )
        .to_socket_addrs()
        .map_err(|_| StandardEgressError::Resolution)?
        .map(|address| address.ip())
        .collect();
    authorize_resolved_provider(
        adapter_id,
        &endpoint,
        addresses,
        certificate_authorities,
        allowed_private_cidrs,
    )
}

fn authorize_resolved_provider(
    adapter_id: &str,
    endpoint: &CanonicalHttpsEndpoint,
    addresses: impl IntoIterator<Item = IpAddr>,
    certificate_authorities: CertificateAuthorityMode,
    allowed_private_cidrs: Vec<IpCidr>,
) -> Result<AllowedProviderEgress, StandardEgressError> {
    let mut addresses: Vec<_> = addresses.into_iter().collect();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > 8 {
        return Err(StandardEgressError::Resolution);
    }
    let observation = DnsObservation::new(
        endpoint.origin().hostname().clone(),
        addresses
            .into_iter()
            .map(|address| DnsAnswer {
                address,
                ttl_seconds: STANDARD_PIN_LIFETIME_SECONDS,
            })
            .collect(),
    );
    let exact_path =
        EndpointPathRule::exact(endpoint.path()).map_err(|_| StandardEgressError::Policy)?;
    let allowed_origin =
        AllowedProviderOrigin::try_new(endpoint.origin().clone(), vec![exact_path])
            .map_err(|_| StandardEgressError::Policy)?;
    let adapter = ProviderAdapterEgressPolicy::try_new(adapter_id, vec![allowed_origin])
        .map_err(|_| StandardEgressError::Policy)?;
    let upstream_dns_policy = DnsPolicy::try_new(8, 1, 3_600, allowed_private_cidrs)
        .map_err(|_| StandardEgressError::Policy)?;
    let policy = ProviderEgressPolicy::try_new(
        vec![adapter],
        ProviderProxyMode::Direct,
        certificate_authorities,
        upstream_dns_policy,
        DnsPolicy::default(),
    )
    .map_err(|_| StandardEgressError::Policy)?;
    match policy.authorize(
        adapter_id,
        endpoint,
        &ProviderRouteObservation::Direct {
            upstream_dns: observation,
        },
    ) {
        ProviderEgressDecision::Allowed(authorization) => Ok(authorization),
        ProviderEgressDecision::Denied(_) => Err(StandardEgressError::Denied),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use revoot_core::{CanonicalHttpsEndpoint, CertificateAuthorityMode, IpCidr};

    use super::{
        StandardEgressError, authorize_resolved_provider, authorize_resolved_standard_provider,
    };

    #[test]
    fn standard_mode_authorizes_exact_public_endpoint_and_deduplicates_answers() {
        let endpoint =
            CanonicalHttpsEndpoint::parse("https://api.example.com/v1/messages").expect("endpoint");
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let allowed =
            authorize_resolved_standard_provider("anthropic", &endpoint, [public, public])
                .expect("public address");
        assert_eq!(allowed.adapter_id(), "anthropic");
        assert_eq!(allowed.endpoint().path(), "/v1/messages");
        assert_eq!(allowed.resolution().pinned_addresses(), &[public]);
    }

    #[test]
    fn standard_mode_rejects_private_provider_resolution() {
        let endpoint =
            CanonicalHttpsEndpoint::parse("https://api.example.com/v1/messages").expect("endpoint");
        assert_eq!(
            authorize_resolved_standard_provider(
                "anthropic",
                &endpoint,
                [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            ),
            Err(StandardEgressError::Denied)
        );
    }

    #[test]
    fn configured_mode_allows_only_the_exact_private_network_exception() {
        let endpoint =
            CanonicalHttpsEndpoint::parse("https://gitlab.internal/api/v4").expect("endpoint");
        let allowed_network =
            IpCidr::private(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 0)), 16).expect("private CIDR");
        let allowed = authorize_resolved_provider(
            "gitlab-rest",
            &endpoint,
            [IpAddr::V4(Ipv4Addr::new(10, 20, 4, 8))],
            CertificateAuthorityMode::BundledWebPki,
            vec![allowed_network.clone()],
        )
        .expect("explicit private exception");
        assert_eq!(allowed.resolution().pinned_addresses().len(), 1);
        assert_eq!(
            authorize_resolved_provider(
                "gitlab-rest",
                &endpoint,
                [IpAddr::V4(Ipv4Addr::new(10, 21, 4, 8))],
                CertificateAuthorityMode::BundledWebPki,
                vec![allowed_network],
            ),
            Err(StandardEgressError::Denied)
        );
    }
}
