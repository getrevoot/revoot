//! Shared trusted construction for the supported direct model providers.

use std::ffi::OsString;

use revoot_core::{Diagnostic, ErrorCode, ProviderAdapter};
use serde::Deserialize;

use crate::credentials::{CredentialKind, DiscoveredCredentials};
use crate::egress_setup::authorize_standard_provider;
use crate::providers::ApiKey;
use crate::providers::anthropic::{AnthropicAdapter, AnthropicConfig};
use crate::providers::openai::{OpenAiAdapter, OpenAiConfig};

const MODEL_CATALOG_SCHEMA_VERSION: &str = "revoot.model-catalog/v1";
const MODEL_CATALOG: &str = include_str!("../assets/model-catalog-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelCatalog {
    schema_version: String,
    providers: Vec<ModelCatalogProvider>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelCatalogProvider {
    adapter: String,
    default_model: String,
}

/// Discover only direct-provider credentials from trusted process input.
///
/// # Errors
///
/// Returns a payload-free diagnostic when credential discovery fails.
pub fn discover_credentials(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<DiscoveredCredentials, Diagnostic> {
    DiscoveredCredentials::discover(environment).map_err(|_| {
        Diagnostic::new(
            ErrorCode::ProviderUnavailable,
            "provider credential discovery failed",
        )
    })
}

/// Select exactly `anthropic` or `openai` from bounded configuration.
///
/// # Errors
///
/// Returns a payload-free diagnostic when the provider is unsupported or its
/// credential is unavailable.
pub fn select_provider(
    configured: &str,
    credentials: &DiscoveredCredentials,
) -> Result<String, Diagnostic> {
    match configured {
        "anthropic" => require_credential(credentials, CredentialKind::Anthropic, "anthropic"),
        "openai" => require_credential(credentials, CredentialKind::OpenAiCompatible, "openai"),
        "auto" => match (
            credentials.get(CredentialKind::Anthropic).is_some(),
            credentials.get(CredentialKind::OpenAiCompatible).is_some(),
        ) {
            (true, _) => Ok("anthropic".to_owned()),
            (false, true) => Ok("openai".to_owned()),
            (false, false) => Err(missing_provider_credential()),
        },
        _ => Err(Diagnostic::new(
            ErrorCode::ProviderUnavailable,
            "configured provider adapter is unsupported",
        )),
    }
}

/// Resolve the configured model or the pinned direct-provider default.
///
/// # Errors
///
/// Returns a payload-free diagnostic when the embedded catalog is invalid or
/// contains no bounded default for the selected provider.
pub fn select_model(provider: &str, configured: &str) -> Result<String, Diagnostic> {
    if configured != "auto" {
        return Ok(configured.to_owned());
    }
    let catalog: ModelCatalog = serde_json::from_str(MODEL_CATALOG)
        .map_err(|_| contract_error("model catalog is invalid"))?;
    if catalog.schema_version != MODEL_CATALOG_SCHEMA_VERSION
        || catalog.providers.is_empty()
        || catalog.providers.len() > 64
    {
        return Err(contract_error("model catalog is invalid"));
    }
    catalog
        .providers
        .into_iter()
        .find(|entry| entry.adapter == provider)
        .filter(|entry| {
            !entry.default_model.is_empty()
                && entry.default_model.len() <= revoot_core::MAX_MODEL_ID_BYTES
                && !entry
                    .default_model
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        })
        .map(|entry| entry.default_model)
        .ok_or_else(|| {
            Diagnostic::new(
                ErrorCode::ProviderUnavailable,
                "the selected provider has no valid default model",
            )
        })
}

/// Construct the hardened direct adapter for one selected provider.
///
/// # Errors
///
/// Returns a payload-free diagnostic when egress authorization, credential
/// binding, or adapter construction fails.
pub fn build_provider(
    provider: &str,
    credentials: &DiscoveredCredentials,
) -> Result<Box<dyn ProviderAdapter>, Diagnostic> {
    match provider {
        "anthropic" => {
            let authorization =
                authorize_standard_provider("anthropic", "https://api.anthropic.com/v1/messages")
                    .map_err(|_| provider_setup_error())?;
            let key = provider_key(credentials, CredentialKind::Anthropic)?;
            AnthropicAdapter::new(&AnthropicConfig::default(), key, &authorization)
                .map(|adapter| Box::new(adapter) as Box<dyn ProviderAdapter>)
                .map_err(|_| provider_setup_error())
        }
        "openai" => {
            let authorization =
                authorize_standard_provider("openai", "https://api.openai.com/v1/responses")
                    .map_err(|_| provider_setup_error())?;
            let key = provider_key(credentials, CredentialKind::OpenAiCompatible)?;
            OpenAiAdapter::new(&OpenAiConfig::default(), key, &authorization)
                .map(|adapter| Box::new(adapter) as Box<dyn ProviderAdapter>)
                .map_err(|_| provider_setup_error())
        }
        _ => Err(provider_setup_error()),
    }
}

fn require_credential(
    credentials: &DiscoveredCredentials,
    kind: CredentialKind,
    provider: &str,
) -> Result<String, Diagnostic> {
    credentials
        .get(kind)
        .map(|_| provider.to_owned())
        .ok_or_else(missing_provider_credential)
}

fn provider_key(
    credentials: &DiscoveredCredentials,
    kind: CredentialKind,
) -> Result<ApiKey, Diagnostic> {
    let value = credentials
        .get(kind)
        .ok_or_else(missing_provider_credential)?;
    ApiKey::new(value.expose()).map_err(|_| provider_setup_error())
}

fn missing_provider_credential() -> Diagnostic {
    Diagnostic::new(
        ErrorCode::ProviderUnavailable,
        "no credential is available for the selected provider",
    )
    .with_remediation("provide ANTHROPIC_API_KEY or OPENAI_API_KEY")
}

fn provider_setup_error() -> Diagnostic {
    Diagnostic::new(
        ErrorCode::ProviderUnavailable,
        "direct provider adapter setup failed",
    )
}

fn contract_error(message: &'static str) -> Diagnostic {
    Diagnostic::new(ErrorCode::ContractInvalid, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_defaults_are_internal_and_provider_bounded() {
        assert_ne!(select_model("anthropic", "auto").expect("catalog"), "auto");
        assert_ne!(select_model("openai", "auto").expect("catalog"), "auto");
        assert_eq!(
            select_model("openai", "custom").expect("explicit"),
            "custom"
        );
        assert!(select_model("unknown", "auto").is_err());
    }

    #[test]
    fn missing_credentials_fail_without_provider_construction() {
        let credentials =
            discover_credentials(Vec::<(OsString, OsString)>::new()).expect("empty discovery");
        assert!(select_provider("openai", &credentials).is_err());
        assert!(select_provider("anthropic", &credentials).is_err());
    }
}
