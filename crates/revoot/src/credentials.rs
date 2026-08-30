//! Narrow, redaction-safe credential discovery for local and CI operation.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
};

const MAX_SECRET_BYTES: usize = 16 * 1024;

/// Supported credential purpose. Provider credentials are intentionally
/// distinct so selecting one provider cannot expose another provider's key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CredentialKind {
    Anthropic,
    OpenAiCompatible,
}

/// Validated secret bytes. Debug output and errors never contain the value.
pub struct SecretValue(Box<[u8]>);

impl SecretValue {
    /// Validate a non-empty HTTP-header-safe secret.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, non-UTF-8, whitespace, and control-containing
    /// values without retaining or echoing them.
    pub fn new(value: &OsStr) -> Result<Self, CredentialError> {
        let Some(value) = value.to_str() else {
            return Err(CredentialError::InvalidValue);
        };
        if value.is_empty()
            || value.len() > MAX_SECRET_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
        {
            return Err(CredentialError::InvalidValue);
        }
        Ok(Self(value.as_bytes().to_vec().into_boxed_slice()))
    }

    /// Borrow secret bytes only at the adapter construction boundary.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(<redacted>)")
    }
}

/// Credential discovery result. Unknown environment variables are ignored.
#[derive(Default)]
pub struct DiscoveredCredentials {
    values: BTreeMap<CredentialKind, SecretValue>,
}

impl DiscoveredCredentials {
    /// Discover standard model-provider variable names.
    ///
    /// # Errors
    ///
    /// Fails if aliases provide more than one value for the same purpose or a
    /// recognized value is unsafe for an HTTP header.
    pub fn discover(
        environment: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Result<Self, CredentialError> {
        let mut discovered = Self::default();
        for (name, value) in environment {
            let Some(name) = name.to_str() else { continue };
            let kind = match name {
                "ANTHROPIC_API_KEY" => Some(CredentialKind::Anthropic),
                "OPENAI_API_KEY" | "REVOOT_MODEL_TOKEN" => Some(CredentialKind::OpenAiCompatible),
                _ => None,
            };
            let Some(kind) = kind else { continue };
            if value.is_empty() {
                continue;
            }
            if discovered
                .values
                .insert(kind, SecretValue::new(&value)?)
                .is_some()
            {
                return Err(CredentialError::Ambiguous(kind));
            }
        }
        Ok(discovered)
    }

    #[must_use]
    pub fn get(&self, kind: CredentialKind) -> Option<&SecretValue> {
        self.values.get(&kind)
    }
}

impl fmt::Debug for DiscoveredCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveredCredentials")
            .field("kinds", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    InvalidValue,
    Ambiguous(CredentialKind),
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{CredentialError, CredentialKind, DiscoveredCredentials};

    #[test]
    fn discovers_standard_names_without_retaining_unknown_values() {
        let credentials = DiscoveredCredentials::discover([
            (
                OsString::from("ANTHROPIC_API_KEY"),
                OsString::from("sk-ant"),
            ),
            (
                OsString::from("CI_JOB_TOKEN"),
                OsString::from("ignored-job-token"),
            ),
            (
                OsString::from("UNRELATED_SECRET"),
                OsString::from("ignored"),
            ),
        ])
        .expect("valid credentials");
        assert_eq!(
            credentials
                .get(CredentialKind::Anthropic)
                .expect("anthropic key")
                .expose(),
            b"sk-ant"
        );
        assert!(credentials.get(CredentialKind::OpenAiCompatible).is_none());
        assert!(!format!("{credentials:?}").contains("sk-ant"));
    }

    #[test]
    fn duplicate_aliases_are_ambiguous_and_values_are_never_formatted() {
        let error = DiscoveredCredentials::discover([
            (OsString::from("OPENAI_API_KEY"), OsString::from("first")),
            (
                OsString::from("REVOOT_MODEL_TOKEN"),
                OsString::from("second"),
            ),
        ])
        .expect_err("aliases must not silently override");
        assert_eq!(
            error,
            CredentialError::Ambiguous(CredentialKind::OpenAiCompatible)
        );
        assert!(!format!("{error:?}").contains("first"));
        assert!(!format!("{error:?}").contains("second"));
    }

    #[test]
    fn rejects_header_unsafe_values() {
        let error = DiscoveredCredentials::discover([(
            OsString::from("ANTHROPIC_API_KEY"),
            OsString::from("bad token"),
        )])
        .expect_err("whitespace must be rejected");
        assert_eq!(error, CredentialError::InvalidValue);
    }

    #[test]
    fn ignores_empty_provider_variables_from_ci_workflows() {
        let credentials = DiscoveredCredentials::discover([
            (OsString::from("ANTHROPIC_API_KEY"), OsString::new()),
            (
                OsString::from("OPENAI_API_KEY"),
                OsString::from("openai-key"),
            ),
        ])
        .expect("one configured provider");

        assert!(credentials.get(CredentialKind::Anthropic).is_none());
        assert_eq!(
            credentials
                .get(CredentialKind::OpenAiCompatible)
                .expect("OpenAI key")
                .expose(),
            b"openai-key"
        );
    }
}
