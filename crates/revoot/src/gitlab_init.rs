//! Deterministic `revoot init gitlab` output generation.

use std::error::Error;
use std::fmt;

const DEFAULT_COMPONENT: &str = "gitlab.com/getrevoot/revoot-ci/review";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabInitOptions {
    pub component: String,
    pub version: String,
    pub provider: String,
    pub model: String,
    pub fork_behavior: String,
}

impl Default for GitLabInitOptions {
    fn default() -> Self {
        Self {
            component: DEFAULT_COMPONENT.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            provider: "anthropic".to_owned(),
            model: "auto".to_owned(),
            fork_behavior: "skip".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabInitError {
    InvalidComponent,
    InvalidVersion,
    InvalidProvider,
    InvalidModel,
    InvalidForkBehavior,
}

impl fmt::Display for GitLabInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GitLab CI configuration rejected: {self:?}")
    }
}

impl Error for GitLabInitError {}

/// Generate a version-pinned GitLab CI/CD component import.
///
/// # Errors
///
/// Rejects component, version, provider, model, and fork-behavior values outside
/// the deliberately narrow YAML-safe syntax.
pub fn render_gitlab_ci(options: &GitLabInitOptions) -> Result<String, GitLabInitError> {
    validate_component(&options.component)?;
    validate_atom(&options.version).map_err(|()| GitLabInitError::InvalidVersion)?;
    validate_atom(&options.provider).map_err(|()| GitLabInitError::InvalidProvider)?;
    validate_atom(&options.model).map_err(|()| GitLabInitError::InvalidModel)?;
    if !matches!(options.fork_behavior.as_str(), "report-only" | "skip") {
        return Err(GitLabInitError::InvalidForkBehavior);
    }
    Ok(format!(
        "include:\n  - component: {component}@{version}\n    inputs:\n      provider: {provider}\n      model: {model}\n      fork_behavior: {fork_behavior}\n",
        component = options.component,
        version = options.version,
        provider = options.provider,
        model = options.model,
        fork_behavior = options.fork_behavior,
    ))
}

fn validate_component(value: &str) -> Result<(), GitLabInitError> {
    if value.len() > 512
        || value.split('/').count() < 3
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_'))
    {
        return Err(GitLabInitError::InvalidComponent);
    }
    Ok(())
}

fn validate_atom(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_version_pinned_and_fork_safe() {
        let output = render_gitlab_ci(&GitLabInitOptions {
            version: "1.2.3".to_owned(),
            ..GitLabInitOptions::default()
        })
        .unwrap();
        assert!(output.contains("review@1.2.3"));
        assert!(output.contains("fork_behavior: skip"));
        assert!(!output.contains("latest"));
    }

    #[test]
    fn rejects_yaml_injection() {
        let result = render_gitlab_ci(&GitLabInitOptions {
            model: "auto\nscript: bad".to_owned(),
            ..GitLabInitOptions::default()
        });
        assert_eq!(result, Err(GitLabInitError::InvalidModel));
    }
}
