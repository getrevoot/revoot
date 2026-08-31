//! Deterministic `revoot init gitlab` output generation.

use std::error::Error;
use std::fmt;

const DEFAULT_COMPONENT: &str = "gitlab.com/revoot/revoot-ci/review";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitLabInitOptions {
    pub image: String,
    pub component: String,
    pub version: String,
    pub provider: String,
    pub model: String,
    pub fork_behavior: String,
}

impl Default for GitLabInitOptions {
    fn default() -> Self {
        Self {
            image: String::new(),
            component: DEFAULT_COMPONENT.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            provider: "auto".to_owned(),
            model: "auto".to_owned(),
            fork_behavior: "skip".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabInitError {
    InvalidComponent,
    InvalidImage,
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
    validate_image_digest(&options.image)?;
    validate_atom(&options.version).map_err(|()| GitLabInitError::InvalidVersion)?;
    validate_atom(&options.provider).map_err(|()| GitLabInitError::InvalidProvider)?;
    validate_atom(&options.model).map_err(|()| GitLabInitError::InvalidModel)?;
    if !matches!(options.fork_behavior.as_str(), "report-only" | "skip") {
        return Err(GitLabInitError::InvalidForkBehavior);
    }
    Ok(format!(
        "include:\n  - component: {component}@{version}\n    inputs:\n      image: {image}\n      provider: {provider}\n      model: {model}\n      fork_behavior: {fork_behavior}\n",
        component = options.component,
        image = options.image,
        version = options.version,
        provider = options.provider,
        model = options.model,
        fork_behavior = options.fork_behavior,
    ))
}

fn validate_image_digest(value: &str) -> Result<(), GitLabInitError> {
    let Some((image, digest)) = value.rsplit_once("@sha256:") else {
        return Err(GitLabInitError::InvalidImage);
    };
    if image.is_empty()
        || !image.contains('/')
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b':' | b'@' | b'_' | b'-')
        })
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(GitLabInitError::InvalidImage);
    }
    Ok(())
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

    fn options() -> GitLabInitOptions {
        GitLabInitOptions {
            image: format!("ghcr.io/getrevoot/revoot:1.2.3@sha256:{}", "a".repeat(64)),
            ..GitLabInitOptions::default()
        }
    }

    #[test]
    fn output_is_version_pinned_and_fork_safe() {
        let output = render_gitlab_ci(&GitLabInitOptions {
            version: "1.2.3".to_owned(),
            ..options()
        })
        .unwrap();
        assert!(output.contains("review@1.2.3"));
        assert!(output.contains("provider: auto"));
        assert!(output.contains("image: ghcr.io/getrevoot/revoot:1.2.3@sha256:"));
        assert!(output.contains("fork_behavior: skip"));
        assert!(!output.contains("latest"));
    }

    #[test]
    fn rejects_yaml_injection() {
        let result = render_gitlab_ci(&GitLabInitOptions {
            model: "auto\nscript: bad".to_owned(),
            ..options()
        });
        assert_eq!(result, Err(GitLabInitError::InvalidModel));
    }

    #[test]
    fn mutable_image_tags_are_rejected() {
        assert_eq!(
            render_gitlab_ci(&GitLabInitOptions {
                image: "ghcr.io/getrevoot/revoot:1.2.3".to_owned(),
                ..options()
            }),
            Err(GitLabInitError::InvalidImage)
        );
    }
}
