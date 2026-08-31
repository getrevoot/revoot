//! Deterministic GitHub Actions workflow generation.

use std::error::Error;
use std::fmt;

const CHECKOUT_ACTION: &str = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd";
const UPLOAD_ACTION: &str = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubInitOptions {
    pub image: String,
    pub provider: String,
    pub model: String,
    pub fork_behavior: String,
}

impl Default for GitHubInitOptions {
    fn default() -> Self {
        Self {
            image: String::new(),
            provider: "auto".to_owned(),
            model: "auto".to_owned(),
            fork_behavior: "skip".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubInitError {
    Image,
    Provider,
    Model,
    ForkBehavior,
}

impl fmt::Display for GitHubInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image => formatter.write_str(
                "GitHub workflow image must be an immutable image@sha256 digest reference",
            ),
            Self::Provider | Self::Model | Self::ForkBehavior => {
                formatter.write_str("GitHub workflow input is invalid")
            }
        }
    }
}

impl Error for GitHubInitError {}

/// Render one deterministic, fork-safe Actions workflow.
///
/// # Errors
///
/// Rejects unsupported or YAML-unsafe image, provider, model, and fork inputs.
pub fn render_github_actions(options: &GitHubInitOptions) -> Result<String, GitHubInitError> {
    if !valid_image_digest(&options.image) {
        return Err(GitHubInitError::Image);
    }
    if !matches!(options.provider.as_str(), "anthropic" | "openai" | "auto") {
        return Err(GitHubInitError::Provider);
    }
    if !valid_atom(&options.model, revoot_core::MAX_MODEL_ID_BYTES) {
        return Err(GitHubInitError::Model);
    }
    if !matches!(options.fork_behavior.as_str(), "skip" | "report-only") {
        return Err(GitHubInitError::ForkBehavior);
    }
    let fork_condition = if options.fork_behavior == "skip" {
        " && github.event.pull_request.head.repo.full_name == github.repository"
    } else {
        ""
    };
    let provider = format!("${{{{ vars.REVOOT_PROVIDER || '{}' }}}}", options.provider);
    let model = format!("${{{{ vars.REVOOT_MODEL || '{}' }}}}", options.model);
    Ok(format!(
        r#"name: Revoot review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  packages: read
  pull-requests: write

concurrency:
  group: revoot-${{{{ github.event.pull_request.number }}}}
  cancel-in-progress: true

jobs:
  review:
    name: Review pull request
    if: github.event.pull_request.draft == false{fork_condition}
    runs-on: ubuntu-latest
    timeout-minutes: 10
    container:
      image: {image}
      credentials:
        username: ${{{{ github.actor }}}}
        password: ${{{{ github.token }}}}
      options: --user 0:0 --security-opt no-new-privileges
    steps:
      - name: Check out source
        uses: {CHECKOUT_ACTION}
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - name: Prepare workspace
        run: |
          chown 65532:65532 "$GITHUB_WORKSPACE"
          chown -R 65532:65532 "$GITHUB_WORKSPACE/.git"
      - name: Review pull request
        run: su -p -s /bin/sh revoot -c 'exec revoot review --ci --format json --output revoot-review.json'
        env:
          GITHUB_TOKEN: ${{{{ github.token }}}}
          REVOOT_GITHUB_TOKEN: ${{{{ secrets.REVOOT_GITHUB_TOKEN }}}}
          ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
          OPENAI_API_KEY: ${{{{ secrets.OPENAI_API_KEY }}}}
          REVOOT_PROVIDER: {provider}
          REVOOT_MODEL: {model}
          REVOOT_FORK_BEHAVIOR: {fork_behavior}
          REVOOT_PUBLICATION_ENABLED: "true"
      - name: Upload report
        if: always()
        uses: {UPLOAD_ACTION}
        with:
          name: revoot-review
          path: revoot-review.json
          if-no-files-found: ignore
          retention-days: 7
"#,
        image = options.image,
        fork_behavior = options.fork_behavior,
    ))
}

fn valid_atom(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b':' | b'@' | b'_' | b'-')
        })
}

fn valid_image_digest(value: &str) -> bool {
    let Some((image, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    valid_atom(value, 512)
        && image.contains('/')
        && !image.ends_with('/')
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> GitHubInitOptions {
        GitHubInitOptions {
            image: format!("ghcr.io/getrevoot/revoot:0.1.0@sha256:{}", "a".repeat(64)),
            ..GitHubInitOptions::default()
        }
    }

    #[test]
    fn workflow_is_head_bound_pinned_and_least_privilege() {
        let workflow = render_github_actions(&options()).expect("workflow");
        assert!(workflow.contains("ref: ${{ github.event.pull_request.head.sha }}"));
        assert!(workflow.contains(CHECKOUT_ACTION));
        assert!(workflow.contains("contents: read"));
        assert!(workflow.contains("packages: read"));
        assert!(workflow.contains("pull-requests: write"));
        assert!(workflow.contains("head.repo.full_name == github.repository"));
        assert!(workflow.contains("REVOOT_PUBLICATION_ENABLED: \"true\""));
        assert!(workflow.contains("REVOOT_PROVIDER: ${{ vars.REVOOT_PROVIDER || 'auto' }}"));
        assert!(workflow.contains("REVOOT_MODEL: ${{ vars.REVOOT_MODEL || 'auto' }}"));
        assert!(workflow.contains("REVOOT_GITHUB_TOKEN: ${{ secrets.REVOOT_GITHUB_TOKEN }}"));
        assert!(workflow.contains("image: ghcr.io/getrevoot/revoot:0.1.0@sha256:"));
        assert!(workflow.contains("--security-opt no-new-privileges"));
        assert!(workflow.contains("chown 65532:65532 \"$GITHUB_WORKSPACE\""));
        assert!(workflow.contains("chown -R 65532:65532 \"$GITHUB_WORKSPACE/.git\""));
        assert!(workflow.contains("su -p -s /bin/sh revoot"));
        assert!(!workflow.contains("pull_request_target"));
        assert!(!workflow.contains("workflow_run"));
        assert!(!workflow.contains("@main"));
    }

    #[test]
    fn injected_inputs_are_rejected() {
        let options = GitHubInitOptions {
            image: "image\nrun: curl evil".to_owned(),
            ..options()
        };
        assert_eq!(render_github_actions(&options), Err(GitHubInitError::Image));
    }

    #[test]
    fn workflow_variables_override_generated_fallbacks() {
        let workflow = render_github_actions(&GitHubInitOptions {
            provider: "openai".to_owned(),
            model: "gpt-5.3-codex".to_owned(),
            ..options()
        })
        .expect("workflow");

        assert!(workflow.contains("REVOOT_PROVIDER: ${{ vars.REVOOT_PROVIDER || 'openai' }}"));
        assert!(workflow.contains("REVOOT_MODEL: ${{ vars.REVOOT_MODEL || 'gpt-5.3-codex' }}"));
    }

    #[test]
    fn mutable_image_tags_are_rejected() {
        let value = GitHubInitOptions {
            image: "ghcr.io/getrevoot/revoot:0.1.0".to_owned(),
            ..options()
        };
        assert_eq!(render_github_actions(&value), Err(GitHubInitError::Image));
        assert_eq!(
            render_github_actions(&GitHubInitOptions::default()),
            Err(GitHubInitError::Image)
        );
    }
}
