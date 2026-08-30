//! Deterministic GitHub Actions workflow generation.

use std::error::Error;
use std::fmt;

const CHECKOUT_ACTION: &str = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5";

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
            image: "ghcr.io/getrevoot/revoot:0.1.0".to_owned(),
            provider: "anthropic".to_owned(),
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
        formatter.write_str("GitHub workflow input is invalid")
    }
}

impl Error for GitHubInitError {}

/// Render one deterministic, fork-safe Actions workflow.
///
/// # Errors
///
/// Rejects unsupported or YAML-unsafe image, provider, model, and fork inputs.
pub fn render_github_actions(options: &GitHubInitOptions) -> Result<String, GitHubInitError> {
    if !valid_atom(&options.image, 512)
        || !options.image.contains('/')
        || !options.image.contains(':') && !options.image.contains("@sha256:")
    {
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
    Ok(format!(
        "name: Revoot review\n\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review]\n\npermissions:\n  contents: read\n  pull-requests: write\n\nconcurrency:\n  group: revoot-${{{{ github.event.pull_request.number }}}}\n  cancel-in-progress: true\n\njobs:\n  review:\n    if: github.event.pull_request.draft == false{fork_condition}\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    container:\n      image: {}\n    steps:\n      - uses: {CHECKOUT_ACTION}\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n      - name: Review pull request\n        run: revoot review --ci --format json --output revoot-review.json\n        env:\n          GITHUB_TOKEN: ${{{{ github.token }}}}\n          ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}\n          OPENAI_API_KEY: ${{{{ secrets.OPENAI_API_KEY }}}}\n          REVOOT_PROVIDER: {}\n          REVOOT_MODEL: {}\n          REVOOT_FORK_BEHAVIOR: {}\n          REVOOT_PUBLICATION_ENABLED: \"true\"\n      - name: Upload report\n        if: always()\n        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with:\n          name: revoot-review\n          path: revoot-review.json\n          if-no-files-found: ignore\n          retention-days: 7\n",
        options.image, options.provider, options.model, options.fork_behavior
    ))
}

fn valid_atom(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b':' | b'@' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_is_head_bound_pinned_and_least_privilege() {
        let workflow = render_github_actions(&GitHubInitOptions::default()).expect("workflow");
        assert!(workflow.contains("ref: ${{ github.event.pull_request.head.sha }}"));
        assert!(workflow.contains(CHECKOUT_ACTION));
        assert!(workflow.contains("contents: read"));
        assert!(workflow.contains("pull-requests: write"));
        assert!(workflow.contains("head.repo.full_name == github.repository"));
        assert!(workflow.contains("REVOOT_PUBLICATION_ENABLED: \"true\""));
        assert!(!workflow.contains("pull_request_target"));
        assert!(!workflow.contains("workflow_run"));
        assert!(!workflow.contains("@main"));
    }

    #[test]
    fn injected_inputs_are_rejected() {
        let options = GitHubInitOptions {
            image: "image\nrun: curl evil".to_owned(),
            ..GitHubInitOptions::default()
        };
        assert_eq!(render_github_actions(&options), Err(GitHubInitError::Image));
    }
}
