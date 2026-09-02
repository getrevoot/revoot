//! Versioned shell-completion assets shared by archives and package managers.

use std::fmt;

pub const BASH_COMPLETION: &str = include_str!("../../../packaging/completions/revoot.bash");
pub const ZSH_COMPLETION: &str = include_str!("../../../packaging/completions/_revoot");
pub const FISH_COMPLETION: &str = include_str!("../../../packaging/completions/revoot.fish");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

impl TryFrom<&str> for CompletionShell {
    type Error = CompletionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            _ => Err(CompletionError),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionError;

impl fmt::Display for CompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("completion shell must be bash, zsh, or fish")
    }
}

impl std::error::Error for CompletionError {}

#[must_use]
pub const fn render(shell: CompletionShell) -> &'static str {
    match shell {
        CompletionShell::Bash => BASH_COMPLETION,
        CompletionShell::Zsh => ZSH_COMPLETION,
        CompletionShell::Fish => FISH_COMPLETION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_shells_include_review_and_read_only_auxiliary_surfaces() {
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
        ] {
            let completion = render(shell);
            assert!(completion.ends_with('\n'));
            assert!(completion.contains("review"));
            for command in ["scan", "delegate", "rules", "mcp"] {
                assert!(completion.contains(command));
            }
            assert!(completion.contains("preview"));
            assert!(completion.contains("manifest"));
            assert!(completion.contains("effort"));
            assert!(completion.contains("sarif"));
            assert!(completion.contains("--mr") || completion.contains("-l mr"));
            assert!(completion.contains("--pr") || completion.contains("-l pr"));
            assert!(completion.contains("--repo") || completion.contains("-l repo"));
            assert!(completion.contains("--base") || completion.contains("-l base"));
            assert!(completion.contains("github"));
            assert!(!completion.contains("--depth"));
            assert!(!completion.contains("opencode"));
        }
    }

    #[test]
    fn unknown_shell_is_rejected() {
        assert_eq!(
            CompletionShell::try_from("powershell"),
            Err(CompletionError)
        );
    }
}
