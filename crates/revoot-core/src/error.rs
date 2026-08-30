use serde::{Deserialize, Serialize};

/// Stable, redaction-safe machine error codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    CliInvalidArgument,
    CapabilityUnavailable,
    ContractInvalid,
    RepositoryUnavailable,
    ProviderUnavailable,
    GitLabUnavailable,
    GitHubUnavailable,
    ReviewFailed,
}

impl ErrorCode {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CliInvalidArgument => "RVT-CLI-0001",
            Self::CapabilityUnavailable => "RVT-CAPABILITY-0001",
            Self::ContractInvalid => "RVT-CONTRACT-0001",
            Self::RepositoryUnavailable => "RVT-REPOSITORY-0001",
            Self::ProviderUnavailable => "RVT-PROVIDER-0001",
            Self::GitLabUnavailable => "RVT-GITLAB-0001",
            Self::GitHubUnavailable => "RVT-GITHUB-0001",
            Self::ReviewFailed => "RVT-REVIEW-0001",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub code: ErrorCode,
    pub machine_code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Diagnostic {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            machine_code: code.code().to_owned(),
            message: message.into(),
            remediation: None,
        }
    }

    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;

    #[test]
    fn codes_are_stable_and_namespaced() {
        assert_eq!(
            ErrorCode::CapabilityUnavailable.code(),
            "RVT-CAPABILITY-0001"
        );
        assert_eq!(ErrorCode::ContractInvalid.code(), "RVT-CONTRACT-0001");
        assert_eq!(
            ErrorCode::RepositoryUnavailable.code(),
            "RVT-REPOSITORY-0001"
        );
        assert_eq!(ErrorCode::ProviderUnavailable.code(), "RVT-PROVIDER-0001");
        assert_eq!(ErrorCode::GitLabUnavailable.code(), "RVT-GITLAB-0001");
        assert_eq!(ErrorCode::GitHubUnavailable.code(), "RVT-GITHUB-0001");
        assert_eq!(ErrorCode::ReviewFailed.code(), "RVT-REVIEW-0001");
    }
}
