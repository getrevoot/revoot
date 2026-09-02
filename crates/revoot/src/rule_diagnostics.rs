//! Deterministic rule-precedence diagnostics.
//!
//! Inputs and outputs contain only identifiers, path patterns, paths, booleans,
//! and fixed enums. Guidance text, source slices, provider configuration, and
//! model behavior are deliberately outside this contract.

use std::collections::BTreeSet;
use std::fmt;

use globset::Glob;
use revoot_core::RepositoryRelativePath;
use serde::{Deserialize, Serialize};

use crate::review_rules::resolve_embedded_rule;

const MAX_DIAGNOSTIC_PATHS: usize = 32;
const MAX_DIAGNOSTIC_PATH_BYTES: usize = 1_024;
const MAX_DIAGNOSTIC_PATH_TOTAL_BYTES: usize = 16 * 1_024;
const MAX_REPOSITORY_RULES: usize = 32;
const MAX_PATTERNS_PER_RULE: usize = 32;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_RULE_ID_BYTES: usize = 128;
const MAX_REPORT_BYTES: usize = 128 * 1_024;

const COMPILED_SAFETY_RULE_ID: &str = "compiled:safety-invariants";
const BASE_GUIDANCE_RULE_ID: &str = "base:repository-guidance";
const GENERIC_RULE_ID: &str = "generic:review";

/// Metadata required to determine whether one repository rule matches a path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRuleMetadata {
    pub id: String,
    pub path_patterns: Vec<String>,
}

/// Trusted rule-presence metadata resolved from the immutable base commit.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDiagnosticPolicy {
    pub base_guidance_present: bool,
    pub repository_rules: Vec<RepositoryRuleMetadata>,
}

/// Fixed rule layer in descending policy precedence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePrecedenceSource {
    CompiledSafety,
    BaseConfiguration,
    RepositoryRule,
    EmbeddedRule,
    GenericRule,
}

/// One rule layer evaluated for one exact repository path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulePrecedenceTrace {
    pub precedence: u8,
    pub source: RulePrecedenceSource,
    pub active: bool,
    pub rule_ids: Vec<String>,
}

/// Complete path-specific precedence without rule guidance text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathRuleDiagnostics {
    pub path: RepositoryRelativePath,
    pub trace: Vec<RulePrecedenceTrace>,
}

/// Stable JSON contract for `rules check <path...> --json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDiagnosticsReport {
    pub schema_version: String,
    pub paths: Vec<PathRuleDiagnostics>,
}

impl RuleDiagnosticsReport {
    pub const SCHEMA_VERSION: &'static str = "revoot.rule-diagnostics/v1";

    /// Serialize a deterministic metadata-only JSON report.
    ///
    /// # Errors
    ///
    /// Returns a closed error if serialization fails or exceeds the report cap.
    pub fn canonical_json(&self) -> Result<Vec<u8>, RuleDiagnosticsError> {
        let encoded = serde_json::to_vec(self).map_err(|_| RuleDiagnosticsError::Serialization)?;
        if encoded.len() > MAX_REPORT_BYTES {
            return Err(RuleDiagnosticsError::ReportTooLarge);
        }
        Ok(encoded)
    }
}

/// Payload-free diagnostics contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleDiagnosticsError {
    NoPaths,
    TooManyPaths,
    PathTooLong,
    PathInputTooLarge,
    InvalidPath,
    DuplicatePath,
    TooManyRepositoryRules,
    DuplicateRuleIdentifier,
    InvalidRuleIdentifier,
    PatternCount,
    InvalidPattern,
    EmbeddedRule,
    Serialization,
    ReportTooLarge,
}

impl fmt::Display for RuleDiagnosticsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoPaths => "rule diagnostics require at least one path",
            Self::TooManyPaths => "rule diagnostics exceed the path count limit",
            Self::PathTooLong => "rule diagnostics contain an overlong path",
            Self::PathInputTooLarge => "rule diagnostics exceed the aggregate path byte limit",
            Self::InvalidPath => "rule diagnostics contain an invalid repository path",
            Self::DuplicatePath => "rule diagnostics contain a duplicate repository path",
            Self::TooManyRepositoryRules => "rule diagnostics exceed the repository rule limit",
            Self::DuplicateRuleIdentifier => {
                "rule diagnostics contain a duplicate repository rule identifier"
            }
            Self::InvalidRuleIdentifier => {
                "rule diagnostics contain an invalid repository rule identifier"
            }
            Self::PatternCount => "repository rule pattern count is outside the supported range",
            Self::InvalidPattern => "repository rule contains an invalid path pattern",
            Self::EmbeddedRule => "embedded rule resolution failed",
            Self::Serialization => "rule diagnostics serialization failed",
            Self::ReportTooLarge => "rule diagnostics report exceeds its byte limit",
        })
    }
}

impl std::error::Error for RuleDiagnosticsError {}

struct CompiledRepositoryRule {
    id: String,
    matchers: Vec<globset::GlobMatcher>,
}

/// Resolve the fixed rule precedence for bounded repository paths.
///
/// Input paths and output records are sorted lexically. Repository rule matches
/// are sorted by identifier, independent of configuration iteration order.
///
/// # Errors
///
/// Rejects empty, duplicate, malformed, or excessive paths and invalid or
/// ambiguous repository-rule metadata.
pub fn diagnose_rules(
    paths: impl IntoIterator<Item = String>,
    policy: &RuleDiagnosticPolicy,
) -> Result<RuleDiagnosticsReport, RuleDiagnosticsError> {
    let paths = validate_paths(paths)?;
    let repository_rules = compile_repository_rules(policy)?;
    let mut diagnostics = Vec::with_capacity(paths.len());
    for path in paths {
        let mut repository_rule_ids = repository_rules
            .iter()
            .filter(|rule| {
                rule.matchers
                    .iter()
                    .any(|matcher| matcher.is_match(path.as_str()))
            })
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>();
        repository_rule_ids.sort();
        let embedded =
            resolve_embedded_rule(path.as_str()).map_err(|_| RuleDiagnosticsError::EmbeddedRule)?;
        diagnostics.push(PathRuleDiagnostics {
            path,
            trace: vec![
                trace(
                    1,
                    RulePrecedenceSource::CompiledSafety,
                    vec![COMPILED_SAFETY_RULE_ID.to_owned()],
                ),
                trace(
                    2,
                    RulePrecedenceSource::BaseConfiguration,
                    policy
                        .base_guidance_present
                        .then(|| BASE_GUIDANCE_RULE_ID.to_owned())
                        .into_iter()
                        .collect(),
                ),
                trace(3, RulePrecedenceSource::RepositoryRule, repository_rule_ids),
                trace(
                    4,
                    RulePrecedenceSource::EmbeddedRule,
                    vec![embedded.id.to_owned()],
                ),
                trace(
                    5,
                    RulePrecedenceSource::GenericRule,
                    vec![GENERIC_RULE_ID.to_owned()],
                ),
            ],
        });
    }
    let report = RuleDiagnosticsReport {
        schema_version: RuleDiagnosticsReport::SCHEMA_VERSION.to_owned(),
        paths: diagnostics,
    };
    report.canonical_json()?;
    Ok(report)
}

fn trace(
    precedence: u8,
    source: RulePrecedenceSource,
    rule_ids: Vec<String>,
) -> RulePrecedenceTrace {
    RulePrecedenceTrace {
        precedence,
        source,
        active: !rule_ids.is_empty(),
        rule_ids,
    }
}

fn validate_paths(
    paths: impl IntoIterator<Item = String>,
) -> Result<Vec<RepositoryRelativePath>, RuleDiagnosticsError> {
    let supplied = paths.into_iter().collect::<Vec<_>>();
    if supplied.is_empty() {
        return Err(RuleDiagnosticsError::NoPaths);
    }
    if supplied.len() > MAX_DIAGNOSTIC_PATHS {
        return Err(RuleDiagnosticsError::TooManyPaths);
    }
    let total_bytes = supplied.iter().try_fold(0_usize, |total, path| {
        if path.len() > MAX_DIAGNOSTIC_PATH_BYTES {
            return Err(RuleDiagnosticsError::PathTooLong);
        }
        total
            .checked_add(path.len())
            .ok_or(RuleDiagnosticsError::PathInputTooLarge)
    })?;
    if total_bytes > MAX_DIAGNOSTIC_PATH_TOTAL_BYTES {
        return Err(RuleDiagnosticsError::PathInputTooLarge);
    }
    let mut paths = supplied
        .into_iter()
        .map(|path| {
            RepositoryRelativePath::try_from(path).map_err(|_| RuleDiagnosticsError::InvalidPath)
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RuleDiagnosticsError::DuplicatePath);
    }
    Ok(paths)
}

fn compile_repository_rules(
    policy: &RuleDiagnosticPolicy,
) -> Result<Vec<CompiledRepositoryRule>, RuleDiagnosticsError> {
    if policy.repository_rules.len() > MAX_REPOSITORY_RULES {
        return Err(RuleDiagnosticsError::TooManyRepositoryRules);
    }
    let mut observed_ids = BTreeSet::new();
    let mut compiled = Vec::with_capacity(policy.repository_rules.len());
    for rule in &policy.repository_rules {
        if !valid_rule_id(&rule.id) {
            return Err(RuleDiagnosticsError::InvalidRuleIdentifier);
        }
        if !observed_ids.insert(rule.id.clone()) {
            return Err(RuleDiagnosticsError::DuplicateRuleIdentifier);
        }
        if rule.path_patterns.is_empty() || rule.path_patterns.len() > MAX_PATTERNS_PER_RULE {
            return Err(RuleDiagnosticsError::PatternCount);
        }
        let matchers = rule
            .path_patterns
            .iter()
            .map(|pattern| {
                if pattern.is_empty()
                    || pattern.len() > MAX_PATTERN_BYTES
                    || pattern.chars().any(char::is_control)
                {
                    return Err(RuleDiagnosticsError::InvalidPattern);
                }
                Glob::new(pattern)
                    .map(|glob| glob.compile_matcher())
                    .map_err(|_| RuleDiagnosticsError::InvalidPattern)
            })
            .collect::<Result<Vec<_>, _>>()?;
        compiled.push(CompiledRepositoryRule {
            id: rule.id.clone(),
            matchers,
        });
    }
    Ok(compiled)
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_RULE_ID_BYTES
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn traces_fixed_precedence_and_embedded_rule_ids() {
        let report = diagnose_rules(
            ["README.md".to_owned(), "src/lib.rs".to_owned()],
            &RuleDiagnosticPolicy {
                base_guidance_present: true,
                repository_rules: vec![
                    RepositoryRuleMetadata {
                        id: "repo:rust-correctness".to_owned(),
                        path_patterns: vec!["**/*.rs".to_owned()],
                    },
                    RepositoryRuleMetadata {
                        id: "repo:documentation".to_owned(),
                        path_patterns: vec!["**/*.md".to_owned()],
                    },
                ],
            },
        )
        .expect("diagnostics");
        assert_eq!(report.paths[0].path.as_str(), "README.md");
        assert_eq!(report.paths[1].path.as_str(), "src/lib.rs");
        for path in &report.paths {
            assert_eq!(
                path.trace
                    .iter()
                    .map(|layer| layer.precedence)
                    .collect::<Vec<_>>(),
                [1, 2, 3, 4, 5]
            );
            assert_eq!(path.trace[0].source, RulePrecedenceSource::CompiledSafety);
            assert_eq!(
                path.trace[1].source,
                RulePrecedenceSource::BaseConfiguration
            );
            assert!(path.trace[1].active);
            assert_eq!(path.trace[4].source, RulePrecedenceSource::GenericRule);
        }
        assert_eq!(report.paths[0].trace[3].rule_ids, ["default.md"]);
        assert_eq!(report.paths[1].trace[3].rule_ids, ["rust.md"]);
        assert_eq!(report.paths[1].trace[2].rule_ids, ["repo:rust-correctness"]);
    }

    #[test]
    fn inactive_layers_remain_visible_without_rule_content() {
        let report = diagnose_rules(["src/lib.rs".to_owned()], &RuleDiagnosticPolicy::default())
            .expect("diagnostics");
        assert!(!report.paths[0].trace[1].active);
        assert!(!report.paths[0].trace[2].active);
        let encoded = report.canonical_json().expect("JSON");
        let value: Value = serde_json::from_slice(&encoded).expect("valid JSON");
        assert_metadata_keys_only(&value);
        let text = String::from_utf8(encoded).expect("UTF-8 JSON");
        assert!(!text.contains("guidance"));
        assert!(!text.contains("provider"));
        assert!(!text.contains("prompt"));
    }

    #[test]
    fn rule_match_output_is_sorted_by_identifier() {
        let report = diagnose_rules(
            ["src/lib.rs".to_owned()],
            &RuleDiagnosticPolicy {
                base_guidance_present: false,
                repository_rules: vec![
                    RepositoryRuleMetadata {
                        id: "repo:z".to_owned(),
                        path_patterns: vec!["src/**".to_owned()],
                    },
                    RepositoryRuleMetadata {
                        id: "repo:a".to_owned(),
                        path_patterns: vec!["**/*.rs".to_owned()],
                    },
                ],
            },
        )
        .expect("diagnostics");
        assert_eq!(report.paths[0].trace[2].rule_ids, ["repo:a", "repo:z"]);
    }

    #[test]
    fn rejects_empty_duplicate_and_invalid_paths() {
        assert_eq!(
            diagnose_rules(Vec::new(), &RuleDiagnosticPolicy::default()).expect_err("empty paths"),
            RuleDiagnosticsError::NoPaths
        );
        assert_eq!(
            diagnose_rules(
                ["src/lib.rs".to_owned(), "src/lib.rs".to_owned()],
                &RuleDiagnosticPolicy::default(),
            )
            .expect_err("duplicate path"),
            RuleDiagnosticsError::DuplicatePath
        );
        assert_eq!(
            diagnose_rules(["../secret".to_owned()], &RuleDiagnosticPolicy::default(),)
                .expect_err("invalid path"),
            RuleDiagnosticsError::InvalidPath
        );
    }

    #[test]
    fn rejects_excessive_path_count() {
        let paths = (0..=MAX_DIAGNOSTIC_PATHS)
            .map(|index| format!("src/{index}.rs"))
            .collect::<Vec<_>>();
        assert_eq!(
            diagnose_rules(paths, &RuleDiagnosticPolicy::default()).expect_err("too many paths"),
            RuleDiagnosticsError::TooManyPaths
        );
    }

    #[test]
    fn rejects_invalid_or_ambiguous_repository_rule_metadata() {
        let invalid_id = RuleDiagnosticPolicy {
            base_guidance_present: false,
            repository_rules: vec![RepositoryRuleMetadata {
                id: "repo\nrule".to_owned(),
                path_patterns: vec!["src/**".to_owned()],
            }],
        };
        assert_eq!(
            diagnose_rules(["src/lib.rs".to_owned()], &invalid_id).expect_err("invalid ID"),
            RuleDiagnosticsError::InvalidRuleIdentifier
        );

        let duplicate = RuleDiagnosticPolicy {
            base_guidance_present: false,
            repository_rules: vec![
                RepositoryRuleMetadata {
                    id: "repo:one".to_owned(),
                    path_patterns: vec!["src/**".to_owned()],
                },
                RepositoryRuleMetadata {
                    id: "repo:one".to_owned(),
                    path_patterns: vec!["tests/**".to_owned()],
                },
            ],
        };
        assert_eq!(
            diagnose_rules(["src/lib.rs".to_owned()], &duplicate).expect_err("duplicate ID"),
            RuleDiagnosticsError::DuplicateRuleIdentifier
        );

        let invalid_pattern = RuleDiagnosticPolicy {
            base_guidance_present: false,
            repository_rules: vec![RepositoryRuleMetadata {
                id: "repo:one".to_owned(),
                path_patterns: vec!["[".to_owned()],
            }],
        };
        assert_eq!(
            diagnose_rules(["src/lib.rs".to_owned()], &invalid_pattern)
                .expect_err("invalid pattern"),
            RuleDiagnosticsError::InvalidPattern
        );
    }

    fn assert_metadata_keys_only(value: &Value) {
        let root = value.as_object().expect("root object");
        assert_eq!(
            root.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["paths", "schema_version"])
        );
        for path in root["paths"].as_array().expect("paths") {
            let path = path.as_object().expect("path object");
            assert_eq!(
                path.keys().map(String::as_str).collect::<BTreeSet<_>>(),
                BTreeSet::from(["path", "trace"])
            );
            for layer in path["trace"].as_array().expect("trace") {
                assert_eq!(
                    layer
                        .as_object()
                        .expect("trace object")
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from(["active", "precedence", "rule_ids", "source"])
                );
            }
        }
    }
}
