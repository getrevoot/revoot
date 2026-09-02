//! Closed contracts for the internal review-worker tool registry.
//!
//! This module defines schemas and limits only. It contains no tool handlers,
//! filesystem access, network behavior, process launch, or provider behavior.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

const MAX_TOOL_RESULT_BYTES: u32 = 32 * 1_024;
const MAX_CHECKPOINT_BYTES: u32 = 4 * 1_024;
const MAX_BATCH_ITEMS: u16 = 32;
const MAX_SEARCH_RESULTS: u16 = 500;
const MAX_FILE_LINES: u16 = 500;
const MAX_FINDINGS: u16 = 25;

/// Complete allowlisted internal tool identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewToolId {
    DiffManifest,
    ReadDiff,
    SearchDiff,
    ReadFile,
    FindFiles,
    SearchCode,
    ListChangeCommits,
    ShowCommitContext,
    GetExistingRevootFindings,
    CheckpointReview,
    SubmitCandidateFinding,
    CompleteGroup,
}

/// Authority flags evaluated before a handler may be connected.
///
/// `read` covers bounded allowlisted repository, artifact, history, or review
/// metadata reads. `write` is external filesystem or repository mutation and is
/// always false. Internal worker transitions have a separate flag.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewToolPermission {
    Denied,
    Allowed,
}

/// Typed authority flags evaluated before a handler may be connected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewToolAuthority {
    pub read: ReviewToolPermission,
    pub write: ReviewToolPermission,
    pub network: ReviewToolPermission,
    pub process: ReviewToolPermission,
    pub environment: ReviewToolPermission,
    pub internal_state_update: ReviewToolPermission,
}

/// Fixed ceilings applied before and after each tool invocation.
///
/// Zero means the dimension is not accepted by that tool, never unbounded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewToolLimits {
    pub batch_items: u16,
    pub result_bytes: u32,
    pub results: u16,
    pub lines_per_read: u16,
    pub checkpoint_bytes: u32,
    pub findings: u16,
}

/// Machine-accounted effect of a successful tool result on worker coverage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewToolCoverageEffect {
    ManifestMetadata,
    DeliveredDiffPage,
    NarrowEvidence,
    CompletionContract,
}

/// One closed tool contract with no executable handler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewToolContract {
    pub id: ReviewToolId,
    pub authority: ReviewToolAuthority,
    pub limits: ReviewToolLimits,
    pub coverage: BTreeSet<ReviewToolCoverageEffect>,
}

/// Versioned deterministic registry for internal group workers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewToolRegistry {
    pub schema_version: String,
    pub tools: Vec<ReviewToolContract>,
}

impl ReviewToolRegistry {
    pub const SCHEMA_VERSION: &'static str = "revoot.review-tools/v1";

    /// Validate the exact allowlist, ordering, flags, ceilings, and effects.
    ///
    /// # Errors
    ///
    /// Rejects any schema drift, missing or added tool, expanded authority,
    /// weakened bound, or changed coverage effect.
    pub fn validate(&self) -> Result<(), ReviewToolRegistryError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ReviewToolRegistryError::SchemaVersion);
        }
        let expected = build_review_tool_registry();
        if self.tools.len() != expected.tools.len()
            || self
                .tools
                .iter()
                .map(|tool| tool.id)
                .ne(expected.tools.iter().map(|tool| tool.id))
        {
            return Err(ReviewToolRegistryError::ToolSurface);
        }
        for (tool, expected) in self.tools.iter().zip(expected.tools) {
            if tool.authority != expected.authority {
                return Err(ReviewToolRegistryError::Authority);
            }
            if tool.limits != expected.limits {
                return Err(ReviewToolRegistryError::Limits);
            }
            if tool.coverage != expected.coverage {
                return Err(ReviewToolRegistryError::Coverage);
            }
        }
        Ok(())
    }

    /// Serialize the validated registry with stable field and list ordering.
    ///
    /// # Errors
    ///
    /// Returns a closed error for validation or serialization failure.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ReviewToolRegistryError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ReviewToolRegistryError::Serialization)
    }
}

/// Payload-free registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewToolRegistryError {
    SchemaVersion,
    ToolSurface,
    Authority,
    Limits,
    Coverage,
    Serialization,
}

impl fmt::Display for ReviewToolRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "review tool registry schema version is unsupported",
            Self::ToolSurface => "review tool registry surface is invalid",
            Self::Authority => "review tool authority exceeds the closed contract",
            Self::Limits => "review tool limits differ from the fixed contract",
            Self::Coverage => "review tool coverage effects differ from the fixed contract",
            Self::Serialization => "review tool registry serialization failed",
        })
    }
}

impl std::error::Error for ReviewToolRegistryError {}

/// Build the exact internal group-worker tool registry.
#[must_use]
pub fn build_review_tool_registry() -> ReviewToolRegistry {
    ReviewToolRegistry {
        schema_version: ReviewToolRegistry::SCHEMA_VERSION.to_owned(),
        tools: vec![
            read_tool(
                ReviewToolId::DiffManifest,
                limits(1, MAX_TOOL_RESULT_BYTES, 0, 0, 0, 0),
                coverage(&[ReviewToolCoverageEffect::ManifestMetadata]),
            ),
            read_tool(
                ReviewToolId::ReadDiff,
                limits(MAX_BATCH_ITEMS, MAX_TOOL_RESULT_BYTES, 0, 0, 0, 0),
                coverage(&[
                    ReviewToolCoverageEffect::DeliveredDiffPage,
                    ReviewToolCoverageEffect::NarrowEvidence,
                ]),
            ),
            read_tool(
                ReviewToolId::SearchDiff,
                limits(
                    MAX_BATCH_ITEMS,
                    MAX_TOOL_RESULT_BYTES,
                    MAX_SEARCH_RESULTS,
                    0,
                    0,
                    0,
                ),
                coverage(&[ReviewToolCoverageEffect::NarrowEvidence]),
            ),
            read_tool(
                ReviewToolId::ReadFile,
                limits(
                    MAX_BATCH_ITEMS,
                    MAX_TOOL_RESULT_BYTES,
                    0,
                    MAX_FILE_LINES,
                    0,
                    0,
                ),
                coverage(&[ReviewToolCoverageEffect::NarrowEvidence]),
            ),
            read_tool(
                ReviewToolId::FindFiles,
                limits(
                    MAX_BATCH_ITEMS,
                    MAX_TOOL_RESULT_BYTES,
                    MAX_SEARCH_RESULTS,
                    0,
                    0,
                    0,
                ),
                no_coverage(),
            ),
            read_tool(
                ReviewToolId::SearchCode,
                limits(
                    MAX_BATCH_ITEMS,
                    MAX_TOOL_RESULT_BYTES,
                    MAX_SEARCH_RESULTS,
                    0,
                    0,
                    0,
                ),
                coverage(&[ReviewToolCoverageEffect::NarrowEvidence]),
            ),
            read_tool(
                ReviewToolId::ListChangeCommits,
                limits(1, MAX_TOOL_RESULT_BYTES, 256, 0, 0, 0),
                no_coverage(),
            ),
            read_tool(
                ReviewToolId::ShowCommitContext,
                limits(MAX_BATCH_ITEMS, MAX_TOOL_RESULT_BYTES, 0, 0, 0, 0),
                coverage(&[ReviewToolCoverageEffect::NarrowEvidence]),
            ),
            read_tool(
                ReviewToolId::GetExistingRevootFindings,
                limits(1, MAX_TOOL_RESULT_BYTES, 10, 0, 0, 0),
                coverage(&[ReviewToolCoverageEffect::NarrowEvidence]),
            ),
            state_tool(
                ReviewToolId::CheckpointReview,
                limits(1, MAX_CHECKPOINT_BYTES, 0, 0, MAX_CHECKPOINT_BYTES, 0),
                no_coverage(),
            ),
            state_tool(
                ReviewToolId::SubmitCandidateFinding,
                limits(1, MAX_TOOL_RESULT_BYTES, 0, 0, 0, MAX_FINDINGS),
                no_coverage(),
            ),
            state_tool(
                ReviewToolId::CompleteGroup,
                limits(1, MAX_CHECKPOINT_BYTES, 0, 0, 0, 0),
                coverage(&[ReviewToolCoverageEffect::CompletionContract]),
            ),
        ],
    }
}

fn read_tool(
    id: ReviewToolId,
    limits: ReviewToolLimits,
    coverage: BTreeSet<ReviewToolCoverageEffect>,
) -> ReviewToolContract {
    ReviewToolContract {
        id,
        authority: ReviewToolAuthority {
            read: ReviewToolPermission::Allowed,
            write: ReviewToolPermission::Denied,
            network: ReviewToolPermission::Denied,
            process: ReviewToolPermission::Denied,
            environment: ReviewToolPermission::Denied,
            internal_state_update: ReviewToolPermission::Denied,
        },
        limits,
        coverage,
    }
}

fn state_tool(
    id: ReviewToolId,
    limits: ReviewToolLimits,
    coverage: BTreeSet<ReviewToolCoverageEffect>,
) -> ReviewToolContract {
    ReviewToolContract {
        id,
        authority: ReviewToolAuthority {
            read: ReviewToolPermission::Denied,
            write: ReviewToolPermission::Denied,
            network: ReviewToolPermission::Denied,
            process: ReviewToolPermission::Denied,
            environment: ReviewToolPermission::Denied,
            internal_state_update: ReviewToolPermission::Allowed,
        },
        limits,
        coverage,
    }
}

const fn limits(
    max_batch_items: u16,
    max_result_bytes: u32,
    max_results: u16,
    max_lines_per_read: u16,
    max_checkpoint_bytes: u32,
    max_findings: u16,
) -> ReviewToolLimits {
    ReviewToolLimits {
        batch_items: max_batch_items,
        result_bytes: max_result_bytes,
        results: max_results,
        lines_per_read: max_lines_per_read,
        checkpoint_bytes: max_checkpoint_bytes,
        findings: max_findings,
    }
}

fn coverage(effects: &[ReviewToolCoverageEffect]) -> BTreeSet<ReviewToolCoverageEffect> {
    effects.iter().copied().collect()
}

fn no_coverage() -> BTreeSet<ReviewToolCoverageEffect> {
    BTreeSet::new()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn canonical_registry_is_deterministic_and_complete() {
        let registry = build_review_tool_registry();
        let first = registry.canonical_json().expect("registry JSON");
        let second = build_review_tool_registry()
            .canonical_json()
            .expect("registry replay JSON");
        assert_eq!(first, second);
        assert_eq!(
            registry
                .tools
                .iter()
                .map(|tool| tool.id)
                .collect::<Vec<_>>(),
            [
                ReviewToolId::DiffManifest,
                ReviewToolId::ReadDiff,
                ReviewToolId::SearchDiff,
                ReviewToolId::ReadFile,
                ReviewToolId::FindFiles,
                ReviewToolId::SearchCode,
                ReviewToolId::ListChangeCommits,
                ReviewToolId::ShowCommitContext,
                ReviewToolId::GetExistingRevootFindings,
                ReviewToolId::CheckpointReview,
                ReviewToolId::SubmitCandidateFinding,
                ReviewToolId::CompleteGroup,
            ]
        );
    }

    #[test]
    fn every_tool_denies_external_write_network_process_and_environment() {
        let registry = build_review_tool_registry();
        assert!(registry.tools.iter().all(|tool| {
            tool.authority.write == ReviewToolPermission::Denied
                && tool.authority.network == ReviewToolPermission::Denied
                && tool.authority.process == ReviewToolPermission::Denied
                && tool.authority.environment == ReviewToolPermission::Denied
        }));
        assert!(registry.tools[..9].iter().all(|tool| {
            tool.authority.read == ReviewToolPermission::Allowed
                && tool.authority.internal_state_update == ReviewToolPermission::Denied
        }));
        assert!(registry.tools[9..].iter().all(|tool| {
            tool.authority.read == ReviewToolPermission::Denied
                && tool.authority.internal_state_update == ReviewToolPermission::Allowed
        }));
    }

    #[test]
    fn bounds_match_fixed_batch_result_and_payload_ceilings() {
        let registry = build_review_tool_registry();
        assert!(registry.tools.iter().all(|tool| tool.limits.batch_items > 0
            && tool.limits.batch_items <= MAX_BATCH_ITEMS
            && tool.limits.result_bytes > 0
            && tool.limits.result_bytes <= MAX_TOOL_RESULT_BYTES));
        let read_file = tool(&registry, ReviewToolId::ReadFile);
        assert_eq!(read_file.limits.lines_per_read, 500);
        let search = tool(&registry, ReviewToolId::SearchCode);
        assert_eq!(search.limits.results, 500);
        let checkpoint = tool(&registry, ReviewToolId::CheckpointReview);
        assert_eq!(checkpoint.limits.checkpoint_bytes, 4 * 1_024);
        let submit = tool(&registry, ReviewToolId::SubmitCandidateFinding);
        assert_eq!(submit.limits.findings, 25);
    }

    #[test]
    fn coverage_effects_distinguish_delivery_evidence_and_completion() {
        let registry = build_review_tool_registry();
        assert!(
            tool(&registry, ReviewToolId::DiffManifest)
                .coverage
                .contains(&ReviewToolCoverageEffect::ManifestMetadata)
        );
        let read_diff = &tool(&registry, ReviewToolId::ReadDiff).coverage;
        assert!(read_diff.contains(&ReviewToolCoverageEffect::DeliveredDiffPage));
        assert!(read_diff.contains(&ReviewToolCoverageEffect::NarrowEvidence));
        let search_diff = &tool(&registry, ReviewToolId::SearchDiff).coverage;
        assert!(!search_diff.contains(&ReviewToolCoverageEffect::DeliveredDiffPage));
        assert!(search_diff.contains(&ReviewToolCoverageEffect::NarrowEvidence));
        assert!(
            tool(&registry, ReviewToolId::CompleteGroup)
                .coverage
                .contains(&ReviewToolCoverageEffect::CompletionContract)
        );
    }

    #[test]
    fn deserialization_rejects_generic_or_expansive_tool_identities() {
        let base = serde_json::to_value(build_review_tool_registry()).expect("registry value");
        for forbidden in [
            "shell",
            "awk",
            "http",
            "environment",
            "write_file",
            "execute_command",
        ] {
            let mut value = base.clone();
            value["tools"][0]["id"] = Value::String(forbidden.to_owned());
            assert!(serde_json::from_value::<ReviewToolRegistry>(value).is_err());
        }
    }

    #[test]
    fn validation_rejects_authority_limit_coverage_or_surface_changes() {
        let mut registry = build_review_tool_registry();
        registry.tools[0].authority.process = ReviewToolPermission::Allowed;
        assert_eq!(
            registry.validate().expect_err("process authority"),
            ReviewToolRegistryError::Authority
        );

        let mut registry = build_review_tool_registry();
        registry.tools[1].limits.result_bytes += 1;
        assert_eq!(
            registry.validate().expect_err("larger result"),
            ReviewToolRegistryError::Limits
        );

        let mut registry = build_review_tool_registry();
        registry.tools[2]
            .coverage
            .insert(ReviewToolCoverageEffect::DeliveredDiffPage);
        assert_eq!(
            registry.validate().expect_err("coverage inflation"),
            ReviewToolRegistryError::Coverage
        );

        let mut registry = build_review_tool_registry();
        registry.tools.pop();
        assert_eq!(
            registry.validate().expect_err("missing tool"),
            ReviewToolRegistryError::ToolSurface
        );
    }

    #[test]
    fn canonical_json_is_schema_only_and_contains_no_handler_payload() {
        let encoded = build_review_tool_registry()
            .canonical_json()
            .expect("registry JSON");
        let value: Value = serde_json::from_slice(&encoded).expect("valid JSON");
        assert_eq!(value["schema_version"], ReviewToolRegistry::SCHEMA_VERSION);
        assert_eq!(value["tools"].as_array().expect("tools").len(), 12);
        let text = String::from_utf8(encoded).expect("UTF-8 JSON");
        for absent in ["handler", "command", "executable", "endpoint", "payload"] {
            assert!(!text.contains(absent));
        }
        assert_eq!(
            value["tools"][0]["authority"],
            json!({
                "read": "allowed",
                "write": "denied",
                "network": "denied",
                "process": "denied",
                "environment": "denied",
                "internal_state_update": "denied"
            })
        );
    }

    fn tool(registry: &ReviewToolRegistry, id: ReviewToolId) -> &ReviewToolContract {
        registry
            .tools
            .iter()
            .find(|tool| tool.id == id)
            .expect("registry tool")
    }
}
