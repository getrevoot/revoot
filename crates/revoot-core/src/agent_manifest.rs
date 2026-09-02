//! Provider-neutral integration manifest for external review agents.
//!
//! The contract advertises only credential-free CLI metadata workflows and the
//! bounded stdio MCP surface. It grants no repository mutation, publication,
//! network, secret, or arbitrary-process authority.

use std::fmt;

use serde::{Deserialize, Serialize};

const EXECUTABLE: &str = "revoot";
const DELEGATION_SCHEMA: &str = "revoot.delegation/v1";
const RULE_DIAGNOSTICS_SCHEMA: &str = "revoot.rule-diagnostics/v1";

/// Stable identity for one credential-free CLI metadata workflow.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCliWorkflowId {
    IntegrationManifest,
    DelegationPreview,
    DelegationRule,
    RuleDiagnostics,
}

/// Fixed CLI invocation metadata. Arguments are individual atoms, not a
/// command string interpreted by another process layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCliWorkflow {
    pub id: AgentCliWorkflowId,
    pub arguments: Vec<String>,
    pub output_schema: String,
}

/// Only supported host-agent transport.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMcpTransport {
    Stdio,
}

/// Coarse access class for one MCP operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMcpAccess {
    OpenSnapshot,
    ReadMetadata,
    ReadDiff,
    ReadFile,
    SearchSnapshot,
    ReadRules,
    ValidateFindings,
}

/// One bounded MCP operation exposed to a host agent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMcpTool {
    pub name: String,
    pub access: AgentMcpAccess,
    pub requires_review_handle: bool,
}

/// Stdio launch metadata and the complete allowlisted tool surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMcpSurface {
    pub transport: AgentMcpTransport,
    pub launch_arguments: Vec<String>,
    pub tools: Vec<AgentMcpTool>,
}

/// One explicit authority decision in the integration manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorityState {
    Denied,
    Granted,
}

/// Explicitly closed authority available through the integration manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIntegrationAuthority {
    pub repository_mutation: AgentAuthorityState,
    pub publication: AgentAuthorityState,
    pub outbound_network: AgentAuthorityState,
    pub secret_access: AgentAuthorityState,
    pub arbitrary_processes: AgentAuthorityState,
}

/// Deterministic provider-neutral CLI and MCP integration contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIntegrationManifest {
    pub schema_version: String,
    pub executable: String,
    pub cli_workflows: Vec<AgentCliWorkflow>,
    pub mcp: AgentMcpSurface,
    pub authority: AgentIntegrationAuthority,
}

impl AgentIntegrationManifest {
    pub const SCHEMA_VERSION: &'static str = "revoot.agent-integration/v1";

    /// Validate that the manifest is exactly the supported closed surface.
    ///
    /// # Errors
    ///
    /// Rejects schema drift, added or reordered commands/tools, and any granted
    /// authority outside the immutable review surface.
    pub fn validate(&self) -> Result<(), AgentManifestError> {
        let expected = build_agent_integration_manifest();
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(AgentManifestError::SchemaVersion);
        }
        if self.executable != expected.executable || self.cli_workflows != expected.cli_workflows {
            return Err(AgentManifestError::CliSurface);
        }
        if self.mcp != expected.mcp {
            return Err(AgentManifestError::McpSurface);
        }
        if self.authority != expected.authority {
            return Err(AgentManifestError::Authority);
        }
        Ok(())
    }

    /// Serialize the validated manifest with stable field and list ordering.
    ///
    /// # Errors
    ///
    /// Returns a closed error for contract drift or serialization failure.
    pub fn canonical_json(&self) -> Result<Vec<u8>, AgentManifestError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| AgentManifestError::Serialization)
    }
}

/// Payload-free manifest contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentManifestError {
    SchemaVersion,
    CliSurface,
    McpSurface,
    Authority,
    Serialization,
}

impl fmt::Display for AgentManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "agent integration schema version is unsupported",
            Self::CliSurface => "agent integration CLI surface is invalid",
            Self::McpSurface => "agent integration MCP surface is invalid",
            Self::Authority => "agent integration authority must remain closed",
            Self::Serialization => "agent integration manifest serialization failed",
        })
    }
}

impl std::error::Error for AgentManifestError {}

/// Build the one supported external-agent integration manifest.
#[must_use]
pub fn build_agent_integration_manifest() -> AgentIntegrationManifest {
    AgentIntegrationManifest {
        schema_version: AgentIntegrationManifest::SCHEMA_VERSION.to_owned(),
        executable: EXECUTABLE.to_owned(),
        cli_workflows: vec![
            AgentCliWorkflow {
                id: AgentCliWorkflowId::IntegrationManifest,
                arguments: strings(&["delegate", "manifest"]),
                output_schema: AgentIntegrationManifest::SCHEMA_VERSION.to_owned(),
            },
            AgentCliWorkflow {
                id: AgentCliWorkflowId::DelegationPreview,
                arguments: strings(&["delegate", "preview"]),
                output_schema: DELEGATION_SCHEMA.to_owned(),
            },
            AgentCliWorkflow {
                id: AgentCliWorkflowId::DelegationRule,
                arguments: strings(&["delegate", "rule", "<path...>"]),
                output_schema: DELEGATION_SCHEMA.to_owned(),
            },
            AgentCliWorkflow {
                id: AgentCliWorkflowId::RuleDiagnostics,
                arguments: strings(&["rules", "check", "<path...>", "--json"]),
                output_schema: RULE_DIAGNOSTICS_SCHEMA.to_owned(),
            },
        ],
        mcp: AgentMcpSurface {
            transport: AgentMcpTransport::Stdio,
            launch_arguments: strings(&["mcp", "serve"]),
            tools: vec![
                mcp_tool("revoot_open_review", AgentMcpAccess::OpenSnapshot, false),
                mcp_tool(
                    "revoot_list_changed_files",
                    AgentMcpAccess::ReadMetadata,
                    true,
                ),
                mcp_tool("revoot_read_diff", AgentMcpAccess::ReadDiff, true),
                mcp_tool("revoot_read_file", AgentMcpAccess::ReadFile, true),
                mcp_tool("revoot_find_files", AgentMcpAccess::SearchSnapshot, true),
                mcp_tool("revoot_search_code", AgentMcpAccess::SearchSnapshot, true),
                mcp_tool("revoot_search_diff", AgentMcpAccess::SearchSnapshot, true),
                mcp_tool("revoot_get_rules", AgentMcpAccess::ReadRules, true),
                mcp_tool(
                    "revoot_validate_findings",
                    AgentMcpAccess::ValidateFindings,
                    true,
                ),
            ],
        },
        authority: AgentIntegrationAuthority {
            repository_mutation: AgentAuthorityState::Denied,
            publication: AgentAuthorityState::Denied,
            outbound_network: AgentAuthorityState::Denied,
            secret_access: AgentAuthorityState::Denied,
            arbitrary_processes: AgentAuthorityState::Denied,
        },
    }
}

fn mcp_tool(name: &str, access: AgentMcpAccess, requires_review_handle: bool) -> AgentMcpTool {
    AgentMcpTool {
        name: name.to_owned(),
        access,
        requires_review_handle,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn canonical_json_matches_the_versioned_closed_surface() {
        let manifest = build_agent_integration_manifest();
        let first = manifest.canonical_json().expect("canonical manifest");
        let second = build_agent_integration_manifest()
            .canonical_json()
            .expect("canonical manifest replay");
        assert_eq!(first, second);

        let value: Value = serde_json::from_slice(&first).expect("manifest JSON");
        assert_eq!(
            value["schema_version"],
            AgentIntegrationManifest::SCHEMA_VERSION
        );
        assert_eq!(value["executable"], EXECUTABLE);
        assert_eq!(value["mcp"]["transport"], "stdio");
        assert_eq!(value["mcp"]["launch_arguments"], json!(["mcp", "serve"]));
        assert_eq!(
            value["cli_workflows"].as_array().expect("workflows").len(),
            4
        );
    }

    #[test]
    fn advertises_the_complete_read_only_mcp_allowlist() {
        let manifest = build_agent_integration_manifest();
        assert_eq!(
            manifest
                .mcp
                .tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            [
                "revoot_open_review",
                "revoot_list_changed_files",
                "revoot_read_diff",
                "revoot_read_file",
                "revoot_find_files",
                "revoot_search_code",
                "revoot_search_diff",
                "revoot_get_rules",
                "revoot_validate_findings",
            ]
        );
        assert!(!manifest.mcp.tools[0].requires_review_handle);
        assert!(
            manifest
                .mcp
                .tools
                .iter()
                .skip(1)
                .all(|tool| tool.requires_review_handle)
        );
    }

    #[test]
    fn exposes_only_delegation_and_rule_diagnostic_cli_workflows() {
        let manifest = build_agent_integration_manifest();
        assert_eq!(
            manifest
                .cli_workflows
                .iter()
                .map(|workflow| workflow.id)
                .collect::<Vec<_>>(),
            [
                AgentCliWorkflowId::IntegrationManifest,
                AgentCliWorkflowId::DelegationPreview,
                AgentCliWorkflowId::DelegationRule,
                AgentCliWorkflowId::RuleDiagnostics,
            ]
        );
        assert_eq!(
            manifest.cli_workflows[0].arguments,
            ["delegate", "manifest"]
        );
        assert_eq!(manifest.cli_workflows[1].arguments, ["delegate", "preview"]);
        assert_eq!(
            manifest.cli_workflows[2].arguments,
            ["delegate", "rule", "<path...>"]
        );
        assert_eq!(
            manifest.cli_workflows[3].arguments,
            ["rules", "check", "<path...>", "--json"]
        );
    }

    #[test]
    fn grants_no_mutating_or_external_authority() {
        let authority = build_agent_integration_manifest().authority;
        assert_eq!(authority.repository_mutation, AgentAuthorityState::Denied);
        assert_eq!(authority.publication, AgentAuthorityState::Denied);
        assert_eq!(authority.outbound_network, AgentAuthorityState::Denied);
        assert_eq!(authority.secret_access, AgentAuthorityState::Denied);
        assert_eq!(authority.arbitrary_processes, AgentAuthorityState::Denied);
    }

    #[test]
    fn serialized_contract_contains_no_unlisted_execution_or_install_workflow() {
        let encoded = build_agent_integration_manifest()
            .canonical_json()
            .expect("manifest JSON");
        let text = String::from_utf8(encoded)
            .expect("manifest JSON must be UTF-8")
            .to_ascii_lowercase();
        for forbidden in [
            "auto_install",
            "install_command",
            "package_manager",
            "npm",
            "bun",
            "node",
            "shell",
            "raw_git",
            "api_key",
            "code_edit",
            "command_string",
            "provider_key",
            "raw_repository_command",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn validation_rejects_surface_or_authority_expansion() {
        let mut manifest = build_agent_integration_manifest();
        manifest
            .mcp
            .tools
            .push(mcp_tool("revoot_extra", AgentMcpAccess::ReadMetadata, true));
        assert_eq!(
            manifest.validate().expect_err("extra MCP tool"),
            AgentManifestError::McpSurface
        );

        let mut manifest = build_agent_integration_manifest();
        manifest.authority.repository_mutation = AgentAuthorityState::Granted;
        assert_eq!(
            manifest.validate().expect_err("expanded authority"),
            AgentManifestError::Authority
        );

        let mut manifest = build_agent_integration_manifest();
        manifest.cli_workflows[0].arguments.push("extra".to_owned());
        assert_eq!(
            manifest.validate().expect_err("expanded CLI workflow"),
            AgentManifestError::CliSurface
        );
    }

    #[test]
    fn deserialization_rejects_unknown_fields() {
        let mut value =
            serde_json::to_value(build_agent_integration_manifest()).expect("manifest value");
        value
            .as_object_mut()
            .expect("manifest object")
            .insert("extra".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<AgentIntegrationManifest>(value).is_err());
    }
}
