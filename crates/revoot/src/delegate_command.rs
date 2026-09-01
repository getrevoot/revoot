//! Provider-free delegation CLI over immutable local review preparation.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;

use revoot_core::{
    AgentBudgetLimits, ConfigValue, DelegationRuleGroupInput, Diagnostic, ErrorCode,
    PartitionLimits, RepositoryPath, ReviewPartitionPlan, ReviewSelectionPolicy, Sha256Digest,
    UnifiedDiffLimits, build_delegation_manifest,
};

use crate::config::{
    RepositoryReviewPolicy, ResolvedReviewConfiguration, resolve_review_configuration,
};
use crate::local_review::{
    LocalReviewContext, LocalReviewContextOptions, build_local_review_context, capture_local_git,
    local_snapshot_is_fresh,
};
use crate::rule_diagnostics::{
    PathRuleDiagnostics, RepositoryRuleMetadata, RuleDiagnosticPolicy, diagnose_rules,
};

const DEFERRED_PROVIDER: &str = "delegation";
const DEFERRED_MODEL: &str = "no-model";
const RULE_DIAGNOSTIC_BATCH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
enum DelegateScope {
    Preview,
    Rule(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ParsedDelegateArgs {
    Help,
    Execute(DelegateScope),
}

/// Run a provider-free delegation command and write one body-free JSON
/// manifest to stdout.
///
/// # Errors
///
/// Returns redaction-safe CLI, repository, configuration, snapshot, rule, or
/// serialization diagnostics. This operation never discovers credentials or
/// constructs a provider adapter.
pub fn run(
    args: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    current_directory: &Path,
) -> Result<i32, Diagnostic> {
    match parse_args(args)? {
        ParsedDelegateArgs::Help => {
            print_help();
            Ok(0)
        }
        ParsedDelegateArgs::Execute(scope) => {
            let output = build_output(scope, environment, current_directory)?;
            println!(
                "{}",
                String::from_utf8(output).map_err(|_| {
                    contract_error("delegation manifest serialization was not UTF-8")
                })?
            );
            Ok(0)
        }
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<ParsedDelegateArgs, Diagnostic> {
    let mut args = args;
    let Some(subcommand) = args.next() else {
        return Err(cli_error(
            "delegate requires the `preview` or `rule` subcommand",
        ));
    };
    if matches!(subcommand.as_str(), "help" | "--help" | "-h") {
        return Ok(ParsedDelegateArgs::Help);
    }
    match subcommand.as_str() {
        "preview" => {
            if let Some(argument) = args.next() {
                if matches!(argument.as_str(), "help" | "--help" | "-h") && args.next().is_none() {
                    return Ok(ParsedDelegateArgs::Help);
                }
                return Err(cli_error("usage: revoot delegate preview"));
            }
            Ok(ParsedDelegateArgs::Execute(DelegateScope::Preview))
        }
        "rule" => {
            let paths = args.collect::<Vec<_>>();
            if paths.len() == 1 && matches!(paths[0].as_str(), "help" | "--help" | "-h") {
                return Ok(ParsedDelegateArgs::Help);
            }
            if paths.is_empty() {
                return Err(cli_error(
                    "delegate rule requires at least one repository path",
                ));
            }
            if paths.iter().any(|path| path.starts_with('-')) {
                return Err(cli_error("delegate rule accepts repository paths only"));
            }
            Ok(ParsedDelegateArgs::Execute(DelegateScope::Rule(paths)))
        }
        _ => Err(cli_error("unknown delegate subcommand")),
    }
}

fn build_output(
    scope: DelegateScope,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    current_directory: &Path,
) -> Result<Vec<u8>, Diagnostic> {
    let capture = capture_local_git(current_directory, None).map_err(|error| {
        repository_error(error.to_string()).with_remediation(
            "run inside a Git repository with an available default-branch history",
        )
    })?;
    let resolved = resolve_review_configuration(
        &capture.root,
        Some(&capture.identity.base_sha),
        None,
        environment,
    )?;
    let context = build_local_context(capture, &resolved)?;
    let selected_paths = selected_paths(&context.partition);
    let requested_paths = match scope {
        DelegateScope::Preview => selected_paths.clone(),
        DelegateScope::Rule(paths) => {
            let supplied_count = paths.len();
            let paths = paths
                .into_iter()
                .map(|path| {
                    RepositoryPath::try_from(path)
                        .map_err(|_| cli_error("delegate rule contains an invalid path"))
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if paths.len() != supplied_count {
                return Err(cli_error("delegate rule contains a duplicate path"));
            }
            if paths.is_empty() || !paths.is_subset(&selected_paths) {
                return Err(cli_error(
                    "delegate rule paths must be selected changed paths",
                ));
            }
            paths
        }
    };
    let diagnostic_policy = rule_policy(&resolved.repository);
    let all_diagnostics = diagnose_path_batches(&selected_paths, &diagnostic_policy)?;
    let rule_groups = delegation_rule_groups(&all_diagnostics, &requested_paths)?;
    let repository_policy_sha256 = Sha256Digest::of_bytes(
        &serde_json::to_vec(&resolved.repository)
            .map_err(|_| contract_error("repository policy digest serialization failed"))?,
    );
    let rule_set_sha256 = Sha256Digest::of_bytes(
        &serde_json::to_vec(&all_diagnostics)
            .map_err(|_| contract_error("rule-set digest serialization failed"))?,
    );
    let manifest = build_delegation_manifest(
        &context.partition,
        repository_policy_sha256,
        rule_set_sha256,
        rule_groups,
    )
    .map_err(|error| contract_error(error.to_string()))?;
    if !local_snapshot_is_fresh(&context) {
        return Err(repository_error(
            "local repository changed while delegation metadata was prepared",
        ));
    }
    manifest
        .canonical_json(&context.partition)
        .map_err(|_| contract_error("delegation manifest serialization failed"))
}

fn build_local_context(
    capture: crate::local_review::LocalGitCapture,
    resolved: &ResolvedReviewConfiguration,
) -> Result<LocalReviewContext, Diagnostic> {
    let resolution = &resolved.effective;
    build_local_review_context(
        capture,
        &LocalReviewContextOptions {
            provider_adapter: DEFERRED_PROVIDER.to_owned(),
            model_id: DEFERRED_MODEL.to_owned(),
            agent_limits: AgentBudgetLimits::default(),
            diff_limits: UnifiedDiffLimits {
                context_radius_lines: u32_value(resolution, "review.context_lines")?,
                ..UnifiedDiffLimits::default()
            },
            selection_policy: selection_policy(resolution, &resolved.repository)?,
            partition_limits: partition_limits(resolution)?,
        },
    )
    .map_err(|error| repository_error(error.to_string()))
}

fn partition_limits(
    resolution: &revoot_core::ConfigurationResolution,
) -> Result<PartitionLimits, Diagnostic> {
    let max_files = u32_value(resolution, "budget.max_files")?;
    let max_total_bytes = config_unsigned(resolution, "budget.max_input_bytes")?;
    Ok(PartitionLimits {
        max_files,
        max_total_bytes,
        max_work_units: max_files.min(128),
        max_files_per_work_unit: max_files.min(20),
        max_bytes_per_work_unit: max_total_bytes.min(512 * 1024),
        max_anchors_per_work_unit: 10_000,
    })
}

fn selection_policy(
    resolution: &revoot_core::ConfigurationResolution,
    repository_policy: &RepositoryReviewPolicy,
) -> Result<ReviewSelectionPolicy, Diagnostic> {
    let mut policy = ReviewSelectionPolicy {
        version: "automatic-v3".to_owned(),
        included_paths: BTreeSet::new(),
        included_prefixes: Vec::new(),
        included_suffixes: Vec::new(),
        excluded_paths: BTreeSet::new(),
        excluded_prefixes: vec![".git/".to_owned(), "vendor/".to_owned()],
        excluded_suffixes: vec![".generated".to_owned()],
        excluded_basename_prefixes: Vec::new(),
        include_generated: config_bool(resolution, "review.include_generated")?,
        max_file_bytes: 2 * 1024 * 1024,
    };
    compile_selection_patterns(
        config_string_list(resolution, "review.include_patterns")?,
        &mut policy.included_paths,
        &mut policy.included_prefixes,
        &mut policy.included_suffixes,
    )?;
    compile_selection_patterns(
        config_string_list(resolution, "review.exclude_patterns")?,
        &mut policy.excluded_paths,
        &mut policy.excluded_prefixes,
        &mut policy.excluded_suffixes,
    )?;
    compile_selection_patterns(
        &repository_policy.model_context.exclude,
        &mut policy.excluded_paths,
        &mut policy.excluded_prefixes,
        &mut policy.excluded_suffixes,
    )?;
    policy
        .validate()
        .map_err(|_| contract_error("review path selection patterns are invalid"))?;
    Ok(policy)
}

fn compile_selection_patterns(
    patterns: &[String],
    exact: &mut BTreeSet<RepositoryPath>,
    prefixes: &mut Vec<String>,
    suffixes: &mut Vec<String>,
) -> Result<(), Diagnostic> {
    for pattern in patterns {
        if let Some(prefix) = pattern.strip_suffix("/**")
            && !prefix.is_empty()
            && !prefix.contains('*')
        {
            prefixes.push(format!("{prefix}/"));
        } else if let Some(suffix) = pattern.strip_prefix("**/*")
            && !suffix.is_empty()
            && !suffix.contains('*')
        {
            suffixes.push(suffix.to_owned());
        } else if !pattern.contains('*') {
            exact.insert(
                RepositoryPath::try_from(pattern.clone())
                    .map_err(|_| contract_error("review path selection pattern is invalid"))?,
            );
        } else {
            return Err(contract_error(
                "review path patterns support exact paths, directory/**, or **/*suffix",
            ));
        }
    }
    prefixes.sort();
    prefixes.dedup();
    suffixes.sort();
    suffixes.dedup();
    Ok(())
}

fn selected_paths(partition: &ReviewPartitionPlan) -> BTreeSet<RepositoryPath> {
    partition
        .work_units
        .iter()
        .flat_map(|unit| unit.files.iter().map(|file| file.path.new_path.clone()))
        .collect()
}

fn rule_policy(repository: &RepositoryReviewPolicy) -> RuleDiagnosticPolicy {
    RuleDiagnosticPolicy {
        base_guidance_present: repository.guidance.is_some(),
        repository_rules: repository
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| RepositoryRuleMetadata {
                id: format!("repository:rule-{index:03}"),
                path_patterns: rule.paths.clone(),
            })
            .collect(),
    }
}

fn diagnose_path_batches(
    paths: &BTreeSet<RepositoryPath>,
    policy: &RuleDiagnosticPolicy,
) -> Result<Vec<PathRuleDiagnostics>, Diagnostic> {
    let paths = paths
        .iter()
        .map(|path| path.as_str().to_owned())
        .collect::<Vec<_>>();
    let mut diagnostics = Vec::with_capacity(paths.len());
    for batch in paths.chunks(RULE_DIAGNOSTIC_BATCH) {
        diagnostics.extend(
            diagnose_rules(batch.iter().cloned(), policy)
                .map_err(|error| contract_error(error.to_string()))?
                .paths,
        );
    }
    Ok(diagnostics)
}

fn delegation_rule_groups(
    diagnostics: &[PathRuleDiagnostics],
    requested_paths: &BTreeSet<RepositoryPath>,
) -> Result<Vec<DelegationRuleGroupInput>, Diagnostic> {
    let mut grouped: BTreeMap<Vec<String>, Vec<RepositoryPath>> = BTreeMap::new();
    for path in diagnostics {
        let repository_path = RepositoryPath::try_from(path.path.as_str().to_owned())
            .map_err(|_| contract_error("rule diagnostics returned an invalid path"))?;
        if !requested_paths.contains(&repository_path) {
            continue;
        }
        let mut rule_ids = path
            .trace
            .iter()
            .filter(|trace| trace.active)
            .flat_map(|trace| trace.rule_ids.iter().cloned())
            .collect::<Vec<_>>();
        rule_ids.sort();
        rule_ids.dedup();
        grouped.entry(rule_ids).or_default().push(repository_path);
    }
    grouped
        .into_iter()
        .map(|(rule_ids, matched_paths)| {
            let digest = Sha256Digest::of_bytes(
                &serde_json::to_vec(&rule_ids)
                    .map_err(|_| contract_error("rule group serialization failed"))?,
            );
            Ok(DelegationRuleGroupInput {
                id: format!("rules:{}", digest.as_str()),
                rule_ids,
                matched_paths,
            })
        })
        .collect()
}

fn config_string_list<'a>(
    resolution: &'a revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<&'a [String], Diagnostic> {
    match resolution.effective().get(key) {
        Some(ConfigValue::StringList(value)) => Ok(value),
        _ => Err(contract_error("effective review configuration is invalid")),
    }
}

fn config_unsigned(
    resolution: &revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<u64, Diagnostic> {
    match resolution.effective().get(key) {
        Some(ConfigValue::Unsigned(value)) => Ok(*value),
        _ => Err(contract_error("effective review configuration is invalid")),
    }
}

fn config_bool(
    resolution: &revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<bool, Diagnostic> {
    match resolution.effective().get(key) {
        Some(ConfigValue::Bool(value)) => Ok(*value),
        _ => Err(contract_error("effective review configuration is invalid")),
    }
}

fn u32_value(
    resolution: &revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<u32, Diagnostic> {
    u32::try_from(config_unsigned(resolution, key)?)
        .map_err(|_| contract_error("effective review configuration exceeds supported limits"))
}

fn cli_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::CliInvalidArgument, message)
}

fn repository_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::RepositoryUnavailable, message)
}

fn contract_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::ContractInvalid, message)
}

fn print_help() {
    println!("USAGE:\n  revoot delegate preview\n  revoot delegate rule <path...>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_only_fixed_provider_free_surface() {
        assert_eq!(
            parse_args(["preview".to_owned()].into_iter()).expect("preview"),
            ParsedDelegateArgs::Execute(DelegateScope::Preview)
        );
        assert_eq!(
            parse_args(["rule".to_owned(), "src/lib.rs".to_owned()].into_iter()).expect("rule"),
            ParsedDelegateArgs::Execute(DelegateScope::Rule(vec!["src/lib.rs".to_owned()]))
        );
        assert!(parse_args(["rule".to_owned()].into_iter()).is_err());
        assert!(parse_args(["preview".to_owned(), "extra".to_owned()].into_iter()).is_err());
        assert!(parse_args(["provider".to_owned()].into_iter()).is_err());
    }

    #[test]
    fn rule_groups_contain_only_ids_and_requested_paths() {
        let diagnostics = vec![PathRuleDiagnostics {
            path: revoot_core::RepositoryRelativePath::try_from("src/lib.rs".to_owned())
                .expect("path"),
            trace: vec![crate::rule_diagnostics::RulePrecedenceTrace {
                precedence: 1,
                source: crate::rule_diagnostics::RulePrecedenceSource::CompiledSafety,
                active: true,
                rule_ids: vec!["compiled:safety-invariants".to_owned()],
            }],
        }];
        let groups = delegation_rule_groups(
            &diagnostics,
            &BTreeSet::from([RepositoryPath::try_from("src/lib.rs".to_owned()).expect("path")]),
        )
        .expect("groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].matched_paths[0].as_str(), "src/lib.rs");
        assert_eq!(groups[0].rule_ids, ["compiled:safety-invariants"]);
        let json = serde_json::to_string(&groups[0].rule_ids).expect("JSON");
        assert!(!json.contains("guidance"));
        assert!(!json.contains("diff"));
    }

    #[test]
    fn repository_rule_identifiers_are_stable_and_body_free() {
        let repository = RepositoryReviewPolicy {
            guidance: Some("private guidance body".to_owned()),
            rules: vec![crate::config::RepositoryRule {
                paths: vec!["src/**".to_owned()],
                focus: vec!["correctness".to_owned()],
                guidance: "private rule body".to_owned(),
            }],
            ..RepositoryReviewPolicy::default()
        };
        let policy = rule_policy(&repository);
        assert!(policy.base_guidance_present);
        assert_eq!(policy.repository_rules[0].id, "repository:rule-000");
        let encoded = serde_json::to_string(&policy).expect("JSON");
        assert!(!encoded.contains("private guidance body"));
        assert!(!encoded.contains("private rule body"));
    }

    #[test]
    fn agent_manifest_declares_exact_delegate_workflows() {
        let manifest = revoot_core::build_agent_integration_manifest();
        let workflows = manifest
            .cli_workflows
            .iter()
            .map(|workflow| workflow.arguments.as_slice())
            .collect::<Vec<_>>();
        assert!(workflows.contains(&["delegate".to_owned(), "preview".to_owned()].as_slice()));
        assert!(
            workflows.contains(
                &[
                    "delegate".to_owned(),
                    "rule".to_owned(),
                    "<path...>".to_owned()
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn delegation_manifest_contract_is_body_free() {
        let field_names = serde_json::to_value(revoot_core::DelegationManifest::SCHEMA_VERSION)
            .expect("schema version");
        assert_eq!(field_names, "revoot.delegation/v1");
    }
}
