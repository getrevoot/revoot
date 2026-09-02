//! Provider-free rule-precedence diagnostics for repository paths.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::Path;

use revoot_core::{Diagnostic, ErrorCode, RepositoryRelativePath};

use crate::config::{
    RepositoryReviewPolicy, ResolvedReviewConfiguration, resolve_review_configuration,
};
use crate::local_review::capture_local_git;
use crate::rule_diagnostics::{
    RepositoryRuleMetadata, RuleDiagnosticPolicy, RuleDiagnosticsReport, RulePrecedenceSource,
    diagnose_rules,
};

const MAX_PATHS: usize = 32;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_TOTAL_PATH_BYTES: usize = 16 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    Human,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckArgs {
    paths: Vec<String>,
    output: OutputMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ParsedRulesArgs {
    Help,
    Check(CheckArgs),
}

/// Resolve base-commit policy and print path-specific rule precedence without
/// loading credentials or constructing a provider.
///
/// # Errors
///
/// Returns a redaction-safe CLI, repository, configuration, or contract
/// diagnostic. Output never contains guidance bodies or repository contents.
pub fn run(
    args: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    current_directory: &Path,
) -> Result<i32, Diagnostic> {
    match parse_args(args)? {
        ParsedRulesArgs::Help => {
            print_help();
            Ok(0)
        }
        ParsedRulesArgs::Check(arguments) => {
            let report = build_report(arguments.paths, environment, current_directory)?;
            let output = render_report(&report, arguments.output)?;
            println!("{output}");
            Ok(0)
        }
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<ParsedRulesArgs, Diagnostic> {
    let mut args = args;
    let Some(subcommand) = args.next() else {
        return Err(cli_error("rules requires the `check` subcommand"));
    };
    if matches!(subcommand.as_str(), "help" | "--help" | "-h") {
        if args.next().is_some() {
            return Err(cli_error("usage: revoot rules check <path...> [--json]"));
        }
        return Ok(ParsedRulesArgs::Help);
    }
    if subcommand != "check" {
        return Err(cli_error("unknown rules subcommand"));
    }

    let supplied = args.collect::<Vec<_>>();
    if supplied.len() == 1 && matches!(supplied[0].as_str(), "help" | "--help" | "-h") {
        return Ok(ParsedRulesArgs::Help);
    }
    let mut output = OutputMode::Human;
    let mut paths = Vec::new();
    for argument in supplied {
        match argument.as_str() {
            "--json" if output == OutputMode::Human => output = OutputMode::Json,
            "--json" => return Err(cli_error("rules check accepts `--json` only once")),
            value if value.starts_with('-') => {
                return Err(cli_error("unknown rules check option"));
            }
            _ => paths.push(argument),
        }
    }
    validate_paths(&paths)?;
    Ok(ParsedRulesArgs::Check(CheckArgs { paths, output }))
}

fn validate_paths(paths: &[String]) -> Result<(), Diagnostic> {
    if paths.is_empty() {
        return Err(cli_error(
            "rules check requires at least one repository path",
        ));
    }
    if paths.len() > MAX_PATHS {
        return Err(cli_error("rules check accepts at most 32 repository paths"));
    }
    let mut total_bytes = 0_usize;
    let mut unique = BTreeSet::new();
    for path in paths {
        if path.len() > MAX_PATH_BYTES {
            return Err(cli_error("rules check contains an overlong path"));
        }
        total_bytes = total_bytes
            .checked_add(path.len())
            .ok_or_else(|| cli_error("rules check path input is too large"))?;
        RepositoryRelativePath::try_from(path.clone())
            .map_err(|_| cli_error("rules check contains an unsafe repository path"))?;
        if !unique.insert(path) {
            return Err(cli_error("rules check contains a duplicate path"));
        }
    }
    if total_bytes > MAX_TOTAL_PATH_BYTES {
        return Err(cli_error("rules check path input is too large"));
    }
    Ok(())
}

fn build_report(
    paths: Vec<String>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    current_directory: &Path,
) -> Result<RuleDiagnosticsReport, Diagnostic> {
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
    diagnose_for_policy(paths, &resolved)
}

fn diagnose_for_policy(
    paths: Vec<String>,
    resolved: &ResolvedReviewConfiguration,
) -> Result<RuleDiagnosticsReport, Diagnostic> {
    diagnose_rules(paths, &rule_policy(&resolved.repository))
        .map_err(|error| contract_error(error.to_string()))
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

fn render_report(report: &RuleDiagnosticsReport, output: OutputMode) -> Result<String, Diagnostic> {
    match output {
        OutputMode::Json => String::from_utf8(
            report
                .canonical_json()
                .map_err(|error| contract_error(error.to_string()))?,
        )
        .map_err(|_| contract_error("rule diagnostics serialization was not UTF-8")),
        OutputMode::Human => Ok(render_human(report)),
    }
}

fn render_human(report: &RuleDiagnosticsReport) -> String {
    let mut output = String::new();
    for (path_index, path) in report.paths.iter().enumerate() {
        if path_index > 0 {
            output.push('\n');
        }
        writeln!(&mut output, "{}", path.path.as_str()).expect("writing to String cannot fail");
        for trace in &path.trace {
            let status = if trace.active { "active" } else { "inactive" };
            let identifiers = if trace.rule_ids.is_empty() {
                "-".to_owned()
            } else {
                trace.rule_ids.join(",")
            };
            writeln!(
                &mut output,
                "  {} {} {} {}",
                trace.precedence,
                source_name(trace.source),
                status,
                identifiers
            )
            .expect("writing to String cannot fail");
        }
    }
    output.pop();
    output
}

const fn source_name(source: RulePrecedenceSource) -> &'static str {
    match source {
        RulePrecedenceSource::CompiledSafety => "compiled_safety",
        RulePrecedenceSource::BaseConfiguration => "base_configuration",
        RulePrecedenceSource::RepositoryRule => "repository_rule",
        RulePrecedenceSource::EmbeddedRule => "embedded_rule",
        RulePrecedenceSource::GenericRule => "generic_rule",
    }
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
    println!("USAGE:\n  revoot rules check <path...> [--json]");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RepositoryReviewPolicy, RepositoryRule};

    fn arguments(values: &[&str]) -> impl Iterator<Item = String> {
        values.iter().map(ToString::to_string)
    }

    fn test_report() -> RuleDiagnosticsReport {
        diagnose_rules(
            ["src/lib.rs".to_owned()],
            &RuleDiagnosticPolicy {
                base_guidance_present: true,
                repository_rules: vec![RepositoryRuleMetadata {
                    id: "repository:rule-000".to_owned(),
                    path_patterns: vec!["src/**".to_owned()],
                }],
            },
        )
        .expect("diagnostics")
    }

    #[test]
    fn parser_accepts_check_paths_and_json_in_either_position() {
        assert_eq!(
            parse_args(arguments(&["check", "src/lib.rs", "tests/a.rs", "--json"]))
                .expect("arguments"),
            ParsedRulesArgs::Check(CheckArgs {
                paths: vec!["src/lib.rs".to_owned(), "tests/a.rs".to_owned()],
                output: OutputMode::Json,
            })
        );
        assert!(matches!(
            parse_args(arguments(&["check", "--json", "src/lib.rs"])),
            Ok(ParsedRulesArgs::Check(CheckArgs {
                output: OutputMode::Json,
                ..
            }))
        ));
    }

    #[test]
    fn parser_rejects_unknown_flags_missing_paths_and_duplicates() {
        for values in [
            &["check", "--verbose"][..],
            &["check", "--json"][..],
            &["check", "src/lib.rs", "src/lib.rs"][..],
            &["check", "src/lib.rs", "--json", "--json"][..],
        ] {
            assert_eq!(
                parse_args(arguments(values))
                    .expect_err("invalid arguments")
                    .code,
                ErrorCode::CliInvalidArgument
            );
        }
    }

    #[test]
    fn parser_rejects_unsafe_and_excessive_paths_before_repository_access() {
        for path in ["../secret", "/tmp/secret", ".git/config", "src/./lib.rs"] {
            assert_eq!(
                parse_args(arguments(&["check", path]))
                    .expect_err("unsafe path")
                    .code,
                ErrorCode::CliInvalidArgument
            );
        }
        let mut values = vec!["check".to_owned()];
        values.extend((0..=MAX_PATHS).map(|index| format!("src/{index}.rs")));
        assert_eq!(
            parse_args(values.into_iter())
                .expect_err("too many paths")
                .code,
            ErrorCode::CliInvalidArgument
        );
    }

    #[test]
    fn human_output_contains_only_path_typed_precedence_and_rule_ids() {
        let output = render_report(&test_report(), OutputMode::Human).expect("human output");
        assert_eq!(
            output,
            "src/lib.rs\n  1 compiled_safety active compiled:safety-invariants\n  2 base_configuration active base:repository-guidance\n  3 repository_rule active repository:rule-000\n  4 embedded_rule active rust.md\n  5 generic_rule active generic:review"
        );
        assert!(!output.contains("guidance body"));
    }

    #[test]
    fn json_output_is_canonical_and_contains_no_guidance_fields() {
        let output = render_report(&test_report(), OutputMode::Json).expect("JSON output");
        let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(
            value["schema_version"],
            RuleDiagnosticsReport::SCHEMA_VERSION
        );
        assert!(output.contains("repository:rule-000"));
        assert!(!output.contains("\"guidance\":"));
        assert!(!output.contains("path_patterns"));
    }

    #[test]
    fn repository_policy_conversion_discards_guidance_bodies() {
        let policy = RepositoryReviewPolicy {
            guidance: Some("private base guidance".to_owned()),
            rules: vec![RepositoryRule {
                paths: vec!["src/**".to_owned()],
                focus: vec!["private focus".to_owned()],
                guidance: "private rule guidance".to_owned(),
            }],
            ..RepositoryReviewPolicy::default()
        };
        let metadata = rule_policy(&policy);
        let serialized = serde_json::to_string(&metadata).expect("metadata JSON");
        assert!(metadata.base_guidance_present);
        assert_eq!(metadata.repository_rules[0].id, "repository:rule-000");
        assert!(!serialized.contains("private"));
    }
}
