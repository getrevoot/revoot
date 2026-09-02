use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use revoot_core::{
    AssignmentScope, ConfigAssignment, ConfigExplainRecord, ConfigField, ConfigKey, ConfigSource,
    ConfigValue, ConfigurationResolution, ConfigurationSchema, Diagnostic, ErrorCode, GitSha,
    PolicyConstraint, PolicyRule, Sha256Digest, SourceProvenance, ValueConstraint,
    is_sensitive_model_context_path,
};
use serde::{Deserialize, Serialize};

use crate::embedded_git::EmbeddedRepository;

const CONFIG_SCHEMA_VERSION: u64 = 1;
const EXPLAIN_SCHEMA_VERSION: &str = "revoot.config-explain/v2";
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_SECRET_REFERENCE_BYTES: usize = 4 * 1024;
const MAX_RULES: usize = 32;
const MAX_SUPPRESSIONS: usize = 64;

/// Safe repository-owned review semantics extracted from `.revoot.toml`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryReviewPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    pub rules: Vec<RepositoryRule>,
    pub suppressions: Vec<RepositorySuppression>,
    pub model_context: ModelContextPolicy,
}

impl RepositoryReviewPolicy {
    /// Render deterministic, explicitly untrusted guidance for the reviewer.
    #[must_use]
    pub fn guidance_text(&self) -> Option<String> {
        let mut output = String::new();
        if let Some(guidance) = &self.guidance {
            output.push_str("Repository guidance:\n");
            output.push_str(guidance.trim());
            output.push('\n');
        }
        for (index, rule) in self.rules.iter().enumerate() {
            use std::fmt::Write as _;
            let _ = writeln!(output, "\nPath rule {}:", index + 1);
            let _ = writeln!(output, "Paths: {}", rule.paths.join(", "));
            let _ = writeln!(output, "Focus: {}", rule.focus.join(", "));
            output.push_str(rule.guidance.trim());
            output.push('\n');
        }
        (!output.is_empty()).then_some(output)
    }

    #[must_use]
    pub fn suppresses(&self, finding_key: &Sha256Digest) -> bool {
        self.suppressions
            .iter()
            .any(|suppression| &suppression.fingerprint == finding_key)
    }

    /// Return whether a repository path may be exposed to the model.
    ///
    /// The built-in denylist is always applied. Repository-owned exclusions
    /// may narrow the context further, but cannot re-enable a built-in denial.
    #[must_use]
    pub fn allows_model_context(&self, path: &str) -> bool {
        !is_sensitive_model_context_path(path)
            && !self
                .model_context
                .exclude
                .iter()
                .any(|pattern| context_pattern_matches(pattern, path))
    }
}

/// Repository-owned restrictions on files that may be exposed to a model.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelContextPolicy {
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRule {
    pub paths: Vec<String>,
    pub focus: Vec<String>,
    pub guidance: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySuppression {
    pub fingerprint: Sha256Digest,
    pub reason: String,
    pub expires: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

/// Effective scalar configuration plus structured repository policy.
pub struct ResolvedReviewConfiguration {
    pub effective: ConfigurationResolution,
    pub repository: RepositoryReviewPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum OutputMode {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Default)]
struct ExplainArgs {
    output: OutputMode,
    base_config: Option<PathBuf>,
    local_config: Option<PathBuf>,
    cli_assignments: Vec<ConfigAssignment>,
}

#[derive(Serialize)]
struct ExplainReport<'a> {
    schema_version: &'static str,
    credentials_loaded: bool,
    fields: &'a [ConfigExplainRecord],
    repository: &'a RepositoryReviewPolicy,
}

/// Run the credential-free configuration explanation command.
///
/// # Errors
///
/// Returns a redaction-safe diagnostic for invalid arguments, sources, or
/// resolved product policy.
pub fn run(
    mut args: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<i32, Diagnostic> {
    let Some(subcommand) = args.next() else {
        return Err(cli_error("config requires the `explain` subcommand"));
    };
    if matches!(subcommand.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(0);
    }
    if subcommand != "explain" {
        return Err(cli_error(format!(
            "unknown config subcommand: {subcommand}"
        )));
    }
    let Some(parsed) = parse_explain_args(args)? else {
        print_help();
        return Ok(0);
    };
    let resolved = resolve_bundle(&parsed, environment)?;
    match parsed.output {
        OutputMode::Json => println!(
            "{}",
            serde_json::to_string_pretty(&ExplainReport {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                credentials_loaded: false,
                fields: resolved.effective.explain(),
                repository: &resolved.repository,
            })
            .map_err(|_| contract_error("configuration explanation serialization failed"))?
        ),
        OutputMode::Human => {
            print_human(resolved.effective.explain());
            println!("repository.rules: {}", resolved.repository.rules.len());
            println!(
                "repository.suppressions: {}",
                resolved.repository.suppressions.len()
            );
        }
    }
    Ok(0)
}

/// Resolve the product configuration for a review controller without loading
/// any credential referenced by the configuration.
///
/// # Errors
///
/// Returns a redaction-safe diagnostic when a configuration source or the
/// resolved product policy is invalid.
pub fn resolve_review_configuration(
    repository_root: &Path,
    base_sha: Option<&GitSha>,
    local_config: Option<&Path>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<ResolvedReviewConfiguration, Diagnostic> {
    let repository_document = load_repository_document(repository_root, base_sha)?;
    resolve_documents(repository_document, local_config, environment, Vec::new())
}

fn parse_explain_args(
    args: impl Iterator<Item = String>,
) -> Result<Option<ExplainArgs>, Diagnostic> {
    let mut parsed = ExplainArgs::default();
    let mut args = args.peekable();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--json" => parsed.output = OutputMode::Json,
            "--base-config" => set_path_once(
                &mut parsed.base_config,
                required_value(&mut args, "--base-config")?,
                "--base-config",
            )?,
            "--config" => set_path_once(
                &mut parsed.local_config,
                required_value(&mut args, "--config")?,
                "--config",
            )?,
            "--context-lines" => parsed.cli_assignments.push(cli_unsigned(
                "review.context_lines",
                "--context-lines",
                required_value(&mut args, "--context-lines")?,
            )?),
            "--minimum-confidence" => parsed.cli_assignments.push(cli_unsigned(
                "review.minimum_confidence",
                "--minimum-confidence",
                required_value(&mut args, "--minimum-confidence")?,
            )?),
            "--model" => parsed.cli_assignments.push(cli_string(
                "review.model",
                "--model",
                required_value(&mut args, "--model")?,
            )),
            "--provider" => parsed.cli_assignments.push(cli_string(
                "review.provider",
                "--provider",
                required_value(&mut args, "--provider")?,
            )),
            "--max-files" => parsed.cli_assignments.push(cli_unsigned(
                "budget.max_files",
                "--max-files",
                required_value(&mut args, "--max-files")?,
            )?),
            "--max-input-bytes" => parsed.cli_assignments.push(cli_unsigned(
                "budget.max_input_bytes",
                "--max-input-bytes",
                required_value(&mut args, "--max-input-bytes")?,
            )?),
            "--max-findings" => parsed.cli_assignments.push(cli_unsigned(
                "budget.max_findings",
                "--max-findings",
                required_value(&mut args, "--max-findings")?,
            )?),
            "--max-model-requests" => parsed.cli_assignments.push(cli_unsigned(
                "budget.max_model_requests",
                "--max-model-requests",
                required_value(&mut args, "--max-model-requests")?,
            )?),
            "--deadline-seconds" => parsed.cli_assignments.push(cli_unsigned(
                "budget.deadline_seconds",
                "--deadline-seconds",
                required_value(&mut args, "--deadline-seconds")?,
            )?),
            "--publish" => {
                parsed
                    .cli_assignments
                    .push(cli_bool("publication.enabled", "--publish", true));
            }
            "--no-publish" => {
                parsed
                    .cli_assignments
                    .push(cli_bool("publication.enabled", "--no-publish", false));
            }
            "--help" | "-h" => return Ok(None),
            _ => {
                return Err(cli_error(format!(
                    "unknown config explain option: {argument}"
                )));
            }
        }
    }
    Ok(Some(parsed))
}

fn set_path_once(
    target: &mut Option<PathBuf>,
    value: String,
    option: &str,
) -> Result<(), Diagnostic> {
    if target.is_some() {
        return Err(cli_error(format!("{option} may be specified only once")));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}

fn required_value(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> Result<String, Diagnostic> {
    args.next()
        .ok_or_else(|| cli_error(format!("{option} requires a value")))
}

fn cli_unsigned(
    key: &str,
    option: &str,
    value: impl AsRef<str>,
) -> Result<ConfigAssignment, Diagnostic> {
    let parsed = parse_canonical_unsigned(value.as_ref())
        .ok_or_else(|| cli_error(format!("{option} requires a canonical unsigned integer")))?;
    Ok(assignment(
        key,
        ConfigValue::Unsigned(parsed),
        ConfigSource::CommandLine,
        format!("cli:{option}"),
    ))
}

fn cli_string(key: &str, option: &str, value: String) -> ConfigAssignment {
    assignment(
        key,
        ConfigValue::String(value),
        ConfigSource::CommandLine,
        format!("cli:{option}"),
    )
}

fn cli_bool(key: &str, option: &str, value: bool) -> ConfigAssignment {
    assignment(
        key,
        ConfigValue::Bool(value),
        ConfigSource::CommandLine,
        format!("cli:{option}"),
    )
}

#[cfg(test)]
fn resolve(
    args: &ExplainArgs,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<ConfigurationResolution, Diagnostic> {
    resolve_bundle(args, environment).map(|resolved| resolved.effective)
}

fn resolve_bundle(
    args: &ExplainArgs,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<ResolvedReviewConfiguration, Diagnostic> {
    let repository_document = args.base_config.as_deref().map(parse_file).transpose()?;
    resolve_documents(
        repository_document,
        args.local_config.as_deref(),
        environment,
        args.cli_assignments.clone(),
    )
}

fn resolve_documents(
    repository_document: Option<TomlConfig>,
    local_config: Option<&Path>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    cli_assignments: Vec<ConfigAssignment>,
) -> Result<ResolvedReviewConfiguration, Diagnostic> {
    let mut assignments = Vec::new();
    let mut secret_references = SecretReferences::default();
    let mut repository = RepositoryReviewPolicy::default();
    if let Some(parsed) = repository_document {
        let adapted = adapt_document(parsed, ConfigSource::BaseRepository, "base-config")?;
        assignments.extend(adapted.assignments);
        secret_references.extend(adapted.secret_references)?;
        repository = adapted.repository;
    }
    if let Some(path) = local_config {
        let parsed = parse_file(path)?;
        let adapted = adapt_document(parsed, ConfigSource::TrustedLocal, "trusted-local-config")?;
        assignments.extend(adapted.assignments);
        secret_references.extend(adapted.secret_references)?;
    }
    let adapted_environment = adapt_environment(environment)?;
    assignments.extend(adapted_environment.assignments);
    secret_references.extend(adapted_environment.secret_references)?;
    assignments.extend(cli_assignments);

    // Validated references are deliberately retained as opaque values and then
    // dropped. `config explain` never opens their paths or serializes them.
    secret_references.validate_retained_references();

    let effective = product_schema()?
        .resolve(assignments, product_policy())
        .map_err(|error| contract_error(format!("configuration resolution rejected: {error:?}")))?;
    Ok(ResolvedReviewConfiguration {
        effective,
        repository,
    })
}

fn load_repository_document(
    root: &Path,
    base_sha: Option<&GitSha>,
) -> Result<Option<TomlConfig>, Diagnostic> {
    if let Some(base_sha) = base_sha {
        return read_git_blob(root, base_sha)
            .and_then(|bytes| bytes.as_deref().map(parse_toml_bytes).transpose());
    }
    let path = root.join(".revoot.toml");
    if !path.exists() {
        return Ok(None);
    }
    parse_file(&path).map(Some)
}

fn read_git_blob(root: &Path, commit: &GitSha) -> Result<Option<Vec<u8>>, Diagnostic> {
    let repository = EmbeddedRepository::discover(root)
        .map_err(|_| contract_error("embedded repository is unavailable for base configuration"))?;
    repository
        .read_file_at_commit(
            commit,
            &revoot_core::RepositoryRelativePath::try_from(".revoot.toml".to_owned())
                .expect("static repository path"),
            u64::try_from(MAX_CONFIG_BYTES).expect("config bound fits u64"),
        )
        .map_err(|error| match error {
            crate::embedded_git::EmbeddedGitError::CommitUnavailable => {
                contract_error("the authoritative base commit is unavailable in the checkout")
                    .with_remediation("configure CI with full Git history (fetch-depth 0)")
            }
            crate::embedded_git::EmbeddedGitError::ObjectTooLarge => {
                contract_error("configuration input exceeds the byte limit")
            }
            _ => contract_error("base configuration could not be read"),
        })
}

fn parse_file(path: &Path) -> Result<TomlConfig, Diagnostic> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| contract_error("configuration file could not be opened"))?;
    let metadata = file
        .metadata()
        .map_err(|_| contract_error("configuration file metadata is unavailable"))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(contract_error(
            "configuration input must be a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(MAX_CONFIG_BYTES.min(4096));
    file.by_ref()
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| contract_error("configuration file could not be read"))?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(contract_error("configuration input exceeds the byte limit"));
    }
    parse_toml_bytes(&bytes)
}

fn parse_toml_bytes(bytes: &[u8]) -> Result<TomlConfig, Diagnostic> {
    let input = std::str::from_utf8(bytes)
        .map_err(|_| contract_error("configuration input must be UTF-8"))?;
    parse_toml(input)
}

fn parse_toml(input: &str) -> Result<TomlConfig, Diagnostic> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(contract_error("configuration input exceeds the byte limit"));
    }
    if input
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(contract_error(
            "configuration contains unsupported control characters",
        ));
    }
    let parsed = toml::from_str::<TomlConfig>(input)
        .map_err(|_| contract_error("configuration TOML was rejected by the strict parser"))?;
    if parsed.version != CONFIG_SCHEMA_VERSION {
        return Err(contract_error(
            "configuration version is missing or unsupported",
        ));
    }
    Ok(parsed)
}

fn parse_canonical_unsigned(value: &str) -> Option<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlConfig {
    version: u64,
    review: Option<TomlReview>,
    repository: Option<TomlRepository>,
    model_context: Option<TomlModelContext>,
    execution: Option<TomlExecution>,
    budget: Option<TomlReviewBudget>,
    publication: Option<TomlPublication>,
    network: Option<TomlNetwork>,
    secrets: Option<TomlSecrets>,
    #[serde(default)]
    rules: Vec<TomlRule>,
    #[serde(default)]
    suppressions: Vec<TomlSuppression>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlReview {
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    minimum_confidence: Option<u64>,
    max_findings: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRepository {
    guidance: Option<String>,
    generated_files: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlModelContext {
    exclude: Option<Vec<String>>,
    max_inline_diff_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlExecution {
    context_lines: Option<u64>,
    model: Option<String>,
    provider: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlReviewBudget {
    max_files: Option<u64>,
    max_input_bytes: Option<u64>,
    max_model_requests: Option<u64>,
    max_model_tokens: Option<u64>,
    max_tool_calls: Option<u64>,
    deadline_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlPublication {
    enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlNetwork {
    github_ca_bundle_file: Option<String>,
    github_private_cidrs: Option<Vec<String>>,
    gitlab_ca_bundle_file: Option<String>,
    gitlab_private_cidrs: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlSecrets {
    gitlab_token_file: Option<String>,
    model_token_file: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRule {
    paths: Vec<String>,
    focus: Vec<String>,
    guidance: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlSuppression {
    fingerprint: String,
    reason: String,
    expires: String,
    ticket: Option<String>,
}

#[derive(Default)]
struct AdaptedInputs {
    assignments: Vec<ConfigAssignment>,
    secret_references: SecretReferences,
    repository: RepositoryReviewPolicy,
}

#[allow(clippy::too_many_lines)]
fn adapt_document(
    document: TomlConfig,
    source: ConfigSource,
    label: &str,
) -> Result<AdaptedInputs, Diagnostic> {
    let repository_contains_operator_settings = source == ConfigSource::BaseRepository
        && (document.execution.is_some()
            || document.publication.is_some()
            || document.network.is_some()
            || document.secrets.is_some());
    let trusted_contains_repository_policy = source != ConfigSource::BaseRepository
        && (document.repository.is_some()
            || document.model_context.is_some()
            || !document.rules.is_empty()
            || !document.suppressions.is_empty());
    let mut adapted = AdaptedInputs::default();
    {
        let mut push = |key: &str, value: ConfigValue| {
            adapted
                .assignments
                .push(assignment(key, value, source, label.to_owned()));
        };
        if let Some(review) = document.review {
            if let Some(value) = review.include {
                push("review.include_patterns", ConfigValue::StringList(value));
            }
            if let Some(value) = review.exclude {
                push("review.exclude_patterns", ConfigValue::StringList(value));
            }
            if let Some(value) = review.minimum_confidence {
                push("review.minimum_confidence", ConfigValue::Unsigned(value));
            }
            if let Some(value) = review.max_findings {
                push("budget.max_findings", ConfigValue::Unsigned(value));
            }
        }
        if let Some(repository) = document.repository {
            if let Some(value) = repository.generated_files {
                let include = match value.as_str() {
                    "ignore" => false,
                    "review" => true,
                    _ => {
                        return Err(contract_error(
                            "repository.generated_files must be `ignore` or `review`",
                        ));
                    }
                };
                push("review.include_generated", ConfigValue::Bool(include));
            }
            adapted.repository.guidance = repository.guidance;
        }
        if let Some(model_context) = document.model_context {
            if let Some(exclude) = model_context.exclude {
                adapted.repository.model_context.exclude = exclude;
            }
            if let Some(value) = model_context.max_inline_diff_bytes {
                if value > 16_384 {
                    return Err(contract_error(
                        "repository model_context.max_inline_diff_bytes may only lower the default",
                    ));
                }
                push(
                    "model_context.max_inline_diff_bytes",
                    ConfigValue::Unsigned(value),
                );
            }
        }
        if let Some(execution) = document.execution {
            if let Some(value) = execution.context_lines {
                push("review.context_lines", ConfigValue::Unsigned(value));
            }
            if let Some(value) = execution.model {
                push("review.model", ConfigValue::String(value));
            }
            if let Some(value) = execution.provider {
                push("review.provider", ConfigValue::String(value));
            }
        }
        if let Some(budget) = document.budget {
            if budget.max_model_requests.is_some_and(|value| value > 64)
                || budget
                    .max_model_tokens
                    .is_some_and(|value| value > 2_000_000)
                || budget.max_tool_calls.is_some_and(|value| value > 256)
                || budget.deadline_seconds.is_some_and(|value| value > 600)
            {
                return Err(contract_error(
                    "repository budget values may only lower their defaults",
                ));
            }
            for (key, value) in [
                ("budget.max_files", budget.max_files),
                ("budget.max_input_bytes", budget.max_input_bytes),
                ("budget.max_model_requests", budget.max_model_requests),
                ("budget.max_model_tokens", budget.max_model_tokens),
                ("budget.max_tool_calls", budget.max_tool_calls),
                ("budget.deadline_seconds", budget.deadline_seconds),
            ] {
                if let Some(value) = value {
                    push(key, ConfigValue::Unsigned(value));
                }
            }
        }
        if let Some(publication) = document.publication
            && let Some(value) = publication.enabled
        {
            push("publication.enabled", ConfigValue::Bool(value));
        }
        if let Some(network) = document.network {
            if let Some(value) = network.github_ca_bundle_file {
                push("network.github_ca_bundle_file", ConfigValue::String(value));
            }
            if let Some(value) = network.github_private_cidrs {
                push(
                    "network.github_private_cidrs",
                    ConfigValue::StringList(value),
                );
            }
            if let Some(value) = network.gitlab_ca_bundle_file {
                push("network.gitlab_ca_bundle_file", ConfigValue::String(value));
            }
            if let Some(value) = network.gitlab_private_cidrs {
                push(
                    "network.gitlab_private_cidrs",
                    ConfigValue::StringList(value),
                );
            }
        }
    }

    if repository_contains_operator_settings {
        return Err(contract_error(
            "repository configuration contains operator-owned execution settings",
        ));
    }

    if trusted_contains_repository_policy {
        return Err(contract_error(
            "repository guidance, model context, rules, and suppressions require repository configuration",
        ));
    }
    if source == ConfigSource::BaseRepository {
        adapted.repository.rules = document
            .rules
            .into_iter()
            .map(|rule| RepositoryRule {
                paths: rule.paths,
                focus: rule.focus,
                guidance: rule.guidance,
            })
            .collect();
        adapted.repository.suppressions = document
            .suppressions
            .into_iter()
            .map(|suppression| {
                Ok(RepositorySuppression {
                    fingerprint: Sha256Digest::try_from(suppression.fingerprint)
                        .map_err(|_| contract_error("suppression fingerprint must be SHA-256"))?,
                    reason: suppression.reason,
                    expires: suppression.expires,
                    ticket: suppression.ticket,
                })
            })
            .collect::<Result<Vec<_>, Diagnostic>>()?;
        validate_repository_policy(&adapted.repository)?;
    }

    if let Some(secrets) = document.secrets {
        if source == ConfigSource::BaseRepository {
            return Err(contract_error(
                "repository configuration may not contain secret references",
            ));
        }
        if let Some(path) = secrets.gitlab_token_file {
            adapted.secret_references.insert(SecretReference::file(
                SecretKind::GitLabToken,
                PathBuf::from(path),
                source,
            )?)?;
        }
        if let Some(path) = secrets.model_token_file {
            adapted.secret_references.insert(SecretReference::file(
                SecretKind::ModelToken,
                PathBuf::from(path),
                source,
            )?)?;
        }
    }
    Ok(adapted)
}

fn validate_repository_policy(policy: &RepositoryReviewPolicy) -> Result<(), Diagnostic> {
    if policy.rules.len() > MAX_RULES || policy.suppressions.len() > MAX_SUPPRESSIONS {
        return Err(contract_error(
            "repository policy exceeds the rule or suppression count limit",
        ));
    }
    if let Some(guidance) = &policy.guidance {
        validate_text(guidance, 8 * 1024, "repository guidance")?;
    }
    if policy.model_context.exclude.len() > 64 {
        return Err(contract_error(
            "model context policy exceeds the exclusion count limit",
        ));
    }
    for pattern in &policy.model_context.exclude {
        validate_context_pattern(pattern)?;
    }
    for rule in &policy.rules {
        if rule.paths.is_empty() || rule.paths.len() > 32 {
            return Err(contract_error(
                "each repository rule requires 1 to 32 paths",
            ));
        }
        validate_string_list(&rule.paths, 256, "repository rule paths")?;
        if rule.focus.is_empty() || rule.focus.len() > 16 {
            return Err(contract_error(
                "each repository rule requires 1 to 16 focus areas",
            ));
        }
        validate_string_list(&rule.focus, 64, "repository rule focus areas")?;
        if rule.focus.iter().any(|focus| {
            !focus
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        }) {
            return Err(contract_error(
                "repository rule focus areas contain unsupported characters",
            ));
        }
        validate_text(&rule.guidance, 4 * 1024, "repository rule guidance")?;
    }
    let today = unix_days(SystemTime::now())?;
    let mut fingerprints = BTreeSet::new();
    for suppression in &policy.suppressions {
        if !fingerprints.insert(suppression.fingerprint.clone()) {
            return Err(contract_error(
                "repository suppressions contain duplicate fingerprints",
            ));
        }
        validate_text(&suppression.reason, 512, "suppression reason")?;
        if suppression
            .ticket
            .as_deref()
            .is_some_and(|ticket| validate_text(ticket, 128, "suppression ticket").is_err())
        {
            return Err(contract_error("suppression ticket is invalid"));
        }
        let expiry = parse_date_days(&suppression.expires)
            .ok_or_else(|| contract_error("suppression expiry must be a valid YYYY-MM-DD date"))?;
        if expiry < today {
            return Err(
                contract_error("repository configuration contains an expired suppression")
                    .with_remediation("remove the suppression or set a reviewed future expiry"),
            );
        }
    }
    Ok(())
}

fn validate_context_pattern(pattern: &str) -> Result<(), Diagnostic> {
    let path = if let Some(prefix) = pattern.strip_suffix("/**") {
        prefix
    } else if let Some(suffix) = pattern.strip_prefix("**/*") {
        if suffix.is_empty() || suffix.contains('*') || suffix.contains('/') {
            return Err(contract_error("model context exclusion pattern is invalid"));
        }
        return validate_text(pattern, 256, "model context exclusion pattern");
    } else if pattern.contains('*') {
        return Err(contract_error(
            "model context exclusions support exact paths, directory/**, or **/*suffix",
        ));
    } else {
        pattern
    };
    if revoot_core::RepositoryRelativePath::try_from(path.to_owned()).is_err() {
        return Err(contract_error("model context exclusion pattern is invalid"));
    }
    validate_text(pattern, 256, "model context exclusion pattern")
}

fn context_pattern_matches(pattern: &str, path: &str) -> bool {
    pattern
        .strip_suffix("/**")
        .is_some_and(|prefix| path.starts_with(&format!("{prefix}/")))
        || pattern
            .strip_prefix("**/*")
            .is_some_and(|suffix| path.ends_with(suffix))
        || pattern == path
}

fn validate_string_list(values: &[String], maximum: usize, label: &str) -> Result<(), Diagnostic> {
    if values
        .iter()
        .any(|value| validate_text(value, maximum, label).is_err())
    {
        return Err(contract_error(format!("{label} are invalid")));
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), Diagnostic> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(contract_error(format!("{label} is invalid")));
    }
    Ok(())
}

fn unix_days(time: SystemTime) -> Result<i64, Diagnostic> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| contract_error("system clock predates the supported configuration epoch"))?
        .as_secs();
    i64::try_from(seconds / 86_400)
        .map_err(|_| contract_error("system clock exceeds the supported configuration range"))
}

fn parse_date_days(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return None;
    }
    let year = value[0..4].parse::<i64>().ok()?;
    let month = value[5..7].parse::<u32>().ok()?;
    let day = value[8..10].parse::<u32>().ok()?;
    if year < 1970 || !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month as i64 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn adapt_environment(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<AdaptedInputs, Diagnostic> {
    let mut adapted = AdaptedInputs::default();
    for (name, value) in environment {
        match name.to_str() {
            // Credential ownership is deliberately separate from effective
            // configuration. Standard local/CI secret variables are ignored
            // here and discovered only by the selected adapter.
            Some(
                "ANTHROPIC_API_KEY"
                | "OPENAI_API_KEY"
                | "GITLAB_TOKEN"
                | "CI_JOB_TOKEN"
                | "REVOOT_GITLAB_TOKEN"
                | "REVOOT_MODEL_TOKEN",
            )
            | None => {}
            Some("REVOOT_GITLAB_TOKEN_FILE") => {
                adapted.secret_references.insert(SecretReference::file(
                    SecretKind::GitLabToken,
                    PathBuf::from(value),
                    ConfigSource::AllowedCiVariable,
                )?)?;
            }
            Some("REVOOT_MODEL_TOKEN_FILE") => {
                adapted.secret_references.insert(SecretReference::file(
                    SecretKind::ModelToken,
                    PathBuf::from(value),
                    ConfigSource::AllowedCiVariable,
                )?)?;
            }
            Some(name) => {
                let Some((key, kind)) = environment_mapping(name) else {
                    continue;
                };
                let value = value.to_str().ok_or_else(|| {
                    contract_error(format!(
                        "{name} must contain valid UTF-8 configuration data"
                    ))
                })?;
                let value = match kind {
                    EnvironmentValueKind::Unsigned => {
                        ConfigValue::Unsigned(parse_canonical_unsigned(value).ok_or_else(|| {
                            contract_error(format!("{name} must be a canonical unsigned integer"))
                        })?)
                    }
                    EnvironmentValueKind::Bool => ConfigValue::Bool(match value {
                        "true" => true,
                        "false" => false,
                        _ => {
                            return Err(contract_error(format!(
                                "{name} must be exactly true or false"
                            )));
                        }
                    }),
                    EnvironmentValueKind::String => ConfigValue::String(value.to_owned()),
                    EnvironmentValueKind::CommaSeparatedStringList => {
                        let values = if value.is_empty() {
                            Vec::new()
                        } else {
                            value.split(',').map(str::to_owned).collect()
                        };
                        if values.iter().any(String::is_empty) {
                            return Err(contract_error(format!(
                                "{name} must be a comma-separated list without empty entries"
                            )));
                        }
                        ConfigValue::StringList(values)
                    }
                };
                adapted.assignments.push(assignment(
                    key,
                    value,
                    ConfigSource::AllowedCiVariable,
                    format!("env:{name}"),
                ));
            }
        }
    }
    Ok(adapted)
}

#[derive(Clone, Copy)]
enum EnvironmentValueKind {
    Unsigned,
    Bool,
    String,
    CommaSeparatedStringList,
}

fn environment_mapping(name: &str) -> Option<(&'static str, EnvironmentValueKind)> {
    match name {
        "REVOOT_REVIEW_CONTEXT_LINES" => {
            Some(("review.context_lines", EnvironmentValueKind::Unsigned))
        }
        "REVOOT_MINIMUM_CONFIDENCE" => {
            Some(("review.minimum_confidence", EnvironmentValueKind::Unsigned))
        }
        "REVOOT_MODEL" | "REVOOT_REVIEW_MODEL" => {
            Some(("review.model", EnvironmentValueKind::String))
        }
        "REVOOT_PROVIDER" => Some(("review.provider", EnvironmentValueKind::String)),
        "REVOOT_GITHUB_CA_BUNDLE_FILE" => Some((
            "network.github_ca_bundle_file",
            EnvironmentValueKind::String,
        )),
        "REVOOT_GITHUB_PRIVATE_CIDRS" => Some((
            "network.github_private_cidrs",
            EnvironmentValueKind::CommaSeparatedStringList,
        )),
        "REVOOT_GITLAB_CA_BUNDLE_FILE" => Some((
            "network.gitlab_ca_bundle_file",
            EnvironmentValueKind::String,
        )),
        "REVOOT_GITLAB_PRIVATE_CIDRS" => Some((
            "network.gitlab_private_cidrs",
            EnvironmentValueKind::CommaSeparatedStringList,
        )),
        "REVOOT_MAX_FILES" => Some(("budget.max_files", EnvironmentValueKind::Unsigned)),
        "REVOOT_MAX_INPUT_BYTES" => {
            Some(("budget.max_input_bytes", EnvironmentValueKind::Unsigned))
        }
        "REVOOT_MAX_FINDINGS" => Some(("budget.max_findings", EnvironmentValueKind::Unsigned)),
        "REVOOT_MAX_MODEL_REQUESTS" => {
            Some(("budget.max_model_requests", EnvironmentValueKind::Unsigned))
        }
        "REVOOT_MAX_MODEL_TOKENS" => {
            Some(("budget.max_model_tokens", EnvironmentValueKind::Unsigned))
        }
        "REVOOT_MAX_TOOL_CALLS" => Some(("budget.max_tool_calls", EnvironmentValueKind::Unsigned)),
        "REVOOT_MAX_INLINE_DIFF_BYTES" => Some((
            "model_context.max_inline_diff_bytes",
            EnvironmentValueKind::Unsigned,
        )),
        "REVOOT_REVIEW_EFFORT" => Some(("review.effort", EnvironmentValueKind::String)),
        "REVOOT_MAX_PARALLEL_GROUPS" => {
            Some(("review.max_parallel_groups", EnvironmentValueKind::Unsigned))
        }
        "REVOOT_DEADLINE_SECONDS" => {
            Some(("budget.deadline_seconds", EnvironmentValueKind::Unsigned))
        }
        "REVOOT_PUBLICATION_ENABLED" => Some(("publication.enabled", EnvironmentValueKind::Bool)),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn product_schema() -> Result<ConfigurationSchema, Diagnostic> {
    ConfigurationSchema::try_new([
        unsigned_field(
            "budget.deadline_seconds",
            600,
            AssignmentScope::RepositoryAndTrusted,
            1,
            600,
        ),
        unsigned_field(
            "budget.max_files",
            100,
            AssignmentScope::RepositoryAndTrusted,
            1,
            10_000,
        ),
        unsigned_field(
            "budget.max_findings",
            25,
            AssignmentScope::RepositoryAndTrusted,
            1,
            1_000,
        ),
        unsigned_field(
            "budget.max_input_bytes",
            1_000_000,
            AssignmentScope::RepositoryAndTrusted,
            1,
            100_000_000,
        ),
        unsigned_field(
            "budget.max_model_requests",
            64,
            AssignmentScope::RepositoryAndTrusted,
            1,
            256,
        ),
        unsigned_field(
            "budget.max_model_tokens",
            2_000_000,
            AssignmentScope::RepositoryAndTrusted,
            1,
            2_000_000,
        ),
        unsigned_field(
            "budget.max_tool_calls",
            256,
            AssignmentScope::RepositoryAndTrusted,
            1,
            2_048,
        ),
        unsigned_field(
            "model_context.max_inline_diff_bytes",
            16_384,
            AssignmentScope::RepositoryAndTrusted,
            1,
            16_384,
        ),
        unsigned_field(
            "review.max_parallel_groups",
            2,
            AssignmentScope::TrustedOnly,
            1,
            8,
        ),
        ConfigField::new(
            key("review.effort"),
            ConfigValue::String("medium".to_owned()),
            AssignmentScope::TrustedOnly,
            ValueConstraint::String {
                allow_empty: false,
                max_bytes: 6,
            },
        ),
        ConfigField::new(
            key("publication.enabled"),
            ConfigValue::Bool(false),
            AssignmentScope::TrustedOnly,
            ValueConstraint::Any,
        ),
        ConfigField::new(
            key("network.github_ca_bundle_file"),
            ConfigValue::String(String::new()),
            AssignmentScope::TrustedOnly,
            ValueConstraint::String {
                allow_empty: true,
                max_bytes: MAX_SECRET_REFERENCE_BYTES,
            },
        ),
        ConfigField::new(
            key("network.github_private_cidrs"),
            ConfigValue::StringList(Vec::new()),
            AssignmentScope::TrustedOnly,
            ValueConstraint::StringList {
                allow_empty_items: false,
                max_items: 16,
                max_item_bytes: 64,
            },
        ),
        ConfigField::new(
            key("network.gitlab_ca_bundle_file"),
            ConfigValue::String(String::new()),
            AssignmentScope::TrustedOnly,
            ValueConstraint::String {
                allow_empty: true,
                max_bytes: MAX_SECRET_REFERENCE_BYTES,
            },
        ),
        ConfigField::new(
            key("network.gitlab_private_cidrs"),
            ConfigValue::StringList(Vec::new()),
            AssignmentScope::TrustedOnly,
            ValueConstraint::StringList {
                allow_empty_items: false,
                max_items: 16,
                max_item_bytes: 64,
            },
        ),
        unsigned_field(
            "review.context_lines",
            40,
            AssignmentScope::RepositoryAndTrusted,
            0,
            500,
        ),
        string_list_field("review.exclude_patterns"),
        string_list_field("review.include_patterns"),
        ConfigField::new(
            key("review.include_generated"),
            ConfigValue::Bool(false),
            AssignmentScope::RepositoryAndTrusted,
            ValueConstraint::Any,
        ),
        unsigned_field(
            "review.minimum_confidence",
            70,
            AssignmentScope::RepositoryAndTrusted,
            0,
            100,
        ),
        ConfigField::new(
            key("review.model"),
            ConfigValue::String("auto".to_owned()),
            AssignmentScope::TrustedOnly,
            ValueConstraint::String {
                allow_empty: false,
                max_bytes: 128,
            },
        ),
        ConfigField::new(
            key("review.provider"),
            ConfigValue::String("auto".to_owned()),
            AssignmentScope::TrustedOnly,
            ValueConstraint::String {
                allow_empty: false,
                max_bytes: 128,
            },
        ),
        ConfigField::new(
            key("review.repository_execution"),
            ConfigValue::Bool(false),
            AssignmentScope::CompiledDefaultOnly,
            ValueConstraint::Any,
        ),
    ])
    .map_err(|error| {
        contract_error(format!(
            "product configuration schema is invalid: {error:?}"
        ))
    })
}

fn product_policy() -> Vec<PolicyRule> {
    [
        ("budget.deadline_seconds", 1, 600),
        ("budget.max_files", 1, 100),
        ("budget.max_findings", 1, 25),
        ("budget.max_input_bytes", 1, 1_000_000),
        ("budget.max_model_requests", 1, 256),
        ("budget.max_model_tokens", 1, 2_000_000),
        ("budget.max_tool_calls", 1, 2_048),
        ("model_context.max_inline_diff_bytes", 1, 16_384),
        ("review.max_parallel_groups", 1, 8),
        ("review.context_lines", 0, 200),
        ("review.minimum_confidence", 70, 100),
    ]
    .into_iter()
    .map(|(key_name, min, max)| {
        PolicyRule::new(
            key(key_name),
            PolicyConstraint::ClampUnsigned { min, max },
            "product-policy:v1",
        )
    })
    .collect()
}

fn unsigned_field(
    name: &str,
    default: u64,
    scope: AssignmentScope,
    min: u64,
    max: u64,
) -> ConfigField {
    ConfigField::new(
        key(name),
        ConfigValue::Unsigned(default),
        scope,
        ValueConstraint::UnsignedRange { min, max },
    )
}

fn string_list_field(name: &str) -> ConfigField {
    ConfigField::new(
        key(name),
        ConfigValue::StringList(Vec::new()),
        AssignmentScope::RepositoryAndTrusted,
        ValueConstraint::StringList {
            max_items: 128,
            allow_empty_items: false,
            max_item_bytes: 256,
        },
    )
}

fn key(value: &str) -> ConfigKey {
    ConfigKey::new(value).expect("static product configuration key is valid")
}

fn assignment(
    key_name: &str,
    value: ConfigValue,
    source: ConfigSource,
    label: String,
) -> ConfigAssignment {
    ConfigAssignment::new(key(key_name), value, SourceProvenance::new(source, label))
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum SecretKind {
    GitLabToken,
    ModelToken,
}

struct SecretReference {
    kind: SecretKind,
    file: PathBuf,
    source: ConfigSource,
}

impl SecretReference {
    fn file(kind: SecretKind, file: PathBuf, source: ConfigSource) -> Result<Self, Diagnostic> {
        if !file.is_absolute() {
            return Err(contract_error(
                "secret file references must be absolute paths",
            ));
        }
        if file.as_os_str().as_encoded_bytes().len() > MAX_SECRET_REFERENCE_BYTES {
            return Err(contract_error(
                "secret file reference exceeds the byte limit",
            ));
        }
        Ok(Self { kind, file, source })
    }
}

#[derive(Default)]
struct SecretReferences(BTreeMap<SecretKind, SecretReference>);

impl SecretReferences {
    fn insert(&mut self, reference: SecretReference) -> Result<(), Diagnostic> {
        if let Some(current) = self.0.get(&reference.kind) {
            if current.source == reference.source {
                return Err(contract_error("duplicate secret reference assignment"));
            }
            if current.source > reference.source {
                return Ok(());
            }
        }
        self.0.insert(reference.kind, reference);
        Ok(())
    }

    fn extend(&mut self, other: Self) -> Result<(), Diagnostic> {
        for reference in other.0.into_values() {
            self.insert(reference)?;
        }
        Ok(())
    }

    fn validate_retained_references(&self) {
        for reference in self.0.values() {
            debug_assert!(reference.file.is_absolute());
            let _ = reference.source;
        }
    }
}

fn print_human(fields: &[ConfigExplainRecord]) {
    for field in fields {
        println!(
            "{}: requested={:?} source={:?} policy={:?} effective={:?}",
            field.key,
            field.requested.value(),
            field.requested.provenance().source(),
            field.policy.constraint,
            field.effective
        );
    }
}

fn print_help() {
    println!(
        "USAGE:\n  revoot config explain [--json] [--base-config PATH] [--config PATH]\n                        [--context-lines N] [--minimum-confidence N]\n                        [--provider PROVIDER] [--model MODEL]\n                        [--max-files N] [--max-input-bytes N]\n                        [--max-findings N] [--max-model-requests N]\n                        [--deadline-seconds N] [--publish|--no-publish]"
    );
}

fn cli_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::CliInvalidArgument, message)
}

fn contract_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::ContractInvalid, message)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use revoot_core::{ConfigSource, ConfigValue, GitSha};

    use super::{
        CONFIG_SCHEMA_VERSION, ExplainArgs, OutputMode, adapt_document, adapt_environment,
        load_repository_document, parse_explain_args, parse_file, parse_toml, product_policy,
        product_schema, resolve,
    };

    static FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    const VALID: &str = r#"version = 1

[review]
include = ["src/**", "tests/**"]
exclude = ["vendor/**"]
minimum_confidence = 75
max_findings = 12

[repository]
generated_files = "ignore"
guidance = "All writes are idempotent."

[model_context]
exclude = ["private/**", "**/*.secret"]

[[rules]]
paths = ["src/payments/**"]
focus = ["authorization", "idempotency"]
guidance = "Amounts use integer cents."

[[suppressions]]
fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
reason = "Accepted eventual consistency."
expires = "2099-12-31"
ticket = "ENG-42"
"#;

    fn args(values: &[&str]) -> impl Iterator<Item = String> {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn product_defaults_and_fixed_invariants_resolve() {
        let resolution = product_schema()
            .unwrap()
            .resolve(Vec::new(), product_policy())
            .unwrap();
        assert_eq!(
            resolution.effective().get("review.repository_execution"),
            Some(&ConfigValue::Bool(false))
        );
    }

    #[test]
    fn valid_toml_is_typed_and_repository_policy_is_bounded() {
        let parsed = parse_toml(VALID).unwrap();
        assert_eq!(parsed.version, CONFIG_SCHEMA_VERSION);
        let adapted = adapt_document(parsed, ConfigSource::BaseRepository, "base").unwrap();
        let resolution = product_schema()
            .unwrap()
            .resolve(adapted.assignments, product_policy())
            .unwrap();
        assert_eq!(
            resolution.effective().get("budget.max_findings"),
            Some(&ConfigValue::Unsigned(12))
        );
        assert_eq!(adapted.repository.rules.len(), 1);
        assert_eq!(adapted.repository.suppressions.len(), 1);
        assert_eq!(
            adapted.repository.model_context.exclude,
            ["private/**", "**/*.secret"]
        );
        let guidance = adapted.repository.guidance_text().unwrap();
        assert!(guidance.contains("src/payments/**"));
        assert!(guidance.contains("integer cents"));
    }

    #[test]
    fn model_context_is_fail_closed_for_sensitive_and_repository_excluded_paths() {
        let policy = super::RepositoryReviewPolicy {
            model_context: super::ModelContextPolicy {
                exclude: vec!["internal/**".to_owned(), "**/*.vault".to_owned()],
            },
            ..super::RepositoryReviewPolicy::default()
        };

        for denied in [
            ".env",
            "services/api/.env.production",
            ".aws/credentials",
            "ops/.terraform/terraform.tfstate",
            "certs/signing.pem",
            "internal/runbook.md",
            "fixtures/passwords.vault",
        ] {
            assert!(!policy.allows_model_context(denied), "{denied} was allowed");
        }
        for allowed in ["src/lib.rs", "docs/security.md"] {
            assert!(policy.allows_model_context(allowed), "{allowed} was denied");
        }
    }

    #[test]
    fn duplicate_unknown_wrong_version_and_operator_repository_settings_are_rejected() {
        let cases = [
            VALID.replacen("version = 1", "version = 1\nversion = 1", 1),
            VALID.replacen("[review]", "unknown = true\n\n[review]", 1),
            VALID.replacen("version = 1", "version = 2", 1),
        ];
        for input in cases {
            assert!(parse_toml(&input).is_err(), "invalid TOML was accepted");
        }
        let operator = "version = 1\n[execution]\nmodel = \"attacker\"\n";
        assert!(
            adapt_document(
                parse_toml(operator).unwrap(),
                ConfigSource::BaseRepository,
                "base"
            )
            .is_err()
        );
        assert!(
            adapt_document(
                parse_toml("version = 1\n[repository]\nguidance = \"local\"\n").unwrap(),
                ConfigSource::TrustedLocal,
                "local"
            )
            .is_err()
        );
    }

    #[test]
    fn oversized_and_wrong_version_documents_are_rejected() {
        let oversized = format!(
            "version = 1\n[repository]\nguidance = \"{}\"\n",
            "x".repeat(super::MAX_CONFIG_BYTES)
        );
        assert!(parse_toml(&oversized).is_err());
        assert!(parse_toml(&VALID.replacen("version = 1", "version = 2", 1)).is_err());
        let expired = VALID.replace("2099-12-31", "2020-01-01");
        assert!(
            adapt_document(
                parse_toml(&expired).unwrap(),
                ConfigSource::BaseRepository,
                "base"
            )
            .is_err()
        );
    }

    #[test]
    fn configuration_files_do_not_follow_symbolic_links() {
        let sequence = FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "revoot-config-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("fixture directory");
        let target = directory.join("target.toml");
        let link = directory.join("config.toml");
        fs::write(&target, VALID).expect("fixture config");
        symlink(&target, &link).expect("fixture symlink");
        assert!(parse_file(&link).is_err());
        fs::remove_dir_all(directory).expect("fixture cleanup");
    }

    #[test]
    fn repository_cannot_assign_trusted_fields_or_secret_references() {
        let secret = "version = 1\n[secrets]\ngitlab_token_file = \"/not/read\"\n";
        assert!(
            adapt_document(
                parse_toml(secret).unwrap(),
                ConfigSource::BaseRepository,
                "base"
            )
            .is_err()
        );
    }

    #[test]
    fn self_managed_network_exceptions_require_a_trusted_source() {
        let document = "version = 1\n[network]\ngitlab_ca_bundle_file = \"/etc/revoot/gitlab-ca.pem\"\ngitlab_private_cidrs = [\"10.20.0.0/16\"]\n";
        assert!(
            adapt_document(
                parse_toml(document).unwrap(),
                ConfigSource::BaseRepository,
                "base"
            )
            .is_err()
        );
        let parsed = parse_toml(document).expect("network configuration");
        let trusted = adapt_document(parsed, ConfigSource::TrustedLocal, "local")
            .expect("typed trusted configuration");
        let resolution = product_schema()
            .unwrap()
            .resolve(trusted.assignments, product_policy())
            .expect("trusted network configuration");
        assert_eq!(
            resolution.effective().get("network.gitlab_private_cidrs"),
            Some(&ConfigValue::StringList(vec!["10.20.0.0/16".to_owned()]))
        );
    }

    #[test]
    fn environment_is_an_explicit_allowlist_and_unknown_names_are_ignored() {
        let adapted = adapt_environment([
            (
                OsString::from("REVOOT_REVIEW_CONTEXT_LINES"),
                OsString::from("90"),
            ),
            (
                OsString::from("REVOOT_UNKNOWN_SETTING"),
                OsString::from("ignored"),
            ),
            (OsString::from("REVOOT_MODEL"), OsString::from("model-id")),
            (
                OsString::from("REVOOT_GITLAB_PRIVATE_CIDRS"),
                OsString::from("10.20.0.0/16,fd00::/8"),
            ),
        ])
        .unwrap();
        assert_eq!(adapted.assignments.len(), 3);
        assert_eq!(
            adapted.assignments[0].provenance().source(),
            ConfigSource::AllowedCiVariable
        );
    }

    #[test]
    fn direct_secret_values_do_not_enter_effective_configuration() {
        let adapted = adapt_environment([(
            OsString::from("REVOOT_GITLAB_TOKEN"),
            OsString::from("super-secret-value"),
        )])
        .expect("credentials are owned by adapters");
        assert!(adapted.assignments.is_empty());
        assert!(adapted.secret_references.0.is_empty());
    }

    #[test]
    fn secret_file_references_are_validated_but_never_opened_or_serialized() {
        let parsed = ExplainArgs {
            output: OutputMode::Json,
            ..ExplainArgs::default()
        };
        let resolution = resolve(
            &parsed,
            [(
                OsString::from("REVOOT_GITLAB_TOKEN_FILE"),
                OsString::from("/definitely/not/opened/by-config-explain"),
            )],
        )
        .unwrap();
        let json = String::from_utf8(resolution.canonical_explain_json().unwrap()).unwrap();
        assert!(!json.contains("not/opened"));
        assert!(!json.to_ascii_lowercase().contains("token_file"));
    }

    #[test]
    fn relative_secret_file_references_are_rejected() {
        assert!(
            adapt_environment([(
                OsString::from("REVOOT_MODEL_TOKEN_FILE"),
                OsString::from("relative/token"),
            )])
            .is_err()
        );
    }

    #[test]
    fn secret_references_follow_source_precedence_without_exposing_paths() {
        let local = "version = 1\n[secrets]\ngitlab_token_file = \"/trusted/local-token\"\n";
        let mut references = adapt_document(
            parse_toml(local).unwrap(),
            ConfigSource::TrustedLocal,
            "local",
        )
        .unwrap()
        .secret_references;
        references
            .extend(
                adapt_environment([(
                    OsString::from("REVOOT_GITLAB_TOKEN_FILE"),
                    OsString::from("/ci/token"),
                )])
                .unwrap()
                .secret_references,
            )
            .unwrap();
        let selected = references.0.values().next().unwrap();
        assert_eq!(selected.source, ConfigSource::AllowedCiVariable);
        assert_eq!(selected.file, std::path::Path::new("/ci/token"));
    }

    #[test]
    fn cli_has_highest_requested_precedence_but_product_policy_still_wins() {
        let mut parsed = parse_explain_args(args(&["--context-lines", "300"]))
            .unwrap()
            .unwrap();
        parsed.output = OutputMode::Json;
        let resolution = resolve(
            &parsed,
            [(
                OsString::from("REVOOT_REVIEW_CONTEXT_LINES"),
                OsString::from("100"),
            )],
        )
        .unwrap();
        let requested = resolution.requested().get("review.context_lines").unwrap();
        assert_eq!(requested.value(), &ConfigValue::Unsigned(300));
        assert_eq!(requested.provenance().source(), ConfigSource::CommandLine);
        assert_eq!(
            resolution.effective().get("review.context_lines"),
            Some(&ConfigValue::Unsigned(200))
        );
    }

    #[test]
    fn duplicate_and_unknown_cli_assignments_fail_closed() {
        let duplicate = parse_explain_args(args(&["--max-files", "10", "--max-files", "20"]))
            .unwrap()
            .unwrap();
        assert!(resolve(&duplicate, []).is_err());
        assert!(parse_explain_args(args(&["--invented"])).is_err());
        assert!(parse_explain_args(args(&["--max-files", "01"])).is_err());
    }

    #[test]
    fn ci_configuration_is_read_from_the_exact_base_commit() {
        let sequence = FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "revoot-config-git-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        for command in [
            vec!["init", "--quiet"],
            vec!["config", "user.email", "test@example.com"],
            vec!["config", "user.name", "Revoot Test"],
            vec!["config", "commit.gpgsign", "false"],
        ] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&directory)
                    .args(command)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        fs::write(directory.join(".revoot.toml"), VALID).unwrap();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&directory)
                .args(["add", ".revoot.toml"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&directory)
                .args(["commit", "--quiet", "-m", "base"])
                .status()
                .unwrap()
                .success()
        );
        let output = Command::new("git")
            .arg("-C")
            .arg(&directory)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let sha =
            GitSha::try_from(String::from_utf8(output.stdout).unwrap().trim().to_owned()).unwrap();
        fs::write(
            directory.join(".revoot.toml"),
            "version = 1\n[execution]\nmodel = \"attacker\"\n",
        )
        .unwrap();
        let base = load_repository_document(&directory, Some(&sha))
            .unwrap()
            .unwrap();
        let adapted = adapt_document(base, ConfigSource::BaseRepository, "base").unwrap();
        assert_eq!(adapted.repository.rules.len(), 1);
        fs::remove_dir_all(directory).unwrap();
    }
}
