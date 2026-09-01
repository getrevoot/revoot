//! CLI preparation and bounded local-only execution for source scans.
//!
//! This module parses scan arguments, captures an immutable local repository
//! state, constructs the shared body-free scan plan, and delegates model work
//! to the common tool-first engine. Scan results are never published.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use gix::bstr::ByteSlice;
use revoot_core::{
    CancellationToken, ConfigValue, Diagnostic, ErrorCode, RepositoryPath, RepositoryRelativePath,
    ReviewBudgetBroker, SarifCoverageMetadata, SarifRunMetadata, ScanFileInput, ScanFileTracking,
    ScanLimits, ScanPlan, ScanRequestMetadata, ScanUntrackedPolicy, build_scan_plan, render_sarif,
};
use serde::Serialize;

use crate::config::{ResolvedReviewConfiguration, resolve_review_configuration};
use crate::direct_provider::{build_provider, discover_credentials, select_model, select_provider};
use crate::group_worker_engine::GroupWorkerClock;
use crate::local_review::{LocalGitCapture, capture_local_git};
use crate::review_adjudicator::ReviewAdjudicatorClock;
use crate::review_command::{partition_limits, selection_policy, tool_first_limits};
use crate::review_grouper::ReviewGrouperClock;
use crate::review_strategy_config::{ReviewStrategyConfiguration, strategy_from_resolved};
use crate::review_verifier::ReviewVerifierClock;
use crate::reviewer_policy::{REVIEWER_POLICY_VERSION, tool_first_reviewer_system_policy};
use crate::scan_engine::{ScanEngineOutput, ScanEngineRequest, ScanEngineStatus, run_scan_engine};

const MAX_REQUESTED_PATHS: usize = 256;
const MAX_REQUESTED_PATH_BYTES: usize = 32 * 1024;
const MAX_PREPARATION_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Stable output formats accepted by `revoot scan`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ScanOutputFormat {
    #[default]
    Human,
    Json,
    Sarif,
}

/// Strictly parsed scan command arguments.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanCommandArgs {
    pub requested_paths: Vec<RepositoryPath>,
    pub include_untracked: bool,
    pub preview: bool,
    pub format: ScanOutputFormat,
}

/// Result of parsing, including the help-only branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedScanCommand {
    Help,
    Execute(ScanCommandArgs),
}

/// Trusted classification of the process that requested a local scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanInvocationAuthority {
    ExplicitLocal,
    ContinuousIntegration,
}

/// Immutable, in-memory preparation for the later scan execution boundary.
pub struct PreparedScan {
    root: PathBuf,
    repository_paths: BTreeSet<RepositoryRelativePath>,
    plan: ScanPlan,
    inputs: Vec<ScanFileInput>,
}

impl std::fmt::Debug for PreparedScan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedScan")
            .field("plan_sha256", &self.plan.plan_sha256)
            .field("repository_path_count", &self.repository_paths.len())
            .field("input_count", &self.inputs.len())
            .finish_non_exhaustive()
    }
}

impl PreparedScan {
    #[must_use]
    pub const fn plan(&self) -> &ScanPlan {
        &self.plan
    }

    /// Revalidate that the body-free plan still corresponds to the retained
    /// immutable source inputs.
    ///
    /// # Errors
    ///
    /// Returns a payload-free contract diagnostic if replay diverges.
    pub fn validate_replay(&self) -> Result<(), Diagnostic> {
        self.plan
            .validate_replay(&self.inputs)
            .map_err(|_| contract_error("prepared scan plan failed replay validation"))
    }

    /// Split the immutable plan and retained bodies for the shared tool-first
    /// scan engine.
    #[must_use]
    pub fn into_execution_parts(
        self,
    ) -> (
        PathBuf,
        BTreeSet<RepositoryRelativePath>,
        ScanPlan,
        Vec<ScanFileInput>,
    ) {
        (self.root, self.repository_paths, self.plan, self.inputs)
    }
}

#[derive(Serialize)]
struct ScanPreview<'a> {
    schema_version: &'static str,
    state: &'static str,
    provider_calls: u8,
    publication: &'static str,
    plan: &'a ScanPlan,
}

#[derive(Serialize)]
struct ScanOutput<'a> {
    schema_version: &'static str,
    provider: &'a str,
    model: &'a str,
    publication: &'static str,
    scan: &'a ScanEngineOutput,
}

struct ProcessClock(Instant);

impl ProcessClock {
    fn start() -> Self {
        Self(Instant::now())
    }
}

impl ReviewGrouperClock for ProcessClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

impl GroupWorkerClock for ProcessClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

impl ReviewVerifierClock for ProcessClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

impl ReviewAdjudicatorClock for ProcessClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Parse `revoot scan` arguments without reading environment or repository
/// state.
///
/// # Errors
///
/// Rejects unknown or repeated singleton options, missing values, malformed or
/// duplicate paths, excessive path selectors, and SARIF preview requests.
pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<ParsedScanCommand, Diagnostic> {
    let arguments = args.into_iter().collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    {
        return if arguments.len() == 1 {
            Ok(ParsedScanCommand::Help)
        } else {
            Err(cli_error("--help cannot be combined with scan options"))
        };
    }

    let mut parsed = ScanCommandArgs::default();
    let mut paths = BTreeSet::new();
    let mut path_bytes = 0_usize;
    let mut preview_seen = false;
    let mut untracked_seen = false;
    let mut format_seen = false;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--path" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| cli_error("--path requires a repository path"))?;
                if value.starts_with('-') {
                    return Err(cli_error("--path requires a repository path"));
                }
                let path = RepositoryPath::try_from(value)
                    .map_err(|_| cli_error("--path contains an invalid repository path"))?;
                path_bytes = path_bytes
                    .checked_add(path.as_str().len())
                    .ok_or_else(|| cli_error("scan path selectors exceed their byte bound"))?;
                if path_bytes > MAX_REQUESTED_PATH_BYTES {
                    return Err(cli_error("scan path selectors exceed their byte bound"));
                }
                if !paths.insert(path) {
                    return Err(cli_error("--path contains a duplicate repository path"));
                }
                if paths.len() > MAX_REQUESTED_PATHS {
                    return Err(cli_error("scan accepts at most 256 path selectors"));
                }
            }
            "--include-untracked" => {
                if untracked_seen {
                    return Err(cli_error("--include-untracked may be supplied only once"));
                }
                untracked_seen = true;
                parsed.include_untracked = true;
            }
            "--preview" => {
                if preview_seen {
                    return Err(cli_error("--preview may be supplied only once"));
                }
                preview_seen = true;
                parsed.preview = true;
            }
            "--format" => {
                if format_seen {
                    return Err(cli_error("--format may be supplied only once"));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| cli_error("--format requires a value"))?;
                parsed.format = match value.as_str() {
                    "human" => ScanOutputFormat::Human,
                    "json" => ScanOutputFormat::Json,
                    "sarif" => ScanOutputFormat::Sarif,
                    _ => return Err(cli_error("--format must be human, json, or sarif")),
                };
                format_seen = true;
            }
            _ => return Err(cli_error(format!("unknown scan option: {argument}"))),
        }
    }
    parsed.requested_paths = paths.into_iter().collect();
    if parsed.preview && parsed.format == ScanOutputFormat::Sarif {
        return Err(cli_error(
            "scan preview supports human or json output, not sarif",
        ));
    }
    Ok(ParsedScanCommand::Execute(parsed))
}

/// Classify whether process environment grants only local scan authority or
/// indicates continuous integration.
#[must_use]
pub fn classify_invocation_authority(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> ScanInvocationAuthority {
    const CI_MARKERS: [&str; 5] = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE"];
    if environment.into_iter().any(|(key, value)| {
        CI_MARKERS
            .iter()
            .any(|candidate| key == OsStr::new(candidate))
            && environment_value_is_true(&value)
    }) {
        ScanInvocationAuthority::ContinuousIntegration
    } else {
        ScanInvocationAuthority::ExplicitLocal
    }
}

/// Enforce that untracked content is admitted only by an explicit local CLI
/// request and never in a CI-classified process.
///
/// # Errors
///
/// Returns a CLI diagnostic when the request exceeds its authority.
pub fn validate_untracked_authority(
    args: &ScanCommandArgs,
    authority: ScanInvocationAuthority,
) -> Result<(), Diagnostic> {
    if args.include_untracked && authority != ScanInvocationAuthority::ExplicitLocal {
        return Err(
            cli_error("--include-untracked is available only for an explicit local scan")
                .with_remediation("remove --include-untracked when running in CI"),
        );
    }
    Ok(())
}

/// Capture a stable local snapshot and build the shared body-free scan plan.
///
/// Source bodies are retained only in memory for the future execution boundary.
/// Untracked paths are never enumerated into the scan input unless the caller
/// explicitly requested them and already passed the authority gate.
///
/// # Errors
///
/// Returns redaction-safe repository or contract diagnostics on unsafe paths,
/// unavailable history, excessive preparation input, snapshot races, or an
/// invalid core plan.
pub fn prepare_scan(
    args: &ScanCommandArgs,
    current_directory: &Path,
) -> Result<PreparedScan, Diagnostic> {
    let initial = capture_local_git(current_directory, None).map_err(|error| {
        repository_error(error.to_string()).with_remediation(
            "run inside a Git repository with an available default-branch history",
        )
    })?;
    let limits = ScanLimits::default();
    let inputs = capture_scan_inputs(&initial, args, limits)?;
    if !args.requested_paths.is_empty() && inputs.is_empty() {
        return Err(repository_error(
            "no admitted local scan file matches the requested path selectors",
        ));
    }
    let request = ScanRequestMetadata {
        snapshot: initial.identity.clone(),
        requested_paths: args.requested_paths.clone(),
        untracked_policy: if args.include_untracked {
            ScanUntrackedPolicy::IncludeExplicitLocal
        } else {
            ScanUntrackedPolicy::Exclude
        },
    };
    let plan = build_scan_plan(request, limits, inputs.clone())
        .map_err(|_| contract_error("local scan plan construction failed"))?;
    let final_capture = capture_local_git(&initial.root, Some(initial.identity.base_sha.as_str()))
        .map_err(|_| repository_error("local repository changed during scan preparation"))?;
    if initial.identity != final_capture.identity {
        return Err(repository_error(
            "local repository changed during scan preparation",
        ));
    }
    let mut repository_paths = BTreeSet::new();
    for input in &inputs {
        repository_paths.insert(
            RepositoryRelativePath::try_from(input.path.as_str().to_owned())
                .map_err(|_| repository_error("local repository contains an unsafe path"))?,
        );
    }
    let prepared = PreparedScan {
        root: initial.root,
        repository_paths,
        plan,
        inputs,
    };
    prepared.validate_replay()?;
    Ok(prepared)
}

/// Render provider-free preview output. SARIF is reserved for completed scan
/// findings and is therefore rejected here.
///
/// # Errors
///
/// Returns a contract diagnostic for replay failure, unsupported format, or
/// serialization failure.
pub fn render_preview(
    prepared: &PreparedScan,
    format: ScanOutputFormat,
) -> Result<Vec<u8>, Diagnostic> {
    prepared.validate_replay()?;
    match format {
        ScanOutputFormat::Human => Ok(render_human_preview(prepared.plan()).into_bytes()),
        ScanOutputFormat::Json => serde_json::to_vec_pretty(&ScanPreview {
            schema_version: "revoot.scan-preview/v1",
            state: "preview",
            provider_calls: 0,
            publication: "disabled",
            plan: prepared.plan(),
        })
        .map(|mut output| {
            output.push(b'\n');
            output
        })
        .map_err(|_| contract_error("scan preview serialization failed")),
        ScanOutputFormat::Sarif => Err(contract_error(
            "SARIF output requires completed scan findings",
        )),
    }
}

/// Run a provider-free preview or a bounded model-backed local scan.
///
/// # Errors
///
/// Returns redaction-safe CLI, repository, contract, or capability diagnostics.
pub fn run(
    args: impl IntoIterator<Item = String>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    current_directory: &Path,
) -> Result<i32, Diagnostic> {
    let parsed = parse_args(args)?;
    let ParsedScanCommand::Execute(args) = parsed else {
        print_help();
        return Ok(0);
    };
    let environment = environment.into_iter().collect::<Vec<_>>();
    let authority = classify_invocation_authority(environment.iter().cloned());
    validate_untracked_authority(&args, authority)?;
    let prepared = prepare_scan(&args, current_directory)?;
    if args.preview {
        let output = render_preview(&prepared, args.format)?;
        print!(
            "{}",
            String::from_utf8(output)
                .map_err(|_| contract_error("scan preview serialization was not UTF-8"))?
        );
        return Ok(0);
    }

    let base_sha = prepared.plan().request.snapshot.base_sha.clone();
    let resolved = resolve_review_configuration(
        current_directory,
        Some(&base_sha),
        None,
        environment.iter().cloned(),
    )?;
    let strategy = strategy_from_resolved(&resolved)
        .map_err(|_| contract_error("scan strategy configuration is invalid"))?;
    let configured_provider = config_string(&resolved, "review.provider")?;
    let configured_model = config_string(&resolved, "review.model")?;
    let credentials = discover_credentials(environment.iter().cloned())?;
    let provider = select_provider(configured_provider, &credentials)?;
    let model = select_model(&provider, configured_model)?;
    let adapter =
        Arc::<dyn revoot_core::ProviderAdapter>::from(build_provider(&provider, &credentials)?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| contract_error("failed to start the scan runtime"))?;
    let scan = runtime.block_on(execute_prepared_scan(
        prepared,
        &resolved,
        &strategy,
        adapter,
        model.clone(),
    ))?;
    let output = render_scan_output(&scan, &provider, &model, args.format)?;
    print!(
        "{}",
        String::from_utf8(output)
            .map_err(|_| contract_error("scan output serialization was not UTF-8"))?
    );
    Ok(0)
}

async fn execute_prepared_scan(
    prepared: PreparedScan,
    resolved: &ResolvedReviewConfiguration,
    strategy: &ReviewStrategyConfiguration,
    adapter: Arc<dyn revoot_core::ProviderAdapter>,
    model: String,
) -> Result<ScanEngineOutput, Diagnostic> {
    let frozen_root = prepared.root.clone();
    let frozen_snapshot = prepared.plan.request.snapshot.clone();
    let fresh = capture_local_git(&frozen_root, Some(frozen_snapshot.base_sha.as_str()))
        .map_err(|_| repository_error("local repository changed before scan execution"))?;
    if fresh.identity != frozen_snapshot {
        return Err(repository_error(
            "local repository changed before scan execution",
        ));
    }
    let minimum_confidence_percent =
        u8::try_from(config_unsigned(resolved, "review.minimum_confidence")?)
            .map_err(|_| contract_error("scan confidence configuration is invalid"))?;
    let max_findings = usize::try_from(config_unsigned(resolved, "budget.max_findings")?)
        .map_err(|_| contract_error("scan finding configuration is invalid"))?;
    let selection = selection_policy(&resolved.effective, &resolved.repository)?;
    let partition = partition_limits(&resolved.effective)?;
    let limits = tool_first_limits(&model, strategy, &resolved.effective)?;
    let (repository_root, repository_paths, plan, inputs) = prepared.into_execution_parts();
    let budget = ReviewBudgetBroker::new(strategy.aggregate_budget, 0)
        .map_err(|_| contract_error("scan aggregate budget is invalid"))?;
    let cancellation = CancellationToken::default();
    let output = run_scan_engine(ScanEngineRequest {
        provider: adapter,
        repository_root,
        repository_paths,
        model,
        plan,
        inputs,
        selection_policy: selection,
        partition_limits: partition,
        rule_policy: resolved.repository.clone(),
        limits,
        minimum_confidence_percent,
        max_findings,
        budget,
        cancellation,
        clock: Arc::new(ProcessClock::start()),
        system_policy_id: format!("{REVIEWER_POLICY_VERSION}.tool-first-scan"),
        system_policy: tool_first_reviewer_system_policy(),
    })
    .await
    .map_err(|_| Diagnostic::new(ErrorCode::ReviewFailed, "local scan execution failed"))?;
    let final_capture = capture_local_git(&frozen_root, Some(frozen_snapshot.base_sha.as_str()))
        .map_err(|_| repository_error("local repository changed during scan execution"))?;
    if final_capture.identity != frozen_snapshot {
        return Err(repository_error(
            "local repository changed during scan execution",
        ));
    }
    Ok(output)
}

fn render_scan_output(
    scan: &ScanEngineOutput,
    provider: &str,
    model: &str,
    format: ScanOutputFormat,
) -> Result<Vec<u8>, Diagnostic> {
    match format {
        ScanOutputFormat::Human => {
            let mut output = scan.human();
            for finding in &scan.findings {
                if let Some(anchor) = scan.anchors.resolve(finding.anchor_id.as_str()) {
                    use std::fmt::Write as _;
                    let line = match anchor.position {
                        revoot_core::AnchorPosition::Addition { new_line }
                        | revoot_core::AnchorPosition::Context { new_line, .. } => new_line,
                        revoot_core::AnchorPosition::Deletion { old_line } => old_line,
                    };
                    let _ = writeln!(
                        output,
                        "{}:{}: {}",
                        anchor.path.new_path.as_str(),
                        line,
                        finding.rendered_body
                    );
                }
            }
            Ok(output.into_bytes())
        }
        ScanOutputFormat::Json => serde_json::to_vec_pretty(&ScanOutput {
            schema_version: ScanEngineOutput::SCHEMA_VERSION,
            provider,
            model,
            publication: "disabled",
            scan,
        })
        .map(|mut output| {
            output.push(b'\n');
            output
        })
        .map_err(|_| contract_error("scan JSON serialization failed")),
        ScanOutputFormat::Sarif => render_sarif(
            &scan.findings,
            &scan.anchors,
            SarifRunMetadata {
                partial: scan.status != ScanEngineStatus::Complete,
                coverage: SarifCoverageMetadata {
                    selected_files: scan.coverage.selected_files,
                    fully_read_files: scan.coverage.fully_read_files,
                    sampled_files: scan.coverage.sampled_files,
                    manifest_only_files: scan.coverage.manifest_only_files,
                    delivered_high_risk_hunks: scan.coverage.delivered_high_risk_hunks,
                    required_high_risk_hunks: scan.coverage.required_high_risk_hunks,
                    explicit_deferrals: scan
                        .coverage
                        .explicit_deferrals
                        .saturating_add(scan.coverage.omitted_files),
                    failed_groups: scan.coverage.failed_groups,
                    policy_version: scan.coverage.policy_version.to_owned(),
                },
            },
        )
        .and_then(|sarif| sarif.canonical_json())
        .map(|mut output| {
            output.push(b'\n');
            output
        })
        .map_err(|_| contract_error("scan SARIF serialization failed")),
    }
}

fn config_string<'a>(
    resolved: &'a ResolvedReviewConfiguration,
    key: &str,
) -> Result<&'a str, Diagnostic> {
    match resolved.effective.effective().get(key) {
        Some(ConfigValue::String(value)) => Ok(value),
        _ => Err(contract_error("effective scan configuration is invalid")),
    }
}

fn config_unsigned(resolved: &ResolvedReviewConfiguration, key: &str) -> Result<u64, Diagnostic> {
    match resolved.effective.effective().get(key) {
        Some(ConfigValue::Unsigned(value)) => Ok(*value),
        _ => Err(contract_error("effective scan configuration is invalid")),
    }
}

fn capture_scan_inputs(
    capture: &LocalGitCapture,
    args: &ScanCommandArgs,
    limits: ScanLimits,
) -> Result<Vec<ScanFileInput>, Diagnostic> {
    let tracked = tracked_paths(&capture.root)?;
    let candidates = if args.include_untracked {
        capture.repository_paths().clone()
    } else {
        tracked.clone()
    };
    let mut retained_bytes = 0_u64;
    let mut inputs = Vec::new();
    for path in candidates {
        let repository_path = RepositoryPath::try_from(path.as_str().to_owned())
            .map_err(|_| repository_error("local repository contains an unsafe path"))?;
        if !path_requested(&repository_path, &args.requested_paths) {
            continue;
        }
        let tracking = if tracked.contains(&path) {
            ScanFileTracking::Tracked
        } else {
            ScanFileTracking::Untracked
        };
        let content = read_scan_source(
            &capture.root,
            &path,
            limits.max_file_bytes,
            &mut retained_bytes,
        )?;
        inputs.push(ScanFileInput {
            path: repository_path,
            tracking,
            content,
        });
    }
    Ok(inputs)
}

fn tracked_paths(root: &Path) -> Result<BTreeSet<RepositoryRelativePath>, Diagnostic> {
    let repository = gix::discover_opts(
        root,
        gix::discover::upwards::Options::default(),
        gix::open::Options::isolated()
            .bail_if_untrusted(true)
            .strict_config(true),
    )
    .map_err(|_| repository_error("local Git index is unavailable"))?;
    let index = repository
        .index_or_empty()
        .map_err(|_| repository_error("local Git index is unavailable"))?;
    let worktree = repository
        .workdir()
        .ok_or_else(|| repository_error("local Git worktree is unavailable"))?;
    let mut paths = BTreeSet::new();
    for entry in index.entries() {
        if entry.stage() != gix::index::entry::Stage::Unconflicted {
            return Err(repository_error(
                "local repository contains unresolved conflicts",
            ));
        }
        let value = entry
            .path(&index)
            .to_str()
            .map_err(|_| repository_error("local repository contains an unsafe path"))?;
        let path = RepositoryRelativePath::try_from(value.to_owned())
            .map_err(|_| repository_error("local repository contains an unsafe path"))?;
        if worktree.join(path.as_str()).is_file() {
            paths.insert(path);
        }
    }
    Ok(paths)
}

fn read_scan_source(
    root: &Path,
    path: &RepositoryRelativePath,
    file_limit: u64,
    retained_bytes: &mut u64,
) -> Result<String, Diagnostic> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(path.as_str()))
        .map_err(|_| repository_error("a local scan file is unavailable or unsafe"))?;
    let metadata = file
        .metadata()
        .map_err(|_| repository_error("local scan file metadata is unavailable"))?;
    if !metadata.is_file() {
        return Err(repository_error("a local scan path is not a regular file"));
    }

    let read_limit = file_limit
        .checked_add(1)
        .ok_or_else(|| contract_error("scan file byte bound overflowed"))?;
    let allocation = metadata.len().min(read_limit);
    *retained_bytes = retained_bytes
        .checked_add(allocation)
        .ok_or_else(|| contract_error("scan preparation byte accounting overflowed"))?;
    if *retained_bytes > MAX_PREPARATION_BODY_BYTES {
        return Err(
            repository_error("local scan preparation exceeds its in-memory byte bound")
                .with_remediation("narrow the scan with one or more --path options"),
        );
    }
    if metadata.len() > file_limit {
        let size = usize::try_from(read_limit)
            .map_err(|_| contract_error("scan file byte bound is unsupported"))?;
        return Ok(" ".repeat(size));
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| contract_error("scan file size is unsupported"))?,
    );
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| repository_error("a local scan file could not be read"))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(repository_error(
            "local repository changed during scan preparation",
        ));
    }
    if bytes.contains(&0) {
        return Ok("\0".to_owned());
    }
    String::from_utf8(bytes).or_else(|_| Ok("\0".to_owned()))
}

fn path_requested(path: &RepositoryPath, requested: &[RepositoryPath]) -> bool {
    requested.is_empty()
        || requested.iter().any(|candidate| {
            path == candidate
                || path
                    .as_str()
                    .strip_prefix(candidate.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn render_human_preview(plan: &ScanPlan) -> String {
    format!(
        "Revoot scan preview\nPlan: {}\nFiles: {} included, {} omitted, {} input\nCoverage: {} bytes in {} chunk(s), {}\nUntracked input: {}\nProvider calls: 0\nPublication: disabled\n",
        plan.plan_sha256.as_str(),
        plan.coverage.included_files,
        plan.coverage.omitted_files,
        plan.coverage.input_files,
        plan.coverage.included_bytes,
        plan.coverage.chunks,
        if plan.coverage.complete {
            "complete"
        } else {
            "partial"
        },
        match plan.request.untracked_policy {
            ScanUntrackedPolicy::Exclude => "excluded",
            ScanUntrackedPolicy::IncludeExplicitLocal => "explicitly included",
        },
    )
}

fn environment_value_is_true(value: &OsStr) -> bool {
    value.to_str().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn cli_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::CliInvalidArgument, message)
}

fn contract_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::ContractInvalid, message)
}

fn repository_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(ErrorCode::RepositoryUnavailable, message)
}

fn print_help() {
    println!(
        "USAGE:\n  revoot scan [--path PATH]... [--include-untracked] [--preview] [--format human|json|sarif]"
    );
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use revoot_core::{
        ModelContent, ModelFinishReason, ModelRequest, ModelResponse, ModelUsage, ProviderAdapter,
        ProviderError, ProviderFuture,
    };
    use serde_json::Value;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn parser_accepts_and_sorts_the_complete_surface() {
        let parsed = parse_args([
            "--path".to_owned(),
            "src/z.rs".to_owned(),
            "--include-untracked".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--preview".to_owned(),
            "--path".to_owned(),
            "src/a.rs".to_owned(),
        ])
        .expect("arguments");
        let ParsedScanCommand::Execute(parsed) = parsed else {
            panic!("execute")
        };
        assert_eq!(
            parsed
                .requested_paths
                .iter()
                .map(RepositoryPath::as_str)
                .collect::<Vec<_>>(),
            ["src/a.rs", "src/z.rs"]
        );
        assert!(parsed.include_untracked);
        assert!(parsed.preview);
        assert_eq!(parsed.format, ScanOutputFormat::Json);
    }

    #[test]
    fn parser_rejects_ambiguous_or_unsupported_forms() {
        for arguments in [
            vec!["--path"],
            vec!["--path", "--preview"],
            vec!["--preview", "--preview"],
            vec!["--include-untracked", "--include-untracked"],
            vec!["--format", "json", "--format", "human"],
            vec!["--path", "src", "--path", "src"],
            vec!["--preview", "--format", "sarif"],
            vec!["src/lib.rs"],
            vec!["--help", "--preview"],
        ] {
            let debug = format!("{arguments:?}");
            assert!(
                parse_args(arguments.into_iter().map(str::to_owned)).is_err(),
                "{debug}"
            );
        }
        assert_eq!(
            parse_args(["--help".to_owned()]).expect("help"),
            ParsedScanCommand::Help
        );
    }

    #[test]
    fn untracked_authority_is_local_and_explicit() {
        let args = ScanCommandArgs {
            include_untracked: true,
            ..ScanCommandArgs::default()
        };
        assert!(
            validate_untracked_authority(&args, ScanInvocationAuthority::ExplicitLocal).is_ok()
        );
        assert!(
            validate_untracked_authority(&args, ScanInvocationAuthority::ContinuousIntegration)
                .is_err()
        );
        assert_eq!(
            classify_invocation_authority([(OsString::from("CI"), OsString::from("true"))]),
            ScanInvocationAuthority::ContinuousIntegration
        );
        assert_eq!(
            classify_invocation_authority([(OsString::from("CI"), OsString::from("false"))]),
            ScanInvocationAuthority::ExplicitLocal
        );
    }

    #[test]
    fn preparation_builds_replayable_body_free_preview() {
        let fixture = repository_fixture();
        write(
            &fixture,
            "src/untracked.rs",
            "const SECRET_BODY: &str = \"hidden\";\n",
        );
        let args = ScanCommandArgs {
            requested_paths: vec![RepositoryPath::try_from("src".to_owned()).expect("path")],
            include_untracked: true,
            preview: true,
            format: ScanOutputFormat::Json,
        };
        let prepared = prepare_scan(&args, fixture.path()).expect("prepared scan");
        prepared.validate_replay().expect("replay");
        assert_eq!(prepared.plan().coverage.included_files, 2);
        assert_eq!(
            prepared
                .plan()
                .files
                .iter()
                .map(|file| file.tracking)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([ScanFileTracking::Tracked, ScanFileTracking::Untracked])
        );
        let json = String::from_utf8(
            render_preview(&prepared, ScanOutputFormat::Json).expect("JSON preview"),
        )
        .expect("UTF-8");
        assert!(!json.contains("SECRET_BODY"));
        let value: Value = serde_json::from_str(&json).expect("preview JSON");
        assert_eq!(value["schema_version"], "revoot.scan-preview/v1");
        assert_eq!(value["state"], "preview");
        assert_eq!(value["provider_calls"], 0);
        assert_eq!(value["publication"], "disabled");
        let (_root, repository_paths, plan, inputs) = prepared.into_execution_parts();
        assert_eq!(repository_paths.len(), 2);
        assert_eq!(plan.coverage.input_files, 2);
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn untracked_files_are_not_prepared_without_the_flag() {
        let fixture = repository_fixture();
        write(&fixture, "untracked.txt", "not admitted\n");
        let args = ScanCommandArgs {
            preview: true,
            ..ScanCommandArgs::default()
        };
        let prepared = prepare_scan(&args, fixture.path()).expect("prepared scan");
        assert_eq!(prepared.plan().coverage.input_files, 1);
        assert!(
            prepared
                .plan()
                .files
                .iter()
                .all(|file| file.tracking == ScanFileTracking::Tracked)
        );
        let (_root, repository_paths, _plan, _inputs) = prepared.into_execution_parts();
        assert_eq!(
            repository_paths,
            BTreeSet::from([
                RepositoryRelativePath::try_from("src/lib.rs".to_owned()).expect("path")
            ])
        );
    }

    #[test]
    fn explicit_path_without_an_admitted_match_is_rejected() {
        let fixture = repository_fixture();
        let error = prepare_scan(
            &ScanCommandArgs {
                requested_paths: vec![
                    RepositoryPath::try_from("missing".to_owned()).expect("path"),
                ],
                ..ScanCommandArgs::default()
            },
            fixture.path(),
        )
        .expect_err("empty explicit selection");
        assert_eq!(error.code, ErrorCode::RepositoryUnavailable);
    }

    #[test]
    fn preview_run_needs_no_provider_credentials() {
        let fixture = repository_fixture();
        let exit = run(
            [
                "--preview".to_owned(),
                "--format".to_owned(),
                "json".to_owned(),
            ],
            Vec::<(OsString, OsString)>::new(),
            fixture.path(),
        )
        .expect("preview remains provider-free");
        assert_eq!(exit, 0);
    }

    #[test]
    fn non_preview_discovers_direct_provider_credentials() {
        let fixture = repository_fixture();
        let error = run(
            Vec::<String>::new(),
            Vec::<(OsString, OsString)>::new(),
            fixture.path(),
        )
        .expect_err("model-backed scan requires a direct credential");
        assert_eq!(error.code, ErrorCode::ProviderUnavailable);
    }

    struct FakeProvider {
        requests: Mutex<Vec<ModelRequest>>,
        calls: AtomicUsize,
        mutate_path: Option<PathBuf>,
    }

    impl ProviderAdapter for FakeProvider {
        fn adapter_id(&self) -> &'static str {
            "fake"
        }

        fn complete<'a>(
            &'a self,
            request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            if let Some(path) = &self.mutate_path {
                fs::write(path, "changed during scan\n").expect("mutate scan fixture");
            }
            let request_index = {
                let mut requests = self.requests.lock().expect("requests");
                requests.push(request.clone());
                requests.len()
            };
            let call_index = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            let packet = request
                .messages
                .iter()
                .flat_map(|message| &message.content)
                .find_map(|content| match content {
                    ModelContent::Text { text } => serde_json::from_str::<Value>(text).ok(),
                    ModelContent::ToolUse { .. } | ModelContent::ToolResult { .. } => None,
                });
            let response = if call_index == 1 {
                packet.map(|packet| ModelResponse {
                    provider_response_id: None,
                    model: "fake-model".to_owned(),
                    content: vec![ModelContent::ToolUse {
                        id: format!("read-{request_index}"),
                        name: "read_diff".to_owned(),
                        input: serde_json::json!({"reads":[{
                            "path": packet["files"][0]["path"].clone(),
                            "hunk_id": packet["files"][0]["hunk_ids"][0].clone(),
                            "page": 1
                        }]}),
                    }],
                    finish_reason: ModelFinishReason::ToolUse,
                    usage: ModelUsage::default(),
                })
            } else if call_index == 2 {
                Some(ModelResponse {
                    provider_response_id: None,
                    model: "fake-model".to_owned(),
                    content: vec![ModelContent::ToolUse {
                        id: format!("checkpoint-{request_index}"),
                        name: "checkpoint_review".to_owned(),
                        input: serde_json::json!({
                            "checkpoint": {
                                "hypotheses": [],
                                "evidence_references": [],
                                "unresolved_coverage": []
                            }
                        }),
                    }],
                    finish_reason: ModelFinishReason::ToolUse,
                    usage: ModelUsage::default(),
                })
            } else {
                Some(ModelResponse {
                    provider_response_id: None,
                    model: "fake-model".to_owned(),
                    content: vec![ModelContent::ToolUse {
                        id: format!("complete-{request_index}"),
                        name: "complete_group".to_owned(),
                        input: serde_json::json!({
                            "checkpoint": {
                                "hypotheses": [],
                                "evidence_references": [],
                                "unresolved_coverage": []
                            },
                            "summary": {"text":"reviewed","assumptions":[]}
                        }),
                    }],
                    finish_reason: ModelFinishReason::ToolUse,
                    usage: ModelUsage::default(),
                })
            };
            Box::pin(async move {
                response.ok_or_else(|| {
                    ProviderError::new(revoot_core::DirectProviderErrorKind::Protocol, None, false)
                })
            })
        }
    }

    #[tokio::test]
    async fn prepared_scan_crosses_the_fake_provider_boundary_body_free() {
        let fixture = repository_fixture();
        let args = ScanCommandArgs::default();
        let prepared = prepare_scan(&args, fixture.path()).expect("prepared scan");
        let base_sha = prepared.plan().request.snapshot.base_sha.clone();
        let resolved = resolve_review_configuration(
            fixture.path(),
            Some(&base_sha),
            None,
            Vec::<(OsString, OsString)>::new(),
        )
        .expect("configuration");
        let strategy = strategy_from_resolved(&resolved).expect("strategy");
        let provider = Arc::new(FakeProvider {
            requests: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            mutate_path: None,
        });
        let output = execute_prepared_scan(
            prepared,
            &resolved,
            &strategy,
            Arc::clone(&provider) as Arc<dyn ProviderAdapter>,
            "fake-model".to_owned(),
        )
        .await
        .expect("scan execution");
        let requests = provider.requests.lock().expect("requests");
        assert_eq!(output.status, ScanEngineStatus::Complete);
        assert!(requests.len() >= 2);
        let initial = serde_json::to_string(&requests[0]).expect("initial request");
        assert!(!initial.contains("pub fn answer"));
    }

    #[tokio::test]
    async fn completed_model_work_is_rejected_when_the_snapshot_changes() {
        let fixture = repository_fixture();
        let prepared =
            prepare_scan(&ScanCommandArgs::default(), fixture.path()).expect("prepared scan");
        let base_sha = prepared.plan().request.snapshot.base_sha.clone();
        let resolved = resolve_review_configuration(
            fixture.path(),
            Some(&base_sha),
            None,
            Vec::<(OsString, OsString)>::new(),
        )
        .expect("configuration");
        let strategy = strategy_from_resolved(&resolved).expect("strategy");
        let provider = Arc::new(FakeProvider {
            requests: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            mutate_path: Some(fixture.path().join("src/lib.rs")),
        });
        let error = execute_prepared_scan(
            prepared,
            &resolved,
            &strategy,
            provider as Arc<dyn ProviderAdapter>,
            "fake-model".to_owned(),
        )
        .await
        .expect_err("stale completed scan");
        assert_eq!(error.code, ErrorCode::RepositoryUnavailable);
    }

    fn repository_fixture() -> TempDir {
        let fixture = tempfile::tempdir().expect("temporary repository");
        command(fixture.path(), &["init", "-b", "main"]);
        command(
            fixture.path(),
            &["config", "user.email", "scan@example.test"],
        );
        command(fixture.path(), &["config", "user.name", "Scan Test"]);
        write(&fixture, "src/lib.rs", "pub fn answer() -> u8 { 42 }\n");
        command(fixture.path(), &["add", "src/lib.rs"]);
        command(fixture.path(), &["commit", "-m", "initial"]);
        fixture
    }

    fn write(fixture: &TempDir, path: &str, content: &str) {
        let path = fixture.path().join(path);
        fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        fs::write(path, content).expect("fixture file");
    }

    fn command(root: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("git fixture command");
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
