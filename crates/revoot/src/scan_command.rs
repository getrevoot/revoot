//! Provider-free CLI preparation for bounded local source scans.
//!
//! This module parses scan arguments, captures an immutable local repository
//! state, and constructs the shared body-free scan plan. Model execution and
//! result publication are intentionally outside this slice.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use gix::bstr::ByteSlice;
use revoot_core::{
    Diagnostic, ErrorCode, RepositoryPath, RepositoryRelativePath, ScanFileInput, ScanFileTracking,
    ScanLimits, ScanPlan, ScanRequestMetadata, ScanUntrackedPolicy, build_scan_plan,
};
use serde::Serialize;

use crate::local_review::{LocalGitCapture, capture_local_git};

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
    plan: ScanPlan,
    inputs: Vec<ScanFileInput>,
}

impl std::fmt::Debug for PreparedScan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedScan")
            .field("plan_sha256", &self.plan.plan_sha256)
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

    /// Hand the immutable plan and retained bodies to the future model-backed
    /// scan engine. This module does not execute them.
    #[must_use]
    pub fn into_execution_parts(self) -> (ScanPlan, Vec<ScanFileInput>) {
        (self.plan, self.inputs)
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
    let prepared = PreparedScan { plan, inputs };
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

/// Run the currently available scan command slice.
///
/// Preview is complete and provider-free. Non-preview execution fails clearly
/// at the unwired model-engine boundary and never claims findings or publishes.
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
    let authority = classify_invocation_authority(environment);
    validate_untracked_authority(&args, authority)?;
    if !args.preview {
        return Err(Diagnostic::new(
            ErrorCode::CapabilityUnavailable,
            "model-backed scan execution is not wired yet",
        )
        .with_remediation("use --preview to inspect the immutable local scan plan"));
    }
    let prepared = prepare_scan(&args, current_directory)?;
    let output = render_preview(&prepared, args.format)?;
    print!(
        "{}",
        String::from_utf8(output)
            .map_err(|_| contract_error("scan preview serialization was not UTF-8"))?
    );
    Ok(0)
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
        let (plan, inputs) = prepared.into_execution_parts();
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
    }

    #[test]
    fn non_preview_stops_at_the_execution_boundary() {
        let error = run(
            Vec::<String>::new(),
            Vec::<(OsString, OsString)>::new(),
            Path::new("."),
        )
        .expect_err("execution is not wired");
        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert!(error.message.contains("not wired"));
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
