//! Production composition for the single `revoot review` operation.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use revoot_core::provider::ProviderAdapter;
use revoot_core::{
    AgentBudgetLimits, AgentBudgetUsage, AgentOmission, AgentOmissionReason, AnchorId, AnchorTable,
    CancellationToken, CertificateAuthorityMode, ConfigValue, Diagnostic, ErrorCode,
    GitLabOriginPolicy, GitLabProjectIdentity, GitLabVerificationInput, GitLabWireLimits, GitSha,
    IpCidr, IssuedWorkUnitAnchors, MergeRequestIid, PartitionLimits, PublicationCandidate,
    PublicationTarget, PullRequestNumber, RankedFinding, RepositoryPath, RepositoryToolLimits,
    ReviewBudgetBroker, ReviewGroupingSource, ReviewOmissionReason, ReviewOutcome,
    ReviewPartitionPlan, ReviewPreview, ReviewPreviewGroupInput, ReviewPreviewRule,
    ReviewPreviewRuleSource, ReviewPreviewStrategy, ReviewReportCoverage, ReviewReportOverview,
    ReviewReportPhase, ReviewReportPhaseUsage, ReviewReportPublication, ReviewReportSelection,
    ReviewReportState, ReviewReportStrategy, ReviewReportUsage, ReviewReportUsageTotals,
    ReviewReportV3, ReviewSelectionPolicy, ReviewSnapshotIdentity, ReviewValueTier, Severity,
    Sha256Digest, SnapshotReadiness, UnifiedDiffLimits, build_review_group_plan,
    build_review_preview, classify_gitlab_ci_environment, parse_project_response,
    validate_rank_and_render,
};
use rustls::pki_types::pem::{PemObject, SectionKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{
    RepositoryReviewPolicy, ResolvedReviewConfiguration, resolve_review_configuration,
};
use crate::credentials::DiscoveredCredentials;
use crate::egress_setup::authorize_configured_provider;
use crate::git_history::GitHistoryToolbox;
use crate::github_checkout::{
    DiscoveredGitHubRepository, GitHubCiContext, GitHubRepositorySlug, GitHubServer,
    classify_github_actions, discover_github_actions_repository, discover_github_repository,
};
use crate::github_review::{
    GitHubReviewContext, GitHubReviewContextOptions, GitHubReviewError,
    acquire_github_review_context, publish_github_findings, update_github_overview,
};
use crate::github_transport::{
    GitHubCaMode, GitHubClient, GitHubCustomCaBundle, load_github_token,
};
use crate::gitlab_checkout::{
    DiscoveredGitRepository, ExplicitGitLabMergeRequest, bind_checkout_to_snapshot,
    discover_gitlab_repository, select_gitlab_merge_request,
};
use crate::gitlab_ci_runtime::{
    GitLabCheckoutBinding, GitLabCredentialSource, GitLabExecutionMode, GitLabForkBehavior,
    GitLabProviderReadiness, GitLabPublicationPreference, GitLabReadinessInput,
    GitLabTargetPipelineTrust, diagnose_gitlab_readiness, load_gitlab_credentials,
    probe_gitlab_user,
};
use crate::gitlab_publication::{
    GitLabPublicationController, GitLabPublicationLimits, GitLabPublicationOutcome,
};
use crate::gitlab_review_context::{
    GitLabReviewContext, GitLabReviewContextOptions, build_gitlab_review_context,
};
use crate::gitlab_snapshot::{
    AcquiredGitLabSnapshot, GitLabSnapshotAcquisitionLimits, GitLabSnapshotAcquisitionOutcome,
    GitLabSnapshotController,
};
use crate::gitlab_transport::{
    GitLabCaMode, GitLabCustomCaBundle, GitLabReadClient, GitLabReadEndpoint,
    GitLabTransportConfig, GitLabTransportLimits, GitLabWriteClient,
};
use crate::group_worker_engine::{GroupWorkerClock, GroupWorkerLimits};
use crate::local_review::{
    LocalReviewContext, LocalReviewContextOptions, build_local_review_context, capture_local_git,
    local_snapshot_is_fresh,
};
use crate::prior_review::{acquire_github_prior_review, acquire_gitlab_prior_review};
use crate::review_adjudicator::ReviewAdjudicatorClock;
use crate::review_checkpoint::{
    ReviewAttention, ReviewCheckpoint, extract_checkpoint, plan_attention,
};
use crate::review_contracts::{
    PriorFindingDisposition, PriorFindingDispositionKind, ReviewCoverage, ReviewStrategy,
};
use crate::review_grouper::ReviewGrouperClock;
use crate::review_overview::{
    ReviewOverview, ReviewRunMetadata, RiskLevel, render_review_overview,
};
use crate::review_sarif::render_report_v3_sarif;
use crate::review_strategy_config::{
    ReviewStrategyConfiguration, escalate_effort_for_large_diff, strategy_from_resolved,
};
use crate::review_verifier::ReviewVerifierClock;
use crate::reviewer_policy::{REVIEWER_POLICY_VERSION, tool_first_reviewer_system_policy};
use crate::rule_diagnostics::{
    RepositoryRuleMetadata, RuleDiagnosticPolicy, RulePrecedenceSource, diagnose_rules,
};
use crate::tool_first_engine::{
    ToolFirstEngineLimits, ToolFirstEngineReport, ToolFirstEngineRequest, run_tool_first_engine,
};
use crate::tool_first_report::{ToolFirstReportInput, build_tool_first_report};

const TERMINAL_REPORT_SCHEMA_VERSION: &str = "revoot.review-terminal/v1";
const MAX_CODE_HOST_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
const DEFERRED_PROVIDER: &str = "deferred";
const DEFERRED_MODEL: &str = "deferred";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum OutputFormat {
    #[default]
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Default)]
struct ReviewArgs {
    ci: bool,
    preview: bool,
    effort: Option<revoot_core::ReviewEffort>,
    max_parallel_groups: Option<u8>,
    format: OutputFormat,
    output: Option<PathBuf>,
    base_ref: Option<String>,
    merge_request_iid: Option<MergeRequestIid>,
    pull_request_number: Option<PullRequestNumber>,
    github_repository: Option<GitHubRepositorySlug>,
}

#[derive(Serialize)]
struct ReviewOutput<'a> {
    schema_version: &'static str,
    provider: &'a str,
    model: &'a str,
    review: &'a CanonicalReviewReport,
}

enum ReviewCommandResult {
    Review {
        provider: String,
        model: String,
        report: Box<CanonicalReviewReport>,
    },
    Preview(Box<ReviewPreview>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CanonicalReviewReport {
    #[serde(skip)]
    stable_report: Option<ReviewReportV3>,
    #[serde(skip)]
    sarif_anchors: Option<AnchorTable>,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    overview: Option<ReviewOverview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    findings: Vec<RankedFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    omissions: Vec<AgentOmission>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    prior_finding_dispositions: Vec<PriorFindingDisposition>,
    duplicates_omitted: u32,
    usage: AgentBudgetUsage,
    turns: u32,
    tool_calls: u32,
    admitted_candidates: u32,
    suppressed_candidates: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<ReviewStrategy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coverage: Option<ReviewCoverage>,
    selection: CanonicalSelection,
    publication: CanonicalPublication,
    #[serde(skip)]
    finding_locations: BTreeMap<AnchorId, String>,
}

impl CanonicalReviewReport {
    /// Authorize only explicitly fixed lineages from a complete review.
    /// Partial or failed work may still publish new findings, but must preserve
    /// every previous lineage.
    fn authorized_fixed_lineages(&self) -> BTreeSet<revoot_core::Sha256Digest> {
        if !matches!(self.state, "complete" | "no_findings")
            || !self.omissions.is_empty()
            || self.selection.omitted_files != 0
        {
            return BTreeSet::new();
        }
        self.prior_finding_dispositions
            .iter()
            .filter(|item| item.disposition == PriorFindingDispositionKind::Fixed)
            .map(|item| item.lineage_id.clone())
            .collect()
    }

    fn checkpoint_complete(&self) -> bool {
        matches!(self.state, "complete" | "no_findings")
            && self.omissions.is_empty()
            && self.selection.omitted_files == 0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
struct CanonicalSelection {
    changed_files: u32,
    selected_files: u32,
    omitted_files: u32,
    selected_high_signal_files: u32,
    selected_standard_signal_files: u32,
    selected_low_signal_files: u32,
    low_signal_deferred_files: u32,
    selected_diff_bytes: u64,
}

impl CanonicalSelection {
    fn from_partition(partition: &ReviewPartitionPlan) -> Self {
        let mut selection = Self {
            changed_files: partition.coverage.input_files,
            selected_files: partition.coverage.included_files,
            omitted_files: partition.coverage.omitted_files,
            selected_diff_bytes: partition.coverage.included_bytes,
            low_signal_deferred_files: partition
                .omitted
                .iter()
                .filter(|file| file.reason == ReviewOmissionReason::LowSignalBudget)
                .count()
                .try_into()
                .unwrap_or(u32::MAX),
            ..Self::default()
        };
        for file in partition
            .work_units
            .iter()
            .flat_map(|unit| unit.files.iter())
        {
            let counter = match file.review_value.tier {
                ReviewValueTier::High => &mut selection.selected_high_signal_files,
                ReviewValueTier::Standard => &mut selection.selected_standard_signal_files,
                ReviewValueTier::Low => &mut selection.selected_low_signal_files,
            };
            *counter = counter.saturating_add(1);
        }
        selection
    }
}

impl CanonicalReviewReport {
    fn human_summary(&self) -> String {
        use std::fmt::Write as _;

        let mut output = format!(
            "Revoot review {}: {} finding(s), {}/{} changed file(s) selected ({} low-signal deferred), {} turn(s), {} tool call(s), publication {}",
            self.state,
            self.findings.len(),
            self.selection.selected_files,
            self.selection.changed_files,
            self.selection.low_signal_deferred_files,
            self.turns,
            self.tool_calls,
            self.publication.state,
        );
        for finding in &self.findings {
            let location = self
                .finding_locations
                .get(&finding.anchor_id)
                .map_or("unknown location", String::as_str);
            let _ = write!(output, "\n\n{location}\n{}", finding.rendered_body);
        }
        output
    }

    fn publication_failed(&self) -> bool {
        self.publication.failed()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CanonicalPublication {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    actions_confirmed: u32,
    published_findings: u32,
    mutation_attempts: u32,
    resolved_discussions: u32,
}

impl CanonicalPublication {
    fn failed(&self) -> bool {
        matches!(self.state, "failed" | "unavailable")
    }

    const fn pending() -> Self {
        Self {
            state: "pending",
            reason: None,
            actions_confirmed: 0,
            published_findings: 0,
            mutation_attempts: 0,
            resolved_discussions: 0,
        }
    }

    const fn terminal(state: &'static str, reason: Option<&'static str>) -> Self {
        Self {
            state,
            reason,
            actions_confirmed: 0,
            published_findings: 0,
            mutation_attempts: 0,
            resolved_discussions: 0,
        }
    }
}

struct PreparedGitLabReview {
    context: GitLabReviewContext,
    snapshot: AcquiredGitLabSnapshot,
    read: GitLabReadClient,
    write: Option<GitLabWriteClient>,
    ci: revoot_core::GitLabCiContext,
    credential_source: GitLabCredentialSource,
    publication_preference: GitLabPublicationPreference,
    fork_behavior: GitLabForkBehavior,
    prior_review: revoot_core::PriorReviewContext,
    checkpoint: Option<ReviewCheckpoint>,
}

struct PreparedGitHubReview {
    context: GitHubReviewContext,
    client: GitHubClient,
    publication_enabled: bool,
    fork: bool,
    prior_review: revoot_core::PriorReviewContext,
    checkpoint: Option<ReviewCheckpoint>,
}

struct PreparedLocalReview {
    context: LocalReviewContext,
}

struct ExplicitGitHubPullRequest {
    number: Option<PullRequestNumber>,
    repository: Option<GitHubRepositorySlug>,
}

enum PreparedReview {
    GitLab(Box<PreparedGitLabReview>),
    GitHub(Box<PreparedGitHubReview>),
    Local(Box<PreparedLocalReview>),
}

impl PreparedReview {
    fn prior_review(&self) -> revoot_core::PriorReviewContext {
        match self {
            Self::GitLab(prepared) => prepared.prior_review.clone(),
            Self::GitHub(prepared) => prepared.prior_review.clone(),
            Self::Local(_) => revoot_core::PriorReviewContext::default(),
        }
    }

    fn prior_checkpoint(&self) -> Option<&ReviewCheckpoint> {
        match self {
            Self::GitLab(prepared) => prepared.checkpoint.as_ref(),
            Self::GitHub(prepared) => prepared.checkpoint.as_ref(),
            Self::Local(_) => None,
        }
    }

    fn root(&self) -> &Path {
        match self {
            Self::GitLab(prepared) => &prepared.context.checkout.repository.root,
            Self::GitHub(prepared) => &prepared.context.repository.root,
            Self::Local(prepared) => &prepared.context.root,
        }
    }

    fn partition(&self) -> &ReviewPartitionPlan {
        match self {
            Self::GitLab(prepared) => &prepared.context.partition,
            Self::GitHub(prepared) => &prepared.context.partition,
            Self::Local(prepared) => &prepared.context.partition,
        }
    }

    fn bind_provider_model(&mut self, provider: &str, model: &str) -> Result<(), Diagnostic> {
        let invocation = match self {
            Self::GitLab(prepared) => prepared.context.invocation.as_mut(),
            Self::GitHub(prepared) => prepared.context.invocation.as_mut(),
            Self::Local(prepared) => prepared.context.invocation.as_mut(),
        }
        .ok_or_else(|| {
            diagnostic(
                ErrorCode::ContractInvalid,
                "reviewable partition has no invocation",
            )
        })?;
        provider.clone_into(&mut invocation.provider_adapter);
        model.clone_into(&mut invocation.model_id);
        invocation.validate().map_err(|_| {
            diagnostic(
                ErrorCode::ContractInvalid,
                "selected provider or model is invalid",
            )
        })
    }

    fn base_sha(&self) -> &GitSha {
        match &self.partition().snapshot {
            ReviewSnapshotIdentity::GitLab(identity) => {
                &identity.version.diff_version.refs.base_sha
            }
            ReviewSnapshotIdentity::GitHub(identity) => &identity.base_sha,
            ReviewSnapshotIdentity::Local(identity) => &identity.base_sha,
        }
    }

    fn head_sha(&self) -> &GitSha {
        match &self.partition().snapshot {
            ReviewSnapshotIdentity::GitLab(identity) => {
                &identity.version.diff_version.refs.head_sha
            }
            ReviewSnapshotIdentity::GitHub(identity) => &identity.head_sha,
            ReviewSnapshotIdentity::Local(identity) => &identity.head_sha,
        }
    }

    fn commit_url(&self) -> Option<String> {
        match self {
            Self::GitLab(prepared) => {
                let repository = &prepared.context.checkout.repository;
                Some(format!(
                    "{}/{}/-/commit/{}",
                    repository.remote.origin.as_str(),
                    repository.remote.project_path.as_str(),
                    self.head_sha().as_str()
                ))
            }
            Self::GitHub(prepared) => Some(format!(
                "{}/{}/commit/{}",
                prepared.context.repository.remote.server.web_origin,
                prepared.context.repository.remote.repository.as_str(),
                self.head_sha().as_str()
            )),
            Self::Local(_) => None,
        }
    }

    fn manifest_sha256(&self) -> &revoot_core::Sha256Digest {
        match &self.partition().snapshot {
            ReviewSnapshotIdentity::GitLab(identity) => &identity.exact_diff_manifest_sha256,
            ReviewSnapshotIdentity::GitHub(identity) => &identity.exact_diff_manifest_sha256,
            ReviewSnapshotIdentity::Local(identity) => &identity.exact_diff_manifest_sha256,
        }
    }

    fn review_attention(&self) -> ReviewAttention {
        let paths = self
            .repository_diffs()
            .iter()
            .map(|diff| diff.path.clone())
            .collect::<BTreeSet<_>>();
        plan_attention(
            self.root(),
            self.base_sha(),
            self.head_sha(),
            &paths,
            self.prior_checkpoint(),
        )
    }

    fn repository_diffs(&self) -> &[revoot_core::RepositoryDiff] {
        match self {
            Self::GitLab(prepared) => &prepared.context.repository_diffs,
            Self::GitHub(prepared) => &prepared.context.repository_diffs,
            Self::Local(prepared) => &prepared.context.repository_diffs,
        }
    }

    fn anchors(&self) -> &AnchorTable {
        match self {
            Self::GitLab(prepared) => &prepared.context.anchors,
            Self::GitHub(prepared) => &prepared.context.anchors,
            Self::Local(prepared) => &prepared.context.anchors,
        }
    }

    fn issued_anchors(&self) -> &IssuedWorkUnitAnchors {
        match self {
            Self::GitLab(prepared) => &prepared.context.issued_anchors,
            Self::GitHub(prepared) => &prepared.context.issued_anchors,
            Self::Local(prepared) => &prepared.context.issued_anchors,
        }
    }

    fn initial_omissions(&self) -> Vec<AgentOmission> {
        let mut omissions = Vec::new();
        for omitted in &self.partition().omitted {
            let (code, reason) = partition_omission(omitted.reason);
            push_unique_omission(&mut omissions, format!("partition:{code}"), reason);
        }
        match self {
            Self::GitHub(prepared) if prepared.context.omitted_patch_count > 0 => {
                push_unique_omission(
                    &mut omissions,
                    "github:patches".to_owned(),
                    AgentOmissionReason::DiffUnavailable,
                );
            }
            Self::GitLab(prepared)
                if matches!(
                    &prepared.context.snapshot_readiness,
                    SnapshotReadiness::Partial { .. }
                ) =>
            {
                push_unique_omission(
                    &mut omissions,
                    "gitlab:snapshot".to_owned(),
                    AgentOmissionReason::DiffUnavailable,
                );
            }
            Self::Local(prepared) if prepared.context.omitted_diff_count > 0 => {
                push_unique_omission(
                    &mut omissions,
                    "local:diffs".to_owned(),
                    AgentOmissionReason::DiffUnavailable,
                );
            }
            _ => {}
        }
        omissions
    }

    fn toolbox(
        &self,
        repository_policy: &RepositoryReviewPolicy,
        cancellation: &CancellationToken,
    ) -> Result<revoot_core::RepositoryToolbox, Diagnostic> {
        let paths = match self {
            Self::Local(prepared) => prepared.context.repository_paths.clone(),
            Self::GitLab(_) | Self::GitHub(_) => {
                crate::embedded_git::EmbeddedRepository::discover(self.root())
                    .and_then(|repository| repository.tracked_paths())
                    .map_err(|_| {
                        diagnostic(
                            ErrorCode::RepositoryUnavailable,
                            "tracked checkout inventory could not be established",
                        )
                    })?
            }
        };
        let paths = paths
            .into_iter()
            .filter(|path| repository_policy.allows_model_context(path.as_str()));
        let diffs = self
            .repository_diffs()
            .iter()
            .filter(|diff| repository_policy.allows_model_context(diff.path.as_str()))
            .cloned();
        revoot_core::RepositoryToolbox::open_selected(
            self.root(),
            RepositoryToolLimits::default(),
            diffs,
            paths,
            cancellation,
        )
        .map_err(|_| {
            diagnostic(
                ErrorCode::RepositoryUnavailable,
                "policy-scoped checkout inventory construction failed",
            )
        })
    }

    fn is_fresh(&self) -> bool {
        match self {
            Self::Local(prepared) => local_snapshot_is_fresh(&prepared.context),
            Self::GitLab(_) | Self::GitHub(_) => true,
        }
    }
}

fn push_unique_omission(
    omissions: &mut Vec<AgentOmission>,
    subject_id: String,
    reason: AgentOmissionReason,
) {
    let omission = AgentOmission { subject_id, reason };
    if !omissions.contains(&omission) {
        omissions.push(omission);
    }
}

const fn partition_omission(reason: ReviewOmissionReason) -> (&'static str, AgentOmissionReason) {
    match reason {
        ReviewOmissionReason::Binary => ("binary", AgentOmissionReason::BinaryFile),
        ReviewOmissionReason::UnsupportedEncoding => {
            ("encoding", AgentOmissionReason::UnsupportedEncoding)
        }
        ReviewOmissionReason::FileTooLarge => ("file-too-large", AgentOmissionReason::FileTooLarge),
        ReviewOmissionReason::LowSignalBudget => {
            ("low-signal", AgentOmissionReason::LowSignalDeferred)
        }
        ReviewOmissionReason::MissingExactDiff | ReviewOmissionReason::EmptyObjectSet => {
            ("diff-unavailable", AgentOmissionReason::DiffUnavailable)
        }
        ReviewOmissionReason::ExactPathPolicy
        | ReviewOmissionReason::NotIncludedPolicy
        | ReviewOmissionReason::PrefixPolicy
        | ReviewOmissionReason::SuffixPolicy
        | ReviewOmissionReason::GeneratedPolicy => ("policy", AgentOmissionReason::PolicyExcluded),
        ReviewOmissionReason::DuplicateObjectRole
        | ReviewOmissionReason::DuplicateAnchor
        | ReviewOmissionReason::InputByteOverflow
        | ReviewOmissionReason::FileBudget
        | ReviewOmissionReason::TotalByteBudget
        | ReviewOmissionReason::WorkUnitBudget
        | ReviewOmissionReason::WorkUnitFileCapacity
        | ReviewOmissionReason::WorkUnitByteCapacity
        | ReviewOmissionReason::WorkUnitAnchorCapacity => {
            ("budget", AgentOmissionReason::BudgetExhausted)
        }
    }
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

/// Run the automatic review from a checked-out GitHub or GitLab repository.
///
/// # Errors
///
/// Returns an actionable, redaction-safe diagnostic for invalid arguments,
/// repository/code-host/provider setup, acquisition, or review failure.
pub fn run(
    args: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    current_directory: &Path,
) -> Result<i32, Diagnostic> {
    let Some(args) = parse_args(args)? else {
        print_help();
        return Ok(0);
    };
    let mut environment: Vec<_> = environment.into_iter().collect();
    if let Some(effort) = args.effort {
        set_operator_environment(
            &mut environment,
            "REVOOT_REVIEW_EFFORT",
            match effort {
                revoot_core::ReviewEffort::Low => "low",
                revoot_core::ReviewEffort::Medium => "medium",
                revoot_core::ReviewEffort::High => "high",
            },
        );
    }
    if let Some(maximum) = args.max_parallel_groups {
        set_operator_environment(
            &mut environment,
            "REVOOT_MAX_PARALLEL_GROUPS",
            &maximum.to_string(),
        );
    }
    if args.preview {
        set_operator_environment(&mut environment, "REVOOT_PUBLICATION_ENABLED", "false");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| {
            diagnostic(
                ErrorCode::ReviewFailed,
                "failed to start the review runtime",
            )
        })?;
    let result = runtime.block_on(run_async(
        &environment,
        current_directory,
        args.ci,
        args.preview,
        args.base_ref.as_deref(),
        args.merge_request_iid,
        args.pull_request_number,
        args.github_repository.clone(),
    ))?;
    let (provider, model, report) = match result {
        ReviewCommandResult::Review {
            provider,
            model,
            report,
        } => (provider, model, report),
        ReviewCommandResult::Preview(preview) => {
            emit_preview(&args, &preview)?;
            return Ok(0);
        }
    };
    emit_report(&args, &provider, &model, &report)?;
    if report.publication.reason == Some("github_thread_resolution_unavailable") {
        eprintln!(
            "GitHub did not permit automatic review-thread resolution. Revoot preserved the finding lifecycle in the evolving overview; resolve conversations manually or configure an optional GitHub App."
        );
    }
    if report.publication_failed() {
        if let Some(reason) = report.publication.reason {
            eprintln!("Revoot publication failed ({reason}); see the review report for details.");
        }
        return Ok(3);
    }
    Ok(0)
}

fn set_operator_environment(environment: &mut Vec<(OsString, OsString)>, name: &str, value: &str) {
    environment.retain(|(existing, _)| existing != name);
    environment.push((OsString::from(name), OsString::from(value)));
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_async(
    environment: &[(OsString, OsString)],
    current_directory: &Path,
    ci_requested: bool,
    preview: bool,
    explicit_base: Option<&str>,
    merge_request_iid: Option<MergeRequestIid>,
    pull_request_number: Option<PullRequestNumber>,
    explicit_github_repository: Option<GitHubRepositorySlug>,
) -> Result<ReviewCommandResult, Diagnostic> {
    if merge_request_iid.is_some()
        && (pull_request_number.is_some() || explicit_github_repository.is_some())
    {
        return Err(diagnostic(
            ErrorCode::CliInvalidArgument,
            "--mr cannot be combined with --pr or --repo",
        ));
    }
    let string_environment = utf8_environment(environment);
    let github_ci = classify_github_actions(&string_environment).map_err(|_| {
        diagnostic(
            ErrorCode::RepositoryUnavailable,
            "GitHub Actions pull-request context is invalid",
        )
    })?;
    let configured_github_server = configured_github_server(&string_environment)?;
    let expected_github_server = github_ci
        .as_ref()
        .map(|context| &context.server)
        .or(configured_github_server.as_ref());
    let discovered_github = github_ci.as_ref().map_or_else(
        || discover_github_repository(current_directory, expected_github_server).ok(),
        |context| discover_github_actions_repository(current_directory, context).ok(),
    );
    let origin_policy = GitLabOriginPolicy::default();
    let gitlab_ci = classify_gitlab_ci_environment(string_environment.clone(), &origin_policy);
    let gitlab_ci_active = !matches!(gitlab_ci, revoot_core::GitLabCiContext::Missing { .. });
    if github_ci.is_some() && gitlab_ci_active {
        return Err(diagnostic(
            ErrorCode::RepositoryUnavailable,
            "both GitHub and GitLab CI contexts are present",
        ));
    }
    if !preview
        && matches!(gitlab_ci, revoot_core::GitLabCiContext::ForkMismatch { .. })
        && matches!(
            fork_behavior(&string_environment)?,
            GitLabForkBehavior::Skip
        )
    {
        return Ok(ReviewCommandResult::Review {
            provider: "not_used".to_owned(),
            model: "not_used".to_owned(),
            report: Box::new(skipped_fork_review_report()),
        });
    }
    let explicit_host = ci_requested
        || merge_request_iid.is_some()
        || pull_request_number.is_some()
        || explicit_github_repository.is_some();
    if github_ci.is_none() && !gitlab_ci_active && !explicit_host {
        return run_local_review(environment, current_directory, explicit_base, preview).await;
    }
    if explicit_base.is_some() {
        return Err(diagnostic(
            ErrorCode::CliInvalidArgument,
            "--base is available only for local branch review",
        ));
    }
    let expected_gitlab_origin = gitlab_ci.hint().map(|hint| &hint.origin);
    let discovered_gitlab =
        discover_gitlab_repository(current_directory, &origin_policy, expected_gitlab_origin).ok();
    let explicit_github = pull_request_number.is_some() || explicit_github_repository.is_some();
    let github_requested = if github_ci.is_some() {
        true
    } else if gitlab_ci_active {
        false
    } else if explicit_github {
        true
    } else if merge_request_iid.is_some() {
        false
    } else {
        match (discovered_github.is_some(), discovered_gitlab.is_some()) {
            (true, false) => true,
            (false, true) => false,
            (true, true) => {
                return Err(diagnostic(
                    ErrorCode::RepositoryUnavailable,
                    "checkout has both GitHub and GitLab identities",
                )
                .with_remediation("select the change request explicitly with --pr or --mr"));
            }
            (false, false) => {
                return Err(diagnostic(
                    ErrorCode::RepositoryUnavailable,
                    "could not discover a supported GitHub or GitLab checkout",
                ));
            }
        }
    };
    let mut gitlab_repository = None;
    let github_repository = if github_requested {
        Some(discovered_github.ok_or_else(|| {
            diagnostic(
                ErrorCode::RepositoryUnavailable,
                "could not discover an unambiguous GitHub checkout",
            )
            .with_remediation("run from a Git repository with one canonical GitHub remote")
        })?)
    } else {
        gitlab_repository = Some(discovered_gitlab.ok_or_else(|| {
            diagnostic(
                ErrorCode::RepositoryUnavailable,
                "could not discover an unambiguous GitLab checkout",
            )
            .with_remediation("run from a Git repository with one canonical GitLab remote")
        })?);
        None
    };
    let root = github_repository.as_ref().map_or_else(
        || &gitlab_repository.as_ref().expect("selected GitLab").root,
        |repository| &repository.root,
    );
    let configuration_base_sha = if let Some(context) = &github_ci {
        Some(context.base_sha.clone())
    } else if gitlab_ci_active {
        gitlab_diff_base_sha(&string_environment)?
    } else {
        None
    };
    let resolved = resolve_review_configuration(
        root,
        configuration_base_sha.as_ref(),
        None,
        environment.iter().cloned(),
    )?;
    let resolution = &resolved.effective;
    let strategy = typed_review_strategy(&resolved)?;
    let mut prepared = if let Some(repository) = github_repository {
        PreparedReview::GitHub(Box::new(
            acquire_github_context(
                repository,
                github_ci.as_ref(),
                &string_environment,
                resolution,
                &strategy,
                &resolved.repository,
                DEFERRED_PROVIDER,
                DEFERRED_MODEL,
                ExplicitGitHubPullRequest {
                    number: pull_request_number,
                    repository: explicit_github_repository,
                },
            )
            .await?,
        ))
    } else {
        PreparedReview::GitLab(Box::new(
            acquire_gitlab_context(
                gitlab_repository.expect("selected GitLab"),
                &origin_policy,
                environment,
                resolution,
                &strategy,
                &resolved.repository,
                DEFERRED_PROVIDER,
                DEFERRED_MODEL,
                merge_request_iid,
            )
            .await?,
        ))
    };
    if configuration_base_sha
        .as_ref()
        .is_some_and(|base_sha| base_sha != prepared.base_sha())
    {
        return Err(diagnostic(
            ErrorCode::RepositoryUnavailable,
            "CI base configuration identity does not match the authoritative review snapshot",
        ));
    }
    if preview {
        return build_prepared_preview(&prepared, &resolved, &strategy)
            .map(Box::new)
            .map(ReviewCommandResult::Preview);
    }
    let job_url = ci_job_url(&string_environment, &prepared)?;
    if prepared.partition().work_units.is_empty() {
        let provider = "deterministic".to_owned();
        let model = "no-model".to_owned();
        let mut report = no_model_review_report(&prepared);
        report.publication =
            publish_with_checkpoint(&prepared, &report, &provider, &model, job_url.as_deref(), 0)
                .await;
        attach_no_model_stable_report(&mut report, &prepared, &strategy)?;
        return Ok(ReviewCommandResult::Review {
            provider,
            model,
            report: Box::new(report),
        });
    }
    let credentials = crate::direct_provider::discover_credentials(environment.iter().cloned())?;
    let provider = select_provider(config_string(resolution, "review.provider")?, &credentials)?;
    let model = select_model(&provider, config_string(resolution, "review.model")?)?;
    prepared.bind_provider_model(&provider, &model)?;
    execute_prepared_review(provider, model, credentials, resolved, prepared, job_url)
        .await
        .map(|(provider, model, report)| ReviewCommandResult::Review {
            provider,
            model,
            report: Box::new(report),
        })
}

async fn run_local_review(
    environment: &[(OsString, OsString)],
    current_directory: &Path,
    explicit_base: Option<&str>,
    preview: bool,
) -> Result<ReviewCommandResult, Diagnostic> {
    let capture = capture_local_git(current_directory, explicit_base).map_err(|error| {
        diagnostic(ErrorCode::RepositoryUnavailable, error.to_string()).with_remediation(
            "run inside a Git repository with an available default-branch history, or pass --base <ref>",
        )
    })?;
    let base_sha = capture.identity.base_sha.clone();
    let resolved = resolve_review_configuration(
        &capture.root,
        Some(&base_sha),
        None,
        environment.iter().cloned(),
    )?;
    let resolution = &resolved.effective;
    let strategy = typed_review_strategy(&resolved)?;
    let context = build_local_review_context(
        capture,
        &LocalReviewContextOptions {
            provider_adapter: DEFERRED_PROVIDER.to_owned(),
            model_id: DEFERRED_MODEL.to_owned(),
            agent_limits: agent_limits(resolution, &strategy)?,
            diff_limits: diff_limits(resolution)?,
            selection_policy: selection_policy(resolution, &resolved.repository)?,
            partition_limits: partition_limits(resolution)?,
        },
    )
    .map_err(|error| diagnostic(ErrorCode::ReviewFailed, error.to_string()))?;
    let mut prepared = PreparedReview::Local(Box::new(PreparedLocalReview { context }));
    if preview {
        return build_prepared_preview(&prepared, &resolved, &strategy)
            .map(Box::new)
            .map(ReviewCommandResult::Preview);
    }
    if prepared.partition().work_units.is_empty() {
        let mut report = no_model_review_report(&prepared);
        attach_no_model_stable_report(&mut report, &prepared, &strategy)?;
        return Ok(ReviewCommandResult::Review {
            provider: "not_used".to_owned(),
            model: "not_used".to_owned(),
            report: Box::new(report),
        });
    }
    let credentials = crate::direct_provider::discover_credentials(environment.iter().cloned())?;
    let provider = select_provider(config_string(resolution, "review.provider")?, &credentials)?;
    let model = select_model(&provider, config_string(resolution, "review.model")?)?;
    prepared.bind_provider_model(&provider, &model)?;
    execute_prepared_review(provider, model, credentials, resolved, prepared, None)
        .await
        .map(|(provider, model, report)| ReviewCommandResult::Review {
            provider,
            model,
            report: Box::new(report),
        })
}

fn build_prepared_preview(
    prepared: &PreparedReview,
    resolved: &ResolvedReviewConfiguration,
    strategy: &ReviewStrategyConfiguration,
) -> Result<ReviewPreview, Diagnostic> {
    let partition = prepared.partition();
    let group_plan =
        build_review_group_plan(partition, None, ReviewGroupingSource::DeterministicFallback)
            .map_err(|_| preview_contract_error("deterministic preview grouping failed"))?;
    let changed_lines = preview_changed_lines(prepared)?;
    let group_inputs = group_plan
        .groups
        .iter()
        .map(|group| {
            let (maximum, total) =
                group
                    .files
                    .iter()
                    .try_fold((0_u32, 0_u32), |(maximum, total), file| {
                        let lines =
                            changed_lines
                                .get(&file.path.new_path)
                                .copied()
                                .ok_or_else(|| {
                                    preview_contract_error("preview diff metadata is incomplete")
                                })?;
                        total
                            .checked_add(lines)
                            .map(|total| (maximum.max(lines), total))
                            .ok_or_else(|| preview_contract_error("preview line count overflowed"))
                    })?;
            let metadata_bytes = u64::try_from(
                serde_json::to_vec(group)
                    .map_err(|_| preview_contract_error("preview metadata serialization failed"))?
                    .len(),
            )
            .map_err(|_| preview_contract_error("preview metadata is too large"))?;
            let estimated_initial_input_tokens = group
                .input_bytes
                .checked_add(metadata_bytes)
                .and_then(|tokens| tokens.checked_add(1_024))
                .ok_or_else(|| preview_contract_error("preview token estimate overflowed"))?;
            Ok(ReviewPreviewGroupInput {
                group_id: group.id.clone(),
                exact_diff_bytes: group.input_bytes,
                max_file_changed_lines: maximum,
                total_changed_lines: total,
                estimated_initial_input_tokens,
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    let rules = preview_rules(partition, &resolved.repository)?;
    let budgets = agent_limits(&resolved.effective, strategy)?;
    let preview_strategy = ReviewPreviewStrategy {
        effort: strategy.effort,
        rounds_per_group: strategy.effort.rounds(),
        max_turns_per_group: strategy.effort.max_group_turns(),
        max_parallel_groups: strategy.max_parallel_groups,
        budgets,
        max_inline_diff_bytes: strategy.max_inline_diff_bytes,
        target_request_input_tokens: strategy.target_request_input_tokens,
        max_request_output_tokens: strategy.max_request_output_tokens,
    };
    build_review_preview(
        partition,
        &group_plan,
        preview_strategy,
        group_inputs,
        rules,
    )
    .map_err(|_| preview_contract_error("review preview construction failed"))
}

fn preview_changed_lines(
    prepared: &PreparedReview,
) -> Result<BTreeMap<RepositoryPath, u32>, Diagnostic> {
    prepared
        .repository_diffs()
        .iter()
        .map(|diff| {
            let path = RepositoryPath::try_from(diff.path.as_str().to_owned())
                .map_err(|_| preview_contract_error("preview contains an unsafe diff path"))?;
            let lines = diff
                .text
                .lines()
                .try_fold(0_u32, |count, line| {
                    if (line.starts_with('+') && !line.starts_with("+++"))
                        || (line.starts_with('-') && !line.starts_with("---"))
                    {
                        count.checked_add(1)
                    } else {
                        Some(count)
                    }
                })
                .ok_or_else(|| preview_contract_error("preview line count overflowed"))?;
            Ok((path, lines))
        })
        .collect()
}

fn preview_rules(
    partition: &ReviewPartitionPlan,
    repository: &RepositoryReviewPolicy,
) -> Result<Vec<ReviewPreviewRule>, Diagnostic> {
    let selected_paths = partition
        .work_units
        .iter()
        .flat_map(|unit| unit.files.iter())
        .map(|file| file.path.new_path.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let policy = RuleDiagnosticPolicy {
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
    };
    let mut indexed =
        BTreeMap::<(ReviewPreviewRuleSource, String), BTreeSet<RepositoryPath>>::new();
    let paths = selected_paths.into_iter().collect::<Vec<_>>();
    for batch in paths.chunks(32) {
        let diagnostics = diagnose_rules(batch.iter().cloned(), &policy)
            .map_err(|_| preview_contract_error("preview rule resolution failed"))?;
        for path in diagnostics.paths {
            let repository_path = RepositoryPath::try_from(path.path.as_str().to_owned())
                .map_err(|_| preview_contract_error("preview contains an unsafe rule path"))?;
            for trace in path.trace.into_iter().filter(|trace| trace.active) {
                let source = match trace.source {
                    RulePrecedenceSource::CompiledSafety => ReviewPreviewRuleSource::CompiledSafety,
                    RulePrecedenceSource::BaseConfiguration => {
                        ReviewPreviewRuleSource::BaseConfiguration
                    }
                    RulePrecedenceSource::RepositoryRule => ReviewPreviewRuleSource::RepositoryRule,
                    RulePrecedenceSource::EmbeddedRule => ReviewPreviewRuleSource::EmbeddedLanguage,
                    RulePrecedenceSource::GenericRule => ReviewPreviewRuleSource::Generic,
                };
                for id in trace.rule_ids {
                    indexed
                        .entry((source, id))
                        .or_default()
                        .insert(repository_path.clone());
                }
            }
        }
    }
    Ok(indexed
        .into_iter()
        .map(|((source, id), matched_paths)| ReviewPreviewRule {
            id,
            source,
            matched_paths: matched_paths.into_iter().collect(),
        })
        .collect())
}

fn preview_contract_error(message: &'static str) -> Diagnostic {
    diagnostic(ErrorCode::ContractInvalid, message)
}

#[allow(clippy::too_many_lines)]
async fn execute_prepared_review(
    provider: String,
    model: String,
    credentials: DiscoveredCredentials,
    resolved: ResolvedReviewConfiguration,
    prepared: PreparedReview,
    job_url: Option<String>,
) -> Result<(String, String, CanonicalReviewReport), Diagnostic> {
    let resolution = &resolved.effective;
    let strategy = typed_review_strategy(&resolved)?;
    let strategy = escalate_effort_for_large_diff(
        strategy,
        resolution,
        prepared.partition().coverage.included_files,
        prepared.partition().coverage.included_bytes,
    );
    if prepared.partition().work_units.is_empty() {
        let mut report = no_model_review_report(&prepared);
        attach_no_model_stable_report(&mut report, &prepared, &strategy)?;
        return Ok((provider, model, report));
    }
    let attention = prepared.review_attention();
    let adapter: Arc<dyn ProviderAdapter> = Arc::from(build_provider(&provider, &credentials)?);
    let minimum_confidence_percent =
        u8::try_from(config_unsigned(resolution, "review.minimum_confidence")?)
            .map_err(|_| diagnostic(ErrorCode::ContractInvalid, "minimum confidence is invalid"))?;
    let maximum_findings = usize::try_from(config_unsigned(resolution, "budget.max_findings")?)
        .map_err(|_| diagnostic(ErrorCode::ContractInvalid, "finding limit is invalid"))?;
    let mut engine_report =
        run_prepared_tool_first_engine(&prepared, &resolved, &strategy, &model, adapter).await?;
    if !prepared.is_fresh() {
        engine_report.result.outcome = ReviewOutcome::Stale {
            usage: review_outcome_usage(&engine_report.result.outcome),
        };
    }
    let repository_suppressions = filter_tool_first_findings(
        &mut engine_report,
        prepared.issued_anchors(),
        prepared.anchors(),
        maximum_findings,
        minimum_confidence_percent,
        &resolved.repository,
    )?;
    let mut report = canonicalize_report(
        &engine_report,
        prepared.issued_anchors(),
        prepared.anchors(),
        maximum_findings,
        repository_suppressions,
        strategy.effort,
        CanonicalSelection::from_partition(prepared.partition()),
    )?;
    report.publication = publish_with_checkpoint(
        &prepared,
        &report,
        &provider,
        &model,
        job_url.as_deref(),
        attention.next_generation(),
    )
    .await;
    let snapshot_sha256 = Sha256Digest::of_bytes(
        &serde_json::to_vec(&prepared.partition().snapshot).map_err(|_| {
            diagnostic(
                ErrorCode::ContractInvalid,
                "snapshot identity serialization failed",
            )
        })?,
    );
    report.stable_report = Some(
        build_tool_first_report(ToolFirstReportInput {
            engine: &engine_report,
            partition: prepared.partition(),
            anchors: prepared.anchors(),
            snapshot_sha256,
            selection: stable_selection(prepared.partition()),
            publication: stable_publication(&report),
            effort: strategy.effort,
            phase_usage: Some(engine_report.phase_usage.clone()),
        })
        .map_err(|error| diagnostic(ErrorCode::ContractInvalid, error.to_string()))?,
    );
    Ok((provider, model, report))
}

async fn run_prepared_tool_first_engine(
    prepared: &PreparedReview,
    resolved: &ResolvedReviewConfiguration,
    strategy: &ReviewStrategyConfiguration,
    model: &str,
    provider: Arc<dyn ProviderAdapter>,
) -> Result<ToolFirstEngineReport, Diagnostic> {
    let cancellation = CancellationToken::default();
    let toolbox = Arc::new(prepared.toolbox(&resolved.repository, &cancellation)?);
    let mut initial_omissions = prepared.initial_omissions();
    let history = if let Ok(history) = GitHistoryToolbox::open(
        prepared.root(),
        prepared.base_sha().clone(),
        prepared.head_sha().clone(),
    ) {
        if !history.coverage().is_complete() {
            push_unique_omission(
                &mut initial_omissions,
                "change-history".to_owned(),
                AgentOmissionReason::HistoryIncomplete,
            );
        }
        Some(Arc::new(history))
    } else {
        push_unique_omission(
            &mut initial_omissions,
            "change-history".to_owned(),
            AgentOmissionReason::HistoryUnavailable,
        );
        None
    };
    let clock = Arc::new(ProcessClock::start());
    let budget = ReviewBudgetBroker::new(
        strategy.aggregate_budget,
        ReviewGrouperClock::now_millis(clock.as_ref()),
    )
    .map_err(|_| {
        diagnostic(
            ErrorCode::ContractInvalid,
            "aggregate review budget is invalid",
        )
    })?;
    run_tool_first_engine(ToolFirstEngineRequest {
        provider,
        toolbox,
        history,
        prior_review: prepared.prior_review(),
        anchor_table: prepared.anchors().clone(),
        partition: prepared.partition().clone(),
        rule_policy: resolved.repository.clone(),
        budget,
        cancellation,
        clock,
        limits: tool_first_limits(model, strategy, &resolved.effective)?,
        system_policy_id: format!("{REVIEWER_POLICY_VERSION}.tool-first"),
        system_policy: tool_first_reviewer_system_policy(),
        initial_omissions,
    })
    .await
    .map_err(|error| diagnostic(ErrorCode::ReviewFailed, error.to_string()))
}

pub(crate) fn tool_first_limits(
    model: &str,
    strategy: &ReviewStrategyConfiguration,
    resolution: &revoot_core::ConfigurationResolution,
) -> Result<ToolFirstEngineLimits, Diagnostic> {
    let max_output_tokens = u32::try_from(strategy.max_request_output_tokens).map_err(|_| {
        diagnostic(
            ErrorCode::ContractInvalid,
            "per-request output token limit is invalid",
        )
    })?;
    let max_findings = u32_value(resolution, "budget.max_findings")?;
    let max_group_turns = strategy.effort.max_group_turns();
    let mut limits = ToolFirstEngineLimits::new(model);
    limits.effort = strategy.effort;
    limits.max_parallel_groups = usize::from(strategy.max_parallel_groups);
    limits.max_inline_diff_bytes = strategy.max_inline_diff_bytes;
    limits.worker = GroupWorkerLimits {
        max_output_tokens,
        max_input_tokens: strategy.target_request_input_tokens,
        local_tool_budget: AgentBudgetLimits {
            max_turns: max_group_turns,
            max_model_requests: max_group_turns,
            max_tool_calls: strategy.aggregate_budget.max_tool_calls,
            max_input_tokens: strategy.aggregate_budget.max_model_tokens,
            max_output_tokens: strategy.aggregate_budget.max_output_tokens,
            max_cost_microusd: strategy.aggregate_budget.max_cost_microusd,
            max_candidate_findings: max_findings,
            max_elapsed_millis: strategy.aggregate_budget.max_elapsed_millis,
            ..AgentBudgetLimits::default()
        },
        ..GroupWorkerLimits::default()
    };
    limits.grouper.max_output_tokens = limits.grouper.max_output_tokens.min(max_output_tokens);
    limits.verifier.max_output_tokens = limits.verifier.max_output_tokens.min(max_output_tokens);
    limits.adjudicator.max_output_tokens =
        limits.adjudicator.max_output_tokens.min(max_output_tokens);
    Ok(limits)
}

fn filter_tool_first_findings(
    engine: &mut ToolFirstEngineReport,
    issued: &IssuedWorkUnitAnchors,
    anchors: &AnchorTable,
    maximum: usize,
    minimum_confidence_percent: u8,
    repository_policy: &RepositoryReviewPolicy,
) -> Result<u32, Diagnostic> {
    let envelopes = match &mut engine.result.outcome {
        ReviewOutcome::Complete { findings, .. } | ReviewOutcome::Partial { findings, .. } => {
            findings
        }
        ReviewOutcome::NoFindings { .. }
        | ReviewOutcome::Stale { .. }
        | ReviewOutcome::Blocked { .. }
        | ReviewOutcome::Failed { .. }
        | ReviewOutcome::Cancelled { .. } => return Ok(0),
    };
    validate_rank_and_render(envelopes.clone(), issued, anchors, maximum).map_err(|_| {
        diagnostic(
            ErrorCode::ReviewFailed,
            "tool-first findings failed anchor or capacity validation",
        )
    })?;
    let mut suppressed = 0_u32;
    for envelope in envelopes {
        let mut retained = Vec::with_capacity(envelope.findings.len());
        for finding in std::mem::take(&mut envelope.findings) {
            let ranked = validate_rank_and_render(
                [revoot_core::FindingsEnvelope {
                    schema_version: envelope.schema_version.clone(),
                    work_unit_id: envelope.work_unit_id.clone(),
                    findings: vec![finding.clone()],
                    summary: envelope.summary.clone(),
                }],
                issued,
                anchors,
                25,
            )
            .map_err(|_| {
                diagnostic(
                    ErrorCode::ReviewFailed,
                    "tool-first finding identity derivation failed",
                )
            })?;
            let ranked = ranked.findings.first().ok_or_else(|| {
                diagnostic(
                    ErrorCode::ReviewFailed,
                    "tool-first finding identity is missing",
                )
            })?;
            if finding.confidence_percent < minimum_confidence_percent
                || repository_policy.suppresses(&ranked.finding_key)
            {
                suppressed = suppressed.saturating_add(1);
            } else {
                retained.push(finding);
            }
        }
        envelope.findings = retained;
    }
    Ok(suppressed)
}

fn stable_selection(partition: &ReviewPartitionPlan) -> ReviewReportSelection {
    ReviewReportSelection {
        changed_files: partition.coverage.input_files,
        selected_files: partition.coverage.included_files,
        omitted_files: partition.coverage.omitted_files,
        selected_diff_bytes: partition.coverage.included_bytes,
        omission_reasons: partition.coverage.omission_reasons.clone(),
    }
}

fn stable_publication(report: &CanonicalReviewReport) -> ReviewReportPublication {
    let planned_findings = u32::try_from(report.findings.len()).unwrap_or(u32::MAX);
    let published_findings = report.publication.published_findings.min(planned_findings);
    ReviewReportPublication {
        planned_findings,
        published_findings,
        suppressed_findings: 0,
        publication_complete: published_findings == planned_findings
            && !report.publication.failed(),
    }
}

fn review_outcome_usage(outcome: &ReviewOutcome) -> AgentBudgetUsage {
    match outcome {
        ReviewOutcome::Complete { usage, .. }
        | ReviewOutcome::Partial { usage, .. }
        | ReviewOutcome::NoFindings { usage, .. }
        | ReviewOutcome::Stale { usage }
        | ReviewOutcome::Blocked { usage, .. }
        | ReviewOutcome::Failed { usage, .. }
        | ReviewOutcome::Cancelled { usage } => *usage,
    }
}

fn skipped_fork_review_report() -> CanonicalReviewReport {
    CanonicalReviewReport {
        stable_report: None,
        sarif_anchors: None,
        state: "skipped",
        overview: None,
        summary: Some("Fork merge request skipped by policy.".to_owned()),
        findings: Vec::new(),
        omissions: Vec::new(),
        prior_finding_dispositions: Vec::new(),
        duplicates_omitted: 0,
        usage: AgentBudgetUsage::default(),
        turns: 0,
        tool_calls: 0,
        admitted_candidates: 0,
        suppressed_candidates: 0,
        strategy: None,
        coverage: None,
        selection: CanonicalSelection::default(),
        publication: CanonicalPublication::terminal("skipped", Some("fork_policy")),
        finding_locations: BTreeMap::new(),
    }
}

fn no_model_review_report(prepared: &PreparedReview) -> CanonicalReviewReport {
    let no_changes = prepared.partition().coverage.input_files == 0;
    let summary = if no_changes {
        "No local changes to review."
    } else {
        "No changed files were selected for model review."
    };
    CanonicalReviewReport {
        stable_report: None,
        sarif_anchors: None,
        state: "no_findings",
        overview: Some(ReviewOverview {
            summary: summary.to_owned(),
            overall_risk: if no_changes {
                RiskLevel::Low
            } else {
                RiskLevel::Moderate
            },
            overall_basis: if no_changes {
                "The immutable snapshot contains no changed files.".to_owned()
            } else {
                "The overall risk could not be fully assessed because no changed files were selected for model review.".to_owned()
            },
            risks: Vec::new(),
            assumptions_and_gaps: if no_changes {
                Vec::new()
            } else {
                vec!["The omitted files were not reviewed by the model.".to_owned()]
            },
            manual_validations: Vec::new(),
        }),
        summary: Some(summary.to_owned()),
        findings: Vec::new(),
        omissions: prepared.initial_omissions(),
        prior_finding_dispositions: Vec::new(),
        duplicates_omitted: 0,
        usage: AgentBudgetUsage::default(),
        turns: 0,
        tool_calls: 0,
        admitted_candidates: 0,
        suppressed_candidates: 0,
        strategy: None,
        coverage: None,
        selection: CanonicalSelection::from_partition(prepared.partition()),
        publication: CanonicalPublication::terminal("not_needed", Some("no_model_work")),
        finding_locations: BTreeMap::new(),
    }
}

fn attach_no_model_stable_report(
    report: &mut CanonicalReviewReport,
    prepared: &PreparedReview,
    strategy: &ReviewStrategyConfiguration,
) -> Result<(), Diagnostic> {
    let partition = prepared.partition();
    let selection = stable_selection(partition);
    let partial = !report.omissions.is_empty() || selection.omitted_files > 0;
    report.state = if partial { "partial" } else { "no_findings" };
    let overview_text = report
        .summary
        .clone()
        .unwrap_or_else(|| "No supported defects found.".to_owned());
    let phases = [
        ReviewReportPhase::Grouping,
        ReviewReportPhase::Planning,
        ReviewReportPhase::Review,
        ReviewReportPhase::Verification,
        ReviewReportPhase::Adjudication,
    ]
    .into_iter()
    .map(|phase| ReviewReportPhaseUsage {
        phase,
        model_requests: 0,
        input_tokens: 0,
        output_tokens: 0,
        tool_calls: 0,
        cost_microusd: 0,
    })
    .collect();
    let snapshot_sha256 =
        Sha256Digest::of_bytes(&serde_json::to_vec(&partition.snapshot).map_err(|_| {
            diagnostic(
                ErrorCode::ContractInvalid,
                "snapshot identity serialization failed",
            )
        })?);
    let stable = ReviewReportV3::new(
        if partial {
            ReviewReportState::Partial
        } else {
            ReviewReportState::NoFindings
        },
        snapshot_sha256,
        partition.plan_sha256.clone(),
        Vec::new(),
        ReviewReportOverview {
            content_sha256: Sha256Digest::of_bytes(overview_text.as_bytes()),
            text: overview_text,
        },
        Vec::new(),
        stable_publication(report),
        selection,
        ReviewReportStrategy {
            effort: strategy.effort,
            grouping_source: ReviewGroupingSource::DeterministicFallback,
            group_count: 0,
            max_parallel_groups: strategy.max_parallel_groups,
        },
        ReviewReportCoverage {
            policy_version: "revoot.risk-adaptive-coverage/v1".to_owned(),
            high_risk_files: 0,
            standard_risk_files: 0,
            low_risk_files: 0,
            fully_read_files: 0,
            sampled_files: 0,
            manifest_only_files: 0,
            delivered_high_risk_hunks: 0,
            required_high_risk_hunks: 0,
            explicit_deferrals: partition.coverage.omitted_files,
            failed_groups: 0,
        },
        ReviewReportUsage {
            phases,
            totals: ReviewReportUsageTotals::default(),
        },
    )
    .map_err(|error| diagnostic(ErrorCode::ContractInvalid, error.to_string()))?;
    stable
        .validate_against_anchors(prepared.anchors())
        .map_err(|error| diagnostic(ErrorCode::ContractInvalid, error.to_string()))?;
    report.sarif_anchors = Some(prepared.anchors().clone());
    report.stable_report = Some(stable);
    Ok(())
}

fn minimum_review_risk(
    findings: &[RankedFinding],
    selection: &CanonicalSelection,
) -> (RiskLevel, &'static str) {
    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
    {
        (
            RiskLevel::Critical,
            "The review identified a critical-severity finding.",
        )
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::High)
    {
        (
            RiskLevel::High,
            "The review identified a high-severity finding.",
        )
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::Medium)
    {
        (
            RiskLevel::Moderate,
            "The review identified a medium-severity finding.",
        )
    } else if selection.selected_high_signal_files > 0 {
        (
            RiskLevel::Moderate,
            "The change affects code that warrants additional scrutiny.",
        )
    } else {
        (RiskLevel::Low, "")
    }
}

fn canonicalize_report(
    engine: &ToolFirstEngineReport,
    issued: &IssuedWorkUnitAnchors,
    anchors: &AnchorTable,
    maximum: usize,
    deterministic_suppressions: u32,
    effort: revoot_core::ReviewEffort,
    selection: CanonicalSelection,
) -> Result<CanonicalReviewReport, Diagnostic> {
    let mut overview = engine.result.overview.clone();
    let CanonicalOutcomeParts {
        state,
        summary,
        envelopes,
        omissions,
        usage,
    } = canonical_outcome_parts(&engine.result.outcome);
    let ranked = validate_rank_and_render(envelopes, issued, anchors, maximum).map_err(|_| {
        diagnostic(
            ErrorCode::ReviewFailed,
            "review findings failed anchor, ranking, or deduplication validation",
        )
    })?;
    let (minimum_risk, minimum_basis) = minimum_review_risk(&ranked.findings, &selection);
    if overview.overall_risk < minimum_risk {
        overview.overall_risk = minimum_risk;
        minimum_basis.clone_into(&mut overview.overall_basis);
    }
    let finding_locations = finding_locations(&ranked.findings, anchors);
    Ok(CanonicalReviewReport {
        stable_report: None,
        sarif_anchors: Some(anchors.clone()),
        state,
        overview: matches!(state, "complete" | "partial" | "no_findings").then_some(overview),
        summary,
        findings: ranked.findings,
        omissions,
        prior_finding_dispositions: engine.result.prior_finding_dispositions.clone(),
        duplicates_omitted: ranked.duplicates_omitted,
        usage,
        turns: engine.budget_usage.model_requests,
        tool_calls: engine.budget_usage.tool_calls,
        admitted_candidates: engine.verified_candidates,
        suppressed_candidates: engine
            .verification_suppressions
            .saturating_add(deterministic_suppressions),
        strategy: Some(ReviewStrategy {
            effort,
            grouping_source: match engine.grouping_mode {
                crate::review_grouper::ReviewGrouperMode::DeterministicSmallSelection => {
                    ReviewGroupingSource::Deterministic
                }
                crate::review_grouper::ReviewGrouperMode::Semantic => {
                    ReviewGroupingSource::Semantic
                }
                crate::review_grouper::ReviewGrouperMode::DeterministicFallback(_) => {
                    ReviewGroupingSource::DeterministicFallback
                }
            },
            group_count: engine.group_count,
            max_parallel_groups: engine.schedule.max_parallel_groups,
        }),
        coverage: Some(engine.result.coverage.clone()),
        selection,
        publication: CanonicalPublication::pending(),
        finding_locations,
    })
}

struct CanonicalOutcomeParts {
    state: &'static str,
    summary: Option<String>,
    envelopes: Vec<revoot_core::FindingsEnvelope>,
    omissions: Vec<AgentOmission>,
    usage: AgentBudgetUsage,
}

fn canonical_outcome_parts(outcome: &ReviewOutcome) -> CanonicalOutcomeParts {
    let (state, summary, envelopes, omissions, usage) = match outcome {
        ReviewOutcome::Complete {
            findings,
            summary,
            usage,
        } => (
            "complete",
            Some(summary.clone()),
            findings.clone(),
            Vec::new(),
            *usage,
        ),
        ReviewOutcome::Partial {
            findings,
            summary,
            omissions,
            usage,
        } => (
            "partial",
            Some(summary.clone()),
            findings.clone(),
            omissions.clone(),
            *usage,
        ),
        ReviewOutcome::NoFindings {
            summary,
            omissions,
            usage,
        } => (
            "no_findings",
            Some(summary.clone()),
            Vec::new(),
            omissions.clone(),
            *usage,
        ),
        ReviewOutcome::Stale { usage } => ("stale", None, Vec::new(), Vec::new(), *usage),
        ReviewOutcome::Blocked { usage, .. } => ("blocked", None, Vec::new(), Vec::new(), *usage),
        ReviewOutcome::Failed { usage, .. } => ("failed", None, Vec::new(), Vec::new(), *usage),
        ReviewOutcome::Cancelled { usage } => ("cancelled", None, Vec::new(), Vec::new(), *usage),
    };
    CanonicalOutcomeParts {
        state,
        summary,
        envelopes,
        omissions,
        usage,
    }
}

fn finding_locations(
    findings: &[RankedFinding],
    anchors: &AnchorTable,
) -> BTreeMap<AnchorId, String> {
    findings
        .iter()
        .filter_map(|finding| {
            anchors.resolve(finding.anchor_id.as_str()).map(|anchor| {
                let (path, line) = match anchor.position {
                    revoot_core::AnchorPosition::Deletion { old_line } => {
                        (anchor.path.old_path.as_str(), old_line)
                    }
                    revoot_core::AnchorPosition::Addition { new_line }
                    | revoot_core::AnchorPosition::Context { new_line, .. } => {
                        (anchor.path.new_path.as_str(), new_line)
                    }
                };
                (finding.anchor_id.clone(), format!("{path}:{line}"))
            })
        })
        .collect()
}

#[cfg(test)]
fn apply_repository_suppressions(
    findings: &mut Vec<RankedFinding>,
    repository_policy: &RepositoryReviewPolicy,
) -> u32 {
    let original = findings.len();
    findings.retain(|finding| !repository_policy.suppresses(&finding.finding_key));
    u32::try_from(original.saturating_sub(findings.len())).unwrap_or(u32::MAX)
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn acquire_github_context(
    repository: DiscoveredGitHubRepository,
    ci: Option<&GitHubCiContext>,
    environment: &[(String, String)],
    resolution: &revoot_core::ConfigurationResolution,
    strategy: &ReviewStrategyConfiguration,
    repository_policy: &RepositoryReviewPolicy,
    provider: &str,
    model: &str,
    explicit: ExplicitGitHubPullRequest,
) -> Result<PreparedGitHubReview, Diagnostic> {
    let (target_repository, pull_number, fork) = if let Some(ci) = ci {
        if explicit
            .number
            .is_some_and(|number| number != ci.pull_request_number)
        {
            return Err(diagnostic(
                ErrorCode::CliInvalidArgument,
                "--pr conflicts with the GitHub Actions pull-request number",
            ));
        }
        if explicit
            .repository
            .as_ref()
            .is_some_and(|selected| selected != &ci.target_repository)
        {
            return Err(diagnostic(
                ErrorCode::CliInvalidArgument,
                "--repo conflicts with the GitHub Actions target repository",
            ));
        }
        (
            ci.target_repository.clone(),
            ci.pull_request_number,
            ci.fork,
        )
    } else {
        (
            explicit
                .repository
                .unwrap_or_else(|| repository.remote.repository.clone()),
            explicit.number.ok_or_else(|| {
                diagnostic(
                    ErrorCode::CliInvalidArgument,
                    "local GitHub review requires --pr NUMBER",
                )
                .with_remediation("run `revoot review --pr <pull-request-number>`")
            })?,
            false,
        )
    };
    let (token, _) = load_github_token(environment).map_err(|_| {
        diagnostic(
            ErrorCode::GitHubUnavailable,
            "no usable GitHub API credential is available",
        )
        .with_remediation("provide GITHUB_TOKEN or a masked REVOOT_GITHUB_TOKEN")
    })?;
    let network = code_host_network_policy(resolution, "github")?;
    let (ca_mode, authorized_ca) = match network.custom_ca {
        Some(custom) => (
            GitHubCaMode::CustomBundle(
                GitHubCustomCaBundle::from_der(custom.certificates, custom.digest)
                    .map_err(|_| code_host_network_error())?,
            ),
            CertificateAuthorityMode::CustomBundle {
                sha256: custom.digest,
            },
        ),
        None => (
            GitHubCaMode::BundledWebPki,
            CertificateAuthorityMode::BundledWebPki,
        ),
    };
    let authorization = authorize_configured_provider(
        "github-rest",
        &repository.remote.server.api_root,
        authorized_ca,
        network.private_cidrs,
    )
    .map_err(|_| {
        diagnostic(
            ErrorCode::GitHubUnavailable,
            "GitHub API endpoint authorization failed",
        )
    })?;
    let client = GitHubClient::new_with_ca(
        &repository.remote.server.api_root,
        token,
        &authorization,
        &ca_mode,
    )
    .map_err(|_| diagnostic(ErrorCode::GitHubUnavailable, "GitHub client setup failed"))?;
    let context = acquire_github_review_context(
        &client,
        repository,
        target_repository,
        pull_number,
        ci,
        &GitHubReviewContextOptions {
            provider_adapter: provider.to_owned(),
            model_id: model.to_owned(),
            agent_limits: agent_limits(resolution, strategy)?,
            diff_limits: diff_limits(resolution)?,
            selection_policy: selection_policy(resolution, repository_policy)?,
            partition_limits: partition_limits(resolution)?,
        },
    )
    .await
    .map_err(|error| diagnostic(ErrorCode::GitHubUnavailable, error.to_string()))?;
    let prior_review = acquire_github_prior_review(
        &client,
        &context.target_repository,
        context.identity.pull_request_number,
        &context.identity.head_sha,
    )
    .await
    .map_err(|_| {
        diagnostic(
            ErrorCode::GitHubUnavailable,
            "GitHub prior review discussion acquisition failed",
        )
    })?;
    let checkpoint = extract_checkpoint(&context.description);
    Ok(PreparedGitHubReview {
        context,
        client,
        publication_enabled: config_bool(resolution, "publication.enabled")? && !fork,
        fork,
        prior_review,
        checkpoint,
    })
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn acquire_gitlab_context(
    repository: DiscoveredGitRepository,
    origin_policy: &GitLabOriginPolicy,
    environment: &[(OsString, OsString)],
    resolution: &revoot_core::ConfigurationResolution,
    strategy: &ReviewStrategyConfiguration,
    repository_policy: &RepositoryReviewPolicy,
    provider: &str,
    model: &str,
    merge_request_iid: Option<MergeRequestIid>,
) -> Result<PreparedGitLabReview, Diagnostic> {
    let string_environment = utf8_environment(environment);
    let ci = classify_gitlab_ci_environment(string_environment.clone(), origin_policy);
    let credentials = load_gitlab_credentials(string_environment.clone()).map_err(|_| {
        diagnostic(
            ErrorCode::GitLabUnavailable,
            "no usable GitLab read credential is available",
        )
        .with_remediation("provide CI_JOB_TOKEN or a masked REVOOT_GITLAB_TOKEN")
    })?;
    let endpoint = format!("{}/api/v4", repository.remote.origin.as_str());
    let network = code_host_network_policy(resolution, "gitlab")?;
    let (ca_mode, authorized_ca) = match network.custom_ca {
        Some(custom) => (
            GitLabCaMode::CustomBundle(
                GitLabCustomCaBundle::from_der(custom.certificates, custom.digest)
                    .map_err(|_| code_host_network_error())?,
            ),
            CertificateAuthorityMode::CustomBundle {
                sha256: custom.digest,
            },
        ),
        None => (
            GitLabCaMode::BundledWebPki,
            CertificateAuthorityMode::BundledWebPki,
        ),
    };
    let egress = authorize_configured_provider(
        "gitlab-rest",
        &endpoint,
        authorized_ca,
        network.private_cidrs,
    )
    .map_err(|_| {
        diagnostic(
            ErrorCode::GitLabUnavailable,
            "GitLab API endpoint authorization failed",
        )
    })?;
    let config = GitLabTransportConfig::new(
        repository.remote.origin.clone(),
        ca_mode,
        GitLabTransportLimits::default(),
    );
    let client = GitLabReadClient::new(&config, credentials.read, &egress)
        .map_err(|_| diagnostic(ErrorCode::GitLabUnavailable, "GitLab client setup failed"))?;
    let write = credentials
        .write
        .map(|token| GitLabWriteClient::new(&config, token, &egress))
        .transpose()
        .map_err(|_| {
            diagnostic(
                ErrorCode::GitLabUnavailable,
                "GitLab publication client setup failed",
            )
        })?;
    let verification = select_review(&repository, &ci, merge_request_iid, &client).await?;
    let snapshot = acquire_snapshot(&client, verification).await?;
    let checkout = bind_checkout_to_snapshot(repository, &snapshot).map_err(|_| {
        diagnostic(
            ErrorCode::RepositoryUnavailable,
            "checkout HEAD does not match the authoritative merge-request head",
        )
    })?;
    let context = build_gitlab_review_context(
        &snapshot,
        checkout,
        &GitLabReviewContextOptions {
            provider_adapter: provider.to_owned(),
            model_id: model.to_owned(),
            agent_limits: agent_limits(resolution, strategy)?,
            diff_limits: diff_limits(resolution)?,
            selection_policy: selection_policy(resolution, repository_policy)?,
            partition_limits: partition_limits(resolution)?,
        },
    )
    .map_err(|_| {
        diagnostic(
            ErrorCode::ReviewFailed,
            "review context construction failed",
        )
    })?;
    let bot_user_id = probe_gitlab_user(&client).await.ok();
    let scope = &snapshot.evidence().identity.version.scope;
    let prior_review = acquire_gitlab_prior_review(
        &client,
        scope.project_id,
        scope.merge_request_iid,
        bot_user_id,
        &snapshot
            .evidence()
            .identity
            .version
            .diff_version
            .refs
            .head_sha,
    )
    .await
    .map_err(|_| {
        diagnostic(
            ErrorCode::GitLabUnavailable,
            "GitLab prior review discussion acquisition failed",
        )
    })?;
    let checkpoint = acquire_gitlab_checkpoint_hint(&client, &snapshot).await;
    Ok(PreparedGitLabReview {
        context,
        snapshot,
        read: client,
        write,
        ci,
        credential_source: credentials.source,
        publication_preference: if config_bool(resolution, "publication.enabled")? {
            GitLabPublicationPreference::Publish
        } else {
            GitLabPublicationPreference::ReportOnly
        },
        fork_behavior: fork_behavior(&string_environment)?,
        prior_review,
        checkpoint,
    })
}

#[derive(Deserialize)]
struct GitLabCheckpointDescription {
    project_id: u64,
    iid: u64,
    state: String,
    sha: String,
    description: Option<String>,
}

async fn acquire_gitlab_checkpoint_hint(
    client: &GitLabReadClient,
    snapshot: &AcquiredGitLabSnapshot,
) -> Option<ReviewCheckpoint> {
    let identity = &snapshot.evidence().identity.version;
    let response = client
        .get(&GitLabReadEndpoint::MergeRequest {
            project_id: identity.scope.project_id,
            merge_request_iid: identity.scope.merge_request_iid,
        })
        .await
        .ok()?;
    let value: GitLabCheckpointDescription =
        serde_json::from_slice(&response.observation().body).ok()?;
    if value.project_id != identity.scope.project_id.get()
        || value.iid != identity.scope.merge_request_iid.get()
        || value.state != "opened"
        || value.sha != identity.diff_version.refs.head_sha.as_str()
    {
        return None;
    }
    extract_checkpoint(value.description.as_deref().unwrap_or_default())
}

async fn select_review(
    repository: &DiscoveredGitRepository,
    ci: &revoot_core::GitLabCiContext,
    merge_request_iid: Option<MergeRequestIid>,
    client: &GitLabReadClient,
) -> Result<GitLabVerificationInput, Diagnostic> {
    match ci {
        revoot_core::GitLabCiContext::Ready(hint)
        | revoot_core::GitLabCiContext::ForkMismatch { hint } => {
            if merge_request_iid.is_some_and(|iid| iid != hint.merge_request_iid) {
                return Err(diagnostic(
                    ErrorCode::CliInvalidArgument,
                    "--mr conflicts with the GitLab CI merge-request IID",
                ));
            }
            select_gitlab_merge_request(repository, Some(ci), None).map_err(|_| {
                diagnostic(
                    ErrorCode::GitLabUnavailable,
                    "could not select the merge request from GitLab CI context",
                )
            })
        }
        revoot_core::GitLabCiContext::Missing { .. } => {
            let merge_request_iid = merge_request_iid.ok_or_else(|| {
                diagnostic(
                    ErrorCode::CliInvalidArgument,
                    "local review requires --mr IID",
                )
                .with_remediation("run `revoot review --mr <merge-request-iid>`")
            })?;
            let target_project = resolve_local_project(client, repository).await?;
            select_gitlab_merge_request(
                repository,
                None,
                Some(&ExplicitGitLabMergeRequest {
                    origin: repository.remote.origin.clone(),
                    target_project,
                    merge_request_iid,
                }),
            )
            .map_err(|_| {
                diagnostic(
                    ErrorCode::GitLabUnavailable,
                    "local merge-request selection is inconsistent with the checkout",
                )
            })
        }
        revoot_core::GitLabCiContext::Ambiguous { .. } => Err(diagnostic(
            ErrorCode::GitLabUnavailable,
            "GitLab CI merge-request variables are ambiguous",
        )),
    }
}

async fn resolve_local_project(
    client: &GitLabReadClient,
    repository: &DiscoveredGitRepository,
) -> Result<GitLabProjectIdentity, Diagnostic> {
    let response = client
        .get(
            &crate::gitlab_transport::GitLabReadEndpoint::ProjectByPath {
                project_path: repository.remote.project_path.clone(),
            },
        )
        .await
        .map_err(|_| diagnostic(ErrorCode::GitLabUnavailable, "GitLab project lookup failed"))?;
    let project = parse_project_response(response.observation(), GitLabWireLimits::default())
        .map_err(|_| {
            diagnostic(
                ErrorCode::GitLabUnavailable,
                "GitLab project lookup returned an invalid identity",
            )
        })?;
    if project.path != repository.remote.project_path {
        return Err(diagnostic(
            ErrorCode::GitLabUnavailable,
            "GitLab project lookup contradicted the checkout remote",
        ));
    }
    Ok(project)
}

async fn acquire_snapshot(
    client: &GitLabReadClient,
    verification: revoot_core::GitLabVerificationInput,
) -> Result<AcquiredGitLabSnapshot, Diagnostic> {
    let controller =
        GitLabSnapshotController::new(client, GitLabSnapshotAcquisitionLimits::default()).map_err(
            |_| {
                diagnostic(
                    ErrorCode::GitLabUnavailable,
                    "GitLab snapshot limits are invalid",
                )
            },
        )?;
    match controller.acquire(verification).await {
        GitLabSnapshotAcquisitionOutcome::Complete(snapshot)
        | GitLabSnapshotAcquisitionOutcome::Partial(snapshot) => Ok(snapshot),
        GitLabSnapshotAcquisitionOutcome::Blocked(_) => Err(diagnostic(
            ErrorCode::GitLabUnavailable,
            "the authoritative GitLab snapshot is not reviewable",
        )),
        GitLabSnapshotAcquisitionOutcome::Failed(_) => Err(diagnostic(
            ErrorCode::GitLabUnavailable,
            "GitLab snapshot acquisition failed",
        )),
    }
}

async fn publish_gitlab_review(
    prepared: &PreparedGitLabReview,
    report: &CanonicalReviewReport,
    overview: Option<&str>,
) -> CanonicalPublication {
    if matches!(
        prepared.publication_preference,
        GitLabPublicationPreference::ReportOnly
    ) {
        return CanonicalPublication::terminal("report_only", Some("publication_disabled"));
    }
    let Some(write) = prepared.write.as_ref() else {
        return CanonicalPublication::terminal("report_only", Some("write_credential_unavailable"));
    };
    let authenticated_user = probe_gitlab_user(&prepared.read).await;
    let readiness = diagnose_gitlab_readiness(GitLabReadinessInput {
        ci: &prepared.ci,
        credential_source: Some(prepared.credential_source),
        authenticated_user,
        checkout: GitLabCheckoutBinding::Bound,
        provider: GitLabProviderReadiness::Ready,
        publication: prepared.publication_preference,
        fork_behavior: prepared.fork_behavior,
        target_pipeline: GitLabTargetPipelineTrust::Untrusted,
    });
    match readiness.mode {
        GitLabExecutionMode::Skip => {
            return CanonicalPublication::terminal("skipped", Some("fork_policy"));
        }
        GitLabExecutionMode::ReportOnly => {
            return CanonicalPublication::terminal("report_only", Some("fork_policy"));
        }
        GitLabExecutionMode::Publish => {}
    }
    let (Some(authorization), Some(bot_user_id)) =
        (readiness.publication_authorization(), readiness.bot_user_id)
    else {
        return CanonicalPublication::terminal("unavailable", Some("readiness_failed"));
    };
    if !gitlab_discussions_unchanged(prepared, bot_user_id).await {
        return CanonicalPublication::terminal("unavailable", Some("discussion_changed"));
    }
    let Ok(controller) =
        GitLabPublicationController::new(&prepared.read, write, GitLabPublicationLimits::default())
    else {
        return CanonicalPublication::terminal("failed", Some("invalid_limits"));
    };
    let candidates = publication_candidates(
        report,
        &prepared
            .snapshot
            .evidence()
            .identity
            .version
            .diff_version
            .refs
            .head_sha,
    );
    canonical_gitlab_publication(
        controller
            .publish(
                authorization,
                prepared.snapshot.evidence().identity.clone(),
                &prepared.context.anchors,
                bot_user_id,
                overview,
                candidates,
                &report.authorized_fixed_lineages(),
            )
            .await,
    )
}

fn canonical_gitlab_publication(outcome: GitLabPublicationOutcome) -> CanonicalPublication {
    match outcome {
        GitLabPublicationOutcome::Completed { journal, evidence } => {
            let published_findings = confirmed_gitlab_inline_findings(&journal);
            CanonicalPublication {
                state: "completed",
                reason: None,
                actions_confirmed: u32::try_from(journal.entries.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(evidence.overview_confirmed),
                published_findings,
                mutation_attempts: evidence.mutation_attempts,
                resolved_discussions: evidence.resolved_discussions,
            }
        }
        GitLabPublicationOutcome::GateClosed { evidence } => CanonicalPublication {
            state: "unavailable",
            reason: Some("gate_closed"),
            actions_confirmed: 0,
            published_findings: 0,
            mutation_attempts: evidence.mutation_attempts,
            resolved_discussions: evidence.resolved_discussions,
        },
        GitLabPublicationOutcome::Stopped {
            journal, evidence, ..
        } => {
            let published_findings = journal.as_ref().map_or(0, confirmed_gitlab_inline_findings);
            CanonicalPublication {
                state: "failed",
                reason: Some("publication_stopped"),
                actions_confirmed: journal.as_ref().map_or(0, |value| {
                    u32::try_from(value.entries.len()).unwrap_or(u32::MAX)
                }),
                published_findings,
                mutation_attempts: evidence.mutation_attempts,
                resolved_discussions: evidence.resolved_discussions,
            }
        }
    }
}

fn confirmed_gitlab_inline_findings(journal: &revoot_core::PublicationJournal) -> u32 {
    u32::try_from(
        journal
            .entries
            .iter()
            .filter(|entry| {
                usize::try_from(entry.action)
                    .ok()
                    .and_then(|index| journal.actions.get(index))
                    .is_some_and(|action| {
                        matches!(action.publication.target, PublicationTarget::Inline(_))
                    })
            })
            .count(),
    )
    .unwrap_or(u32::MAX)
}

async fn gitlab_discussions_unchanged(prepared: &PreparedGitLabReview, bot_user_id: u64) -> bool {
    let identity = &prepared.snapshot.evidence().identity.version;
    acquire_gitlab_prior_review(
        &prepared.read,
        identity.scope.project_id,
        identity.scope.merge_request_iid,
        Some(bot_user_id),
        &identity.diff_version.refs.head_sha,
    )
    .await
    .as_ref()
        == Ok(&prepared.prior_review)
}

async fn publish_prepared_review(
    prepared: &PreparedReview,
    report: &CanonicalReviewReport,
    provider: &str,
    model: &str,
    job_url: Option<&str>,
    checkpoint: ReviewCheckpoint,
) -> CanonicalPublication {
    let overview = match render_overview(
        report,
        provider,
        model,
        prepared.head_sha(),
        prepared.commit_url().as_deref(),
        job_url,
        checkpoint,
    ) {
        Ok(overview) => overview,
        Err(publication) => return publication,
    };
    match prepared {
        PreparedReview::GitLab(prepared) => {
            publish_gitlab_review(prepared, report, overview.as_deref()).await
        }
        PreparedReview::GitHub(prepared) => {
            publish_github_review(prepared, report, overview.as_deref()).await
        }
        PreparedReview::Local(_) => {
            if report.findings.is_empty() {
                CanonicalPublication::terminal("not_needed", Some("no_findings"))
            } else {
                CanonicalPublication::terminal("report_only", Some("local_review"))
            }
        }
    }
}

async fn publish_with_checkpoint(
    prepared: &PreparedReview,
    report: &CanonicalReviewReport,
    provider: &str,
    model: &str,
    job_url: Option<&str>,
    generation: u8,
) -> CanonicalPublication {
    let checkpoint = ReviewCheckpoint::current(
        prepared.base_sha().clone(),
        prepared.head_sha().clone(),
        prepared.manifest_sha256().clone(),
        report.checkpoint_complete(),
        generation,
    );
    publish_prepared_review(prepared, report, provider, model, job_url, checkpoint).await
}

async fn publish_github_review(
    prepared: &PreparedGitHubReview,
    report: &CanonicalReviewReport,
    overview: Option<&str>,
) -> CanonicalPublication {
    if prepared.fork {
        return CanonicalPublication::terminal("report_only", Some("fork_policy"));
    }
    if !prepared.publication_enabled {
        return CanonicalPublication::terminal("report_only", Some("publication_disabled"));
    }
    let evidence = match publish_github_findings(
        &prepared.client,
        &prepared.context,
        &publication_candidates(report, &prepared.context.identity.head_sha),
        &prepared.prior_review,
        &report.authorized_fixed_lineages(),
    )
    .await
    {
        Ok(evidence) => evidence,
        Err(failure) => {
            return github_publication_failure(
                failure,
                u32::try_from(report.findings.len()).unwrap_or(u32::MAX),
            );
        }
    };
    let overview_mutated = if let Some(overview) = overview {
        match update_github_overview(&prepared.client, &prepared.context, overview).await {
            Ok(mutated) => mutated,
            Err(_) => {
                return CanonicalPublication {
                    state: "failed",
                    reason: Some("overview_update_failed"),
                    actions_confirmed: evidence.actions_confirmed,
                    published_findings: u32::try_from(report.findings.len())
                        .unwrap_or(u32::MAX)
                        .min(evidence.actions_confirmed),
                    mutation_attempts: evidence.mutation_attempts,
                    resolved_discussions: evidence.superseded_comments,
                };
            }
        }
    } else {
        false
    };
    CanonicalPublication {
        state: "completed",
        reason: (evidence.deferred_thread_resolutions != 0)
            .then_some("github_thread_resolution_unavailable"),
        actions_confirmed: evidence
            .actions_confirmed
            .saturating_add(u32::from(overview.is_some())),
        published_findings: u32::try_from(report.findings.len()).unwrap_or(u32::MAX),
        mutation_attempts: evidence
            .mutation_attempts
            .saturating_add(u32::from(overview_mutated)),
        resolved_discussions: evidence.superseded_comments,
    }
}

const fn github_publication_failure(
    failure: crate::github_review::GitHubPublicationFailure,
    planned_findings: u32,
) -> CanonicalPublication {
    let state = if matches!(failure.error, GitHubReviewError::PublicationStateChanged)
        && failure.evidence.mutation_attempts == 0
    {
        "stopped"
    } else {
        "failed"
    };
    CanonicalPublication {
        state,
        reason: Some(github_publication_failure_reason(failure.error)),
        actions_confirmed: failure.evidence.actions_confirmed,
        published_findings: if failure.evidence.actions_confirmed < planned_findings {
            failure.evidence.actions_confirmed
        } else {
            planned_findings
        },
        mutation_attempts: failure.evidence.mutation_attempts,
        resolved_discussions: failure.evidence.superseded_comments,
    }
}

const fn github_publication_failure_reason(error: GitHubReviewError) -> &'static str {
    match error {
        GitHubReviewError::ThreadResolution => "github_thread_resolution_failed",
        GitHubReviewError::PublicationStale
        | GitHubReviewError::IdentityMismatch
        | GitHubReviewError::CheckoutHeadMismatch
        | GitHubReviewError::PullRequestClosed => "github_pull_request_changed",
        GitHubReviewError::PublicationStateChanged => "github_review_state_changed",
        GitHubReviewError::PublicationAmbiguous => "github_comment_ownership_ambiguous",
        GitHubReviewError::PublicationInventory => "github_comment_inventory_invalid",
        GitHubReviewError::PublicationMutation | GitHubReviewError::Anchor => {
            "github_comment_publication_failed"
        }
        GitHubReviewError::Transport => "github_api_failed",
        GitHubReviewError::Overview => "github_overview_update_failed",
        GitHubReviewError::InvalidPullRequest
        | GitHubReviewError::PaginationLimit
        | GitHubReviewError::InvalidFile
        | GitHubReviewError::DuplicateFile
        | GitHubReviewError::Diff
        | GitHubReviewError::Partition
        | GitHubReviewError::EmptyReview
        | GitHubReviewError::Invocation => "github_publication_failed",
    }
}

fn render_overview(
    report: &CanonicalReviewReport,
    provider: &str,
    model: &str,
    head_sha: &GitSha,
    commit_url: Option<&str>,
    job_url: Option<&str>,
    checkpoint: ReviewCheckpoint,
) -> Result<Option<String>, CanonicalPublication> {
    let Some(overview) = report.overview.as_ref() else {
        return Ok(None);
    };
    let Some(commit_url) = commit_url else {
        return Ok(None);
    };
    let metadata =
        ReviewRunMetadata::try_new(provider, model, head_sha.clone(), commit_url, job_url)
            .map_err(|_| {
                CanonicalPublication::terminal("failed", Some("overview_metadata_invalid"))
            })?
            .with_checkpoint(checkpoint);
    render_review_overview(overview, &metadata)
        .map(Some)
        .map_err(|_| CanonicalPublication::terminal("failed", Some("overview_render_failed")))
}

fn publication_candidates(
    report: &CanonicalReviewReport,
    reviewed_head: &GitSha,
) -> Vec<PublicationCandidate> {
    report
        .findings
        .iter()
        .map(|finding| {
            let marker = revoot_core::FindingLineageMarker::new(
                finding
                    .lineage_id
                    .clone()
                    .unwrap_or_else(|| finding.finding_key.clone()),
                reviewed_head.clone(),
                finding.content_digest.clone(),
            );
            PublicationCandidate {
                target: PublicationTarget::Inline(finding.anchor_id.clone()),
                body: format!("{}\n{}", finding.rendered_body, marker.render()),
            }
        })
        .collect()
}

fn fork_behavior(environment: &[(String, String)]) -> Result<GitLabForkBehavior, Diagnostic> {
    let mut configured = None;
    for (name, value) in environment {
        if name == "REVOOT_FORK_BEHAVIOR" && configured.replace(value.as_str()).is_some() {
            return Err(diagnostic(
                ErrorCode::ContractInvalid,
                "REVOOT_FORK_BEHAVIOR was supplied more than once",
            ));
        }
    }
    match configured.unwrap_or("skip") {
        "report-only" => Ok(GitLabForkBehavior::ReportOnly),
        "skip" => Ok(GitLabForkBehavior::Skip),
        _ => Err(diagnostic(
            ErrorCode::ContractInvalid,
            "REVOOT_FORK_BEHAVIOR is invalid",
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn parse_args(args: impl Iterator<Item = String>) -> Result<Option<ReviewArgs>, Diagnostic> {
    let mut parsed = ReviewArgs::default();
    let mut args = args.peekable();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--ci" => {
                if parsed.ci {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--ci may be supplied only once",
                    ));
                }
                parsed.ci = true;
            }
            "--preview" => {
                if parsed.preview {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--preview may be supplied only once",
                    ));
                }
                parsed.preview = true;
            }
            "--effort" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(ErrorCode::CliInvalidArgument, "--effort requires a value")
                })?;
                let effort = match value.as_str() {
                    "low" => revoot_core::ReviewEffort::Low,
                    "medium" => revoot_core::ReviewEffort::Medium,
                    "high" => revoot_core::ReviewEffort::High,
                    _ => {
                        return Err(diagnostic(
                            ErrorCode::CliInvalidArgument,
                            "--effort must be low, medium, or high",
                        ));
                    }
                };
                if parsed.effort.replace(effort).is_some() {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--effort may be supplied only once",
                    ));
                }
            }
            "--max-parallel-groups" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--max-parallel-groups requires a value",
                    )
                })?;
                let maximum = value.parse::<u8>().map_err(|_| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--max-parallel-groups must be between 1 and 8",
                    )
                })?;
                if !(1..=8).contains(&maximum)
                    || parsed.max_parallel_groups.replace(maximum).is_some()
                {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--max-parallel-groups must be supplied once with a value from 1 to 8",
                    ));
                }
            }
            "--base" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(ErrorCode::CliInvalidArgument, "--base requires a Git ref")
                })?;
                if value.is_empty() || parsed.base_ref.replace(value).is_some() {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--base requires one non-empty Git ref",
                    ));
                }
            }
            "--format" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(ErrorCode::CliInvalidArgument, "--format requires a value")
                })?;
                parsed.format = match value.as_str() {
                    "human" => OutputFormat::Human,
                    "json" => OutputFormat::Json,
                    "sarif" => OutputFormat::Sarif,
                    _ => {
                        return Err(diagnostic(
                            ErrorCode::CliInvalidArgument,
                            "--format must be human, json, or sarif",
                        ));
                    }
                };
            }
            "--output" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(ErrorCode::CliInvalidArgument, "--output requires a path")
                })?;
                if parsed.output.replace(PathBuf::from(value)).is_some() {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--output may be supplied only once",
                    ));
                }
            }
            "--mr" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(ErrorCode::CliInvalidArgument, "--mr requires an IID")
                })?;
                let iid = value.parse::<u64>().map_err(|_| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--mr requires a positive integer IID",
                    )
                })?;
                let iid = MergeRequestIid::try_from(iid).map_err(|_| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--mr requires a positive integer IID",
                    )
                })?;
                if parsed.merge_request_iid.replace(iid).is_some() {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--mr may be supplied only once",
                    ));
                }
            }
            "--pr" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(ErrorCode::CliInvalidArgument, "--pr requires a number")
                })?;
                let number = value.parse::<u64>().map_err(|_| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--pr requires a positive integer",
                    )
                })?;
                let number = PullRequestNumber::try_from(number).map_err(|_| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--pr requires a positive integer",
                    )
                })?;
                if parsed.pull_request_number.replace(number).is_some() {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--pr may be supplied only once",
                    ));
                }
            }
            "--repo" => {
                let value = args.next().ok_or_else(|| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--repo requires OWNER/REPOSITORY",
                    )
                })?;
                let repository = GitHubRepositorySlug::parse(value).map_err(|_| {
                    diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--repo requires a valid OWNER/REPOSITORY",
                    )
                })?;
                if parsed.github_repository.replace(repository).is_some() {
                    return Err(diagnostic(
                        ErrorCode::CliInvalidArgument,
                        "--repo may be supplied only once",
                    ));
                }
            }
            "--help" | "-h" => return Ok(None),
            _ => {
                return Err(diagnostic(
                    ErrorCode::CliInvalidArgument,
                    format!("unknown review option: {argument}"),
                ));
            }
        }
    }
    if parsed.merge_request_iid.is_some()
        && (parsed.pull_request_number.is_some() || parsed.github_repository.is_some())
    {
        return Err(diagnostic(
            ErrorCode::CliInvalidArgument,
            "--mr cannot be combined with --pr or --repo",
        ));
    }
    if parsed.base_ref.is_some()
        && (parsed.ci
            || parsed.merge_request_iid.is_some()
            || parsed.pull_request_number.is_some()
            || parsed.github_repository.is_some())
    {
        return Err(diagnostic(
            ErrorCode::CliInvalidArgument,
            "--base cannot be combined with --ci, --mr, --pr, or --repo",
        ));
    }
    if parsed.preview && parsed.format == OutputFormat::Sarif {
        return Err(diagnostic(
            ErrorCode::CliInvalidArgument,
            "review preview supports human or json output, not sarif",
        ));
    }
    Ok(Some(parsed))
}

fn configured_github_server(
    environment: &[(String, String)],
) -> Result<Option<GitHubServer>, Diagnostic> {
    let mut values = environment
        .iter()
        .filter(|(name, _)| name == "REVOOT_GITHUB_SERVER_URL")
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(diagnostic(
            ErrorCode::CliInvalidArgument,
            "REVOOT_GITHUB_SERVER_URL is defined more than once",
        ));
    }
    GitHubServer::from_web_origin(value).map(Some).map_err(|_| {
        diagnostic(
            ErrorCode::CliInvalidArgument,
            "REVOOT_GITHUB_SERVER_URL must be an HTTPS origin",
        )
    })
}

fn select_provider(
    configured: &str,
    credentials: &DiscoveredCredentials,
) -> Result<String, Diagnostic> {
    crate::direct_provider::select_provider(configured, credentials)
}

fn select_model(provider: &str, configured: &str) -> Result<String, Diagnostic> {
    crate::direct_provider::select_model(provider, configured)
}

fn build_provider(
    provider: &str,
    credentials: &DiscoveredCredentials,
) -> Result<Box<dyn ProviderAdapter>, Diagnostic> {
    crate::direct_provider::build_provider(provider, credentials)
}

fn agent_limits(
    resolution: &revoot_core::ConfigurationResolution,
    strategy: &ReviewStrategyConfiguration,
) -> Result<AgentBudgetLimits, Diagnostic> {
    let budget = &strategy.aggregate_budget;
    let max_findings = u32_value(resolution, "budget.max_findings")?;
    Ok(AgentBudgetLimits {
        max_turns: budget.max_model_requests,
        max_model_requests: budget.max_model_requests,
        max_candidate_findings: max_findings,
        max_elapsed_millis: budget.max_elapsed_millis,
        max_input_tokens: budget.max_model_tokens,
        max_output_tokens: budget.max_output_tokens,
        max_tool_calls: budget.max_tool_calls,
        max_cost_microusd: budget.max_cost_microusd,
        ..AgentBudgetLimits::default()
    })
}

fn typed_review_strategy(
    resolved: &ResolvedReviewConfiguration,
) -> Result<ReviewStrategyConfiguration, Diagnostic> {
    strategy_from_resolved(resolved)
        .map_err(|error| diagnostic(ErrorCode::ContractInvalid, error.to_string()))
}

pub(crate) fn partition_limits(
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

pub(crate) fn selection_policy(
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
    policy.validate().map_err(|_| {
        diagnostic(
            ErrorCode::ContractInvalid,
            "review path selection patterns are invalid",
        )
    })?;
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
            exact.insert(RepositoryPath::try_from(pattern.clone()).map_err(|_| {
                diagnostic(
                    ErrorCode::ContractInvalid,
                    "review path selection pattern is invalid",
                )
            })?);
        } else {
            return Err(diagnostic(
                ErrorCode::ContractInvalid,
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

fn diff_limits(
    resolution: &revoot_core::ConfigurationResolution,
) -> Result<UnifiedDiffLimits, Diagnostic> {
    let context_radius_lines = u32_value(resolution, "review.context_lines")?;
    Ok(UnifiedDiffLimits {
        context_radius_lines,
        ..UnifiedDiffLimits::default()
    })
}

struct CodeHostNetworkPolicy {
    custom_ca: Option<CustomCaMaterial>,
    private_cidrs: Vec<IpCidr>,
}

struct CustomCaMaterial {
    certificates: Vec<Vec<u8>>,
    digest: [u8; 32],
}

fn code_host_network_policy(
    resolution: &revoot_core::ConfigurationResolution,
    host: &str,
) -> Result<CodeHostNetworkPolicy, Diagnostic> {
    let private_cidr_key = format!("network.{host}_private_cidrs");
    let ca_bundle_key = format!("network.{host}_ca_bundle_file");
    let private_cidrs = config_string_list(resolution, &private_cidr_key)?
        .iter()
        .map(|value| parse_private_cidr(value))
        .collect::<Result<Vec<_>, _>>()?;
    let ca_path = config_string(resolution, &ca_bundle_key)?;
    if ca_path.is_empty() {
        return Ok(CodeHostNetworkPolicy {
            custom_ca: None,
            private_cidrs,
        });
    }
    let certificates = read_ca_certificates(Path::new(ca_path))?;
    let mut hasher = Sha256::new();
    for certificate in &certificates {
        let length = u64::try_from(certificate.len()).map_err(|_| code_host_network_error())?;
        hasher.update(length.to_be_bytes());
        hasher.update(certificate);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(CodeHostNetworkPolicy {
        custom_ca: Some(CustomCaMaterial {
            certificates,
            digest,
        }),
        private_cidrs,
    })
}

fn parse_private_cidr(value: &str) -> Result<IpCidr, Diagnostic> {
    let (address, prefix) = value.split_once('/').ok_or_else(code_host_network_error)?;
    if address.is_empty() || prefix.is_empty() || prefix.starts_with('+') || prefix.starts_with('0')
    {
        return Err(code_host_network_error());
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| code_host_network_error())?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| code_host_network_error())?;
    IpCidr::private(address, prefix).map_err(|_| code_host_network_error())
}

fn read_ca_certificates(path: &Path) -> Result<Vec<Vec<u8>>, Diagnostic> {
    if !path.is_absolute() {
        return Err(code_host_network_error());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| code_host_network_error())?;
    let metadata = file.metadata().map_err(|_| code_host_network_error())?;
    if !metadata.is_file() || metadata.len() > MAX_CODE_HOST_CA_BUNDLE_BYTES {
        return Err(code_host_network_error());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len().min(MAX_CODE_HOST_CA_BUNDLE_BYTES)).unwrap_or(0),
    );
    Read::by_ref(&mut file)
        .take(MAX_CODE_HOST_CA_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| code_host_network_error())?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CODE_HOST_CA_BUNDLE_BYTES
    {
        return Err(code_host_network_error());
    }
    if bytes.starts_with(b"-----BEGIN ") {
        <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(&bytes)
            .map(|item| {
                let (kind, der) = item.map_err(|_| code_host_network_error())?;
                match kind {
                    SectionKind::Certificate => Ok(der),
                    _ => Err(code_host_network_error()),
                }
            })
            .collect()
    } else {
        Ok(vec![bytes])
    }
}

fn code_host_network_error() -> Diagnostic {
    diagnostic(
        ErrorCode::ContractInvalid,
        "self-managed code-host network configuration is invalid",
    )
    .with_remediation(
        "use an absolute CA bundle path and canonical private CIDRs such as 10.20.0.0/16",
    )
}

fn config_string<'a>(
    resolution: &'a revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<&'a str, Diagnostic> {
    match resolution.effective().get(key) {
        Some(ConfigValue::String(value)) => Ok(value),
        _ => Err(diagnostic(
            ErrorCode::ContractInvalid,
            "effective review configuration is invalid",
        )),
    }
}

fn config_string_list<'a>(
    resolution: &'a revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<&'a [String], Diagnostic> {
    match resolution.effective().get(key) {
        Some(ConfigValue::StringList(value)) => Ok(value),
        _ => Err(diagnostic(
            ErrorCode::ContractInvalid,
            "effective review configuration is invalid",
        )),
    }
}

fn config_unsigned(
    resolution: &revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<u64, Diagnostic> {
    match resolution.effective().get(key) {
        Some(ConfigValue::Unsigned(value)) => Ok(*value),
        _ => Err(diagnostic(
            ErrorCode::ContractInvalid,
            "effective review configuration is invalid",
        )),
    }
}

fn config_bool(
    resolution: &revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<bool, Diagnostic> {
    match resolution.effective().get(key) {
        Some(ConfigValue::Bool(value)) => Ok(*value),
        _ => Err(diagnostic(
            ErrorCode::ContractInvalid,
            "effective review configuration is invalid",
        )),
    }
}

fn u32_value(
    resolution: &revoot_core::ConfigurationResolution,
    key: &str,
) -> Result<u32, Diagnostic> {
    u32::try_from(config_unsigned(resolution, key)?).map_err(|_| {
        diagnostic(
            ErrorCode::ContractInvalid,
            "effective review configuration exceeds supported limits",
        )
    })
}

fn utf8_environment(environment: &[(OsString, OsString)]) -> Vec<(String, String)> {
    environment
        .iter()
        .filter_map(|(name, value)| Some((name.to_str()?.to_owned(), value.to_str()?.to_owned())))
        .collect()
}

fn ci_job_url(
    environment: &[(String, String)],
    prepared: &PreparedReview,
) -> Result<Option<String>, Diagnostic> {
    match prepared {
        PreparedReview::GitLab(prepared) => {
            let Some(job_url) = exact_environment_value(environment, "CI_JOB_URL")? else {
                return Ok(None);
            };
            validate_bound_job_url(
                job_url,
                prepared.context.checkout.repository.remote.origin.as_str(),
                "GitLab CI job",
            )
            .map(Some)
        }
        PreparedReview::GitHub(prepared) => {
            let Some(run_id) = exact_environment_value(environment, "GITHUB_RUN_ID")? else {
                return Ok(None);
            };
            if matches!(run_id.parse::<u64>(), Ok(0) | Err(_)) {
                return Err(diagnostic(
                    ErrorCode::ContractInvalid,
                    "GitHub Actions run identity is invalid",
                ));
            }
            Ok(Some(format!(
                "{}/{}/actions/runs/{run_id}",
                prepared.context.repository.remote.server.web_origin,
                prepared.context.target_repository.as_str(),
            )))
        }
        PreparedReview::Local(_) => Ok(None),
    }
}

fn validate_bound_job_url(
    job_url: String,
    code_host_origin: &str,
    label: &str,
) -> Result<String, Diagnostic> {
    let expected_prefix = format!("{}/", code_host_origin.trim_end_matches('/'));
    if !job_url.starts_with(&expected_prefix) {
        return Err(diagnostic(
            ErrorCode::ContractInvalid,
            format!("{label} URL is not bound to the reviewed code host"),
        ));
    }
    Ok(job_url)
}

fn exact_environment_value(
    environment: &[(String, String)],
    name: &str,
) -> Result<Option<String>, Diagnostic> {
    let mut selected = None;
    for (_, value) in environment
        .iter()
        .filter(|(candidate, _)| candidate == name)
    {
        if value.is_empty() || selected.replace(value.clone()).is_some() {
            return Err(diagnostic(
                ErrorCode::ContractInvalid,
                format!("{name} is invalid or duplicated"),
            ));
        }
    }
    Ok(selected)
}

fn gitlab_diff_base_sha(environment: &[(String, String)]) -> Result<Option<GitSha>, Diagnostic> {
    let mut selected = None;
    for (name, value) in environment {
        if name == "CI_MERGE_REQUEST_DIFF_BASE_SHA" && selected.replace(value.as_str()).is_some() {
            return Err(diagnostic(
                ErrorCode::RepositoryUnavailable,
                "CI_MERGE_REQUEST_DIFF_BASE_SHA was supplied more than once",
            ));
        }
    }
    selected
        .map(|value| {
            GitSha::try_from(value.to_owned()).map_err(|_| {
                diagnostic(
                    ErrorCode::RepositoryUnavailable,
                    "CI_MERGE_REQUEST_DIFF_BASE_SHA is invalid",
                )
            })
        })
        .transpose()
}

fn emit_report(
    args: &ReviewArgs,
    provider: &str,
    model: &str,
    report: &CanonicalReviewReport,
) -> Result<(), Diagnostic> {
    let output = match args.format {
        OutputFormat::Human => format!("{}\n", report.human_summary()),
        OutputFormat::Json => {
            if let Some(stable) = &report.stable_report {
                String::from_utf8(stable.canonical_json().map_err(|_| {
                    diagnostic(
                        ErrorCode::ContractInvalid,
                        "review report serialization failed",
                    )
                })?)
                .map(|value| format!("{value}\n"))
                .map_err(|_| {
                    diagnostic(
                        ErrorCode::ContractInvalid,
                        "review report serialization failed",
                    )
                })?
            } else {
                serde_json::to_string_pretty(&ReviewOutput {
                    schema_version: TERMINAL_REPORT_SCHEMA_VERSION,
                    provider,
                    model,
                    review: report,
                })
                .map(|value| format!("{value}\n"))
                .map_err(|_| {
                    diagnostic(
                        ErrorCode::ContractInvalid,
                        "review report serialization failed",
                    )
                })?
            }
        }
        OutputFormat::Sarif => render_sarif(report)?,
    };
    if let Some(path) = &args.output {
        write_report_atomically(path, output.as_bytes()).map_err(|_| {
            diagnostic(
                ErrorCode::RepositoryUnavailable,
                "review report output could not be written",
            )
        })?;
    } else {
        print!("{output}");
    }
    Ok(())
}

fn emit_preview(args: &ReviewArgs, preview: &ReviewPreview) -> Result<(), Diagnostic> {
    let output = match args.format {
        OutputFormat::Human => preview.human(),
        OutputFormat::Json => String::from_utf8(preview.canonical_json().map_err(|_| {
            diagnostic(
                ErrorCode::ContractInvalid,
                "review preview serialization failed",
            )
        })?)
        .map(|value| format!("{value}\n"))
        .map_err(|_| {
            diagnostic(
                ErrorCode::ContractInvalid,
                "review preview serialization produced invalid UTF-8",
            )
        })?,
        OutputFormat::Sarif => {
            return Err(diagnostic(
                ErrorCode::CliInvalidArgument,
                "review preview supports human or json output, not sarif",
            ));
        }
    };
    if let Some(path) = &args.output {
        write_report_atomically(path, output.as_bytes()).map_err(|_| {
            diagnostic(
                ErrorCode::RepositoryUnavailable,
                "review preview output could not be written",
            )
        })?;
    } else {
        print!("{output}");
    }
    Ok(())
}

fn render_sarif(report: &CanonicalReviewReport) -> Result<String, Diagnostic> {
    let stable = report.stable_report.as_ref().ok_or_else(|| {
        diagnostic(
            ErrorCode::ContractInvalid,
            "SARIF requires a canonical exact-anchor review report",
        )
    })?;
    let anchors = report.sarif_anchors.as_ref().ok_or_else(|| {
        diagnostic(
            ErrorCode::ContractInvalid,
            "SARIF requires the trusted review anchor table",
        )
    })?;
    let log = render_report_v3_sarif(stable, anchors).map_err(|_| {
        diagnostic(
            ErrorCode::ContractInvalid,
            "SARIF exact-anchor validation failed",
        )
    })?;
    String::from_utf8(
        log.canonical_json()
            .map_err(|_| diagnostic(ErrorCode::ContractInvalid, "SARIF serialization failed"))?,
    )
    .map(|value| format!("{value}\n"))
    .map_err(|_| diagnostic(ErrorCode::ContractInvalid, "SARIF serialization failed"))
}

fn write_report_atomically(path: &Path, output: &[u8]) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    for attempt in 0_u8..32 {
        let temporary = parent.join(format!(
            ".{}.revoot-tmp-{}-{attempt}",
            name.to_string_lossy(),
            std::process::id()
        ));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        if let Err(error) = file.write_all(output).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        drop(file);
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        return Ok(());
    }
    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
}

fn diagnostic(code: ErrorCode, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(code, message)
}

fn print_help() {
    println!(
        "USAGE:\n  revoot review [--base REF] [--preview] [--effort low|medium|high] [--max-parallel-groups 1-8] [--format human|json|sarif] [--output PATH]\n  revoot review --ci [--preview] [--format human|json|sarif] [--output PATH]\n  revoot review --mr IID | --pr NUMBER [--repo OWNER/REPOSITORY]"
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use revoot_core::provider::{ProviderAdapter, ProviderFuture};
    use revoot_core::{
        AgentBudgetLimits, AgentBudgetUsage, AnchorId, CancellationToken, ErrorCode,
        FindingCategory, MergeRequestIid, ModelContent, ModelFinishReason, ModelRequest,
        ModelResponse, ModelUsage, PullRequestNumber, RankedFinding, ReviewOutcome,
        ReviewReportPhase, Severity, Sha256Digest,
    };

    use crate::config::{
        RepositoryReviewPolicy, RepositorySuppression, resolve_review_configuration,
    };
    use crate::github_review::{
        GitHubPublicationEvidence, GitHubPublicationFailure, GitHubReviewError,
    };
    use crate::review_overview::RiskLevel;
    use serde_json::json;

    use super::{
        CanonicalPublication, CanonicalReviewReport, CanonicalSelection, OutputFormat,
        ReviewOutput, TERMINAL_REPORT_SCHEMA_VERSION, agent_limits, apply_repository_suppressions,
        diff_limits, fork_behavior, github_publication_failure, minimum_review_risk, parse_args,
        parse_private_cidr, partition_limits, run_prepared_tool_first_engine, select_model,
        selection_policy, typed_review_strategy, validate_bound_job_url, write_report_atomically,
    };

    static LOCAL_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn github_review_state_change_is_non_failing_only_before_mutation() {
        let stopped = github_publication_failure(
            GitHubPublicationFailure {
                error: GitHubReviewError::PublicationStateChanged,
                evidence: GitHubPublicationEvidence::default(),
            },
            1,
        );
        assert_eq!(stopped.state, "stopped");
        assert_eq!(stopped.reason, Some("github_review_state_changed"));
        assert_eq!(stopped.mutation_attempts, 0);
        assert!(!stopped.failed());

        let partial = github_publication_failure(
            GitHubPublicationFailure {
                error: GitHubReviewError::PublicationStateChanged,
                evidence: GitHubPublicationEvidence {
                    actions_confirmed: 1,
                    mutation_attempts: 2,
                    superseded_comments: 1,
                    ..GitHubPublicationEvidence::default()
                },
            },
            2,
        );
        assert_eq!(partial.state, "failed");
        assert_eq!(partial.actions_confirmed, 1);
        assert_eq!(partial.mutation_attempts, 2);
        assert_eq!(partial.resolved_discussions, 1);
        assert!(partial.failed());
    }

    struct CleanLocalRepository(PathBuf);

    impl CleanLocalRepository {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "revoot-review-command-local-{}-{}",
                std::process::id(),
                LOCAL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).expect("local repository fixture");
            for arguments in [
                vec!["init", "-b", "main"],
                vec!["config", "user.email", "revoot@example.invalid"],
                vec!["config", "user.name", "Revoot Test"],
                vec!["config", "commit.gpgsign", "false"],
            ] {
                git(&root, &arguments);
            }
            fs::write(root.join("README.md"), "# clean\n").expect("fixture file");
            git(&root, &["add", "."]);
            git(&root, &["commit", "-m", "base"]);
            Self(root)
        }
    }

    impl Drop for CleanLocalRepository {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct CommandToolFirstProvider {
        calls: AtomicUsize,
    }

    impl ProviderAdapter for CommandToolFirstProvider {
        fn adapter_id(&self) -> &'static str {
            "command-tool-first-fake"
        }

        fn complete<'a>(
            &'a self,
            _request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(ModelResponse {
                    provider_response_id: None,
                    model: "model-v1".to_owned(),
                    content: vec![ModelContent::ToolUse {
                        id: "complete-1".to_owned(),
                        name: "complete_group".to_owned(),
                        input: json!({
                            "checkpoint": {
                                "hypotheses": [],
                                "evidence_references": [],
                                "unresolved_coverage": []
                            },
                            "summary": {"text": "reviewed", "assumptions": []}
                        }),
                    }],
                    finish_reason: ModelFinishReason::ToolUse,
                    usage: ModelUsage::default(),
                })
            })
        }
    }

    #[tokio::test]
    async fn command_boundary_dispatches_selected_local_work_to_tool_first_engine() {
        let repository = CleanLocalRepository::new();
        fs::write(repository.0.join("README.md"), "# changed\n").expect("changed fixture");
        let capture =
            crate::local_review::capture_local_git(&repository.0, None).expect("local snapshot");
        let base_sha = capture.identity.base_sha.clone();
        let resolved = resolve_review_configuration(
            &capture.root,
            Some(&base_sha),
            None,
            [(
                OsString::from("REVOOT_REVIEW_EFFORT"),
                OsString::from("low"),
            )],
        )
        .expect("configuration");
        let strategy = typed_review_strategy(&resolved).expect("strategy");
        let context = crate::local_review::build_local_review_context(
            capture,
            &crate::local_review::LocalReviewContextOptions {
                provider_adapter: "command-tool-first-fake".to_owned(),
                model_id: "model-v1".to_owned(),
                agent_limits: agent_limits(&resolved.effective, &strategy).expect("agent limits"),
                diff_limits: diff_limits(&resolved.effective).expect("diff limits"),
                selection_policy: selection_policy(&resolved.effective, &resolved.repository)
                    .expect("selection policy"),
                partition_limits: partition_limits(&resolved.effective).expect("partition limits"),
            },
        )
        .expect("local review context");
        let prepared =
            super::PreparedReview::Local(Box::new(super::PreparedLocalReview { context }));
        assert!(!prepared.partition().work_units.is_empty());
        let provider = Arc::new(CommandToolFirstProvider {
            calls: AtomicUsize::new(0),
        });
        let report = run_prepared_tool_first_engine(
            &prepared,
            &resolved,
            &strategy,
            "model-v1",
            provider.clone(),
        )
        .await
        .expect("tool-first command execution");
        assert_eq!(report.group_count, 1);
        assert!(matches!(
            report.result.outcome,
            ReviewOutcome::NoFindings { .. }
        ));
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            report
                .phase_usage
                .iter()
                .map(|usage| usage.phase)
                .collect::<Vec<_>>(),
            vec![
                ReviewReportPhase::Grouping,
                ReviewReportPhase::Planning,
                ReviewReportPhase::Review,
                ReviewReportPhase::Verification,
                ReviewReportPhase::Adjudication,
            ]
        );
    }

    fn git(root: &Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(arguments)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("git")
                .success()
        );
    }

    fn fork_gitlab_environment() -> Vec<(OsString, OsString)> {
        [
            ("CI_SERVER_URL", "https://gitlab.example.com"),
            ("CI_PIPELINE_SOURCE", "merge_request_event"),
            ("CI_PROJECT_ID", "99"),
            ("CI_PROJECT_PATH", "contributor/project"),
            ("CI_MERGE_REQUEST_PROJECT_ID", "42"),
            ("CI_MERGE_REQUEST_PROJECT_PATH", "group/project"),
            ("CI_MERGE_REQUEST_IID", "7"),
            ("CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "99"),
            (
                "CI_MERGE_REQUEST_SOURCE_PROJECT_PATH",
                "contributor/project",
            ),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "feature/fork"),
            ("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main"),
            ("CI_MERGE_REQUEST_EVENT_TYPE", "detached"),
            ("CI_COMMIT_SHA", "0123456789abcdef0123456789abcdef01234567"),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", ""),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect()
    }

    #[test]
    fn changed_file_selection_limits_do_not_cap_repository_exploration() {
        let repository = CleanLocalRepository::new();
        let resolved = resolve_review_configuration(
            &repository.0,
            None,
            None,
            [
                (OsString::from("REVOOT_MAX_FILES"), OsString::from("1")),
                (
                    OsString::from("REVOOT_MAX_INPUT_BYTES"),
                    OsString::from("1"),
                ),
            ],
        )
        .expect("configuration resolves");

        let selection = partition_limits(&resolved.effective).expect("selection limits");
        assert_eq!(selection.max_files, 1);
        assert_eq!(selection.max_total_bytes, 1);

        let strategy = typed_review_strategy(&resolved).expect("strategy");
        let exploration = agent_limits(&resolved.effective, &strategy).expect("agent limits");
        let defaults = AgentBudgetLimits::default();
        assert_eq!(
            exploration.max_repository_files,
            defaults.max_repository_files
        );
        assert_eq!(
            exploration.max_repository_bytes,
            defaults.max_repository_bytes
        );
        assert_eq!(exploration.max_input_tokens, 2_000_000);
        assert_eq!(exploration.max_output_tokens, 64 * 4_096);
    }

    #[test]
    fn parser_exposes_output_and_bounded_review_strategy() {
        let parsed = parse_args(
            [
                "--ci",
                "--mr",
                "17",
                "--format",
                "json",
                "--output",
                "report.json",
                "--preview",
                "--effort",
                "high",
                "--max-parallel-groups",
                "8",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("arguments")
        .expect("not help");
        assert_eq!(parsed.format, OutputFormat::Json);
        assert!(parsed.output.is_some());
        assert!(parsed.preview);
        assert_eq!(parsed.effort, Some(revoot_core::ReviewEffort::High));
        assert_eq!(parsed.max_parallel_groups, Some(8));
        assert_eq!(parsed.merge_request_iid.map(MergeRequestIid::get), Some(17));
        assert!(parsed.pull_request_number.is_none());
        let github = parse_args(["--pr", "9"].into_iter().map(str::to_owned))
            .expect("GitHub arguments")
            .expect("not help");
        assert_eq!(
            github.pull_request_number.map(PullRequestNumber::get),
            Some(9)
        );
        let selected = parse_args(
            ["--pr", "9", "--repo", "getrevoot/revoot"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("selected GitHub arguments")
        .expect("not help");
        assert_eq!(
            selected.github_repository.expect("repository").as_str(),
            "getrevoot/revoot"
        );
        assert!(parse_args(["--depth".to_owned()].into_iter()).is_err());
        assert!(parse_args(["--effort", "extreme"].into_iter().map(str::to_owned)).is_err());
        assert!(
            parse_args(
                ["--max-parallel-groups", "9"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
        let local = parse_args(["--base", "origin/release"].into_iter().map(str::to_owned))
            .expect("local arguments")
            .expect("not help");
        assert_eq!(local.base_ref.as_deref(), Some("origin/release"));
        assert!(parse_args(["--base", "main", "--ci"].into_iter().map(str::to_owned)).is_err());
    }

    #[test]
    fn zero_argument_clean_local_review_needs_no_code_host_or_provider_credential() {
        let repository = CleanLocalRepository::new();
        let exit = super::run(
            std::iter::empty(),
            std::iter::empty::<(std::ffi::OsString, std::ffi::OsString)>(),
            &repository.0,
        )
        .expect("clean local review succeeds");
        assert_eq!(exit, 0);
    }

    #[test]
    fn clean_local_review_emits_valid_v3_json_and_empty_exact_anchor_sarif() {
        let repository = CleanLocalRepository::new();
        let outputs = tempfile::tempdir().expect("output directory");
        let json_output = outputs.path().join("review.json");
        let sarif_output = outputs.path().join("review.sarif");
        for (format, output) in [("json", &json_output), ("sarif", &sarif_output)] {
            let exit = super::run(
                [
                    "--format".to_owned(),
                    format.to_owned(),
                    "--output".to_owned(),
                    output.to_string_lossy().into_owned(),
                ]
                .into_iter(),
                std::iter::empty::<(OsString, OsString)>(),
                &repository.0,
            )
            .expect("clean local report");
            assert_eq!(exit, 0);
        }

        let report: revoot_core::ReviewReportV3 =
            serde_json::from_slice(&fs::read(json_output).expect("JSON report"))
                .expect("version-3 report");
        report.validate().expect("valid report");
        assert_eq!(report.state, revoot_core::ReviewReportState::NoFindings);
        assert!(report.findings.is_empty());
        let sarif: serde_json::Value =
            serde_json::from_slice(&fs::read(sarif_output).expect("SARIF report"))
                .expect("SARIF JSON");
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(
            sarif["runs"][0]["results"].as_array().map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn binary_only_local_review_uses_no_provider_credential() {
        let repository = CleanLocalRepository::new();
        fs::write(repository.0.join("artifact.bin"), [0_u8, 1, 2, 3]).expect("binary fixture");
        let exit = super::run(
            std::iter::empty(),
            std::iter::empty::<(std::ffi::OsString, std::ffi::OsString)>(),
            &repository.0,
        )
        .expect("binary-only review succeeds");
        assert_eq!(exit, 0);
    }

    #[test]
    fn local_preview_needs_no_selected_provider_credential() {
        let repository = CleanLocalRepository::new();
        fs::write(
            repository.0.join("README.md"),
            "# changed without a provider credential\n",
        )
        .expect("changed fixture");
        let output = repository.0.join("preview.json");
        let exit = super::run(
            [
                "--preview".to_owned(),
                "--format".to_owned(),
                "json".to_owned(),
                "--output".to_owned(),
                output.to_string_lossy().into_owned(),
            ]
            .into_iter(),
            [(OsString::from("REVOOT_PROVIDER"), OsString::from("openai"))],
            &repository.0,
        )
        .expect("preview returns before provider credential discovery");
        assert_eq!(exit, 0);

        let preview: serde_json::Value =
            serde_json::from_slice(&fs::read(&output).expect("preview output"))
                .expect("preview json");
        assert_eq!(
            preview["schema_version"],
            revoot_core::ReviewPreview::SCHEMA_VERSION
        );
        assert_eq!(preview["grouping_source"], "deterministic_fallback");
        assert_eq!(preview["groups"].as_array().map(Vec::len), Some(1));
        assert!(preview.get("provider").is_none());
        assert!(preview.get("model").is_none());
    }

    #[test]
    fn parser_rejects_sarif_preview_before_review_preparation() {
        let error = parse_args(
            ["--preview", "--format", "sarif"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect_err("SARIF preview is unsupported");
        assert_eq!(error.code, ErrorCode::CliInvalidArgument);
    }

    #[test]
    fn skipped_gitlab_fork_needs_no_checkout_code_host_or_provider_credential() {
        let sequence = LOCAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let output = std::env::temp_dir().join(format!(
            "revoot-skipped-gitlab-fork-{}-{sequence}.json",
            std::process::id()
        ));
        let missing_checkout = std::env::temp_dir().join(format!(
            "revoot-missing-gitlab-checkout-{}-{sequence}",
            std::process::id()
        ));
        let exit = super::run(
            [
                "--ci".to_owned(),
                "--format".to_owned(),
                "json".to_owned(),
                "--output".to_owned(),
                output.to_string_lossy().into_owned(),
            ]
            .into_iter(),
            fork_gitlab_environment(),
            &missing_checkout,
        )
        .expect("default fork policy skips before external acquisition");
        assert_eq!(exit, 0);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&output).expect("skipped report"))
                .expect("terminal JSON");
        assert_eq!(report["schema_version"], TERMINAL_REPORT_SCHEMA_VERSION);
        assert_eq!(report["provider"], "not_used");
        assert_eq!(report["review"]["state"], "skipped");
        assert_eq!(report["review"]["publication"]["reason"], "fork_policy");
        fs::remove_file(output).expect("remove skipped report");
    }

    #[test]
    fn automatic_model_alias_is_internal_to_provider_selection() {
        assert_ne!(select_model("anthropic", "auto").expect("catalog"), "auto");
        assert_ne!(select_model("openai", "auto").expect("catalog"), "auto");
        assert_eq!(
            select_model("anthropic", "custom").expect("explicit"),
            "custom"
        );
        assert!(select_model("unknown", "auto").is_err());
    }

    #[test]
    fn private_network_exceptions_are_canonical_and_private_only() {
        assert!(parse_private_cidr("10.20.0.0/16").is_ok());
        assert!(parse_private_cidr("fd00::/8").is_ok());
        assert!(parse_private_cidr("10.20.1.0/16").is_err());
        assert!(parse_private_cidr("10.20.0.0/016").is_err());
        assert!(parse_private_cidr("8.8.8.0/24").is_err());
    }

    #[test]
    fn ci_job_links_are_bound_to_the_reviewed_code_host() {
        assert_eq!(
            validate_bound_job_url(
                "https://gitlab.example.com/acme/revoot/-/jobs/42".to_owned(),
                "https://gitlab.example.com",
                "GitLab CI job",
            )
            .expect("bound URL"),
            "https://gitlab.example.com/acme/revoot/-/jobs/42"
        );
        assert!(
            validate_bound_job_url(
                "https://gitlab.example.com.evil.invalid/jobs/42".to_owned(),
                "https://gitlab.example.com",
                "GitLab CI job",
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_silent_report_omits_a_findings_payload() {
        let review = CanonicalReviewReport {
            stable_report: None,
            sarif_anchors: None,
            state: "no_findings",
            overview: None,
            summary: Some("No supported defects found.".to_owned()),
            findings: Vec::new(),
            omissions: Vec::new(),
            prior_finding_dispositions: Vec::new(),
            duplicates_omitted: 0,
            usage: AgentBudgetUsage::default(),
            turns: 2,
            tool_calls: 3,
            admitted_candidates: 0,
            suppressed_candidates: 0,
            strategy: None,
            coverage: None,
            selection: CanonicalSelection::default(),
            publication: CanonicalPublication::terminal("not_needed", Some("no_findings")),
            finding_locations: BTreeMap::new(),
        };
        let encoded = serde_json::to_string(&ReviewOutput {
            schema_version: TERMINAL_REPORT_SCHEMA_VERSION,
            provider: "anthropic",
            model: "model",
            review: &review,
        })
        .expect("report");
        assert!(!encoded.contains("\"findings\":"));
        assert!(encoded.contains("no_findings"));
        assert!(encoded.contains("\"selection\":"));
        assert!(super::render_sarif(&review).is_err());
    }

    #[test]
    fn fork_behavior_is_bounded_and_defaults_safe() {
        assert_eq!(
            fork_behavior(&[]).expect("default"),
            crate::gitlab_ci_runtime::GitLabForkBehavior::Skip
        );
        assert_eq!(
            fork_behavior(&[("REVOOT_FORK_BEHAVIOR".to_owned(), "skip".to_owned())]).expect("skip"),
            crate::gitlab_ci_runtime::GitLabForkBehavior::Skip
        );
        assert!(
            fork_behavior(&[("REVOOT_FORK_BEHAVIOR".to_owned(), "unbounded".to_owned())]).is_err()
        );
    }

    #[test]
    fn exact_repository_suppression_removes_only_the_matching_finding() {
        let suppressed = Sha256Digest::try_from("a".repeat(64)).unwrap();
        let retained = Sha256Digest::try_from("b".repeat(64)).unwrap();
        let finding = |finding_key: Sha256Digest| RankedFinding {
            work_unit_id: "unit".to_owned(),
            anchor_id: AnchorId::try_from(format!("ga1_{}", "c".repeat(64))).unwrap(),
            severity: Severity::High,
            confidence_percent: 95,
            category: FindingCategory::Correctness,
            finding_key,
            content_digest: Sha256Digest::try_from("d".repeat(64)).unwrap(),
            lineage_id: None,
            rendered_body: "bounded finding".to_owned(),
        };
        let mut findings = vec![finding(suppressed.clone()), finding(retained.clone())];
        let policy = RepositoryReviewPolicy {
            suppressions: vec![RepositorySuppression {
                fingerprint: suppressed,
                reason: "tracked false positive".to_owned(),
                expires: "2099-12-31".to_owned(),
                ticket: None,
            }],
            ..RepositoryReviewPolicy::default()
        };
        assert_eq!(apply_repository_suppressions(&mut findings, &policy), 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_key, retained);
    }

    #[test]
    fn findings_and_selected_code_set_clear_minimum_risk_bases() {
        let finding = |severity| RankedFinding {
            work_unit_id: "unit".to_owned(),
            anchor_id: AnchorId::try_from(format!("ga1_{}", "a".repeat(64))).unwrap(),
            severity,
            confidence_percent: 95,
            category: FindingCategory::Correctness,
            finding_key: Sha256Digest::try_from("b".repeat(64)).unwrap(),
            content_digest: Sha256Digest::try_from("c".repeat(64)).unwrap(),
            lineage_id: None,
            rendered_body: "bounded finding".to_owned(),
        };
        let selection = CanonicalSelection::default();

        assert_eq!(
            minimum_review_risk(&[finding(Severity::Critical)], &selection),
            (
                RiskLevel::Critical,
                "The review identified a critical-severity finding."
            )
        );
        assert_eq!(
            minimum_review_risk(&[finding(Severity::High)], &selection),
            (
                RiskLevel::High,
                "The review identified a high-severity finding."
            )
        );
        assert_eq!(
            minimum_review_risk(&[finding(Severity::Medium)], &selection),
            (
                RiskLevel::Moderate,
                "The review identified a medium-severity finding."
            )
        );

        let selected_code = CanonicalSelection {
            selected_high_signal_files: 1,
            ..CanonicalSelection::default()
        };
        assert_eq!(
            minimum_review_risk(&[], &selected_code),
            (
                RiskLevel::Moderate,
                "The change affects code that warrants additional scrutiny."
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn report_write_replaces_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("revoot-report-write-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("test root");
        let target = root.join("target");
        let report = root.join("report.json");
        std::fs::write(&target, b"protected").expect("target");
        symlink(&target, &report).expect("report symlink");
        write_report_atomically(&report, b"review").expect("atomic report");
        assert_eq!(
            std::fs::read(&target).expect("target remains"),
            b"protected"
        );
        assert_eq!(std::fs::read(&report).expect("report"), b"review");
        std::fs::remove_dir_all(root).expect("cleanup");
    }
}
