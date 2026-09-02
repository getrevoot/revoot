//! Deterministic domain contracts for Revoot.
//!
//! This crate intentionally has no network, process, CLI, or platform APIs.

#![forbid(unsafe_code)]

pub mod adjudication_fallback;
pub mod agent;
pub mod agent_manifest;
pub mod concurrency_trace;
pub mod config;
pub mod coverage_gate;
pub mod delegation;
pub mod diff;
pub mod diff_hazards;
pub mod egress;
pub mod error;
pub mod evaluation;
pub mod execution_graph;
pub mod findings;
pub mod gitlab_context;
pub mod gitlab_wire;
pub mod group_metrics;
pub mod lineage_coverage;
pub mod partition;
pub mod provider;
pub mod publication;
pub mod repository;
pub mod review_budget;
pub mod review_group;
pub mod review_history;
pub mod review_packet;
pub mod review_preview;
pub mod review_report;
pub mod review_tools;
pub mod review_verification;
pub mod review_worker;
pub mod sarif;
pub mod scan;
pub mod snapshot;
pub mod synthetic_dogfood_check;
pub mod token_efficiency;
pub mod tool_cursor;

pub use adjudication_fallback::{
    AdjudicationFallbackCoverage, AdjudicationFallbackError, deterministic_adjudication_fallback,
};
pub use agent_manifest::{
    AgentAuthorityState, AgentCliWorkflow, AgentCliWorkflowId, AgentIntegrationAuthority,
    AgentIntegrationManifest, AgentManifestError, AgentMcpAccess, AgentMcpSurface, AgentMcpTool,
    AgentMcpTransport, build_agent_integration_manifest,
};
pub use concurrency_trace::{
    ConcurrencyTrace, ConcurrencyTraceError, ConcurrencyTraceEvent, ConcurrencyTraceUsage,
    ConcurrencyWorkItem, ProviderSettlementStatus, WorkerSignal, build_concurrency_trace,
};
pub use config::{
    AssignmentScope, ConfigAssignment, ConfigCandidate, ConfigExplainRecord, ConfigField,
    ConfigKey, ConfigKeyError, ConfigSource, ConfigValue, ConfigValueKind, ConfigurationError,
    ConfigurationResolution, ConfigurationSchema, ConstraintViolation, EffectiveConfiguration,
    PolicyConstraint, PolicyExplanation, PolicyRule, RequestedConfiguration, ResolvedValue,
    SourceProvenance, ValueConstraint, ValueViolation,
};
pub use coverage_gate::{
    CoverageCompletionGate, CoverageGateError, GroupCompletion, GroupPartialCause,
};
pub use delegation::{
    DelegationCanonicalError, DelegationError, DelegationExclusion, DelegationFile,
    DelegationManifest, DelegationPolicyDigests, DelegationRuleGroup, DelegationRuleGroupInput,
    build_delegation_manifest,
};
pub use diff::{
    DiffSide, ParsedFileDiff, UnifiedDiffError, UnifiedDiffLimits, parse_gitlab_file_diff,
};
pub use diff_hazards::{
    DiffHazardError, DiffHazardFileInput, DiffHazardHunkInput, DiffHazardInspection,
    DiffHazardReport, DiffHazardSignal, DiffHazardToken, DiffHunkHazardDecision,
    DiffHunkLineClasses, classify_diff_hazards,
};
pub use egress::{
    AllowedProviderEgress, AllowedProviderOrigin, CanonicalHostname, CanonicalHttpsEndpoint,
    CanonicalHttpsOrigin, CertificateAuthorityKind, CertificateAuthorityMode, DnsAnswer, DnsDenial,
    DnsObservation, DnsPolicy, DnsPolicyError, DnsRebindingDecision, EgressDenial,
    EgressPolicyError, EgressRouteKind, EndpointError, EndpointPathRule, IpAddressClass, IpCidr,
    IpCidrError, ProviderAdapterEgressPolicy, ProviderEgressDecision, ProviderEgressPolicy,
    ProviderProxyMode, ProviderRouteObservation, ValidatedDnsResolution, classify_ip_address,
    compare_dns_rebinding,
};
pub use error::{Diagnostic, ErrorCode};
pub use evaluation::{
    EvaluationCase, EvaluationCorpusScore, EvaluationError, EvaluationGate, EvaluationGateFailure,
    EvaluationScore, EvaluationThresholds, ExpectedDefect, evaluate_corpus,
};
pub use execution_graph::{
    ExecutionFact, ExecutionGraph, ExecutionGraphError, ExecutionGraphEvent,
    ExecutionGraphEventKind, ExecutionGraphLimits, ExecutionGraphPlan, ExecutionGraphSummary,
    ExecutionGraphUsage, ExecutionNodeContribution, ExecutionNodeId, ExecutionNodeKind,
    ExecutionNodeSpec, ExecutionNodeState,
};
pub use findings::{
    Finding, FindingCategory, FindingsEnvelope, FindingsPipelineError, FindingsValidationError,
    IssuedWorkUnitAnchors, RankedFinding, RankedFindings, Severity, validate_rank_and_render,
};
pub use gitlab_context::{
    AuthoritativeGitLabMergeRequest, GitLabCiAmbiguity, GitLabCiContext, GitLabCiField,
    GitLabOrigin, GitLabOriginError, GitLabOriginPolicy, GitLabOriginPolicyError,
    GitLabProjectIdentity, GitLabProjectPath, GitLabProjectPathError, GitLabVerificationInput,
    GitLabVerificationMismatch, GitLabVerificationResult, GitRefName, GitRefNameError,
    UntrustedGitLabCiHint, VerifiedGitLabContext, classify_gitlab_ci_environment,
};
pub use gitlab_wire::{
    GitLabChangedFileWire, GitLabDiffRefsWire, GitLabDiffVersionWire, GitLabDiscussionAuthorWire,
    GitLabDiscussionNoteWire, GitLabDiscussionWire, GitLabExactDiffVersionWire,
    GitLabMergeRequestState, GitLabMergeRequestWire, GitLabPage, GitLabPaginationMetadata,
    GitLabProjectWire, GitLabResponseHeader, GitLabResponseMetadata, GitLabResponseObservation,
    GitLabWireError, GitLabWireLimits, ValidatedChangedFile, ValidatedCreatedPublication,
    ValidatedDiffVersion, ValidatedDiscussion, ValidatedExactDiffVersion,
    ValidatedMergeRequestMetadata, ValidatedRawBlob, collect_complete_pages,
    collect_discussion_inventory, parse_changed_files_page, parse_created_discussion_response,
    parse_created_note_response, parse_diff_versions_page, parse_discussion_resolution_response,
    parse_discussions_page, parse_exact_diff_version_response, parse_merge_request_response,
    parse_project_response, parse_raw_blob_response, parse_response_metadata,
};
pub use group_metrics::{
    GroupFileManifest, GroupFileMetrics, GroupHunkCoverageRequirement, GroupHunkManifest,
    GroupHunkMetrics, GroupInitialContext, GroupInlineMetrics, GroupMetricsError,
    GroupMetricsPolicy, GroupPlanningMetrics, ReviewGroupMetricsReport, build_group_metrics,
};
pub use lineage_coverage::{
    AuthorizedLineageAction, AuthorizedLineageDecision, DeliveredAnchorEvidence,
    LineageAuthorization, LineageCoverageError, LineageCoverageEvidence, LineageDecisionResponse,
    LineagePreservationReason, LineageResolutionEvidence, PriorLineageRecord, PriorLineageTarget,
    ProposedLineageDecision, ProposedLineageDisposition, authorize_lineage_decisions,
};
pub use partition::{
    OmittedReviewFile, PartitionBuildError, PartitionCanonicalError, PartitionConfigurationError,
    PartitionCoverage, PartitionLimits, PartitionReplayError, ReviewFileClass, ReviewFileInput,
    ReviewObject, ReviewObjectRole, ReviewOmissionReason, ReviewPartitionPlan,
    ReviewSelectionPolicy, ReviewValue, ReviewValueReason, ReviewValueTier, ReviewWorkUnit,
    WorkUnitFile, WorkUnitId, build_partition_plan, classify_review_value,
    is_sensitive_model_context_path,
};
pub use provider::ProviderErrorKind as DirectProviderErrorKind;
pub use provider::{
    CancellationToken, MAX_CONTENT_BLOCKS, MAX_MODEL_ID_BYTES, MAX_MODEL_MESSAGES, MAX_MODEL_TOOLS,
    MAX_TEXT_BYTES, MAX_TOOL_ID_BYTES, MAX_TOOL_JSON_BYTES, MAX_TOOL_NAME_BYTES, ModelContent,
    ModelFinishReason, ModelMessage, ModelRequest, ModelRequestError, ModelResponse, ModelRole,
    ModelStreamEvent, ModelTool, ModelUsage, ProviderAdapter, ProviderCancellationReason,
    ProviderError, ProviderFuture,
};
pub use publication::{
    ExistingPublicationNote, FindingLineageMarker, PreparedPublication, PublicationAction,
    PublicationCandidate, PublicationCandidateError, PublicationDecision, PublicationInventory,
    PublicationJournal, PublicationJournalEntry, PublicationJournalError,
    PublicationJournalOutcome, PublicationJournalReplayError, PublicationJournalState,
    PublicationMarker, PublicationPlan, PublicationPlanError, PublicationReconciliation,
    PublicationReplayError, PublicationTarget, PublicationTargetKind, build_publication_plan,
    finding_lineage_id, prepare_review_publication, review_publication_scope_digest,
};
pub use repository::{
    CodeSearchRequest, InventoryCoverage, InventoryGapReason, LineRange, ListFilesResult,
    ReadFileResult, RepositoryDiff, RepositoryFile, RepositoryInventory, RepositoryLimitError,
    RepositoryPathError, RepositoryRelativePath, RepositoryToolError, RepositoryToolLimits,
    RepositoryToolbox, SearchMatch, SearchRequest, SearchResult, ShowDiffResult,
};
pub use review_budget::{
    CONSERVATIVE_BYTES_PER_TOKEN, ConservativeChargeReason, OutstandingReviewReservations,
    ReviewBudgetBroker, ReviewBudgetDimension, ReviewBudgetError, ReviewBudgetLimits,
    ReviewBudgetPhase, ReviewBudgetSnapshot, ReviewBudgetUsage, ReviewBudgetValidationError,
    ReviewCallUsage, ReviewModelPermit, ReviewModelReservation, ReviewModelSettlement,
    ReviewModelUsage, estimate_tokens_from_bytes,
};
pub use review_group::{
    CoverageError, CoverageRequirement, CoverageRequirementKind, FileCoverageLedger,
    GroupCoverageLedger, HunkCoverage, ProposedReviewGroup, ReviewEffort, ReviewGroup,
    ReviewGroupFile, ReviewGroupId, ReviewGroupLimits, ReviewGroupPlan, ReviewGroupPlanError,
    ReviewGroupingSource, UnreadHunkDisposition, UnreadHunkDispositionKind,
    build_review_group_plan,
};
pub use review_history::{
    PriorReviewContext, PriorReviewContextError, PriorReviewDiscussion, PriorReviewReply,
    PriorReviewResolution, PriorReviewSource, PriorReviewState,
};
pub use review_preview::{
    ReviewPreview, ReviewPreviewError, ReviewPreviewFile, ReviewPreviewGroup,
    ReviewPreviewGroupInput, ReviewPreviewInitialContext, ReviewPreviewOmission, ReviewPreviewRule,
    ReviewPreviewRuleSource, ReviewPreviewStrategy, build_review_preview,
};
pub use review_report::{
    ReviewReportCoverage, ReviewReportError, ReviewReportFinding, ReviewReportFindingCoordinate,
    ReviewReportFindingSide, ReviewReportLineage, ReviewReportLineageDisposition,
    ReviewReportOverview, ReviewReportPhase, ReviewReportPhaseUsage, ReviewReportPublication,
    ReviewReportSelection, ReviewReportState, ReviewReportStrategy, ReviewReportUsage,
    ReviewReportUsageTotals, ReviewReportV3,
};
pub use review_tools::{
    ReviewToolAuthority, ReviewToolContract, ReviewToolCoverageEffect, ReviewToolId,
    ReviewToolLimits, ReviewToolPermission, ReviewToolRegistry, ReviewToolRegistryError,
    build_review_tool_registry,
};
pub use review_verification::{
    AdjudicatedOverview, AdjudicationOutcome, AdjudicationSuppression,
    AdjudicationSuppressionReason, AdjudicatorResponse, AdjudicatorResponseError,
    CandidateForVerification, CandidateVerificationError, GloballySuppressedCandidate,
    PreparedVerificationBatch, PreparedVerificationCandidate, SuppressedVerificationCandidate,
    VerificationOutcome, VerifiedCandidate, VerifierDecision, VerifierDecisionKind,
    VerifierResponse, VerifierResponseError, VerifierSuppressionReason, apply_adjudicator_response,
    apply_verifier_response, prepare_verification_batch,
};
pub use review_worker::{
    ReviewGroupMetrics, ReviewRound, ReviewWorkerCheckpoint, ReviewWorkerError, ReviewWorkerPhase,
    ReviewWorkerPlan, ReviewWorkerState,
};
pub use sarif::{
    SarifArtifactLocation, SarifCoverageMetadata, SarifDiffSide, SarifDriver, SarifError,
    SarifFingerprints, SarifInvocation, SarifLevel, SarifLocation, SarifLog, SarifMessage,
    SarifPhysicalLocation, SarifRegion, SarifResult, SarifResultProperties, SarifRule, SarifRun,
    SarifRunMetadata, SarifRunProperties, SarifTool, render_sarif,
};
pub use scan::{
    ScanCanonicalError, ScanChunk, ScanCoverage, ScanFile, ScanFileInput, ScanFileTracking,
    ScanLimits, ScanOmission, ScanOmissionReason, ScanPlan, ScanPlanError, ScanRequestMetadata,
    ScanUntrackedPolicy, build_scan_plan,
};
pub use snapshot::{
    AnchorId, AnchorPosition, AnchorTable, AnchorTableError, BlobAcquisition, BlobIdentity,
    BlobRepresentation, BlobRequest, BlobSide, BlobUnavailableReason, ChangedFile,
    ChangedFileCount, ChangedPath, ChangedPathIssue, CommentableLine, CoverageGap,
    DiffAvailability, DiffRefs, DiffUnavailableReason, DiffVersionId, DiffVersionRecord,
    DiffVersionState, FileChangeKind, GitHubRepositoryId, GitHubSnapshotIdentity,
    GitLabDiffVersionIdentity, GitLabSnapshotIdentity, GitSha, IdentityBlocker,
    LocalSnapshotIdentity, MergeRequestIid, PageReceipt, PaginatedAcquisition,
    PaginationCompleteness, PaginationIssue, ProjectId, PullRequestNumber, RepositoryPath,
    ReviewSnapshotIdentity, Sha256Digest, SnapshotAssessment, SnapshotBinding, SnapshotBlocker,
    SnapshotEvidence, SnapshotReadiness, SnapshotScope, TrustedAnchor, UnrepresentedFileCount,
    bind_latest_snapshot,
};
pub use token_efficiency::{
    EfficiencyGroup, EfficiencyHunkDelivery, EfficiencyPhase, EfficiencyPhaseTotals,
    EfficiencyRequest, EfficiencyToolResult, TokenEfficiencyError, TokenEfficiencyReport,
    measure_token_efficiency,
};
pub use tool_cursor::{
    CursorTool, ToolCursorBinding, ToolCursorError, ToolCursorStore, ToolPageRequest,
    ToolResultLimits, ToolResultLimitsError, ToolResultPage,
};

/// The schema version for machine-readable doctor output.
pub const DOCTOR_SCHEMA_VERSION: &str = "revoot.doctor/v3";
pub use agent::{
    AdmitAllCandidates, AgentBudget, AgentBudgetDimension, AgentBudgetError, AgentBudgetLimits,
    AgentBudgetUsage, AgentBudgetValidationError, AgentOmission, AgentOmissionReason,
    AgentProviderTurnError, AgentRun, AgentRunError, AgentState, AgentTool, AgentTurn,
    AgentTurnPurpose, CandidateAdmission, CandidateAdmissionError, CandidateAdmissionHook,
    CandidateSubmission, CandidateSuppressionReason, ModelRequestReservation, ModelRequestUsage,
    ReviewBlockReason, ReviewFailureReason, ReviewInvocation, ReviewInvocationError, ReviewOutcome,
};
