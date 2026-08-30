//! Provider-neutral contracts and state machines for an in-process review.
//!
//! This module owns invocation identity, aggregate budgets, cancellation,
//! bounded model turns, candidate admission, and terminal outcomes. It performs
//! no network, filesystem, process, publication, or clock operation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::provider::{
    CancellationToken, ModelRequest, ModelRequestError, ModelResponse, ProviderAdapter,
    ProviderError,
};
use crate::{FindingsEnvelope, FindingsValidationError, ReviewSnapshotIdentity};

const MAX_LABEL_BYTES: usize = 128;
const MAX_WORK_UNITS: usize = 128;
const MAX_SUMMARY_BYTES: usize = 8 * 1024;
const MAX_OMISSIONS: usize = 1_000;

/// Review-wide hard limits shared by model turns and repository tools.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBudgetLimits {
    pub max_turns: u32,
    pub max_model_requests: u32,
    pub max_tool_calls: u32,
    pub max_repository_files: u64,
    pub max_repository_bytes: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_cost_microusd: u64,
    pub max_candidate_findings: u32,
    pub max_elapsed_millis: u64,
}

impl Default for AgentBudgetLimits {
    fn default() -> Self {
        Self {
            max_turns: 24,
            max_model_requests: 24,
            max_tool_calls: 96,
            max_repository_files: 2_000,
            max_repository_bytes: 32 * 1024 * 1024,
            max_input_tokens: 500_000,
            max_output_tokens: 64_000,
            max_cost_microusd: 5_000_000,
            max_candidate_findings: 250,
            max_elapsed_millis: 15 * 60 * 1_000,
        }
    }
}

/// The first invalid aggregate limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentBudgetValidationError {
    Turns,
    ModelRequests,
    ToolCalls,
    RepositoryFiles,
    RepositoryBytes,
    InputTokens,
    OutputTokens,
    CandidateFindings,
    ElapsedTime,
}

impl AgentBudgetLimits {
    /// Validate that every non-cost dimension admits work.
    ///
    /// A zero monetary limit intentionally supports free or local providers.
    ///
    /// # Errors
    ///
    /// Returns the first unusable limit.
    pub const fn validate(self) -> Result<(), AgentBudgetValidationError> {
        if self.max_turns == 0 {
            return Err(AgentBudgetValidationError::Turns);
        }
        if self.max_model_requests == 0 || self.max_model_requests < self.max_turns {
            return Err(AgentBudgetValidationError::ModelRequests);
        }
        if self.max_tool_calls == 0 {
            return Err(AgentBudgetValidationError::ToolCalls);
        }
        if self.max_repository_files == 0 {
            return Err(AgentBudgetValidationError::RepositoryFiles);
        }
        if self.max_repository_bytes == 0 {
            return Err(AgentBudgetValidationError::RepositoryBytes);
        }
        if self.max_input_tokens == 0 {
            return Err(AgentBudgetValidationError::InputTokens);
        }
        if self.max_output_tokens == 0 {
            return Err(AgentBudgetValidationError::OutputTokens);
        }
        if self.max_candidate_findings == 0 {
            return Err(AgentBudgetValidationError::CandidateFindings);
        }
        if self.max_elapsed_millis == 0 {
            return Err(AgentBudgetValidationError::ElapsedTime);
        }
        Ok(())
    }
}

/// A review-wide budget dimension.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentBudgetDimension {
    Turns,
    ModelRequests,
    ToolCalls,
    RepositoryFiles,
    RepositoryBytes,
    InputTokens,
    OutputTokens,
    Cost,
    CandidateFindings,
    ElapsedTime,
}

/// Current aggregate use. All counters are monotonic.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBudgetUsage {
    pub turns: u32,
    pub model_requests: u32,
    pub tool_calls: u32,
    pub repository_files: u64,
    pub repository_bytes: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
    pub candidate_findings: u32,
    pub elapsed_millis: u64,
}

/// Budget state-machine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentBudgetError {
    InvalidLimits(AgentBudgetValidationError),
    ClockRegression,
    Exhausted(AgentBudgetDimension),
    ModelRequestInFlight,
    NoModelRequestInFlight,
    ModelRequestMismatch,
    ReservationExceeded(AgentBudgetDimension),
}

/// Conservative reservation for one provider request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequestReservation {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
}

/// Authoritative or conservatively accounted provider use for one request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequestUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InFlightModelRequest {
    id: u32,
    reservation: ModelRequestReservation,
}

/// Shared aggregate ledger for one review invocation.
pub struct AgentBudget {
    limits: AgentBudgetLimits,
    usage: AgentBudgetUsage,
    started_at_millis: u64,
    last_observed_millis: u64,
    in_flight: Option<InFlightModelRequest>,
}

impl AgentBudget {
    /// Create an empty aggregate ledger in the caller's monotonic clock domain.
    ///
    /// # Errors
    ///
    /// Returns an error for unusable limits.
    pub fn new(
        limits: AgentBudgetLimits,
        started_at_millis: u64,
    ) -> Result<Self, AgentBudgetError> {
        limits.validate().map_err(AgentBudgetError::InvalidLimits)?;
        Ok(Self {
            limits,
            usage: AgentBudgetUsage::default(),
            started_at_millis,
            last_observed_millis: started_at_millis,
            in_flight: None,
        })
    }

    /// Return the immutable limits.
    #[must_use]
    pub const fn limits(&self) -> AgentBudgetLimits {
        self.limits
    }

    /// Return current redaction-safe usage.
    #[must_use]
    pub const fn usage(&self) -> AgentBudgetUsage {
        self.usage
    }

    /// Reserve one model request and turn.
    ///
    /// # Errors
    ///
    /// Returns an error for time regression/expiry, concurrent requests, or
    /// exhausted request, turn, token, or cost limits.
    pub fn begin_model_request(
        &mut self,
        reservation: ModelRequestReservation,
        now_millis: u64,
    ) -> Result<u32, AgentBudgetError> {
        self.observe_time(now_millis)?;
        if self.in_flight.is_some() {
            return Err(AgentBudgetError::ModelRequestInFlight);
        }
        ensure_u32(
            self.usage.turns,
            1,
            self.limits.max_turns,
            AgentBudgetDimension::Turns,
        )?;
        ensure_u32(
            self.usage.model_requests,
            1,
            self.limits.max_model_requests,
            AgentBudgetDimension::ModelRequests,
        )?;
        ensure_u64(
            self.usage.input_tokens,
            reservation.input_tokens,
            self.limits.max_input_tokens,
            AgentBudgetDimension::InputTokens,
        )?;
        ensure_u64(
            self.usage.output_tokens,
            reservation.output_tokens,
            self.limits.max_output_tokens,
            AgentBudgetDimension::OutputTokens,
        )?;
        ensure_u64(
            self.usage.cost_microusd,
            reservation.cost_microusd,
            self.limits.max_cost_microusd,
            AgentBudgetDimension::Cost,
        )?;
        self.usage.turns = self.usage.turns.saturating_add(1);
        self.usage.model_requests = self.usage.model_requests.saturating_add(1);
        let id = self.usage.model_requests;
        self.in_flight = Some(InFlightModelRequest { id, reservation });
        Ok(id)
    }

    /// Settle the active model request with actual provider usage.
    ///
    /// # Errors
    ///
    /// Returns an error for time/request mismatch or actual use beyond the
    /// reservation. A provider adapter must reserve conservatively.
    pub fn finish_model_request(
        &mut self,
        request_id: u32,
        usage: ModelRequestUsage,
        now_millis: u64,
    ) -> Result<(), AgentBudgetError> {
        self.observe_time(now_millis)?;
        let request = self
            .in_flight
            .ok_or(AgentBudgetError::NoModelRequestInFlight)?;
        if request.id != request_id {
            return Err(AgentBudgetError::ModelRequestMismatch);
        }
        if usage.input_tokens > request.reservation.input_tokens {
            return Err(AgentBudgetError::ReservationExceeded(
                AgentBudgetDimension::InputTokens,
            ));
        }
        if usage.output_tokens > request.reservation.output_tokens {
            return Err(AgentBudgetError::ReservationExceeded(
                AgentBudgetDimension::OutputTokens,
            ));
        }
        if usage.cost_microusd > request.reservation.cost_microusd {
            return Err(AgentBudgetError::ReservationExceeded(
                AgentBudgetDimension::Cost,
            ));
        }
        self.usage.input_tokens = self.usage.input_tokens.saturating_add(usage.input_tokens);
        self.usage.output_tokens = self.usage.output_tokens.saturating_add(usage.output_tokens);
        self.usage.cost_microusd = self.usage.cost_microusd.saturating_add(usage.cost_microusd);
        self.in_flight = None;
        Ok(())
    }

    /// Abandon the active provider request and conservatively charge its full
    /// reservation so retries cannot bypass aggregate limits.
    ///
    /// # Errors
    ///
    /// Returns an error for time or request identity mismatch.
    pub fn abandon_model_request(
        &mut self,
        request_id: u32,
        now_millis: u64,
    ) -> Result<(), AgentBudgetError> {
        self.observe_time(now_millis)?;
        let request = self
            .in_flight
            .ok_or(AgentBudgetError::NoModelRequestInFlight)?;
        if request.id != request_id {
            return Err(AgentBudgetError::ModelRequestMismatch);
        }
        self.usage.input_tokens = self
            .usage
            .input_tokens
            .saturating_add(request.reservation.input_tokens);
        self.usage.output_tokens = self
            .usage
            .output_tokens
            .saturating_add(request.reservation.output_tokens);
        self.usage.cost_microusd = self
            .usage
            .cost_microusd
            .saturating_add(request.reservation.cost_microusd);
        self.in_flight = None;
        Ok(())
    }

    /// Charge one successful repository tool result atomically.
    ///
    /// # Errors
    ///
    /// Returns an error without changing counters if any aggregate tool, file,
    /// byte, or time limit would be exceeded.
    pub fn charge_tool(
        &mut self,
        calls: u32,
        files: u64,
        bytes: u64,
        now_millis: u64,
    ) -> Result<(), AgentBudgetError> {
        self.observe_time(now_millis)?;
        ensure_u32(
            self.usage.tool_calls,
            calls,
            self.limits.max_tool_calls,
            AgentBudgetDimension::ToolCalls,
        )?;
        ensure_u64(
            self.usage.repository_files,
            files,
            self.limits.max_repository_files,
            AgentBudgetDimension::RepositoryFiles,
        )?;
        ensure_u64(
            self.usage.repository_bytes,
            bytes,
            self.limits.max_repository_bytes,
            AgentBudgetDimension::RepositoryBytes,
        )?;
        self.usage.tool_calls = self.usage.tool_calls.saturating_add(calls);
        self.usage.repository_files = self.usage.repository_files.saturating_add(files);
        self.usage.repository_bytes = self.usage.repository_bytes.saturating_add(bytes);
        Ok(())
    }

    fn charge_candidates(&mut self, count: u32) -> Result<(), AgentBudgetError> {
        ensure_u32(
            self.usage.candidate_findings,
            count,
            self.limits.max_candidate_findings,
            AgentBudgetDimension::CandidateFindings,
        )?;
        self.usage.candidate_findings = self.usage.candidate_findings.saturating_add(count);
        Ok(())
    }

    fn observe_time(&mut self, now_millis: u64) -> Result<(), AgentBudgetError> {
        if now_millis < self.last_observed_millis {
            return Err(AgentBudgetError::ClockRegression);
        }
        let elapsed = now_millis.saturating_sub(self.started_at_millis);
        if elapsed > self.limits.max_elapsed_millis {
            return Err(AgentBudgetError::Exhausted(
                AgentBudgetDimension::ElapsedTime,
            ));
        }
        self.last_observed_millis = now_millis;
        self.usage.elapsed_millis = elapsed;
        Ok(())
    }
}

fn ensure_u32(
    current: u32,
    added: u32,
    maximum: u32,
    dimension: AgentBudgetDimension,
) -> Result<(), AgentBudgetError> {
    if current
        .checked_add(added)
        .is_none_or(|value| value > maximum)
    {
        Err(AgentBudgetError::Exhausted(dimension))
    } else {
        Ok(())
    }
}

fn ensure_u64(
    current: u64,
    added: u64,
    maximum: u64,
    dimension: AgentBudgetDimension,
) -> Result<(), AgentBudgetError> {
    if current
        .checked_add(added)
        .is_none_or(|value| value > maximum)
    {
        Err(AgentBudgetError::Exhausted(dimension))
    } else {
        Ok(())
    }
}

/// One model-callable semantic tool controlled by Revoot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTool {
    ReadFile,
    Search,
    ListFiles,
    InspectChangedFile,
    InspectTests,
    ShowDiff,
    GetMergeRequestMetadata,
    GetPullRequestMetadata,
    GetExistingRevootFindings,
    ListChangeCommits,
    ShowCommitContext,
    SubmitCandidateFinding,
    SubmitReviewSummary,
}

/// Immutable invocation identity and authority for one review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInvocation {
    pub review_id: String,
    pub snapshot: ReviewSnapshotIdentity,
    pub work_unit_ids: BTreeSet<String>,
    pub provider_adapter: String,
    pub model_id: String,
    pub allowed_tools: BTreeSet<AgentTool>,
    pub limits: AgentBudgetLimits,
}

/// An invalid invocation field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewInvocationError {
    ReviewId,
    WorkUnitIds,
    ProviderAdapter,
    ModelId,
    ToolAllowlist,
    Budget(AgentBudgetValidationError),
}

impl ReviewInvocation {
    /// Validate bounded identifiers, authority, and budgets.
    ///
    /// # Errors
    ///
    /// Returns the first invalid invocation field.
    pub fn validate(&self) -> Result<(), ReviewInvocationError> {
        if !valid_label(&self.review_id) {
            return Err(ReviewInvocationError::ReviewId);
        }
        if self.work_unit_ids.is_empty()
            || self.work_unit_ids.len() > MAX_WORK_UNITS
            || self.work_unit_ids.iter().any(|id| !valid_label(id))
        {
            return Err(ReviewInvocationError::WorkUnitIds);
        }
        if !valid_label(&self.provider_adapter) {
            return Err(ReviewInvocationError::ProviderAdapter);
        }
        if !valid_label(&self.model_id) {
            return Err(ReviewInvocationError::ModelId);
        }
        if self.allowed_tools.is_empty() {
            return Err(ReviewInvocationError::ToolAllowlist);
        }
        self.limits
            .validate()
            .map_err(ReviewInvocationError::Budget)
    }

    /// Return whether the invocation authorizes a tool.
    #[must_use]
    pub fn allows(&self, tool: AgentTool) -> bool {
        self.allowed_tools.contains(&tool)
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

/// Why a model turn was requested.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTurnPurpose {
    InitialReview,
    ContinueInvestigation,
    VerifyCandidates,
    Synthesize,
}

/// Provider-neutral identity for one bounded turn.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTurn {
    pub turn_id: u32,
    pub request_id: u32,
    pub purpose: AgentTurnPurpose,
}

/// Observable agent lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum AgentState {
    Ready,
    TurnInFlight { turn_id: u32 },
    Finished,
}

/// Candidate hook decision. Suppression reasons remain bounded closed data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateAdmission {
    Admit,
    Suppress(CandidateSuppressionReason),
}

/// Why an otherwise valid candidate envelope was suppressed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSuppressionReason {
    BelowConfidenceThreshold,
    UnsupportedCategory,
    Policy,
    Duplicate,
}

/// Deterministic policy hook applied after schema and work-unit validation.
pub trait CandidateAdmissionHook {
    fn admit(&self, candidate: &FindingsEnvelope) -> CandidateAdmission;
}

/// Hook which admits every schema-valid, authorized candidate.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdmitAllCandidates;

impl CandidateAdmissionHook for AdmitAllCandidates {
    fn admit(&self, _candidate: &FindingsEnvelope) -> CandidateAdmission {
        CandidateAdmission::Admit
    }
}

/// Candidate submission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateAdmissionError {
    AgentNotActive,
    NoTurnInFlight,
    ToolNotAllowed,
    InvalidEnvelope(FindingsValidationError),
    UnknownWorkUnit,
    Budget(AgentBudgetError),
}

/// Result of submitting one candidate envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateSubmission {
    Admitted,
    Suppressed(CandidateSuppressionReason),
}

/// Why review coverage is partial.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentOmissionReason {
    InventoryIncomplete,
    FileTooLarge,
    BinaryFile,
    UnsupportedEncoding,
    SearchTruncated,
    DiffUnavailable,
    BudgetExhausted,
    LowSignalDeferred,
    HistoryUnavailable,
    HistoryIncomplete,
    ProviderLimited,
    PolicyExcluded,
}

/// One bounded omission recorded without exposing arbitrary filesystem paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOmission {
    pub subject_id: String,
    pub reason: AgentOmissionReason,
}

/// Terminal review result family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ReviewOutcome {
    Complete {
        findings: Vec<FindingsEnvelope>,
        summary: String,
        usage: AgentBudgetUsage,
    },
    Partial {
        findings: Vec<FindingsEnvelope>,
        summary: String,
        omissions: Vec<AgentOmission>,
        usage: AgentBudgetUsage,
    },
    NoFindings {
        summary: String,
        omissions: Vec<AgentOmission>,
        usage: AgentBudgetUsage,
    },
    Stale {
        usage: AgentBudgetUsage,
    },
    Blocked {
        reason: ReviewBlockReason,
        usage: AgentBudgetUsage,
    },
    Failed {
        reason: ReviewFailureReason,
        usage: AgentBudgetUsage,
    },
    Cancelled {
        usage: AgentBudgetUsage,
    },
}

/// Closed configuration or authority blocker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewBlockReason {
    Configuration,
    ProviderCapability,
    RepositoryUnavailable,
    SnapshotUnavailable,
}

/// Closed operational failure family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFailureReason {
    Provider,
    ToolContract,
    CandidateContract,
    Internal,
}

/// Agent state-machine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRunError {
    InvalidInvocation(ReviewInvocationError),
    Budget(AgentBudgetError),
    Cancelled,
    NotActive,
    TurnInFlight,
    NoTurnInFlight,
    TurnMismatch,
    ToolNotAllowed,
    Summary,
    Omissions,
}

/// Failure while bridging a bounded agent turn to a direct provider adapter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AgentProviderTurnError {
    Agent(AgentRunError),
    InvalidRequest(ModelRequestError),
    AdapterMismatch,
    ModelMismatch,
    Provider(ProviderError),
}

/// Deterministic in-process review loop state.
pub struct AgentRun {
    invocation: ReviewInvocation,
    cancellation: CancellationToken,
    budget: AgentBudget,
    state: AgentState,
    accepted_candidates: Vec<FindingsEnvelope>,
}

impl AgentRun {
    /// Start a validated review run.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid invocation identity, authority, or budgets.
    pub fn new(
        invocation: ReviewInvocation,
        cancellation: CancellationToken,
        started_at_millis: u64,
    ) -> Result<Self, AgentRunError> {
        invocation
            .validate()
            .map_err(AgentRunError::InvalidInvocation)?;
        let budget = AgentBudget::new(invocation.limits, started_at_millis)
            .map_err(AgentRunError::Budget)?;
        Ok(Self {
            invocation,
            cancellation,
            budget,
            state: AgentState::Ready,
            accepted_candidates: Vec::new(),
        })
    }

    /// Return the invocation contract.
    #[must_use]
    pub const fn invocation(&self) -> &ReviewInvocation {
        &self.invocation
    }

    /// Return the cooperative cancellation token.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Return current state.
    #[must_use]
    pub const fn state(&self) -> AgentState {
        self.state
    }

    /// Mutably borrow the shared aggregate budget for repository tool calls.
    #[must_use]
    pub fn budget_mut(&mut self) -> &mut AgentBudget {
        &mut self.budget
    }

    /// Begin one provider-neutral model turn.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, inactive/concurrent state, or budget
    /// exhaustion.
    pub fn begin_turn(
        &mut self,
        purpose: AgentTurnPurpose,
        reservation: ModelRequestReservation,
        now_millis: u64,
    ) -> Result<AgentTurn, AgentRunError> {
        self.require_not_cancelled()?;
        match self.state {
            AgentState::Ready => {}
            AgentState::TurnInFlight { .. } => return Err(AgentRunError::TurnInFlight),
            AgentState::Finished => return Err(AgentRunError::NotActive),
        }
        let request_id = self
            .budget
            .begin_model_request(reservation, now_millis)
            .map_err(AgentRunError::Budget)?;
        let turn = AgentTurn {
            turn_id: request_id,
            request_id,
            purpose,
        };
        self.state = AgentState::TurnInFlight {
            turn_id: turn.turn_id,
        };
        Ok(turn)
    }

    /// Complete a provider turn and settle its aggregate usage.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, turn mismatch, or reservation
    /// violation.
    pub fn finish_turn(
        &mut self,
        turn: AgentTurn,
        usage: ModelRequestUsage,
        now_millis: u64,
    ) -> Result<(), AgentRunError> {
        self.require_not_cancelled()?;
        match self.state {
            AgentState::TurnInFlight { turn_id } if turn_id == turn.turn_id => {}
            AgentState::TurnInFlight { .. } => return Err(AgentRunError::TurnMismatch),
            AgentState::Ready => return Err(AgentRunError::NoTurnInFlight),
            AgentState::Finished => return Err(AgentRunError::NotActive),
        }
        self.budget
            .finish_model_request(turn.request_id, usage, now_millis)
            .map_err(AgentRunError::Budget)?;
        self.state = AgentState::Ready;
        Ok(())
    }

    /// Execute one bounded request through the provider-neutral adapter.
    ///
    /// The caller supplies a monotonic clock so the core remains independent
    /// of a runtime. Provider-reported tokens are authoritative; the reserved
    /// monetary cost is charged conservatively because the provider boundary
    /// intentionally does not assign prices.
    ///
    /// # Errors
    ///
    /// Returns an error for request/invocation mismatch, invalid request data,
    /// provider failure, cancellation, or any agent budget/state violation.
    pub async fn complete_provider_turn(
        &mut self,
        adapter: &dyn ProviderAdapter,
        request: &ModelRequest,
        purpose: AgentTurnPurpose,
        reservation: ModelRequestReservation,
        monotonic_millis: &impl Fn() -> u64,
    ) -> Result<ModelResponse, AgentProviderTurnError> {
        request
            .validate()
            .map_err(AgentProviderTurnError::InvalidRequest)?;
        if adapter.adapter_id() != self.invocation.provider_adapter {
            return Err(AgentProviderTurnError::AdapterMismatch);
        }
        if request.model != self.invocation.model_id {
            return Err(AgentProviderTurnError::ModelMismatch);
        }
        let turn = self
            .begin_turn(purpose, reservation, monotonic_millis())
            .map_err(AgentProviderTurnError::Agent)?;
        let response = match adapter.complete(request, &self.cancellation).await {
            Ok(response) => response,
            Err(error) => {
                self.budget
                    .abandon_model_request(turn.request_id, monotonic_millis())
                    .map_err(AgentRunError::Budget)
                    .map_err(AgentProviderTurnError::Agent)?;
                self.state = AgentState::Ready;
                return Err(AgentProviderTurnError::Provider(error));
            }
        };
        if response.model != self.invocation.model_id {
            self.budget
                .abandon_model_request(turn.request_id, monotonic_millis())
                .map_err(AgentRunError::Budget)
                .map_err(AgentProviderTurnError::Agent)?;
            self.state = AgentState::Ready;
            return Err(AgentProviderTurnError::ModelMismatch);
        }
        let usage = ModelRequestUsage {
            input_tokens: response.usage.input_tokens,
            output_tokens: response.usage.output_tokens,
            cost_microusd: reservation.cost_microusd,
        };
        self.finish_turn(turn, usage, monotonic_millis())
            .map_err(AgentProviderTurnError::Agent)?;
        Ok(response)
    }

    /// Validate and apply the configured admission hook to one candidate envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for state/authority violations, malformed candidate
    /// data, unknown work units, or candidate budget exhaustion.
    pub fn submit_candidate(
        &mut self,
        candidate: FindingsEnvelope,
        hook: &impl CandidateAdmissionHook,
    ) -> Result<CandidateSubmission, CandidateAdmissionError> {
        if self.state == AgentState::Finished {
            return Err(CandidateAdmissionError::AgentNotActive);
        }
        if !self.invocation.allows(AgentTool::SubmitCandidateFinding) {
            return Err(CandidateAdmissionError::ToolNotAllowed);
        }
        candidate
            .validate()
            .map_err(CandidateAdmissionError::InvalidEnvelope)?;
        if !self
            .invocation
            .work_unit_ids
            .contains(&candidate.work_unit_id)
        {
            return Err(CandidateAdmissionError::UnknownWorkUnit);
        }
        let count = u32::try_from(candidate.findings.len()).unwrap_or(u32::MAX);
        self.budget
            .charge_candidates(count)
            .map_err(CandidateAdmissionError::Budget)?;
        if self
            .accepted_candidates
            .iter()
            .any(|accepted| accepted.work_unit_id == candidate.work_unit_id)
        {
            return Ok(CandidateSubmission::Suppressed(
                CandidateSuppressionReason::Duplicate,
            ));
        }
        match hook.admit(&candidate) {
            CandidateAdmission::Admit => {
                self.accepted_candidates.push(candidate);
                Ok(CandidateSubmission::Admitted)
            }
            CandidateAdmission::Suppress(reason) => Ok(CandidateSubmission::Suppressed(reason)),
        }
    }

    /// Finish successfully, selecting complete/partial/no-findings deterministically.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, an active turn, invalid summary, or
    /// excessive/invalid omission metadata.
    pub fn finish(
        &mut self,
        summary: String,
        omissions: Vec<AgentOmission>,
    ) -> Result<ReviewOutcome, AgentRunError> {
        self.require_not_cancelled()?;
        if matches!(self.state, AgentState::TurnInFlight { .. }) {
            return Err(AgentRunError::TurnInFlight);
        }
        if self.state == AgentState::Finished {
            return Err(AgentRunError::NotActive);
        }
        if summary.trim().is_empty() || summary.len() > MAX_SUMMARY_BYTES {
            return Err(AgentRunError::Summary);
        }
        if omissions.len() > MAX_OMISSIONS
            || omissions.iter().any(|item| !valid_label(&item.subject_id))
        {
            return Err(AgentRunError::Omissions);
        }
        self.state = AgentState::Finished;
        let findings = std::mem::take(&mut self.accepted_candidates);
        let usage = self.budget.usage();
        if findings.is_empty() {
            return Ok(ReviewOutcome::NoFindings {
                summary,
                omissions,
                usage,
            });
        }
        if omissions.is_empty() {
            Ok(ReviewOutcome::Complete {
                findings,
                summary,
                usage,
            })
        } else {
            Ok(ReviewOutcome::Partial {
                findings,
                summary,
                omissions,
                usage,
            })
        }
    }

    /// Finish immediately as stale.
    ///
    /// # Errors
    ///
    /// Returns an error if the run is already terminal.
    pub fn stale(&mut self) -> Result<ReviewOutcome, AgentRunError> {
        self.terminal(|usage| ReviewOutcome::Stale { usage })
    }

    /// Finish immediately as blocked.
    ///
    /// # Errors
    ///
    /// Returns an error if the run is already terminal.
    pub fn blocked(&mut self, reason: ReviewBlockReason) -> Result<ReviewOutcome, AgentRunError> {
        self.terminal(|usage| ReviewOutcome::Blocked { reason, usage })
    }

    /// Finish immediately as failed.
    ///
    /// # Errors
    ///
    /// Returns an error if the run is already terminal.
    pub fn failed(&mut self, reason: ReviewFailureReason) -> Result<ReviewOutcome, AgentRunError> {
        self.terminal(|usage| ReviewOutcome::Failed { reason, usage })
    }

    /// Convert cooperative cancellation into a terminal outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if cancellation was not requested or the run is
    /// already terminal.
    pub fn cancelled(&mut self) -> Result<ReviewOutcome, AgentRunError> {
        if !self.cancellation.is_cancelled() {
            return Err(AgentRunError::NotActive);
        }
        self.terminal(|usage| ReviewOutcome::Cancelled { usage })
    }

    fn terminal(
        &mut self,
        build: impl FnOnce(AgentBudgetUsage) -> ReviewOutcome,
    ) -> Result<ReviewOutcome, AgentRunError> {
        if self.state == AgentState::Finished {
            return Err(AgentRunError::NotActive);
        }
        self.state = AgentState::Finished;
        Ok(build(self.budget.usage()))
    }

    fn require_not_cancelled(&self) -> Result<(), AgentRunError> {
        if self.cancellation.is_cancelled() {
            Err(AgentRunError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    use serde_json::json;

    use super::*;
    use crate::findings::{Finding, FindingCategory, Severity};
    use crate::provider::{
        ModelContent, ModelFinishReason, ModelMessage, ModelRole, ModelUsage, ProviderFuture,
    };

    fn invocation(limits: AgentBudgetLimits) -> ReviewInvocation {
        ReviewInvocation {
            review_id: "review-1".to_owned(),
            snapshot: serde_json::from_value(json!({
                "version": {
                    "scope": {
                        "instance_origin_digest": "11".repeat(32),
                        "project_id": 7,
                        "merge_request_iid": 9
                    },
                    "diff_version": {
                        "id": 3,
                        "refs": {
                            "base_sha": "aa".repeat(20),
                            "start_sha": "bb".repeat(20),
                            "head_sha": "cc".repeat(20)
                        }
                    }
                },
                "exact_diff_manifest_sha256": "22".repeat(32)
            }))
            .expect("valid fixture snapshot"),
            work_unit_ids: BTreeSet::from(["unit-1".to_owned()]),
            provider_adapter: "fixture".to_owned(),
            model_id: "fixture-v1".to_owned(),
            allowed_tools: BTreeSet::from([
                AgentTool::ReadFile,
                AgentTool::Search,
                AgentTool::ListFiles,
                AgentTool::ShowDiff,
                AgentTool::SubmitCandidateFinding,
                AgentTool::SubmitReviewSummary,
            ]),
            limits,
        }
    }

    fn reservation() -> ModelRequestReservation {
        ModelRequestReservation {
            input_tokens: 100,
            output_tokens: 50,
            cost_microusd: 10,
        }
    }

    fn candidate(work_unit_id: &str) -> FindingsEnvelope {
        FindingsEnvelope {
            schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
            work_unit_id: work_unit_id.to_owned(),
            findings: vec![Finding {
                anchor_id: "ga1_fixture".to_owned(),
                severity: Severity::High,
                confidence_percent: 92,
                category: FindingCategory::Correctness,
                title: "Incorrect fallback".to_owned(),
                explanation: "The fallback returns the previous value.".to_owned(),
                evidence: "The changed branch skips the new value.".to_owned(),
                lineage_id: None,
                suggested_replacement: None,
            }],
            summary: "One supported defect.".to_owned(),
        }
    }

    #[test]
    fn aggregate_budget_rejects_atomically() {
        let limits = AgentBudgetLimits {
            max_tool_calls: 1,
            max_repository_files: 2,
            max_repository_bytes: 10,
            ..AgentBudgetLimits::default()
        };
        let mut budget = AgentBudget::new(limits, 100).expect("valid limits");
        budget.charge_tool(1, 1, 8, 101).expect("first result");
        assert_eq!(
            budget.charge_tool(1, 1, 1, 102),
            Err(AgentBudgetError::Exhausted(AgentBudgetDimension::ToolCalls))
        );
        assert_eq!(
            budget.usage(),
            AgentBudgetUsage {
                tool_calls: 1,
                repository_files: 1,
                repository_bytes: 8,
                elapsed_millis: 2,
                ..AgentBudgetUsage::default()
            }
        );
    }

    #[test]
    fn turn_candidate_and_partial_outcome_are_deterministic() {
        let mut run = AgentRun::new(
            invocation(AgentBudgetLimits::default()),
            CancellationToken::default(),
            1_000,
        )
        .expect("valid run");
        let turn = run
            .begin_turn(AgentTurnPurpose::InitialReview, reservation(), 1_010)
            .expect("turn starts");
        assert_eq!(
            run.submit_candidate(candidate("unit-1"), &AdmitAllCandidates),
            Ok(CandidateSubmission::Admitted)
        );
        run.finish_turn(
            turn,
            ModelRequestUsage {
                input_tokens: 80,
                output_tokens: 30,
                cost_microusd: 8,
            },
            1_020,
        )
        .expect("turn settles");
        let outcome = run
            .finish(
                "Reviewed the fixture.".to_owned(),
                vec![AgentOmission {
                    subject_id: "file-2".to_owned(),
                    reason: AgentOmissionReason::BinaryFile,
                }],
            )
            .expect("run finishes");
        let ReviewOutcome::Partial {
            findings,
            omissions,
            usage,
            ..
        } = outcome
        else {
            panic!("expected partial outcome")
        };
        assert_eq!(findings, vec![candidate("unit-1")]);
        assert_eq!(omissions.len(), 1);
        assert_eq!(usage.turns, 1);
        assert_eq!(usage.candidate_findings, 1);
    }

    struct SuppressAll;

    impl CandidateAdmissionHook for SuppressAll {
        fn admit(&self, _candidate: &FindingsEnvelope) -> CandidateAdmission {
            CandidateAdmission::Suppress(CandidateSuppressionReason::Policy)
        }
    }

    #[test]
    fn admission_hook_suppresses_without_hiding_candidate_cost() {
        let mut run = AgentRun::new(
            invocation(AgentBudgetLimits::default()),
            CancellationToken::default(),
            0,
        )
        .expect("valid run");
        let turn = run
            .begin_turn(AgentTurnPurpose::InitialReview, reservation(), 0)
            .expect("turn starts");
        assert_eq!(
            run.submit_candidate(candidate("unit-1"), &SuppressAll),
            Ok(CandidateSubmission::Suppressed(
                CandidateSuppressionReason::Policy
            ))
        );
        run.finish_turn(
            turn,
            ModelRequestUsage {
                input_tokens: 1,
                output_tokens: 1,
                cost_microusd: 1,
            },
            1,
        )
        .expect("turn settles");
        let ReviewOutcome::NoFindings { usage, .. } = run
            .finish("No findings passed policy.".to_owned(), Vec::new())
            .expect("run finishes")
        else {
            panic!("expected no findings")
        };
        assert_eq!(usage.candidate_findings, 1);
    }

    struct FixtureAdapter;

    impl ProviderAdapter for FixtureAdapter {
        fn adapter_id(&self) -> &'static str {
            "fixture"
        }

        fn complete<'a>(
            &'a self,
            request: &'a ModelRequest,
            _cancellation: &'a CancellationToken,
        ) -> ProviderFuture<'a> {
            Box::pin(async move {
                Ok(ModelResponse {
                    provider_response_id: Some("response-1".to_owned()),
                    model: request.model.clone(),
                    content: vec![ModelContent::Text {
                        text: "Inspect src/lib.rs next.".to_owned(),
                    }],
                    finish_reason: ModelFinishReason::Stop,
                    usage: ModelUsage {
                        input_tokens: 25,
                        output_tokens: 7,
                        cached_input_tokens: 0,
                    },
                })
            })
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn direct_provider_bridge_uses_shared_contract_and_budget() {
        let mut run = AgentRun::new(
            invocation(AgentBudgetLimits::default()),
            CancellationToken::default(),
            10,
        )
        .expect("valid run");
        let request = ModelRequest {
            model: "fixture-v1".to_owned(),
            system: Some("Review only supported defects.".to_owned()),
            messages: vec![ModelMessage {
                role: ModelRole::User,
                content: vec![ModelContent::Text {
                    text: "Review this fixture.".to_owned(),
                }],
            }],
            tools: Vec::new(),
            max_output_tokens: 50,
            temperature: Some(0.0),
        };
        let clock = || 11;
        let response = block_on(run.complete_provider_turn(
            &FixtureAdapter,
            &request,
            AgentTurnPurpose::InitialReview,
            reservation(),
            &clock,
        ))
        .expect("provider turn succeeds");
        assert_eq!(response.finish_reason, ModelFinishReason::Stop);
        assert_eq!(run.state(), AgentState::Ready);
        assert_eq!(run.budget.usage().input_tokens, 25);
        assert_eq!(run.budget.usage().output_tokens, 7);
        assert_eq!(run.budget.usage().cost_microusd, 10);
        assert_eq!(
            run.submit_candidate(candidate("unit-1"), &AdmitAllCandidates),
            Ok(CandidateSubmission::Admitted)
        );
    }

    #[test]
    fn cancellation_stops_new_turns_and_has_terminal_outcome() {
        let cancellation = CancellationToken::default();
        let mut run = AgentRun::new(
            invocation(AgentBudgetLimits::default()),
            cancellation.clone(),
            0,
        )
        .expect("valid run");
        cancellation.cancel(crate::provider::ProviderCancellationReason::Shutdown);
        assert_eq!(
            run.begin_turn(AgentTurnPurpose::InitialReview, reservation(), 1),
            Err(AgentRunError::Cancelled)
        );
        assert!(matches!(
            run.cancelled(),
            Ok(ReviewOutcome::Cancelled { .. })
        ));
    }
}
