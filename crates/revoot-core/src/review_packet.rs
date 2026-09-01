//! Bounded composition contracts for one provider request.
//!
//! Packets carry immutable review metadata, at most one complete small-group
//! diff, and at most the immediately preceding tool exchange. They have no
//! serializable persistence surface and redact payload-bearing debug output.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::Value;

use crate::{
    AnchorId, FindingCategory, RepositoryPath, ReviewValueTier, ReviewWorkerCheckpoint, Severity,
    Sha256Digest,
};

const MAX_INLINE_DIFF_BYTES: u64 = 16_384;
const MAX_REQUEST_INPUT_TOKENS: u64 = 32_000;
const MAX_GROUP_FILES: usize = 10;
const MAX_HUNKS_PER_FILE: usize = 4_096;
const MAX_RULE_IDS: usize = 1_024;
const MAX_SUMMARY_IDS: usize = 256;
const MAX_CANDIDATES: usize = 25;
const MAX_EVIDENCE_IDS: usize = 32;
const MAX_UNRESOLVED_COVERAGE: usize = 10_000;
const MAX_TOOL_CALLS_PER_EXCHANGE: usize = 32;
const MAX_TOOL_ARGUMENT_BYTES: usize = 32 * 1024;
const MAX_TOOL_RESULT_BYTES: usize = 32 * 1024;
const MAX_LABEL_BYTES: usize = 128;

/// Exact purpose of one freshly composed request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewPacketPurpose {
    GroupInitial,
    Planning,
    ReviewRound { round: u8 },
    Verification,
    Adjudication,
}

/// One selected file in the immutable compact group brief.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPacketFileBrief {
    pub path: RepositoryPath,
    pub tier: ReviewValueTier,
    pub changed_lines: u32,
    pub hunk_ids: Vec<String>,
}

/// Snapshot-bound immutable brief repeated on each fresh turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPacketGroupBrief {
    pub group_id: String,
    pub snapshot_sha256: Sha256Digest,
    pub partition_sha256: Sha256Digest,
    pub group_plan_sha256: Sha256Digest,
    pub files: Vec<ReviewPacketFileBrief>,
}

/// Trusted policy identity. Policy text is resolved outside the packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPacketPolicy {
    pub system_policy_id: String,
    pub system_policy_sha256: Sha256Digest,
    pub rule_ids: Vec<String>,
}

/// Structured planning output represented by opaque IDs only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReviewPacketPlanSummary {
    pub focus_area_ids: Vec<String>,
    pub hunk_ids: Vec<String>,
    pub dependency_question_ids: Vec<String>,
    pub risk_hypothesis_ids: Vec<String>,
}

/// Accepted finding identity carried between fresh rounds without prose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPacketFindingSummary {
    pub candidate_id: String,
    pub anchor_id: AnchorId,
    pub severity: Severity,
    pub confidence_percent: u8,
    pub category: FindingCategory,
    pub evidence_ids: Vec<String>,
}

/// Body-free hunk manifest for one complete group diff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPacketDiffManifest {
    pub complete_diff_sha256: Sha256Digest,
    pub complete_diff_bytes: u64,
    pub file_count: u32,
    pub hunk_count: u32,
}

/// Complete diff source supplied to the initial composition call.
///
/// A small group must supply its entire exact diff. A large group supplies only
/// trusted metadata; there is deliberately no partial-body variant.
#[derive(Clone, Eq, PartialEq)]
pub enum ReviewPacketCompleteDiff {
    SmallComplete { body: String, sha256: Sha256Digest },
    LargeManifestOnly { sha256: Sha256Digest, bytes: u64 },
}

impl fmt::Debug for ReviewPacketCompleteDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SmallComplete { sha256, body } => formatter
                .debug_struct("SmallComplete")
                .field("body", &"[redacted]")
                .field("bytes", &body.len())
                .field("sha256", sha256)
                .finish(),
            Self::LargeManifestOnly { sha256, bytes } => formatter
                .debug_struct("LargeManifestOnly")
                .field("sha256", sha256)
                .field("bytes", bytes)
                .finish(),
        }
    }
}

/// One assistant tool call from the immediately preceding exchange.
#[derive(Clone, Eq, PartialEq)]
pub struct ReviewPacketToolCall {
    pub call_id: String,
    pub tool_name: String,
    pub arguments: Value,
}

impl fmt::Debug for ReviewPacketToolCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewPacketToolCall")
            .field("call_id", &self.call_id)
            .field("tool_name", &self.tool_name)
            .field("arguments", &"[redacted]")
            .finish()
    }
}

/// Matching tool result from the immediately preceding exchange.
#[derive(Clone, Eq, PartialEq)]
pub struct ReviewPacketToolResult {
    pub call_id: String,
    pub tool_name: String,
    pub body: String,
    pub truncated: bool,
}

impl fmt::Debug for ReviewPacketToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewPacketToolResult")
            .field("call_id", &self.call_id)
            .field("tool_name", &self.tool_name)
            .field("body", &"[redacted]")
            .field("bytes", &self.body.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// The single assistant-call/result exchange eligible for rebased context.
#[derive(Clone, Eq, PartialEq)]
pub struct ReviewPacketRecentExchange {
    pub assistant_calls: Vec<ReviewPacketToolCall>,
    pub tool_results: Vec<ReviewPacketToolResult>,
}

impl fmt::Debug for ReviewPacketRecentExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewPacketRecentExchange")
            .field("assistant_call_count", &self.assistant_calls.len())
            .field("tool_result_count", &self.tool_results.len())
            .finish()
    }
}

/// Caller-supplied tokenizer measurements for the two allowed initial shapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewPacketTokenEstimates {
    /// Complete request with manifest-only diff context.
    pub manifest_request_tokens: u64,
    /// Complete request with the small group's full diff, when available.
    pub inline_request_tokens: Option<u64>,
}

/// Non-persistable request composition input.
#[derive(Clone, Eq, PartialEq)]
pub struct ReviewPacketInput {
    pub purpose: ReviewPacketPurpose,
    pub group_brief: ReviewPacketGroupBrief,
    pub policy: ReviewPacketPolicy,
    pub checkpoint: ReviewWorkerCheckpoint,
    pub plan_summary: Option<ReviewPacketPlanSummary>,
    pub accepted_findings: Vec<ReviewPacketFindingSummary>,
    pub unresolved_coverage_ids: Vec<String>,
    pub recent_exchange: Option<ReviewPacketRecentExchange>,
    pub diff_manifest: ReviewPacketDiffManifest,
    pub complete_diff: Option<ReviewPacketCompleteDiff>,
    pub token_estimates: ReviewPacketTokenEstimates,
}

impl fmt::Debug for ReviewPacketInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewPacketInput")
            .field("purpose", &self.purpose)
            .field("group_id", &self.group_brief.group_id)
            .field("policy_id", &self.policy.system_policy_id)
            .field("checkpoint", &"[redacted structured checkpoint]")
            .field("plan_summary_present", &self.plan_summary.is_some())
            .field("accepted_finding_count", &self.accepted_findings.len())
            .field(
                "unresolved_coverage_count",
                &self.unresolved_coverage_ids.len(),
            )
            .field("recent_exchange", &self.recent_exchange)
            .field("diff_manifest", &self.diff_manifest)
            .field("complete_diff", &self.complete_diff)
            .field("token_estimates", &self.token_estimates)
            .finish()
    }
}

/// Diff context selected for one actual provider request.
#[derive(Clone, Eq, PartialEq)]
pub enum ReviewPacketDiffContext {
    InlineComplete { body: String, sha256: Sha256Digest },
    ManifestOnly(ReviewPacketDiffManifest),
}

impl fmt::Debug for ReviewPacketDiffContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InlineComplete { body, sha256 } => formatter
                .debug_struct("InlineComplete")
                .field("body", &"[redacted]")
                .field("bytes", &body.len())
                .field("sha256", sha256)
                .finish(),
            Self::ManifestOnly(manifest) => formatter
                .debug_tuple("ManifestOnly")
                .field(manifest)
                .finish(),
        }
    }
}

/// Ephemeral, validated provider request packet.
#[derive(Clone, Eq, PartialEq)]
pub struct ReviewPacket {
    pub purpose: ReviewPacketPurpose,
    pub group_brief: ReviewPacketGroupBrief,
    pub policy: ReviewPacketPolicy,
    pub checkpoint: ReviewWorkerCheckpoint,
    pub plan_summary: Option<ReviewPacketPlanSummary>,
    pub accepted_findings: Vec<ReviewPacketFindingSummary>,
    pub unresolved_coverage_ids: Vec<String>,
    pub recent_exchange: Option<ReviewPacketRecentExchange>,
    pub diff_context: ReviewPacketDiffContext,
    pub estimated_input_tokens: u64,
}

impl fmt::Debug for ReviewPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewPacket")
            .field("purpose", &self.purpose)
            .field("group_id", &self.group_brief.group_id)
            .field("policy_id", &self.policy.system_policy_id)
            .field("checkpoint", &"[redacted structured checkpoint]")
            .field("plan_summary_present", &self.plan_summary.is_some())
            .field("accepted_finding_count", &self.accepted_findings.len())
            .field(
                "unresolved_coverage_count",
                &self.unresolved_coverage_ids.len(),
            )
            .field("recent_exchange", &self.recent_exchange)
            .field("diff_context", &self.diff_context)
            .field("estimated_input_tokens", &self.estimated_input_tokens)
            .finish()
    }
}

/// Per-group state preventing repeated initial composition or diff reinsertion.
#[derive(Debug)]
pub struct ReviewPacketComposer {
    group_id: String,
    group_plan_sha256: Sha256Digest,
    initial_composed: bool,
    inline_diff_issued: bool,
}

impl ReviewPacketComposer {
    #[must_use]
    pub fn new(group_id: String, group_plan_sha256: Sha256Digest) -> Self {
        Self {
            group_id,
            group_plan_sha256,
            initial_composed: false,
            inline_diff_issued: false,
        }
    }

    #[must_use]
    pub const fn inline_diff_issued(&self) -> bool {
        self.inline_diff_issued
    }

    /// Compose one fresh request while enforcing inline-once and mandatory
    /// context limits.
    ///
    /// # Errors
    ///
    /// Returns a payload-free contract error for malformed metadata or invalid
    /// lifecycle. Mandatory context overflow returns a partial outcome instead.
    pub fn compose(
        &mut self,
        input: ReviewPacketInput,
    ) -> Result<ReviewPacketComposition, ReviewPacketError> {
        validate_input(&input)?;
        if input.group_brief.group_id != self.group_id
            || input.group_brief.group_plan_sha256 != self.group_plan_sha256
        {
            return Err(ReviewPacketError::GroupBinding);
        }
        let initial = input.purpose == ReviewPacketPurpose::GroupInitial;
        if initial == self.initial_composed {
            return Err(if initial {
                ReviewPacketError::InitialAlreadyComposed
            } else {
                ReviewPacketError::InitialRequired
            });
        }
        if input.token_estimates.manifest_request_tokens > MAX_REQUEST_INPUT_TOKENS {
            return Ok(ReviewPacketComposition::Partial(
                ReviewPacketPartialFailure::MandatoryContextTooLarge,
            ));
        }

        let (diff_context, estimated_input_tokens, issued_inline) = if initial {
            initial_diff_context(&input)?
        } else {
            if input.complete_diff.is_some()
                || input.token_estimates.inline_request_tokens.is_some()
            {
                return Err(ReviewPacketError::DiffReinsertion);
            }
            (
                ReviewPacketDiffContext::ManifestOnly(input.diff_manifest.clone()),
                input.token_estimates.manifest_request_tokens,
                false,
            )
        };
        self.initial_composed |= initial;
        self.inline_diff_issued |= issued_inline;
        Ok(ReviewPacketComposition::Ready(Box::new(ReviewPacket {
            purpose: input.purpose,
            group_brief: input.group_brief,
            policy: input.policy,
            checkpoint: input.checkpoint,
            plan_summary: input.plan_summary,
            accepted_findings: input.accepted_findings,
            unresolved_coverage_ids: input.unresolved_coverage_ids,
            recent_exchange: input.recent_exchange,
            diff_context,
            estimated_input_tokens,
        })))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ReviewPacketComposition {
    Ready(Box<ReviewPacket>),
    Partial(ReviewPacketPartialFailure),
}

impl fmt::Debug for ReviewPacketComposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(packet) => formatter.debug_tuple("Ready").field(packet).finish(),
            Self::Partial(reason) => formatter.debug_tuple("Partial").field(reason).finish(),
        }
    }
}

/// Payload-free reason request composition stopped the group as partial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewPacketPartialFailure {
    MandatoryContextTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewPacketError {
    GroupBinding,
    InvalidPurpose,
    InitialRequired,
    InitialAlreadyComposed,
    Brief,
    Policy,
    Checkpoint,
    PlanSummary,
    FindingSummary,
    CoverageIds,
    Exchange,
    Manifest,
    CompleteDiff,
    PartialInline,
    DiffReinsertion,
    TokenEstimate,
    Serialization,
}

impl fmt::Display for ReviewPacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GroupBinding => "the request packet group binding is invalid",
            Self::InvalidPurpose => "the request packet purpose is invalid",
            Self::InitialRequired => "the initial group packet must be composed first",
            Self::InitialAlreadyComposed => "the initial group packet was already composed",
            Self::Brief => "the compact group brief is invalid",
            Self::Policy => "the request packet policy identity is invalid",
            Self::Checkpoint => "the request packet checkpoint is invalid",
            Self::PlanSummary => "the request packet plan summary is invalid",
            Self::FindingSummary => "a request packet finding summary is invalid",
            Self::CoverageIds => "the unresolved coverage identities are invalid",
            Self::Exchange => "the recent tool exchange is invalid",
            Self::Manifest => "the request packet diff manifest is invalid",
            Self::CompleteDiff => "the complete group diff identity is invalid",
            Self::PartialInline => "partial inline diff content is forbidden",
            Self::DiffReinsertion => "the complete diff cannot be reinserted after initial context",
            Self::TokenEstimate => "the request packet token estimate is invalid",
            Self::Serialization => "request packet metadata serialization failed",
        })
    }
}

impl std::error::Error for ReviewPacketError {}

fn validate_input(input: &ReviewPacketInput) -> Result<(), ReviewPacketError> {
    validate_brief(&input.group_brief)?;
    validate_policy(&input.policy)?;
    input
        .checkpoint
        .validate()
        .map_err(|_| ReviewPacketError::Checkpoint)?;
    if let Some(plan) = &input.plan_summary {
        for ids in [
            plan.focus_area_ids.as_slice(),
            plan.hunk_ids.as_slice(),
            plan.dependency_question_ids.as_slice(),
            plan.risk_hypothesis_ids.as_slice(),
        ] {
            validate_ids(ids, MAX_SUMMARY_IDS).map_err(|()| ReviewPacketError::PlanSummary)?;
        }
    }
    validate_findings(&input.accepted_findings)?;
    validate_ids(&input.unresolved_coverage_ids, MAX_UNRESOLVED_COVERAGE)
        .map_err(|()| ReviewPacketError::CoverageIds)?;
    if let Some(exchange) = &input.recent_exchange {
        validate_exchange(exchange)?;
    }
    validate_manifest(&input.diff_manifest, &input.group_brief)?;
    if input.token_estimates.manifest_request_tokens == 0
        || input
            .token_estimates
            .inline_request_tokens
            .is_some_and(|tokens| tokens == 0)
    {
        return Err(ReviewPacketError::TokenEstimate);
    }
    match input.purpose {
        ReviewPacketPurpose::GroupInitial => {
            if input.complete_diff.is_none() {
                return Err(ReviewPacketError::CompleteDiff);
            }
        }
        ReviewPacketPurpose::ReviewRound { round: 0 } => {
            return Err(ReviewPacketError::InvalidPurpose);
        }
        ReviewPacketPurpose::Planning
        | ReviewPacketPurpose::ReviewRound { .. }
        | ReviewPacketPurpose::Verification
        | ReviewPacketPurpose::Adjudication => {}
    }
    Ok(())
}

fn initial_diff_context(
    input: &ReviewPacketInput,
) -> Result<(ReviewPacketDiffContext, u64, bool), ReviewPacketError> {
    let complete = input
        .complete_diff
        .as_ref()
        .ok_or(ReviewPacketError::CompleteDiff)?;
    match complete {
        ReviewPacketCompleteDiff::SmallComplete { body, sha256 } => {
            let bytes = u64::try_from(body.len()).map_err(|_| ReviewPacketError::CompleteDiff)?;
            if bytes > MAX_INLINE_DIFF_BYTES
                || bytes != input.diff_manifest.complete_diff_bytes
                || *sha256 != input.diff_manifest.complete_diff_sha256
                || Sha256Digest::of_bytes(body.as_bytes()) != *sha256
            {
                return Err(if bytes > MAX_INLINE_DIFF_BYTES {
                    ReviewPacketError::PartialInline
                } else {
                    ReviewPacketError::CompleteDiff
                });
            }
            let inline_tokens = input
                .token_estimates
                .inline_request_tokens
                .ok_or(ReviewPacketError::TokenEstimate)?;
            if inline_tokens <= MAX_REQUEST_INPUT_TOKENS {
                Ok((
                    ReviewPacketDiffContext::InlineComplete {
                        body: body.clone(),
                        sha256: sha256.clone(),
                    },
                    inline_tokens,
                    true,
                ))
            } else {
                Ok((
                    ReviewPacketDiffContext::ManifestOnly(input.diff_manifest.clone()),
                    input.token_estimates.manifest_request_tokens,
                    false,
                ))
            }
        }
        ReviewPacketCompleteDiff::LargeManifestOnly { sha256, bytes } => {
            if *bytes <= MAX_INLINE_DIFF_BYTES
                || *bytes != input.diff_manifest.complete_diff_bytes
                || *sha256 != input.diff_manifest.complete_diff_sha256
                || input.token_estimates.inline_request_tokens.is_some()
            {
                return Err(ReviewPacketError::CompleteDiff);
            }
            Ok((
                ReviewPacketDiffContext::ManifestOnly(input.diff_manifest.clone()),
                input.token_estimates.manifest_request_tokens,
                false,
            ))
        }
    }
}

fn validate_brief(brief: &ReviewPacketGroupBrief) -> Result<(), ReviewPacketError> {
    if !valid_id(&brief.group_id)
        || brief.files.is_empty()
        || brief.files.len() > MAX_GROUP_FILES
        || !brief
            .files
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    {
        return Err(ReviewPacketError::Brief);
    }
    for file in &brief.files {
        if validate_ids(&file.hunk_ids, MAX_HUNKS_PER_FILE).is_err() {
            return Err(ReviewPacketError::Brief);
        }
    }
    Ok(())
}

fn validate_policy(policy: &ReviewPacketPolicy) -> Result<(), ReviewPacketError> {
    if !valid_id(&policy.system_policy_id) || validate_ids(&policy.rule_ids, MAX_RULE_IDS).is_err()
    {
        return Err(ReviewPacketError::Policy);
    }
    Ok(())
}

fn validate_findings(findings: &[ReviewPacketFindingSummary]) -> Result<(), ReviewPacketError> {
    if findings.len() > MAX_CANDIDATES {
        return Err(ReviewPacketError::FindingSummary);
    }
    let mut candidates = BTreeSet::new();
    for finding in findings {
        if !valid_id(&finding.candidate_id)
            || !candidates.insert(&finding.candidate_id)
            || finding.confidence_percent > 100
            || validate_ids(&finding.evidence_ids, MAX_EVIDENCE_IDS).is_err()
        {
            return Err(ReviewPacketError::FindingSummary);
        }
    }
    Ok(())
}

fn validate_exchange(exchange: &ReviewPacketRecentExchange) -> Result<(), ReviewPacketError> {
    if exchange.assistant_calls.is_empty()
        || exchange.assistant_calls.len() > MAX_TOOL_CALLS_PER_EXCHANGE
        || exchange.assistant_calls.len() != exchange.tool_results.len()
    {
        return Err(ReviewPacketError::Exchange);
    }
    let mut calls = BTreeSet::new();
    for call in &exchange.assistant_calls {
        let argument_bytes = serde_json::to_vec(&call.arguments)
            .map_err(|_| ReviewPacketError::Serialization)?
            .len();
        if !valid_id(&call.call_id)
            || !valid_id(&call.tool_name)
            || !calls.insert((&call.call_id, &call.tool_name))
            || argument_bytes > MAX_TOOL_ARGUMENT_BYTES
        {
            return Err(ReviewPacketError::Exchange);
        }
    }
    let mut results = BTreeSet::new();
    for result in &exchange.tool_results {
        if !valid_id(&result.call_id)
            || !valid_id(&result.tool_name)
            || result.body.len() > MAX_TOOL_RESULT_BYTES
            || result.body.contains('\0')
            || !results.insert((&result.call_id, &result.tool_name))
        {
            return Err(ReviewPacketError::Exchange);
        }
    }
    if calls != results {
        return Err(ReviewPacketError::Exchange);
    }
    Ok(())
}

fn validate_manifest(
    manifest: &ReviewPacketDiffManifest,
    brief: &ReviewPacketGroupBrief,
) -> Result<(), ReviewPacketError> {
    if manifest.complete_diff_bytes == 0
        || usize::try_from(manifest.file_count).ok() != Some(brief.files.len())
        || manifest.hunk_count
            != brief
                .files
                .iter()
                .try_fold(0_u32, |total, file| {
                    total.checked_add(u32::try_from(file.hunk_ids.len()).ok()?)
                })
                .ok_or(ReviewPacketError::Manifest)?
    {
        return Err(ReviewPacketError::Manifest);
    }
    Ok(())
}

fn validate_ids(ids: &[String], max: usize) -> Result<(), ()> {
    if ids.len() > max
        || ids.iter().any(|id| !valid_id(id))
        || !ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(());
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn brief() -> ReviewPacketGroupBrief {
        ReviewPacketGroupBrief {
            group_id: "group-1".to_owned(),
            snapshot_sha256: digest('a'),
            partition_sha256: digest('b'),
            group_plan_sha256: digest('c'),
            files: vec![ReviewPacketFileBrief {
                path: path("src/lib.rs"),
                tier: ReviewValueTier::High,
                changed_lines: 10,
                hunk_ids: vec!["hunk-1".to_owned()],
            }],
        }
    }

    fn input(body: &str, inline_tokens: u64) -> ReviewPacketInput {
        let sha256 = Sha256Digest::of_bytes(body.as_bytes());
        ReviewPacketInput {
            purpose: ReviewPacketPurpose::GroupInitial,
            group_brief: brief(),
            policy: ReviewPacketPolicy {
                system_policy_id: "reviewer-v1".to_owned(),
                system_policy_sha256: digest('d'),
                rule_ids: vec!["rust.correctness".to_owned()],
            },
            checkpoint: ReviewWorkerCheckpoint::default(),
            plan_summary: None,
            accepted_findings: Vec::new(),
            unresolved_coverage_ids: vec!["hunk-1".to_owned()],
            recent_exchange: None,
            diff_manifest: ReviewPacketDiffManifest {
                complete_diff_sha256: sha256.clone(),
                complete_diff_bytes: u64::try_from(body.len()).unwrap(),
                file_count: 1,
                hunk_count: 1,
            },
            complete_diff: Some(ReviewPacketCompleteDiff::SmallComplete {
                body: body.to_owned(),
                sha256,
            }),
            token_estimates: ReviewPacketTokenEstimates {
                manifest_request_tokens: 1_000,
                inline_request_tokens: Some(inline_tokens),
            },
        }
    }

    fn new_composer() -> ReviewPacketComposer {
        ReviewPacketComposer::new("group-1".to_owned(), digest('c'))
    }

    #[test]
    fn small_group_inlines_complete_diff_once_then_rebases_to_manifest() {
        let mut composer = new_composer();
        let body = "@@ -1 +1 @@\n-old\n+new\n";
        let ready = composer.compose(input(body, 2_000)).unwrap();
        let ReviewPacketComposition::Ready(packet) = ready else {
            panic!("expected ready packet");
        };
        assert!(matches!(
            packet.diff_context,
            ReviewPacketDiffContext::InlineComplete { .. }
        ));
        assert!(composer.inline_diff_issued());

        let mut next = input(body, 2_000);
        next.purpose = ReviewPacketPurpose::ReviewRound { round: 1 };
        next.complete_diff = None;
        next.token_estimates.inline_request_tokens = None;
        next.recent_exchange = Some(ReviewPacketRecentExchange {
            assistant_calls: vec![ReviewPacketToolCall {
                call_id: "call-1".to_owned(),
                tool_name: "read_diff".to_owned(),
                arguments: serde_json::json!({"hunk_id": "hunk-1"}),
            }],
            tool_results: vec![ReviewPacketToolResult {
                call_id: "call-1".to_owned(),
                tool_name: "read_diff".to_owned(),
                body: "latest bounded tool result".to_owned(),
                truncated: false,
            }],
        });
        let ReviewPacketComposition::Ready(packet) = composer.compose(next).unwrap() else {
            panic!("expected ready packet");
        };
        assert!(matches!(
            packet.diff_context,
            ReviewPacketDiffContext::ManifestOnly(_)
        ));
        assert!(packet.recent_exchange.is_some());
    }

    #[test]
    fn large_groups_are_manifest_only_and_have_no_partial_inline_variant() {
        let mut composer = new_composer();
        let mut large_input = input("metadata placeholder", 2_000);
        large_input.diff_manifest.complete_diff_bytes = 20_000;
        large_input.diff_manifest.complete_diff_sha256 = digest('e');
        large_input.complete_diff = Some(ReviewPacketCompleteDiff::LargeManifestOnly {
            sha256: digest('e'),
            bytes: 20_000,
        });
        large_input.token_estimates.inline_request_tokens = None;
        let ReviewPacketComposition::Ready(packet) = composer.compose(large_input).unwrap() else {
            panic!("expected ready packet");
        };
        assert!(matches!(
            packet.diff_context,
            ReviewPacketDiffContext::ManifestOnly(_)
        ));

        let oversized_body = "x".repeat(16_385);
        assert_eq!(
            new_composer().compose(input(&oversized_body, 5_000)),
            Err(ReviewPacketError::PartialInline)
        );
    }

    #[test]
    fn token_pressure_uses_manifest_and_mandatory_overflow_is_partial() {
        let mut composer = new_composer();
        let ReviewPacketComposition::Ready(packet) = composer
            .compose(input("small complete diff", 32_001))
            .unwrap()
        else {
            panic!("expected manifest fallback");
        };
        assert!(matches!(
            packet.diff_context,
            ReviewPacketDiffContext::ManifestOnly(_)
        ));

        let mut composer = new_composer();
        let mut oversized = input("small complete diff", 32_001);
        oversized.token_estimates.manifest_request_tokens = 32_001;
        assert_eq!(
            composer.compose(oversized).unwrap(),
            ReviewPacketComposition::Partial(ReviewPacketPartialFailure::MandatoryContextTooLarge)
        );
        assert!(!composer.inline_diff_issued());
    }

    #[test]
    fn checkpoint_exchange_and_summary_bounds_fail_closed() {
        let mut invalid = input("small diff", 2_000);
        invalid.checkpoint.hypotheses = vec!["x".repeat(513)];
        assert_eq!(
            new_composer().compose(invalid),
            Err(ReviewPacketError::Checkpoint)
        );

        let mut invalid = input("small diff", 2_000);
        invalid.recent_exchange = Some(ReviewPacketRecentExchange {
            assistant_calls: vec![ReviewPacketToolCall {
                call_id: "call-1".to_owned(),
                tool_name: "read_diff".to_owned(),
                arguments: serde_json::json!({}),
            }],
            tool_results: vec![ReviewPacketToolResult {
                call_id: "call-2".to_owned(),
                tool_name: "read_diff".to_owned(),
                body: "result".to_owned(),
                truncated: false,
            }],
        });
        assert_eq!(
            new_composer().compose(invalid),
            Err(ReviewPacketError::Exchange)
        );
    }

    #[test]
    fn debug_surfaces_redact_diff_tool_and_checkpoint_payloads() {
        let mut input = input("private diff sentinel", 2_000);
        input.checkpoint.hypotheses = vec!["private checkpoint sentinel".to_owned()];
        input.recent_exchange = Some(ReviewPacketRecentExchange {
            assistant_calls: vec![ReviewPacketToolCall {
                call_id: "call-1".to_owned(),
                tool_name: "read_diff".to_owned(),
                arguments: serde_json::json!({"secret": "argument sentinel"}),
            }],
            tool_results: vec![ReviewPacketToolResult {
                call_id: "call-1".to_owned(),
                tool_name: "read_diff".to_owned(),
                body: "tool result sentinel".to_owned(),
                truncated: false,
            }],
        });
        let debug = format!("{input:?}");
        for secret in [
            "private diff sentinel",
            "private checkpoint sentinel",
            "argument sentinel",
            "tool result sentinel",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("[redacted]"));
    }
}
