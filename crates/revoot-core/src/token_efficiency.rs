//! Payload-free token-efficiency measurement and acceptance gates.
//!
//! Measurements retain only counts, sizes, stable labels, and token estimates.
//! They never retain request text, source, diff bodies, or tool-result bodies.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ReviewEffort, Sha256Digest};

const DEFAULT_REQUEST_TOKEN_TARGET: u64 = 96_000;
const MAX_TOOL_RESULT_BYTES: u32 = 32 * 1024;
const MAX_GROUPS: usize = 128;
const MAX_REQUESTS: usize = 256;
const MAX_RESULTS_PER_REQUEST: usize = 128;
const MAX_DELIVERIES_PER_REQUEST: usize = 4_096;
const MAX_LABEL_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EfficiencyPhase {
    Grouping,
    Planning,
    GroupInitial,
    ReviewRound,
    Verification,
    Adjudication,
}

/// Body-free metadata for one selected semantic group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EfficiencyGroup {
    pub group_id: String,
    pub file_count: u32,
    pub full_diff_bytes: u64,
    pub full_diff_estimated_tokens: u64,
    pub max_inline_diff_bytes: u64,
}

/// Size-only record for one tool result carried into a request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EfficiencyToolResult {
    pub result_id: String,
    pub bytes: u32,
}

/// Size-only record for one exact hunk page first delivered to a worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EfficiencyHunkDelivery {
    pub delivery_id: String,
    pub bytes: u32,
}

/// Accounting record for one model request without its payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EfficiencyRequest {
    pub request_id: String,
    pub phase: EfficiencyPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round: Option<u8>,
    pub payload_bytes: u64,
    pub estimated_input_tokens: u64,
    pub diff_body_bytes: u64,
    pub diff_body_estimated_tokens: u64,
    pub tool_results: Vec<EfficiencyToolResult>,
    pub hunk_deliveries: Vec<EfficiencyHunkDelivery>,
}

/// Aggregate request measurements for one phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EfficiencyPhaseTotals {
    pub phase: EfficiencyPhase,
    pub requests: u32,
    pub payload_bytes: u64,
    pub estimated_input_tokens: u64,
    pub diff_body_bytes: u64,
    pub tool_result_bytes: u64,
}

/// Derived gate evidence for one deterministic review simulation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEfficiencyReport {
    pub schema_version: String,
    pub effort: ReviewEffort,
    pub request_token_target: u64,
    pub groups: Vec<EfficiencyGroup>,
    pub requests: Vec<EfficiencyRequest>,
    pub phase_totals: Vec<EfficiencyPhaseTotals>,
    pub selected_files: u32,
    pub selected_diff_bytes: u64,
    pub actual_input_tokens: u64,
    pub full_diff_reinsert_baseline_tokens: u64,
    pub actual_percent_of_baseline: u16,
    pub report_sha256: Sha256Digest,
}

impl TokenEfficiencyReport {
    pub const SCHEMA_VERSION: &'static str = "revoot.token-efficiency/v1";

    /// Validate all size gates, uniqueness, totals, baseline accounting, and
    /// the medium-effort 40% threshold.
    ///
    /// # Errors
    ///
    /// Returns the first structural or efficiency-gate failure.
    pub fn validate(&self) -> Result<(), TokenEfficiencyError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(TokenEfficiencyError::SchemaVersion);
        }
        validate_groups(&self.groups)?;
        validate_requests(&self.requests, &self.groups, self.request_token_target)?;
        if self.requests.iter().any(|request| {
            request.phase == EfficiencyPhase::ReviewRound
                && request
                    .round
                    .is_none_or(|round| round == 0 || round > self.effort.rounds())
        }) {
            return Err(TokenEfficiencyError::InvalidRequest);
        }
        let derived = derive_totals(&self.groups, &self.requests)?;
        if self.phase_totals != derived.phase_totals
            || self.selected_files != derived.selected_files
            || self.selected_diff_bytes != derived.selected_diff_bytes
            || self.actual_input_tokens != derived.actual_tokens
            || self.full_diff_reinsert_baseline_tokens != derived.baseline_tokens
            || self.actual_percent_of_baseline
                != percent_rounded_up(derived.actual_tokens, derived.baseline_tokens)?
        {
            return Err(TokenEfficiencyError::Totals);
        }
        if self.effort == ReviewEffort::Medium
            && u128::from(self.actual_input_tokens) * 100
                > u128::from(self.full_diff_reinsert_baseline_tokens) * 40
        {
            return Err(TokenEfficiencyError::MediumEfficiencyGate);
        }
        if self.report_sha256 != report_digest(self)? {
            return Err(TokenEfficiencyError::ReportDigest);
        }
        Ok(())
    }

    /// Serialize a fully validated metadata-only report.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed JSON serialization error.
    pub fn canonical_json(&self) -> Result<Vec<u8>, TokenEfficiencyError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| TokenEfficiencyError::Serialization)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEfficiencyError {
    SchemaVersion,
    InvalidTarget,
    TooManyGroups,
    InvalidGroup,
    DuplicateGroup,
    TooManyRequests,
    InvalidRequest,
    DuplicateRequest,
    UnknownGroup,
    DiffInGrouping,
    DiffInLargeInitialRequest,
    ToolResultTooLarge,
    RequestTokenTarget,
    RepeatedHunkDelivery,
    MissingReviewBaseline,
    Overflow,
    Totals,
    MediumEfficiencyGate,
    ReportDigest,
    Serialization,
}

impl fmt::Display for TokenEfficiencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "the token-efficiency schema version is invalid",
            Self::InvalidTarget => "the request token target is invalid",
            Self::TooManyGroups => "the token-efficiency group limit was exceeded",
            Self::InvalidGroup => "a token-efficiency group is invalid",
            Self::DuplicateGroup => "a token-efficiency group is duplicated",
            Self::TooManyRequests => "the token-efficiency request limit was exceeded",
            Self::InvalidRequest => "a token-efficiency request is invalid",
            Self::DuplicateRequest => "a token-efficiency request is duplicated",
            Self::UnknownGroup => "a token-efficiency request names an unknown group",
            Self::DiffInGrouping => "a grouping request contains diff-body bytes",
            Self::DiffInLargeInitialRequest => {
                "a large-group initial request contains diff-body bytes"
            }
            Self::ToolResultTooLarge => "a tool result exceeds 32 KiB",
            Self::RequestTokenTarget => "a request exceeds its token target",
            Self::RepeatedHunkDelivery => "a hunk page was delivered more than once",
            Self::MissingReviewBaseline => "the full-diff reinsert baseline is unavailable",
            Self::Overflow => "token-efficiency accounting overflowed",
            Self::Totals => "token-efficiency aggregate totals do not match",
            Self::MediumEfficiencyGate => "medium-effort input exceeds 40% of the baseline",
            Self::ReportDigest => "the token-efficiency report digest is invalid",
            Self::Serialization => "the token-efficiency report could not be serialized",
        })
    }
}

impl std::error::Error for TokenEfficiencyError {}

/// Build and validate one canonical efficiency report.
///
/// # Errors
///
/// Rejects unsafe labels, excessive measurements, any fixed gate violation,
/// accounting overflow, or failure of the medium-effort ratio.
pub fn measure_token_efficiency(
    effort: ReviewEffort,
    request_token_target: u64,
    mut groups: Vec<EfficiencyGroup>,
    mut requests: Vec<EfficiencyRequest>,
) -> Result<TokenEfficiencyReport, TokenEfficiencyError> {
    if request_token_target == 0 || request_token_target > DEFAULT_REQUEST_TOKEN_TARGET {
        return Err(TokenEfficiencyError::InvalidTarget);
    }
    groups.sort_by(|left, right| left.group_id.cmp(&right.group_id));
    requests.sort_by(|left, right| {
        left.phase
            .cmp(&right.phase)
            .then_with(|| left.group_id.cmp(&right.group_id))
            .then_with(|| left.round.cmp(&right.round))
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
    validate_groups(&groups)?;
    validate_requests(&requests, &groups, request_token_target)?;
    let derived = derive_totals(&groups, &requests)?;
    let mut report = TokenEfficiencyReport {
        schema_version: TokenEfficiencyReport::SCHEMA_VERSION.to_owned(),
        effort,
        request_token_target,
        groups,
        requests,
        phase_totals: derived.phase_totals,
        selected_files: derived.selected_files,
        selected_diff_bytes: derived.selected_diff_bytes,
        actual_input_tokens: derived.actual_tokens,
        full_diff_reinsert_baseline_tokens: derived.baseline_tokens,
        actual_percent_of_baseline: percent_rounded_up(
            derived.actual_tokens,
            derived.baseline_tokens,
        )?,
        report_sha256: Sha256Digest::of_bytes(&[]),
    };
    report.report_sha256 = report_digest(&report)?;
    report.validate()?;
    Ok(report)
}

struct DerivedTotals {
    phase_totals: Vec<EfficiencyPhaseTotals>,
    selected_files: u32,
    selected_diff_bytes: u64,
    actual_tokens: u64,
    baseline_tokens: u64,
}

fn validate_groups(groups: &[EfficiencyGroup]) -> Result<(), TokenEfficiencyError> {
    if groups.is_empty() || groups.len() > MAX_GROUPS {
        return Err(TokenEfficiencyError::TooManyGroups);
    }
    let mut previous: Option<&str> = None;
    for group in groups {
        if previous.is_some_and(|value| value >= group.group_id.as_str()) {
            return Err(if previous == Some(group.group_id.as_str()) {
                TokenEfficiencyError::DuplicateGroup
            } else {
                TokenEfficiencyError::InvalidGroup
            });
        }
        previous = Some(&group.group_id);
        if !valid_label(&group.group_id)
            || group.file_count == 0
            || group.full_diff_bytes == 0
            || group.full_diff_estimated_tokens == 0
            || group.max_inline_diff_bytes == 0
            || group.max_inline_diff_bytes > 16 * 1024
        {
            return Err(TokenEfficiencyError::InvalidGroup);
        }
    }
    Ok(())
}

fn validate_requests(
    requests: &[EfficiencyRequest],
    groups: &[EfficiencyGroup],
    request_token_target: u64,
) -> Result<(), TokenEfficiencyError> {
    if request_token_target == 0 || request_token_target > DEFAULT_REQUEST_TOKEN_TARGET {
        return Err(TokenEfficiencyError::InvalidTarget);
    }
    if requests.is_empty() || requests.len() > MAX_REQUESTS {
        return Err(TokenEfficiencyError::TooManyRequests);
    }
    let groups = groups
        .iter()
        .map(|group| (group.group_id.as_str(), group))
        .collect::<BTreeMap<_, _>>();
    let mut request_ids = BTreeSet::new();
    let mut delivery_ids = BTreeSet::new();
    for request in requests {
        if !valid_label(&request.request_id)
            || request.payload_bytes == 0
            || request.estimated_input_tokens == 0
            || request.diff_body_bytes > request.payload_bytes
            || request.diff_body_estimated_tokens > request.estimated_input_tokens
            || request.tool_results.len() > MAX_RESULTS_PER_REQUEST
            || request.hunk_deliveries.len() > MAX_DELIVERIES_PER_REQUEST
        {
            return Err(TokenEfficiencyError::InvalidRequest);
        }
        if !request_ids.insert(&request.request_id) {
            return Err(TokenEfficiencyError::DuplicateRequest);
        }
        if request.estimated_input_tokens > request_token_target {
            return Err(TokenEfficiencyError::RequestTokenTarget);
        }
        let group = match &request.group_id {
            Some(group_id) => Some(
                groups
                    .get(group_id.as_str())
                    .ok_or(TokenEfficiencyError::UnknownGroup)?,
            ),
            None => None,
        };
        if request.phase == EfficiencyPhase::Grouping {
            if request.group_id.is_some() || request.round.is_some() {
                return Err(TokenEfficiencyError::InvalidRequest);
            }
            if request.diff_body_bytes != 0 || request.diff_body_estimated_tokens != 0 {
                return Err(TokenEfficiencyError::DiffInGrouping);
            }
        } else if request.phase == EfficiencyPhase::GroupInitial {
            let group = group.ok_or(TokenEfficiencyError::InvalidRequest)?;
            if request.round.is_some() {
                return Err(TokenEfficiencyError::InvalidRequest);
            }
            if group.full_diff_bytes > group.max_inline_diff_bytes
                && (request.diff_body_bytes != 0 || request.diff_body_estimated_tokens != 0)
            {
                return Err(TokenEfficiencyError::DiffInLargeInitialRequest);
            }
        } else if request.phase == EfficiencyPhase::ReviewRound {
            if group.is_none() || request.round.is_none_or(|round| round == 0) {
                return Err(TokenEfficiencyError::InvalidRequest);
            }
        } else if request.round.is_some() {
            return Err(TokenEfficiencyError::InvalidRequest);
        }
        let mut result_ids = BTreeSet::new();
        for result in &request.tool_results {
            if !valid_label(&result.result_id) || !result_ids.insert(&result.result_id) {
                return Err(TokenEfficiencyError::InvalidRequest);
            }
            if result.bytes > MAX_TOOL_RESULT_BYTES {
                return Err(TokenEfficiencyError::ToolResultTooLarge);
            }
        }
        let mut request_deliveries = BTreeSet::new();
        for delivery in &request.hunk_deliveries {
            let group_id = request
                .group_id
                .as_deref()
                .ok_or(TokenEfficiencyError::InvalidRequest)?;
            if !valid_label(&delivery.delivery_id)
                || delivery.bytes == 0
                || delivery.bytes > MAX_TOOL_RESULT_BYTES
                || !request_deliveries.insert(&delivery.delivery_id)
                || !delivery_ids.insert((group_id, delivery.delivery_id.as_str()))
            {
                return Err(TokenEfficiencyError::RepeatedHunkDelivery);
            }
        }
    }
    Ok(())
}

fn derive_totals(
    groups: &[EfficiencyGroup],
    requests: &[EfficiencyRequest],
) -> Result<DerivedTotals, TokenEfficiencyError> {
    let group_map = groups
        .iter()
        .map(|group| (group.group_id.as_str(), group))
        .collect::<BTreeMap<_, _>>();
    let selected_files = groups.iter().try_fold(0_u32, |sum, group| {
        sum.checked_add(group.file_count)
            .ok_or(TokenEfficiencyError::Overflow)
    })?;
    let selected_diff_bytes = groups.iter().try_fold(0_u64, |sum, group| {
        sum.checked_add(group.full_diff_bytes)
            .ok_or(TokenEfficiencyError::Overflow)
    })?;
    let mut phases: BTreeMap<EfficiencyPhase, EfficiencyPhaseTotals> = BTreeMap::new();
    let mut actual_tokens = 0_u64;
    let mut baseline_tokens = 0_u64;
    let mut review_rounds = 0_u32;
    for request in requests {
        actual_tokens = actual_tokens
            .checked_add(request.estimated_input_tokens)
            .ok_or(TokenEfficiencyError::Overflow)?;
        let phase = phases
            .entry(request.phase)
            .or_insert(EfficiencyPhaseTotals {
                phase: request.phase,
                requests: 0,
                payload_bytes: 0,
                estimated_input_tokens: 0,
                diff_body_bytes: 0,
                tool_result_bytes: 0,
            });
        phase.requests = phase
            .requests
            .checked_add(1)
            .ok_or(TokenEfficiencyError::Overflow)?;
        phase.payload_bytes = phase
            .payload_bytes
            .checked_add(request.payload_bytes)
            .ok_or(TokenEfficiencyError::Overflow)?;
        phase.estimated_input_tokens = phase
            .estimated_input_tokens
            .checked_add(request.estimated_input_tokens)
            .ok_or(TokenEfficiencyError::Overflow)?;
        phase.diff_body_bytes = phase
            .diff_body_bytes
            .checked_add(request.diff_body_bytes)
            .ok_or(TokenEfficiencyError::Overflow)?;
        phase.tool_result_bytes =
            request
                .tool_results
                .iter()
                .try_fold(phase.tool_result_bytes, |sum, result| {
                    sum.checked_add(u64::from(result.bytes))
                        .ok_or(TokenEfficiencyError::Overflow)
                })?;
        let baseline = if request.phase == EfficiencyPhase::ReviewRound {
            review_rounds = review_rounds
                .checked_add(1)
                .ok_or(TokenEfficiencyError::Overflow)?;
            let group = group_map
                .get(
                    request
                        .group_id
                        .as_deref()
                        .ok_or(TokenEfficiencyError::UnknownGroup)?,
                )
                .ok_or(TokenEfficiencyError::UnknownGroup)?;
            request
                .estimated_input_tokens
                .checked_sub(request.diff_body_estimated_tokens)
                .and_then(|tokens| tokens.checked_add(group.full_diff_estimated_tokens))
                .ok_or(TokenEfficiencyError::Overflow)?
        } else {
            request.estimated_input_tokens
        };
        baseline_tokens = baseline_tokens
            .checked_add(baseline)
            .ok_or(TokenEfficiencyError::Overflow)?;
    }
    if review_rounds == 0 || baseline_tokens == 0 {
        return Err(TokenEfficiencyError::MissingReviewBaseline);
    }
    Ok(DerivedTotals {
        phase_totals: phases.into_values().collect(),
        selected_files,
        selected_diff_bytes,
        actual_tokens,
        baseline_tokens,
    })
}

fn percent_rounded_up(actual: u64, baseline: u64) -> Result<u16, TokenEfficiencyError> {
    if baseline == 0 {
        return Err(TokenEfficiencyError::MissingReviewBaseline);
    }
    let percent = (u128::from(actual) * 100).div_ceil(u128::from(baseline));
    u16::try_from(percent.min(u128::from(u16::MAX))).map_err(|_| TokenEfficiencyError::Overflow)
}

fn report_digest(report: &TokenEfficiencyReport) -> Result<Sha256Digest, TokenEfficiencyError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        effort: ReviewEffort,
        request_token_target: u64,
        groups: &'a [EfficiencyGroup],
        requests: &'a [EfficiencyRequest],
        phase_totals: &'a [EfficiencyPhaseTotals],
        selected_files: u32,
        selected_diff_bytes: u64,
        actual_input_tokens: u64,
        full_diff_reinsert_baseline_tokens: u64,
        actual_percent_of_baseline: u16,
    }
    serde_json::to_vec(&DigestInput {
        schema_version: &report.schema_version,
        effort: report.effort,
        request_token_target: report.request_token_target,
        groups: &report.groups,
        requests: &report.requests,
        phase_totals: &report.phase_totals,
        selected_files: report.selected_files,
        selected_diff_bytes: report.selected_diff_bytes,
        actual_input_tokens: report.actual_input_tokens,
        full_diff_reinsert_baseline_tokens: report.full_diff_reinsert_baseline_tokens,
        actual_percent_of_baseline: report.actual_percent_of_baseline,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| TokenEfficiencyError::Serialization)
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_groups() -> Vec<EfficiencyGroup> {
        let base = 1024 * 1024 / 10;
        let remainder = 1024 * 1024 % 10;
        (0..10)
            .map(|index| {
                let bytes = base + usize::from(index < remainder);
                EfficiencyGroup {
                    group_id: format!("group-{index:02}"),
                    file_count: 10,
                    full_diff_bytes: u64::try_from(bytes).unwrap(),
                    full_diff_estimated_tokens: u64::try_from(bytes.div_ceil(4)).unwrap(),
                    max_inline_diff_bytes: 16 * 1024,
                }
            })
            .collect()
    }

    fn synthetic_requests(groups: &[EfficiencyGroup]) -> Vec<EfficiencyRequest> {
        let mut requests = vec![EfficiencyRequest {
            request_id: "grouping".to_owned(),
            phase: EfficiencyPhase::Grouping,
            group_id: None,
            round: None,
            payload_bytes: 4_000,
            estimated_input_tokens: 1_000,
            diff_body_bytes: 0,
            diff_body_estimated_tokens: 0,
            tool_results: Vec::new(),
            hunk_deliveries: Vec::new(),
        }];
        for group in groups {
            requests.push(EfficiencyRequest {
                request_id: format!("{}-initial", group.group_id),
                phase: EfficiencyPhase::GroupInitial,
                group_id: Some(group.group_id.clone()),
                round: None,
                payload_bytes: 1_000,
                estimated_input_tokens: 250,
                diff_body_bytes: 0,
                diff_body_estimated_tokens: 0,
                tool_results: Vec::new(),
                hunk_deliveries: Vec::new(),
            });
            requests.push(EfficiencyRequest {
                request_id: format!("{}-round-1", group.group_id),
                phase: EfficiencyPhase::ReviewRound,
                group_id: Some(group.group_id.clone()),
                round: Some(1),
                payload_bytes: 10_000,
                estimated_input_tokens: 2_500,
                diff_body_bytes: 8_192,
                diff_body_estimated_tokens: 2_048,
                tool_results: vec![EfficiencyToolResult {
                    result_id: format!("{}-read", group.group_id),
                    bytes: 8_192,
                }],
                hunk_deliveries: vec![EfficiencyHunkDelivery {
                    delivery_id: "hunk-1-page-1".to_owned(),
                    bytes: 8_192,
                }],
            });
            requests.push(EfficiencyRequest {
                request_id: format!("{}-round-2", group.group_id),
                phase: EfficiencyPhase::ReviewRound,
                group_id: Some(group.group_id.clone()),
                round: Some(2),
                payload_bytes: 1_800,
                estimated_input_tokens: 450,
                diff_body_bytes: 0,
                diff_body_estimated_tokens: 0,
                tool_results: Vec::new(),
                hunk_deliveries: Vec::new(),
            });
        }
        requests
    }

    #[test]
    fn one_mib_hundred_file_medium_fixture_meets_every_gate() {
        let groups = synthetic_groups();
        assert_eq!(
            groups.iter().map(|group| group.file_count).sum::<u32>(),
            100
        );
        assert_eq!(
            groups
                .iter()
                .map(|group| group.full_diff_bytes)
                .sum::<u64>(),
            1024 * 1024
        );
        let report = measure_token_efficiency(
            ReviewEffort::Medium,
            96_000,
            groups.clone(),
            synthetic_requests(&groups),
        )
        .unwrap();
        assert_eq!(report.selected_files, 100);
        assert_eq!(report.selected_diff_bytes, 1024 * 1024);
        assert!(report.actual_percent_of_baseline <= 40);
        assert!(
            report
                .requests
                .iter()
                .all(|request| request.estimated_input_tokens <= 96_000)
        );
        assert!(
            report
                .requests
                .iter()
                .flat_map(|request| &request.tool_results)
                .all(|result| result.bytes <= 32 * 1024)
        );
        assert!(
            report
                .requests
                .iter()
                .filter(|request| matches!(
                    request.phase,
                    EfficiencyPhase::Grouping | EfficiencyPhase::GroupInitial
                ))
                .all(|request| request.diff_body_bytes == 0)
        );
        report.validate().unwrap();
    }

    #[test]
    fn grouping_and_large_initial_diff_bodies_are_rejected() {
        let groups = synthetic_groups();
        let mut requests = synthetic_requests(&groups);
        requests[0].diff_body_bytes = 1;
        requests[0].diff_body_estimated_tokens = 1;
        assert_eq!(
            measure_token_efficiency(ReviewEffort::Medium, 96_000, groups.clone(), requests),
            Err(TokenEfficiencyError::DiffInGrouping)
        );

        let mut requests = synthetic_requests(&groups);
        let initial = requests
            .iter_mut()
            .find(|request| request.phase == EfficiencyPhase::GroupInitial)
            .unwrap();
        initial.diff_body_bytes = 1;
        initial.diff_body_estimated_tokens = 1;
        assert_eq!(
            measure_token_efficiency(ReviewEffort::Medium, 96_000, groups, requests),
            Err(TokenEfficiencyError::DiffInLargeInitialRequest)
        );
    }

    #[test]
    fn result_request_and_repeat_delivery_gates_fail_closed() {
        let groups = synthetic_groups();
        let mut requests = synthetic_requests(&groups);
        requests
            .iter_mut()
            .find_map(|request| request.tool_results.first_mut())
            .unwrap()
            .bytes = 32 * 1024 + 1;
        assert_eq!(
            measure_token_efficiency(ReviewEffort::Medium, 96_000, groups.clone(), requests),
            Err(TokenEfficiencyError::ToolResultTooLarge)
        );

        let mut requests = synthetic_requests(&groups);
        requests[1].estimated_input_tokens = 96_001;
        assert_eq!(
            measure_token_efficiency(ReviewEffort::Medium, 96_000, groups.clone(), requests),
            Err(TokenEfficiencyError::RequestTokenTarget)
        );

        let mut requests = synthetic_requests(&groups);
        let repeated = requests
            .iter_mut()
            .find(|request| {
                request.phase == EfficiencyPhase::ReviewRound && request.round == Some(2)
            })
            .unwrap();
        repeated.hunk_deliveries.push(EfficiencyHunkDelivery {
            delivery_id: "hunk-1-page-1".to_owned(),
            bytes: 1,
        });
        assert_eq!(
            measure_token_efficiency(ReviewEffort::Medium, 96_000, groups, requests),
            Err(TokenEfficiencyError::RepeatedHunkDelivery)
        );
    }

    #[test]
    fn report_serialization_contains_only_measurements() {
        let groups = synthetic_groups();
        let report = measure_token_efficiency(
            ReviewEffort::Medium,
            96_000,
            groups.clone(),
            synthetic_requests(&groups),
        )
        .unwrap();
        let json = String::from_utf8(report.canonical_json().unwrap()).unwrap();
        for forbidden in [
            "artifact_path",
            "diff_body_text",
            "prompt",
            "response",
            "source_body",
            "tool_result_body",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
