//! Typed authority boundary for tool-first review strategy configuration.
//!
//! The existing configuration loader remains responsible for bounded TOML,
//! trusted-local, environment, and CLI parsing. This slice audits provenance,
//! enforces repository-only narrowing, and converts the effective scalar values
//! into one closed runtime strategy contract.

use std::ffi::OsString;
use std::fmt;
use std::path::Path;

use revoot_core::{
    ConfigSource, ConfigValue, ConfigurationResolution, Diagnostic, ErrorCode, GitSha,
    ReviewBudgetLimits, ReviewEffort, review_budget::conservative_model_cost_limit,
};
use serde::Serialize;

use crate::config::{ResolvedReviewConfiguration, resolve_review_configuration};

const DEFAULT_MODEL_REQUESTS: u64 = 64;
const MAX_MODEL_REQUESTS: u64 = 256;
const MAX_MODEL_TOKENS: u64 = 2_000_000;
const DEFAULT_TOOL_CALLS: u64 = 256;
const MAX_TOOL_CALLS: u64 = 2_048;
const DEFAULT_DEADLINE_SECONDS: u64 = 600;
const DEFAULT_INLINE_DIFF_BYTES: u64 = 16_384;
const MIN_PARALLEL_GROUPS: u64 = 1;
const DEFAULT_PARALLEL_GROUPS: u64 = 2;
const MAX_PARALLEL_GROUPS: u64 = 8;
const TARGET_REQUEST_INPUT_TOKENS: u64 = 96_000;

/// The aggregate token pool a full review draws its per-request reservations
/// from. Every reservation is deliberately pessimistic (one encoded request
/// byte reserves one token, with no discount for real tokenization - see
/// `estimate_wire_tokens`), so this pool has to be sized for
/// `DEFAULT_MODEL_REQUESTS` real requests each near
/// `TARGET_REQUEST_INPUT_TOKENS`, not for their much smaller actual token
/// cost. A flat 300,000 only covered about three worst-case requests before
/// `Exhausted(ModelTokens)` fired, starving every group after it regardless
/// of real usage - clamped to the existing `MAX_MODEL_TOKENS` ceiling
/// operators can already select, since `max_model_requests` and
/// `max_cost_microusd` (bounded independently, $0.50/request) remain the
/// real governors of total spend.
const DEFAULT_MODEL_TOKENS: u64 =
    if DEFAULT_MODEL_REQUESTS * TARGET_REQUEST_INPUT_TOKENS > MAX_MODEL_TOKENS {
        MAX_MODEL_TOKENS
    } else {
        DEFAULT_MODEL_REQUESTS * TARGET_REQUEST_INPUT_TOKENS
    };
const MAX_REQUEST_OUTPUT_TOKENS: u64 = 4_096;
const STRATEGY_VERSION: &str = "tool-first-v1";

/// Operator-selected and repository-narrowed runtime review strategy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStrategyConfiguration {
    pub strategy_version: &'static str,
    pub effort: ReviewEffort,
    pub max_parallel_groups: u8,
    pub max_inline_diff_bytes: u64,
    pub target_request_input_tokens: u64,
    pub max_request_output_tokens: u64,
    pub aggregate_budget: ReviewBudgetLimits,
}

impl Default for ReviewStrategyConfiguration {
    fn default() -> Self {
        let max_output_tokens = DEFAULT_MODEL_REQUESTS
            .saturating_mul(MAX_REQUEST_OUTPUT_TOKENS)
            .min(DEFAULT_MODEL_TOKENS);
        Self {
            strategy_version: STRATEGY_VERSION,
            effort: ReviewEffort::Medium,
            max_parallel_groups: u8::try_from(DEFAULT_PARALLEL_GROUPS)
                .expect("compiled parallelism fits u8"),
            max_inline_diff_bytes: DEFAULT_INLINE_DIFF_BYTES,
            target_request_input_tokens: TARGET_REQUEST_INPUT_TOKENS,
            max_request_output_tokens: MAX_REQUEST_OUTPUT_TOKENS,
            aggregate_budget: ReviewBudgetLimits {
                max_model_requests: u32::try_from(DEFAULT_MODEL_REQUESTS)
                    .expect("compiled request limit fits u32"),
                max_model_tokens: DEFAULT_MODEL_TOKENS,
                max_output_tokens,
                max_tool_calls: u32::try_from(DEFAULT_TOOL_CALLS)
                    .expect("compiled tool limit fits u32"),
                max_cost_microusd: conservative_model_cost_limit(DEFAULT_MODEL_REQUESTS)
                    .expect("compiled request ceiling has a representable cost reservation"),
                max_elapsed_millis: DEFAULT_DEADLINE_SECONDS * 1_000,
            },
        }
    }
}

/// Stable field identity for payload-free configuration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewStrategyField {
    Effort,
    ParallelGroups,
    ModelRequests,
    ModelTokens,
    ToolCalls,
    Deadline,
    InlineDiffBytes,
}

/// Closed failure from typed strategy resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewStrategyConfigError {
    MissingField(ReviewStrategyField),
    WrongType(ReviewStrategyField),
    InvalidValue(ReviewStrategyField),
    RepositoryAuthority(ReviewStrategyField),
    RepositoryExpansion(ReviewStrategyField),
    ExistingResolverConflict(ReviewStrategyField),
    AggregateBudget,
}

impl fmt::Display for ReviewStrategyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingField(_) => "review strategy configuration is missing a required field",
            Self::WrongType(_) => "review strategy configuration contains a wrong value type",
            Self::InvalidValue(_) => "review strategy configuration is outside product bounds",
            Self::RepositoryAuthority(_) => {
                "repository configuration attempted to control review strategy"
            }
            Self::RepositoryExpansion(_) => {
                "repository configuration attempted to expand a resource limit"
            }
            Self::ExistingResolverConflict(_) => {
                "existing configuration resolution conflicts with the review strategy contract"
            }
            Self::AggregateBudget => "review strategy aggregate budget is invalid",
        })
    }
}

impl std::error::Error for ReviewStrategyConfigError {}

/// Selected-file count above which an unconfigured effort escalates.
pub const LARGE_DIFF_ESCALATION_FILES: u32 = 40;
/// Selected-byte count above which an unconfigured effort escalates.
pub const LARGE_DIFF_ESCALATION_BYTES: u64 = 512 * 1024;

/// Escalate an unconfigured medium effort to high for a large selected diff.
///
/// Only the compiled default is ever escalated; an effort the operator, CI
/// variable, or command line explicitly selected is always left untouched,
/// preserving the existing operator-only authority over effort.
#[must_use]
pub fn escalate_effort_for_large_diff(
    mut strategy: ReviewStrategyConfiguration,
    resolution: &ConfigurationResolution,
    selected_files: u32,
    selected_bytes: u64,
) -> ReviewStrategyConfiguration {
    let large = selected_files > LARGE_DIFF_ESCALATION_FILES
        || selected_bytes > LARGE_DIFF_ESCALATION_BYTES;
    if strategy.effort == ReviewEffort::Medium && large && effort_is_compiled_default(resolution) {
        strategy.effort = ReviewEffort::High;
    }
    strategy
}

fn effort_is_compiled_default(resolution: &ConfigurationResolution) -> bool {
    resolution
        .explain()
        .iter()
        .find(|record| record.key.as_str() == "review.effort")
        .is_some_and(|record| {
            record.requested.provenance().source() == ConfigSource::CompiledDefault
        })
}

/// Resolve all trusted operator sources and the immutable base-repository
/// configuration, then construct the typed strategy contract.
///
/// # Errors
///
/// Returns existing redaction-safe configuration diagnostics or a typed
/// authority/range conflict converted to a contract diagnostic.
pub fn resolve_review_strategy_configuration(
    repository_root: &Path,
    base_sha: Option<&GitSha>,
    local_config: Option<&Path>,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<ReviewStrategyConfiguration, Diagnostic> {
    let resolved =
        resolve_review_configuration(repository_root, base_sha, local_config, environment)?;
    strategy_from_resolved(&resolved).map_err(strategy_diagnostic)
}

/// Audit one already-resolved configuration and build a closed strategy.
///
/// Repository candidates may lower resource limits only. Effort, concurrency,
/// the tool suite, and strategy shape remain compiled/operator authority.
///
/// # Errors
///
/// Rejects missing/wrong fields, out-of-range values, provenance violations,
/// repository expansion, and known mismatches in the existing scalar resolver.
pub fn strategy_from_resolved(
    resolved: &ResolvedReviewConfiguration,
) -> Result<ReviewStrategyConfiguration, ReviewStrategyConfigError> {
    let resolution = &resolved.effective;
    audit_authority(resolution)?;
    let scalars = resolve_scalars(resolution)?;
    Ok(ReviewStrategyConfiguration {
        strategy_version: STRATEGY_VERSION,
        effort: scalars.effort,
        max_parallel_groups: u8::try_from(scalars.max_parallel_groups).map_err(|_| {
            ReviewStrategyConfigError::InvalidValue(ReviewStrategyField::ParallelGroups)
        })?,
        max_inline_diff_bytes: scalars.max_inline_diff_bytes,
        target_request_input_tokens: TARGET_REQUEST_INPUT_TOKENS,
        max_request_output_tokens: MAX_REQUEST_OUTPUT_TOKENS,
        aggregate_budget: build_aggregate_budget(scalars)?,
    })
}

#[derive(Clone, Copy)]
struct StrategyScalars {
    effort: ReviewEffort,
    max_parallel_groups: u64,
    max_model_requests: u64,
    max_model_tokens: u64,
    max_tool_calls: u64,
    deadline_seconds: u64,
    max_inline_diff_bytes: u64,
}

fn resolve_scalars(
    resolution: &ConfigurationResolution,
) -> Result<StrategyScalars, ReviewStrategyConfigError> {
    let effort = match string(resolution, "review.effort", ReviewStrategyField::Effort)? {
        "low" => ReviewEffort::Low,
        "medium" => ReviewEffort::Medium,
        "high" => ReviewEffort::High,
        _ => {
            return Err(ReviewStrategyConfigError::InvalidValue(
                ReviewStrategyField::Effort,
            ));
        }
    };
    let max_parallel_groups = bounded_unsigned(
        resolution,
        "review.max_parallel_groups",
        ReviewStrategyField::ParallelGroups,
        MIN_PARALLEL_GROUPS,
        MAX_PARALLEL_GROUPS,
    )?;
    let max_model_requests = bounded_unsigned(
        resolution,
        "budget.max_model_requests",
        ReviewStrategyField::ModelRequests,
        1,
        MAX_MODEL_REQUESTS,
    )?;
    let max_model_tokens = bounded_unsigned(
        resolution,
        "budget.max_model_tokens",
        ReviewStrategyField::ModelTokens,
        1,
        MAX_MODEL_TOKENS,
    )?;
    let max_tool_calls = bounded_unsigned(
        resolution,
        "budget.max_tool_calls",
        ReviewStrategyField::ToolCalls,
        1,
        MAX_TOOL_CALLS,
    )?;
    let deadline_seconds = bounded_unsigned(
        resolution,
        "budget.deadline_seconds",
        ReviewStrategyField::Deadline,
        1,
        DEFAULT_DEADLINE_SECONDS,
    )?;
    let max_inline_diff_bytes = unsigned(
        resolution,
        "model_context.max_inline_diff_bytes",
        ReviewStrategyField::InlineDiffBytes,
    )?;
    if max_inline_diff_bytes == 0 {
        return Err(ReviewStrategyConfigError::InvalidValue(
            ReviewStrategyField::InlineDiffBytes,
        ));
    }
    if max_inline_diff_bytes > DEFAULT_INLINE_DIFF_BYTES {
        return Err(ReviewStrategyConfigError::ExistingResolverConflict(
            ReviewStrategyField::InlineDiffBytes,
        ));
    }
    Ok(StrategyScalars {
        effort,
        max_parallel_groups,
        max_model_requests,
        max_model_tokens,
        max_tool_calls,
        deadline_seconds,
        max_inline_diff_bytes,
    })
}

fn build_aggregate_budget(
    scalars: StrategyScalars,
) -> Result<ReviewBudgetLimits, ReviewStrategyConfigError> {
    let maximum_aggregate_output = scalars
        .max_model_requests
        .checked_mul(MAX_REQUEST_OUTPUT_TOKENS)
        .ok_or(ReviewStrategyConfigError::AggregateBudget)?
        .min(scalars.max_model_tokens);
    let maximum_aggregate_cost = conservative_model_cost_limit(scalars.max_model_requests)
        .ok_or(ReviewStrategyConfigError::AggregateBudget)?;
    let aggregate_budget = ReviewBudgetLimits {
        max_model_requests: u32::try_from(scalars.max_model_requests).map_err(|_| {
            ReviewStrategyConfigError::InvalidValue(ReviewStrategyField::ModelRequests)
        })?,
        max_model_tokens: scalars.max_model_tokens,
        max_output_tokens: maximum_aggregate_output,
        max_tool_calls: u32::try_from(scalars.max_tool_calls)
            .map_err(|_| ReviewStrategyConfigError::InvalidValue(ReviewStrategyField::ToolCalls))?,
        max_cost_microusd: maximum_aggregate_cost,
        max_elapsed_millis: scalars
            .deadline_seconds
            .checked_mul(1_000)
            .ok_or(ReviewStrategyConfigError::AggregateBudget)?,
    };
    aggregate_budget
        .validate()
        .map_err(|_| ReviewStrategyConfigError::AggregateBudget)?;
    Ok(aggregate_budget)
}

fn audit_authority(resolution: &ConfigurationResolution) -> Result<(), ReviewStrategyConfigError> {
    for (key, field) in [
        ("review.effort", ReviewStrategyField::Effort),
        (
            "review.max_parallel_groups",
            ReviewStrategyField::ParallelGroups,
        ),
    ] {
        for candidate in candidates(resolution, key, field)? {
            if candidate.provenance.source() == ConfigSource::BaseRepository {
                return Err(ReviewStrategyConfigError::RepositoryAuthority(field));
            }
        }
    }
    for (key, field, default) in [
        (
            "budget.max_model_requests",
            ReviewStrategyField::ModelRequests,
            DEFAULT_MODEL_REQUESTS,
        ),
        (
            "budget.max_model_tokens",
            ReviewStrategyField::ModelTokens,
            DEFAULT_MODEL_TOKENS,
        ),
        (
            "budget.max_tool_calls",
            ReviewStrategyField::ToolCalls,
            DEFAULT_TOOL_CALLS,
        ),
        (
            "budget.deadline_seconds",
            ReviewStrategyField::Deadline,
            DEFAULT_DEADLINE_SECONDS,
        ),
        (
            "model_context.max_inline_diff_bytes",
            ReviewStrategyField::InlineDiffBytes,
            DEFAULT_INLINE_DIFF_BYTES,
        ),
    ] {
        for candidate in candidates(resolution, key, field)? {
            if candidate.provenance.source() != ConfigSource::BaseRepository {
                continue;
            }
            let ConfigValue::Unsigned(value) = candidate.value else {
                return Err(ReviewStrategyConfigError::WrongType(field));
            };
            if value > default {
                return Err(ReviewStrategyConfigError::RepositoryExpansion(field));
            }
        }
    }
    Ok(())
}

fn candidates<'a>(
    resolution: &'a ConfigurationResolution,
    key: &str,
    field: ReviewStrategyField,
) -> Result<&'a [revoot_core::ConfigCandidate], ReviewStrategyConfigError> {
    resolution
        .explain()
        .iter()
        .find(|record| record.key.as_str() == key)
        .map(|record| record.candidates.as_slice())
        .ok_or(ReviewStrategyConfigError::MissingField(field))
}

fn unsigned(
    resolution: &ConfigurationResolution,
    key: &str,
    field: ReviewStrategyField,
) -> Result<u64, ReviewStrategyConfigError> {
    match resolution.effective().get(key) {
        Some(ConfigValue::Unsigned(value)) => Ok(*value),
        Some(_) => Err(ReviewStrategyConfigError::WrongType(field)),
        None => Err(ReviewStrategyConfigError::MissingField(field)),
    }
}

fn string<'a>(
    resolution: &'a ConfigurationResolution,
    key: &str,
    field: ReviewStrategyField,
) -> Result<&'a str, ReviewStrategyConfigError> {
    match resolution.effective().get(key) {
        Some(ConfigValue::String(value)) => Ok(value),
        Some(_) => Err(ReviewStrategyConfigError::WrongType(field)),
        None => Err(ReviewStrategyConfigError::MissingField(field)),
    }
}

fn require_range(
    value: u64,
    minimum: u64,
    maximum: u64,
    field: ReviewStrategyField,
) -> Result<(), ReviewStrategyConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(ReviewStrategyConfigError::InvalidValue(field))
    }
}

fn bounded_unsigned(
    resolution: &ConfigurationResolution,
    key: &str,
    field: ReviewStrategyField,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ReviewStrategyConfigError> {
    let value = unsigned(resolution, key, field)?;
    require_range(value, minimum, maximum, field)?;
    Ok(value)
}

fn strategy_diagnostic(error: ReviewStrategyConfigError) -> Diagnostic {
    Diagnostic::new(ErrorCode::ContractInvalid, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use revoot_core::review_budget::CONSERVATIVE_MODEL_CALL_COST_MICROUSD;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn compiled_defaults_match_the_fixed_strategy_contract() {
        let root = tempfile::tempdir().expect("root");
        let strategy = resolve(root.path(), []).expect("strategy");
        assert_eq!(strategy, ReviewStrategyConfiguration::default());
        assert_eq!(strategy.effort, ReviewEffort::Medium);
        assert_eq!(strategy.max_parallel_groups, 2);
        assert_eq!(strategy.aggregate_budget.max_model_requests, 64);
        assert_eq!(
            strategy.aggregate_budget.max_cost_microusd,
            64 * CONSERVATIVE_MODEL_CALL_COST_MICROUSD
        );
        assert_eq!(strategy.aggregate_budget.max_model_tokens, 2_000_000);
        assert_eq!(strategy.aggregate_budget.max_tool_calls, 256);
        assert_eq!(strategy.aggregate_budget.max_elapsed_millis, 600_000);
        assert_eq!(strategy.max_inline_diff_bytes, 16_384);
        assert_eq!(strategy.target_request_input_tokens, 96_000);
        assert_eq!(strategy.max_request_output_tokens, 4_096);
        assert_eq!(strategy.strategy_version, "tool-first-v1");
    }

    #[test]
    fn trusted_environment_uses_operator_ranges() {
        let root = tempfile::tempdir().expect("root");
        let strategy = resolve(
            root.path(),
            [
                ("REVOOT_REVIEW_EFFORT", "high"),
                ("REVOOT_MAX_PARALLEL_GROUPS", "8"),
                ("REVOOT_MAX_MODEL_REQUESTS", "256"),
                ("REVOOT_MAX_MODEL_TOKENS", "2000000"),
                ("REVOOT_MAX_TOOL_CALLS", "2048"),
                ("REVOOT_DEADLINE_SECONDS", "1"),
                ("REVOOT_MAX_INLINE_DIFF_BYTES", "16384"),
            ],
        )
        .expect("strategy");
        assert_eq!(strategy.effort, ReviewEffort::High);
        assert_eq!(strategy.max_parallel_groups, 8);
        assert_eq!(strategy.aggregate_budget.max_model_requests, 256);
        assert_eq!(
            strategy.aggregate_budget.max_cost_microusd,
            256 * CONSERVATIVE_MODEL_CALL_COST_MICROUSD
        );
        assert_eq!(strategy.aggregate_budget.max_model_tokens, 2_000_000);
        assert_eq!(strategy.aggregate_budget.max_tool_calls, 2_048);
        assert_eq!(strategy.aggregate_budget.max_elapsed_millis, 1_000);
        assert_eq!(strategy.aggregate_budget.max_output_tokens, 256 * 4_096);
    }

    #[test]
    fn repository_can_only_narrow_resource_fields() {
        let root = repository_config(
            "version = 1\n[budget]\nmax_model_requests = 12\nmax_model_tokens = 200000\nmax_tool_calls = 100\ndeadline_seconds = 300\n[model_context]\nmax_inline_diff_bytes = 8000\n",
        );
        let strategy = resolve(root.path(), []).expect("strategy");
        assert_eq!(strategy.aggregate_budget.max_model_requests, 12);
        assert_eq!(
            strategy.aggregate_budget.max_cost_microusd,
            12 * CONSERVATIVE_MODEL_CALL_COST_MICROUSD
        );
        assert_eq!(strategy.aggregate_budget.max_model_tokens, 200_000);
        assert_eq!(strategy.aggregate_budget.max_tool_calls, 100);
        assert_eq!(strategy.aggregate_budget.max_elapsed_millis, 300_000);
        assert_eq!(strategy.max_inline_diff_bytes, 8_000);
        assert_eq!(strategy.effort, ReviewEffort::Medium);
        assert_eq!(strategy.max_parallel_groups, 2);
    }

    #[test]
    fn repository_deadline_expansion_is_rejected() {
        let root = repository_config("version = 1\n[budget]\ndeadline_seconds = 601\n");
        let error = resolve(root.path(), []).expect_err("repository expansion");
        assert_eq!(error.code, ErrorCode::ContractInvalid);
    }

    #[test]
    fn trusted_inline_threshold_cannot_exceed_fixed_limit() {
        let root = tempfile::tempdir().expect("root");
        let error = resolve(root.path(), [("REVOOT_MAX_INLINE_DIFF_BYTES", "65536")])
            .expect_err("fixed inline threshold");
        assert_eq!(error.code, ErrorCode::ContractInvalid);
    }

    #[test]
    fn repository_cannot_select_effort_concurrency_tools_or_strategy() {
        for document in [
            "version = 1\n[review]\neffort = \"high\"\n",
            "version = 1\n[review]\nmax_parallel_groups = 8\n",
            "version = 1\n[tools]\nenabled = [\"shell\"]\n",
            "version = 1\n[strategy]\nmode = \"prompt-first\"\n",
        ] {
            let root = repository_config(document);
            let error = resolve(root.path(), []).expect_err("repository authority");
            assert_eq!(error.code, ErrorCode::ContractInvalid);
        }
    }

    #[test]
    fn operator_overrides_repository_narrowing_within_product_bounds() {
        let root = repository_config(
            "version = 1\n[budget]\nmax_model_tokens = 100000\nmax_tool_calls = 32\ndeadline_seconds = 300\n[model_context]\nmax_inline_diff_bytes = 8000\n",
        );
        let strategy = resolve(
            root.path(),
            [
                ("REVOOT_MAX_MODEL_TOKENS", "500000"),
                ("REVOOT_MAX_TOOL_CALLS", "512"),
                ("REVOOT_DEADLINE_SECONDS", "600"),
                ("REVOOT_MAX_INLINE_DIFF_BYTES", "16384"),
            ],
        )
        .expect("operator override");
        assert_eq!(strategy.aggregate_budget.max_model_tokens, 500_000);
        assert_eq!(strategy.aggregate_budget.max_tool_calls, 512);
        assert_eq!(strategy.aggregate_budget.max_elapsed_millis, 600_000);
        assert_eq!(strategy.max_inline_diff_bytes, 16_384);
    }

    #[test]
    fn large_diff_escalates_unconfigured_medium_to_high() {
        let root = tempfile::tempdir().expect("root");
        let resolved = resolve_review_configuration(root.path(), None, None, []).expect("config");
        let strategy = strategy_from_resolved(&resolved).expect("strategy");
        assert_eq!(strategy.effort, ReviewEffort::Medium);
        let escalated = escalate_effort_for_large_diff(
            strategy,
            &resolved.effective,
            LARGE_DIFF_ESCALATION_FILES + 1,
            0,
        );
        assert_eq!(escalated.effort, ReviewEffort::High);
    }

    #[test]
    fn small_diff_stays_at_the_default_medium_effort() {
        let root = tempfile::tempdir().expect("root");
        let resolved = resolve_review_configuration(root.path(), None, None, []).expect("config");
        let strategy = strategy_from_resolved(&resolved).expect("strategy");
        let unescalated = escalate_effort_for_large_diff(
            strategy,
            &resolved.effective,
            LARGE_DIFF_ESCALATION_FILES,
            LARGE_DIFF_ESCALATION_BYTES,
        );
        assert_eq!(unescalated.effort, ReviewEffort::Medium);
    }

    #[test]
    fn operator_specified_effort_is_never_escalated() {
        let root = tempfile::tempdir().expect("root");
        let resolved = resolve_review_configuration(
            root.path(),
            None,
            None,
            [(
                OsString::from("REVOOT_REVIEW_EFFORT"),
                OsString::from("medium"),
            )],
        )
        .expect("config");
        let strategy = strategy_from_resolved(&resolved).expect("strategy");
        let unescalated = escalate_effort_for_large_diff(
            strategy,
            &resolved.effective,
            LARGE_DIFF_ESCALATION_FILES + 1,
            LARGE_DIFF_ESCALATION_BYTES + 1,
        );
        assert_eq!(unescalated.effort, ReviewEffort::Medium);
    }

    /// Replays the request/settlement pattern actually observed dogfooding
    /// PR #30 at full scale (24 requests: 11 read_diff-heavy, 13 light;
    /// reservations pessimistic per `estimate_wire_tokens`, settlements the
    /// real reported averages from that run's usage report), `repeats` times
    /// in a row against a given budget. Requests are reserved two at a time
    /// before either settles, mirroring the real run's `max_parallel_groups:
    /// 2` - the peak pressure comes from outstanding, not-yet-settled
    /// reservations held concurrently, not from the eventual settled sum.
    /// Returns how many requests it admitted before the aggregate token
    /// dimension was exhausted, or `None` if every repeat admitted in full.
    fn admit_observed_dogfood_pattern(limits: ReviewBudgetLimits, repeats: usize) -> Option<usize> {
        use revoot_core::review_budget::{ReviewBudgetDimension, ReviewBudgetError};
        use revoot_core::{ReviewBudgetBroker, ReviewModelReservation, ReviewModelUsage};

        // Heavy turns follow a read_diff delivery: recent_exchange echoes the
        // large result body back, so the pessimistic byte-based reservation
        // is large even though the real settled token count is not.
        const HEAVY_RESERVED_INPUT: u64 = 85_000;
        const HEAVY_SETTLED_INPUT: u64 = 15_000;
        const LIGHT_RESERVED_INPUT: u64 = 12_000;
        const LIGHT_SETTLED_INPUT: u64 = 8_000;
        const SETTLED_OUTPUT: u64 = 700;
        const RESERVED_OUTPUT: u64 = 4_096;

        let broker = ReviewBudgetBroker::new(limits, 0).expect("valid budget");

        let reserve = |heavy: bool| {
            broker.reserve_model_request(
                ReviewModelReservation {
                    input_tokens: if heavy {
                        HEAVY_RESERVED_INPUT
                    } else {
                        LIGHT_RESERVED_INPUT
                    },
                    output_tokens: RESERVED_OUTPUT,
                    cost_microusd:
                        revoot_core::review_budget::CONSERVATIVE_MODEL_CALL_COST_MICROUSD,
                },
                0,
            )
        };
        let settle = |permit: revoot_core::ReviewModelPermit, heavy: bool| {
            permit
                .commit(
                    Some(ReviewModelUsage {
                        input_tokens: if heavy {
                            HEAVY_SETTLED_INPUT
                        } else {
                            LIGHT_SETTLED_INPUT
                        },
                        output_tokens: SETTLED_OUTPUT,
                        cost_microusd:
                            revoot_core::review_budget::CONSERVATIVE_MODEL_CALL_COST_MICROUSD,
                    }),
                    0,
                )
                .expect("settlement");
        };

        let one_pass = [true; 11].into_iter().chain([false; 13]);
        let pattern: Vec<bool> = std::iter::repeat_n(one_pass, repeats).flatten().collect();
        let mut admitted = 0;
        for pair in pattern.chunks(2) {
            let mut permits = Vec::with_capacity(pair.len());
            for &heavy in pair {
                match reserve(heavy) {
                    Ok(permit) => permits.push((permit, heavy)),
                    Err(ReviewBudgetError::Exhausted(ReviewBudgetDimension::ModelTokens)) => {
                        return Some(admitted);
                    }
                    Err(error) => panic!("unexpected budget error: {error:?}"),
                }
                admitted += 1;
            }
            for (permit, heavy) in permits {
                settle(permit, heavy);
            }
        }
        None
    }

    #[test]
    fn old_default_would_have_exhausted_the_observed_dogfood_pattern() {
        let old_limits = ReviewBudgetLimits {
            max_model_tokens: 300_000,
            ..ReviewStrategyConfiguration::default().aggregate_budget
        };
        let stopped_after = admit_observed_dogfood_pattern(old_limits, 1);
        assert!(
            stopped_after.is_some_and(|count| count < 24),
            "the old 300,000 ceiling should reproduce the dogfood exhaustion locally"
        );
    }

    #[test]
    fn new_default_admits_the_full_observed_dogfood_pattern_with_headroom() {
        let budget = ReviewStrategyConfiguration::default().aggregate_budget;
        assert!(
            admit_observed_dogfood_pattern(budget, 1).is_none(),
            "the new default should admit every request PR #30's dogfood run actually made"
        );
        // Headroom check: the same pattern replayed a second full time, as a
        // stand-in for the additional turns the five starved groups never
        // got to make, should still fit within the default request count.
        assert!(
            admit_observed_dogfood_pattern(budget, 2).is_none(),
            "the new default should have headroom left for the requests the starved groups never made"
        );
    }

    fn resolve<const N: usize>(
        root: &Path,
        environment: [(&str, &str); N],
    ) -> Result<ReviewStrategyConfiguration, Diagnostic> {
        resolve_review_strategy_configuration(
            root,
            None,
            None,
            environment
                .into_iter()
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
    }

    fn repository_config(document: &str) -> TempDir {
        let root = tempfile::tempdir().expect("root");
        fs::write(root.path().join(".revoot.toml"), document).expect("repository config");
        root
    }
}
