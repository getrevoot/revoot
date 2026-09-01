//! Deterministic validation for concurrent review-worker execution traces.
//!
//! Traces contain only scheduling identities, reservations, usage, outcomes,
//! and counts. They never retain provider payloads, prompts, source, or diffs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    RepositoryPath, ReviewBudgetLimits, ReviewModelReservation, ReviewModelUsage, Sha256Digest,
};

const MAX_WORK_ITEMS: usize = 128;
const MAX_EVENTS: usize = 2_048;
const MAX_LABEL_BYTES: usize = 128;
const MAX_RETAINED_FINDINGS: u32 = 25;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerSignal {
    High,
    Standard,
    Low,
}

/// One scheduler work item. `stable_path` is ordering metadata only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyWorkItem {
    pub group_id: String,
    pub signal: WorkerSignal,
    pub stable_path: RepositoryPath,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSettlementStatus {
    Completed,
    Failed,
    Cancelled,
}

/// Typed scheduler trace event. Reservations contain capacity only; settlement
/// retains only authoritative usage and verified-result counts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConcurrencyTraceEvent {
    BudgetReserved {
        reservation_id: String,
        group_id: String,
        reservation: ReviewModelReservation,
    },
    ProviderDispatched {
        reservation_id: String,
        group_id: String,
    },
    CancellationRequested,
    ProviderSettled {
        reservation_id: String,
        group_id: String,
        status: ProviderSettlementStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        usage: Option<ReviewModelUsage>,
        retained_verified_findings: u32,
    },
    RunFinished {
        partial: bool,
        retained_verified_findings: u32,
    },
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyTraceUsage {
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
    pub retained_verified_findings: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyTrace {
    pub schema_version: String,
    pub max_parallel: u8,
    pub budget_limits: ReviewBudgetLimits,
    pub work_items: Vec<ConcurrencyWorkItem>,
    pub events: Vec<ConcurrencyTraceEvent>,
    pub usage: ConcurrencyTraceUsage,
    pub trace_sha256: Sha256Digest,
}

impl ConcurrencyTrace {
    pub const SCHEMA_VERSION: &'static str = "revoot.concurrency-trace/v1";

    /// Replay dispatch order, reservations, active width, cancellation, usage,
    /// retained results, terminal partial state, and the canonical digest.
    ///
    /// # Errors
    ///
    /// Returns the first payload-free scheduling or accounting violation.
    pub fn validate(&self) -> Result<(), ConcurrencyTraceError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ConcurrencyTraceError::SchemaVersion);
        }
        validate_configuration(self.max_parallel, self.budget_limits, &self.work_items)?;
        if self.events.is_empty() || self.events.len() > MAX_EVENTS {
            return Err(ConcurrencyTraceError::EventCount);
        }
        let usage = replay(self)?;
        if usage != self.usage {
            return Err(ConcurrencyTraceError::Usage);
        }
        if self.trace_sha256 != trace_digest(self)? {
            return Err(ConcurrencyTraceError::Digest);
        }
        Ok(())
    }

    /// Serialize a fully replayed trace.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed JSON serialization error.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ConcurrencyTraceError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ConcurrencyTraceError::Serialization)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConcurrencyTraceError {
    SchemaVersion,
    Parallelism,
    BudgetLimits,
    WorkItems,
    EventCount,
    Reservation,
    DispatchWithoutReservation,
    DispatchOrder,
    ParallelLimit,
    DispatchAfterCancellation,
    Settlement,
    ReservationUsage,
    ActiveWorkers,
    ResultRetention,
    Terminal,
    Overflow,
    Usage,
    Digest,
    Serialization,
}

impl fmt::Display for ConcurrencyTraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "the concurrency trace schema version is invalid",
            Self::Parallelism => "concurrency must be between one and eight",
            Self::BudgetLimits => "the concurrency trace budget limits are invalid",
            Self::WorkItems => "the concurrency trace work items are invalid",
            Self::EventCount => "the concurrency trace event count is invalid",
            Self::Reservation => "a provider reservation is invalid or exceeds shared capacity",
            Self::DispatchWithoutReservation => "provider dispatch lacks an immediate reservation",
            Self::DispatchOrder => "workers were not dispatched in stable signal order",
            Self::ParallelLimit => "the active worker limit was exceeded",
            Self::DispatchAfterCancellation => "new work was dispatched after cancellation",
            Self::Settlement => "a provider settlement does not match active work",
            Self::ReservationUsage => "reported provider usage exceeds its reservation",
            Self::ActiveWorkers => "active provider work was not settled",
            Self::ResultRetention => "verified partial result accounting is invalid",
            Self::Terminal => "the concurrency trace terminal state is invalid",
            Self::Overflow => "concurrency trace accounting overflowed",
            Self::Usage => "concurrency trace usage does not match its events",
            Self::Digest => "the concurrency trace digest is invalid",
            Self::Serialization => "the concurrency trace could not be serialized",
        })
    }
}

impl std::error::Error for ConcurrencyTraceError {}

/// Build, replay, and digest one canonical execution trace.
///
/// # Errors
///
/// Rejects invalid configuration, unsafe order, missing/over-capacity
/// reservations, cancellation violations, unsettled work, or usage mismatch.
pub fn build_concurrency_trace(
    max_parallel: u8,
    budget_limits: ReviewBudgetLimits,
    mut work_items: Vec<ConcurrencyWorkItem>,
    events: Vec<ConcurrencyTraceEvent>,
) -> Result<ConcurrencyTrace, ConcurrencyTraceError> {
    work_items.sort_by(|left, right| {
        left.signal
            .cmp(&right.signal)
            .then_with(|| left.stable_path.cmp(&right.stable_path))
            .then_with(|| left.group_id.cmp(&right.group_id))
    });
    validate_configuration(max_parallel, budget_limits, &work_items)?;
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err(ConcurrencyTraceError::EventCount);
    }
    let mut trace = ConcurrencyTrace {
        schema_version: ConcurrencyTrace::SCHEMA_VERSION.to_owned(),
        max_parallel,
        budget_limits,
        work_items,
        events,
        usage: ConcurrencyTraceUsage::default(),
        trace_sha256: Sha256Digest::of_bytes(&[]),
    };
    trace.usage = replay(&trace)?;
    trace.trace_sha256 = trace_digest(&trace)?;
    trace.validate()?;
    Ok(trace)
}

fn validate_configuration(
    max_parallel: u8,
    budget_limits: ReviewBudgetLimits,
    work_items: &[ConcurrencyWorkItem],
) -> Result<(), ConcurrencyTraceError> {
    if !(1..=8).contains(&max_parallel) {
        return Err(ConcurrencyTraceError::Parallelism);
    }
    budget_limits
        .validate()
        .map_err(|_| ConcurrencyTraceError::BudgetLimits)?;
    if work_items.is_empty() || work_items.len() > MAX_WORK_ITEMS {
        return Err(ConcurrencyTraceError::WorkItems);
    }
    let mut groups = BTreeSet::new();
    let sorted = work_items.windows(2).all(|pair| {
        (&pair[0].signal, &pair[0].stable_path, &pair[0].group_id)
            < (&pair[1].signal, &pair[1].stable_path, &pair[1].group_id)
    });
    if !sorted
        || work_items
            .iter()
            .any(|item| !valid_label(&item.group_id) || !groups.insert(&item.group_id))
    {
        return Err(ConcurrencyTraceError::WorkItems);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ActiveReservation {
    reservation: ReviewModelReservation,
    group_index: usize,
}

#[allow(clippy::too_many_lines)]
fn replay(trace: &ConcurrencyTrace) -> Result<ConcurrencyTraceUsage, ConcurrencyTraceError> {
    let mut next_dispatch = 0_usize;
    let mut cancelled = false;
    let mut pending: Option<(&str, &str, ReviewModelReservation)> = None;
    let mut active = BTreeMap::<&str, ActiveReservation>::new();
    let mut reservation_ids = BTreeSet::new();
    let mut committed_input = 0_u64;
    let mut committed_output = 0_u64;
    let mut committed_cost = 0_u64;
    let mut outstanding_input = 0_u64;
    let mut outstanding_output = 0_u64;
    let mut outstanding_cost = 0_u64;
    let mut requests = 0_u32;
    let mut retained = 0_u32;
    let mut failure_observed = false;
    let mut finished = false;

    for (index, event) in trace.events.iter().enumerate() {
        if finished {
            return Err(ConcurrencyTraceError::Terminal);
        }
        if pending.is_some() && !matches!(event, ConcurrencyTraceEvent::ProviderDispatched { .. }) {
            return Err(ConcurrencyTraceError::DispatchWithoutReservation);
        }
        match event {
            ConcurrencyTraceEvent::BudgetReserved {
                reservation_id,
                group_id,
                reservation,
            } => {
                if cancelled {
                    return Err(ConcurrencyTraceError::DispatchAfterCancellation);
                }
                if pending.is_some()
                    || !valid_label(reservation_id)
                    || !reservation_ids.insert(reservation_id.as_str())
                    || reservation.input_tokens == 0
                    || reservation.output_tokens == 0
                {
                    return Err(ConcurrencyTraceError::Reservation);
                }
                let expected = trace
                    .work_items
                    .get(next_dispatch)
                    .ok_or(ConcurrencyTraceError::DispatchOrder)?;
                if expected.group_id != *group_id {
                    return Err(ConcurrencyTraceError::DispatchOrder);
                }
                let reserved_tokens = committed_input
                    .checked_add(committed_output)
                    .and_then(|tokens| tokens.checked_add(outstanding_input))
                    .and_then(|tokens| tokens.checked_add(outstanding_output))
                    .and_then(|tokens| tokens.checked_add(reservation.input_tokens))
                    .and_then(|tokens| tokens.checked_add(reservation.output_tokens))
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                let reserved_output = committed_output
                    .checked_add(outstanding_output)
                    .and_then(|tokens| tokens.checked_add(reservation.output_tokens))
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                let reserved_cost = committed_cost
                    .checked_add(outstanding_cost)
                    .and_then(|cost| cost.checked_add(reservation.cost_microusd))
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                if requests >= trace.budget_limits.max_model_requests
                    || reserved_tokens > trace.budget_limits.max_model_tokens
                    || reserved_output > trace.budget_limits.max_output_tokens
                    || reserved_cost > trace.budget_limits.max_cost_microusd
                {
                    return Err(ConcurrencyTraceError::Reservation);
                }
                outstanding_input = outstanding_input
                    .checked_add(reservation.input_tokens)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                outstanding_output = outstanding_output
                    .checked_add(reservation.output_tokens)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                outstanding_cost = outstanding_cost
                    .checked_add(reservation.cost_microusd)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                requests = requests
                    .checked_add(1)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                pending = Some((reservation_id, group_id, *reservation));
            }
            ConcurrencyTraceEvent::ProviderDispatched {
                reservation_id,
                group_id,
            } => {
                if cancelled {
                    return Err(ConcurrencyTraceError::DispatchAfterCancellation);
                }
                let Some((pending_id, pending_group, reservation)) = pending.take() else {
                    return Err(ConcurrencyTraceError::DispatchWithoutReservation);
                };
                if pending_id != reservation_id || pending_group != group_id {
                    return Err(ConcurrencyTraceError::DispatchWithoutReservation);
                }
                if active.len() >= usize::from(trace.max_parallel)
                    || active
                        .insert(
                            reservation_id,
                            ActiveReservation {
                                reservation,
                                group_index: next_dispatch,
                            },
                        )
                        .is_some()
                {
                    return Err(ConcurrencyTraceError::ParallelLimit);
                }
                next_dispatch += 1;
            }
            ConcurrencyTraceEvent::CancellationRequested => {
                if cancelled {
                    return Err(ConcurrencyTraceError::Terminal);
                }
                cancelled = true;
            }
            ConcurrencyTraceEvent::ProviderSettled {
                reservation_id,
                group_id,
                status,
                usage,
                retained_verified_findings,
            } => {
                let active_reservation = active
                    .remove(reservation_id.as_str())
                    .ok_or(ConcurrencyTraceError::Settlement)?;
                let item = trace
                    .work_items
                    .get(active_reservation.group_index)
                    .ok_or(ConcurrencyTraceError::Settlement)?;
                if item.group_id != *group_id {
                    return Err(ConcurrencyTraceError::Settlement);
                }
                let charged = usage.unwrap_or(ReviewModelUsage {
                    input_tokens: active_reservation.reservation.input_tokens,
                    output_tokens: active_reservation.reservation.output_tokens,
                    cost_microusd: active_reservation.reservation.cost_microusd,
                });
                if charged.input_tokens > active_reservation.reservation.input_tokens
                    || charged.output_tokens > active_reservation.reservation.output_tokens
                    || charged.cost_microusd > active_reservation.reservation.cost_microusd
                {
                    return Err(ConcurrencyTraceError::ReservationUsage);
                }
                if *retained_verified_findings > MAX_RETAINED_FINDINGS {
                    return Err(ConcurrencyTraceError::ResultRetention);
                }
                outstanding_input -= active_reservation.reservation.input_tokens;
                outstanding_output -= active_reservation.reservation.output_tokens;
                outstanding_cost -= active_reservation.reservation.cost_microusd;
                committed_input = committed_input
                    .checked_add(charged.input_tokens)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                committed_output = committed_output
                    .checked_add(charged.output_tokens)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                committed_cost = committed_cost
                    .checked_add(charged.cost_microusd)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                retained = retained
                    .checked_add(*retained_verified_findings)
                    .ok_or(ConcurrencyTraceError::Overflow)?;
                if retained > MAX_RETAINED_FINDINGS {
                    return Err(ConcurrencyTraceError::ResultRetention);
                }
                failure_observed |= !matches!(status, ProviderSettlementStatus::Completed);
            }
            ConcurrencyTraceEvent::RunFinished {
                partial,
                retained_verified_findings,
            } => {
                if index + 1 != trace.events.len() || pending.is_some() || !active.is_empty() {
                    return Err(ConcurrencyTraceError::ActiveWorkers);
                }
                let expected_partial =
                    cancelled || failure_observed || next_dispatch < trace.work_items.len();
                if *partial != expected_partial {
                    return Err(ConcurrencyTraceError::Terminal);
                }
                if *retained_verified_findings != retained {
                    return Err(ConcurrencyTraceError::ResultRetention);
                }
                finished = true;
            }
        }
    }
    if !finished || pending.is_some() || !active.is_empty() {
        return Err(ConcurrencyTraceError::Terminal);
    }
    Ok(ConcurrencyTraceUsage {
        model_requests: requests,
        input_tokens: committed_input,
        output_tokens: committed_output,
        cost_microusd: committed_cost,
        retained_verified_findings: retained,
    })
}

fn trace_digest(trace: &ConcurrencyTrace) -> Result<Sha256Digest, ConcurrencyTraceError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        max_parallel: u8,
        budget_limits: ReviewBudgetLimits,
        work_items: &'a [ConcurrencyWorkItem],
        events: &'a [ConcurrencyTraceEvent],
        usage: ConcurrencyTraceUsage,
    }
    serde_json::to_vec(&DigestInput {
        schema_version: &trace.schema_version,
        max_parallel: trace.max_parallel,
        budget_limits: trace.budget_limits,
        work_items: &trace.work_items,
        events: &trace.events,
        usage: trace.usage,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| ConcurrencyTraceError::Serialization)
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

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn limits() -> ReviewBudgetLimits {
        ReviewBudgetLimits {
            max_model_requests: 8,
            max_model_tokens: 10_000,
            max_output_tokens: 2_000,
            max_tool_calls: 10,
            max_cost_microusd: 1_000,
            max_elapsed_millis: 10_000,
        }
    }

    fn reservation() -> ReviewModelReservation {
        ReviewModelReservation {
            input_tokens: 1_000,
            output_tokens: 100,
            cost_microusd: 10,
        }
    }

    fn usage() -> ReviewModelUsage {
        ReviewModelUsage {
            input_tokens: 800,
            output_tokens: 80,
            cost_microusd: 8,
        }
    }

    fn items() -> Vec<ConcurrencyWorkItem> {
        vec![
            ConcurrencyWorkItem {
                group_id: "standard".to_owned(),
                signal: WorkerSignal::Standard,
                stable_path: path("src/c.rs"),
            },
            ConcurrencyWorkItem {
                group_id: "high-b".to_owned(),
                signal: WorkerSignal::High,
                stable_path: path("src/b.rs"),
            },
            ConcurrencyWorkItem {
                group_id: "high-a".to_owned(),
                signal: WorkerSignal::High,
                stable_path: path("src/a.rs"),
            },
        ]
    }

    fn reserve(id: &str, group: &str) -> ConcurrencyTraceEvent {
        ConcurrencyTraceEvent::BudgetReserved {
            reservation_id: id.to_owned(),
            group_id: group.to_owned(),
            reservation: reservation(),
        }
    }

    fn dispatch(id: &str, group: &str) -> ConcurrencyTraceEvent {
        ConcurrencyTraceEvent::ProviderDispatched {
            reservation_id: id.to_owned(),
            group_id: group.to_owned(),
        }
    }

    fn settle(id: &str, group: &str, retained: u32) -> ConcurrencyTraceEvent {
        ConcurrencyTraceEvent::ProviderSettled {
            reservation_id: id.to_owned(),
            group_id: group.to_owned(),
            status: ProviderSettlementStatus::Completed,
            usage: Some(usage()),
            retained_verified_findings: retained,
        }
    }

    #[test]
    fn high_signal_dispatches_first_with_stable_path_ties() {
        let events = vec![
            reserve("r1", "high-a"),
            dispatch("r1", "high-a"),
            reserve("r2", "high-b"),
            dispatch("r2", "high-b"),
            settle("r2", "high-b", 1),
            reserve("r3", "standard"),
            dispatch("r3", "standard"),
            settle("r1", "high-a", 2),
            settle("r3", "standard", 0),
            ConcurrencyTraceEvent::RunFinished {
                partial: false,
                retained_verified_findings: 3,
            },
        ];
        let trace = build_concurrency_trace(2, limits(), items(), events).unwrap();
        assert_eq!(trace.work_items[0].group_id, "high-a");
        assert_eq!(trace.work_items[1].group_id, "high-b");
        assert_eq!(trace.usage.retained_verified_findings, 3);
    }

    #[test]
    fn parallel_range_and_atomic_reservation_are_enforced() {
        for parallel in [0, 9] {
            assert_eq!(
                build_concurrency_trace(parallel, limits(), items(), vec![]),
                Err(ConcurrencyTraceError::Parallelism)
            );
        }
        assert_eq!(
            build_concurrency_trace(
                1,
                limits(),
                items(),
                vec![
                    dispatch("r1", "high-a"),
                    ConcurrencyTraceEvent::RunFinished {
                        partial: true,
                        retained_verified_findings: 0,
                    },
                ],
            ),
            Err(ConcurrencyTraceError::DispatchWithoutReservation)
        );
    }

    #[test]
    fn cancellation_stops_dispatch_but_active_work_settles_and_is_retained() {
        let events = vec![
            reserve("r1", "high-a"),
            dispatch("r1", "high-a"),
            reserve("r2", "high-b"),
            dispatch("r2", "high-b"),
            ConcurrencyTraceEvent::CancellationRequested,
            settle("r1", "high-a", 2),
            ConcurrencyTraceEvent::ProviderSettled {
                reservation_id: "r2".to_owned(),
                group_id: "high-b".to_owned(),
                status: ProviderSettlementStatus::Cancelled,
                usage: None,
                retained_verified_findings: 1,
            },
            ConcurrencyTraceEvent::RunFinished {
                partial: true,
                retained_verified_findings: 3,
            },
        ];
        let trace = build_concurrency_trace(2, limits(), items(), events).unwrap();
        assert_eq!(trace.usage.retained_verified_findings, 3);
        assert_eq!(trace.usage.model_requests, 2);

        let invalid = vec![
            reserve("r1", "high-a"),
            dispatch("r1", "high-a"),
            ConcurrencyTraceEvent::CancellationRequested,
            reserve("r2", "high-b"),
        ];
        assert_eq!(
            build_concurrency_trace(2, limits(), items(), invalid),
            Err(ConcurrencyTraceError::DispatchAfterCancellation)
        );
    }

    #[test]
    fn missing_usage_is_conservatively_charged_and_partial_results_survive() {
        let events = vec![
            reserve("r1", "high-a"),
            dispatch("r1", "high-a"),
            ConcurrencyTraceEvent::ProviderSettled {
                reservation_id: "r1".to_owned(),
                group_id: "high-a".to_owned(),
                status: ProviderSettlementStatus::Failed,
                usage: None,
                retained_verified_findings: 2,
            },
            ConcurrencyTraceEvent::RunFinished {
                partial: true,
                retained_verified_findings: 2,
            },
        ];
        let trace = build_concurrency_trace(1, limits(), items(), events).unwrap();
        assert_eq!(trace.usage.input_tokens, reservation().input_tokens);
        assert_eq!(trace.usage.output_tokens, reservation().output_tokens);
        assert_eq!(trace.usage.retained_verified_findings, 2);
    }

    #[test]
    fn trace_json_has_no_provider_or_source_payload_fields() {
        let events = vec![
            reserve("r1", "high-a"),
            dispatch("r1", "high-a"),
            settle("r1", "high-a", 0),
            ConcurrencyTraceEvent::RunFinished {
                partial: true,
                retained_verified_findings: 0,
            },
        ];
        let trace = build_concurrency_trace(1, limits(), items(), events).unwrap();
        let json = String::from_utf8(trace.canonical_json().unwrap()).unwrap();
        for forbidden in [
            "diff_body",
            "prompt",
            "response_body",
            "source_body",
            "tool_payload",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
