//! Thread-safe aggregate budget reservations for concurrent review workers.
//!
//! Provider capacity is reserved before dispatch. Successful calls settle to
//! authoritative usage and release unused capacity; failed, cancelled, or
//! ambiguously reported calls retain their full conservative charge.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

/// Conservative monetary capacity reserved for one model request when direct
/// provider adapters cannot report an authoritative monetary cost.
pub const CONSERVATIVE_MODEL_CALL_COST_MICROUSD: u64 = 500_000;

/// Derive aggregate conservative monetary capacity from a request ceiling.
#[must_use]
pub const fn conservative_model_cost_limit(max_model_requests: u64) -> Option<u64> {
    max_model_requests.checked_mul(CONSERVATIVE_MODEL_CALL_COST_MICROUSD)
}

/// Review-wide limits shared by every review worker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBudgetLimits {
    pub max_model_requests: u32,
    /// Combined model input and output tokens.
    pub max_model_tokens: u64,
    /// Aggregate output-token ceiling within `max_model_tokens`.
    pub max_output_tokens: u64,
    pub max_tool_calls: u32,
    pub max_cost_microusd: u64,
    pub max_elapsed_millis: u64,
}

impl Default for ReviewBudgetLimits {
    fn default() -> Self {
        let max_model_requests = 64;
        Self {
            max_model_requests,
            max_model_tokens: 300_000,
            max_output_tokens: 64 * 4_096,
            max_tool_calls: 256,
            max_cost_microusd: conservative_model_cost_limit(u64::from(max_model_requests))
                .expect("compiled request ceiling has a representable cost reservation"),
            max_elapsed_millis: 10 * 60 * 1_000,
        }
    }
}

/// The first unusable aggregate limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewBudgetValidationError {
    ModelRequests,
    ModelTokens,
    OutputTokens,
    ToolCalls,
    ElapsedTime,
}

impl ReviewBudgetLimits {
    /// Validate limits before review work begins.
    ///
    /// A zero cost limit is valid for providers that do not report or incur a
    /// monetary cost.
    ///
    /// # Errors
    ///
    /// Returns the first dimension that cannot admit work.
    pub const fn validate(self) -> Result<(), ReviewBudgetValidationError> {
        if self.max_model_requests == 0 {
            return Err(ReviewBudgetValidationError::ModelRequests);
        }
        if self.max_model_tokens == 0 {
            return Err(ReviewBudgetValidationError::ModelTokens);
        }
        if self.max_output_tokens == 0 || self.max_output_tokens > self.max_model_tokens {
            return Err(ReviewBudgetValidationError::OutputTokens);
        }
        if self.max_tool_calls == 0 {
            return Err(ReviewBudgetValidationError::ToolCalls);
        }
        if self.max_elapsed_millis == 0 {
            return Err(ReviewBudgetValidationError::ElapsedTime);
        }
        Ok(())
    }
}

/// One aggregate capacity dimension.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewBudgetDimension {
    ModelRequests,
    ModelTokens,
    OutputTokens,
    ToolCalls,
    Cost,
    ElapsedTime,
}

/// Stable review phase used for authoritative aggregate accounting.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewBudgetPhase {
    Grouping,
    Planning,
    Review,
    Verification,
    Adjudication,
}

/// A conservative reservation made before one provider call.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewModelReservation {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
}

/// Authoritative provider usage for one completed call.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
}

/// Payload-free usage charged for exactly one successfully reserved provider call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewCallUsage {
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
}

impl ReviewCallUsage {
    #[must_use]
    pub const fn conservative(reservation: ReviewModelReservation) -> Self {
        Self {
            model_requests: 1,
            input_tokens: reservation.input_tokens,
            output_tokens: reservation.output_tokens,
            cost_microusd: reservation.cost_microusd,
        }
    }

    #[must_use]
    pub const fn settled(settlement: ReviewModelSettlement) -> Self {
        let usage = match settlement {
            ReviewModelSettlement::Reported(usage)
            | ReviewModelSettlement::Conservative { charged: usage, .. } => usage,
        };
        Self {
            model_requests: 1,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cost_microusd: usage.cost_microusd,
        }
    }

    #[must_use]
    pub const fn into_budget_usage(self) -> ReviewBudgetUsage {
        ReviewBudgetUsage {
            model_requests: self.model_requests,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            tool_calls: 0,
            cost_microusd: self.cost_microusd,
            elapsed_millis: 0,
        }
    }
}

/// Settled aggregate usage. Outstanding capacity is reported separately.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBudgetUsage {
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tool_calls: u32,
    pub cost_microusd: u64,
    pub elapsed_millis: u64,
}

/// Capacity held by provider calls that have not yet settled.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutstandingReviewReservations {
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
}

/// Redaction-safe aggregate state for reporting and scheduling.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBudgetSnapshot {
    pub limits: ReviewBudgetLimits,
    pub usage: ReviewBudgetUsage,
    pub outstanding: OutstandingReviewReservations,
}

/// Why a provider call received its conservative reservation charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConservativeChargeReason {
    MissingUsage,
    AmbiguousUsage(ReviewBudgetDimension),
    PermitDropped,
}

/// How one provider reservation was settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewModelSettlement {
    Reported(ReviewModelUsage),
    Conservative {
        charged: ReviewModelUsage,
        reason: ConservativeChargeReason,
    },
}

/// Aggregate broker failure. Rejected reservations never consume capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewBudgetError {
    InvalidLimits(ReviewBudgetValidationError),
    InvalidReservation,
    ClockRegression,
    Exhausted(ReviewBudgetDimension),
    ReservationNotFound,
}

#[derive(Clone, Copy, Debug)]
struct OutstandingReservation {
    reservation: ReviewModelReservation,
    phase: Option<ReviewBudgetPhase>,
}

#[derive(Debug)]
struct ReviewBudgetState {
    usage: ReviewBudgetUsage,
    phase_usage: BTreeMap<ReviewBudgetPhase, ReviewBudgetUsage>,
    outstanding_usage: OutstandingReviewReservations,
    outstanding: BTreeMap<u64, OutstandingReservation>,
    next_reservation_id: u64,
    last_observed_millis: u64,
}

struct ReviewBudgetInner {
    limits: ReviewBudgetLimits,
    started_at_millis: u64,
    state: Mutex<ReviewBudgetState>,
}

/// Cloneable, thread-safe aggregate budget broker for one review invocation.
#[derive(Clone)]
pub struct ReviewBudgetBroker {
    inner: Arc<ReviewBudgetInner>,
}

impl ReviewBudgetBroker {
    /// Create an empty broker in the caller's monotonic clock domain.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit cannot admit work.
    pub fn new(
        limits: ReviewBudgetLimits,
        started_at_millis: u64,
    ) -> Result<Self, ReviewBudgetError> {
        limits
            .validate()
            .map_err(ReviewBudgetError::InvalidLimits)?;
        Ok(Self {
            inner: Arc::new(ReviewBudgetInner {
                limits,
                started_at_millis,
                state: Mutex::new(ReviewBudgetState {
                    usage: ReviewBudgetUsage::default(),
                    phase_usage: BTreeMap::new(),
                    outstanding_usage: OutstandingReviewReservations::default(),
                    outstanding: BTreeMap::new(),
                    next_reservation_id: 1,
                    last_observed_millis: started_at_millis,
                }),
            }),
        })
    }

    /// Return the immutable limits.
    #[must_use]
    pub fn limits(&self) -> ReviewBudgetLimits {
        self.inner.limits
    }

    /// Return settled and currently reserved capacity.
    #[must_use]
    pub fn snapshot(&self) -> ReviewBudgetSnapshot {
        let state = lock_state(&self.inner);
        ReviewBudgetSnapshot {
            limits: self.inner.limits,
            usage: state.usage,
            outstanding: state.outstanding_usage,
        }
    }

    /// Check whether the aggregate deadline still permits new dispatch.
    ///
    /// This observation is redaction-safe and does not consume request, token,
    /// tool, output, or cost capacity. It uses the same monotonic-clock and
    /// deadline validation as an atomic reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when time regresses or the aggregate deadline passed.
    pub fn ensure_dispatch_deadline(&self, now_millis: u64) -> Result<(), ReviewBudgetError> {
        let mut state = lock_state(&self.inner);
        observe_for_dispatch(&self.inner, &mut state, now_millis)
    }

    /// Atomically reserve request, token, output, cost, and deadline capacity.
    ///
    /// The returned permit conservatively settles itself if dropped before an
    /// explicit commit, including cancellation and early-return paths.
    ///
    /// # Errors
    ///
    /// Returns an error without reserving capacity when time regresses, the
    /// deadline has passed, the reservation is empty, or a limit is exhausted.
    pub fn reserve_model_request(
        &self,
        reservation: ReviewModelReservation,
        now_millis: u64,
    ) -> Result<ReviewModelPermit, ReviewBudgetError> {
        self.reserve_model_request_inner(reservation, now_millis, None)
    }

    /// Atomically reserve provider capacity and bind its eventual charge to a phase.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::reserve_model_request`].
    pub fn reserve_model_request_for_phase(
        &self,
        phase: ReviewBudgetPhase,
        reservation: ReviewModelReservation,
        now_millis: u64,
    ) -> Result<ReviewModelPermit, ReviewBudgetError> {
        self.reserve_model_request_inner(reservation, now_millis, Some(phase))
    }

    fn reserve_model_request_inner(
        &self,
        reservation: ReviewModelReservation,
        now_millis: u64,
        phase: Option<ReviewBudgetPhase>,
    ) -> Result<ReviewModelPermit, ReviewBudgetError> {
        let model_tokens = reservation
            .input_tokens
            .checked_add(reservation.output_tokens)
            .ok_or(ReviewBudgetError::InvalidReservation)?;
        if model_tokens == 0 {
            return Err(ReviewBudgetError::InvalidReservation);
        }

        let mut state = lock_state(&self.inner);
        observe_for_dispatch(&self.inner, &mut state, now_millis)?;
        ensure_u32(
            state.usage.model_requests,
            1,
            self.inner.limits.max_model_requests,
            ReviewBudgetDimension::ModelRequests,
        )?;

        let allocated_input = state
            .usage
            .input_tokens
            .checked_add(state.outstanding_usage.input_tokens)
            .ok_or(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::ModelTokens,
            ))?;
        let allocated_output = state
            .usage
            .output_tokens
            .checked_add(state.outstanding_usage.output_tokens)
            .ok_or(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::OutputTokens,
            ))?;
        let allocated_tokens =
            allocated_input
                .checked_add(allocated_output)
                .ok_or(ReviewBudgetError::Exhausted(
                    ReviewBudgetDimension::ModelTokens,
                ))?;
        ensure_u64(
            allocated_tokens,
            model_tokens,
            self.inner.limits.max_model_tokens,
            ReviewBudgetDimension::ModelTokens,
        )?;
        ensure_u64(
            allocated_output,
            reservation.output_tokens,
            self.inner.limits.max_output_tokens,
            ReviewBudgetDimension::OutputTokens,
        )?;

        let allocated_cost = state
            .usage
            .cost_microusd
            .checked_add(state.outstanding_usage.cost_microusd)
            .ok_or(ReviewBudgetError::Exhausted(ReviewBudgetDimension::Cost))?;
        ensure_u64(
            allocated_cost,
            reservation.cost_microusd,
            self.inner.limits.max_cost_microusd,
            ReviewBudgetDimension::Cost,
        )?;

        let id = state.next_reservation_id;
        state.next_reservation_id =
            state
                .next_reservation_id
                .checked_add(1)
                .ok_or(ReviewBudgetError::Exhausted(
                    ReviewBudgetDimension::ModelRequests,
                ))?;
        state.usage.model_requests = state.usage.model_requests.saturating_add(1);
        if let Some(phase) = phase {
            let phase_usage = state.phase_usage.entry(phase).or_default();
            phase_usage.model_requests = phase_usage.model_requests.saturating_add(1);
        }
        state.outstanding_usage.model_requests =
            state.outstanding_usage.model_requests.saturating_add(1);
        state.outstanding_usage.input_tokens = state
            .outstanding_usage
            .input_tokens
            .saturating_add(reservation.input_tokens);
        state.outstanding_usage.output_tokens = state
            .outstanding_usage
            .output_tokens
            .saturating_add(reservation.output_tokens);
        state.outstanding_usage.cost_microusd = state
            .outstanding_usage
            .cost_microusd
            .saturating_add(reservation.cost_microusd);
        state
            .outstanding
            .insert(id, OutstandingReservation { reservation, phase });
        drop(state);

        Ok(ReviewModelPermit {
            inner: Arc::clone(&self.inner),
            reservation_id: id,
            active: true,
        })
    }

    /// Charge local tool calls before dispatching them.
    ///
    /// Tool calls remain charged whether the tool succeeds or fails.
    ///
    /// # Errors
    ///
    /// Returns an error without charging calls when the amount is zero, time
    /// regresses, the deadline has passed, or capacity is exhausted.
    pub fn charge_tool_calls(&self, calls: u32, now_millis: u64) -> Result<(), ReviewBudgetError> {
        self.charge_tool_calls_inner(calls, now_millis, None)
    }

    /// Charge tool calls and bind them to a stable review phase.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::charge_tool_calls`].
    pub fn charge_tool_calls_for_phase(
        &self,
        phase: ReviewBudgetPhase,
        calls: u32,
        now_millis: u64,
    ) -> Result<(), ReviewBudgetError> {
        self.charge_tool_calls_inner(calls, now_millis, Some(phase))
    }

    fn charge_tool_calls_inner(
        &self,
        calls: u32,
        now_millis: u64,
        phase: Option<ReviewBudgetPhase>,
    ) -> Result<(), ReviewBudgetError> {
        if calls == 0 {
            return Err(ReviewBudgetError::InvalidReservation);
        }
        let mut state = lock_state(&self.inner);
        observe_for_dispatch(&self.inner, &mut state, now_millis)?;
        ensure_u32(
            state.usage.tool_calls,
            calls,
            self.inner.limits.max_tool_calls,
            ReviewBudgetDimension::ToolCalls,
        )?;
        state.usage.tool_calls = state.usage.tool_calls.saturating_add(calls);
        if let Some(phase) = phase {
            let phase_usage = state.phase_usage.entry(phase).or_default();
            phase_usage.tool_calls = phase_usage.tool_calls.saturating_add(calls);
        }
        Ok(())
    }

    /// Return authoritative settled usage for one phase.
    #[must_use]
    pub fn phase_usage(&self, phase: ReviewBudgetPhase) -> ReviewBudgetUsage {
        lock_state(&self.inner)
            .phase_usage
            .get(&phase)
            .copied()
            .unwrap_or_default()
    }
}

/// Exclusive settlement authority for one reserved provider call.
///
/// Dropping a live permit charges the full reservation, which makes task
/// cancellation and unwinding fail closed without an async cleanup hook.
pub struct ReviewModelPermit {
    inner: Arc<ReviewBudgetInner>,
    reservation_id: u64,
    active: bool,
}

impl ReviewModelPermit {
    /// Return the process-local reservation identity for diagnostics.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.reservation_id
    }

    /// Settle the provider call and release unused reserved capacity.
    ///
    /// `None` and any reported value outside the reservation are charged at
    /// the full reservation. This method consumes the permit, preventing a
    /// second settlement.
    ///
    /// # Errors
    ///
    /// Returns an error for clock regression or an invalid permit identity.
    /// On error, dropping the consumed permit still charges conservatively.
    pub fn commit(
        mut self,
        reported: Option<ReviewModelUsage>,
        now_millis: u64,
    ) -> Result<ReviewModelSettlement, ReviewBudgetError> {
        let settlement =
            settle_reservation(&self.inner, self.reservation_id, reported, now_millis)?;
        self.active = false;
        Ok(settlement)
    }
}

impl Drop for ReviewModelPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        settle_dropped_reservation(&self.inner, self.reservation_id);
        self.active = false;
    }
}

fn settle_reservation(
    inner: &ReviewBudgetInner,
    reservation_id: u64,
    reported: Option<ReviewModelUsage>,
    now_millis: u64,
) -> Result<ReviewModelSettlement, ReviewBudgetError> {
    let mut state = lock_state(inner);
    observe_for_settlement(inner, &mut state, now_millis)?;
    let entry = state
        .outstanding
        .get(&reservation_id)
        .copied()
        .ok_or(ReviewBudgetError::ReservationNotFound)?;
    let reservation = entry.reservation;
    let settlement = classify_settlement(reservation, reported);
    apply_settlement(&mut state, reservation_id, entry, settlement);
    Ok(settlement)
}

fn settle_dropped_reservation(inner: &ReviewBudgetInner, reservation_id: u64) {
    let mut state = lock_state(inner);
    let Some(entry) = state.outstanding.get(&reservation_id).copied() else {
        return;
    };
    let reservation = entry.reservation;
    let charged = reservation.into();
    apply_settlement(
        &mut state,
        reservation_id,
        entry,
        ReviewModelSettlement::Conservative {
            charged,
            reason: ConservativeChargeReason::PermitDropped,
        },
    );
}

fn classify_settlement(
    reservation: ReviewModelReservation,
    reported: Option<ReviewModelUsage>,
) -> ReviewModelSettlement {
    let Some(reported) = reported else {
        return ReviewModelSettlement::Conservative {
            charged: reservation.into(),
            reason: ConservativeChargeReason::MissingUsage,
        };
    };
    let ambiguous_dimension = if reported.input_tokens > reservation.input_tokens {
        Some(ReviewBudgetDimension::ModelTokens)
    } else if reported.output_tokens > reservation.output_tokens {
        Some(ReviewBudgetDimension::OutputTokens)
    } else if reported.cost_microusd > reservation.cost_microusd {
        Some(ReviewBudgetDimension::Cost)
    } else {
        None
    };
    ambiguous_dimension.map_or(ReviewModelSettlement::Reported(reported), |dimension| {
        ReviewModelSettlement::Conservative {
            charged: reservation.into(),
            reason: ConservativeChargeReason::AmbiguousUsage(dimension),
        }
    })
}

fn apply_settlement(
    state: &mut ReviewBudgetState,
    reservation_id: u64,
    entry: OutstandingReservation,
    settlement: ReviewModelSettlement,
) {
    let reservation = entry.reservation;
    let charged = match settlement {
        ReviewModelSettlement::Reported(usage)
        | ReviewModelSettlement::Conservative { charged: usage, .. } => usage,
    };
    state.outstanding.remove(&reservation_id);
    state.outstanding_usage.model_requests =
        state.outstanding_usage.model_requests.saturating_sub(1);
    state.outstanding_usage.input_tokens = state
        .outstanding_usage
        .input_tokens
        .saturating_sub(reservation.input_tokens);
    state.outstanding_usage.output_tokens = state
        .outstanding_usage
        .output_tokens
        .saturating_sub(reservation.output_tokens);
    state.outstanding_usage.cost_microusd = state
        .outstanding_usage
        .cost_microusd
        .saturating_sub(reservation.cost_microusd);
    state.usage.input_tokens = state
        .usage
        .input_tokens
        .saturating_add(charged.input_tokens);
    state.usage.output_tokens = state
        .usage
        .output_tokens
        .saturating_add(charged.output_tokens);
    state.usage.cost_microusd = state
        .usage
        .cost_microusd
        .saturating_add(charged.cost_microusd);
    if let Some(phase) = entry.phase {
        let phase_usage = state.phase_usage.entry(phase).or_default();
        phase_usage.input_tokens = phase_usage
            .input_tokens
            .saturating_add(charged.input_tokens);
        phase_usage.output_tokens = phase_usage
            .output_tokens
            .saturating_add(charged.output_tokens);
        phase_usage.cost_microusd = phase_usage
            .cost_microusd
            .saturating_add(charged.cost_microusd);
    }
}

fn observe_for_dispatch(
    inner: &ReviewBudgetInner,
    state: &mut ReviewBudgetState,
    now_millis: u64,
) -> Result<(), ReviewBudgetError> {
    observe_time(inner, state, now_millis)?;
    if state.usage.elapsed_millis > inner.limits.max_elapsed_millis {
        return Err(ReviewBudgetError::Exhausted(
            ReviewBudgetDimension::ElapsedTime,
        ));
    }
    Ok(())
}

fn observe_for_settlement(
    inner: &ReviewBudgetInner,
    state: &mut ReviewBudgetState,
    now_millis: u64,
) -> Result<(), ReviewBudgetError> {
    observe_time(inner, state, now_millis)
}

fn observe_time(
    inner: &ReviewBudgetInner,
    state: &mut ReviewBudgetState,
    now_millis: u64,
) -> Result<(), ReviewBudgetError> {
    if now_millis < state.last_observed_millis {
        return Err(ReviewBudgetError::ClockRegression);
    }
    state.last_observed_millis = now_millis;
    state.usage.elapsed_millis = now_millis.saturating_sub(inner.started_at_millis);
    Ok(())
}

fn lock_state(inner: &ReviewBudgetInner) -> MutexGuard<'_, ReviewBudgetState> {
    inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ensure_u32(
    current: u32,
    added: u32,
    maximum: u32,
    dimension: ReviewBudgetDimension,
) -> Result<(), ReviewBudgetError> {
    if current
        .checked_add(added)
        .is_none_or(|value| value > maximum)
    {
        Err(ReviewBudgetError::Exhausted(dimension))
    } else {
        Ok(())
    }
}

fn ensure_u64(
    current: u64,
    added: u64,
    maximum: u64,
    dimension: ReviewBudgetDimension,
) -> Result<(), ReviewBudgetError> {
    if current
        .checked_add(added)
        .is_none_or(|value| value > maximum)
    {
        Err(ReviewBudgetError::Exhausted(dimension))
    } else {
        Ok(())
    }
}

impl From<ReviewModelReservation> for ReviewModelUsage {
    fn from(reservation: ReviewModelReservation) -> Self {
        Self {
            input_tokens: reservation.input_tokens,
            output_tokens: reservation.output_tokens,
            cost_microusd: reservation.cost_microusd,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    fn limits() -> ReviewBudgetLimits {
        ReviewBudgetLimits {
            max_model_requests: 3,
            max_model_tokens: 300,
            max_output_tokens: 100,
            max_tool_calls: 3,
            max_cost_microusd: 30,
            max_elapsed_millis: 100,
        }
    }

    fn reservation() -> ReviewModelReservation {
        ReviewModelReservation {
            input_tokens: 80,
            output_tokens: 20,
            cost_microusd: 10,
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn broker_and_permit_are_send_sync() {
        assert_send_sync::<ReviewBudgetBroker>();
        assert_send_sync::<ReviewModelPermit>();
    }

    #[test]
    fn default_cost_capacity_admits_every_default_request_reservation() {
        let defaults = ReviewBudgetLimits::default();
        assert_eq!(
            defaults.max_cost_microusd,
            u64::from(defaults.max_model_requests) * CONSERVATIVE_MODEL_CALL_COST_MICROUSD
        );
        let broker = ReviewBudgetBroker::new(defaults, 0).expect("default broker");
        for now in 0..defaults.max_model_requests {
            broker
                .reserve_model_request(
                    ReviewModelReservation {
                        input_tokens: 1,
                        output_tokens: 1,
                        cost_microusd: CONSERVATIVE_MODEL_CALL_COST_MICROUSD,
                    },
                    u64::from(now),
                )
                .expect("request capacity must not be shortened by cost capacity")
                .commit(
                    Some(ReviewModelUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        cost_microusd: CONSERVATIVE_MODEL_CALL_COST_MICROUSD,
                    }),
                    u64::from(now),
                )
                .expect("reported use is within its reservation");
        }
        assert!(matches!(
            broker.reserve_model_request(
                ReviewModelReservation {
                    input_tokens: 1,
                    output_tokens: 1,
                    cost_microusd: CONSERVATIVE_MODEL_CALL_COST_MICROUSD,
                },
                u64::from(defaults.max_model_requests)
            ),
            Err(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::ModelRequests
            ))
        ));
        assert_eq!(
            conservative_model_cost_limit(u64::MAX),
            None,
            "derivation must fail rather than saturate"
        );
    }

    #[test]
    fn validates_every_required_limit() {
        let defaults = ReviewBudgetLimits::default();
        for (limits, expected) in [
            (
                ReviewBudgetLimits {
                    max_model_requests: 0,
                    ..defaults
                },
                ReviewBudgetValidationError::ModelRequests,
            ),
            (
                ReviewBudgetLimits {
                    max_model_tokens: 0,
                    ..defaults
                },
                ReviewBudgetValidationError::ModelTokens,
            ),
            (
                ReviewBudgetLimits {
                    max_output_tokens: 0,
                    ..defaults
                },
                ReviewBudgetValidationError::OutputTokens,
            ),
            (
                ReviewBudgetLimits {
                    max_output_tokens: defaults.max_model_tokens + 1,
                    ..defaults
                },
                ReviewBudgetValidationError::OutputTokens,
            ),
            (
                ReviewBudgetLimits {
                    max_tool_calls: 0,
                    ..defaults
                },
                ReviewBudgetValidationError::ToolCalls,
            ),
            (
                ReviewBudgetLimits {
                    max_elapsed_millis: 0,
                    ..defaults
                },
                ReviewBudgetValidationError::ElapsedTime,
            ),
        ] {
            assert_eq!(limits.validate(), Err(expected));
        }
        assert!(
            ReviewBudgetLimits {
                max_cost_microusd: 0,
                ..defaults
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn concurrent_reservations_cannot_over_allocate_tokens() {
        let broker = ReviewBudgetBroker::new(
            ReviewBudgetLimits {
                max_model_tokens: 100,
                max_output_tokens: 100,
                ..limits()
            },
            0,
        )
        .expect("valid broker");
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let broker = broker.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    broker.reserve_model_request(reservation(), 1)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread completes"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        drop(results);
        assert_eq!(broker.snapshot().usage.input_tokens, 80);
    }

    #[test]
    fn reported_usage_releases_unused_capacity() {
        let broker = ReviewBudgetBroker::new(limits(), 10).expect("valid broker");
        let permit = broker
            .reserve_model_request(reservation(), 11)
            .expect("first reservation");
        assert_eq!(broker.snapshot().outstanding.input_tokens, 80);
        assert_eq!(
            permit.commit(
                Some(ReviewModelUsage {
                    input_tokens: 20,
                    output_tokens: 5,
                    cost_microusd: 2,
                }),
                12,
            ),
            Ok(ReviewModelSettlement::Reported(ReviewModelUsage {
                input_tokens: 20,
                output_tokens: 5,
                cost_microusd: 2,
            }))
        );
        let second = broker
            .reserve_model_request(
                ReviewModelReservation {
                    input_tokens: 200,
                    output_tokens: 50,
                    cost_microusd: 20,
                },
                13,
            )
            .expect("released capacity is reusable");
        drop(second);
        let snapshot = broker.snapshot();
        assert_eq!(
            snapshot.outstanding,
            OutstandingReviewReservations::default()
        );
        assert_eq!(snapshot.usage.model_requests, 2);
        assert_eq!(snapshot.usage.input_tokens, 220);
        assert_eq!(snapshot.usage.output_tokens, 55);
    }

    #[test]
    fn absent_usage_charges_full_reservation() {
        let broker = ReviewBudgetBroker::new(limits(), 0).expect("valid broker");
        let permit = broker
            .reserve_model_request(reservation(), 1)
            .expect("reservation");
        assert_eq!(
            permit.commit(None, 2),
            Ok(ReviewModelSettlement::Conservative {
                charged: reservation().into(),
                reason: ConservativeChargeReason::MissingUsage,
            })
        );
        assert_eq!(broker.snapshot().usage.input_tokens, 80);
    }

    #[test]
    fn per_call_usage_matches_reported_and_conservative_settlements() {
        let reported = ReviewModelSettlement::Reported(ReviewModelUsage {
            input_tokens: 12,
            output_tokens: 3,
            cost_microusd: 4,
        });
        assert_eq!(
            ReviewCallUsage::settled(reported).into_budget_usage(),
            ReviewBudgetUsage {
                model_requests: 1,
                input_tokens: 12,
                output_tokens: 3,
                cost_microusd: 4,
                ..ReviewBudgetUsage::default()
            }
        );
        assert_eq!(
            ReviewCallUsage::conservative(reservation()).into_budget_usage(),
            ReviewBudgetUsage {
                model_requests: 1,
                input_tokens: 80,
                output_tokens: 20,
                cost_microusd: 10,
                ..ReviewBudgetUsage::default()
            }
        );
    }

    #[test]
    fn usage_over_any_reservation_dimension_is_ambiguous() {
        for (usage, dimension) in [
            (
                ReviewModelUsage {
                    input_tokens: 81,
                    output_tokens: 1,
                    cost_microusd: 1,
                },
                ReviewBudgetDimension::ModelTokens,
            ),
            (
                ReviewModelUsage {
                    input_tokens: 1,
                    output_tokens: 21,
                    cost_microusd: 1,
                },
                ReviewBudgetDimension::OutputTokens,
            ),
            (
                ReviewModelUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cost_microusd: 11,
                },
                ReviewBudgetDimension::Cost,
            ),
        ] {
            let broker = ReviewBudgetBroker::new(limits(), 0).expect("valid broker");
            let permit = broker
                .reserve_model_request(reservation(), 1)
                .expect("reservation");
            assert_eq!(
                permit.commit(Some(usage), 2),
                Ok(ReviewModelSettlement::Conservative {
                    charged: reservation().into(),
                    reason: ConservativeChargeReason::AmbiguousUsage(dimension),
                })
            );
            assert_eq!(broker.snapshot().usage.input_tokens, 80);
        }
    }

    #[test]
    fn dropping_permit_conservatively_settles_it() {
        let broker = ReviewBudgetBroker::new(limits(), 0).expect("valid broker");
        let permit = broker
            .reserve_model_request(reservation(), 1)
            .expect("reservation");
        assert_eq!(permit.id(), 1);
        drop(permit);
        let snapshot = broker.snapshot();
        assert_eq!(
            snapshot.outstanding,
            OutstandingReviewReservations::default()
        );
        assert_eq!(snapshot.usage.input_tokens, 80);
        assert_eq!(snapshot.usage.output_tokens, 20);
        assert_eq!(snapshot.usage.cost_microusd, 10);
    }

    #[test]
    fn request_count_is_charged_at_dispatch_and_never_refunded() {
        let broker = ReviewBudgetBroker::new(
            ReviewBudgetLimits {
                max_model_requests: 1,
                ..limits()
            },
            0,
        )
        .expect("valid broker");
        broker
            .reserve_model_request(reservation(), 0)
            .expect("first request")
            .commit(
                Some(ReviewModelUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    cost_microusd: 1,
                }),
                1,
            )
            .expect("settled");
        assert!(matches!(
            broker.reserve_model_request(reservation(), 2),
            Err(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::ModelRequests
            ))
        ));
    }

    #[test]
    fn output_and_cost_limits_are_reserved_independently() {
        let broker = ReviewBudgetBroker::new(
            ReviewBudgetLimits {
                max_model_tokens: 1_000,
                max_output_tokens: 20,
                max_cost_microusd: 10,
                ..limits()
            },
            0,
        )
        .expect("valid broker");
        let permit = broker
            .reserve_model_request(reservation(), 0)
            .expect("exact capacity is admitted");
        assert!(matches!(
            broker.reserve_model_request(
                ReviewModelReservation {
                    input_tokens: 1,
                    output_tokens: 1,
                    cost_microusd: 0,
                },
                1,
            ),
            Err(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::OutputTokens
            ))
        ));
        drop(permit);
        assert!(matches!(
            broker.reserve_model_request(
                ReviewModelReservation {
                    input_tokens: 1,
                    output_tokens: 0,
                    cost_microusd: 1,
                },
                2,
            ),
            Err(ReviewBudgetError::Exhausted(ReviewBudgetDimension::Cost))
        ));
    }

    #[test]
    fn tool_charges_are_atomic_and_obey_deadline() {
        let broker = ReviewBudgetBroker::new(limits(), 1_000).expect("valid broker");
        broker.charge_tool_calls(2, 1_050).expect("within budget");
        assert_eq!(
            broker.charge_tool_calls(2, 1_060),
            Err(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::ToolCalls
            ))
        );
        assert_eq!(broker.snapshot().usage.tool_calls, 2);
        assert_eq!(
            broker.charge_tool_calls(1, 1_101),
            Err(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::ElapsedTime
            ))
        );
        assert_eq!(broker.snapshot().usage.tool_calls, 2);
        assert_eq!(
            broker.charge_tool_calls(1, 1_100),
            Err(ReviewBudgetError::ClockRegression)
        );
    }

    #[test]
    fn calls_may_settle_after_deadline() {
        let broker = ReviewBudgetBroker::new(limits(), 0).expect("valid broker");
        let permit = broker
            .reserve_model_request(reservation(), 100)
            .expect("dispatch at deadline");
        permit
            .commit(
                Some(ReviewModelUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    cost_microusd: 1,
                }),
                150,
            )
            .expect("in-flight call can settle after deadline");
        assert_eq!(broker.snapshot().usage.elapsed_millis, 150);
        assert!(matches!(
            broker.reserve_model_request(reservation(), 151),
            Err(ReviewBudgetError::Exhausted(
                ReviewBudgetDimension::ElapsedTime
            ))
        ));
    }

    #[test]
    fn rejected_reservation_does_not_change_capacity_counters() {
        let broker = ReviewBudgetBroker::new(limits(), 0).expect("valid broker");
        assert!(matches!(
            broker.reserve_model_request(
                ReviewModelReservation {
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microusd: 0,
                },
                1,
            ),
            Err(ReviewBudgetError::InvalidReservation)
        ));
        assert_eq!(broker.snapshot().usage.model_requests, 0);
        assert_eq!(broker.snapshot().outstanding.model_requests, 0);
    }

    #[test]
    fn phase_usage_is_atomic_for_settled_dropped_and_tool_charges() {
        let broker = ReviewBudgetBroker::new(limits(), 0).expect("valid broker");
        let settled = broker
            .reserve_model_request_for_phase(ReviewBudgetPhase::Grouping, reservation(), 1)
            .expect("grouping reservation");
        settled
            .commit(
                Some(ReviewModelUsage {
                    input_tokens: 7,
                    output_tokens: 3,
                    cost_microusd: 2,
                }),
                2,
            )
            .expect("settled grouping call");
        let dropped = broker
            .reserve_model_request_for_phase(ReviewBudgetPhase::Review, reservation(), 3)
            .expect("review reservation");
        drop(dropped);
        broker
            .charge_tool_calls_for_phase(ReviewBudgetPhase::Review, 2, 4)
            .expect("review tools");

        assert_eq!(
            broker.phase_usage(ReviewBudgetPhase::Grouping),
            ReviewBudgetUsage {
                model_requests: 1,
                input_tokens: 7,
                output_tokens: 3,
                cost_microusd: 2,
                ..ReviewBudgetUsage::default()
            }
        );
        assert_eq!(
            broker.phase_usage(ReviewBudgetPhase::Review),
            ReviewBudgetUsage {
                model_requests: 1,
                input_tokens: 80,
                output_tokens: 20,
                tool_calls: 2,
                cost_microusd: 10,
                ..ReviewBudgetUsage::default()
            }
        );
        let aggregate = broker.snapshot().usage;
        let grouping = broker.phase_usage(ReviewBudgetPhase::Grouping);
        let review = broker.phase_usage(ReviewBudgetPhase::Review);
        assert_eq!(
            aggregate.model_requests,
            grouping.model_requests + review.model_requests
        );
        assert_eq!(
            aggregate.input_tokens,
            grouping.input_tokens + review.input_tokens
        );
        assert_eq!(
            aggregate.output_tokens,
            grouping.output_tokens + review.output_tokens
        );
        assert_eq!(
            aggregate.tool_calls,
            grouping.tool_calls + review.tool_calls
        );
        assert_eq!(
            aggregate.cost_microusd,
            grouping.cost_microusd + review.cost_microusd
        );
    }
}
