//! Typed provider-request allocation across review phases.
//!
//! Required worker, verifier, and adjudicator headroom is reserved before
//! high-signal groups are dispatched. Optional planning or review turns can
//! consume only capacity not protected for those required phases.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::ReviewEffort;

const MAX_MODEL_REQUESTS: u32 = 256;
const MAX_GROUPS: usize = 128;
const MAX_GROUP_ID_BYTES: usize = 128;
const MAX_ORDER_KEY_BYTES: usize = 4_096;
const GLOBAL_ADJUDICATOR_TURN_CEILING: u8 = 4;

/// Aggregate phase-allocation limits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseBudgetLimits {
    pub max_model_requests: u32,
}

impl Default for PhaseBudgetLimits {
    fn default() -> Self {
        Self {
            max_model_requests: 64,
        }
    }
}

impl PhaseBudgetLimits {
    /// Validate the configurable aggregate request range.
    ///
    /// # Errors
    ///
    /// Rejects zero or product-maximum-breaking values.
    pub const fn validate(self) -> Result<(), PhaseBudgetError> {
        if self.max_model_requests == 0 || self.max_model_requests > MAX_MODEL_REQUESTS {
            Err(PhaseBudgetError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Deterministic signal ordering for group dispatch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchSignal {
    High,
    Standard,
    Low,
}

impl DispatchSignal {
    const fn priority(self) -> u8 {
        match self {
            Self::High => 3,
            Self::Standard => 2,
            Self::Low => 1,
        }
    }
}

/// Metadata-only group dispatch input. No diff or source body is representable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDispatchCandidate {
    pub group_id: String,
    pub signal: DispatchSignal,
    pub stable_order_key: String,
    pub complex: bool,
}

/// Opaque allocator-issued authority for one dispatched group.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PhaseGroupHandle(u32);

/// Group identity and typed allocation handle returned by dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchedPhaseGroup {
    pub handle: PhaseGroupHandle,
    pub group_id: String,
    pub signal: DispatchSignal,
    pub complex: bool,
}

/// Result of requesting the next high-signal group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupDispatchResult {
    Dispatched(DispatchedPhaseGroup),
    Complete,
    Exhausted { undispatched_groups: u32 },
}

/// Typed group-phase request. Invalid review-round numbers are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupRequestPhase {
    Planning,
    Review { round: u8 },
    Verification,
}

/// Typed global request phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalRequestPhase {
    GroupingMetadataOnly,
    Adjudication,
}

/// One charged provider request allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseRequestAllocation {
    pub request_number: u32,
    pub phase: AllocatedRequestPhase,
}

/// Fully typed phase retained for usage reporting and provider dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocatedRequestPhase {
    GroupingMetadataOnly,
    GroupPlanning { group: PhaseGroupHandle },
    GroupReview { group: PhaseGroupHandle, round: u8 },
    GroupVerification { group: PhaseGroupHandle },
    GlobalAdjudication,
}

/// Redaction-safe aggregate request usage by phase.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseBudgetUsage {
    pub model_requests: u32,
    pub grouping_requests: u32,
    pub planning_requests: u32,
    pub review_requests: u32,
    pub verification_requests: u32,
    pub adjudication_requests: u32,
    pub dispatched_groups: u32,
}

/// Current protected headroom and aggregate use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseBudgetSnapshot {
    pub limits: PhaseBudgetLimits,
    pub usage: PhaseBudgetUsage,
    pub required_worker_requests: u32,
    pub reserved_verifier_requests: u32,
    pub reserved_adjudicator_requests: u32,
    pub queued_groups: u32,
    pub dispatch_stopped: bool,
}

/// Stable, payload-free allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseBudgetError {
    InvalidLimits,
    InvalidGroup,
    DuplicateGroup,
    TooManyGroups,
    GroupingRequestLimit,
    AdjudicatorTurnLimit,
    UnknownGroup,
    GroupTurnLimit,
    PlanningNotAllowed,
    PlanningRequired,
    ReviewRequired,
    InvalidReviewRound,
    ReviewRoundOrder,
    VerificationRequestLimit,
    Exhausted,
    CounterOverflow,
}

#[derive(Clone, Debug)]
struct ActiveGroup {
    turn_ceiling: u8,
    review_rounds: u8,
    turns_used: u8,
    highest_review_round: u8,
    state: ActiveGroupState,
}

#[derive(Clone, Copy, Debug)]
struct ActiveGroupState(u8);

impl ActiveGroupState {
    const COMPLEX: u8 = 1 << 0;
    const PLANNING_USED: u8 = 1 << 1;
    const REVIEW_USED: u8 = 1 << 2;
    const VERIFICATION_USED: u8 = 1 << 3;
    const PLANNING_RESERVED: u8 = 1 << 4;
    const REVIEW_RESERVED: u8 = 1 << 5;
    const VERIFIER_RESERVED: u8 = 1 << 6;

    const fn new(complex: bool) -> Self {
        let mut value = Self::REVIEW_RESERVED | Self::VERIFIER_RESERVED;
        if complex {
            value |= Self::COMPLEX | Self::PLANNING_RESERVED;
        }
        Self(value)
    }

    const fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }

    fn remove(&mut self, flag: u8) {
        self.0 &= !flag;
    }
}

/// Deterministic typed allocator for all provider-call phases.
pub struct PhaseBudgetAllocator {
    limits: PhaseBudgetLimits,
    effort: ReviewEffort,
    queue: VecDeque<GroupDispatchCandidate>,
    active: BTreeMap<PhaseGroupHandle, ActiveGroup>,
    next_group_handle: u32,
    usage: PhaseBudgetUsage,
    grouping_used: bool,
    adjudicator_turns: u8,
    adjudicator_reserved: bool,
    dispatch_stopped: bool,
}

impl PhaseBudgetAllocator {
    /// Validate, sort, and retain body-free group dispatch metadata.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, identifiers, duplicate groups, or excessive
    /// group counts without including metadata in the error.
    pub fn new(
        limits: PhaseBudgetLimits,
        effort: ReviewEffort,
        mut groups: Vec<GroupDispatchCandidate>,
    ) -> Result<Self, PhaseBudgetError> {
        limits.validate()?;
        if groups.len() > MAX_GROUPS {
            return Err(PhaseBudgetError::TooManyGroups);
        }
        let mut ids = std::collections::BTreeSet::new();
        for group in &groups {
            if !valid_group_id(&group.group_id)
                || group.stable_order_key.is_empty()
                || group.stable_order_key.len() > MAX_ORDER_KEY_BYTES
                || group.stable_order_key.contains('\0')
            {
                return Err(PhaseBudgetError::InvalidGroup);
            }
            if !ids.insert(group.group_id.as_str()) {
                return Err(PhaseBudgetError::DuplicateGroup);
            }
        }
        groups.sort_by(|left, right| {
            right
                .signal
                .priority()
                .cmp(&left.signal.priority())
                .then_with(|| left.stable_order_key.cmp(&right.stable_order_key))
                .then_with(|| left.group_id.cmp(&right.group_id))
        });
        Ok(Self {
            limits,
            effort,
            queue: groups.into(),
            active: BTreeMap::new(),
            next_group_handle: 1,
            usage: PhaseBudgetUsage::default(),
            grouping_used: false,
            adjudicator_turns: 0,
            adjudicator_reserved: true,
            dispatch_stopped: false,
        })
    }

    /// Return phase ceilings for the selected effort.
    #[must_use]
    pub const fn group_turn_ceiling(&self) -> u8 {
        effort_turn_ceiling(self.effort)
    }

    /// Return review rounds for the selected effort.
    #[must_use]
    pub const fn review_rounds(&self) -> u8 {
        effort_review_rounds(self.effort)
    }

    /// Return redaction-safe current use and protected headroom.
    #[must_use]
    pub fn snapshot(&self) -> PhaseBudgetSnapshot {
        PhaseBudgetSnapshot {
            limits: self.limits,
            usage: self.usage,
            required_worker_requests: self.required_worker_requests(),
            reserved_verifier_requests: self.reserved_verifier_requests(),
            reserved_adjudicator_requests: u32::from(self.adjudicator_reserved),
            queued_groups: self.queue.len().try_into().unwrap_or(u32::MAX),
            dispatch_stopped: self.dispatch_stopped,
        }
    }

    /// Reserve the sole metadata-only semantic grouping request.
    ///
    /// # Errors
    ///
    /// Rejects a second grouping request or aggregate exhaustion. Global
    /// adjudicator headroom remains protected.
    pub fn reserve_global_request(
        &mut self,
        phase: GlobalRequestPhase,
    ) -> Result<PhaseRequestAllocation, PhaseBudgetError> {
        match phase {
            GlobalRequestPhase::GroupingMetadataOnly => {
                if self.grouping_used {
                    return Err(PhaseBudgetError::GroupingRequestLimit);
                }
                self.consume_free_request()?;
                self.grouping_used = true;
                self.usage.grouping_requests = self.usage.grouping_requests.saturating_add(1);
                Ok(self.allocation(AllocatedRequestPhase::GroupingMetadataOnly))
            }
            GlobalRequestPhase::Adjudication => {
                if self.adjudicator_turns >= GLOBAL_ADJUDICATOR_TURN_CEILING {
                    return Err(PhaseBudgetError::AdjudicatorTurnLimit);
                }
                if self.adjudicator_reserved {
                    self.adjudicator_reserved = false;
                    self.consume_request()?;
                } else {
                    self.consume_free_request()?;
                }
                self.adjudicator_turns = self.adjudicator_turns.saturating_add(1);
                self.usage.adjudication_requests =
                    self.usage.adjudication_requests.saturating_add(1);
                Ok(self.allocation(AllocatedRequestPhase::GlobalAdjudication))
            }
        }
    }

    /// Dispatch the next highest-signal group only if required planning,
    /// initial review, verifier, and global adjudicator headroom all fit.
    ///
    /// Once the highest-signal pending group cannot fit, dispatch stops rather
    /// than bypassing it for a lower-signal group.
    pub fn dispatch_next_group(&mut self) -> GroupDispatchResult {
        if self.dispatch_stopped {
            return GroupDispatchResult::Exhausted {
                undispatched_groups: self.queue.len().try_into().unwrap_or(u32::MAX),
            };
        }
        let Some(next) = self.queue.front() else {
            return GroupDispatchResult::Complete;
        };
        let required_worker = if next.complex { 2 } else { 1 };
        let new_protected = required_worker + 1;
        if self
            .usage
            .model_requests
            .checked_add(self.protected_requests())
            .and_then(|total| total.checked_add(new_protected))
            .is_none_or(|total| total > self.limits.max_model_requests)
        {
            self.dispatch_stopped = true;
            return GroupDispatchResult::Exhausted {
                undispatched_groups: self.queue.len().try_into().unwrap_or(u32::MAX),
            };
        }
        let Some(next) = self.queue.pop_front() else {
            return GroupDispatchResult::Complete;
        };
        let handle = PhaseGroupHandle(self.next_group_handle);
        self.next_group_handle = self.next_group_handle.saturating_add(1);
        self.active.insert(
            handle,
            ActiveGroup {
                turn_ceiling: effort_turn_ceiling(self.effort),
                review_rounds: effort_review_rounds(self.effort),
                turns_used: 0,
                highest_review_round: 0,
                state: ActiveGroupState::new(next.complex),
            },
        );
        self.usage.dispatched_groups = self.usage.dispatched_groups.saturating_add(1);
        GroupDispatchResult::Dispatched(DispatchedPhaseGroup {
            handle,
            group_id: next.group_id,
            signal: next.signal,
            complex: next.complex,
        })
    }

    /// Reserve one typed request within a dispatched group.
    ///
    /// # Errors
    ///
    /// Enforces complexity, planning, review-round, per-group turn, verifier,
    /// and aggregate protected-headroom limits.
    pub fn reserve_group_request(
        &mut self,
        handle: PhaseGroupHandle,
        phase: GroupRequestPhase,
    ) -> Result<PhaseRequestAllocation, PhaseBudgetError> {
        let group = self
            .active
            .get(&handle)
            .ok_or(PhaseBudgetError::UnknownGroup)?;
        if group.turns_used >= group.turn_ceiling {
            return Err(PhaseBudgetError::GroupTurnLimit);
        }
        validate_group_phase(group, phase)?;

        let protected = match phase {
            GroupRequestPhase::Planning
                if group.state.contains(ActiveGroupState::PLANNING_RESERVED) =>
            {
                true
            }
            GroupRequestPhase::Review { .. }
                if group.state.contains(ActiveGroupState::REVIEW_RESERVED) =>
            {
                true
            }
            GroupRequestPhase::Verification
                if group.state.contains(ActiveGroupState::VERIFIER_RESERVED) =>
            {
                true
            }
            GroupRequestPhase::Planning
            | GroupRequestPhase::Review { .. }
            | GroupRequestPhase::Verification => false,
        };
        if protected {
            self.consume_request()?;
        } else {
            self.consume_free_request()?;
        }

        let group = self
            .active
            .get_mut(&handle)
            .ok_or(PhaseBudgetError::UnknownGroup)?;
        group.turns_used = group.turns_used.saturating_add(1);
        let allocated_phase = match phase {
            GroupRequestPhase::Planning => {
                group.state.insert(ActiveGroupState::PLANNING_USED);
                group.state.remove(ActiveGroupState::PLANNING_RESERVED);
                self.usage.planning_requests = self.usage.planning_requests.saturating_add(1);
                AllocatedRequestPhase::GroupPlanning { group: handle }
            }
            GroupRequestPhase::Review { round } => {
                group.state.insert(ActiveGroupState::REVIEW_USED);
                group.state.remove(ActiveGroupState::REVIEW_RESERVED);
                group.highest_review_round = group.highest_review_round.max(round);
                self.usage.review_requests = self.usage.review_requests.saturating_add(1);
                AllocatedRequestPhase::GroupReview {
                    group: handle,
                    round,
                }
            }
            GroupRequestPhase::Verification => {
                group.state.insert(ActiveGroupState::VERIFICATION_USED);
                group.state.remove(ActiveGroupState::VERIFIER_RESERVED);
                self.usage.verification_requests =
                    self.usage.verification_requests.saturating_add(1);
                AllocatedRequestPhase::GroupVerification { group: handle }
            }
        };
        Ok(self.allocation(allocated_phase))
    }

    /// Finish a group and release any unused required/verifier headroom.
    ///
    /// # Errors
    ///
    /// Rejects an unknown or already-finished handle.
    pub fn finish_group(&mut self, handle: PhaseGroupHandle) -> Result<(), PhaseBudgetError> {
        self.active
            .remove(&handle)
            .ok_or(PhaseBudgetError::UnknownGroup)?;
        Ok(())
    }

    fn allocation(&self, phase: AllocatedRequestPhase) -> PhaseRequestAllocation {
        PhaseRequestAllocation {
            request_number: self.usage.model_requests,
            phase,
        }
    }

    fn consume_request(&mut self) -> Result<(), PhaseBudgetError> {
        if self.usage.model_requests >= self.limits.max_model_requests {
            return Err(PhaseBudgetError::Exhausted);
        }
        self.usage.model_requests = self
            .usage
            .model_requests
            .checked_add(1)
            .ok_or(PhaseBudgetError::CounterOverflow)?;
        Ok(())
    }

    fn consume_free_request(&mut self) -> Result<(), PhaseBudgetError> {
        if self
            .usage
            .model_requests
            .checked_add(self.protected_requests())
            .is_none_or(|total| total >= self.limits.max_model_requests)
        {
            return Err(PhaseBudgetError::Exhausted);
        }
        self.consume_request()
    }

    fn required_worker_requests(&self) -> u32 {
        self.active.values().fold(0_u32, |total, group| {
            total
                .saturating_add(u32::from(
                    group.state.contains(ActiveGroupState::PLANNING_RESERVED),
                ))
                .saturating_add(u32::from(
                    group.state.contains(ActiveGroupState::REVIEW_RESERVED),
                ))
        })
    }

    fn reserved_verifier_requests(&self) -> u32 {
        self.active
            .values()
            .filter(|group| group.state.contains(ActiveGroupState::VERIFIER_RESERVED))
            .count()
            .try_into()
            .unwrap_or(u32::MAX)
    }

    fn protected_requests(&self) -> u32 {
        self.required_worker_requests()
            .saturating_add(self.reserved_verifier_requests())
            .saturating_add(u32::from(self.adjudicator_reserved))
    }
}

fn validate_group_phase(
    group: &ActiveGroup,
    phase: GroupRequestPhase,
) -> Result<(), PhaseBudgetError> {
    match phase {
        GroupRequestPhase::Planning if !group.state.contains(ActiveGroupState::COMPLEX) => {
            Err(PhaseBudgetError::PlanningNotAllowed)
        }
        GroupRequestPhase::Planning
            if group.state.contains(ActiveGroupState::REVIEW_USED)
                || group.state.contains(ActiveGroupState::VERIFICATION_USED) =>
        {
            Err(PhaseBudgetError::ReviewRoundOrder)
        }
        GroupRequestPhase::Review { .. }
            if group.state.contains(ActiveGroupState::COMPLEX)
                && group.state.contains(ActiveGroupState::PLANNING_RESERVED) =>
        {
            Err(PhaseBudgetError::PlanningRequired)
        }
        GroupRequestPhase::Review { round } if round == 0 || round > group.review_rounds => {
            Err(PhaseBudgetError::InvalidReviewRound)
        }
        GroupRequestPhase::Review { round }
            if round > group.highest_review_round.saturating_add(1) =>
        {
            Err(PhaseBudgetError::ReviewRoundOrder)
        }
        GroupRequestPhase::Review { round }
            if group.highest_review_round != 0 && round < group.highest_review_round =>
        {
            Err(PhaseBudgetError::ReviewRoundOrder)
        }
        GroupRequestPhase::Review { .. }
            if group.state.contains(ActiveGroupState::VERIFICATION_USED) =>
        {
            Err(PhaseBudgetError::ReviewRoundOrder)
        }
        GroupRequestPhase::Verification
            if group.state.contains(ActiveGroupState::VERIFICATION_USED) =>
        {
            Err(PhaseBudgetError::VerificationRequestLimit)
        }
        GroupRequestPhase::Verification
            if group.state.contains(ActiveGroupState::PLANNING_RESERVED) =>
        {
            Err(PhaseBudgetError::PlanningRequired)
        }
        GroupRequestPhase::Verification
            if group.state.contains(ActiveGroupState::REVIEW_RESERVED) =>
        {
            Err(PhaseBudgetError::ReviewRequired)
        }
        GroupRequestPhase::Planning
        | GroupRequestPhase::Review { .. }
        | GroupRequestPhase::Verification => Ok(()),
    }
}

const fn effort_turn_ceiling(effort: ReviewEffort) -> u8 {
    match effort {
        ReviewEffort::Low => 12,
        ReviewEffort::Medium => 20,
        ReviewEffort::High => 32,
    }
}

const fn effort_review_rounds(effort: ReviewEffort) -> u8 {
    match effort {
        ReviewEffort::Low => 1,
        ReviewEffort::Medium => 2,
        ReviewEffort::High => 3,
    }
}

fn valid_group_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GROUP_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, signal: DispatchSignal, complex: bool) -> GroupDispatchCandidate {
        GroupDispatchCandidate {
            group_id: id.to_owned(),
            signal,
            stable_order_key: format!("src/{id}.rs"),
            complex,
        }
    }

    fn dispatched(result: GroupDispatchResult) -> DispatchedPhaseGroup {
        let GroupDispatchResult::Dispatched(group) = result else {
            panic!("expected dispatched group")
        };
        group
    }

    #[test]
    fn default_and_effort_ceilings_are_fixed() {
        assert_eq!(PhaseBudgetLimits::default().max_model_requests, 64);
        for (effort, rounds, turns) in [
            (ReviewEffort::Low, 1, 12),
            (ReviewEffort::Medium, 2, 20),
            (ReviewEffort::High, 3, 32),
        ] {
            let allocator =
                PhaseBudgetAllocator::new(PhaseBudgetLimits::default(), effort, Vec::new())
                    .expect("allocator");
            assert_eq!(allocator.review_rounds(), rounds);
            assert_eq!(allocator.group_turn_ceiling(), turns);
        }
    }

    #[test]
    fn grouping_is_metadata_only_and_limited_to_one_request() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits::default(),
            ReviewEffort::Medium,
            Vec::new(),
        )
        .expect("allocator");
        assert!(matches!(
            allocator.reserve_global_request(GlobalRequestPhase::GroupingMetadataOnly),
            Ok(PhaseRequestAllocation {
                phase: AllocatedRequestPhase::GroupingMetadataOnly,
                ..
            })
        ));
        assert_eq!(
            allocator.reserve_global_request(GlobalRequestPhase::GroupingMetadataOnly),
            Err(PhaseBudgetError::GroupingRequestLimit)
        );
    }

    #[test]
    fn high_signal_dispatch_is_stable() {
        let groups = vec![
            candidate("low", DispatchSignal::Low, false),
            candidate("high-z", DispatchSignal::High, false),
            candidate("standard", DispatchSignal::Standard, false),
            candidate("high-a", DispatchSignal::High, false),
        ];
        let mut allocator =
            PhaseBudgetAllocator::new(PhaseBudgetLimits::default(), ReviewEffort::Medium, groups)
                .expect("allocator");
        let order: Vec<_> = (0..4)
            .map(|_| dispatched(allocator.dispatch_next_group()).group_id)
            .collect();
        assert_eq!(order, ["high-a", "high-z", "standard", "low"]);
    }

    #[test]
    fn dispatch_stops_instead_of_bypassing_exhausted_high_signal_group() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits {
                max_model_requests: 3,
            },
            ReviewEffort::Medium,
            vec![
                candidate("high-complex", DispatchSignal::High, true),
                candidate("low-simple", DispatchSignal::Low, false),
            ],
        )
        .expect("allocator");
        assert_eq!(
            allocator.dispatch_next_group(),
            GroupDispatchResult::Exhausted {
                undispatched_groups: 2
            }
        );
        assert_eq!(
            allocator.dispatch_next_group(),
            GroupDispatchResult::Exhausted {
                undispatched_groups: 2
            }
        );
    }

    #[test]
    fn optional_turns_cannot_consume_verifier_or_adjudicator_headroom() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits {
                max_model_requests: 4,
            },
            ReviewEffort::Medium,
            vec![candidate("group", DispatchSignal::High, false)],
        )
        .expect("allocator");
        let group = dispatched(allocator.dispatch_next_group());
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 })
            .expect("required review");
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 })
            .expect("one optional turn");
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 }),
            Err(PhaseBudgetError::Exhausted)
        );
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Verification)
            .expect("reserved verifier");
        allocator
            .reserve_global_request(GlobalRequestPhase::Adjudication)
            .expect("reserved adjudicator");
        assert_eq!(allocator.snapshot().usage.model_requests, 4);
    }

    #[test]
    fn complex_group_requires_planning_then_review_before_verification() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits::default(),
            ReviewEffort::Medium,
            vec![candidate("complex", DispatchSignal::High, true)],
        )
        .expect("allocator");
        let group = dispatched(allocator.dispatch_next_group());
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 }),
            Err(PhaseBudgetError::PlanningRequired)
        );
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Planning)
            .expect("planning");
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Verification),
            Err(PhaseBudgetError::ReviewRequired)
        );
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 })
            .expect("review");
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Verification)
            .expect("verification");
    }

    #[test]
    fn review_round_count_and_order_are_enforced() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits::default(),
            ReviewEffort::Medium,
            vec![candidate("group", DispatchSignal::High, false)],
        )
        .expect("allocator");
        let group = dispatched(allocator.dispatch_next_group());
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Review { round: 2 }),
            Err(PhaseBudgetError::ReviewRoundOrder)
        );
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 })
            .expect("round one");
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Review { round: 2 })
            .expect("round two");
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 }),
            Err(PhaseBudgetError::ReviewRoundOrder)
        );
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Review { round: 3 }),
            Err(PhaseBudgetError::InvalidReviewRound)
        );
    }

    #[test]
    fn per_group_turn_ceiling_includes_verification() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits::default(),
            ReviewEffort::Low,
            vec![candidate("group", DispatchSignal::High, false)],
        )
        .expect("allocator");
        let group = dispatched(allocator.dispatch_next_group());
        for _ in 0..11 {
            allocator
                .reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 })
                .expect("review turn");
        }
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Verification)
            .expect("twelfth group turn");
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Verification),
            Err(PhaseBudgetError::GroupTurnLimit)
        );
    }

    #[test]
    fn verifier_and_adjudicator_have_fixed_turn_limits() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits::default(),
            ReviewEffort::Medium,
            vec![candidate("group", DispatchSignal::High, false)],
        )
        .expect("allocator");
        let group = dispatched(allocator.dispatch_next_group());
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Review { round: 1 })
            .expect("review");
        allocator
            .reserve_group_request(group.handle, GroupRequestPhase::Verification)
            .expect("verifier");
        assert_eq!(
            allocator.reserve_group_request(group.handle, GroupRequestPhase::Verification),
            Err(PhaseBudgetError::VerificationRequestLimit)
        );
        for _ in 0..GLOBAL_ADJUDICATOR_TURN_CEILING {
            allocator
                .reserve_global_request(GlobalRequestPhase::Adjudication)
                .expect("adjudicator turn");
        }
        assert_eq!(
            allocator.reserve_global_request(GlobalRequestPhase::Adjudication),
            Err(PhaseBudgetError::AdjudicatorTurnLimit)
        );
    }

    #[test]
    fn finishing_failed_group_releases_unused_required_headroom() {
        let mut allocator = PhaseBudgetAllocator::new(
            PhaseBudgetLimits {
                max_model_requests: 5,
            },
            ReviewEffort::Medium,
            vec![
                candidate("first", DispatchSignal::High, true),
                candidate("second", DispatchSignal::Standard, false),
            ],
        )
        .expect("allocator");
        let first = dispatched(allocator.dispatch_next_group());
        assert!(matches!(
            allocator.dispatch_next_group(),
            GroupDispatchResult::Exhausted { .. }
        ));
        allocator.finish_group(first.handle).expect("finish");
        // Exhaustion intentionally stops dispatch permanently to preserve
        // stable high-signal ordering for the run.
        assert!(matches!(
            allocator.dispatch_next_group(),
            GroupDispatchResult::Exhausted { .. }
        ));
        assert_eq!(allocator.snapshot().required_worker_requests, 0);
        assert_eq!(allocator.snapshot().reserved_verifier_requests, 0);
    }
}
