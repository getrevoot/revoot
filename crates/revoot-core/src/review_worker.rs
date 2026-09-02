//! Deterministic lifecycle contracts for one isolated review group.
//!
//! The state machine performs no provider, filesystem, network, process, clock,
//! or publication operation. Runtime adapters must drive it explicitly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{RepositoryPath, ReviewEffort, ReviewGroup};

const COMPLEX_FILE_CHANGED_LINES: u32 = 50;
const COMPLEX_GROUP_CHANGED_LINES: u32 = 100;
const MAX_CHECKPOINT_BYTES: usize = 4 * 1024;
const MAX_CHECKPOINT_ITEMS: usize = 64;
const MAX_CHECKPOINT_ITEM_BYTES: usize = 512;

/// Changed-line metrics used to decide whether a planning pass is required.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGroupMetrics {
    pub changed_lines_by_path: BTreeMap<RepositoryPath, u32>,
}

impl ReviewGroupMetrics {
    /// Validate that metrics describe exactly the files assigned to the group.
    ///
    /// # Errors
    ///
    /// Returns a closed contract error for missing, unknown, or zero metrics.
    pub fn validate_against(&self, group: &ReviewGroup) -> Result<(), ReviewWorkerError> {
        if self.changed_lines_by_path.len() != group.files.len()
            || group.files.iter().any(|file| {
                self.changed_lines_by_path
                    .get(&file.path.new_path)
                    .is_none_or(|changed| *changed == 0)
            })
        {
            return Err(ReviewWorkerError::Metrics);
        }
        Ok(())
    }

    fn planning_required(&self) -> bool {
        self.changed_lines_by_path
            .values()
            .any(|changed| *changed >= COMPLEX_FILE_CHANGED_LINES)
            || self
                .changed_lines_by_path
                .values()
                .copied()
                .fold(0_u32, u32::saturating_add)
                >= COMPLEX_GROUP_CHANGED_LINES
    }
}

/// One fresh review round in an isolated worker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRound {
    pub number: u8,
}

/// Immutable execution policy for one group worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewWorkerPlan {
    pub group_id: String,
    pub effort: ReviewEffort,
    pub planning_required: bool,
    pub rounds: Vec<ReviewRound>,
    pub max_provider_turns: u32,
}

impl ReviewWorkerPlan {
    /// Build the fixed lifecycle for one validated group.
    ///
    /// # Errors
    ///
    /// Returns a closed contract error when the metrics do not match the group.
    pub fn build(
        group: &ReviewGroup,
        effort: ReviewEffort,
        metrics: &ReviewGroupMetrics,
    ) -> Result<Self, ReviewWorkerError> {
        metrics.validate_against(group)?;
        let rounds = (1..=effort.rounds())
            .map(|number| ReviewRound { number })
            .collect();
        Ok(Self {
            group_id: group.id.as_str().to_owned(),
            effort,
            planning_required: metrics.planning_required(),
            rounds,
            max_provider_turns: effort.max_group_turns(),
        })
    }
}

/// Bounded evidence retained when a later provider turn starts fresh.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewWorkerCheckpoint {
    pub hypotheses: Vec<String>,
    pub evidence_references: Vec<String>,
    pub unresolved_coverage: Vec<String>,
}

impl ReviewWorkerCheckpoint {
    /// Validate item counts, text bounds, and the encoded 4 KiB ceiling.
    ///
    /// # Errors
    ///
    /// Returns a closed contract error without retaining checkpoint contents.
    pub fn validate(&self) -> Result<(), ReviewWorkerError> {
        let lists = [
            self.hypotheses.as_slice(),
            self.evidence_references.as_slice(),
            self.unresolved_coverage.as_slice(),
        ];
        if lists.iter().any(|items| {
            items.len() > MAX_CHECKPOINT_ITEMS
                || items.iter().any(|item| {
                    item.is_empty() || item.len() > MAX_CHECKPOINT_ITEM_BYTES || item.contains('\0')
                })
        }) {
            return Err(ReviewWorkerError::Checkpoint);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ReviewWorkerError::Checkpoint)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(ReviewWorkerError::Checkpoint);
        }
        Ok(())
    }
}

/// Current phase of one isolated worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewWorkerPhase {
    Planning,
    Reviewing { round: u8 },
    Verifying,
    Complete,
    Partial,
}

/// Explicit state machine driven by the runtime worker.
#[derive(Debug)]
pub struct ReviewWorkerState {
    plan: ReviewWorkerPlan,
    phase: ReviewWorkerPhase,
    provider_turns: u32,
    phase_provider_turns: u32,
    checkpoint: ReviewWorkerCheckpoint,
}

impl ReviewWorkerState {
    /// Start at planning for complex groups and at round one otherwise.
    #[must_use]
    pub fn new(plan: ReviewWorkerPlan) -> Self {
        let phase = if plan.planning_required {
            ReviewWorkerPhase::Planning
        } else {
            ReviewWorkerPhase::Reviewing { round: 1 }
        };
        Self {
            plan,
            phase,
            provider_turns: 0,
            phase_provider_turns: 0,
            checkpoint: ReviewWorkerCheckpoint::default(),
        }
    }

    #[must_use]
    pub const fn phase(&self) -> ReviewWorkerPhase {
        self.phase
    }

    #[must_use]
    pub const fn provider_turns(&self) -> u32 {
        self.provider_turns
    }

    #[must_use]
    pub const fn phase_provider_turns(&self) -> u32 {
        self.phase_provider_turns
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &ReviewWorkerCheckpoint {
        &self.checkpoint
    }

    /// Account for a provider request before it is dispatched.
    ///
    /// # Errors
    ///
    /// Rejects terminal workers and requests beyond the effort ceiling.
    pub fn reserve_provider_turn(&mut self) -> Result<(), ReviewWorkerError> {
        if matches!(
            self.phase,
            ReviewWorkerPhase::Complete | ReviewWorkerPhase::Partial
        ) {
            return Err(ReviewWorkerError::Transition);
        }
        if self.provider_turns >= self.plan.max_provider_turns {
            self.phase = ReviewWorkerPhase::Partial;
            return Err(ReviewWorkerError::TurnBudget);
        }
        self.provider_turns += 1;
        self.phase_provider_turns += 1;
        Ok(())
    }

    /// Finish the optional planning phase with a validated checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects an invalid checkpoint or a worker outside the planning phase.
    pub fn finish_planning(
        &mut self,
        checkpoint: ReviewWorkerCheckpoint,
    ) -> Result<(), ReviewWorkerError> {
        if self.phase != ReviewWorkerPhase::Planning {
            return Err(ReviewWorkerError::Transition);
        }
        checkpoint.validate()?;
        self.checkpoint = checkpoint;
        self.phase = ReviewWorkerPhase::Reviewing { round: 1 };
        self.phase_provider_turns = 0;
        Ok(())
    }

    /// Finish one review round and start a fresh next round or verification.
    ///
    /// # Errors
    ///
    /// Rejects an invalid checkpoint or a worker outside a review round.
    pub fn finish_round(
        &mut self,
        checkpoint: ReviewWorkerCheckpoint,
    ) -> Result<(), ReviewWorkerError> {
        let ReviewWorkerPhase::Reviewing { round } = self.phase else {
            return Err(ReviewWorkerError::Transition);
        };
        checkpoint.validate()?;
        self.checkpoint = checkpoint;
        if usize::from(round) < self.plan.rounds.len() {
            self.phase = ReviewWorkerPhase::Reviewing { round: round + 1 };
        } else {
            self.phase = ReviewWorkerPhase::Verifying;
        }
        self.phase_provider_turns = 0;
        Ok(())
    }

    /// Finish verification after the runtime has enforced coverage and gates.
    ///
    /// # Errors
    ///
    /// Rejects a worker outside the verification phase.
    pub fn finish_verification(&mut self) -> Result<(), ReviewWorkerError> {
        if self.phase != ReviewWorkerPhase::Verifying {
            return Err(ReviewWorkerError::Transition);
        }
        self.phase = ReviewWorkerPhase::Complete;
        Ok(())
    }

    /// Mark a nonterminal worker partial after a bounded runtime failure.
    ///
    /// # Errors
    ///
    /// Rejects a worker that is already complete or partial.
    pub fn mark_partial(&mut self) -> Result<(), ReviewWorkerError> {
        if matches!(
            self.phase,
            ReviewWorkerPhase::Complete | ReviewWorkerPhase::Partial
        ) {
            return Err(ReviewWorkerError::Transition);
        }
        self.phase = ReviewWorkerPhase::Partial;
        Ok(())
    }
}

/// Redaction-safe lifecycle contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewWorkerError {
    Metrics,
    Checkpoint,
    TurnBudget,
    Transition,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    fn group() -> ReviewGroup {
        serde_json::from_value(json!({
            "id": format!("rg-{}", "a".repeat(64)),
            "files": [{
                "path": {
                    "old_path": "src/lib.rs",
                    "new_path": "src/lib.rs",
                    "kind": "modified"
                },
                "tier": "high",
                "input_bytes": 100,
                "anchor_ids": [],
                "work_unit_id": format!("wu-{}", "b".repeat(64))
            }],
            "input_bytes": 100,
            "anchor_count": 0
        }))
        .unwrap()
    }

    fn metrics(changed: u32) -> ReviewGroupMetrics {
        ReviewGroupMetrics {
            changed_lines_by_path: BTreeMap::from([(
                RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap(),
                changed,
            )]),
        }
    }

    #[test]
    fn complex_groups_plan_before_effort_rounds() {
        let plan = ReviewWorkerPlan::build(&group(), ReviewEffort::High, &metrics(50)).unwrap();
        assert!(plan.planning_required);
        assert_eq!(plan.rounds.len(), 3);
        assert_eq!(plan.max_provider_turns, 32);
        let mut state = ReviewWorkerState::new(plan);
        assert_eq!(state.phase(), ReviewWorkerPhase::Planning);
        state.reserve_provider_turn().unwrap();
        assert_eq!(state.phase_provider_turns(), 1);
        state
            .finish_planning(ReviewWorkerCheckpoint::default())
            .unwrap();
        assert_eq!(state.phase_provider_turns(), 0);
        for round in 1..=3 {
            assert_eq!(state.phase(), ReviewWorkerPhase::Reviewing { round });
            state.reserve_provider_turn().unwrap();
            state
                .finish_round(ReviewWorkerCheckpoint::default())
                .unwrap();
            assert_eq!(state.phase_provider_turns(), 0);
        }
        assert_eq!(state.phase(), ReviewWorkerPhase::Verifying);
        state.finish_verification().unwrap();
        assert_eq!(state.phase(), ReviewWorkerPhase::Complete);
    }

    #[test]
    fn simple_low_effort_group_skips_planning() {
        let plan = ReviewWorkerPlan::build(&group(), ReviewEffort::Low, &metrics(10)).unwrap();
        let state = ReviewWorkerState::new(plan);
        assert_eq!(state.phase(), ReviewWorkerPhase::Reviewing { round: 1 });
    }

    #[test]
    fn metrics_must_match_assigned_files() {
        let error = ReviewWorkerPlan::build(
            &group(),
            ReviewEffort::Medium,
            &ReviewGroupMetrics::default(),
        )
        .unwrap_err();
        assert_eq!(error, ReviewWorkerError::Metrics);
    }

    #[test]
    fn checkpoint_is_bounded_by_encoded_size() {
        let checkpoint = ReviewWorkerCheckpoint {
            hypotheses: (0..9).map(|_| "x".repeat(500)).collect(),
            ..ReviewWorkerCheckpoint::default()
        };
        assert_eq!(checkpoint.validate(), Err(ReviewWorkerError::Checkpoint));
    }

    #[test]
    fn turn_exhaustion_marks_worker_partial() {
        let plan = ReviewWorkerPlan::build(&group(), ReviewEffort::Low, &metrics(10)).unwrap();
        let mut state = ReviewWorkerState::new(plan);
        for _ in 0..12 {
            state.reserve_provider_turn().unwrap();
        }
        assert_eq!(
            state.reserve_provider_turn(),
            Err(ReviewWorkerError::TurnBudget)
        );
        assert_eq!(state.phase(), ReviewWorkerPhase::Partial);
    }
}
