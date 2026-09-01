//! Deterministic bounded scheduling for isolated review groups.
//!
//! The scheduler owns no provider, model, filesystem, or async-runtime behavior.
//! Callers pull ready assignments, run them concurrently, and report one closed
//! outcome per assignment. Queue order depends only on immutable group metadata.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use revoot_core::{ReviewGroup, ReviewGroupId, ReviewGroupPlan, ReviewValueTier, Sha256Digest};
use serde::{Deserialize, Serialize};

pub const MIN_PARALLEL_GROUPS: usize = 1;
pub const MAX_PARALLEL_GROUPS: usize = 8;

/// One group released to a worker, with its immutable priority position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledReviewGroup {
    pub priority_position: u32,
    pub group: ReviewGroup,
}

/// A bounded reason why a worker returned useful but incomplete work.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPartialReason {
    BudgetExhausted,
    CoverageIncomplete,
    DeadlineExceeded,
    ProviderUnavailable,
    ToolError,
    VerificationFailed,
}

/// A bounded reason why a worker could not return review results.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupFailureReason {
    InvalidOutput,
    PreparationFailed,
    ProviderFailed,
    RuntimeFailure,
}

/// Terminal result supplied by an isolated group worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupRunOutcome {
    Complete,
    Partial(GroupPartialReason),
    Failed(GroupFailureReason),
    Cancelled,
}

/// Stable lifecycle state for one group in priority order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum GroupScheduleStatus {
    Queued,
    Running,
    Complete,
    Partial(GroupPartialReason),
    Failed(GroupFailureReason),
    CancelledBeforeDispatch,
    CancelledWhileRunning,
}

impl GroupScheduleStatus {
    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete
                | Self::Partial(_)
                | Self::Failed(_)
                | Self::CancelledBeforeDispatch
                | Self::CancelledWhileRunning
        )
    }

    const fn is_partial(self) -> bool {
        !matches!(self, Self::Queued | Self::Running | Self::Complete)
    }
}

/// One redaction-safe scheduling record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupScheduleRecord {
    pub group_id: ReviewGroupId,
    pub priority_position: u32,
    pub status: GroupScheduleStatus,
}

/// Aggregate scheduler state. Records always retain immutable priority order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupScheduleSnapshot {
    pub plan_sha256: Sha256Digest,
    pub max_parallel_groups: u8,
    pub cancellation_requested: bool,
    pub queued_groups: u32,
    pub running_groups: u32,
    pub complete_groups: u32,
    pub partial_groups: u32,
    pub failed_groups: u32,
    pub cancelled_groups: u32,
    pub partial: bool,
    pub records: Vec<GroupScheduleRecord>,
}

/// Closed scheduling contract failure with no source payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupSchedulerError {
    InvalidParallelism,
    TooManyGroups,
    DuplicateGroupId,
    UnknownGroup,
    GroupNotRunning,
    GroupAlreadyFinished,
}

impl fmt::Display for GroupSchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidParallelism => "parallel group limit is outside the supported range",
            Self::TooManyGroups => "group count cannot be represented by the scheduler",
            Self::DuplicateGroupId => "review group identifiers must be unique",
            Self::UnknownGroup => "review group is not part of this schedule",
            Self::GroupNotRunning => "review group is not currently running",
            Self::GroupAlreadyFinished => "review group already has a terminal outcome",
        })
    }
}

impl std::error::Error for GroupSchedulerError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RiskProfile {
    high: u32,
    standard: u32,
    low: u32,
}

impl RiskProfile {
    fn for_group(group: &ReviewGroup) -> Self {
        let mut profile = Self::default();
        for file in &group.files {
            match file.tier {
                ReviewValueTier::High => profile.high += 1,
                ReviewValueTier::Standard => profile.standard += 1,
                ReviewValueTier::Low => profile.low += 1,
            }
        }
        profile
    }
}

/// Stateful dispatcher enforcing the configured concurrency bound.
#[derive(Debug)]
pub struct GroupScheduler {
    plan_sha256: Sha256Digest,
    max_parallel_groups: u8,
    cancellation_requested: bool,
    queued: VecDeque<ScheduledReviewGroup>,
    running: BTreeSet<ReviewGroupId>,
    records: Vec<GroupScheduleRecord>,
    record_by_id: BTreeMap<ReviewGroupId, usize>,
}

impl GroupScheduler {
    /// Build a priority queue from an immutable group plan.
    ///
    /// High-tier groups dispatch before standard- and low-tier groups. Within
    /// the same tier profile, the lexically first changed path wins the tie.
    ///
    /// # Errors
    ///
    /// Rejects concurrency outside `1..=8`, unrepresentable group counts, and
    /// duplicate group identities.
    pub fn new(
        plan: &ReviewGroupPlan,
        max_parallel_groups: usize,
    ) -> Result<Self, GroupSchedulerError> {
        if !(MIN_PARALLEL_GROUPS..=MAX_PARALLEL_GROUPS).contains(&max_parallel_groups) {
            return Err(GroupSchedulerError::InvalidParallelism);
        }
        u32::try_from(plan.groups.len()).map_err(|_| GroupSchedulerError::TooManyGroups)?;

        let mut groups = plan.groups.clone();
        groups.sort_by(group_priority_cmp);

        let mut queued = VecDeque::with_capacity(groups.len());
        let mut records = Vec::with_capacity(groups.len());
        let mut record_by_id = BTreeMap::new();
        for (index, group) in groups.into_iter().enumerate() {
            let priority_position =
                u32::try_from(index + 1).map_err(|_| GroupSchedulerError::TooManyGroups)?;
            if record_by_id
                .insert(group.id.clone(), records.len())
                .is_some()
            {
                return Err(GroupSchedulerError::DuplicateGroupId);
            }
            records.push(GroupScheduleRecord {
                group_id: group.id.clone(),
                priority_position,
                status: GroupScheduleStatus::Queued,
            });
            queued.push_back(ScheduledReviewGroup {
                priority_position,
                group,
            });
        }

        let max_parallel_groups = u8::try_from(max_parallel_groups)
            .map_err(|_| GroupSchedulerError::InvalidParallelism)?;
        Ok(Self {
            plan_sha256: plan.plan_sha256.clone(),
            max_parallel_groups,
            cancellation_requested: false,
            queued,
            running: BTreeSet::new(),
            records,
            record_by_id,
        })
    }

    /// Release as many assignments as the concurrency window permits.
    ///
    /// Once cancellation is requested, this method permanently returns an
    /// empty set. Already-running workers remain visible until they report a
    /// terminal outcome.
    pub fn dispatch_ready(&mut self) -> Vec<ScheduledReviewGroup> {
        if self.cancellation_requested {
            return Vec::new();
        }
        let available = usize::from(self.max_parallel_groups).saturating_sub(self.running.len());
        let mut dispatched = Vec::with_capacity(available.min(self.queued.len()));
        for _ in 0..available {
            let Some(scheduled) = self.queued.pop_front() else {
                break;
            };
            let group_id = scheduled.group.id.clone();
            self.running.insert(group_id.clone());
            if let Some(index) = self.record_by_id.get(&group_id).copied() {
                self.records[index].status = GroupScheduleStatus::Running;
            }
            dispatched.push(scheduled);
        }
        dispatched
    }

    /// Record one terminal worker result and make its concurrency slot reusable.
    ///
    /// # Errors
    ///
    /// Rejects unknown, queued, or already-terminal group identities.
    pub fn finish_group(
        &mut self,
        group_id: &ReviewGroupId,
        outcome: GroupRunOutcome,
    ) -> Result<(), GroupSchedulerError> {
        let Some(record_index) = self.record_by_id.get(group_id).copied() else {
            return Err(GroupSchedulerError::UnknownGroup);
        };
        let current = self.records[record_index].status;
        if current.is_terminal() {
            return Err(GroupSchedulerError::GroupAlreadyFinished);
        }
        if current != GroupScheduleStatus::Running || !self.running.remove(group_id) {
            return Err(GroupSchedulerError::GroupNotRunning);
        }
        let status = match outcome {
            GroupRunOutcome::Complete => GroupScheduleStatus::Complete,
            GroupRunOutcome::Partial(reason) => GroupScheduleStatus::Partial(reason),
            GroupRunOutcome::Failed(reason) => GroupScheduleStatus::Failed(reason),
            GroupRunOutcome::Cancelled => GroupScheduleStatus::CancelledWhileRunning,
        };
        self.records[record_index].status = status;
        Ok(())
    }

    /// Stop future dispatch and mark every queued assignment as not inspected.
    ///
    /// Returns the number of groups cancelled before dispatch. Repeated calls
    /// are idempotent.
    pub fn request_cancellation(&mut self) -> usize {
        self.cancellation_requested = true;
        let cancelled = self.queued.len();
        while let Some(scheduled) = self.queued.pop_front() {
            if let Some(index) = self.record_by_id.get(&scheduled.group.id).copied() {
                self.records[index].status = GroupScheduleStatus::CancelledBeforeDispatch;
            }
        }
        cancelled
    }

    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.queued.is_empty()
            && self.running.is_empty()
            && self
                .records
                .iter()
                .all(|record| record.status.is_terminal())
    }

    #[must_use]
    pub fn running_groups(&self) -> usize {
        self.running.len()
    }

    #[must_use]
    pub fn queued_groups(&self) -> usize {
        self.queued.len()
    }

    /// Return deterministic aggregate and per-group bookkeeping.
    #[must_use]
    pub fn snapshot(&self) -> GroupScheduleSnapshot {
        let mut queued_groups = 0_u32;
        let mut running_groups = 0_u32;
        let mut complete_groups = 0_u32;
        let mut partial_groups = 0_u32;
        let mut failed_groups = 0_u32;
        let mut cancelled_groups = 0_u32;
        for record in &self.records {
            match record.status {
                GroupScheduleStatus::Queued => queued_groups += 1,
                GroupScheduleStatus::Running => running_groups += 1,
                GroupScheduleStatus::Complete => complete_groups += 1,
                GroupScheduleStatus::Partial(_) => partial_groups += 1,
                GroupScheduleStatus::Failed(_) => failed_groups += 1,
                GroupScheduleStatus::CancelledBeforeDispatch
                | GroupScheduleStatus::CancelledWhileRunning => cancelled_groups += 1,
            }
        }
        GroupScheduleSnapshot {
            plan_sha256: self.plan_sha256.clone(),
            max_parallel_groups: self.max_parallel_groups,
            cancellation_requested: self.cancellation_requested,
            queued_groups,
            running_groups,
            complete_groups,
            partial_groups,
            failed_groups,
            cancelled_groups,
            partial: self.records.iter().any(|record| record.status.is_partial()),
            records: self.records.clone(),
        }
    }
}

fn group_priority_cmp(left: &ReviewGroup, right: &ReviewGroup) -> Ordering {
    let left_profile = RiskProfile::for_group(left);
    let right_profile = RiskProfile::for_group(right);
    right_profile
        .high
        .cmp(&left_profile.high)
        .then_with(|| right_profile.standard.cmp(&left_profile.standard))
        .then_with(|| right_profile.low.cmp(&left_profile.low))
        .then_with(|| first_path(left).cmp(first_path(right)))
        .then_with(|| left.id.cmp(&right.id))
}

fn first_path(group: &ReviewGroup) -> &str {
    group
        .files
        .iter()
        .map(|file| file.path.new_path.as_str())
        .min()
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use revoot_core::{
        ChangedPath, FileChangeKind, RepositoryPath, ReviewGroupFile, ReviewGroupLimits,
        ReviewGroupingSource,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn rejects_parallelism_outside_product_bounds() {
        let plan = plan(vec![]);
        assert_eq!(
            GroupScheduler::new(&plan, 0).expect_err("zero must fail"),
            GroupSchedulerError::InvalidParallelism
        );
        assert_eq!(
            GroupScheduler::new(&plan, 9).expect_err("nine must fail"),
            GroupSchedulerError::InvalidParallelism
        );
        GroupScheduler::new(&plan, 1).expect("lower bound");
        GroupScheduler::new(&plan, 8).expect("upper bound");
    }

    #[test]
    fn dispatches_high_signal_first_and_paths_break_ties() {
        let plan = plan(vec![
            group("low", &[("z-low.txt", ReviewValueTier::Low)]),
            group("std-z", &[("z-standard.rs", ReviewValueTier::Standard)]),
            group("high", &[("middle.rs", ReviewValueTier::High)]),
            group("std-a", &[("a-standard.rs", ReviewValueTier::Standard)]),
        ]);
        let mut scheduler = GroupScheduler::new(&plan, 4).expect("scheduler");
        let paths = scheduler
            .dispatch_ready()
            .into_iter()
            .map(|scheduled| first_path(&scheduled.group).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            ["middle.rs", "a-standard.rs", "z-standard.rs", "z-low.txt"]
        );
    }

    #[test]
    fn more_high_signal_files_win_within_the_same_top_tier() {
        let plan = plan(vec![
            group("one", &[("a.rs", ReviewValueTier::High)]),
            group(
                "two",
                &[
                    ("z.rs", ReviewValueTier::High),
                    ("zz.rs", ReviewValueTier::High),
                ],
            ),
        ]);
        let mut scheduler = GroupScheduler::new(&plan, 1).expect("scheduler");
        let first = scheduler.dispatch_ready();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].group.files.len(), 2);
    }

    #[test]
    fn completion_releases_exactly_one_concurrency_slot() {
        let plan = plan(vec![
            group("a", &[("a.rs", ReviewValueTier::High)]),
            group("b", &[("b.rs", ReviewValueTier::Standard)]),
            group("c", &[("c.rs", ReviewValueTier::Low)]),
        ]);
        let mut scheduler = GroupScheduler::new(&plan, 2).expect("scheduler");
        let initial = scheduler.dispatch_ready();
        assert_eq!(initial.len(), 2);
        assert!(scheduler.dispatch_ready().is_empty());

        scheduler
            .finish_group(&initial[1].group.id, GroupRunOutcome::Complete)
            .expect("finish running group");
        let next = scheduler.dispatch_ready();
        assert_eq!(next.len(), 1);
        assert_eq!(scheduler.running_groups(), 2);
        assert_eq!(scheduler.queued_groups(), 0);
    }

    #[test]
    fn cancellation_is_idempotent_and_preserves_running_bookkeeping() {
        let plan = plan(vec![
            group("a", &[("a.rs", ReviewValueTier::High)]),
            group("b", &[("b.rs", ReviewValueTier::Standard)]),
            group("c", &[("c.rs", ReviewValueTier::Low)]),
        ]);
        let mut scheduler = GroupScheduler::new(&plan, 1).expect("scheduler");
        let running = scheduler.dispatch_ready();
        assert_eq!(scheduler.request_cancellation(), 2);
        assert_eq!(scheduler.request_cancellation(), 0);
        assert!(scheduler.dispatch_ready().is_empty());
        assert!(!scheduler.is_finished());

        scheduler
            .finish_group(&running[0].group.id, GroupRunOutcome::Cancelled)
            .expect("cancel running group");
        let snapshot = scheduler.snapshot();
        assert!(scheduler.is_finished());
        assert_eq!(snapshot.cancelled_groups, 3);
        assert!(snapshot.partial);
        assert!(snapshot.cancellation_requested);
    }

    #[test]
    fn terminal_outcomes_remain_in_priority_order() {
        let plan = plan(vec![
            group("a", &[("a.rs", ReviewValueTier::High)]),
            group("b", &[("b.rs", ReviewValueTier::Standard)]),
            group("c", &[("c.rs", ReviewValueTier::Low)]),
        ]);
        let mut scheduler = GroupScheduler::new(&plan, 3).expect("scheduler");
        let running = scheduler.dispatch_ready();
        scheduler
            .finish_group(
                &running[2].group.id,
                GroupRunOutcome::Failed(GroupFailureReason::ProviderFailed),
            )
            .expect("failure");
        scheduler
            .finish_group(&running[0].group.id, GroupRunOutcome::Complete)
            .expect("complete");
        scheduler
            .finish_group(
                &running[1].group.id,
                GroupRunOutcome::Partial(GroupPartialReason::CoverageIncomplete),
            )
            .expect("partial");

        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.complete_groups, 1);
        assert_eq!(snapshot.partial_groups, 1);
        assert_eq!(snapshot.failed_groups, 1);
        assert!(snapshot.partial);
        assert_eq!(
            snapshot
                .records
                .iter()
                .map(|record| record.priority_position)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
    }

    #[test]
    fn queued_and_terminal_groups_cannot_be_finished_again() {
        let plan = plan(vec![group("a", &[("a.rs", ReviewValueTier::High)])]);
        let mut scheduler = GroupScheduler::new(&plan, 1).expect("scheduler");
        let id = plan.groups[0].id.clone();
        assert_eq!(
            scheduler
                .finish_group(&id, GroupRunOutcome::Complete)
                .expect_err("queued group"),
            GroupSchedulerError::GroupNotRunning
        );
        scheduler.dispatch_ready();
        scheduler
            .finish_group(&id, GroupRunOutcome::Complete)
            .expect("first completion");
        assert_eq!(
            scheduler
                .finish_group(&id, GroupRunOutcome::Complete)
                .expect_err("terminal group"),
            GroupSchedulerError::GroupAlreadyFinished
        );
    }

    fn plan(groups: Vec<ReviewGroup>) -> ReviewGroupPlan {
        ReviewGroupPlan {
            schema_version: ReviewGroupPlan::SCHEMA_VERSION.to_owned(),
            partition_sha256: Sha256Digest::of_bytes(b"partition"),
            source: ReviewGroupingSource::Deterministic,
            limits: ReviewGroupLimits::default(),
            groups,
            plan_sha256: Sha256Digest::of_bytes(b"group-plan"),
        }
    }

    fn group(id: &str, files: &[(&str, ReviewValueTier)]) -> ReviewGroup {
        let files = files
            .iter()
            .map(|(path, tier)| ReviewGroupFile {
                path: changed_path(path),
                tier: *tier,
                input_bytes: 10,
                anchor_ids: Vec::new(),
                work_unit_id: serde_json::from_value(json!(format!("wu-{id}")))
                    .expect("work unit id"),
            })
            .collect::<Vec<_>>();
        ReviewGroup {
            id: serde_json::from_value(json!(format!("rg-{id}"))).expect("group id"),
            input_bytes: u64::try_from(files.len()).expect("file count") * 10,
            anchor_count: 0,
            files,
        }
    }

    fn changed_path(path: &str) -> ChangedPath {
        let path = RepositoryPath::try_from(path.to_owned()).expect("repository path");
        ChangedPath {
            old_path: path.clone(),
            new_path: path,
            kind: FileChangeKind::Modified,
        }
    }
}
