//! Bounded asynchronous execution for isolated review groups.
//!
//! The runtime retains only generic caller-approved results and redaction-safe
//! scheduler metadata. Provider requests, tool payloads, and source content are
//! owned by the worker future and are not represented by this module.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

use revoot_core::{CancellationToken, ReviewGroupId, ReviewGroupPlan};
use tokio::task::{Id as TaskId, JoinSet};

use crate::group_scheduler::{
    GroupFailureReason, GroupPartialReason, GroupRunOutcome, GroupScheduleSnapshot, GroupScheduler,
    GroupSchedulerError, ScheduledReviewGroup,
};

/// Synchronous shared-budget observation made immediately before dispatch.
///
/// Workers remain responsible for atomically reserving their exact request,
/// token, tool, cost, and deadline capacity. Returning `false` pauses new
/// group dispatch for this call only; it is re-evaluated on every loop
/// iteration and does not by itself close future dispatch. Capacity is
/// counted with outstanding (not yet settled) reservations included, so it
/// can dip below the threshold only momentarily while other groups are still
/// in flight and free back up once they settle.
pub trait GroupDispatchBudget: Send + Sync {
    fn has_dispatch_capacity(&self) -> bool;
}

impl<F> GroupDispatchBudget for F
where
    F: Fn() -> bool + Send + Sync,
{
    fn has_dispatch_capacity(&self) -> bool {
        self()
    }
}

/// Closed worker result. Only complete results and explicitly verified partial
/// results can be retained by the runtime.
pub enum GroupWorkerResult<R> {
    Complete(R),
    Partial {
        reason: GroupPartialReason,
        verified_result: Option<R>,
    },
    Failed(GroupFailureReason),
    Cancelled,
}

impl<R> fmt::Debug for GroupWorkerResult<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete(_) => formatter.write_str("Complete([redacted])"),
            Self::Partial {
                reason,
                verified_result,
            } => formatter
                .debug_struct("Partial")
                .field("reason", reason)
                .field(
                    "verified_result",
                    &verified_result.as_ref().map(|_| "[redacted]"),
                )
                .finish(),
            Self::Failed(reason) => formatter.debug_tuple("Failed").field(reason).finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
        }
    }
}

/// Why the runtime permanently stopped dispatching queued groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupRuntimeStopReason {
    CancellationRequested,
    BudgetExhausted,
}

/// Provenance of one caller-approved retained result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedGroupResultKind {
    Complete,
    VerifiedPartial(GroupPartialReason),
}

/// One retained result in immutable scheduler-priority order.
pub struct RetainedGroupResult<R> {
    pub group_id: ReviewGroupId,
    pub priority_position: u32,
    pub kind: RetainedGroupResultKind,
    pub result: R,
}

impl<R> fmt::Debug for RetainedGroupResult<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedGroupResult")
            .field("group_id", &self.group_id)
            .field("priority_position", &self.priority_position)
            .field("kind", &self.kind)
            .field("result", &"[redacted]")
            .finish()
    }
}

/// Deterministic reduction of one bounded concurrent run.
pub struct GroupRuntimeReport<R> {
    pub schedule: GroupScheduleSnapshot,
    pub stop_reason: Option<GroupRuntimeStopReason>,
    pub retained_results: Vec<RetainedGroupResult<R>>,
}

impl<R> fmt::Debug for GroupRuntimeReport<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupRuntimeReport")
            .field("schedule", &self.schedule)
            .field("stop_reason", &self.stop_reason)
            .field("retained_result_count", &self.retained_results.len())
            .finish()
    }
}

/// Payload-free runtime orchestration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupRuntimeError {
    Scheduler(GroupSchedulerError),
    TaskBookkeeping,
}

impl fmt::Display for GroupRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Scheduler(_) => "group runtime scheduler transition failed",
            Self::TaskBookkeeping => "group runtime task bookkeeping failed",
        })
    }
}

impl std::error::Error for GroupRuntimeError {}

impl From<GroupSchedulerError> for GroupRuntimeError {
    fn from(error: GroupSchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

struct CompletedTask<R> {
    group_id: ReviewGroupId,
    priority_position: u32,
    result: GroupWorkerResult<R>,
}

/// Execute isolated groups with real concurrency bounded to `1..=8`.
///
/// `GroupScheduler` supplies stable high-signal ordering. The runtime checks
/// cancellation and shared-budget state before each refill. Cancellation is a
/// permanent stop; a shared-budget shortfall pauses new dispatch and only
/// becomes a permanent stop once no group is left running to free more
/// capacity, since outstanding reservations from in-flight groups can settle
/// for less than reserved. Already completed results and explicitly verified
/// partial results are retained even when the overall run stops early.
///
/// # Errors
///
/// Rejects invalid parallelism or scheduler/task lifecycle inconsistencies.
/// Worker panics are converted into a payload-free per-group runtime failure and
/// do not discard other completed results.
pub async fn run_group_runtime<R, W, WorkerFuture, B>(
    plan: &ReviewGroupPlan,
    max_parallel_groups: usize,
    cancellation: CancellationToken,
    budget: B,
    worker: W,
) -> Result<GroupRuntimeReport<R>, GroupRuntimeError>
where
    R: Send + 'static,
    W: Fn(ScheduledReviewGroup, CancellationToken) -> WorkerFuture + Send + Sync + 'static,
    WorkerFuture: Future<Output = GroupWorkerResult<R>> + Send + 'static,
    B: GroupDispatchBudget,
{
    let mut scheduler = GroupScheduler::new(plan, max_parallel_groups)?;
    let worker = Arc::new(worker);
    let mut tasks = JoinSet::new();
    let mut task_groups = HashMap::<TaskId, ReviewGroupId>::new();
    let mut retained_results = Vec::new();
    let mut stop_reason = None;

    loop {
        if dispatch_may_proceed(&mut scheduler, &cancellation, &budget, &mut stop_reason) {
            dispatch_ready(
                &mut scheduler,
                &mut tasks,
                &mut task_groups,
                &worker,
                &cancellation,
            );
        }
        if scheduler.is_finished() {
            break;
        }

        let joined = tasks
            .join_next_with_id()
            .await
            .ok_or(GroupRuntimeError::TaskBookkeeping)?;
        match joined {
            Ok((task_id, completion)) => {
                let expected = task_groups
                    .remove(&task_id)
                    .ok_or(GroupRuntimeError::TaskBookkeeping)?;
                if expected != completion.group_id {
                    return Err(GroupRuntimeError::TaskBookkeeping);
                }
                finish_completed_task(&mut scheduler, completion, &mut retained_results)?;
            }
            Err(join_error) => {
                let group_id = task_groups
                    .remove(&join_error.id())
                    .ok_or(GroupRuntimeError::TaskBookkeeping)?;
                scheduler.finish_group(
                    &group_id,
                    GroupRunOutcome::Failed(GroupFailureReason::RuntimeFailure),
                )?;
            }
        }
    }

    retained_results.sort_by_key(|result| result.priority_position);
    Ok(GroupRuntimeReport {
        schedule: scheduler.snapshot(),
        stop_reason,
        retained_results,
    })
}

/// Decide whether the scheduler may dispatch more queued groups this
/// iteration, re-evaluating shared capacity fresh every call rather than
/// latching a stale verdict.
///
/// Cancellation is a one-way, permanent stop. A momentary capacity shortfall
/// is not: outstanding (not yet settled) reservations from groups already in
/// flight can free up real capacity once those groups finish, so a shortfall
/// only becomes terminal once nothing is left running to free more of it.
fn dispatch_may_proceed<B: GroupDispatchBudget>(
    scheduler: &mut GroupScheduler,
    cancellation: &CancellationToken,
    budget: &B,
    stop_reason: &mut Option<GroupRuntimeStopReason>,
) -> bool {
    if matches!(
        stop_reason,
        Some(GroupRuntimeStopReason::CancellationRequested)
    ) {
        return false;
    }
    if cancellation.is_cancelled() {
        *stop_reason = Some(GroupRuntimeStopReason::CancellationRequested);
        scheduler.request_cancellation();
        return false;
    }
    if budget.has_dispatch_capacity() {
        return true;
    }
    if scheduler.running_groups() == 0 && scheduler.queued_groups() > 0 {
        *stop_reason = Some(GroupRuntimeStopReason::BudgetExhausted);
        scheduler.request_cancellation();
    }
    false
}

fn dispatch_ready<R, W, WorkerFuture>(
    scheduler: &mut GroupScheduler,
    tasks: &mut JoinSet<CompletedTask<R>>,
    task_groups: &mut HashMap<TaskId, ReviewGroupId>,
    worker: &Arc<W>,
    cancellation: &CancellationToken,
) where
    R: Send + 'static,
    W: Fn(ScheduledReviewGroup, CancellationToken) -> WorkerFuture + Send + Sync + 'static,
    WorkerFuture: Future<Output = GroupWorkerResult<R>> + Send + 'static,
{
    for scheduled in scheduler.dispatch_ready() {
        let group_id = scheduled.group.id.clone();
        let task_group_id = group_id.clone();
        let priority_position = scheduled.priority_position;
        let worker = Arc::clone(worker);
        let cancellation = cancellation.clone();
        let handle = tasks.spawn(async move {
            CompletedTask {
                group_id,
                priority_position,
                result: worker(scheduled, cancellation).await,
            }
        });
        task_groups.insert(handle.id(), task_group_id);
    }
}

fn finish_completed_task<R>(
    scheduler: &mut GroupScheduler,
    completion: CompletedTask<R>,
    retained_results: &mut Vec<RetainedGroupResult<R>>,
) -> Result<(), GroupRuntimeError> {
    let CompletedTask {
        group_id,
        priority_position,
        result,
    } = completion;
    match result {
        GroupWorkerResult::Complete(result) => {
            scheduler.finish_group(&group_id, GroupRunOutcome::Complete)?;
            retained_results.push(RetainedGroupResult {
                group_id,
                priority_position,
                kind: RetainedGroupResultKind::Complete,
                result,
            });
        }
        GroupWorkerResult::Partial {
            reason,
            verified_result,
        } => {
            scheduler.finish_group(&group_id, GroupRunOutcome::Partial(reason))?;
            if let Some(result) = verified_result {
                retained_results.push(RetainedGroupResult {
                    group_id,
                    priority_position,
                    kind: RetainedGroupResultKind::VerifiedPartial(reason),
                    result,
                });
            }
            // A worker's own reservation losing a race for the last shared
            // capacity does not by itself mean no other group can proceed;
            // the dispatch loop's own capacity check decides that, and only
            // gives up once nothing is left running to free more of it.
        }
        GroupWorkerResult::Failed(reason) => {
            scheduler.finish_group(&group_id, GroupRunOutcome::Failed(reason))?;
        }
        GroupWorkerResult::Cancelled => {
            scheduler.finish_group(&group_id, GroupRunOutcome::Cancelled)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use revoot_core::{
        ChangedPath, FileChangeKind, ProviderCancellationReason, RepositoryPath, ReviewGroup,
        ReviewGroupFile, ReviewGroupLimits, ReviewGroupingSource, ReviewValueTier, Sha256Digest,
    };
    use serde_json::json;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn enforces_real_max_concurrency() {
        let plan = plan((0..8).map(|index| standard_group(index, index)).collect());
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let report = run_group_runtime(&plan, 3, CancellationToken::default(), || true, {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            move |scheduled, _| {
                let active = Arc::clone(&active);
                let maximum = Arc::clone(&maximum);
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    GroupWorkerResult::Complete(scheduled.priority_position)
                }
            }
        })
        .await
        .expect("runtime");
        assert_eq!(maximum.load(Ordering::SeqCst), 3);
        assert_eq!(report.schedule.complete_groups, 8);
        assert_eq!(report.retained_results.len(), 8);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatches_in_stable_high_signal_order() {
        let plan = plan(vec![
            group("low", "z.txt", ReviewValueTier::Low),
            group("standard-z", "z.rs", ReviewValueTier::Standard),
            group("high", "m.rs", ReviewValueTier::High),
            group("standard-a", "a.rs", ReviewValueTier::Standard),
        ]);
        let started = Arc::new(Mutex::new(Vec::new()));
        let report = run_group_runtime(&plan, 1, CancellationToken::default(), || true, {
            let started = Arc::clone(&started);
            move |scheduled, _| {
                let started = Arc::clone(&started);
                async move {
                    started
                        .lock()
                        .expect("started lock")
                        .push(scheduled.group.id.as_str().to_owned());
                    GroupWorkerResult::Complete(scheduled.priority_position)
                }
            }
        })
        .await
        .expect("runtime");
        assert_eq!(
            *started.lock().expect("started lock"),
            ["rg-high", "rg-standard-a", "rg-standard-z", "rg-low"]
        );
        assert_eq!(report.schedule.complete_groups, 4);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_stops_dispatch_and_running_worker_cooperates() {
        let plan = plan((0..4).map(|index| standard_group(index, index)).collect());
        let cancellation = CancellationToken::default();
        let cancel_from_task = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel_from_task.cancel(ProviderCancellationReason::UserRequested);
        });
        let started = Arc::new(AtomicUsize::new(0));
        let report = run_group_runtime(&plan, 1, cancellation, || true, {
            let started = Arc::clone(&started);
            move |_scheduled, cancellation| {
                let started = Arc::clone(&started);
                async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    while !cancellation.is_cancelled() {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    GroupWorkerResult::<u32>::Cancelled
                }
            }
        })
        .await
        .expect("runtime");
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(
            report.stop_reason,
            Some(GroupRuntimeStopReason::CancellationRequested)
        );
        assert_eq!(report.schedule.cancelled_groups, 4);
        assert!(report.retained_results.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn budget_exhaustion_stops_refill_and_retains_verified_partial() {
        let plan = plan((0..4).map(|index| standard_group(index, index)).collect());
        let budget_available = Arc::new(AtomicBool::new(true));
        let started = Arc::new(AtomicUsize::new(0));
        let report: GroupRuntimeReport<u32> = run_group_runtime(
            &plan,
            1,
            CancellationToken::default(),
            {
                let budget_available = Arc::clone(&budget_available);
                move || budget_available.load(Ordering::SeqCst)
            },
            {
                let budget_available = Arc::clone(&budget_available);
                let started = Arc::clone(&started);
                move |scheduled, _| {
                    let budget_available = Arc::clone(&budget_available);
                    let started = Arc::clone(&started);
                    async move {
                        started.fetch_add(1, Ordering::SeqCst);
                        budget_available.store(false, Ordering::SeqCst);
                        GroupWorkerResult::Partial {
                            reason: GroupPartialReason::BudgetExhausted,
                            verified_result: Some(scheduled.priority_position),
                        }
                    }
                }
            },
        )
        .await
        .expect("runtime");
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(
            report.stop_reason,
            Some(GroupRuntimeStopReason::BudgetExhausted)
        );
        assert_eq!(report.schedule.partial_groups, 1);
        assert_eq!(report.schedule.cancelled_groups, 3);
        assert_eq!(report.retained_results.len(), 1);
        assert_eq!(
            report.retained_results[0].kind,
            RetainedGroupResultKind::VerifiedPartial(GroupPartialReason::BudgetExhausted)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn budget_shortfall_pauses_refill_but_lets_running_groups_finish() {
        let plan = plan((0..3).map(|index| standard_group(index, index)).collect());
        let budget_available = Arc::new(AtomicBool::new(true));
        // Whichever of the two concurrently dispatched groups is polled
        // first (dispatch order is the scheduler's own high-signal order,
        // not necessarily plan order) reports the shortfall immediately; the
        // other keeps running past that report and must be allowed to finish.
        let shortfall_claimed = Arc::new(AtomicBool::new(false));
        let report: GroupRuntimeReport<u32> = run_group_runtime(
            &plan,
            2,
            CancellationToken::default(),
            {
                let budget_available = Arc::clone(&budget_available);
                move || budget_available.load(Ordering::SeqCst)
            },
            {
                let budget_available = Arc::clone(&budget_available);
                let shortfall_claimed = Arc::clone(&shortfall_claimed);
                move |scheduled, _| {
                    let budget_available = Arc::clone(&budget_available);
                    let shortfall_claimed = Arc::clone(&shortfall_claimed);
                    async move {
                        if shortfall_claimed
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            budget_available.store(false, Ordering::SeqCst);
                            return GroupWorkerResult::Partial {
                                reason: GroupPartialReason::BudgetExhausted,
                                verified_result: Some(scheduled.priority_position),
                            };
                        }
                        // Outlives the shortfall report; must not be
                        // preemptively cancelled by that alone.
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        GroupWorkerResult::Complete(scheduled.priority_position)
                    }
                }
            },
        )
        .await
        .expect("runtime");
        assert_eq!(
            report.stop_reason,
            Some(GroupRuntimeStopReason::BudgetExhausted)
        );
        assert_eq!(report.schedule.cancelled_groups, 1);
        assert_eq!(report.retained_results.len(), 2);
        assert!(
            report
                .retained_results
                .iter()
                .any(|result| result.kind == RetainedGroupResultKind::Complete),
            "the group that outlived the shortfall report must still be retained"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reduction_is_priority_ordered_despite_completion_order() {
        let plan = plan((0..3).map(|index| standard_group(index, index)).collect());
        let report = run_group_runtime(
            &plan,
            3,
            CancellationToken::default(),
            || true,
            |scheduled, _| async move {
                let delay = 4_u64.saturating_sub(u64::from(scheduled.priority_position));
                tokio::time::sleep(Duration::from_millis(delay * 5)).await;
                GroupWorkerResult::Complete(scheduled.group.id.as_str().to_owned())
            },
        )
        .await
        .expect("runtime");
        assert_eq!(
            report
                .retained_results
                .iter()
                .map(|result| result.priority_position)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(
            report
                .retained_results
                .iter()
                .map(|result| result.result.as_str())
                .collect::<Vec<_>>(),
            ["rg-0", "rg-1", "rg-2"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_work_is_recorded_without_retaining_a_result() {
        let plan = plan(vec![standard_group(0, 0)]);
        let report = run_group_runtime(
            &plan,
            1,
            CancellationToken::default(),
            || true,
            |_scheduled, _| async {
                GroupWorkerResult::<u32>::Failed(GroupFailureReason::ProviderFailed)
            },
        )
        .await
        .expect("runtime");
        assert_eq!(report.schedule.failed_groups, 1);
        assert!(report.retained_results.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn worker_panic_becomes_a_payload_free_group_failure() {
        let plan = plan(vec![standard_group(0, 0)]);
        let report: GroupRuntimeReport<u32> = run_group_runtime(
            &plan,
            1,
            CancellationToken::default(),
            || true,
            |_scheduled, _| async { panic!("private worker payload") },
        )
        .await
        .expect("runtime survives worker panic");
        assert_eq!(report.schedule.failed_groups, 1);
        assert!(report.retained_results.is_empty());
        assert_eq!(
            report.schedule.records[0].status,
            crate::group_scheduler::GroupScheduleStatus::Failed(GroupFailureReason::RuntimeFailure)
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

    fn standard_group(id: usize, order: usize) -> ReviewGroup {
        group(
            &id.to_string(),
            &format!("{order:03}.rs"),
            ReviewValueTier::Standard,
        )
    }

    fn group(id: &str, path: &str, tier: ReviewValueTier) -> ReviewGroup {
        let repository_path = RepositoryPath::try_from(path.to_owned()).expect("path");
        ReviewGroup {
            id: serde_json::from_value(json!(format!("rg-{id}"))).expect("group ID"),
            input_bytes: 1,
            anchor_count: 0,
            files: vec![ReviewGroupFile {
                path: ChangedPath {
                    old_path: repository_path.clone(),
                    new_path: repository_path,
                    kind: FileChangeKind::Modified,
                },
                tier,
                input_bytes: 1,
                anchor_ids: Vec::new(),
                work_unit_id: serde_json::from_value(json!(format!("wu-{id}")))
                    .expect("work unit ID"),
            }],
        }
    }
}
