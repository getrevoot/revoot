//! Convergent GitLab publication controller behind an explicit readiness gate.
//!
//! The accepted authorization is issued only by GitLab CI readiness after
//! authentication, checkout binding, provider readiness, and fork policy are
//! evaluated. The transport can only replace Revoot's bounded overview block,
//! create Revoot comments, or resolve exact Revoot-owned discussions selected
//! from a complete inventory; freshness and reconciliation are controller-owned
//! prerequisites.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use revoot_core::{
    AnchorPosition, AnchorTable, GitLabMergeRequestState, GitLabPage, GitLabSnapshotIdentity,
    GitLabWireError, GitLabWireLimits, MergeRequestIid, ProjectId, PublicationAction,
    PublicationCandidate, PublicationDecision, PublicationInventory, PublicationJournal,
    PublicationJournalError, PublicationJournalState, PublicationPlanError,
    PublicationReconciliation, PublicationTarget, Sha256Digest, SnapshotBinding,
    ValidatedDiffVersion, bind_latest_snapshot, collect_complete_pages,
    collect_discussion_inventory, finding_lineage_id, parse_created_discussion_response,
    parse_created_note_response, parse_diff_versions_page, parse_discussion_resolution_response,
    parse_discussions_page, parse_merge_request_response,
};
use serde::Deserialize;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::time::{Instant, sleep, timeout_at};

#[cfg(test)]
use revoot_core::build_publication_plan;

use crate::gitlab_incremental::{GitLabDiscussionResolution, build_incremental_publication_plan};
use crate::gitlab_transport::{
    GitLabFailureKind, GitLabPagination, GitLabReadClient, GitLabReadEndpoint, GitLabTextPosition,
    GitLabTransportError, GitLabWriteClient, GitLabWriteEndpoint, GitLabWriteFailureEffect,
};
use crate::retry::{RetryJitter, RetryPolicy};
use crate::review_overview::update_description;

const HARD_MAX_REQUESTS: u32 = 100_000;
const HARD_MAX_ATTEMPTS: u8 = 16;
const HARD_MAX_TIMEOUT: Duration = Duration::from_hours(1);
const HARD_MAX_DELAY: Duration = Duration::from_mins(5);
const HARD_MAX_LOCK_KEYS: usize = 1_024;

/// Consumed publication authorization issued by GitLab readiness.
#[derive(Debug, Default)]
pub struct GitLabPublicationAuthorization {
    accepted: bool,
}

impl GitLabPublicationAuthorization {
    pub(crate) const fn accepted() -> Self {
        Self { accepted: true }
    }

    #[cfg(test)]
    fn accepted_for_test() -> Self {
        Self::accepted()
    }
}

/// Controller-wide bounds for pagination, retries, and elapsed work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLabPublicationLimits {
    pub wire: GitLabWireLimits,
    pub per_page: u32,
    pub max_total_requests: u32,
    pub max_read_attempts: u8,
    pub max_write_attempts: u8,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_retry_after: Duration,
    pub operation_timeout: Duration,
}

impl Default for GitLabPublicationLimits {
    fn default() -> Self {
        Self {
            wire: GitLabWireLimits::default(),
            per_page: 100,
            max_total_requests: 10_000,
            max_read_attempts: 3,
            max_write_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(30),
            operation_timeout: Duration::from_mins(10),
        }
    }
}

/// Invalid configuration is rejected before authorization or network work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitLabPublicationBuildError {
    InvalidLimits,
}

/// Counters describing publication work without retaining response payloads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitLabPublicationEvidence {
    pub requests_started: u32,
    pub inventory_pages: u32,
    pub freshness_checks: u32,
    pub mutation_attempts: u32,
    pub read_retry_attempts: u32,
    pub write_retry_attempts: u32,
    pub ambiguous_results: u32,
    pub reconciliations: u32,
    pub resolved_discussions: u32,
    pub reopened_discussions: u32,
    pub overview_confirmed: u32,
}

/// Redaction-safe terminal reason. It contains no URL, body, path, SHA, token,
/// or arbitrary response header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitLabPublicationFailure {
    GateClosed,
    ConcurrentLimit,
    Deadline,
    RequestLimit,
    Endpoint,
    Transport {
        kind: GitLabFailureKind,
        status: Option<u16>,
    },
    Wire(GitLabWireError),
    Plan(PublicationPlanError),
    Journal(PublicationJournalError),
    SnapshotMismatch,
    AnchorMissing,
    RetryExhausted,
    Overview,
}

/// Honest terminal result, retaining an exact journal for partial publication.
#[derive(Clone, Eq, PartialEq)]
pub enum GitLabPublicationOutcome {
    GateClosed {
        evidence: GitLabPublicationEvidence,
    },
    Completed {
        journal: PublicationJournal,
        evidence: GitLabPublicationEvidence,
    },
    Stopped {
        journal: Option<PublicationJournal>,
        failure: GitLabPublicationFailure,
        evidence: GitLabPublicationEvidence,
    },
}

impl fmt::Debug for GitLabPublicationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GateClosed { evidence } => formatter
                .debug_struct("GateClosed")
                .field("evidence", evidence)
                .finish(),
            Self::Completed { journal, evidence } => formatter
                .debug_struct("Completed")
                .field("journal_state", &journal.state)
                .field("completed_actions", &journal.entries.len())
                .field("evidence", evidence)
                .finish(),
            Self::Stopped {
                journal,
                failure,
                evidence,
            } => formatter
                .debug_struct("Stopped")
                .field("journal_state", &journal.as_ref().map(|value| value.state))
                .field(
                    "completed_actions",
                    &journal.as_ref().map_or(0, |value| value.entries.len()),
                )
                .field("failure", failure)
                .field("evidence", evidence)
                .finish(),
        }
    }
}

/// Publication controller. It owns no credentials and cannot mutate without a
/// consumed authorization value issued by the readiness controller.
pub struct GitLabPublicationController<'client> {
    read: &'client GitLabReadClient,
    write: &'client GitLabWriteClient,
    limits: GitLabPublicationLimits,
}

impl<'client> GitLabPublicationController<'client> {
    /// Construct a readiness-gated publication controller with bounded limits.
    ///
    /// # Errors
    ///
    /// Rejects invalid wire, pagination, request, retry, backoff, or deadline
    /// limits before any network work.
    pub fn new(
        read: &'client GitLabReadClient,
        write: &'client GitLabWriteClient,
        limits: GitLabPublicationLimits,
    ) -> Result<Self, GitLabPublicationBuildError> {
        if limits.wire.validate().is_err()
            || limits.per_page == 0
            || limits.per_page > 100
            || limits.per_page > limits.wire.max_items_per_page
            || limits.max_total_requests == 0
            || limits.max_total_requests > HARD_MAX_REQUESTS
            || limits.max_read_attempts == 0
            || limits.max_read_attempts > HARD_MAX_ATTEMPTS
            || limits.max_write_attempts == 0
            || limits.max_write_attempts > HARD_MAX_ATTEMPTS
            || limits.initial_backoff.is_zero()
            || limits.initial_backoff > limits.max_backoff
            || limits.max_backoff > HARD_MAX_DELAY
            || limits.max_retry_after.is_zero()
            || limits.max_retry_after > HARD_MAX_DELAY
            || limits.operation_timeout.is_zero()
            || limits.operation_timeout > HARD_MAX_TIMEOUT
        {
            return Err(GitLabPublicationBuildError::InvalidLimits);
        }
        Ok(Self {
            read,
            write,
            limits,
        })
    }

    /// Execute a deterministic overview/create/no-op/resolve plan. Authorization
    /// is consumed and checked before locks, inventory reads, or any network effect.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish(
        &self,
        authorization: GitLabPublicationAuthorization,
        snapshot: GitLabSnapshotIdentity,
        anchors: &AnchorTable,
        bot_user_id: u64,
        overview_block: Option<&str>,
        candidates: impl IntoIterator<Item = PublicationCandidate>,
        fixed_lineages: &BTreeSet<Sha256Digest>,
    ) -> GitLabPublicationOutcome {
        let mut run = PublicationRun::new(self, Instant::now() + self.limits.operation_timeout);
        if !authorization.accepted {
            return GitLabPublicationOutcome::GateClosed {
                evidence: run.evidence,
            };
        }
        if anchors.identity() != &snapshot {
            return run.stopped(None, GitLabPublicationFailure::SnapshotMismatch);
        }
        let scope = &snapshot.version.scope;
        let read_origin = Sha256Digest::of_bytes(self.read.origin().as_str().as_bytes());
        let write_origin = Sha256Digest::of_bytes(self.write.origin().as_str().as_bytes());
        if read_origin != scope.instance_origin_digest
            || write_origin != scope.instance_origin_digest
        {
            return run.stopped(None, GitLabPublicationFailure::SnapshotMismatch);
        }
        let lease = match PublicationLease::acquire(
            LockKey {
                origin: scope.instance_origin_digest.clone(),
                project: scope.project_id,
                merge_request: scope.merge_request_iid,
            },
            run.deadline,
        )
        .await
        {
            Ok(lease) => lease,
            Err(failure) => return run.stopped(None, failure),
        };
        let inventory = match run
            .inventory(scope.project_id, scope.merge_request_iid)
            .await
        {
            Ok(inventory) => inventory,
            Err(failure) => return run.stopped(None, failure),
        };
        let candidates = candidates.into_iter().collect::<Vec<_>>();
        let (planning_inventory, reanchored) =
            inventory_for_current_anchors(anchors, bot_user_id, &candidates, &inventory);
        let incremental = match build_incremental_publication_plan(
            snapshot.clone(),
            bot_user_id,
            candidates,
            &planning_inventory,
            fixed_lineages,
        ) {
            Ok(plan) => plan,
            Err(error) => return run.stopped(None, GitLabPublicationFailure::Plan(error)),
        };
        let mut resolutions = incremental.stale_discussions;
        resolutions.extend(incremental.superseded_discussions);
        resolutions.extend(reanchored);
        resolutions.sort_unstable();
        resolutions.dedup();
        let reopens = incremental.reopened_discussions;
        let plan = incremental.publication;
        let Ok(journal) = PublicationJournal::try_new(&plan) else {
            return run.stopped(None, GitLabPublicationFailure::SnapshotMismatch);
        };
        run.execute(
            snapshot,
            anchors,
            bot_user_id,
            journal,
            resolutions,
            reopens,
            overview_block,
            lease,
        )
        .await
    }
}

fn inventory_for_current_anchors(
    anchors: &AnchorTable,
    bot_user_id: u64,
    candidates: &[PublicationCandidate],
    inventory: &PublicationInventory,
) -> (PublicationInventory, Vec<GitLabDiscussionResolution>) {
    let current = candidates
        .iter()
        .filter_map(|candidate| {
            let lineage = finding_lineage_id(&candidate.body)?;
            let PublicationTarget::Inline(anchor_id) = &candidate.target else {
                return None;
            };
            let anchor = anchors.resolve(anchor_id.as_str())?;
            let (path, line) = match anchor.position {
                AnchorPosition::Deletion { old_line } => {
                    (anchor.path.old_path.as_str().to_owned(), old_line)
                }
                AnchorPosition::Addition { new_line }
                | AnchorPosition::Context { new_line, .. } => {
                    (anchor.path.new_path.as_str().to_owned(), new_line)
                }
            };
            Some((lineage, (path, line)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut reanchored = Vec::new();
    let mut planning = inventory.clone();
    planning.notes.retain(|note| {
        if note.author_user_id != bot_user_id {
            return true;
        }
        let Some(lineage) = finding_lineage_id(&note.body) else {
            return true;
        };
        let Some((path, line)) = current.get(&lineage) else {
            return true;
        };
        if note.path.is_none() || note.line.is_none() {
            return true;
        }
        if note.path.as_ref() == Some(path) && note.line == Some(*line) {
            return true;
        }
        if note.resolved && note.resolved_by_user_id != Some(bot_user_id) {
            return true;
        }
        if !note.resolved
            && let Some(discussion_id) = &note.discussion_id
            && note.resolvable
        {
            reanchored.push(GitLabDiscussionResolution {
                discussion_id: discussion_id.clone(),
                note_id: note.note_id,
            });
        }
        false
    });
    reanchored.sort_unstable();
    (planning, reanchored)
}

enum CreateResult {
    Created(u64),
    Ambiguous { retryable: bool },
}

struct PublicationRun<'controller, 'client> {
    controller: &'controller GitLabPublicationController<'client>,
    deadline: Instant,
    evidence: GitLabPublicationEvidence,
    action_attempts: u8,
    action_fingerprint: Option<Sha256Digest>,
}

impl<'controller, 'client> PublicationRun<'controller, 'client> {
    fn new(
        controller: &'controller GitLabPublicationController<'client>,
        deadline: Instant,
    ) -> Self {
        Self {
            controller,
            deadline,
            evidence: GitLabPublicationEvidence::default(),
            action_attempts: 0,
            action_fingerprint: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &mut self,
        snapshot: GitLabSnapshotIdentity,
        anchors: &AnchorTable,
        bot_user_id: u64,
        mut journal: PublicationJournal,
        resolutions: Vec<GitLabDiscussionResolution>,
        reopens: Vec<GitLabDiscussionResolution>,
        overview_block: Option<&str>,
        _lease: PublicationLease,
    ) -> GitLabPublicationOutcome {
        while !matches!(journal.state, PublicationJournalState::Completed) {
            if let Err(failure) = self.refresh_before_action(&snapshot, &mut journal).await {
                return self.stopped(Some(journal), failure);
            }
            let action = match journal.begin_next(&snapshot) {
                Ok(action) => action.clone(),
                Err(error) => {
                    return self.stopped(Some(journal), GitLabPublicationFailure::Journal(error));
                }
            };
            if let Err(failure) = self
                .execute_action(&snapshot, anchors, bot_user_id, &action, &mut journal)
                .await
            {
                return self.stopped(Some(journal), failure);
            }
        }
        for resolution in &resolutions {
            if let Err(failure) = self
                .set_discussion_resolved(&snapshot, bot_user_id, resolution, true)
                .await
            {
                return self.stopped(Some(journal), failure);
            }
        }
        for reopen in &reopens {
            if let Err(failure) = self
                .set_discussion_resolved(&snapshot, bot_user_id, reopen, false)
                .await
            {
                return self.stopped(Some(journal), failure);
            }
        }
        if let Some(overview_block) = overview_block
            && let Err(failure) = self.update_overview(&snapshot, overview_block).await
        {
            return self.stopped(Some(journal), failure);
        }
        GitLabPublicationOutcome::Completed {
            journal,
            evidence: self.evidence,
        }
    }

    async fn set_discussion_resolved(
        &mut self,
        snapshot: &GitLabSnapshotIdentity,
        bot_user_id: u64,
        resolution: &GitLabDiscussionResolution,
        resolved: bool,
    ) -> Result<(), GitLabPublicationFailure> {
        if !self.fresh(snapshot).await? {
            return Err(GitLabPublicationFailure::SnapshotMismatch);
        }
        let scope = &snapshot.version.scope;
        let endpoint = GitLabWriteEndpoint::SetDiscussionResolved {
            project_id: scope.project_id,
            merge_request_iid: scope.merge_request_iid,
            discussion_id: &resolution.discussion_id,
            resolved,
        };
        for attempt in 1..=self.controller.limits.max_write_attempts {
            self.reserve()?;
            self.evidence.mutation_attempts = self.evidence.mutation_attempts.saturating_add(1);
            let sent = timeout_at(self.deadline, self.controller.write.mutate(&endpoint)).await;
            if let Ok(Ok(response)) = &sent
                && parse_discussion_resolution_response(
                    &response.observation,
                    &resolution.discussion_id,
                    resolution.note_id,
                    bot_user_id,
                    resolved,
                    self.controller.limits.wire,
                )
                .is_ok()
            {
                self.record_resolution_change(resolved);
                return Ok(());
            }
            let non_retryable = match &sent {
                Ok(Err(error)) if !error.retryable_after_reconciliation => {
                    Some((error.kind, error.status))
                }
                _ => None,
            };
            let inventory = self
                .inventory(scope.project_id, scope.merge_request_iid)
                .await?;
            self.evidence.reconciliations = self.evidence.reconciliations.saturating_add(1);
            if inventory.notes.iter().any(|note| {
                note.note_id == resolution.note_id
                    && note.author_user_id == bot_user_id
                    && note.discussion_id.as_deref() == Some(resolution.discussion_id.as_str())
                    && note.resolved == resolved
            }) {
                self.record_resolution_change(resolved);
                return Ok(());
            }
            if let Some((kind, status)) = non_retryable {
                return Err(GitLabPublicationFailure::Transport { kind, status });
            }
            if attempt == self.controller.limits.max_write_attempts {
                return Err(GitLabPublicationFailure::RetryExhausted);
            }
            self.evidence.write_retry_attempts =
                self.evidence.write_retry_attempts.saturating_add(1);
            self.backoff(None).await?;
        }
        Err(GitLabPublicationFailure::RetryExhausted)
    }

    fn record_resolution_change(&mut self, resolved: bool) {
        if resolved {
            self.evidence.resolved_discussions =
                self.evidence.resolved_discussions.saturating_add(1);
        } else {
            self.evidence.reopened_discussions =
                self.evidence.reopened_discussions.saturating_add(1);
        }
    }

    async fn refresh_before_action(
        &mut self,
        snapshot: &GitLabSnapshotIdentity,
        journal: &mut PublicationJournal,
    ) -> Result<(), GitLabPublicationFailure> {
        match self.fresh(snapshot).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                journal
                    .stop_stale()
                    .map_err(GitLabPublicationFailure::Journal)?;
                Err(GitLabPublicationFailure::SnapshotMismatch)
            }
            Err(failure) => {
                let _ = journal.fail();
                Err(failure)
            }
        }
    }

    async fn execute_action(
        &mut self,
        snapshot: &GitLabSnapshotIdentity,
        anchors: &AnchorTable,
        bot_user_id: u64,
        action: &PublicationAction,
        journal: &mut PublicationJournal,
    ) -> Result<(), GitLabPublicationFailure> {
        match action.decision {
            PublicationDecision::NoOp { existing_note_id } => journal
                .confirm(existing_note_id)
                .map_err(GitLabPublicationFailure::Journal),
            PublicationDecision::Create => {
                match self
                    .create(snapshot, anchors, bot_user_id, &action.publication)
                    .await
                {
                    Ok(CreateResult::Created(note_id)) => journal
                        .confirm(note_id)
                        .map_err(GitLabPublicationFailure::Journal),
                    Ok(CreateResult::Ambiguous { retryable }) => {
                        self.reconcile_ambiguous(snapshot, journal, retryable).await
                    }
                    Err(failure) => {
                        let _ = journal.fail();
                        Err(failure)
                    }
                }
            }
        }
    }

    async fn reconcile_ambiguous(
        &mut self,
        snapshot: &GitLabSnapshotIdentity,
        journal: &mut PublicationJournal,
        retryable: bool,
    ) -> Result<(), GitLabPublicationFailure> {
        journal
            .mark_ambiguous()
            .map_err(GitLabPublicationFailure::Journal)?;
        let scope = &snapshot.version.scope;
        let inventory = self
            .inventory(scope.project_id, scope.merge_request_iid)
            .await?;
        self.evidence.reconciliations = self.evidence.reconciliations.saturating_add(1);
        match journal.reconcile_ambiguous(&inventory) {
            Ok(PublicationReconciliation::Recovered { .. }) => Ok(()),
            Ok(PublicationReconciliation::RetryAuthorized) if retryable => {
                if self.action_attempts >= self.controller.limits.max_write_attempts {
                    let _ = journal.fail();
                    return Err(GitLabPublicationFailure::RetryExhausted);
                }
                self.evidence.write_retry_attempts =
                    self.evidence.write_retry_attempts.saturating_add(1);
                if let Err(failure) = self.backoff(None).await {
                    let _ = journal.fail();
                    return Err(failure);
                }
                Ok(())
            }
            Ok(PublicationReconciliation::RetryAuthorized) => {
                let _ = journal.fail();
                Err(GitLabPublicationFailure::RetryExhausted)
            }
            Err(error) => Err(GitLabPublicationFailure::Journal(error)),
        }
    }

    fn stopped(
        &self,
        journal: Option<PublicationJournal>,
        failure: GitLabPublicationFailure,
    ) -> GitLabPublicationOutcome {
        GitLabPublicationOutcome::Stopped {
            journal,
            failure,
            evidence: self.evidence,
        }
    }

    async fn request(
        &mut self,
        endpoint: &GitLabReadEndpoint,
    ) -> Result<revoot_core::GitLabResponseObservation, GitLabPublicationFailure> {
        for attempt in 1..=self.controller.limits.max_read_attempts {
            self.reserve()?;
            let result = timeout_at(self.deadline, self.controller.read.get(endpoint))
                .await
                .map_err(|_| GitLabPublicationFailure::Deadline)?;
            match result {
                Ok(response) => return Ok(response.into_observation()),
                Err(error)
                    if error.retry().eligible_read
                        && attempt < self.controller.limits.max_read_attempts =>
                {
                    self.evidence.read_retry_attempts =
                        self.evidence.read_retry_attempts.saturating_add(1);
                    let after = error.retry().after_seconds.map(Duration::from_secs);
                    self.backoff(after).await?;
                }
                Err(error) => return Err(transport_failure(&error)),
            }
        }
        Err(GitLabPublicationFailure::RetryExhausted)
    }

    async fn update_overview(
        &mut self,
        snapshot: &GitLabSnapshotIdentity,
        overview_block: &str,
    ) -> Result<(), GitLabPublicationFailure> {
        let scope = &snapshot.version.scope;
        let observation = self
            .request(&GitLabReadEndpoint::MergeRequest {
                project_id: scope.project_id,
                merge_request_iid: scope.merge_request_iid,
            })
            .await?;
        let current: MergeRequestDescription = serde_json::from_slice(&observation.body)
            .map_err(|_| GitLabPublicationFailure::Overview)?;
        if current.project_id != scope.project_id.get()
            || current.iid != scope.merge_request_iid.get()
            || current.state != "opened"
            || current.sha != snapshot.version.diff_version.refs.head_sha.as_str()
        {
            return Err(GitLabPublicationFailure::SnapshotMismatch);
        }
        let description = current.description.as_deref().unwrap_or_default();
        let updated = update_description(description, overview_block)
            .map_err(|_| GitLabPublicationFailure::Overview)?;
        if updated == description {
            self.evidence.overview_confirmed = self.evidence.overview_confirmed.saturating_add(1);
            return Ok(());
        }
        self.reserve()?;
        self.evidence.mutation_attempts = self.evidence.mutation_attempts.saturating_add(1);
        let endpoint = GitLabWriteEndpoint::UpdateMergeRequestDescription {
            project_id: scope.project_id,
            merge_request_iid: scope.merge_request_iid,
            description: &updated,
        };
        let response = timeout_at(self.deadline, self.controller.write.mutate(&endpoint))
            .await
            .map_err(|_| GitLabPublicationFailure::Overview)?
            .map_err(|error| GitLabPublicationFailure::Transport {
                kind: error.kind,
                status: error.status,
            })?;
        let observed: MergeRequestDescription = serde_json::from_slice(&response.observation.body)
            .map_err(|_| GitLabPublicationFailure::Overview)?;
        if observed.project_id != scope.project_id.get()
            || observed.iid != scope.merge_request_iid.get()
            || observed.state != "opened"
            || observed.sha != snapshot.version.diff_version.refs.head_sha.as_str()
            || observed.description.as_deref() != Some(updated.as_str())
        {
            return Err(GitLabPublicationFailure::Overview);
        }
        self.evidence.overview_confirmed = self.evidence.overview_confirmed.saturating_add(1);
        Ok(())
    }

    async fn inventory(
        &mut self,
        project: ProjectId,
        iid: MergeRequestIid,
    ) -> Result<PublicationInventory, GitLabPublicationFailure> {
        let mut pages = Vec::new();
        let mut requested = 1_u32;
        loop {
            let pagination = GitLabPagination::new(requested, self.controller.limits.per_page)
                .map_err(|_| GitLabPublicationFailure::Endpoint)?;
            let observation = self
                .request(&GitLabReadEndpoint::Discussions {
                    project_id: project,
                    merge_request_iid: iid,
                    pagination,
                })
                .await?;
            let page = parse_discussions_page(
                &observation,
                requested,
                self.controller.limits.per_page,
                self.controller.limits.wire,
            )
            .map_err(GitLabPublicationFailure::Wire)?;
            self.evidence.inventory_pages = self.evidence.inventory_pages.saturating_add(1);
            let next = page.metadata.next_page;
            pages.push(page);
            match next {
                Some(value) if value > requested => requested = value,
                Some(_) => {
                    return Err(GitLabPublicationFailure::Wire(
                        GitLabWireError::PaginationCycle,
                    ));
                }
                None => break,
            }
        }
        collect_discussion_inventory(pages, self.controller.limits.wire)
            .map_err(GitLabPublicationFailure::Wire)
    }

    async fn fresh(
        &mut self,
        expected: &GitLabSnapshotIdentity,
    ) -> Result<bool, GitLabPublicationFailure> {
        self.evidence.freshness_checks = self.evidence.freshness_checks.saturating_add(1);
        let scope = &expected.version.scope;
        let observation = self
            .request(&GitLabReadEndpoint::MergeRequest {
                project_id: scope.project_id,
                merge_request_iid: scope.merge_request_iid,
            })
            .await?;
        let mr = parse_merge_request_response(&observation, self.controller.limits.wire)
            .map_err(GitLabPublicationFailure::Wire)?;
        if mr.project_id != scope.project_id
            || mr.iid != scope.merge_request_iid
            || mr.state != GitLabMergeRequestState::Opened
            || mr.diff_refs.as_ref() != Some(&expected.version.diff_version.refs)
            || mr.head_sha != expected.version.diff_version.refs.head_sha
        {
            return Ok(false);
        }
        let mut pages: Vec<GitLabPage<ValidatedDiffVersion>> = Vec::new();
        let mut requested = 1_u32;
        loop {
            let pagination = GitLabPagination::new(requested, self.controller.limits.per_page)
                .map_err(|_| GitLabPublicationFailure::Endpoint)?;
            let observation = self
                .request(&GitLabReadEndpoint::DiffVersions {
                    project_id: scope.project_id,
                    merge_request_iid: scope.merge_request_iid,
                    pagination,
                })
                .await?;
            let page = parse_diff_versions_page(
                &observation,
                requested,
                self.controller.limits.per_page,
                self.controller.limits.wire,
            )
            .map_err(GitLabPublicationFailure::Wire)?;
            let next = page.metadata.next_page;
            pages.push(page);
            match next {
                Some(value) if value > requested => requested = value,
                Some(_) => {
                    return Err(GitLabPublicationFailure::Wire(
                        GitLabWireError::PaginationCycle,
                    ));
                }
                None => break,
            }
        }
        let versions = collect_complete_pages(pages, self.controller.limits.wire)
            .map_err(GitLabPublicationFailure::Wire)?;
        if versions
            .items
            .iter()
            .any(|version| version.merge_request_id != Some(mr.merge_request_id))
        {
            return Ok(false);
        }
        let records = revoot_core::PaginatedAcquisition {
            items: versions
                .items
                .into_iter()
                .map(|version| version.record)
                .collect(),
            pages: versions.pages,
        };
        Ok(matches!(
            bind_latest_snapshot(scope.clone(), mr.diff_refs.as_ref(), &records),
            SnapshotBinding::Bound { identity } if identity == expected.version
        ))
    }

    async fn create(
        &mut self,
        snapshot: &GitLabSnapshotIdentity,
        anchors: &AnchorTable,
        bot_user_id: u64,
        publication: &revoot_core::PreparedPublication,
    ) -> Result<CreateResult, GitLabPublicationFailure> {
        if self.action_fingerprint.as_ref() != Some(&publication.marker.fingerprint_sha256) {
            self.action_fingerprint = Some(publication.marker.fingerprint_sha256.clone());
            self.action_attempts = 0;
        }
        self.reserve()?;
        self.action_attempts = self.action_attempts.saturating_add(1);
        self.evidence.mutation_attempts = self.evidence.mutation_attempts.saturating_add(1);
        let scope = &snapshot.version.scope;
        let position;
        let endpoint = match &publication.target {
            PublicationTarget::Inline(anchor_id) => {
                let anchor = anchors
                    .resolve(anchor_id.as_str())
                    .ok_or(GitLabPublicationFailure::AnchorMissing)?;
                let (old_line, new_line) = match anchor.position {
                    AnchorPosition::Addition { new_line } => (None, Some(new_line)),
                    AnchorPosition::Deletion { old_line } => (Some(old_line), None),
                    AnchorPosition::Context { old_line, new_line } => {
                        (Some(old_line), Some(new_line))
                    }
                };
                let refs = &snapshot.version.diff_version.refs;
                position = GitLabTextPosition {
                    position_type: "text",
                    base_sha: refs.base_sha.as_str().to_owned(),
                    start_sha: refs.start_sha.as_str().to_owned(),
                    head_sha: refs.head_sha.as_str().to_owned(),
                    old_path: anchor.path.old_path.as_str().to_owned(),
                    new_path: anchor.path.new_path.as_str().to_owned(),
                    old_line,
                    new_line,
                };
                GitLabWriteEndpoint::Discussion {
                    project_id: scope.project_id,
                    merge_request_iid: scope.merge_request_iid,
                    body: &publication.marked_body,
                    position: &position,
                }
            }
            PublicationTarget::Summary => GitLabWriteEndpoint::SummaryNote {
                project_id: scope.project_id,
                merge_request_iid: scope.merge_request_iid,
                body: &publication.marked_body,
            },
        };
        let Ok(response) = timeout_at(self.deadline, self.controller.write.mutate(&endpoint)).await
        else {
            self.evidence.ambiguous_results = self.evidence.ambiguous_results.saturating_add(1);
            return Ok(CreateResult::Ambiguous { retryable: true });
        };
        match response {
            Ok(response) => {
                let parsed = match publication.target {
                    PublicationTarget::Inline(_) => parse_created_discussion_response(
                        &response.observation,
                        &publication.marked_body,
                        bot_user_id,
                        self.controller.limits.wire,
                    ),
                    PublicationTarget::Summary => parse_created_note_response(
                        &response.observation,
                        &publication.marked_body,
                        bot_user_id,
                        self.controller.limits.wire,
                    ),
                };
                if let Ok(created) = parsed {
                    Ok(CreateResult::Created(created.note_id))
                } else {
                    self.evidence.ambiguous_results =
                        self.evidence.ambiguous_results.saturating_add(1);
                    Ok(CreateResult::Ambiguous { retryable: false })
                }
            }
            Err(error) if error.effect == GitLabWriteFailureEffect::Ambiguous => {
                self.evidence.ambiguous_results = self.evidence.ambiguous_results.saturating_add(1);
                Ok(CreateResult::Ambiguous {
                    retryable: error.retryable_after_reconciliation,
                })
            }
            Err(error) if error.retryable_after_reconciliation => {
                self.evidence.ambiguous_results = self.evidence.ambiguous_results.saturating_add(1);
                Ok(CreateResult::Ambiguous { retryable: true })
            }
            Err(error) => Err(GitLabPublicationFailure::Transport {
                kind: error.kind,
                status: error.status,
            }),
        }
    }

    fn reserve(&mut self) -> Result<(), GitLabPublicationFailure> {
        if Instant::now() >= self.deadline {
            return Err(GitLabPublicationFailure::Deadline);
        }
        if self.evidence.requests_started >= self.controller.limits.max_total_requests {
            return Err(GitLabPublicationFailure::RequestLimit);
        }
        self.evidence.requests_started = self.evidence.requests_started.saturating_add(1);
        Ok(())
    }

    async fn backoff(&self, retry_after: Option<Duration>) -> Result<(), GitLabPublicationFailure> {
        let exponent = self
            .evidence
            .read_retry_attempts
            .saturating_add(self.evidence.write_retry_attempts)
            .min(31);
        let retry_after =
            retry_after.map(|value| value.min(self.controller.limits.max_retry_after));
        let mut jitter = RetryJitter::new(u64::from(exponent).saturating_add(1));
        let delay = RetryPolicy {
            max_attempts: self
                .controller
                .limits
                .max_read_attempts
                .max(self.controller.limits.max_write_attempts),
            initial_delay: self.controller.limits.initial_backoff,
            max_delay: self.controller.limits.max_backoff,
            max_retry_after: self.controller.limits.max_retry_after,
            total_budget: self.deadline.saturating_duration_since(Instant::now()),
        }
        .delay(
            u8::try_from(exponent).unwrap_or(u8::MAX).saturating_add(1),
            retry_after,
            &mut jitter,
        );
        timeout_at(self.deadline, sleep(delay))
            .await
            .map_err(|_| GitLabPublicationFailure::Deadline)
    }
}

#[derive(Deserialize)]
struct MergeRequestDescription {
    project_id: u64,
    iid: u64,
    state: String,
    sha: String,
    #[serde(default)]
    description: Option<String>,
}

fn transport_failure(error: &GitLabTransportError) -> GitLabPublicationFailure {
    GitLabPublicationFailure::Transport {
        kind: error.kind(),
        status: error.status(),
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct LockKey {
    origin: Sha256Digest,
    project: ProjectId,
    merge_request: MergeRequestIid,
}

static PUBLICATION_LOCKS: OnceLock<Mutex<BTreeMap<LockKey, Arc<AsyncMutex<()>>>>> = OnceLock::new();

struct PublicationLease {
    key: LockKey,
    mutex: Arc<AsyncMutex<()>>,
    guard: Option<OwnedMutexGuard<()>>,
}

impl PublicationLease {
    async fn acquire(key: LockKey, deadline: Instant) -> Result<Self, GitLabPublicationFailure> {
        let mutex = {
            let mut locks = PUBLICATION_LOCKS
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .map_err(|_| GitLabPublicationFailure::ConcurrentLimit)?;
            if !locks.contains_key(&key) && locks.len() >= HARD_MAX_LOCK_KEYS {
                return Err(GitLabPublicationFailure::ConcurrentLimit);
            }
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let Ok(guard) = timeout_at(deadline, mutex.clone().lock_owned()).await else {
            cleanup_lock(&key, &mutex);
            return Err(GitLabPublicationFailure::Deadline);
        };
        Ok(Self {
            key,
            mutex,
            guard: Some(guard),
        })
    }
}

impl Drop for PublicationLease {
    fn drop(&mut self) {
        self.guard.take();
        cleanup_lock(&self.key, &self.mutex);
    }
}

fn cleanup_lock(key: &LockKey, mutex: &Arc<AsyncMutex<()>>) {
    if let Ok(mut locks) = PUBLICATION_LOCKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        && Arc::strong_count(mutex) == 2
        && locks
            .get(key)
            .is_some_and(|stored| Arc::ptr_eq(stored, mutex))
    {
        locks.remove(key);
    }
}

impl fmt::Display for GitLabPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitLab publication stopped")
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use revoot_core::{
        AnchorTable, ChangedPath, CommentableLine, DiffRefs, DiffVersionId, DiffVersionRecord,
        ExistingPublicationNote, FileChangeKind, FindingLineageMarker, GitLabDiffVersionIdentity,
        GitLabOrigin, GitLabOriginPolicy, GitLabSnapshotIdentity, GitSha,
        PublicationJournalOutcome, PublicationTarget, RepositoryPath, SnapshotScope,
    };
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as TokioMutex;

    use crate::gitlab_transport::{
        GitLabAccessToken, GitLabCaMode, GitLabTransportConfig, GitLabTransportLimits,
        GitLabWriteAccessToken,
    };

    use super::*;

    enum Reply {
        Json {
            status: &'static str,
            body: Value,
            headers: String,
        },
        Created {
            note_id: u64,
            discussion: bool,
        },
        DropRemember {
            note_id: u64,
        },
        InventoryRemember,
        Resolved {
            discussion_id: String,
            note_id: u64,
            body: String,
        },
        UpdateDescription,
        Hang(Duration),
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let count = stream.read(&mut buffer).await.expect("read request");
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(head_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let head_end = head_end + 4;
                let head = std::str::from_utf8(&request[..head_end]).expect("ASCII request head");
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= head_end + length {
                    break;
                }
            }
        }
        request
    }

    fn request_json(request: &[u8]) -> Value {
        let start = request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("head")
            + 4;
        serde_json::from_slice(&request[start..]).expect("request JSON")
    }

    fn page_headers(page: u32, next: Option<u32>, total: u32, total_pages: u32) -> String {
        page_headers_with_per_page(page, 100, next, total, total_pages)
    }

    fn page_headers_with_per_page(
        page: u32,
        per_page: u32,
        next: Option<u32>,
        total: u32,
        total_pages: u32,
    ) -> String {
        format!(
            "X-Page: {page}\r\nX-Per-Page: {per_page}\r\nX-Prev-Page: {}\r\nX-Next-Page: {}\r\nX-Total: {total}\r\nX-Total-Pages: {total_pages}\r\n",
            if page > 1 {
                (page - 1).to_string()
            } else {
                String::new()
            },
            next.map_or_else(String::new, |value| value.to_string()),
        )
    }

    async fn write_json(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        body: &Value,
        headers: &str,
    ) {
        let bytes = serde_json::to_vec(body).expect("response JSON");
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
            bytes.len(),
        );
        stream.write_all(head.as_bytes()).await.expect("write head");
        stream.write_all(&bytes).await.expect("write body");
    }

    async fn serve_script(
        replies: Vec<Reply>,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            let remembered: Arc<TokioMutex<Option<(u64, String)>>> =
                Arc::new(TokioMutex::new(None));
            for reply in replies {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let request = read_request(&mut stream).await;
                match reply {
                    Reply::Json {
                        status,
                        body,
                        headers,
                    } => write_json(&mut stream, status, &body, &headers).await,
                    Reply::Created {
                        note_id,
                        discussion,
                    } => {
                        let body = request_json(&request)["body"]
                            .as_str()
                            .expect("body")
                            .to_owned();
                        let note = json!({"id": note_id, "type": "DiffNote", "body": body,
                            "author": {"id": 7, "username": "revoot"}, "system": false});
                        let value = if discussion {
                            json!({"id": format!("discussion-{note_id}"), "individual_note": false, "notes": [note]})
                        } else {
                            note
                        };
                        write_json(&mut stream, "201 Created", &value, "").await;
                    }
                    Reply::DropRemember { note_id } => {
                        let body = request_json(&request)["body"]
                            .as_str()
                            .expect("body")
                            .to_owned();
                        *remembered.lock().await = Some((note_id, body));
                    }
                    Reply::InventoryRemember => {
                        let (note_id, body) =
                            remembered.lock().await.clone().expect("remembered create");
                        let value = json!([{"id": "reconciled", "individual_note": false, "notes": [{
                            "id": note_id, "type": "DiffNote", "body": body,
                            "author": {"id": 7, "username": "revoot"}, "system": false
                        }]}]);
                        write_json(&mut stream, "200 OK", &value, &page_headers(1, None, 1, 1))
                            .await;
                    }
                    Reply::Resolved {
                        discussion_id,
                        note_id,
                        body,
                    } => {
                        assert!(request.starts_with(b"PUT "));
                        assert_eq!(request_json(&request)["resolved"], true);
                        let value = json!({
                            "id": discussion_id,
                            "individual_note": false,
                            "notes": [{
                                "id": note_id,
                                "type": "DiffNote",
                                "body": body,
                                "author": {"id": 7, "username": "revoot"},
                                "system": false,
                                "resolvable": true,
                                "resolved": true
                            }]
                        });
                        write_json(&mut stream, "200 OK", &value, "").await;
                    }
                    Reply::UpdateDescription => {
                        assert!(request.starts_with(b"PUT "));
                        assert!(
                            request
                                .starts_with(b"PUT /api/v4/projects/1/merge_requests/2 HTTP/1.1")
                        );
                        let description = request_json(&request)["description"]
                            .as_str()
                            .expect("description")
                            .to_owned();
                        let mut value = mr('d');
                        value["description"] = Value::String(description);
                        write_json(&mut stream, "200 OK", &value, "").await;
                    }
                    Reply::Hang(duration) => sleep(duration).await,
                }
                requests.push(request);
            }
            requests
        });
        (address, task)
    }

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).expect("digest")
    }

    fn sha(marker: char) -> String {
        marker.to_string().repeat(40)
    }

    fn origin() -> GitLabOrigin {
        GitLabOrigin::parse(
            "https://gitlab.example.test",
            &GitLabOriginPolicy::default(),
        )
        .expect("origin")
    }

    fn snapshot() -> GitLabSnapshotIdentity {
        GitLabDiffVersionIdentity {
            scope: SnapshotScope {
                instance_origin_digest: Sha256Digest::of_bytes(origin().as_str().as_bytes()),
                project_id: ProjectId::try_from(1).expect("project"),
                merge_request_iid: MergeRequestIid::try_from(2).expect("iid"),
            },
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(3).expect("version"),
                refs: DiffRefs {
                    base_sha: sha('a').try_into().expect("sha"),
                    start_sha: sha('b').try_into().expect("sha"),
                    head_sha: sha('d').try_into().expect("sha"),
                },
            },
        }
        .freeze(digest('e'))
    }

    fn anchors(snapshot: &GitLabSnapshotIdentity) -> AnchorTable {
        AnchorTable::build(
            snapshot.clone(),
            [CommentableLine {
                path: ChangedPath {
                    old_path: RepositoryPath::try_from("src/lib.rs".to_owned()).expect("path"),
                    new_path: RepositoryPath::try_from("src/lib.rs".to_owned()).expect("path"),
                    kind: FileChangeKind::Modified,
                },
                position: AnchorPosition::addition(4).expect("position"),
                exact_line_digest: digest('1'),
                context_digest: digest('2'),
            }],
        )
        .expect("anchors")
    }

    fn mr(head: char) -> Value {
        json!({
            "id": 99, "iid": 2, "project_id": 1, "source_project_id": 1,
            "target_project_id": 1, "state": "opened", "source_branch": "feature",
            "target_branch": "main", "sha": sha(head), "changes_count": "1",
            "diff_refs": {"base_sha": sha('a'), "start_sha": sha('b'), "head_sha": sha(head)}
        })
    }

    fn versions() -> Value {
        json!([{ "id": 3, "head_commit_sha": sha('d'), "base_commit_sha": sha('a'),
            "start_commit_sha": sha('b'), "state": "collected", "real_size": "1",
            "created_at": "2026-08-24T00:00:00Z", "merge_request_id": 99,
            "patch_id_sha": sha('c') }])
    }

    fn contradictory_versions() -> Value {
        json!([
            { "id": 3, "head_commit_sha": sha('d'), "base_commit_sha": sha('a'),
                "start_commit_sha": sha('b'), "state": "collected", "real_size": "1",
                "created_at": "2026-08-24T00:00:00Z", "merge_request_id": 99,
                "patch_id_sha": sha('c') },
            { "id": 4, "head_commit_sha": sha('d'), "base_commit_sha": sha('a'),
                "start_commit_sha": sha('b'), "state": "collected", "real_size": "1",
                "created_at": "2026-08-24T00:01:00Z", "merge_request_id": 99,
                "patch_id_sha": sha('c') }
        ])
    }

    fn empty_inventory() -> Reply {
        Reply::Json {
            status: "200 OK",
            body: json!([]),
            headers: page_headers(1, None, 0, 1),
        }
    }

    fn fresh_mr() -> Reply {
        Reply::Json {
            status: "200 OK",
            body: mr('d'),
            headers: String::new(),
        }
    }

    fn fresh_versions() -> Reply {
        Reply::Json {
            status: "200 OK",
            body: versions(),
            headers: page_headers(1, None, 1, 1),
        }
    }

    fn clients(address: SocketAddr) -> (GitLabReadClient, GitLabWriteClient) {
        let config = GitLabTransportConfig::new(
            origin(),
            GitLabCaMode::BundledWebPki,
            GitLabTransportLimits::default(),
        );
        let read = GitLabReadClient::new_for_loopback(
            &config,
            GitLabAccessToken::new(b"read-token".to_vec()).expect("read token"),
            address,
        )
        .expect("read client");
        let write = GitLabWriteClient::new_for_loopback(
            &config,
            GitLabWriteAccessToken::new(b"write-token".to_vec()).expect("write token"),
            address,
        )
        .expect("write client");
        (read, write)
    }

    fn inline_candidates(table: &AnchorTable, count: usize) -> Vec<PublicationCandidate> {
        let anchor = table.iter().next().expect("anchor").id.clone();
        (0..count)
            .map(|index| PublicationCandidate {
                target: PublicationTarget::Inline(anchor.clone()),
                body: format!("finding {index}"),
            })
            .collect()
    }

    #[test]
    fn reanchoring_requires_known_position_and_preserves_human_resolution() {
        let snapshot = snapshot();
        let table = anchors(&snapshot);
        let lineage = digest('9');
        let marker = FindingLineageMarker::new(
            lineage,
            snapshot.version.diff_version.refs.head_sha.clone(),
            digest('8'),
        );
        let anchor = table.iter().next().expect("anchor").id.clone();
        let candidate = PublicationCandidate {
            target: PublicationTarget::Inline(anchor),
            body: format!("finding\n{}", marker.render()),
        };
        let open_moved = ExistingPublicationNote {
            note_id: 10,
            author_user_id: 7,
            body: candidate.body.clone(),
            discussion_id: Some("open-moved".to_owned()),
            resolvable: true,
            path: Some("src/lib.rs".to_owned()),
            line: Some(3),
            ..ExistingPublicationNote::default()
        };
        let human_resolved = ExistingPublicationNote {
            note_id: 11,
            discussion_id: Some("human-resolved".to_owned()),
            resolved: true,
            resolved_by_user_id: Some(8),
            ..open_moved.clone()
        };
        let legacy_position = ExistingPublicationNote {
            note_id: 12,
            discussion_id: Some("legacy".to_owned()),
            path: None,
            line: None,
            ..open_moved.clone()
        };
        let (planning, resolutions) = inventory_for_current_anchors(
            &table,
            7,
            &[candidate],
            &PublicationInventory {
                complete: true,
                notes: vec![open_moved, human_resolved.clone(), legacy_position.clone()],
            },
        );
        assert_eq!(planning.notes, vec![human_resolved, legacy_position]);
        assert_eq!(
            resolutions,
            vec![GitLabDiscussionResolution {
                discussion_id: "open-moved".to_owned(),
                note_id: 10,
            }]
        );
    }

    #[tokio::test]
    async fn gate_is_closed_before_any_network_request() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let snapshot = snapshot();
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::default(),
                snapshot.clone(),
                &anchors(&snapshot),
                7,
                None,
                [],
                &BTreeSet::new(),
            )
            .await;
        assert!(
            matches!(outcome, GitLabPublicationOutcome::GateClosed { evidence } if evidence.requests_started == 0)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn overview_replaces_only_owned_description_block() {
        let snapshot = snapshot();
        let mut initial = mr('d');
        initial["description"] = Value::String("author prefix\n\nauthor suffix".to_owned());
        let overview = concat!(
            "<!-- revoot:overview:v1:start -->\n",
            "<details>overview</details>\n",
            "<!-- revoot:overview:v1:end -->"
        );
        let (address, server) = serve_script(vec![
            empty_inventory(),
            Reply::Json {
                status: "200 OK",
                body: initial,
                headers: String::new(),
            },
            Reply::UpdateDescription,
        ])
        .await;
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot.clone(),
                &anchors(&snapshot),
                7,
                Some(overview),
                [],
                &BTreeSet::new(),
            )
            .await;
        let GitLabPublicationOutcome::Completed { evidence, .. } = outcome else {
            panic!("expected overview publication: {outcome:?}")
        };
        assert_eq!(evidence.overview_confirmed, 1);
        assert_eq!(evidence.mutation_attempts, 1);
        let requests = server.await.expect("server");
        let request_body = request_json(&requests[2]);
        let description = request_body["description"].as_str().expect("description");
        assert_eq!(
            description,
            format!("author prefix\n\nauthor suffix\n\n{overview}")
        );
    }

    #[tokio::test]
    async fn stale_before_mutation_writes_nothing_and_stale_during_retains_exact_partial() {
        let (address, server) = serve_script(vec![
            empty_inventory(),
            Reply::Json {
                status: "200 OK",
                body: mr('f'),
                headers: String::new(),
            },
        ])
        .await;
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let snapshot = snapshot();
        let table = anchors(&snapshot);
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot.clone(),
                &table,
                7,
                None,
                inline_candidates(&table, 1),
                &BTreeSet::new(),
            )
            .await;
        let GitLabPublicationOutcome::Stopped {
            journal: Some(journal),
            failure: GitLabPublicationFailure::SnapshotMismatch,
            ..
        } = outcome
        else {
            panic!("expected stale")
        };
        assert!(journal.entries.is_empty());
        let requests = server.await.expect("server");
        assert!(requests.iter().all(|request| request.starts_with(b"GET ")));

        let (address, server) = serve_script(vec![
            empty_inventory(),
            fresh_mr(),
            fresh_versions(),
            Reply::Created {
                note_id: 10,
                discussion: true,
            },
            Reply::Json {
                status: "200 OK",
                body: mr('f'),
                headers: String::new(),
            },
        ])
        .await;
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot.clone(),
                &table,
                7,
                None,
                inline_candidates(&table, 2),
                &BTreeSet::new(),
            )
            .await;
        let GitLabPublicationOutcome::Stopped {
            journal: Some(journal),
            failure: GitLabPublicationFailure::SnapshotMismatch,
            ..
        } = outcome
        else {
            panic!("expected stale partial")
        };
        assert_eq!(journal.entries.len(), 1);
        assert!(matches!(
            journal.entries[0].outcome,
            PublicationJournalOutcome::Created { note_id: 10 }
        ));
        let requests = server.await.expect("server");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with(b"POST "))
                .count(),
            1
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn human_marker_is_untouched_and_response_loss_converges() {
        let snapshot = snapshot();
        let table = anchors(&snapshot);
        let candidate = inline_candidates(&table, 1).remove(0);
        let plan = build_publication_plan(
            snapshot.clone(),
            7,
            [candidate.clone()],
            &PublicationInventory {
                complete: true,
                notes: vec![],
            },
        )
        .expect("plan");
        let forged = plan.actions[0].publication.marked_body.clone();
        let inventory = json!([{"id": "human", "individual_note": false, "notes": [{
            "id": 5, "type": "DiffNote", "body": forged,
            "author": {"id": 8, "username": "human"}, "system": false
        }]}]);
        let (address, server) = serve_script(vec![
            Reply::Json {
                status: "200 OK",
                body: inventory,
                headers: page_headers(1, None, 1, 1),
            },
            fresh_mr(),
            fresh_versions(),
            Reply::Created {
                note_id: 11,
                discussion: true,
            },
        ])
        .await;
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot.clone(),
                &table,
                7,
                None,
                [candidate.clone()],
                &BTreeSet::new(),
            )
            .await;
        assert!(matches!(
            outcome,
            GitLabPublicationOutcome::Completed { .. }
        ));
        let requests = server.await.expect("server");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with(b"POST "))
                .count(),
            1
        );
        assert!(
            requests
                .iter()
                .all(|request| request.starts_with(b"GET ") || request.starts_with(b"POST "))
        );

        let (address, server) = serve_script(vec![
            empty_inventory(),
            fresh_mr(),
            fresh_versions(),
            Reply::DropRemember { note_id: 12 },
            Reply::InventoryRemember,
        ])
        .await;
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot,
                &table,
                7,
                None,
                [candidate],
                &BTreeSet::new(),
            )
            .await;
        let GitLabPublicationOutcome::Completed { journal, evidence } = outcome else {
            panic!("expected convergence")
        };
        assert!(matches!(
            journal.entries[0].outcome,
            PublicationJournalOutcome::Reconciled { note_id: 12 }
        ));
        assert_eq!(evidence.ambiguous_results, 1);
        let requests = server.await.expect("server");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with(b"POST "))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn changed_head_publishes_current_finding_then_resolves_owned_stale_thread() {
        let current = snapshot();
        let table = anchors(&current);
        let candidate = inline_candidates(&table, 1).remove(0);
        let mut prior = current.clone();
        prior.version.diff_version.refs.head_sha = GitSha::try_from(sha('c')).expect("prior head");
        let prior_plan = build_publication_plan(
            prior,
            7,
            [candidate.clone()],
            &PublicationInventory {
                complete: true,
                notes: Vec::new(),
            },
        )
        .expect("prior plan");
        let stale_body = prior_plan.actions[0].publication.marked_body.clone();
        let fixed_lineages = BTreeSet::from([
            revoot_core::finding_lineage_id(&stale_body).expect("owned stale lineage")
        ]);
        let inventory = json!([{
            "id": "stale-discussion",
            "individual_note": false,
            "notes": [{
                "id": 5,
                "type": "DiffNote",
                "body": stale_body,
                "author": {"id": 7, "username": "revoot"},
                "system": false,
                "resolvable": true,
                "resolved": false
            }]
        }]);
        let (address, server) = serve_script(vec![
            Reply::Json {
                status: "200 OK",
                body: inventory,
                headers: page_headers(1, None, 1, 1),
            },
            fresh_mr(),
            fresh_versions(),
            Reply::Created {
                note_id: 12,
                discussion: true,
            },
            fresh_mr(),
            fresh_versions(),
            Reply::Resolved {
                discussion_id: "stale-discussion".to_owned(),
                note_id: 5,
                body: stale_body,
            },
        ])
        .await;
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                current,
                &table,
                7,
                None,
                [candidate],
                &fixed_lineages,
            )
            .await;
        let GitLabPublicationOutcome::Completed { evidence, .. } = outcome else {
            panic!("expected converged incremental publication");
        };
        assert_eq!(evidence.resolved_discussions, 1);
        let requests = server.await.expect("server");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with(b"POST "))
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with(b"PUT "))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn complete_pagination_and_rate_retry_are_bounded() {
        let note = |discussion: &str, note_id: u64| {
            json!({
                "id": discussion, "individual_note": false, "notes": [{
                    "id": note_id, "type": "DiffNote", "body": "human note",
                    "author": {"id": 8, "username": "human"}, "system": false
                }]
            })
        };
        let first = Reply::Json {
            status: "200 OK",
            body: json!([note("d1", 1)]),
            headers: page_headers_with_per_page(1, 1, Some(2), 2, 2),
        };
        let limited = Reply::Json {
            status: "429 Too Many Requests",
            body: json!({}),
            headers: "Retry-After: 0\r\n".to_owned(),
        };
        let second = Reply::Json {
            status: "200 OK",
            body: json!([note("d2", 2)]),
            headers: page_headers_with_per_page(2, 1, None, 2, 2),
        };
        let (address, server) = serve_script(vec![first, limited, second]).await;
        let (read, write) = clients(address);
        let limits = GitLabPublicationLimits {
            per_page: 1,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            ..GitLabPublicationLimits::default()
        };
        let controller =
            GitLabPublicationController::new(&read, &write, limits).expect("controller");
        let snapshot = snapshot();
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot.clone(),
                &anchors(&snapshot),
                7,
                None,
                [],
                &BTreeSet::new(),
            )
            .await;
        let GitLabPublicationOutcome::Completed { evidence, .. } = outcome else {
            panic!("expected completion")
        };
        assert_eq!(evidence.inventory_pages, 2);
        assert_eq!(evidence.read_retry_attempts, 1);
        assert_eq!(evidence.requests_started, 3);
        assert_eq!(server.await.expect("server").len(), 3);
    }

    #[tokio::test]
    async fn origin_mismatch_is_zero_request_and_post_timeout_remains_ambiguous() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let mut mismatched = snapshot();
        mismatched.version.scope.instance_origin_digest = digest('f');
        let table = anchors(&mismatched);
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                mismatched,
                &table,
                7,
                None,
                [],
                &BTreeSet::new(),
            )
            .await;
        assert!(
            matches!(outcome, GitLabPublicationOutcome::Stopped { failure: GitLabPublicationFailure::SnapshotMismatch, evidence, .. } if evidence.requests_started == 0)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );

        let (address, server) = serve_script(vec![
            empty_inventory(),
            fresh_mr(),
            fresh_versions(),
            Reply::Hang(Duration::from_secs(2)),
        ])
        .await;
        let (read, write) = clients(address);
        let limits = GitLabPublicationLimits {
            operation_timeout: Duration::from_millis(500),
            ..GitLabPublicationLimits::default()
        };
        let controller =
            GitLabPublicationController::new(&read, &write, limits).expect("controller");
        let snapshot = snapshot();
        let table = anchors(&snapshot);
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot,
                &table,
                7,
                None,
                inline_candidates(&table, 1),
                &BTreeSet::new(),
            )
            .await;
        let GitLabPublicationOutcome::Stopped {
            journal: Some(journal),
            failure: GitLabPublicationFailure::Deadline,
            evidence,
        } = outcome
        else {
            panic!("expected ambiguous deadline")
        };
        assert!(matches!(
            journal.state,
            PublicationJournalState::AmbiguousOutcome { .. }
        ));
        assert_eq!(evidence.ambiguous_results, 1);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn contradictory_newer_version_after_expected_stops_before_post() {
        let (address, server) = serve_script(vec![
            empty_inventory(),
            fresh_mr(),
            Reply::Json {
                status: "200 OK",
                body: contradictory_versions(),
                headers: page_headers(1, None, 2, 1),
            },
        ])
        .await;
        let (read, write) = clients(address);
        let controller =
            GitLabPublicationController::new(&read, &write, GitLabPublicationLimits::default())
                .expect("controller");
        let snapshot = snapshot();
        let table = anchors(&snapshot);
        let outcome = controller
            .publish(
                GitLabPublicationAuthorization::accepted_for_test(),
                snapshot,
                &table,
                7,
                None,
                inline_candidates(&table, 1),
                &BTreeSet::new(),
            )
            .await;
        let GitLabPublicationOutcome::Stopped {
            journal: Some(journal),
            failure: GitLabPublicationFailure::SnapshotMismatch,
            ..
        } = outcome
        else {
            panic!("contradictory ordering must stop publication")
        };
        assert!(journal.entries.is_empty());
        assert!(matches!(
            journal.state,
            PublicationJournalState::StoppedStale { before_action: 0 }
        ));
        let requests = server.await.expect("server");
        assert!(requests.iter().all(|request| request.starts_with(b"GET ")));
    }
}
