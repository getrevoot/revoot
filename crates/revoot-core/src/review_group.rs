// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 alibaba/open-code-review Contributors
// Copyright 2026 Revoot Contributors
// Modified for Revoot's bounded, snapshot-bound review domain.

//! Snapshot-bound review groups and risk-adaptive coverage contracts.
//!
//! This module is deterministic and performs no model, filesystem, network,
//! process, clock, or publication operation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AnchorId, ChangedPath, RepositoryPath, ReviewPartitionPlan, ReviewValueTier, Sha256Digest,
    WorkUnitId,
};

const GROUP_ID_PREFIX: &str = "rg-";
const MAX_GROUP_FILES: u32 = 10;
const MAX_GROUP_BYTES: u64 = 512 * 1024;
const MAX_GROUP_ANCHORS: u32 = 10_000;
const MAX_GROUPS: usize = 128;
const MAX_HUNKS_PER_FILE: usize = 4_096;
const MAX_PAGES_PER_HUNK: u32 = 4_096;
const MAX_DISPOSITION_NOTE_BYTES: usize = 512;

/// Operator-selected depth of review.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewEffort {
    Low,
    #[default]
    Medium,
    High,
}

impl ReviewEffort {
    /// Number of independent review rounds for one group.
    #[must_use]
    pub const fn rounds(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }

    /// Maximum provider turns available to one group across all rounds.
    #[must_use]
    pub const fn max_group_turns(self) -> u32 {
        match self {
            Self::Low => 12,
            Self::Medium => 20,
            Self::High => 32,
        }
    }
}

/// Hard bounds applied after either semantic or deterministic grouping.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGroupLimits {
    pub max_files: u32,
    pub max_input_bytes: u64,
    pub max_anchors: u32,
}

impl Default for ReviewGroupLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_GROUP_FILES,
            max_input_bytes: MAX_GROUP_BYTES,
            max_anchors: MAX_GROUP_ANCHORS,
        }
    }
}

impl ReviewGroupLimits {
    fn valid(self) -> bool {
        self.max_files > 0
            && self.max_files <= MAX_GROUP_FILES
            && self.max_input_bytes > 0
            && self.max_input_bytes <= MAX_GROUP_BYTES
            && self.max_anchors > 0
            && self.max_anchors <= MAX_GROUP_ANCHORS
    }
}

/// Whether the final group layout came from model metadata or a safe fallback.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewGroupingSource {
    Deterministic,
    Semantic,
    DeterministicFallback,
}

/// Stable opaque group identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ReviewGroupId(String);

impl ReviewGroupId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One selected file assigned to exactly one runtime review group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGroupFile {
    pub path: ChangedPath,
    pub tier: ReviewValueTier,
    pub input_bytes: u64,
    pub anchor_ids: Vec<AnchorId>,
    pub work_unit_id: WorkUnitId,
}

/// One bounded, isolated reviewer assignment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGroup {
    pub id: ReviewGroupId,
    pub files: Vec<ReviewGroupFile>,
    pub input_bytes: u64,
    pub anchor_count: u32,
}

/// Actual runtime grouping bound to a deterministic partition plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGroupPlan {
    pub schema_version: String,
    pub partition_sha256: Sha256Digest,
    pub source: ReviewGroupingSource,
    pub limits: ReviewGroupLimits,
    pub groups: Vec<ReviewGroup>,
    pub plan_sha256: Sha256Digest,
}

impl ReviewGroupPlan {
    pub const SCHEMA_VERSION: &'static str = "revoot.review-group-plan/v1";

    /// Validate group identities, capacity, complete assignment, and digest.
    ///
    /// # Errors
    ///
    /// Returns the first closed contract violation in the supplied plan.
    pub fn validate_against(
        &self,
        partition: &ReviewPartitionPlan,
    ) -> Result<(), ReviewGroupPlanError> {
        partition
            .validate_replay()
            .map_err(|_| ReviewGroupPlanError::Partition)?;
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ReviewGroupPlanError::SchemaVersion);
        }
        if self.partition_sha256 != partition.plan_sha256 {
            return Err(ReviewGroupPlanError::Partition);
        }
        if !self.limits.valid() || self.groups.len() > MAX_GROUPS {
            return Err(ReviewGroupPlanError::Limits);
        }
        let expected_files = selected_files(partition)?;
        let mut observed = BTreeSet::new();
        let mut previous_id: Option<&ReviewGroupId> = None;
        for group in &self.groups {
            if group.files.is_empty()
                || previous_id.is_some_and(|previous| previous >= &group.id)
                || !valid_group_id(&group.id)
            {
                return Err(ReviewGroupPlanError::GroupIdentity);
            }
            previous_id = Some(&group.id);
            let (bytes, anchors) = group_totals(&group.files)?;
            if bytes != group.input_bytes
                || anchors != group.anchor_count
                || group.files.len() > usize::try_from(self.limits.max_files).unwrap_or(usize::MAX)
                || bytes > self.limits.max_input_bytes
                || anchors > self.limits.max_anchors
                || group.id != derive_group_id(&group.files)?
            {
                return Err(ReviewGroupPlanError::Limits);
            }
            for file in &group.files {
                let path = file.path.new_path.clone();
                if !observed.insert(path.clone()) {
                    return Err(ReviewGroupPlanError::DuplicateFile);
                }
                let Some(expected) = expected_files.get(&path) else {
                    return Err(ReviewGroupPlanError::UnknownFile);
                };
                if expected != file {
                    return Err(ReviewGroupPlanError::FileMismatch);
                }
            }
        }
        if observed != expected_files.keys().cloned().collect() {
            return Err(ReviewGroupPlanError::IncompleteAssignment);
        }
        if self.plan_sha256 != derive_plan_digest(self)? {
            return Err(ReviewGroupPlanError::Digest);
        }
        Ok(())
    }
}

/// A semantic grouping proposal contains only selected paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedReviewGroup {
    pub paths: Vec<RepositoryPath>,
}

/// Redaction-safe grouping contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewGroupPlanError {
    Partition,
    SchemaVersion,
    Limits,
    GroupIdentity,
    DuplicateFile,
    UnknownFile,
    FileMismatch,
    IncompleteAssignment,
    Digest,
    Serialization,
}

/// Build a complete bounded group plan.
///
/// Invalid semantic proposals do not need to reach this function: callers may
/// pass `None` and identify the source as `DeterministicFallback`.
///
/// # Errors
///
/// Returns a closed grouping error when the partition or proposed assignment
/// violates identity, completeness, or capacity bounds.
pub fn build_review_group_plan(
    partition: &ReviewPartitionPlan,
    proposal: Option<&[ProposedReviewGroup]>,
    source: ReviewGroupingSource,
) -> Result<ReviewGroupPlan, ReviewGroupPlanError> {
    partition
        .validate_replay()
        .map_err(|_| ReviewGroupPlanError::Partition)?;
    let limits = ReviewGroupLimits::default();
    let selected = selected_files(partition)?;
    let ordered = proposal_order(&selected, proposal)?;
    let mut groups = Vec::new();
    for proposal_files in ordered {
        pack_files(proposal_files, limits, &mut groups)?;
    }
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    let mut plan = ReviewGroupPlan {
        schema_version: ReviewGroupPlan::SCHEMA_VERSION.to_owned(),
        partition_sha256: partition.plan_sha256.clone(),
        source,
        limits,
        groups,
        plan_sha256: Sha256Digest::of_bytes(b"pending"),
    };
    plan.plan_sha256 = derive_plan_digest(&plan)?;
    plan.validate_against(partition)?;
    Ok(plan)
}

fn selected_files(
    partition: &ReviewPartitionPlan,
) -> Result<BTreeMap<RepositoryPath, ReviewGroupFile>, ReviewGroupPlanError> {
    let mut selected = BTreeMap::new();
    for unit in &partition.work_units {
        for file in &unit.files {
            let group_file = ReviewGroupFile {
                path: file.path.clone(),
                tier: file.review_value.tier,
                input_bytes: file.input_bytes,
                anchor_ids: file.anchor_ids.clone(),
                work_unit_id: unit.id.clone(),
            };
            if selected
                .insert(file.path.new_path.clone(), group_file)
                .is_some()
            {
                return Err(ReviewGroupPlanError::DuplicateFile);
            }
        }
    }
    Ok(selected)
}

fn proposal_order(
    selected: &BTreeMap<RepositoryPath, ReviewGroupFile>,
    proposal: Option<&[ProposedReviewGroup]>,
) -> Result<Vec<Vec<ReviewGroupFile>>, ReviewGroupPlanError> {
    let Some(proposal) = proposal else {
        return Ok(vec![selected.values().cloned().collect()]);
    };
    if proposal.len() > MAX_GROUPS {
        return Err(ReviewGroupPlanError::Limits);
    }
    let mut assigned = BTreeSet::new();
    let mut groups = Vec::new();
    for proposed in proposal {
        if proposed.paths.is_empty() {
            return Err(ReviewGroupPlanError::IncompleteAssignment);
        }
        let mut files = Vec::new();
        for path in &proposed.paths {
            if !assigned.insert(path.clone()) {
                return Err(ReviewGroupPlanError::DuplicateFile);
            }
            files.push(
                selected
                    .get(path)
                    .cloned()
                    .ok_or(ReviewGroupPlanError::UnknownFile)?,
            );
        }
        files.sort_by(|left, right| left.path.new_path.cmp(&right.path.new_path));
        groups.push(files);
    }
    let unassigned = selected
        .iter()
        .filter(|(path, _)| !assigned.contains(*path))
        .map(|(_, file)| file.clone())
        .collect::<Vec<_>>();
    if !unassigned.is_empty() {
        groups.push(unassigned);
    }
    Ok(groups)
}

fn pack_files(
    files: Vec<ReviewGroupFile>,
    limits: ReviewGroupLimits,
    groups: &mut Vec<ReviewGroup>,
) -> Result<(), ReviewGroupPlanError> {
    let mut current = Vec::new();
    let mut bytes = 0_u64;
    let mut anchors = 0_u32;
    for file in files {
        let file_anchors =
            u32::try_from(file.anchor_ids.len()).map_err(|_| ReviewGroupPlanError::Limits)?;
        if file.input_bytes > limits.max_input_bytes || file_anchors > limits.max_anchors {
            return Err(ReviewGroupPlanError::Limits);
        }
        let would_overflow = !current.is_empty()
            && (current.len() >= usize::try_from(limits.max_files).unwrap_or(usize::MAX)
                || bytes.saturating_add(file.input_bytes) > limits.max_input_bytes
                || anchors.saturating_add(file_anchors) > limits.max_anchors);
        if would_overflow {
            groups.push(finish_group(std::mem::take(&mut current))?);
            bytes = 0;
            anchors = 0;
        }
        bytes = bytes.saturating_add(file.input_bytes);
        anchors = anchors.saturating_add(file_anchors);
        current.push(file);
    }
    if !current.is_empty() {
        groups.push(finish_group(current)?);
    }
    Ok(())
}

fn finish_group(mut files: Vec<ReviewGroupFile>) -> Result<ReviewGroup, ReviewGroupPlanError> {
    files.sort_by(|left, right| left.path.new_path.cmp(&right.path.new_path));
    let (input_bytes, anchor_count) = group_totals(&files)?;
    Ok(ReviewGroup {
        id: derive_group_id(&files)?,
        files,
        input_bytes,
        anchor_count,
    })
}

fn group_totals(files: &[ReviewGroupFile]) -> Result<(u64, u32), ReviewGroupPlanError> {
    let bytes = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.input_bytes)
            .ok_or(ReviewGroupPlanError::Limits)
    })?;
    let anchors = files.iter().try_fold(0_u32, |total, file| {
        total
            .checked_add(
                u32::try_from(file.anchor_ids.len()).map_err(|_| ReviewGroupPlanError::Limits)?,
            )
            .ok_or(ReviewGroupPlanError::Limits)
    })?;
    Ok((bytes, anchors))
}

fn derive_group_id(files: &[ReviewGroupFile]) -> Result<ReviewGroupId, ReviewGroupPlanError> {
    let bytes = serde_json::to_vec(files).map_err(|_| ReviewGroupPlanError::Serialization)?;
    Ok(ReviewGroupId(format!(
        "{GROUP_ID_PREFIX}{}",
        Sha256Digest::of_bytes(&bytes).as_str()
    )))
}

fn valid_group_id(id: &ReviewGroupId) -> bool {
    id.0.strip_prefix(GROUP_ID_PREFIX).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn derive_plan_digest(plan: &ReviewGroupPlan) -> Result<Sha256Digest, ReviewGroupPlanError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        partition_sha256: &'a Sha256Digest,
        source: ReviewGroupingSource,
        limits: ReviewGroupLimits,
        groups: &'a [ReviewGroup],
    }
    let bytes = serde_json::to_vec(&DigestInput {
        schema_version: &plan.schema_version,
        partition_sha256: &plan.partition_sha256,
        source: plan.source,
        limits: plan.limits,
        groups: &plan.groups,
    })
    .map_err(|_| ReviewGroupPlanError::Serialization)?;
    Ok(Sha256Digest::of_bytes(&bytes))
}

/// Why an unread hunk was not delivered to a model.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnreadHunkDispositionKind {
    ManifestLowRisk,
    RedundantPattern,
    BudgetExhausted,
    ToolError,
}

/// Bounded explanation for one unread hunk.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnreadHunkDisposition {
    pub kind: UnreadHunkDispositionKind,
    pub note: String,
}

/// Delivered-page state for one exact diff hunk.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HunkCoverage {
    pub hunk_id: String,
    pub total_pages: u32,
    pub delivered_pages: BTreeSet<u32>,
    pub hazardous: bool,
}

impl HunkCoverage {
    fn fully_delivered(&self) -> bool {
        self.total_pages > 0
            && self.delivered_pages.len() == usize::try_from(self.total_pages).unwrap_or(usize::MAX)
            && (1..=self.total_pages).all(|page| self.delivered_pages.contains(&page))
    }
}

/// Coverage evidence for one selected file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileCoverageLedger {
    pub path: RepositoryPath,
    pub tier: ReviewValueTier,
    pub manifested: bool,
    pub metadata_only: bool,
    pub hunks: Vec<HunkCoverage>,
    pub unread_dispositions: BTreeMap<String, UnreadHunkDisposition>,
}

/// Risk-adaptive group coverage computed from actual tool delivery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupCoverageLedger {
    pub policy_version: String,
    pub files: BTreeMap<RepositoryPath, FileCoverageLedger>,
}

impl GroupCoverageLedger {
    pub const POLICY_VERSION: &'static str = "revoot.risk-adaptive-coverage/v1";

    /// Construct a ledger before any model-visible manifest is built.
    ///
    /// # Errors
    ///
    /// Returns a closed error for duplicated files or malformed hunk metadata.
    pub fn new(files: impl IntoIterator<Item = FileCoverageLedger>) -> Result<Self, CoverageError> {
        let mut indexed = BTreeMap::new();
        for file in files {
            if file.hunks.len() > MAX_HUNKS_PER_FILE
                || file.hunks.iter().any(|hunk| {
                    hunk.hunk_id.is_empty()
                        || hunk.total_pages == 0
                        || hunk.total_pages > MAX_PAGES_PER_HUNK
                        || hunk
                            .delivered_pages
                            .iter()
                            .any(|page| *page == 0 || *page > hunk.total_pages)
                })
                || indexed.insert(file.path.clone(), file).is_some()
            {
                return Err(CoverageError::InvalidLedger);
            }
        }
        Ok(Self {
            policy_version: Self::POLICY_VERSION.to_owned(),
            files: indexed,
        })
    }

    /// Mark a file manifest as delivered.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError::UnknownFile`] for a path outside the group.
    pub fn mark_manifested(&mut self, path: &RepositoryPath) -> Result<(), CoverageError> {
        self.files
            .get_mut(path)
            .ok_or(CoverageError::UnknownFile)?
            .manifested = true;
        Ok(())
    }

    /// Record one successfully delivered hunk page.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unknown file, hunk, or page.
    pub fn record_hunk_page(
        &mut self,
        path: &RepositoryPath,
        hunk_id: &str,
        page: u32,
    ) -> Result<(), CoverageError> {
        let file = self.files.get_mut(path).ok_or(CoverageError::UnknownFile)?;
        let hunk = file
            .hunks
            .iter_mut()
            .find(|hunk| hunk.hunk_id == hunk_id)
            .ok_or(CoverageError::UnknownHunk)?;
        if page == 0 || page > hunk.total_pages {
            return Err(CoverageError::InvalidPage);
        }
        hunk.delivered_pages.insert(page);
        Ok(())
    }

    /// Record the bounded reason an otherwise optional hunk was not delivered.
    ///
    /// # Errors
    ///
    /// Returns a closed error for unknown targets or malformed explanations.
    pub fn set_unread_disposition(
        &mut self,
        path: &RepositoryPath,
        hunk_id: &str,
        disposition: UnreadHunkDisposition,
    ) -> Result<(), CoverageError> {
        if disposition.note.len() > MAX_DISPOSITION_NOTE_BYTES
            || disposition.note.contains('\0')
            || disposition
                .note
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(CoverageError::InvalidDisposition);
        }
        let file = self.files.get_mut(path).ok_or(CoverageError::UnknownFile)?;
        if !file.hunks.iter().any(|hunk| hunk.hunk_id == hunk_id) {
            return Err(CoverageError::UnknownHunk);
        }
        file.unread_dispositions
            .insert(hunk_id.to_owned(), disposition);
        Ok(())
    }

    /// Add deterministic manifest-only dispositions for eligible low-risk files.
    pub fn finalize_low_risk_deferrals(&mut self) {
        for file in self
            .files
            .values_mut()
            .filter(|file| file.tier == ReviewValueTier::Low && file.manifested)
        {
            for hunk in &file.hunks {
                if !hunk.hazardous && !hunk.fully_delivered() {
                    file.unread_dispositions
                        .entry(hunk.hunk_id.clone())
                        .or_insert_with(|| UnreadHunkDisposition {
                            kind: UnreadHunkDispositionKind::ManifestLowRisk,
                            note: "deferred by the deterministic low-risk policy".to_owned(),
                        });
                }
            }
        }
    }

    /// Return every unmet requirement; an empty list authorizes completion.
    #[must_use]
    pub fn missing_requirements(&self) -> Vec<CoverageRequirement> {
        let mut missing = Vec::new();
        for file in self.files.values() {
            if !file.manifested {
                missing.push(CoverageRequirement {
                    path: file.path.clone(),
                    hunk_id: None,
                    kind: CoverageRequirementKind::Manifest,
                });
                continue;
            }
            if file.metadata_only {
                continue;
            }
            let fully_delivered = file
                .hunks
                .iter()
                .filter(|hunk| hunk.fully_delivered())
                .count();
            if file.tier == ReviewValueTier::Standard
                && !file.hunks.is_empty()
                && fully_delivered == 0
            {
                missing.push(CoverageRequirement {
                    path: file.path.clone(),
                    hunk_id: None,
                    kind: CoverageRequirementKind::Sample,
                });
            }
            for hunk in &file.hunks {
                if hunk.fully_delivered() {
                    continue;
                }
                let disposition = file.unread_dispositions.get(&hunk.hunk_id);
                let required_body = file.tier == ReviewValueTier::High || hunk.hazardous;
                if required_body {
                    missing.push(CoverageRequirement {
                        path: file.path.clone(),
                        hunk_id: Some(hunk.hunk_id.clone()),
                        kind: CoverageRequirementKind::HunkBody,
                    });
                } else if disposition.is_none() {
                    missing.push(CoverageRequirement {
                        path: file.path.clone(),
                        hunk_id: Some(hunk.hunk_id.clone()),
                        kind: CoverageRequirementKind::Disposition,
                    });
                }
            }
        }
        missing
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing_requirements().is_empty()
    }
}

/// A concrete requirement returned when completion is rejected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageRequirement {
    pub path: RepositoryPath,
    pub hunk_id: Option<String>,
    pub kind: CoverageRequirementKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageRequirementKind {
    Manifest,
    Sample,
    HunkBody,
    Disposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageError {
    InvalidLedger,
    UnknownFile,
    UnknownHunk,
    InvalidPage,
    InvalidDisposition,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FileChangeKind, GitSha, LocalSnapshotIdentity, PartitionLimits, ReviewFileClass,
        ReviewFileInput, ReviewObject, ReviewObjectRole, ReviewSelectionPolicy, ReviewValue,
        ReviewValueReason, build_partition_plan,
    };

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn partition(count: usize) -> ReviewPartitionPlan {
        let files = (0..count)
            .map(|index| {
                let path = path(&format!("src/file-{index}.rs"));
                ReviewFileInput {
                    path: ChangedPath {
                        old_path: path.clone(),
                        new_path: path,
                        kind: FileChangeKind::Modified,
                    },
                    class: ReviewFileClass::Text,
                    review_value: ReviewValue {
                        tier: ReviewValueTier::Standard,
                        score: 100,
                        reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                    },
                    objects: vec![ReviewObject {
                        role: ReviewObjectRole::ExactDiff,
                        content_sha256: Sha256Digest::of_bytes(format!("diff-{index}").as_bytes()),
                        size_bytes: 100,
                    }],
                    anchor_ids: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        let sha = |marker: char| GitSha::try_from(marker.to_string().repeat(40)).unwrap();
        build_partition_plan(
            crate::ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
                repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
                base_sha: sha('a'),
                head_sha: sha('b'),
                working_tree_sha256: Sha256Digest::of_bytes(b"working-tree"),
                exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
            }),
            &ReviewSelectionPolicy {
                version: "policy-v1".to_owned(),
                included_paths: BTreeSet::new(),
                included_prefixes: Vec::new(),
                included_suffixes: Vec::new(),
                excluded_paths: BTreeSet::new(),
                excluded_prefixes: Vec::new(),
                excluded_suffixes: Vec::new(),
                excluded_basename_prefixes: Vec::new(),
                include_generated: false,
                max_file_bytes: 1_000,
            },
            PartitionLimits {
                max_files: 100,
                max_total_bytes: 1_000_000,
                max_work_units: 100,
                max_files_per_work_unit: 20,
                max_bytes_per_work_unit: 512 * 1024,
                max_anchors_per_work_unit: 10_000,
            },
            files,
        )
        .unwrap()
    }

    #[test]
    fn deterministic_groups_are_complete_and_capacity_bounded() {
        let partition = partition(23);
        let plan =
            build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic).unwrap();
        assert_eq!(plan.groups.len(), 3);
        assert!(plan.groups.iter().all(|group| group.files.len() <= 10));
        assert_eq!(plan.validate_against(&partition), Ok(()));
    }

    #[test]
    fn semantic_proposal_gets_deterministic_unassigned_fallback() {
        let partition = partition(4);
        let proposal = [ProposedReviewGroup {
            paths: vec![path("src/file-2.rs")],
        }];
        let plan =
            build_review_group_plan(&partition, Some(&proposal), ReviewGroupingSource::Semantic)
                .unwrap();
        assert_eq!(
            plan.groups
                .iter()
                .map(|group| group.files.len())
                .sum::<usize>(),
            4
        );
        assert_eq!(plan.validate_against(&partition), Ok(()));
    }

    fn coverage(tier: ReviewValueTier, hazardous: bool) -> GroupCoverageLedger {
        GroupCoverageLedger::new([FileCoverageLedger {
            path: path("src/lib.rs"),
            tier,
            manifested: true,
            metadata_only: false,
            hunks: vec![HunkCoverage {
                hunk_id: "hunk-1".to_owned(),
                total_pages: 2,
                delivered_pages: BTreeSet::new(),
                hazardous,
            }],
            unread_dispositions: BTreeMap::new(),
        }])
        .unwrap()
    }

    #[test]
    fn high_risk_requires_every_page() {
        let mut ledger = coverage(ReviewValueTier::High, false);
        assert!(!ledger.is_complete());
        ledger
            .record_hunk_page(&path("src/lib.rs"), "hunk-1", 1)
            .unwrap();
        assert!(!ledger.is_complete());
        ledger
            .record_hunk_page(&path("src/lib.rs"), "hunk-1", 2)
            .unwrap();
        assert!(ledger.is_complete());
    }

    #[test]
    fn low_risk_can_be_deterministically_deferred_but_hazard_cannot() {
        let mut low = coverage(ReviewValueTier::Low, false);
        low.finalize_low_risk_deferrals();
        assert!(low.is_complete());

        let mut hazard = coverage(ReviewValueTier::Low, true);
        hazard.finalize_low_risk_deferrals();
        assert!(!hazard.is_complete());
    }
}
