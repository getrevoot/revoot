//! Deterministic group measurements from body-free manifests.
//!
//! The builder joins one authoritative group assignment with exact numeric hunk
//! metadata and deterministic hazard reports. No diff or source body is accepted
//! or retained by any contract in this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::diff_hazards::{DiffHazardInspection, DiffHazardReport};
use crate::{FileChangeKind, RepositoryPath, ReviewGroup, ReviewGroupId, ReviewValueTier};

const MAX_GROUP_FILES: usize = 10;
const MAX_HUNKS_PER_FILE: usize = 4_096;
const MAX_HUNK_ID_BYTES: usize = 128;
const MAX_PAGES_PER_HUNK: u32 = 4_096;
const MAX_CHANGED_LINES_PER_HUNK: u32 = 1_000_000;
const MAX_INLINE_DIFF_BYTES: u64 = 16 * 1_024;
const MAX_REQUEST_INPUT_TOKENS: u64 = 96_000;
const FILE_PLANNING_THRESHOLD: u32 = 50;
const GROUP_PLANNING_THRESHOLD: u32 = 100;
const MAX_METRICS_JSON_BYTES: usize = 1024 * 1024;

/// Body-free exact hunk measurements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupHunkManifest {
    pub hunk_id: String,
    pub changed_lines: u32,
    pub pages: u32,
}

/// Exact body-free manifest for one selected file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupFileManifest {
    pub path: RepositoryPath,
    pub status: FileChangeKind,
    pub exact_diff_bytes: u64,
    pub metadata_only: bool,
    pub hunks: Vec<GroupHunkManifest>,
}

/// Trusted bounds and fixed-context estimate for the initial request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMetricsPolicy {
    pub inline_diff_bytes: u64,
    pub request_input_tokens: u64,
    pub fixed_context_tokens: u64,
}

impl Default for GroupMetricsPolicy {
    fn default() -> Self {
        Self {
            inline_diff_bytes: MAX_INLINE_DIFF_BYTES,
            request_input_tokens: MAX_REQUEST_INPUT_TOKENS,
            fixed_context_tokens: 0,
        }
    }
}

/// All-or-nothing initial group context decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupInitialContext {
    InlineCompleteGroup,
    ManifestOnly,
}

/// Per-hunk risk-adaptive delivery requirement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupHunkCoverageRequirement {
    AllPages,
    StandardSampleOrDisposition,
    ManifestDeferrable,
}

/// One hunk requirement derived from tier plus local hazards.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupHunkMetrics {
    pub hunk_id: String,
    pub changed_lines: u32,
    pub pages: u32,
    pub hazardous: bool,
    pub coverage: GroupHunkCoverageRequirement,
}

/// Exact file totals and risk-adaptive coverage requirements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupFileMetrics {
    pub path: RepositoryPath,
    pub status: FileChangeKind,
    pub original_tier: ReviewValueTier,
    pub effective_tier: ReviewValueTier,
    pub exact_diff_bytes: u64,
    pub changed_lines: u32,
    pub hunk_count: u32,
    pub page_count: u32,
    pub metadata_only: bool,
    pub manifest_required: bool,
    pub minimum_delivered_hunks: u32,
    pub hunks: Vec<GroupHunkMetrics>,
}

/// Planning threshold inputs retained alongside the decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPlanningMetrics {
    pub max_file_changed_lines: u32,
    pub total_changed_lines: u32,
    pub file_threshold: u32,
    pub group_threshold: u32,
    pub required: bool,
}

/// Initial-context accounting with a conservative one-token-per-byte estimate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInlineMetrics {
    pub context: GroupInitialContext,
    pub exact_diff_bytes: u64,
    pub conservative_diff_tokens: u64,
    pub estimated_request_tokens: u64,
}

/// Complete body-free metrics for one isolated review group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewGroupMetricsReport {
    pub schema_version: String,
    pub group_id: ReviewGroupId,
    pub file_count: u32,
    pub exact_diff_bytes: u64,
    pub changed_lines: u32,
    pub hunk_count: u32,
    pub page_count: u32,
    pub planning: GroupPlanningMetrics,
    pub inline: GroupInlineMetrics,
    pub files: Vec<GroupFileMetrics>,
}

impl ReviewGroupMetricsReport {
    pub const SCHEMA_VERSION: &'static str = "revoot.group-metrics/v1";

    /// Serialize deterministic sorted metrics without source content.
    ///
    /// # Errors
    ///
    /// Returns a closed error if serialization fails or exceeds the output cap.
    pub fn canonical_json(&self) -> Result<Vec<u8>, GroupMetricsError> {
        let encoded = serde_json::to_vec(self).map_err(|_| GroupMetricsError::Serialization)?;
        if encoded.len() > MAX_METRICS_JSON_BYTES {
            return Err(GroupMetricsError::OutputTooLarge);
        }
        Ok(encoded)
    }
}

/// Payload-free group metric failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupMetricsError {
    InvalidPolicy,
    InvalidGroup,
    MissingManifest,
    DuplicateManifest,
    CrossGroupManifest,
    InvalidManifest,
    MissingHazards,
    DuplicateHazards,
    CrossGroupHazards,
    HazardMismatch,
    CountOverflow,
    Serialization,
    OutputTooLarge,
}

impl fmt::Display for GroupMetricsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "group metrics policy is invalid",
            Self::InvalidGroup => "group metrics require a valid nonempty group",
            Self::MissingManifest => "group metrics are missing a file manifest",
            Self::DuplicateManifest => "group metrics contain a duplicate file manifest",
            Self::CrossGroupManifest => "group metrics contain a manifest outside the group",
            Self::InvalidManifest => "group metrics contain invalid hunk metadata",
            Self::MissingHazards => "group metrics are missing a hazard report",
            Self::DuplicateHazards => "group metrics contain a duplicate hazard report",
            Self::CrossGroupHazards => "group metrics contain hazards outside the group",
            Self::HazardMismatch => "group metrics hazard and hunk metadata do not match",
            Self::CountOverflow => "group metrics count overflowed",
            Self::Serialization => "group metrics serialization failed",
            Self::OutputTooLarge => "group metrics output exceeds its byte bound",
        })
    }
}

impl std::error::Error for GroupMetricsError {}

/// Join exact group, hunk, and hazard metadata into deterministic metrics.
///
/// Input order is irrelevant. Paths and hunk identifiers in output are sorted.
/// The inline decision always applies to the complete group diff.
///
/// # Errors
///
/// Rejects invalid policy bounds, missing/duplicate/cross-group facts, malformed
/// hunk manifests, hazard mismatches, or arithmetic overflow.
pub fn build_group_metrics(
    group: &ReviewGroup,
    manifests: impl IntoIterator<Item = GroupFileManifest>,
    hazards: impl IntoIterator<Item = DiffHazardReport>,
    policy: GroupMetricsPolicy,
) -> Result<ReviewGroupMetricsReport, GroupMetricsError> {
    validate_policy(policy)?;
    if group.files.is_empty() || group.files.len() > MAX_GROUP_FILES {
        return Err(GroupMetricsError::InvalidGroup);
    }
    let selected = group
        .files
        .iter()
        .map(|file| (file.path.new_path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    if selected.len() != group.files.len() {
        return Err(GroupMetricsError::InvalidGroup);
    }
    let selected_bytes = group
        .files
        .iter()
        .try_fold(0_u64, |total, file| total.checked_add(file.input_bytes));
    let selected_anchors = group.files.iter().try_fold(0_u32, |total, file| {
        u32::try_from(file.anchor_ids.len())
            .ok()
            .and_then(|anchors| total.checked_add(anchors))
    });
    if selected_bytes != Some(group.input_bytes) || selected_anchors != Some(group.anchor_count) {
        return Err(GroupMetricsError::InvalidGroup);
    }
    let manifests = index_manifests(manifests, &selected)?;
    let hazards = index_hazards(hazards, &selected)?;

    let mut files = Vec::with_capacity(selected.len());
    let mut exact_diff_bytes = 0_u64;
    let mut changed_lines = 0_u32;
    let mut hunk_count = 0_u32;
    let mut page_count = 0_u32;
    let mut max_file_changed_lines = 0_u32;
    for (path, selected_file) in selected {
        let manifest = manifests
            .get(&path)
            .ok_or(GroupMetricsError::MissingManifest)?;
        let hazard = hazards
            .get(&path)
            .ok_or(GroupMetricsError::MissingHazards)?;
        let file = join_file(
            selected_file.tier,
            selected_file.path.kind,
            manifest,
            hazard,
        )?;
        exact_diff_bytes = exact_diff_bytes
            .checked_add(file.exact_diff_bytes)
            .ok_or(GroupMetricsError::CountOverflow)?;
        changed_lines = changed_lines
            .checked_add(file.changed_lines)
            .ok_or(GroupMetricsError::CountOverflow)?;
        hunk_count = hunk_count
            .checked_add(file.hunk_count)
            .ok_or(GroupMetricsError::CountOverflow)?;
        page_count = page_count
            .checked_add(file.page_count)
            .ok_or(GroupMetricsError::CountOverflow)?;
        max_file_changed_lines = max_file_changed_lines.max(file.changed_lines);
        files.push(file);
    }
    let file_count = u32::try_from(files.len()).map_err(|_| GroupMetricsError::CountOverflow)?;
    let conservative_diff_tokens = exact_diff_bytes;
    let estimated_request_tokens = policy
        .fixed_context_tokens
        .checked_add(conservative_diff_tokens)
        .ok_or(GroupMetricsError::CountOverflow)?;
    let context = if exact_diff_bytes > 0
        && exact_diff_bytes <= policy.inline_diff_bytes
        && estimated_request_tokens <= policy.request_input_tokens
    {
        GroupInitialContext::InlineCompleteGroup
    } else {
        GroupInitialContext::ManifestOnly
    };
    let planning = GroupPlanningMetrics {
        max_file_changed_lines,
        total_changed_lines: changed_lines,
        file_threshold: FILE_PLANNING_THRESHOLD,
        group_threshold: GROUP_PLANNING_THRESHOLD,
        required: max_file_changed_lines >= FILE_PLANNING_THRESHOLD
            || changed_lines >= GROUP_PLANNING_THRESHOLD,
    };
    Ok(ReviewGroupMetricsReport {
        schema_version: ReviewGroupMetricsReport::SCHEMA_VERSION.to_owned(),
        group_id: group.id.clone(),
        file_count,
        exact_diff_bytes,
        changed_lines,
        hunk_count,
        page_count,
        planning,
        inline: GroupInlineMetrics {
            context,
            exact_diff_bytes,
            conservative_diff_tokens,
            estimated_request_tokens,
        },
        files,
    })
}

fn validate_policy(policy: GroupMetricsPolicy) -> Result<(), GroupMetricsError> {
    if policy.inline_diff_bytes == 0
        || policy.inline_diff_bytes > MAX_INLINE_DIFF_BYTES
        || policy.request_input_tokens == 0
        || policy.request_input_tokens > MAX_REQUEST_INPUT_TOKENS
        || policy.fixed_context_tokens > policy.request_input_tokens
    {
        return Err(GroupMetricsError::InvalidPolicy);
    }
    Ok(())
}

fn index_manifests(
    manifests: impl IntoIterator<Item = GroupFileManifest>,
    selected: &BTreeMap<RepositoryPath, &crate::ReviewGroupFile>,
) -> Result<BTreeMap<RepositoryPath, GroupFileManifest>, GroupMetricsError> {
    let mut indexed = BTreeMap::new();
    for manifest in manifests {
        let Some(selected_file) = selected.get(&manifest.path) else {
            return Err(GroupMetricsError::CrossGroupManifest);
        };
        validate_manifest(&manifest)?;
        if manifest.exact_diff_bytes > selected_file.input_bytes {
            return Err(GroupMetricsError::InvalidManifest);
        }
        if indexed.insert(manifest.path.clone(), manifest).is_some() {
            return Err(GroupMetricsError::DuplicateManifest);
        }
    }
    if indexed.len() != selected.len() {
        return Err(GroupMetricsError::MissingManifest);
    }
    Ok(indexed)
}

fn index_hazards(
    hazards: impl IntoIterator<Item = DiffHazardReport>,
    selected: &BTreeMap<RepositoryPath, &crate::ReviewGroupFile>,
) -> Result<BTreeMap<RepositoryPath, DiffHazardReport>, GroupMetricsError> {
    let mut indexed = BTreeMap::new();
    for hazard in hazards {
        if !selected.contains_key(&hazard.path) {
            return Err(GroupMetricsError::CrossGroupHazards);
        }
        hazard
            .validate()
            .map_err(|_| GroupMetricsError::HazardMismatch)?;
        if indexed.insert(hazard.path.clone(), hazard).is_some() {
            return Err(GroupMetricsError::DuplicateHazards);
        }
    }
    if indexed.len() != selected.len() {
        return Err(GroupMetricsError::MissingHazards);
    }
    Ok(indexed)
}

fn validate_manifest(manifest: &GroupFileManifest) -> Result<(), GroupMetricsError> {
    if manifest.hunks.len() > MAX_HUNKS_PER_FILE
        || manifest.metadata_only && !manifest.hunks.is_empty()
        || !manifest.metadata_only && manifest.hunks.is_empty()
    {
        return Err(GroupMetricsError::InvalidManifest);
    }
    let mut observed = BTreeSet::new();
    for hunk in &manifest.hunks {
        if !valid_hunk_id(&hunk.hunk_id)
            || hunk.changed_lines == 0
            || hunk.changed_lines > MAX_CHANGED_LINES_PER_HUNK
            || hunk.pages == 0
            || hunk.pages > MAX_PAGES_PER_HUNK
            || !observed.insert(hunk.hunk_id.clone())
        {
            return Err(GroupMetricsError::InvalidManifest);
        }
    }
    Ok(())
}

fn join_file(
    tier: ReviewValueTier,
    status: FileChangeKind,
    manifest: &GroupFileManifest,
    hazard: &DiffHazardReport,
) -> Result<GroupFileMetrics, GroupMetricsError> {
    if manifest.status != status
        || manifest.path != hazard.path
        || manifest.status != hazard.status
        || tier != hazard.original_tier
        || manifest.hunks.len() != hazard.hunks.len()
    {
        return Err(GroupMetricsError::HazardMismatch);
    }
    let hazard_hunks = hazard
        .hunks
        .iter()
        .map(|hunk| (hunk.hunk_id.as_str(), hunk))
        .collect::<BTreeMap<_, _>>();
    let mut hunks = Vec::with_capacity(manifest.hunks.len());
    let mut changed_lines = 0_u32;
    let mut page_count = 0_u32;
    for hunk in &manifest.hunks {
        let hazard_hunk = hazard_hunks
            .get(hunk.hunk_id.as_str())
            .ok_or(GroupMetricsError::HazardMismatch)?;
        if hazard_hunk.total_pages != hunk.pages {
            return Err(GroupMetricsError::HazardMismatch);
        }
        changed_lines = changed_lines
            .checked_add(hunk.changed_lines)
            .ok_or(GroupMetricsError::CountOverflow)?;
        page_count = page_count
            .checked_add(hunk.pages)
            .ok_or(GroupMetricsError::CountOverflow)?;
        let hazardous = hazard_hunk.inspection == DiffHazardInspection::AllPages
            && tier != ReviewValueTier::High;
        let coverage = if tier == ReviewValueTier::High || hazardous {
            GroupHunkCoverageRequirement::AllPages
        } else if tier == ReviewValueTier::Standard {
            GroupHunkCoverageRequirement::StandardSampleOrDisposition
        } else {
            GroupHunkCoverageRequirement::ManifestDeferrable
        };
        hunks.push(GroupHunkMetrics {
            hunk_id: hunk.hunk_id.clone(),
            changed_lines: hunk.changed_lines,
            pages: hunk.pages,
            hazardous,
            coverage,
        });
    }
    hunks.sort_by(|left, right| left.hunk_id.cmp(&right.hunk_id));
    let hunk_count = u32::try_from(hunks.len()).map_err(|_| GroupMetricsError::CountOverflow)?;
    let minimum_delivered_hunks = match tier {
        ReviewValueTier::High => hunk_count,
        ReviewValueTier::Standard if hunk_count > 0 => 1,
        ReviewValueTier::Low | ReviewValueTier::Standard => 0,
    };
    Ok(GroupFileMetrics {
        path: manifest.path.clone(),
        status: manifest.status,
        original_tier: tier,
        effective_tier: hazard.effective_tier,
        exact_diff_bytes: manifest.exact_diff_bytes,
        changed_lines,
        hunk_count,
        page_count,
        metadata_only: manifest.metadata_only,
        manifest_required: true,
        minimum_delivered_hunks,
        hunks,
    })
}

fn valid_hunk_id(hunk_id: &str) -> bool {
    !hunk_id.is_empty()
        && hunk_id.len() <= MAX_HUNK_ID_BYTES
        && hunk_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use crate::{
        ChangedPath, DiffHazardFileInput, DiffHazardHunkInput, DiffHazardToken,
        DiffHunkLineClasses, ReviewGroupFile, classify_diff_hazards,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn derives_exact_group_totals_and_planning_inputs() {
        let group = group(&[
            ("src/a.rs", ReviewValueTier::Standard),
            ("src/b.rs", ReviewValueTier::Standard),
        ]);
        let manifests = vec![
            manifest("src/a.rs", 40, 2, 100),
            manifest("src/b.rs", 60, 3, 200),
        ];
        let hazards = manifests
            .iter()
            .map(|manifest| hazard(manifest, ReviewValueTier::Standard, &BTreeSet::new()))
            .collect::<Vec<_>>();
        let metrics =
            build_group_metrics(&group, manifests, hazards, GroupMetricsPolicy::default())
                .expect("metrics");
        assert_eq!(metrics.file_count, 2);
        assert_eq!(metrics.exact_diff_bytes, 300);
        assert_eq!(metrics.changed_lines, 100);
        assert_eq!(metrics.hunk_count, 2);
        assert_eq!(metrics.page_count, 5);
        assert_eq!(metrics.planning.max_file_changed_lines, 60);
        assert!(metrics.planning.required);
    }

    #[test]
    fn planning_uses_fixed_file_or_group_thresholds() {
        let group = group(&[
            ("src/a.rs", ReviewValueTier::Standard),
            ("src/b.rs", ReviewValueTier::Standard),
        ]);
        let manifests = vec![
            manifest("src/a.rs", 49, 1, 100),
            manifest("src/b.rs", 49, 1, 100),
        ];
        let hazards = manifests
            .iter()
            .map(|manifest| hazard(manifest, ReviewValueTier::Standard, &BTreeSet::new()))
            .collect::<Vec<_>>();
        let metrics =
            build_group_metrics(&group, manifests, hazards, GroupMetricsPolicy::default())
                .expect("metrics");
        assert!(!metrics.planning.required);

        let manifests = vec![
            manifest("src/a.rs", 50, 1, 100),
            manifest("src/b.rs", 49, 1, 100),
        ];
        let hazards = manifests
            .iter()
            .map(|manifest| hazard(manifest, ReviewValueTier::Standard, &BTreeSet::new()))
            .collect::<Vec<_>>();
        assert!(
            build_group_metrics(&group, manifests, hazards, GroupMetricsPolicy::default())
                .expect("metrics")
                .planning
                .required
        );
    }

    #[test]
    fn inline_decision_is_complete_group_or_manifest_only() {
        let group = group(&[
            ("src/a.rs", ReviewValueTier::Standard),
            ("src/b.rs", ReviewValueTier::Standard),
        ]);
        let manifests = vec![
            manifest("src/a.rs", 10, 1, 8_000),
            manifest("src/b.rs", 10, 1, 8_000),
        ];
        let hazards = manifests
            .iter()
            .map(|manifest| hazard(manifest, ReviewValueTier::Standard, &BTreeSet::new()))
            .collect::<Vec<_>>();
        let inline = build_group_metrics(
            &group,
            manifests.clone(),
            hazards,
            GroupMetricsPolicy::default(),
        )
        .expect("inline");
        assert_eq!(
            inline.inline.context,
            GroupInitialContext::InlineCompleteGroup
        );

        let mut oversized = manifests.clone();
        oversized[1].exact_diff_bytes = 8_500;
        let hazards = oversized
            .iter()
            .map(|manifest| hazard(manifest, ReviewValueTier::Standard, &BTreeSet::new()))
            .collect::<Vec<_>>();
        let manifest_only =
            build_group_metrics(&group, oversized, hazards, GroupMetricsPolicy::default())
                .expect("manifest only");
        assert_eq!(
            manifest_only.inline.context,
            GroupInitialContext::ManifestOnly
        );

        let hazards = manifests
            .iter()
            .map(|manifest| hazard(manifest, ReviewValueTier::Standard, &BTreeSet::new()))
            .collect::<Vec<_>>();
        let token_limited = build_group_metrics(
            &group,
            manifests,
            hazards,
            GroupMetricsPolicy {
                fixed_context_tokens: 90_000,
                ..GroupMetricsPolicy::default()
            },
        )
        .expect("token limited");
        assert_eq!(
            token_limited.inline.context,
            GroupInitialContext::ManifestOnly
        );
    }

    #[test]
    fn coverage_requirements_combine_tier_and_hazards() {
        let group = group(&[
            ("low.txt", ReviewValueTier::Low),
            ("src/standard.rs", ReviewValueTier::Standard),
            ("src/high.rs", ReviewValueTier::High),
        ]);
        let manifests = vec![
            manifest("low.txt", 2, 2, 20),
            manifest("src/standard.rs", 2, 2, 20),
            manifest("src/high.rs", 2, 2, 20),
        ];
        let hazards = vec![
            hazard(
                &manifests[0],
                ReviewValueTier::Low,
                &BTreeSet::from([DiffHazardToken::IgnoredError]),
            ),
            hazard(&manifests[1], ReviewValueTier::Standard, &BTreeSet::new()),
            hazard(&manifests[2], ReviewValueTier::High, &BTreeSet::new()),
        ];
        let metrics =
            build_group_metrics(&group, manifests, hazards, GroupMetricsPolicy::default())
                .expect("metrics");
        assert_eq!(
            metrics.files[0].hunks[0].coverage,
            GroupHunkCoverageRequirement::AllPages
        );
        assert!(metrics.files[0].hunks[0].hazardous);
        let standard = metrics
            .files
            .iter()
            .find(|file| file.path.as_str() == "src/standard.rs")
            .expect("standard file");
        assert_eq!(
            standard.hunks[0].coverage,
            GroupHunkCoverageRequirement::StandardSampleOrDisposition
        );
        assert_eq!(standard.minimum_delivered_hunks, 1);
        let high = metrics
            .files
            .iter()
            .find(|file| file.path.as_str() == "src/high.rs")
            .expect("high file");
        assert_eq!(
            high.hunks[0].coverage,
            GroupHunkCoverageRequirement::AllPages
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_cross_group_facts() {
        let group = group(&[
            ("src/a.rs", ReviewValueTier::Standard),
            ("src/b.rs", ReviewValueTier::Standard),
        ]);
        let a = manifest("src/a.rs", 10, 1, 20);
        let b = manifest("src/b.rs", 10, 1, 20);
        let hazards = vec![
            hazard(&a, ReviewValueTier::Standard, &BTreeSet::new()),
            hazard(&b, ReviewValueTier::Standard, &BTreeSet::new()),
        ];
        assert_eq!(
            build_group_metrics(
                &group,
                vec![a.clone()],
                hazards.clone(),
                GroupMetricsPolicy::default()
            )
            .expect_err("missing"),
            GroupMetricsError::MissingManifest
        );
        assert_eq!(
            build_group_metrics(
                &group,
                vec![a.clone(), a],
                hazards.clone(),
                GroupMetricsPolicy::default()
            )
            .expect_err("duplicate"),
            GroupMetricsError::DuplicateManifest
        );
        let outside = manifest("src/outside.rs", 10, 1, 20);
        assert_eq!(
            build_group_metrics(
                &group,
                vec![b, outside],
                hazards,
                GroupMetricsPolicy::default()
            )
            .expect_err("cross group"),
            GroupMetricsError::CrossGroupManifest
        );
    }

    #[test]
    fn rejects_hunk_page_status_and_tier_mismatches() {
        let group = group(&[("src/a.rs", ReviewValueTier::Standard)]);
        let manifest = manifest("src/a.rs", 10, 2, 20);
        let mut wrong_pages = hazard(&manifest, ReviewValueTier::Standard, &BTreeSet::new());
        wrong_pages.hunks[0].total_pages = 1;
        assert_eq!(
            build_group_metrics(
                &group,
                vec![manifest.clone()],
                vec![wrong_pages],
                GroupMetricsPolicy::default()
            )
            .expect_err("pages"),
            GroupMetricsError::HazardMismatch
        );

        let wrong_tier = hazard(&manifest, ReviewValueTier::Low, &BTreeSet::new());
        assert_eq!(
            build_group_metrics(
                &group,
                vec![manifest],
                vec![wrong_tier],
                GroupMetricsPolicy::default()
            )
            .expect_err("tier"),
            GroupMetricsError::HazardMismatch
        );
    }

    #[test]
    fn output_is_stable_and_contains_no_body_or_token_fields() {
        let group = group(&[
            ("src/a.rs", ReviewValueTier::Standard),
            ("src/b.rs", ReviewValueTier::Standard),
        ]);
        let mut manifests = vec![
            manifest("src/b.rs", 10, 1, 20),
            manifest("src/a.rs", 10, 1, 20),
        ];
        let mut hazards = manifests
            .iter()
            .map(|manifest| hazard(manifest, ReviewValueTier::Standard, &BTreeSet::new()))
            .collect::<Vec<_>>();
        let first = build_group_metrics(
            &group,
            manifests.clone(),
            hazards.clone(),
            GroupMetricsPolicy::default(),
        )
        .expect("metrics")
        .canonical_json()
        .expect("JSON");
        manifests.reverse();
        hazards.reverse();
        let second = build_group_metrics(&group, manifests, hazards, GroupMetricsPolicy::default())
            .expect("metrics")
            .canonical_json()
            .expect("JSON");
        assert_eq!(first, second);
        let text = String::from_utf8(first).expect("UTF-8 JSON");
        for absent in [
            "\"tokens\"",
            "\"body\"",
            "\"content\"",
            "\"patch\"",
            "\"source\"",
        ] {
            assert!(!text.contains(absent));
        }
    }

    fn group(files: &[(&str, ReviewValueTier)]) -> ReviewGroup {
        let files = files
            .iter()
            .map(|(path, tier)| {
                let path = RepositoryPath::try_from((*path).to_owned()).expect("path");
                ReviewGroupFile {
                    path: ChangedPath {
                        old_path: path.clone(),
                        new_path: path,
                        kind: FileChangeKind::Modified,
                    },
                    tier: *tier,
                    input_bytes: 20_000,
                    anchor_ids: Vec::new(),
                    work_unit_id: serde_json::from_value(json!("wu-1")).expect("work unit"),
                }
            })
            .collect::<Vec<_>>();
        ReviewGroup {
            id: serde_json::from_value(json!("rg-group")).expect("group ID"),
            input_bytes: u64::try_from(files.len()).expect("files") * 20_000,
            anchor_count: 0,
            files,
        }
    }

    fn manifest(path: &str, changed_lines: u32, pages: u32, bytes: u64) -> GroupFileManifest {
        GroupFileManifest {
            path: RepositoryPath::try_from(path.to_owned()).expect("path"),
            status: FileChangeKind::Modified,
            exact_diff_bytes: bytes,
            metadata_only: false,
            hunks: vec![GroupHunkManifest {
                hunk_id: "hunk-1".to_owned(),
                changed_lines,
                pages,
            }],
        }
    }

    fn hazard(
        manifest: &GroupFileManifest,
        tier: ReviewValueTier,
        tokens: &BTreeSet<DiffHazardToken>,
    ) -> DiffHazardReport {
        classify_diff_hazards(&DiffHazardFileInput {
            path: manifest.path.clone(),
            status: manifest.status,
            tier,
            hunks: manifest
                .hunks
                .iter()
                .map(|hunk| DiffHazardHunkInput {
                    hunk_id: hunk.hunk_id.clone(),
                    total_pages: hunk.pages,
                    lines: DiffHunkLineClasses {
                        added: hunk.changed_lines,
                        deleted: 0,
                        context: 0,
                    },
                    tokens: tokens.clone(),
                })
                .collect(),
        })
        .expect("hazard")
    }
}
