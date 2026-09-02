//! Trusted metadata derivation for grouping and isolated review workers.
//!
//! This module joins the immutable partition, private artifact index, and
//! deterministic rule resolution without reading or retaining diff bodies.

use std::collections::{BTreeMap, BTreeSet};

use revoot_core::{
    FileChangeKind, GroupFileManifest, GroupHunkManifest, RepositoryPath, RepositoryRelativePath,
    ReviewGroup, ReviewGroupPlan, ReviewObjectRole, ReviewPartitionPlan, ReviewValueReason,
    Sha256Digest, WorkUnitId,
};
use serde::Serialize;

use crate::diff_artifact::{DiffArtifactError, DiffArtifactStore, DiffFileManifest};
use crate::grouping::{GroupingDependencyHint, GroupingDependencyKind, GroupingFileFacts};
use crate::rule_diagnostics::{RuleDiagnosticPolicy, RuleDiagnosticsError, diagnose_rules};

const RULE_DIAGNOSTIC_BATCH: usize = 32;
const MAX_RULE_IDS_PER_FILE: usize = 32;
const MAX_DEPENDENCY_HINTS_PER_FILE: usize = 64;
const MAX_CHANGED_LINES_PER_FILE: u32 = 10_000_000;

/// Integrity-bound selected-file metadata used before and after grouping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedSelectedReviewInputs {
    partition_sha256: Sha256Digest,
    input_sha256: Sha256Digest,
    grouping_facts: Vec<GroupingFileFacts>,
    files: BTreeMap<RepositoryPath, TrustedSelectedFile>,
}

impl TrustedSelectedReviewInputs {
    #[must_use]
    pub fn partition_sha256(&self) -> &Sha256Digest {
        &self.partition_sha256
    }

    #[must_use]
    pub fn input_sha256(&self) -> &Sha256Digest {
        &self.input_sha256
    }

    #[must_use]
    pub fn grouping_facts(&self) -> &[GroupingFileFacts] {
        &self.grouping_facts
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedSelectedFile {
    artifact_sha256: Sha256Digest,
    work_unit_id: WorkUnitId,
    rule_ids: Vec<String>,
    manifest: GroupFileManifest,
}

/// One body-free file input bound to an exact private artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedGroupFileInput {
    pub artifact_sha256: Sha256Digest,
    pub work_unit_id: WorkUnitId,
    pub rule_ids: Vec<String>,
    pub manifest: GroupFileManifest,
}

/// Complete body-free trusted input for one isolated group worker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedReviewGroupInput {
    pub partition_sha256: Sha256Digest,
    pub group_plan_sha256: Sha256Digest,
    pub selected_input_sha256: Sha256Digest,
    pub group: ReviewGroup,
    pub file_count: u32,
    pub exact_diff_bytes: u64,
    pub changed_line_count: u32,
    pub hunk_count: u32,
    pub files: Vec<TrustedGroupFileInput>,
}

/// Payload-free trusted-input derivation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewGroupInputError {
    Partition,
    Artifact,
    ArtifactSet,
    Path,
    DuplicatePath,
    ExactDiffObject,
    ExactDiffDigest,
    ExactDiffSize,
    RuleDiagnostics,
    RuleCapacity,
    CountCapacity,
    Serialization,
    SelectedDigest,
    GroupPlan,
    GroupAssignment,
}

/// Derive exact metadata-only grouping facts from the trusted preparation state.
///
/// Artifact digests and sizes must match the partition's exact-diff objects.
/// Rules are resolved in bounded batches and retained only as identifiers.
/// Dependency hints come exclusively from deterministic path/status metadata.
///
/// # Errors
///
/// Rejects invalid partitions, missing/extra/mismatched artifacts, invalid rule
/// metadata, arithmetic overflow, or fixed grouping-capacity violations.
pub fn derive_selected_review_inputs(
    partition: &ReviewPartitionPlan,
    artifacts: &DiffArtifactStore,
    rule_policy: &RuleDiagnosticPolicy,
) -> Result<TrustedSelectedReviewInputs, ReviewGroupInputError> {
    partition
        .validate_replay()
        .map_err(|_| ReviewGroupInputError::Partition)?;
    let selected = selected_files(partition)?;
    if selected.len() != artifacts.artifact_count() {
        return Err(ReviewGroupInputError::ArtifactSet);
    }
    let relative_paths = selected
        .keys()
        .map(|path| {
            RepositoryRelativePath::try_from(path.as_str().to_owned())
                .map_err(|_| ReviewGroupInputError::Path)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifests = artifacts
        .manifest(&relative_paths)
        .map_err(map_artifact_error)?;
    if manifests.len() != selected.len() {
        return Err(ReviewGroupInputError::ArtifactSet);
    }
    let rules = resolve_rule_ids(selected.keys(), rule_policy)?;
    let dependencies = derive_dependencies(&selected);
    let mut files = BTreeMap::new();
    let mut grouping_facts = Vec::with_capacity(selected.len());
    for manifest in manifests {
        let path = RepositoryPath::try_from(manifest.path.as_str().to_owned())
            .map_err(|_| ReviewGroupInputError::Path)?;
        let file = selected
            .get(&path)
            .ok_or(ReviewGroupInputError::ArtifactSet)?;
        validate_exact_diff(file.file, &manifest)?;
        let group_manifest = convert_manifest(file.file.path.kind, &path, &manifest)?;
        let changed_line_count = group_manifest
            .hunks
            .iter()
            .try_fold(0_u32, |total, hunk| total.checked_add(hunk.changed_lines))
            .ok_or(ReviewGroupInputError::CountCapacity)?;
        if changed_line_count > MAX_CHANGED_LINES_PER_FILE {
            return Err(ReviewGroupInputError::CountCapacity);
        }
        let rule_ids = rules
            .get(&path)
            .cloned()
            .ok_or(ReviewGroupInputError::RuleDiagnostics)?;
        let dependency_hints = dependencies.get(&path).cloned().unwrap_or_default();
        grouping_facts.push(GroupingFileFacts {
            path: path.clone(),
            rule_ids: rule_ids.clone(),
            changed_line_count,
            hunk_count: u32::try_from(group_manifest.hunks.len())
                .map_err(|_| ReviewGroupInputError::CountCapacity)?,
            dependency_hints,
        });
        if files
            .insert(
                path,
                TrustedSelectedFile {
                    artifact_sha256: manifest.sha256,
                    work_unit_id: file.work_unit_id.clone(),
                    rule_ids,
                    manifest: group_manifest,
                },
            )
            .is_some()
        {
            return Err(ReviewGroupInputError::DuplicatePath);
        }
    }
    grouping_facts.sort_by(|left, right| left.path.cmp(&right.path));
    if files.len() != selected.len() || grouping_facts.len() != selected.len() {
        return Err(ReviewGroupInputError::ArtifactSet);
    }
    let partition_sha256 = partition.plan_sha256.clone();
    let input_sha256 = derive_selected_digest(&partition_sha256, &grouping_facts, &files)?;
    Ok(TrustedSelectedReviewInputs {
        partition_sha256,
        input_sha256,
        grouping_facts,
        files,
    })
}

/// Bind derived selected-file inputs to every group in a validated group plan.
///
/// # Errors
///
/// Rejects stale/tampered selected inputs, a group plan from another partition,
/// incomplete assignments, or aggregate count overflow.
pub fn derive_review_group_inputs(
    partition: &ReviewPartitionPlan,
    group_plan: &ReviewGroupPlan,
    selected: &TrustedSelectedReviewInputs,
) -> Result<Vec<TrustedReviewGroupInput>, ReviewGroupInputError> {
    partition
        .validate_replay()
        .map_err(|_| ReviewGroupInputError::Partition)?;
    group_plan
        .validate_against(partition)
        .map_err(|_| ReviewGroupInputError::GroupPlan)?;
    validate_selected(partition, selected)?;
    let mut assigned = BTreeSet::new();
    let mut inputs = Vec::with_capacity(group_plan.groups.len());
    for group in &group_plan.groups {
        let mut exact_diff_bytes = 0_u64;
        let mut changed_line_count = 0_u32;
        let mut hunk_count = 0_u32;
        let mut files = Vec::with_capacity(group.files.len());
        for group_file in &group.files {
            let path = &group_file.path.new_path;
            if !assigned.insert(path.clone()) {
                return Err(ReviewGroupInputError::GroupAssignment);
            }
            let file = selected
                .files
                .get(path)
                .ok_or(ReviewGroupInputError::GroupAssignment)?;
            if file.manifest.status != group_file.path.kind
                || file.manifest.path != *path
                || file.manifest.exact_diff_bytes > group_file.input_bytes
                || file.work_unit_id != group_file.work_unit_id
            {
                return Err(ReviewGroupInputError::GroupAssignment);
            }
            exact_diff_bytes = exact_diff_bytes
                .checked_add(file.manifest.exact_diff_bytes)
                .ok_or(ReviewGroupInputError::CountCapacity)?;
            let file_changed_lines = file
                .manifest
                .hunks
                .iter()
                .try_fold(0_u32, |total, hunk| total.checked_add(hunk.changed_lines))
                .ok_or(ReviewGroupInputError::CountCapacity)?;
            changed_line_count = changed_line_count
                .checked_add(file_changed_lines)
                .ok_or(ReviewGroupInputError::CountCapacity)?;
            hunk_count = hunk_count
                .checked_add(
                    u32::try_from(file.manifest.hunks.len())
                        .map_err(|_| ReviewGroupInputError::CountCapacity)?,
                )
                .ok_or(ReviewGroupInputError::CountCapacity)?;
            files.push(TrustedGroupFileInput {
                artifact_sha256: file.artifact_sha256.clone(),
                work_unit_id: file.work_unit_id.clone(),
                rule_ids: file.rule_ids.clone(),
                manifest: file.manifest.clone(),
            });
        }
        files.sort_by(|left, right| left.manifest.path.cmp(&right.manifest.path));
        inputs.push(TrustedReviewGroupInput {
            partition_sha256: partition.plan_sha256.clone(),
            group_plan_sha256: group_plan.plan_sha256.clone(),
            selected_input_sha256: selected.input_sha256.clone(),
            group: group.clone(),
            file_count: u32::try_from(files.len())
                .map_err(|_| ReviewGroupInputError::CountCapacity)?,
            exact_diff_bytes,
            changed_line_count,
            hunk_count,
            files,
        });
    }
    if assigned.len() != selected.files.len() {
        return Err(ReviewGroupInputError::GroupAssignment);
    }
    Ok(inputs)
}

fn selected_files(
    partition: &ReviewPartitionPlan,
) -> Result<BTreeMap<RepositoryPath, SelectedPartitionFile<'_>>, ReviewGroupInputError> {
    let mut selected = BTreeMap::new();
    for unit in &partition.work_units {
        for file in &unit.files {
            if selected
                .insert(
                    file.path.new_path.clone(),
                    SelectedPartitionFile {
                        file,
                        work_unit_id: &unit.id,
                    },
                )
                .is_some()
            {
                return Err(ReviewGroupInputError::DuplicatePath);
            }
        }
    }
    Ok(selected)
}

#[derive(Clone, Copy)]
struct SelectedPartitionFile<'a> {
    file: &'a revoot_core::WorkUnitFile,
    work_unit_id: &'a WorkUnitId,
}

fn validate_exact_diff(
    file: &revoot_core::WorkUnitFile,
    manifest: &DiffFileManifest,
) -> Result<(), ReviewGroupInputError> {
    let mut exact = file
        .objects
        .iter()
        .filter(|object| object.role == ReviewObjectRole::ExactDiff);
    let object = exact.next().ok_or(ReviewGroupInputError::ExactDiffObject)?;
    if exact.next().is_some() {
        return Err(ReviewGroupInputError::ExactDiffObject);
    }
    if object.content_sha256 != manifest.sha256 {
        return Err(ReviewGroupInputError::ExactDiffDigest);
    }
    if object.size_bytes != manifest.size_bytes {
        return Err(ReviewGroupInputError::ExactDiffSize);
    }
    Ok(())
}

fn convert_manifest(
    status: FileChangeKind,
    path: &RepositoryPath,
    manifest: &DiffFileManifest,
) -> Result<GroupFileManifest, ReviewGroupInputError> {
    let hunks = manifest
        .hunks
        .iter()
        .map(|hunk| {
            if hunk.changed_lines == 0 || hunk.pages == 0 {
                return Err(ReviewGroupInputError::CountCapacity);
            }
            Ok(GroupHunkManifest {
                hunk_id: hunk.hunk_id.clone(),
                changed_lines: hunk.changed_lines,
                pages: hunk.pages,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if hunks.is_empty() && status != FileChangeKind::Renamed {
        return Err(ReviewGroupInputError::CountCapacity);
    }
    Ok(GroupFileManifest {
        path: path.clone(),
        status,
        exact_diff_bytes: manifest.size_bytes,
        metadata_only: hunks.is_empty(),
        hunks,
    })
}

fn resolve_rule_ids<'a>(
    paths: impl Iterator<Item = &'a RepositoryPath>,
    policy: &RuleDiagnosticPolicy,
) -> Result<BTreeMap<RepositoryPath, Vec<String>>, ReviewGroupInputError> {
    let paths = paths
        .map(|path| path.as_str().to_owned())
        .collect::<Vec<_>>();
    let mut rules = BTreeMap::new();
    for batch in paths.chunks(RULE_DIAGNOSTIC_BATCH) {
        let report = diagnose_rules(batch.iter().cloned(), policy).map_err(map_rule_error)?;
        for diagnostic in report.paths {
            let path = RepositoryPath::try_from(diagnostic.path.as_str().to_owned())
                .map_err(|_| ReviewGroupInputError::Path)?;
            let mut rule_ids = diagnostic
                .trace
                .into_iter()
                .filter(|trace| trace.active)
                .flat_map(|trace| trace.rule_ids)
                .collect::<Vec<_>>();
            rule_ids.sort();
            rule_ids.dedup();
            if rule_ids.is_empty() || rule_ids.len() > MAX_RULE_IDS_PER_FILE {
                return Err(ReviewGroupInputError::RuleCapacity);
            }
            if rules.insert(path, rule_ids).is_some() {
                return Err(ReviewGroupInputError::DuplicatePath);
            }
        }
    }
    if rules.len() != paths.len() {
        return Err(ReviewGroupInputError::RuleDiagnostics);
    }
    Ok(rules)
}

fn derive_dependencies(
    selected: &BTreeMap<RepositoryPath, SelectedPartitionFile<'_>>,
) -> BTreeMap<RepositoryPath, Vec<GroupingDependencyHint>> {
    let mut candidates = selected
        .keys()
        .cloned()
        .map(|path| (path, Vec::<(u8, GroupingDependencyHint)>::new()))
        .collect::<BTreeMap<_, _>>();
    let files = selected
        .values()
        .map(|selected| selected.file)
        .collect::<Vec<_>>();
    for (index, left) in files.iter().enumerate() {
        for right in files.iter().skip(index + 1) {
            let Some((priority, kind)) = dependency_kind(left, right) else {
                continue;
            };
            candidates
                .get_mut(&left.path.new_path)
                .expect("selected dependency path")
                .push((
                    priority,
                    GroupingDependencyHint {
                        related_path: right.path.new_path.clone(),
                        kind,
                    },
                ));
            candidates
                .get_mut(&right.path.new_path)
                .expect("selected dependency path")
                .push((
                    priority,
                    GroupingDependencyHint {
                        related_path: left.path.new_path.clone(),
                        kind,
                    },
                ));
        }
    }
    candidates
        .into_iter()
        .map(|(path, mut hints)| {
            hints.sort_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then_with(|| left.1.related_path.cmp(&right.1.related_path))
                    .then_with(|| left.1.kind.cmp(&right.1.kind))
            });
            hints.truncate(MAX_DEPENDENCY_HINTS_PER_FILE);
            let mut hints = hints.into_iter().map(|(_, hint)| hint).collect::<Vec<_>>();
            hints.sort();
            (path, hints)
        })
        .collect()
}

fn dependency_kind(
    left: &revoot_core::WorkUnitFile,
    right: &revoot_core::WorkUnitFile,
) -> Option<(u8, GroupingDependencyKind)> {
    if left.path.old_path == right.path.new_path || right.path.old_path == left.path.new_path {
        return Some((0, GroupingDependencyKind::RenamePair));
    }
    if manifest_scopes(left, right) || manifest_scopes(right, left) {
        return Some((1, GroupingDependencyKind::ManifestScope));
    }
    let left_stem = file_stem(&left.path.new_path);
    if !left_stem.is_empty() && left_stem == file_stem(&right.path.new_path) {
        return Some((2, GroupingDependencyKind::SharedStem));
    }
    (parent(&left.path.new_path) == parent(&right.path.new_path))
        .then_some((3, GroupingDependencyKind::SameDirectory))
}

fn manifest_scopes(
    manifest: &revoot_core::WorkUnitFile,
    other: &revoot_core::WorkUnitFile,
) -> bool {
    if !manifest
        .review_value
        .reasons
        .contains(&ReviewValueReason::DependencyManifest)
    {
        return false;
    }
    let scope = parent(&manifest.path.new_path);
    scope.is_empty()
        || other
            .path
            .new_path
            .as_str()
            .starts_with(&format!("{scope}/"))
}

fn parent(path: &RepositoryPath) -> &str {
    path.as_str()
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent)
}

fn file_stem(path: &RepositoryPath) -> &str {
    let name = path.as_str().rsplit('/').next().unwrap_or(path.as_str());
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

fn validate_selected(
    partition: &ReviewPartitionPlan,
    selected: &TrustedSelectedReviewInputs,
) -> Result<(), ReviewGroupInputError> {
    if selected.partition_sha256 != partition.plan_sha256 {
        return Err(ReviewGroupInputError::SelectedDigest);
    }
    let partition_paths = selected_files(partition)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    if partition_paths != selected.files.keys().cloned().collect()
        || partition_paths
            != selected
                .grouping_facts
                .iter()
                .map(|facts| facts.path.clone())
                .collect()
    {
        return Err(ReviewGroupInputError::GroupAssignment);
    }
    let expected = derive_selected_digest(
        &selected.partition_sha256,
        &selected.grouping_facts,
        &selected.files,
    )?;
    if expected != selected.input_sha256 {
        return Err(ReviewGroupInputError::SelectedDigest);
    }
    Ok(())
}

fn derive_selected_digest(
    partition_sha256: &Sha256Digest,
    grouping_facts: &[GroupingFileFacts],
    files: &BTreeMap<RepositoryPath, TrustedSelectedFile>,
) -> Result<Sha256Digest, ReviewGroupInputError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        partition_sha256: &'a Sha256Digest,
        grouping_facts: &'a [GroupingFileFacts],
        files: &'a BTreeMap<RepositoryPath, TrustedSelectedFile>,
    }
    serde_json::to_vec(&DigestInput {
        partition_sha256,
        grouping_facts,
        files,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| ReviewGroupInputError::Serialization)
}

const fn map_artifact_error(_: DiffArtifactError) -> ReviewGroupInputError {
    ReviewGroupInputError::Artifact
}

const fn map_rule_error(_: RuleDiagnosticsError) -> ReviewGroupInputError {
    ReviewGroupInputError::RuleDiagnostics
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use revoot_core::{
        ChangedPath, PartitionLimits, ReviewFileClass, ReviewFileInput, ReviewGroupingSource,
        ReviewObject, ReviewSelectionPolicy, ReviewValue, ReviewValueTier, build_partition_plan,
        build_review_group_plan,
    };

    use crate::rule_diagnostics::RepositoryRuleMetadata;

    use super::*;

    #[test]
    fn derives_exact_body_free_facts_and_group_inputs() {
        let fixtures = fixtures();
        let partition = partition(&fixtures);
        let store = store(&fixtures);
        let selected =
            derive_selected_review_inputs(&partition, &store, &RuleDiagnosticPolicy::default())
                .expect("selected inputs");
        assert_eq!(selected.grouping_facts().len(), fixtures.len());
        assert!(selected.grouping_facts().iter().all(|facts| {
            facts.changed_line_count == 2 && facts.hunk_count == 1 && !facts.rule_ids.is_empty()
        }));
        let plan = build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic)
            .expect("group plan");
        let groups =
            derive_review_group_inputs(&partition, &plan, &selected).expect("group inputs");
        assert_eq!(groups.iter().map(|group| group.file_count).sum::<u32>(), 6);
        assert_eq!(groups.iter().map(|group| group.hunk_count).sum::<u32>(), 6);
        let encoded = serde_json::to_string(&groups).expect("group JSON");
        assert!(!encoded.contains("SECRET_BODY_SENTINEL"));
        assert!(!encoded.contains("@@ -1 +1 @@"));
        assert!(!encoded.contains("header"));
    }

    #[test]
    fn derives_only_allowlisted_deterministic_dependency_kinds() {
        let fixtures = fixtures();
        let partition = partition(&fixtures);
        let store = store(&fixtures);
        let first =
            derive_selected_review_inputs(&partition, &store, &RuleDiagnosticPolicy::default())
                .expect("first");
        let second =
            derive_selected_review_inputs(&partition, &store, &RuleDiagnosticPolicy::default())
                .expect("second");
        assert_eq!(first.grouping_facts(), second.grouping_facts());
        let kinds = first
            .grouping_facts()
            .iter()
            .flat_map(|facts| &facts.dependency_hints)
            .map(|hint| hint.kind)
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains(&GroupingDependencyKind::SameDirectory));
        assert!(kinds.contains(&GroupingDependencyKind::SharedStem));
        assert!(kinds.contains(&GroupingDependencyKind::ManifestScope));
        assert!(kinds.contains(&GroupingDependencyKind::RenamePair));
        assert!(!kinds.contains(&GroupingDependencyKind::CallerCallee));
    }

    #[test]
    fn preserves_original_work_unit_binding_across_semantic_groups() {
        let fixtures = fixtures();
        let partition = partition_with_capacity(&fixtures, 2);
        assert_eq!(partition.work_units.len(), 3);
        let store = store(&fixtures);
        let selected =
            derive_selected_review_inputs(&partition, &store, &RuleDiagnosticPolicy::default())
                .expect("selected");
        let plan = build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic)
            .expect("cross-work-unit group");
        assert_eq!(plan.groups.len(), 1);
        let groups = derive_review_group_inputs(&partition, &plan, &selected).expect("inputs");
        let work_units = groups[0]
            .files
            .iter()
            .map(|file| file.work_unit_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(work_units.len(), 3);
        for file in &groups[0].files {
            let expected = partition
                .work_units
                .iter()
                .find(|unit| {
                    unit.files
                        .iter()
                        .any(|selected| selected.path.new_path == file.manifest.path)
                })
                .expect("original work unit");
            assert_eq!(file.work_unit_id, expected.id);
        }
    }

    #[test]
    fn rejects_mismatched_or_extra_artifacts() {
        let fixtures = fixtures();
        let partition = partition(&fixtures);
        let mut mismatched = fixtures.clone();
        mismatched[0].diff.push_str("+extra\n");
        assert_eq!(
            derive_selected_review_inputs(
                &partition,
                &store(&mismatched),
                &RuleDiagnosticPolicy::default(),
            ),
            Err(ReviewGroupInputError::ExactDiffDigest)
        );

        let mut extra = fixtures.clone();
        extra.push(Fixture::modified("extra.rs"));
        assert_eq!(
            derive_selected_review_inputs(
                &partition,
                &store(&extra),
                &RuleDiagnosticPolicy::default(),
            ),
            Err(ReviewGroupInputError::ArtifactSet)
        );
    }

    #[test]
    fn rejects_rule_capacity_and_tampered_selected_digest() {
        let fixtures = fixtures();
        let partition = partition(&fixtures);
        let store = store(&fixtures);
        let policy = RuleDiagnosticPolicy {
            base_guidance_present: true,
            repository_rules: (0..32)
                .map(|index| RepositoryRuleMetadata {
                    id: format!("repo:{index}"),
                    path_patterns: vec!["**/*".to_owned()],
                })
                .collect(),
        };
        assert_eq!(
            derive_selected_review_inputs(&partition, &store, &policy),
            Err(ReviewGroupInputError::RuleCapacity)
        );

        let mut selected =
            derive_selected_review_inputs(&partition, &store, &RuleDiagnosticPolicy::default())
                .expect("selected");
        selected.grouping_facts[0].hunk_count = 9;
        let plan = build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic)
            .expect("plan");
        assert_eq!(
            derive_review_group_inputs(&partition, &plan, &selected),
            Err(ReviewGroupInputError::SelectedDigest)
        );
    }

    #[derive(Clone)]
    struct Fixture {
        path: ChangedPath,
        diff: String,
        value: ReviewValue,
    }

    impl Fixture {
        fn modified(path: &str) -> Self {
            let path = RepositoryPath::try_from(path.to_owned()).expect("path");
            Self::with_path(ChangedPath {
                old_path: path.clone(),
                new_path: path,
                kind: FileChangeKind::Modified,
            })
        }

        fn with_path(path: ChangedPath) -> Self {
            let diff = format!(
                "diff --git a/{0} b/{1}\n--- a/{0}\n+++ b/{1}\n@@ -1 +1 @@\n-old\n+SECRET_BODY_SENTINEL\n",
                path.old_path.as_str(),
                path.new_path.as_str()
            );
            let manifest = path.new_path.as_str().ends_with("Cargo.toml");
            Self {
                path,
                diff,
                value: ReviewValue {
                    tier: ReviewValueTier::Standard,
                    score: 100,
                    reasons: BTreeSet::from([if manifest {
                        ReviewValueReason::DependencyManifest
                    } else {
                        ReviewValueReason::SourceCode
                    }]),
                },
            }
        }
    }

    fn fixtures() -> Vec<Fixture> {
        let renamed = Fixture::with_path(ChangedPath {
            old_path: RepositoryPath::try_from("legacy.rs".to_owned()).expect("old"),
            new_path: RepositoryPath::try_from("renamed.rs".to_owned()).expect("new"),
            kind: FileChangeKind::Renamed,
        });
        vec![
            Fixture::modified("Cargo.toml"),
            Fixture::modified("src/foo.rs"),
            Fixture::modified("tests/foo.rs"),
            Fixture::modified("src/bar.rs"),
            Fixture::modified("legacy.rs"),
            renamed,
        ]
    }

    fn partition(fixtures: &[Fixture]) -> ReviewPartitionPlan {
        partition_with_capacity(fixtures, 20)
    }

    fn partition_with_capacity(
        fixtures: &[Fixture],
        max_files_per_work_unit: u32,
    ) -> ReviewPartitionPlan {
        let inputs: Vec<ReviewFileInput> = fixtures
            .iter()
            .map(|fixture| ReviewFileInput {
                path: fixture.path.clone(),
                class: ReviewFileClass::Text,
                review_value: fixture.value.clone(),
                objects: vec![ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: Sha256Digest::of_bytes(fixture.diff.as_bytes()),
                    size_bytes: u64::try_from(fixture.diff.len()).expect("diff size"),
                }],
                anchor_ids: Vec::new(),
            })
            .collect();
        build_partition_plan(
            revoot_core::LocalSnapshotIdentity {
                repository_identity_sha256: Sha256Digest::of_bytes(b"repository"),
                base_sha: "a".repeat(40).try_into().expect("base"),
                head_sha: "b".repeat(40).try_into().expect("head"),
                working_tree_sha256: Sha256Digest::of_bytes(b"tree"),
                exact_diff_manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
            },
            &ReviewSelectionPolicy {
                version: "selection-v1".to_owned(),
                included_paths: BTreeSet::new(),
                included_prefixes: Vec::new(),
                included_suffixes: Vec::new(),
                excluded_paths: BTreeSet::new(),
                excluded_prefixes: Vec::new(),
                excluded_suffixes: Vec::new(),
                excluded_basename_prefixes: Vec::new(),
                include_generated: false,
                max_file_bytes: 10_000,
            },
            PartitionLimits {
                max_files: 100,
                max_total_bytes: 100_000,
                max_work_units: 100,
                max_files_per_work_unit,
                max_bytes_per_work_unit: 20_000,
                max_anchors_per_work_unit: 100,
            },
            inputs,
        )
        .expect("partition")
    }

    fn store(fixtures: &[Fixture]) -> DiffArtifactStore {
        let paths = fixtures
            .iter()
            .map(|fixture| {
                RepositoryRelativePath::try_from(fixture.path.new_path.as_str().to_owned())
                    .expect("relative path")
            })
            .collect::<Vec<_>>();
        DiffArtifactStore::create(
            paths
                .iter()
                .zip(fixtures.iter())
                .map(|(path, fixture)| (path, fixture.diff.as_str())),
            128,
        )
        .expect("artifact store")
    }
}
