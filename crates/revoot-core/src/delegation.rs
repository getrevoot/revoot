//! Deterministic, provider-free delegation contracts.
//!
//! A delegation manifest contains only immutable review metadata. It grants no
//! process, network, repository-write, provider, or publication authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    ChangedPath, PartitionReplayError, RepositoryPath, ReviewFileClass, ReviewOmissionReason,
    ReviewPartitionPlan, ReviewSnapshotIdentity, ReviewValueTier, Sha256Digest, WorkUnitId,
};

const MAX_RULE_GROUPS: usize = 1_024;
const MAX_RULES_PER_GROUP: usize = 1_024;
const MAX_IDENTIFIER_BYTES: usize = 128;

/// Digests binding a delegation manifest to every deterministic policy layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationPolicyDigests {
    /// Digest derived directly from the partition's selection policy.
    pub selection_policy_sha256: Sha256Digest,
    /// Digest of trusted repository guidance resolved for the snapshot.
    pub repository_policy_sha256: Sha256Digest,
    /// Digest of the complete resolved rule set.
    pub rule_set_sha256: Sha256Digest,
}

/// Input used to construct one normalized rule group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRuleGroupInput {
    pub id: String,
    pub rule_ids: Vec<String>,
    pub matched_paths: Vec<RepositoryPath>,
}

/// A deterministic group of rules and the selected paths to which it applies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRuleGroup {
    pub id: String,
    pub rule_ids: Vec<String>,
    pub matched_paths: Vec<RepositoryPath>,
}

/// Metadata for one selected file. No source or diff body is included.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationFile {
    pub path: ChangedPath,
    pub class: ReviewFileClass,
    pub tier: ReviewValueTier,
    pub selected_input_bytes: u64,
    pub anchor_count: u32,
    pub work_unit_id: WorkUnitId,
    pub rule_group_ids: Vec<String>,
}

/// One deterministically excluded file and the exact exclusion reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationExclusion {
    pub path: ChangedPath,
    pub reason: ReviewOmissionReason,
}

/// Snapshot-bound provider-free context for an external review agent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationManifest {
    pub schema_version: String,
    pub snapshot: ReviewSnapshotIdentity,
    pub partition_sha256: Sha256Digest,
    pub policy_digests: DelegationPolicyDigests,
    pub files: Vec<DelegationFile>,
    pub exclusions: Vec<DelegationExclusion>,
    pub rule_groups: Vec<DelegationRuleGroup>,
    pub manifest_sha256: Sha256Digest,
}

impl DelegationManifest {
    pub const SCHEMA_VERSION: &'static str = "revoot.delegation/v1";

    /// Validate the manifest against the authoritative deterministic partition.
    ///
    /// # Errors
    ///
    /// Returns the first binding, ordering, rule, or digest violation.
    pub fn validate_against(&self, partition: &ReviewPartitionPlan) -> Result<(), DelegationError> {
        partition
            .validate_replay()
            .map_err(DelegationError::Partition)?;
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(DelegationError::SchemaVersion);
        }
        if self.snapshot != partition.snapshot || self.partition_sha256 != partition.plan_sha256 {
            return Err(DelegationError::SnapshotBinding);
        }
        if self.policy_digests.selection_policy_sha256 != selection_policy_digest(partition)? {
            return Err(DelegationError::PolicyBinding);
        }
        validate_rule_groups(&self.rule_groups, &selected_paths(partition))?;
        if self.files != selected_files(partition, &self.rule_groups)? {
            return Err(DelegationError::FileBinding);
        }
        if self.exclusions != exclusions(partition) {
            return Err(DelegationError::ExclusionBinding);
        }
        if self.manifest_sha256 != derive_manifest_digest(self)? {
            return Err(DelegationError::ManifestDigest);
        }
        Ok(())
    }

    /// Serialize a validated manifest in stable field and collection order.
    ///
    /// # Errors
    ///
    /// Returns an error when replay validation or JSON serialization fails.
    pub fn canonical_json(
        &self,
        partition: &ReviewPartitionPlan,
    ) -> Result<Vec<u8>, DelegationCanonicalError> {
        self.validate_against(partition)
            .map_err(DelegationCanonicalError::Validation)?;
        serde_json::to_vec(self).map_err(DelegationCanonicalError::Serialization)
    }
}

/// Failure while constructing or validating a delegation manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationError {
    Partition(PartitionReplayError),
    SchemaVersion,
    SnapshotBinding,
    PolicyBinding,
    TooManyRuleGroups,
    DuplicateRuleGroup,
    InvalidRuleGroup,
    InvalidRuleIdentifier,
    UnknownRulePath,
    FileBinding,
    ExclusionBinding,
    CountOverflow,
    ManifestDigest,
    Serialization,
}

impl fmt::Display for DelegationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Partition(_) => "the review partition is invalid",
            Self::SchemaVersion => "the delegation schema version is invalid",
            Self::SnapshotBinding => "the delegation snapshot binding is invalid",
            Self::PolicyBinding => "the delegation policy binding is invalid",
            Self::TooManyRuleGroups => "the delegation contains too many rule groups",
            Self::DuplicateRuleGroup => "the delegation contains a duplicate rule group",
            Self::InvalidRuleGroup => "the delegation contains an invalid rule group",
            Self::InvalidRuleIdentifier => "the delegation contains an invalid rule identifier",
            Self::UnknownRulePath => "a delegation rule group targets an unselected path",
            Self::FileBinding => "the delegated file metadata does not match the partition",
            Self::ExclusionBinding => "the delegated exclusions do not match the partition",
            Self::CountOverflow => "a delegation metadata count overflowed",
            Self::ManifestDigest => "the delegation manifest digest is invalid",
            Self::Serialization => "the delegation manifest could not be serialized",
        })
    }
}

impl std::error::Error for DelegationError {}

/// Error returned by canonical manifest serialization.
#[derive(Debug)]
pub enum DelegationCanonicalError {
    Validation(DelegationError),
    Serialization(serde_json::Error),
}

/// Build a canonical delegation manifest without invoking a provider.
///
/// Input rule groups may arrive in any order. Their identifiers, rule IDs, and
/// matched paths are normalized before the manifest digest is calculated.
///
/// # Errors
///
/// Rejects an invalid partition, unsafe or duplicate identifiers, rule paths
/// outside the selected partition, excessive input, or serialization failure.
pub fn build_delegation_manifest(
    partition: &ReviewPartitionPlan,
    repository_policy_sha256: Sha256Digest,
    rule_set_sha256: Sha256Digest,
    rule_groups: impl IntoIterator<Item = DelegationRuleGroupInput>,
) -> Result<DelegationManifest, DelegationError> {
    partition
        .validate_replay()
        .map_err(DelegationError::Partition)?;
    let selected_paths = selected_paths(partition);
    let mut normalized_groups = Vec::new();
    for rule_group in rule_groups {
        if normalized_groups.len() == MAX_RULE_GROUPS {
            return Err(DelegationError::TooManyRuleGroups);
        }
        normalized_groups.push(normalize_rule_group(rule_group)?);
    }
    let mut rule_groups = normalized_groups;
    rule_groups.sort_by(|left, right| left.id.cmp(&right.id));
    validate_rule_groups(&rule_groups, &selected_paths)?;

    let mut manifest = DelegationManifest {
        schema_version: DelegationManifest::SCHEMA_VERSION.to_owned(),
        snapshot: partition.snapshot.clone(),
        partition_sha256: partition.plan_sha256.clone(),
        policy_digests: DelegationPolicyDigests {
            selection_policy_sha256: selection_policy_digest(partition)?,
            repository_policy_sha256,
            rule_set_sha256,
        },
        files: selected_files(partition, &rule_groups)?,
        exclusions: exclusions(partition),
        rule_groups,
        manifest_sha256: Sha256Digest::of_bytes(&[]),
    };
    manifest.manifest_sha256 = derive_manifest_digest(&manifest)?;
    manifest.validate_against(partition)?;
    Ok(manifest)
}

fn normalize_rule_group(
    mut input: DelegationRuleGroupInput,
) -> Result<DelegationRuleGroup, DelegationError> {
    if !valid_identifier(&input.id) {
        return Err(DelegationError::InvalidRuleGroup);
    }
    if input.rule_ids.len() > MAX_RULES_PER_GROUP {
        return Err(DelegationError::InvalidRuleGroup);
    }
    if input.rule_ids.iter().any(|id| !valid_identifier(id)) {
        return Err(DelegationError::InvalidRuleIdentifier);
    }
    input.rule_ids.sort();
    input.rule_ids.dedup();
    input.matched_paths.sort();
    input.matched_paths.dedup();
    if input.rule_ids.is_empty() || input.matched_paths.is_empty() {
        return Err(DelegationError::InvalidRuleGroup);
    }
    Ok(DelegationRuleGroup {
        id: input.id,
        rule_ids: input.rule_ids,
        matched_paths: input.matched_paths,
    })
}

fn validate_rule_groups(
    groups: &[DelegationRuleGroup],
    selected_paths: &BTreeSet<RepositoryPath>,
) -> Result<(), DelegationError> {
    if groups.len() > MAX_RULE_GROUPS {
        return Err(DelegationError::TooManyRuleGroups);
    }
    let mut previous: Option<&str> = None;
    for group in groups {
        if previous.is_some_and(|id| id >= group.id.as_str()) {
            return Err(if previous == Some(group.id.as_str()) {
                DelegationError::DuplicateRuleGroup
            } else {
                DelegationError::InvalidRuleGroup
            });
        }
        previous = Some(&group.id);
        if !valid_identifier(&group.id)
            || group.rule_ids.is_empty()
            || group.rule_ids.len() > MAX_RULES_PER_GROUP
            || !strictly_sorted(&group.rule_ids)
            || group.rule_ids.iter().any(|id| !valid_identifier(id))
            || group.matched_paths.is_empty()
            || !strictly_sorted(&group.matched_paths)
        {
            return Err(DelegationError::InvalidRuleGroup);
        }
        if group
            .matched_paths
            .iter()
            .any(|path| !selected_paths.contains(path))
        {
            return Err(DelegationError::UnknownRulePath);
        }
    }
    Ok(())
}

fn selected_paths(partition: &ReviewPartitionPlan) -> BTreeSet<RepositoryPath> {
    partition
        .work_units
        .iter()
        .flat_map(|unit| unit.files.iter().map(|file| file.path.new_path.clone()))
        .collect()
}

fn selected_files(
    partition: &ReviewPartitionPlan,
    rule_groups: &[DelegationRuleGroup],
) -> Result<Vec<DelegationFile>, DelegationError> {
    let mut path_groups: BTreeMap<&RepositoryPath, Vec<String>> = BTreeMap::new();
    for group in rule_groups {
        for path in &group.matched_paths {
            path_groups.entry(path).or_default().push(group.id.clone());
        }
    }
    let mut files = Vec::new();
    for unit in &partition.work_units {
        for file in &unit.files {
            files.push(DelegationFile {
                path: file.path.clone(),
                class: file.class,
                tier: file.review_value.tier,
                selected_input_bytes: file.input_bytes,
                anchor_count: u32::try_from(file.anchor_ids.len())
                    .map_err(|_| DelegationError::CountOverflow)?,
                work_unit_id: unit.id.clone(),
                rule_group_ids: path_groups
                    .get(&file.path.new_path)
                    .cloned()
                    .unwrap_or_default(),
            });
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn exclusions(partition: &ReviewPartitionPlan) -> Vec<DelegationExclusion> {
    partition
        .omitted
        .iter()
        .map(|item| DelegationExclusion {
            path: item.path.clone(),
            reason: item.reason,
        })
        .collect()
}

fn selection_policy_digest(
    partition: &ReviewPartitionPlan,
) -> Result<Sha256Digest, DelegationError> {
    serde_json::to_vec(&partition.policy)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| DelegationError::Serialization)
}

fn derive_manifest_digest(manifest: &DelegationManifest) -> Result<Sha256Digest, DelegationError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        snapshot: &'a ReviewSnapshotIdentity,
        partition_sha256: &'a Sha256Digest,
        policy_digests: &'a DelegationPolicyDigests,
        files: &'a [DelegationFile],
        exclusions: &'a [DelegationExclusion],
        rule_groups: &'a [DelegationRuleGroup],
    }
    serde_json::to_vec(&DigestInput {
        schema_version: &manifest.schema_version,
        snapshot: &manifest.snapshot,
        partition_sha256: &manifest.partition_sha256,
        policy_digests: &manifest.policy_digests,
        files: &manifest.files,
        exclusions: &manifest.exclusions,
        rule_groups: &manifest.rule_groups,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| DelegationError::Serialization)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        FileChangeKind, GitSha, LocalSnapshotIdentity, PartitionLimits, ReviewFileInput,
        ReviewObject, ReviewObjectRole, ReviewSelectionPolicy, ReviewValue, ReviewValueReason,
        build_partition_plan,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn changed(value: &str) -> ChangedPath {
        let path = path(value);
        ChangedPath {
            old_path: path.clone(),
            new_path: path,
            kind: FileChangeKind::Modified,
        }
    }

    fn partition() -> ReviewPartitionPlan {
        let snapshot = ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
            repository_identity_sha256: digest('a'),
            base_sha: GitSha::try_from("b".repeat(40)).unwrap(),
            head_sha: GitSha::try_from("c".repeat(40)).unwrap(),
            working_tree_sha256: digest('d'),
            exact_diff_manifest_sha256: digest('e'),
        });
        let files = [
            ("src/high.rs", ReviewValueTier::High, 220, '1'),
            ("tests/standard.rs", ReviewValueTier::Standard, 90, '2'),
        ]
        .into_iter()
        .map(|(name, tier, score, marker)| ReviewFileInput {
            path: changed(name),
            class: ReviewFileClass::Text,
            review_value: ReviewValue {
                tier,
                score,
                reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
            },
            objects: vec![ReviewObject {
                role: ReviewObjectRole::ExactDiff,
                content_sha256: digest(marker),
                size_bytes: 40,
            }],
            anchor_ids: Vec::new(),
        });
        build_partition_plan(
            snapshot,
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
                max_file_bytes: 100,
            },
            PartitionLimits {
                max_files: 10,
                max_total_bytes: 1_000,
                max_work_units: 10,
                max_files_per_work_unit: 10,
                max_bytes_per_work_unit: 1_000,
                max_anchors_per_work_unit: 10,
            },
            files,
        )
        .unwrap()
    }

    fn groups() -> Vec<DelegationRuleGroupInput> {
        vec![
            DelegationRuleGroupInput {
                id: "rust".to_owned(),
                rule_ids: vec!["correctness".to_owned(), "correctness".to_owned()],
                matched_paths: vec![path("tests/standard.rs"), path("src/high.rs")],
            },
            DelegationRuleGroupInput {
                id: "tests".to_owned(),
                rule_ids: vec!["test-quality".to_owned()],
                matched_paths: vec![path("tests/standard.rs")],
            },
        ]
    }

    #[test]
    fn build_is_deterministic_and_snapshot_bound() {
        let partition = partition();
        let left =
            build_delegation_manifest(&partition, digest('f'), digest('0'), groups()).unwrap();
        let right = build_delegation_manifest(
            &partition,
            digest('f'),
            digest('0'),
            groups().into_iter().rev(),
        )
        .unwrap();
        assert_eq!(left, right);
        assert_eq!(left.schema_version, DelegationManifest::SCHEMA_VERSION);
        assert_eq!(left.snapshot, partition.snapshot);
        assert_eq!(left.partition_sha256, partition.plan_sha256);
        assert_eq!(left.files[0].path.new_path.as_str(), "src/high.rs");
        assert_eq!(left.files[1].path.new_path.as_str(), "tests/standard.rs");
        assert_eq!(left.rule_groups[0].rule_ids, ["correctness"]);
        left.validate_against(&partition).unwrap();
        assert_eq!(
            left.canonical_json(&partition).unwrap(),
            right.canonical_json(&partition).unwrap()
        );
    }

    #[test]
    fn manifest_contains_no_execution_or_provider_authority_fields() {
        let partition = partition();
        let manifest =
            build_delegation_manifest(&partition, digest('f'), digest('0'), groups()).unwrap();
        let json = String::from_utf8(manifest.canonical_json(&partition).unwrap()).unwrap();
        for forbidden in [
            "command",
            "credential",
            "network",
            "provider",
            "publication",
            "shell",
            "tool",
        ] {
            assert!(
                !json.contains(forbidden),
                "unexpected authority field: {forbidden}"
            );
        }
    }

    #[test]
    fn unknown_paths_and_unsafe_identifiers_are_rejected() {
        let partition = partition();
        let unknown = vec![DelegationRuleGroupInput {
            id: "rust".to_owned(),
            rule_ids: vec!["correctness".to_owned()],
            matched_paths: vec![path("src/not-selected.rs")],
        }];
        assert_eq!(
            build_delegation_manifest(&partition, digest('f'), digest('0'), unknown),
            Err(DelegationError::UnknownRulePath)
        );

        let unsafe_id = vec![DelegationRuleGroupInput {
            id: "run git status".to_owned(),
            rule_ids: vec!["correctness".to_owned()],
            matched_paths: vec![path("src/high.rs")],
        }];
        assert_eq!(
            build_delegation_manifest(&partition, digest('f'), digest('0'), unsafe_id),
            Err(DelegationError::InvalidRuleGroup)
        );
    }

    #[test]
    fn tampering_fails_closed() {
        let partition = partition();
        let mut manifest =
            build_delegation_manifest(&partition, digest('f'), digest('0'), groups()).unwrap();
        manifest.files[0].selected_input_bytes += 1;
        assert_eq!(
            manifest.validate_against(&partition),
            Err(DelegationError::FileBinding)
        );

        let mut manifest =
            build_delegation_manifest(&partition, digest('f'), digest('0'), groups()).unwrap();
        manifest.policy_digests.selection_policy_sha256 = digest('9');
        assert_eq!(
            manifest.validate_against(&partition),
            Err(DelegationError::PolicyBinding)
        );

        let mut manifest =
            build_delegation_manifest(&partition, digest('f'), digest('0'), groups()).unwrap();
        manifest.manifest_sha256 = digest('9');
        assert_eq!(
            manifest.validate_against(&partition),
            Err(DelegationError::ManifestDigest)
        );
    }
}
