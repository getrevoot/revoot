//! Metadata-only semantic grouping contracts.
//!
//! Small selections bypass model grouping entirely. Larger selections expose
//! only bounded identifiers, paths, enums, and numeric counts. This module has
//! no representation capable of carrying a diff body or source-content slice.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use revoot_core::{
    FileChangeKind, ProposedReviewGroup, RepositoryPath, ReviewGroupLimits, ReviewGroupPlan,
    ReviewGroupPlanError, ReviewGroupingSource, ReviewPartitionPlan, ReviewValueTier, Sha256Digest,
    build_review_group_plan,
};
use serde::{Deserialize, Serialize};

const METADATA_GROUPING_THRESHOLD: usize = 4;
const MAX_GROUPING_REQUEST_BYTES: usize = 32 * 1024;
const MAX_GROUPING_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_GROUPING_RULES_PER_FILE: usize = 32;
const MAX_GROUPING_DEPENDENCIES_PER_FILE: usize = 64;
const MAX_RULE_ID_BYTES: usize = 128;
const MAX_GROUPING_HUNKS: u32 = 4_096;
const MAX_GROUPING_CHANGED_LINES: u32 = 10_000_000;
const MAX_PROPOSED_GROUPS: usize = 128;

/// Typed basis for a cross-file grouping hint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupingDependencyKind {
    CallerCallee,
    ManifestScope,
    RenamePair,
    SameDirectory,
    SharedStem,
}

/// One allowlisted path relationship with no source-content field.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupingDependencyHint {
    pub related_path: RepositoryPath,
    pub kind: GroupingDependencyKind,
}

/// Caller-supplied numeric and identifier facts for one selected file.
///
/// Status and risk are deliberately absent: they are copied from the trusted
/// partition rather than accepted from an integration boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupingFileFacts {
    pub path: RepositoryPath,
    pub rule_ids: Vec<String>,
    pub changed_line_count: u32,
    pub hunk_count: u32,
    pub dependency_hints: Vec<GroupingDependencyHint>,
}

/// Complete metadata for one selected file in a grouping request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupingFileMetadata {
    pub path: RepositoryPath,
    pub status: FileChangeKind,
    pub risk_tier: ReviewValueTier,
    pub rule_ids: Vec<String>,
    pub changed_line_count: u32,
    pub hunk_count: u32,
    pub dependency_hints: Vec<GroupingDependencyHint>,
}

/// Snapshot-bound grouping request containing metadata and no diff payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupingRequest {
    pub schema_version: String,
    pub partition_sha256: Sha256Digest,
    pub files: Vec<GroupingFileMetadata>,
}

impl GroupingRequest {
    pub const SCHEMA_VERSION: &'static str = "revoot.grouping-request/v1";

    /// Serialize the metadata request in stable file/path order.
    ///
    /// # Errors
    ///
    /// Returns a closed error if serialization fails or exceeds the request cap.
    pub fn canonical_json(&self) -> Result<Vec<u8>, GroupingError> {
        let encoded = serde_json::to_vec(self).map_err(|_| GroupingError::Serialization)?;
        if encoded.len() > MAX_GROUPING_REQUEST_BYTES {
            return Err(GroupingError::RequestTooLarge);
        }
        Ok(encoded)
    }
}

/// Preparation either bypasses grouping or yields one metadata-only request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupingPreparation {
    Deterministic(ReviewGroupPlan),
    MetadataRequest(GroupingRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupingProposal {
    schema_version: String,
    groups: Vec<GroupingProposalPaths>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupingProposalPaths {
    paths: Vec<RepositoryPath>,
}

/// Payload-free grouping contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupingError {
    Partition,
    FactsRequired,
    DuplicateFact,
    MissingFact,
    UnknownFact,
    MetricLimit,
    RuleLimit,
    InvalidRuleIdentifier,
    DependencyLimit,
    UnknownDependency,
    SelfDependency,
    RequestTooLarge,
    ResponseTooLarge,
    Serialization,
    InvalidResponse,
    ResponseSchema,
    EmptyProposal,
    EmptyGroup,
    TooManyGroups,
    UnknownAssignment,
    DuplicateAssignment,
    GroupCapacity,
    GroupPlan,
}

impl fmt::Display for GroupingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Partition => "grouping requires a valid partition plan",
            Self::FactsRequired => "metadata grouping requires file facts",
            Self::DuplicateFact => "grouping file facts contain a duplicate path",
            Self::MissingFact => "grouping file facts omit a selected path",
            Self::UnknownFact => "grouping file facts contain an unselected path",
            Self::MetricLimit => "grouping file metrics exceed a fixed bound",
            Self::RuleLimit => "grouping rule identifiers exceed a fixed bound",
            Self::InvalidRuleIdentifier => "grouping rule identifier is invalid",
            Self::DependencyLimit => "grouping dependency hints exceed a fixed bound",
            Self::UnknownDependency => "grouping dependency hint targets an unselected path",
            Self::SelfDependency => "grouping dependency hint targets its own path",
            Self::RequestTooLarge => "grouping metadata request exceeds its byte bound",
            Self::ResponseTooLarge => "grouping proposal exceeds its byte bound",
            Self::Serialization => "grouping metadata serialization failed",
            Self::InvalidResponse => "grouping proposal is malformed",
            Self::ResponseSchema => "grouping proposal schema is unsupported",
            Self::EmptyProposal => "grouping proposal contains no groups",
            Self::EmptyGroup => "grouping proposal contains an empty group",
            Self::TooManyGroups => "grouping proposal contains too many groups",
            Self::UnknownAssignment => "grouping proposal assigns an unselected path",
            Self::DuplicateAssignment => "grouping proposal assigns a path more than once",
            Self::GroupCapacity => "grouping proposal exceeds a group capacity bound",
            Self::GroupPlan => "grouping proposal could not produce a valid group plan",
        })
    }
}

impl std::error::Error for GroupingError {}

/// Choose deterministic grouping for at most three selected files, otherwise
/// build the one allowed metadata-only grouping request.
///
/// Passing `None` for facts is valid for small selections, proving that the
/// no-provider path does not need to construct or serialize grouping metadata.
///
/// # Errors
///
/// Rejects an invalid partition or incomplete, unknown, duplicate, or unbounded
/// metadata facts for a larger selection.
pub fn prepare_grouping(
    partition: &ReviewPartitionPlan,
    facts: Option<&[GroupingFileFacts]>,
) -> Result<GroupingPreparation, GroupingError> {
    partition
        .validate_replay()
        .map_err(|_| GroupingError::Partition)?;
    let selected = selected_files(partition)?;
    if selected.len() < METADATA_GROUPING_THRESHOLD {
        return build_review_group_plan(partition, None, ReviewGroupingSource::Deterministic)
            .map(GroupingPreparation::Deterministic)
            .map_err(map_group_plan_error);
    }
    let facts = facts.ok_or(GroupingError::FactsRequired)?;
    let files = validate_and_join_facts(&selected, facts)?;
    let request = GroupingRequest {
        schema_version: GroupingRequest::SCHEMA_VERSION.to_owned(),
        partition_sha256: partition.plan_sha256.clone(),
        files,
    };
    request.canonical_json()?;
    Ok(GroupingPreparation::MetadataRequest(request))
}

/// Parse a strict metadata-grouping response and build a complete bounded plan.
///
/// Selected paths omitted by the response are left out of the semantic proposal
/// passed to the core planner. That planner places them into deterministic
/// fallback groups while retaining a semantic grouping source.
///
/// # Errors
///
/// Rejects malformed, oversized, unknown, duplicate, empty, or over-capacity
/// assignments, as well as an invalid partition.
pub fn parse_grouping_proposal(
    partition: &ReviewPartitionPlan,
    response: &[u8],
) -> Result<ReviewGroupPlan, GroupingError> {
    partition
        .validate_replay()
        .map_err(|_| GroupingError::Partition)?;
    if response.len() > MAX_GROUPING_RESPONSE_BYTES {
        return Err(GroupingError::ResponseTooLarge);
    }
    let proposal: GroupingProposal =
        serde_json::from_slice(response).map_err(|_| GroupingError::InvalidResponse)?;
    if proposal.schema_version != "revoot.grouping-proposal/v1" {
        return Err(GroupingError::ResponseSchema);
    }
    if proposal.groups.is_empty() {
        return Err(GroupingError::EmptyProposal);
    }
    if proposal.groups.len() > MAX_PROPOSED_GROUPS {
        return Err(GroupingError::TooManyGroups);
    }

    let selected = selected_files(partition)?;
    let limits = ReviewGroupLimits::default();
    let mut assigned = BTreeSet::new();
    let mut groups = Vec::with_capacity(proposal.groups.len());
    for group in proposal.groups {
        if group.paths.is_empty() {
            return Err(GroupingError::EmptyGroup);
        }
        let mut input_bytes = 0_u64;
        let mut anchors = 0_u32;
        for path in &group.paths {
            let Some(file) = selected.get(path) else {
                return Err(GroupingError::UnknownAssignment);
            };
            if !assigned.insert(path.clone()) {
                return Err(GroupingError::DuplicateAssignment);
            }
            input_bytes = input_bytes
                .checked_add(file.input_bytes)
                .ok_or(GroupingError::GroupCapacity)?;
            anchors = anchors
                .checked_add(
                    u32::try_from(file.anchor_count).map_err(|_| GroupingError::GroupCapacity)?,
                )
                .ok_or(GroupingError::GroupCapacity)?;
        }
        if group.paths.len()
            > usize::try_from(limits.max_files).map_err(|_| GroupingError::GroupCapacity)?
            || input_bytes > limits.max_input_bytes
            || anchors > limits.max_anchors
        {
            return Err(GroupingError::GroupCapacity);
        }
        groups.push(ProposedReviewGroup { paths: group.paths });
    }

    build_review_group_plan(partition, Some(&groups), ReviewGroupingSource::Semantic)
        .map_err(map_group_plan_error)
}

/// Build the safe complete fallback after grouping is unavailable or rejected.
///
/// # Errors
///
/// Returns a closed error if the partition is invalid or cannot be packed.
pub fn deterministic_grouping_fallback(
    partition: &ReviewPartitionPlan,
) -> Result<ReviewGroupPlan, GroupingError> {
    build_review_group_plan(partition, None, ReviewGroupingSource::DeterministicFallback)
        .map_err(map_group_plan_error)
}

#[derive(Clone, Copy)]
struct SelectedFile<'a> {
    status: FileChangeKind,
    risk_tier: ReviewValueTier,
    input_bytes: u64,
    anchor_count: usize,
    path: &'a RepositoryPath,
}

fn selected_files(
    partition: &ReviewPartitionPlan,
) -> Result<BTreeMap<RepositoryPath, SelectedFile<'_>>, GroupingError> {
    let mut selected = BTreeMap::new();
    for unit in &partition.work_units {
        for file in &unit.files {
            let metadata = SelectedFile {
                status: file.path.kind,
                risk_tier: file.review_value.tier,
                input_bytes: file.input_bytes,
                anchor_count: file.anchor_ids.len(),
                path: &file.path.new_path,
            };
            if selected
                .insert(file.path.new_path.clone(), metadata)
                .is_some()
            {
                return Err(GroupingError::Partition);
            }
        }
    }
    Ok(selected)
}

fn validate_and_join_facts(
    selected: &BTreeMap<RepositoryPath, SelectedFile<'_>>,
    facts: &[GroupingFileFacts],
) -> Result<Vec<GroupingFileMetadata>, GroupingError> {
    let selected_paths = selected.keys().cloned().collect::<BTreeSet<_>>();
    let mut facts_by_path = BTreeMap::new();
    for fact in facts {
        if !selected.contains_key(&fact.path) {
            return Err(GroupingError::UnknownFact);
        }
        if facts_by_path.insert(fact.path.clone(), fact).is_some() {
            return Err(GroupingError::DuplicateFact);
        }
    }
    if facts_by_path.len() != selected.len() {
        return Err(GroupingError::MissingFact);
    }

    let mut files = Vec::with_capacity(selected.len());
    for (path, selected_file) in selected {
        let fact = facts_by_path.get(path).ok_or(GroupingError::MissingFact)?;
        if fact.hunk_count > MAX_GROUPING_HUNKS
            || fact.changed_line_count > MAX_GROUPING_CHANGED_LINES
        {
            return Err(GroupingError::MetricLimit);
        }
        if fact.rule_ids.is_empty() || fact.rule_ids.len() > MAX_GROUPING_RULES_PER_FILE {
            return Err(GroupingError::RuleLimit);
        }
        let mut rule_ids = fact.rule_ids.clone();
        if rule_ids.iter().any(|id| !valid_rule_id(id)) {
            return Err(GroupingError::InvalidRuleIdentifier);
        }
        rule_ids.sort();
        rule_ids.dedup();

        if fact.dependency_hints.len() > MAX_GROUPING_DEPENDENCIES_PER_FILE {
            return Err(GroupingError::DependencyLimit);
        }
        let mut dependency_hints = fact.dependency_hints.clone();
        for hint in &dependency_hints {
            if hint.related_path == *path {
                return Err(GroupingError::SelfDependency);
            }
            if !selected_paths.contains(&hint.related_path) {
                return Err(GroupingError::UnknownDependency);
            }
        }
        dependency_hints.sort();
        dependency_hints.dedup();

        files.push(GroupingFileMetadata {
            path: selected_file.path.clone(),
            status: selected_file.status,
            risk_tier: selected_file.risk_tier,
            rule_ids,
            changed_line_count: fact.changed_line_count,
            hunk_count: fact.hunk_count,
            dependency_hints,
        });
    }
    Ok(files)
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_RULE_ID_BYTES
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

const fn map_group_plan_error(error: ReviewGroupPlanError) -> GroupingError {
    match error {
        ReviewGroupPlanError::Partition => GroupingError::Partition,
        ReviewGroupPlanError::Limits => GroupingError::GroupCapacity,
        ReviewGroupPlanError::DuplicateFile => GroupingError::DuplicateAssignment,
        ReviewGroupPlanError::UnknownFile => GroupingError::UnknownAssignment,
        ReviewGroupPlanError::SchemaVersion
        | ReviewGroupPlanError::GroupIdentity
        | ReviewGroupPlanError::FileMismatch
        | ReviewGroupPlanError::IncompleteAssignment
        | ReviewGroupPlanError::Digest
        | ReviewGroupPlanError::Serialization => GroupingError::GroupPlan,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use revoot_core::{
        ChangedPath, LocalSnapshotIdentity, PartitionLimits, RepositoryPath, ReviewFileClass,
        ReviewFileInput, ReviewObject, ReviewObjectRole, ReviewSelectionPolicy, Sha256Digest,
        build_partition_plan, classify_review_value,
    };
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn three_files_bypass_metadata_and_need_no_facts() {
        let partition = partition(&["src/a.rs", "src/b.rs", "src/c.rs"]);
        let preparation = prepare_grouping(&partition, None).expect("deterministic grouping");
        let GroupingPreparation::Deterministic(plan) = preparation else {
            panic!("small selection must not request grouping metadata");
        };
        assert_eq!(plan.source, ReviewGroupingSource::Deterministic);
        assert_eq!(assigned_paths(&plan).len(), 3);
    }

    #[test]
    fn four_files_produce_metadata_without_diff_shaped_fields() {
        let partition = partition(&["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
        assert_eq!(
            prepare_grouping(&partition, None).expect_err("facts required"),
            GroupingError::FactsRequired
        );
        let preparation =
            prepare_grouping(&partition, Some(&facts(&partition))).expect("metadata request");
        let GroupingPreparation::MetadataRequest(request) = preparation else {
            panic!("large selection must request metadata grouping");
        };
        assert_eq!(request.files.len(), 4);
        let encoded = request.canonical_json().expect("canonical request");
        let value: Value = serde_json::from_slice(&encoded).expect("request JSON");
        assert_only_metadata_keys(&value);
        assert_eq!(request.files[0].status, FileChangeKind::Modified);
        assert_eq!(request.files[0].changed_line_count, 7);
        assert_eq!(request.files[0].hunk_count, 2);
    }

    #[test]
    fn facts_are_exact_bounded_and_allowlisted() {
        let partition = partition(&["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
        let mut supplied = facts(&partition);
        supplied.pop();
        assert_eq!(
            prepare_grouping(&partition, Some(&supplied)).expect_err("missing fact"),
            GroupingError::MissingFact
        );

        let mut supplied = facts(&partition);
        supplied.push(supplied[0].clone());
        assert_eq!(
            prepare_grouping(&partition, Some(&supplied)).expect_err("duplicate fact"),
            GroupingError::DuplicateFact
        );

        let mut supplied = facts(&partition);
        supplied[0].rule_ids = vec!["diff\nbody".to_owned()];
        assert_eq!(
            prepare_grouping(&partition, Some(&supplied)).expect_err("invalid rule"),
            GroupingError::InvalidRuleIdentifier
        );

        let mut supplied = facts(&partition);
        supplied[0].dependency_hints = vec![GroupingDependencyHint {
            related_path: RepositoryPath::try_from("outside.rs".to_owned()).expect("path"),
            kind: GroupingDependencyKind::CallerCallee,
        }];
        assert_eq!(
            prepare_grouping(&partition, Some(&supplied)).expect_err("unknown dependency"),
            GroupingError::UnknownDependency
        );
    }

    #[test]
    fn omitted_assignments_are_packed_into_a_complete_fallback_group() {
        let partition = partition(&["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
        let response = serde_json::to_vec(&json!({
            "schema_version": "revoot.grouping-proposal/v1",
            "groups": [{"paths": ["src/a.rs", "src/b.rs"]}]
        }))
        .expect("proposal");
        let plan = parse_grouping_proposal(&partition, &response).expect("group plan");
        assert_eq!(plan.source, ReviewGroupingSource::Semantic);
        assert_eq!(assigned_paths(&plan).len(), 4);
        assert!(plan.groups.iter().any(|group| {
            group
                .files
                .iter()
                .any(|file| file.path.new_path.as_str() == "src/d.rs")
        }));
    }

    #[test]
    fn proposal_rejects_unknown_duplicate_and_empty_assignments() {
        let partition = partition(&["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
        let unknown = json!({
            "schema_version": "revoot.grouping-proposal/v1",
            "groups": [{"paths": ["outside.rs"]}]
        });
        assert_eq!(
            parse_grouping_proposal(&partition, &serde_json::to_vec(&unknown).expect("JSON"))
                .expect_err("unknown"),
            GroupingError::UnknownAssignment
        );
        let duplicate = json!({
            "schema_version": "revoot.grouping-proposal/v1",
            "groups": [{"paths": ["src/a.rs"]}, {"paths": ["src/a.rs"]}]
        });
        assert_eq!(
            parse_grouping_proposal(&partition, &serde_json::to_vec(&duplicate).expect("JSON"))
                .expect_err("duplicate"),
            GroupingError::DuplicateAssignment
        );
        let empty = json!({
            "schema_version": "revoot.grouping-proposal/v1",
            "groups": [{"paths": []}]
        });
        assert_eq!(
            parse_grouping_proposal(&partition, &serde_json::to_vec(&empty).expect("JSON"))
                .expect_err("empty"),
            GroupingError::EmptyGroup
        );
    }

    #[test]
    fn proposal_rejects_group_above_ten_files() {
        let names = (0..11)
            .map(|index| format!("src/{index}.rs"))
            .collect::<Vec<_>>();
        let paths = names.iter().map(String::as_str).collect::<Vec<_>>();
        let partition = partition(&paths);
        let response = serde_json::to_vec(&json!({
            "schema_version": "revoot.grouping-proposal/v1",
            "groups": [{"paths": paths}]
        }))
        .expect("proposal");
        assert_eq!(
            parse_grouping_proposal(&partition, &response).expect_err("capacity"),
            GroupingError::GroupCapacity
        );
    }

    #[test]
    fn malformed_proposal_can_fall_back_deterministically() {
        let partition = partition(&["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
        let malformed =
            br#"{"schema_version":"revoot.grouping-proposal/v1","groups":[],"extra":true}"#;
        assert_eq!(
            parse_grouping_proposal(&partition, malformed).expect_err("unknown field"),
            GroupingError::InvalidResponse
        );
        let fallback = deterministic_grouping_fallback(&partition).expect("fallback");
        assert_eq!(fallback.source, ReviewGroupingSource::DeterministicFallback);
        assert_eq!(assigned_paths(&fallback).len(), 4);
    }

    fn partition(paths: &[&str]) -> ReviewPartitionPlan {
        let files = paths
            .iter()
            .enumerate()
            .map(|(index, path)| file(path, index))
            .collect::<Vec<_>>();
        build_partition_plan(
            LocalSnapshotIdentity {
                repository_identity_sha256: digest(b'r'),
                base_sha: "a".repeat(40).try_into().expect("base SHA"),
                head_sha: "b".repeat(40).try_into().expect("head SHA"),
                working_tree_sha256: digest(b'w'),
                exact_diff_manifest_sha256: digest(b'm'),
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
                max_files_per_work_unit: 20,
                max_bytes_per_work_unit: 10_000,
                max_anchors_per_work_unit: 100,
            },
            files,
        )
        .expect("partition")
    }

    fn file(path: &str, index: usize) -> ReviewFileInput {
        let repository_path = RepositoryPath::try_from(path.to_owned()).expect("path");
        let changed_path = ChangedPath {
            old_path: repository_path.clone(),
            new_path: repository_path,
            kind: FileChangeKind::Modified,
        };
        ReviewFileInput {
            review_value: classify_review_value(&changed_path, ReviewFileClass::Text, None),
            path: changed_path,
            class: ReviewFileClass::Text,
            objects: vec![ReviewObject {
                role: ReviewObjectRole::ExactDiff,
                content_sha256: Sha256Digest::of_bytes(format!("file-{index}").as_bytes()),
                size_bytes: 10,
            }],
            anchor_ids: Vec::new(),
        }
    }

    fn facts(partition: &ReviewPartitionPlan) -> Vec<GroupingFileFacts> {
        partition
            .work_units
            .iter()
            .flat_map(|unit| &unit.files)
            .map(|file| GroupingFileFacts {
                path: file.path.new_path.clone(),
                rule_ids: vec!["rust.md".to_owned(), "repository:correctness".to_owned()],
                changed_line_count: 7,
                hunk_count: 2,
                dependency_hints: Vec::new(),
            })
            .collect()
    }

    fn assigned_paths(plan: &ReviewGroupPlan) -> BTreeSet<RepositoryPath> {
        plan.groups
            .iter()
            .flat_map(|group| &group.files)
            .map(|file| file.path.new_path.clone())
            .collect()
    }

    fn assert_only_metadata_keys(value: &Value) {
        let root = value.as_object().expect("request object");
        assert_eq!(
            root.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["files", "partition_sha256", "schema_version"])
        );
        for file in root["files"].as_array().expect("files") {
            let keys = file
                .as_object()
                .expect("file object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                keys,
                BTreeSet::from([
                    "changed_line_count",
                    "dependency_hints",
                    "hunk_count",
                    "path",
                    "risk_tier",
                    "rule_ids",
                    "status"
                ])
            );
            assert!(keys.is_disjoint(&BTreeSet::from([
                "body", "content", "diff", "patch", "source"
            ])));
        }
    }

    fn digest(marker: u8) -> Sha256Digest {
        Sha256Digest::of_bytes(&[marker])
    }
}
