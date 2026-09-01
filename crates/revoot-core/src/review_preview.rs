//! Deterministic, provider-free review preview projections.
//!
//! Previews contain only snapshot-bound metadata and resource decisions. They
//! contain no source bodies, diff bodies, provider operations, credentials, or
//! temporary artifact locations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AgentBudgetLimits, ChangedPath, ReviewEffort, ReviewFileClass, ReviewGroupingSource,
    ReviewOmissionReason, ReviewPartitionPlan, ReviewSnapshotIdentity, ReviewValueTier,
    Sha256Digest, WorkUnitId,
    review_group::{ReviewGroupId, ReviewGroupPlan, ReviewGroupPlanError},
};

const MAX_PARALLEL_GROUPS: u8 = 8;
const MAX_INLINE_DIFF_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_INPUT_TOKENS: u64 = 32_000;
const MAX_REQUEST_OUTPUT_TOKENS: u64 = 4_096;
const MAX_RULES: usize = 4_096;
const MAX_RULE_ID_BYTES: usize = 128;

/// Trusted per-group measurements used to preview the initial context shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPreviewGroupInput {
    pub group_id: ReviewGroupId,
    pub exact_diff_bytes: u64,
    pub max_file_changed_lines: u32,
    pub total_changed_lines: u32,
    pub estimated_initial_input_tokens: u64,
}

/// Guidance-layer precedence retained in preview diagnostics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPreviewRuleSource {
    CompiledSafety,
    BaseConfiguration,
    RepositoryRule,
    EmbeddedLanguage,
    Generic,
}

/// Body-free rule-resolution record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPreviewRule {
    pub id: String,
    pub source: ReviewPreviewRuleSource,
    pub matched_paths: Vec<crate::RepositoryPath>,
}

/// Fixed strategy and budget projection for one review invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPreviewStrategy {
    pub effort: ReviewEffort,
    pub rounds_per_group: u8,
    pub max_turns_per_group: u32,
    pub max_parallel_groups: u8,
    pub budgets: AgentBudgetLimits,
    pub max_inline_diff_bytes: u64,
    pub target_request_input_tokens: u64,
    pub max_request_output_tokens: u64,
}

/// Whether the complete group diff or only its manifest enters initial context.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPreviewInitialContext {
    InlineCompleteDiff,
    ManifestOnly,
}

/// Selected file metadata shown without content or anchor identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPreviewFile {
    pub path: ChangedPath,
    pub class: ReviewFileClass,
    pub tier: ReviewValueTier,
    pub selected_input_bytes: u64,
    pub anchor_count: u32,
    pub work_unit_id: WorkUnitId,
}

/// One runtime group's bounded preview.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPreviewGroup {
    pub id: ReviewGroupId,
    pub files: Vec<ReviewPreviewFile>,
    pub exact_diff_bytes: u64,
    pub anchor_count: u32,
    pub max_file_changed_lines: u32,
    pub total_changed_lines: u32,
    pub estimated_initial_input_tokens: u64,
    pub initial_context: ReviewPreviewInitialContext,
    pub complex: bool,
    pub rule_ids: Vec<String>,
}

/// One deterministic partition omission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPreviewOmission {
    pub path: ChangedPath,
    pub reason: ReviewOmissionReason,
}

/// Canonical machine and human preview source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPreview {
    pub schema_version: String,
    pub snapshot: ReviewSnapshotIdentity,
    pub partition_sha256: Sha256Digest,
    pub group_plan_sha256: Sha256Digest,
    pub grouping_source: ReviewGroupingSource,
    pub strategy: ReviewPreviewStrategy,
    pub groups: Vec<ReviewPreviewGroup>,
    pub omissions: Vec<ReviewPreviewOmission>,
    pub rules: Vec<ReviewPreviewRule>,
    pub rules_sha256: Sha256Digest,
    pub preview_sha256: Sha256Digest,
}

impl ReviewPreview {
    pub const SCHEMA_VERSION: &'static str = "revoot.review-preview/v1";

    /// Validate this preview against its authoritative partition and group plan.
    ///
    /// # Errors
    ///
    /// Returns the first snapshot, strategy, grouping, rule, or digest mismatch.
    pub fn validate_against(
        &self,
        partition: &ReviewPartitionPlan,
        group_plan: &ReviewGroupPlan,
    ) -> Result<(), ReviewPreviewError> {
        partition
            .validate_replay()
            .map_err(|_| ReviewPreviewError::Partition)?;
        group_plan
            .validate_against(partition)
            .map_err(ReviewPreviewError::Grouping)?;
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ReviewPreviewError::SchemaVersion);
        }
        if self.snapshot != partition.snapshot
            || self.partition_sha256 != partition.plan_sha256
            || self.group_plan_sha256 != group_plan.plan_sha256
            || self.grouping_source != group_plan.source
        {
            return Err(ReviewPreviewError::SnapshotBinding);
        }
        validate_strategy(&self.strategy)?;
        validate_rules(&self.rules, partition)?;
        if self.rules_sha256 != rules_digest(&self.rules)? {
            return Err(ReviewPreviewError::RuleDigest);
        }
        if self.omissions != preview_omissions(partition) {
            return Err(ReviewPreviewError::OmissionBinding);
        }
        if !strictly_sorted_by(&self.groups, |group| group.id.as_str())
            || self.groups.len() != group_plan.groups.len()
        {
            return Err(ReviewPreviewError::GroupBinding);
        }
        let rules_by_path = rules_by_path(&self.rules);
        for (preview, group) in self.groups.iter().zip(&group_plan.groups) {
            if preview.id != group.id
                || preview.anchor_count != group.anchor_count
                || preview.files != preview_files(partition, group)?
                || preview.complex
                    != (preview.max_file_changed_lines >= 50 || preview.total_changed_lines >= 100)
                || preview.initial_context
                    != initial_context(
                        preview.exact_diff_bytes,
                        preview.estimated_initial_input_tokens,
                        &self.strategy,
                    )
                || preview.rule_ids != group_rule_ids(group, &rules_by_path)
            {
                return Err(ReviewPreviewError::GroupBinding);
            }
        }
        if self.preview_sha256 != preview_digest(self)? {
            return Err(ReviewPreviewError::PreviewDigest);
        }
        Ok(())
    }

    /// Deterministic compact human projection without source or artifact data.
    #[must_use]
    pub fn human(&self) -> String {
        let mut omission_counts = BTreeMap::new();
        for omission in &self.omissions {
            *omission_counts.entry(omission.reason).or_insert(0_u32) += 1;
        }
        let mut output = format!(
            "Review preview\nSnapshot: {}\nPartition: {}\nGroups: {} ({:?})\nEffort: {:?} ({} rounds, {} turns/group)\nParallel groups: {}\nBudgets: {} model requests, {} model tokens, {} tool calls, {} ms\nInline threshold: {} bytes; request target: {} tokens\nRules: {}\nOmissions: {}\n",
            snapshot_digest(&self.snapshot).as_str(),
            self.partition_sha256.as_str(),
            self.groups.len(),
            self.grouping_source,
            self.strategy.effort,
            self.strategy.rounds_per_group,
            self.strategy.max_turns_per_group,
            self.strategy.max_parallel_groups,
            self.strategy.budgets.max_model_requests,
            self.strategy
                .budgets
                .max_input_tokens
                .saturating_add(self.strategy.budgets.max_output_tokens),
            self.strategy.budgets.max_tool_calls,
            self.strategy.budgets.max_elapsed_millis,
            self.strategy.max_inline_diff_bytes,
            self.strategy.target_request_input_tokens,
            self.rules.len(),
            self.omissions.len(),
        );
        for group in &self.groups {
            output.push_str(&format!(
                "- {}: {} files, {} changed lines, {} diff bytes, {} anchors, {:?}, complex={}, {} rules\n",
                group.id.as_str(),
                group.files.len(),
                group.total_changed_lines,
                group.exact_diff_bytes,
                group.anchor_count,
                group.initial_context,
                group.complex,
                group.rule_ids.len(),
            ));
        }
        for (reason, count) in omission_counts {
            output.push_str(&format!("- omitted {:?}: {}\n", reason, count));
        }
        output
    }

    /// Stable JSON projection of the same body-free contract.
    ///
    /// # Errors
    ///
    /// Returns an error only if typed serialization unexpectedly fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ReviewPreviewError> {
        serde_json::to_vec(self).map_err(|_| ReviewPreviewError::Serialization)
    }
}

/// Failure while building or validating a review preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewPreviewError {
    Partition,
    Grouping(ReviewGroupPlanError),
    SchemaVersion,
    SnapshotBinding,
    InvalidStrategy,
    InvalidRule,
    UnknownRulePath,
    DuplicateRule,
    RuleDigest,
    MissingGroupInput,
    DuplicateGroupInput,
    UnknownGroupInput,
    GroupBinding,
    OmissionBinding,
    CountOverflow,
    PreviewDigest,
    Serialization,
}

impl fmt::Display for ReviewPreviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Partition => "the review preview partition is invalid",
            Self::Grouping(_) => "the review preview grouping is invalid",
            Self::SchemaVersion => "the review preview schema version is invalid",
            Self::SnapshotBinding => "the review preview snapshot binding is invalid",
            Self::InvalidStrategy => "the review preview strategy is invalid",
            Self::InvalidRule => "the review preview contains an invalid rule",
            Self::UnknownRulePath => "a review preview rule targets an unselected path",
            Self::DuplicateRule => "the review preview contains a duplicate rule",
            Self::RuleDigest => "the review preview rule digest is invalid",
            Self::MissingGroupInput => "the review preview is missing group measurements",
            Self::DuplicateGroupInput => "the review preview repeats group measurements",
            Self::UnknownGroupInput => "the review preview contains unknown group measurements",
            Self::GroupBinding => "the review preview group metadata is invalid",
            Self::OmissionBinding => "the review preview omission metadata is invalid",
            Self::CountOverflow => "a review preview count overflowed",
            Self::PreviewDigest => "the review preview digest is invalid",
            Self::Serialization => "the review preview could not be serialized",
        })
    }
}

impl std::error::Error for ReviewPreviewError {}

/// Build one deterministic provider-free review preview.
///
/// # Errors
///
/// Rejects invalid source plans, strategy settings, rule records, incomplete or
/// unknown group measurements, metadata overflows, and serialization failures.
pub fn build_review_preview(
    partition: &ReviewPartitionPlan,
    group_plan: &ReviewGroupPlan,
    strategy: ReviewPreviewStrategy,
    group_inputs: impl IntoIterator<Item = ReviewPreviewGroupInput>,
    rules: impl IntoIterator<Item = ReviewPreviewRule>,
) -> Result<ReviewPreview, ReviewPreviewError> {
    partition
        .validate_replay()
        .map_err(|_| ReviewPreviewError::Partition)?;
    group_plan
        .validate_against(partition)
        .map_err(ReviewPreviewError::Grouping)?;
    validate_strategy(&strategy)?;
    let mut rules = rules.into_iter().collect::<Vec<_>>();
    if rules.len() > MAX_RULES {
        return Err(ReviewPreviewError::InvalidRule);
    }
    for rule in &mut rules {
        rule.matched_paths.sort();
        rule.matched_paths.dedup();
    }
    rules.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.id.cmp(&right.id))
    });
    validate_rules(&rules, partition)?;

    let mut inputs = BTreeMap::new();
    for input in group_inputs {
        if inputs.insert(input.group_id.clone(), input).is_some() {
            return Err(ReviewPreviewError::DuplicateGroupInput);
        }
    }
    if inputs.len() != group_plan.groups.len() {
        return Err(ReviewPreviewError::MissingGroupInput);
    }
    let rules_by_path = rules_by_path(&rules);
    let mut groups = Vec::with_capacity(group_plan.groups.len());
    for group in &group_plan.groups {
        let input = inputs
            .remove(&group.id)
            .ok_or(ReviewPreviewError::MissingGroupInput)?;
        groups.push(ReviewPreviewGroup {
            id: group.id.clone(),
            files: preview_files(partition, group)?,
            exact_diff_bytes: input.exact_diff_bytes,
            anchor_count: group.anchor_count,
            max_file_changed_lines: input.max_file_changed_lines,
            total_changed_lines: input.total_changed_lines,
            estimated_initial_input_tokens: input.estimated_initial_input_tokens,
            initial_context: initial_context(
                input.exact_diff_bytes,
                input.estimated_initial_input_tokens,
                &strategy,
            ),
            complex: input.max_file_changed_lines >= 50 || input.total_changed_lines >= 100,
            rule_ids: group_rule_ids(group, &rules_by_path),
        });
    }
    if !inputs.is_empty() {
        return Err(ReviewPreviewError::UnknownGroupInput);
    }
    groups.sort_by(|left, right| left.id.cmp(&right.id));
    let mut preview = ReviewPreview {
        schema_version: ReviewPreview::SCHEMA_VERSION.to_owned(),
        snapshot: partition.snapshot.clone(),
        partition_sha256: partition.plan_sha256.clone(),
        group_plan_sha256: group_plan.plan_sha256.clone(),
        grouping_source: group_plan.source,
        strategy,
        groups,
        omissions: preview_omissions(partition),
        rules_sha256: rules_digest(&rules)?,
        rules,
        preview_sha256: Sha256Digest::of_bytes(&[]),
    };
    preview.preview_sha256 = preview_digest(&preview)?;
    preview.validate_against(partition, group_plan)?;
    Ok(preview)
}

fn validate_strategy(strategy: &ReviewPreviewStrategy) -> Result<(), ReviewPreviewError> {
    if strategy.rounds_per_group != strategy.effort.rounds()
        || strategy.max_turns_per_group != strategy.effort.max_group_turns()
        || strategy.max_parallel_groups == 0
        || strategy.max_parallel_groups > MAX_PARALLEL_GROUPS
        || strategy.budgets.validate().is_err()
        || strategy.max_inline_diff_bytes == 0
        || strategy.max_inline_diff_bytes > MAX_INLINE_DIFF_BYTES
        || strategy.target_request_input_tokens == 0
        || strategy.target_request_input_tokens > MAX_REQUEST_INPUT_TOKENS
        || strategy.max_request_output_tokens == 0
        || strategy.max_request_output_tokens > MAX_REQUEST_OUTPUT_TOKENS
    {
        return Err(ReviewPreviewError::InvalidStrategy);
    }
    Ok(())
}

fn validate_rules(
    rules: &[ReviewPreviewRule],
    partition: &ReviewPartitionPlan,
) -> Result<(), ReviewPreviewError> {
    if rules.len() > MAX_RULES
        || !rules.windows(2).all(|pair| {
            (pair[0].source, pair[0].id.as_str()) < (pair[1].source, pair[1].id.as_str())
        })
    {
        return Err(ReviewPreviewError::DuplicateRule);
    }
    let selected = partition
        .work_units
        .iter()
        .flat_map(|unit| unit.files.iter().map(|file| &file.path.new_path))
        .collect::<BTreeSet<_>>();
    for rule in rules {
        if !valid_rule_id(&rule.id)
            || rule.matched_paths.is_empty()
            || !strictly_sorted_by(&rule.matched_paths, |path| path.as_str())
        {
            return Err(ReviewPreviewError::InvalidRule);
        }
        if rule
            .matched_paths
            .iter()
            .any(|path| !selected.contains(path))
        {
            return Err(ReviewPreviewError::UnknownRulePath);
        }
    }
    Ok(())
}

fn preview_files(
    partition: &ReviewPartitionPlan,
    group: &crate::ReviewGroup,
) -> Result<Vec<ReviewPreviewFile>, ReviewPreviewError> {
    let source = partition
        .work_units
        .iter()
        .flat_map(|unit| unit.files.iter().map(move |file| (&unit.id, file)))
        .map(|(unit_id, file)| (&file.path.new_path, (unit_id, file)))
        .collect::<BTreeMap<_, _>>();
    let mut files = Vec::with_capacity(group.files.len());
    for group_file in &group.files {
        let (unit_id, file) = source
            .get(&group_file.path.new_path)
            .ok_or(ReviewPreviewError::GroupBinding)?;
        files.push(ReviewPreviewFile {
            path: file.path.clone(),
            class: file.class,
            tier: file.review_value.tier,
            selected_input_bytes: file.input_bytes,
            anchor_count: u32::try_from(file.anchor_ids.len())
                .map_err(|_| ReviewPreviewError::CountOverflow)?,
            work_unit_id: (*unit_id).clone(),
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn initial_context(
    exact_diff_bytes: u64,
    estimated_tokens: u64,
    strategy: &ReviewPreviewStrategy,
) -> ReviewPreviewInitialContext {
    if exact_diff_bytes <= strategy.max_inline_diff_bytes
        && estimated_tokens <= strategy.target_request_input_tokens
    {
        ReviewPreviewInitialContext::InlineCompleteDiff
    } else {
        ReviewPreviewInitialContext::ManifestOnly
    }
}

fn rules_by_path(
    rules: &[ReviewPreviewRule],
) -> BTreeMap<&crate::RepositoryPath, BTreeSet<String>> {
    let mut by_path = BTreeMap::new();
    for rule in rules {
        for path in &rule.matched_paths {
            by_path
                .entry(path)
                .or_insert_with(BTreeSet::new)
                .insert(rule.id.clone());
        }
    }
    by_path
}

fn group_rule_ids(
    group: &crate::ReviewGroup,
    by_path: &BTreeMap<&crate::RepositoryPath, BTreeSet<String>>,
) -> Vec<String> {
    group
        .files
        .iter()
        .filter_map(|file| by_path.get(&file.path.new_path))
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn preview_omissions(partition: &ReviewPartitionPlan) -> Vec<ReviewPreviewOmission> {
    partition
        .omitted
        .iter()
        .map(|item| ReviewPreviewOmission {
            path: item.path.clone(),
            reason: item.reason,
        })
        .collect()
}

fn rules_digest(rules: &[ReviewPreviewRule]) -> Result<Sha256Digest, ReviewPreviewError> {
    serde_json::to_vec(rules)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| ReviewPreviewError::Serialization)
}

fn snapshot_digest(snapshot: &ReviewSnapshotIdentity) -> Sha256Digest {
    Sha256Digest::of_bytes(
        &serde_json::to_vec(snapshot).expect("snapshot domain values serialize infallibly"),
    )
}

fn preview_digest(preview: &ReviewPreview) -> Result<Sha256Digest, ReviewPreviewError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        snapshot: &'a ReviewSnapshotIdentity,
        partition_sha256: &'a Sha256Digest,
        group_plan_sha256: &'a Sha256Digest,
        grouping_source: ReviewGroupingSource,
        strategy: &'a ReviewPreviewStrategy,
        groups: &'a [ReviewPreviewGroup],
        omissions: &'a [ReviewPreviewOmission],
        rules: &'a [ReviewPreviewRule],
        rules_sha256: &'a Sha256Digest,
    }
    serde_json::to_vec(&DigestInput {
        schema_version: &preview.schema_version,
        snapshot: &preview.snapshot,
        partition_sha256: &preview.partition_sha256,
        group_plan_sha256: &preview.group_plan_sha256,
        grouping_source: preview.grouping_source,
        strategy: &preview.strategy,
        groups: &preview.groups,
        omissions: &preview.omissions,
        rules: &preview.rules,
        rules_sha256: &preview.rules_sha256,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| ReviewPreviewError::Serialization)
}

fn valid_rule_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RULE_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

fn strictly_sorted_by<T, U: Ord + ?Sized>(items: &[T], key: impl Fn(&T) -> &U) -> bool {
    items.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        FileChangeKind, GitSha, LocalSnapshotIdentity, PartitionLimits, RepositoryPath,
        ReviewFileInput, ReviewObject, ReviewObjectRole, ReviewSelectionPolicy, ReviewValue,
        ReviewValueReason, build_partition_plan, build_review_group_plan,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn partition() -> ReviewPartitionPlan {
        let files = [
            ("src/a.rs", ReviewValueTier::High, 220, 80, '1'),
            ("tests/a.rs", ReviewValueTier::Standard, 90, 20, '2'),
        ]
        .into_iter()
        .map(|(name, tier, score, size, marker)| {
            let path = path(name);
            ReviewFileInput {
                path: ChangedPath {
                    old_path: path.clone(),
                    new_path: path,
                    kind: FileChangeKind::Modified,
                },
                class: ReviewFileClass::Text,
                review_value: ReviewValue {
                    tier,
                    score,
                    reasons: BTreeSet::from([ReviewValueReason::SourceCode]),
                },
                objects: vec![ReviewObject {
                    role: ReviewObjectRole::ExactDiff,
                    content_sha256: digest(marker),
                    size_bytes: size,
                }],
                anchor_ids: Vec::new(),
            }
        });
        build_partition_plan(
            ReviewSnapshotIdentity::Local(LocalSnapshotIdentity {
                repository_identity_sha256: digest('a'),
                base_sha: GitSha::try_from("b".repeat(40)).unwrap(),
                head_sha: GitSha::try_from("c".repeat(40)).unwrap(),
                working_tree_sha256: digest('d'),
                exact_diff_manifest_sha256: digest('e'),
            }),
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
                max_file_bytes: 1_000,
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

    fn strategy() -> ReviewPreviewStrategy {
        let effort = ReviewEffort::Medium;
        ReviewPreviewStrategy {
            effort,
            rounds_per_group: effort.rounds(),
            max_turns_per_group: effort.max_group_turns(),
            max_parallel_groups: 4,
            budgets: AgentBudgetLimits {
                max_turns: 64,
                max_model_requests: 64,
                max_tool_calls: 256,
                max_repository_files: 2_000,
                max_repository_bytes: 32 * 1024 * 1024,
                max_input_tokens: 295_904,
                max_output_tokens: 4_096,
                max_cost_microusd: 5_000_000,
                max_candidate_findings: 25,
                max_elapsed_millis: 600_000,
            },
            max_inline_diff_bytes: 16 * 1024,
            target_request_input_tokens: 32_000,
            max_request_output_tokens: 4_096,
        }
    }

    #[test]
    fn preview_is_deterministic_and_projects_inline_decisions() {
        let partition = partition();
        let groups =
            build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic).unwrap();
        let input = groups
            .groups
            .iter()
            .map(|group| ReviewPreviewGroupInput {
                group_id: group.id.clone(),
                exact_diff_bytes: 17 * 1024,
                max_file_changed_lines: 50,
                total_changed_lines: 100,
                estimated_initial_input_tokens: 2_000,
            })
            .collect::<Vec<_>>();
        let rules = vec![ReviewPreviewRule {
            id: "rust.correctness".to_owned(),
            source: ReviewPreviewRuleSource::EmbeddedLanguage,
            matched_paths: vec![path("tests/a.rs"), path("src/a.rs")],
        }];
        let left = build_review_preview(
            &partition,
            &groups,
            strategy(),
            input.clone(),
            rules.clone(),
        )
        .unwrap();
        let right = build_review_preview(
            &partition,
            &groups,
            strategy(),
            input.into_iter().rev(),
            rules,
        )
        .unwrap();
        assert_eq!(left, right);
        assert!(
            left.groups.iter().all(|group| {
                group.initial_context == ReviewPreviewInitialContext::ManifestOnly
            })
        );
        assert!(left.groups.iter().all(|group| group.complex));
        left.validate_against(&partition, &groups).unwrap();
        assert_eq!(
            left.canonical_json().unwrap(),
            right.canonical_json().unwrap()
        );
        assert_eq!(left.human(), right.human());
    }

    #[test]
    fn token_target_can_force_manifest_only_without_partial_inline() {
        let partition = partition();
        let groups =
            build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic).unwrap();
        let input = groups.groups.iter().map(|group| ReviewPreviewGroupInput {
            group_id: group.id.clone(),
            exact_diff_bytes: 10,
            max_file_changed_lines: 10,
            total_changed_lines: 20,
            estimated_initial_input_tokens: 32_001,
        });
        let preview = build_review_preview(
            &partition,
            &groups,
            strategy(),
            input,
            Vec::<ReviewPreviewRule>::new(),
        )
        .unwrap();
        assert!(
            preview.groups.iter().all(|group| {
                group.initial_context == ReviewPreviewInitialContext::ManifestOnly
            })
        );
    }

    #[test]
    fn unsafe_rules_and_incomplete_group_measurements_fail_closed() {
        let partition = partition();
        let groups =
            build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic).unwrap();
        let bad_rule = ReviewPreviewRule {
            id: "do something".to_owned(),
            source: ReviewPreviewRuleSource::Generic,
            matched_paths: vec![path("src/a.rs")],
        };
        assert_eq!(
            build_review_preview(
                &partition,
                &groups,
                strategy(),
                groups.groups.iter().map(|group| ReviewPreviewGroupInput {
                    group_id: group.id.clone(),
                    exact_diff_bytes: 10,
                    max_file_changed_lines: 10,
                    total_changed_lines: 20,
                    estimated_initial_input_tokens: 100,
                }),
                [bad_rule],
            ),
            Err(ReviewPreviewError::InvalidRule)
        );
        assert_eq!(
            build_review_preview(
                &partition,
                &groups,
                strategy(),
                Vec::<ReviewPreviewGroupInput>::new(),
                Vec::<ReviewPreviewRule>::new(),
            ),
            Err(ReviewPreviewError::MissingGroupInput)
        );
    }

    #[test]
    fn human_and_json_projections_have_no_payload_or_authority_fields() {
        let partition = partition();
        let groups =
            build_review_group_plan(&partition, None, ReviewGroupingSource::Deterministic).unwrap();
        let preview = build_review_preview(
            &partition,
            &groups,
            strategy(),
            groups.groups.iter().map(|group| ReviewPreviewGroupInput {
                group_id: group.id.clone(),
                exact_diff_bytes: 10,
                max_file_changed_lines: 10,
                total_changed_lines: 20,
                estimated_initial_input_tokens: 100,
            }),
            Vec::<ReviewPreviewRule>::new(),
        )
        .unwrap();
        let combined = format!(
            "{}\n{}",
            preview.human(),
            String::from_utf8(preview.canonical_json().unwrap()).unwrap()
        );
        for forbidden in [
            "artifact_path",
            "credential",
            "diff_body",
            "network",
            "prompt",
            "provider_call",
            "response",
            "source_body",
        ] {
            assert!(!combined.contains(forbidden));
        }
    }
}
