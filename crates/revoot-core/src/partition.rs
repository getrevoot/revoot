//! Deterministic review-input selection, work-unit packing, and replay binding.
//!
//! The caller supplies already-validated immutable snapshot objects. This module
//! performs no filesystem, network, model, process, or publication operations.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AnchorId, ChangedPath, RepositoryPath, ReviewSnapshotIdentity, Sha256Digest};

const MAX_POLICY_PATTERNS: usize = 1_024;
const MAX_PATTERN_BYTES: usize = 1_024;
const MAX_PLAN_FILES: usize = 100_000;
const WORK_UNIT_PREFIX: &str = "wu2_";
const LOW_SIGNAL_BUDGET_DIVISOR: u64 = 10;
const MAX_LOW_SIGNAL_BYTES: u64 = 64 * 1_024;

/// Stable classification used by deterministic exclusion policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFileClass {
    Text,
    Generated,
    Binary,
    UnsupportedEncoding,
}

/// Coarse review-value tier used to allocate bounded model context.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewValueTier {
    Low,
    Standard,
    High,
}

/// Deterministic evidence explaining why a changed file received its value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewValueReason {
    BinaryArtifact,
    UnsupportedEncodingArtifact,
    GeneratedArtifact,
    Lockfile,
    SnapshotArtifact,
    Documentation,
    TestCode,
    SourceCode,
    Configuration,
    DependencyManifest,
    BuildOrDeployment,
    PublicInterface,
    DatabaseMigration,
    SensitiveSubsystem,
    DeletedFile,
    ConflictMarker,
    CredentialMaterial,
    OtherText,
}

/// Stable review value assigned without a model call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewValue {
    pub tier: ReviewValueTier,
    pub score: u8,
    pub reasons: BTreeSet<ReviewValueReason>,
}

impl ReviewValue {
    fn is_valid(&self) -> bool {
        !self.reasons.is_empty()
            && match self.tier {
                ReviewValueTier::Low => self.score < 50,
                ReviewValueTier::Standard => (50..200).contains(&self.score),
                ReviewValueTier::High => self.score >= 200,
            }
    }
}

/// Immutable content object made available to one review file.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewObject {
    pub role: ReviewObjectRole,
    pub content_sha256: Sha256Digest,
    pub size_bytes: u64,
}

/// Semantic role of an immutable review object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewObjectRole {
    ExactDiff,
    OldBlob,
    NewBlob,
    BoundedContext,
}

/// A file eligible for deterministic selection and partitioning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewFileInput {
    pub path: ChangedPath,
    pub class: ReviewFileClass,
    pub review_value: ReviewValue,
    pub objects: Vec<ReviewObject>,
    pub anchor_ids: Vec<AnchorId>,
}

impl ReviewFileInput {
    fn canonical_path(&self) -> &RepositoryPath {
        &self.path.new_path
    }

    fn total_bytes(&self) -> Option<u64> {
        self.objects
            .iter()
            .try_fold(0_u64, |total, object| total.checked_add(object.size_bytes))
    }
}

/// Closed deterministic exclusion policy. Patterns are literal path strings,
/// not globs or regular expressions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewSelectionPolicy {
    pub version: String,
    pub included_paths: BTreeSet<RepositoryPath>,
    pub included_prefixes: Vec<String>,
    pub included_suffixes: Vec<String>,
    pub excluded_paths: BTreeSet<RepositoryPath>,
    pub excluded_prefixes: Vec<String>,
    pub excluded_suffixes: Vec<String>,
    pub include_generated: bool,
    pub max_file_bytes: u64,
}

/// Hard deterministic partition bounds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionLimits {
    pub max_files: u32,
    pub max_total_bytes: u64,
    pub max_work_units: u32,
    pub max_files_per_work_unit: u32,
    pub max_bytes_per_work_unit: u64,
    pub max_anchors_per_work_unit: u32,
}

/// Invalid policy or partition limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartitionConfigurationError {
    PolicyVersion,
    PatternCount,
    Pattern,
    FileBytes,
    Files,
    TotalBytes,
    WorkUnits,
    FilesPerWorkUnit,
    BytesPerWorkUnit,
    AnchorsPerWorkUnit,
}

impl ReviewSelectionPolicy {
    /// Validate that policy data is bounded and unambiguous.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe version, empty/overlong pattern, too many
    /// patterns, duplicate pattern, or zero file-byte limit.
    pub fn validate(&self) -> Result<(), PartitionConfigurationError> {
        if !valid_label(&self.version) {
            return Err(PartitionConfigurationError::PolicyVersion);
        }
        if self.included_paths.len()
            + self.included_prefixes.len()
            + self.included_suffixes.len()
            + self.excluded_paths.len()
            + self.excluded_prefixes.len()
            + self.excluded_suffixes.len()
            > MAX_POLICY_PATTERNS
        {
            return Err(PartitionConfigurationError::PatternCount);
        }
        for patterns in [
            &self.included_prefixes,
            &self.included_suffixes,
            &self.excluded_prefixes,
            &self.excluded_suffixes,
        ] {
            if patterns.iter().any(|pattern| {
                pattern.is_empty()
                    || pattern.len() > MAX_PATTERN_BYTES
                    || pattern.contains('\0')
                    || pattern.chars().any(char::is_control)
            }) {
                return Err(PartitionConfigurationError::Pattern);
            }
            let unique: BTreeSet<_> = patterns.iter().collect();
            if unique.len() != patterns.len() {
                return Err(PartitionConfigurationError::Pattern);
            }
        }
        if self.max_file_bytes == 0 {
            return Err(PartitionConfigurationError::FileBytes);
        }
        Ok(())
    }
}

impl PartitionLimits {
    /// Validate nonzero and internally consistent hard limits.
    ///
    /// # Errors
    ///
    /// Returns the first unusable dimension.
    pub fn validate(self) -> Result<(), PartitionConfigurationError> {
        if self.max_files == 0
            || usize::try_from(self.max_files).unwrap_or(usize::MAX) > MAX_PLAN_FILES
        {
            return Err(PartitionConfigurationError::Files);
        }
        if self.max_total_bytes == 0 {
            return Err(PartitionConfigurationError::TotalBytes);
        }
        if self.max_work_units == 0 {
            return Err(PartitionConfigurationError::WorkUnits);
        }
        if self.max_files_per_work_unit == 0 || self.max_files_per_work_unit > self.max_files {
            return Err(PartitionConfigurationError::FilesPerWorkUnit);
        }
        if self.max_bytes_per_work_unit == 0 || self.max_bytes_per_work_unit > self.max_total_bytes
        {
            return Err(PartitionConfigurationError::BytesPerWorkUnit);
        }
        if self.max_anchors_per_work_unit == 0 {
            return Err(PartitionConfigurationError::AnchorsPerWorkUnit);
        }
        Ok(())
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

/// Classify one exact changed path before any model tokens are spent.
///
/// Path roles establish a conservative baseline. Cheap scans of newly added
/// diff lines can promote noisy artifacts when they contain structural hazards
/// such as merge-conflict markers or private credential material.
#[must_use]
pub fn classify_review_value(
    path: &ChangedPath,
    class: ReviewFileClass,
    exact_diff: Option<&str>,
) -> ReviewValue {
    let normalized = path.new_path.as_str().to_ascii_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    let components = normalized.split('/').collect::<Vec<_>>();
    let mut reasons = BTreeSet::new();
    let mut score = match class {
        ReviewFileClass::Binary => {
            reasons.insert(ReviewValueReason::BinaryArtifact);
            0
        }
        ReviewFileClass::UnsupportedEncoding => {
            reasons.insert(ReviewValueReason::UnsupportedEncodingArtifact);
            0
        }
        ReviewFileClass::Generated => {
            reasons.insert(ReviewValueReason::GeneratedArtifact);
            5
        }
        ReviewFileClass::Text if is_lockfile(file_name) => {
            reasons.insert(ReviewValueReason::Lockfile);
            10
        }
        ReviewFileClass::Text if is_snapshot(&normalized, file_name) => {
            reasons.insert(ReviewValueReason::SnapshotArtifact);
            15
        }
        ReviewFileClass::Text if is_documentation(&normalized, file_name) => {
            reasons.insert(ReviewValueReason::Documentation);
            30
        }
        ReviewFileClass::Text if is_test_path(&components, file_name) => {
            reasons.insert(ReviewValueReason::TestCode);
            90
        }
        ReviewFileClass::Text if is_source_file(file_name) => {
            reasons.insert(ReviewValueReason::SourceCode);
            120
        }
        ReviewFileClass::Text if is_configuration_file(file_name) => {
            reasons.insert(ReviewValueReason::Configuration);
            100
        }
        ReviewFileClass::Text => {
            reasons.insert(ReviewValueReason::OtherText);
            70
        }
    };

    if matches!(class, ReviewFileClass::Text | ReviewFileClass::Generated) {
        promote_path_roles(
            &normalized,
            file_name,
            &components,
            &mut score,
            &mut reasons,
        );
        if matches!(path.kind, crate::FileChangeKind::Deleted) {
            reasons.insert(ReviewValueReason::DeletedFile);
            score = score.saturating_add(10);
        }
        if let Some(diff) = exact_diff {
            let added = added_diff_lines(diff);
            if added.iter().any(|line| contains_conflict_marker(line)) {
                reasons.insert(ReviewValueReason::ConflictMarker);
                score = 255;
            } else if added.iter().any(|line| contains_credential_material(line)) {
                reasons.insert(ReviewValueReason::CredentialMaterial);
                score = score.max(250);
            }
        }
    }

    ReviewValue {
        tier: if score >= 200 {
            ReviewValueTier::High
        } else if score >= 50 {
            ReviewValueTier::Standard
        } else {
            ReviewValueTier::Low
        },
        score,
        reasons,
    }
}

fn promote_path_roles(
    normalized: &str,
    file_name: &str,
    components: &[&str],
    score: &mut u8,
    reasons: &mut BTreeSet<ReviewValueReason>,
) {
    if is_dependency_manifest(file_name) {
        reasons.insert(ReviewValueReason::DependencyManifest);
        *score = (*score).max(210);
    }
    if is_build_or_deployment(normalized, file_name, components) {
        reasons.insert(ReviewValueReason::BuildOrDeployment);
        *score = (*score).max(220);
    }
    if is_public_interface(normalized, file_name) {
        reasons.insert(ReviewValueReason::PublicInterface);
        *score = (*score).max(210);
    }
    if components.iter().any(|component| {
        matches!(
            *component,
            "migration" | "migrations" | "schema-migrations" | "database-migrations"
        )
    }) {
        reasons.insert(ReviewValueReason::DatabaseMigration);
        *score = (*score).max(240);
    }
    if components
        .iter()
        .any(|component| sensitive_component(component))
    {
        reasons.insert(ReviewValueReason::SensitiveSubsystem);
        *score = (*score).max(230);
    }
}

fn is_lockfile(file_name: &str) -> bool {
    extension_is(file_name, "lock")
        || matches!(
            file_name,
            "go.sum"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "composer.lock"
                | "gemfile.lock"
                | "podfile.lock"
                | "flake.lock"
        )
}

fn is_snapshot(path: &str, file_name: &str) -> bool {
    path.contains("/__snapshots__/")
        || path.contains("/snapshots/")
        || extension_is(file_name, "snap")
        || extension_is(file_name, "golden")
        || file_name.ends_with(".min.js")
        || file_name.ends_with(".min.css")
        || extension_is(file_name, "map")
}

fn is_documentation(path: &str, file_name: &str) -> bool {
    path.starts_with("docs/")
        || matches!(
            file_name,
            "readme" | "license" | "changelog" | "contributing"
        )
        || [".md", ".mdx", ".rst", ".adoc", ".txt"]
            .iter()
            .any(|suffix| file_name.ends_with(suffix))
}

fn is_test_path(components: &[&str], file_name: &str) -> bool {
    components
        .iter()
        .any(|component| matches!(*component, "test" | "tests" | "spec" | "specs" | "fixtures"))
        || file_name.contains("_test.")
        || file_name.contains(".test.")
        || file_name.contains(".spec.")
}

fn is_source_file(file_name: &str) -> bool {
    [
        ".rs", ".go", ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts",
        ".swift", ".c", ".h", ".cc", ".cpp", ".cs", ".rb", ".php", ".scala", ".ex", ".exs", ".erl",
        ".hrl", ".fs", ".fsx", ".sh", ".bash", ".zsh", ".fish", ".sql", ".vue", ".svelte",
    ]
    .iter()
    .any(|suffix| file_name.ends_with(suffix))
}

fn is_configuration_file(file_name: &str) -> bool {
    [
        ".toml", ".yaml", ".yml", ".json", ".jsonc", ".ini", ".cfg", ".conf", ".env", ".xml",
    ]
    .iter()
    .any(|suffix| file_name.ends_with(suffix))
}

fn is_dependency_manifest(file_name: &str) -> bool {
    matches!(
        file_name,
        "cargo.toml"
            | "package.json"
            | "pyproject.toml"
            | "go.mod"
            | "gemfile"
            | "composer.json"
            | "mix.exs"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "requirements.txt"
    ) || file_name.starts_with("requirements-") && extension_is(file_name, "txt")
}

fn is_build_or_deployment(path: &str, file_name: &str, components: &[&str]) -> bool {
    path.starts_with(".github/workflows/")
        || matches!(file_name, ".gitlab-ci.yml" | "dockerfile" | "makefile")
        || extension_is(file_name, "tf")
        || components.iter().any(|component| {
            matches!(
                *component,
                "ci" | "deploy"
                    | "deployment"
                    | "infra"
                    | "terraform"
                    | "k8s"
                    | "kubernetes"
                    | "helm"
            )
        })
}

fn is_public_interface(path: &str, file_name: &str) -> bool {
    path.contains("openapi")
        || path.contains("swagger")
        || extension_is(file_name, "proto")
        || extension_is(file_name, "graphql")
        || extension_is(file_name, "gql")
}

fn extension_is(file_name: &str, expected: &str) -> bool {
    std::path::Path::new(file_name)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| extension == expected)
}

fn sensitive_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    matches!(
        stem,
        "auth"
            | "authentication"
            | "authorization"
            | "permission"
            | "permissions"
            | "acl"
            | "crypto"
            | "cryptography"
            | "payment"
            | "payments"
            | "billing"
            | "secret"
            | "secrets"
    )
}

fn added_diff_lines(diff: &str) -> Vec<&str> {
    diff.lines()
        .filter_map(|line| line.strip_prefix('+'))
        .filter(|line| !line.starts_with("++"))
        .collect()
}

fn contains_conflict_marker(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("<<<<<<<") || line.starts_with(">>>>>>>") || line == "======="
}

fn contains_credential_material(line: &str) -> bool {
    let line = line.trim();
    line.contains("-----BEGIN PRIVATE KEY-----")
        || line.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || line.contains("-----BEGIN ") && line.contains(" PRIVATE KEY-----")
        || line.contains("github_pat_")
        || line.contains("ghp_")
        || line
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|word| word.len() == 20 && word.starts_with("AKIA"))
}

/// Stable reason one file was omitted before model work.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewOmissionReason {
    NotIncludedPolicy,
    ExactPathPolicy,
    PrefixPolicy,
    SuffixPolicy,
    GeneratedPolicy,
    Binary,
    UnsupportedEncoding,
    FileTooLarge,
    MissingExactDiff,
    EmptyObjectSet,
    DuplicateObjectRole,
    DuplicateAnchor,
    InputByteOverflow,
    FileBudget,
    TotalByteBudget,
    LowSignalBudget,
    WorkUnitBudget,
    WorkUnitFileCapacity,
    WorkUnitByteCapacity,
    WorkUnitAnchorCapacity,
}

/// An explicitly omitted path and its single precedence-selected reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OmittedReviewFile {
    pub path: ChangedPath,
    pub reason: ReviewOmissionReason,
}

/// One immutable file assignment inside a work unit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkUnitFile {
    pub path: ChangedPath,
    pub class: ReviewFileClass,
    pub review_value: ReviewValue,
    pub objects: Vec<ReviewObject>,
    pub anchor_ids: Vec<AnchorId>,
    pub input_bytes: u64,
}

/// Stable opaque work-unit identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkUnitId(String);

impl WorkUnitId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A deterministically packed bounded work unit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewWorkUnit {
    pub id: WorkUnitId,
    pub files: Vec<WorkUnitFile>,
    pub input_bytes: u64,
    pub anchor_count: u32,
}

/// Counts and omissions that never overstate review coverage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionCoverage {
    pub input_files: u32,
    pub included_files: u32,
    pub omitted_files: u32,
    pub included_bytes: u64,
    pub omission_reasons: BTreeMap<ReviewOmissionReason, u32>,
    pub complete: bool,
}

/// Canonical replay plan bound to one immutable snapshot and policy version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPartitionPlan {
    pub schema_version: String,
    pub snapshot: ReviewSnapshotIdentity,
    pub policy: ReviewSelectionPolicy,
    pub limits: PartitionLimits,
    pub work_units: Vec<ReviewWorkUnit>,
    pub omitted: Vec<OmittedReviewFile>,
    pub coverage: PartitionCoverage,
    pub plan_sha256: Sha256Digest,
}

impl ReviewPartitionPlan {
    pub const SCHEMA_VERSION: &'static str = "revoot.partition-plan/v2";

    /// Validate every derived count, order, work-unit ID, and plan digest.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed replay error for any tampering or contradiction.
    pub fn validate_replay(&self) -> Result<(), PartitionReplayError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(PartitionReplayError::SchemaVersion);
        }
        self.limits
            .validate()
            .map_err(PartitionReplayError::Configuration)?;
        self.policy
            .validate()
            .map_err(PartitionReplayError::Configuration)?;
        if !strictly_sorted(&self.policy.excluded_prefixes)
            || !strictly_sorted(&self.policy.excluded_suffixes)
        {
            return Err(PartitionReplayError::Configuration(
                PartitionConfigurationError::Pattern,
            ));
        }
        let mut previous_id: Option<&WorkUnitId> = None;
        let mut paths: BTreeSet<RepositoryPath> = BTreeSet::new();
        let mut anchors = BTreeSet::new();
        let mut included_files = 0_u32;
        let mut included_bytes = 0_u64;
        let mut included_low_signal_bytes = 0_u64;
        for unit in &self.work_units {
            if previous_id.is_some_and(|previous| previous >= &unit.id) {
                return Err(PartitionReplayError::WorkUnitOrder);
            }
            previous_id = Some(&unit.id);
            let (bytes, anchor_count) = validate_unit_files(&unit.files, &mut paths, &mut anchors)?;
            if bytes != unit.input_bytes || anchor_count != unit.anchor_count {
                return Err(PartitionReplayError::DerivedCount);
            }
            if unit.files.len()
                > usize::try_from(self.limits.max_files_per_work_unit).unwrap_or(usize::MAX)
                || bytes > self.limits.max_bytes_per_work_unit
                || anchor_count > self.limits.max_anchors_per_work_unit
            {
                return Err(PartitionReplayError::LimitExceeded);
            }
            let expected = derive_work_unit_id(&self.snapshot, &self.policy, &unit.files);
            if expected != unit.id {
                return Err(PartitionReplayError::WorkUnitId);
            }
            included_files = included_files
                .checked_add(
                    u32::try_from(unit.files.len())
                        .map_err(|_| PartitionReplayError::DerivedCount)?,
                )
                .ok_or(PartitionReplayError::DerivedCount)?;
            included_bytes = included_bytes
                .checked_add(bytes)
                .ok_or(PartitionReplayError::DerivedCount)?;
            included_low_signal_bytes = unit
                .files
                .iter()
                .filter(|file| file.review_value.tier == ReviewValueTier::Low)
                .try_fold(included_low_signal_bytes, |total, file| {
                    total.checked_add(file.input_bytes)
                })
                .ok_or(PartitionReplayError::DerivedCount)?;
        }
        if self.work_units.len() > usize::try_from(self.limits.max_work_units).unwrap_or(usize::MAX)
            || included_files > self.limits.max_files
            || included_bytes > self.limits.max_total_bytes
            || included_low_signal_bytes > low_signal_byte_limit(self.limits)
        {
            return Err(PartitionReplayError::LimitExceeded);
        }
        let mut omitted_reasons = BTreeMap::new();
        let mut previous_omitted: Option<&ChangedPath> = None;
        for item in &self.omitted {
            if previous_omitted.is_some_and(|previous| previous >= &item.path) {
                return Err(PartitionReplayError::OmissionOrder);
            }
            previous_omitted = Some(&item.path);
            if item.path.semantic_issue().is_some() || !paths.insert(item.path.new_path.clone()) {
                return Err(PartitionReplayError::DuplicatePath);
            }
            *omitted_reasons.entry(item.reason).or_insert(0_u32) += 1;
        }
        let omitted_files =
            u32::try_from(self.omitted.len()).map_err(|_| PartitionReplayError::DerivedCount)?;
        let input_files = included_files
            .checked_add(omitted_files)
            .ok_or(PartitionReplayError::DerivedCount)?;
        if self.coverage.input_files != input_files
            || self.coverage.included_files != included_files
            || self.coverage.omitted_files != omitted_files
            || self.coverage.included_bytes != included_bytes
            || self.coverage.omission_reasons != omitted_reasons
            || self.coverage.complete != self.omitted.is_empty()
        {
            return Err(PartitionReplayError::Coverage);
        }
        let expected_digest =
            derive_plan_digest(self).map_err(|_| PartitionReplayError::Serialization)?;
        if expected_digest != self.plan_sha256 {
            return Err(PartitionReplayError::PlanDigest);
        }
        Ok(())
    }

    /// Serialize the validated plan with stable struct and collection ordering.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or replay validation rejects it.
    pub fn canonical_json(&self) -> Result<Vec<u8>, PartitionCanonicalError> {
        self.validate_replay()
            .map_err(PartitionCanonicalError::Replay)?;
        serde_json::to_vec(self).map_err(PartitionCanonicalError::Serialization)
    }
}

/// Failure while constructing a deterministic plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PartitionBuildError {
    Configuration(PartitionConfigurationError),
    TooManyInputs,
    DuplicatePath(ChangedPath),
    InvalidChangedPath(ChangedPath),
    InvalidReviewValue(ChangedPath),
    Serialization,
    InternalReplay(PartitionReplayError),
}

/// Failure while validating a serialized or retained replay plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PartitionReplayError {
    SchemaVersion,
    PolicyVersion,
    Configuration(PartitionConfigurationError),
    WorkUnitOrder,
    OmissionOrder,
    DuplicatePath,
    DuplicateAnchor,
    FileOrder,
    ObjectOrder,
    AnchorOrder,
    DerivedCount,
    LimitExceeded,
    WorkUnitId,
    Coverage,
    PlanDigest,
    Serialization,
}

/// Error from canonical serialization.
#[derive(Debug)]
pub enum PartitionCanonicalError {
    Replay(PartitionReplayError),
    Serialization(serde_json::Error),
}

/// Build a deterministic plan independent of input iteration order.
///
/// Files are filtered by a fixed reason precedence, then packed by review value
/// before size. Low-signal artifacts receive a small shared byte quota. Resulting
/// work units are sorted by derived opaque ID for canonical serialization.
///
/// # Errors
///
/// Rejects invalid configuration, excessive/duplicate inputs, or an internal
/// replay mismatch.
pub fn build_partition_plan(
    snapshot: impl Into<ReviewSnapshotIdentity>,
    policy: &ReviewSelectionPolicy,
    limits: PartitionLimits,
    files: impl IntoIterator<Item = ReviewFileInput>,
) -> Result<ReviewPartitionPlan, PartitionBuildError> {
    policy
        .validate()
        .map_err(PartitionBuildError::Configuration)?;
    limits
        .validate()
        .map_err(PartitionBuildError::Configuration)?;
    let files: Vec<_> = files.into_iter().collect();
    if files.len() > MAX_PLAN_FILES {
        return Err(PartitionBuildError::TooManyInputs);
    }
    let mut normalized_policy = policy.clone();
    normalized_policy.excluded_prefixes.sort();
    normalized_policy.excluded_suffixes.sort();
    let (included, omitted) = prepare_inputs(files, &normalized_policy)?;
    let packed = pack_files(included, omitted, limits);
    finalize_plan(snapshot.into(), &normalized_policy, limits, packed)
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn prepare_inputs(
    mut files: Vec<ReviewFileInput>,
    policy: &ReviewSelectionPolicy,
) -> Result<(Vec<WorkUnitFile>, Vec<OmittedReviewFile>), PartitionBuildError> {
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut canonical_paths = BTreeSet::new();
    for file in &files {
        if file.path.semantic_issue().is_some() {
            return Err(PartitionBuildError::InvalidChangedPath(file.path.clone()));
        }
        if !file.review_value.is_valid() {
            return Err(PartitionBuildError::InvalidReviewValue(file.path.clone()));
        }
        if !canonical_paths.insert(file.canonical_path().clone()) {
            return Err(PartitionBuildError::DuplicatePath(file.path.clone()));
        }
    }

    let mut included = Vec::new();
    let mut omitted = Vec::new();
    let mut global_anchors = BTreeSet::new();
    for file in files {
        match prepare_file(file, policy, &mut global_anchors) {
            Ok(file) => included.push(file),
            Err(item) => omitted.push(item),
        }
    }
    included.sort_by(|left, right| {
        right
            .review_value
            .tier
            .cmp(&left.review_value.tier)
            .then_with(|| right.review_value.score.cmp(&left.review_value.score))
            .then_with(|| left.input_bytes.cmp(&right.input_bytes))
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok((included, omitted))
}

struct PackingResult {
    bins: Vec<Vec<WorkUnitFile>>,
    omitted: Vec<OmittedReviewFile>,
    admitted_files: u32,
    admitted_bytes: u64,
}

const fn low_signal_byte_limit(limits: PartitionLimits) -> u64 {
    let proportional = limits.max_total_bytes / LOW_SIGNAL_BUDGET_DIVISOR;
    if proportional < MAX_LOW_SIGNAL_BYTES {
        proportional
    } else {
        MAX_LOW_SIGNAL_BYTES
    }
}

fn file_capacity_reason(
    file: &WorkUnitFile,
    limits: PartitionLimits,
    admitted_files: u32,
    admitted_bytes: u64,
    admitted_low_signal_bytes: u64,
) -> Option<ReviewOmissionReason> {
    if admitted_files >= limits.max_files {
        Some(ReviewOmissionReason::FileBudget)
    } else if file.review_value.tier == ReviewValueTier::Low
        && admitted_low_signal_bytes
            .checked_add(file.input_bytes)
            .is_none_or(|total| total > low_signal_byte_limit(limits))
    {
        Some(ReviewOmissionReason::LowSignalBudget)
    } else if admitted_bytes
        .checked_add(file.input_bytes)
        .is_none_or(|total| total > limits.max_total_bytes)
    {
        Some(ReviewOmissionReason::TotalByteBudget)
    } else if file.input_bytes > limits.max_bytes_per_work_unit {
        Some(ReviewOmissionReason::WorkUnitByteCapacity)
    } else if file.anchor_ids.len()
        > usize::try_from(limits.max_anchors_per_work_unit).unwrap_or(usize::MAX)
    {
        Some(ReviewOmissionReason::WorkUnitAnchorCapacity)
    } else {
        None
    }
}

fn pack_files(
    included: Vec<WorkUnitFile>,
    mut omitted: Vec<OmittedReviewFile>,
    limits: PartitionLimits,
) -> PackingResult {
    let mut bins: Vec<Vec<WorkUnitFile>> = Vec::new();
    let mut admitted_files = 0_u32;
    let mut admitted_bytes = 0_u64;
    let mut admitted_low_signal_bytes = 0_u64;
    for file in included {
        if let Some(reason) = file_capacity_reason(
            &file,
            limits,
            admitted_files,
            admitted_bytes,
            admitted_low_signal_bytes,
        ) {
            omitted.push(OmittedReviewFile {
                path: file.path,
                reason,
            });
            continue;
        }

        let mut destination = None;
        for (index, bin) in bins.iter().enumerate() {
            let bytes = bin.iter().map(|entry| entry.input_bytes).sum::<u64>();
            let anchors = bin
                .iter()
                .map(|entry| entry.anchor_ids.len())
                .sum::<usize>();
            if bin.len() < usize::try_from(limits.max_files_per_work_unit).unwrap_or(usize::MAX)
                && bytes
                    .checked_add(file.input_bytes)
                    .is_some_and(|total| total <= limits.max_bytes_per_work_unit)
                && anchors
                    .checked_add(file.anchor_ids.len())
                    .is_some_and(|total| {
                        total
                            <= usize::try_from(limits.max_anchors_per_work_unit)
                                .unwrap_or(usize::MAX)
                    })
            {
                destination = Some(index);
                break;
            }
        }
        if destination.is_none()
            && bins.len() < usize::try_from(limits.max_work_units).unwrap_or(usize::MAX)
        {
            bins.push(Vec::new());
            destination = Some(bins.len() - 1);
        }
        let Some(destination) = destination else {
            let reason = if bins.iter().all(|bin| {
                bin.len() >= usize::try_from(limits.max_files_per_work_unit).unwrap_or(usize::MAX)
            }) {
                ReviewOmissionReason::WorkUnitFileCapacity
            } else if bins.iter().all(|bin| {
                bin.iter()
                    .map(|entry| entry.input_bytes)
                    .sum::<u64>()
                    .checked_add(file.input_bytes)
                    .is_none_or(|total| total > limits.max_bytes_per_work_unit)
            }) {
                ReviewOmissionReason::WorkUnitByteCapacity
            } else if bins.iter().all(|bin| {
                bin.iter()
                    .map(|entry| entry.anchor_ids.len())
                    .sum::<usize>()
                    .checked_add(file.anchor_ids.len())
                    .is_none_or(|total| {
                        total
                            > usize::try_from(limits.max_anchors_per_work_unit)
                                .unwrap_or(usize::MAX)
                    })
            }) {
                ReviewOmissionReason::WorkUnitAnchorCapacity
            } else {
                ReviewOmissionReason::WorkUnitBudget
            };
            omitted.push(OmittedReviewFile {
                path: file.path,
                reason,
            });
            continue;
        };
        admitted_files += 1;
        admitted_bytes += file.input_bytes;
        if file.review_value.tier == ReviewValueTier::Low {
            admitted_low_signal_bytes += file.input_bytes;
        }
        bins[destination].push(file);
    }
    PackingResult {
        bins,
        omitted,
        admitted_files,
        admitted_bytes,
    }
}

fn finalize_plan(
    snapshot: ReviewSnapshotIdentity,
    policy: &ReviewSelectionPolicy,
    limits: PartitionLimits,
    packed: PackingResult,
) -> Result<ReviewPartitionPlan, PartitionBuildError> {
    let mut work_units = Vec::with_capacity(packed.bins.len());
    for mut files in packed.bins {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let input_bytes = files.iter().map(|file| file.input_bytes).sum();
        let anchor_count = u32::try_from(
            files
                .iter()
                .map(|file| file.anchor_ids.len())
                .sum::<usize>(),
        )
        .unwrap_or(u32::MAX);
        work_units.push(ReviewWorkUnit {
            id: derive_work_unit_id(&snapshot, policy, &files),
            files,
            input_bytes,
            anchor_count,
        });
    }
    work_units.sort_by(|left, right| left.id.cmp(&right.id));
    let mut omitted = packed.omitted;
    omitted.sort_by(|left, right| left.path.cmp(&right.path));
    let mut omission_reasons = BTreeMap::new();
    for item in &omitted {
        *omission_reasons.entry(item.reason).or_insert(0_u32) += 1;
    }
    let omitted_files =
        u32::try_from(omitted.len()).map_err(|_| PartitionBuildError::TooManyInputs)?;
    let input_files = packed
        .admitted_files
        .checked_add(omitted_files)
        .ok_or(PartitionBuildError::TooManyInputs)?;
    let coverage = PartitionCoverage {
        input_files,
        included_files: packed.admitted_files,
        omitted_files,
        included_bytes: packed.admitted_bytes,
        omission_reasons,
        complete: omitted.is_empty(),
    };
    let mut plan = ReviewPartitionPlan {
        schema_version: ReviewPartitionPlan::SCHEMA_VERSION.to_owned(),
        snapshot,
        policy: policy.clone(),
        limits,
        work_units,
        omitted,
        coverage,
        plan_sha256: Sha256Digest::of_bytes(&[]),
    };
    plan.plan_sha256 = derive_plan_digest(&plan).map_err(|_| PartitionBuildError::Serialization)?;
    plan.validate_replay()
        .map_err(PartitionBuildError::InternalReplay)?;
    Ok(plan)
}

fn prepare_file(
    mut file: ReviewFileInput,
    policy: &ReviewSelectionPolicy,
    global_anchors: &mut BTreeSet<AnchorId>,
) -> Result<WorkUnitFile, OmittedReviewFile> {
    let path = file.path.clone();
    let reason = selection_reason(&file, policy);
    if let Some(reason) = reason {
        return Err(OmittedReviewFile { path, reason });
    }
    file.objects.sort();
    if file
        .objects
        .windows(2)
        .any(|pair| pair[0].role == pair[1].role)
    {
        return Err(OmittedReviewFile {
            path,
            reason: ReviewOmissionReason::DuplicateObjectRole,
        });
    }
    file.anchor_ids.sort();
    if file.anchor_ids.windows(2).any(|pair| pair[0] == pair[1])
        || file
            .anchor_ids
            .iter()
            .any(|anchor| global_anchors.contains(anchor))
    {
        return Err(OmittedReviewFile {
            path,
            reason: ReviewOmissionReason::DuplicateAnchor,
        });
    }
    global_anchors.extend(file.anchor_ids.iter().cloned());
    let Some(input_bytes) = file.total_bytes() else {
        return Err(OmittedReviewFile {
            path,
            reason: ReviewOmissionReason::InputByteOverflow,
        });
    };
    Ok(WorkUnitFile {
        path: file.path,
        class: file.class,
        review_value: file.review_value,
        objects: file.objects,
        anchor_ids: file.anchor_ids,
        input_bytes,
    })
}

fn selection_reason(
    file: &ReviewFileInput,
    policy: &ReviewSelectionPolicy,
) -> Option<ReviewOmissionReason> {
    let path = file.canonical_path();
    let has_includes = !policy.included_paths.is_empty()
        || !policy.included_prefixes.is_empty()
        || !policy.included_suffixes.is_empty();
    let included = policy.included_paths.contains(path)
        || policy
            .included_prefixes
            .iter()
            .any(|prefix| path.as_str().starts_with(prefix))
        || policy
            .included_suffixes
            .iter()
            .any(|suffix| path.as_str().ends_with(suffix));
    if has_includes && !included {
        return Some(ReviewOmissionReason::NotIncludedPolicy);
    }
    if policy.excluded_paths.contains(path) {
        return Some(ReviewOmissionReason::ExactPathPolicy);
    }
    if policy
        .excluded_prefixes
        .iter()
        .any(|prefix| path.as_str().starts_with(prefix))
    {
        return Some(ReviewOmissionReason::PrefixPolicy);
    }
    if policy
        .excluded_suffixes
        .iter()
        .any(|suffix| path.as_str().ends_with(suffix))
    {
        return Some(ReviewOmissionReason::SuffixPolicy);
    }
    match file.class {
        ReviewFileClass::Generated if !policy.include_generated => {
            return Some(ReviewOmissionReason::GeneratedPolicy);
        }
        ReviewFileClass::Binary => return Some(ReviewOmissionReason::Binary),
        ReviewFileClass::UnsupportedEncoding => {
            return Some(ReviewOmissionReason::UnsupportedEncoding);
        }
        ReviewFileClass::Text | ReviewFileClass::Generated => {}
    }
    if file.objects.is_empty() {
        return Some(ReviewOmissionReason::EmptyObjectSet);
    }
    if !file
        .objects
        .iter()
        .any(|object| object.role == ReviewObjectRole::ExactDiff)
    {
        return Some(ReviewOmissionReason::MissingExactDiff);
    }
    match file.total_bytes() {
        None => Some(ReviewOmissionReason::InputByteOverflow),
        Some(bytes) if bytes > policy.max_file_bytes => Some(ReviewOmissionReason::FileTooLarge),
        Some(_) => None,
    }
}

fn validate_unit_files(
    files: &[WorkUnitFile],
    paths: &mut BTreeSet<RepositoryPath>,
    anchors: &mut BTreeSet<AnchorId>,
) -> Result<(u64, u32), PartitionReplayError> {
    let mut previous_path: Option<&ChangedPath> = None;
    let mut bytes = 0_u64;
    let mut anchor_count = 0_u32;
    for file in files {
        if previous_path.is_some_and(|previous| previous >= &file.path) {
            return Err(PartitionReplayError::FileOrder);
        }
        previous_path = Some(&file.path);
        if file.path.semantic_issue().is_some() || !paths.insert(file.path.new_path.clone()) {
            return Err(PartitionReplayError::DuplicatePath);
        }
        if !file.review_value.is_valid()
            || file.objects.is_empty()
            || !file
                .objects
                .iter()
                .any(|object| object.role == ReviewObjectRole::ExactDiff)
        {
            return Err(PartitionReplayError::DerivedCount);
        }
        if file.objects.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PartitionReplayError::ObjectOrder);
        }
        if file.anchor_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PartitionReplayError::AnchorOrder);
        }
        if file
            .anchor_ids
            .iter()
            .any(|anchor| !anchors.insert(anchor.clone()))
        {
            return Err(PartitionReplayError::DuplicateAnchor);
        }
        let object_bytes = file
            .objects
            .iter()
            .try_fold(0_u64, |total, object| total.checked_add(object.size_bytes))
            .ok_or(PartitionReplayError::DerivedCount)?;
        if object_bytes != file.input_bytes {
            return Err(PartitionReplayError::DerivedCount);
        }
        bytes = bytes
            .checked_add(object_bytes)
            .ok_or(PartitionReplayError::DerivedCount)?;
        anchor_count = anchor_count
            .checked_add(
                u32::try_from(file.anchor_ids.len())
                    .map_err(|_| PartitionReplayError::DerivedCount)?,
            )
            .ok_or(PartitionReplayError::DerivedCount)?;
    }
    Ok((bytes, anchor_count))
}

fn derive_work_unit_id(
    snapshot: &ReviewSnapshotIdentity,
    policy: &ReviewSelectionPolicy,
    files: &[WorkUnitFile],
) -> WorkUnitId {
    let mut hasher = Sha256::new();
    hash_serialized(&mut hasher, "revoot-work-unit-v2");
    hash_serialized(&mut hasher, snapshot);
    hash_serialized(&mut hasher, policy);
    hash_serialized(&mut hasher, files);
    WorkUnitId(format!("{WORK_UNIT_PREFIX}{:x}", hasher.finalize()))
}

#[derive(Serialize)]
struct PlanDigestView<'a> {
    schema_version: &'a str,
    snapshot: &'a ReviewSnapshotIdentity,
    policy: &'a ReviewSelectionPolicy,
    limits: PartitionLimits,
    work_units: &'a [ReviewWorkUnit],
    omitted: &'a [OmittedReviewFile],
    coverage: &'a PartitionCoverage,
}

fn derive_plan_digest(plan: &ReviewPartitionPlan) -> Result<Sha256Digest, serde_json::Error> {
    let view = PlanDigestView {
        schema_version: &plan.schema_version,
        snapshot: &plan.snapshot,
        policy: &plan.policy,
        limits: plan.limits,
        work_units: &plan.work_units,
        omitted: &plan.omitted,
        coverage: &plan.coverage,
    };
    Ok(Sha256Digest::of_bytes(&serde_json::to_vec(&view)?))
}

fn hash_serialized(hasher: &mut Sha256, value: &(impl Serialize + ?Sized)) {
    let bytes = serde_json::to_vec(value).expect("domain values serialize infallibly");
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use crate::GitLabSnapshotIdentity;

    use super::*;
    use crate::{
        DiffRefs, DiffVersionId, DiffVersionRecord, FileChangeKind, GitLabDiffVersionIdentity,
        MergeRequestIid, ProjectId, SnapshotScope,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn snapshot() -> GitLabSnapshotIdentity {
        GitLabDiffVersionIdentity {
            scope: SnapshotScope {
                instance_origin_digest: digest('a'),
                project_id: ProjectId::try_from(1).unwrap(),
                merge_request_iid: MergeRequestIid::try_from(2).unwrap(),
            },
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(3).unwrap(),
                refs: DiffRefs {
                    base_sha: "b".repeat(40).try_into().unwrap(),
                    start_sha: "c".repeat(40).try_into().unwrap(),
                    head_sha: "d".repeat(40).try_into().unwrap(),
                },
            },
        }
        .freeze(digest('e'))
    }

    fn policy() -> ReviewSelectionPolicy {
        ReviewSelectionPolicy {
            version: "selection-v1".to_owned(),
            included_paths: BTreeSet::new(),
            included_prefixes: Vec::new(),
            included_suffixes: Vec::new(),
            excluded_paths: BTreeSet::new(),
            excluded_prefixes: vec!["vendor/".to_owned()],
            excluded_suffixes: vec![".min.js".to_owned()],
            include_generated: false,
            max_file_bytes: 1_000,
        }
    }

    const fn limits() -> PartitionLimits {
        PartitionLimits {
            max_files: 10,
            max_total_bytes: 1_000,
            max_work_units: 3,
            max_files_per_work_unit: 2,
            max_bytes_per_work_unit: 180,
            max_anchors_per_work_unit: 4,
        }
    }

    fn anchor(marker: char) -> AnchorId {
        AnchorId::try_from(format!("ga1_{}", marker.to_string().repeat(64))).unwrap()
    }

    fn file(name: &str, bytes: u64, marker: char) -> ReviewFileInput {
        let path = RepositoryPath::try_from(name.to_owned()).unwrap();
        let changed = ChangedPath {
            old_path: path.clone(),
            new_path: path,
            kind: FileChangeKind::Modified,
        };
        ReviewFileInput {
            review_value: classify_review_value(&changed, ReviewFileClass::Text, None),
            path: changed,
            class: ReviewFileClass::Text,
            objects: vec![ReviewObject {
                role: ReviewObjectRole::ExactDiff,
                content_sha256: digest(marker),
                size_bytes: bytes,
            }],
            anchor_ids: vec![anchor(marker)],
        }
    }

    #[test]
    fn plan_is_input_order_independent_and_replay_valid() {
        let forward = build_partition_plan(
            snapshot(),
            &policy(),
            limits(),
            [
                file("a.rs", 100, '1'),
                file("b.rs", 80, '2'),
                file("c.rs", 70, '3'),
            ],
        )
        .unwrap();
        let reverse = build_partition_plan(
            snapshot(),
            &policy(),
            limits(),
            [
                file("c.rs", 70, '3'),
                file("b.rs", 80, '2'),
                file("a.rs", 100, '1'),
            ],
        )
        .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.work_units.len(), 2);
        assert!(forward.coverage.complete);
        assert!(forward.validate_replay().is_ok());
        assert_eq!(
            forward.canonical_json().unwrap(),
            reverse.canonical_json().unwrap()
        );
    }

    #[test]
    fn exclusions_have_stable_reason_precedence_and_never_claim_complete() {
        let mut generated = file("vendor/generated.min.js", 10, '1');
        generated.class = ReviewFileClass::Generated;
        let plan = build_partition_plan(snapshot(), &policy(), limits(), [generated]).unwrap();
        assert_eq!(plan.coverage.included_files, 0);
        assert_eq!(plan.coverage.omitted_files, 1);
        assert!(!plan.coverage.complete);
        assert_eq!(plan.omitted[0].reason, ReviewOmissionReason::PrefixPolicy);
    }

    #[test]
    fn inclusion_policy_omits_nonmatching_files_without_claiming_complete_coverage() {
        let mut selection = policy();
        selection.included_prefixes = vec!["src/".to_owned()];
        let plan = build_partition_plan(
            snapshot(),
            &selection,
            limits(),
            [file("src/lib.rs", 10, '1'), file("tests/lib.rs", 10, '2')],
        )
        .unwrap();
        assert_eq!(plan.coverage.included_files, 1);
        assert_eq!(plan.coverage.omitted_files, 1);
        assert!(!plan.coverage.complete);
        assert_eq!(
            plan.omitted[0].reason,
            ReviewOmissionReason::NotIncludedPolicy
        );
    }

    #[test]
    fn duplicate_paths_and_global_anchors_fail_closed() {
        assert!(matches!(
            build_partition_plan(
                snapshot(),
                &policy(),
                limits(),
                [file("a.rs", 10, '1'), file("a.rs", 11, '2')]
            ),
            Err(PartitionBuildError::DuplicatePath(_))
        ));

        let first = file("a.rs", 10, '1');
        let mut second = file("b.rs", 10, '2');
        second.anchor_ids = first.anchor_ids.clone();
        let plan = build_partition_plan(snapshot(), &policy(), limits(), [first, second]).unwrap();
        assert_eq!(plan.coverage.included_files, 1);
        assert_eq!(
            plan.omitted[0].reason,
            ReviewOmissionReason::DuplicateAnchor
        );
    }

    #[test]
    fn malformed_objects_and_budget_exhaustion_are_visible_omissions() {
        let mut no_diff = file("a.rs", 10, '1');
        no_diff.objects[0].role = ReviewObjectRole::NewBlob;
        let mut too_large = file("b.rs", 1_001, '2');
        too_large.objects.push(ReviewObject {
            role: ReviewObjectRole::NewBlob,
            content_sha256: digest('f'),
            size_bytes: 1,
        });
        let plan =
            build_partition_plan(snapshot(), &policy(), limits(), [no_diff, too_large]).unwrap();
        assert_eq!(plan.coverage.included_files, 0);
        assert_eq!(plan.coverage.omitted_files, 2);
        assert!(
            plan.coverage
                .omission_reasons
                .contains_key(&ReviewOmissionReason::MissingExactDiff)
        );
        assert!(
            plan.coverage
                .omission_reasons
                .contains_key(&ReviewOmissionReason::FileTooLarge)
        );
    }

    #[test]
    fn tampered_work_unit_and_plan_digests_are_rejected() {
        let mut plan =
            build_partition_plan(snapshot(), &policy(), limits(), [file("a.rs", 10, '1')]).unwrap();
        plan.work_units[0].files[0].input_bytes += 1;
        assert_eq!(
            plan.validate_replay(),
            Err(PartitionReplayError::DerivedCount)
        );

        let mut plan =
            build_partition_plan(snapshot(), &policy(), limits(), [file("a.rs", 10, '1')]).unwrap();
        plan.plan_sha256 = digest('f');
        assert_eq!(
            plan.validate_replay(),
            Err(PartitionReplayError::PlanDigest)
        );
    }

    #[test]
    fn oversized_single_file_is_not_forced_into_a_work_unit() {
        let mut policy = policy();
        policy.max_file_bytes = 1_000;
        let plan =
            build_partition_plan(snapshot(), &policy, limits(), [file("a.rs", 181, '1')]).unwrap();
        assert!(plan.work_units.is_empty());
        assert_eq!(
            plan.omitted[0].reason,
            ReviewOmissionReason::WorkUnitByteCapacity
        );
        assert!(!plan.coverage.complete);
    }

    #[test]
    fn classifier_demotes_noise_and_promotes_local_hazards_without_a_model() {
        let lock = file("Cargo.lock", 10, '1');
        assert_eq!(lock.review_value.tier, ReviewValueTier::Low);
        assert!(
            lock.review_value
                .reasons
                .contains(&ReviewValueReason::Lockfile)
        );

        let changed = lock.path.clone();
        let conflict = classify_review_value(
            &changed,
            ReviewFileClass::Text,
            Some("@@ -1 +1,2 @@\n package = \"demo\"\n+<<<<<<< HEAD\n"),
        );
        assert_eq!(conflict.tier, ReviewValueTier::High);
        assert_eq!(conflict.score, 255);
        assert!(
            conflict
                .reasons
                .contains(&ReviewValueReason::ConflictMarker)
        );

        let sensitive_path = file("src/auth.rs", 10, '2').path;
        let sensitive = classify_review_value(&sensitive_path, ReviewFileClass::Text, None);
        assert_eq!(sensitive.tier, ReviewValueTier::High);
        assert!(
            sensitive
                .reasons
                .contains(&ReviewValueReason::SensitiveSubsystem)
        );

        let documentation_path = file("docs/design.md", 10, '3').path;
        let documentation = classify_review_value(&documentation_path, ReviewFileClass::Text, None);
        assert_eq!(documentation.tier, ReviewValueTier::Low);

        let manifest_path = file("Cargo.toml", 10, '4').path;
        let manifest = classify_review_value(&manifest_path, ReviewFileClass::Text, None);
        assert_eq!(manifest.tier, ReviewValueTier::High);
        assert!(
            manifest
                .reasons
                .contains(&ReviewValueReason::DependencyManifest)
        );

        let binary_path = file("assets/logo.png", 10, '5').path;
        let binary = classify_review_value(&binary_path, ReviewFileClass::Binary, None);
        assert_eq!(binary.tier, ReviewValueTier::Low);
        assert_eq!(binary.score, 0);
    }

    #[test]
    fn high_value_files_win_budget_before_larger_low_signal_files() {
        let mut constrained = limits();
        constrained.max_total_bytes = 100;
        constrained.max_bytes_per_work_unit = 100;
        let high = file("src/auth.rs", 80, '1');
        let low = file("Cargo.lock", 90, '2');
        let plan = build_partition_plan(snapshot(), &policy(), constrained, [low, high]).unwrap();

        let included = plan
            .work_units
            .iter()
            .flat_map(|unit| unit.files.iter())
            .map(|file| file.path.new_path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(included, ["src/auth.rs"]);
        assert_eq!(plan.omitted.len(), 1);
        assert_eq!(
            plan.omitted[0].reason,
            ReviewOmissionReason::LowSignalBudget
        );
    }

    #[test]
    fn low_signal_files_share_a_small_explicit_quota() {
        let mut lock = file("Cargo.lock", 101, '1');
        lock.review_value = classify_review_value(&lock.path, lock.class, None);
        let plan = build_partition_plan(snapshot(), &policy(), limits(), [lock]).unwrap();

        assert!(plan.work_units.is_empty());
        assert_eq!(
            plan.omitted[0].reason,
            ReviewOmissionReason::LowSignalBudget
        );
    }
}
