//! Deterministic local hazard classification for diff hunks.
//!
//! Inputs contain only paths, status enums, line-class counts, page counts, and
//! fixed categorical tokens. Outputs retain no source text or token inventory.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{FileChangeKind, RepositoryPath, ReviewValueTier};

const MAX_PATH_BYTES: usize = 4 * 1_024;
const MAX_HUNKS: usize = 4_096;
const MAX_HUNK_ID_BYTES: usize = 128;
const MAX_HUNK_LINES: u32 = 1_000_000;
const MAX_HUNK_PAGES: u32 = 4_096;
const MAX_REPORT_BYTES: usize = 1024 * 1024;

/// Counts of structural unified-diff line classes in one hunk.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffHunkLineClasses {
    pub added: u32,
    pub deleted: u32,
    pub context: u32,
}

/// Fixed lexical or structural token emitted by a bounded local scanner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffHazardToken {
    AuthenticationBoundary,
    AuthorizationCheck,
    PermissionGrant,
    PermissionRevoke,
    SchemaDefinition,
    DataMigration,
    Locking,
    AtomicOperation,
    Threading,
    AsyncBoundary,
    UnsafeOperation,
    ForeignFunction,
    PanicPath,
    IgnoredError,
    UncheckedResult,
    PublicSymbol,
    BreakingPublicSignature,
    ConfigurationKey,
    FeatureFlag,
    DependencyDeclaration,
    DependencyVersion,
}

/// Metadata-only input for one exact hunk.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffHazardHunkInput {
    pub hunk_id: String,
    pub total_pages: u32,
    pub lines: DiffHunkLineClasses,
    pub tokens: BTreeSet<DiffHazardToken>,
}

/// Metadata-only input for one selected file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffHazardFileInput {
    pub path: RepositoryPath,
    pub status: FileChangeKind,
    pub tier: ReviewValueTier,
    pub hunks: Vec<DiffHazardHunkInput>,
}

/// Stable local signal requiring extra inspection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffHazardSignal {
    Authentication,
    Permissions,
    DatabaseMigration,
    Concurrency,
    UnsafeCode,
    ErrorHandling,
    PublicApi,
    Configuration,
    Dependencies,
}

/// Delivery requirement after deterministic promotion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffHazardInspection {
    TierBaseline,
    AllPages,
}

/// Stable decision for one hunk. Input tokens and line counts are not retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffHunkHazardDecision {
    pub hunk_id: String,
    pub total_pages: u32,
    pub signals: BTreeSet<DiffHazardSignal>,
    pub inspection: DiffHazardInspection,
    pub promoted: bool,
}

/// Bounded deterministic hazard output for one selected file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffHazardReport {
    pub schema_version: String,
    pub path: RepositoryPath,
    pub status: FileChangeKind,
    pub original_tier: ReviewValueTier,
    pub effective_tier: ReviewValueTier,
    pub signals: BTreeSet<DiffHazardSignal>,
    pub promoted_hunks: u32,
    pub hunks: Vec<DiffHunkHazardDecision>,
}

impl DiffHazardReport {
    pub const SCHEMA_VERSION: &'static str = "revoot.diff-hazards/v1";

    /// Validate derived signal, promotion, order, and count invariants.
    ///
    /// # Errors
    ///
    /// Returns a closed error if a retained or deserialized report is
    /// internally inconsistent.
    pub fn validate(&self) -> Result<(), DiffHazardError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(DiffHazardError::SchemaVersion);
        }
        validate_path(&self.path)?;
        if self.hunks.len() > MAX_HUNKS {
            return Err(DiffHazardError::HunkLimit);
        }
        if self.hunks.is_empty() && self.status != FileChangeKind::Renamed {
            return Err(DiffHazardError::MissingHunks);
        }
        let mut previous: Option<&str> = None;
        let path_hazards = path_signals(self.path.as_str());
        let mut union = path_hazards.clone();
        let mut promoted_hunks = 0_u32;
        for hunk in &self.hunks {
            if !valid_hunk_id(&hunk.hunk_id)
                || hunk.total_pages == 0
                || hunk.total_pages > MAX_HUNK_PAGES
                || previous.is_some_and(|previous| previous >= hunk.hunk_id.as_str())
            {
                return Err(DiffHazardError::HunkMetadata);
            }
            if !path_hazards.is_subset(&hunk.signals) {
                return Err(DiffHazardError::DerivedOutput);
            }
            previous = Some(&hunk.hunk_id);
            union.extend(hunk.signals.iter().copied());
            let expected_inspection =
                if self.original_tier == ReviewValueTier::High || !hunk.signals.is_empty() {
                    DiffHazardInspection::AllPages
                } else {
                    DiffHazardInspection::TierBaseline
                };
            let expected_promoted =
                self.original_tier != ReviewValueTier::High && !hunk.signals.is_empty();
            if hunk.inspection != expected_inspection || hunk.promoted != expected_promoted {
                return Err(DiffHazardError::Promotion);
            }
            if hunk.promoted {
                promoted_hunks = promoted_hunks
                    .checked_add(1)
                    .ok_or(DiffHazardError::CountOverflow)?;
            }
        }
        if union != self.signals || promoted_hunks != self.promoted_hunks {
            return Err(DiffHazardError::DerivedOutput);
        }
        let expected_tier = effective_tier(self.original_tier, &self.signals);
        if self.effective_tier != expected_tier {
            return Err(DiffHazardError::Promotion);
        }
        Ok(())
    }

    /// Serialize a validated report without input tokens or source content.
    ///
    /// # Errors
    ///
    /// Returns a closed error for validation, serialization, or output size.
    pub fn canonical_json(&self) -> Result<Vec<u8>, DiffHazardError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| DiffHazardError::Serialization)?;
        if encoded.len() > MAX_REPORT_BYTES {
            return Err(DiffHazardError::ReportTooLarge);
        }
        Ok(encoded)
    }
}

/// Payload-free classification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffHazardError {
    SchemaVersion,
    InvalidPath,
    HunkLimit,
    HunkMetadata,
    LineCount,
    DuplicateHunk,
    MissingHunks,
    Promotion,
    DerivedOutput,
    CountOverflow,
    Serialization,
    ReportTooLarge,
}

impl fmt::Display for DiffHazardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "diff hazard schema version is unsupported",
            Self::InvalidPath => "diff hazard path metadata is invalid",
            Self::HunkLimit => "diff hazard hunk count exceeds its fixed bound",
            Self::HunkMetadata => "diff hazard hunk metadata is invalid",
            Self::LineCount => "diff hazard line-class counts are invalid",
            Self::DuplicateHunk => "diff hazard input contains a duplicate hunk",
            Self::MissingHunks => "diff hazard input requires at least one changed hunk",
            Self::Promotion => "diff hazard inspection promotion is inconsistent",
            Self::DerivedOutput => "diff hazard derived output is inconsistent",
            Self::CountOverflow => "diff hazard count overflowed",
            Self::Serialization => "diff hazard report serialization failed",
            Self::ReportTooLarge => "diff hazard report exceeds its byte bound",
        })
    }
}

impl std::error::Error for DiffHazardError {}

/// Classify local hunk hazards without source retention or model work.
///
/// Input hunk order is normalized by opaque hunk identifier. Every hazardous
/// low- or standard-tier hunk is promoted to full-page delivery.
///
/// # Errors
///
/// Rejects invalid paths, hunk identities, page/line bounds, duplicate hunks,
/// or missing changed hunks for non-rename statuses.
pub fn classify_diff_hazards(
    input: &DiffHazardFileInput,
) -> Result<DiffHazardReport, DiffHazardError> {
    validate_path(&input.path)?;
    if input.hunks.len() > MAX_HUNKS {
        return Err(DiffHazardError::HunkLimit);
    }
    if input.hunks.is_empty() && input.status != FileChangeKind::Renamed {
        return Err(DiffHazardError::MissingHunks);
    }

    let path_signals = path_signals(input.path.as_str());
    let mut observed_hunks = BTreeSet::new();
    let mut decisions = Vec::with_capacity(input.hunks.len());
    for hunk in &input.hunks {
        validate_hunk(hunk)?;
        if !observed_hunks.insert(hunk.hunk_id.clone()) {
            return Err(DiffHazardError::DuplicateHunk);
        }
        let mut signals = path_signals.clone();
        signals.extend(hunk.tokens.iter().copied().map(token_signal));
        let promoted = input.tier != ReviewValueTier::High && !signals.is_empty();
        let inspection = if input.tier == ReviewValueTier::High || !signals.is_empty() {
            DiffHazardInspection::AllPages
        } else {
            DiffHazardInspection::TierBaseline
        };
        decisions.push(DiffHunkHazardDecision {
            hunk_id: hunk.hunk_id.clone(),
            total_pages: hunk.total_pages,
            signals,
            inspection,
            promoted,
        });
    }
    decisions.sort_by(|left, right| left.hunk_id.cmp(&right.hunk_id));
    let mut signals = path_signals;
    for decision in &decisions {
        signals.extend(decision.signals.iter().copied());
    }
    let promoted_hunks = u32::try_from(decisions.iter().filter(|hunk| hunk.promoted).count())
        .map_err(|_| DiffHazardError::CountOverflow)?;
    let report = DiffHazardReport {
        schema_version: DiffHazardReport::SCHEMA_VERSION.to_owned(),
        path: input.path.clone(),
        status: input.status,
        original_tier: input.tier,
        effective_tier: effective_tier(input.tier, &signals),
        signals,
        promoted_hunks,
        hunks: decisions,
    };
    report.validate()?;
    Ok(report)
}

fn validate_path(path: &RepositoryPath) -> Result<(), DiffHazardError> {
    if path.as_str().len() > MAX_PATH_BYTES
        || path.as_str().chars().any(char::is_control)
        || path.as_str().starts_with('/')
    {
        return Err(DiffHazardError::InvalidPath);
    }
    Ok(())
}

fn validate_hunk(hunk: &DiffHazardHunkInput) -> Result<(), DiffHazardError> {
    if !valid_hunk_id(&hunk.hunk_id) || hunk.total_pages == 0 || hunk.total_pages > MAX_HUNK_PAGES {
        return Err(DiffHazardError::HunkMetadata);
    }
    let changed = hunk
        .lines
        .added
        .checked_add(hunk.lines.deleted)
        .ok_or(DiffHazardError::LineCount)?;
    let total = changed
        .checked_add(hunk.lines.context)
        .ok_or(DiffHazardError::LineCount)?;
    if changed == 0 || total > MAX_HUNK_LINES {
        return Err(DiffHazardError::LineCount);
    }
    Ok(())
}

fn valid_hunk_id(hunk_id: &str) -> bool {
    !hunk_id.is_empty()
        && hunk_id.len() <= MAX_HUNK_ID_BYTES
        && hunk_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn path_signals(path: &str) -> BTreeSet<DiffHazardSignal> {
    let normalized = path.to_ascii_lowercase();
    let components = normalized.split('/').collect::<Vec<_>>();
    let basename = components.last().copied().unwrap_or(normalized.as_str());
    let mut signals = BTreeSet::new();
    if components.iter().any(|component| {
        matches!(
            *component,
            "auth" | "authentication" | "oauth" | "oidc" | "identity" | "session"
        )
    }) {
        signals.insert(DiffHazardSignal::Authentication);
    }
    if components.iter().any(|component| {
        matches!(
            *component,
            "authorization" | "permission" | "permissions" | "rbac" | "acl" | "policy"
        )
    }) {
        signals.insert(DiffHazardSignal::Permissions);
    }
    if components.iter().any(|component| {
        matches!(
            *component,
            "migration" | "migrations" | "schema-migrations" | "database-migrations"
        )
    }) || matches!(basename, "schema.sql" | "schema.rb")
    {
        signals.insert(DiffHazardSignal::DatabaseMigration);
    }
    if components
        .iter()
        .any(|component| matches!(*component, "concurrency" | "synchronization" | "parallel"))
    {
        signals.insert(DiffHazardSignal::Concurrency);
    }
    if components
        .iter()
        .any(|component| matches!(*component, "unsafe" | "ffi"))
    {
        signals.insert(DiffHazardSignal::UnsafeCode);
    }
    if components
        .iter()
        .any(|component| matches!(*component, "api" | "public" | "include"))
        || matches_extension(basename, &["proto", "graphql", "gql"])
    {
        signals.insert(DiffHazardSignal::PublicApi);
    }
    if components
        .iter()
        .any(|component| matches!(*component, "config" | "configuration"))
        || matches_extension(
            basename,
            &["toml", "yaml", "yml", "ini", "cfg", "conf", "properties"],
        )
    {
        signals.insert(DiffHazardSignal::Configuration);
    }
    if dependency_file(basename) {
        signals.insert(DiffHazardSignal::Dependencies);
    }
    signals
}

const fn token_signal(token: DiffHazardToken) -> DiffHazardSignal {
    match token {
        DiffHazardToken::AuthenticationBoundary => DiffHazardSignal::Authentication,
        DiffHazardToken::AuthorizationCheck
        | DiffHazardToken::PermissionGrant
        | DiffHazardToken::PermissionRevoke => DiffHazardSignal::Permissions,
        DiffHazardToken::SchemaDefinition | DiffHazardToken::DataMigration => {
            DiffHazardSignal::DatabaseMigration
        }
        DiffHazardToken::Locking
        | DiffHazardToken::AtomicOperation
        | DiffHazardToken::Threading
        | DiffHazardToken::AsyncBoundary => DiffHazardSignal::Concurrency,
        DiffHazardToken::UnsafeOperation | DiffHazardToken::ForeignFunction => {
            DiffHazardSignal::UnsafeCode
        }
        DiffHazardToken::PanicPath
        | DiffHazardToken::IgnoredError
        | DiffHazardToken::UncheckedResult => DiffHazardSignal::ErrorHandling,
        DiffHazardToken::PublicSymbol | DiffHazardToken::BreakingPublicSignature => {
            DiffHazardSignal::PublicApi
        }
        DiffHazardToken::ConfigurationKey | DiffHazardToken::FeatureFlag => {
            DiffHazardSignal::Configuration
        }
        DiffHazardToken::DependencyDeclaration | DiffHazardToken::DependencyVersion => {
            DiffHazardSignal::Dependencies
        }
    }
}

fn effective_tier(
    original: ReviewValueTier,
    signals: &BTreeSet<DiffHazardSignal>,
) -> ReviewValueTier {
    match (original, signals.is_empty()) {
        (ReviewValueTier::Low, false) => ReviewValueTier::Standard,
        (tier, _) => tier,
    }
}

fn matches_extension(basename: &str, extensions: &[&str]) -> bool {
    basename
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extensions.contains(&extension))
}

fn dependency_file(basename: &str) -> bool {
    matches!(
        basename,
        "cargo.toml"
            | "cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "go.mod"
            | "go.sum"
            | "pom.xml"
            | "build.gradle"
            | "composer.json"
            | "gemfile"
            | "gemfile.lock"
            | "pyproject.toml"
            | "requirements.txt"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorical_tokens_cover_every_fixed_hazard_signal() {
        let input = file_input(
            "src/logic.rs",
            ReviewValueTier::Standard,
            BTreeSet::from([
                DiffHazardToken::AuthenticationBoundary,
                DiffHazardToken::PermissionRevoke,
                DiffHazardToken::DataMigration,
                DiffHazardToken::AtomicOperation,
                DiffHazardToken::UnsafeOperation,
                DiffHazardToken::IgnoredError,
                DiffHazardToken::BreakingPublicSignature,
                DiffHazardToken::FeatureFlag,
                DiffHazardToken::DependencyVersion,
            ]),
        );
        let report = classify_diff_hazards(&input).expect("hazard report");
        assert_eq!(report.signals.len(), 9);
        assert_eq!(report.promoted_hunks, 1);
        assert_eq!(report.hunks[0].inspection, DiffHazardInspection::AllPages);
    }

    #[test]
    fn path_metadata_detects_sensitive_roles_without_tokens() {
        let cases = [
            ("src/auth/login.rs", DiffHazardSignal::Authentication),
            ("src/rbac/rules.rs", DiffHazardSignal::Permissions),
            ("db/migrations/001.sql", DiffHazardSignal::DatabaseMigration),
            ("src/concurrency/pool.rs", DiffHazardSignal::Concurrency),
            ("src/ffi/bindings.rs", DiffHazardSignal::UnsafeCode),
            ("public/api.proto", DiffHazardSignal::PublicApi),
            ("config/service.toml", DiffHazardSignal::Configuration),
            ("Cargo.lock", DiffHazardSignal::Dependencies),
        ];
        for (path, expected) in cases {
            let input = file_input(path, ReviewValueTier::Low, BTreeSet::new());
            let report = classify_diff_hazards(&input).expect("path hazard");
            assert!(report.signals.contains(&expected), "missing {expected:?}");
            assert_eq!(report.effective_tier, ReviewValueTier::Standard);
        }
    }

    #[test]
    fn low_and_standard_hazards_require_every_page() {
        for tier in [ReviewValueTier::Low, ReviewValueTier::Standard] {
            let input = file_input(
                "src/lib.rs",
                tier,
                BTreeSet::from([DiffHazardToken::UncheckedResult]),
            );
            let report = classify_diff_hazards(&input).expect("promotion");
            assert!(report.hunks[0].promoted);
            assert_eq!(report.hunks[0].inspection, DiffHazardInspection::AllPages);
        }
    }

    #[test]
    fn clean_hunks_keep_tier_baseline_but_high_tier_still_reads_all_pages() {
        let low = classify_diff_hazards(&file_input(
            "notes.txt",
            ReviewValueTier::Low,
            BTreeSet::new(),
        ))
        .expect("low report");
        assert_eq!(low.hunks[0].inspection, DiffHazardInspection::TierBaseline);
        assert!(!low.hunks[0].promoted);

        let high = classify_diff_hazards(&file_input(
            "src/logic.rs",
            ReviewValueTier::High,
            BTreeSet::new(),
        ))
        .expect("high report");
        assert_eq!(high.hunks[0].inspection, DiffHazardInspection::AllPages);
        assert!(!high.hunks[0].promoted);
    }

    #[test]
    fn hunk_outputs_are_stably_sorted() {
        let mut input = file_input("src/lib.rs", ReviewValueTier::Standard, BTreeSet::new());
        input.hunks.push(hunk("hunk-a", BTreeSet::new()));
        input.hunks[0].hunk_id = "hunk-z".to_owned();
        let first = classify_diff_hazards(&input)
            .expect("report")
            .canonical_json()
            .expect("JSON");
        input.hunks.reverse();
        let second = classify_diff_hazards(&input)
            .expect("reordered report")
            .canonical_json()
            .expect("JSON");
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_duplicate_invalid_or_unbounded_hunk_metadata() {
        let mut duplicate = file_input("src/lib.rs", ReviewValueTier::Standard, BTreeSet::new());
        duplicate.hunks.push(duplicate.hunks[0].clone());
        assert_eq!(
            classify_diff_hazards(&duplicate).expect_err("duplicate"),
            DiffHazardError::DuplicateHunk
        );

        let mut invalid = file_input("src/lib.rs", ReviewValueTier::Standard, BTreeSet::new());
        invalid.hunks[0].total_pages = 0;
        assert_eq!(
            classify_diff_hazards(&invalid).expect_err("invalid pages"),
            DiffHazardError::HunkMetadata
        );

        let mut no_changes = file_input("src/lib.rs", ReviewValueTier::Standard, BTreeSet::new());
        no_changes.hunks[0].lines.added = 0;
        assert_eq!(
            classify_diff_hazards(&no_changes).expect_err("no changed lines"),
            DiffHazardError::LineCount
        );
    }

    #[test]
    fn report_retains_no_token_or_line_inventory() {
        let report = classify_diff_hazards(&file_input(
            "src/lib.rs",
            ReviewValueTier::Standard,
            BTreeSet::from([DiffHazardToken::IgnoredError]),
        ))
        .expect("report");
        let encoded = report.canonical_json().expect("report JSON");
        let text = String::from_utf8(encoded).expect("UTF-8 JSON");
        for absent in ["tokens", "lines", "added", "deleted", "context"] {
            assert!(!text.contains(absent));
        }
    }

    fn file_input(
        path: &str,
        tier: ReviewValueTier,
        tokens: BTreeSet<DiffHazardToken>,
    ) -> DiffHazardFileInput {
        DiffHazardFileInput {
            path: RepositoryPath::try_from(path.to_owned()).expect("path"),
            status: FileChangeKind::Modified,
            tier,
            hunks: vec![hunk("hunk-1", tokens)],
        }
    }

    fn hunk(hunk_id: &str, tokens: BTreeSet<DiffHazardToken>) -> DiffHazardHunkInput {
        DiffHazardHunkInput {
            hunk_id: hunk_id.to_owned(),
            total_pages: 2,
            lines: DiffHunkLineClasses {
                added: 1,
                deleted: 0,
                context: 2,
            },
            tokens,
        }
    }
}
