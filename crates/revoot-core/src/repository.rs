//! Bounded, read-only access to a checked-out repository.
//!
//! The tools in this module never execute repository content, follow symbolic
//! links, or invoke a subprocess. Every result is deterministic for the bytes
//! observed during the call and is charged to the review-wide agent budget.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::agent::{AgentBudget, AgentBudgetError};
use crate::provider::CancellationToken;

const MAX_QUERY_BYTES: usize = 512;
const MAX_SEARCH_EXCERPT_BYTES: usize = 512;

/// A normalized, repository-relative UTF-8 path.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepositoryRelativePath(String);

impl RepositoryRelativePath {
    /// Return the normalized slash-separated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn to_path_buf(&self) -> PathBuf {
        self.0.split('/').collect()
    }
}

impl TryFrom<String> for RepositoryRelativePath {
    type Error = RepositoryPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(RepositoryPathError::Empty);
        }
        if value.contains('\0') {
            return Err(RepositoryPathError::Nul);
        }
        let path = Path::new(&value);
        if path.is_absolute() {
            return Err(RepositoryPathError::Absolute);
        }
        let mut normalized = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    let text = part.to_str().ok_or(RepositoryPathError::NonUtf8)?;
                    if text.is_empty() {
                        return Err(RepositoryPathError::NotNormalized);
                    }
                    normalized.push(text);
                }
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => return Err(RepositoryPathError::NotNormalized),
            }
        }
        if normalized.is_empty()
            || normalized
                .iter()
                .any(|component| component.eq_ignore_ascii_case(".git"))
        {
            return Err(RepositoryPathError::Reserved);
        }
        let canonical = normalized.join("/");
        if canonical != value {
            return Err(RepositoryPathError::NotNormalized);
        }
        Ok(Self(canonical))
    }
}

impl From<RepositoryRelativePath> for String {
    fn from(value: RepositoryRelativePath) -> Self {
        value.0
    }
}

/// Why a repository-relative path was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryPathError {
    Empty,
    Nul,
    Absolute,
    NonUtf8,
    NotNormalized,
    Reserved,
}

impl fmt::Display for RepositoryPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "repository path rejected: {self:?}")
    }
}

/// Per-tool limits which complement the aggregate invocation budget.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryToolLimits {
    pub max_inventory_entries: u32,
    pub max_inventory_files: u32,
    pub max_inventory_depth: u16,
    pub max_file_bytes: u64,
    pub max_read_bytes: u64,
    pub max_search_bytes: u64,
    pub max_search_matches: u32,
    pub max_list_results: u32,
    pub max_diff_bytes: u64,
}

impl Default for RepositoryToolLimits {
    fn default() -> Self {
        Self {
            max_inventory_entries: 100_000,
            max_inventory_files: 25_000,
            max_inventory_depth: 64,
            max_file_bytes: 2 * 1024 * 1024,
            max_read_bytes: 256 * 1024,
            max_search_bytes: 8 * 1024 * 1024,
            max_search_matches: 200,
            max_list_results: 2_000,
            max_diff_bytes: 2 * 1024 * 1024,
        }
    }
}

/// An invalid repository tool limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryLimitError {
    InventoryEntries,
    InventoryFiles,
    InventoryDepth,
    FileBytes,
    ReadBytes,
    SearchBytes,
    SearchMatches,
    ListResults,
    DiffBytes,
}

impl RepositoryToolLimits {
    /// Validate that every tool can perform at least one bounded operation.
    ///
    /// # Errors
    ///
    /// Returns the first zero or internally inconsistent limit.
    pub const fn validate(self) -> Result<(), RepositoryLimitError> {
        if self.max_inventory_entries == 0 || self.max_inventory_entries < self.max_inventory_files
        {
            return Err(RepositoryLimitError::InventoryEntries);
        }
        if self.max_inventory_files == 0 {
            return Err(RepositoryLimitError::InventoryFiles);
        }
        if self.max_inventory_depth == 0 {
            return Err(RepositoryLimitError::InventoryDepth);
        }
        if self.max_file_bytes == 0 {
            return Err(RepositoryLimitError::FileBytes);
        }
        if self.max_read_bytes == 0 || self.max_read_bytes > self.max_file_bytes {
            return Err(RepositoryLimitError::ReadBytes);
        }
        if self.max_search_bytes == 0 {
            return Err(RepositoryLimitError::SearchBytes);
        }
        if self.max_search_matches == 0 {
            return Err(RepositoryLimitError::SearchMatches);
        }
        if self.max_list_results == 0 {
            return Err(RepositoryLimitError::ListResults);
        }
        if self.max_diff_bytes == 0 {
            return Err(RepositoryLimitError::DiffBytes);
        }
        Ok(())
    }
}

/// One regular file admitted to the checkout inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryFile {
    pub path: RepositoryRelativePath,
    pub size_bytes: u64,
}

/// Why a checkout entry could not be represented in the inventory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryGapReason {
    DepthLimit,
    EntryLimit,
    FileLimit,
    NonUtf8Path,
    HardLink,
    SymbolicLink,
    UnsupportedFileType,
    MetadataUnavailable,
    DirectoryUnavailable,
}

/// Explicit inventory coverage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum InventoryCoverage {
    Complete,
    Partial {
        omitted_entries: u32,
        reasons: BTreeSet<InventoryGapReason>,
    },
}

/// Stable, sorted checkout inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryInventory {
    pub files: Vec<RepositoryFile>,
    pub coverage: InventoryCoverage,
}

/// One exact in-memory diff made available to `show_diff`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryDiff {
    pub path: RepositoryRelativePath,
    pub text: String,
}

/// A one-based inclusive line range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

impl LineRange {
    fn valid(self) -> bool {
        self.start > 0 && self.end >= self.start
    }
}

/// Result from listing an inventory prefix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListFilesResult {
    pub files: Vec<RepositoryFile>,
    pub truncated: bool,
}

/// Bounded file contents with the returned line interval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFileResult {
    pub path: RepositoryRelativePath,
    pub start_line: u32,
    pub end_line: u32,
    pub content: String,
    pub truncated: bool,
}

/// One fixed-string search match.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchMatch {
    pub path: RepositoryRelativePath,
    pub line: u32,
    pub column: u32,
    pub excerpt: String,
}

/// A bounded fixed-string repository search request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRequest {
    pub query: String,
    pub paths: Vec<RepositoryRelativePath>,
    pub max_results: u32,
}

/// A bounded literal or Rust-regex repository search request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeSearchRequest {
    pub query: String,
    pub regex: bool,
    pub case_sensitive: bool,
    pub paths: Vec<RepositoryRelativePath>,
    pub max_results: u32,
}

/// Search results plus honest coverage evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResult {
    pub matches: Vec<SearchMatch>,
    pub scanned_files: u32,
    pub skipped_files: u32,
    pub truncated: bool,
}

/// A bounded exact diff result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShowDiffResult {
    pub path: RepositoryRelativePath,
    pub content: String,
}

/// Redaction-safe repository tool failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryToolError {
    InvalidLimits(RepositoryLimitError),
    RootUnavailable,
    RootNotDirectory,
    InventoryUnavailable,
    InvalidRange,
    InvalidQuery,
    ResultLimit,
    PathNotInventoried,
    PathChanged,
    SymbolicLink,
    NotRegularFile,
    FileTooLarge,
    FileUnavailable,
    NonUtf8Content,
    DiffUnavailable,
    DiffTooLarge,
    Cancelled,
    Budget(AgentBudgetError),
}

impl From<AgentBudgetError> for RepositoryToolError {
    fn from(value: AgentBudgetError) -> Self {
        Self::Budget(value)
    }
}

/// Read-only tool implementation bound to one canonical checkout root.
pub struct RepositoryToolbox {
    root: PathBuf,
    limits: RepositoryToolLimits,
    inventory: RepositoryInventory,
    files: BTreeMap<RepositoryRelativePath, InventoriedFile>,
    diffs: BTreeMap<RepositoryRelativePath, String>,
}

impl RepositoryToolbox {
    /// Build a bounded inventory without following symbolic links.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error for invalid limits or an unavailable root.
    pub fn open(
        root: impl AsRef<Path>,
        limits: RepositoryToolLimits,
        diffs: impl IntoIterator<Item = RepositoryDiff>,
        cancellation: &CancellationToken,
    ) -> Result<Self, RepositoryToolError> {
        check_cancelled(cancellation)?;
        limits
            .validate()
            .map_err(RepositoryToolError::InvalidLimits)?;
        let root = fs::canonicalize(root).map_err(|_| RepositoryToolError::RootUnavailable)?;
        if !root.is_dir() {
            return Err(RepositoryToolError::RootNotDirectory);
        }
        let (inventory, files) = build_inventory(&root, limits, cancellation)?;
        let diffs = diffs
            .into_iter()
            .map(|diff| (diff.path, diff.text))
            .collect();
        Ok(Self {
            root,
            limits,
            inventory,
            files,
            diffs,
        })
    }

    /// Build a bounded inventory from an authoritative path allowlist.
    ///
    /// This is used when an acquisition adapter, such as local Git, has a
    /// stronger definition of repository membership than a raw directory walk.
    /// Paths remain subject to the same no-symlink, regular-file, identity, and
    /// aggregate limits as [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error for invalid limits or an unavailable root.
    pub fn open_selected(
        root: impl AsRef<Path>,
        limits: RepositoryToolLimits,
        diffs: impl IntoIterator<Item = RepositoryDiff>,
        paths: impl IntoIterator<Item = RepositoryRelativePath>,
        cancellation: &CancellationToken,
    ) -> Result<Self, RepositoryToolError> {
        check_cancelled(cancellation)?;
        limits
            .validate()
            .map_err(RepositoryToolError::InvalidLimits)?;
        let root = fs::canonicalize(root).map_err(|_| RepositoryToolError::RootUnavailable)?;
        if !root.is_dir() {
            return Err(RepositoryToolError::RootNotDirectory);
        }
        let (inventory, files) =
            build_selected_inventory(&root, limits, paths.into_iter().collect(), cancellation)?;
        let diffs = diffs
            .into_iter()
            .map(|diff| (diff.path, diff.text))
            .collect();
        Ok(Self {
            root,
            limits,
            inventory,
            files,
            diffs,
        })
    }

    /// Return the immutable inventory evidence.
    #[must_use]
    pub const fn inventory(&self) -> &RepositoryInventory {
        &self.inventory
    }

    /// Iterate the exact trusted diffs without charging a model tool budget.
    ///
    /// This setup-only view allows the runtime to materialize private indexed
    /// artifacts before any model call. It does not expose checkout paths or
    /// bytes outside the current process.
    pub fn exact_diffs(&self) -> impl Iterator<Item = (&RepositoryRelativePath, &str)> {
        self.diffs.iter().map(|(path, text)| (path, text.as_str()))
    }

    /// List files below an optional repository-relative prefix.
    ///
    /// # Errors
    ///
    /// Returns an error on cancellation, an invalid result limit, or aggregate
    /// budget exhaustion.
    pub fn list_files(
        &self,
        prefix: Option<&RepositoryRelativePath>,
        max_results: u32,
        budget: &mut AgentBudget,
        cancellation: &CancellationToken,
        now_millis: u64,
    ) -> Result<ListFilesResult, RepositoryToolError> {
        check_cancelled(cancellation)?;
        if max_results == 0 || max_results > self.limits.max_list_results {
            return Err(RepositoryToolError::ResultLimit);
        }
        let mut matching = self
            .inventory
            .files
            .iter()
            .filter(|file| prefix.is_none_or(|prefix| is_below(&file.path, prefix)))
            .cloned();
        let take = usize::try_from(max_results).unwrap_or(usize::MAX);
        let files: Vec<_> = matching.by_ref().take(take).collect();
        let truncated = matching.next().is_some();
        budget.charge_tool(
            1,
            u64::try_from(files.len()).unwrap_or(u64::MAX),
            0,
            now_millis,
        )?;
        Ok(ListFilesResult { files, truncated })
    }

    /// Read a bounded inclusive line range from an inventoried regular file.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, invalid range/path state, binary or
    /// oversized content, or aggregate budget exhaustion.
    pub fn read_file(
        &self,
        path: &RepositoryRelativePath,
        range: LineRange,
        budget: &mut AgentBudget,
        cancellation: &CancellationToken,
        now_millis: u64,
    ) -> Result<ReadFileResult, RepositoryToolError> {
        check_cancelled(cancellation)?;
        if !range.valid() {
            return Err(RepositoryToolError::InvalidRange);
        }
        let expected = self
            .files
            .get(path)
            .ok_or(RepositoryToolError::PathNotInventoried)?;
        budget.charge_tool(
            1,
            1,
            expected.public.size_bytes.min(self.limits.max_read_bytes),
            now_millis,
        )?;
        let bytes = self.read_inventoried(path)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| RepositoryToolError::NonUtf8Content)?;
        let (content, end_line, truncated) = select_lines(text, range, self.limits.max_read_bytes)?;
        Ok(ReadFileResult {
            path: path.clone(),
            start_line: range.start,
            end_line,
            content,
            truncated,
        })
    }

    /// Search UTF-8 inventoried files for an exact, case-sensitive string.
    ///
    /// Empty `paths` searches the complete admitted inventory. Non-UTF-8 and
    /// individually oversized files are counted as skipped rather than hidden.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid query/scope, cancellation, or aggregate
    /// budget exhaustion.
    pub fn search(
        &self,
        request: &SearchRequest,
        budget: &mut AgentBudget,
        cancellation: &CancellationToken,
        now_millis: u64,
    ) -> Result<SearchResult, RepositoryToolError> {
        check_cancelled(cancellation)?;
        if request.query.is_empty()
            || request.query.len() > MAX_QUERY_BYTES
            || request.query.contains(['\n', '\r', '\0'])
        {
            return Err(RepositoryToolError::InvalidQuery);
        }
        if request.max_results == 0 || request.max_results > self.limits.max_search_matches {
            return Err(RepositoryToolError::ResultLimit);
        }
        let candidates: Vec<_> = if request.paths.is_empty() {
            self.inventory.files.iter().map(|file| &file.path).collect()
        } else {
            request
                .paths
                .iter()
                .map(|path| {
                    self.files
                        .get_key_value(path)
                        .map(|(key, _)| key)
                        .ok_or(RepositoryToolError::PathNotInventoried)
                })
                .collect::<Result<_, _>>()?
        };
        let reserved_bytes = candidates
            .iter()
            .filter_map(|path| self.files.get(*path))
            .map(|file| file.public.size_bytes.min(self.limits.max_file_bytes))
            .fold(0_u64, u64::saturating_add)
            .min(self.limits.max_search_bytes);
        budget.charge_tool(
            1,
            u64::try_from(candidates.len()).unwrap_or(u64::MAX),
            reserved_bytes,
            now_millis,
        )?;
        let mut matches = Vec::new();
        let mut scanned_files = 0_u32;
        let mut skipped_files = 0_u32;
        let mut scanned_bytes = 0_u64;
        let mut truncated = false;
        for path in candidates {
            check_cancelled(cancellation)?;
            let Some(file) = self.files.get(path) else {
                return Err(RepositoryToolError::PathNotInventoried);
            };
            if file.public.size_bytes > self.limits.max_file_bytes
                || scanned_bytes.saturating_add(file.public.size_bytes)
                    > self.limits.max_search_bytes
            {
                skipped_files = skipped_files.saturating_add(1);
                truncated = true;
                continue;
            }
            let bytes = match self.read_inventoried(path) {
                Ok(bytes) => bytes,
                Err(RepositoryToolError::NonUtf8Content | RepositoryToolError::FileTooLarge) => {
                    skipped_files = skipped_files.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(error),
            };
            scanned_bytes =
                scanned_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            let Ok(text) = std::str::from_utf8(&bytes) else {
                skipped_files = skipped_files.saturating_add(1);
                continue;
            };
            scanned_files = scanned_files.saturating_add(1);
            collect_matches(path, text, request, &mut matches, &mut truncated);
            if matches.len() >= usize::try_from(request.max_results).unwrap_or(usize::MAX) {
                truncated = true;
                break;
            }
        }
        Ok(SearchResult {
            matches,
            scanned_files,
            skipped_files,
            truncated,
        })
    }

    /// Search UTF-8 inventoried files using a literal or bounded Rust regex.
    ///
    /// Empty `paths` searches the complete admitted inventory. The regex crate
    /// guarantees linear-time matching; compilation size is additionally
    /// bounded so untrusted patterns cannot create excessive automata.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid query or regex, invalid scope,
    /// cancellation, changed files, or aggregate budget exhaustion.
    pub fn search_code(
        &self,
        request: &CodeSearchRequest,
        budget: &mut AgentBudget,
        cancellation: &CancellationToken,
        now_millis: u64,
    ) -> Result<SearchResult, RepositoryToolError> {
        check_cancelled(cancellation)?;
        if request.query.is_empty()
            || request.query.len() > MAX_QUERY_BYTES
            || request.query.contains(['\n', '\r', '\0'])
            || request.max_results == 0
            || request.max_results > self.limits.max_search_matches
        {
            return Err(RepositoryToolError::InvalidQuery);
        }
        let pattern = if request.regex {
            request.query.clone()
        } else {
            regex::escape(&request.query)
        };
        let compiled_regex = RegexBuilder::new(&pattern)
            .case_insensitive(!request.case_sensitive)
            .size_limit(1024 * 1024)
            .dfa_size_limit(1024 * 1024)
            .build()
            .map_err(|_| RepositoryToolError::InvalidQuery)?;
        let candidates: Vec<_> = if request.paths.is_empty() {
            self.inventory.files.iter().map(|file| &file.path).collect()
        } else {
            request
                .paths
                .iter()
                .map(|path| {
                    self.files
                        .get_key_value(path)
                        .map(|(key, _)| key)
                        .ok_or(RepositoryToolError::PathNotInventoried)
                })
                .collect::<Result<_, _>>()?
        };
        let reserved_bytes = candidates
            .iter()
            .filter_map(|path| self.files.get(*path))
            .map(|file| file.public.size_bytes.min(self.limits.max_file_bytes))
            .fold(0_u64, u64::saturating_add)
            .min(self.limits.max_search_bytes);
        budget.charge_tool(
            1,
            u64::try_from(candidates.len()).unwrap_or(u64::MAX),
            reserved_bytes,
            now_millis,
        )?;
        let mut matches = Vec::new();
        let mut scanned_files = 0_u32;
        let mut skipped_files = 0_u32;
        let mut scanned_bytes = 0_u64;
        let mut truncated = false;
        for path in candidates {
            check_cancelled(cancellation)?;
            let Some(file) = self.files.get(path) else {
                return Err(RepositoryToolError::PathNotInventoried);
            };
            if file.public.size_bytes > self.limits.max_file_bytes
                || scanned_bytes.saturating_add(file.public.size_bytes)
                    > self.limits.max_search_bytes
            {
                skipped_files = skipped_files.saturating_add(1);
                truncated = true;
                continue;
            }
            let bytes = match self.read_inventoried(path) {
                Ok(bytes) => bytes,
                Err(RepositoryToolError::NonUtf8Content | RepositoryToolError::FileTooLarge) => {
                    skipped_files = skipped_files.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(error),
            };
            scanned_bytes =
                scanned_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            let Ok(text) = std::str::from_utf8(&bytes) else {
                skipped_files = skipped_files.saturating_add(1);
                continue;
            };
            scanned_files = scanned_files.saturating_add(1);
            collect_regex_matches(
                path,
                text,
                &compiled_regex,
                request.max_results,
                &mut matches,
                &mut truncated,
            );
            if matches.len() >= usize::try_from(request.max_results).unwrap_or(usize::MAX) {
                truncated = true;
                break;
            }
        }
        Ok(SearchResult {
            matches,
            scanned_files,
            skipped_files,
            truncated,
        })
    }

    /// Return a bounded exact diff supplied by the trusted acquisition layer.
    ///
    /// # Errors
    ///
    /// Returns an error for cancellation, missing/oversized diff text, or
    /// aggregate budget exhaustion.
    pub fn show_diff(
        &self,
        path: &RepositoryRelativePath,
        budget: &mut AgentBudget,
        cancellation: &CancellationToken,
        now_millis: u64,
    ) -> Result<ShowDiffResult, RepositoryToolError> {
        check_cancelled(cancellation)?;
        let content = self
            .diffs
            .get(path)
            .ok_or(RepositoryToolError::DiffUnavailable)?;
        let bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
        if bytes > self.limits.max_diff_bytes {
            return Err(RepositoryToolError::DiffTooLarge);
        }
        budget.charge_tool(1, 1, bytes, now_millis)?;
        Ok(ShowDiffResult {
            path: path.clone(),
            content: content.clone(),
        })
    }

    fn read_inventoried(
        &self,
        path: &RepositoryRelativePath,
    ) -> Result<Vec<u8>, RepositoryToolError> {
        let expected = self
            .files
            .get(path)
            .ok_or(RepositoryToolError::PathNotInventoried)?;
        let absolute = self.root.join(path.to_path_buf());
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let mut file = options
            .open(&absolute)
            .map_err(|_| RepositoryToolError::FileUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| RepositoryToolError::FileUnavailable)?;
        if !metadata.is_file() {
            return Err(RepositoryToolError::NotRegularFile);
        }
        if metadata.nlink() != 1 {
            return Err(RepositoryToolError::PathChanged);
        }
        if !expected.matches(&metadata) {
            return Err(RepositoryToolError::PathChanged);
        }
        if metadata.len() > self.limits.max_file_bytes {
            return Err(RepositoryToolError::FileTooLarge);
        }
        let bytes = read_bounded_file(&mut file, self.limits.max_file_bytes)?;
        let final_metadata = file
            .metadata()
            .map_err(|_| RepositoryToolError::FileUnavailable)?;
        if !expected.matches(&final_metadata) {
            return Err(RepositoryToolError::PathChanged);
        }
        Ok(bytes)
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), RepositoryToolError> {
    if cancellation.is_cancelled() {
        Err(RepositoryToolError::Cancelled)
    } else {
        Ok(())
    }
}

fn is_below(path: &RepositoryRelativePath, prefix: &RepositoryRelativePath) -> bool {
    path == prefix
        || path
            .as_str()
            .strip_prefix(prefix.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn select_lines(
    text: &str,
    range: LineRange,
    max_bytes: u64,
) -> Result<(String, u32, bool), RepositoryToolError> {
    let mut content = String::new();
    let mut last_line = range.start.saturating_sub(1);
    let mut truncated = false;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let line_number = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        if line_number < range.start {
            continue;
        }
        if line_number > range.end {
            break;
        }
        let next_len = content.len().saturating_add(line.len());
        if u64::try_from(next_len).unwrap_or(u64::MAX) > max_bytes {
            truncated = true;
            break;
        }
        content.push_str(line);
        last_line = line_number;
    }
    if content.is_empty() && !text.is_empty() && last_line < range.start {
        return Err(RepositoryToolError::InvalidRange);
    }
    Ok((content, last_line, truncated))
}

fn collect_matches(
    path: &RepositoryRelativePath,
    text: &str,
    request: &SearchRequest,
    matches: &mut Vec<SearchMatch>,
    truncated: &mut bool,
) {
    let maximum = usize::try_from(request.max_results).unwrap_or(usize::MAX);
    for (line_index, line) in text.lines().enumerate() {
        for (column, _) in line.match_indices(&request.query) {
            if matches.len() == maximum {
                *truncated = true;
                return;
            }
            matches.push(SearchMatch {
                path: path.clone(),
                line: u32::try_from(line_index)
                    .unwrap_or(u32::MAX)
                    .saturating_add(1),
                column: u32::try_from(column).unwrap_or(u32::MAX).saturating_add(1),
                excerpt: bounded_excerpt(line, column, MAX_SEARCH_EXCERPT_BYTES),
            });
        }
    }
}

fn collect_regex_matches(
    path: &RepositoryRelativePath,
    text: &str,
    compiled_regex: &Regex,
    max_results: u32,
    matches: &mut Vec<SearchMatch>,
    truncated: &mut bool,
) {
    let maximum = usize::try_from(max_results).unwrap_or(usize::MAX);
    for (line_index, line) in text.lines().enumerate() {
        for matched in compiled_regex.find_iter(line) {
            if matches.len() == maximum {
                *truncated = true;
                return;
            }
            matches.push(SearchMatch {
                path: path.clone(),
                line: u32::try_from(line_index)
                    .unwrap_or(u32::MAX)
                    .saturating_add(1),
                column: u32::try_from(matched.start())
                    .unwrap_or(u32::MAX)
                    .saturating_add(1),
                excerpt: bounded_excerpt(line, matched.start(), MAX_SEARCH_EXCERPT_BYTES),
            });
        }
    }
}

fn build_inventory(
    root: &Path,
    limits: RepositoryToolLimits,
    cancellation: &CancellationToken,
) -> Result<
    (
        RepositoryInventory,
        BTreeMap<RepositoryRelativePath, InventoriedFile>,
    ),
    RepositoryToolError,
> {
    let mut files = Vec::new();
    let mut identities = BTreeMap::new();
    let mut reasons = BTreeSet::new();
    let mut omitted_entries = 0_u32;
    let mut entries_seen = 0_u32;
    walk_directory(
        root,
        root,
        0,
        limits,
        &mut files,
        &mut identities,
        &mut reasons,
        &mut omitted_entries,
        &mut entries_seen,
        cancellation,
    )?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let coverage = if reasons.is_empty() {
        InventoryCoverage::Complete
    } else {
        InventoryCoverage::Partial {
            omitted_entries,
            reasons,
        }
    };
    Ok((RepositoryInventory { files, coverage }, identities))
}

fn build_selected_inventory(
    root: &Path,
    limits: RepositoryToolLimits,
    paths: BTreeSet<RepositoryRelativePath>,
    cancellation: &CancellationToken,
) -> Result<
    (
        RepositoryInventory,
        BTreeMap<RepositoryRelativePath, InventoriedFile>,
    ),
    RepositoryToolError,
> {
    let mut files = Vec::new();
    let mut identities = BTreeMap::new();
    let mut reasons = BTreeSet::new();
    let mut omitted_entries = 0_u32;
    for (index, path) in paths.into_iter().enumerate() {
        check_cancelled(cancellation)?;
        if index >= usize::try_from(limits.max_inventory_entries).unwrap_or(usize::MAX) {
            note_gap(
                &mut reasons,
                &mut omitted_entries,
                InventoryGapReason::EntryLimit,
            );
            continue;
        }
        if path.as_str().split('/').count() > usize::from(limits.max_inventory_depth) {
            note_gap(
                &mut reasons,
                &mut omitted_entries,
                InventoryGapReason::DepthLimit,
            );
            continue;
        }
        if files.len() >= usize::try_from(limits.max_inventory_files).unwrap_or(usize::MAX) {
            note_gap(
                &mut reasons,
                &mut omitted_entries,
                InventoryGapReason::FileLimit,
            );
            continue;
        }
        let absolute = root.join(path.to_path_buf());
        if selected_path_has_symlink(root, &path) {
            note_gap(
                &mut reasons,
                &mut omitted_entries,
                InventoryGapReason::SymbolicLink,
            );
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&absolute) else {
            note_gap(
                &mut reasons,
                &mut omitted_entries,
                InventoryGapReason::MetadataUnavailable,
            );
            continue;
        };
        if !metadata.is_file() {
            note_gap(
                &mut reasons,
                &mut omitted_entries,
                InventoryGapReason::UnsupportedFileType,
            );
            continue;
        }
        if metadata.nlink() != 1 {
            note_gap(
                &mut reasons,
                &mut omitted_entries,
                InventoryGapReason::HardLink,
            );
            continue;
        }
        let public = RepositoryFile {
            path,
            size_bytes: metadata.len(),
        };
        identities.insert(
            public.path.clone(),
            InventoriedFile {
                public: public.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            },
        );
        files.push(public);
    }
    let coverage = if reasons.is_empty() {
        InventoryCoverage::Complete
    } else {
        InventoryCoverage::Partial {
            omitted_entries,
            reasons,
        }
    };
    Ok((RepositoryInventory { files, coverage }, identities))
}

fn selected_path_has_symlink(root: &Path, path: &RepositoryRelativePath) -> bool {
    let mut current = root.to_path_buf();
    for component in path.as_str().split('/') {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

#[derive(Clone, Debug)]
struct InventoriedFile {
    public: RepositoryFile,
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl InventoriedFile {
    fn matches(&self, metadata: &fs::Metadata) -> bool {
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.len() == self.public.size_bytes
            && metadata.ctime() == self.changed_seconds
            && metadata.ctime_nsec() == self.changed_nanoseconds
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn walk_directory(
    root: &Path,
    directory: &Path,
    depth: u16,
    limits: RepositoryToolLimits,
    files: &mut Vec<RepositoryFile>,
    identities: &mut BTreeMap<RepositoryRelativePath, InventoriedFile>,
    reasons: &mut BTreeSet<InventoryGapReason>,
    omitted_entries: &mut u32,
    entries_seen: &mut u32,
    cancellation: &CancellationToken,
) -> Result<(), RepositoryToolError> {
    check_cancelled(cancellation)?;
    if depth > limits.max_inventory_depth {
        note_gap(reasons, omitted_entries, InventoryGapReason::DepthLimit);
        return Ok(());
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) if directory == root => return Err(RepositoryToolError::InventoryUnavailable),
        Err(_) => {
            note_gap(
                reasons,
                omitted_entries,
                InventoryGapReason::DirectoryUnavailable,
            );
            return Ok(());
        }
    };
    let mut entries = collect_directory_entries(entries, reasons, omitted_entries);
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        check_cancelled(cancellation)?;
        if *entries_seen >= limits.max_inventory_entries {
            note_gap(reasons, omitted_entries, InventoryGapReason::EntryLimit);
            continue;
        }
        *entries_seen = entries_seen.saturating_add(1);
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
        {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            note_gap(
                reasons,
                omitted_entries,
                InventoryGapReason::MetadataUnavailable,
            );
            continue;
        };
        if metadata.file_type().is_symlink() {
            note_gap(reasons, omitted_entries, InventoryGapReason::SymbolicLink);
            continue;
        }
        if metadata.is_dir() {
            walk_directory(
                root,
                &path,
                depth.saturating_add(1),
                limits,
                files,
                identities,
                reasons,
                omitted_entries,
                entries_seen,
                cancellation,
            )?;
            continue;
        }
        if !metadata.is_file() {
            note_gap(
                reasons,
                omitted_entries,
                InventoryGapReason::UnsupportedFileType,
            );
            continue;
        }
        if metadata.nlink() != 1 {
            note_gap(reasons, omitted_entries, InventoryGapReason::HardLink);
            continue;
        }
        if files.len() >= usize::try_from(limits.max_inventory_files).unwrap_or(usize::MAX) {
            note_gap(reasons, omitted_entries, InventoryGapReason::FileLimit);
            continue;
        }
        let Ok(relative) = path.strip_prefix(root) else {
            note_gap(reasons, omitted_entries, InventoryGapReason::NonUtf8Path);
            continue;
        };
        let Some(relative) = relative.to_str() else {
            note_gap(reasons, omitted_entries, InventoryGapReason::NonUtf8Path);
            continue;
        };
        let normalized = relative.replace(std::path::MAIN_SEPARATOR, "/");
        let Ok(path) = RepositoryRelativePath::try_from(normalized) else {
            note_gap(reasons, omitted_entries, InventoryGapReason::NonUtf8Path);
            continue;
        };
        let public = RepositoryFile {
            path,
            size_bytes: metadata.len(),
        };
        identities.insert(
            public.path.clone(),
            InventoriedFile {
                public: public.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            },
        );
        files.push(public);
    }
    Ok(())
}

fn collect_directory_entries(
    entries: fs::ReadDir,
    reasons: &mut BTreeSet<InventoryGapReason>,
    omitted_entries: &mut u32,
) -> Vec<fs::DirEntry> {
    let mut collected = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => collected.push(entry),
            Err(_) => note_gap(
                reasons,
                omitted_entries,
                InventoryGapReason::MetadataUnavailable,
            ),
        }
    }
    collected
}

fn read_bounded_file(file: &mut File, maximum: u64) -> Result<Vec<u8>, RepositoryToolError> {
    let take = maximum.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(take)
        .read_to_end(&mut bytes)
        .map_err(|_| RepositoryToolError::FileUnavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(RepositoryToolError::FileTooLarge);
    }
    Ok(bytes)
}

fn bounded_excerpt(line: &str, match_column: usize, maximum: usize) -> String {
    if line.len() <= maximum {
        return line.to_owned();
    }
    let mut start = match_column.saturating_sub(maximum / 4);
    while start > 0 && !line.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = start.saturating_add(maximum).min(line.len());
    while end > start && !line.is_char_boundary(end) {
        end -= 1;
    }
    line[start..end].to_owned()
}

fn note_gap(
    reasons: &mut BTreeSet<InventoryGapReason>,
    omitted_entries: &mut u32,
    reason: InventoryGapReason,
) {
    reasons.insert(reason);
    *omitted_entries = omitted_entries.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::agent::{AgentBudgetLimits, AgentBudgetUsage};

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "revoot-repository-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("src")).expect("fixture src directory");
            fs::create_dir_all(root.join("tests")).expect("fixture tests directory");
            fs::create_dir_all(root.join(".git")).expect("fixture git directory");
            fs::write(
                root.join("src/lib.rs"),
                "pub fn answer() -> u32 {\n    42\n}\n",
            )
            .expect("fixture source");
            fs::write(
                root.join("tests/answer.rs"),
                "#[test]\nfn answer_is_stable() { assert_eq!(answer(), 42); }\n",
            )
            .expect("fixture test");
            fs::write(root.join("README.md"), "# Fixture\nanswer is 42\n").expect("fixture readme");
            fs::write(root.join(".git/config"), "secret-ish metadata")
                .expect("fixture git metadata");
            Self { root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn path(value: &str) -> RepositoryRelativePath {
        RepositoryRelativePath::try_from(value.to_owned()).expect("valid fixture path")
    }

    fn budget() -> AgentBudget {
        AgentBudget::new(
            AgentBudgetLimits {
                max_tool_calls: 20,
                max_repository_files: 100,
                max_repository_bytes: 1024 * 1024,
                ..AgentBudgetLimits::default()
            },
            0,
        )
        .expect("valid budget")
    }

    fn toolbox(fixture: &Fixture) -> RepositoryToolbox {
        RepositoryToolbox::open(
            &fixture.root,
            RepositoryToolLimits::default(),
            [RepositoryDiff {
                path: path("src/lib.rs"),
                text: "@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            }],
            &CancellationToken::default(),
        )
        .expect("toolbox opens")
    }

    #[test]
    fn path_contract_rejects_escape_and_git_metadata() {
        assert_eq!(
            RepositoryRelativePath::try_from("../secret".to_owned()),
            Err(RepositoryPathError::NotNormalized)
        );
        assert_eq!(
            RepositoryRelativePath::try_from(".git/config".to_owned()),
            Err(RepositoryPathError::Reserved)
        );
        assert_eq!(
            RepositoryRelativePath::try_from(".GIT/config".to_owned()),
            Err(RepositoryPathError::Reserved)
        );
        assert_eq!(
            RepositoryRelativePath::try_from("src//lib.rs".to_owned()),
            Err(RepositoryPathError::NotNormalized)
        );
    }

    #[test]
    fn inventory_is_sorted_and_excludes_git_metadata() {
        let fixture = Fixture::new();
        let toolbox = toolbox(&fixture);
        let paths: Vec<_> = toolbox
            .inventory()
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(paths, vec!["README.md", "src/lib.rs", "tests/answer.rs"]);
        assert_eq!(toolbox.inventory().coverage, InventoryCoverage::Complete);
    }

    #[test]
    fn selected_inventory_exposes_only_authoritative_repository_membership() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.root.join("target")).expect("ignored-like directory");
        fs::write(fixture.root.join("target/cache"), "generated").expect("generated cache");
        let toolbox = RepositoryToolbox::open_selected(
            &fixture.root,
            RepositoryToolLimits::default(),
            Vec::new(),
            [path("src/lib.rs"), path("README.md")],
            &CancellationToken::default(),
        )
        .expect("selected toolbox opens");
        let paths = toolbox
            .inventory()
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["README.md", "src/lib.rs"]);
        assert!(!toolbox.files.contains_key(&path("target/cache")));
        assert_eq!(toolbox.inventory().coverage, InventoryCoverage::Complete);
    }

    #[cfg(unix)]
    #[test]
    fn inventory_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        symlink("src/lib.rs", fixture.root.join("linked.rs")).expect("fixture symlink");
        let toolbox = toolbox(&fixture);
        assert!(!toolbox.files.contains_key(&path("linked.rs")));
        assert!(matches!(
            toolbox.inventory().coverage,
            InventoryCoverage::Partial { ref reasons, .. }
                if reasons.contains(&InventoryGapReason::SymbolicLink)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn inventory_rejects_hard_link_aliases() {
        let fixture = Fixture::new();
        fs::hard_link(
            fixture.root.join("src/lib.rs"),
            fixture.root.join("alias.rs"),
        )
        .expect("hard-link fixture");
        let toolbox = toolbox(&fixture);
        assert!(!toolbox.files.contains_key(&path("src/lib.rs")));
        assert!(!toolbox.files.contains_key(&path("alias.rs")));
        assert!(matches!(
            toolbox.inventory().coverage,
            InventoryCoverage::Partial { ref reasons, .. }
                if reasons.contains(&InventoryGapReason::HardLink)
        ));
    }

    #[test]
    fn read_search_list_and_diff_share_one_aggregate_budget() {
        let fixture = Fixture::new();
        let toolbox = toolbox(&fixture);
        let cancellation = CancellationToken::default();
        let mut budget = budget();

        let listed = toolbox
            .list_files(Some(&path("src")), 10, &mut budget, &cancellation, 1)
            .expect("list succeeds");
        assert_eq!(listed.files.len(), 1);
        assert_eq!(listed.files[0].path, path("src/lib.rs"));

        let read = toolbox
            .read_file(
                &path("src/lib.rs"),
                LineRange { start: 1, end: 2 },
                &mut budget,
                &cancellation,
                2,
            )
            .expect("read succeeds");
        assert_eq!(read.content, "pub fn answer() -> u32 {\n    42\n");
        assert_eq!(read.end_line, 2);

        let search = toolbox
            .search(
                &SearchRequest {
                    query: "answer".to_owned(),
                    paths: Vec::new(),
                    max_results: 10,
                },
                &mut budget,
                &cancellation,
                3,
            )
            .expect("search succeeds");
        assert_eq!(search.matches.len(), 4);
        assert_eq!(search.matches[0].path, path("README.md"));

        let diff = toolbox
            .show_diff(&path("src/lib.rs"), &mut budget, &cancellation, 4)
            .expect("diff succeeds");
        assert!(diff.content.contains("+new"));

        assert_eq!(budget.usage().tool_calls, 4);
        assert_eq!(budget.usage().repository_files, 6);
        assert!(budget.usage().repository_bytes > 0);
    }

    #[test]
    fn code_search_supports_bounded_regex_and_case_insensitive_literals() {
        let fixture = Fixture::new();
        let toolbox = toolbox(&fixture);
        let cancellation = CancellationToken::default();
        let mut budget = budget();
        let regex = toolbox
            .search_code(
                &CodeSearchRequest {
                    query: r"answer(_is)?".to_owned(),
                    regex: true,
                    case_sensitive: true,
                    paths: vec![path("tests/answer.rs")],
                    max_results: 10,
                },
                &mut budget,
                &cancellation,
                1,
            )
            .expect("regex search succeeds");
        assert_eq!(regex.matches.len(), 2);

        let literal = toolbox
            .search_code(
                &CodeSearchRequest {
                    query: "FIXTURE".to_owned(),
                    regex: false,
                    case_sensitive: false,
                    paths: vec![path("README.md")],
                    max_results: 10,
                },
                &mut budget,
                &cancellation,
                2,
            )
            .expect("case-insensitive literal search succeeds");
        assert_eq!(literal.matches.len(), 1);

        assert_eq!(
            toolbox.search_code(
                &CodeSearchRequest {
                    query: "(".to_owned(),
                    regex: true,
                    case_sensitive: true,
                    paths: Vec::new(),
                    max_results: 10,
                },
                &mut budget,
                &cancellation,
                3,
            ),
            Err(RepositoryToolError::InvalidQuery)
        );
    }

    #[test]
    fn cancellation_prevents_read_without_spending_budget() {
        let fixture = Fixture::new();
        let toolbox = toolbox(&fixture);
        let cancellation = CancellationToken::default();
        cancellation.cancel(crate::provider::ProviderCancellationReason::UserRequested);
        let mut budget = budget();
        assert_eq!(
            toolbox.read_file(
                &path("src/lib.rs"),
                LineRange { start: 1, end: 1 },
                &mut budget,
                &cancellation,
                1,
            ),
            Err(RepositoryToolError::Cancelled)
        );
        assert_eq!(budget.usage(), AgentBudgetUsage::default());
    }

    #[test]
    fn replaced_inventory_path_is_rejected() {
        let fixture = Fixture::new();
        let toolbox = toolbox(&fixture);
        fs::write(fixture.root.join("src/lib.rs"), "changed after inventory\n")
            .expect("replace fixture source");
        let mut budget = budget();
        assert_eq!(
            toolbox.read_file(
                &path("src/lib.rs"),
                LineRange { start: 1, end: 1 },
                &mut budget,
                &CancellationToken::default(),
                1,
            ),
            Err(RepositoryToolError::PathChanged)
        );
    }

    #[test]
    fn same_size_inventory_mutation_is_rejected() {
        let fixture = Fixture::new();
        let toolbox = toolbox(&fixture);
        let original = fs::read(fixture.root.join("src/lib.rs")).expect("fixture source");
        let replacement = vec![b'x'; original.len()];
        fs::write(fixture.root.join("src/lib.rs"), replacement).expect("replace fixture source");
        let mut budget = budget();
        assert_eq!(
            toolbox.read_file(
                &path("src/lib.rs"),
                LineRange { start: 1, end: 1 },
                &mut budget,
                &CancellationToken::default(),
                1,
            ),
            Err(RepositoryToolError::PathChanged)
        );
    }

    #[test]
    fn search_excerpts_are_bounded_per_match() {
        let fixture = Fixture::new();
        fs::write(
            fixture.root.join("src/huge.rs"),
            format!("{}needle{}needle\n", "a".repeat(700), "b".repeat(700)),
        )
        .expect("large line fixture");
        let toolbox = toolbox(&fixture);
        let mut budget = budget();
        let result = toolbox
            .search(
                &SearchRequest {
                    query: "needle".to_owned(),
                    paths: vec![path("src/huge.rs")],
                    max_results: 10,
                },
                &mut budget,
                &CancellationToken::default(),
                1,
            )
            .expect("search succeeds");
        assert_eq!(result.matches.len(), 2);
        assert!(
            result
                .matches
                .iter()
                .all(|matched| matched.excerpt.len() <= MAX_SEARCH_EXCERPT_BYTES)
        );
    }
}
