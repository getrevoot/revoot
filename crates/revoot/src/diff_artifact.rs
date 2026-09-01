//! Private on-disk diff artifacts and bounded hunk/search access.
//!
//! Artifact paths are never model-visible. All public errors are payload-free,
//! and every returned source slice is explicitly bounded.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use regex::Regex;
use revoot_core::{
    AnchorPosition, FileCoverageLedger, GroupCoverageLedger, HunkCoverage, RepositoryPath,
    RepositoryRelativePath, ReviewGroup, Sha256Digest,
};
use serde::Serialize;
use tempfile::{Builder, TempDir};

pub const DEFAULT_DIFF_PAGE_BYTES: usize = 24 * 1024;
pub const MAX_INLINE_GROUP_DIFF_BYTES: u64 = 16 * 1024;
pub const MAX_DIFF_SEARCH_MATCHES: u32 = 500;

const MAX_QUERY_BYTES: usize = 512;
const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;
const MAX_HUNKS: usize = 4_096;
const MAX_TOOL_RESULT_BYTES: usize = 32 * 1024;

/// Stable metadata for one indexed unified-diff hunk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffHunkManifest {
    pub hunk_id: String,
    pub header: String,
    pub old_start: u32,
    pub old_count: u32,
    pub new_start: u32,
    pub new_count: u32,
    pub changed_lines: u32,
    pub hazardous: bool,
    pub pages: u32,
}

/// Model-safe metadata for one changed file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffFileManifest {
    pub path: RepositoryRelativePath,
    pub size_bytes: u64,
    pub sha256: Sha256Digest,
    pub hunks: Vec<DiffHunkManifest>,
}

/// Bounded hunk page returned by `read_diff`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffHunkPage {
    pub path: RepositoryRelativePath,
    pub hunk_id: String,
    pub page: u32,
    pub total_pages: u32,
    pub content: String,
    /// Exact changed-side coordinates physically present in this page. This is
    /// trusted runtime metadata and is deliberately not serialized to models;
    /// callers expose only matching opaque anchor IDs.
    #[serde(skip)]
    pub positions: BTreeSet<AnchorPosition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffSearchKind {
    Any,
    Added,
    Deleted,
    Context,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffSearchRequest {
    pub query: String,
    pub regex: bool,
    pub case_sensitive: bool,
    pub paths: Vec<RepositoryRelativePath>,
    pub kind: DiffSearchKind,
    pub max_results: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffSearchMatch {
    pub path: RepositoryRelativePath,
    pub hunk_id: String,
    pub diff_line: u32,
    pub excerpt: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiffSearchResult {
    pub matches: Vec<DiffSearchMatch>,
    pub scanned_files: u32,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffArtifactError {
    TemporaryDirectory,
    InvalidPermissions,
    InvalidPath,
    DuplicatePath,
    MissingDiff,
    InputTooLarge,
    InvalidDiff,
    TooManyHunks,
    Io,
    ContentChanged,
    UnknownHunk,
    InvalidPage,
    InvalidQuery,
    InvalidLimit,
    ResultTooLarge,
    Coverage,
}

impl fmt::Display for DiffArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "diff artifact operation failed: {self:?}")
    }
}

impl std::error::Error for DiffArtifactError {}

struct IndexedHunk {
    manifest: DiffHunkManifest,
    pages: Vec<(usize, usize)>,
}

struct DiffArtifact {
    path: RepositoryRelativePath,
    artifact_path: PathBuf,
    size_bytes: u64,
    sha256: Sha256Digest,
    hunks: Vec<IndexedHunk>,
}

/// Private, per-run diff materialization.
pub struct DiffArtifactStore {
    directory: TempDir,
    artifacts: BTreeMap<RepositoryRelativePath, DiffArtifact>,
    page_bytes: usize,
}

impl fmt::Debug for DiffArtifactStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiffArtifactStore")
            .field("artifact_count", &self.artifacts.len())
            .field("page_bytes", &self.page_bytes)
            .field("private_directory_ready", &self.directory.path().is_dir())
            .finish_non_exhaustive()
    }
}

impl DiffArtifactStore {
    /// Materialize exact diffs into a randomized private temporary directory.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid limits, filesystem state, or diff input.
    pub fn create<'a>(
        diffs: impl IntoIterator<Item = (&'a RepositoryRelativePath, &'a str)>,
        page_bytes: usize,
    ) -> Result<Self, DiffArtifactError> {
        Self::create_with_parent(diffs, page_bytes, None)
    }

    fn create_with_parent<'a>(
        diffs: impl IntoIterator<Item = (&'a RepositoryRelativePath, &'a str)>,
        page_bytes: usize,
        temporary_parent: Option<&Path>,
    ) -> Result<Self, DiffArtifactError> {
        if page_bytes == 0 || page_bytes > MAX_TOOL_RESULT_BYTES {
            return Err(DiffArtifactError::InvalidLimit);
        }
        let mut builder = Builder::new();
        builder.prefix("revoot-review-");
        let directory = if let Some(parent) = temporary_parent {
            builder.tempdir_in(parent)
        } else {
            builder.tempdir()
        }
        .map_err(|_| DiffArtifactError::TemporaryDirectory)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| DiffArtifactError::InvalidPermissions)?;
        let mut artifacts = BTreeMap::new();
        for (path, text) in diffs {
            if text.is_empty() || text.len() > MAX_ARTIFACT_BYTES {
                return Err(if text.is_empty() {
                    DiffArtifactError::InvalidDiff
                } else {
                    DiffArtifactError::InputTooLarge
                });
            }
            let digest = Sha256Digest::of_bytes(text.as_bytes());
            let artifact_path = directory.path().join(format!("{}.diff", digest.as_str()));
            write_private(&artifact_path, text.as_bytes())?;
            let hunks = index_hunks(path, text, page_bytes)?;
            let artifact = DiffArtifact {
                path: path.clone(),
                artifact_path,
                size_bytes: u64::try_from(text.len()).unwrap_or(u64::MAX),
                sha256: digest,
                hunks,
            };
            if artifacts.insert(path.clone(), artifact).is_some() {
                return Err(DiffArtifactError::DuplicatePath);
            }
        }
        Ok(Self {
            directory,
            artifacts,
            page_bytes,
        })
    }

    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Return bounded metadata without revealing artifact paths or hunk bodies.
    ///
    /// # Errors
    ///
    /// Returns an error when a requested path has no exact diff artifact.
    pub fn manifest(
        &self,
        paths: &[RepositoryRelativePath],
    ) -> Result<Vec<DiffFileManifest>, DiffArtifactError> {
        paths
            .iter()
            .map(|path| {
                let artifact = self
                    .artifacts
                    .get(path)
                    .ok_or(DiffArtifactError::MissingDiff)?;
                Ok(DiffFileManifest {
                    path: artifact.path.clone(),
                    size_bytes: artifact.size_bytes,
                    sha256: artifact.sha256.clone(),
                    hunks: artifact
                        .hunks
                        .iter()
                        .map(|hunk| hunk.manifest.clone())
                        .collect(),
                })
            })
            .collect()
    }

    /// Return the complete diff only when the group satisfies the inline cap.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or modified artifact.
    pub fn inline_group_diff(
        &self,
        paths: &[RepositoryRelativePath],
        maximum_bytes: u64,
    ) -> Result<Option<String>, DiffArtifactError> {
        let total = paths.iter().try_fold(0_u64, |total, path| {
            let artifact = self
                .artifacts
                .get(path)
                .ok_or(DiffArtifactError::MissingDiff)?;
            total
                .checked_add(artifact.size_bytes)
                .ok_or(DiffArtifactError::InputTooLarge)
        })?;
        if total > maximum_bytes {
            return Ok(None);
        }
        let mut output = String::with_capacity(usize::try_from(total).unwrap_or(usize::MAX));
        for path in paths {
            let artifact = self
                .artifacts
                .get(path)
                .ok_or(DiffArtifactError::MissingDiff)?;
            output.push_str(&read_verified(artifact)?);
        }
        Ok(Some(output))
    }

    /// Read one exact hunk page.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown target, invalid page, or changed artifact.
    pub fn read_hunk_page(
        &self,
        path: &RepositoryRelativePath,
        hunk_id: &str,
        page: u32,
    ) -> Result<DiffHunkPage, DiffArtifactError> {
        let artifact = self
            .artifacts
            .get(path)
            .ok_or(DiffArtifactError::MissingDiff)?;
        let hunk = artifact
            .hunks
            .iter()
            .find(|hunk| hunk.manifest.hunk_id == hunk_id)
            .ok_or(DiffArtifactError::UnknownHunk)?;
        if page == 0 || page > hunk.manifest.pages {
            return Err(DiffArtifactError::InvalidPage);
        }
        let text = read_verified(artifact)?;
        let (start, end) = hunk.pages[usize::try_from(page - 1).unwrap_or(usize::MAX)];
        let content = text
            .get(start..end)
            .ok_or(DiffArtifactError::ContentChanged)?
            .to_owned();
        if content.len() > self.page_bytes {
            return Err(DiffArtifactError::ResultTooLarge);
        }
        Ok(DiffHunkPage {
            path: path.clone(),
            hunk_id: hunk_id.to_owned(),
            page,
            total_pages: hunk.manifest.pages,
            content,
            positions: page_positions(&text, hunk, start, end)?,
        })
    }

    /// Search indexed diff lines without invoking an external executable.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed search input or unavailable artifacts.
    pub fn search(
        &self,
        request: &DiffSearchRequest,
    ) -> Result<DiffSearchResult, DiffArtifactError> {
        validate_search(request)?;
        let matcher = SearchMatcher::new(request)?;
        let requested = if request.paths.is_empty() {
            self.artifacts.keys().cloned().collect::<Vec<_>>()
        } else {
            let mut paths = request.paths.clone();
            paths.sort();
            paths.dedup();
            paths
        };
        let mut results = Vec::new();
        let mut scanned_files = 0_u32;
        let mut result_bytes = 0_usize;
        let mut truncated = false;
        for path in requested {
            let artifact = self
                .artifacts
                .get(&path)
                .ok_or(DiffArtifactError::MissingDiff)?;
            let text = read_verified(artifact)?;
            scanned_files = scanned_files.saturating_add(1);
            for hunk in &artifact.hunks {
                let Some((start, end)) = hunk
                    .pages
                    .first()
                    .zip(hunk.pages.last())
                    .map(|(first, last)| (first.0, last.1))
                else {
                    continue;
                };
                let body = text
                    .get(start..end)
                    .ok_or(DiffArtifactError::ContentChanged)?;
                for (line_index, line) in body.lines().enumerate() {
                    if !line_kind_matches(line, request.kind) {
                        continue;
                    }
                    let searchable = line.get(1..).unwrap_or(line);
                    if !matcher.matches(searchable) {
                        continue;
                    }
                    let excerpt = truncate_utf8(line, 512);
                    let added = path
                        .as_str()
                        .len()
                        .saturating_add(hunk.manifest.hunk_id.len())
                        .saturating_add(excerpt.len())
                        .saturating_add(32);
                    if results.len() >= usize::try_from(request.max_results).unwrap_or(usize::MAX)
                        || result_bytes.saturating_add(added) > MAX_TOOL_RESULT_BYTES
                    {
                        truncated = true;
                        break;
                    }
                    result_bytes = result_bytes.saturating_add(added);
                    results.push(DiffSearchMatch {
                        path: path.clone(),
                        hunk_id: hunk.manifest.hunk_id.clone(),
                        diff_line: u32::try_from(line_index + 1).unwrap_or(u32::MAX),
                        excerpt,
                    });
                }
                if truncated {
                    break;
                }
            }
            if truncated {
                break;
            }
        }
        Ok(DiffSearchResult {
            matches: results,
            scanned_files,
            truncated,
        })
    }

    /// Build an empty risk-adaptive ledger for one validated group.
    ///
    /// # Errors
    ///
    /// Returns an error if the group references unavailable or invalid paths.
    pub fn coverage_for_group(
        &self,
        group: &ReviewGroup,
    ) -> Result<GroupCoverageLedger, DiffArtifactError> {
        let files = group
            .files
            .iter()
            .map(|file| {
                let relative =
                    RepositoryRelativePath::try_from(file.path.new_path.as_str().to_owned())
                        .map_err(|_| DiffArtifactError::InvalidPath)?;
                let artifact = self
                    .artifacts
                    .get(&relative)
                    .ok_or(DiffArtifactError::MissingDiff)?;
                let hunks = artifact
                    .hunks
                    .iter()
                    .map(|hunk| HunkCoverage {
                        hunk_id: hunk.manifest.hunk_id.clone(),
                        total_pages: hunk.manifest.pages,
                        delivered_pages: BTreeSet::new(),
                        hazardous: hunk.manifest.hazardous,
                    })
                    .collect::<Vec<_>>();
                Ok(FileCoverageLedger {
                    path: RepositoryPath::try_from(relative.as_str().to_owned())
                        .map_err(|_| DiffArtifactError::InvalidPath)?,
                    tier: file.tier,
                    manifested: false,
                    metadata_only: hunks.is_empty(),
                    hunks,
                    unread_dispositions: BTreeMap::new(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        GroupCoverageLedger::new(files).map_err(|_| DiffArtifactError::Coverage)
    }

    #[cfg(test)]
    pub(crate) fn directory_path(&self) -> &Path {
        self.directory.path()
    }
}

fn page_positions(
    text: &str,
    hunk: &IndexedHunk,
    page_start: usize,
    page_end: usize,
) -> Result<BTreeSet<AnchorPosition>, DiffArtifactError> {
    let (hunk_start, hunk_end) = hunk
        .pages
        .first()
        .zip(hunk.pages.last())
        .map(|(first, last)| (first.0, last.1))
        .ok_or(DiffArtifactError::InvalidDiff)?;
    let body = text
        .get(hunk_start..hunk_end)
        .ok_or(DiffArtifactError::ContentChanged)?;
    let mut old_line = hunk.manifest.old_start;
    let mut new_line = hunk.manifest.new_start;
    let mut offset = hunk_start;
    let mut positions = BTreeSet::new();
    for (index, line) in body.split_inclusive('\n').enumerate() {
        let line_start = offset;
        offset = offset
            .checked_add(line.len())
            .ok_or(DiffArtifactError::InvalidDiff)?;
        if index == 0 {
            continue;
        }
        let in_page = line_start >= page_start && line_start < page_end;
        match line.as_bytes().first().copied() {
            Some(b'-') => {
                if in_page {
                    positions.insert(
                        AnchorPosition::deletion(old_line)
                            .map_err(|_| DiffArtifactError::InvalidDiff)?,
                    );
                }
                old_line = old_line
                    .checked_add(1)
                    .ok_or(DiffArtifactError::InvalidDiff)?;
            }
            Some(b'+') => {
                if in_page {
                    positions.insert(
                        AnchorPosition::addition(new_line)
                            .map_err(|_| DiffArtifactError::InvalidDiff)?,
                    );
                }
                new_line = new_line
                    .checked_add(1)
                    .ok_or(DiffArtifactError::InvalidDiff)?;
            }
            Some(b' ') => {
                if in_page {
                    positions.insert(
                        AnchorPosition::context(old_line, new_line)
                            .map_err(|_| DiffArtifactError::InvalidDiff)?,
                    );
                }
                old_line = old_line
                    .checked_add(1)
                    .ok_or(DiffArtifactError::InvalidDiff)?;
                new_line = new_line
                    .checked_add(1)
                    .ok_or(DiffArtifactError::InvalidDiff)?;
            }
            Some(b'\\') => {}
            _ => return Err(DiffArtifactError::InvalidDiff),
        }
    }
    Ok(positions)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), DiffArtifactError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|_| DiffArtifactError::Io)?;
    file.write_all(bytes).map_err(|_| DiffArtifactError::Io)?;
    file.sync_all().map_err(|_| DiffArtifactError::Io)?;
    let metadata = file.metadata().map_err(|_| DiffArtifactError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(DiffArtifactError::InvalidPermissions);
    }
    Ok(())
}

fn read_verified(artifact: &DiffArtifact) -> Result<String, DiffArtifactError> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(&artifact.artifact_path)
        .map_err(|_| DiffArtifactError::Io)?;
    let metadata = file.metadata().map_err(|_| DiffArtifactError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != artifact.size_bytes
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(DiffArtifactError::ContentChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    file.take(artifact.size_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| DiffArtifactError::Io)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != artifact.size_bytes
        || Sha256Digest::of_bytes(&bytes) != artifact.sha256
    {
        return Err(DiffArtifactError::ContentChanged);
    }
    String::from_utf8(bytes).map_err(|_| DiffArtifactError::ContentChanged)
}

fn index_hunks(
    path: &RepositoryRelativePath,
    text: &str,
    page_bytes: usize,
) -> Result<Vec<IndexedHunk>, DiffArtifactError> {
    let mut starts = Vec::new();
    let mut offset = 0_usize;
    for line in text.split_inclusive('\n') {
        if line.starts_with("@@ ") {
            starts.push(offset);
        }
        offset = offset.saturating_add(line.len());
    }
    if starts.len() > MAX_HUNKS {
        return Err(DiffArtifactError::TooManyHunks);
    }
    let mut hunks = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().copied().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(text.len());
        let body = text.get(start..end).ok_or(DiffArtifactError::InvalidDiff)?;
        let header = body.lines().next().ok_or(DiffArtifactError::InvalidDiff)?;
        let (old_start, old_count, new_start, new_count) = parse_hunk_header(header)?;
        let changed_lines = body
            .lines()
            .skip(1)
            .filter(|line| {
                (line.starts_with('+') && !line.starts_with("+++"))
                    || (line.starts_with('-') && !line.starts_with("---"))
            })
            .count()
            .try_into()
            .unwrap_or(u32::MAX);
        let hazardous = body.lines().skip(1).any(is_hazardous_added_line);
        let digest_input = format!(
            "{}\n{index}\n{header}\n{}",
            path.as_str(),
            Sha256Digest::of_bytes(body.as_bytes()).as_str()
        );
        let hunk_id = format!(
            "hunk-{}",
            Sha256Digest::of_bytes(digest_input.as_bytes()).as_str()
        );
        let pages = page_ranges(text, start, end, page_bytes)?;
        hunks.push(IndexedHunk {
            manifest: DiffHunkManifest {
                hunk_id,
                header: header.to_owned(),
                old_start,
                old_count,
                new_start,
                new_count,
                changed_lines,
                hazardous,
                pages: u32::try_from(pages.len()).map_err(|_| DiffArtifactError::InputTooLarge)?,
            },
            pages,
        });
    }
    Ok(hunks)
}

fn parse_hunk_header(header: &str) -> Result<(u32, u32, u32, u32), DiffArtifactError> {
    let content = header
        .strip_prefix("@@ ")
        .and_then(|value| value.split_once(" @@"))
        .map(|(ranges, _)| ranges)
        .ok_or(DiffArtifactError::InvalidDiff)?;
    let mut fields = content.split_whitespace();
    let old = fields.next().ok_or(DiffArtifactError::InvalidDiff)?;
    let new = fields.next().ok_or(DiffArtifactError::InvalidDiff)?;
    if fields.next().is_some() || !old.starts_with('-') || !new.starts_with('+') {
        return Err(DiffArtifactError::InvalidDiff);
    }
    let (old_start, old_count) = parse_range(&old[1..])?;
    let (new_start, new_count) = parse_range(&new[1..])?;
    Ok((old_start, old_count, new_start, new_count))
}

fn parse_range(value: &str) -> Result<(u32, u32), DiffArtifactError> {
    let (start, count) = value
        .split_once(',')
        .map_or((value, "1"), |(start, count)| (start, count));
    let start = start.parse().map_err(|_| DiffArtifactError::InvalidDiff)?;
    let count = count.parse().map_err(|_| DiffArtifactError::InvalidDiff)?;
    Ok((start, count))
}

fn page_ranges(
    text: &str,
    start: usize,
    end: usize,
    maximum: usize,
) -> Result<Vec<(usize, usize)>, DiffArtifactError> {
    let mut pages = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let target = cursor.saturating_add(maximum).min(end);
        let mut boundary = target;
        while boundary > cursor && !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        if boundary < end
            && let Some(newline) = text[cursor..boundary].rfind('\n')
            && newline > 0
        {
            boundary = cursor + newline + 1;
        }
        if boundary <= cursor {
            return Err(DiffArtifactError::InvalidDiff);
        }
        pages.push((cursor, boundary));
        cursor = boundary;
    }
    if pages.is_empty() {
        return Err(DiffArtifactError::InvalidDiff);
    }
    Ok(pages)
}

fn is_hazardous_added_line(line: &str) -> bool {
    let Some(added) = line.strip_prefix('+') else {
        return false;
    };
    !line.starts_with("+++")
        && (added.trim_start().starts_with("<<<<<<<")
            || added.trim_start().starts_with(">>>>>>>")
            || added.trim() == "======="
            || added.contains("-----BEGIN PRIVATE KEY-----")
            || added.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
            || added.contains("github_pat_")
            || added.contains("ghp_"))
}

fn validate_search(request: &DiffSearchRequest) -> Result<(), DiffArtifactError> {
    if request.query.is_empty()
        || request.query.len() > MAX_QUERY_BYTES
        || request.query.contains(['\0', '\n', '\r'])
    {
        return Err(DiffArtifactError::InvalidQuery);
    }
    if request.max_results == 0 || request.max_results > MAX_DIFF_SEARCH_MATCHES {
        return Err(DiffArtifactError::InvalidLimit);
    }
    Ok(())
}

enum SearchMatcher {
    Literal {
        needle: String,
        case_sensitive: bool,
    },
    Regex(Regex),
}

impl SearchMatcher {
    fn new(request: &DiffSearchRequest) -> Result<Self, DiffArtifactError> {
        if request.regex {
            let pattern = if request.case_sensitive {
                request.query.clone()
            } else {
                format!("(?i:{})", request.query)
            };
            Regex::new(&pattern)
                .map(Self::Regex)
                .map_err(|_| DiffArtifactError::InvalidQuery)
        } else {
            Ok(Self::Literal {
                needle: if request.case_sensitive {
                    request.query.clone()
                } else {
                    request.query.to_lowercase()
                },
                case_sensitive: request.case_sensitive,
            })
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Literal {
                needle,
                case_sensitive,
            } => {
                if *case_sensitive {
                    value.contains(needle)
                } else {
                    value.to_lowercase().contains(needle)
                }
            }
            Self::Regex(regex) => regex.is_match(value),
        }
    }
}

fn line_kind_matches(line: &str, kind: DiffSearchKind) -> bool {
    match kind {
        DiffSearchKind::Any => line.starts_with(['+', '-', ' ']),
        DiffSearchKind::Added => line.starts_with('+') && !line.starts_with("+++"),
        DiffSearchKind::Deleted => line.starts_with('-') && !line.starts_with("---"),
        DiffSearchKind::Context => line.starts_with(' '),
    }
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    fn relative(value: &str) -> RepositoryRelativePath {
        RepositoryRelativePath::try_from(value.to_owned()).unwrap()
    }

    fn diff() -> String {
        "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,3 @@\n old\n+new value\n context\n@@ -10,1 +11,1 @@\n-secret\n+github_pat_example\n".to_owned()
    }

    #[test]
    fn private_store_indexes_reads_searches_and_cleans_up() {
        let path = relative("src/lib.rs");
        let root;
        {
            let text = diff();
            let store = DiffArtifactStore::create([(&path, text.as_str())], 64).unwrap();
            root = store.directory_path().to_path_buf();
            let debug = format!("{store:?}");
            assert!(!debug.contains(path.as_str()));
            assert!(!debug.contains("github_pat_example"));
            assert!(!debug.contains(&root.to_string_lossy().into_owned()));
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            let manifest = store.manifest(std::slice::from_ref(&path)).unwrap();
            let entries = fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), 1);
            assert_eq!(
                entries[0].file_name().and_then(|name| name.to_str()),
                Some(format!("{}.diff", manifest[0].sha256.as_str()).as_str())
            );
            assert_eq!(
                fs::metadata(&entries[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert!(!entries[0].to_string_lossy().contains("src/lib.rs"));
            assert_eq!(manifest[0].hunks.len(), 2);
            assert!(manifest[0].hunks[1].hazardous);
            let page = store
                .read_hunk_page(&path, &manifest[0].hunks[0].hunk_id, 1)
                .unwrap();
            assert!(page.content.starts_with("@@"));
            let result = store
                .search(&DiffSearchRequest {
                    query: "new value".to_owned(),
                    regex: false,
                    case_sensitive: true,
                    paths: Vec::new(),
                    kind: DiffSearchKind::Added,
                    max_results: 20,
                })
                .unwrap();
            assert_eq!(result.matches.len(), 1);
        }
        assert!(!root.exists());
    }

    #[test]
    fn large_group_is_not_inlined() {
        let path = relative("src/lib.rs");
        let text = diff();
        let store = DiffArtifactStore::create([(&path, text.as_str())], 64).unwrap();
        assert_eq!(
            store.inline_group_diff(std::slice::from_ref(&path), 1),
            Ok(None)
        );
        assert!(
            store
                .inline_group_diff(std::slice::from_ref(&path), 10_000)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn oversized_hunk_pages_issue_only_positions_present_on_each_page() {
        let path = relative("src/lib.rs");
        let text = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -7,2 +7,2 @@\n-old-one\n-old-two\n+new-one\n+new-two\n";
        let store = DiffArtifactStore::create([(&path, text)], 24).expect("store");
        let manifest = store
            .manifest(std::slice::from_ref(&path))
            .expect("manifest");
        let hunk = &manifest[0].hunks[0];
        assert!(hunk.pages > 1);

        let mut observed = BTreeSet::new();
        for page_number in 1..=hunk.pages {
            let page = store
                .read_hunk_page(&path, &hunk.hunk_id, page_number)
                .expect("page");
            assert!(observed.is_disjoint(&page.positions));
            observed.extend(page.positions);
        }
        assert_eq!(
            observed,
            BTreeSet::from([
                AnchorPosition::deletion(7).expect("position"),
                AnchorPosition::deletion(8).expect("position"),
                AnchorPosition::addition(7).expect("position"),
                AnchorPosition::addition(8).expect("position"),
            ])
        );
    }

    #[test]
    fn symlink_hardlink_and_content_tampering_fail_closed() {
        let path = relative("src/private-name.rs");
        let text = diff();

        let store = DiffArtifactStore::create([(&path, text.as_str())], 64).unwrap();
        let artifact = only_artifact_path(&store);
        let alias = store.directory_path().join("alias.diff");
        fs::hard_link(&artifact, &alias).unwrap();
        assert_eq!(
            read_first_page(&store, &path),
            Err(DiffArtifactError::ContentChanged)
        );
        assert!(!format!("{:?}", read_first_page(&store, &path)).contains("private-name"));
        drop(store);

        let store = DiffArtifactStore::create([(&path, text.as_str())], 64).unwrap();
        let artifact = only_artifact_path(&store);
        fs::write(&artifact, "x".repeat(text.len())).unwrap();
        assert_eq!(
            read_first_page(&store, &path),
            Err(DiffArtifactError::ContentChanged)
        );
        drop(store);

        let store = DiffArtifactStore::create([(&path, text.as_str())], 64).unwrap();
        let artifact = only_artifact_path(&store);
        let target = store.directory_path().join("target");
        fs::write(&target, text.as_bytes()).unwrap();
        fs::remove_file(&artifact).unwrap();
        symlink(&target, &artifact).unwrap();
        assert_eq!(read_first_page(&store, &path), Err(DiffArtifactError::Io));
        assert!(!DiffArtifactError::Io.to_string().contains(path.as_str()));
        assert!(
            !DiffArtifactError::Io
                .to_string()
                .contains("github_pat_example")
        );
    }

    #[test]
    fn midway_creation_failure_removes_private_directory() {
        let parent = tempfile::tempdir().unwrap();
        let valid_path = relative("src/valid.rs");
        let invalid_path = relative("src/invalid.rs");
        let text = diff();
        let error = DiffArtifactStore::create_with_parent(
            [
                (&valid_path, text.as_str()),
                (&invalid_path, "@@ invalid\n"),
            ],
            64,
            Some(parent.path()),
        )
        .expect_err("second artifact fails after first write");
        assert_eq!(error, DiffArtifactError::InvalidDiff);
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn panic_unwind_removes_private_directory() {
        let path = relative("src/lib.rs");
        let text = diff();
        let store = DiffArtifactStore::create([(&path, text.as_str())], 64).unwrap();
        let directory = store.directory_path().to_path_buf();
        let unwind = catch_unwind(AssertUnwindSafe(move || {
            let _owned_store = store;
            panic!("test unwind");
        }));
        assert!(unwind.is_err());
        assert!(!directory.exists());
    }

    fn only_artifact_path(store: &DiffArtifactStore) -> PathBuf {
        let entries = fs::read_dir(store.directory_path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        entries.into_iter().next().unwrap()
    }

    fn read_first_page(
        store: &DiffArtifactStore,
        path: &RepositoryRelativePath,
    ) -> Result<DiffHunkPage, DiffArtifactError> {
        let manifest = store.manifest(std::slice::from_ref(path)).unwrap();
        store.read_hunk_page(path, &manifest[0].hunks[0].hunk_id, 1)
    }
}
