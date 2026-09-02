//! Deterministic contracts for bounded local source scans.
//!
//! Plans contain content identities and line ranges, never source bodies. They
//! grant no provider, process, network, repository-write, or publication
//! authority.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{LocalSnapshotIdentity, RepositoryPath, Sha256Digest};

const MAX_FILES: u32 = 100_000;
const MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_CHUNKS: u32 = 200_000;
const MAX_CHUNK_LINES: u32 = 500;
const MAX_CHUNK_BYTES: u32 = 32 * 1024;
const CHUNK_ID_PREFIX: &str = "sc1_";

/// Whether a local file belongs to the tracked snapshot or was explicitly
/// admitted as an untracked local input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanFileTracking {
    Tracked,
    Untracked,
}

/// Closed authority for admitting untracked content to a local scan.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanUntrackedPolicy {
    #[default]
    Exclude,
    IncludeExplicitLocal,
}

/// Trusted metadata describing the local CLI scan request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequestMetadata {
    pub snapshot: LocalSnapshotIdentity,
    /// Empty means every otherwise eligible path. Entries are exact paths or
    /// directory prefixes selected by the local caller.
    pub requested_paths: Vec<RepositoryPath>,
    pub untracked_policy: ScanUntrackedPolicy,
}

/// Hard deterministic bounds for source selection and chunk construction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanLimits {
    pub max_files: u32,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_chunks: u32,
    pub max_chunk_lines: u32,
    pub max_chunk_bytes: u32,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_total_bytes: 20 * 1024 * 1024,
            max_file_bytes: 1024 * 1024,
            max_chunks: 50_000,
            max_chunk_lines: MAX_CHUNK_LINES,
            max_chunk_bytes: MAX_CHUNK_BYTES,
        }
    }
}

impl ScanLimits {
    fn validate(self) -> Result<(), ScanPlanError> {
        if self.max_files == 0 || self.max_files > MAX_FILES {
            return Err(ScanPlanError::InvalidLimits);
        }
        if self.max_total_bytes == 0 || self.max_total_bytes > MAX_TOTAL_BYTES {
            return Err(ScanPlanError::InvalidLimits);
        }
        if self.max_file_bytes == 0
            || self.max_file_bytes > MAX_FILE_BYTES
            || self.max_file_bytes > self.max_total_bytes
        {
            return Err(ScanPlanError::InvalidLimits);
        }
        if self.max_chunks == 0 || self.max_chunks > MAX_CHUNKS {
            return Err(ScanPlanError::InvalidLimits);
        }
        if self.max_chunk_lines == 0 || self.max_chunk_lines > MAX_CHUNK_LINES {
            return Err(ScanPlanError::InvalidLimits);
        }
        if self.max_chunk_bytes == 0 || self.max_chunk_bytes > MAX_CHUNK_BYTES {
            return Err(ScanPlanError::InvalidLimits);
        }
        Ok(())
    }
}

/// One post-change local source input. The body is consumed only while the
/// plan is constructed and is not retained in the plan.
#[derive(Clone, Eq, PartialEq)]
pub struct ScanFileInput {
    pub path: RepositoryPath,
    pub tracking: ScanFileTracking,
    pub content: String,
}

impl fmt::Debug for ScanFileInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanFileInput")
            .field("path", &self.path)
            .field("tracking", &self.tracking)
            .field("content", &"[redacted]")
            .finish()
    }
}

/// Exact body-free identity and range for one bounded source chunk.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanChunk {
    pub id: String,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u64,
    pub end_byte: u64,
    pub body_bytes: u32,
    pub body_sha256: Sha256Digest,
}

/// One fully represented post-change file and all of its ordered chunks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanFile {
    pub path: RepositoryPath,
    pub tracking: ScanFileTracking,
    pub content_bytes: u64,
    pub line_count: u32,
    pub content_sha256: Sha256Digest,
    pub chunks: Vec<ScanChunk>,
}

/// Deterministic reason a local source input was not chunked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanOmissionReason {
    NotRequested,
    UntrackedNotAuthorized,
    BinaryLikeContent,
    FileTooLarge,
    LineTooLarge,
    FileBudget,
    TotalByteBudget,
    ChunkBudget,
}

/// One path omitted before any model work.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanOmission {
    pub path: RepositoryPath,
    pub tracking: ScanFileTracking,
    pub reason: ScanOmissionReason,
}

/// Counts that expose exactly how much local content the plan represents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCoverage {
    pub input_files: u32,
    pub included_files: u32,
    pub omitted_files: u32,
    pub included_bytes: u64,
    pub chunks: u32,
    pub complete: bool,
}

/// Canonical body-free plan for a bounded local source scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanPlan {
    pub schema_version: String,
    pub request: ScanRequestMetadata,
    pub limits: ScanLimits,
    pub files: Vec<ScanFile>,
    pub omissions: Vec<ScanOmission>,
    pub coverage: ScanCoverage,
    pub plan_sha256: Sha256Digest,
}

impl ScanPlan {
    pub const SCHEMA_VERSION: &'static str = "revoot.scan-plan/v1";

    /// Rebuild the plan from the exact post-change inputs and compare every
    /// field, range, digest, omission, count, and request binding.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for invalid input or replay divergence.
    pub fn validate_replay(&self, inputs: &[ScanFileInput]) -> Result<(), ScanPlanError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ScanPlanError::SchemaVersion);
        }
        self.limits.validate()?;
        validate_request(&self.request)?;
        validate_structure(self)?;
        let expected = derive_scan_plan(self.request.clone(), self.limits, inputs.to_vec())?;
        if *self != expected {
            return Err(ScanPlanError::ReplayMismatch);
        }
        Ok(())
    }

    /// Serialize a replay-validated plan in stable order.
    ///
    /// # Errors
    ///
    /// Returns an error when replay validation or JSON serialization fails.
    pub fn canonical_json(&self, inputs: &[ScanFileInput]) -> Result<Vec<u8>, ScanCanonicalError> {
        self.validate_replay(inputs)
            .map_err(ScanCanonicalError::Validation)?;
        serde_json::to_vec(self).map_err(ScanCanonicalError::Serialization)
    }
}

/// Failure while building or replaying a local scan plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanPlanError {
    SchemaVersion,
    InvalidRequest,
    InvalidLimits,
    TooManyInputs,
    DuplicatePath,
    InvalidStructure,
    CountOverflow,
    ReplayMismatch,
    Serialization,
}

impl fmt::Display for ScanPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "the scan plan schema version is invalid",
            Self::InvalidRequest => "the scan request metadata is invalid",
            Self::InvalidLimits => "the scan limits are invalid",
            Self::TooManyInputs => "the scan contains too many input files",
            Self::DuplicatePath => "the scan contains a duplicate path",
            Self::InvalidStructure => "the scan plan structure is invalid",
            Self::CountOverflow => "a scan metadata count overflowed",
            Self::ReplayMismatch => "the scan plan does not replay from the supplied inputs",
            Self::Serialization => "the scan plan could not be serialized",
        })
    }
}

impl std::error::Error for ScanPlanError {}

/// Error returned by canonical scan-plan serialization.
#[derive(Debug)]
pub enum ScanCanonicalError {
    Validation(ScanPlanError),
    Serialization(serde_json::Error),
}

/// Build a deterministic body-free scan plan from post-change local files.
///
/// # Errors
///
/// Rejects invalid limits or request metadata, excessive or duplicate inputs,
/// and metadata count/serialization failures.
pub fn build_scan_plan(
    request: ScanRequestMetadata,
    limits: ScanLimits,
    inputs: impl IntoIterator<Item = ScanFileInput>,
) -> Result<ScanPlan, ScanPlanError> {
    limits.validate()?;
    validate_request(&request)?;
    let mut bounded_inputs = Vec::new();
    for input in inputs {
        if bounded_inputs.len() == usize::try_from(MAX_FILES).unwrap_or(usize::MAX) {
            return Err(ScanPlanError::TooManyInputs);
        }
        bounded_inputs.push(input);
    }
    derive_scan_plan(request, limits, bounded_inputs)
}

fn derive_scan_plan(
    request: ScanRequestMetadata,
    limits: ScanLimits,
    mut inputs: Vec<ScanFileInput>,
) -> Result<ScanPlan, ScanPlanError> {
    inputs.sort_by(|left, right| left.path.cmp(&right.path));
    if inputs.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(ScanPlanError::DuplicatePath);
    }

    let mut files = Vec::new();
    let mut omissions = Vec::new();
    let mut included_bytes = 0_u64;
    let mut chunk_count = 0_u32;
    for input in &inputs {
        let omission = preliminary_omission(&request, limits, input, files.len(), included_bytes);
        if let Some(reason) = omission {
            omissions.push(ScanOmission {
                path: input.path.clone(),
                tracking: input.tracking,
                reason,
            });
            continue;
        }
        let Some(chunks) = chunks_for(input, limits)? else {
            omissions.push(ScanOmission {
                path: input.path.clone(),
                tracking: input.tracking,
                reason: ScanOmissionReason::LineTooLarge,
            });
            continue;
        };
        let file_chunks = u32::try_from(chunks.len()).map_err(|_| ScanPlanError::CountOverflow)?;
        if chunk_count.saturating_add(file_chunks) > limits.max_chunks {
            omissions.push(ScanOmission {
                path: input.path.clone(),
                tracking: input.tracking,
                reason: ScanOmissionReason::ChunkBudget,
            });
            continue;
        }
        let content_bytes =
            u64::try_from(input.content.len()).map_err(|_| ScanPlanError::CountOverflow)?;
        included_bytes = included_bytes
            .checked_add(content_bytes)
            .ok_or(ScanPlanError::CountOverflow)?;
        chunk_count = chunk_count
            .checked_add(file_chunks)
            .ok_or(ScanPlanError::CountOverflow)?;
        files.push(ScanFile {
            path: input.path.clone(),
            tracking: input.tracking,
            content_bytes,
            line_count: line_count(&input.content)?,
            content_sha256: Sha256Digest::of_bytes(input.content.as_bytes()),
            chunks,
        });
    }

    let input_files = u32::try_from(inputs.len()).map_err(|_| ScanPlanError::CountOverflow)?;
    let included_files = u32::try_from(files.len()).map_err(|_| ScanPlanError::CountOverflow)?;
    let omitted_files = u32::try_from(omissions.len()).map_err(|_| ScanPlanError::CountOverflow)?;
    let mut plan = ScanPlan {
        schema_version: ScanPlan::SCHEMA_VERSION.to_owned(),
        request,
        limits,
        files,
        omissions,
        coverage: ScanCoverage {
            input_files,
            included_files,
            omitted_files,
            included_bytes,
            chunks: chunk_count,
            complete: omitted_files == 0,
        },
        plan_sha256: Sha256Digest::of_bytes(&[]),
    };
    plan.plan_sha256 = derive_plan_digest(&plan)?;
    validate_structure(&plan)?;
    Ok(plan)
}

fn preliminary_omission(
    request: &ScanRequestMetadata,
    limits: ScanLimits,
    input: &ScanFileInput,
    included_files: usize,
    included_bytes: u64,
) -> Option<ScanOmissionReason> {
    if !path_requested(&input.path, &request.requested_paths) {
        return Some(ScanOmissionReason::NotRequested);
    }
    if input.tracking == ScanFileTracking::Untracked
        && request.untracked_policy != ScanUntrackedPolicy::IncludeExplicitLocal
    {
        return Some(ScanOmissionReason::UntrackedNotAuthorized);
    }
    if input.content.contains('\0') {
        return Some(ScanOmissionReason::BinaryLikeContent);
    }
    let bytes = u64::try_from(input.content.len()).unwrap_or(u64::MAX);
    if bytes > limits.max_file_bytes {
        return Some(ScanOmissionReason::FileTooLarge);
    }
    if included_files >= usize::try_from(limits.max_files).unwrap_or(usize::MAX) {
        return Some(ScanOmissionReason::FileBudget);
    }
    if included_bytes.saturating_add(bytes) > limits.max_total_bytes {
        return Some(ScanOmissionReason::TotalByteBudget);
    }
    None
}

fn chunks_for(
    input: &ScanFileInput,
    limits: ScanLimits,
) -> Result<Option<Vec<ScanChunk>>, ScanPlanError> {
    let lines = source_lines(&input.content);
    if lines
        .iter()
        .any(|(_, line)| line.len() > usize::try_from(limits.max_chunk_bytes).unwrap_or(usize::MAX))
    {
        return Ok(None);
    }
    let mut chunks = Vec::new();
    let mut index = 0_usize;
    while index < lines.len() {
        let start = index;
        let start_byte = lines[index].0;
        let mut bytes = 0_usize;
        while index < lines.len()
            && index - start < usize::try_from(limits.max_chunk_lines).unwrap_or(usize::MAX)
            && bytes.saturating_add(lines[index].1.len())
                <= usize::try_from(limits.max_chunk_bytes).unwrap_or(usize::MAX)
        {
            bytes += lines[index].1.len();
            index += 1;
        }
        let end_byte = start_byte
            .checked_add(bytes)
            .ok_or(ScanPlanError::CountOverflow)?;
        let body = &input.content.as_bytes()[start_byte..end_byte];
        let start_line = u32::try_from(start + 1).map_err(|_| ScanPlanError::CountOverflow)?;
        let end_line = u32::try_from(index).map_err(|_| ScanPlanError::CountOverflow)?;
        let body_bytes = u32::try_from(bytes).map_err(|_| ScanPlanError::CountOverflow)?;
        let body_sha256 = Sha256Digest::of_bytes(body);
        let id = chunk_id(
            &input.path,
            input.tracking,
            start_line,
            end_line,
            u64::try_from(start_byte).map_err(|_| ScanPlanError::CountOverflow)?,
            u64::try_from(end_byte).map_err(|_| ScanPlanError::CountOverflow)?,
            &body_sha256,
        )?;
        chunks.push(ScanChunk {
            id,
            start_line,
            end_line,
            start_byte: u64::try_from(start_byte).map_err(|_| ScanPlanError::CountOverflow)?,
            end_byte: u64::try_from(end_byte).map_err(|_| ScanPlanError::CountOverflow)?,
            body_bytes,
            body_sha256,
        });
    }
    Ok(Some(chunks))
}

fn source_lines(content: &str) -> Vec<(usize, &str)> {
    let mut offset = 0_usize;
    content
        .split_inclusive('\n')
        .map(|line| {
            let start = offset;
            offset += line.len();
            (start, line)
        })
        .collect()
}

fn line_count(content: &str) -> Result<u32, ScanPlanError> {
    if content.is_empty() {
        return Ok(0);
    }
    u32::try_from(content.split_inclusive('\n').count()).map_err(|_| ScanPlanError::CountOverflow)
}

fn path_requested(path: &RepositoryPath, requested: &[RepositoryPath]) -> bool {
    requested.is_empty()
        || requested.iter().any(|candidate| {
            path == candidate
                || path
                    .as_str()
                    .strip_prefix(candidate.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn validate_request(request: &ScanRequestMetadata) -> Result<(), ScanPlanError> {
    if !strictly_sorted(&request.requested_paths) {
        return Err(ScanPlanError::InvalidRequest);
    }
    Ok(())
}

fn validate_structure(plan: &ScanPlan) -> Result<(), ScanPlanError> {
    if !strictly_sorted_by(&plan.files, |file| &file.path)
        || !strictly_sorted_by(&plan.omissions, |item| &item.path)
        || plan.files.iter().any(|file| {
            file.chunks.len() > usize::try_from(plan.limits.max_chunks).unwrap_or(usize::MAX)
                || !valid_chunks(file, plan.limits)
        })
    {
        return Err(ScanPlanError::InvalidStructure);
    }
    let included_files =
        u32::try_from(plan.files.len()).map_err(|_| ScanPlanError::CountOverflow)?;
    let omitted_files =
        u32::try_from(plan.omissions.len()).map_err(|_| ScanPlanError::CountOverflow)?;
    let input_files = included_files
        .checked_add(omitted_files)
        .ok_or(ScanPlanError::CountOverflow)?;
    let included_bytes = plan
        .files
        .iter()
        .try_fold(0_u64, |total, file| total.checked_add(file.content_bytes));
    let chunks = plan.files.iter().try_fold(0_u32, |total, file| {
        total.checked_add(u32::try_from(file.chunks.len()).ok()?)
    });
    if plan.coverage.input_files != input_files
        || plan.coverage.included_files != included_files
        || plan.coverage.omitted_files != omitted_files
        || Some(plan.coverage.included_bytes) != included_bytes
        || Some(plan.coverage.chunks) != chunks
        || plan.coverage.complete != plan.omissions.is_empty()
        || plan.coverage.included_files > plan.limits.max_files
        || plan.coverage.included_bytes > plan.limits.max_total_bytes
        || plan.coverage.chunks > plan.limits.max_chunks
        || plan.plan_sha256 != derive_plan_digest(plan)?
    {
        return Err(ScanPlanError::InvalidStructure);
    }
    let included = plan
        .files
        .iter()
        .map(|file| &file.path)
        .collect::<BTreeSet<_>>();
    if plan
        .omissions
        .iter()
        .any(|item| included.contains(&item.path))
    {
        return Err(ScanPlanError::InvalidStructure);
    }
    Ok(())
}

fn valid_chunks(file: &ScanFile, limits: ScanLimits) -> bool {
    if file.content_bytes > limits.max_file_bytes
        || file.chunks.is_empty() != (file.content_bytes == 0)
    {
        return false;
    }
    let mut next_line = 1_u32;
    let mut next_byte = 0_u64;
    for chunk in &file.chunks {
        let line_count = chunk.end_line.checked_sub(chunk.start_line).map(|n| n + 1);
        if !valid_chunk_id(&chunk.id)
            || chunk.start_line != next_line
            || chunk.start_byte != next_byte
            || chunk.end_line < chunk.start_line
            || chunk.end_byte <= chunk.start_byte
            || chunk.end_byte - chunk.start_byte != u64::from(chunk.body_bytes)
            || line_count.is_none_or(|count| count > limits.max_chunk_lines)
            || chunk.body_bytes > limits.max_chunk_bytes
        {
            return false;
        }
        next_line = match chunk.end_line.checked_add(1) {
            Some(line) => line,
            None => return false,
        };
        next_byte = chunk.end_byte;
    }
    next_byte == file.content_bytes && file.line_count.checked_add(1) == Some(next_line)
}

fn chunk_id(
    path: &RepositoryPath,
    tracking: ScanFileTracking,
    start_line: u32,
    end_line: u32,
    start_byte: u64,
    end_byte: u64,
    body_sha256: &Sha256Digest,
) -> Result<String, ScanPlanError> {
    let bytes = serde_json::to_vec(&(
        path,
        tracking,
        start_line,
        end_line,
        start_byte,
        end_byte,
        body_sha256,
    ))
    .map_err(|_| ScanPlanError::Serialization)?;
    Ok(format!(
        "{CHUNK_ID_PREFIX}{}",
        Sha256Digest::of_bytes(&bytes).as_str()
    ))
}

fn valid_chunk_id(id: &str) -> bool {
    id.strip_prefix(CHUNK_ID_PREFIX).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn derive_plan_digest(plan: &ScanPlan) -> Result<Sha256Digest, ScanPlanError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        request: &'a ScanRequestMetadata,
        limits: ScanLimits,
        files: &'a [ScanFile],
        omissions: &'a [ScanOmission],
        coverage: &'a ScanCoverage,
    }
    serde_json::to_vec(&DigestInput {
        schema_version: &plan.schema_version,
        request: &plan.request,
        limits: plan.limits,
        files: &plan.files,
        omissions: &plan.omissions,
        coverage: &plan.coverage,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| ScanPlanError::Serialization)
}

fn strictly_sorted<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, U: Ord>(items: &[T], key: impl Fn(&T) -> &U) -> bool {
    items.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GitSha;

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).unwrap()
    }

    fn request(untracked_policy: ScanUntrackedPolicy) -> ScanRequestMetadata {
        ScanRequestMetadata {
            snapshot: LocalSnapshotIdentity {
                repository_identity_sha256: digest('a'),
                base_sha: GitSha::try_from("b".repeat(40)).unwrap(),
                head_sha: GitSha::try_from("c".repeat(40)).unwrap(),
                working_tree_sha256: digest('d'),
                exact_diff_manifest_sha256: digest('e'),
            },
            requested_paths: Vec::new(),
            untracked_policy,
        }
    }

    fn input(path_value: &str, tracking: ScanFileTracking, content: &str) -> ScanFileInput {
        ScanFileInput {
            path: path(path_value),
            tracking,
            content: content.to_owned(),
        }
    }

    #[test]
    fn chunks_are_bounded_body_free_and_deterministic() {
        let limits = ScanLimits {
            max_chunk_lines: 2,
            max_chunk_bytes: 8,
            ..ScanLimits::default()
        };
        let inputs = vec![
            input("src/b.rs", ScanFileTracking::Tracked, "bb\ncc\ndd\n"),
            input("src/a.rs", ScanFileTracking::Tracked, "a1\na2\na3"),
        ];
        let left = build_scan_plan(
            request(ScanUntrackedPolicy::Exclude),
            limits,
            inputs.clone(),
        )
        .unwrap();
        let right = build_scan_plan(
            request(ScanUntrackedPolicy::Exclude),
            limits,
            inputs.iter().cloned().rev(),
        )
        .unwrap();
        assert_eq!(left, right);
        assert_eq!(left.files[0].path.as_str(), "src/a.rs");
        assert_eq!(left.files[0].chunks.len(), 2);
        assert_eq!(
            (
                left.files[0].chunks[0].start_line,
                left.files[0].chunks[0].end_line
            ),
            (1, 2)
        );
        assert!(
            left.files
                .iter()
                .flat_map(|file| &file.chunks)
                .all(|chunk| {
                    chunk.body_bytes <= limits.max_chunk_bytes
                        && chunk.end_line - chunk.start_line < limits.max_chunk_lines
                })
        );
        let json = String::from_utf8(left.canonical_json(&inputs).unwrap()).unwrap();
        assert!(!json.contains("a1\na2"));
        left.validate_replay(&inputs).unwrap();
    }

    #[test]
    fn untracked_files_require_explicit_local_authority() {
        let inputs = vec![input(
            "src/new.rs",
            ScanFileTracking::Untracked,
            "fn new() {}\n",
        )];
        let excluded = build_scan_plan(
            request(ScanUntrackedPolicy::Exclude),
            ScanLimits::default(),
            inputs.clone(),
        )
        .unwrap();
        assert!(excluded.files.is_empty());
        assert_eq!(
            excluded.omissions[0].reason,
            ScanOmissionReason::UntrackedNotAuthorized
        );

        let included = build_scan_plan(
            request(ScanUntrackedPolicy::IncludeExplicitLocal),
            ScanLimits::default(),
            inputs,
        )
        .unwrap();
        assert_eq!(included.files.len(), 1);
        assert_eq!(included.files[0].tracking, ScanFileTracking::Untracked);
    }

    #[test]
    fn request_filters_and_capacity_omissions_are_explicit() {
        let mut metadata = request(ScanUntrackedPolicy::Exclude);
        metadata.requested_paths = vec![path("src")];
        let limits = ScanLimits {
            max_files: 1,
            max_total_bytes: 10,
            max_file_bytes: 10,
            ..ScanLimits::default()
        };
        let plan = build_scan_plan(
            metadata,
            limits,
            vec![
                input("docs/a.md", ScanFileTracking::Tracked, "skip"),
                input("src/a.rs", ScanFileTracking::Tracked, "12345"),
                input("src/b.rs", ScanFileTracking::Tracked, "67890"),
            ],
        )
        .unwrap();
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.omissions.len(), 2);
        assert_eq!(plan.omissions[0].reason, ScanOmissionReason::NotRequested);
        assert_eq!(plan.omissions[1].reason, ScanOmissionReason::FileBudget);
        assert!(!plan.coverage.complete);
    }

    #[test]
    fn oversized_lines_and_binary_like_content_are_omitted() {
        let limits = ScanLimits {
            max_chunk_bytes: 4,
            ..ScanLimits::default()
        };
        let plan = build_scan_plan(
            request(ScanUntrackedPolicy::Exclude),
            limits,
            vec![
                input("src/binary", ScanFileTracking::Tracked, "a\0b"),
                input("src/long.rs", ScanFileTracking::Tracked, "12345\n"),
            ],
        )
        .unwrap();
        assert!(plan.files.is_empty());
        assert_eq!(
            plan.omissions
                .iter()
                .map(|item| item.reason)
                .collect::<Vec<_>>(),
            [
                ScanOmissionReason::BinaryLikeContent,
                ScanOmissionReason::LineTooLarge
            ]
        );
    }

    #[test]
    fn replay_rejects_source_or_plan_tampering() {
        let inputs = vec![input(
            "src/lib.rs",
            ScanFileTracking::Tracked,
            "pub fn value() -> u8 { 1 }\n",
        )];
        let plan = build_scan_plan(
            request(ScanUntrackedPolicy::Exclude),
            ScanLimits::default(),
            inputs.clone(),
        )
        .unwrap();
        let changed_inputs = vec![input(
            "src/lib.rs",
            ScanFileTracking::Tracked,
            "pub fn value() -> u8 { 2 }\n",
        )];
        assert_eq!(
            plan.validate_replay(&changed_inputs),
            Err(ScanPlanError::ReplayMismatch)
        );

        let mut tampered = plan;
        tampered.files[0].chunks[0].end_line += 1;
        assert_eq!(
            tampered.validate_replay(&inputs),
            Err(ScanPlanError::InvalidStructure)
        );
    }

    #[test]
    fn plan_json_has_no_execution_or_publication_authority() {
        let inputs = vec![input(
            "src/lib.rs",
            ScanFileTracking::Tracked,
            "pub fn value() {}\n",
        )];
        let plan = build_scan_plan(
            request(ScanUntrackedPolicy::Exclude),
            ScanLimits::default(),
            inputs.clone(),
        )
        .unwrap();
        let json = String::from_utf8(plan.canonical_json(&inputs).unwrap()).unwrap();
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
    fn source_input_debug_is_redacted() {
        let input = input(
            "src/lib.rs",
            ScanFileTracking::Tracked,
            "private source sentinel",
        );
        let debug = format!("{input:?}");
        assert!(!debug.contains("private source sentinel"));
        assert!(debug.contains("[redacted]"));
    }
}
