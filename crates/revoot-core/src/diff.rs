//! Bounded, deterministic parsing of one GitLab unified file diff.
//!
//! Input is an explicit byte slice. Only valid UTF-8 with LF or CRLF records is
//! accepted; no lossy decoding, Git invocation, path discovery, or recovery is performed.

use std::fmt;
use std::str;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::snapshot::{
    AnchorPosition, ChangedPath, ChangedPathIssue, CommentableLine, FileChangeKind, Sha256Digest,
};

const NO_NEWLINE_MARKER: &str = "\\ No newline at end of file";

/// Resource limits applied before or during parsing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnifiedDiffLimits {
    pub max_input_bytes: usize,
    pub max_input_lines: u32,
    pub max_line_bytes: usize,
    pub max_hunks: u32,
    pub max_lines_per_hunk: u32,
    pub max_commentable_lines: u32,
    pub context_radius_lines: u32,
}

impl Default for UnifiedDiffLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 2 * 1024 * 1024,
            max_input_lines: 100_000,
            max_line_bytes: 64 * 1024,
            max_hunks: 4_096,
            max_lines_per_hunk: 50_000,
            max_commentable_lines: 100_000,
            context_radius_lines: 3,
        }
    }
}

impl UnifiedDiffLimits {
    const fn valid(self) -> bool {
        self.max_input_bytes > 0
            && self.max_input_lines > 0
            && self.max_line_bytes > 0
            && self.max_hunks > 0
            && self.max_lines_per_hunk > 0
            && self.max_commentable_lines > 0
            && self.context_radius_lines <= self.max_lines_per_hunk
    }
}

/// Which hunk range failed accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffSide {
    Old,
    New,
}

/// A closed failure taxonomy for untrusted diff bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnifiedDiffError {
    InvalidLimits,
    InvalidChangedPath(ChangedPathIssue),
    EmptyInput,
    InputTooLarge {
        observed: usize,
        maximum: usize,
    },
    TooManyInputLines {
        observed: u32,
        maximum: u32,
    },
    LineTooLong {
        line: u32,
        observed: usize,
        maximum: usize,
    },
    InvalidUtf8 {
        valid_up_to: usize,
    },
    MissingFinalLineFeed,
    EmbeddedCarriageReturn {
        line: u32,
    },
    CombinedDiff {
        line: u32,
    },
    BinaryDiff {
        line: u32,
    },
    UnexpectedPrelude {
        line: u32,
    },
    DuplicateFileHeader {
        line: u32,
    },
    IncompleteFileHeader {
        line: u32,
    },
    FileHeaderMismatch {
        line: u32,
        side: DiffSide,
    },
    NoHunks,
    TooManyHunks {
        maximum: u32,
    },
    MalformedHunkHeader {
        line: u32,
    },
    NumericOverflow {
        line: u32,
    },
    InvalidRangeStart {
        line: u32,
        side: DiffSide,
    },
    EmptyHunk {
        line: u32,
    },
    DeclaredHunkTooLarge {
        line: u32,
        side: DiffSide,
        declared: u32,
        maximum: u32,
    },
    TooManyLinesInHunk {
        hunk_header_line: u32,
        maximum: u32,
    },
    TooManyCommentableLines {
        maximum: u32,
    },
    UnexpectedHunkLine {
        line: u32,
    },
    NoNewlineMarkerWithoutContent {
        line: u32,
    },
    DuplicateNoNewlineMarker {
        line: u32,
    },
    HunkCountExceeded {
        line: u32,
        side: DiffSide,
    },
    HunkCountMismatch {
        hunk_header_line: u32,
        expected_old: u32,
        observed_old: u32,
        expected_new: u32,
        observed_new: u32,
    },
    LineNumberOverflow {
        line: u32,
        side: DiffSide,
    },
    FileChangeLineMismatch {
        line: u32,
    },
    UnexpectedTrailingContent {
        line: u32,
    },
}

impl fmt::Display for UnifiedDiffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unified diff rejected: {self:?}")
    }
}

/// Successful, fully accounted parser output for one file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedFileDiff {
    pub input_sha256: Sha256Digest,
    pub hunk_count: u32,
    pub commentable_lines: Vec<CommentableLine>,
}

/// Parse one complete GitLab per-file diff into trusted commentable lines.
///
/// GitLab hunk-only input and a full unified prelude with one matching `---`/`+++`
/// pair are accepted. Every hunk count must be consumed exactly. Context digests use
/// at most `context_radius_lines` preceding and following records from the same hunk.
///
/// # Errors
///
/// Returns a closed [`UnifiedDiffError`] for invalid encoding, syntax, path/header
/// mismatch, incomplete accounting, unsupported binary/combined input, or any limit.
pub fn parse_gitlab_file_diff(
    path: &ChangedPath,
    input: &[u8],
    limits: UnifiedDiffLimits,
) -> Result<ParsedFileDiff, UnifiedDiffError> {
    if !limits.valid() {
        return Err(UnifiedDiffError::InvalidLimits);
    }
    if let Some(issue) = path.semantic_issue() {
        return Err(UnifiedDiffError::InvalidChangedPath(issue));
    }
    let lines = validated_lines(input, limits)?;
    let mut parser = Parser {
        path,
        lines,
        limits,
        cursor: 0,
        hunk_count: 0,
        commentable_lines: Vec::new(),
    };
    parser.parse_prelude()?;
    parser.parse_hunks()?;
    Ok(ParsedFileDiff {
        input_sha256: Sha256Digest::of_bytes(input),
        hunk_count: parser.hunk_count,
        commentable_lines: parser.commentable_lines,
    })
}

fn validated_lines(input: &[u8], limits: UnifiedDiffLimits) -> Result<Vec<&str>, UnifiedDiffError> {
    if input.is_empty() {
        return Err(UnifiedDiffError::EmptyInput);
    }
    if input.len() > limits.max_input_bytes {
        return Err(UnifiedDiffError::InputTooLarge {
            observed: input.len(),
            maximum: limits.max_input_bytes,
        });
    }
    let text = str::from_utf8(input).map_err(|error| UnifiedDiffError::InvalidUtf8 {
        valid_up_to: error.valid_up_to(),
    })?;
    if !text.ends_with('\n') {
        return Err(UnifiedDiffError::MissingFinalLineFeed);
    }

    let mut lines = Vec::new();
    for raw in text[..text.len() - 1].split('\n') {
        let line_number = u32::try_from(lines.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        if line_number > limits.max_input_lines {
            return Err(UnifiedDiffError::TooManyInputLines {
                observed: line_number,
                maximum: limits.max_input_lines,
            });
        }
        if raw.len() > limits.max_line_bytes {
            return Err(UnifiedDiffError::LineTooLong {
                line: line_number,
                observed: raw.len(),
                maximum: limits.max_line_bytes,
            });
        }
        let normalized = raw.strip_suffix('\r').unwrap_or(raw);
        if normalized.contains('\r') {
            return Err(UnifiedDiffError::EmbeddedCarriageReturn { line: line_number });
        }
        lines.push(normalized);
    }
    Ok(lines)
}

struct Parser<'a> {
    path: &'a ChangedPath,
    lines: Vec<&'a str>,
    limits: UnifiedDiffLimits,
    cursor: usize,
    hunk_count: u32,
    commentable_lines: Vec<CommentableLine>,
}

impl<'a> Parser<'a> {
    fn parse_prelude(&mut self) -> Result<(), UnifiedDiffError> {
        let mut saw_diff_header = false;
        let mut saw_old_header = false;
        let mut saw_new_header = false;

        while let Some(line) = self.current_line() {
            let line_number = self.line_number();
            reject_unsupported(line, line_number)?;
            if is_hunk_header(line) {
                if saw_old_header != saw_new_header || (saw_diff_header && !saw_new_header) {
                    return Err(UnifiedDiffError::IncompleteFileHeader { line: line_number });
                }
                return Ok(());
            }
            if let Some(header_path) = line.strip_prefix("--- ") {
                if saw_old_header || saw_new_header {
                    return Err(UnifiedDiffError::DuplicateFileHeader { line: line_number });
                }
                if header_path != self.expected_old_header() {
                    return Err(UnifiedDiffError::FileHeaderMismatch {
                        line: line_number,
                        side: DiffSide::Old,
                    });
                }
                saw_old_header = true;
            } else if let Some(header_path) = line.strip_prefix("+++ ") {
                if !saw_old_header || saw_new_header {
                    return Err(UnifiedDiffError::DuplicateFileHeader { line: line_number });
                }
                if header_path != self.expected_new_header() {
                    return Err(UnifiedDiffError::FileHeaderMismatch {
                        line: line_number,
                        side: DiffSide::New,
                    });
                }
                saw_new_header = true;
            } else if line.starts_with("diff --git ") {
                if saw_diff_header || saw_old_header || saw_new_header {
                    return Err(UnifiedDiffError::UnexpectedPrelude { line: line_number });
                }
                saw_diff_header = true;
            } else if is_metadata_line(line) && !saw_old_header {
                // Structured ChangedPath and the validated ---/+++ pair are authoritative.
            } else {
                return Err(UnifiedDiffError::UnexpectedPrelude { line: line_number });
            }
            self.cursor += 1;
        }

        if saw_old_header != saw_new_header || (saw_diff_header && !saw_new_header) {
            Err(UnifiedDiffError::IncompleteFileHeader {
                line: self.line_number(),
            })
        } else {
            Err(UnifiedDiffError::NoHunks)
        }
    }

    fn parse_hunks(&mut self) -> Result<(), UnifiedDiffError> {
        while self.cursor < self.lines.len() {
            let line_number = self.line_number();
            let line = self.current_line().expect("cursor was bounds checked");
            reject_unsupported(line, line_number)?;
            if !is_hunk_header(line) {
                return Err(UnifiedDiffError::UnexpectedTrailingContent { line: line_number });
            }
            if self.hunk_count == self.limits.max_hunks {
                return Err(UnifiedDiffError::TooManyHunks {
                    maximum: self.limits.max_hunks,
                });
            }
            let header = parse_hunk_header(line, line_number, self.limits)?;
            self.cursor += 1;
            let records = self.parse_hunk(header)?;
            self.append_commentable_lines(&records)?;
            self.hunk_count += 1;
        }

        if self.hunk_count == 0 {
            Err(UnifiedDiffError::NoHunks)
        } else {
            Ok(())
        }
    }

    fn parse_hunk(&mut self, header: HunkHeader) -> Result<Vec<HunkLine<'a>>, UnifiedDiffError> {
        let mut accounting = HunkAccounting::new(header);
        let mut records = Vec::new();
        let mut marker_state = MarkerState::None;

        while !accounting.complete() {
            let Some(line) = self.current_line() else {
                return Err(accounting.mismatch());
            };
            let line_number = self.line_number();
            reject_unsupported(line, line_number)?;
            if is_hunk_header(line) {
                return Err(accounting.mismatch());
            }
            if line == NO_NEWLINE_MARKER {
                apply_no_newline_marker(&mut records, &mut marker_state, line_number)?;
                self.cursor += 1;
                continue;
            }
            let record = accounting.consume(self.path, line, line_number)?;
            records.push(record);
            marker_state = MarkerState::Content;
            self.cursor += 1;
            if u32::try_from(records.len()).unwrap_or(u32::MAX) > self.limits.max_lines_per_hunk {
                return Err(UnifiedDiffError::TooManyLinesInHunk {
                    hunk_header_line: header.line,
                    maximum: self.limits.max_lines_per_hunk,
                });
            }
        }

        if self.current_line() == Some(NO_NEWLINE_MARKER) {
            apply_no_newline_marker(&mut records, &mut marker_state, self.line_number())?;
            self.cursor += 1;
        }
        if self.current_line() == Some(NO_NEWLINE_MARKER) {
            return Err(UnifiedDiffError::DuplicateNoNewlineMarker {
                line: self.line_number(),
            });
        }
        Ok(records)
    }

    fn append_commentable_lines(
        &mut self,
        records: &[HunkLine<'_>],
    ) -> Result<(), UnifiedDiffError> {
        let prospective = self
            .commentable_lines
            .len()
            .checked_add(records.len())
            .and_then(|count| u32::try_from(count).ok())
            .ok_or(UnifiedDiffError::TooManyCommentableLines {
                maximum: self.limits.max_commentable_lines,
            })?;
        if prospective > self.limits.max_commentable_lines {
            return Err(UnifiedDiffError::TooManyCommentableLines {
                maximum: self.limits.max_commentable_lines,
            });
        }

        let radius = usize::try_from(self.limits.context_radius_lines).unwrap_or(usize::MAX);
        self.commentable_lines
            .extend(
                records
                    .iter()
                    .enumerate()
                    .map(|(index, record)| CommentableLine {
                        path: self.path.clone(),
                        position: record.position,
                        exact_line_digest: exact_line_digest(record),
                        context_digest: context_digest(records, index, radius),
                    }),
            );
        Ok(())
    }

    fn expected_old_header(&self) -> String {
        if self.path.kind == FileChangeKind::Added {
            "/dev/null".to_owned()
        } else {
            format!("a/{}", self.path.old_path.as_str())
        }
    }

    fn expected_new_header(&self) -> String {
        if self.path.kind == FileChangeKind::Deleted {
            "/dev/null".to_owned()
        } else {
            format!("b/{}", self.path.new_path.as_str())
        }
    }

    fn current_line(&self) -> Option<&'a str> {
        self.lines.get(self.cursor).copied()
    }

    fn line_number(&self) -> u32 {
        u32::try_from(self.cursor)
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }
}

fn is_hunk_header(line: &str) -> bool {
    line.starts_with("@@ ") || line.starts_with("@@-")
}

fn is_metadata_line(line: &str) -> bool {
    [
        "index ",
        "old mode ",
        "new mode ",
        "deleted file mode ",
        "new file mode ",
        "similarity index ",
        "dissimilarity index ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

fn reject_unsupported(line: &str, line_number: u32) -> Result<(), UnifiedDiffError> {
    if line.starts_with("diff --cc ")
        || line.starts_with("diff --combined ")
        || line.starts_with("@@@")
    {
        return Err(UnifiedDiffError::CombinedDiff { line: line_number });
    }
    if line == "GIT binary patch"
        || (line.starts_with("Binary files ") && line.ends_with(" differ"))
    {
        return Err(UnifiedDiffError::BinaryDiff { line: line_number });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct HunkRange {
    start: u32,
    count: u32,
}

#[derive(Clone, Copy)]
struct HunkHeader {
    line: u32,
    old: HunkRange,
    new: HunkRange,
}

fn parse_hunk_header(
    value: &str,
    line: u32,
    limits: UnifiedDiffLimits,
) -> Result<HunkHeader, UnifiedDiffError> {
    if value.starts_with("@@@") {
        return Err(UnifiedDiffError::CombinedDiff { line });
    }
    let Some(value) = value.strip_prefix("@@ -") else {
        return Err(UnifiedDiffError::MalformedHunkHeader { line });
    };
    let Some((ranges, section)) = value.split_once(" @@") else {
        return Err(UnifiedDiffError::MalformedHunkHeader { line });
    };
    if !section.is_empty() && !section.starts_with(' ') {
        return Err(UnifiedDiffError::MalformedHunkHeader { line });
    }
    let Some((old, new)) = ranges.split_once(" +") else {
        return Err(UnifiedDiffError::MalformedHunkHeader { line });
    };
    let old = parse_hunk_range(old, line, DiffSide::Old)?;
    let new = parse_hunk_range(new, line, DiffSide::New)?;
    if old.count == 0 && new.count == 0 {
        return Err(UnifiedDiffError::EmptyHunk { line });
    }
    for (side, range) in [(DiffSide::Old, old), (DiffSide::New, new)] {
        if range.count > limits.max_lines_per_hunk {
            return Err(UnifiedDiffError::DeclaredHunkTooLarge {
                line,
                side,
                declared: range.count,
                maximum: limits.max_lines_per_hunk,
            });
        }
    }
    Ok(HunkHeader { line, old, new })
}

fn parse_hunk_range(value: &str, line: u32, side: DiffSide) -> Result<HunkRange, UnifiedDiffError> {
    let (start, count) = match value.split_once(',') {
        Some((start, count)) if !count.contains(',') => {
            (parse_decimal(start, line)?, parse_decimal(count, line)?)
        }
        Some(_) => return Err(UnifiedDiffError::MalformedHunkHeader { line }),
        None => (parse_decimal(value, line)?, 1),
    };
    if count > 0 && start == 0 {
        return Err(UnifiedDiffError::InvalidRangeStart { line, side });
    }
    if count > 0 && start.checked_add(count - 1).is_none() {
        return Err(UnifiedDiffError::NumericOverflow { line });
    }
    Ok(HunkRange { start, count })
}

fn parse_decimal(value: &str, line: u32) -> Result<u32, UnifiedDiffError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(UnifiedDiffError::MalformedHunkHeader { line });
    }
    value
        .parse::<u32>()
        .map_err(|_| UnifiedDiffError::NumericOverflow { line })
}

#[derive(Clone, Copy)]
enum HunkLineKind {
    Context,
    Deletion,
    Addition,
}

struct HunkLine<'a> {
    kind: HunkLineKind,
    position: AnchorPosition,
    content: &'a str,
    no_newline: bool,
}

struct HunkAccounting {
    header: HunkHeader,
    old_seen: u32,
    new_seen: u32,
    old_line: u32,
    new_line: u32,
}

impl HunkAccounting {
    const fn new(header: HunkHeader) -> Self {
        Self {
            header,
            old_seen: 0,
            new_seen: 0,
            old_line: header.old.start,
            new_line: header.new.start,
        }
    }

    const fn complete(&self) -> bool {
        self.old_seen == self.header.old.count && self.new_seen == self.header.new.count
    }

    fn consume<'a>(
        &mut self,
        path: &ChangedPath,
        line: &'a str,
        line_number: u32,
    ) -> Result<HunkLine<'a>, UnifiedDiffError> {
        let Some(prefix) = line.as_bytes().first().copied() else {
            return Err(UnifiedDiffError::UnexpectedHunkLine { line: line_number });
        };
        let content = &line[1..];
        let (kind, position) = match prefix {
            b' ' => {
                validate_line_kind(path.kind, HunkLineKind::Context, line_number)?;
                self.require_remaining(DiffSide::Old, line_number)?;
                self.require_remaining(DiffSide::New, line_number)?;
                let position =
                    AnchorPosition::context(self.old_line, self.new_line).map_err(|_| {
                        UnifiedDiffError::InvalidRangeStart {
                            line: line_number,
                            side: if self.old_line == 0 {
                                DiffSide::Old
                            } else {
                                DiffSide::New
                            },
                        }
                    })?;
                self.consume_old(line_number)?;
                self.consume_new(line_number)?;
                (HunkLineKind::Context, position)
            }
            b'-' => {
                validate_line_kind(path.kind, HunkLineKind::Deletion, line_number)?;
                self.require_remaining(DiffSide::Old, line_number)?;
                let position = AnchorPosition::deletion(self.old_line).map_err(|_| {
                    UnifiedDiffError::InvalidRangeStart {
                        line: line_number,
                        side: DiffSide::Old,
                    }
                })?;
                self.consume_old(line_number)?;
                (HunkLineKind::Deletion, position)
            }
            b'+' => {
                validate_line_kind(path.kind, HunkLineKind::Addition, line_number)?;
                self.require_remaining(DiffSide::New, line_number)?;
                let position = AnchorPosition::addition(self.new_line).map_err(|_| {
                    UnifiedDiffError::InvalidRangeStart {
                        line: line_number,
                        side: DiffSide::New,
                    }
                })?;
                self.consume_new(line_number)?;
                (HunkLineKind::Addition, position)
            }
            _ => return Err(UnifiedDiffError::UnexpectedHunkLine { line: line_number }),
        };
        Ok(HunkLine {
            kind,
            position,
            content,
            no_newline: false,
        })
    }

    const fn require_remaining(&self, side: DiffSide, line: u32) -> Result<(), UnifiedDiffError> {
        let exceeded = match side {
            DiffSide::Old => self.old_seen >= self.header.old.count,
            DiffSide::New => self.new_seen >= self.header.new.count,
        };
        if exceeded {
            Err(UnifiedDiffError::HunkCountExceeded { line, side })
        } else {
            Ok(())
        }
    }

    fn consume_old(&mut self, line: u32) -> Result<(), UnifiedDiffError> {
        self.old_seen += 1;
        if self.old_seen < self.header.old.count {
            self.old_line =
                self.old_line
                    .checked_add(1)
                    .ok_or(UnifiedDiffError::LineNumberOverflow {
                        line,
                        side: DiffSide::Old,
                    })?;
        }
        Ok(())
    }

    fn consume_new(&mut self, line: u32) -> Result<(), UnifiedDiffError> {
        self.new_seen += 1;
        if self.new_seen < self.header.new.count {
            self.new_line =
                self.new_line
                    .checked_add(1)
                    .ok_or(UnifiedDiffError::LineNumberOverflow {
                        line,
                        side: DiffSide::New,
                    })?;
        }
        Ok(())
    }

    fn mismatch(&self) -> UnifiedDiffError {
        UnifiedDiffError::HunkCountMismatch {
            hunk_header_line: self.header.line,
            expected_old: self.header.old.count,
            observed_old: self.old_seen,
            expected_new: self.header.new.count,
            observed_new: self.new_seen,
        }
    }
}

fn validate_line_kind(
    file_kind: FileChangeKind,
    line_kind: HunkLineKind,
    line: u32,
) -> Result<(), UnifiedDiffError> {
    let valid = match (file_kind, line_kind) {
        (FileChangeKind::Added, HunkLineKind::Addition)
        | (FileChangeKind::Deleted, HunkLineKind::Deletion)
        | (FileChangeKind::Modified | FileChangeKind::Renamed, _) => true,
        (FileChangeKind::Added, HunkLineKind::Context | HunkLineKind::Deletion)
        | (FileChangeKind::Deleted, HunkLineKind::Context | HunkLineKind::Addition) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(UnifiedDiffError::FileChangeLineMismatch { line })
    }
}

#[derive(Clone, Copy)]
enum MarkerState {
    None,
    Content,
    Marker,
}

fn apply_no_newline_marker(
    records: &mut [HunkLine<'_>],
    state: &mut MarkerState,
    line: u32,
) -> Result<(), UnifiedDiffError> {
    match state {
        MarkerState::None => Err(UnifiedDiffError::NoNewlineMarkerWithoutContent { line }),
        MarkerState::Marker => Err(UnifiedDiffError::DuplicateNoNewlineMarker { line }),
        MarkerState::Content => {
            let Some(last) = records.last_mut() else {
                return Err(UnifiedDiffError::NoNewlineMarkerWithoutContent { line });
            };
            last.no_newline = true;
            *state = MarkerState::Marker;
            Ok(())
        }
    }
}

fn exact_line_digest(record: &HunkLine<'_>) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"revoot-diff-line-v1");
    hash_line(&mut hasher, record);
    Sha256Digest::try_from(format!("{:x}", hasher.finalize()))
        .expect("SHA-256 formatter always returns lowercase 64-character hex")
}

fn context_digest(records: &[HunkLine<'_>], anchor: usize, radius: usize) -> Sha256Digest {
    let start = anchor.saturating_sub(radius);
    let end = anchor
        .saturating_add(radius)
        .saturating_add(1)
        .min(records.len());
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"revoot-diff-context-v1");
    hash_field(
        &mut hasher,
        &u64::try_from(radius).unwrap_or(u64::MAX).to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        &u64::try_from(anchor - start)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        &u64::try_from(end - start).unwrap_or(u64::MAX).to_be_bytes(),
    );
    for record in &records[start..end] {
        hash_line(&mut hasher, record);
    }
    Sha256Digest::try_from(format!("{:x}", hasher.finalize()))
        .expect("SHA-256 formatter always returns lowercase 64-character hex")
}

fn hash_line(hasher: &mut Sha256, record: &HunkLine<'_>) {
    let kind = match record.kind {
        HunkLineKind::Context => b"context".as_slice(),
        HunkLineKind::Deletion => b"deletion".as_slice(),
        HunkLineKind::Addition => b"addition".as_slice(),
    };
    hash_field(hasher, kind);
    match record.position {
        AnchorPosition::Addition { new_line } => {
            hash_field(hasher, b"none");
            hash_field(hasher, &new_line.to_be_bytes());
        }
        AnchorPosition::Deletion { old_line } => {
            hash_field(hasher, &old_line.to_be_bytes());
            hash_field(hasher, b"none");
        }
        AnchorPosition::Context { old_line, new_line } => {
            hash_field(hasher, &old_line.to_be_bytes());
            hash_field(hasher, &new_line.to_be_bytes());
        }
    }
    hash_field(hasher, &[u8::from(record.no_newline)]);
    hash_field(hasher, record.content.as_bytes());
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::RepositoryPath;

    const GOLDEN_DIFF: &[u8] = b"@@ -10,3 +20,4 @@ fn demo\n same\n-old\n+new\n+extra\n tail\n";

    fn path(kind: FileChangeKind, old: &str, new: &str) -> ChangedPath {
        ChangedPath {
            old_path: RepositoryPath::try_from(old.to_owned()).unwrap(),
            new_path: RepositoryPath::try_from(new.to_owned()).unwrap(),
            kind,
        }
    }

    fn modified() -> ChangedPath {
        path(FileChangeKind::Modified, "src/lib.rs", "src/lib.rs")
    }

    fn parse(input: &[u8]) -> Result<ParsedFileDiff, UnifiedDiffError> {
        parse_gitlab_file_diff(&modified(), input, UnifiedDiffLimits::default())
    }

    #[test]
    fn golden_mixed_hunk_has_exact_positions_and_stable_digests() {
        let parsed = parse(GOLDEN_DIFF).unwrap();
        assert_eq!(parsed.hunk_count, 1);
        assert_eq!(parsed.input_sha256, Sha256Digest::of_bytes(GOLDEN_DIFF));
        assert_eq!(
            parsed
                .commentable_lines
                .iter()
                .map(|line| line.position)
                .collect::<Vec<_>>(),
            vec![
                AnchorPosition::Context {
                    old_line: 10,
                    new_line: 20,
                },
                AnchorPosition::Deletion { old_line: 11 },
                AnchorPosition::Addition { new_line: 21 },
                AnchorPosition::Addition { new_line: 22 },
                AnchorPosition::Context {
                    old_line: 12,
                    new_line: 23,
                },
            ]
        );
        let exact = parsed
            .commentable_lines
            .iter()
            .map(|line| line.exact_line_digest.as_str())
            .collect::<Vec<_>>();
        let context = parsed
            .commentable_lines
            .iter()
            .map(|line| line.context_digest.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            exact,
            vec![
                "97eba54c0f4b45da21bb185ab5a9761d006edeba4cb0de9fedbd76ef1d1311fd",
                "c523819a2cb1137ea33e93c1456bcd6f7ef0becb9a93063f283a217605bad21c",
                "03377250e15dab3ae73e7f697ed8f62602bff3435da8390433410e0af0a04b2d",
                "42f0472febb3898d26d3eb36f0a0b957b3e264ec8856dee6103f95056ec5255b",
                "0932e9d5318836f76cfda88a9d035af5c9c7f493890b6d7f325d0344cb6c7e86",
            ]
        );
        assert_eq!(
            context,
            vec![
                "2ee96bb929bcbbb4dd5f0f31db719b9b3128db7a457df34ae06f2a27cdc505c1",
                "f946073c00266548862e062ba585f9571fdf1c39d70c6a16c8468df486f98756",
                "2b7e234052af9d778a36a98959c245de7b6f7648cfac6f7495a6ebdec4883f93",
                "fe05565deb38a152e7ffabbfb1a992e0975f23c44314f2689964e3c5a708c6df",
                "d4ea3d56a28d3d87d8f727035f86687b40a5a59165585b494f7b521bb873e471",
            ]
        );
    }

    #[test]
    fn parses_matching_rename_prelude_and_diff_prefix_content() {
        let changed = path(FileChangeKind::Renamed, "old name.rs", "new name.rs");
        let input = b"diff --git ignored provider display names\nsimilarity index 80%\nrename from old name.rs\nrename to new name.rs\n--- a/old name.rs\n+++ b/new name.rs\n@@ -1,2 +1,2 @@\n--- literal deletion\n\\ No newline at end of file\n+++ literal addition\n\\ No newline at end of file\n keep\n";
        let parsed = parse_gitlab_file_diff(&changed, input, UnifiedDiffLimits::default()).unwrap();
        assert_eq!(parsed.hunk_count, 1);
        assert_eq!(parsed.commentable_lines.len(), 3);
        assert_eq!(
            parsed.commentable_lines[0].position,
            AnchorPosition::Deletion { old_line: 1 }
        );
        assert_eq!(
            parsed.commentable_lines[1].position,
            AnchorPosition::Addition { new_line: 1 }
        );
        assert_eq!(
            parsed.commentable_lines[2].position,
            AnchorPosition::Context {
                old_line: 2,
                new_line: 2,
            }
        );
    }

    #[test]
    fn accepts_added_and_deleted_zero_ranges() {
        let added = path(FileChangeKind::Added, "new.rs", "new.rs");
        let added_diff = b"diff --git a/new.rs b/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/new.rs\n@@ -0,0 +1,2 @@\n+one\n+two\n";
        let parsed =
            parse_gitlab_file_diff(&added, added_diff, UnifiedDiffLimits::default()).unwrap();
        assert_eq!(
            parsed
                .commentable_lines
                .iter()
                .map(|line| line.position)
                .collect::<Vec<_>>(),
            vec![
                AnchorPosition::Addition { new_line: 1 },
                AnchorPosition::Addition { new_line: 2 },
            ]
        );

        let deleted = path(FileChangeKind::Deleted, "old.rs", "old.rs");
        let deleted_diff =
            b"deleted file mode 100644\n--- a/old.rs\n+++ /dev/null\n@@ -4,2 +0,0 @@\n-one\n-two\n";
        let parsed =
            parse_gitlab_file_diff(&deleted, deleted_diff, UnifiedDiffLimits::default()).unwrap();
        assert_eq!(
            parsed
                .commentable_lines
                .iter()
                .map(|line| line.position)
                .collect::<Vec<_>>(),
            vec![
                AnchorPosition::Deletion { old_line: 4 },
                AnchorPosition::Deletion { old_line: 5 },
            ]
        );
    }

    #[test]
    fn crlf_changes_input_identity_but_not_semantic_digests() {
        let lf = parse(b"@@ -1 +1 @@\n-old\n+new\n").unwrap();
        let crlf = parse(b"@@ -1 +1 @@\r\n-old\r\n+new\r\n").unwrap();
        assert_ne!(lf.input_sha256, crlf.input_sha256);
        assert_eq!(lf.commentable_lines, crlf.commentable_lines);
    }

    #[test]
    fn no_newline_marker_is_semantic_and_strictly_placed() {
        let marked = parse(b"@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n").unwrap();
        let ordinary = parse(b"@@ -1 +1 @@\n-old\n+new\n").unwrap();
        assert_ne!(
            marked.commentable_lines[1].exact_line_digest,
            ordinary.commentable_lines[1].exact_line_digest
        );
        assert_eq!(
            parse(b"@@ -1 +1 @@\n\\ No newline at end of file\n-old\n+new\n"),
            Err(UnifiedDiffError::NoNewlineMarkerWithoutContent { line: 2 })
        );
        assert_eq!(
            parse(b"@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n\\ No newline at end of file\n"),
            Err(UnifiedDiffError::DuplicateNoNewlineMarker { line: 5 })
        );
    }

    #[test]
    fn rejects_encoding_and_record_ambiguity() {
        assert_eq!(
            parse(&[0xff, b'\n']),
            Err(UnifiedDiffError::InvalidUtf8 { valid_up_to: 0 })
        );
        assert_eq!(
            parse(b"@@ -1 +1 @@\n-old\n+new"),
            Err(UnifiedDiffError::MissingFinalLineFeed)
        );
        assert_eq!(
            parse(b"@@ -1 +1 @@\n-old\rcontent\n+new\n"),
            Err(UnifiedDiffError::EmbeddedCarriageReturn { line: 2 })
        );
        assert_eq!(
            parse(b"@@ -1 +1 @@\n-old\n+new\n\n"),
            Err(UnifiedDiffError::UnexpectedTrailingContent { line: 4 })
        );
    }

    #[test]
    fn rejects_combined_binary_and_mismatched_headers() {
        assert_eq!(
            parse(b"@@@ -1,1 -1,1 +1,1 @@@\n line\n"),
            Err(UnifiedDiffError::CombinedDiff { line: 1 })
        );
        assert_eq!(
            parse(b"GIT binary patch\n"),
            Err(UnifiedDiffError::BinaryDiff { line: 1 })
        );
        assert_eq!(
            parse(b"--- a/other.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n"),
            Err(UnifiedDiffError::FileHeaderMismatch {
                line: 1,
                side: DiffSide::Old,
            })
        );
        assert_eq!(
            parse(b"diff --git a/src/lib.rs b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n"),
            Err(UnifiedDiffError::IncompleteFileHeader { line: 2 })
        );
    }

    #[test]
    fn rejects_malformed_zero_overflow_and_empty_ranges() {
        for input in [
            b"@@ -01 +1 @@\n-old\n+new\n".as_slice(),
            b"@@ -1, +1 @@\n-old\n+new\n".as_slice(),
            b"@@ -1 +1 @@garbage\n-old\n+new\n".as_slice(),
        ] {
            assert_eq!(
                parse(input),
                Err(UnifiedDiffError::MalformedHunkHeader { line: 1 })
            );
        }
        assert_eq!(
            parse(b"@@ -0 +1 @@\n-old\n+new\n"),
            Err(UnifiedDiffError::InvalidRangeStart {
                line: 1,
                side: DiffSide::Old,
            })
        );
        assert_eq!(
            parse(b"@@ -0,0 +0,0 @@\n"),
            Err(UnifiedDiffError::EmptyHunk { line: 1 })
        );
        assert_eq!(
            parse(b"@@ -4294967295,2 +1 @@\n"),
            Err(UnifiedDiffError::NumericOverflow { line: 1 })
        );
    }

    #[test]
    fn rejects_truncated_exceeded_and_mismatched_hunks() {
        assert_eq!(
            parse(b"@@ -1,2 +1,2 @@\n same\n"),
            Err(UnifiedDiffError::HunkCountMismatch {
                hunk_header_line: 1,
                expected_old: 2,
                observed_old: 1,
                expected_new: 2,
                observed_new: 1,
            })
        );
        assert_eq!(
            parse(b"@@ -1,1 +1,2 @@\n same\n another\n"),
            Err(UnifiedDiffError::HunkCountExceeded {
                line: 3,
                side: DiffSide::Old,
            })
        );
        assert_eq!(
            parse(b"@@ -1,2 +1,2 @@\n same\n@@ -4 +4 @@\n next\n"),
            Err(UnifiedDiffError::HunkCountMismatch {
                hunk_header_line: 1,
                expected_old: 2,
                observed_old: 1,
                expected_new: 2,
                observed_new: 1,
            })
        );
    }

    #[test]
    fn rejects_lines_incompatible_with_file_kind() {
        let added = path(FileChangeKind::Added, "new.rs", "new.rs");
        assert_eq!(
            parse_gitlab_file_diff(
                &added,
                b"@@ -1 +1 @@\n-old\n+new\n",
                UnifiedDiffLimits::default(),
            ),
            Err(UnifiedDiffError::FileChangeLineMismatch { line: 2 })
        );
    }

    #[test]
    fn enforces_resource_limits() {
        let limits = UnifiedDiffLimits {
            max_input_bytes: GOLDEN_DIFF.len() - 1,
            ..UnifiedDiffLimits::default()
        };
        assert_eq!(
            parse_gitlab_file_diff(&modified(), GOLDEN_DIFF, limits),
            Err(UnifiedDiffError::InputTooLarge {
                observed: GOLDEN_DIFF.len(),
                maximum: GOLDEN_DIFF.len() - 1,
            })
        );

        let limits = UnifiedDiffLimits {
            max_hunks: 1,
            ..UnifiedDiffLimits::default()
        };
        assert_eq!(
            parse_gitlab_file_diff(
                &modified(),
                b"@@ -1 +1 @@\n same\n@@ -3 +3 @@\n same\n",
                limits,
            ),
            Err(UnifiedDiffError::TooManyHunks { maximum: 1 })
        );

        let limits = UnifiedDiffLimits {
            max_input_lines: 2,
            ..UnifiedDiffLimits::default()
        };
        assert_eq!(
            parse_gitlab_file_diff(&modified(), b"@@ -1 +1 @@\n-old\n+new\n", limits,),
            Err(UnifiedDiffError::TooManyInputLines {
                observed: 3,
                maximum: 2,
            })
        );

        let limits = UnifiedDiffLimits {
            max_line_bytes: 5,
            ..UnifiedDiffLimits::default()
        };
        assert_eq!(
            parse_gitlab_file_diff(&modified(), b"@@ -1 +1 @@\n-old\n+new\n", limits),
            Err(UnifiedDiffError::LineTooLong {
                line: 1,
                observed: 11,
                maximum: 5,
            })
        );

        let limits = UnifiedDiffLimits {
            max_lines_per_hunk: 2,
            context_radius_lines: 2,
            ..UnifiedDiffLimits::default()
        };
        assert_eq!(
            parse_gitlab_file_diff(&modified(), GOLDEN_DIFF, limits),
            Err(UnifiedDiffError::DeclaredHunkTooLarge {
                line: 1,
                side: DiffSide::Old,
                declared: 3,
                maximum: 2,
            })
        );

        let limits = UnifiedDiffLimits {
            max_lines_per_hunk: 2,
            context_radius_lines: 2,
            ..UnifiedDiffLimits::default()
        };
        assert_eq!(
            parse_gitlab_file_diff(
                &modified(),
                b"@@ -1,2 +1,2 @@\n-old one\n-old two\n+new one\n+new two\n",
                limits,
            ),
            Err(UnifiedDiffError::TooManyLinesInHunk {
                hunk_header_line: 1,
                maximum: 2,
            })
        );

        let limits = UnifiedDiffLimits {
            max_commentable_lines: 1,
            ..UnifiedDiffLimits::default()
        };
        assert_eq!(
            parse_gitlab_file_diff(&modified(), b"@@ -1 +1 @@\n-old\n+new\n", limits,),
            Err(UnifiedDiffError::TooManyCommentableLines { maximum: 1 })
        );

        assert_eq!(
            parse_gitlab_file_diff(
                &modified(),
                b"@@ -1 +1 @@\n-old\n+new\n",
                UnifiedDiffLimits {
                    max_lines_per_hunk: 1,
                    context_radius_lines: 2,
                    ..UnifiedDiffLimits::default()
                },
            ),
            Err(UnifiedDiffError::InvalidLimits)
        );
    }

    #[test]
    fn context_is_hunk_local_bounded_and_deterministic() {
        let input = b"@@ -1,2 +1,2 @@\n same\n-old\n+new\n@@ -10 +10 @@\n same\n";
        let limits = UnifiedDiffLimits {
            context_radius_lines: 1,
            ..UnifiedDiffLimits::default()
        };
        let first = parse_gitlab_file_diff(&modified(), input, limits).unwrap();
        let second = parse_gitlab_file_diff(&modified(), input, limits).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.hunk_count, 2);
        assert_ne!(
            first.commentable_lines[0].context_digest,
            first.commentable_lines[3].context_digest
        );

        let zero_radius = parse_gitlab_file_diff(
            &modified(),
            input,
            UnifiedDiffLimits {
                context_radius_lines: 0,
                ..UnifiedDiffLimits::default()
            },
        )
        .unwrap();
        assert_ne!(
            first.commentable_lines[0].context_digest,
            zero_radius.commentable_lines[0].context_digest
        );
    }

    #[test]
    fn contradictory_changed_path_is_rejected_before_parsing() {
        let invalid = path(FileChangeKind::Renamed, "same.rs", "same.rs");
        assert_eq!(
            parse_gitlab_file_diff(
                &invalid,
                b"@@ -1 +1 @@\n-old\n+new\n",
                UnifiedDiffLimits::default(),
            ),
            Err(UnifiedDiffError::InvalidChangedPath(
                ChangedPathIssue::DistinctPathsRequired
            ))
        );
    }
}
