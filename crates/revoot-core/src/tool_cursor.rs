//! Opaque, process-local cursors and deterministic tool-result pagination.
//!
//! Cursor tokens contain no repository path, query, snapshot, source, or tool
//! payload. The server retains those bindings and authenticates every page
//! transition before returning bounded JSON values.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::Sha256Digest;

const CURSOR_PREFIX: &str = "rtc1";
const CURSOR_ID_HEX_BYTES: usize = 16;
const CURSOR_MAC_HEX_BYTES: usize = 64;
const CURSOR_TOKEN_BYTES: usize =
    CURSOR_PREFIX.len() + 1 + CURSOR_ID_HEX_BYTES + 1 + CURSOR_MAC_HEX_BYTES;
const MAX_TOOL_RESULT_BYTES: u32 = 32 * 1024;
const MAX_SEARCH_MATCHES: u16 = 500;
const DEFAULT_SEARCH_MATCHES: u16 = 200;

/// Tool identity included in every cursor binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorTool {
    ListChangedFiles,
    DiffManifest,
    ReadDiff,
    ReadFile,
    FindFiles,
    SearchCode,
    SearchDiff,
    GetRules,
    ValidateFindings,
}

/// Trusted identity against which an opaque cursor is resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCursorBinding {
    pub handle_digest: Sha256Digest,
    pub snapshot_digest: Sha256Digest,
    pub tool: CursorTool,
    pub query_digest: Sha256Digest,
}

/// Hard result bounds for one process-local cursor store.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultLimits {
    pub max_result_bytes: u32,
    pub default_search_matches: u16,
    pub max_search_matches: u16,
}

impl Default for ToolResultLimits {
    fn default() -> Self {
        Self {
            max_result_bytes: MAX_TOOL_RESULT_BYTES,
            default_search_matches: DEFAULT_SEARCH_MATCHES,
            max_search_matches: MAX_SEARCH_MATCHES,
        }
    }
}

/// The first invalid result limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolResultLimitsError {
    ResultBytes,
    DefaultMatches,
    MaximumMatches,
}

impl ToolResultLimits {
    /// Validate fixed product ceilings.
    ///
    /// # Errors
    ///
    /// Returns the first unusable or overly broad dimension.
    pub const fn validate(self) -> Result<(), ToolResultLimitsError> {
        if self.max_result_bytes == 0 || self.max_result_bytes > MAX_TOOL_RESULT_BYTES {
            return Err(ToolResultLimitsError::ResultBytes);
        }
        if self.default_search_matches == 0 || self.default_search_matches > DEFAULT_SEARCH_MATCHES
        {
            return Err(ToolResultLimitsError::DefaultMatches);
        }
        if self.max_search_matches == 0
            || self.max_search_matches > MAX_SEARCH_MATCHES
            || self.max_search_matches < self.default_search_matches
        {
            return Err(ToolResultLimitsError::MaximumMatches);
        }
        Ok(())
    }
}

/// Caller-requested page narrowing. Omitted values use store defaults.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPageRequest {
    pub max_result_bytes: Option<u32>,
    pub max_matches: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectivePageLimits {
    max_result_bytes: u32,
    max_matches: u16,
}

/// One bounded page ready for MCP serialization.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultPage {
    pub page_number: u32,
    pub items: Vec<Value>,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl ToolResultPage {
    /// Return the exact serialized JSON size used by the page bound.
    ///
    /// # Errors
    ///
    /// Serialization failure is reported without retaining or reflecting the
    /// page payload.
    pub fn encoded_len(&self) -> Result<usize, ToolCursorError> {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .map_err(|_| ToolCursorError::Serialization)
    }
}

/// Stable, payload-free cursor or pagination failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolCursorError {
    InvalidSecret,
    InvalidLimits(ToolResultLimitsError),
    InvalidPageRequest,
    InvalidCursor,
    UnknownCursor,
    HandleMismatch,
    SnapshotMismatch,
    ToolMismatch,
    QueryMismatch,
    PageOverflow,
    ItemTooLarge,
    Serialization,
}

#[derive(Clone, Debug)]
struct CursorRecord {
    binding: ToolCursorBinding,
    next_item_index: usize,
    page_number: u32,
}

struct ToolCursorState {
    next_cursor_id: u64,
    records: BTreeMap<u64, CursorRecord>,
}

struct ToolCursorInner {
    secret: [u8; 32],
    limits: ToolResultLimits,
    state: Mutex<ToolCursorState>,
}

/// Cloneable process-local cursor registry with authenticated opaque tokens.
#[derive(Clone)]
pub struct ToolCursorStore {
    inner: Arc<ToolCursorInner>,
}

impl ToolCursorStore {
    /// Create a cursor store from a trusted process-local random secret.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero secret and invalid product limits.
    pub fn new(secret: [u8; 32], limits: ToolResultLimits) -> Result<Self, ToolCursorError> {
        if secret == [0; 32] {
            return Err(ToolCursorError::InvalidSecret);
        }
        limits.validate().map_err(ToolCursorError::InvalidLimits)?;
        Ok(Self {
            inner: Arc::new(ToolCursorInner {
                secret,
                limits,
                state: Mutex::new(ToolCursorState {
                    next_cursor_id: 1,
                    records: BTreeMap::new(),
                }),
            }),
        })
    }

    /// Return immutable result limits.
    #[must_use]
    pub fn limits(&self) -> ToolResultLimits {
        self.inner.limits
    }

    /// Paginate deterministic JSON items from the beginning or an authenticated
    /// continuation cursor.
    ///
    /// # Errors
    ///
    /// Rejects invalid requests, cursors, bindings, oversized individual
    /// items, cursor-state overflow, or serialization failure.
    pub fn paginate(
        &self,
        binding: &ToolCursorBinding,
        items: &[Value],
        cursor: Option<&str>,
        request: ToolPageRequest,
    ) -> Result<ToolResultPage, ToolCursorError> {
        let limits = effective_limits(self.inner.limits, request)?;
        let (start_index, page_number) =
            cursor.map_or(Ok((0, 1)), |cursor| self.resolve_cursor(cursor, binding))?;
        if start_index > items.len() {
            return Err(ToolCursorError::InvalidCursor);
        }
        let maximum_matches = usize::from(limits.max_matches);
        let mut end_index = start_index;
        while end_index < items.len() && end_index.saturating_sub(start_index) < maximum_matches {
            let candidate_end = end_index.saturating_add(1);
            let will_truncate = candidate_end < items.len();
            let trial = ToolResultPage {
                page_number,
                items: items[start_index..candidate_end].to_vec(),
                truncated: will_truncate,
                next_cursor: will_truncate.then(|| placeholder_cursor().to_owned()),
            };
            if trial.encoded_len()?
                > usize::try_from(limits.max_result_bytes)
                    .map_err(|_| ToolCursorError::PageOverflow)?
            {
                break;
            }
            end_index = candidate_end;
        }
        if end_index == start_index && start_index < items.len() {
            return Err(ToolCursorError::ItemTooLarge);
        }
        let truncated = end_index < items.len();
        let next_cursor = if truncated {
            Some(
                self.issue_cursor(CursorRecord {
                    binding: binding.clone(),
                    next_item_index: end_index,
                    page_number: page_number
                        .checked_add(1)
                        .ok_or(ToolCursorError::PageOverflow)?,
                })?,
            )
        } else {
            None
        };
        let page = ToolResultPage {
            page_number,
            items: items[start_index..end_index].to_vec(),
            truncated,
            next_cursor,
        };
        if page.encoded_len()?
            > usize::try_from(limits.max_result_bytes).map_err(|_| ToolCursorError::PageOverflow)?
        {
            return Err(ToolCursorError::PageOverflow);
        }
        Ok(page)
    }

    /// Invalidate every cursor issued for one process-local review handle.
    pub fn invalidate_handle(&self, handle_digest: &Sha256Digest) {
        let mut state = lock_state(&self.inner);
        state
            .records
            .retain(|_, record| &record.binding.handle_digest != handle_digest);
    }

    fn resolve_cursor(
        &self,
        cursor: &str,
        expected: &ToolCursorBinding,
    ) -> Result<(usize, u32), ToolCursorError> {
        let (id, supplied_mac) = parse_cursor(cursor)?;
        let state = lock_state(&self.inner);
        let record = state
            .records
            .get(&id)
            .ok_or(ToolCursorError::UnknownCursor)?;
        let expected_mac = cursor_mac(&self.inner.secret, id, record);
        if !constant_time_eq(supplied_mac.as_bytes(), expected_mac.as_bytes()) {
            return Err(ToolCursorError::InvalidCursor);
        }
        validate_binding(&record.binding, expected)?;
        Ok((record.next_item_index, record.page_number))
    }

    fn issue_cursor(&self, record: CursorRecord) -> Result<String, ToolCursorError> {
        let mut state = lock_state(&self.inner);
        let id = state.next_cursor_id;
        state.next_cursor_id = state
            .next_cursor_id
            .checked_add(1)
            .ok_or(ToolCursorError::PageOverflow)?;
        let mac = cursor_mac(&self.inner.secret, id, &record);
        state.records.insert(id, record);
        Ok(format!("{CURSOR_PREFIX}.{id:016x}.{mac}"))
    }
}

fn effective_limits(
    limits: ToolResultLimits,
    request: ToolPageRequest,
) -> Result<EffectivePageLimits, ToolCursorError> {
    if request.max_result_bytes == Some(0) || request.max_matches == Some(0) {
        return Err(ToolCursorError::InvalidPageRequest);
    }
    Ok(EffectivePageLimits {
        max_result_bytes: request
            .max_result_bytes
            .unwrap_or(limits.max_result_bytes)
            .min(limits.max_result_bytes),
        max_matches: request
            .max_matches
            .unwrap_or(limits.default_search_matches)
            .min(limits.max_search_matches),
    })
}

fn validate_binding(
    actual: &ToolCursorBinding,
    expected: &ToolCursorBinding,
) -> Result<(), ToolCursorError> {
    if actual.handle_digest != expected.handle_digest {
        return Err(ToolCursorError::HandleMismatch);
    }
    if actual.snapshot_digest != expected.snapshot_digest {
        return Err(ToolCursorError::SnapshotMismatch);
    }
    if actual.tool != expected.tool {
        return Err(ToolCursorError::ToolMismatch);
    }
    if actual.query_digest != expected.query_digest {
        return Err(ToolCursorError::QueryMismatch);
    }
    Ok(())
}

fn cursor_mac(secret: &[u8; 32], id: u64, record: &CursorRecord) -> String {
    let mut digest = Sha256::new();
    digest.update(b"revoot-tool-cursor-v1\0");
    digest.update(secret);
    digest.update(id.to_be_bytes());
    digest.update(record.binding.handle_digest.as_str().as_bytes());
    digest.update(record.binding.snapshot_digest.as_str().as_bytes());
    digest.update([record.binding.tool as u8]);
    digest.update(record.binding.query_digest.as_str().as_bytes());
    digest.update(record.next_item_index.to_be_bytes());
    digest.update(record.page_number.to_be_bytes());
    digest.update(secret);
    format!("{:x}", digest.finalize())
}

fn parse_cursor(cursor: &str) -> Result<(u64, &str), ToolCursorError> {
    if cursor.len() != CURSOR_TOKEN_BYTES {
        return Err(ToolCursorError::InvalidCursor);
    }
    let mut parts = cursor.split('.');
    let prefix = parts.next().ok_or(ToolCursorError::InvalidCursor)?;
    let id = parts.next().ok_or(ToolCursorError::InvalidCursor)?;
    let mac = parts.next().ok_or(ToolCursorError::InvalidCursor)?;
    if prefix != CURSOR_PREFIX
        || id.len() != CURSOR_ID_HEX_BYTES
        || mac.len() != CURSOR_MAC_HEX_BYTES
        || parts.next().is_some()
        || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !mac.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ToolCursorError::InvalidCursor);
    }
    let id = u64::from_str_radix(id, 16).map_err(|_| ToolCursorError::InvalidCursor)?;
    Ok((id, mac))
}

fn placeholder_cursor() -> &'static str {
    "rtc1.0000000000000000.0000000000000000000000000000000000000000000000000000000000000000"
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn lock_state(inner: &ToolCursorInner) -> MutexGuard<'_, ToolCursorState> {
    inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).expect("digest")
    }

    fn store() -> ToolCursorStore {
        ToolCursorStore::new([7; 32], ToolResultLimits::default()).expect("store")
    }

    fn binding() -> ToolCursorBinding {
        ToolCursorBinding {
            handle_digest: digest('a'),
            snapshot_digest: digest('b'),
            tool: CursorTool::SearchDiff,
            query_digest: digest('c'),
        }
    }

    fn items(count: usize, body_bytes: usize) -> Vec<Value> {
        (0..count)
            .map(|index| {
                serde_json::json!({
                    "index": index,
                    "body": "x".repeat(body_bytes)
                })
            })
            .collect()
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn cursor_store_is_send_sync() {
        assert_send_sync::<ToolCursorStore>();
    }

    #[test]
    fn limits_never_exceed_product_ceilings() {
        assert_eq!(ToolResultLimits::default().validate(), Ok(()));
        assert_eq!(
            ToolResultLimits {
                max_result_bytes: MAX_TOOL_RESULT_BYTES + 1,
                ..ToolResultLimits::default()
            }
            .validate(),
            Err(ToolResultLimitsError::ResultBytes)
        );
        assert_eq!(
            ToolResultLimits {
                max_search_matches: MAX_SEARCH_MATCHES + 1,
                ..ToolResultLimits::default()
            }
            .validate(),
            Err(ToolResultLimitsError::MaximumMatches)
        );
    }

    #[test]
    fn pages_are_byte_bounded_and_deterministic() {
        let store = store();
        let values = items(20, 200);
        let request = ToolPageRequest {
            max_result_bytes: Some(1_024),
            max_matches: Some(500),
        };
        let first = store
            .paginate(&binding(), &values, None, request)
            .expect("first page");
        assert!(first.encoded_len().expect("size") <= 1_024);
        assert!(first.truncated);
        let replay = store
            .paginate(&binding(), &values, None, request)
            .expect("replayed first page");
        assert_eq!(first.items, replay.items);
        let second = store
            .paginate(&binding(), &values, first.next_cursor.as_deref(), request)
            .expect("second page");
        assert_eq!(second.page_number, 2);
        assert_ne!(first.items, second.items);
        assert!(second.encoded_len().expect("size") <= 1_024);
    }

    #[test]
    fn default_and_hard_search_match_counts_are_enforced() {
        let store = store();
        let values = items(700, 1);
        let default_page = store
            .paginate(&binding(), &values, None, ToolPageRequest::default())
            .expect("default page");
        assert_eq!(default_page.items.len(), 200);
        let maximum_page = store
            .paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: None,
                    max_matches: Some(u16::MAX),
                },
            )
            .expect("maximum page");
        assert_eq!(maximum_page.items.len(), 500);
    }

    #[test]
    fn cursor_contains_no_binding_or_payload_text() {
        let store = store();
        let values = items(3, 100);
        let page = store
            .paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: Some(300),
                    max_matches: None,
                },
            )
            .expect("page");
        let cursor = page.next_cursor.expect("cursor");
        assert_eq!(cursor.len(), CURSOR_TOKEN_BYTES);
        assert!(!cursor.contains("src"));
        assert!(!cursor.contains("search"));
        assert!(!cursor.contains(digest('a').as_str()));
        assert!(!cursor.contains(digest('b').as_str()));
        assert!(!cursor.contains(digest('c').as_str()));
    }

    #[test]
    fn tampered_cursor_is_rejected() {
        let store = store();
        let values = items(3, 100);
        let page = store
            .paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: Some(300),
                    max_matches: None,
                },
            )
            .expect("page");
        let mut cursor = page.next_cursor.expect("cursor").into_bytes();
        let last = cursor.len() - 1;
        cursor[last] = if cursor[last] == b'0' { b'1' } else { b'0' };
        let cursor = String::from_utf8(cursor).expect("UTF-8");
        assert_eq!(
            store.paginate(
                &binding(),
                &values,
                Some(&cursor),
                ToolPageRequest::default()
            ),
            Err(ToolCursorError::InvalidCursor)
        );
    }

    #[test]
    fn stale_and_cross_snapshot_cursors_fail_closed() {
        let store = store();
        let values = items(3, 100);
        let page = store
            .paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: Some(300),
                    max_matches: None,
                },
            )
            .expect("page");
        let cursor = page.next_cursor.expect("cursor");

        let mut cross_snapshot = binding();
        cross_snapshot.snapshot_digest = digest('d');
        assert_eq!(
            store.paginate(
                &cross_snapshot,
                &values,
                Some(&cursor),
                ToolPageRequest::default()
            ),
            Err(ToolCursorError::SnapshotMismatch)
        );

        store.invalidate_handle(&binding().handle_digest);
        assert_eq!(
            store.paginate(
                &binding(),
                &values,
                Some(&cursor),
                ToolPageRequest::default()
            ),
            Err(ToolCursorError::UnknownCursor)
        );
    }

    #[test]
    fn every_binding_component_is_checked() {
        let store = store();
        let values = items(3, 100);
        let page = store
            .paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: Some(300),
                    max_matches: None,
                },
            )
            .expect("page");
        let cursor = page.next_cursor.expect("cursor");
        let cases = [
            (
                ToolCursorBinding {
                    handle_digest: digest('d'),
                    ..binding()
                },
                ToolCursorError::HandleMismatch,
            ),
            (
                ToolCursorBinding {
                    tool: CursorTool::ReadDiff,
                    ..binding()
                },
                ToolCursorError::ToolMismatch,
            ),
            (
                ToolCursorBinding {
                    query_digest: digest('d'),
                    ..binding()
                },
                ToolCursorError::QueryMismatch,
            ),
        ];
        for (wrong_binding, expected) in cases {
            assert_eq!(
                store.paginate(
                    &wrong_binding,
                    &values,
                    Some(&cursor),
                    ToolPageRequest::default()
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn cursors_are_process_local() {
        let first_store = store();
        let second_store =
            ToolCursorStore::new([8; 32], ToolResultLimits::default()).expect("store");
        let values = items(3, 100);
        let page = first_store
            .paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: Some(300),
                    max_matches: None,
                },
            )
            .expect("page");
        assert_eq!(
            second_store.paginate(
                &binding(),
                &values,
                page.next_cursor.as_deref(),
                ToolPageRequest::default()
            ),
            Err(ToolCursorError::UnknownCursor)
        );
    }

    #[test]
    fn oversized_single_item_is_rejected_without_payload() {
        let store = store();
        let values = items(1, 40_000);
        let error = store
            .paginate(&binding(), &values, None, ToolPageRequest::default())
            .expect_err("oversized item");
        assert_eq!(error, ToolCursorError::ItemTooLarge);
        assert_eq!(format!("{error:?}"), "ItemTooLarge");
    }

    #[test]
    fn invalid_narrowing_is_rejected_and_broadening_is_clamped() {
        let store = store();
        let values = items(1, 1);
        assert_eq!(
            store.paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: Some(0),
                    max_matches: None,
                }
            ),
            Err(ToolCursorError::InvalidPageRequest)
        );
        let page = store
            .paginate(
                &binding(),
                &values,
                None,
                ToolPageRequest {
                    max_result_bytes: Some(u32::MAX),
                    max_matches: Some(u16::MAX),
                },
            )
            .expect("clamped");
        assert!(
            page.encoded_len().expect("size") <= usize::try_from(MAX_TOOL_RESULT_BYTES).unwrap()
        );
    }
}
