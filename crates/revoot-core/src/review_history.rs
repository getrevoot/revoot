//! Bounded, host-neutral prior-review context reconstructed from code-host discussions.
//!
//! Discussion text is untrusted model input. Host state and Revoot ownership
//! are established by the transport/controller before constructing this value.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{FindingLineageMarker, Sha256Digest};

const MAX_DISCUSSIONS: usize = 500;
const MAX_DISCUSSION_ID_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_BODY_BYTES: usize = 4 * 1024;
const MAX_TOTAL_BODY_BYTES: usize = 256 * 1024;
const MAX_REPLIES_PER_DISCUSSION: usize = 100;
const MAX_TIMESTAMP_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorReviewSource {
    Revoot,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorReviewState {
    Open,
    Resolved,
    Outdated,
}

/// One reply with host-established authorship. Text remains untrusted data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorReviewReply {
    pub comment_id: String,
    pub source: PriorReviewSource,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Host-established resolution provenance for an owned discussion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorReviewResolution {
    pub source: PriorReviewSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
}

/// One discussion represented by its root comment and current host state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorReviewDiscussion {
    pub thread_id: String,
    pub comment_id: String,
    pub source: PriorReviewSource,
    pub state: PriorReviewState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_line: Option<u32>,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replies: Vec<PriorReviewReply>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<PriorReviewResolution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<FindingLineageMarker>,
}

/// Complete prior-discussion inventory supplied to one review invocation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorReviewContext {
    discussions: Vec<PriorReviewDiscussion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorReviewContextError {
    TooManyDiscussions,
    InvalidIdentity,
    DuplicateIdentity,
    InvalidPath,
    InvalidBody,
    TotalBodyBytes,
    DuplicateLineage,
    TooManyReplies,
    InvalidTimestamp,
}

impl PriorReviewContext {
    /// Validate, sort, and retain a complete discussion inventory.
    ///
    /// # Errors
    ///
    /// Rejects oversized content, ambiguous identities, and multiple Revoot
    /// root comments claiming the same lineage.
    pub fn try_new(
        mut discussions: Vec<PriorReviewDiscussion>,
    ) -> Result<Self, PriorReviewContextError> {
        if discussions.len() > MAX_DISCUSSIONS {
            return Err(PriorReviewContextError::TooManyDiscussions);
        }
        let mut identities = BTreeSet::new();
        let mut active_owned_lineages = BTreeSet::new();
        let mut total_body_bytes = 0_usize;
        for discussion in &discussions {
            if !valid_identity(&discussion.thread_id) || !valid_identity(&discussion.comment_id) {
                return Err(PriorReviewContextError::InvalidIdentity);
            }
            if !identities.insert((discussion.thread_id.clone(), discussion.comment_id.clone())) {
                return Err(PriorReviewContextError::DuplicateIdentity);
            }
            if discussion.path.as_ref().is_some_and(|path| {
                path.is_empty()
                    || path.len() > MAX_PATH_BYTES
                    || path.contains('\0')
                    || path.starts_with('/')
            }) {
                return Err(PriorReviewContextError::InvalidPath);
            }
            if discussion.line == Some(0) || discussion.original_line == Some(0) {
                return Err(PriorReviewContextError::InvalidPath);
            }
            if discussion.body.is_empty()
                || discussion.body.len() > MAX_BODY_BYTES
                || discussion.body.contains('\0')
            {
                return Err(PriorReviewContextError::InvalidBody);
            }
            if discussion.replies.len() > MAX_REPLIES_PER_DISCUSSION {
                return Err(PriorReviewContextError::TooManyReplies);
            }
            let mut reply_ids = BTreeSet::new();
            for reply in &discussion.replies {
                if !valid_identity(&reply.comment_id)
                    || reply.comment_id == discussion.comment_id
                    || !reply_ids.insert(reply.comment_id.clone())
                {
                    return Err(PriorReviewContextError::DuplicateIdentity);
                }
                if reply.body.is_empty()
                    || reply.body.len() > MAX_BODY_BYTES
                    || reply.body.contains('\0')
                {
                    return Err(PriorReviewContextError::InvalidBody);
                }
                if !valid_timestamp(reply.created_at.as_deref())
                    || !valid_timestamp(reply.updated_at.as_deref())
                {
                    return Err(PriorReviewContextError::InvalidTimestamp);
                }
                total_body_bytes = total_body_bytes
                    .checked_add(reply.body.len())
                    .ok_or(PriorReviewContextError::TotalBodyBytes)?;
            }
            if discussion
                .resolution
                .as_ref()
                .is_some_and(|resolution| !valid_timestamp(resolution.resolved_at.as_deref()))
            {
                return Err(PriorReviewContextError::InvalidTimestamp);
            }
            if (discussion.state == PriorReviewState::Resolved) != discussion.resolution.is_some() {
                return Err(PriorReviewContextError::InvalidIdentity);
            }
            total_body_bytes = total_body_bytes
                .checked_add(discussion.body.len())
                .ok_or(PriorReviewContextError::TotalBodyBytes)?;
            if total_body_bytes > MAX_TOTAL_BODY_BYTES {
                return Err(PriorReviewContextError::TotalBodyBytes);
            }
            if discussion.source == PriorReviewSource::Revoot
                && discussion.state != PriorReviewState::Resolved
                && let Some(lineage) = &discussion.lineage
                && !active_owned_lineages.insert(lineage.lineage_sha256.clone())
            {
                return Err(PriorReviewContextError::DuplicateLineage);
            }
        }
        discussions.sort_by(|left, right| {
            left.thread_id
                .cmp(&right.thread_id)
                .then_with(|| left.comment_id.cmp(&right.comment_id))
        });
        Ok(Self { discussions })
    }

    #[must_use]
    pub fn discussions(&self) -> &[PriorReviewDiscussion] {
        &self.discussions
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.discussions.is_empty()
    }

    #[must_use]
    pub fn owned_lineages(&self) -> BTreeSet<Sha256Digest> {
        self.discussions
            .iter()
            .filter(|discussion| discussion.source == PriorReviewSource::Revoot)
            .filter_map(|discussion| {
                discussion
                    .lineage
                    .as_ref()
                    .map(|marker| marker.lineage_sha256.clone())
            })
            .collect()
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DISCUSSION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>')
}

fn valid_timestamp(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_TIMESTAMP_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GitSha;

    fn digest(value: &[u8]) -> Sha256Digest {
        Sha256Digest::of_bytes(value)
    }

    #[test]
    fn inventory_is_canonical_and_lineages_are_explicit() {
        let marker = FindingLineageMarker::new(
            digest(b"lineage"),
            GitSha::try_from("a".repeat(40)).unwrap(),
            digest(b"evidence"),
        );
        let context = PriorReviewContext::try_new(vec![PriorReviewDiscussion {
            thread_id: "thread-1".to_owned(),
            comment_id: "10".to_owned(),
            source: PriorReviewSource::Revoot,
            state: PriorReviewState::Resolved,
            path: Some("src/lib.rs".to_owned()),
            line: Some(12),
            original_line: Some(12),
            body: "A prior finding".to_owned(),
            replies: Vec::new(),
            resolution: Some(PriorReviewResolution {
                source: PriorReviewSource::Other,
                resolved_at: Some("2026-08-29T10:00:00Z".to_owned()),
            }),
            lineage: Some(marker.clone()),
        }])
        .unwrap();
        assert_eq!(context.discussions().len(), 1);
        assert_eq!(
            context.owned_lineages(),
            BTreeSet::from([marker.lineage_sha256])
        );
    }

    #[test]
    fn duplicate_active_owned_lineage_is_ambiguous() {
        let marker = FindingLineageMarker::new(
            digest(b"lineage"),
            GitSha::try_from("a".repeat(40)).unwrap(),
            digest(b"evidence"),
        );
        let discussion = |id: &str| PriorReviewDiscussion {
            thread_id: id.to_owned(),
            comment_id: id.to_owned(),
            source: PriorReviewSource::Revoot,
            state: PriorReviewState::Open,
            path: None,
            line: None,
            original_line: None,
            body: "finding".to_owned(),
            replies: Vec::new(),
            resolution: None,
            lineage: Some(marker.clone()),
        };
        assert_eq!(
            PriorReviewContext::try_new(vec![discussion("1"), discussion("2")]),
            Err(PriorReviewContextError::DuplicateLineage)
        );
    }
}
