//! Complete code-host discussion acquisition before semantic review.

use revoot_core::{
    FindingLineageMarker, GitLabWireLimits, MergeRequestIid, PriorReviewContext,
    PriorReviewDiscussion, PriorReviewReply, PriorReviewResolution, PriorReviewSource,
    PriorReviewState, ProjectId, PublicationMarker, Sha256Digest, collect_complete_pages,
    parse_discussions_page,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::github_checkout::GitHubRepositorySlug;
use crate::github_transport::GitHubClient;
use crate::gitlab_transport::{GitLabPagination, GitLabReadClient, GitLabReadEndpoint};

const PAGE_SIZE: u32 = 100;
const MAX_PAGES: u32 = 100;
const MAX_DISCUSSION_BODY_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorReviewAcquisitionError {
    Transport,
    Wire,
    Pagination,
    Identity,
    Inventory,
}

/// Acquire every GitLab merge-request discussion and classify Revoot roots.
///
/// # Errors
///
/// Rejects transport failures, incomplete pagination, malformed wire data,
/// ambiguous identities, and inventories exceeding the semantic-review bounds.
pub async fn acquire_gitlab_prior_review(
    client: &GitLabReadClient,
    project_id: ProjectId,
    merge_request_iid: MergeRequestIid,
    bot_user_id: Option<u64>,
    current_head: &revoot_core::GitSha,
) -> Result<PriorReviewContext, PriorReviewAcquisitionError> {
    let limits = GitLabWireLimits::default();
    let mut pages = Vec::new();
    let mut requested = 1_u32;
    loop {
        let pagination = GitLabPagination::new(requested, PAGE_SIZE)
            .map_err(|_| PriorReviewAcquisitionError::Pagination)?;
        let response = client
            .get(&GitLabReadEndpoint::Discussions {
                project_id,
                merge_request_iid,
                pagination,
            })
            .await
            .map_err(|_| PriorReviewAcquisitionError::Transport)?;
        let page = parse_discussions_page(response.observation(), requested, PAGE_SIZE, limits)
            .map_err(|_| PriorReviewAcquisitionError::Wire)?;
        let next = page.metadata.next_page;
        pages.push(page);
        match next {
            Some(next) if next > requested && pages.len() < MAX_PAGES as usize => requested = next,
            Some(_) => return Err(PriorReviewAcquisitionError::Pagination),
            None => break,
        }
    }
    let acquisition =
        collect_complete_pages(pages, limits).map_err(|_| PriorReviewAcquisitionError::Wire)?;
    let mut discussions = Vec::with_capacity(acquisition.items.len());
    for discussion in acquisition.items {
        let Some(root) = discussion.notes.first() else {
            return Err(PriorReviewAcquisitionError::Wire);
        };
        let owned = bot_user_id.is_some_and(|id| root.author_user_id == id)
            && publication_marker(&root.body).is_some();
        let lineage = owned
            .then(|| lineage_marker(&root.body, current_head))
            .flatten();
        let (body, replies) = bounded_discussion(
            &root.body,
            discussion.notes.iter().skip(1).map(|note| RawReply {
                comment_id: note.note_id.to_string(),
                source: if bot_user_id == Some(note.author_user_id) {
                    PriorReviewSource::Revoot
                } else {
                    PriorReviewSource::Other
                },
                body: &note.body,
                created_at: note.created_at.as_deref(),
                updated_at: note.updated_at.as_deref(),
            }),
        );
        discussions.push(PriorReviewDiscussion {
            thread_id: discussion.id,
            comment_id: root.note_id.to_string(),
            source: if owned {
                PriorReviewSource::Revoot
            } else {
                PriorReviewSource::Other
            },
            state: if root.resolved {
                PriorReviewState::Resolved
            } else {
                PriorReviewState::Open
            },
            path: root.path.clone(),
            line: root.line,
            original_line: root.original_line,
            body,
            replies,
            resolution: root.resolved.then(|| PriorReviewResolution {
                source: if bot_user_id == root.resolved_by_user_id {
                    PriorReviewSource::Revoot
                } else {
                    PriorReviewSource::Other
                },
                resolved_at: root.resolved_at.clone(),
            }),
            lineage,
        });
    }
    PriorReviewContext::try_new(discussions).map_err(|_| PriorReviewAcquisitionError::Inventory)
}

/// Acquire every GitHub pull-request review thread, including live resolution state.
///
/// # Errors
///
/// Rejects transport or GraphQL failures, incomplete thread or reply
/// pagination, malformed identities, and inventories exceeding the bounds.
pub async fn acquire_github_prior_review(
    client: &GitHubClient,
    repository: &GitHubRepositorySlug,
    pull_request_number: revoot_core::PullRequestNumber,
    current_head: &revoot_core::GitSha,
) -> Result<PriorReviewContext, PriorReviewAcquisitionError> {
    let mut discussions = Vec::new();
    let mut after: Option<String> = None;
    let mut authenticated_login: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let response = client
            .graphql(&json!({
                "query": GITHUB_REVIEW_THREADS_QUERY,
                "variables": {
                    "owner": repository.owner(),
                    "name": repository.repository(),
                    "number": pull_request_number.get(),
                    "after": after,
                }
            }))
            .await
            .map_err(|_| PriorReviewAcquisitionError::Transport)?;
        let envelope: GitHubGraphQlEnvelope = serde_json::from_slice(&response.body)
            .map_err(|_| PriorReviewAcquisitionError::Wire)?;
        if envelope.errors.is_some() {
            return Err(PriorReviewAcquisitionError::Wire);
        }
        let data = envelope.data.ok_or(PriorReviewAcquisitionError::Wire)?;
        let viewer = data.viewer.ok_or(PriorReviewAcquisitionError::Identity)?;
        if viewer.login.is_empty()
            || authenticated_login
                .as_ref()
                .is_some_and(|login| login != &viewer.login)
        {
            return Err(PriorReviewAcquisitionError::Identity);
        }
        let authenticated_login = authenticated_login.get_or_insert(viewer.login);
        let connection = data
            .repository
            .and_then(|repository| repository.pull_request)
            .map(|pull| pull.review_threads)
            .ok_or(PriorReviewAcquisitionError::Wire)?;
        for thread in connection.nodes {
            discussions.push(github_discussion(
                thread,
                authenticated_login,
                current_head,
            )?);
        }
        match (
            connection.page_info.has_next_page,
            connection.page_info.end_cursor,
        ) {
            (false, _) => {
                return PriorReviewContext::try_new(discussions)
                    .map_err(|_| PriorReviewAcquisitionError::Inventory);
            }
            (true, Some(cursor)) if !cursor.is_empty() => after = Some(cursor),
            _ => return Err(PriorReviewAcquisitionError::Pagination),
        }
    }
    Err(PriorReviewAcquisitionError::Pagination)
}

fn github_discussion(
    thread: GitHubReviewThread,
    authenticated_login: &str,
    current_head: &revoot_core::GitSha,
) -> Result<PriorReviewDiscussion, PriorReviewAcquisitionError> {
    if thread.comments.page_info.has_next_page {
        return Err(PriorReviewAcquisitionError::Pagination);
    }
    let Some(root) = thread.comments.nodes.first() else {
        return Err(PriorReviewAcquisitionError::Wire);
    };
    let owned = github_source(root.author.as_ref(), authenticated_login)
        == PriorReviewSource::Revoot
        && publication_marker(&root.body).is_some();
    let fallback_head = root
        .original_commit
        .as_ref()
        .and_then(|commit| revoot_core::GitSha::try_from(commit.oid.clone()).ok())
        .unwrap_or_else(|| current_head.clone());
    let lineage = owned
        .then(|| lineage_marker(&root.body, &fallback_head))
        .flatten();
    let (body, replies) = bounded_discussion(
        &root.body,
        thread
            .comments
            .nodes
            .iter()
            .skip(1)
            .map(|comment| RawReply {
                comment_id: comment.database_id.to_string(),
                source: github_source(comment.author.as_ref(), authenticated_login),
                body: &comment.body,
                created_at: comment.created_at.as_deref(),
                updated_at: comment.updated_at.as_deref(),
            }),
    );
    Ok(PriorReviewDiscussion {
        thread_id: thread.id,
        comment_id: root.database_id.to_string(),
        source: if owned {
            PriorReviewSource::Revoot
        } else {
            PriorReviewSource::Other
        },
        state: if thread.is_resolved {
            PriorReviewState::Resolved
        } else if thread.is_outdated {
            PriorReviewState::Outdated
        } else {
            PriorReviewState::Open
        },
        path: Some(thread.path),
        line: thread.line,
        original_line: thread.original_line,
        body,
        replies,
        resolution: thread.is_resolved.then(|| PriorReviewResolution {
            source: github_source(thread.resolved_by.as_ref(), authenticated_login),
            resolved_at: None,
        }),
        lineage,
    })
}

fn publication_marker(body: &str) -> Option<PublicationMarker> {
    let mut markers = body.lines().filter_map(PublicationMarker::parse);
    let marker = markers.next()?;
    markers.next().is_none().then_some(marker)
}

fn lineage_marker(body: &str, fallback_head: &revoot_core::GitSha) -> Option<FindingLineageMarker> {
    FindingLineageMarker::from_body(body).or_else(|| {
        let publication = publication_marker(body)?;
        let lineage = Sha256Digest::of_bytes(publication.fingerprint_sha256.as_str().as_bytes());
        Some(FindingLineageMarker::new(
            lineage,
            fallback_head.clone(),
            Sha256Digest::of_bytes(body.as_bytes()),
        ))
    })
}

struct RawReply<'a> {
    comment_id: String,
    source: PriorReviewSource,
    body: &'a str,
    created_at: Option<&'a str>,
    updated_at: Option<&'a str>,
}

fn bounded_discussion<'a>(
    root: &'a str,
    replies: impl IntoIterator<Item = RawReply<'a>>,
) -> (String, Vec<PriorReviewReply>) {
    let replies = replies
        .into_iter()
        .filter(|reply| !reply.body.is_empty())
        .collect::<Vec<_>>();
    let root_budget = if replies.is_empty() {
        MAX_DISCUSSION_BODY_BYTES
    } else {
        MAX_DISCUSSION_BODY_BYTES * 3 / 4
    };
    let root = bounded_text(root, root_budget);
    let mut remaining = MAX_DISCUSSION_BODY_BYTES.saturating_sub(root.len());
    let mut retained = Vec::new();
    for reply in replies.into_iter().rev() {
        if remaining == 0 {
            break;
        }
        let body = bounded_text(reply.body, remaining);
        remaining = remaining.saturating_sub(body.len());
        retained.push(PriorReviewReply {
            comment_id: reply.comment_id,
            source: reply.source,
            body,
            created_at: reply.created_at.map(str::to_owned),
            updated_at: reply.updated_at.map(str::to_owned),
        });
    }
    retained.reverse();
    (root, retained)
}

fn bounded_text(value: &str, maximum: usize) -> String {
    let mut end = value.len().min(maximum);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn github_source(author: Option<&GitHubActor>, authenticated_login: &str) -> PriorReviewSource {
    if author.is_some_and(|author| author.login == authenticated_login) {
        PriorReviewSource::Revoot
    } else {
        PriorReviewSource::Other
    }
}

const GITHUB_REVIEW_THREADS_QUERY: &str = r"query RevootReviewThreads($owner: String!, $name: String!, $number: Int!, $after: String) {
  viewer { login }
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) {
        nodes {
          id
          isResolved
          isOutdated
          originalLine
          resolvedBy { login }
          path
          line
          comments(first: 100) {
            nodes {
              databaseId
              body
              author { login }
              originalCommit { oid }
              createdAt
              updatedAt
            }
            pageInfo { hasNextPage }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}";

#[derive(Deserialize)]
struct GitHubViewer {
    login: String,
}

#[derive(Deserialize)]
struct GitHubGraphQlEnvelope {
    data: Option<GitHubGraphQlData>,
    errors: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct GitHubGraphQlData {
    viewer: Option<GitHubViewer>,
    repository: Option<GitHubGraphQlRepository>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubGraphQlRepository {
    pull_request: Option<GitHubGraphQlPullRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubGraphQlPullRequest {
    review_threads: GitHubReviewThreadConnection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubReviewThreadConnection {
    nodes: Vec<GitHubReviewThread>,
    page_info: GitHubPageInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubReviewThread {
    id: String,
    is_resolved: bool,
    is_outdated: bool,
    path: String,
    line: Option<u32>,
    original_line: Option<u32>,
    resolved_by: Option<GitHubActor>,
    comments: GitHubReviewCommentConnection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubReviewCommentConnection {
    nodes: Vec<GitHubReviewComment>,
    page_info: GitHubPageInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubReviewComment {
    database_id: u64,
    body: String,
    author: Option<GitHubActor>,
    original_commit: Option<GitHubCommit>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Deserialize)]
struct GitHubActor {
    login: String,
}

#[derive(Deserialize)]
struct GitHubCommit {
    oid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GitHubPageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use crate::github_transport::GitHubToken;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn bounded_body_preserves_utf8_boundaries() {
        let body = "é".repeat(MAX_DISCUSSION_BODY_BYTES);
        let (bounded, replies) = bounded_discussion(&body, []);
        assert!(bounded.len() <= MAX_DISCUSSION_BODY_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(replies.is_empty());
    }

    #[tokio::test]
    async fn github_inventory_preserves_resolution_and_owned_lineage() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let head = revoot_core::GitSha::try_from("a".repeat(40)).unwrap();
        let marker = FindingLineageMarker::new(
            Sha256Digest::of_bytes(b"lineage"),
            head.clone(),
            Sha256Digest::of_bytes(b"evidence"),
        );
        let body = format!(
            "finding\n{}\n<!-- revoot:v1 scope={} fingerprint={} kind=inline -->",
            marker.render(),
            "b".repeat(64),
            "c".repeat(64)
        );
        let server = tokio::spawn(async move {
            let (mut graphql, _) = listener.accept().await.unwrap();
            let request = read_request(&mut graphql).await;
            assert!(request.starts_with(b"POST /graphql "));
            write_json(
                &mut graphql,
                &json!({
                    "data": {"viewer": {"login": "revoot-bot"}, "repository": {"pullRequest": {"reviewThreads": {
                        "nodes": [{
                            "id": "PRRT_thread",
                            "isResolved": true,
                            "isOutdated": false,
                            "path": "src/lib.rs",
                            "line": 12,
                            "originalLine": 12,
                            "resolvedBy": {"login": "reviewer", "databaseId": 8},
                            "comments": {
                                "nodes": [{
                                    "databaseId": 9,
                                    "body": body,
                                    "author": {"login": "revoot-bot", "databaseId": 7},
                                    "originalCommit": {"oid": "a".repeat(40)},
                                    "createdAt": "2026-08-29T10:00:00Z",
                                    "updatedAt": "2026-08-29T10:00:00Z"
                                }, {
                                    "databaseId": 10,
                                    "body": "This is an intentional exception for this pull request.",
                                    "author": {"login": "reviewer", "databaseId": 8},
                                    "originalCommit": {"oid": "a".repeat(40)},
                                    "createdAt": "2026-08-29T10:05:00Z",
                                    "updatedAt": "2026-08-29T10:05:00Z"
                                }],
                                "pageInfo": {"hasNextPage": false}
                            }
                        }],
                        "pageInfo": {"hasNextPage": false, "endCursor": null}
                    }}}}
                }),
            )
            .await;
        });
        let client =
            GitHubClient::new_for_loopback(GitHubToken::new(b"token".to_vec()).unwrap(), address)
                .unwrap();
        let context = acquire_github_prior_review(
            &client,
            &GitHubRepositorySlug::parse("acme/widgets").unwrap(),
            revoot_core::PullRequestNumber::try_from(7).unwrap(),
            &head,
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(context.discussions().len(), 1);
        assert_eq!(context.discussions()[0].source, PriorReviewSource::Revoot);
        assert_eq!(context.discussions()[0].state, PriorReviewState::Resolved);
        assert_eq!(context.discussions()[0].lineage, Some(marker));
        assert_eq!(context.discussions()[0].original_line, Some(12));
        assert_eq!(context.discussions()[0].replies.len(), 1);
        assert_eq!(
            context.discussions()[0].replies[0].source,
            PriorReviewSource::Other
        );
        assert_eq!(
            context.discussions()[0]
                .resolution
                .as_ref()
                .map(|resolution| resolution.source),
            Some(PriorReviewSource::Other)
        );
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(head_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let head_end = head_end + 4;
                let head = std::str::from_utf8(&request[..head_end]).unwrap();
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= head_end + length {
                    break;
                }
            }
        }
        request
    }

    async fn write_json(stream: &mut tokio::net::TcpStream, value: &Value) {
        let body = serde_json::to_vec(value).unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    }
}
