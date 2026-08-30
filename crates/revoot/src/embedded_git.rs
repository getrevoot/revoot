//! One non-executing boundary over the embedded, pure-Rust Git reader.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use gix::bstr::ByteSlice;
use revoot_core::{GitSha, RepositoryRelativePath};

const MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REPOSITORY_PATHS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmbeddedGitError {
    RepositoryUnavailable,
    UnsupportedObjectFormat,
    CommitUnavailable,
    ReferenceUnavailable,
    HistoryUnavailable,
    IndexUnavailable,
    Conflict,
    InvalidPath,
    ObjectUnavailable,
    ObjectTooLarge,
    StatusUnavailable,
    PathLimit,
}

impl fmt::Display for EmbeddedGitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RepositoryUnavailable => "embedded Git repository is unavailable",
            Self::UnsupportedObjectFormat => "Git object format is unsupported",
            Self::CommitUnavailable => "Git commit is unavailable",
            Self::ReferenceUnavailable => "Git reference is unavailable",
            Self::HistoryUnavailable => "Git history is unavailable",
            Self::IndexUnavailable => "Git index is unavailable",
            Self::Conflict => "Git index contains unresolved conflicts",
            Self::InvalidPath => "Git repository path is invalid",
            Self::ObjectUnavailable => "Git object is unavailable",
            Self::ObjectTooLarge => "Git object exceeds the read limit",
            Self::StatusUnavailable => "Git working-tree status is unavailable",
            Self::PathLimit => "Git repository path limit was exceeded",
        })
    }
}

impl std::error::Error for EmbeddedGitError {}

/// A trusted, read-only repository opened without consulting Git or user/system config.
pub(crate) struct EmbeddedRepository {
    repository: gix::Repository,
    root: PathBuf,
}

impl EmbeddedRepository {
    pub(crate) fn discover(start: &Path) -> Result<Self, EmbeddedGitError> {
        Self::discover_with_options(start, safe_open_options())
    }

    /// Open a CI-mounted checkout without trusting repository-local configuration.
    pub(crate) fn discover_ci_checkout(start: &Path) -> Result<Self, EmbeddedGitError> {
        Self::discover_with_options(start, safe_open_options().bail_if_untrusted(false))
    }

    fn discover_with_options(
        start: &Path,
        options: gix::open::Options,
    ) -> Result<Self, EmbeddedGitError> {
        let repository =
            gix::discover_opts(start, gix::discover::upwards::Options::default(), options)
                .map_err(|_| EmbeddedGitError::RepositoryUnavailable)?;
        let root = repository
            .workdir()
            .ok_or(EmbeddedGitError::RepositoryUnavailable)?
            .to_path_buf();
        let root =
            std::fs::canonicalize(root).map_err(|_| EmbeddedGitError::RepositoryUnavailable)?;
        Ok(Self { repository, root })
    }

    pub(crate) fn root(&self) -> &Path {
        self.root.as_path()
    }

    pub(crate) const fn repository(&self) -> &gix::Repository {
        &self.repository
    }

    pub(crate) fn head(&self) -> Result<GitSha, EmbeddedGitError> {
        let id = self
            .repository
            .rev_parse_single("HEAD")
            .map_err(|_| EmbeddedGitError::CommitUnavailable)?;
        self.commit_sha(id.detach())
    }

    pub(crate) fn resolve_commit(&self, reference: &str) -> Result<GitSha, EmbeddedGitError> {
        let id = self
            .repository
            .rev_parse_single(reference)
            .map_err(|_| EmbeddedGitError::ReferenceUnavailable)?;
        self.commit_sha(id.detach())
    }

    pub(crate) fn merge_base(
        &self,
        base: &GitSha,
        head: &GitSha,
    ) -> Result<GitSha, EmbeddedGitError> {
        let base = object_id(base)?;
        let head = object_id(head)?;
        let id = self
            .repository
            .merge_base(base, head)
            .map_err(|_| EmbeddedGitError::HistoryUnavailable)?;
        git_sha(id.detach())
    }

    pub(crate) fn remote_urls(&self) -> Result<BTreeMap<String, String>, EmbeddedGitError> {
        let mut remotes = BTreeMap::new();
        for name in self.repository.remote_names() {
            let name = name
                .to_str()
                .map_err(|_| EmbeddedGitError::InvalidPath)?
                .to_owned();
            let remote = self
                .repository
                .try_find_remote_without_url_rewrite(name.as_bytes().as_bstr())
                .ok_or(EmbeddedGitError::ReferenceUnavailable)?
                .map_err(|_| EmbeddedGitError::ReferenceUnavailable)?;
            let Some(url) = remote.url(gix::remote::Direction::Fetch) else {
                continue;
            };
            let value = url
                .to_bstring()
                .to_str()
                .map_err(|_| EmbeddedGitError::InvalidPath)?
                .to_owned();
            remotes.insert(name, value);
        }
        Ok(remotes)
    }

    pub(crate) fn symbolic_reference(&self, name: &str) -> Option<String> {
        let reference = self.repository.try_find_reference(name).ok()??;
        reference
            .target()
            .try_name()
            .and_then(|name| name.shorten().to_str().ok())
            .map(str::to_owned)
    }

    pub(crate) fn root_commits(&self, head: &GitSha) -> Result<Vec<GitSha>, EmbeddedGitError> {
        let head = object_id(head)?;
        let walk = self
            .repository
            .rev_walk([head])
            .use_commit_graph(false)
            .all()
            .map_err(|_| EmbeddedGitError::HistoryUnavailable)?;
        let mut roots = Vec::new();
        for item in walk {
            let id = item.map_err(|_| EmbeddedGitError::HistoryUnavailable)?.id;
            let commit = self
                .repository
                .find_commit(id)
                .map_err(|_| EmbeddedGitError::CommitUnavailable)?;
            if commit.parent_ids().next().is_none() {
                roots.push(git_sha(id)?);
            }
        }
        roots.sort_unstable();
        roots.dedup();
        if roots.is_empty() {
            return Err(EmbeddedGitError::HistoryUnavailable);
        }
        Ok(roots)
    }

    pub(crate) fn read_file_at_commit(
        &self,
        commit: &GitSha,
        path: &RepositoryRelativePath,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>, EmbeddedGitError> {
        let commit = self
            .repository
            .find_commit(object_id(commit)?)
            .map_err(|_| EmbeddedGitError::CommitUnavailable)?;
        let tree = commit
            .tree()
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        let entry = tree
            .lookup_entry(path.as_str().split('/'))
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        if !entry.mode().is_blob() {
            return Ok(None);
        }
        let header = self
            .repository
            .find_header(entry.id())
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        if header.size() > maximum {
            return Err(EmbeddedGitError::ObjectTooLarge);
        }
        let mut blob = entry
            .object()
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?
            .try_into_blob()
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        Ok(Some(blob.take_data()))
    }

    pub(crate) fn base_files(
        &self,
        commit: &GitSha,
    ) -> Result<BTreeMap<RepositoryRelativePath, gix::ObjectId>, EmbeddedGitError> {
        let commit = self
            .repository
            .find_commit(object_id(commit)?)
            .map_err(|_| EmbeddedGitError::CommitUnavailable)?;
        let tree = commit
            .tree()
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        let entries = tree
            .traverse()
            .breadthfirst
            .files()
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        if entries.len() > MAX_REPOSITORY_PATHS {
            return Err(EmbeddedGitError::PathLimit);
        }
        entries
            .into_iter()
            .filter(|entry| entry.mode.is_blob())
            .map(|entry| {
                let path = entry
                    .filepath
                    .to_str()
                    .map_err(|_| EmbeddedGitError::InvalidPath)?;
                let path = RepositoryRelativePath::try_from(path.to_owned())
                    .map_err(|_| EmbeddedGitError::InvalidPath)?;
                Ok((path, entry.oid))
            })
            .collect()
    }

    pub(crate) fn working_paths(
        &self,
    ) -> Result<BTreeSet<RepositoryRelativePath>, EmbeddedGitError> {
        let index = self
            .repository
            .index_or_empty()
            .map_err(|_| EmbeddedGitError::IndexUnavailable)?;
        let mut paths = BTreeSet::new();
        for entry in index.entries() {
            if entry.stage() != gix::index::entry::Stage::Unconflicted {
                return Err(EmbeddedGitError::Conflict);
            }
            let path = entry.path(&index);
            let path = path.to_str().map_err(|_| EmbeddedGitError::InvalidPath)?;
            let path = RepositoryRelativePath::try_from(path.to_owned())
                .map_err(|_| EmbeddedGitError::InvalidPath)?;
            if self.root.join(path.as_str()).is_file() {
                paths.insert(path);
            }
            if paths.len() > MAX_REPOSITORY_PATHS {
                return Err(EmbeddedGitError::PathLimit);
            }
        }

        let options = self
            .repository
            .dirwalk_options()
            .map_err(|_| EmbeddedGitError::StatusUnavailable)?
            .emit_untracked(gix::dir::walk::EmissionMode::Matching)
            .emit_tracked(false);
        let mut entries = gix::dir::walk::delegate::Collect::default();
        self.repository
            .dirwalk(
                &index,
                Vec::<gix::bstr::BString>::new(),
                &AtomicBool::new(false),
                options,
                &mut entries,
            )
            .map_err(|_| EmbeddedGitError::StatusUnavailable)?;
        for (entry, _) in entries.into_entries_by_path() {
            if entry.status != gix::dir::entry::Status::Untracked {
                continue;
            }
            let path = entry
                .rela_path
                .to_str()
                .map_err(|_| EmbeddedGitError::InvalidPath)?;
            let path = RepositoryRelativePath::try_from(path.to_owned())
                .map_err(|_| EmbeddedGitError::InvalidPath)?;
            if self.root.join(path.as_str()).is_file() {
                paths.insert(path);
            }
            if paths.len() > MAX_REPOSITORY_PATHS {
                return Err(EmbeddedGitError::PathLimit);
            }
        }
        Ok(paths)
    }

    pub(crate) fn object_bytes(
        &self,
        id: gix::ObjectId,
        maximum: u64,
    ) -> Result<Vec<u8>, EmbeddedGitError> {
        let header = self
            .repository
            .find_header(id)
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        if header.kind() != gix::objs::Kind::Blob {
            return Err(EmbeddedGitError::ObjectUnavailable);
        }
        if header.size() > maximum.min(MAX_BLOB_BYTES) {
            return Err(EmbeddedGitError::ObjectTooLarge);
        }
        let mut blob = self
            .repository
            .find_blob(id)
            .map_err(|_| EmbeddedGitError::ObjectUnavailable)?;
        Ok(blob.take_data())
    }

    fn commit_sha(&self, id: gix::ObjectId) -> Result<GitSha, EmbeddedGitError> {
        self.repository
            .find_commit(id)
            .map_err(|_| EmbeddedGitError::CommitUnavailable)?;
        git_sha(id)
    }
}

pub(crate) fn safe_open_options() -> gix::open::Options {
    gix::open::Options::isolated()
        .bail_if_untrusted(true)
        .strict_config(true)
}

pub(crate) fn object_id(sha: &GitSha) -> Result<gix::ObjectId, EmbeddedGitError> {
    gix::ObjectId::from_hex(sha.as_str().as_bytes())
        .map_err(|_| EmbeddedGitError::UnsupportedObjectFormat)
}

pub(crate) fn git_sha(id: gix::ObjectId) -> Result<GitSha, EmbeddedGitError> {
    GitSha::try_from(id.to_string()).map_err(|_| EmbeddedGitError::UnsupportedObjectFormat)
}
