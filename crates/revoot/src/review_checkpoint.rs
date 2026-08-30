//! Host-embedded review checkpoints used only to prioritize reviewer attention.
//!
//! Change-request descriptions are author-editable, so checkpoint metadata is
//! never authority to omit code. A checkpoint is accepted only after local
//! ancestry and tree-delta verification, and the full authoritative change
//! remains available to the reviewer.

use std::collections::BTreeSet;

use revoot_core::{GitSha, RepositoryRelativePath, Sha256Digest};

use crate::embedded_git::EmbeddedRepository;
use crate::review_engine::REVIEWER_POLICY_VERSION;
use crate::review_overview::{OVERVIEW_END, OVERVIEW_START};

const PREFIX: &str = "<!-- revoot:checkpoint:v1 ";
const SUFFIX: &str = " -->";
const MAX_INCREMENTAL_GENERATION: u8 = 2;
const MAX_DELTA_PATHS: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewCheckpoint {
    pub base: GitSha,
    pub head: GitSha,
    pub manifest: Sha256Digest,
    pub policy: Sha256Digest,
    pub complete: bool,
    pub generation: u8,
}

impl ReviewCheckpoint {
    #[must_use]
    pub fn current(
        base: GitSha,
        head: GitSha,
        manifest: Sha256Digest,
        complete: bool,
        generation: u8,
    ) -> Self {
        Self {
            base,
            head,
            manifest,
            policy: current_policy_digest(),
            complete,
            generation,
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{PREFIX}base={} head={} manifest={} policy={} complete={} generation={}{SUFFIX}",
            self.base.as_str(),
            self.head.as_str(),
            self.manifest.as_str(),
            self.policy.as_str(),
            self.complete,
            self.generation,
        )
    }

    fn parse(value: &str) -> Option<Self> {
        let content = value.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
        let mut fields = content.split(' ');
        let base = fields.next()?.strip_prefix("base=")?;
        let head = fields.next()?.strip_prefix("head=")?;
        let manifest = fields.next()?.strip_prefix("manifest=")?;
        let policy = fields.next()?.strip_prefix("policy=")?;
        let complete = fields.next()?.strip_prefix("complete=")?;
        let generation = fields.next()?.strip_prefix("generation=")?;
        if fields.next().is_some() {
            return None;
        }
        Some(Self {
            base: GitSha::try_from(base.to_owned()).ok()?,
            head: GitSha::try_from(head.to_owned()).ok()?,
            manifest: Sha256Digest::try_from(manifest.to_owned()).ok()?,
            policy: Sha256Digest::try_from(policy.to_owned()).ok()?,
            complete: match complete {
                "true" => true,
                "false" => false,
                _ => return None,
            },
            generation: generation.parse().ok()?,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ReviewAttention {
    #[default]
    Full,
    Incremental {
        previous_head: GitSha,
        delta_paths: Vec<RepositoryRelativePath>,
        generation: u8,
    },
}

impl ReviewAttention {
    #[must_use]
    pub const fn next_generation(&self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Incremental { generation, .. } => generation.saturating_add(1),
        }
    }
}

#[must_use]
pub fn extract_checkpoint(description: &str) -> Option<ReviewCheckpoint> {
    let start = description
        .match_indices(OVERVIEW_START)
        .collect::<Vec<_>>();
    let end = description.match_indices(OVERVIEW_END).collect::<Vec<_>>();
    let ([(start, _)], [(end, _)]) = (start.as_slice(), end.as_slice()) else {
        return None;
    };
    if start >= end {
        return None;
    }
    let owned = &description[*start..end.saturating_add(OVERVIEW_END.len())];
    let markers = owned
        .lines()
        .filter(|line| line.starts_with(PREFIX))
        .collect::<Vec<_>>();
    let [marker] = markers.as_slice() else {
        return None;
    };
    ReviewCheckpoint::parse(marker)
}

#[must_use]
pub fn plan_attention(
    root: &std::path::Path,
    base: &GitSha,
    head: &GitSha,
    current_paths: &BTreeSet<RepositoryRelativePath>,
    checkpoint: Option<&ReviewCheckpoint>,
) -> ReviewAttention {
    let Some(checkpoint) = checkpoint else {
        return ReviewAttention::Full;
    };
    if !checkpoint.complete
        || checkpoint.base != *base
        || checkpoint.policy != current_policy_digest()
        || checkpoint.generation >= MAX_INCREMENTAL_GENERATION
        || checkpoint.head == *head
    {
        return ReviewAttention::Full;
    }
    let Ok(repository) = EmbeddedRepository::discover(root) else {
        return ReviewAttention::Full;
    };
    if repository.merge_base(&checkpoint.head, head).ok().as_ref() != Some(&checkpoint.head) {
        return ReviewAttention::Full;
    }
    let (Ok(previous), Ok(current)) = (
        repository.base_files(&checkpoint.head),
        repository.base_files(head),
    ) else {
        return ReviewAttention::Full;
    };
    let mut candidates = previous
        .keys()
        .chain(current.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    candidates
        .retain(|path| previous.get(path) != current.get(path) && current_paths.contains(path));
    if candidates.is_empty() || candidates.len() > MAX_DELTA_PATHS {
        return ReviewAttention::Full;
    }
    ReviewAttention::Incremental {
        previous_head: checkpoint.head.clone(),
        delta_paths: candidates.into_iter().collect(),
        generation: checkpoint.generation,
    }
}

#[must_use]
pub fn current_policy_digest() -> Sha256Digest {
    Sha256Digest::of_bytes(REVIEWER_POLICY_VERSION.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn sha(marker: char) -> GitSha {
        GitSha::try_from(marker.to_string().repeat(40)).unwrap()
    }

    #[test]
    fn checkpoint_round_trips_only_inside_one_owned_overview() {
        let checkpoint = ReviewCheckpoint::current(
            sha('a'),
            sha('b'),
            Sha256Digest::of_bytes(b"manifest"),
            true,
            1,
        );
        let description = format!(
            "author\n{OVERVIEW_START}\n{}\n{OVERVIEW_END}",
            checkpoint.render()
        );
        assert_eq!(extract_checkpoint(&description), Some(checkpoint));
        assert!(extract_checkpoint(&format!("{description}\n{description}")).is_none());
    }

    #[test]
    fn incomplete_wrong_policy_and_periodic_checkpoints_force_full_attention() {
        let base = sha('a');
        let head = sha('b');
        let manifest = Sha256Digest::of_bytes(b"manifest");
        let mut checkpoint = ReviewCheckpoint::current(base.clone(), sha('c'), manifest, false, 0);
        assert_eq!(
            plan_attention(
                std::path::Path::new("."),
                &base,
                &head,
                &BTreeSet::new(),
                Some(&checkpoint)
            ),
            ReviewAttention::Full
        );
        checkpoint.complete = true;
        checkpoint.policy = Sha256Digest::of_bytes(b"old-policy");
        assert_eq!(
            plan_attention(
                std::path::Path::new("."),
                &base,
                &head,
                &BTreeSet::new(),
                Some(&checkpoint)
            ),
            ReviewAttention::Full
        );
        checkpoint.policy = current_policy_digest();
        checkpoint.generation = MAX_INCREMENTAL_GENERATION;
        assert_eq!(
            plan_attention(
                std::path::Path::new("."),
                &base,
                &head,
                &BTreeSet::new(),
                Some(&checkpoint)
            ),
            ReviewAttention::Full
        );
    }

    #[test]
    fn verified_descendant_checkpoint_prioritizes_only_the_tree_delta() {
        let root = std::env::temp_dir().join(format!(
            "revoot-checkpoint-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        for arguments in [
            &["init", "-b", "main"][..],
            &["config", "user.email", "revoot@example.invalid"][..],
            &["config", "user.name", "Revoot Test"][..],
            &["config", "commit.gpgsign", "false"][..],
        ] {
            git(&root, arguments);
        }
        fs::write(root.join("src/old.rs"), "old\n").unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-m", "base"]);
        let base = rev(&root, "HEAD");
        fs::write(root.join("src/old.rs"), "reviewed\n").unwrap();
        git(&root, &["commit", "-am", "reviewed"]);
        let reviewed = rev(&root, "HEAD");
        fs::write(root.join("src/new.rs"), "new\n").unwrap();
        git(&root, &["add", "."]);
        git(&root, &["commit", "-m", "new delta"]);
        let head = rev(&root, "HEAD");
        let checkpoint = ReviewCheckpoint::current(
            base.clone(),
            reviewed.clone(),
            Sha256Digest::of_bytes(b"prior-manifest"),
            true,
            0,
        );
        let paths = ["src/old.rs", "src/new.rs"]
            .into_iter()
            .map(|path| RepositoryRelativePath::try_from(path.to_owned()).unwrap())
            .collect();
        assert_eq!(
            plan_attention(&root, &base, &head, &paths, Some(&checkpoint)),
            ReviewAttention::Incremental {
                previous_head: reviewed,
                delta_paths: vec![
                    RepositoryRelativePath::try_from("src/new.rs".to_owned()).unwrap()
                ],
                generation: 0,
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn git(root: &std::path::Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(arguments)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }

    fn rev(root: &std::path::Path, revision: &str) -> GitSha {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", revision])
            .output()
            .unwrap();
        assert!(output.status.success());
        GitSha::try_from(String::from_utf8(output.stdout).unwrap().trim().to_owned()).unwrap()
    }
}
