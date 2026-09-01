//! Trusted process adapters for Revoot.

#![forbid(unsafe_code)]

pub mod completion;
pub mod config;
pub mod credentials;
pub mod egress_setup;
mod embedded_git;
pub mod git_history;
pub mod github_checkout;
pub mod github_init;
pub mod github_review;
pub mod github_transport;
pub mod gitlab_checkout;
pub mod gitlab_ci_runtime;
pub mod gitlab_incremental;
pub mod gitlab_init;
pub mod gitlab_publication;
pub mod gitlab_review_context;
pub mod gitlab_snapshot;
pub mod gitlab_transport;
pub mod local_review;
pub mod prior_review;
pub mod providers;
pub(crate) mod retry;
pub mod review_checkpoint;
pub mod review_command;
pub mod review_engine;
pub mod review_overview;
