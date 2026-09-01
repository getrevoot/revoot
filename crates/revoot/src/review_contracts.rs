//! Provider-neutral result and runtime contracts shared by review surfaces.

use revoot_core::{ReviewEffort, ReviewGroupingSource, Sha256Digest};
use serde::{Deserialize, Serialize};

/// Public strategy metadata for one review execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStrategy {
    pub effort: ReviewEffort,
    pub grouping_source: ReviewGroupingSource,
    pub group_count: u32,
    pub max_parallel_groups: u8,
}

/// Deterministically computed review coverage accounting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCoverage {
    pub policy_version: &'static str,
    pub high_risk_files: u32,
    pub standard_risk_files: u32,
    pub low_risk_files: u32,
    pub fully_read_files: u32,
    pub sampled_files: u32,
    pub manifest_only_files: u32,
    pub delivered_high_risk_hunks: u32,
    pub required_high_risk_hunks: u32,
    pub explicit_deferrals: u32,
    pub failed_groups: u32,
}

/// Trusted final state of one prior finding lineage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorFindingDispositionKind {
    StillPresent,
    Fixed,
    Uncertain,
}

/// Evidence-bound disposition for one prior finding lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorFindingDisposition {
    pub lineage_id: Sha256Digest,
    pub disposition: PriorFindingDispositionKind,
    pub evidence: String,
}
