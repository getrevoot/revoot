//! Small deterministic execution-graph contracts for the internal reviewer.
//!
//! The graph is deliberately not a general workflow language. Plans are built
//! by trusted Revoot code, nodes use a closed vocabulary, and the runtime owns
//! only dependency scheduling, bounded transitions, reduction, and evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

const MAX_NODE_ID_BYTES: usize = 128;
const HARD_MAX_NODES: u32 = 256;
const HARD_MAX_EVENTS: u32 = 2_048;
const HARD_MAX_PARALLEL_NODES: u32 = 32;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ExecutionNodeId(String);

impl ExecutionNodeId {
    /// Construct a bounded, log-safe node identity.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-canonical identifiers.
    pub fn try_new(value: impl Into<String>) -> Result<Self, ExecutionGraphError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_NODE_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(ExecutionGraphError::InvalidNodeId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionNodeKind {
    ReviewPreparation,
    Investigation,
    CandidateVerification,
    Adjudication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGraphLimits {
    pub max_nodes: u32,
    pub max_events: u32,
    pub max_parallel_nodes: u32,
}

impl Default for ExecutionGraphLimits {
    fn default() -> Self {
        Self {
            max_nodes: 32,
            max_events: 256,
            max_parallel_nodes: 8,
        }
    }
}

impl ExecutionGraphLimits {
    const fn validate(self) -> Result<(), ExecutionGraphError> {
        if self.max_nodes == 0 || self.max_nodes > HARD_MAX_NODES {
            return Err(ExecutionGraphError::InvalidLimits);
        }
        if self.max_events == 0 || self.max_events > HARD_MAX_EVENTS {
            return Err(ExecutionGraphError::InvalidLimits);
        }
        if self.max_parallel_nodes == 0
            || self.max_parallel_nodes > HARD_MAX_PARALLEL_NODES
            || self.max_parallel_nodes > self.max_nodes
        {
            return Err(ExecutionGraphError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionNodeSpec {
    pub id: ExecutionNodeId,
    pub kind: ExecutionNodeKind,
    pub dependencies: BTreeSet<ExecutionNodeId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionGraphPlan {
    nodes: BTreeMap<ExecutionNodeId, ExecutionNodeSpec>,
    limits: ExecutionGraphLimits,
}

impl ExecutionGraphPlan {
    /// Validate and compile one trusted acyclic graph.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, duplicate/missing/self dependencies, cycles,
    /// empty plans, or plans that cannot record start and completion events.
    pub fn try_new(
        nodes: impl IntoIterator<Item = ExecutionNodeSpec>,
        limits: ExecutionGraphLimits,
    ) -> Result<Self, ExecutionGraphError> {
        limits.validate()?;
        let mut compiled = BTreeMap::new();
        for node in nodes {
            if compiled.insert(node.id.clone(), node).is_some() {
                return Err(ExecutionGraphError::DuplicateNode);
            }
        }
        if compiled.is_empty()
            || compiled.len() > limits.max_nodes as usize
            || compiled
                .len()
                .checked_mul(2)
                .is_none_or(|minimum| minimum > limits.max_events as usize)
        {
            return Err(ExecutionGraphError::InvalidLimits);
        }
        for node in compiled.values() {
            if node.dependencies.contains(&node.id) {
                return Err(ExecutionGraphError::SelfDependency);
            }
            if node
                .dependencies
                .iter()
                .any(|dependency| !compiled.contains_key(dependency))
            {
                return Err(ExecutionGraphError::MissingDependency);
            }
        }
        validate_acyclic(&compiled)?;
        Ok(Self {
            nodes: compiled,
            limits,
        })
    }

    #[must_use]
    pub const fn limits(&self) -> ExecutionGraphLimits {
        self.limits
    }

    #[must_use]
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = &ExecutionNodeSpec> {
        self.nodes.values()
    }
}

fn validate_acyclic(
    nodes: &BTreeMap<ExecutionNodeId, ExecutionNodeSpec>,
) -> Result<(), ExecutionGraphError> {
    let mut remaining = nodes
        .iter()
        .map(|(id, node)| (id.clone(), node.dependencies.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = remaining
        .iter()
        .filter(|(_, dependencies)| dependencies.is_empty())
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let mut visited = 0_usize;
    while let Some(id) = ready.pop_first() {
        visited = visited.saturating_add(1);
        remaining.remove(&id);
        for (candidate, dependencies) in &mut remaining {
            if dependencies.remove(&id) && dependencies.is_empty() {
                ready.insert(candidate.clone());
            }
        }
    }
    if visited == nodes.len() {
        Ok(())
    } else {
        Err(ExecutionGraphError::Cycle)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionNodeState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionFact {
    RequestValidated,
    RepositoryInspected,
    DiffInspected,
    CandidateAdmitted,
    CandidateSuppressed,
    SummarySubmitted,
    OutcomeFinalized,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGraphUsage {
    pub model_turns: u32,
    pub tool_calls: u32,
    pub admitted_candidates: u32,
    pub suppressed_candidates: u32,
}

impl ExecutionGraphUsage {
    fn checked_add(self, other: Self) -> Result<Self, ExecutionGraphError> {
        Ok(Self {
            model_turns: self
                .model_turns
                .checked_add(other.model_turns)
                .ok_or(ExecutionGraphError::UsageOverflow)?,
            tool_calls: self
                .tool_calls
                .checked_add(other.tool_calls)
                .ok_or(ExecutionGraphError::UsageOverflow)?,
            admitted_candidates: self
                .admitted_candidates
                .checked_add(other.admitted_candidates)
                .ok_or(ExecutionGraphError::UsageOverflow)?,
            suppressed_candidates: self
                .suppressed_candidates
                .checked_add(other.suppressed_candidates)
                .ok_or(ExecutionGraphError::UsageOverflow)?,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionNodeContribution {
    pub facts: BTreeSet<ExecutionFact>,
    pub usage: ExecutionGraphUsage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionGraphEventKind {
    Started,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGraphEvent {
    pub sequence: u32,
    pub node_id: ExecutionNodeId,
    pub kind: ExecutionGraphEventKind,
    pub observed_at_millis: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGraphSummary {
    pub node_count: u32,
    pub completed_nodes: u32,
    pub failed_nodes: u32,
    pub cancelled_nodes: u32,
    pub event_count: u32,
    pub facts: BTreeSet<ExecutionFact>,
    pub usage: ExecutionGraphUsage,
}

pub struct ExecutionGraph {
    plan: ExecutionGraphPlan,
    states: BTreeMap<ExecutionNodeId, ExecutionNodeState>,
    events: Vec<ExecutionGraphEvent>,
    facts: BTreeSet<ExecutionFact>,
    usage: ExecutionGraphUsage,
    last_observed_millis: u64,
}

impl ExecutionGraph {
    #[must_use]
    pub fn new(plan: ExecutionGraphPlan, started_at_millis: u64) -> Self {
        let states = plan
            .nodes
            .keys()
            .cloned()
            .map(|id| (id, ExecutionNodeState::Pending))
            .collect();
        Self {
            plan,
            states,
            events: Vec::new(),
            facts: BTreeSet::new(),
            usage: ExecutionGraphUsage::default(),
            last_observed_millis: started_at_millis,
        }
    }

    /// Return currently runnable nodes in canonical order and within the
    /// configured parallelism cap.
    #[must_use]
    pub fn ready_nodes(&self) -> Vec<ExecutionNodeId> {
        let running = self
            .states
            .values()
            .filter(|state| **state == ExecutionNodeState::Running)
            .count();
        let capacity = (self.plan.limits.max_parallel_nodes as usize).saturating_sub(running);
        self.plan
            .nodes
            .values()
            .filter(|node| {
                self.states.get(&node.id) == Some(&ExecutionNodeState::Pending)
                    && node.dependencies.iter().all(|dependency| {
                        self.states.get(dependency) == Some(&ExecutionNodeState::Completed)
                    })
            })
            .take(capacity)
            .map(|node| node.id.clone())
            .collect()
    }

    /// Begin one ready node.
    ///
    /// # Errors
    ///
    /// Rejects unknown, non-ready, over-parallel, time-regressing, or
    /// event-exhausting transitions.
    pub fn start(
        &mut self,
        id: &ExecutionNodeId,
        now_millis: u64,
    ) -> Result<(), ExecutionGraphError> {
        if !self.ready_nodes().contains(id) {
            return Err(ExecutionGraphError::NodeNotReady);
        }
        self.transition(
            id,
            ExecutionNodeState::Running,
            ExecutionGraphEventKind::Started,
            now_millis,
        )
    }

    /// Complete one running node and deterministically reduce its contribution.
    ///
    /// # Errors
    ///
    /// Rejects invalid transitions, time regression, event exhaustion, or
    /// accounting overflow.
    pub fn complete(
        &mut self,
        id: &ExecutionNodeId,
        contribution: ExecutionNodeContribution,
        now_millis: u64,
    ) -> Result<(), ExecutionGraphError> {
        if self.states.get(id) != Some(&ExecutionNodeState::Running) {
            return Err(ExecutionGraphError::NodeNotRunning);
        }
        let usage = self.usage.checked_add(contribution.usage)?;
        self.transition(
            id,
            ExecutionNodeState::Completed,
            ExecutionGraphEventKind::Completed,
            now_millis,
        )?;
        self.usage = usage;
        self.facts.extend(contribution.facts);
        Ok(())
    }

    /// Mark one running node failed without retaining a provider or tool payload.
    ///
    /// # Errors
    ///
    /// Rejects invalid transitions, time regression, or event exhaustion.
    pub fn fail(
        &mut self,
        id: &ExecutionNodeId,
        now_millis: u64,
    ) -> Result<(), ExecutionGraphError> {
        if self.states.get(id) != Some(&ExecutionNodeState::Running) {
            return Err(ExecutionGraphError::NodeNotRunning);
        }
        self.transition(
            id,
            ExecutionNodeState::Failed,
            ExecutionGraphEventKind::Failed,
            now_millis,
        )
    }

    /// Cancel every pending or running node in canonical order.
    ///
    /// # Errors
    ///
    /// Rejects time regression or event-budget exhaustion.
    pub fn cancel_remaining(&mut self, now_millis: u64) -> Result<(), ExecutionGraphError> {
        let ids = self
            .states
            .iter()
            .filter(|(_, state)| {
                matches!(
                    state,
                    ExecutionNodeState::Pending | ExecutionNodeState::Running
                )
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            self.transition(
                &id,
                ExecutionNodeState::Cancelled,
                ExecutionGraphEventKind::Cancelled,
                now_millis,
            )?;
        }
        Ok(())
    }

    fn transition(
        &mut self,
        id: &ExecutionNodeId,
        state: ExecutionNodeState,
        kind: ExecutionGraphEventKind,
        now_millis: u64,
    ) -> Result<(), ExecutionGraphError> {
        if now_millis < self.last_observed_millis {
            return Err(ExecutionGraphError::ClockRegression);
        }
        if self.events.len() >= self.plan.limits.max_events as usize {
            return Err(ExecutionGraphError::EventBudget);
        }
        let selected = self
            .states
            .get_mut(id)
            .ok_or(ExecutionGraphError::UnknownNode)?;
        *selected = state;
        self.last_observed_millis = now_millis;
        self.events.push(ExecutionGraphEvent {
            sequence: u32::try_from(self.events.len() + 1)
                .map_err(|_| ExecutionGraphError::EventBudget)?,
            node_id: id.clone(),
            kind,
            observed_at_millis: now_millis,
        });
        Ok(())
    }

    #[must_use]
    pub fn state(&self, id: &ExecutionNodeId) -> Option<ExecutionNodeState> {
        self.states.get(id).copied()
    }

    #[must_use]
    pub fn journal(&self) -> &[ExecutionGraphEvent] {
        &self.events
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.states
            .values()
            .all(|state| *state == ExecutionNodeState::Completed)
    }

    #[must_use]
    pub fn summary(&self) -> ExecutionGraphSummary {
        ExecutionGraphSummary {
            node_count: u32::try_from(self.states.len()).unwrap_or(u32::MAX),
            completed_nodes: count_state(&self.states, ExecutionNodeState::Completed),
            failed_nodes: count_state(&self.states, ExecutionNodeState::Failed),
            cancelled_nodes: count_state(&self.states, ExecutionNodeState::Cancelled),
            event_count: u32::try_from(self.events.len()).unwrap_or(u32::MAX),
            facts: self.facts.clone(),
            usage: self.usage,
        }
    }
}

fn count_state(
    states: &BTreeMap<ExecutionNodeId, ExecutionNodeState>,
    selected: ExecutionNodeState,
) -> u32 {
    u32::try_from(states.values().filter(|state| **state == selected).count()).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionGraphError {
    InvalidNodeId,
    InvalidLimits,
    DuplicateNode,
    MissingDependency,
    SelfDependency,
    Cycle,
    UnknownNode,
    NodeNotReady,
    NodeNotRunning,
    ClockRegression,
    EventBudget,
    UsageOverflow,
}

impl fmt::Display for ExecutionGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("review execution graph transition failed")
    }
}

impl std::error::Error for ExecutionGraphError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> ExecutionNodeId {
        ExecutionNodeId::try_new(value).expect("node id")
    }

    fn node(value: &str, dependencies: &[&str]) -> ExecutionNodeSpec {
        ExecutionNodeSpec {
            id: id(value),
            kind: ExecutionNodeKind::Investigation,
            dependencies: dependencies.iter().map(|value| id(value)).collect(),
        }
    }

    #[test]
    fn plan_rejects_missing_dependencies_cycles_and_event_underprovisioning() {
        assert_eq!(
            ExecutionGraphPlan::try_new([node("a", &["missing"])], ExecutionGraphLimits::default()),
            Err(ExecutionGraphError::MissingDependency)
        );
        assert_eq!(
            ExecutionGraphPlan::try_new(
                [node("a", &["b"]), node("b", &["a"])],
                ExecutionGraphLimits::default()
            ),
            Err(ExecutionGraphError::Cycle)
        );
        assert_eq!(
            ExecutionGraphPlan::try_new(
                [node("a", &[]), node("b", &[])],
                ExecutionGraphLimits {
                    max_nodes: 2,
                    max_events: 3,
                    max_parallel_nodes: 2,
                }
            ),
            Err(ExecutionGraphError::InvalidLimits)
        );
    }

    #[test]
    fn parallel_readiness_and_reduction_are_canonical() {
        let plan = ExecutionGraphPlan::try_new(
            [
                node("prepare", &[]),
                node("inspect:b", &["prepare"]),
                node("inspect:a", &["prepare"]),
                node("adjudicate", &["inspect:a", "inspect:b"]),
            ],
            ExecutionGraphLimits {
                max_nodes: 4,
                max_events: 8,
                max_parallel_nodes: 2,
            },
        )
        .expect("plan");
        let mut graph = ExecutionGraph::new(plan, 10);
        assert_eq!(graph.ready_nodes(), vec![id("prepare")]);
        graph.start(&id("prepare"), 10).expect("start");
        graph
            .complete(
                &id("prepare"),
                ExecutionNodeContribution {
                    facts: BTreeSet::from([ExecutionFact::RequestValidated]),
                    usage: ExecutionGraphUsage::default(),
                },
                11,
            )
            .expect("complete");
        assert_eq!(graph.ready_nodes(), vec![id("inspect:a"), id("inspect:b")]);
        graph.start(&id("inspect:b"), 12).expect("start b");
        graph.start(&id("inspect:a"), 12).expect("start a");
        graph
            .complete(
                &id("inspect:b"),
                ExecutionNodeContribution {
                    facts: BTreeSet::from([ExecutionFact::DiffInspected]),
                    usage: ExecutionGraphUsage {
                        tool_calls: 2,
                        ..ExecutionGraphUsage::default()
                    },
                },
                13,
            )
            .expect("complete b");
        graph
            .complete(
                &id("inspect:a"),
                ExecutionNodeContribution {
                    facts: BTreeSet::from([ExecutionFact::RepositoryInspected]),
                    usage: ExecutionGraphUsage {
                        tool_calls: 3,
                        ..ExecutionGraphUsage::default()
                    },
                },
                14,
            )
            .expect("complete a");
        assert_eq!(graph.ready_nodes(), vec![id("adjudicate")]);
        let summary = graph.summary();
        assert_eq!(summary.usage.tool_calls, 5);
        assert_eq!(
            summary.facts,
            BTreeSet::from([
                ExecutionFact::RequestValidated,
                ExecutionFact::RepositoryInspected,
                ExecutionFact::DiffInspected,
            ])
        );
    }

    #[test]
    fn cancellation_and_failure_are_bounded_payload_free_events() {
        let plan = ExecutionGraphPlan::try_new(
            [node("a", &[]), node("b", &["a"])],
            ExecutionGraphLimits {
                max_nodes: 2,
                max_events: 4,
                max_parallel_nodes: 1,
            },
        )
        .expect("plan");
        let mut failed = ExecutionGraph::new(plan.clone(), 1);
        failed.start(&id("a"), 1).expect("start");
        failed.fail(&id("a"), 2).expect("fail");
        assert!(failed.ready_nodes().is_empty());
        assert_eq!(failed.summary().failed_nodes, 1);

        let mut cancelled = ExecutionGraph::new(plan, 1);
        cancelled.start(&id("a"), 1).expect("start");
        cancelled.cancel_remaining(2).expect("cancel");
        assert_eq!(cancelled.summary().cancelled_nodes, 2);
        assert_eq!(cancelled.journal().len(), 3);
        assert_eq!(
            format!("{:?}", ExecutionGraphError::NodeNotReady),
            "NodeNotReady"
        );
    }

    #[test]
    fn bounded_fanout_reduces_canonically_across_supported_widths() {
        for width in 1_u32..=8 {
            let root = id("root");
            let terminal = id("terminal");
            let branches = (0..width)
                .map(|index| id(&format!("branch-{index:02}")))
                .collect::<Vec<_>>();
            let mut nodes = vec![ExecutionNodeSpec {
                id: root.clone(),
                kind: ExecutionNodeKind::ReviewPreparation,
                dependencies: BTreeSet::new(),
            }];
            nodes.extend(branches.iter().cloned().map(|branch| ExecutionNodeSpec {
                id: branch,
                kind: ExecutionNodeKind::Investigation,
                dependencies: BTreeSet::from([root.clone()]),
            }));
            nodes.push(ExecutionNodeSpec {
                id: terminal.clone(),
                kind: ExecutionNodeKind::Adjudication,
                dependencies: branches.iter().cloned().collect(),
            });
            let node_count = width.saturating_add(2);
            let plan = ExecutionGraphPlan::try_new(
                nodes,
                ExecutionGraphLimits {
                    max_nodes: node_count,
                    max_events: node_count.saturating_mul(2),
                    max_parallel_nodes: width,
                },
            )
            .expect("generated acyclic fanout");
            let mut graph = ExecutionGraph::new(plan, 1);
            graph.start(&root, 1).expect("root starts");
            graph
                .complete(&root, ExecutionNodeContribution::default(), 2)
                .expect("root completes");
            assert_eq!(graph.ready_nodes(), branches);
            let mut now = 3;
            for branch in branches.iter().rev() {
                graph.start(branch, now).expect("branch starts");
                now += 1;
                graph
                    .complete(
                        branch,
                        ExecutionNodeContribution {
                            facts: BTreeSet::from([ExecutionFact::RepositoryInspected]),
                            usage: ExecutionGraphUsage {
                                tool_calls: 1,
                                ..ExecutionGraphUsage::default()
                            },
                        },
                        now,
                    )
                    .expect("branch completes");
                now += 1;
            }
            assert_eq!(graph.ready_nodes(), vec![terminal.clone()]);
            graph.start(&terminal, now).expect("terminal starts");
            now += 1;
            graph
                .complete(&terminal, ExecutionNodeContribution::default(), now)
                .expect("terminal completes");
            assert!(graph.is_complete());
            assert_eq!(graph.summary().usage.tool_calls, width);
            assert_eq!(graph.summary().event_count, node_count.saturating_mul(2));
        }
    }
}
