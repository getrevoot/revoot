//! Deterministic fake-provider transcripts for worker lifecycle tests.
//!
//! Transcripts store only typed control-flow events and numeric usage. They do
//! not retain prompts, responses, source, diff text, reasoning, or tool payloads.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ReviewEffort, Sha256Digest};

const MAX_EVENTS: usize = 1_024;
const MAX_BATCHED_TOOLS: usize = 32;
const MAX_VERIFIED_CANDIDATES: u32 = 25;
const MAX_GROUP_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTranscriptPlan {
    pub group_id: String,
    pub effort: ReviewEffort,
    pub planning_required: bool,
    pub verification_required: bool,
    pub adjudication_required: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptModelPhase {
    Planning,
    Review,
    Verification,
    Adjudication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptTool {
    DiffManifest,
    ReadDiff,
    SearchDiff,
    ReadFile,
    FindFiles,
    SearchCode,
    CommitHistory,
    PriorReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptPartialReason {
    BudgetExhausted,
    Cancelled,
    VerifierFailure,
    AdjudicatorFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum TranscriptTerminalOutcome {
    Complete,
    Partial { reason: TranscriptPartialReason },
}

/// Typed lifecycle event. Model events retain usage only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerTranscriptEvent {
    ModelCall {
        phase: TranscriptModelPhase,
        input_tokens: u64,
        output_tokens: u64,
        cost_microusd: u64,
    },
    PlanningCompleted,
    RoundStarted {
        round: u8,
    },
    ToolBatch {
        tools: Vec<TranscriptTool>,
    },
    CoverageCompletionRejected {
        missing_requirements: u32,
    },
    CoverageCorrected {
        delivered_requirements: u32,
    },
    RoundCompleted {
        round: u8,
    },
    VerifierSucceeded,
    VerifierFailed,
    AdjudicatorSucceeded,
    AdjudicatorFailedFallback {
        verified_candidates: u32,
    },
    BudgetExhausted,
    Cancelled,
    Finished {
        outcome: TranscriptTerminalOutcome,
    },
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTranscriptUsage {
    pub model_requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tool_calls: u32,
    pub cost_microusd: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTranscript {
    pub schema_version: String,
    pub plan: WorkerTranscriptPlan,
    pub events: Vec<WorkerTranscriptEvent>,
    pub usage: WorkerTranscriptUsage,
    pub transcript_sha256: Sha256Digest,
}

impl WorkerTranscript {
    pub const SCHEMA_VERSION: &'static str = "revoot.worker-transcript/v1";

    /// Replay every typed event and verify lifecycle, usage, and digest.
    ///
    /// # Errors
    ///
    /// Returns a payload-free structural, transition, usage, or digest error.
    pub fn validate(&self) -> Result<(), WorkerTranscriptError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(WorkerTranscriptError::SchemaVersion);
        }
        validate_plan(&self.plan)?;
        if self.events.is_empty() || self.events.len() > MAX_EVENTS {
            return Err(WorkerTranscriptError::EventCount);
        }
        let usage = replay(&self.plan, &self.events)?;
        if self.usage != usage {
            return Err(WorkerTranscriptError::Usage);
        }
        if self.transcript_sha256 != transcript_digest(self)? {
            return Err(WorkerTranscriptError::Digest);
        }
        Ok(())
    }

    /// Serialize a fully replayed transcript.
    ///
    /// # Errors
    ///
    /// Returns a validation or typed JSON serialization error.
    pub fn canonical_json(&self) -> Result<Vec<u8>, WorkerTranscriptError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| WorkerTranscriptError::Serialization)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerTranscriptError {
    SchemaVersion,
    Plan,
    EventCount,
    Transition,
    Planning,
    Round,
    ToolBatch,
    Coverage,
    Verification,
    Adjudication,
    Terminal,
    Overflow,
    Usage,
    Digest,
    Serialization,
}

impl fmt::Display for WorkerTranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "the worker transcript schema version is invalid",
            Self::Plan => "the worker transcript plan is invalid",
            Self::EventCount => "the worker transcript event count is invalid",
            Self::Transition => "the worker transcript contains an invalid transition",
            Self::Planning => "the worker planning transcript is invalid",
            Self::Round => "the worker round transcript is invalid",
            Self::ToolBatch => "the worker tool batch is invalid",
            Self::Coverage => "the worker coverage correction transcript is invalid",
            Self::Verification => "the worker verification transcript is invalid",
            Self::Adjudication => "the worker adjudication transcript is invalid",
            Self::Terminal => "the worker transcript terminal outcome is invalid",
            Self::Overflow => "worker transcript usage overflowed",
            Self::Usage => "worker transcript usage does not match its events",
            Self::Digest => "the worker transcript digest is invalid",
            Self::Serialization => "the worker transcript could not be serialized",
        })
    }
}

impl std::error::Error for WorkerTranscriptError {}

/// Build a canonical transcript and derive usage from its typed events.
///
/// # Errors
///
/// Rejects an invalid plan, excessive events, any lifecycle contradiction,
/// usage overflow, or serialization failure.
pub fn build_worker_transcript(
    plan: WorkerTranscriptPlan,
    events: Vec<WorkerTranscriptEvent>,
) -> Result<WorkerTranscript, WorkerTranscriptError> {
    validate_plan(&plan)?;
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err(WorkerTranscriptError::EventCount);
    }
    let usage = replay(&plan, &events)?;
    let mut transcript = WorkerTranscript {
        schema_version: WorkerTranscript::SCHEMA_VERSION.to_owned(),
        plan,
        events,
        usage,
        transcript_sha256: Sha256Digest::of_bytes(&[]),
    };
    transcript.transcript_sha256 = transcript_digest(&transcript)?;
    transcript.validate()?;
    Ok(transcript)
}

fn validate_plan(plan: &WorkerTranscriptPlan) -> Result<(), WorkerTranscriptError> {
    if !valid_label(&plan.group_id) {
        return Err(WorkerTranscriptError::Plan);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayStage {
    Planning {
        called: bool,
    },
    Round {
        round: u8,
        started: bool,
        called: bool,
        missing_coverage: u32,
    },
    Verification {
        called: bool,
    },
    Adjudication {
        called: bool,
    },
    AwaitTerminal,
    Terminal,
}

#[allow(clippy::too_many_lines)]
fn replay(
    plan: &WorkerTranscriptPlan,
    events: &[WorkerTranscriptEvent],
) -> Result<WorkerTranscriptUsage, WorkerTranscriptError> {
    let mut stage = if plan.planning_required {
        ReplayStage::Planning { called: false }
    } else {
        ReplayStage::Round {
            round: 1,
            started: false,
            called: false,
            missing_coverage: 0,
        }
    };
    let mut partial_reason = None;
    let mut usage = WorkerTranscriptUsage::default();
    for event in events {
        match event {
            WorkerTranscriptEvent::ModelCall {
                phase,
                input_tokens,
                output_tokens,
                cost_microusd,
            } => {
                if *input_tokens == 0 || *output_tokens == 0 {
                    return Err(WorkerTranscriptError::Transition);
                }
                match (&mut stage, phase) {
                    (ReplayStage::Planning { called }, TranscriptModelPhase::Planning)
                    | (ReplayStage::Verification { called }, TranscriptModelPhase::Verification)
                    | (ReplayStage::Adjudication { called }, TranscriptModelPhase::Adjudication) => {
                        if *called {
                            return Err(WorkerTranscriptError::Transition);
                        }
                        *called = true;
                    }
                    (
                        ReplayStage::Round {
                            started, called, ..
                        },
                        TranscriptModelPhase::Review,
                    ) if *started => *called = true,
                    _ => return Err(WorkerTranscriptError::Transition),
                }
                usage.model_requests = usage
                    .model_requests
                    .checked_add(1)
                    .ok_or(WorkerTranscriptError::Overflow)?;
                if usage.model_requests > plan.effort.max_group_turns() {
                    return Err(WorkerTranscriptError::Transition);
                }
                usage.input_tokens = usage
                    .input_tokens
                    .checked_add(*input_tokens)
                    .ok_or(WorkerTranscriptError::Overflow)?;
                usage.output_tokens = usage
                    .output_tokens
                    .checked_add(*output_tokens)
                    .ok_or(WorkerTranscriptError::Overflow)?;
                usage.cost_microusd = usage
                    .cost_microusd
                    .checked_add(*cost_microusd)
                    .ok_or(WorkerTranscriptError::Overflow)?;
            }
            WorkerTranscriptEvent::PlanningCompleted => match stage {
                ReplayStage::Planning { called: true } => {
                    stage = ReplayStage::Round {
                        round: 1,
                        started: false,
                        called: false,
                        missing_coverage: 0,
                    };
                }
                _ => return Err(WorkerTranscriptError::Planning),
            },
            WorkerTranscriptEvent::RoundStarted { round } => match &mut stage {
                ReplayStage::Round {
                    round: expected,
                    started,
                    ..
                } if round == expected && !*started => *started = true,
                _ => return Err(WorkerTranscriptError::Round),
            },
            WorkerTranscriptEvent::ToolBatch { tools } => {
                if tools.is_empty()
                    || tools.len() > MAX_BATCHED_TOOLS
                    || !matches!(
                        stage,
                        ReplayStage::Planning { .. }
                            | ReplayStage::Round { started: true, .. }
                            | ReplayStage::Adjudication { .. }
                    )
                {
                    return Err(WorkerTranscriptError::ToolBatch);
                }
                usage.tool_calls = usage
                    .tool_calls
                    .checked_add(
                        u32::try_from(tools.len()).map_err(|_| WorkerTranscriptError::Overflow)?,
                    )
                    .ok_or(WorkerTranscriptError::Overflow)?;
            }
            WorkerTranscriptEvent::CoverageCompletionRejected {
                missing_requirements,
            } => match &mut stage {
                ReplayStage::Round {
                    started: true,
                    missing_coverage,
                    ..
                } if *missing_requirements > 0 && *missing_coverage == 0 => {
                    *missing_coverage = *missing_requirements;
                }
                _ => return Err(WorkerTranscriptError::Coverage),
            },
            WorkerTranscriptEvent::CoverageCorrected {
                delivered_requirements,
            } => match &mut stage {
                ReplayStage::Round {
                    started: true,
                    missing_coverage,
                    ..
                } if *delivered_requirements > 0
                    && *delivered_requirements <= *missing_coverage =>
                {
                    *missing_coverage -= *delivered_requirements;
                }
                _ => return Err(WorkerTranscriptError::Coverage),
            },
            WorkerTranscriptEvent::RoundCompleted { round } => match stage {
                ReplayStage::Round {
                    round: expected,
                    started: true,
                    called: true,
                    missing_coverage: 0,
                } if *round == expected => {
                    stage = if expected < plan.effort.rounds() {
                        ReplayStage::Round {
                            round: expected + 1,
                            started: false,
                            called: false,
                            missing_coverage: 0,
                        }
                    } else {
                        next_after_rounds(plan)
                    };
                }
                _ => return Err(WorkerTranscriptError::Round),
            },
            WorkerTranscriptEvent::VerifierSucceeded => match stage {
                ReplayStage::Verification { called: true } => {
                    stage = next_after_verification(plan);
                }
                _ => return Err(WorkerTranscriptError::Verification),
            },
            WorkerTranscriptEvent::VerifierFailed => match stage {
                ReplayStage::Verification { called: true } => {
                    partial_reason.get_or_insert(TranscriptPartialReason::VerifierFailure);
                    stage = next_after_verification(plan);
                }
                _ => return Err(WorkerTranscriptError::Verification),
            },
            WorkerTranscriptEvent::AdjudicatorSucceeded => match stage {
                ReplayStage::Adjudication { called: true } => {
                    stage = ReplayStage::AwaitTerminal;
                }
                _ => return Err(WorkerTranscriptError::Adjudication),
            },
            WorkerTranscriptEvent::AdjudicatorFailedFallback {
                verified_candidates,
            } => match stage {
                ReplayStage::Adjudication { called: true }
                    if *verified_candidates <= MAX_VERIFIED_CANDIDATES =>
                {
                    partial_reason.get_or_insert(TranscriptPartialReason::AdjudicatorFailure);
                    stage = ReplayStage::AwaitTerminal;
                }
                _ => return Err(WorkerTranscriptError::Adjudication),
            },
            WorkerTranscriptEvent::BudgetExhausted => {
                if matches!(stage, ReplayStage::AwaitTerminal | ReplayStage::Terminal) {
                    return Err(WorkerTranscriptError::Transition);
                }
                partial_reason = Some(TranscriptPartialReason::BudgetExhausted);
                stage = ReplayStage::AwaitTerminal;
            }
            WorkerTranscriptEvent::Cancelled => {
                if matches!(stage, ReplayStage::AwaitTerminal | ReplayStage::Terminal) {
                    return Err(WorkerTranscriptError::Transition);
                }
                partial_reason = Some(TranscriptPartialReason::Cancelled);
                stage = ReplayStage::AwaitTerminal;
            }
            WorkerTranscriptEvent::Finished { outcome } => {
                if stage != ReplayStage::AwaitTerminal {
                    return Err(WorkerTranscriptError::Terminal);
                }
                match (partial_reason, outcome) {
                    (None, TranscriptTerminalOutcome::Complete)
                    | (
                        Some(TranscriptPartialReason::BudgetExhausted),
                        TranscriptTerminalOutcome::Partial {
                            reason: TranscriptPartialReason::BudgetExhausted,
                        },
                    )
                    | (
                        Some(TranscriptPartialReason::Cancelled),
                        TranscriptTerminalOutcome::Partial {
                            reason: TranscriptPartialReason::Cancelled,
                        },
                    )
                    | (
                        Some(TranscriptPartialReason::VerifierFailure),
                        TranscriptTerminalOutcome::Partial {
                            reason: TranscriptPartialReason::VerifierFailure,
                        },
                    )
                    | (
                        Some(TranscriptPartialReason::AdjudicatorFailure),
                        TranscriptTerminalOutcome::Partial {
                            reason: TranscriptPartialReason::AdjudicatorFailure,
                        },
                    ) => stage = ReplayStage::Terminal,
                    _ => return Err(WorkerTranscriptError::Terminal),
                }
            }
        }
    }
    if stage != ReplayStage::Terminal {
        return Err(WorkerTranscriptError::Terminal);
    }
    Ok(usage)
}

fn next_after_rounds(plan: &WorkerTranscriptPlan) -> ReplayStage {
    if plan.verification_required {
        ReplayStage::Verification { called: false }
    } else if plan.adjudication_required {
        ReplayStage::Adjudication { called: false }
    } else {
        ReplayStage::AwaitTerminal
    }
}

fn next_after_verification(plan: &WorkerTranscriptPlan) -> ReplayStage {
    if plan.adjudication_required {
        ReplayStage::Adjudication { called: false }
    } else {
        ReplayStage::AwaitTerminal
    }
}

fn transcript_digest(transcript: &WorkerTranscript) -> Result<Sha256Digest, WorkerTranscriptError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema_version: &'a str,
        plan: &'a WorkerTranscriptPlan,
        events: &'a [WorkerTranscriptEvent],
        usage: WorkerTranscriptUsage,
    }
    serde_json::to_vec(&DigestInput {
        schema_version: &transcript.schema_version,
        plan: &transcript.plan,
        events: &transcript.events,
        usage: transcript.usage,
    })
    .map(|bytes| Sha256Digest::of_bytes(&bytes))
    .map_err(|_| WorkerTranscriptError::Serialization)
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GROUP_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(phase: TranscriptModelPhase) -> WorkerTranscriptEvent {
        WorkerTranscriptEvent::ModelCall {
            phase,
            input_tokens: 100,
            output_tokens: 20,
            cost_microusd: 5,
        }
    }

    fn successful_events(plan: &WorkerTranscriptPlan) -> Vec<WorkerTranscriptEvent> {
        let mut events = Vec::new();
        if plan.planning_required {
            events.push(model(TranscriptModelPhase::Planning));
            events.push(WorkerTranscriptEvent::PlanningCompleted);
        }
        for round in 1..=plan.effort.rounds() {
            events.push(WorkerTranscriptEvent::RoundStarted { round });
            events.push(model(TranscriptModelPhase::Review));
            if round == 1 {
                events.push(WorkerTranscriptEvent::ToolBatch {
                    tools: vec![
                        TranscriptTool::DiffManifest,
                        TranscriptTool::ReadDiff,
                        TranscriptTool::ReadDiff,
                        TranscriptTool::SearchCode,
                    ],
                });
            }
            events.push(WorkerTranscriptEvent::RoundCompleted { round });
        }
        if plan.verification_required {
            events.push(model(TranscriptModelPhase::Verification));
            events.push(WorkerTranscriptEvent::VerifierSucceeded);
        }
        if plan.adjudication_required {
            events.push(model(TranscriptModelPhase::Adjudication));
            events.push(WorkerTranscriptEvent::AdjudicatorSucceeded);
        }
        events.push(WorkerTranscriptEvent::Finished {
            outcome: TranscriptTerminalOutcome::Complete,
        });
        events
    }

    fn plan(effort: ReviewEffort, planning_required: bool) -> WorkerTranscriptPlan {
        WorkerTranscriptPlan {
            group_id: "group-1".to_owned(),
            effort,
            planning_required,
            verification_required: true,
            adjudication_required: true,
        }
    }

    #[test]
    fn planning_choice_and_one_two_three_rounds_replay() {
        for (effort, rounds) in [
            (ReviewEffort::Low, 1),
            (ReviewEffort::Medium, 2),
            (ReviewEffort::High, 3),
        ] {
            for planning_required in [false, true] {
                let plan = plan(effort, planning_required);
                let transcript =
                    build_worker_transcript(plan.clone(), successful_events(&plan)).unwrap();
                assert_eq!(
                    transcript
                        .events
                        .iter()
                        .filter(|event| matches!(
                            event,
                            WorkerTranscriptEvent::RoundCompleted { .. }
                        ))
                        .count(),
                    rounds
                );
                assert_eq!(
                    transcript
                        .events
                        .iter()
                        .any(|event| matches!(event, WorkerTranscriptEvent::PlanningCompleted)),
                    planning_required
                );
                assert_eq!(transcript.usage.tool_calls, 4);
                transcript.validate().unwrap();
            }
        }
    }

    #[test]
    fn coverage_rejection_must_be_corrected_before_round_completion() {
        let plan = WorkerTranscriptPlan {
            verification_required: false,
            adjudication_required: false,
            ..plan(ReviewEffort::Low, false)
        };
        let events = vec![
            WorkerTranscriptEvent::RoundStarted { round: 1 },
            model(TranscriptModelPhase::Review),
            WorkerTranscriptEvent::CoverageCompletionRejected {
                missing_requirements: 2,
            },
            WorkerTranscriptEvent::CoverageCorrected {
                delivered_requirements: 2,
            },
            WorkerTranscriptEvent::RoundCompleted { round: 1 },
            WorkerTranscriptEvent::Finished {
                outcome: TranscriptTerminalOutcome::Complete,
            },
        ];
        build_worker_transcript(plan.clone(), events.clone()).unwrap();
        let mut invalid = events;
        invalid.remove(3);
        assert_eq!(
            build_worker_transcript(plan, invalid),
            Err(WorkerTranscriptError::Round)
        );
    }

    #[test]
    fn verifier_and_adjudicator_failures_use_typed_partial_fallbacks() {
        let plan = plan(ReviewEffort::Low, false);
        let mut verifier = successful_events(&plan);
        let verifier_index = verifier
            .iter()
            .position(|event| matches!(event, WorkerTranscriptEvent::VerifierSucceeded))
            .unwrap();
        verifier[verifier_index] = WorkerTranscriptEvent::VerifierFailed;
        verifier.pop();
        verifier.push(WorkerTranscriptEvent::Finished {
            outcome: TranscriptTerminalOutcome::Partial {
                reason: TranscriptPartialReason::VerifierFailure,
            },
        });
        build_worker_transcript(plan.clone(), verifier).unwrap();

        let mut adjudicator = successful_events(&plan);
        let index = adjudicator
            .iter()
            .position(|event| matches!(event, WorkerTranscriptEvent::AdjudicatorSucceeded))
            .unwrap();
        adjudicator[index] = WorkerTranscriptEvent::AdjudicatorFailedFallback {
            verified_candidates: 2,
        };
        adjudicator.pop();
        adjudicator.push(WorkerTranscriptEvent::Finished {
            outcome: TranscriptTerminalOutcome::Partial {
                reason: TranscriptPartialReason::AdjudicatorFailure,
            },
        });
        build_worker_transcript(plan, adjudicator).unwrap();
    }

    #[test]
    fn budget_and_cancellation_stop_with_partial_outcomes() {
        for (event, reason) in [
            (
                WorkerTranscriptEvent::BudgetExhausted,
                TranscriptPartialReason::BudgetExhausted,
            ),
            (
                WorkerTranscriptEvent::Cancelled,
                TranscriptPartialReason::Cancelled,
            ),
        ] {
            let plan = plan(ReviewEffort::Medium, true);
            let transcript = build_worker_transcript(
                plan,
                vec![
                    model(TranscriptModelPhase::Planning),
                    event,
                    WorkerTranscriptEvent::Finished {
                        outcome: TranscriptTerminalOutcome::Partial { reason },
                    },
                ],
            )
            .unwrap();
            assert_eq!(transcript.usage.model_requests, 1);
        }
    }

    #[test]
    fn transcript_json_contains_no_provider_payloads() {
        let plan = plan(ReviewEffort::Low, false);
        let transcript = build_worker_transcript(plan.clone(), successful_events(&plan)).unwrap();
        let json = String::from_utf8(transcript.canonical_json().unwrap()).unwrap();
        for forbidden in [
            "diff_body",
            "prompt",
            "reasoning",
            "response_body",
            "source_body",
            "tool_payload",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
