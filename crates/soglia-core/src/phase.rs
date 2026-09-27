// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The lifecycle of one Execution.
//!
//! Every path that created a resource ends in `TearingDown`, and only `TearingDown` can reach a
//! terminal phase. That is what makes "the Caller saw success, so the Execution is gone" true by
//! construction rather than by care.

use serde::{Deserialize, Serialize};

/// Where an Execution is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionPhase {
    /// Waiting for a concurrency slot; no resource exists yet.
    Queued,
    /// Network namespace, ownership records and sandbox bundle are being created.
    Creating,
    /// The agent process is starting.
    Starting,
    /// The agent's listener answers.
    Ready,
    /// The invocation has been forwarded to the agent.
    Running,
    /// The agent's response is being read into the bounded buffer.
    CapturingResponse,
    /// Every resource of the Execution is being destroyed.
    TearingDown,
    /// Teardown was verified and the invocation succeeded.
    Completed,
    /// Teardown was verified and the invocation failed.
    Failed,
    /// Teardown could not be verified; the Execution's resources are quarantined.
    CleanupFailed,
}

impl ExecutionPhase {
    /// `true` once nothing further can happen to the Execution.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::CleanupFailed)
    }

    /// Whether the lifecycle allows moving from `self` to `next`.
    pub fn can_transition_to(self, next: Self) -> bool {
        use ExecutionPhase::*;

        match (self, next) {
            // Nothing exists while queued, so there is nothing to tear down.
            (Queued, Creating | Failed) => true,
            (Creating, Starting | TearingDown) => true,
            (Starting, Ready | TearingDown) => true,
            (Ready, Running | TearingDown) => true,
            (Running, CapturingResponse | TearingDown) => true,
            (CapturingResponse, TearingDown) => true,
            (TearingDown, Completed | Failed | CleanupFailed) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutionPhase::*;
    use super::*;

    const ALL: [ExecutionPhase; 10] = [
        Queued,
        Creating,
        Starting,
        Ready,
        Running,
        CapturingResponse,
        TearingDown,
        Completed,
        Failed,
        CleanupFailed,
    ];

    #[test]
    fn the_success_path_is_allowed() {
        let path = [
            Queued,
            Creating,
            Starting,
            Ready,
            Running,
            CapturingResponse,
            TearingDown,
            Completed,
        ];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_transition_to(pair[1]),
                "{:?} -> {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn a_phase_that_created_resources_reaches_an_end_only_through_teardown() {
        for from in [Creating, Starting, Ready, Running, CapturingResponse] {
            for to in [Completed, Failed, CleanupFailed] {
                assert!(
                    !from.can_transition_to(to),
                    "{from:?} -> {to:?} must go through teardown"
                );
            }
            assert!(from.can_transition_to(TearingDown));
        }
    }

    #[test]
    fn terminal_phases_are_final() {
        for from in ALL.into_iter().filter(|phase| phase.is_terminal()) {
            for to in ALL {
                assert!(!from.can_transition_to(to), "{from:?} is terminal");
            }
        }
    }

    #[test]
    fn success_is_reachable_only_from_teardown() {
        for from in ALL {
            assert_eq!(from.can_transition_to(Completed), from == TearingDown);
        }
    }
}
