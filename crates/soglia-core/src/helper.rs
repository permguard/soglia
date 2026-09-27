// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The messages the Supervisor and the privileged helpers exchange.
//!
//! The first frame on a helper channel is [`Hello`]: the configuration text the original trusted
//! process read, so both sides work from one view of it. Every later request names an Execution
//! and, where needed, a pool slot and an agent from that configuration — never a path, an address
//! or a command. A helper derives everything else itself, so a Supervisor that has gone wrong can
//! ask a helper only for the operations a well-behaved one could.

use serde::{Deserialize, Serialize};

use crate::id::{ExecutionId, ResourceTag};

/// The first frame on every helper channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The configuration, exactly as the original process read it.
    pub config_yaml: String,
}

/// What the Supervisor asks the network enforcer to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EnforcerRequest {
    /// Create and configure the network of a new Execution.
    Prepare {
        /// The Execution.
        id: ExecutionId,
        /// The pool slot the Supervisor reserved for it.
        slot: u32,
        /// The configured agent it will run.
        agent: String,
    },
    /// Deny every packet of the Execution from now on.
    Freeze {
        /// The Execution's resource tag.
        tag: ResourceTag,
    },
    /// Remove every network resource of the Execution and verify that it is gone.
    Destroy {
        /// The Execution's resource tag.
        tag: ResourceTag,
    },
}

/// What the Supervisor asks the sandbox helper to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SandboxRequest {
    /// Create the cgroup and bundle of a new Execution and start its agent.
    Start {
        /// The Execution.
        id: ExecutionId,
        /// The configured agent to run.
        agent: String,
    },
    /// Freeze and kill every process of the Execution, and wait until none is left.
    Kill {
        /// The Execution's resource tag.
        tag: ResourceTag,
    },
    /// Remove the runtime state, bundle and cgroup of the Execution and verify that they are gone.
    Destroy {
        /// The Execution's resource tag.
        tag: ResourceTag,
    },
}

/// A helper's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HelperResponse {
    /// The helper swept what a previous run left behind, passed its probe and is ready.
    Ready {
        /// The resources the startup sweep removed.
        swept: Vec<String>,
    },
    /// The request was carried out and verified.
    Done,
    /// The agent of a started Execution exited.
    Exited {
        /// How it ended.
        outcome: ExitOutcome,
    },
    /// The request failed; the reason is for the log.
    Failed {
        /// What went wrong.
        reason: String,
    },
}

/// How an agent process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExitOutcome {
    /// It exited with this status.
    Status(i32),
    /// It was killed for exceeding `memory.max`.
    MemoryLimit,
    /// It was killed after exceeding `pids.max`.
    PidsLimit,
    /// It was killed by Soglia.
    Killed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_carry_identifiers_not_paths() {
        let id = ExecutionId::generate().unwrap();
        let request = EnforcerRequest::Prepare {
            id,
            slot: 3,
            agent: "echo".into(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<EnforcerRequest>(&json).unwrap(),
            request
        );

        // An operation nobody defined, or an extra field, does not decode.
        assert!(
            serde_json::from_str::<EnforcerRequest>(r#"{"Run":{"command":"/bin/sh"}}"#).is_err()
        );
        assert!(
            serde_json::from_str::<SandboxRequest>(&format!(
                r#"{{"Kill":{{"tag":"{}","path":"/"}}}}"#,
                id.tag()
            ))
            .is_err()
        );
    }
}
