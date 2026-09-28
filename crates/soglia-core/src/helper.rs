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

use crate::id::{BindingKey, ExecutionId, ExecutionNonce, ResourceTag};

/// The canonical IPv4 TCP tuple used by Candidate-A Resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketTupleV4 {
    /// Source address as the four network-order octets interpreted as native bytes.
    pub source_address: [u8; 4],
    /// Destination address in the same representation.
    pub destination_address: [u8; 4],
    /// Source port in host order.
    pub source_port: u16,
    /// Destination port in host order.
    pub destination_port: u16,
}

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
    /// Revalidate the exact production attachment, pin and policy inventory.
    Health,
    /// Create and configure the network of a new Execution.
    Prepare {
        /// The Execution.
        id: ExecutionId,
        /// The pool slot the Supervisor reserved for it.
        slot: u32,
        /// The configured agent it will run.
        agent: String,
        /// Random identity of this exact Execution incarnation.
        nonce: ExecutionNonce,
    },
    /// Prove the paused init's placement while policy remains frozen.
    VerifyPlacement {
        /// The Execution whose durable frozen record already exists.
        id: ExecutionId,
        /// Host PID observed by the trusted Sandbox helper after `runc create`.
        pid: i32,
    },
    /// Activate only after the Supervisor has installed the returned live binding.
    Activate {
        /// The Execution whose placement was verified.
        id: ExecutionId,
        /// Candidate-A identity returned by placement verification; absent for netns-nft.
        binding: Option<BindingKey>,
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

/// Requests accepted only on the Enforcer's bounded attribution channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ResolverRequest {
    /// Consume and validate one proxy-accepted tuple.
    Resolve {
        /// Monotonic identifier that must be echoed by the matching response.
        request_id: u64,
        /// Tuple derived from kernel peer/local socket addresses before application reads.
        tuple: SocketTupleV4,
    },
}

/// One non-blocking lookup attempt performed by the Enforcer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveAttempt {
    /// No final answer exists yet; the Supervisor may retry within its deadline.
    Pending {
        /// Trusted internal reason used only for timeout telemetry.
        reason: ResolvePending,
    },
    /// The Enforcer reached one of the six final Resolve outcomes.
    Complete {
        /// Final trusted result of this Resolve.
        result: ResolveResult,
    },
}

/// Why one non-blocking Resolve attempt could not yet produce a final answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolvePending {
    /// The BPF tuple has not been published.
    TupleAbsent,
    /// A lifecycle operation currently owns the backend lock.
    BackendBusy,
}

/// Correlated response on the dedicated Candidate-A Resolve channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverReply {
    /// Exact identifier from the request this response answers.
    pub request_id: u64,
    /// One non-blocking lookup attempt.
    pub attempt: ResolveAttempt,
}

/// Which trusted attribution boundary disagreed with the complete Candidate-A identity.
///
/// This is diagnostic metadata only. Authorization always compares the complete [`BindingKey`]
/// first and never authorizes from a per-field comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveMismatch {
    /// The kernel cgroup identity differs.
    CgroupId,
    /// The Execution incarnation nonce differs.
    ExecutionNonce,
    /// The host-wide backend generation differs.
    BackendGeneration,
    /// The cookie map is absent or disagrees with the consumed tuple.
    Cookie,
    /// The tuple state disagrees with the current owned identity.
    Tuple,
    /// No current root-owned Execution record agrees with the observed identity.
    OwnershipRecord,
    /// The policy map is absent or disagrees with the current owned identity.
    Policy,
    /// More than one identity component differs.
    Multiple,
}

/// The Enforcer's typed answer on the dedicated Candidate-A Resolve channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveResult {
    /// Every privileged boundary agreed on this complete identity.
    Resolved {
        /// The complete identity validated by the Enforcer.
        binding: BindingKey,
    },
    /// No attribution state exists for this request.
    NotFound,
    /// Attribution state exists but a trusted boundary disagrees.
    IdentityMismatch {
        /// The single differing boundary, or [`ResolveMismatch::Multiple`].
        reason: ResolveMismatch,
    },
    /// The complete identity was found but its Execution is already frozen.
    Revoked {
        /// The identity whose revocation was observed.
        binding: BindingKey,
    },
    /// Tuple publication did not complete within the configured bounded wait.
    Timeout,
    /// Owned state could not be decoded or verified safely.
    IntegrityFailure,
}

/// What the Supervisor asks the sandbox helper to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SandboxRequest {
    /// Durably reserve an empty Execution cgroup before network preparation.
    Reserve {
        /// The Execution.
        id: ExecutionId,
        /// The configured agent to run.
        agent: String,
    },
    /// Perform `runc create` and leave the init process paused.
    CreatePaused {
        /// The Execution whose cgroup is already reserved.
        id: ExecutionId,
    },
    /// Release one verified paused init with `runc start`.
    Start {
        /// The Execution to start.
        id: ExecutionId,
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
    /// The exact empty cgroup the Sandbox reserved, reported as a trusted observation.
    Reserved {
        /// Filesystem inode of the cgroup directory.
        cgroup_inode: u64,
    },
    /// A container exists but its init process has not run agent code.
    CreatedPaused {
        /// Trusted host PID observed from runc state.
        pid: i32,
        /// Filesystem inode of the target cgroup.
        cgroup_inode: u64,
    },
    /// The Enforcer proved placement while the kernel policy is still frozen.
    PlacementVerified {
        /// Candidate-A identity; all fields must be compared together.
        binding: BindingKey,
    },
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
            nonce: ExecutionNonce::generate().unwrap(),
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

    #[test]
    fn resolve_results_round_trip_without_text_classification() {
        let binding = BindingKey {
            cgroup_id: 37,
            execution_nonce: ExecutionNonce::generate().unwrap(),
            backend_generation: 9,
        };
        let results = [
            ResolveResult::Resolved { binding },
            ResolveResult::NotFound,
            ResolveResult::IdentityMismatch {
                reason: ResolveMismatch::ExecutionNonce,
            },
            ResolveResult::Revoked { binding },
            ResolveResult::Timeout,
            ResolveResult::IntegrityFailure,
        ];
        for result in results {
            let encoded = serde_json::to_vec(&result).unwrap();
            assert_eq!(
                serde_json::from_slice::<ResolveResult>(&encoded).unwrap(),
                result
            );
        }

        let request = ResolverRequest::Resolve {
            request_id: 17,
            tuple: SocketTupleV4 {
                source_address: [10, 0, 0, 2],
                destination_address: [10, 0, 0, 1],
                source_port: 40_000,
                destination_port: 15_001,
            },
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<ResolverRequest>(&encoded).unwrap(),
            request
        );
        let reply = ResolverReply {
            request_id: 17,
            attempt: ResolveAttempt::Complete {
                result: ResolveResult::Timeout,
            },
        };
        let encoded = serde_json::to_vec(&reply).unwrap();
        assert_eq!(
            serde_json::from_slice::<ResolverReply>(&encoded).unwrap(),
            reply
        );
    }
}
