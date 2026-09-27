// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One invocation, from a fresh Execution to its verified destruction.
//!
//! The Supervisor holds no privilege. It decides the order of things and asks the helpers, which
//! derive every resource from the configuration they were started with:
//!
//! ```text
//! QUEUED -> CREATING -> STARTING -> READY -> RUNNING -> CAPTURING_RESPONSE -> TEARING_DOWN
//!   -> COMPLETED | FAILED | CLEANUP_FAILED
//!
//! TEARING_DOWN
//!   1 revoke the attribution: the egress proxy stops serving the Execution and closes its tunnels
//!   2 enforcer  freeze: deny every packet
//!   3 sandbox   kill the whole cgroup and wait until it is empty
//!   4 sandbox   remove the runtime state, the bundle and the cgroup, verifying each
//!   5 enforcer  remove the host set elements, the veth and the namespace, verifying each
//!   6 release the attribution, the pool slot and the tag
//!   7 release the concurrency slot, then the buffered response
//! ```
//!
//! Every Execution runs on a task of its own, so a caller that disconnects cannot cut a teardown
//! short. If any teardown step cannot be verified the Execution is `CLEANUP_FAILED`: the caller gets
//! an error, its slot, tag, address and concurrency permit are quarantined, and once the configured
//! number of cleanup failures is reached no new Execution is admitted.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::StatusCode;
use soglia_core::config::{AgentConfig, Config};
use soglia_core::helper::{EnforcerRequest, ExitOutcome, HelperResponse, SandboxRequest};
use soglia_core::net::ExecutionPool;
use soglia_core::{ExecutionId, ExecutionPhase, ResourceTag};
use soglia_proxy::attribution::AttributionTable;
use soglia_proxy::ingress::{Execution, Executor, Invocation, Outcome};
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;
use tracing::{error, info, warn};

use crate::forward::{self, Answer, ForwardError};
use crate::helpers::{Helper, HelperError};
use crate::slots::Slots;

/// The Supervisor.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

struct Inner {
    config: Arc<Config>,
    pool: ExecutionPool,
    sandbox: Helper,
    enforcer: Helper,
    attribution: Arc<AttributionTable>,
    slots: Mutex<Slots>,
    waiting: Semaphore,
    running: Arc<Semaphore>,
    cleanup_failures: AtomicU32,
    runtime: RuntimeState,
}

/// The one-way runtime state shared by admission, effect cancellation and helper-loss observers.
struct RuntimeState {
    admitting: AtomicBool,
    helper_lost: AtomicBool,
    fatal: watch::Sender<bool>,
    cancel: watch::Sender<bool>,
}

impl RuntimeState {
    fn new(fatal: watch::Sender<bool>, cancel: watch::Sender<bool>) -> Self {
        Self {
            admitting: AtomicBool::new(true),
            helper_lost: AtomicBool::new(false),
            fatal,
            cancel,
        }
    }

    fn is_admitting(&self) -> bool {
        self.admitting.load(Ordering::SeqCst)
    }

    fn stop_admitting(&self) {
        self.admitting.store(false, Ordering::SeqCst);
    }

    /// Linearizes helper loss and broadcasts cancellation exactly once.
    fn begin_helper_loss(&self) -> bool {
        self.stop_admitting();
        if self.helper_lost.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.cancel.send_replace(true);
        true
    }

    fn finish_helper_loss(&self) {
        self.fatal.send_replace(true);
    }
}

/// Why an Execution ended before its agent answered.
#[derive(Debug)]
enum Failure {
    /// A helper could not create or start it.
    Setup(String),
    /// The agent never answered on its listener.
    NotReady,
    /// The exchange with the agent failed.
    Agent(ForwardError),
    /// The invocation ran out of time.
    Timeout,
}

/// One Execution's resources, as far as the Supervisor knows them.
struct Run {
    id: ExecutionId,
    tag: ResourceTag,
    slot: u32,
    address: IpAddr,
    listener: SocketAddr,
    phase: ExecutionPhase,
    bound: bool,
}

impl Run {
    fn enter(&mut self, next: ExecutionPhase) {
        if !self.phase.can_transition_to(next) {
            error!(
                event.name = "execution.illegal_transition",
                execution_id = %self.id,
                from = ?self.phase,
                to = ?next,
                "an illegal lifecycle transition was attempted"
            );
        }
        self.phase = next;
        info!(event.name = "execution.phase", execution_id = %self.id, phase = ?next, "execution phase");
    }
}

impl Supervisor {
    /// A Supervisor over ready helpers.
    pub fn new(
        config: Arc<Config>,
        pool: ExecutionPool,
        sandbox: Helper,
        enforcer: Helper,
        attribution: Arc<AttributionTable>,
        fatal: watch::Sender<bool>,
        cancel: watch::Sender<bool>,
    ) -> Self {
        let runtime = &config.runtime;
        Self {
            inner: Arc::new(Inner {
                slots: Mutex::new(Slots::new(pool.slot_count())),
                waiting: Semaphore::new(runtime.max_queue as usize),
                running: Arc::new(Semaphore::new(runtime.max_concurrency as usize)),
                cleanup_failures: AtomicU32::new(0),
                runtime: RuntimeState::new(fatal, cancel),
                pool,
                sandbox,
                enforcer,
                attribution,
                config,
            }),
        }
    }

    /// Stops admitting new Executions.
    pub fn stop_admitting(&self) {
        self.inner.runtime.stop_admitting();
    }

    /// Enters the one-way fail-closed transition after a helper child exits unexpectedly.
    ///
    /// The same transition is used when a concurrent RPC discovers a broken helper channel. Only
    /// the first observer closes runtime work and helper channels; later observations are harmless.
    pub fn helper_exited(&self, role: &'static str, reason: impl Into<String>) {
        let reason = reason.into();
        self.inner.helper_lost(role, &reason);
    }

    /// Waits until no Execution is running, or `deadline` passes.
    pub async fn drain(&self, deadline: Duration) -> bool {
        let all = self.inner.config.runtime.max_concurrency;
        let quarantined = self
            .inner
            .slots
            .lock()
            .map_or(0, |slots| slots.quarantined());
        let reachable = all.saturating_sub(u32::try_from(quarantined).unwrap_or(all));
        tokio::time::timeout(deadline, self.inner.running.acquire_many(reachable))
            .await
            .is_ok()
    }
}

impl Executor for Supervisor {
    fn execute(&self, invocation: Invocation) -> Execution<'_> {
        let inner = Arc::clone(&self.inner);
        // Detached: dropping the caller's future does not cancel the Execution, so its teardown
        // always runs to the end.
        let task = tokio::spawn(async move { inner.execute(invocation).await });
        Box::pin(async move {
            task.await.unwrap_or_else(|error| Outcome::Refused {
                execution: None,
                status: StatusCode::INTERNAL_SERVER_ERROR,
                reason: format!("the execution task failed: {error}"),
            })
        })
    }
}

impl Inner {
    async fn execute(self: Arc<Self>, invocation: Invocation) -> Outcome {
        let Some(agent) = self.config.agents.get(&invocation.agent).cloned() else {
            return refused(
                None,
                StatusCode::NOT_FOUND,
                format!("no agent `{}` is configured", invocation.agent),
            );
        };
        if !self.runtime.is_admitting() {
            return refused(
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "the runtime is not admitting new Executions".to_owned(),
            );
        }

        // QUEUED: a free concurrency slot is taken at once; otherwise the invocation waits, but only
        // if the bounded queue has room.
        let permit = match Arc::clone(&self.running).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let Ok(waiting) = self.waiting.try_acquire() else {
                    return refused(
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "the invocation queue is full".to_owned(),
                    );
                };
                let Ok(permit) = Arc::clone(&self.running).acquire_owned().await else {
                    return refused(
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "the runtime is shutting down".to_owned(),
                    );
                };
                drop(waiting);
                permit
            }
        };
        if !self.runtime.is_admitting() {
            return refused(
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "the runtime is not admitting new Executions".to_owned(),
            );
        }

        let mut run = match self.allocate(&agent) {
            Ok(run) => run,
            Err(reason) => return refused(None, StatusCode::SERVICE_UNAVAILABLE, reason),
        };
        info!(
            event.name = "execution.admitted",
            execution_id = %run.id,
            agent = %invocation.agent,
            slot = run.slot,
            "execution admitted"
        );

        let deadline = Instant::now() + Duration::from_millis(agent.timeout_ms);
        let driven =
            tokio::time::timeout_at(deadline, self.drive(&mut run, &agent, &invocation)).await;
        let driven = driven.unwrap_or(Err(Failure::Timeout));

        run.enter(ExecutionPhase::TearingDown);
        match self.teardown(&mut run).await {
            Ok(exit) => {
                // Only now, with every resource verified gone, do the slot and the answer go out.
                drop(permit);
                self.finish(&mut run, driven, exit)
            }
            Err(reason) => {
                run.enter(ExecutionPhase::CleanupFailed);
                self.quarantine(&run, permit, &reason);
                refused(
                    Some(run.id),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the Execution could not be verifiably destroyed".to_owned(),
                )
            }
        }
    }

    fn allocate(&self, agent: &AgentConfig) -> Result<Run, String> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| "the slot table is poisoned".to_owned())?;
        let id = loop {
            let id = ExecutionId::generate().map_err(|error| format!("no identifier: {error}"))?;
            if !slots.tag_in_use(&id.tag()) {
                break id;
            }
        };
        let slot = slots
            .reserve(id.tag())
            .ok_or_else(|| "no Execution address is free".to_owned())?;
        let addresses = self
            .pool
            .slot(slot)
            .ok_or_else(|| "the reserved slot is outside the pool".to_owned())?;
        let address = IpAddr::V4(addresses.execution);

        Ok(Run {
            id,
            tag: id.tag(),
            slot,
            address,
            listener: SocketAddr::new(address, agent.port),
            phase: ExecutionPhase::Queued,
            bound: false,
        })
    }

    /// CREATING through CAPTURING_RESPONSE.
    async fn drive(
        &self,
        run: &mut Run,
        agent: &AgentConfig,
        invocation: &Invocation,
    ) -> Result<Answer, Failure> {
        run.enter(ExecutionPhase::Creating);
        self.expect_done(
            "enforcer",
            self.enforcer
                .call(EnforcerRequest::Prepare {
                    id: run.id,
                    slot: run.slot,
                    agent: invocation.agent.clone(),
                })
                .await,
        )
        .map_err(Failure::Setup)?;
        // The address attributes this Execution before its agent can open a single connection.
        self.attribution
            .bind(run.address, run.id)
            .map_err(|error| Failure::Setup(error.to_string()))?;
        run.bound = true;

        run.enter(ExecutionPhase::Starting);
        self.expect_done(
            "sandboxd",
            self.sandbox
                .call(SandboxRequest::Start {
                    id: run.id,
                    agent: invocation.agent.clone(),
                })
                .await,
        )
        .map_err(Failure::Setup)?;

        let startup = Duration::from_millis(agent.startup_timeout_ms);
        if !forward::wait_ready(run.listener, startup).await {
            return Err(Failure::NotReady);
        }
        run.enter(ExecutionPhase::Ready);

        run.enter(ExecutionPhase::Running);
        let max_response =
            usize::try_from(self.config.ingress.max_response_bytes).unwrap_or(usize::MAX);
        let exchange = forward::invoke(run.listener, &agent.invoke_path, invocation, max_response);
        let answer = exchange.await.map_err(Failure::Agent)?;
        run.enter(ExecutionPhase::CapturingResponse);

        Ok(answer)
    }

    /// TEARING_DOWN. Returns how the agent ended, or why teardown could not be verified.
    async fn teardown(&self, run: &mut Run) -> Result<ExitOutcome, String> {
        let tag = run.tag;
        if run.bound {
            self.attribution.revoke(run.address);
        }
        self.expect_done(
            "enforcer",
            self.enforcer.call(EnforcerRequest::Freeze { tag }).await,
        )
        .map_err(|reason| format!("freeze: {reason}"))?;
        let exit = match self.sandbox.call(SandboxRequest::Kill { tag }).await {
            Ok(HelperResponse::Exited { outcome }) => outcome,
            Ok(other) => return Err(format!("kill: unexpected answer {other:?}")),
            Err(error) => {
                self.on_helper_error("sandboxd", &error);
                return Err(format!("kill: {error}"));
            }
        };
        self.expect_done(
            "sandboxd",
            self.sandbox.call(SandboxRequest::Destroy { tag }).await,
        )
        .map_err(|reason| format!("sandbox destroy: {reason}"))?;
        self.expect_done(
            "enforcer",
            self.enforcer.call(EnforcerRequest::Destroy { tag }).await,
        )
        .map_err(|reason| format!("network destroy: {reason}"))?;

        if run.bound && !self.attribution.remove(run.address, run.id) {
            return Err("the attribution could not be released".to_owned());
        }
        if let Ok(mut slots) = self.slots.lock() {
            slots.release(run.slot, &tag);
        } else {
            return Err("the slot table is poisoned".to_owned());
        }
        info!(event.name = "execution.destroyed", execution_id = %run.id, exit = ?exit, "execution destroyed and verified");

        Ok(exit)
    }

    fn finish(&self, run: &mut Run, driven: Result<Answer, Failure>, exit: ExitOutcome) -> Outcome {
        match driven {
            Ok(answer) => {
                run.enter(ExecutionPhase::Completed);
                Outcome::Answered {
                    execution: run.id,
                    status: answer.status,
                    content_type: answer.content_type,
                    body: answer.body,
                }
            }
            Err(failure) => {
                run.enter(ExecutionPhase::Failed);
                let (status, reason) = match (&failure, exit) {
                    (_, ExitOutcome::MemoryLimit) => (
                        StatusCode::BAD_GATEWAY,
                        "the agent exceeded its memory limit".to_owned(),
                    ),
                    (_, ExitOutcome::PidsLimit) => (
                        StatusCode::BAD_GATEWAY,
                        "the agent exceeded its process limit".to_owned(),
                    ),
                    (Failure::Timeout, _) => (
                        StatusCode::GATEWAY_TIMEOUT,
                        "the invocation timed out".to_owned(),
                    ),
                    (Failure::NotReady, _) => (
                        StatusCode::BAD_GATEWAY,
                        "the agent did not become ready".to_owned(),
                    ),
                    (Failure::Agent(ForwardError::TooLarge), _) => (
                        StatusCode::BAD_GATEWAY,
                        "the agent response exceeds ingress.max_response_bytes".to_owned(),
                    ),
                    (Failure::Agent(error), _) => (
                        StatusCode::BAD_GATEWAY,
                        format!("the agent failed: {error}"),
                    ),
                    (Failure::Setup(reason), _) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("the Execution could not be set up: {reason}"),
                    ),
                };
                warn!(event.name = "execution.failed", execution_id = %run.id, status = status.as_u16(), reason = %reason, exit = ?exit, "execution failed");
                refused(Some(run.id), status, reason)
            }
        }
    }

    fn quarantine(&self, run: &Run, permit: tokio::sync::OwnedSemaphorePermit, reason: &str) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.quarantine(run.slot);
        }
        // The concurrency permit is never returned: the Execution may still hold resources.
        permit.forget();
        let failures = self.cleanup_failures.fetch_add(1, Ordering::SeqCst) + 1;
        error!(
            event.name = "execution.cleanup_failed",
            execution_id = %run.id,
            slot = run.slot,
            reason = %reason,
            failures,
            "teardown could not be verified; the Execution is quarantined"
        );
        if failures >= self.config.runtime.cleanup_failure_threshold {
            self.runtime.stop_admitting();
            error!(
                event.name = "runtime.admission_stopped",
                failures, "the cleanup-failure threshold is reached; no new Execution is admitted"
            );
        }
    }

    fn expect_done(
        &self,
        role: &'static str,
        answer: Result<HelperResponse, HelperError>,
    ) -> Result<(), String> {
        match answer {
            Ok(HelperResponse::Done) => Ok(()),
            Ok(other) => Err(format!("unexpected answer {other:?}")),
            Err(error) => {
                self.on_helper_error(role, &error);
                Err(error.to_string())
            }
        }
    }

    fn on_helper_error(&self, role: &'static str, error: &HelperError) {
        if let HelperError::Channel(reason) = error {
            self.helper_lost(role, reason);
        }
    }

    fn helper_lost(&self, role: &'static str, reason: &str) {
        // Closing admission is the transition's linearization point. An operation that passed its
        // final admission check before this store is already in flight and is cancelled below.
        if !self.runtime.begin_helper_loss() {
            return;
        }

        // Stop effect-producing work before terminating agents. The proxy and ingress receivers
        // close active connections as well as their accept loops.
        // sandboxd interprets EOF as kill-all. The duplicate descriptor makes this non-blocking
        // even when another task is inside a helper exchange.
        self.enforcer.close_channel();
        self.sandbox.close_channel();
        error!(event.name = "runtime.helper_lost", helper = role, reason = %reason, "a privileged helper is gone; the runtime stops fail-closed");
        self.runtime.finish_helper_loss();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_loss_is_idempotent_stops_admission_and_cancels_work() {
        let (fatal, fatal_seen) = watch::channel(false);
        let (cancel, cancel_seen) = watch::channel(false);
        let state = RuntimeState::new(fatal, cancel);

        assert!(state.is_admitting());
        assert!(state.begin_helper_loss());
        assert!(!state.is_admitting());
        assert!(*cancel_seen.borrow());
        assert!(
            !*fatal_seen.borrow(),
            "fatal follows helper-channel closure"
        );

        state.finish_helper_loss();
        assert!(*fatal_seen.borrow());
        assert!(!state.begin_helper_loss(), "duplicate loss is a no-op");
    }
}

fn refused(execution: Option<ExecutionId>, status: StatusCode, reason: String) -> Outcome {
    Outcome::Refused {
        execution,
        status,
        reason,
    }
}
