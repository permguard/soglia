// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The privileged helper processes and the channel to each.
//!
//! The original trusted process — still root — creates one socketpair per helper, starts the helper
//! by re-executing the Soglia binary in its role, and hands it exactly one end as its standard input.
//! It keeps exactly the other end. The helper inherits no other descriptor: the standard library
//! opens everything close-on-exec. There is no socket path, so nothing else — least of all an
//! Execution — can connect to the channel.
//!
//! What authenticates the Supervisor to a helper is possession of that descriptor. `SO_PEERCRED`
//! would report the credentials at socketpair creation, which were root, and says nothing about the
//! Supervisor after it dropped privileges, so it is not used as proof.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde::de::DeserializeOwned;
use soglia_core::helper::{
    Hello, HelperFailure, HelperResponse, RESOLVER_PROTOCOL_VERSION, ResolveAttempt,
    ResolveMismatch, ResolvePending, ResolveResult, ResolverHello, ResolverReady, ResolverReply,
    ResolverRequest, SocketTupleV4,
};
use soglia_core::ipc::{
    MAX_RESOLVER_FRAME_BYTES, read_frame, read_frame_limited, write_frame, write_frame_limited,
};
use soglia_proxy::attribution::{AttributionResult, AttributionTable, ConnectionAttributor};
use tokio::sync::{Semaphore, oneshot};
use tracing::{debug, info, warn};

/// Callback invoked once when the Resolve channel first becomes permanently unhealthy.
pub type ResolveHealthCallback = Arc<dyn Fn(ResolveHealthFailure) + Send + Sync>;

/// Why a helper exchange failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperError {
    /// The channel broke: the helper is gone, and the runtime cannot continue safely.
    Channel(String),
    /// The helper carried out the request and it failed.
    Failed(HelperFailure),
    /// The helper answered with something the request does not allow.
    Unexpected(String),
}

impl fmt::Display for HelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(reason) => write!(formatter, "the helper channel failed: {reason}"),
            Self::Failed(failure) => write!(formatter, "{}", failure.detail()),
            Self::Unexpected(reason) => write!(formatter, "unexpected helper answer: {reason}"),
        }
    }
}

impl std::error::Error for HelperError {}

/// One privileged helper.
pub struct Helper {
    role: &'static str,
    channel: Arc<Mutex<UnixStream>>,
    resolver: Option<Arc<ResolverState>>,
    shutdown: UnixStream,
    resolver_shutdown: Option<UnixStream>,
    process: Arc<Mutex<Child>>,
}

impl Helper {
    /// Starts `executable` in `role` with one end of a fresh socketpair as its standard input.
    pub fn spawn(executable: &Path, role: &'static str) -> io::Result<Self> {
        Self::spawn_inner(executable, role, false)
    }

    /// Starts the Enforcer with independent lifecycle and bounded Resolve socketpairs.
    pub fn spawn_enforcer(executable: &Path) -> io::Result<Self> {
        Self::spawn_inner(executable, "enforcer", true)
    }

    fn spawn_inner(executable: &Path, role: &'static str, with_resolver: bool) -> io::Result<Self> {
        let (ours, theirs) = UnixStream::pair()?;
        let shutdown = ours.try_clone()?;
        let (resolver, resolver_shutdown, child_stdout) = if with_resolver {
            let (ours, theirs) = UnixStream::pair()?;
            let shutdown = ours.try_clone()?;
            let poison_shutdown = ours.try_clone()?;
            (
                Some(Arc::new(ResolverState {
                    channel: Mutex::new(Some(ours)),
                    sender: Mutex::new(None),
                    inflight: Mutex::new(HashMap::new()),
                    submission: Mutex::new(()),
                    shutdown: poison_shutdown,
                    poisoned: AtomicBool::new(false),
                    next_request_id: AtomicU64::new(1),
                    on_unavailable: Mutex::new(None),
                })),
                Some(shutdown),
                Stdio::from(OwnedFd::from(theirs)),
            )
        } else {
            (None, None, Stdio::null())
        };
        let process = Command::new(executable)
            .arg(format!("__{role}"))
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(child_stdout)
            .stderr(Stdio::inherit())
            .spawn()?;

        Ok(Self {
            role,
            channel: Arc::new(Mutex::new(ours)),
            resolver,
            shutdown,
            resolver_shutdown,
            process: Arc::new(Mutex::new(process)),
        })
    }

    /// The helper's role, for logs.
    pub fn role(&self) -> &'static str {
        self.role
    }

    /// Waits for the helper child itself to exit, independently of any channel exchange.
    ///
    /// This is started once per helper after the async runtime exists. The child status is polled
    /// without holding the process lock between polls, so `Drop` retains its bounded shutdown wait.
    /// Closing the helper channel makes a healthy helper finish, while an abrupt exit is observed
    /// without waiting for a later RPC.
    pub fn watch_exit(&self) -> tokio::task::JoinHandle<Result<ExitStatus, HelperError>> {
        let process = Arc::clone(&self.process);
        tokio::spawn(async move {
            loop {
                let status = process
                    .lock()
                    .map_err(|_| HelperError::Channel("the child lock is poisoned".to_owned()))?
                    .try_wait()
                    .map_err(|error| HelperError::Channel(error.to_string()))?;
                if let Some(status) = status {
                    return Ok(status);
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
    }

    /// Confirms the helper is still alive at the final synchronous readiness barrier.
    pub fn ensure_running(&self) -> Result<(), HelperError> {
        let status = self
            .process
            .lock()
            .map_err(|_| HelperError::Channel("the child lock is poisoned".to_owned()))?
            .try_wait()
            .map_err(|error| HelperError::Channel(error.to_string()))?;
        match status {
            None => Ok(()),
            Some(status) => Err(HelperError::Channel(format!(
                "the {} helper exited before readiness ({status})",
                self.role
            ))),
        }
    }

    /// Permanently closes the helper IPC channel, interrupting any in-flight exchange.
    ///
    /// `shutdown` is a duplicate of the Supervisor's socket end and does not need the exchange
    /// lock. In particular, Enforcer loss can close sandboxd's channel even if another task is
    /// blocked in an RPC; sandboxd treats EOF as the fail-closed instruction to kill every live
    /// Execution.
    pub fn close_channel(&self) {
        let _ = self.shutdown.shutdown(std::net::Shutdown::Both);
        if let Some(shutdown) = &self.resolver_shutdown {
            let _ = shutdown.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Sends the configuration and waits until the helper has swept and is ready. Blocking: it runs
    /// before the async runtime exists.
    pub fn hello(&self, config_yaml: &str) -> Result<Vec<String>, HelperError> {
        let hello = Hello {
            config_yaml: config_yaml.to_owned(),
        };
        let answer = if let Some(resolver) = &self.resolver {
            let mut lifecycle = self
                .channel
                .lock()
                .map_err(|_| HelperError::Channel("the channel lock is poisoned".to_owned()))?;
            write_frame(&mut *lifecycle, &hello)
                .map_err(|error| HelperError::Channel(error.to_string()))?;
            let config = soglia_core::config::Config::from_yaml(config_yaml)
                .map_err(|error| HelperError::Unexpected(error.to_string()))?;
            resolver.begin_negotiation(
                config.cgroup_bpf.max_pending_resolves,
                config.cgroup_bpf.resolve_workers,
            )?;
            let answer: HelperResponse = read_frame(&mut *lifecycle)
                .map_err(|error| HelperError::Channel(error.to_string()))?;
            if matches!(answer, HelperResponse::Ready { .. }) {
                resolver.finish_negotiation(
                    config.cgroup_bpf.max_pending_resolves,
                    config.cgroup_bpf.resolve_workers,
                )?;
            }
            answer
        } else {
            exchange(&self.channel, &hello)?
        };
        match answer {
            HelperResponse::Ready { swept } => Ok(swept),
            HelperResponse::Failed { failure } => Err(HelperError::Failed(failure)),
            other => Err(HelperError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Sends one request and waits for its answer, off the async executor.
    ///
    /// The request and its answer are exchanged under one lock, so an exchange that outlives the
    /// caller — a timed-out Execution — still completes as a pair and leaves the channel in step.
    pub async fn call<R>(&self, request: R) -> Result<HelperResponse, HelperError>
    where
        R: Serialize + Send + 'static,
    {
        let channel = Arc::clone(&self.channel);
        let answer = tokio::task::spawn_blocking(move || exchange(&channel, &request))
            .await
            .map_err(|error| HelperError::Channel(error.to_string()))??;
        match answer {
            HelperResponse::Failed { failure } => Err(HelperError::Failed(failure)),
            other => Ok(other),
        }
    }

    /// A clonable client for the Enforcer's separate attribution channel.
    pub fn resolver_client(&self) -> Result<ResolverClient, HelperError> {
        self.resolver
            .as_ref()
            .map(|state| ResolverClient {
                state: Arc::clone(state),
            })
            .ok_or_else(|| HelperError::Unexpected("this helper has no Resolve channel".to_owned()))
    }
}

/// The unprivileged endpoint of the Enforcer's authenticated Resolve socketpair.
struct ResolverState {
    channel: Mutex<Option<UnixStream>>,
    sender: Mutex<Option<SyncSender<ResolverCommand>>>,
    inflight: Mutex<HashMap<u64, InflightResolve>>,
    submission: Mutex<()>,
    shutdown: UnixStream,
    poisoned: AtomicBool,
    next_request_id: AtomicU64,
    on_unavailable: Mutex<Option<ResolveHealthCallback>>,
}

struct InflightResolve {
    response: oneshot::Sender<Result<ResolveAttempt, HelperError>>,
    written_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone, Copy)]
struct ResolverCommand {
    request_id: u64,
    tuple: SocketTupleV4,
}

#[derive(Clone)]
pub struct ResolverClient {
    state: Arc<ResolverState>,
}

/// A Resolve failure that makes the runtime unsafe to keep ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveHealthFailure {
    /// The authenticated Resolve channel broke or its worker stopped responding.
    Unavailable,
    /// The Enforcer could not decode or verify owned attribution state.
    IntegrityFailure,
}

/// Candidate-A attribution: privileged tuple consumption followed by exact live-binding lookup.
pub struct CandidateAAttributor {
    resolver: ResolverClient,
    bindings: Arc<AttributionTable>,
    publication_timeout: std::time::Duration,
    exchange_watchdog: std::time::Duration,
    queue: Semaphore,
    queue_capacity: usize,
    queue_high_water: AtomicU64,
    queue_refused: AtomicU64,
    on_health_failure: ResolveHealthCallback,
    observability: ResolveObservability,
}

/// A one-shot IPC exchange performs one try-lock and at most one BPF map lookup. One second leaves
/// ample scheduler headroom while still detecting a stuck authenticated channel promptly.
const RESOLVE_EXCHANGE_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(1);
/// This preserves the previously qualified publication polling cadence without holding any lock.
const RESOLVE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(2);
const RESOLVE_OBSERVABILITY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const RESOLVE_LATENCY_BUCKET_US: [u64; 8] = [100, 250, 500, 1_000, 2_000, 5_000, 10_000, u64::MAX];
const RESOLVE_OUTCOME_COUNT: usize = 8;

struct ResolveObservability {
    state: Mutex<ResolveMetricState>,
}

struct ResolveMetricState {
    interval_started: std::time::Instant,
    outcomes: [u64; RESOLVE_OUTCOME_COUNT],
    delayed_hits: u64,
    stale_generation: u64,
    latency_buckets: [u64; RESOLVE_LATENCY_BUCKET_US.len()],
    latency_max_us: u64,
}

impl ResolveObservability {
    fn new() -> Self {
        Self {
            state: Mutex::new(ResolveMetricState {
                interval_started: std::time::Instant::now(),
                outcomes: [0; RESOLVE_OUTCOME_COUNT],
                delayed_hits: 0,
                stale_generation: 0,
                latency_buckets: [0; RESOLVE_LATENCY_BUCKET_US.len()],
                latency_max_us: 0,
            }),
        }
    }

    fn record(&self, result: &AttributionResult, attempts: u32, elapsed: std::time::Duration) {
        let Ok(mut state) = self.state.lock() else {
            warn!(
                event.name = "cgroup_bpf.resolve_observability_unavailable",
                "Resolve telemetry state is poisoned"
            );
            return;
        };
        let outcome = match result {
            AttributionResult::Resolved(_) => 0,
            AttributionResult::NotFound => 1,
            AttributionResult::IdentityMismatch(reason) => {
                if *reason == ResolveMismatch::BackendGeneration {
                    state.stale_generation = state.stale_generation.saturating_add(1);
                }
                2
            }
            AttributionResult::Revoked => 3,
            AttributionResult::Timeout => 4,
            AttributionResult::QueueFull => 5,
            AttributionResult::Unavailable => 6,
            AttributionResult::IntegrityFailure => 7,
        };
        state.outcomes[outcome] = state.outcomes[outcome].saturating_add(1);
        if matches!(result, AttributionResult::Resolved(_)) && attempts > 1 {
            state.delayed_hits = state.delayed_hits.saturating_add(1);
        }
        let latency_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        if latency_us > RESOLVE_LATENCY_BUCKET_US[RESOLVE_LATENCY_BUCKET_US.len() - 2] {
            let last = RESOLVE_LATENCY_BUCKET_US.len() - 1;
            state.latency_buckets[last] = state.latency_buckets[last].saturating_add(1);
        } else {
            for (index, bound) in RESOLVE_LATENCY_BUCKET_US[..RESOLVE_LATENCY_BUCKET_US.len() - 1]
                .iter()
                .enumerate()
            {
                if latency_us <= *bound {
                    state.latency_buckets[index] = state.latency_buckets[index].saturating_add(1);
                }
            }
        }
        state.latency_max_us = state.latency_max_us.max(latency_us);
        let interval = state.interval_started.elapsed();
        if interval < RESOLVE_OBSERVABILITY_INTERVAL {
            return;
        }
        let interval_ms = duration_millis(interval);
        info!(
            event.name = "cgroup_bpf.resolve_health",
            interval_ms,
            resolved = state.outcomes[0],
            delayed_hit = state.delayed_hits,
            not_found = state.outcomes[1],
            identity_mismatch = state.outcomes[2],
            stale_generation = state.stale_generation,
            revoked = state.outcomes[3],
            timeout = state.outcomes[4],
            queue_refusal = state.outcomes[5],
            unavailable = state.outcomes[6],
            integrity_failure = state.outcomes[7],
            latency_le_100us = state.latency_buckets[0],
            latency_le_250us = state.latency_buckets[1],
            latency_le_500us = state.latency_buckets[2],
            latency_le_1ms = state.latency_buckets[3],
            latency_le_2ms = state.latency_buckets[4],
            latency_le_5ms = state.latency_buckets[5],
            latency_le_10ms = state.latency_buckets[6],
            latency_over_10ms = state.latency_buckets[7],
            latency_max_us = state.latency_max_us,
            "bounded Candidate-A Resolve health snapshot"
        );
        state.interval_started = std::time::Instant::now();
        state.outcomes = [0; RESOLVE_OUTCOME_COUNT];
        state.delayed_hits = 0;
        state.stale_generation = 0;
        state.latency_buckets = [0; RESOLVE_LATENCY_BUCKET_US.len()];
        state.latency_max_us = 0;
    }
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl CandidateAAttributor {
    /// Builds a bounded fail-closed proxy attribution service.
    pub fn new(
        resolver: ResolverClient,
        bindings: Arc<AttributionTable>,
        publication_timeout: std::time::Duration,
        queue_depth: usize,
        on_health_failure: ResolveHealthCallback,
    ) -> Self {
        resolver.set_on_unavailable(Arc::clone(&on_health_failure));
        Self {
            resolver,
            bindings,
            publication_timeout,
            exchange_watchdog: RESOLVE_EXCHANGE_WATCHDOG,
            queue: Semaphore::new(queue_depth.max(1)),
            queue_capacity: queue_depth.max(1),
            queue_high_water: AtomicU64::new(0),
            queue_refused: AtomicU64::new(0),
            on_health_failure,
            observability: ResolveObservability::new(),
        }
    }
}

impl ConnectionAttributor for CandidateAAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let mut attempts = 0_u32;
            let (IpAddr::V4(peer_ip), IpAddr::V4(local_ip)) = (peer.ip(), local.ip()) else {
                let result = AttributionResult::NotFound;
                self.observability
                    .record(&result, attempts, started.elapsed());
                return result;
            };
            let Ok(_permit) = self.queue.try_acquire() else {
                let refused_total = self
                    .queue_refused
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                warn!(
                    event.name = "cgroup_bpf.resolve_queue_full",
                    limit = self.queue_capacity,
                    refused_total,
                    "Candidate-A Resolve denied"
                );
                let result = AttributionResult::QueueFull;
                self.observability
                    .record(&result, attempts, started.elapsed());
                return result;
            };
            let active = self
                .queue_capacity
                .saturating_sub(self.queue.available_permits());
            let active = u64::try_from(active).unwrap_or(u64::MAX);
            self.queue_high_water.fetch_max(active, Ordering::Relaxed);
            debug!(
                event.name = "cgroup_bpf.resolve_queue_occupancy",
                active,
                high_water = self.queue_high_water.load(Ordering::Relaxed),
                limit = self.queue_capacity,
                refused_total = self.queue_refused.load(Ordering::Relaxed),
                "bounded Candidate-A Resolve queue occupancy"
            );
            let tuple = SocketTupleV4 {
                source_address: peer_ip.octets(),
                destination_address: local_ip.octets(),
                source_port: peer.port(),
                destination_port: local.port(),
            };
            let deadline = tokio::time::Instant::now() + self.publication_timeout;
            let mut tuple_absent = false;
            let mut backend_busy = false;
            loop {
                if tokio::time::Instant::now() >= deadline {
                    let result = self.publication_timed_out(tuple_absent, backend_busy);
                    self.observability
                        .record(&result, attempts, started.elapsed());
                    return result;
                }
                attempts = attempts.saturating_add(1);
                // The authenticated-channel watchdog is deliberately independent from the
                // publication deadline. A healthy exchange that starts just before the deadline
                // must not be mistaken for channel loss merely because its response arrives
                // after that deadline.
                let attempt = match tokio::time::timeout(
                    self.exchange_watchdog,
                    self.resolver.request(tuple),
                )
                .await
                {
                    Ok(Ok(attempt)) => attempt,
                    Ok(Err(error)) => {
                        self.resolver.poison();
                        let result = self.unavailable(error);
                        self.observability
                            .record(&result, attempts, started.elapsed());
                        return result;
                    }
                    Err(_) => {
                        self.resolver.poison();
                        let result = self.unavailable(HelperError::Channel(format!(
                            "the active Resolve exchange exceeded its {} ms watchdog",
                            self.exchange_watchdog.as_millis()
                        )));
                        self.observability
                            .record(&result, attempts, started.elapsed());
                        return result;
                    }
                };
                match attempt {
                    ResolveAttempt::Complete { result } => {
                        let result = self.complete(result);
                        self.observability
                            .record(&result, attempts, started.elapsed());
                        return result;
                    }
                    ResolveAttempt::Pending {
                        reason: ResolvePending::TupleAbsent,
                    } => tuple_absent = true,
                    ResolveAttempt::Pending {
                        reason: ResolvePending::BackendBusy,
                    } => backend_busy = true,
                    ResolveAttempt::QueueFull => {
                        let result = AttributionResult::QueueFull;
                        self.observability
                            .record(&result, attempts, started.elapsed());
                        return result;
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    let result = self.publication_timed_out(tuple_absent, backend_busy);
                    self.observability
                        .record(&result, attempts, started.elapsed());
                    return result;
                }
                let wake = tokio::time::Instant::now() + RESOLVE_RETRY_INTERVAL;
                if wake < deadline {
                    tokio::time::sleep_until(wake).await;
                }
            }
        })
    }
}

impl CandidateAAttributor {
    fn complete(&self, result: ResolveResult) -> AttributionResult {
        match result {
            ResolveResult::Resolved { binding } => {
                let resolved = self.bindings.lookup_key_result(binding);
                if matches!(resolved, AttributionResult::IntegrityFailure) {
                    (self.on_health_failure)(ResolveHealthFailure::IntegrityFailure);
                }
                debug!(
                    event.name = "cgroup_bpf.resolve",
                    result = ?resolved,
                    "Candidate-A Resolve completed"
                );
                resolved
            }
            ResolveResult::NotFound => AttributionResult::NotFound,
            ResolveResult::IdentityMismatch { reason } => {
                warn!(
                    event.name = "cgroup_bpf.resolve_identity_mismatch",
                    ?reason,
                    "Candidate-A Resolve denied"
                );
                AttributionResult::IdentityMismatch(reason)
            }
            ResolveResult::Revoked { .. } => AttributionResult::Revoked,
            ResolveResult::Timeout => AttributionResult::Timeout,
            ResolveResult::IntegrityFailure => {
                warn!(
                    event.name = "cgroup_bpf.resolve_integrity_failure",
                    "Candidate-A Resolve denied and runtime health failed"
                );
                (self.on_health_failure)(ResolveHealthFailure::IntegrityFailure);
                AttributionResult::IntegrityFailure
            }
        }
    }

    fn publication_timed_out(&self, tuple_absent: bool, backend_busy: bool) -> AttributionResult {
        let reason = if backend_busy && !tuple_absent {
            "backend_busy_entire_window"
        } else if tuple_absent {
            "tuple_absent"
        } else {
            "no_attempt_completed"
        };
        warn!(
            event.name = "cgroup_bpf.resolve_timeout",
            reason, "Candidate-A Resolve denied at its publication deadline"
        );
        AttributionResult::Timeout
    }

    fn unavailable(&self, error: HelperError) -> AttributionResult {
        warn!(
            event.name = "cgroup_bpf.resolve_unavailable",
            %error,
            "Candidate-A Resolve denied and runtime health failed"
        );
        AttributionResult::Unavailable
    }
}

impl ResolverClient {
    fn set_on_unavailable(&self, callback: ResolveHealthCallback) {
        if let Ok(mut installed) = self.state.on_unavailable.lock() {
            *installed = Some(Arc::clone(&callback));
        }
        if self.state.poisoned.load(Ordering::Acquire) {
            callback(ResolveHealthFailure::Unavailable);
        }
    }

    async fn request(&self, tuple: SocketTupleV4) -> Result<ResolveAttempt, HelperError> {
        if self.state.poisoned.load(Ordering::Acquire) {
            return Err(HelperError::Channel(
                "the Resolve channel is permanently unavailable".to_owned(),
            ));
        }
        let receiver = {
            let _submission = self.state.submission.lock().map_err(|_| {
                HelperError::Channel("the Resolve submission lock is poisoned".to_owned())
            })?;
            let request_id = self.state.next_request_id()?;
            let (response, receiver) = oneshot::channel();
            self.state
                .inflight
                .lock()
                .map_err(|_| HelperError::Channel("the Resolve table lock is poisoned".to_owned()))?
                .insert(
                    request_id,
                    InflightResolve {
                        response,
                        written_at: None,
                    },
                );
            let sender = self
                .state
                .sender
                .lock()
                .map_err(|_| {
                    HelperError::Channel("the Resolve sender lock is poisoned".to_owned())
                })?
                .clone()
                .ok_or_else(|| {
                    HelperError::Channel("the Resolve protocol is not ready".to_owned())
                })?;
            match sender.try_send(ResolverCommand { request_id, tuple }) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.state.remove_inflight(request_id);
                    return Ok(ResolveAttempt::QueueFull);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.state.remove_inflight(request_id);
                    self.state.poison();
                    return Err(HelperError::Channel(
                        "the Resolve writer is unavailable".to_owned(),
                    ));
                }
            }
            receiver
        };
        receiver
            .await
            .map_err(|_| HelperError::Channel("the Resolve response was abandoned".to_owned()))?
    }

    fn poison(&self) {
        self.state.poison();
    }
}

impl ResolverState {
    fn begin_negotiation(
        &self,
        max_pending_resolves: u32,
        resolve_workers: u16,
    ) -> Result<(), HelperError> {
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| HelperError::Channel("the Resolve channel lock is poisoned".to_owned()))?;
        let channel = channel
            .as_mut()
            .ok_or_else(|| HelperError::Unexpected("Resolve was negotiated twice".to_owned()))?;
        let hello = ResolverHello {
            version: RESOLVER_PROTOCOL_VERSION,
            max_pending_resolves,
            resolve_workers,
        };
        write_frame_limited(channel, &hello, MAX_RESOLVER_FRAME_BYTES)
            .map_err(|error| HelperError::Channel(error.to_string()))
    }

    fn finish_negotiation(
        self: &Arc<Self>,
        max_pending_resolves: u32,
        resolve_workers: u16,
    ) -> Result<(), HelperError> {
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| HelperError::Channel("the Resolve channel lock is poisoned".to_owned()))?
            .take()
            .ok_or_else(|| HelperError::Unexpected("Resolve was negotiated twice".to_owned()))?;
        let ready: ResolverReady = read_frame_limited(&mut channel, MAX_RESOLVER_FRAME_BYTES)
            .map_err(|error| HelperError::Channel(error.to_string()))?;
        if ready
            != (ResolverReady {
                version: RESOLVER_PROTOCOL_VERSION,
                max_pending_resolves,
                resolve_workers,
            })
        {
            return Err(HelperError::Unexpected(format!(
                "the Enforcer accepted a different Resolve contract: {ready:?}"
            )));
        }
        self.start_pipeline(
            channel,
            usize::try_from(max_pending_resolves).unwrap_or(usize::MAX),
        )
    }

    fn start_pipeline(
        self: &Arc<Self>,
        channel: UnixStream,
        capacity: usize,
    ) -> Result<(), HelperError> {
        self.inflight
            .lock()
            .map_err(|_| HelperError::Channel("the Resolve table lock is poisoned".to_owned()))?
            .try_reserve(capacity)
            .map_err(|error| {
                HelperError::Unexpected(format!(
                    "the bounded Resolve table could not reserve {capacity} entries: {error}"
                ))
            })?;
        let mut reader = channel
            .try_clone()
            .map_err(|error| HelperError::Channel(error.to_string()))?;
        let mut writer = channel;
        let (sender, receiver) = sync_channel(capacity.max(1));
        *self.sender.lock().map_err(|_| {
            HelperError::Channel("the Resolve sender lock is poisoned".to_owned())
        })? = Some(sender);

        let writer_state = Arc::clone(self);
        std::thread::Builder::new()
            .name("soglia-resolve-write".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    let request = ResolverRequest::Resolve {
                        request_id: command.request_id,
                        tuple: command.tuple,
                    };
                    let should_write = writer_state.prepare_write(command.request_id);
                    if !should_write {
                        continue;
                    }
                    if write_frame_limited(&mut writer, &request, MAX_RESOLVER_FRAME_BYTES).is_err()
                    {
                        writer_state.poison();
                        return;
                    }
                }
            })
            .map_err(|error| {
                HelperError::Unexpected(format!("the Resolve writer could not start: {error}"))
            })?;

        let reader_state = Arc::clone(self);
        std::thread::Builder::new()
            .name("soglia-resolve-read".to_owned())
            .spawn(move || {
                loop {
                    let reply: ResolverReply =
                        match read_frame_limited(&mut reader, MAX_RESOLVER_FRAME_BYTES) {
                            Ok(reply) => reply,
                            Err(_) => {
                                reader_state.poison();
                                return;
                            }
                        };
                    let entry = reader_state
                        .inflight
                        .lock()
                        .ok()
                        .and_then(|mut inflight| inflight.remove(&reply.request_id));
                    let Some(entry) = entry else {
                        reader_state.poison();
                        return;
                    };
                    let _ = entry.response.send(Ok(reply.attempt));
                }
            })
            .map_err(|error| {
                HelperError::Unexpected(format!("the Resolve reader could not start: {error}"))
            })?;

        let watchdog_state = Arc::clone(self);
        std::thread::Builder::new()
            .name("soglia-resolve-watchdog".to_owned())
            .spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    if watchdog_state.poisoned.load(Ordering::Acquire) {
                        return;
                    }
                    let expired = watchdog_state.inflight.lock().map_or(true, |inflight| {
                        inflight.values().any(|entry| {
                            entry.written_at.is_some_and(|started| {
                                started.elapsed() > RESOLVE_EXCHANGE_WATCHDOG
                            })
                        })
                    });
                    if expired {
                        watchdog_state.poison();
                        return;
                    }
                }
            })
            .map_err(|error| {
                HelperError::Unexpected(format!("the Resolve watchdog could not start: {error}"))
            })?;
        Ok(())
    }

    fn remove_inflight(&self, request_id: u64) {
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.remove(&request_id);
        }
    }

    fn prepare_write(&self, request_id: u64) -> bool {
        match self.inflight.lock() {
            Ok(mut inflight) => match inflight.get_mut(&request_id) {
                Some(entry) if !entry.response.is_closed() => {
                    entry.written_at = Some(std::time::Instant::now());
                    true
                }
                Some(_) => {
                    inflight.remove(&request_id);
                    false
                }
                None => false,
            },
            Err(_) => {
                self.poison();
                false
            }
        }
    }

    fn next_request_id(&self) -> Result<u64, HelperError> {
        self.next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                self.poison();
                HelperError::Channel("the Resolve request identifier space is exhausted".to_owned())
            })
    }

    fn poison(&self) {
        if !self.poisoned.swap(true, Ordering::AcqRel) {
            let _ = self.shutdown.shutdown(std::net::Shutdown::Both);
            if let Ok(mut inflight) = self.inflight.lock() {
                for (_, entry) in inflight.drain() {
                    let _ = entry.response.send(Err(HelperError::Channel(
                        "the Resolve channel is permanently unavailable".to_owned(),
                    )));
                }
            }
            let callback = self
                .on_unavailable
                .lock()
                .ok()
                .and_then(|installed| installed.clone());
            if let Some(callback) = callback {
                callback(ResolveHealthFailure::Unavailable);
            }
        }
    }
}

/// How long a helper may take to clean up and exit once its channel closes.
const EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

impl Drop for Helper {
    /// Closes the channel and waits for the helper to finish: on end of input it kills or freezes
    /// whatever is still live, and the runtime should not report itself stopped before that is done.
    fn drop(&mut self) {
        self.close_channel();
        let Ok(mut process) = self.process.lock() else {
            return;
        };
        let started = std::time::Instant::now();
        while started.elapsed() < EXIT_GRACE {
            if !matches!(process.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        eprintln!(
            "soglia: the {} helper did not exit after its channel closed",
            self.role
        );
    }
}

fn exchange<R: Serialize, A: DeserializeOwned>(
    channel: &Mutex<UnixStream>,
    request: &R,
) -> Result<A, HelperError> {
    let mut stream = channel
        .lock()
        .map_err(|_| HelperError::Channel("the channel lock is poisoned".to_owned()))?;
    write_frame(&mut *stream, request).map_err(|error| HelperError::Channel(error.to_string()))?;
    read_frame(&mut *stream).map_err(|error| HelperError::Channel(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;

    use soglia_core::helper::{RefusalClass, ResolveMismatch};
    use soglia_core::{BindingKey, ExecutionNonce};

    fn resolver_client(stream: UnixStream) -> ResolverClient {
        let shutdown = stream.try_clone().unwrap();
        let state = Arc::new(ResolverState {
            channel: Mutex::new(None),
            sender: Mutex::new(None),
            inflight: Mutex::new(HashMap::new()),
            submission: Mutex::new(()),
            shutdown,
            poisoned: AtomicBool::new(false),
            next_request_id: AtomicU64::new(1),
            on_unavailable: Mutex::new(None),
        });
        state.start_pipeline(stream, 1024).unwrap();
        ResolverClient { state }
    }

    #[test]
    fn helper_refusal_reaches_the_supervisor_without_text_classification() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let shutdown = ours.try_clone().unwrap();
        let failure = HelperFailure::IncompatibleBpfTopology {
            hook: "soglia_connect4".into(),
            errno: Some(1),
            detail: "exclusive ancestor".into(),
        };
        let sent = failure.clone();
        let server = std::thread::spawn(move || {
            let _: Hello = read_frame(&mut theirs).unwrap();
            write_frame(&mut theirs, &HelperResponse::Failed { failure: sent }).unwrap();
        });
        let process = Command::new("/bin/sh")
            .args(["-c", "sleep 1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let helper = Helper {
            role: "test",
            channel: Arc::new(Mutex::new(ours)),
            resolver: None,
            shutdown,
            resolver_shutdown: None,
            process: Arc::new(Mutex::new(process)),
        };

        assert_eq!(
            helper.hello("runtime: {}"),
            Err(HelperError::Failed(failure))
        );
        server.join().unwrap();

        let classified = HelperError::Failed(HelperFailure::Refused {
            class: RefusalClass::Unknown,
            detail: "untrusted ownership".into(),
        });
        assert!(matches!(
            classified,
            HelperError::Failed(HelperFailure::Refused {
                class: RefusalClass::Unknown,
                ..
            })
        ));
    }

    fn resolver_returning(result: ResolveResult) -> ResolverClient {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let ResolverRequest::Resolve { request_id, .. } = read_frame(&mut theirs).unwrap();
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id,
                    attempt: ResolveAttempt::Complete { result },
                },
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });
        resolver_client(ours)
    }

    fn binding() -> BindingKey {
        BindingKey {
            cgroup_id: 73,
            execution_nonce: ExecutionNonce::generate().unwrap(),
            backend_generation: 5,
        }
    }

    #[test]
    fn resolve_observability_has_bounded_typed_outcomes_and_latency_buckets() {
        let observability = ResolveObservability::new();
        observability.record(&AttributionResult::NotFound, 1, Duration::from_micros(600));
        observability.record(
            &AttributionResult::IdentityMismatch(ResolveMismatch::BackendGeneration),
            2,
            Duration::from_millis(12),
        );
        let state = observability.state.lock().unwrap();
        assert_eq!(state.outcomes[1], 1);
        assert_eq!(state.outcomes[2], 1);
        assert_eq!(state.stale_generation, 1);
        assert_eq!(state.latency_buckets[3], 1);
        assert_eq!(state.latency_buckets[7], 1);
        assert_eq!(state.latency_max_us, 12_000);
        assert_eq!(duration_millis(Duration::from_millis(1_234)), 1_234);
    }

    async fn resolve_once(result: ResolveResult) -> (AttributionResult, Vec<ResolveHealthFailure>) {
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let attributor = CandidateAAttributor::new(
            resolver_returning(result),
            Arc::new(AttributionTable::new()),
            Duration::from_millis(10),
            1,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        );
        let outcome = attributor
            .resolve(
                "127.0.0.1:40000".parse().unwrap(),
                "127.0.0.1:15001".parse().unwrap(),
            )
            .await;
        let failures = failures.lock().unwrap().clone();
        (outcome, failures)
    }

    #[tokio::test]
    async fn mismatch_and_timeout_deny_without_changing_runtime_health() {
        let (mismatch, failures) = resolve_once(ResolveResult::IdentityMismatch {
            reason: ResolveMismatch::ExecutionNonce,
        })
        .await;
        assert!(matches!(
            mismatch,
            AttributionResult::IdentityMismatch(ResolveMismatch::ExecutionNonce)
        ));
        assert!(failures.is_empty());

        let (timeout, failures) = resolve_once(ResolveResult::Timeout).await;
        assert!(matches!(timeout, AttributionResult::Timeout));
        assert!(failures.is_empty());
    }

    #[tokio::test]
    async fn integrity_failure_denies_and_changes_runtime_health() {
        let (outcome, failures) = resolve_once(ResolveResult::IntegrityFailure).await;
        assert!(matches!(outcome, AttributionResult::IntegrityFailure));
        assert_eq!(failures, vec![ResolveHealthFailure::IntegrityFailure]);
    }

    #[tokio::test]
    async fn missing_and_revoked_live_bindings_stay_distinct() {
        let key = binding();
        let (missing, failures) = resolve_once(ResolveResult::Resolved { binding: key }).await;
        assert!(matches!(missing, AttributionResult::NotFound));
        assert!(failures.is_empty());

        let table = Arc::new(AttributionTable::new());
        let id = soglia_core::ExecutionId::generate().unwrap();
        table.bind_key(key, id).unwrap();
        table.revoke_key(key);
        let attributor = CandidateAAttributor::new(
            resolver_returning(ResolveResult::Resolved { binding: key }),
            table,
            Duration::from_millis(10),
            1,
            Arc::new(|_| panic!("revocation is not a health failure")),
        );
        let revoked = attributor
            .resolve(
                "127.0.0.1:40001".parse().unwrap(),
                "127.0.0.1:15001".parse().unwrap(),
            )
            .await;
        assert!(matches!(revoked, AttributionResult::Revoked));
    }

    #[tokio::test]
    async fn broken_resolve_channel_is_unavailable_and_changes_runtime_health() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let attributor = CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_millis(10),
            1,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        );
        let outcome = attributor
            .resolve(
                "127.0.0.1:40002".parse().unwrap(),
                "127.0.0.1:15001".parse().unwrap(),
            )
            .await;
        assert!(matches!(outcome, AttributionResult::Unavailable));
        assert_eq!(
            *failures.lock().unwrap(),
            vec![ResolveHealthFailure::Unavailable]
        );
    }

    fn tuple(port: u16) -> SocketTupleV4 {
        SocketTupleV4 {
            source_address: [127, 0, 0, 1],
            destination_address: [127, 0, 0, 1],
            source_port: port,
            destination_port: 15_001,
        }
    }

    #[tokio::test]
    async fn concurrent_missing_tuples_timeout_without_a_health_failure() {
        const CONCURRENT: usize = 4;
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            while let Ok(ResolverRequest::Resolve { request_id, .. }) = read_frame(&mut theirs) {
                if write_frame(
                    &mut theirs,
                    &ResolverReply {
                        request_id,
                        attempt: ResolveAttempt::Pending {
                            reason: ResolvePending::TupleAbsent,
                        },
                    },
                )
                .is_err()
                {
                    return;
                }
            }
        });
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let attributor = Arc::new(CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_millis(40),
            CONCURRENT,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        ));
        let mut tasks = tokio::task::JoinSet::new();
        for offset in 0..CONCURRENT {
            let attributor = Arc::clone(&attributor);
            tasks.spawn(async move {
                let started = tokio::time::Instant::now();
                let result = attributor
                    .resolve(
                        format!("127.0.0.1:{}", 40_100 + offset).parse().unwrap(),
                        "127.0.0.1:15001".parse().unwrap(),
                    )
                    .await;
                (result, started.elapsed())
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (outcome, elapsed) = result.unwrap();
            assert!(matches!(outcome, AttributionResult::Timeout));
            assert!(elapsed < Duration::from_millis(250), "{elapsed:?}");
        }
        assert!(failures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pending_after_the_publication_deadline_times_out_without_poisoning() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let ResolverRequest::Resolve {
                request_id: first, ..
            } = read_frame(&mut theirs).unwrap();
            std::thread::sleep(Duration::from_millis(60));
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id: first,
                    attempt: ResolveAttempt::Pending {
                        reason: ResolvePending::TupleAbsent,
                    },
                },
            )
            .unwrap();
            let ResolverRequest::Resolve {
                request_id: second, ..
            } = read_frame(&mut theirs).unwrap();
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id: second,
                    attempt: ResolveAttempt::Complete {
                        result: ResolveResult::NotFound,
                    },
                },
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let mut attributor = CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_millis(20),
            1,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        );
        attributor.exchange_watchdog = Duration::from_millis(250);

        let outcome = attributor
            .resolve(
                "127.0.0.1:40410".parse().unwrap(),
                "127.0.0.1:15001".parse().unwrap(),
            )
            .await;
        assert!(matches!(outcome, AttributionResult::Timeout));
        let next = attributor
            .resolve(
                "127.0.0.1:40411".parse().unwrap(),
                "127.0.0.1:15001".parse().unwrap(),
            )
            .await;
        assert!(matches!(next, AttributionResult::NotFound));
        assert!(failures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn complete_after_the_publication_deadline_is_still_consumed() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            for index in 0..2 {
                let ResolverRequest::Resolve { request_id, .. } = read_frame(&mut theirs).unwrap();
                if index == 0 {
                    std::thread::sleep(Duration::from_millis(60));
                }
                write_frame(
                    &mut theirs,
                    &ResolverReply {
                        request_id,
                        attempt: ResolveAttempt::Complete {
                            result: ResolveResult::NotFound,
                        },
                    },
                )
                .unwrap();
            }
            std::thread::sleep(Duration::from_secs(1));
        });
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let mut attributor = CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_millis(20),
            1,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        );
        attributor.exchange_watchdog = Duration::from_millis(250);

        for port in [40_420, 40_421] {
            let outcome = attributor
                .resolve(
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    "127.0.0.1:15001".parse().unwrap(),
                )
                .await;
            assert!(matches!(outcome, AttributionResult::NotFound));
        }
        assert!(failures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_caller_cannot_desynchronize_the_next_exchange() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let ResolverRequest::Resolve {
                request_id: first, ..
            } = read_frame(&mut theirs).unwrap();
            std::thread::sleep(Duration::from_millis(40));
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id: first,
                    attempt: ResolveAttempt::Pending {
                        reason: ResolvePending::TupleAbsent,
                    },
                },
            )
            .unwrap();
            let ResolverRequest::Resolve {
                request_id: second, ..
            } = read_frame(&mut theirs).unwrap();
            assert_eq!(second, first + 1);
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id: second,
                    attempt: ResolveAttempt::Complete {
                        result: ResolveResult::NotFound,
                    },
                },
            )
            .unwrap();
        });
        let client = resolver_client(ours);
        let abandoned_client = client.clone();
        let abandoned = tokio::spawn(async move { abandoned_client.request(tuple(40_200)).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        abandoned.abort();

        let result = tokio::time::timeout(Duration::from_secs(1), client.request(tuple(40_201)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result,
            ResolveAttempt::Complete {
                result: ResolveResult::NotFound
            }
        );
    }

    #[test]
    fn cancellation_before_write_removes_the_request_without_a_frame() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let client = resolver_client(ours);
        let (response, receiver) = oneshot::channel();
        drop(receiver);
        client.state.inflight.lock().unwrap().insert(
            900,
            InflightResolve {
                response,
                written_at: None,
            },
        );
        assert!(!client.state.prepare_write(900));
        assert!(!client.state.inflight.lock().unwrap().contains_key(&900));
    }

    #[tokio::test]
    async fn out_of_order_replies_are_correlated_to_their_request_ids() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let first: ResolverRequest = read_frame(&mut theirs).unwrap();
            let second: ResolverRequest = read_frame(&mut theirs).unwrap();
            let ResolverRequest::Resolve {
                request_id: first_id,
                ..
            } = first;
            let ResolverRequest::Resolve {
                request_id: second_id,
                ..
            } = second;
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id: second_id,
                    attempt: ResolveAttempt::Complete {
                        result: ResolveResult::NotFound,
                    },
                },
            )
            .unwrap();
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id: first_id,
                    attempt: ResolveAttempt::Complete {
                        result: ResolveResult::Timeout,
                    },
                },
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });
        let client = resolver_client(ours);
        let first = {
            let client = client.clone();
            tokio::spawn(async move { client.request(tuple(40_500)).await.unwrap() })
        };
        tokio::time::sleep(Duration::from_millis(1)).await;
        let second = {
            let client = client.clone();
            tokio::spawn(async move { client.request(tuple(40_501)).await.unwrap() })
        };
        assert_eq!(
            second.await.unwrap(),
            ResolveAttempt::Complete {
                result: ResolveResult::NotFound
            }
        );
        assert_eq!(
            first.await.unwrap(),
            ResolveAttempt::Complete {
                result: ResolveResult::Timeout
            }
        );
    }

    #[tokio::test]
    async fn a_full_logical_queue_refuses_only_the_extra_connection() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let ResolverRequest::Resolve { request_id, .. } = read_frame(&mut theirs).unwrap();
            std::thread::sleep(Duration::from_millis(80));
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id,
                    attempt: ResolveAttempt::Complete {
                        result: ResolveResult::NotFound,
                    },
                },
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });
        let attributor = Arc::new(CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_secs(1),
            1,
            Arc::new(|failure| panic!("unexpected health failure: {failure:?}")),
        ));
        let first = {
            let attributor = Arc::clone(&attributor);
            tokio::spawn(async move {
                attributor
                    .resolve(
                        "127.0.0.1:40510".parse().unwrap(),
                        "127.0.0.1:15001".parse().unwrap(),
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        let refused = attributor
            .resolve(
                "127.0.0.1:40511".parse().unwrap(),
                "127.0.0.1:15001".parse().unwrap(),
            )
            .await;
        assert!(matches!(refused, AttributionResult::QueueFull));
        assert!(matches!(first.await.unwrap(), AttributionResult::NotFound));
    }

    #[tokio::test]
    async fn a_wrong_response_id_poisons_the_channel_permanently() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let ResolverRequest::Resolve { request_id, .. } = read_frame(&mut theirs).unwrap();
            write_frame(
                &mut theirs,
                &ResolverReply {
                    request_id: request_id + 1,
                    attempt: ResolveAttempt::Complete {
                        result: ResolveResult::NotFound,
                    },
                },
            )
            .unwrap();
        });
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let attributor = CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_secs(1),
            1,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        );
        for port in [40_300, 40_301] {
            let outcome = attributor
                .resolve(
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    "127.0.0.1:15001".parse().unwrap(),
                )
                .await;
            assert!(matches!(outcome, AttributionResult::Unavailable));
        }
        assert_eq!(
            *failures.lock().unwrap(),
            vec![ResolveHealthFailure::Unavailable]
        );
    }

    #[tokio::test]
    async fn a_duplicate_response_id_poisons_the_channel_after_the_first_reply() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let ResolverRequest::Resolve { request_id, .. } = read_frame(&mut theirs).unwrap();
            let reply = ResolverReply {
                request_id,
                attempt: ResolveAttempt::Complete {
                    result: ResolveResult::NotFound,
                },
            };
            write_frame(&mut theirs, &reply).unwrap();
            write_frame(&mut theirs, &reply).unwrap();
        });
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let attributor = CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_secs(1),
            1,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        );
        assert!(matches!(
            attributor
                .resolve(
                    "127.0.0.1:40310".parse().unwrap(),
                    "127.0.0.1:15001".parse().unwrap(),
                )
                .await,
            AttributionResult::NotFound
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while failures.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            attributor
                .resolve(
                    "127.0.0.1:40311".parse().unwrap(),
                    "127.0.0.1:15001".parse().unwrap(),
                )
                .await,
            AttributionResult::Unavailable
        ));
        assert_eq!(
            *failures.lock().unwrap(),
            vec![ResolveHealthFailure::Unavailable]
        );
    }

    #[tokio::test]
    async fn a_watchdog_timeout_poisons_the_channel_permanently() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let _: ResolverRequest = read_frame(&mut theirs).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let failures = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&failures);
        let mut attributor = CandidateAAttributor::new(
            resolver_client(ours),
            Arc::new(AttributionTable::new()),
            Duration::from_secs(1),
            1,
            Arc::new(move |failure| observed.lock().unwrap().push(failure)),
        );
        attributor.exchange_watchdog = Duration::from_millis(20);
        for port in [40_400, 40_401] {
            let outcome = attributor
                .resolve(
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    "127.0.0.1:15001".parse().unwrap(),
                )
                .await;
            assert!(matches!(outcome, AttributionResult::Unavailable));
        }
        assert_eq!(
            *failures.lock().unwrap(),
            vec![ResolveHealthFailure::Unavailable]
        );
    }

    fn child(script: &str) -> Helper {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let shutdown = ours.try_clone().unwrap();
        let process = Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Helper {
            role: "test",
            channel: Arc::new(Mutex::new(ours)),
            resolver: None,
            shutdown,
            resolver_shutdown: None,
            process: Arc::new(Mutex::new(process)),
        }
    }

    #[tokio::test]
    async fn child_exit_is_observed_without_an_rpc() {
        let helper = child("exit 23");
        let status = tokio::time::timeout(Duration::from_secs(2), helper.watch_exit())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(23));
    }

    #[tokio::test]
    async fn closing_the_channel_releases_a_healthy_helper() {
        let helper = child("cat >/dev/null");
        let exit = helper.watch_exit();
        helper.close_channel();
        let status = tokio::time::timeout(Duration::from_secs(2), exit)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(status.success(), "{status:?}");
        assert_eq!(status.signal(), None);
    }
}
