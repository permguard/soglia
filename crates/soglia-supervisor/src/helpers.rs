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
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde::de::DeserializeOwned;
use soglia_core::helper::{
    Hello, HelperResponse, ResolveAttempt, ResolvePending, ResolveResult, ResolverReply,
    ResolverRequest, SocketTupleV4,
};
use soglia_core::ipc::{read_frame, write_frame};
use soglia_proxy::attribution::{AttributionResult, AttributionTable, ConnectionAttributor};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, Semaphore};
use tracing::{debug, warn};

/// Callback invoked once when the Resolve channel first becomes permanently unhealthy.
pub type ResolveHealthCallback = Arc<dyn Fn(ResolveHealthFailure) + Send + Sync>;

/// Why a helper exchange failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperError {
    /// The channel broke: the helper is gone, and the runtime cannot continue safely.
    Channel(String),
    /// The helper carried out the request and it failed.
    Failed(String),
    /// The helper answered with something the request does not allow.
    Unexpected(String),
}

impl fmt::Display for HelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(reason) => write!(formatter, "the helper channel failed: {reason}"),
            Self::Failed(reason) => write!(formatter, "{reason}"),
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
                    channel: Mutex::new(ours),
                    shutdown: poison_shutdown,
                    gate: Arc::new(AsyncMutex::new(())),
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
        match exchange(&self.channel, &hello)? {
            HelperResponse::Ready { swept } => Ok(swept),
            HelperResponse::Failed { reason } => Err(HelperError::Failed(reason)),
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
            HelperResponse::Failed { reason } => Err(HelperError::Failed(reason)),
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
    channel: Mutex<UnixStream>,
    shutdown: UnixStream,
    gate: Arc<AsyncMutex<()>>,
    poisoned: AtomicBool,
    next_request_id: AtomicU64,
    on_unavailable: Mutex<Option<ResolveHealthCallback>>,
}

#[derive(Clone)]
pub struct ResolverClient {
    state: Arc<ResolverState>,
}

struct ResolveLease {
    state: Arc<ResolverState>,
    guard: OwnedMutexGuard<()>,
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
    on_health_failure: ResolveHealthCallback,
}

/// A one-shot IPC exchange performs one try-lock and at most one BPF map lookup. One second leaves
/// ample scheduler headroom while still detecting a stuck authenticated channel promptly.
const RESOLVE_EXCHANGE_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(1);
/// This preserves the previously qualified publication polling cadence without holding any lock.
const RESOLVE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(2);

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
            on_health_failure,
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
            let (IpAddr::V4(peer_ip), IpAddr::V4(local_ip)) = (peer.ip(), local.ip()) else {
                return AttributionResult::NotFound;
            };
            let Ok(_permit) = self.queue.try_acquire() else {
                warn!(
                    event.name = "cgroup_bpf.resolve_queue_full",
                    "Candidate-A Resolve denied"
                );
                return AttributionResult::QueueFull;
            };
            let tuple = SocketTupleV4 {
                source_address: peer_ip.octets(),
                destination_address: local_ip.octets(),
                source_port: peer.port(),
                destination_port: local.port(),
            };
            let deadline = tokio::time::Instant::now() + self.publication_timeout;
            let mut attempted = false;
            let mut tuple_absent = false;
            let mut backend_busy = false;
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return self.publication_timed_out(tuple_absent, backend_busy);
                }
                let lease = match tokio::time::timeout_at(deadline, self.resolver.acquire()).await {
                    Ok(Ok(lease)) => lease,
                    Ok(Err(error)) => return self.unavailable(error),
                    Err(_) if attempted => {
                        return self.publication_timed_out(tuple_absent, backend_busy);
                    }
                    Err(_) => {
                        warn!(
                            event.name = "cgroup_bpf.resolve_queue_full",
                            "Candidate-A Resolve expired waiting for the IPC gate"
                        );
                        return AttributionResult::QueueFull;
                    }
                };
                attempted = true;
                // The authenticated-channel watchdog is deliberately independent from the
                // publication deadline. A healthy exchange that starts just before the deadline
                // must not be mistaken for channel loss merely because its response arrives
                // after that deadline.
                let exchange = match lease.start(tuple, self.exchange_watchdog) {
                    Ok(exchange) => exchange,
                    Err(error) => return self.unavailable(error),
                };
                let attempt = match tokio::time::timeout(self.exchange_watchdog, exchange).await {
                    Ok(Ok(Ok(attempt))) => attempt,
                    Ok(Ok(Err(error))) => return self.unavailable(error),
                    Ok(Err(error)) => {
                        self.resolver.poison();
                        return self.unavailable(HelperError::Channel(error.to_string()));
                    }
                    Err(_) => {
                        self.resolver.poison();
                        return self.unavailable(HelperError::Channel(format!(
                            "the active Resolve exchange exceeded its {} ms watchdog",
                            self.exchange_watchdog.as_millis()
                        )));
                    }
                };
                match attempt {
                    ResolveAttempt::Complete { result } => return self.complete(result),
                    ResolveAttempt::Pending {
                        reason: ResolvePending::TupleAbsent,
                    } => tuple_absent = true,
                    ResolveAttempt::Pending {
                        reason: ResolvePending::BackendBusy,
                    } => backend_busy = true,
                }
                if tokio::time::Instant::now() >= deadline {
                    return self.publication_timed_out(tuple_absent, backend_busy);
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

    async fn acquire(&self) -> Result<ResolveLease, HelperError> {
        if self.state.poisoned.load(Ordering::Acquire) {
            return Err(HelperError::Channel(
                "the Resolve channel is permanently unavailable".to_owned(),
            ));
        }
        let guard = Arc::clone(&self.state.gate).lock_owned().await;
        if self.state.poisoned.load(Ordering::Acquire) {
            return Err(HelperError::Channel(
                "the Resolve channel is permanently unavailable".to_owned(),
            ));
        }
        Ok(ResolveLease {
            state: Arc::clone(&self.state),
            guard,
        })
    }

    fn poison(&self) {
        self.state.poison();
    }
}

impl ResolverState {
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

impl ResolveLease {
    fn start(
        self,
        tuple: SocketTupleV4,
        watchdog: std::time::Duration,
    ) -> Result<tokio::task::JoinHandle<Result<ResolveAttempt, HelperError>>, HelperError> {
        let request_id = self.state.next_request_id()?;
        let request = ResolverRequest::Resolve { request_id, tuple };
        let state = Arc::clone(&self.state);
        let guard = self.guard;
        Ok(tokio::task::spawn_blocking(move || {
            // The blocking task, not its caller, owns the gate. Dropping or timing out the caller
            // cannot let another write overtake this request's still-pending read.
            let _guard = guard;
            let result =
                correlated_resolve_exchange(&state.channel, &request, request_id, watchdog);
            if result.is_err() {
                state.poison();
            }
            result
        }))
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

fn correlated_resolve_exchange(
    channel: &Mutex<UnixStream>,
    request: &ResolverRequest,
    expected_request_id: u64,
    watchdog: std::time::Duration,
) -> Result<ResolveAttempt, HelperError> {
    let mut stream = channel
        .lock()
        .map_err(|_| HelperError::Channel("the channel lock is poisoned".to_owned()))?;
    stream
        .set_write_timeout(Some(watchdog))
        .map_err(|error| HelperError::Channel(error.to_string()))?;
    stream
        .set_read_timeout(Some(watchdog))
        .map_err(|error| HelperError::Channel(error.to_string()))?;
    let result = (|| {
        write_frame(&mut *stream, request)
            .map_err(|error| HelperError::Channel(error.to_string()))?;
        read_frame(&mut *stream).map_err(|error| HelperError::Channel(error.to_string()))
    })();
    let _ = stream.set_write_timeout(None);
    let _ = stream.set_read_timeout(None);
    let reply: ResolverReply = result?;
    if reply.request_id != expected_request_id {
        return Err(HelperError::Channel(format!(
            "Resolve response id {} did not match request id {expected_request_id}",
            reply.request_id
        )));
    }
    Ok(reply.attempt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;

    use soglia_core::helper::ResolveMismatch;
    use soglia_core::{BindingKey, ExecutionNonce};

    fn resolver_client(stream: UnixStream) -> ResolverClient {
        let shutdown = stream.try_clone().unwrap();
        ResolverClient {
            state: Arc::new(ResolverState {
                channel: Mutex::new(stream),
                shutdown,
                gate: Arc::new(AsyncMutex::new(())),
                poisoned: AtomicBool::new(false),
                next_request_id: AtomicU64::new(1),
                on_unavailable: Mutex::new(None),
            }),
        }
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
        let abandoned = client
            .acquire()
            .await
            .unwrap()
            .start(tuple(40_200), RESOLVE_EXCHANGE_WATCHDOG)
            .unwrap();
        drop(abandoned);

        let lease = tokio::time::timeout(Duration::from_secs(1), client.acquire())
            .await
            .unwrap()
            .unwrap();
        let result = lease
            .start(tuple(40_201), RESOLVE_EXCHANGE_WATCHDOG)
            .unwrap()
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
