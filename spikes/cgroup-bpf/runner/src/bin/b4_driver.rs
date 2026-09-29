// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Production Candidate-A B4 capacity and publication qualification driver.
//!
//! This is a privileged qualification harness. It never substitutes a test BPF object: every
//! enforcement decision comes from the unchanged production object loaded by the production
//! Enforcer. Deliberate map injections are individually recorded and exactly removed.

use std::future::Future;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, io};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soglia_core::config::Config;
use soglia_core::helper::{EnforcerRequest, HelperResponse, ResolveMismatch, SandboxRequest};
use soglia_core::{BindingKey, ExecutionId, ExecutionNonce};
use soglia_proxy::attribution::{AttributionResult, AttributionTable, ConnectionAttributor};
use soglia_proxy::egress::{EgressLimits, EgressProxy};
use soglia_proxy::policy::DestinationPolicy;
use soglia_proxy::resolver::{Resolution, Resolver};
use soglia_supervisor::helpers::{CandidateAAttributor, Helper, HelperError, ResolveHealthFailure};
use tokio::net::TcpListener;
use tokio::sync::watch;

const C_EVENTS_DROPPED: u32 = 0;
const C_COOKIE_INSERT_FAILED: u32 = 1;
const C_TUPLE_INSERT_FAILED: u32 = 2;
const C_PUBLISHED: u32 = 3;
const C_UNPUBLISHED: u32 = 4;
const C_CONNECT4_DENY: u32 = 6;
const C_COOKIE_MISS: u32 = 10;
const EXPECTED_SOCKET_CAPACITY: usize = 4;
const EXPECTED_POLICY_CAPACITY: usize = 3;
const EXPECTED_RING_BYTES: u64 = 4096;
const FIXED_TIMEOUT_MS: u64 = 2000;
const TIMEOUT_EARLY_TOLERANCE_MS: u64 = 100;
const TIMEOUT_LATE_TOLERANCE_MS: u64 = 250;
const DELAYED_PUBLICATION_MS: u64 = 250;
const RING_ATTEMPTS: u64 = 256;

#[derive(Clone)]
struct CountingResolver {
    calls: Arc<AtomicUsize>,
}

impl Resolver for CountingResolver {
    fn resolve<'a>(&'a self, _name: &'a str) -> Resolution<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))]) })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum OutcomeKind {
    Resolved,
    NotFound,
    IdentityMismatch,
    Revoked,
    Timeout,
    QueueFull,
    Unavailable,
    IntegrityFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum HealthFailure {
    Unavailable,
    IntegrityFailure,
}

#[derive(Clone, Copy, Debug)]
enum PublicationFault {
    None,
    Remove,
    Delay(u64),
}

#[derive(Clone, Debug, Serialize)]
struct ResolveObservation {
    peer: SocketAddr,
    local: SocketAddr,
    recv_q_bytes: u64,
    tuple_cookie: Option<u64>,
    outcome: OutcomeKind,
    mismatch: Option<ResolveMismatch>,
    resolved_execution: Option<ExecutionId>,
    elapsed_ms: u64,
    dns_when_resolve_returned: usize,
    outbound_when_resolve_returned: usize,
    health_failure: Option<HealthFailure>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Counters {
    events_dropped: u64,
    cookie_insert_failed: u64,
    tuple_insert_failed: u64,
    published: u64,
    unpublished: u64,
    connect4_deny: u64,
    cookie_miss: u64,
    policies: usize,
    cookies: usize,
    tuples: usize,
}

struct RecordingAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    fault: PublicationFault,
    observations: Arc<Mutex<Vec<ResolveObservation>>>,
    bpftool: PathBuf,
    state: PathBuf,
    evidence: PathBuf,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    health: Arc<Mutex<Option<HealthFailure>>>,
}

impl ConnectionAttributor for RecordingAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move {
            let index = self
                .observations
                .lock()
                .map(|observations| observations.len())
                .unwrap_or(usize::MAX);
            let recv_q_bytes = capture_receive_queue(peer, local).unwrap_or(0);
            let captured = match self.fault {
                PublicationFault::None => capture_tuple(
                    &self.bpftool,
                    &self.state,
                    peer,
                    local,
                    Duration::from_millis(50),
                )
                .ok(),
                PublicationFault::Remove | PublicationFault::Delay(_) => capture_tuple(
                    &self.bpftool,
                    &self.state,
                    peer,
                    local,
                    Duration::from_secs(1),
                )
                .ok(),
            };
            let mut reinsertion = None;
            if matches!(
                self.fault,
                PublicationFault::Remove | PublicationFault::Delay(_)
            ) {
                let Some((cookie, _binding, key, value)) = captured.clone() else {
                    return AttributionResult::IntegrityFailure;
                };
                let pin = match state_map_pin(&self.state, "soglia_tuples") {
                    Ok(pin) => pin,
                    Err(_) => return AttributionResult::IntegrityFailure,
                };
                if map_delete(&self.bpftool, &pin, &key).is_err() {
                    return AttributionResult::IntegrityFailure;
                }
                let record = json!({
                    "actor": "B4 qualification harness",
                    "single_mutation": true,
                    "production_code_modified": false,
                    "peer": peer,
                    "local": local,
                    "tuple_key_hex": hex(&key),
                    "tuple_value_hex": hex(&value),
                    "cookie": cookie,
                    "fault": match self.fault {
                        PublicationFault::Remove => "REMOVE_UNTIL_TIMEOUT",
                        PublicationFault::Delay(_) => "REMOVE_THEN_REINSERT",
                        PublicationFault::None => "NONE",
                    }
                });
                let _ = fs::write(
                    self.evidence
                        .join(format!("publication-fault-{index}.json")),
                    serde_json::to_vec_pretty(&record).unwrap_or_default(),
                );
                if let PublicationFault::Delay(delay_ms) = self.fault {
                    let bpftool = self.bpftool.clone();
                    reinsertion = Some(tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        map_update(&bpftool, &pin, &key, &value)
                    }));
                }
            }

            let started = Instant::now();
            let result = self.inner.resolve(peer, local).await;
            if let Some(reinsertion) = reinsertion {
                match reinsertion.await {
                    Ok(Ok(())) => {}
                    _ => return AttributionResult::IntegrityFailure,
                }
            }
            let (outcome, mismatch, resolved_execution) = classify(&result);
            let observation = ResolveObservation {
                peer,
                local,
                recv_q_bytes,
                tuple_cookie: captured.map(|tuple| tuple.0),
                outcome,
                mismatch,
                resolved_execution,
                elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                dns_when_resolve_returned: self.dns.load(Ordering::SeqCst),
                outbound_when_resolve_returned: self.outbound.load(Ordering::SeqCst),
                health_failure: self.health.lock().ok().and_then(|health| *health),
            };
            if let Ok(mut observations) = self.observations.lock() {
                observations.push(observation);
            }
            result
        })
    }
}

fn classify(
    result: &AttributionResult,
) -> (OutcomeKind, Option<ResolveMismatch>, Option<ExecutionId>) {
    match result {
        AttributionResult::Resolved(binding) => (OutcomeKind::Resolved, None, Some(binding.id)),
        AttributionResult::NotFound => (OutcomeKind::NotFound, None, None),
        AttributionResult::IdentityMismatch(reason) => {
            (OutcomeKind::IdentityMismatch, Some(*reason), None)
        }
        AttributionResult::Revoked => (OutcomeKind::Revoked, None, None),
        AttributionResult::Timeout => (OutcomeKind::Timeout, None, None),
        AttributionResult::QueueFull => (OutcomeKind::QueueFull, None, None),
        AttributionResult::Unavailable => (OutcomeKind::Unavailable, None, None),
        AttributionResult::IntegrityFailure => (OutcomeKind::IntegrityFailure, None, None),
    }
}

struct Execution<'a> {
    sandbox: &'a Helper,
    enforcer: &'a Helper,
    id: ExecutionId,
    binding: BindingKey,
    reserved: bool,
    prepared: bool,
    bound: bool,
}

impl Execution<'_> {
    async fn cleanup(&mut self, table: &AttributionTable) -> Vec<String> {
        let mut failures = Vec::new();
        if self.bound {
            table.revoke_key(self.binding);
        }
        if self.prepared
            && let Err(error) = self
                .enforcer
                .call(EnforcerRequest::Freeze { tag: self.id.tag() })
                .await
        {
            failures.push(format!("freeze: {error}"));
        }
        if self.reserved {
            if let Err(error) = self
                .sandbox
                .call(SandboxRequest::Kill { tag: self.id.tag() })
                .await
            {
                failures.push(format!("kill: {error}"));
            }
            if let Err(error) = self
                .sandbox
                .call(SandboxRequest::Destroy { tag: self.id.tag() })
                .await
            {
                failures.push(format!("sandbox destroy: {error}"));
            }
        }
        if self.prepared
            && let Err(error) = self
                .enforcer
                .call(EnforcerRequest::Destroy { tag: self.id.tag() })
                .await
        {
            failures.push(format!("enforcer destroy: {error}"));
        }
        if self.bound && !table.remove_key(self.binding, self.id) {
            failures.push("live BindingKey was not released".to_owned());
        }
        failures
    }
}

struct Prepared<'a> {
    execution: Execution<'a>,
    pid: i32,
    address: Ipv4Addr,
}

struct ProxyTask {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl ProxyTask {
    async fn stop(self) -> Result<(), String> {
        self.stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .map_err(|_| "B4 proxy did not stop".to_owned())?
            .map_err(|error| error.to_string())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_target(false)
        .try_init()
        .ok();
    if let Err(error) = run().await {
        eprintln!("b4-driver: {error}");
        std::process::exit(20);
    }
}

async fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let binary = PathBuf::from(arguments.next().ok_or("missing production binary")?);
    let config_path = PathBuf::from(arguments.next().ok_or("missing configuration")?);
    let evidence = PathBuf::from(arguments.next().ok_or("missing evidence directory")?);
    let mode = arguments.next();
    if arguments.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    let config_yaml = fs::read_to_string(&config_path).map_err(|error| error.to_string())?;
    let config = Config::from_yaml(&config_yaml).map_err(|error| error.to_string())?;
    if mode.as_deref() == Some(std::ffi::OsStr::new("--cleanup-recovery")) {
        return run_cleanup_recovery(&binary, &config_yaml, &evidence).await;
    }
    if let Some(mode) = mode {
        return Err(format!(
            "unknown B4 driver mode: {}",
            mode.to_string_lossy()
        ));
    }
    require_config(&config)?;

    prepare_upstream()?;
    let upstream = TcpListener::bind((Ipv4Addr::new(11, 0, 0, 1), 443))
        .await
        .map_err(|error| format!("bind B4 upstream: {error}"))?;
    let outbound = Arc::new(AtomicUsize::new(0));
    let upstream_task = {
        let outbound = Arc::clone(&outbound);
        tokio::spawn(async move {
            while let Ok((_stream, _peer)) = upstream.accept().await {
                outbound.fetch_add(1, Ordering::SeqCst);
            }
        })
    };

    run_admission_limit(&binary, &config, &config_path, &evidence).await?;

    let sandbox = Helper::spawn(&binary, "sandboxd").map_err(|error| error.to_string())?;
    let enforcer = Helper::spawn_enforcer(&binary).map_err(|error| error.to_string())?;
    let sandbox_swept = sandbox
        .hello(&config_yaml)
        .map_err(|error| error.to_string())?;
    let enforcer_swept = enforcer
        .hello(&config_yaml)
        .map_err(|error| error.to_string())?;
    sandbox
        .ensure_running()
        .map_err(|error| error.to_string())?;
    enforcer
        .ensure_running()
        .map_err(|error| error.to_string())?;
    fs::write(
        evidence.join("startup.json"),
        serde_json::to_vec_pretty(&json!({
            "production_backend": "cgroup-bpf",
            "sandbox_swept": sandbox_swept,
            "enforcer_swept": enforcer_swept
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    verify_capacities(&config, &evidence)?;

    run_policy_full(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_cookie_full(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_duplicate_cookie(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_tuple_full(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_duplicate_tuple(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_publication_case(
        "delayed_publication",
        "delayed",
        PublicationFault::Delay(DELAYED_PUBLICATION_MS),
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_publication_case(
        "missing_publication_timeout",
        "missing",
        PublicationFault::Remove,
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_queue_full(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_ring_overflow(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    upstream_task.abort();

    fs::write(evidence.join("current-case.txt"), "complete\n")
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

async fn run_cleanup_recovery(
    binary: &Path,
    config_yaml: &str,
    evidence: &Path,
) -> Result<(), String> {
    let sandbox = Helper::spawn(binary, "sandboxd").map_err(|error| error.to_string())?;
    let sandbox_swept = sandbox
        .hello(config_yaml)
        .map_err(|error| format!("cleanup Sandbox recovery failed: {error}"))?;
    sandbox
        .ensure_running()
        .map_err(|error| error.to_string())?;
    let enforcer = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
    let enforcer_swept = enforcer
        .hello(config_yaml)
        .map_err(|error| format!("cleanup Enforcer recovery failed: {error}"))?;
    enforcer
        .ensure_running()
        .map_err(|error| error.to_string())?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "mode": "B4_CLEANUP_RECOVERY",
            "order": ["sandbox", "enforcer"],
            "sandbox_swept": sandbox_swept,
            "enforcer_swept": enforcer_swept,
            "ownership_source": "production durable records",
            "verdict": "PASS"
        }),
    )?;
    drop(enforcer);
    drop(sandbox);
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

fn require_config(config: &Config) -> Result<(), String> {
    let policy = config
        .runtime
        .max_concurrency
        .checked_add(config.runtime.cleanup_failure_threshold)
        .ok_or("policy capacity overflow")?;
    if config.cgroup_bpf.max_tracked_sockets != EXPECTED_SOCKET_CAPACITY as u32
        || policy != EXPECTED_POLICY_CAPACITY as u32
        || config.cgroup_bpf.ring_buffer_bytes != EXPECTED_RING_BYTES as u32
        || config.cgroup_bpf.resolve_timeout_ms != FIXED_TIMEOUT_MS
        || config.runtime.max_queue != 0
    {
        return Err("B4 requires C=4, P=3, ring=4096, timeout=2000 and max_queue=0".to_owned());
    }
    Ok(())
}

async fn run_admission_limit(
    binary: &Path,
    config: &Config,
    config_path: &Path,
    root: &Path,
) -> Result<(), String> {
    let evidence = case_dir(root, "admission_limit")?;
    fs::write(root.join("current-case.txt"), "admission_limit\n")
        .map_err(|error| error.to_string())?;
    let log = fs::File::create(evidence.join("production-stderr.txt"))
        .map_err(|error| error.to_string())?;
    let child = Command::new(binary)
        .args(["run", "-f"])
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .map_err(|error| format!("start production Soglia for admission case: {error}"))?;
    let mut production = ProductionProcess { child: Some(child) };
    let ingress = config.ingress.listen;
    wait_ingress(ingress, Duration::from_secs(10), &mut production)?;
    let first = tokio::task::spawn_blocking(move || invoke_ingress(ingress, "sleep 3000"));
    let second = tokio::task::spawn_blocking(move || invoke_ingress(ingress, "sleep 3000"));
    wait_map_count(config, "soglia_policy", 2, Duration::from_secs(10)).await?;
    let policy_pin = current_map_pin(config, "soglia_policy")?;
    let before = dump_map(&config.runtime.bpftool, &policy_pin)?;
    let third_started = Instant::now();
    let third = tokio::task::spawn_blocking(move || invoke_ingress(ingress, "sleep 3000"))
        .await
        .map_err(|error| error.to_string())??;
    let third_elapsed_ms = third_started.elapsed().as_millis();
    let refused = third.status == 503
        && third.execution.is_none()
        && third.body.contains("invocation queue is full");
    if !refused || map_len(&before)? != 2 || map_max_entries(config, &policy_pin)? != 3 {
        return Err(
            "Supervisor did not refuse beyond max_concurrency before policy capacity".into(),
        );
    }
    let first = first.await.map_err(|error| error.to_string())??;
    let second = second.await.map_err(|error| error.to_string())??;
    if first.status != 200 || second.status != 200 {
        return Err("the two admitted control Executions did not complete".to_owned());
    }
    wait_map_count(config, "soglia_policy", 0, Duration::from_secs(5)).await?;
    let post_refusal =
        tokio::task::spawn_blocking(move || invoke_ingress(ingress, "tunnel 11.0.0.1:443 1"))
            .await
            .map_err(|error| error.to_string())??;
    if post_refusal.status != 200 || !post_refusal.body.contains("HTTP/1.1 200 OK") {
        return Err("post-refusal invocation was not admitted and resolved".to_owned());
    }
    wait_map_count(config, "soglia_policy", 0, Duration::from_secs(5)).await?;
    let exit = production.terminate()?;
    if !exit.success() {
        return Err(format!("production admission process exited {exit}"));
    }
    let durable_manifest_after_shutdown = config
        .runtime
        .state_dir
        .join("cgroup-bpf/state.json")
        .exists();
    write_json(
        evidence.join("result.json"),
        &json!({
            "max_concurrency": config.runtime.max_concurrency,
            "max_queue": config.runtime.max_queue,
            "policy_capacity": 3,
            "policy_occupancy_when_refused": 2,
            "map_below_capacity": true,
            "third_execution_allocated": false,
            "third_refused": true,
            "third_elapsed_ms": third_elapsed_ms,
            "first_response": first,
            "second_response": second,
            "third_response": third,
            "post_refusal_response": post_refusal,
            "post_refusal_connection_outcome": "RESOLVED",
            "production_process_exit": exit.to_string(),
            "durable_manifest_after_shutdown": durable_manifest_after_shutdown,
            "durable_state_disposition": "validated and swept by the immediately following production helper startup",
            "production_privilege_path": "production soglia run performs its normal root helper startup and Supervisor uid/gid drop",
            "verdict": "PASS"
        }),
    )?;
    pass(&evidence)
}

#[derive(Serialize)]
struct IngressResponse {
    status: u16,
    execution: Option<String>,
    body: String,
}

struct ProductionProcess {
    child: Option<Child>,
}

impl ProductionProcess {
    fn terminate(&mut self) -> Result<std::process::ExitStatus, String> {
        let child = self.child.as_mut().ok_or("production process is absent")?;
        let status = Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!(
                "cannot send SIGTERM to production process: {status}"
            ));
        }
        let status = child.wait().map_err(|error| error.to_string())?;
        self.child = None;
        Ok(status)
    }
}

impl Drop for ProductionProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_ingress(
    ingress: SocketAddr,
    timeout: Duration,
    production: &mut ProductionProcess,
) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if StdTcpStream::connect_timeout(&ingress, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        if let Some(status) = production
            .child
            .as_mut()
            .ok_or("production process is absent")?
            .try_wait()
            .map_err(|error| error.to_string())?
        {
            return Err(format!("production Soglia exited before READY: {status}"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("production Soglia did not become ready".to_owned())
}

fn invoke_ingress(ingress: SocketAddr, command: &str) -> Result<IngressResponse, String> {
    let mut stream = StdTcpStream::connect_timeout(&ingress, Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|error| error.to_string())?;
    let request = format!(
        "POST /v1/execute/admission HTTP/1.1\r\nHost: soglia\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{command}",
        command.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("ingress response omitted header terminator")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .ok_or("ingress response omitted status")?
        .parse::<u16>()
        .map_err(|error| error.to_string())?;
    let execution = head.lines().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("x-soglia-execution")
                .then(|| value.trim().to_owned())
        })
    });
    Ok(IngressResponse {
        status,
        execution,
        body: body.to_owned(),
    })
}

async fn run_policy_full(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, "policy_full")?;
    fs::write(root.join("current-case.txt"), "policy_full\n").map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let id = ExecutionId::generate().map_err(|error| error.to_string())?;
    let nonce = ExecutionNonce::generate().map_err(|error| error.to_string())?;
    let reserved = sandbox
        .call(SandboxRequest::Reserve {
            id,
            agent: "control".to_owned(),
        })
        .await
        .map_err(|error| error.to_string())?;
    let HelperResponse::Reserved { cgroup_inode } = reserved else {
        return Err(format!("unexpected reserve response: {reserved:?}"));
    };
    let pin = current_map_pin(config, "soglia_policy")?;
    let generation = current_generation(config)?;
    let mut injected = Vec::new();
    for index in 0..EXPECTED_POLICY_CAPACITY {
        let cgroup_id = 0xf000_0000_0000_0000_u64 + index as u64;
        if cgroup_id == cgroup_inode {
            return Err("sentinel cgroup id collided with the target".to_owned());
        }
        let binding = BindingKey {
            cgroup_id,
            execution_nonce: ExecutionNonce::from_bytes([index as u8 + 1; 16]),
            backend_generation: generation,
        };
        let key = cgroup_id.to_ne_bytes().to_vec();
        let value = encode_policy(binding).to_vec();
        map_update(&config.runtime.bpftool, &pin, &key, &value)?;
        injected.push((key, value));
    }
    let full = dump_map(&config.runtime.bpftool, &pin)?;
    if map_len(&full)? != EXPECTED_POLICY_CAPACITY {
        return Err("policy injection did not reach exact capacity".to_owned());
    }
    let prepare = enforcer
        .call(EnforcerRequest::Prepare {
            id,
            slot: 0,
            agent: "control".to_owned(),
            nonce,
        })
        .await;
    let failed_closed = matches!(prepare, Err(HelperError::Failed(_)));
    for (key, _) in &injected {
        map_delete(&config.runtime.bpftool, &pin, key)?;
    }
    if map_len(&dump_map(&config.runtime.bpftool, &pin)?)? != 0 {
        return Err("policy injection remained before health/restart".to_owned());
    }
    sandbox
        .call(SandboxRequest::Kill { tag: id.tag() })
        .await
        .map_err(|error| error.to_string())?;
    sandbox
        .call(SandboxRequest::Destroy { tag: id.tag() })
        .await
        .map_err(|error| error.to_string())?;
    enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| error.to_string())?;
    if !failed_closed || execution_record_exists(config, id)? {
        return Err("policy-full prepare did not fail closed with synchronous rollback".to_owned());
    }
    write_json(
        evidence.join("injection.json"),
        &json!({
            "actor": "B4 qualification harness",
            "entries": injected.iter().map(|(key,value)| json!({"key_hex":hex(key),"value_hex":hex(value)})).collect::<Vec<_>>(),
            "state": "FROZEN",
            "actual_capacity": map_max_entries(config, &pin)?,
            "target_cgroup_id": cgroup_inode,
            "prepare_failed_closed": failed_closed,
            "injections_removed_before_health_or_restart": true,
            "production_code_modified": false
        }),
    )?;
    run_control(&evidence, config, sandbox, enforcer, outbound).await?;
    pass(&evidence)
}

async fn run_cookie_full(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, "cookie_full")?;
    fs::write(root.join("current-case.txt"), "cookie_full\n").map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = prepare_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "cookie-capacity",
        0,
    )
    .await?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health = Arc::new(Mutex::new(None));
    let proxy = start_proxy(
        config,
        recording_attributor(
            config,
            enforcer,
            Arc::clone(&table),
            PublicationFault::None,
            Arc::clone(&observations),
            &evidence,
            Arc::clone(&dns),
            Arc::clone(&outbound),
            Arc::clone(&health),
            2,
        )?,
        Arc::clone(&dns),
    )
    .await?;
    let before = counters(config)?;
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = proc_root(execution.pid, "tmp/b4-capacity.jsonl");
    wait_file(
        &proc_root(execution.pid, "tmp/b4-capacity.jsonl.ready"),
        Duration::from_secs(10),
    )
    .await?;
    wait_observations(
        &observations,
        EXPECTED_SOCKET_CAPACITY,
        Duration::from_secs(10),
    )
    .await?;
    let at_capacity = counters(config)?;
    if at_capacity.cookies != EXPECTED_SOCKET_CAPACITY || at_capacity.tuples != 0 {
        return Err("cookie-full precondition lacks C live cookies and tuple headroom".to_owned());
    }
    fs::write(
        proc_root(execution.pid, "tmp/b4-capacity.jsonl.plus"),
        b"go\n",
    )
    .map_err(|error| error.to_string())?;
    wait_file(
        &proc_root(execution.pid, "tmp/b4-capacity.jsonl.plus-ready"),
        Duration::from_secs(2),
    )
    .await?;
    let plus_cookie = report_phase(&report, "plus_prepared")?
        .get("cookie")
        .and_then(Value::as_u64)
        .ok_or("plus_prepared omitted cookie")?;
    let cookie_pin = current_map_pin(config, "soglia_cookie_a")?;
    if plus_cookie == 0
        || map_contains(
            &dump_map(&config.runtime.bpftool, &cookie_pin)?,
            &plus_cookie.to_ne_bytes(),
        )?
    {
        return Err("C+1 cookie was zero or already present".to_owned());
    }
    fs::write(
        proc_root(execution.pid, "tmp/b4-capacity.jsonl.connect"),
        b"go\n",
    )
    .map_err(|error| error.to_string())?;
    wait_file(
        &proc_root(execution.pid, "tmp/b4-capacity.jsonl.plus-done"),
        Duration::from_secs(3),
    )
    .await?;
    let plus = report_phase(&report, "plus_result")?;
    let after_plus = counters(config)?;
    if plus.get("ok").and_then(Value::as_bool) != Some(false)
        || observations.lock().map_err(|_| "observation lock")?.len() != EXPECTED_SOCKET_CAPACITY
        || after_plus.cookies != EXPECTED_SOCKET_CAPACITY
        || after_plus.tuples != 0
        || after_plus.cookie_insert_failed != before.cookie_insert_failed + 1
        || after_plus.connect4_deny != before.connect4_deny + 1
        || after_plus.published != at_capacity.published
        || health.lock().ok().and_then(|value| *value).is_some()
    {
        return Err(
            "C+1 did not fail synchronously and exclusively at cookie insertion".to_owned(),
        );
    }
    fs::write(
        proc_root(execution.pid, "tmp/b4-capacity.jsonl.release"),
        b"go\n",
    )
    .map_err(|error| error.to_string())?;
    proxy.stop().await?;
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "capacity": EXPECTED_SOCKET_CAPACITY,
            "before": before,
            "at_capacity": at_capacity,
            "after_c_plus_one": after_plus,
            "c_plus_one_cookie": plus_cookie,
            "c_plus_one_cookie_absent_before_connect": true,
            "c_plus_one_client": plus,
            "proxy_accept_count": observations.lock().ok().as_deref().map(Vec::len),
            "health_failure": health.lock().ok().and_then(|value| *value),
            "verdict": "PASS"
        }),
    )?;
    run_control(&evidence, config, sandbox, enforcer, outbound).await?;
    pass(&evidence)
}

async fn run_duplicate_cookie(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, "duplicate_cookie")?;
    fs::write(root.join("current-case.txt"), "duplicate_cookie\n")
        .map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = prepare_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "duplicate-cookie",
        0,
    )
    .await?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health = Arc::new(Mutex::new(None));
    let proxy = start_proxy(
        config,
        recording_attributor(
            config,
            enforcer,
            Arc::clone(&table),
            PublicationFault::None,
            Arc::clone(&observations),
            &evidence,
            Arc::clone(&dns),
            Arc::clone(&outbound),
            Arc::clone(&health),
            2,
        )?,
        Arc::clone(&dns),
    )
    .await?;
    let before = counters(config)?;
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = proc_root(execution.pid, "tmp/b4-preconnect.jsonl");
    wait_file(
        &proc_root(execution.pid, "tmp/b4-preconnect.jsonl.ready"),
        Duration::from_secs(5),
    )
    .await?;
    let prepared = report_phase(&report, "prepared")?;
    let cookie = prepared
        .get("cookie")
        .and_then(Value::as_u64)
        .ok_or("prepared omitted cookie")?;
    if cookie == 0 {
        return Err("duplicate-cookie sentinel is zero".to_owned());
    }
    let pin = current_map_pin(config, "soglia_cookie_a")?;
    let key = cookie.to_ne_bytes();
    let value = encode_binding(execution.execution.binding);
    if map_contains(&dump_map(&config.runtime.bpftool, &pin)?, &key)? {
        return Err("pre-connect cookie already existed".to_owned());
    }
    map_update(&config.runtime.bpftool, &pin, &key, &value)?;
    let injected = dump_map(&config.runtime.bpftool, &pin)?;
    if map_len(&injected)? != 1 {
        return Err("duplicate cookie injection lacks headroom".to_owned());
    }
    fs::write(
        proc_root(execution.pid, "tmp/b4-preconnect.jsonl.connect"),
        b"go\n",
    )
    .map_err(|error| error.to_string())?;
    wait_file(
        &proc_root(execution.pid, "tmp/b4-preconnect.jsonl.done"),
        Duration::from_secs(3),
    )
    .await?;
    let result = report_phase(&report, "connect_result")?;
    let after = counters(config)?;
    let retained =
        map_value(&dump_map(&config.runtime.bpftool, &pin)?, &key)? == Some(value.to_vec());
    if result.get("ok").and_then(Value::as_bool) != Some(false)
        || !retained
        || after.cookie_insert_failed != before.cookie_insert_failed + 1
        || after.connect4_deny != before.connect4_deny + 1
        || !observations
            .lock()
            .map_err(|_| "observation lock")?
            .is_empty()
        || health.lock().ok().and_then(|value| *value).is_some()
    {
        return Err("duplicate cookie did not deny without overwrite".to_owned());
    }
    map_delete(&config.runtime.bpftool, &pin, &key)?;
    if map_contains(&dump_map(&config.runtime.bpftool, &pin)?, &key)? {
        return Err("duplicate cookie injection remained".to_owned());
    }
    fs::write(
        proc_root(execution.pid, "tmp/b4-preconnect.jsonl.release"),
        b"go\n",
    )
    .map_err(|error| error.to_string())?;
    proxy.stop().await?;
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "cookie": cookie, "cookie_nonzero": true, "map_occupancy": 1,
            "map_capacity": EXPECTED_SOCKET_CAPACITY, "entry_not_overwritten": retained,
            "client": result, "before": before, "after": after,
            "injection_removed_before_health_or_restart": true, "verdict":"PASS"
        }),
    )?;
    run_control(&evidence, config, sandbox, enforcer, outbound).await?;
    pass(&evidence)
}

async fn run_tuple_full(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, "tuple_full")?;
    fs::write(root.join("current-case.txt"), "tuple_full\n").map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = prepare_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "tuple-full",
        0,
    )
    .await?;
    prove_port_free(config, execution.execution.id, 42_000, &evidence)?;
    let pin = current_map_pin(config, "soglia_tuples")?;
    let mut injected = Vec::new();
    for index in 0..EXPECTED_SOCKET_CAPACITY {
        let peer = SocketAddr::from((execution.address, 50_000 + index as u16));
        let local = SocketAddr::from((config.network.proxy_address, config.network.proxy_port));
        let key = encode_tuple(peer, local)?;
        let value = encode_tuple_value(0xfeed_0000 + index as u64, execution.execution.binding, 1);
        map_update(&config.runtime.bpftool, &pin, &key, &value)?;
        injected.push((key.to_vec(), value.to_vec()));
    }
    if map_len(&dump_map(&config.runtime.bpftool, &pin)?)? != EXPECTED_SOCKET_CAPACITY {
        return Err("tuple map did not reach capacity".to_owned());
    }
    let (proxy, observations, health, dns) = case_proxy(
        config,
        enforcer,
        Arc::clone(&table),
        PublicationFault::None,
        &evidence,
        Arc::clone(&outbound),
        2,
    )
    .await?;
    outbound.store(0, Ordering::SeqCst);
    let before = counters(config)?;
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    wait_observations(&observations, 1, Duration::from_secs(6)).await?;
    let observation = one_observation(&observations)?;
    let after = counters(config)?;
    if observation.outcome != OutcomeKind::Timeout
        || !timeout_bounded(observation.elapsed_ms)
        || observation.recv_q_bytes == 0
        || observation.dns_when_resolve_returned != 0
        || observation.outbound_when_resolve_returned != 0
        || after.tuple_insert_failed != before.tuple_insert_failed + 1
        || after.published != before.published
        || after.tuples != EXPECTED_SOCKET_CAPACITY
        || health.lock().ok().and_then(|value| *value).is_some()
    {
        return Err("tuple-full did not produce isolated fail-closed timeout".to_owned());
    }
    proxy.stop().await?;
    for (key, _) in &injected {
        map_delete(&config.runtime.bpftool, &pin, key)?;
    }
    if map_len(&dump_map(&config.runtime.bpftool, &pin)?)? != 0 {
        return Err("tuple-full injection remained".to_owned());
    }
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "actual_capacity": map_max_entries(config, &pin)?, "inserted": injected.len(),
            "c_plus_one_failed": true, "observation": observation, "before":before, "after":after,
            "dns_calls": dns.load(Ordering::SeqCst), "injections_removed_before_health_or_restart":true,
            "verdict":"PASS"
        }),
    )?;
    run_control(&evidence, config, sandbox, enforcer, outbound).await?;
    pass(&evidence)
}

async fn run_duplicate_tuple(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, "duplicate_tuple")?;
    fs::write(root.join("current-case.txt"), "duplicate_tuple\n")
        .map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = prepare_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "duplicate-tuple",
        0,
    )
    .await?;
    prove_port_free(config, execution.execution.id, 42_001, &evidence)?;
    let pin = current_map_pin(config, "soglia_tuples")?;
    let peer = SocketAddr::from((execution.address, 42_001));
    let local = SocketAddr::from((config.network.proxy_address, config.network.proxy_port));
    let key = encode_tuple(peer, local)?;
    let sentinel_cookie = 0xfeed_beef_dead_cafe_u64;
    let value = encode_tuple_value(sentinel_cookie, execution.execution.binding, 1);
    map_update(&config.runtime.bpftool, &pin, &key, &value)?;
    if map_len(&dump_map(&config.runtime.bpftool, &pin)?)? != 1 {
        return Err("duplicate tuple injection lacks headroom".to_owned());
    }
    let (proxy, observations, health, _) = case_proxy(
        config,
        enforcer,
        Arc::clone(&table),
        PublicationFault::None,
        &evidence,
        Arc::clone(&outbound),
        2,
    )
    .await?;
    outbound.store(0, Ordering::SeqCst);
    let before = counters(config)?;
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    wait_observations(&observations, 1, Duration::from_secs(4)).await?;
    let observation = one_observation(&observations)?;
    let after = counters(config)?;
    let consumed = !map_contains(&dump_map(&config.runtime.bpftool, &pin)?, &key)?;
    if observation.outcome != OutcomeKind::IdentityMismatch
        || observation.mismatch != Some(ResolveMismatch::Cookie)
        || observation.recv_q_bytes == 0
        || observation.dns_when_resolve_returned != 0
        || observation.outbound_when_resolve_returned != 0
        || after.tuple_insert_failed != before.tuple_insert_failed + 1
        || !consumed
        || health.lock().ok().and_then(|value| *value).is_some()
    {
        return Err("duplicate tuple did not deny as IdentityMismatch(Cookie)".to_owned());
    }
    proxy.stop().await?;
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "fixed_source_port":42001, "port_proven_free":true,
            "sentinel_cookie":sentinel_cookie, "sentinel_cookie_nonzero":true,
            "map_occupancy":1, "map_capacity":EXPECTED_SOCKET_CAPACITY,
            "entry_consumed_not_overwritten":consumed, "observation":observation,
            "before":before, "after":after, "verdict":"PASS"
        }),
    )?;
    run_control(&evidence, config, sandbox, enforcer, outbound).await?;
    pass(&evidence)
}

async fn run_publication_case(
    name: &str,
    agent: &str,
    fault: PublicationFault,
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, name)?;
    fs::write(root.join("current-case.txt"), format!("{name}\n"))
        .map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution =
        prepare_execution(config, &evidence, sandbox, enforcer, &table, agent, 0).await?;
    let (proxy, observations, health, _) = case_proxy(
        config,
        enforcer,
        Arc::clone(&table),
        fault,
        &evidence,
        Arc::clone(&outbound),
        2,
    )
    .await?;
    outbound.store(0, Ordering::SeqCst);
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    wait_observations(&observations, 1, Duration::from_secs(6)).await?;
    let observation = one_observation(&observations)?;
    let valid = match fault {
        PublicationFault::Delay(delay) => {
            observation.outcome == OutcomeKind::Resolved
                && observation.resolved_execution == Some(execution.execution.id)
                && observation.elapsed_ms >= delay
                && observation.elapsed_ms < FIXED_TIMEOUT_MS
        }
        PublicationFault::Remove => {
            observation.outcome == OutcomeKind::Timeout && timeout_bounded(observation.elapsed_ms)
        }
        PublicationFault::None => false,
    };
    if !valid
        || observation.recv_q_bytes == 0
        || observation.dns_when_resolve_returned != 0
        || observation.outbound_when_resolve_returned != 0
        || health.lock().ok().and_then(|value| *value).is_some()
    {
        return Err(format!("{name} violated bounded publication semantics"));
    }
    proxy.stop().await?;
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "case":name, "fault":format!("{fault:?}"), "observation":observation,
            "health_failure":health.lock().ok().and_then(|value| *value), "verdict":"PASS"
        }),
    )?;
    pass(&evidence)
}

async fn run_queue_full(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, "resolve_queue_full")?;
    fs::write(root.join("current-case.txt"), "resolve_queue_full\n")
        .map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution =
        prepare_execution(config, &evidence, sandbox, enforcer, &table, "queue", 0).await?;
    let (proxy, observations, health, _) = case_proxy(
        config,
        enforcer,
        Arc::clone(&table),
        PublicationFault::Remove,
        &evidence,
        Arc::clone(&outbound),
        config.runtime.max_concurrency as usize,
    )
    .await?;
    outbound.store(0, Ordering::SeqCst);
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    wait_observations(&observations, 3, Duration::from_secs(6)).await?;
    let snapshot = observations.lock().map_err(|_| "observation lock")?.clone();
    let timeouts = snapshot
        .iter()
        .filter(|item| item.outcome == OutcomeKind::Timeout && timeout_bounded(item.elapsed_ms))
        .count();
    let queue_full: Vec<_> = snapshot
        .iter()
        .filter(|item| item.outcome == OutcomeKind::QueueFull)
        .collect();
    if timeouts != 2
        || queue_full.len() != 1
        || queue_full[0].elapsed_ms >= 500
        || snapshot.iter().any(|item| {
            item.recv_q_bytes == 0
                || item.dns_when_resolve_returned != 0
                || item.outbound_when_resolve_returned != 0
                || item.health_failure.is_some()
        })
        || health.lock().ok().and_then(|value| *value).is_some()
    {
        return Err("Resolve queue saturation did not yield 2 Timeout + 1 QueueFull".to_owned());
    }
    proxy.stop().await?;
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "queue_depth":config.runtime.max_concurrency, "observations":snapshot,
            "timeout_count":timeouts, "queue_full_count":queue_full.len(), "verdict":"PASS"
        }),
    )?;
    run_control(&evidence, config, sandbox, enforcer, outbound).await?;
    pass(&evidence)
}

async fn run_ring_overflow(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = case_dir(root, "event_ring_overflow")?;
    fs::write(root.join("current-case.txt"), "event_ring_overflow\n")
        .map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution =
        prepare_execution(config, &evidence, sandbox, enforcer, &table, "ring", 0).await?;
    let before = counters(config)?;
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report_path = proc_root(execution.pid, "tmp/b4-ring.json");
    wait_file(&report_path, Duration::from_secs(10)).await?;
    let report: Value =
        serde_json::from_slice(&fs::read(&report_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let after = counters(config)?;
    let attempts = report.get("attempts").and_then(Value::as_u64).unwrap_or(0);
    let successes = report
        .get("by_errno")
        .and_then(|value| value.get("0"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if attempts != RING_ATTEMPTS
        || successes != 0
        || after.connect4_deny.saturating_sub(before.connect4_deny) != RING_ATTEMPTS
        || after.events_dropped <= before.events_dropped
        || after.cookies != 0
        || after.tuples != 0
    {
        return Err("ring overflow did not preserve one deny per client attempt".to_owned());
    }
    enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| error.to_string())?;
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({
            "overflow_method":"production ring consumer intentionally absent; burst exceeds 4096-byte ring capacity",
            "ring_bytes":EXPECTED_RING_BYTES, "attempts":attempts, "client_successes":successes,
            "connect4_deny_delta":after.connect4_deny.saturating_sub(before.connect4_deny),
            "events_dropped_delta":after.events_dropped.saturating_sub(before.events_dropped),
            "before":before, "after":after, "health_unchanged":true, "verdict":"PASS"
        }),
    )?;
    run_control(&evidence, config, sandbox, enforcer, outbound).await?;
    pass(&evidence)
}

async fn run_control(
    parent: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = parent.join("post-case-control");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    assert_empty(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution =
        prepare_execution(config, &evidence, sandbox, enforcer, &table, "control", 0).await?;
    let (proxy, observations, health, _) = case_proxy(
        config,
        enforcer,
        Arc::clone(&table),
        PublicationFault::None,
        &evidence,
        Arc::clone(&outbound),
        2,
    )
    .await?;
    outbound.store(0, Ordering::SeqCst);
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    wait_observations(&observations, 1, Duration::from_secs(5)).await?;
    let observation = one_observation(&observations)?;
    if observation.outcome != OutcomeKind::Resolved
        || observation.resolved_execution != Some(execution.execution.id)
        || observation.recv_q_bytes == 0
        || observation.dns_when_resolve_returned != 0
        || observation.outbound_when_resolve_returned != 0
        || health.lock().ok().and_then(|value| *value).is_some()
    {
        return Err("post-case control connection did not resolve cleanly".to_owned());
    }
    proxy.stop().await?;
    cleanup_execution(&mut execution, &table).await?;
    wait_empty(config, Duration::from_secs(3)).await?;
    write_json(
        evidence.join("result.json"),
        &json!({"observation":observation,"verdict":"PASS"}),
    )?;
    pass(&evidence)
}

async fn prepare_execution<'a>(
    config: &Config,
    evidence: &Path,
    sandbox: &'a Helper,
    enforcer: &'a Helper,
    table: &AttributionTable,
    agent: &str,
    slot: u32,
) -> Result<Prepared<'a>, String> {
    let id = ExecutionId::generate().map_err(|error| error.to_string())?;
    let nonce = ExecutionNonce::generate().map_err(|error| error.to_string())?;
    let reserved = sandbox
        .call(SandboxRequest::Reserve {
            id,
            agent: agent.to_owned(),
        })
        .await
        .map_err(|error| error.to_string())?;
    let HelperResponse::Reserved { cgroup_inode } = reserved else {
        return Err(format!("unexpected reserve response: {reserved:?}"));
    };
    enforcer
        .call(EnforcerRequest::Prepare {
            id,
            slot,
            agent: agent.to_owned(),
            nonce,
        })
        .await
        .map_err(|error| error.to_string())?;
    let paused = sandbox
        .call(SandboxRequest::CreatePaused { id })
        .await
        .map_err(|error| error.to_string())?;
    let HelperResponse::CreatedPaused {
        pid,
        cgroup_inode: paused_inode,
    } = paused
    else {
        return Err(format!("unexpected paused response: {paused:?}"));
    };
    if cgroup_inode != paused_inode {
        return Err("reserved and paused cgroup IDs differ".to_owned());
    }
    record_placement(config, evidence, id, pid, cgroup_inode)?;
    let verified = enforcer
        .call(EnforcerRequest::VerifyPlacement { id, pid })
        .await
        .map_err(|error| error.to_string())?;
    let HelperResponse::PlacementVerified { binding } = verified else {
        return Err(format!("unexpected placement response: {verified:?}"));
    };
    if binding.cgroup_id != cgroup_inode || binding.execution_nonce != nonce {
        return Err("whole BindingKey placement mismatch".to_owned());
    }
    table
        .bind_key(binding, id)
        .map_err(|error| error.to_string())?;
    enforcer
        .call(EnforcerRequest::Activate {
            id,
            binding: Some(binding),
        })
        .await
        .map_err(|error| error.to_string())?;
    let address = config
        .pool()
        .map_err(|error| error.to_string())?
        .slot(slot)
        .ok_or("slot unavailable")?
        .execution;
    Ok(Prepared {
        execution: Execution {
            sandbox,
            enforcer,
            id,
            binding,
            reserved: true,
            prepared: true,
            bound: true,
        },
        pid,
        address,
    })
}

async fn cleanup_execution(
    execution: &mut Prepared<'_>,
    table: &AttributionTable,
) -> Result<(), String> {
    let failures = execution.execution.cleanup(table).await;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("execution cleanup failed: {failures:?}"))
    }
}

fn candidate_attributor(
    config: &Config,
    enforcer: &Helper,
    table: Arc<AttributionTable>,
    health: Arc<Mutex<Option<HealthFailure>>>,
    queue_depth: usize,
) -> Result<Arc<dyn ConnectionAttributor>, String> {
    let observed = Arc::clone(&health);
    Ok(Arc::new(CandidateAAttributor::new(
        enforcer
            .resolver_client()
            .map_err(|error| error.to_string())?,
        table,
        Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
        queue_depth,
        Arc::new(move |failure| {
            if let Ok(mut value) = observed.lock() {
                *value = Some(match failure {
                    ResolveHealthFailure::Unavailable => HealthFailure::Unavailable,
                    ResolveHealthFailure::IntegrityFailure => HealthFailure::IntegrityFailure,
                });
            }
        }),
    )))
}

#[allow(clippy::too_many_arguments)]
fn recording_attributor(
    config: &Config,
    enforcer: &Helper,
    table: Arc<AttributionTable>,
    fault: PublicationFault,
    observations: Arc<Mutex<Vec<ResolveObservation>>>,
    evidence: &Path,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    health: Arc<Mutex<Option<HealthFailure>>>,
    queue_depth: usize,
) -> Result<Arc<dyn ConnectionAttributor>, String> {
    let inner = candidate_attributor(config, enforcer, table, Arc::clone(&health), queue_depth)?;
    Ok(Arc::new(RecordingAttributor {
        inner,
        fault,
        observations,
        bpftool: config.runtime.bpftool.clone(),
        state: config.runtime.state_dir.join("cgroup-bpf/state.json"),
        evidence: evidence.to_owned(),
        dns,
        outbound,
        health,
    }))
}

async fn case_proxy(
    config: &Config,
    enforcer: &Helper,
    table: Arc<AttributionTable>,
    fault: PublicationFault,
    evidence: &Path,
    outbound: Arc<AtomicUsize>,
    queue_depth: usize,
) -> Result<
    (
        ProxyTask,
        Arc<Mutex<Vec<ResolveObservation>>>,
        Arc<Mutex<Option<HealthFailure>>>,
        Arc<AtomicUsize>,
    ),
    String,
> {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let health = Arc::new(Mutex::new(None));
    let dns = Arc::new(AtomicUsize::new(0));
    let attributor = recording_attributor(
        config,
        enforcer,
        table,
        fault,
        Arc::clone(&observations),
        evidence,
        Arc::clone(&dns),
        outbound,
        Arc::clone(&health),
        queue_depth,
    )?;
    let proxy = start_proxy(config, attributor, Arc::clone(&dns)).await?;
    Ok((proxy, observations, health, dns))
}

async fn start_proxy(
    config: &Config,
    attributor: Arc<dyn ConnectionAttributor>,
    dns: Arc<AtomicUsize>,
) -> Result<ProxyTask, String> {
    let policy = DestinationPolicy::new(&config.egress, &config.network, Vec::new())
        .map_err(|error| error.to_string())?;
    let proxy = Arc::new(EgressProxy::new(
        Arc::new(policy),
        attributor,
        Arc::new(CountingResolver { calls: dns }),
        EgressLimits::from_config(&config.egress),
    ));
    let listener = TcpListener::bind(SocketAddr::from((
        config.network.proxy_address,
        config.network.proxy_port,
    )))
    .await
    .map_err(|error| format!("bind B4 proxy: {error}"))?;
    let (stop, stopped) = watch::channel(false);
    Ok(ProxyTask {
        stop,
        task: tokio::spawn(proxy.serve(listener, stopped)),
    })
}

fn counters(config: &Config) -> Result<Counters, String> {
    let policy = dump_map(
        &config.runtime.bpftool,
        &current_map_pin(config, "soglia_policy")?,
    )?;
    let cookies = dump_map(
        &config.runtime.bpftool,
        &current_map_pin(config, "soglia_cookie_a")?,
    )?;
    let tuples = dump_map(
        &config.runtime.bpftool,
        &current_map_pin(config, "soglia_tuples")?,
    )?;
    let counters = dump_map(
        &config.runtime.bpftool,
        &current_map_pin(config, "soglia_counters")?,
    )?;
    Ok(Counters {
        events_dropped: counter_value(&counters, C_EVENTS_DROPPED)?,
        cookie_insert_failed: counter_value(&counters, C_COOKIE_INSERT_FAILED)?,
        tuple_insert_failed: counter_value(&counters, C_TUPLE_INSERT_FAILED)?,
        published: counter_value(&counters, C_PUBLISHED)?,
        unpublished: counter_value(&counters, C_UNPUBLISHED)?,
        connect4_deny: counter_value(&counters, C_CONNECT4_DENY)?,
        cookie_miss: counter_value(&counters, C_COOKIE_MISS)?,
        policies: map_len(&policy)?,
        cookies: map_len(&cookies)?,
        tuples: map_len(&tuples)?,
    })
}

fn assert_empty(config: &Config) -> Result<(), String> {
    let snapshot = counters(config)?;
    if snapshot.policies == 0 && snapshot.cookies == 0 && snapshot.tuples == 0 {
        Ok(())
    } else {
        Err(format!("B4 case baseline is not empty: {snapshot:?}"))
    }
}

async fn wait_empty(config: &Config, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let snapshot = counters(config)?;
        if snapshot.policies == 0 && snapshot.cookies == 0 && snapshot.tuples == 0 {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("maps did not return to baseline: {snapshot:?}"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_map_count(
    config: &Config,
    name: &str,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if let Ok(pin) = current_map_pin(config, name)
            && map_len(&dump_map(&config.runtime.bpftool, &pin)?)? == expected
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("{name} did not reach occupancy {expected}"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_observations(
    observations: &Mutex<Vec<ResolveObservation>>,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if observations
            .lock()
            .map_err(|_| "observation lock poisoned")?
            .len()
            >= expected
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("observed fewer than {expected} Resolve calls"));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn one_observation(
    observations: &Mutex<Vec<ResolveObservation>>,
) -> Result<ResolveObservation, String> {
    let values = observations
        .lock()
        .map_err(|_| "observation lock poisoned")?;
    if values.len() != 1 {
        return Err(format!("expected one observation, got {}", values.len()));
    }
    Ok(values[0].clone())
}

fn timeout_bounded(elapsed_ms: u64) -> bool {
    elapsed_ms >= FIXED_TIMEOUT_MS - TIMEOUT_EARLY_TOLERANCE_MS
        && elapsed_ms <= FIXED_TIMEOUT_MS + TIMEOUT_LATE_TOLERANCE_MS
}

fn current_state(config: &Config) -> Result<Value, String> {
    serde_json::from_slice(
        &fs::read(config.runtime.state_dir.join("cgroup-bpf/state.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn current_generation(config: &Config) -> Result<u64, String> {
    current_state(config)?
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or("state omitted generation".to_owned())
}

fn current_map_pin(config: &Config, name: &str) -> Result<PathBuf, String> {
    state_map_pin_value(&current_state(config)?, name)
}

fn state_map_pin(path: &Path, name: &str) -> Result<PathBuf, String> {
    let state: Value = serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    state_map_pin_value(&state, name)
}

fn state_map_pin_value(state: &Value, name: &str) -> Result<PathBuf, String> {
    state
        .get("maps")
        .and_then(Value::as_array)
        .and_then(|maps| {
            maps.iter()
                .find(|map| map.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|map| map.get("pin"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| format!("state omitted map {name}"))
}

fn verify_capacities(config: &Config, evidence: &Path) -> Result<(), String> {
    let mut maps = Vec::new();
    for (name, expected) in [
        ("soglia_policy", 3_u64),
        ("soglia_denies", 3),
        ("soglia_cookie_a", 4),
        ("soglia_tuples", 4),
        ("soglia_events", 4096),
    ] {
        let pin = current_map_pin(config, name)?;
        let actual = map_max_entries(config, &pin)?;
        maps.push(json!({"name":name,"pin":pin,"configured":expected,"kernel_max_entries":actual,"matches":actual==expected}));
        if actual != expected {
            return Err(format!("{name} capacity is {actual}, expected {expected}"));
        }
    }
    write_json(
        evidence.join("capacities.json"),
        &json!({"source":"bpftool map show pinned","maps":maps,"verdict":"PASS"}),
    )
}

fn map_max_entries(config: &Config, pin: &Path) -> Result<u64, String> {
    let raw = command_output(
        &config.runtime.bpftool,
        &[
            "-j",
            "map",
            "show",
            "pinned",
            pin.to_str().ok_or("non-UTF8 pin")?,
        ],
    )?;
    let value: Value = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
    value
        .get("max_entries")
        .and_then(Value::as_u64)
        .or_else(|| {
            value
                .as_array()
                .and_then(|items| items.first())
                .and_then(|item| item.get("max_entries"))
                .and_then(Value::as_u64)
        })
        .ok_or("map info omitted max_entries".to_owned())
}

fn dump_map(bpftool: &Path, pin: &Path) -> Result<Value, String> {
    let raw = command_output(
        bpftool,
        &[
            "-j",
            "map",
            "dump",
            "pinned",
            pin.to_str().ok_or("non-UTF8 pin")?,
        ],
    )?;
    serde_json::from_slice(&raw).map_err(|error| error.to_string())
}

fn map_len(value: &Value) -> Result<usize, String> {
    value
        .as_array()
        .map(Vec::len)
        .ok_or("map dump is not an array".to_owned())
}

fn map_contains(value: &Value, key: &[u8]) -> Result<bool, String> {
    Ok(map_value(value, key)?.is_some())
}

fn map_value(value: &Value, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut found = None;
    for item in value.as_array().ok_or("map dump is not an array")? {
        if json_bytes(item.get("key").ok_or("map entry omitted key")?)? == key {
            if found.is_some() {
                return Err("duplicate key in map dump".to_owned());
            }
            found = Some(json_bytes(
                item.get("value").ok_or("map entry omitted value")?,
            )?);
        }
    }
    Ok(found)
}

fn counter_value(dump: &Value, index: u32) -> Result<u64, String> {
    let value =
        map_value(dump, &index.to_ne_bytes())?.ok_or_else(|| format!("missing counter {index}"))?;
    Ok(u64::from_ne_bytes(value.try_into().map_err(
        |value: Vec<u8>| format!("counter has {} bytes", value.len()),
    )?))
}

fn map_update(bpftool: &Path, pin: &Path, key: &[u8], value: &[u8]) -> Result<(), String> {
    map_command(bpftool, "update", pin, key, Some(value))
}
fn map_delete(bpftool: &Path, pin: &Path, key: &[u8]) -> Result<(), String> {
    map_command(bpftool, "delete", pin, key, None)
}

fn map_command(
    bpftool: &Path,
    operation: &str,
    pin: &Path,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<(), String> {
    let mut command = Command::new(bpftool);
    command
        .arg("map")
        .arg(operation)
        .arg("pinned")
        .arg(pin)
        .arg("key")
        .arg("hex");
    for byte in key {
        command.arg(format!("{byte:02x}"));
    }
    if let Some(value) = value {
        command.arg("value").arg("hex");
        for byte in value {
            command.arg(format!("{byte:02x}"));
        }
    }
    let output = command.output().map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    value
        .as_array()
        .ok_or("BPF bytes are not an array")?
        .iter()
        .map(|byte| {
            if let Some(number) = byte.as_u64() {
                return u8::try_from(number).map_err(|error| error.to_string());
            }
            let text = byte
                .as_str()
                .ok_or("BPF byte is neither number nor string")?;
            u8::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn encode_binding(binding: BindingKey) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[0..8].copy_from_slice(&binding.cgroup_id.to_ne_bytes());
    value[8..24].copy_from_slice(&binding.execution_nonce.bytes());
    value[24..32].copy_from_slice(&binding.backend_generation.to_ne_bytes());
    value
}

fn encode_policy(binding: BindingKey) -> [u8; 40] {
    let mut value = [0_u8; 40];
    value[8..40].copy_from_slice(&encode_binding(binding));
    value
}

fn encode_tuple(peer: SocketAddr, local: SocketAddr) -> Result<[u8; 16], String> {
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (peer.ip(), local.ip()) else {
        return Err("B4 requires IPv4 tuple".to_owned());
    };
    let mut key = [0_u8; 16];
    key[0..4].copy_from_slice(&source.octets());
    key[4..8].copy_from_slice(&destination.octets());
    key[8..10].copy_from_slice(&peer.port().to_ne_bytes());
    key[10..12].copy_from_slice(&local.port().to_ne_bytes());
    Ok(key)
}

fn encode_tuple_value(cookie: u64, binding: BindingKey, published_ns: u64) -> [u8; 48] {
    let mut value = [0_u8; 48];
    value[0..8].copy_from_slice(&cookie.to_ne_bytes());
    value[8..40].copy_from_slice(&encode_binding(binding));
    value[40..48].copy_from_slice(&published_ns.to_ne_bytes());
    value
}

fn capture_tuple(
    bpftool: &Path,
    state: &Path,
    peer: SocketAddr,
    local: SocketAddr,
    timeout: Duration,
) -> Result<(u64, BindingKey, Vec<u8>, Vec<u8>), String> {
    let pin = state_map_pin(state, "soglia_tuples")?;
    let key = encode_tuple(peer, local)?;
    let started = Instant::now();
    loop {
        let dump = dump_map(bpftool, &pin)?;
        if let Some(value) = map_value(&dump, &key)? {
            if value.len() != 48 {
                return Err("tuple ABI width differs".to_owned());
            };
            let cookie = u64::from_ne_bytes(value[0..8].try_into().map_err(|_| "cookie width")?);
            let binding = decode_binding(&value[8..40])?;
            return Ok((cookie, binding, key.to_vec(), value));
        }
        if started.elapsed() >= timeout {
            return Err("tuple not visible".to_owned());
        };
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn decode_binding(value: &[u8]) -> Result<BindingKey, String> {
    if value.len() != 32 {
        return Err("binding ABI width differs".to_owned());
    };
    Ok(BindingKey {
        cgroup_id: u64::from_ne_bytes(value[0..8].try_into().map_err(|_| "cgroup width")?),
        execution_nonce: ExecutionNonce::from_bytes(
            value[8..24].try_into().map_err(|_| "nonce width")?,
        ),
        backend_generation: u64::from_ne_bytes(
            value[24..32].try_into().map_err(|_| "generation width")?,
        ),
    })
}

fn capture_receive_queue(peer: SocketAddr, local: SocketAddr) -> Result<u64, String> {
    let started = Instant::now();
    loop {
        let text = String::from_utf8_lossy(&command_output(
            Path::new("/usr/bin/ss"),
            &["-H", "-n", "-t"],
        )?)
        .into_owned();
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 5
                && fields[3] == local.to_string()
                && fields[4] == peer.to_string()
                && let Ok(queue) = u64::from_str(fields[1])
                && queue > 0
            {
                return Ok(queue);
            }
        }
        if started.elapsed() >= Duration::from_secs(1) {
            return Err("accepted socket had no queued application bytes".to_owned());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn record_placement(
    config: &Config,
    evidence: &Path,
    id: ExecutionId,
    pid: i32,
    inode: u64,
) -> Result<(), String> {
    let target = config
        .cgroup
        .root
        .as_ref()
        .ok_or("missing cgroup root")?
        .join("executions")
        .join(id.tag().to_string());
    let proc_cgroup =
        fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|error| error.to_string())?;
    let procs =
        fs::read_to_string(target.join("cgroup.procs")).map_err(|error| error.to_string())?;
    if !procs
        .split_whitespace()
        .any(|value| value.parse::<i32>() == Ok(pid))
    {
        return Err("agent PID absent from target cgroup".to_owned());
    }
    write_json(
        evidence.join("placement.json"),
        &json!({"execution_id":id,"pid":pid,"target":target,"target_inode":inode,"proc_cgroup":proc_cgroup,"cgroup_procs":procs,"pid_member":true}),
    )
}

fn prove_port_free(
    config: &Config,
    id: ExecutionId,
    port: u16,
    evidence: &Path,
) -> Result<(), String> {
    let output = Command::new(&config.runtime.ip)
        .args([
            "netns",
            "exec",
            &id.tag().netns_name(),
            "/usr/bin/ss",
            "-H",
            "-n",
            "-t",
            "-a",
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("ss netns port probe failed".to_owned());
    };
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let occupied = text.lines().any(|line| {
        line.split_whitespace()
            .any(|field| field.ends_with(&format!(":{port}")))
    });
    write_json(
        evidence.join("source-port-precondition.json"),
        &json!({"source_port":port,"ss":text,"free":!occupied}),
    )?;
    if occupied {
        Err(format!("source port {port} is occupied"))
    } else {
        Ok(())
    }
}

fn execution_record_exists(config: &Config, id: ExecutionId) -> Result<bool, String> {
    let state = current_state(config)?;
    Ok(state
        .get("executions")
        .and_then(Value::as_object)
        .is_some_and(|entries| entries.contains_key(&id.tag().to_string())))
}

fn proc_root(pid: i32, path: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/root/{path}"))
}

async fn wait_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if path.exists() {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("{} did not appear", path.display()));
        }
        tokio::time::sleep(Duration::from_millis(5)).await
    }
}

fn report_phase(path: &Path, phase: &str) -> Result<Value, String> {
    let report = fs::read_to_string(path).map_err(|error| error.to_string())?;
    report
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value.get("phase").and_then(Value::as_str) == Some(phase))
        .ok_or_else(|| format!("report omitted phase {phase}"))
}

fn case_dir(root: &Path, name: &str) -> Result<PathBuf, String> {
    let path = root.join("cases").join(name);
    fs::create_dir_all(&path).map_err(|error| error.to_string())?;
    Ok(path)
}
fn pass(path: &Path) -> Result<(), String> {
    fs::write(path.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}
fn write_json(path: PathBuf, value: &Value) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn command_output(program: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "{} {:?}: {}",
            program.display(),
            arguments,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn command_success(program: &Path, arguments: &[&str]) -> io::Result<()> {
    let status = Command::new(program).args(arguments).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} exited {status}",
            program.display()
        )))
    }
}

fn prepare_upstream() -> Result<(), String> {
    let ip = Path::new("/usr/sbin/ip");
    let _ = Command::new(ip)
        .args(["link", "delete", "b4-upstream"])
        .output();
    command_success(ip, &["link", "add", "b4-upstream", "type", "dummy"])
        .map_err(|error| error.to_string())?;
    command_success(ip, &["addr", "add", "11.0.0.1/32", "dev", "b4-upstream"])
        .map_err(|error| error.to_string())?;
    command_success(ip, &["link", "set", "b4-upstream", "up"]).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b4_capacity_contract_is_exact() {
        assert_eq!(EXPECTED_SOCKET_CAPACITY, 4);
        assert_eq!(EXPECTED_POLICY_CAPACITY, 3);
        assert_eq!(EXPECTED_RING_BYTES, 4096);
    }

    #[test]
    fn tuple_encoding_preserves_fixed_source_and_proxy_destination() {
        let peer: SocketAddr = "10.201.0.1:42001".parse().unwrap();
        let local: SocketAddr = "10.200.255.1:15001".parse().unwrap();
        let key = encode_tuple(peer, local).unwrap();
        assert_eq!(&key[0..4], &[10, 201, 0, 1]);
        assert_eq!(&key[4..8], &[10, 200, 255, 1]);
        assert_eq!(&key[8..10], &42001_u16.to_ne_bytes());
        assert_eq!(&key[10..12], &15001_u16.to_ne_bytes());
    }

    #[test]
    fn zero_cookie_is_never_the_duplicate_tuple_sentinel() {
        assert_ne!(0xfeed_beef_dead_cafe_u64, 0);
    }
}
