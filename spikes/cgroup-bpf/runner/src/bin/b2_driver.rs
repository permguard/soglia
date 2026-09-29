// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Diagnostic B2 driver over the production helpers, proxy and Candidate-A object.
//!
//! This is qualification code, not a second backend. It drives the public production lifecycle
//! protocol one operation at a time so every boundary can be observed, and injects at most one
//! named fault per negative case without changing production code.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, io};

use aya::maps::{Map, MapData, RingBuf};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soglia_core::config::Config;
use soglia_core::helper::{EnforcerRequest, HelperResponse, ResolveMismatch, SandboxRequest};
use soglia_core::net::ExecutionPool;
use soglia_core::{BindingKey, ExecutionId, ExecutionNonce};
use soglia_proxy::attribution::{AttributionResult, AttributionTable, ConnectionAttributor};
use soglia_proxy::egress::{EgressLimits, EgressProxy};
use soglia_proxy::policy::DestinationPolicy;
use soglia_proxy::resolver::{Resolution, Resolver};
use soglia_supervisor::helpers::{
    CandidateAAttributor, Helper, HelperError, ResolveHealthFailure, ResolverClient,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Barrier, Notify, watch};

const TIMEOUT_EARLY_TOLERANCE_MS: u64 = 100;
const SINGLE_TIMEOUT_LATE_TOLERANCE_MS: u64 = 100;
const CONCURRENT_TIMEOUT_LATE_TOLERANCE_MS: u64 = 250;
const C_TUPLE_INSERT_FAILED: u32 = 2;
const C_PUBLISHED: u32 = 3;
const C_UNPUBLISHED: u32 = 4;
const C_SOCK_CREATE_DENY: u32 = 5;
const C_CONNECT4_DENY: u32 = 6;
const B5_REASON_NOT_PROXY: u32 = 3;
const B5_REASON_FAMILY: u32 = 5;

const CASES: [Case; 9] = [
    Case::Positive,
    Case::WrongPid,
    Case::WrongCgroup,
    Case::NonceMismatch,
    Case::GenerationMismatch,
    Case::TupleByteOrder,
    Case::WrongDestination,
    Case::MissingCookie,
    Case::IpOnly,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Case {
    Positive,
    WrongPid,
    WrongCgroup,
    NonceMismatch,
    GenerationMismatch,
    TupleByteOrder,
    WrongDestination,
    MissingCookie,
    IpOnly,
}

impl Case {
    const fn name(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::WrongPid => "wrong_pid",
            Self::WrongCgroup => "wrong_cgroup",
            Self::NonceMismatch => "nonce_mismatch",
            Self::GenerationMismatch => "generation_mismatch",
            Self::TupleByteOrder => "tuple_byte_order",
            Self::WrongDestination => "wrong_destination",
            Self::MissingCookie => "missing_cookie",
            Self::IpOnly => "ip_only_identity",
        }
    }

    const fn fault(self) -> Option<MapFault> {
        match self {
            Self::NonceMismatch => Some(MapFault::Nonce),
            Self::GenerationMismatch => Some(MapFault::Generation),
            Self::MissingCookie => Some(MapFault::MissingCookie),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MapFault {
    Nonce,
    Generation,
    MissingCookie,
}

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
enum ObservedResolveOutcome {
    Resolved,
    NotFound,
    IdentityMismatch,
    Revoked,
    Timeout,
    QueueFull,
    Unavailable,
    IntegrityFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ObservedHealthFailure {
    Unavailable,
    IntegrityFailure,
}

#[derive(Serialize, Deserialize)]
struct ResolveObservation {
    case: Case,
    peer: SocketAddr,
    local: SocketAddr,
    queried_peer: SocketAddr,
    queried_local: SocketAddr,
    recv_q_bytes: u64,
    dns_before: usize,
    outbound_before: usize,
    dns_when_resolve_returned: usize,
    outbound_when_resolve_returned: usize,
    outcome: ObservedResolveOutcome,
    mismatch: Option<ResolveMismatch>,
    resolve_elapsed_ms: u64,
    resolved_execution: Option<ExecutionId>,
    health_failure: Option<ObservedHealthFailure>,
}

#[derive(Serialize)]
struct ConcurrentResolveObservation {
    peer: SocketAddr,
    local: SocketAddr,
    queried_peer: SocketAddr,
    queried_local: SocketAddr,
    recv_q_bytes: u64,
    outcome: ObservedResolveOutcome,
    mismatch: Option<ResolveMismatch>,
    resolve_elapsed_ms: u64,
    dns_when_resolve_returned: usize,
    outbound_when_resolve_returned: usize,
    health_failure: Option<ObservedHealthFailure>,
}

fn observed_result(
    result: &AttributionResult,
) -> (
    ObservedResolveOutcome,
    Option<ResolveMismatch>,
    Option<ExecutionId>,
) {
    match result {
        AttributionResult::Resolved(binding) => {
            (ObservedResolveOutcome::Resolved, None, Some(binding.id))
        }
        AttributionResult::NotFound => (ObservedResolveOutcome::NotFound, None, None),
        AttributionResult::IdentityMismatch(reason) => (
            ObservedResolveOutcome::IdentityMismatch,
            Some(*reason),
            None,
        ),
        AttributionResult::Revoked => (ObservedResolveOutcome::Revoked, None, None),
        AttributionResult::Timeout => (ObservedResolveOutcome::Timeout, None, None),
        AttributionResult::QueueFull => (ObservedResolveOutcome::QueueFull, None, None),
        AttributionResult::Unavailable => (ObservedResolveOutcome::Unavailable, None, None),
        AttributionResult::IntegrityFailure => {
            (ObservedResolveOutcome::IntegrityFailure, None, None)
        }
    }
}

fn qualification_query(
    case: Case,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<(SocketAddr, SocketAddr), String> {
    match case {
        Case::TupleByteOrder => {
            let swapped = peer.port().swap_bytes();
            if swapped == peer.port() {
                return Err(format!(
                    "source port {} is byte-symmetric and cannot qualify byte-order handling",
                    peer.port()
                ));
            }
            Ok((SocketAddr::new(peer.ip(), swapped), local))
        }
        Case::WrongDestination => {
            let wrong_port = if local.port() == u16::MAX {
                local.port() - 1
            } else {
                local.port() + 1
            };
            Ok((peer, SocketAddr::new(local.ip(), wrong_port)))
        }
        _ => Ok((peer, local)),
    }
}

fn timeout_duration_is_bounded(
    elapsed_ms: u64,
    configured_timeout_ms: u64,
    late_tolerance_ms: u64,
) -> bool {
    elapsed_ms >= configured_timeout_ms.saturating_sub(TIMEOUT_EARLY_TOLERANCE_MS)
        && elapsed_ms <= configured_timeout_ms.saturating_add(late_tolerance_ms)
}

struct ObservingAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    case: Case,
    evidence: PathBuf,
    state: PathBuf,
    bpftool: PathBuf,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    health_failure: Arc<Mutex<Option<ObservedHealthFailure>>>,
}

impl ConnectionAttributor for ObservingAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move {
            let (recv_q_bytes, ss) =
                capture_receive_queue(peer, local).unwrap_or((0, String::new()));
            let _ = fs::write(self.evidence.join("ss-before-resolve.txt"), ss);
            let dns_before = self.dns.load(Ordering::SeqCst);
            let outbound_before = self.outbound.load(Ordering::SeqCst);
            let _ = fs::write(
                self.evidence.join("pre-resolve.json"),
                serde_json::to_vec_pretty(&json!({
                    "case": self.case,
                    "peer": peer,
                    "local": local,
                    "recv_q_bytes": recv_q_bytes,
                    "dns_calls": dns_before,
                    "outbound_accepts": outbound_before,
                    "application_bytes_read": 0
                }))
                .unwrap_or_default(),
            );

            if let Some(fault) = self.case.fault() {
                let result = inject_map_fault(&self.bpftool, &self.state, fault, &self.evidence);
                if let Err(error) = result {
                    let _ = fs::write(self.evidence.join("injection-error.txt"), error);
                    return AttributionResult::IntegrityFailure;
                }
            }

            let (queried_peer, queried_local) = match qualification_query(self.case, peer, local) {
                Ok(query) => query,
                Err(error) => {
                    let _ = fs::write(self.evidence.join("injection-error.txt"), error);
                    return AttributionResult::IntegrityFailure;
                }
            };
            if matches!(self.case, Case::TupleByteOrder | Case::WrongDestination) {
                let _ = fs::write(
                    self.evidence.join("fault-injection.json"),
                    serde_json::to_vec_pretty(&json!({
                        "actor": "b2_driver qualification wrapper",
                        "fault": self.case,
                        "original": {"peer": peer, "local": local},
                        "injected": {"peer": queried_peer, "local": queried_local},
                        "source_port_changed": queried_peer.port() != peer.port(),
                        "proxy_destination_unchanged": queried_local == local,
                        "production_code_modified": false
                    }))
                    .unwrap_or_default(),
                );
            }
            if self.case == Case::TupleByteOrder {
                if let Err(error) = capture_tuple_before_lookup(
                    &self.bpftool,
                    &self.state,
                    &self.evidence,
                    peer,
                    local,
                    queried_peer,
                    queried_local,
                ) {
                    let _ = fs::write(self.evidence.join("injection-error.txt"), error);
                    return AttributionResult::IntegrityFailure;
                }
            }
            let started = Instant::now();
            let resolved = self.inner.resolve(queried_peer, queried_local).await;
            let resolve_elapsed_ms =
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let (outcome, mismatch, resolved_execution) = observed_result(&resolved);
            let observation = ResolveObservation {
                case: self.case,
                peer,
                local,
                queried_peer,
                queried_local,
                recv_q_bytes,
                dns_before,
                outbound_before,
                dns_when_resolve_returned: self.dns.load(Ordering::SeqCst),
                outbound_when_resolve_returned: self.outbound.load(Ordering::SeqCst),
                outcome,
                mismatch,
                resolve_elapsed_ms,
                resolved_execution,
                health_failure: self.health_failure.lock().ok().and_then(|value| *value),
            };
            let _ = fs::write(
                self.evidence.join("resolve.json"),
                serde_json::to_vec_pretty(&observation).unwrap_or_default(),
            );
            resolved
        })
    }
}

struct ConcurrentObservingAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    observations: Arc<Mutex<Vec<ConcurrentResolveObservation>>>,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    health_failure: Arc<Mutex<Option<ObservedHealthFailure>>>,
}

impl ConnectionAttributor for ConcurrentObservingAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let recv_q_bytes = capture_receive_queue(peer, local)
                .map(|(bytes, _)| bytes)
                .unwrap_or(0);
            let queried_peer = SocketAddr::new(peer.ip(), peer.port().swap_bytes());
            let queried_local = local;
            let started = Instant::now();
            let resolved = self.inner.resolve(queried_peer, queried_local).await;
            let (outcome, mismatch, _) = observed_result(&resolved);
            let observation = ConcurrentResolveObservation {
                peer,
                local,
                queried_peer,
                queried_local,
                recv_q_bytes,
                outcome,
                mismatch,
                resolve_elapsed_ms: u64::try_from(started.elapsed().as_millis())
                    .unwrap_or(u64::MAX),
                dns_when_resolve_returned: self.dns.load(Ordering::SeqCst),
                outbound_when_resolve_returned: self.outbound.load(Ordering::SeqCst),
                health_failure: self.health_failure.lock().ok().and_then(|value| *value),
            };
            if let Ok(mut observations) = self.observations.lock() {
                observations.push(observation);
            }
            resolved
        })
    }
}

struct CountingConnectionAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    calls: Arc<AtomicUsize>,
}

impl ConnectionAttributor for CountingConnectionAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.resolve(peer, local).await
        })
    }
}

struct Execution<'a> {
    sandbox: &'a Helper,
    enforcer: &'a Helper,
    id: ExecutionId,
    binding: Option<BindingKey>,
    key_bound: bool,
    legacy_ip: Option<IpAddr>,
    reserved: bool,
    prepared: bool,
    moved_pid: Option<(i32, PathBuf)>,
}

impl Execution<'_> {
    async fn cleanup(&mut self, table: Option<&AttributionTable>) -> Vec<String> {
        let mut failures = Vec::new();
        if let Some((pid, target)) = self.moved_pid.take()
            && let Err(error) = fs::write(target.join("cgroup.procs"), format!("{pid}\n"))
        {
            failures.push(format!("restore moved pid: {error}"));
        }
        if let (Some(table), Some(binding)) = (table, self.binding)
            && self.key_bound
        {
            table.revoke_key(binding);
        }
        if let (Some(table), Some(ip)) = (table, self.legacy_ip) {
            table.revoke(ip);
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
        if let (Some(table), Some(binding)) = (table, self.binding)
            && self.key_bound
            && !table.remove_key(binding, self.id)
        {
            failures.push("live BindingKey was not released".to_owned());
        }
        if let (Some(table), Some(ip)) = (table, self.legacy_ip)
            && !table.remove(ip, self.id)
        {
            failures.push("injected legacy IP binding was not released".to_owned());
        }
        failures
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
        eprintln!("b2-driver: {error}");
        std::process::exit(20);
    }
}

async fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let binary = PathBuf::from(arguments.next().ok_or("missing production binary")?);
    let config_path = PathBuf::from(arguments.next().ok_or("missing configuration")?);
    let evidence = PathBuf::from(arguments.next().ok_or("missing evidence directory")?);
    let cleanup_probe = match arguments.next() {
        None => false,
        Some(argument) if argument == "--cleanup-probe" => true,
        Some(argument) => return Err(format!("unexpected argument: {}", argument.display())),
    };
    if arguments.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    let config_yaml = fs::read_to_string(&config_path).map_err(|error| error.to_string())?;
    let config = Config::from_yaml(&config_yaml).map_err(|error| error.to_string())?;
    let execution_address = config
        .pool()
        .map_err(|error| error.to_string())?
        .slot(0)
        .ok_or("slot zero is unavailable")?
        .execution;

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
            "sandbox_swept": sandbox_swept,
            "enforcer_swept": enforcer_swept,
            "production_binary": binary,
            "production_backend": "cgroup-bpf"
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if cleanup_probe {
        return run_cleanup_probe(&evidence, &config, &sandbox, &enforcer).await;
    }

    prepare_upstream().map_err(|error| error.to_string())?;
    let upstream = TcpListener::bind((Ipv4Addr::new(11, 0, 0, 1), 443))
        .await
        .map_err(|error| format!("bind upstream: {error}"))?;
    let outbound = Arc::new(AtomicUsize::new(0));
    let outbound_task = {
        let outbound = Arc::clone(&outbound);
        tokio::spawn(async move {
            while let Ok((_stream, _peer)) = upstream.accept().await {
                outbound.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    let mut observed_netns_cookies = Vec::new();
    let mut observed_netns_paths = Vec::new();
    let mut previous_netns_path: Option<PathBuf> = None;
    let mut netns_cookie_unproven = false;

    for case in CASES {
        let case_dir = evidence.join("cases").join(case.name());
        fs::create_dir_all(&case_dir).map_err(|error| error.to_string())?;
        let previous_path_absent = previous_netns_path
            .as_ref()
            .is_none_or(|path| !path.exists());
        fs::write(
            case_dir.join("pre-case-netns.json"),
            serde_json::to_vec_pretty(&json!({
                "case": case,
                "previous_netns_path": previous_netns_path,
                "previous_netns_path_absent": previous_path_absent
            }))
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if !previous_path_absent {
            return Err(format!(
                "{} started while the preceding owned netns path still existed",
                case.name()
            ));
        }
        fs::write(
            evidence.join("current-case.txt"),
            format!("{}\n", case.name()),
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            case_dir.join("scope.json"),
            serde_json::to_vec_pretty(&json!({
                "case": case,
                "same_production_build": true,
                "same_topology": true,
                "injected_fault_count": if case == Case::Positive { 0 } else { 1 },
                "injection_owner": if case == Case::Positive {
                    "none"
                } else {
                    "qualification harness"
                },
                "production_code_modified": false,
                "configured_timeout_ms": config.cgroup_bpf.resolve_timeout_ms,
                "minimum_acceptable_elapsed_ms": if case == Case::TupleByteOrder {
                    Some(config.cgroup_bpf.resolve_timeout_ms
                        .saturating_sub(TIMEOUT_EARLY_TOLERANCE_MS))
                } else {
                    None
                },
                "maximum_acceptable_elapsed_ms": if case == Case::TupleByteOrder {
                    Some(config.cgroup_bpf.resolve_timeout_ms
                        .saturating_add(SINGLE_TIMEOUT_LATE_TOLERANCE_MS))
                } else {
                    None
                }
            }))
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let result = run_case(
            case,
            &case_dir,
            &config,
            execution_address,
            &sandbox,
            &enforcer,
            Arc::clone(&outbound),
        )
        .await;
        if let Err(error) = result {
            fs::write(case_dir.join("verdict.txt"), "FAIL\n").map_err(|write| write.to_string())?;
            fs::write(case_dir.join("failure.txt"), format!("{error}\n"))
                .map_err(|write| write.to_string())?;
            outbound_task.abort();
            return Err(format!("{}: {error}", case.name()));
        }
        let placement: Value = serde_json::from_slice(
            &fs::read(case_dir.join("placement.json")).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let netns = placement
            .get("netns")
            .ok_or("placement evidence omitted the netns object")?;
        let netns_inode = netns
            .get("agent_inode")
            .and_then(Value::as_u64)
            .ok_or("placement evidence omitted the informational agent netns inode")?;
        let netns_path = netns
            .get("owned_path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or("placement evidence omitted the owned netns path")?;
        let agent_matches_owned_netns = netns
            .get("matches")
            .and_then(Value::as_bool)
            .ok_or("placement evidence omitted the agent/owned netns comparison")?;
        let path_unique = !observed_netns_paths.contains(&netns_path);
        let current_path_absent_after_teardown = !netns_path.exists();
        let cookie_supported = netns
            .pointer("/cookie/supported")
            .and_then(Value::as_bool)
            .ok_or("placement evidence omitted netns-cookie support status")?;
        let netns_cookie = netns.pointer("/cookie/value").and_then(Value::as_u64);
        let cookie_unique = if cookie_supported {
            let cookie = netns_cookie.ok_or("supported netns cookie omitted its value")?;
            let unique = !observed_netns_cookies.contains(&cookie);
            if unique {
                observed_netns_cookies.push(cookie);
            }
            Some(unique)
        } else {
            netns_cookie_unproven = true;
            None
        };
        if path_unique {
            observed_netns_paths.push(netns_path.clone());
        }
        fs::write(
            case_dir.join("netns-lifecycle.json"),
            serde_json::to_vec_pretty(&json!({
                "case": case,
                "owned_path": netns_path,
                "owned_path_unique": path_unique,
                "previous_owned_path_absent_before_case": previous_path_absent,
                "current_owned_path_absent_after_teardown": current_path_absent_after_teardown,
                "agent_matches_owned_netns": agent_matches_owned_netns,
                "informational_inode": netns_inode,
                "inode_used_as_identity": false,
                "cookie": {
                    "supported": cookie_supported,
                    "value": netns_cookie,
                    "unique_across_b2_cases": cookie_unique,
                    "criterion": if cookie_supported { "PROVEN" } else { "UNPROVEN" }
                },
                "observed_netns_cookies": observed_netns_cookies,
                "observed_netns_paths": observed_netns_paths
            }))
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if !path_unique || !agent_matches_owned_netns || !current_path_absent_after_teardown {
            return Err(format!(
                "{} did not prove the owned netns path lifecycle",
                case.name()
            ));
        }
        if cookie_unique == Some(false) {
            return Err(format!(
                "{} reused netns cookie {}",
                case.name(),
                netns_cookie.unwrap_or_default()
            ));
        }
        previous_netns_path = Some(netns_path);
        fs::write(case_dir.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    }
    fs::write(
        evidence.join("netns-summary.json"),
        serde_json::to_vec_pretty(&json!({
            "identity_criterion": if netns_cookie_unproven { "UNPROVEN" } else { "PROVEN" },
            "cookie_probe": "SO_NETNS_COOKIE",
            "inode_used_as_identity": false,
            "observed_unique_cookies": observed_netns_cookies,
            "observed_unique_owned_paths": observed_netns_paths,
            "lifecycle_criterion": "PROVEN"
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    run_host_origin_refused_case(&evidence, &config, &enforcer, Arc::clone(&outbound)).await?;
    run_concurrent_timeout_case(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    write_tuple_insert_failed_summary(&evidence)?;
    fs::write(evidence.join("current-case.txt"), "complete\n")
        .map_err(|error| error.to_string())?;
    outbound_task.abort();
    enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| format!("final backend health: {error}"))?;
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    Ok(())
}

async fn run_cleanup_probe(
    evidence: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
) -> Result<(), String> {
    for (name, counter_present) in [("deny_absent", false), ("deny_present", true)] {
        let case_dir = evidence.join("cases").join(name);
        fs::create_dir_all(&case_dir).map_err(|error| error.to_string())?;
        fs::write(evidence.join("current-case.txt"), format!("{name}\n"))
            .map_err(|error| error.to_string())?;
        let id = ExecutionId::generate().map_err(|error| error.to_string())?;
        let nonce = ExecutionNonce::generate().map_err(|error| error.to_string())?;
        let mut execution = Execution {
            sandbox,
            enforcer,
            id,
            binding: None,
            key_bound: false,
            legacy_ip: None,
            reserved: false,
            prepared: false,
            moved_pid: None,
        };
        let result = async {
            let reserved = sandbox
                .call(SandboxRequest::Reserve {
                    id,
                    agent: "probe".to_owned(),
                })
                .await
                .map_err(|error| error.to_string())?;
            let HelperResponse::Reserved { cgroup_inode } = reserved else {
                return Err(format!("unexpected reserve response: {reserved:?}"));
            };
            execution.reserved = true;
            enforcer
                .call(EnforcerRequest::Prepare {
                    id,
                    slot: 0,
                    agent: "probe".to_owned(),
                    nonce,
                })
                .await
                .map_err(|error| error.to_string())?;
            execution.prepared = true;
            let paused = sandbox
                .call(SandboxRequest::CreatePaused { id })
                .await
                .map_err(|error| error.to_string())?;
            let HelperResponse::CreatedPaused {
                pid,
                cgroup_inode: paused_inode,
            } = paused
            else {
                return Err(format!("unexpected create-paused response: {paused:?}"));
            };
            if cgroup_inode != paused_inode {
                return Err("reserved and paused cgroup inodes differ".to_owned());
            }
            record_placement(config, &case_dir, id, pid, cgroup_inode)?;
            let verified = enforcer
                .call(EnforcerRequest::VerifyPlacement { id, pid })
                .await
                .map_err(|error| error.to_string())?;
            let HelperResponse::PlacementVerified { binding } = verified else {
                return Err(format!("unexpected placement response: {verified:?}"));
            };
            execution.binding = Some(binding);
            let state_path = config.runtime.state_dir.join("cgroup-bpf/state.json");
            let state: Value = serde_json::from_slice(
                &fs::read(&state_path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let deny_pin = map_pin(&state, "soglia_denies")?;
            let key = encode_binding_key(binding);
            let before = dump_map(&config.runtime.bpftool, &deny_pin)?;
            if map_dump_contains_key(&before, &key)? {
                return Err("deny counter unexpectedly existed before injection".to_owned());
            }
            if counter_present {
                map_command(
                    &config.runtime.bpftool,
                    "update",
                    &deny_pin,
                    &key,
                    Some(&1_u64.to_ne_bytes()),
                )?;
            }
            let prepared = dump_map(&config.runtime.bpftool, &deny_pin)?;
            if map_dump_contains_key(&prepared, &key)? != counter_present {
                return Err("deny counter precondition was not established".to_owned());
            }
            fs::write(
                case_dir.join("deny-before-destroy.json"),
                serde_json::to_vec_pretty(&prepared).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            fs::write(
                case_dir.join("precondition.json"),
                serde_json::to_vec_pretty(&json!({
                    "case": name,
                    "deny_counter_present": counter_present,
                    "binding": binding,
                    "key_hex": hex(&key),
                    "injection_owner": if counter_present { "qualification harness" } else { "none" },
                    "production_code_modified": false
                }))
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            Ok((deny_pin, key))
        }
        .await;

        let cleanup = execution.cleanup(None).await;
        fs::write(
            case_dir.join("execution-cleanup.json"),
            serde_json::to_vec_pretty(&json!({"failures": cleanup}))
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if !cleanup.is_empty() {
            return Err(format!("{name} cleanup failed: {cleanup:?}"));
        }
        let (deny_pin, key) = result?;
        let after = dump_map(&config.runtime.bpftool, &deny_pin)?;
        fs::write(
            case_dir.join("deny-after-destroy.json"),
            serde_json::to_vec_pretty(&after).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if map_dump_contains_key(&after, &key)? {
            return Err(format!("{name} retained the deny counter"));
        }
        let network_record = config
            .runtime
            .state_dir
            .join("net")
            .join(format!("{}.json", id.tag()));
        if network_record.exists() {
            return Err(format!("{name} retained {}", network_record.display()));
        }
        enforcer
            .call(EnforcerRequest::Health)
            .await
            .map_err(|error| format!("{name} post-destroy health: {error}"))?;
        fs::write(case_dir.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    }
    fs::write(evidence.join("current-case.txt"), "complete\n")
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

async fn run_concurrent_timeout_case(
    evidence: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    const CONCURRENT: usize = 4;
    const FIRST_SOURCE_PORT: u16 = 40_000;
    let case_dir = evidence.join("cases/concurrent_timeout");
    fs::create_dir_all(&case_dir).map_err(|error| error.to_string())?;
    fs::write(evidence.join("current-case.txt"), "concurrent_timeout\n")
        .map_err(|error| error.to_string())?;
    fs::write(
        case_dir.join("scope.json"),
        serde_json::to_vec_pretty(&json!({
            "case": "CONCURRENT_TIMEOUT",
            "connections": CONCURRENT,
            "origin": "agent inside one verified production Execution",
            "agent": "concurrent",
            "source_ports": [40000, 40001, 40002, 40003],
            "lookup_fault": "byte-swap each source port while preserving both addresses and the proxy destination port",
            "expected_tuple_publication": true,
            "configured_timeout_ms": config.cgroup_bpf.resolve_timeout_ms,
            "minimum_acceptable_elapsed_ms": config.cgroup_bpf.resolve_timeout_ms
                .saturating_sub(TIMEOUT_EARLY_TOLERANCE_MS),
            "maximum_acceptable_elapsed_ms": config.cgroup_bpf.resolve_timeout_ms
                .saturating_add(CONCURRENT_TIMEOUT_LATE_TOLERANCE_MS),
            "production_code_modified": false
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    let id = ExecutionId::generate().map_err(|error| error.to_string())?;
    let nonce = ExecutionNonce::generate().map_err(|error| error.to_string())?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = Execution {
        sandbox,
        enforcer,
        id,
        binding: None,
        key_bound: false,
        legacy_ip: None,
        reserved: false,
        prepared: false,
        moved_pid: None,
    };
    let observations = Arc::new(Mutex::new(Vec::new()));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health_failure = Arc::new(Mutex::new(None));
    let result = async {
        let reserved = sandbox
            .call(SandboxRequest::Reserve {
                id,
                agent: "concurrent".to_owned(),
            })
            .await
            .map_err(|error| error.to_string())?;
        let HelperResponse::Reserved { cgroup_inode } = reserved else {
            return Err(format!("unexpected reserve response: {reserved:?}"));
        };
        execution.reserved = true;
        enforcer
            .call(EnforcerRequest::Prepare {
                id,
                slot: 0,
                agent: "concurrent".to_owned(),
                nonce,
            })
            .await
            .map_err(|error| error.to_string())?;
        execution.prepared = true;
        let paused = sandbox
            .call(SandboxRequest::CreatePaused { id })
            .await
            .map_err(|error| error.to_string())?;
        let HelperResponse::CreatedPaused {
            pid,
            cgroup_inode: paused_inode,
        } = paused
        else {
            return Err(format!("unexpected create-paused response: {paused:?}"));
        };
        if cgroup_inode != paused_inode {
            return Err("reserved and paused cgroup inodes differ".to_owned());
        }
        record_placement(config, &case_dir, id, pid, cgroup_inode)?;
        let verified = enforcer
            .call(EnforcerRequest::VerifyPlacement { id, pid })
            .await
            .map_err(|error| error.to_string())?;
        let HelperResponse::PlacementVerified { binding } = verified else {
            return Err(format!("unexpected placement response: {verified:?}"));
        };
        if binding.cgroup_id != cgroup_inode || binding.execution_nonce != nonce {
            return Err("verified BindingKey does not match reserved identity".to_owned());
        }
        execution.binding = Some(binding);
        table
            .bind_key(binding, id)
            .map_err(|error| error.to_string())?;
        execution.key_bound = true;
        enforcer
            .call(EnforcerRequest::Activate {
                id,
                binding: Some(binding),
            })
            .await
            .map_err(|error| error.to_string())?;
        dump_maps(config, &case_dir, "active")?;

        let observed_failure = Arc::clone(&health_failure);
        let production: Arc<dyn ConnectionAttributor> = Arc::new(CandidateAAttributor::new(
            enforcer
                .resolver_client()
                .map_err(|error| error.to_string())?,
            Arc::clone(&table),
            Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
            CONCURRENT,
            Arc::new(move |failure| {
                if let Ok(mut observed) = observed_failure.lock() {
                    *observed = Some(match failure {
                        ResolveHealthFailure::Unavailable => ObservedHealthFailure::Unavailable,
                        ResolveHealthFailure::IntegrityFailure => {
                            ObservedHealthFailure::IntegrityFailure
                        }
                    });
                }
            }),
        ));
        let observing: Arc<dyn ConnectionAttributor> = Arc::new(ConcurrentObservingAttributor {
            inner: production,
            observations: Arc::clone(&observations),
            dns: Arc::clone(&dns),
            outbound: Arc::clone(&outbound),
            health_failure: Arc::clone(&health_failure),
        });
        let policy = DestinationPolicy::new(&config.egress, &config.network, Vec::new())
            .map_err(|error| error.to_string())?;
        let proxy = Arc::new(EgressProxy::new(
            Arc::new(policy),
            observing,
            Arc::new(CountingResolver {
                calls: Arc::clone(&dns),
            }),
            EgressLimits::from_config(&config.egress),
        ));
        let address = SocketAddr::from((config.network.proxy_address, config.network.proxy_port));
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("bind concurrent-timeout proxy: {error}"))?;
        let (stop, stopped) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.serve(listener, stopped));
        sandbox
            .call(SandboxRequest::Start { id })
            .await
            .map_err(|error| error.to_string())?;

        let observation_deadline = Instant::now()
            + Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms)
            + Duration::from_secs(3);
        while observations
            .lock()
            .map_err(|_| "concurrent observation lock poisoned".to_owned())?
            .len()
            < CONCURRENT
        {
            if Instant::now() >= observation_deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let client_outcomes = read_agent_client_outcomes(
            pid,
            &case_dir,
            CONCURRENT,
            FIRST_SOURCE_PORT,
            Duration::from_secs(2),
        )
        .await;
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .map_err(|_| "concurrent-timeout proxy did not stop".to_owned())?
            .map_err(|error| error.to_string())?;
        let client_outcomes = client_outcomes?;
        dump_maps(config, &case_dir, "after-resolve")?;

        let observations = observations
            .lock()
            .map_err(|_| "concurrent observation lock poisoned".to_owned())?;
        fs::write(
            case_dir.join("resolve.json"),
            serde_json::to_vec_pretty(&*observations).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let mut real_ports: Vec<u16> = observations
            .iter()
            .map(|observation| observation.peer.port())
            .collect();
        real_ports.sort_unstable();
        let expected_ports: Vec<u16> = (0..CONCURRENT)
            .map(|index| FIRST_SOURCE_PORT + index as u16)
            .collect();
        if observations.len() != CONCURRENT {
            return Err(format!(
                "observed {} of {CONCURRENT} concurrent Resolve calls",
                observations.len()
            ));
        }
        if real_ports != expected_ports {
            return Err(format!(
                "concurrent Resolve source ports were {real_ports:?}, expected {expected_ports:?}"
            ));
        }
        if observations.iter().any(|observation| {
            observation.queried_peer.ip() != observation.peer.ip()
                || observation.queried_peer.port() != observation.peer.port().swap_bytes()
                || observation.queried_peer.port() == observation.peer.port()
                || observation.queried_local != observation.local
                || observation.outcome != ObservedResolveOutcome::Timeout
                || observation.mismatch.is_some()
                || observation.recv_q_bytes == 0
                || observation.dns_when_resolve_returned != 0
                || observation.outbound_when_resolve_returned != 0
                || observation.health_failure.is_some()
                || !timeout_duration_is_bounded(
                    observation.resolve_elapsed_ms,
                    config.cgroup_bpf.resolve_timeout_ms,
                    CONCURRENT_TIMEOUT_LATE_TOLERANCE_MS,
                )
        }) {
            return Err(
                "a concurrent Resolve violated tuple swap, timeout, no-read, no-effect or health bounds"
                    .to_owned(),
            );
        }
        if client_outcomes.iter().any(|outcome| {
            outcome.get("status").and_then(Value::as_str) != Some("connected")
        }) {
            return Err("an in-Execution concurrent client did not connect to the proxy".to_owned());
        }
        if health_failure
            .lock()
            .map_err(|_| "health observation lock poisoned".to_owned())?
            .is_some()
        {
            return Err("concurrent timeout changed runtime health".to_owned());
        }
        Ok(())
    }
    .await;

    let cleanup = execution.cleanup(Some(&table)).await;
    fs::write(
        case_dir.join("execution-cleanup.json"),
        serde_json::to_vec_pretty(&json!({"failures": cleanup}))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if !cleanup.is_empty() {
        return Err(format!("concurrent_timeout cleanup failed: {cleanup:?}"));
    }
    dump_maps(config, &case_dir, "post-cleanup")?;
    let tuple_entries = map_dump_entry_count(&case_dir, "post-cleanup", "soglia_tuples")?;
    let cookie_entries = map_dump_entry_count(&case_dir, "post-cleanup", "soglia_cookie_a")?;
    let tuple_insert_failed =
        counter_value_from_evidence(&case_dir, "post-cleanup", C_TUPLE_INSERT_FAILED)?;
    fs::write(
        case_dir.join("post-cleanup-attribution.json"),
        serde_json::to_vec_pretty(&json!({
            "case": "CONCURRENT_TIMEOUT",
            "execution_id": id,
            "binding": execution.binding,
            "tuple_entries_after_cleanup": tuple_entries,
            "cookie_entries_after_cleanup": cookie_entries,
            "execution_attribution_absent": tuple_entries == 0 && cookie_entries == 0,
            "C_TUPLE_INSERT_FAILED": tuple_insert_failed,
            "tuple_insert_failed_invariant": tuple_insert_failed == 0
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if tuple_entries != 0 || cookie_entries != 0 {
        return Err(format!(
            "concurrent_timeout retained Candidate-A state: tuples={tuple_entries}, cookies={cookie_entries}"
        ));
    }
    if tuple_insert_failed != 0 {
        return Err(format!(
            "C_TUPLE_INSERT_FAILED is {tuple_insert_failed}, expected 0"
        ));
    }
    enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| format!("post-concurrency backend health: {error}"))?;
    if let Err(error) = &result {
        fs::write(case_dir.join("verdict.txt"), "FAIL\n").map_err(|write| write.to_string())?;
        fs::write(case_dir.join("failure.txt"), format!("{error}\n"))
            .map_err(|write| write.to_string())?;
    } else {
        fs::write(case_dir.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    }
    result
}

async fn run_host_origin_refused_case(
    evidence: &Path,
    config: &Config,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let case_dir = evidence.join("cases/host_origin_refused");
    fs::create_dir_all(&case_dir).map_err(|error| error.to_string())?;
    fs::write(evidence.join("current-case.txt"), "host_origin_refused\n")
        .map_err(|error| error.to_string())?;
    let calls = Arc::new(AtomicUsize::new(0));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health_failure = Arc::new(Mutex::new(None));
    let observed_failure = Arc::clone(&health_failure);
    let production: Arc<dyn ConnectionAttributor> = Arc::new(CandidateAAttributor::new(
        enforcer
            .resolver_client()
            .map_err(|error| error.to_string())?,
        Arc::new(AttributionTable::new()),
        Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
        1,
        Arc::new(move |failure| {
            if let Ok(mut observed) = observed_failure.lock() {
                *observed = Some(match failure {
                    ResolveHealthFailure::Unavailable => ObservedHealthFailure::Unavailable,
                    ResolveHealthFailure::IntegrityFailure => {
                        ObservedHealthFailure::IntegrityFailure
                    }
                });
            }
        }),
    ));
    let observing: Arc<dyn ConnectionAttributor> = Arc::new(CountingConnectionAttributor {
        inner: production,
        calls: Arc::clone(&calls),
    });
    let policy = DestinationPolicy::new(&config.egress, &config.network, Vec::new())
        .map_err(|error| error.to_string())?;
    let proxy = Arc::new(EgressProxy::new(
        Arc::new(policy),
        observing,
        Arc::new(CountingResolver {
            calls: Arc::clone(&dns),
        }),
        EgressLimits::from_config(&config.egress),
    ));
    let address = SocketAddr::from((config.network.proxy_address, config.network.proxy_port));
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| format!("bind host-origin-refused proxy: {error}"))?;
    let (stop, stopped) = watch::channel(false);
    let proxy_task = tokio::spawn(proxy.serve(listener, stopped));
    let started = Instant::now();
    let attempted =
        tokio::time::timeout(Duration::from_millis(1_500), TcpStream::connect(address)).await;
    let (status, error) = match attempted {
        Ok(Ok(_stream)) => ("connected", None),
        Ok(Err(error)) => ("refused", Some(error.to_string())),
        Err(error) => ("timed_out", Some(error.to_string())),
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), proxy_task)
        .await
        .map_err(|_| "host-origin-refused proxy did not stop".to_owned())?
        .map_err(|error| error.to_string())?;
    let resolve_calls = calls.load(Ordering::SeqCst);
    dump_maps(config, &case_dir, "post-case")?;
    let tuple_insert_failed =
        counter_value_from_evidence(&case_dir, "post-case", C_TUPLE_INSERT_FAILED)?;
    fs::write(
        case_dir.join("client-outcomes.json"),
        serde_json::to_vec_pretty(&json!([{
            "origin": "qualification host outside executions/",
            "destination": address,
            "status": status,
            "error": error,
            "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
        }]))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        case_dir.join("scope.json"),
        serde_json::to_vec_pretty(&json!({
            "case": "HOST_ORIGIN_REFUSED",
            "nft_contract": "inet soglia_host input drops proxy-address traffic not arriving from an Execution veth",
            "origin": "qualification host outside the executions cgroup subtree",
            "destination": address,
            "expected": "client refused or timed out, proxy accepts nothing, zero Resolve calls",
            "production_code_modified": false
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        case_dir.join("resolve-count.json"),
        serde_json::to_vec_pretty(&json!({
            "accepted_connections_reaching_attributor": resolve_calls,
            "expected": 0,
            "dns_calls": dns.load(Ordering::SeqCst),
            "outbound_accepts": outbound.load(Ordering::SeqCst),
            "health_failure": health_failure.lock().ok().and_then(|value| *value),
            "C_TUPLE_INSERT_FAILED": tuple_insert_failed
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let result = if status == "connected" || resolve_calls != 0 {
        Err(format!(
            "host origin was {status} and produced {resolve_calls} Resolve calls"
        ))
    } else if dns.load(Ordering::SeqCst) != 0 || outbound.load(Ordering::SeqCst) != 0 {
        Err("host-origin refusal produced DNS or outbound effects".to_owned())
    } else if tuple_insert_failed != 0 {
        Err(format!(
            "C_TUPLE_INSERT_FAILED is {tuple_insert_failed} after host_origin_refused"
        ))
    } else if health_failure
        .lock()
        .map_err(|_| "health observation lock poisoned".to_owned())?
        .is_some()
    {
        Err("host-origin refusal changed runtime health".to_owned())
    } else {
        enforcer
            .call(EnforcerRequest::Health)
            .await
            .map_err(|error| format!("post-host-origin backend health: {error}"))?;
        Ok(())
    };
    if let Err(error) = &result {
        fs::write(case_dir.join("verdict.txt"), "FAIL\n").map_err(|write| write.to_string())?;
        fs::write(case_dir.join("failure.txt"), format!("{error}\n"))
            .map_err(|write| write.to_string())?;
    } else {
        fs::write(case_dir.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    }
    result
}

async fn read_agent_client_outcomes(
    pid: i32,
    evidence: &Path,
    expected_count: usize,
    first_source_port: u16,
    timeout: Duration,
) -> Result<Vec<Value>, String> {
    let report = PathBuf::from(format!("/proc/{pid}/root/tmp/client-outcomes.jsonl"));
    wait_for_file(&report, timeout).await?;
    let raw = fs::read_to_string(&report).map_err(|error| error.to_string())?;
    fs::write(evidence.join("client-outcomes.jsonl"), &raw).map_err(|error| error.to_string())?;
    let outcomes: Vec<Value> = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|error| error.to_string()))
        .collect::<Result<_, _>>()?;
    fs::write(
        evidence.join("client-outcomes.json"),
        serde_json::to_vec_pretty(&outcomes).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if outcomes.len() != expected_count {
        return Err(format!(
            "agent recorded {} of {expected_count} client outcomes",
            outcomes.len()
        ));
    }
    let mut observed = Vec::with_capacity(expected_count);
    for outcome in &outcomes {
        if outcome.get("cmd").and_then(Value::as_str) != Some("proxy-fixed") {
            return Err(format!("unexpected client outcome command: {outcome}"));
        }
        let index = outcome
            .get("i")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("client outcome omitted a valid index: {outcome}"))?;
        let source_port = outcome
            .get("source_port")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| format!("client outcome omitted a valid source port: {outcome}"))?;
        let status = outcome
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("client outcome omitted its status: {outcome}"))?;
        if !matches!(status, "connected" | "refused" | "timed_out") {
            return Err(format!("client outcome has unknown status {status}"));
        }
        observed.push((index, source_port));
    }
    observed.sort_unstable();
    let expected: Vec<(usize, u16)> = (0..expected_count)
        .map(|index| (index, first_source_port + index as u16))
        .collect();
    if observed != expected {
        return Err(format!(
            "client outcome identities were {observed:?}, expected {expected:?}"
        ));
    }
    Ok(outcomes)
}

fn assert_expected_resolve(
    case: Case,
    observation: &ResolveObservation,
    id: ExecutionId,
    configured_timeout_ms: u64,
) -> Result<(), String> {
    let expected = match case {
        Case::Positive => (ObservedResolveOutcome::Resolved, None),
        Case::NonceMismatch => (
            ObservedResolveOutcome::IdentityMismatch,
            Some(ResolveMismatch::ExecutionNonce),
        ),
        Case::GenerationMismatch => (
            ObservedResolveOutcome::IdentityMismatch,
            Some(ResolveMismatch::BackendGeneration),
        ),
        Case::TupleByteOrder => (ObservedResolveOutcome::Timeout, None),
        Case::WrongDestination => (ObservedResolveOutcome::NotFound, None),
        Case::MissingCookie => (
            ObservedResolveOutcome::IdentityMismatch,
            Some(ResolveMismatch::Cookie),
        ),
        Case::IpOnly => (ObservedResolveOutcome::NotFound, None),
        Case::WrongPid | Case::WrongCgroup => {
            return Err("placement-refusal cases must not reach Resolve".to_owned());
        }
    };
    if (observation.outcome, observation.mismatch) != expected {
        return Err(format!(
            "{case:?} produced {:?}/{:?}, expected {:?}/{:?}",
            observation.outcome, observation.mismatch, expected.0, expected.1
        ));
    }
    if observation.health_failure.is_some() {
        return Err(format!(
            "{case:?} unexpectedly changed runtime health: {:?}",
            observation.health_failure
        ));
    }
    match case {
        Case::Positive if observation.resolved_execution != Some(id) => {
            return Err("positive Resolve did not return the correct ExecutionId".to_owned());
        }
        Case::Positive => {}
        _ if observation.resolved_execution.is_some() => {
            return Err("negative case resolved an Execution".to_owned());
        }
        _ => {}
    }
    if case == Case::TupleByteOrder {
        if !timeout_duration_is_bounded(
            observation.resolve_elapsed_ms,
            configured_timeout_ms,
            SINGLE_TIMEOUT_LATE_TOLERANCE_MS,
        ) {
            return Err(format!(
                "Resolve timeout took {} ms, outside configured {} ms minus {} ms / plus {} ms tolerance",
                observation.resolve_elapsed_ms,
                configured_timeout_ms,
                TIMEOUT_EARLY_TOLERANCE_MS,
                SINGLE_TIMEOUT_LATE_TOLERANCE_MS
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_case(
    case: Case,
    evidence: &Path,
    config: &Config,
    execution_address: Ipv4Addr,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let id = ExecutionId::generate().map_err(|error| error.to_string())?;
    let nonce = ExecutionNonce::generate().map_err(|error| error.to_string())?;
    let target = config
        .cgroup
        .root
        .as_ref()
        .ok_or("B2 requires an explicit delegated root")?
        .join("executions")
        .join(id.tag().to_string());
    let mut execution = Execution {
        sandbox,
        enforcer,
        id,
        binding: None,
        key_bound: false,
        legacy_ip: None,
        reserved: false,
        prepared: false,
        moved_pid: None,
    };
    let table = Arc::new(AttributionTable::new());
    let result = async {
        let reserved = sandbox
            .call(SandboxRequest::Reserve {
                id,
                agent: "probe".to_owned(),
            })
            .await
            .map_err(|error| error.to_string())?;
        let HelperResponse::Reserved { cgroup_inode } = reserved else {
            return Err(format!("unexpected reserve response: {reserved:?}"));
        };
        execution.reserved = true;
        enforcer
            .call(EnforcerRequest::Prepare {
                id,
                slot: 0,
                agent: "probe".to_owned(),
                nonce,
            })
            .await
            .map_err(|error| error.to_string())?;
        execution.prepared = true;
        dump_maps(config, evidence, "prepared")?;

        let paused = sandbox
            .call(SandboxRequest::CreatePaused { id })
            .await
            .map_err(|error| error.to_string())?;
        let HelperResponse::CreatedPaused {
            pid,
            cgroup_inode: paused_inode,
        } = paused
        else {
            return Err(format!("unexpected create-paused response: {paused:?}"));
        };
        if cgroup_inode != paused_inode {
            return Err("reserved and paused cgroup inodes differ".to_owned());
        }
        record_placement(config, evidence, id, pid, cgroup_inode)?;

        if case == Case::WrongPid {
            let wrong = i32::try_from(std::process::id()).map_err(|error| error.to_string())?;
            let refusal = typed_placement_refusal(
                enforcer
                    .call(EnforcerRequest::VerifyPlacement { id, pid: wrong })
                    .await,
                "wrong PID",
            )?;
            fs::write(
                evidence.join("fault-injection.json"),
                serde_json::to_vec_pretty(&json!({
                    "fault": "WRONG_PID", "actual_agent_pid": pid, "submitted_pid": wrong,
                    "target_cgroup_unchanged": true, "refusal": refusal
                }))
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        if case == Case::WrongCgroup {
            let sibling = target
                .parent()
                .ok_or("target has no parent")?
                .join("b2-wrong-cgroup");
            fs::create_dir(&sibling).map_err(|error| error.to_string())?;
            fs::write(sibling.join("cgroup.procs"), format!("{pid}\n"))
                .map_err(|error| error.to_string())?;
            execution.moved_pid = Some((pid, target.clone()));
            let refusal = typed_placement_refusal(
                enforcer
                    .call(EnforcerRequest::VerifyPlacement { id, pid })
                    .await,
                "correct PID in wrong cgroup",
            )?;
            fs::write(target.join("cgroup.procs"), format!("{pid}\n"))
                .map_err(|error| error.to_string())?;
            execution.moved_pid = None;
            fs::remove_dir(&sibling).map_err(|error| error.to_string())?;
            fs::write(
                evidence.join("fault-injection.json"),
                serde_json::to_vec_pretty(&json!({
                    "fault": "WRONG_CGROUP", "actual_agent_pid": pid,
                    "submitted_pid_unchanged": true, "temporary_cgroup": sibling,
                    "refusal": refusal
                }))
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            return Ok(());
        }

        let verified = enforcer
            .call(EnforcerRequest::VerifyPlacement { id, pid })
            .await
            .map_err(|error| error.to_string())?;
        let HelperResponse::PlacementVerified { binding } = verified else {
            return Err(format!("unexpected placement response: {verified:?}"));
        };
        if binding.cgroup_id != cgroup_inode || binding.execution_nonce != nonce {
            return Err("verified BindingKey does not match reserved identity".to_owned());
        }
        execution.binding = Some(binding);
        if case == Case::IpOnly {
            table
                .bind(IpAddr::V4(execution_address), id)
                .map_err(|error| error.to_string())?;
            execution.legacy_ip = Some(IpAddr::V4(execution_address));
            fs::write(
                evidence.join("fault-injection.json"),
                serde_json::to_vec_pretty(&json!({
                    "fault": "IP_ONLY_IDENTITY", "ip": execution_address,
                    "BindingKey_installed": false, "legacy_ip_binding_installed": true
                }))
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        } else {
            table
                .bind_key(binding, id)
                .map_err(|error| error.to_string())?;
            execution.key_bound = true;
        }
        enforcer
            .call(EnforcerRequest::Activate {
                id,
                binding: Some(binding),
            })
            .await
            .map_err(|error| error.to_string())?;
        dump_maps(config, evidence, "active")?;

        let dns = Arc::new(AtomicUsize::new(0));
        outbound.store(0, Ordering::SeqCst);
        let health_failure = Arc::new(Mutex::new(None));
        let resolver: ResolverClient = enforcer
            .resolver_client()
            .map_err(|error| error.to_string())?;
        let observed_failure = Arc::clone(&health_failure);
        let production: Arc<dyn ConnectionAttributor> = Arc::new(CandidateAAttributor::new(
            resolver,
            Arc::clone(&table),
            Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
            1,
            Arc::new(move |failure| {
                if let Ok(mut observed) = observed_failure.lock() {
                    *observed = Some(match failure {
                        ResolveHealthFailure::Unavailable => ObservedHealthFailure::Unavailable,
                        ResolveHealthFailure::IntegrityFailure => {
                            ObservedHealthFailure::IntegrityFailure
                        }
                    });
                }
            }),
        ));
        let observing: Arc<dyn ConnectionAttributor> = Arc::new(ObservingAttributor {
            inner: production,
            case,
            evidence: evidence.to_path_buf(),
            state: config.runtime.state_dir.join("cgroup-bpf/state.json"),
            bpftool: config.runtime.bpftool.clone(),
            dns: Arc::clone(&dns),
            outbound: Arc::clone(&outbound),
            health_failure,
        });
        let policy = DestinationPolicy::new(&config.egress, &config.network, Vec::new())
            .map_err(|error| error.to_string())?;
        let proxy = Arc::new(EgressProxy::new(
            Arc::new(policy),
            observing,
            Arc::new(CountingResolver {
                calls: Arc::clone(&dns),
            }),
            EgressLimits::from_config(&config.egress),
        ));
        let listener = TcpListener::bind(SocketAddr::from((
            config.network.proxy_address,
            config.network.proxy_port,
        )))
        .await
        .map_err(|error| format!("bind production proxy: {error}"))?;
        let (stop, stopped) = watch::channel(false);
        let proxy_task = tokio::spawn(proxy.serve(listener, stopped));

        sandbox
            .call(SandboxRequest::Start { id })
            .await
            .map_err(|error| error.to_string())?;
        wait_for_file(&evidence.join("resolve.json"), Duration::from_secs(8)).await?;
        if evidence.join("injection-error.txt").exists() {
            return Err(format!(
                "fault injection failed: {}",
                fs::read_to_string(evidence.join("injection-error.txt"))
                    .map_err(|error| error.to_string())?
                    .trim()
            ));
        }
        if case != Case::Positive && !evidence.join("fault-injection.json").exists() {
            return Err("negative case has no isolated fault record".to_owned());
        }
        let observation: ResolveObservation = serde_json::from_slice(
            &fs::read(evidence.join("resolve.json")).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let recv_q = observation.recv_q_bytes;
        let dns_at_resolve = observation.dns_when_resolve_returned;
        let outbound_at_resolve = observation.outbound_when_resolve_returned;
        if recv_q == 0 || dns_at_resolve != 0 || outbound_at_resolve != 0 {
            return Err("pre-Resolve no-read/no-effect observation failed".to_owned());
        }
        assert_expected_resolve(case, &observation, id, config.cgroup_bpf.resolve_timeout_ms)?;
        if case == Case::Positive {
            wait_for_count(&dns, 1, Duration::from_secs(2)).await?;
            wait_for_count(&outbound, 1, Duration::from_secs(2)).await?;
        } else {
            tokio::time::sleep(Duration::from_millis(150)).await;
            if dns.load(Ordering::SeqCst) != 0 || outbound.load(Ordering::SeqCst) != 0 {
                return Err("negative case produced DNS or outbound effects".to_owned());
            }
        }
        stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .map_err(|_| "proxy did not stop".to_owned())?
            .map_err(|error| error.to_string())?;
        if case == Case::TupleByteOrder {
            wait_for_tuple_byte_order_counters(config, evidence)?;
        }
        dump_maps(config, evidence, "after-resolve")?;
        Ok(())
    }
    .await;

    let cleanup = execution.cleanup(Some(&table)).await;
    fs::write(
        evidence.join("execution-cleanup.json"),
        serde_json::to_vec_pretty(&json!({"failures": cleanup}))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if !cleanup.is_empty() {
        return Err(format!("execution cleanup failed: {cleanup:?}"));
    }
    dump_maps(config, evidence, "post-cleanup")?;
    let tuple_entries = map_dump_entry_count(evidence, "post-cleanup", "soglia_tuples")?;
    let cookie_entries = map_dump_entry_count(evidence, "post-cleanup", "soglia_cookie_a")?;
    let tuple_insert_failed =
        counter_value_from_evidence(evidence, "post-cleanup", C_TUPLE_INSERT_FAILED)?;
    let tuple_entries_before_cleanup = if evidence.join("after-resolve-soglia_tuples.json").exists()
    {
        Some(map_dump_entry_count(
            evidence,
            "after-resolve",
            "soglia_tuples",
        )?)
    } else {
        None
    };
    fs::write(
        evidence.join("post-cleanup-attribution.json"),
        serde_json::to_vec_pretty(&json!({
            "case": case,
            "execution_id": id,
            "binding": execution.binding,
            "tuple_entries_before_cleanup": tuple_entries_before_cleanup,
            "tuple_entries_after_cleanup": tuple_entries,
            "cookie_entries_after_cleanup": cookie_entries,
            "execution_attribution_absent": tuple_entries == 0 && cookie_entries == 0,
            "C_TUPLE_INSERT_FAILED": tuple_insert_failed,
            "tuple_insert_failed_invariant": tuple_insert_failed == 0
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if tuple_entries != 0 || cookie_entries != 0 {
        return Err(format!(
            "post-teardown Candidate-A state is not empty: tuples={tuple_entries}, cookies={cookie_entries}"
        ));
    }
    if tuple_insert_failed != 0 {
        return Err(format!(
            "C_TUPLE_INSERT_FAILED is {tuple_insert_failed} after {}, expected 0",
            case.name()
        ));
    }
    enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| format!("post-case health: {error}"))?;
    result
}

fn typed_placement_refusal(
    result: Result<HelperResponse, HelperError>,
    case: &str,
) -> Result<String, String> {
    match result {
        Err(HelperError::Failed(reason)) => Ok(reason),
        Err(other) => Err(format!(
            "{case} produced the wrong refusal class: {other:?}"
        )),
        Ok(response) => Err(format!(
            "{case} was accepted instead of being refused: {response:?}"
        )),
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
    fs::write(
        evidence.join("proc-cgroup.txt"),
        fs::read(format!("/proc/{pid}/cgroup")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        evidence.join("cgroup-procs.txt"),
        fs::read(target.join("cgroup.procs")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let agent_net =
        fs::metadata(format!("/proc/{pid}/ns/net")).map_err(|error| error.to_string())?;
    let owned_net_path = Path::new("/run/netns").join(id.tag().netns_name());
    let owned_net = fs::metadata(&owned_net_path).map_err(|error| error.to_string())?;
    let netns_cookie = probe_netns_cookie(config, id)?;
    let membership =
        fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|error| error.to_string())?;
    let procs =
        fs::read_to_string(target.join("cgroup.procs")).map_err(|error| error.to_string())?;
    fs::write(
        evidence.join("placement.json"),
        serde_json::to_vec_pretty(&json!({
            "execution_id": id, "tag": id.tag(), "host_pid": pid,
            "target": target, "target_inode": inode,
            "proc_cgroup": membership,
            "target_cgroup_procs": procs,
            "pid_listed": procs.split_whitespace().any(|entry| entry.parse::<i32>() == Ok(pid)),
            "netns": {"owned_path": owned_net_path,
                      "agent_inode": std::os::unix::fs::MetadataExt::ino(&agent_net),
                      "owned_inode": std::os::unix::fs::MetadataExt::ino(&owned_net),
                      "matches": std::os::unix::fs::MetadataExt::ino(&agent_net) == std::os::unix::fs::MetadataExt::ino(&owned_net),
                      "inode_used_as_identity": false,
                      "cookie": netns_cookie}
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            target.to_str().ok_or("non-UTF8 target")?,
        ],
        &evidence.join("hooks-direct.json"),
    )?;
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            target.to_str().ok_or("non-UTF8 target")?,
            "effective",
        ],
        &evidence.join("hooks-effective.json"),
    )
}

fn probe_netns_cookie(config: &Config, id: ExecutionId) -> Result<Value, String> {
    let agent = config.agents.get("probe").ok_or("probe agent is absent")?;
    let entry = agent
        .command
        .first()
        .ok_or("probe agent command is empty")?
        .strip_prefix('/')
        .ok_or("probe agent entry point is not absolute")?;
    let executable = agent.rootfs.join(entry);
    let output = Command::new(&config.runtime.ip)
        .args(["netns", "exec", &id.tag().netns_name()])
        .arg(&executable)
        .arg("netns-cookie")
        .output()
        .map_err(|error| format!("execute netns-cookie probe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "netns-cookie probe exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let observation: Value =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    if observation.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("netns-cookie probe failed: {observation}"));
    }
    let supported = observation
        .get("supported")
        .and_then(Value::as_bool)
        .ok_or("netns-cookie probe omitted support status")?;
    if supported && observation.get("cookie").and_then(Value::as_u64).is_none() {
        return Err("netns-cookie probe omitted the supported cookie".to_owned());
    }
    Ok(json!({
        "probe": "SO_NETNS_COOKIE",
        "socket_opened_by": "soglia-spike-agent executed in the owned netns",
        "supported": supported,
        "value": observation.get("cookie").and_then(Value::as_u64),
        "errno": observation.get("errno").and_then(Value::as_i64)
    }))
}

fn dump_maps(config: &Config, evidence: &Path, stage: &str) -> Result<(), String> {
    let state: Value = serde_json::from_slice(
        &fs::read(config.runtime.state_dir.join("cgroup-bpf/state.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        evidence.join(format!("state-{stage}.json")),
        serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    for name in [
        "soglia_policy",
        "soglia_cookie_a",
        "soglia_tuples",
        "soglia_counters",
    ] {
        let pin = map_pin(&state, name)?;
        run_to_file(
            &config.runtime.bpftool,
            &[
                "-j",
                "map",
                "dump",
                "pinned",
                pin.to_str().ok_or("non-UTF8 pin")?,
            ],
            &evidence.join(format!("{stage}-{name}.json")),
        )?;
    }
    Ok(())
}

fn encode_socket_tuple(peer: SocketAddr, local: SocketAddr) -> Result<[u8; 16], String> {
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (peer.ip(), local.ip()) else {
        return Err("B2 Candidate-A tuple evidence requires IPv4 sockets".to_owned());
    };
    let mut key = [0_u8; 16];
    key[0..4].copy_from_slice(&source.octets());
    key[4..8].copy_from_slice(&destination.octets());
    key[8..10].copy_from_slice(&peer.port().to_ne_bytes());
    key[10..12].copy_from_slice(&local.port().to_ne_bytes());
    Ok(key)
}

fn map_dump_value_for_key(dump: &Value, expected: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut value = None;
    for entry in dump.as_array().ok_or("BPF map dump is not an array")? {
        let key = entry
            .get("key")
            .ok_or_else(|| "BPF map entry omitted its key".to_owned())
            .and_then(json_bytes)?;
        if key != expected {
            continue;
        }
        if value.is_some() {
            return Err("BPF map dump contains a duplicate key".to_owned());
        }
        value = Some(
            entry
                .get("value")
                .ok_or_else(|| "BPF map entry omitted its value".to_owned())
                .and_then(json_bytes)?,
        );
    }
    Ok(value)
}

fn counter_value(dump: &Value, index: u32) -> Result<u64, String> {
    let key = index.to_ne_bytes();
    let value = map_dump_value_for_key(dump, &key)?
        .ok_or_else(|| format!("counter dump omitted index {index}"))?;
    let bytes: [u8; 8] = value.try_into().map_err(|value: Vec<u8>| {
        format!("counter {index} has {} bytes, expected 8", value.len())
    })?;
    Ok(u64::from_ne_bytes(bytes))
}

fn counter_value_from_evidence(evidence: &Path, stage: &str, index: u32) -> Result<u64, String> {
    let dump: Value = serde_json::from_slice(
        &fs::read(evidence.join(format!("{stage}-soglia_counters.json")))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    counter_value(&dump, index)
}

fn capture_tuple_before_lookup(
    bpftool: &Path,
    state_path: &Path,
    evidence: &Path,
    peer: SocketAddr,
    local: SocketAddr,
    queried_peer: SocketAddr,
    queried_local: SocketAddr,
) -> Result<(), String> {
    let state: Value =
        serde_json::from_slice(&fs::read(state_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let tuple_pin = map_pin(&state, "soglia_tuples")?;
    let counter_pin = map_pin(&state, "soglia_counters")?;
    let real_key = encode_socket_tuple(peer, local)?;
    let queried_key = encode_socket_tuple(queried_peer, queried_local)?;
    if real_key == queried_key {
        return Err("tuple_byte_order did not produce a distinct lookup key".to_owned());
    }

    let started = Instant::now();
    let tuple_dump = loop {
        let dump = dump_map(bpftool, &tuple_pin)?;
        if map_dump_contains_key(&dump, &real_key)? {
            break dump;
        }
        if started.elapsed() >= Duration::from_secs(1) {
            fs::write(
                evidence.join("pre-lookup-soglia_tuples.json"),
                serde_json::to_vec_pretty(&dump).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            return Err("real tuple was not published before the byte-swapped lookup".to_owned());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let value = map_dump_value_for_key(&tuple_dump, &real_key)?
        .ok_or("real tuple disappeared before its value could be captured")?;
    if value.len() != 48 {
        return Err(format!(
            "real tuple value has {} bytes, expected 48",
            value.len()
        ));
    }
    let cookie = u64::from_ne_bytes(
        value[0..8]
            .try_into()
            .map_err(|_| "tuple cookie has the wrong width")?,
    );
    let queried_key_present = map_dump_contains_key(&tuple_dump, &queried_key)?;
    let counter_dump = dump_map(bpftool, &counter_pin)?;
    let baseline_published = counter_value_from_evidence(evidence, "active", C_PUBLISHED)?;
    let baseline_unpublished = counter_value_from_evidence(evidence, "active", C_UNPUBLISHED)?;
    let published = counter_value(&counter_dump, C_PUBLISHED)?;
    let unpublished = counter_value(&counter_dump, C_UNPUBLISHED)?;
    let tuple_insert_failed = counter_value(&counter_dump, C_TUPLE_INSERT_FAILED)?;
    fs::write(
        evidence.join("pre-lookup-soglia_tuples.json"),
        serde_json::to_vec_pretty(&tuple_dump).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        evidence.join("pre-lookup-tuple.json"),
        serde_json::to_vec_pretty(&json!({
            "captured_while_socket_open": true,
            "captured_before_userspace_lookup": true,
            "real": {
                "peer": peer,
                "local": local,
                "key_hex": hex(&real_key),
                "present": true,
                "cookie": cookie,
                "cookie_nonzero": cookie != 0
            },
            "queried": {
                "peer": queried_peer,
                "local": queried_local,
                "key_hex": hex(&queried_key),
                "present": queried_key_present
            },
            "counters": {
                "active_baseline": {
                    "C_PUBLISHED": baseline_published,
                    "C_UNPUBLISHED": baseline_unpublished
                },
                "pre_lookup": {
                    "C_TUPLE_INSERT_FAILED": tuple_insert_failed,
                    "C_PUBLISHED": published,
                    "C_UNPUBLISHED": unpublished
                },
                "publication_delta": published.saturating_sub(baseline_published),
                "unpublication_delta_before_lookup": unpublished.saturating_sub(baseline_unpublished)
            }
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if cookie == 0 {
        return Err("real tuple carried a zero socket cookie".to_owned());
    }
    if queried_key_present {
        return Err("byte-swapped lookup key was already present before Resolve".to_owned());
    }
    if tuple_insert_failed != 0 {
        return Err(format!(
            "C_TUPLE_INSERT_FAILED is {tuple_insert_failed} before byte-swapped Resolve"
        ));
    }
    if published != baseline_published + 1 || unpublished != baseline_unpublished {
        return Err(format!(
            "unexpected pre-lookup counter deltas: published {} -> {}, unpublished {} -> {}",
            baseline_published, published, baseline_unpublished, unpublished
        ));
    }
    Ok(())
}

fn wait_for_tuple_byte_order_counters(config: &Config, evidence: &Path) -> Result<(), String> {
    let state: Value = serde_json::from_slice(
        &fs::read(config.runtime.state_dir.join("cgroup-bpf/state.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let counter_pin = map_pin(&state, "soglia_counters")?;
    let baseline_insert_failed =
        counter_value_from_evidence(evidence, "active", C_TUPLE_INSERT_FAILED)?;
    let baseline_published = counter_value_from_evidence(evidence, "active", C_PUBLISHED)?;
    let baseline_unpublished = counter_value_from_evidence(evidence, "active", C_UNPUBLISHED)?;
    let started = Instant::now();
    let final_dump = loop {
        let dump = dump_map(&config.runtime.bpftool, &counter_pin)?;
        let published = counter_value(&dump, C_PUBLISHED)?;
        let unpublished = counter_value(&dump, C_UNPUBLISHED)?;
        if published == baseline_published + 1 && unpublished == baseline_unpublished + 1 {
            break dump;
        }
        if started.elapsed() >= Duration::from_secs(1) {
            break dump;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let final_insert_failed = counter_value(&final_dump, C_TUPLE_INSERT_FAILED)?;
    let final_published = counter_value(&final_dump, C_PUBLISHED)?;
    let final_unpublished = counter_value(&final_dump, C_UNPUBLISHED)?;
    let published_delta = final_published.saturating_sub(baseline_published);
    let unpublished_delta = final_unpublished.saturating_sub(baseline_unpublished);
    fs::write(
        evidence.join("tuple-byte-order-counters.json"),
        serde_json::to_vec_pretty(&json!({
            "source": "production Candidate-A BPF counters",
            "lookup_and_delete_changes_counters": false,
            "active_baseline": {
                "C_TUPLE_INSERT_FAILED": baseline_insert_failed,
                "C_PUBLISHED": baseline_published,
                "C_UNPUBLISHED": baseline_unpublished
            },
            "after_socket_close": {
                "C_TUPLE_INSERT_FAILED": final_insert_failed,
                "C_PUBLISHED": final_published,
                "C_UNPUBLISHED": final_unpublished
            },
            "delta": {
                "C_TUPLE_INSERT_FAILED": final_insert_failed.saturating_sub(baseline_insert_failed),
                "C_PUBLISHED": published_delta,
                "C_UNPUBLISHED": unpublished_delta
            },
            "proves_sockops_unpublish": published_delta == 1 && unpublished_delta == 1,
            "raw_after_socket_close": final_dump
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if baseline_insert_failed != 0 || final_insert_failed != 0 {
        return Err(format!(
            "C_TUPLE_INSERT_FAILED changed from {baseline_insert_failed} to {final_insert_failed}"
        ));
    }
    if published_delta != 1 || unpublished_delta != 1 {
        return Err(format!(
            "tuple_byte_order counter deltas were published={published_delta}, unpublished={unpublished_delta}, expected 1/1"
        ));
    }
    Ok(())
}

fn write_tuple_insert_failed_summary(evidence: &Path) -> Result<(), String> {
    let mut observations = Vec::new();
    for case in CASES {
        let case_dir = evidence.join("cases").join(case.name());
        let value = counter_value_from_evidence(&case_dir, "post-cleanup", C_TUPLE_INSERT_FAILED)?;
        observations.push(json!({"case": case, "stage": "post-cleanup", "value": value}));
        if value != 0 {
            return Err(format!(
                "C_TUPLE_INSERT_FAILED is {value} after {}",
                case.name()
            ));
        }
    }
    let host_dir = evidence.join("cases/host_origin_refused");
    let host = counter_value_from_evidence(&host_dir, "post-case", C_TUPLE_INSERT_FAILED)?;
    observations.push(json!({
        "case": "HOST_ORIGIN_REFUSED",
        "stage": "post-case",
        "value": host
    }));
    if host != 0 {
        return Err(format!(
            "C_TUPLE_INSERT_FAILED is {host} after host_origin_refused"
        ));
    }
    let concurrent_dir = evidence.join("cases/concurrent_timeout");
    let concurrent =
        counter_value_from_evidence(&concurrent_dir, "post-cleanup", C_TUPLE_INSERT_FAILED)?;
    observations.push(json!({
        "case": "CONCURRENT_TIMEOUT",
        "stage": "post-cleanup",
        "value": concurrent
    }));
    if concurrent != 0 {
        return Err(format!(
            "C_TUPLE_INSERT_FAILED is {concurrent} after concurrent_timeout"
        ));
    }
    fs::write(
        evidence.join("tuple-insert-failed-summary.json"),
        serde_json::to_vec_pretty(&json!({
            "counter": "C_TUPLE_INSERT_FAILED",
            "index": C_TUPLE_INSERT_FAILED,
            "expected_throughout_run": 0,
            "observations": observations,
            "holds": true
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn map_dump_entry_count(evidence: &Path, stage: &str, name: &str) -> Result<usize, String> {
    let dump: Value = serde_json::from_slice(
        &fs::read(evidence.join(format!("{stage}-{name}.json")))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    dump.as_array()
        .map(Vec::len)
        .ok_or_else(|| format!("{stage} {name} dump is not an array"))
}

fn inject_map_fault(
    bpftool: &Path,
    state_path: &Path,
    fault: MapFault,
    evidence: &Path,
) -> Result<(), String> {
    let state: Value =
        serde_json::from_slice(&fs::read(state_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let tuple_pin = map_pin(&state, "soglia_tuples")?;
    let started = Instant::now();
    let (key, mut value, raw) = loop {
        let output = command_output(
            bpftool,
            &[
                "-j",
                "map",
                "dump",
                "pinned",
                tuple_pin.to_str().ok_or("non-UTF8 pin")?,
            ],
        )?;
        let entries: Value = serde_json::from_slice(&output).map_err(|error| error.to_string())?;
        if let Some(entry) = entries.as_array().and_then(|items| items.first()) {
            break (
                json_bytes(entry.get("key").ok_or("tuple key missing")?)?,
                json_bytes(entry.get("value").ok_or("tuple value missing")?)?,
                entries,
            );
        }
        if started.elapsed() > Duration::from_secs(1) {
            return Err("tuple was not published before fault injection".to_owned());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if key.len() != 16 || value.len() != 48 {
        return Err("unexpected tuple ABI width".to_owned());
    }
    let before = value.clone();
    let mut cookie_key = None;
    match fault {
        MapFault::Nonce => value[16] ^= 1,
        MapFault::Generation => value[32] ^= 1,
        MapFault::MissingCookie => cookie_key = Some(value[0..8].to_vec()),
    }
    if let Some(ref cookie) = cookie_key {
        let cookie_pin = map_pin(&state, "soglia_cookie_a")?;
        map_command(bpftool, "delete", &cookie_pin, &cookie, None)?;
    } else {
        map_command(bpftool, "update", &tuple_pin, &key, Some(&value))?;
    }
    fs::write(
        evidence.join("fault-injection.json"),
        serde_json::to_vec_pretty(&json!({
            "actor": "b2_driver running as the privileged qualification harness",
            "fault": fault,
            "single_mutation": true,
            "production_code_modified": false,
            "tuple_pin": tuple_pin,
            "tuple_before_dump": raw,
            "tuple_key_hex": hex(&key),
            "tuple_value_before_hex": hex(&before),
            "tuple_value_after_hex": hex(&value),
            "cookie_key_deleted_hex": cookie_key.as_ref().map(|bytes| hex(bytes))
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn map_pin(state: &Value, name: &str) -> Result<PathBuf, String> {
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
        .ok_or_else(|| format!("state does not name {name}"))
}

fn encode_binding_key(binding: BindingKey) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[0..8].copy_from_slice(&binding.cgroup_id.to_ne_bytes());
    key[8..24].copy_from_slice(&binding.execution_nonce.bytes());
    key[24..32].copy_from_slice(&binding.backend_generation.to_ne_bytes());
    key
}

fn dump_map(bpftool: &Path, pin: &Path) -> Result<Value, String> {
    let output = command_output(
        bpftool,
        &[
            "-j",
            "map",
            "dump",
            "pinned",
            pin.to_str().ok_or("non-UTF8 pin")?,
        ],
    )?;
    serde_json::from_slice(&output).map_err(|error| error.to_string())
}

fn map_dump_contains_key(dump: &Value, expected: &[u8]) -> Result<bool, String> {
    dump.as_array()
        .ok_or("BPF map dump is not an array")?
        .iter()
        .map(|entry| {
            entry
                .get("key")
                .ok_or_else(|| "BPF map entry omitted its key".to_owned())
                .and_then(json_bytes)
        })
        .try_fold(false, |found, key| key.map(|key| found || key == expected))
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

fn capture_receive_queue(peer: SocketAddr, local: SocketAddr) -> Result<(u64, String), String> {
    let started = Instant::now();
    loop {
        let output = command_output(Path::new("/usr/bin/ss"), &["-H", "-n", "-t"])?;
        let text = String::from_utf8_lossy(&output).into_owned();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5
                && fields[3] == local.to_string()
                && fields[4] == peer.to_string()
                && let Ok(queue) = u64::from_str(fields[1])
                && queue > 0
            {
                return Ok((queue, text));
            }
        }
        if started.elapsed() > Duration::from_secs(1) {
            return Ok((0, text));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn prepare_upstream() -> io::Result<()> {
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "delete", "b2-upstream"])
        .output();
    command_success(
        Path::new("/usr/sbin/ip"),
        &["link", "add", "b2-upstream", "type", "dummy"],
    )?;
    command_success(
        Path::new("/usr/sbin/ip"),
        &["addr", "add", "11.0.0.1/32", "dev", "b2-upstream"],
    )?;
    command_success(
        Path::new("/usr/sbin/ip"),
        &["link", "set", "b2-upstream", "up"],
    )
}

fn command_success(program: &Path, arguments: &[&str]) -> io::Result<()> {
    let output = Command::new(program).args(arguments).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }
}

fn command_output(program: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn run_to_file(program: &Path, arguments: &[&str], output: &Path) -> Result<(), String> {
    fs::write(output, command_output(program, arguments)?).map_err(|error| error.to_string())
}

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !path.is_file() {
        if started.elapsed() >= timeout {
            return Err(format!("{} did not appear", path.display()));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn wait_for_count(
    counter: &AtomicUsize,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    while counter.load(Ordering::SeqCst) < expected {
        if started.elapsed() >= timeout {
            return Err(format!("counter did not reach {expected}"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const B3_RACE_ITERATIONS: usize = 200;
const B3_CONNECTIONS_PER_EXECUTION: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum B3SingleMode {
    SuccessfulClose,
    Fin,
    Rst,
    ConnectFailure,
    AgentKill,
}

impl B3SingleMode {
    const fn name(self) -> &'static str {
        match self {
            Self::SuccessfulClose => "successful_close",
            Self::Fin => "fin",
            Self::Rst => "rst",
            Self::ConnectFailure => "connect_failure",
            Self::AgentKill => "agent_kill",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct B3ResolveObservation {
    index: usize,
    peer: SocketAddr,
    local: SocketAddr,
    recv_q_bytes: u64,
    cookie: Option<u64>,
    tuple_binding: Option<BindingKey>,
    outcome: ObservedResolveOutcome,
    mismatch: Option<ResolveMismatch>,
    resolved_execution: Option<ExecutionId>,
    elapsed_ms: u64,
    dns_when_resolve_returned: usize,
    outbound_when_resolve_returned: usize,
    health_failure: Option<ObservedHealthFailure>,
}

struct B3RecordingAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    observations: Arc<Mutex<Vec<B3ResolveObservation>>>,
    state: PathBuf,
    bpftool: PathBuf,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    health_failure: Arc<Mutex<Option<ObservedHealthFailure>>>,
    completion_barrier: Option<Arc<Barrier>>,
}

impl ConnectionAttributor for B3RecordingAttributor {
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
            let (recv_q_bytes, _) = capture_receive_queue(peer, local).unwrap_or_default();
            let tuple = capture_live_tuple(
                &self.bpftool,
                &self.state,
                peer,
                local,
                Duration::from_secs(1),
            )
            .ok();
            let started = Instant::now();
            let result = self.inner.resolve(peer, local).await;
            let dns_when_resolve_returned = self.dns.load(Ordering::SeqCst);
            let outbound_when_resolve_returned = self.outbound.load(Ordering::SeqCst);
            if let Some(barrier) = &self.completion_barrier {
                barrier.wait().await;
            }
            let (outcome, mismatch, resolved_execution) = observed_result(&result);
            let observation = B3ResolveObservation {
                index,
                peer,
                local,
                recv_q_bytes,
                cookie: tuple.as_ref().map(|tuple| tuple.0),
                tuple_binding: tuple.as_ref().map(|tuple| tuple.1),
                outcome,
                mismatch,
                resolved_execution,
                elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                dns_when_resolve_returned,
                outbound_when_resolve_returned,
                health_failure: self.health_failure.lock().ok().and_then(|failure| *failure),
            };
            if let Ok(mut observations) = self.observations.lock() {
                observations.push(observation);
            }
            result
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct B3Counters {
    tuple_insert_failed: u64,
    published: u64,
    unpublished: u64,
    live_tuples: usize,
    live_cookies: usize,
}

struct B3Prepared<'a> {
    execution: Execution<'a>,
    pid: i32,
    binding: BindingKey,
    cgroup_inode: u64,
}

struct B3Proxy {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum B3Boundary {
    Tuple,
    Cookie,
    Policy,
    DurableRecord,
    LiveBinding,
}

impl B3Boundary {
    const fn name(self) -> &'static str {
        match self {
            Self::Tuple => "tuple",
            Self::Cookie => "cookie",
            Self::Policy => "policy",
            Self::DurableRecord => "durable_record",
            Self::LiveBinding => "live_binding",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum B3Field {
    CgroupId,
    ExecutionNonce,
    BackendGeneration,
    OldComplete,
    Mixed,
}

impl B3Field {
    const fn name(self) -> &'static str {
        match self {
            Self::CgroupId => "cgroup_id",
            Self::ExecutionNonce => "execution_nonce",
            Self::BackendGeneration => "backend_generation",
            Self::OldComplete => "old_complete_binding",
            Self::Mixed => "mixed_binding",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct B3MatrixCell {
    boundary: B3Boundary,
    field: B3Field,
    covered_by_b2: bool,
}

struct B3FaultAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    config_state: PathBuf,
    bpftool: PathBuf,
    expected: BindingKey,
    cell: B3MatrixCell,
    evidence: PathBuf,
}

impl ConnectionAttributor for B3FaultAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move {
            let injection = inject_b3_boundary_fault(
                &self.bpftool,
                &self.config_state,
                peer,
                local,
                self.expected,
                self.cell,
            );
            let (restore, evidence) = match injection {
                Ok(injection) => injection,
                Err(error) => {
                    let _ = fs::write(self.evidence.join("injection-error.txt"), &error);
                    return AttributionResult::IntegrityFailure;
                }
            };
            let _ = fs::write(
                self.evidence.join("fault-injection.json"),
                serde_json::to_vec_pretty(&evidence).unwrap_or_default(),
            );
            let result = self.inner.resolve(peer, local).await;
            if let Some(restore) = restore
                && let Err(error) = restore_b3_boundary_fault(&self.bpftool, restore)
            {
                let _ = fs::write(self.evidence.join("restore-error.txt"), error);
                return AttributionResult::IntegrityFailure;
            }
            result
        })
    }
}

struct B3FaultRestore {
    pin: PathBuf,
    key: Vec<u8>,
    value: Vec<u8>,
}

enum B3RaceGate {
    Immediate,
    Release(Arc<Notify>),
    Concurrent(Arc<Barrier>),
}

struct B3RaceAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    gate: B3RaceGate,
    entered: Arc<Notify>,
    completed: Arc<Notify>,
    result: Arc<Mutex<Option<(ObservedResolveOutcome, Option<ResolveMismatch>)>>>,
}

impl ConnectionAttributor for B3RaceAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move {
            self.entered.notify_one();
            match &self.gate {
                B3RaceGate::Immediate => {}
                B3RaceGate::Release(release) => release.notified().await,
                B3RaceGate::Concurrent(barrier) => {
                    barrier.wait().await;
                }
            }
            let result = self.inner.resolve(peer, local).await;
            let (outcome, mismatch, _) = observed_result(&result);
            if let Ok(mut observed) = self.result.lock() {
                *observed = Some((outcome, mismatch));
            }
            self.completed.notify_one();
            result
        })
    }
}

impl B3Proxy {
    async fn stop(self) -> Result<(), String> {
        self.stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .map_err(|_| "B3 proxy did not stop".to_owned())?
            .map_err(|error| error.to_string())
    }
}

/// Runs B3 only. The small wrapper binary imports this shared qualification module so B2 keeps
/// using the same already-qualified ABI helpers without introducing a second implementation.
pub async fn run_b3() -> Result<(), String> {
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
        return run_b3_cleanup_recovery(&binary, &config_yaml, &evidence).await;
    }
    if let Some(mode) = mode {
        return Err(format!(
            "unknown B3 driver mode: {}",
            mode.to_string_lossy()
        ));
    }
    if config.runtime.max_concurrency < 2 {
        return Err("B3 requires a configured concurrent-Execution limit of at least two".into());
    }
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
            "sandbox_swept": sandbox_swept,
            "enforcer_swept": enforcer_swept,
            "production_binary": binary,
            "production_backend": "cgroup-bpf",
            "configured_max_concurrency": config.runtime.max_concurrency,
            "race_iterations": B3_RACE_ITERATIONS
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    prepare_b3_upstream().map_err(|error| error.to_string())?;
    let upstream = TcpListener::bind((Ipv4Addr::new(11, 0, 0, 1), 443))
        .await
        .map_err(|error| format!("bind B3 upstream: {error}"))?;
    let outbound = Arc::new(AtomicUsize::new(0));
    let upstream_task = {
        let outbound = Arc::clone(&outbound);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = upstream.accept().await {
                outbound.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut byte = [0_u8; 1];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await;
                });
            }
        })
    };

    run_b3_concurrent_limit(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    for mode in [
        B3SingleMode::SuccessfulClose,
        B3SingleMode::Fin,
        B3SingleMode::Rst,
        B3SingleMode::ConnectFailure,
        B3SingleMode::AgentKill,
    ] {
        run_b3_single_lifecycle(
            mode,
            &evidence,
            &config,
            &sandbox,
            &enforcer,
            Arc::clone(&outbound),
        )
        .await?;
    }
    run_b3_frozen_teardown(&evidence, &config, &sandbox, &enforcer).await?;
    run_b3_source_port_reuse(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_b3_execution_generation(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_b3_binding_matrix(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_b3_freeze_resolve_race(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_b3_connect_tunnel_revocation(
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    run_b3_backend_generation(
        &evidence,
        &config,
        &config_yaml,
        &binary,
        &sandbox,
        enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    upstream_task.abort();
    fs::write(evidence.join("current-case.txt"), "complete\n")
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

async fn run_b3_cleanup_recovery(
    binary: &Path,
    config_yaml: &str,
    evidence: &Path,
) -> Result<(), String> {
    fs::create_dir_all(evidence).map_err(|error| error.to_string())?;
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
    fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(&json!({
            "mode": "B3_CLEANUP_RECOVERY",
            "order": ["sandbox", "enforcer"],
            "sandbox_swept": sandbox_swept,
            "enforcer_swept": enforcer_swept,
            "ownership_source": "production durable records",
            "verdict": "PASS"
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    drop(enforcer);
    drop(sandbox);
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

#[derive(Clone, Debug, Serialize)]
struct B5Event {
    reason: u32,
    cgroup_id: u64,
    cookie: u64,
    raw_hex: String,
}

/// Runs B5 over the unchanged production Candidate-A backend and object. The wrapper binary imports
/// this module so the placement, proxy and cleanup helpers are exactly those already qualified by
/// B2/B3 rather than a second implementation of the lifecycle.
pub async fn run_b5() -> Result<(), String> {
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
        return run_b3_cleanup_recovery(&binary, &config_yaml, &evidence).await;
    }
    if let Some(mode) = mode {
        return Err(format!(
            "unknown B5 driver mode: {}",
            mode.to_string_lossy()
        ));
    }

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
            "sandbox_swept": sandbox_swept,
            "enforcer_swept": enforcer_swept,
            "production_binary": binary,
            "production_backend": "cgroup-bpf",
            "production_object_modified": false
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    b5_record_hook_inventory(&config, &evidence)?;
    b5_record_fd_boundary_source(&evidence)?;

    prepare_b3_upstream().map_err(|error| error.to_string())?;
    let upstream = TcpListener::bind((Ipv4Addr::new(11, 0, 0, 1), 443))
        .await
        .map_err(|error| format!("bind B5 upstream: {error}"))?;
    let outbound = Arc::new(AtomicUsize::new(0));
    let outbound_task = {
        let outbound = Arc::clone(&outbound);
        tokio::spawn(async move {
            while let Ok((_stream, _)) = upstream.accept().await {
                outbound.fetch_add(1, Ordering::SeqCst);
            }
        })
    };

    fs::write(evidence.join("current-case.txt"), "proxy_positive\n")
        .map_err(|error| error.to_string())?;
    run_b3_single_lifecycle(
        B3SingleMode::SuccessfulClose,
        &evidence,
        &config,
        &sandbox,
        &enforcer,
        Arc::clone(&outbound),
    )
    .await?;
    b5_alias_case(&evidence, "successful_close", "proxy_positive")?;
    b5_record_proxy_steering_boundary(&config, &evidence)?;

    run_b5_fd_boundary(&evidence, &config, &sandbox, &enforcer).await?;
    for (name, agent) in [
        ("ipv6_stream_sock_create", "b5-ipv6-stream"),
        ("ipv4_datagram_sock_create", "b5-ipv4-datagram"),
        ("ipv6_datagram_sock_create", "b5-ipv6-datagram"),
    ] {
        run_b5_sock_create_case(name, agent, &evidence, &config, &sandbox, &enforcer).await?;
    }
    run_b5_direct_early_deny(&evidence, &config, &sandbox, &enforcer).await?;
    run_b5_nft_relaxation(&evidence, &config, &sandbox, &enforcer).await?;
    enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| format!("pre-foreign B5 backend health: {error}"))?;
    drop(enforcer);
    b5_release_generation_for_topology(
        &config,
        &evidence.join("topology-transitions/base-to-foreign-allow"),
        "base-to-foreign-allow",
    )?;
    run_b5_foreign_allow(
        &evidence,
        &config,
        &config_yaml,
        &binary,
        &sandbox,
        Arc::clone(&outbound),
    )
    .await?;
    run_b5_foreign_rewrite(&evidence, &config, &config_yaml, &binary, &sandbox).await?;
    outbound_task.abort();
    fs::write(evidence.join("current-case.txt"), "complete\n")
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

fn b5_alias_case(root: &Path, existing: &str, alias: &str) -> Result<(), String> {
    let source = root.join("cases").join(existing).join("result.json");
    let destination = root.join("cases").join(alias);
    fs::create_dir_all(&destination).map_err(|error| error.to_string())?;
    fs::copy(source, destination.join("result.json")).map_err(|error| error.to_string())?;
    fs::write(destination.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

fn b5_record_hook_inventory(config: &Config, evidence: &Path) -> Result<(), String> {
    let executions = config
        .cgroup
        .root
        .as_ref()
        .ok_or("B5 configuration omitted cgroup root")?
        .join("executions");
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            executions.to_str().ok_or("non-UTF8 cgroup")?,
        ],
        &evidence.join("production-hooks-direct.json"),
    )?;
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            executions.to_str().ok_or("non-UTF8 cgroup")?,
            "effective",
        ],
        &evidence.join("production-hooks-effective.json"),
    )?;
    let hooks: Value = serde_json::from_slice(
        &fs::read(evidence.join("production-hooks-direct.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let state = b5_state(config)?;
    fs::write(
        evidence.join("production-state-inventory.json"),
        serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let expected = [
        ("soglia_sock_create", "cgroup_inet_sock_create"),
        ("soglia_connect4", "cgroup_inet4_connect"),
        ("soglia_connect6", "cgroup_inet6_connect"),
        ("soglia_sendmsg4", "cgroup_udp4_sendmsg"),
        ("soglia_sendmsg6", "cgroup_udp6_sendmsg"),
        ("soglia_sockops", "cgroup_sock_ops"),
    ];
    let rows = hooks
        .as_array()
        .ok_or("B5 direct hook inventory is not an array")?;
    let programs = state
        .get("programs")
        .and_then(Value::as_array)
        .ok_or("production state omitted programs")?;
    for (name, attach_type) in expected {
        let direct = rows.iter().find(|row| {
            row.get("name").and_then(Value::as_str) == Some(name)
                && row.get("attach_type").and_then(Value::as_str) == Some(attach_type)
        });
        let recorded = programs.iter().find(|program| {
            program.get("symbol").and_then(Value::as_str) == Some(name)
                && program
                    .get("tag")
                    .and_then(Value::as_u64)
                    .is_some_and(|tag| tag != 0)
        });
        if direct.is_none()
            || recorded.is_none()
            || direct.and_then(|row| row.get("id")).and_then(Value::as_u64)
                != recorded
                    .and_then(|program| program.get("id"))
                    .and_then(Value::as_u64)
        {
            return Err(format!(
                "production hook {name}/{attach_type} missing in B5"
            ));
        }
    }
    fs::write(
        evidence.join("hook-reachability.json"),
        serde_json::to_vec_pretty(&json!({
            "sock_create": "PERFORMED",
            "connect4": "PERFORMED",
            "sockops": "PERFORMED by proxy positive control",
            "connect6": "NOT_PERFORMED: unreachable by construction because sock_create admits only IPv4/TCP and the socket cgroup is fixed at creation",
            "sendmsg4": "NOT_PERFORMED: unreachable by construction because sock_create admits only IPv4/TCP and the socket cgroup is fixed at creation",
            "sendmsg6": "NOT_PERFORMED: unreachable by construction because sock_create admits only IPv4/TCP and the socket cgroup is fixed at creation"
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn b5_record_fd_boundary_source(evidence: &Path) -> Result<(), String> {
    let path = Path::new("/soglia/crates/soglia-sandbox/src/backend.rs");
    let source = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let required = [
        ".stdin(Stdio::null())",
        ".stdout(input.try_clone()?)",
        ".stderr(input)",
    ];
    let required_present = required.iter().all(|needle| source.contains(needle));
    let forbidden = ["--preserve-fds", "SCM_RIGHTS"];
    let forbidden_absent = forbidden.iter().all(|needle| !source.contains(needle));
    if !required_present || !forbidden_absent {
        return Err("production Sandbox FD-boundary source audit failed".to_owned());
    }
    fs::write(
        evidence.join("runtime-fd-boundary.json"),
        serde_json::to_vec_pretty(&json!({
            "source": path,
            "sha256": format!("{:x}", Sha256::digest(source.as_bytes())),
            "runc_stdio": {"stdin":"null","stdout":"bounded pipe","stderr":"bounded pipe"},
            "required_fragments": required,
            "forbidden_fd_passing_fragments": forbidden,
            "forbidden_absent": forbidden_absent,
            "production_runtime_passes_socket_fds": false
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn b5_record_proxy_steering_boundary(config: &Config, evidence: &Path) -> Result<(), String> {
    let source_path = Path::new("/soglia/crates/soglia-enforcer/bpf/candidate_a.c");
    let source = fs::read_to_string(source_path).map_err(|error| error.to_string())?;
    let expected_reads = [
        (
            "user_port",
            "__u32 dport = bpf_ntohs((__u16)ctx->user_port);",
        ),
        (
            "user_ip4",
            "else if (ctx->user_ip4 != proxy_ip4 || dport != proxy_port)",
        ),
    ];
    let fields = ["user_ip4", "user_ip6", "user_port"];
    let mut accesses = Vec::new();
    let mut unexpected_accesses = Vec::new();
    for (index, line) in source.lines().enumerate() {
        for field in fields {
            if !line.contains(&format!("ctx->{field}")) {
                continue;
            }
            let expected = expected_reads
                .iter()
                .any(|(expected_field, expected_line)| {
                    field == *expected_field && line.trim() == *expected_line
                });
            let access = json!({
                "field": field,
                "line": index + 1,
                "source": line.trim(),
                "classification": if expected { "READ" } else { "UNEXPECTED" }
            });
            accesses.push(access.clone());
            if !expected {
                unexpected_accesses.push(access);
            }
        }
    }
    let expected_reads_complete = expected_reads.iter().all(|(field, expected_line)| {
        accesses.iter().any(|access| {
            access.get("field").and_then(Value::as_str) == Some(*field)
                && access.get("source").and_then(Value::as_str) == Some(*expected_line)
                && access.get("classification").and_then(Value::as_str) == Some("READ")
        })
    });
    let bpf_bind_absent = !source.contains("bpf_bind");
    let no_destination_writes = unexpected_accesses.is_empty() && accesses.len() == 2;

    let positive_path = evidence.join("cases/proxy_positive/result.json");
    let positive: Value =
        serde_json::from_slice(&fs::read(&positive_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let agent_report = positive
        .get("agent_report")
        .and_then(Value::as_str)
        .ok_or("B5 proxy-positive evidence omitted the agent report")?;
    let agent: Value = agent_report
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| "B5 proxy-positive agent report was empty".to_owned())
        .and_then(|line| serde_json::from_str(line).map_err(|error| error.to_string()))?;
    let agent_requested = agent
        .get("proxy_destination")
        .and_then(Value::as_str)
        .ok_or("B5 proxy-positive agent report omitted proxy_destination")?;
    let proxy_observed = positive
        .get("observations")
        .and_then(Value::as_array)
        .and_then(|observations| observations.first())
        .and_then(|observation| observation.get("local"))
        .and_then(Value::as_str)
        .ok_or("B5 proxy-positive evidence omitted the proxy local address")?;
    let expected_destination = format!(
        "{}:{}",
        config.network.proxy_address, config.network.proxy_port
    );
    let runtime_match = agent_requested == expected_destination
        && proxy_observed == expected_destination
        && agent_requested == proxy_observed;
    let pass = expected_reads_complete && no_destination_writes && bpf_bind_absent && runtime_match;
    let result = json!({
        "schema": 1,
        "source": source_path,
        "sha256": format!("{:x}", Sha256::digest(source.as_bytes())),
        "audited_destination_fields": fields,
        "access_points": accesses,
        "unexpected_accesses": unexpected_accesses,
        "expected_reads_complete": expected_reads_complete,
        "no_writes_to_destination_fields": no_destination_writes,
        "bpf_bind_absent": bpf_bind_absent,
        "runtime": {
            "agent_requested_destination": agent_requested,
            "proxy_observed_destination": proxy_observed,
            "configured_destination": expected_destination,
            "destinations_match": runtime_match,
            "source_evidence": positive_path
        },
        "proxy_steering_layer": "outside BPF",
        "verdict": if pass { "PASS" } else { "FAIL" }
    });
    fs::write(
        evidence.join("proxy-steering-boundary.json"),
        serde_json::to_vec_pretty(&result).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if !pass {
        return Err(format!(
            "production proxy-steering boundary audit failed: {result}"
        ));
    }
    Ok(())
}

fn b5_state(config: &Config) -> Result<Value, String> {
    serde_json::from_slice(
        &fs::read(config.runtime.state_dir.join("cgroup-bpf/state.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn b5_release_generation_for_topology(
    config: &Config,
    evidence: &Path,
    transition: &str,
) -> Result<(), String> {
    fs::create_dir_all(evidence).map_err(|error| error.to_string())?;
    let state_path = config.runtime.state_dir.join("cgroup-bpf/state.json");
    let state = b5_state(config)?;
    if state.get("phase").and_then(Value::as_str) != Some("READY")
        || state
            .get("executions")
            .and_then(Value::as_object)
            .is_none_or(|executions| !executions.is_empty())
    {
        return Err(format!(
            "B5 topology transition {transition} requires READY with zero Execution records"
        ));
    }
    let pin_root = PathBuf::from(
        state
            .get("pin_root")
            .and_then(Value::as_str)
            .ok_or("B5 state omitted pin_root")?,
    );
    if !pin_root.starts_with(&config.cgroup_bpf.pin_root) || pin_root == config.cgroup_bpf.pin_root {
        return Err(format!(
            "B5 topology transition rejected pin root {}",
            pin_root.display()
        ));
    }
    let pins = state
        .get("links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            state
                .get("maps")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .map(|entry| {
            entry
                .get("pin")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .ok_or("B5 generation entry omitted its pin")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if pins.iter().any(|pin| !pin.starts_with(&pin_root)) {
        return Err("B5 generation manifest contained a pin outside its owned root".to_owned());
    }
    fs::write(
        evidence.join("owned-state-before.json"),
        serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        evidence.join("direct-before.json"),
        command_output(
            &config.runtime.bpftool,
            &[
                "-j",
                "cgroup",
                "show",
                config
                    .cgroup
                    .root
                    .as_ref()
                    .ok_or("B5 cgroup root missing")?
                    .join("executions")
                    .to_str()
                    .ok_or("non-UTF8 executions")?,
            ],
        )?,
    )
    .map_err(|error| error.to_string())?;
    for pin in &pins {
        match fs::remove_file(pin) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove owned pin {}: {error}", pin.display())),
        }
    }
    for directory in [pin_root.join("links"), pin_root.join("maps"), pin_root.clone()] {
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove owned generation directory {}: {error}",
                    directory.display()
                ));
            }
        }
    }
    fs::remove_file(&state_path).map_err(|error| {
        format!(
            "remove owned generation manifest {}: {error}",
            state_path.display()
        )
    })?;

    let executions = config
        .cgroup
        .root
        .as_ref()
        .ok_or("B5 cgroup root missing")?
        .join("executions");
    let started = Instant::now();
    let (direct, programs) = loop {
        let direct_output = command_output(
            &config.runtime.bpftool,
            &[
                "-j",
                "cgroup",
                "show",
                executions.to_str().ok_or("non-UTF8 executions")?,
            ],
        )?;
        let direct: Value = if direct_output.iter().all(u8::is_ascii_whitespace) {
            json!([])
        } else {
            serde_json::from_slice(&direct_output).map_err(|error| error.to_string())?
        };
        let programs: Value = serde_json::from_slice(&command_output(
            &config.runtime.bpftool,
            &["-j", "prog", "show"],
        )?)
        .map_err(|error| error.to_string())?;
        let direct_empty = direct.as_array().is_some_and(Vec::is_empty);
        let no_soglia = programs.as_array().is_some_and(|rows| {
            rows.iter().all(|row| {
                !row.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.starts_with("soglia_"))
            })
        });
        if direct_empty && no_soglia {
            break (direct, programs);
        }
        if started.elapsed() >= Duration::from_secs(2) {
            return Err(format!(
                "B5 topology transition {transition} left production BPF objects"
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if state_path.exists() || pin_root.exists() || pins.iter().any(|pin| pin.exists()) {
        return Err(format!(
            "B5 topology transition {transition} did not remove its exact owned generation"
        ));
    }
    fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(&json!({
            "transition":transition,
            "owner":"qualification harness",
            "precondition":"production Enforcer exited; READY generation; zero Execution records",
            "removed_manifest":state_path,
            "removed_pin_root":pin_root,
            "removed_pins":pins,
            "direct_after":direct,
            "programs_after":programs,
            "network_state_preserved":true,
            "verdict":"PASS"
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn b5_counter(config: &Config, index: u32) -> Result<u64, String> {
    let state = b5_state(config)?;
    counter_value(
        &dump_map(
            &config.runtime.bpftool,
            &map_pin(&state, "soglia_counters")?,
        )?,
        index,
    )
}

fn b5_drain_events(config: &Config) -> Result<Vec<B5Event>, String> {
    let state = b5_state(config)?;
    let pin = map_pin(&state, "soglia_events")?;
    let data = MapData::from_pin(&pin)
        .map_err(|error| format!("open production event ring {}: {error:#}", pin.display()))?;
    let map = Map::from_map_data(data)
        .map_err(|error| format!("classify production event map: {error:#}"))?;
    let mut ring = RingBuf::try_from(map)
        .map_err(|error| format!("classify production event ring: {error:#}"))?;
    let mut events = Vec::new();
    while let Some(raw) = ring.next() {
        if raw.len() != 56 {
            return Err(format!(
                "production event has width {}, expected 56",
                raw.len()
            ));
        }
        events.push(B5Event {
            reason: u32::from_ne_bytes(raw[0..4].try_into().map_err(|_| "event reason width")?),
            cgroup_id: u64::from_ne_bytes(raw[8..16].try_into().map_err(|_| "event cgroup width")?),
            cookie: u64::from_ne_bytes(raw[40..48].try_into().map_err(|_| "event cookie width")?),
            raw_hex: hex(&raw),
        });
    }
    Ok(events)
}

fn b5_agent_report(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/root/tmp/b5-report.json"))
}

async fn b5_read_agent_report(pid: i32) -> Result<Value, String> {
    let path = b5_agent_report(pid);
    wait_for_file(&path, Duration::from_secs(5)).await?;
    let line = fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(line.trim()).map_err(|error| error.to_string())
}

async fn b5_cleanup_execution(
    prepared: &mut B3Prepared<'_>,
    table: &AttributionTable,
) -> Result<(), String> {
    let failures = prepared.execution.cleanup(Some(table)).await;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("B5 execution cleanup failed: {failures:?}"))
    }
}

async fn run_b5_fd_boundary(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
) -> Result<(), String> {
    let evidence = root.join("cases/no_inherited_sockets");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "no_inherited_sockets\n")
        .map_err(|error| error.to_string())?;
    let table = Arc::new(AttributionTable::new());
    let mut prepared = prepare_b3_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "b5-fd-table",
        0,
    )
    .await?;
    b5_record_namespace(config, &evidence, &prepared)?;

    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 19055))
        .map_err(|error| format!("bind inherited-FD control listener: {error}"))?;
    let control = evidence.join("external-inherited-socket.json");
    let netns = prepared.execution.id.tag().netns_name();
    let agent = config
        .agents
        .get("probe")
        .ok_or("B5 probe agent missing")?
        .rootfs
        .join("agent");
    let child = Command::new("/bin/bash")
        .arg("-c")
        .arg("exec 0<>/dev/tcp/127.0.0.1/19055; exec \"$1\" netns exec \"$2\" \"$3\" \"$4\"")
        .arg("b5-inherited-control")
        .arg(&config.runtime.ip)
        .arg(&netns)
        .arg(&agent)
        .arg(format!(
            "b5-inherited-fd-report {}",
            control.display()
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn inherited-FD control: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let accepted = loop {
        match listener.accept() {
            Ok((stream, _)) => break Some(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if started.elapsed() >= Duration::from_secs(2) {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    drop(accepted);
    fs::write(evidence.join("external-control.stdout"), &output.stdout)
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("external-control.stderr"), &output.stderr)
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("inherited-FD control exited {}", output.status));
    }
    let inherited: Value = serde_json::from_slice(
        &fs::read(&control).map_err(|error| format!("read inherited-FD evidence: {error}"))?,
    )
    .map_err(|error| error.to_string())?;
    if inherited
        .get("external_to_current_netns")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("artificial inherited socket was not proven external to the netns".to_owned());
    }

    sandbox
        .call(SandboxRequest::Start {
            id: prepared.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = b5_read_agent_report(prepared.pid).await?;
    let detail = report
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if report.get("ok").and_then(Value::as_bool) != Some(true) || !detail.contains("sockets=[]") {
        return Err(format!(
            "production agent inherited a socket descriptor: {report}"
        ));
    }
    b5_cleanup_execution(&mut prepared, &table).await?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case":"NO_INHERITED_SOCKETS",
            "agent_start_fd_table":report,
            "artificial_external_control":inherited,
            "runtime_fd_path_audit":root.join("runtime-fd-boundary.json"),
            "production_passes_socket_fds":false
        }),
    )
}

fn b5_record_namespace(
    config: &Config,
    evidence: &Path,
    prepared: &B3Prepared<'_>,
) -> Result<(), String> {
    let netns = prepared.execution.id.tag().netns_name();
    let addresses = command_output(&config.runtime.ip, &["-j", "-n", &netns, "addr", "show"])?;
    let routes = command_output(&config.runtime.ip, &["-j", "-n", &netns, "route", "show"])?;
    let nft = command_output(
        &config.runtime.ip,
        &[
            "netns",
            "exec",
            &netns,
            "/usr/sbin/nft",
            "-j",
            "list",
            "ruleset",
        ],
    )?;
    let ipv6 = command_output(
        &config.runtime.ip,
        &[
            "netns",
            "exec",
            &netns,
            "/bin/cat",
            "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        ],
    )?;
    let address_json: Value =
        serde_json::from_slice(&addresses).map_err(|error| error.to_string())?;
    let names = address_json
        .as_array()
        .ok_or("netns address inventory is not an array")?
        .iter()
        .filter_map(|row| row.get("ifname").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let ipv6_disabled = String::from_utf8_lossy(&ipv6).trim() == "1";
    if names.iter().any(|name| *name != "lo" && *name != "eth0") || !ipv6_disabled {
        return Err("owned netns confinement inventory is unexpected".to_owned());
    }
    fs::write(
        evidence.join("namespace-confinement.json"),
        serde_json::to_vec_pretty(&json!({
            "netns":netns,
            "interfaces":serde_json::from_slice::<Value>(&addresses).map_err(|error| error.to_string())?,
            "routes":serde_json::from_slice::<Value>(&routes).map_err(|error| error.to_string())?,
            "nft":serde_json::from_slice::<Value>(&nft).map_err(|error| error.to_string())?,
            "ipv6_disabled":ipv6_disabled,
            "only_expected_interfaces":true
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

async fn run_b5_sock_create_case(
    name: &str,
    agent: &str,
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
) -> Result<(), String> {
    let evidence = root.join("cases").join(name);
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), format!("{name}\n"))
        .map_err(|error| error.to_string())?;
    let table = Arc::new(AttributionTable::new());
    let mut prepared =
        prepare_b3_execution(config, &evidence, sandbox, enforcer, &table, agent, 0).await?;
    let stale = b5_drain_events(config)?;
    if !stale.is_empty() {
        return Err(format!("{name} began with stale BPF events: {stale:?}"));
    }
    let before = b5_counter(config, C_SOCK_CREATE_DENY)?;
    sandbox
        .call(SandboxRequest::Start {
            id: prepared.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = b5_read_agent_report(prepared.pid).await?;
    let after = b5_counter(config, C_SOCK_CREATE_DENY)?;
    let events = b5_drain_events(config)?;
    if report.get("ok").and_then(Value::as_bool) != Some(false)
        || after != before + 1
        || events.len() != 1
        || events[0].reason != B5_REASON_FAMILY
    {
        return Err(format!(
            "{name} did not prove one sock_create denial: report={report} before={before} after={after} events={events:?}"
        ));
    }
    b5_cleanup_execution(&mut prepared, &table).await?;
    write_b3_case_result(
        &evidence,
        &json!({"case":name,"agent":report,"counter_before":before,"counter_after":after,
            "counter_delta":after-before,"events":events,"health":"UNCHANGED"}),
    )
}

fn b5_nft_ruleset(config: &Config, netns: &str) -> Result<Value, String> {
    serde_json::from_slice(&command_output(
        &config.runtime.ip,
        &[
            "netns",
            "exec",
            netns,
            "/usr/sbin/nft",
            "-j",
            "-a",
            "list",
            "ruleset",
        ],
    )?)
    .map_err(|error| error.to_string())
}

fn b5_host_nft_ruleset() -> Result<Value, String> {
    serde_json::from_slice(&command_output(
        Path::new("/usr/sbin/nft"),
        &["-j", "-a", "list", "ruleset"],
    )?)
    .map_err(|error| error.to_string())
}

fn b5_normalized_nft(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(b5_normalized_nft).collect()),
        Value::Object(values) => {
            let mut normalized = serde_json::Map::new();
            for (key, value) in values {
                if !matches!(key.as_str(), "handle" | "packets" | "bytes" | "metainfo") {
                    normalized.insert(key.clone(), b5_normalized_nft(value));
                }
            }
            Value::Object(normalized)
        }
        value => value.clone(),
    }
}

fn b5_nft_hash(value: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(&b5_normalized_nft(value)).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn b5_nft_rule_handle(value: &Value, comment: &str) -> Result<u64, String> {
    value
        .pointer("/nftables")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find_map(|row| {
                let rule = row.get("rule")?;
                (rule.get("comment").and_then(Value::as_str) == Some(comment))
                    .then(|| rule.get("handle").and_then(Value::as_u64))
                    .flatten()
            })
        })
        .ok_or_else(|| format!("nft rule {comment} has no handle"))
}

fn b5_nft_rule_packets(value: &Value, comment: &str) -> Result<u64, String> {
    let expressions = value
        .pointer("/nftables")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find_map(|row| {
                let rule = row.get("rule")?;
                (rule.get("comment").and_then(Value::as_str) == Some(comment))
                    .then(|| rule.get("expr").and_then(Value::as_array))
                    .flatten()
            })
        })
        .ok_or_else(|| format!("nft rule {comment} is absent"))?;
    expressions
        .iter()
        .find_map(|expression| {
            expression
                .pointer("/counter/packets")
                .and_then(Value::as_u64)
        })
        .ok_or_else(|| format!("nft rule {comment} has no packet counter"))
}

fn b5_add_exec_rule(
    config: &Config,
    netns: &str,
    comment: &str,
    verdict: Option<&str>,
) -> Result<u64, String> {
    let mut arguments = vec![
        "netns",
        "exec",
        netns,
        "/usr/sbin/nft",
        "insert",
        "rule",
        "inet",
        "soglia",
        "output",
        "ip",
        "daddr",
        "10.201.0.2",
        "tcp",
        "dport",
        "16001",
        "counter",
    ];
    if let Some(verdict) = verdict {
        arguments.push(verdict);
    }
    arguments.extend(["comment", comment]);
    command_success(&config.runtime.ip, &arguments).map_err(|error| error.to_string())?;
    b5_nft_rule_handle(&b5_nft_ruleset(config, netns)?, comment)
}

fn b5_delete_exec_rule(config: &Config, netns: &str, handle: u64) -> Result<(), String> {
    command_success(
        &config.runtime.ip,
        &[
            "netns",
            "exec",
            netns,
            "/usr/sbin/nft",
            "delete",
            "rule",
            "inet",
            "soglia",
            "output",
            "handle",
            &handle.to_string(),
        ],
    )
    .map_err(|error| error.to_string())
}

fn b5_start_tcpdump(interface: &str, output: &Path) -> Result<Child, String> {
    Command::new("/usr/bin/tcpdump")
        .args(["-U", "-n", "-i", interface, "-c", "1", "-w"])
        .arg(output)
        .arg("tcp[tcpflags] & tcp-syn != 0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start tcpdump: {error}"))
}

fn b5_stop_tcpdump(mut child: Child, capture: &Path, evidence: &Path) -> Result<usize, String> {
    let _ = child.kill();
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("tcpdump-stderr.txt"), output.stderr)
        .map_err(|error| error.to_string())?;
    let decoded = Command::new("/usr/bin/tcpdump")
        .args(["-n", "-r"])
        .arg(capture)
        .output()
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("tcpdump-decoded.txt"), &decoded.stdout)
        .map_err(|error| error.to_string())?;
    Ok(String::from_utf8_lossy(&decoded.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

async fn run_b5_direct_early_deny(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
) -> Result<(), String> {
    let evidence = root.join("cases/direct_ipv4_early_deny");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "direct_ipv4_early_deny\n")
        .map_err(|error| error.to_string())?;
    let table = Arc::new(AttributionTable::new());
    let mut prepared = prepare_b3_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "b5-direct-ipv4",
        0,
    )
    .await?;
    let netns = prepared.execution.id.tag().netns_name();
    let before_rules = b5_nft_ruleset(config, &netns)?;
    let before_hash = b5_nft_hash(&before_rules)?;
    let comment = "soglia-b5-observe-direct";
    let handle = b5_add_exec_rule(config, &netns, comment, None)?;
    let capture = evidence.join("veth-syn.pcap");
    let mut tcpdump = b5_start_tcpdump(&prepared.execution.id.tag().host_veth(), &capture)?;
    std::thread::sleep(Duration::from_millis(100));
    let stale = b5_drain_events(config)?;
    if !stale.is_empty() {
        let _ = tcpdump.kill();
        let _ = b5_delete_exec_rule(config, &netns, handle);
        return Err(format!("direct deny began with stale events: {stale:?}"));
    }
    let before = b5_counter(config, C_CONNECT4_DENY)?;
    sandbox
        .call(SandboxRequest::Start {
            id: prepared.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = b5_read_agent_report(prepared.pid).await?;
    let after = b5_counter(config, C_CONNECT4_DENY)?;
    let events = b5_drain_events(config)?;
    let during = b5_nft_ruleset(config, &netns)?;
    let nft_packets = b5_nft_rule_packets(&during, comment)?;
    let syn_packets = b5_stop_tcpdump(tcpdump, &capture, &evidence)?;
    b5_delete_exec_rule(config, &netns, handle)?;
    let after_rules = b5_nft_ruleset(config, &netns)?;
    let after_hash = b5_nft_hash(&after_rules)?;
    if report.get("ok").and_then(Value::as_bool) != Some(false)
        || after != before + 1
        || nft_packets != 0
        || syn_packets != 0
        || events.len() != 1
        || events[0].reason != B5_REASON_NOT_PROXY
        || before_hash != after_hash
    {
        return Err(format!(
            "direct IPv4 early-deny invariant failed: report={report} counter={before}->{after} nft={nft_packets} syn={syn_packets} events={events:?} hashes={before_hash}/{after_hash}"
        ));
    }
    b5_cleanup_execution(&mut prepared, &table).await?;
    write_b3_case_result(
        &evidence,
        &json!({"case":"DIRECT_IPV4_EARLY_DENY","agent":report,"connect4_deny_delta":after-before,
            "events":events,"execution_nft_drop_path_packets":nft_packets,"veth_syn_packets":syn_packets,
            "nft_semantics":"intact; temporary counter-only observation rule had no verdict",
            "ruleset_hash_before":before_hash,"ruleset_hash_after":after_hash,"restored":true}),
    )
}

async fn run_b5_nft_relaxation(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
) -> Result<(), String> {
    let evidence = root.join("cases/exact_nft_relaxation");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "exact_nft_relaxation\n")
        .map_err(|error| error.to_string())?;
    let table = Arc::new(AttributionTable::new());
    let mut prepared = prepare_b3_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "b5-direct-ipv4",
        1,
    )
    .await?;
    let netns = prepared.execution.id.tag().netns_name();
    let slot = ExecutionPool::new(config.network.execution_pool)
        .map_err(|error| error.to_string())?
        .slot(1)
        .ok_or("B5 exact-relaxation slot 1 is unavailable")?;
    let direct_target = Ipv4Addr::new(10, 201, 0, 2);
    if slot.host != direct_target {
        return Err(format!(
            "B5 fixed direct target {direct_target} does not match slot-1 host {}",
            slot.host
        ));
    }
    let before_rules = b5_nft_ruleset(config, &netns)?;
    let before_hash = b5_nft_hash(&before_rules)?;
    let before_host_rules = b5_host_nft_ruleset()?;
    let before_host_hash = b5_nft_hash(&before_host_rules)?;
    let exec_comment = "soglia-b5-exact-relaxation-exec";
    let host_comment = "soglia-b5-exact-relaxation-host";
    let exec_handle = b5_add_exec_rule(config, &netns, exec_comment, Some("accept"))?;
    let host_handle = b5_add_host_accept(
        &prepared.execution.id.tag().host_veth(),
        slot.execution,
        slot.host,
        16001,
        host_comment,
    )?;
    let during_rules = b5_nft_ruleset(config, &netns)?;
    let during_host_rules = b5_host_nft_ruleset()?;
    let listener = StdTcpListener::bind((direct_target, 16001))
        .map_err(|error| format!("bind direct-path control listener: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let control_report = evidence.join("outside-cgroup-control.json");
    let agent = config
        .agents
        .get("probe")
        .ok_or("B5 probe agent missing")?
        .rootfs
        .join("agent");
    let control = Command::new(&config.runtime.ip)
        .args(["netns", "exec", &netns])
        .arg(&agent)
        .arg(format!(
            "b5-probe-report direct_ipv4 {} 0",
            control_report.to_str().ok_or("non-UTF8 control report")?
        ))
        .output()
        .map_err(|error| format!("run outside-cgroup nft control: {error}"))?;
    fs::write(
        evidence.join("outside-cgroup-control.stdout"),
        &control.stdout,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        evidence.join("outside-cgroup-control.stderr"),
        &control.stderr,
    )
    .map_err(|error| error.to_string())?;
    let accepted_control = listener.accept().is_ok();
    let control_value: Value =
        serde_json::from_slice(&fs::read(&control_report).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if !control.status.success()
        || control_value.get("ok").and_then(Value::as_bool) != Some(true)
        || !accepted_control
    {
        let _ = b5_delete_exec_rule(config, &netns, exec_handle);
        let _ = b5_delete_host_rule(host_handle);
        return Err(
            "exact nft relaxation did not expose the direct path to the outside-cgroup control"
                .to_owned(),
        );
    }

    let stale = b5_drain_events(config)?;
    if !stale.is_empty() {
        let _ = b5_delete_exec_rule(config, &netns, exec_handle);
        let _ = b5_delete_host_rule(host_handle);
        return Err(format!(
            "nft relaxation began agent attempt with stale events: {stale:?}"
        ));
    }
    let before = b5_counter(config, C_CONNECT4_DENY)?;
    sandbox
        .call(SandboxRequest::Start {
            id: prepared.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = b5_read_agent_report(prepared.pid).await?;
    let after = b5_counter(config, C_CONNECT4_DENY)?;
    let events = b5_drain_events(config)?;
    let accepted_agent = listener.accept().is_ok();
    b5_delete_exec_rule(config, &netns, exec_handle)?;
    b5_delete_host_rule(host_handle)?;
    let after_rules = b5_nft_ruleset(config, &netns)?;
    let after_hash = b5_nft_hash(&after_rules)?;
    let after_host_rules = b5_host_nft_ruleset()?;
    let after_host_hash = b5_nft_hash(&after_host_rules)?;
    if report.get("ok").and_then(Value::as_bool) != Some(false)
        || after != before + 1
        || accepted_agent
        || events.len() != 1
        || events[0].reason != B5_REASON_NOT_PROXY
        || before_hash != after_hash
        || before_host_hash != after_host_hash
    {
        return Err(format!(
            "BPF did not remain the direct-path denial after exact nft relaxation: report={report} counter={before}->{after} accepted={accepted_agent} events={events:?} exec_hashes={before_hash}/{after_hash} host_hashes={before_host_hash}/{after_host_hash}"
        ));
    }
    b5_cleanup_execution(&mut prepared, &table).await?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case":"EXACT_NFT_RELAXATION",
            "exact_rules": {
                "execution_output":{"comment":exec_comment,"handle":exec_handle,"source":slot.execution,"destination":"10.201.0.2:16001","verdict":"accept"},
                "host_input":{"comment":host_comment,"handle":host_handle,"interface":prepared.execution.id.tag().host_veth(),"source":slot.execution,"destination":"10.201.0.2:16001","verdict":"accept"}
            },
            "execution_ruleset":{"before":before_rules,"during":during_rules,"after":after_rules,"hash_before":before_hash,"hash_after":after_hash},
            "host_ruleset":{"before":before_host_rules,"during":during_host_rules,"after":after_host_rules,"hash_before":before_host_hash,"hash_after":after_host_hash},
            "restored":true,
            "outside_cgroup_same_netns_control":{"result":control_value,"listener_accepted":accepted_control,"classification":"external qualification control; not a production Execution path"},
            "execution_agent":{"result":report,"listener_accepted":accepted_agent,"connect4_deny_delta":after-before,"events":events},
            "causal_attribution":"the exact nft exposure opened the path for a socket born outside the executions subtree; the production Execution remained denied by connect4"
        }),
    )
}

fn b5_foreign_load(
    object: &Path,
    root: &Path,
    program: &str,
    ancestor: &Path,
) -> Result<Value, String> {
    fs::create_dir(root).map_err(|error| format!("create foreign pin root: {error}"))?;
    command_success(
        Path::new("/usr/sbin/bpftool"),
        &[
            "prog",
            "loadall",
            object.to_str().ok_or("non-UTF8 foreign object")?,
            root.to_str().ok_or("non-UTF8 foreign root")?,
        ],
    )
    .map_err(|error| error.to_string())?;
    let pin = root.join(program);
    command_success(
        Path::new("/usr/sbin/bpftool"),
        &[
            "cgroup",
            "attach",
            ancestor.to_str().ok_or("non-UTF8 ancestor")?,
            "cgroup_inet4_connect",
            "pinned",
            pin.to_str().ok_or("non-UTF8 foreign pin")?,
            "multi",
        ],
    )
    .map_err(|error| error.to_string())?;
    let program_info: Value = serde_json::from_slice(&command_output(
        Path::new("/usr/sbin/bpftool"),
        &[
            "-j",
            "prog",
            "show",
            "pinned",
            pin.to_str().ok_or("non-UTF8 pin")?,
        ],
    )?)
    .map_err(|error| error.to_string())?;
    Ok(json!({"root":root,"pin":pin,"program":program_info}))
}

fn b5_foreign_detach(ancestor: &Path, root: &Path, program: &str) -> Result<(), String> {
    let pin = root.join(program);
    command_success(
        Path::new("/usr/sbin/bpftool"),
        &[
            "cgroup",
            "detach",
            ancestor.to_str().ok_or("non-UTF8 ancestor")?,
            "cgroup_inet4_connect",
            "pinned",
            pin.to_str().ok_or("non-UTF8 foreign pin")?,
        ],
    )
    .map_err(|error| error.to_string())?;
    for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
        fs::remove_file(entry.map_err(|error| error.to_string())?.path())
            .map_err(|error| error.to_string())?;
    }
    fs::remove_dir(root).map_err(|error| error.to_string())
}

fn b5_start_foreign_enforcer(
    binary: &Path,
    config_yaml: &str,
    evidence: &Path,
    program: &str,
) -> Result<Helper, String> {
    let enforcer = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
    let swept = enforcer
        .hello(config_yaml)
        .map_err(|error| format!("start production Enforcer with ancestor {program}: {error}"))?;
    enforcer
        .ensure_running()
        .map_err(|error| error.to_string())?;
    fs::write(
        evidence.join("startup-with-foreign.json"),
        serde_json::to_vec_pretty(&json!({
            "foreign_program":program,
            "foreign_present_before_startup":true,
            "enforcer_swept":swept,
            "production_backend":"cgroup-bpf"
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(enforcer)
}

async fn run_b5_foreign_allow(
    root: &Path,
    config: &Config,
    config_yaml: &str,
    binary: &Path,
    sandbox: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/foreign_ancestor_allow");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "foreign_ancestor_allow\n")
        .map_err(|error| error.to_string())?;
    let ancestor = config
        .cgroup
        .root
        .as_ref()
        .ok_or("missing B5 cgroup root")?;
    let foreign_root = PathBuf::from("/sys/fs/bpf/soglia-b5-foreign-allow");
    let before = b5_foreign_load(
        Path::new("/var/tmp/soglia-spike-2/bpf/foreign.o"),
        &foreign_root,
        "foreign_allow",
        ancestor,
    )?;
    let enforcer = match b5_start_foreign_enforcer(
        binary,
        config_yaml,
        &evidence,
        "foreign_allow",
    ) {
        Ok(enforcer) => enforcer,
        Err(error) => {
            let _ = b5_foreign_detach(ancestor, &foreign_root, "foreign_allow");
            return Err(error);
        }
    };
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            ancestor.to_str().ok_or("non-UTF8 ancestor")?,
        ],
        &evidence.join("ancestor-direct.json"),
    )?;
    let executions = ancestor.join("executions");
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            executions.to_str().ok_or("non-UTF8 executions")?,
            "effective",
        ],
        &evidence.join("executions-effective.json"),
    )?;
    let run =
        run_b3_single_lifecycle(B3SingleMode::Fin, root, config, sandbox, &enforcer, outbound).await;
    let pin = foreign_root.join("foreign_allow");
    let after: Result<Value, String> = serde_json::from_slice(&command_output(
        &config.runtime.bpftool,
        &[
            "-j",
            "prog",
            "show",
            "pinned",
            pin.to_str().ok_or("non-UTF8 pin")?,
        ],
    )?)
    .map_err(|error| error.to_string());
    let health = enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| format!("foreign-ALLOW backend health: {error}"));
    drop(enforcer);
    let release = b5_release_generation_for_topology(
        config,
        &evidence.join("generation-release"),
        "foreign-allow-to-foreign-rewrite",
    );
    let detach = b5_foreign_detach(ancestor, &foreign_root, "foreign_allow");
    run?;
    let after = after?;
    health?;
    release?;
    detach?;
    let before_program = before.get("program").cloned().unwrap_or(Value::Null);
    if before_program.get("id") != after.get("id") || before_program.get("tag") != after.get("tag")
    {
        return Err(
            "foreign ancestor ALLOW identity changed during production lifecycle".to_owned(),
        );
    }
    let fin_result: Value = serde_json::from_slice(
        &fs::read(root.join("cases/fin/result.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case":"FOREIGN_ANCESTOR_ALLOW",
            "foreign_before":before,"foreign_after":after,
            "ancestor_direct":serde_json::from_slice::<Value>(&fs::read(evidence.join("ancestor-direct.json")).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?,
            "child_effective":serde_json::from_slice::<Value>(&fs::read(evidence.join("executions-effective.json")).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?,
            "production_proxy_control":fin_result,
            "foreign_preserved":true,"ordering_claim":"NONE"
        }),
    )
}

fn b5_add_host_observer(comment: &str) -> Result<u64, String> {
    command_success(
        Path::new("/usr/sbin/nft"),
        &[
            "insert",
            "rule",
            "inet",
            "soglia_host",
            "input",
            "iifname",
            "sgh-*",
            "ip",
            "daddr",
            "10.201.0.2",
            "tcp",
            "dport",
            "16001",
            "counter",
            "comment",
            comment,
        ],
    )
    .map_err(|error| error.to_string())?;
    b5_nft_rule_handle(&b5_host_nft_ruleset()?, comment)
}

fn b5_delete_host_rule(handle: u64) -> Result<(), String> {
    command_success(
        Path::new("/usr/sbin/nft"),
        &[
            "delete",
            "rule",
            "inet",
            "soglia_host",
            "input",
            "handle",
            &handle.to_string(),
        ],
    )
    .map_err(|error| error.to_string())
}

fn b5_add_host_accept(
    interface: &str,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    port: u16,
    comment: &str,
) -> Result<u64, String> {
    command_success(
        Path::new("/usr/sbin/nft"),
        &[
            "insert",
            "rule",
            "inet",
            "soglia_host",
            "input",
            "iifname",
            interface,
            "ip",
            "saddr",
            &source.to_string(),
            "ip",
            "daddr",
            &destination.to_string(),
            "tcp",
            "dport",
            &port.to_string(),
            "ct",
            "state",
            "new",
            "counter",
            "accept",
            "comment",
            comment,
        ],
    )
    .map_err(|error| error.to_string())?;
    b5_nft_rule_handle(&b5_host_nft_ruleset()?, comment)
}

async fn run_b5_foreign_rewrite(
    root: &Path,
    config: &Config,
    config_yaml: &str,
    binary: &Path,
    sandbox: &Helper,
) -> Result<(), String> {
    let evidence = root.join("cases/foreign_ancestor_rewrite_nft_barrier");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(
        root.join("current-case.txt"),
        "foreign_ancestor_rewrite_nft_barrier\n",
    )
    .map_err(|error| error.to_string())?;
    let ancestor = config
        .cgroup
        .root
        .as_ref()
        .ok_or("missing B5 cgroup root")?;
    let foreign_root = PathBuf::from("/sys/fs/bpf/soglia-b5-foreign-rewrite");
    let before_foreign = b5_foreign_load(
        Path::new("/var/tmp/soglia-spike-2/bpf/foreign-s10.o"),
        &foreign_root,
        "foreign_rewrite",
        ancestor,
    )?;
    let enforcer = match b5_start_foreign_enforcer(
        binary,
        config_yaml,
        &evidence,
        "foreign_rewrite",
    ) {
        Ok(enforcer) => enforcer,
        Err(error) => {
            let _ = b5_foreign_detach(ancestor, &foreign_root, "foreign_rewrite");
            return Err(error);
        }
    };
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            ancestor.to_str().ok_or("non-UTF8 ancestor")?,
        ],
        &evidence.join("ancestor-direct.json"),
    )?;
    run_to_file(
        &config.runtime.bpftool,
        &[
            "-j",
            "cgroup",
            "show",
            ancestor
                .join("executions")
                .to_str()
                .ok_or("non-UTF8 executions")?,
            "effective",
        ],
        &evidence.join("executions-effective.json"),
    )?;
    let before_host_rules = b5_host_nft_ruleset()?;
    let before_host_hash = b5_nft_hash(&before_host_rules)?;
    let host_comment = "soglia-b5-observe-foreign-rewrite-host";
    let host_handle = b5_add_host_observer(host_comment)?;
    let table = Arc::new(AttributionTable::new());
    let mut prepared = prepare_b3_execution(
        config,
        &evidence,
        sandbox,
        &enforcer,
        &table,
        "b5-foreign-rewrite",
        1,
    )
    .await?;
    let netns = prepared.execution.id.tag().netns_name();
    let before_exec_rules = b5_nft_ruleset(config, &netns)?;
    let before_exec_hash = b5_nft_hash(&before_exec_rules)?;
    let exec_comment = "soglia-b5-observe-foreign-rewrite-exec";
    let exec_handle = b5_add_exec_rule(config, &netns, exec_comment, None)?;
    let listener = StdTcpListener::bind((Ipv4Addr::new(10, 201, 0, 2), 16001))
        .map_err(|error| format!("bind foreign-rewrite listener: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let stale = b5_drain_events(config)?;
    if !stale.is_empty() {
        return Err(format!(
            "foreign rewrite began with stale production events: {stale:?}"
        ));
    }
    let connect_before = b5_counter(config, C_CONNECT4_DENY)?;
    sandbox
        .call(SandboxRequest::Start {
            id: prepared.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = b5_read_agent_report(prepared.pid).await?;
    let connect_after = b5_counter(config, C_CONNECT4_DENY)?;
    let production_events = b5_drain_events(config)?;
    let during_exec_rules = b5_nft_ruleset(config, &netns)?;
    let execution_rewritten_packets =
        b5_nft_rule_packets(&during_exec_rules, exec_comment)?;
    let during_host_rules = b5_host_nft_ruleset()?;
    let host_rewritten_packets = b5_nft_rule_packets(&during_host_rules, host_comment)?;
    let listener_accepted = listener.accept().is_ok();
    let pin = foreign_root.join("foreign_rewrite");
    let after_foreign: Value = serde_json::from_slice(&command_output(
        &config.runtime.bpftool,
        &[
            "-j",
            "prog",
            "show",
            "pinned",
            pin.to_str().ok_or("non-UTF8 pin")?,
        ],
    )?)
    .map_err(|error| error.to_string())?;
    b5_delete_exec_rule(config, &netns, exec_handle)?;
    let after_exec_rules = b5_nft_ruleset(config, &netns)?;
    let after_exec_hash = b5_nft_hash(&after_exec_rules)?;
    b5_delete_host_rule(host_handle)?;
    b5_cleanup_execution(&mut prepared, &table).await?;
    let after_host_rules = b5_host_nft_ruleset()?;
    let after_host_hash = b5_nft_hash(&after_host_rules)?;
    enforcer
        .call(EnforcerRequest::Health)
        .await
        .map_err(|error| format!("foreign-rewrite backend health: {error}"))?;
    drop(enforcer);
    b5_release_generation_for_topology(
        config,
        &evidence.join("generation-release"),
        "foreign-rewrite-to-final-cleanup",
    )?;
    b5_foreign_detach(ancestor, &foreign_root, "foreign_rewrite")?;
    let before_program = before_foreign
        .get("program")
        .cloned()
        .unwrap_or(Value::Null);
    if report.get("ok").and_then(Value::as_bool) != Some(false)
        || execution_rewritten_packets == 0
        || host_rewritten_packets != 0
        || listener_accepted
        || connect_after != connect_before
        || !production_events.is_empty()
        || before_exec_hash != after_exec_hash
        || before_host_hash != after_host_hash
        || before_program.get("id") != after_foreign.get("id")
        || before_program.get("tag") != after_foreign.get("tag")
    {
        return Err(format!(
            "foreign rewrite/final nft barrier was not causal: report={report} execution_packets={execution_rewritten_packets} host_packets={host_rewritten_packets} accepted={listener_accepted} connect4={connect_before}->{connect_after} events={production_events:?} exec_hashes={before_exec_hash}/{after_exec_hash} host_hashes={before_host_hash}/{after_host_hash}"
        ));
    }
    write_b3_case_result(
        &evidence,
        &json!({
            "case":"FOREIGN_ANCESTOR_REWRITE_NFT_BARRIER",
            "agent":report,"foreign_before":before_foreign,"foreign_after":after_foreign,
            "ancestor_direct":serde_json::from_slice::<Value>(&fs::read(evidence.join("ancestor-direct.json")).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?,
            "child_effective":serde_json::from_slice::<Value>(&fs::read(evidence.join("executions-effective.json")).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?,
            "rewritten_destination":"10.201.0.2:16001",
            "execution_nft":{"comment":exec_comment,"packets":execution_rewritten_packets,"ruleset_before":before_exec_rules,"ruleset_during":during_exec_rules,"ruleset_after":after_exec_rules,"hash_before":before_exec_hash,"hash_after":after_exec_hash},
            "host_nft":{"comment":host_comment,"packets":host_rewritten_packets,"ruleset_before":before_host_rules,"ruleset_during":during_host_rules,"ruleset_after":after_host_rules,"hash_before":before_host_hash,"hash_after":after_host_hash},
            "listener_accepted":listener_accepted,"production_connect4_deny_delta":connect_after-connect_before,
            "production_events":production_events,
            "nft_restored":true,"final_barrier":"Execution namespace nft output policy drop","ordering_observed":"production child admitted original proxy destination before ancestor rewrite",
            "ordering_claim":"NONE beyond this recorded topology/run"
        }),
    )
}

async fn prepare_b3_execution<'a>(
    config: &Config,
    evidence: &Path,
    sandbox: &'a Helper,
    enforcer: &'a Helper,
    table: &Arc<AttributionTable>,
    agent: &str,
    slot: u32,
) -> Result<B3Prepared<'a>, String> {
    let id = ExecutionId::generate().map_err(|error| error.to_string())?;
    let nonce = ExecutionNonce::generate().map_err(|error| error.to_string())?;
    let mut execution = Execution {
        sandbox,
        enforcer,
        id,
        binding: None,
        key_bound: false,
        legacy_ip: None,
        reserved: false,
        prepared: false,
        moved_pid: None,
    };
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
    execution.reserved = true;
    enforcer
        .call(EnforcerRequest::Prepare {
            id,
            slot,
            agent: agent.to_owned(),
            nonce,
        })
        .await
        .map_err(|error| error.to_string())?;
    execution.prepared = true;
    let paused = sandbox
        .call(SandboxRequest::CreatePaused { id })
        .await
        .map_err(|error| error.to_string())?;
    let HelperResponse::CreatedPaused {
        pid,
        cgroup_inode: paused_inode,
    } = paused
    else {
        return Err(format!("unexpected create-paused response: {paused:?}"));
    };
    if paused_inode != cgroup_inode {
        return Err("reserved and paused cgroup identities differ".to_owned());
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
        return Err("verified BindingKey does not match reserved identity".to_owned());
    }
    table
        .bind_key(binding, id)
        .map_err(|error| error.to_string())?;
    execution.binding = Some(binding);
    execution.key_bound = true;
    enforcer
        .call(EnforcerRequest::Activate {
            id,
            binding: Some(binding),
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(B3Prepared {
        execution,
        pid,
        binding,
        cgroup_inode,
    })
}

fn b3_attributor(
    config: &Config,
    enforcer: &Helper,
    table: Arc<AttributionTable>,
    observations: Arc<Mutex<Vec<B3ResolveObservation>>>,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    health_failure: Arc<Mutex<Option<ObservedHealthFailure>>>,
    completion_barrier: Option<Arc<Barrier>>,
) -> Result<Arc<dyn ConnectionAttributor>, String> {
    let inner = b3_candidate_attributor(config, enforcer, table, Arc::clone(&health_failure))?;
    Ok(Arc::new(B3RecordingAttributor {
        inner,
        observations,
        state: config.runtime.state_dir.join("cgroup-bpf/state.json"),
        bpftool: config.runtime.bpftool.clone(),
        dns,
        outbound,
        health_failure,
        completion_barrier,
    }))
}

fn b3_candidate_attributor(
    config: &Config,
    enforcer: &Helper,
    table: Arc<AttributionTable>,
    health_failure: Arc<Mutex<Option<ObservedHealthFailure>>>,
) -> Result<Arc<dyn ConnectionAttributor>, String> {
    let observed_failure = Arc::clone(&health_failure);
    Ok(Arc::new(CandidateAAttributor::new(
        enforcer
            .resolver_client()
            .map_err(|error| error.to_string())?,
        table,
        Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
        config.runtime.max_concurrency as usize * B3_CONNECTIONS_PER_EXECUTION,
        Arc::new(move |failure| {
            if let Ok(mut observed) = observed_failure.lock() {
                *observed = Some(match failure {
                    ResolveHealthFailure::Unavailable => ObservedHealthFailure::Unavailable,
                    ResolveHealthFailure::IntegrityFailure => {
                        ObservedHealthFailure::IntegrityFailure
                    }
                });
            }
        }),
    )))
}

fn b3_recording_wrapper(
    config: &Config,
    inner: Arc<dyn ConnectionAttributor>,
    observations: Arc<Mutex<Vec<B3ResolveObservation>>>,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    health_failure: Arc<Mutex<Option<ObservedHealthFailure>>>,
) -> Arc<dyn ConnectionAttributor> {
    Arc::new(B3RecordingAttributor {
        inner,
        observations,
        state: config.runtime.state_dir.join("cgroup-bpf/state.json"),
        bpftool: config.runtime.bpftool.clone(),
        dns,
        outbound,
        health_failure,
        completion_barrier: None,
    })
}

async fn start_b3_proxy(
    config: &Config,
    attributor: Arc<dyn ConnectionAttributor>,
    dns: Arc<AtomicUsize>,
) -> Result<B3Proxy, String> {
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
    .map_err(|error| format!("bind B3 proxy: {error}"))?;
    let (stop, stopped) = watch::channel(false);
    Ok(B3Proxy {
        stop,
        task: tokio::spawn(proxy.serve(listener, stopped)),
    })
}

fn capture_live_tuple(
    bpftool: &Path,
    state_path: &Path,
    peer: SocketAddr,
    local: SocketAddr,
    timeout: Duration,
) -> Result<(u64, BindingKey, Vec<u8>, Vec<u8>), String> {
    let state: Value =
        serde_json::from_slice(&fs::read(state_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let pin = map_pin(&state, "soglia_tuples")?;
    let key = encode_socket_tuple(peer, local)?;
    let started = Instant::now();
    loop {
        let dump = dump_map(bpftool, &pin)?;
        if let Some(value) = map_dump_value_for_key(&dump, &key)? {
            if value.len() != 48 {
                return Err(format!(
                    "tuple value has {} bytes, expected 48",
                    value.len()
                ));
            }
            let cookie = u64::from_ne_bytes(
                value[0..8]
                    .try_into()
                    .map_err(|_| "tuple cookie has the wrong width")?,
            );
            let binding = decode_b3_binding(&value[8..40])?;
            return Ok((cookie, binding, key.to_vec(), value));
        }
        if started.elapsed() >= timeout {
            return Err("tuple did not become visible before B3 Resolve".to_owned());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn decode_b3_binding(bytes: &[u8]) -> Result<BindingKey, String> {
    if bytes.len() != 32 {
        return Err(format!("BindingKey has {} bytes, expected 32", bytes.len()));
    }
    Ok(BindingKey {
        cgroup_id: u64::from_ne_bytes(bytes[0..8].try_into().map_err(|_| "cgroup id width")?),
        execution_nonce: ExecutionNonce::from_bytes(
            bytes[8..24].try_into().map_err(|_| "nonce width")?,
        ),
        backend_generation: u64::from_ne_bytes(
            bytes[24..32].try_into().map_err(|_| "generation width")?,
        ),
    })
}

fn mutate_b3_binding(binding: BindingKey, field: B3Field) -> BindingKey {
    let mut nonce = binding.execution_nonce.bytes();
    match field {
        B3Field::CgroupId => BindingKey {
            cgroup_id: binding.cgroup_id.wrapping_add(1),
            ..binding
        },
        B3Field::ExecutionNonce => {
            nonce[0] ^= 0x80;
            BindingKey {
                execution_nonce: ExecutionNonce::from_bytes(nonce),
                ..binding
            }
        }
        B3Field::BackendGeneration => BindingKey {
            backend_generation: binding.backend_generation.wrapping_add(1),
            ..binding
        },
        B3Field::OldComplete => {
            nonce[0] ^= 0x80;
            BindingKey {
                cgroup_id: binding.cgroup_id.wrapping_add(1),
                execution_nonce: ExecutionNonce::from_bytes(nonce),
                backend_generation: binding.backend_generation.wrapping_add(1),
            }
        }
        B3Field::Mixed => {
            nonce[0] ^= 0x80;
            BindingKey {
                cgroup_id: binding.cgroup_id.wrapping_add(1),
                execution_nonce: ExecutionNonce::from_bytes(nonce),
                backend_generation: binding.backend_generation,
            }
        }
    }
}

fn encode_b3_policy(binding: BindingKey) -> [u8; 40] {
    let mut value = [0_u8; 40];
    value[0..4].copy_from_slice(&1_u32.to_ne_bytes());
    value[8..40].copy_from_slice(&encode_binding_key(binding));
    value
}

fn inject_b3_boundary_fault(
    bpftool: &Path,
    state_path: &Path,
    peer: SocketAddr,
    local: SocketAddr,
    expected: BindingKey,
    cell: B3MatrixCell,
) -> Result<(Option<B3FaultRestore>, Value), String> {
    let state: Value =
        serde_json::from_slice(&fs::read(state_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let (cookie, observed, tuple_key, tuple_value) =
        capture_live_tuple(bpftool, state_path, peer, local, Duration::from_secs(1))?;
    if observed != expected {
        return Err("tuple did not initially carry the exact current BindingKey".to_owned());
    }
    let injected = mutate_b3_binding(expected, cell.field);
    let (pin, key, before, after, restore) = match cell.boundary {
        B3Boundary::Tuple => {
            let pin = map_pin(&state, "soglia_tuples")?;
            let mut after = tuple_value.clone();
            after[8..40].copy_from_slice(&encode_binding_key(injected));
            map_command(bpftool, "update", &pin, &tuple_key, Some(&after))?;
            (pin, tuple_key, tuple_value, after, None)
        }
        B3Boundary::Cookie => {
            let pin = map_pin(&state, "soglia_cookie_a")?;
            let key = cookie.to_ne_bytes().to_vec();
            let before = encode_binding_key(expected).to_vec();
            let after = encode_binding_key(injected).to_vec();
            map_command(bpftool, "update", &pin, &key, Some(&after))?;
            let restore = Some(B3FaultRestore {
                pin: pin.clone(),
                key: key.clone(),
                value: before.clone(),
            });
            (pin, key, before, after, restore)
        }
        B3Boundary::Policy => {
            let pin = map_pin(&state, "soglia_policy")?;
            let key = expected.cgroup_id.to_ne_bytes().to_vec();
            let before = encode_b3_policy(expected).to_vec();
            let after = encode_b3_policy(injected).to_vec();
            map_command(bpftool, "update", &pin, &key, Some(&after))?;
            let restore = Some(B3FaultRestore {
                pin: pin.clone(),
                key: key.clone(),
                value: before.clone(),
            });
            (pin, key, before, after, restore)
        }
        B3Boundary::DurableRecord | B3Boundary::LiveBinding => {
            return Err(format!(
                "{} is not a BPF map boundary",
                cell.boundary.name()
            ));
        }
    };
    Ok((
        restore,
        json!({
            "actor": "B3 qualification harness",
            "boundary": cell.boundary,
            "field": cell.field,
            "covered_by_b2": cell.covered_by_b2,
            "single_boundary_mutation": true,
            "production_code_modified": false,
            "pin": pin,
            "key_hex": hex(&key),
            "value_before_hex": hex(&before),
            "value_after_hex": hex(&after),
            "binding_before": expected,
            "binding_after": injected,
            "socket_cookie": cookie
        }),
    ))
}

fn restore_b3_boundary_fault(bpftool: &Path, restore: B3FaultRestore) -> Result<(), String> {
    map_command(
        bpftool,
        "update",
        &restore.pin,
        &restore.key,
        Some(&restore.value),
    )
}

fn b3_expected_mismatch(cell: B3MatrixCell) -> (ObservedResolveOutcome, Option<ResolveMismatch>) {
    match cell.boundary {
        B3Boundary::Tuple => {
            let reason = match cell.field {
                B3Field::CgroupId => ResolveMismatch::CgroupId,
                B3Field::ExecutionNonce => ResolveMismatch::ExecutionNonce,
                B3Field::BackendGeneration | B3Field::OldComplete => {
                    ResolveMismatch::BackendGeneration
                }
                B3Field::Mixed => ResolveMismatch::OwnershipRecord,
            };
            (ObservedResolveOutcome::IdentityMismatch, Some(reason))
        }
        B3Boundary::Cookie => (
            ObservedResolveOutcome::IdentityMismatch,
            Some(ResolveMismatch::Cookie),
        ),
        B3Boundary::Policy => (
            ObservedResolveOutcome::IdentityMismatch,
            Some(ResolveMismatch::Policy),
        ),
        B3Boundary::LiveBinding => (ObservedResolveOutcome::NotFound, None),
        B3Boundary::DurableRecord => (ObservedResolveOutcome::IntegrityFailure, None),
    }
}

fn b3_counters(config: &Config) -> Result<B3Counters, String> {
    let state: Value = serde_json::from_slice(
        &fs::read(config.runtime.state_dir.join("cgroup-bpf/state.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let counters = dump_map(
        &config.runtime.bpftool,
        &map_pin(&state, "soglia_counters")?,
    )?;
    let tuples = dump_map(&config.runtime.bpftool, &map_pin(&state, "soglia_tuples")?)?;
    let cookies = dump_map(
        &config.runtime.bpftool,
        &map_pin(&state, "soglia_cookie_a")?,
    )?;
    Ok(B3Counters {
        tuple_insert_failed: counter_value(&counters, C_TUPLE_INSERT_FAILED)?,
        published: counter_value(&counters, C_PUBLISHED)?,
        unpublished: counter_value(&counters, C_UNPUBLISHED)?,
        live_tuples: tuples.as_array().ok_or("tuple dump is not an array")?.len(),
        live_cookies: cookies
            .as_array()
            .ok_or("cookie dump is not an array")?
            .len(),
    })
}

fn write_b3_accounting(
    evidence: &Path,
    before: B3Counters,
    after: B3Counters,
    consumed: u64,
) -> Result<(), String> {
    let published = after.published.saturating_sub(before.published);
    let unpublished = after.unpublished.saturating_sub(before.unpublished);
    let live = after.live_tuples as u64;
    let holds = published == unpublished + consumed + live
        && after.live_tuples == 0
        && after.live_cookies == 0
        && after.tuple_insert_failed == 0;
    fs::write(
        evidence.join("counter-accounting.json"),
        serde_json::to_vec_pretty(&json!({
            "before": before,
            "after": after,
            "delta": {
                "published": published,
                "unpublished_by_sockops_close": unpublished,
                "consumed_by_resolve": consumed,
                "live": live
            },
            "equation": "published = unpublished + consumed + live",
            "holds": holds,
            "C_TUPLE_INSERT_FAILED_absolute": after.tuple_insert_failed
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if holds {
        Ok(())
    } else {
        Err(format!(
            "counter accounting failed: published={published}, unpublished={unpublished}, consumed={consumed}, live={live}, cookies={}, insert_failed={}",
            after.live_cookies, after.tuple_insert_failed
        ))
    }
}

async fn wait_b3_observations(
    observations: &Mutex<Vec<B3ResolveObservation>>,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if observations
            .lock()
            .map_err(|_| "B3 observation lock poisoned".to_owned())?
            .len()
            >= expected
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("observed fewer than {expected} B3 Resolve calls"));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn read_b3_report(pid: i32, name: &str, timeout: Duration) -> Result<String, String> {
    let path = PathBuf::from(format!("/proc/{pid}/root/tmp/{name}"));
    wait_for_file(&path, timeout).await?;
    fs::read_to_string(path).map_err(|error| error.to_string())
}

async fn wait_b3_report_lines(
    pid: i32,
    name: &str,
    minimum: usize,
    timeout: Duration,
) -> Result<String, String> {
    let path = PathBuf::from(format!("/proc/{pid}/root/tmp/{name}"));
    let started = Instant::now();
    loop {
        if let Ok(report) = fs::read_to_string(&path)
            && report.lines().count() >= minimum
        {
            return Ok(report);
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "{} did not contain {minimum} lines",
                path.display()
            ));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn write_b3_case_result(evidence: &Path, value: &Value) -> Result<(), String> {
    fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

fn prepare_b3_upstream() -> io::Result<()> {
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "delete", "b3-upstream"])
        .output();
    command_success(
        Path::new("/usr/sbin/ip"),
        &["link", "add", "b3-upstream", "type", "dummy"],
    )?;
    command_success(
        Path::new("/usr/sbin/ip"),
        &["addr", "add", "11.0.0.1/32", "dev", "b3-upstream"],
    )?;
    command_success(
        Path::new("/usr/sbin/ip"),
        &["link", "set", "b3-upstream", "up"],
    )
}

async fn wait_b3_empty(config: &Config, timeout: Duration) -> Result<B3Counters, String> {
    let started = Instant::now();
    loop {
        let counters = b3_counters(config)?;
        if counters.live_tuples == 0 && counters.live_cookies == 0 {
            return Ok(counters);
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "Candidate-A maps did not empty: tuples={}, cookies={}",
                counters.live_tuples, counters.live_cookies
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn run_b3_concurrent_limit(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/concurrent_limit");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "concurrent_limit\n")
        .map_err(|error| error.to_string())?;
    let before = b3_counters(config)?;
    let table = Arc::new(AttributionTable::new());
    let observations = Arc::new(Mutex::new(Vec::new()));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health = Arc::new(Mutex::new(None));
    let total = config.runtime.max_concurrency as usize * B3_CONNECTIONS_PER_EXECUTION;
    let attributor = b3_attributor(
        config,
        enforcer,
        Arc::clone(&table),
        Arc::clone(&observations),
        Arc::clone(&dns),
        Arc::clone(&outbound),
        Arc::clone(&health),
        Some(Arc::new(Barrier::new(total))),
    )?;
    let proxy = start_b3_proxy(config, attributor, Arc::clone(&dns)).await?;
    let mut executions = Vec::new();
    for slot in 0..config.runtime.max_concurrency {
        let case = evidence.join(format!("execution-{slot}"));
        fs::create_dir_all(&case).map_err(|error| error.to_string())?;
        executions.push(
            prepare_b3_execution(
                config,
                &case,
                sandbox,
                enforcer,
                &table,
                &format!("concurrent-{slot}"),
                slot,
            )
            .await?,
        );
    }
    for execution in &executions {
        sandbox
            .call(SandboxRequest::Start {
                id: execution.execution.id,
            })
            .await
            .map_err(|error| error.to_string())?;
    }
    wait_b3_observations(&observations, total, Duration::from_secs(10)).await?;
    let mut reports = Vec::new();
    for execution in &executions {
        reports
            .push(read_b3_report(execution.pid, "b3-report.jsonl", Duration::from_secs(10)).await?);
    }
    proxy.stop().await?;
    let snapshot = observations
        .lock()
        .map_err(|_| "B3 observation lock poisoned".to_owned())?;
    let pool = config.pool().map_err(|error| error.to_string())?;
    let expected: Vec<(IpAddr, ExecutionId)> = executions
        .iter()
        .enumerate()
        .map(|(slot, execution)| {
            let address = pool
                .slot(slot as u32)
                .ok_or_else(|| format!("slot {slot} is unavailable"))?
                .execution;
            Ok((IpAddr::V4(address), execution.execution.id))
        })
        .collect::<Result<_, String>>()?;
    let mut cookies = Vec::new();
    for observation in snapshot.iter() {
        let expected_id = expected
            .iter()
            .find_map(|(address, id)| (*address == observation.peer.ip()).then_some(*id))
            .ok_or_else(|| format!("unexpected peer {}", observation.peer))?;
        if observation.outcome != ObservedResolveOutcome::Resolved
            || observation.resolved_execution != Some(expected_id)
            || observation.recv_q_bytes == 0
            || observation.dns_when_resolve_returned != 0
            || observation.outbound_when_resolve_returned != 0
            || observation.health_failure.is_some()
        {
            return Err(format!(
                "concurrent observation {} violated attribution/no-read/no-effect invariants",
                observation.index
            ));
        }
        let cookie = observation
            .cookie
            .ok_or("concurrent tuple omitted its cookie")?;
        if observation.tuple_binding
            != executions
                .iter()
                .find(|execution| execution.execution.id == expected_id)
                .map(|execution| execution.binding)
        {
            return Err("concurrent tuple carried the wrong BindingKey".to_owned());
        }
        cookies.push(cookie);
    }
    cookies.sort_unstable();
    cookies.dedup();
    if cookies.len() != total {
        return Err(format!(
            "observed {} unique cookies for {total} sockets",
            cookies.len()
        ));
    }
    drop(snapshot);
    let mut cleanup_failures = Vec::new();
    for execution in &mut executions {
        cleanup_failures.extend(execution.execution.cleanup(Some(&table)).await);
    }
    if !cleanup_failures.is_empty() {
        return Err(format!("concurrent cleanup failed: {cleanup_failures:?}"));
    }
    let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
    write_b3_accounting(&evidence, before, after, total as u64)?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case": "CONCURRENT_LIMIT",
            "configured_execution_limit": config.runtime.max_concurrency,
            "connections_per_execution": B3_CONNECTIONS_PER_EXECUTION,
            "total_connections": total,
            "unique_cookies": cookies,
            "observations": observations.lock().ok().as_deref(),
            "agent_reports": reports,
            "cross_attribution": false,
            "health_failure": health.lock().ok().and_then(|failure| *failure)
        }),
    )
}

async fn run_b3_single_lifecycle(
    mode: B3SingleMode,
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases").join(mode.name());
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), format!("{}\n", mode.name()))
        .map_err(|error| error.to_string())?;
    let before = b3_counters(config)?;
    let table = Arc::new(AttributionTable::new());
    let agent = match mode {
        B3SingleMode::SuccessfulClose => "successful-close",
        B3SingleMode::Fin => "fin",
        B3SingleMode::Rst => "rst",
        B3SingleMode::ConnectFailure => "connect-failure",
        B3SingleMode::AgentKill => "agent-kill",
    };
    let mut execution =
        prepare_b3_execution(config, &evidence, sandbox, enforcer, &table, agent, 0).await?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health = Arc::new(Mutex::new(None));
    let proxy = if mode == B3SingleMode::ConnectFailure {
        None
    } else {
        Some(
            start_b3_proxy(
                config,
                b3_attributor(
                    config,
                    enforcer,
                    Arc::clone(&table),
                    Arc::clone(&observations),
                    Arc::clone(&dns),
                    Arc::clone(&outbound),
                    Arc::clone(&health),
                    None,
                )?,
                Arc::clone(&dns),
            )
            .await?,
        )
    };
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    let report = read_b3_report(execution.pid, "b3-report.jsonl", Duration::from_secs(12)).await?;
    let consumed = if mode == B3SingleMode::ConnectFailure {
        if report.lines().any(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|value| value.get("ok").and_then(Value::as_bool).map(|ok| !ok))
                != Some(true)
        }) {
            return Err("connect-failure agent did not record a refused connection".to_owned());
        }
        0
    } else {
        wait_b3_observations(&observations, 1, Duration::from_secs(10)).await?;
        let observations_guard = observations
            .lock()
            .map_err(|_| "B3 observation lock poisoned".to_owned())?;
        let observation = observations_guard
            .first()
            .ok_or("missing Resolve observation")?;
        if observation.outcome != ObservedResolveOutcome::Resolved
            || observation.resolved_execution != Some(execution.execution.id)
            || observation.recv_q_bytes == 0
            || observation.health_failure.is_some()
        {
            return Err(format!("{} violated Resolve invariants", mode.name()));
        }
        1
    };
    if mode == B3SingleMode::AgentKill {
        sandbox
            .call(SandboxRequest::Kill {
                tag: execution.execution.id.tag(),
            })
            .await
            .map_err(|error| error.to_string())?;
    }
    if let Some(proxy) = proxy {
        proxy.stop().await?;
    }
    let cleanup = execution.execution.cleanup(Some(&table)).await;
    if !cleanup.is_empty() {
        return Err(format!("{} cleanup failed: {cleanup:?}", mode.name()));
    }
    let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
    write_b3_accounting(&evidence, before, after, consumed)?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case": mode,
            "execution_id": execution.execution.id,
            "binding": execution.binding,
            "agent_report": report,
            "observations": observations.lock().ok().as_deref(),
            "health_failure": health.lock().ok().and_then(|failure| *failure),
            "cleanup_failures": cleanup
        }),
    )
}

async fn run_b3_frozen_teardown(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
) -> Result<(), String> {
    let evidence = root.join("cases/frozen_teardown");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "frozen_teardown\n")
        .map_err(|error| error.to_string())?;
    let before = b3_counters(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = prepare_b3_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "frozen-teardown",
        0,
    )
    .await?;
    table.revoke_key(execution.binding);
    enforcer
        .call(EnforcerRequest::Freeze {
            tag: execution.execution.id.tag(),
        })
        .await
        .map_err(|error| error.to_string())?;
    let cleanup = execution.execution.cleanup(Some(&table)).await;
    if !cleanup.is_empty() {
        return Err(format!("frozen teardown cleanup failed: {cleanup:?}"));
    }
    let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
    write_b3_accounting(&evidence, before, after, 0)?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case": "FROZEN_TEARDOWN",
            "execution_id": execution.execution.id,
            "binding": execution.binding,
            "started": false,
            "freeze_before_sandbox_destroy": true,
            "cleanup_failures": cleanup
        }),
    )
}

async fn run_b3_source_port_reuse(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/source_port_reuse");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "source_port_reuse\n")
        .map_err(|error| error.to_string())?;
    let before = b3_counters(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = prepare_b3_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "source-reuse",
        0,
    )
    .await?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health = Arc::new(Mutex::new(None));
    let proxy = start_b3_proxy(
        config,
        b3_attributor(
            config,
            enforcer,
            Arc::clone(&table),
            Arc::clone(&observations),
            Arc::clone(&dns),
            Arc::clone(&outbound),
            Arc::clone(&health),
            None,
        )?,
        Arc::clone(&dns),
    )
    .await?;
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    wait_b3_observations(&observations, 1, Duration::from_secs(10)).await?;
    let first = observations
        .lock()
        .map_err(|_| "B3 observation lock poisoned".to_owned())?
        .first()
        .cloned()
        .ok_or("source-port reuse omitted first observation")?;
    if first.outcome != ObservedResolveOutcome::Resolved
        || first.resolved_execution != Some(execution.execution.id)
    {
        return Err("first source-port reuse connection did not resolve".to_owned());
    }
    let state: Value = serde_json::from_slice(
        &fs::read(config.runtime.state_dir.join("cgroup-bpf/state.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let tuple_pin = map_pin(&state, "soglia_tuples")?;
    let key = encode_socket_tuple(first.peer, first.local)?;
    let old_cookie = first
        .cookie
        .ok_or("first source-port reuse cookie is absent")?;
    let injected_cookie = old_cookie.wrapping_add(1).max(1);
    let mut injected = [0_u8; 48];
    injected[0..8].copy_from_slice(&injected_cookie.to_ne_bytes());
    injected[8..40].copy_from_slice(&encode_binding_key(execution.binding));
    map_command(
        &config.runtime.bpftool,
        "update",
        &tuple_pin,
        &key,
        Some(&injected),
    )?;
    let report_root = PathBuf::from(format!("/proc/{}/root/tmp/b3-reuse.jsonl", execution.pid));
    fs::write(
        evidence.join("old-close-injection.json"),
        serde_json::to_vec_pretty(&json!({
            "actor": "B3 qualification harness",
            "tuple_key_hex": hex(&key),
            "old_socket_cookie": old_cookie,
            "replacement_cookie": injected_cookie,
            "replacement_binding": execution.binding,
            "purpose": "prove an old close callback cannot delete a tuple carrying another cookie",
            "production_code_modified": false
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(format!("{}.close", report_root.display()), b"close\n")
        .map_err(|error| error.to_string())?;
    wait_for_file(
        &PathBuf::from(format!("{}.first-closed", report_root.display())),
        Duration::from_secs(5),
    )
    .await?;
    let after_close = dump_map(&config.runtime.bpftool, &tuple_pin)?;
    let retained = map_dump_value_for_key(&after_close, &key)? == Some(injected.to_vec());
    if !retained {
        return Err("old close callback deleted the cookie-mismatched replacement tuple".into());
    }
    map_command(&config.runtime.bpftool, "delete", &tuple_pin, &key, None)?;
    fs::write(format!("{}.second", report_root.display()), b"second\n")
        .map_err(|error| error.to_string())?;
    wait_b3_observations(&observations, 2, Duration::from_secs(10)).await?;
    let report = read_b3_report(execution.pid, "b3-reuse.jsonl", Duration::from_secs(2)).await?;
    proxy.stop().await?;
    let snapshot = observations
        .lock()
        .map_err(|_| "B3 observation lock poisoned".to_owned())?
        .clone();
    if snapshot.len() != 2
        || snapshot.iter().any(|observation| {
            observation.outcome != ObservedResolveOutcome::Resolved
                || observation.resolved_execution != Some(execution.execution.id)
                || observation.peer.port() != 40_000
        })
    {
        return Err("source-port reuse did not produce two exact resolutions".to_owned());
    }
    let cleanup = execution.execution.cleanup(Some(&table)).await;
    if !cleanup.is_empty() {
        return Err(format!("source-port reuse cleanup failed: {cleanup:?}"));
    }
    let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
    write_b3_accounting(&evidence, before, after, 2)?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case": "SOURCE_PORT_REUSE",
            "source_port": 40000,
            "observations": snapshot,
            "agent_report": report,
            "old_close_cookie_guard_proven": retained,
            "injected_tuple_removed_by": "qualification harness before the second connection",
            "health_failure": health.lock().ok().and_then(|failure| *failure)
        }),
    )
}

async fn run_b3_execution_generation(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/execution_generation");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "execution_generation\n")
        .map_err(|error| error.to_string())?;
    let before = b3_counters(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut identities = Vec::new();
    for incarnation in 0..2 {
        let incarnation_dir = evidence.join(format!("incarnation-{incarnation}"));
        fs::create_dir_all(&incarnation_dir).map_err(|error| error.to_string())?;
        let mut execution = prepare_b3_execution(
            config,
            &incarnation_dir,
            sandbox,
            enforcer,
            &table,
            "execution-generation",
            0,
        )
        .await?;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let dns = Arc::new(AtomicUsize::new(0));
        outbound.store(0, Ordering::SeqCst);
        let health = Arc::new(Mutex::new(None));
        let proxy = start_b3_proxy(
            config,
            b3_attributor(
                config,
                enforcer,
                Arc::clone(&table),
                Arc::clone(&observations),
                Arc::clone(&dns),
                Arc::clone(&outbound),
                Arc::clone(&health),
                None,
            )?,
            Arc::clone(&dns),
        )
        .await?;
        sandbox
            .call(SandboxRequest::Start {
                id: execution.execution.id,
            })
            .await
            .map_err(|error| error.to_string())?;
        wait_b3_observations(&observations, 1, Duration::from_secs(10)).await?;
        let observation = observations
            .lock()
            .map_err(|_| "B3 observation lock poisoned".to_owned())?
            .first()
            .cloned()
            .ok_or("execution generation omitted Resolve")?;
        if observation.outcome != ObservedResolveOutcome::Resolved
            || observation.resolved_execution != Some(execution.execution.id)
        {
            return Err(format!("incarnation {incarnation} resolved incorrectly"));
        }
        proxy.stop().await?;
        identities.push(json!({
            "incarnation": incarnation,
            "execution_id": execution.execution.id,
            "binding": execution.binding,
            "cgroup_inode": execution.cgroup_inode,
            "observation": observation
        }));
        let cleanup = execution.execution.cleanup(Some(&table)).await;
        if !cleanup.is_empty() {
            return Err(format!(
                "incarnation {incarnation} cleanup failed: {cleanup:?}"
            ));
        }
        wait_b3_empty(config, Duration::from_secs(2)).await?;
    }
    let first: BindingKey = serde_json::from_value(
        identities[0]
            .get("binding")
            .cloned()
            .ok_or("first binding is absent")?,
    )
    .map_err(|error| error.to_string())?;
    let second: BindingKey = serde_json::from_value(
        identities[1]
            .get("binding")
            .cloned()
            .ok_or("second binding is absent")?,
    )
    .map_err(|error| error.to_string())?;
    if first.execution_nonce == second.execution_nonce
        || first.backend_generation != second.backend_generation
    {
        return Err("fresh Execution did not receive a fresh nonce in the same generation".into());
    }
    let actual_reuse = first.cgroup_id == second.cgroup_id;
    let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
    write_b3_accounting(&evidence, before, after, 2)?;
    fs::write(
        evidence.join("cgroup-id-reuse-scope.json"),
        serde_json::to_vec_pretty(&json!({
            "actual_reuse": if actual_reuse { "PERFORMED" } else { "NOT_PERFORMED" },
            "observed_ids": [first.cgroup_id, second.cgroup_id],
            "attempt_limit": 2,
            "reason_if_not_performed": "the recorded Linux kernel exposes a 64-bit kernfs cgroup identity carrying generation information; destroyed identities were not reused within the bounded qualification lifecycle",
            "inode_used_as_identity": false,
            "synthetic_same_cgroup_with_stale_nonce": "performed by binding_mismatch_matrix",
            "claim_scope": "no claim of empirical kernel cgroup-id reuse when NOT_PERFORMED"
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case": "EXECUTION_GENERATION",
            "identities": identities,
            "fresh_nonce": true,
            "same_backend_generation": true,
            "actual_cgroup_id_reuse": actual_reuse,
            "actual_reuse_scope": if actual_reuse { "PASS" } else { "NOT_PERFORMED" }
        }),
    )
}

async fn run_b3_binding_matrix(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/binding_mismatch_matrix");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "binding_mismatch_matrix\n")
        .map_err(|error| error.to_string())?;
    let mut cells = Vec::new();
    for boundary in [
        B3Boundary::Tuple,
        B3Boundary::Cookie,
        B3Boundary::Policy,
        B3Boundary::LiveBinding,
    ] {
        for field in [
            B3Field::CgroupId,
            B3Field::ExecutionNonce,
            B3Field::BackendGeneration,
        ] {
            cells.push(B3MatrixCell {
                boundary,
                field,
                covered_by_b2: boundary == B3Boundary::Tuple
                    && matches!(field, B3Field::ExecutionNonce | B3Field::BackendGeneration),
            });
        }
    }
    for boundary in [B3Boundary::Tuple, B3Boundary::Cookie] {
        for field in [B3Field::OldComplete, B3Field::Mixed] {
            cells.push(B3MatrixCell {
                boundary,
                field,
                covered_by_b2: false,
            });
        }
    }

    let mut results = Vec::new();
    for (index, cell) in cells.into_iter().enumerate() {
        let cell_name = format!("{}-{}", cell.boundary.name(), cell.field.name());
        let cell_evidence = evidence.join(&cell_name);
        fs::create_dir_all(&cell_evidence).map_err(|error| error.to_string())?;
        let before = b3_counters(config)?;
        let lifecycle_table = Arc::new(AttributionTable::new());
        let mut execution = prepare_b3_execution(
            config,
            &cell_evidence,
            sandbox,
            enforcer,
            &lifecycle_table,
            "binding-matrix",
            0,
        )
        .await?;
        let resolution_table = if cell.boundary == B3Boundary::LiveBinding {
            let table = Arc::new(AttributionTable::new());
            table
                .bind_key(
                    mutate_b3_binding(execution.binding, cell.field),
                    execution.execution.id,
                )
                .map_err(|error| error.to_string())?;
            table
        } else {
            Arc::clone(&lifecycle_table)
        };
        let observations = Arc::new(Mutex::new(Vec::new()));
        let dns = Arc::new(AtomicUsize::new(0));
        outbound.store(0, Ordering::SeqCst);
        let health = Arc::new(Mutex::new(None));
        let candidate = b3_candidate_attributor(
            config,
            enforcer,
            Arc::clone(&resolution_table),
            Arc::clone(&health),
        )?;
        let injected: Arc<dyn ConnectionAttributor> = if matches!(
            cell.boundary,
            B3Boundary::Tuple | B3Boundary::Cookie | B3Boundary::Policy
        ) {
            Arc::new(B3FaultAttributor {
                inner: candidate,
                config_state: config.runtime.state_dir.join("cgroup-bpf/state.json"),
                bpftool: config.runtime.bpftool.clone(),
                expected: execution.binding,
                cell,
                evidence: cell_evidence.clone(),
            })
        } else {
            candidate
        };
        let proxy = start_b3_proxy(
            config,
            b3_recording_wrapper(
                config,
                injected,
                Arc::clone(&observations),
                Arc::clone(&dns),
                Arc::clone(&outbound),
                Arc::clone(&health),
            ),
            Arc::clone(&dns),
        )
        .await?;
        sandbox
            .call(SandboxRequest::Start {
                id: execution.execution.id,
            })
            .await
            .map_err(|error| error.to_string())?;
        wait_b3_observations(&observations, 1, Duration::from_secs(10)).await?;
        let report =
            read_b3_report(execution.pid, "b3-report.jsonl", Duration::from_secs(10)).await?;
        proxy.stop().await?;
        let observation = observations
            .lock()
            .map_err(|_| "B3 observation lock poisoned".to_owned())?
            .first()
            .cloned()
            .ok_or("binding matrix cell omitted Resolve")?;
        let expected = b3_expected_mismatch(cell);
        if (observation.outcome, observation.mismatch) != expected
            || observation.resolved_execution.is_some()
            || observation.recv_q_bytes == 0
            || observation.dns_when_resolve_returned != 0
            || observation.outbound_when_resolve_returned != 0
            || observation.health_failure.is_some()
        {
            return Err(format!(
                "binding matrix cell {cell_name} returned {:?}/{:?}, expected {:?}/{:?}",
                observation.outcome, observation.mismatch, expected.0, expected.1
            ));
        }
        if cell.boundary == B3Boundary::LiveBinding {
            let injected_key = mutate_b3_binding(execution.binding, cell.field);
            resolution_table.revoke_key(injected_key);
            if !resolution_table.remove_key(injected_key, execution.execution.id) {
                return Err(format!(
                    "could not release injected live binding for {cell_name}"
                ));
            }
        }
        let cleanup = execution.execution.cleanup(Some(&lifecycle_table)).await;
        if !cleanup.is_empty() {
            return Err(format!(
                "binding matrix {cell_name} cleanup failed: {cleanup:?}"
            ));
        }
        let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
        write_b3_accounting(&cell_evidence, before, after, 1)?;
        let result = json!({
            "index": index,
            "boundary": cell.boundary,
            "field": cell.field,
            "covered_by_b2": cell.covered_by_b2,
            "expected": {"outcome": expected.0, "mismatch": expected.1},
            "observation": observation,
            "agent_report": report,
            "single_boundary_mutation": true,
            "production_code_modified": false,
            "verdict": "PASS"
        });
        write_b3_case_result(&cell_evidence, &result)?;
        results.push(result);
    }
    fs::write(
        evidence.join("matrix.json"),
        serde_json::to_vec_pretty(&json!({
            "map_and_live_cells": results,
            "durable_record_cells": "recorded after controlled Enforcer restart in backend_generation",
            "b2_overlap": [
                "tuple/execution_nonce",
                "tuple/backend_generation",
                "missing cookie was covered separately by B2"
            ],
            "required_classes": {
                "current_cgroup_stale_nonce": "covered across tuple, cookie, policy and live_binding",
                "current_cgroup_current_nonce_stale_generation": "covered across tuple, cookie, policy and live_binding",
                "stale_cgroup_current_nonce_generation": "covered across tuple, cookie, policy and live_binding",
                "old_complete_or_mixed_cookie_tuple": "covered by four additional cells"
            }
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(evidence.join("verdict.txt"), "PENDING_DURABLE_RECORD\n")
        .map_err(|error| error.to_string())
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum B3RaceOrdering {
    ResolveFirst,
    FreezeFirst,
    Concurrent,
}

async fn run_b3_freeze_resolve_race(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/freeze_resolve_race");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "freeze_resolve_race\n")
        .map_err(|error| error.to_string())?;
    let mut iterations = Vec::with_capacity(B3_RACE_ITERATIONS + 2);
    for iteration in 0..(B3_RACE_ITERATIONS + 2) {
        let ordering = match iteration {
            0 => B3RaceOrdering::ResolveFirst,
            1 => B3RaceOrdering::FreezeFirst,
            _ => B3RaceOrdering::Concurrent,
        };
        let iteration_evidence = evidence.join(format!("iteration-{iteration:03}"));
        fs::create_dir_all(&iteration_evidence).map_err(|error| error.to_string())?;
        let before = b3_counters(config)?;
        let table = Arc::new(AttributionTable::new());
        let mut execution = prepare_b3_execution(
            config,
            &iteration_evidence,
            sandbox,
            enforcer,
            &table,
            "race",
            0,
        )
        .await?;
        let dns = Arc::new(AtomicUsize::new(0));
        outbound.store(0, Ordering::SeqCst);
        let health = Arc::new(Mutex::new(None));
        let entered = Arc::new(Notify::new());
        let completed = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let concurrent = Arc::new(Barrier::new(2));
        let result = Arc::new(Mutex::new(None));
        let gate = match ordering {
            B3RaceOrdering::ResolveFirst => B3RaceGate::Immediate,
            B3RaceOrdering::FreezeFirst => B3RaceGate::Release(Arc::clone(&release)),
            B3RaceOrdering::Concurrent => B3RaceGate::Concurrent(Arc::clone(&concurrent)),
        };
        let candidate =
            b3_candidate_attributor(config, enforcer, Arc::clone(&table), Arc::clone(&health))?;
        let proxy = start_b3_proxy(
            config,
            Arc::new(B3RaceAttributor {
                inner: candidate,
                gate,
                entered: Arc::clone(&entered),
                completed: Arc::clone(&completed),
                result: Arc::clone(&result),
            }),
            Arc::clone(&dns),
        )
        .await?;
        sandbox
            .call(SandboxRequest::Start {
                id: execution.execution.id,
            })
            .await
            .map_err(|error| error.to_string())?;
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .map_err(|_| format!("race iteration {iteration} never entered Resolve"))?;

        match ordering {
            B3RaceOrdering::ResolveFirst => {
                tokio::time::timeout(Duration::from_secs(5), completed.notified())
                    .await
                    .map_err(|_| format!("race iteration {iteration} did not resolve first"))?;
                table.revoke_key(execution.binding);
                enforcer
                    .call(EnforcerRequest::Freeze {
                        tag: execution.execution.id.tag(),
                    })
                    .await
                    .map_err(|error| error.to_string())?;
            }
            B3RaceOrdering::FreezeFirst => {
                table.revoke_key(execution.binding);
                enforcer
                    .call(EnforcerRequest::Freeze {
                        tag: execution.execution.id.tag(),
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                release.notify_one();
                tokio::time::timeout(Duration::from_secs(5), completed.notified())
                    .await
                    .map_err(|_| format!("race iteration {iteration} did not finish"))?;
            }
            B3RaceOrdering::Concurrent => {
                concurrent.wait().await;
                table.revoke_key(execution.binding);
                enforcer
                    .call(EnforcerRequest::Freeze {
                        tag: execution.execution.id.tag(),
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                tokio::time::timeout(Duration::from_secs(5), completed.notified())
                    .await
                    .map_err(|_| format!("race iteration {iteration} did not finish"))?;
            }
        }
        let effects_at_freeze = (dns.load(Ordering::SeqCst), outbound.load(Ordering::SeqCst));
        tokio::time::sleep(Duration::from_millis(25)).await;
        let effects_after_freeze = (dns.load(Ordering::SeqCst), outbound.load(Ordering::SeqCst));
        if effects_at_freeze != effects_after_freeze {
            return Err(format!(
                "race iteration {iteration} caused an effect after freeze"
            ));
        }
        let observed = result
            .lock()
            .map_err(|_| "B3 race result lock poisoned".to_owned())?
            .ok_or_else(|| format!("race iteration {iteration} omitted its result"))?;
        let valid = match ordering {
            B3RaceOrdering::ResolveFirst => observed.0 == ObservedResolveOutcome::Resolved,
            B3RaceOrdering::FreezeFirst => observed.0 == ObservedResolveOutcome::Revoked,
            B3RaceOrdering::Concurrent => matches!(
                observed.0,
                ObservedResolveOutcome::Resolved | ObservedResolveOutcome::Revoked
            ),
        } && observed.1.is_none();
        if !valid || health.lock().ok().and_then(|failure| *failure).is_some() {
            return Err(format!(
                "race iteration {iteration} returned invalid outcome {:?}/{:?}",
                observed.0, observed.1
            ));
        }
        // Freeze can revoke the request before the proxy's CONNECT response
        // reaches the agent. The proxy-side outcome and effect counters are
        // authoritative for this race; established-tunnel closure is proven
        // independently by connect_tunnel_revocation.
        let report_path =
            PathBuf::from(format!("/proc/{}/root/tmp/b3-report.jsonl", execution.pid));
        let report = fs::read_to_string(&report_path)
            .ok()
            .filter(|contents| !contents.trim().is_empty());
        proxy.stop().await?;
        let cleanup = execution.execution.cleanup(Some(&table)).await;
        if !cleanup.is_empty() {
            return Err(format!(
                "race iteration {iteration} cleanup failed: {cleanup:?}"
            ));
        }
        let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
        write_b3_accounting(&iteration_evidence, before, after, 1)?;
        let result = json!({
            "iteration": iteration,
            "ordering": ordering,
            "outcome": observed.0,
            "mismatch": observed.1,
            "resolved_then_revoked": observed.0 == ObservedResolveOutcome::Resolved,
            "effects_at_freeze": {"dns": effects_at_freeze.0, "outbound": effects_at_freeze.1},
            "effects_after_freeze": {"dns": effects_after_freeze.0, "outbound": effects_after_freeze.1},
            "agent_report": report,
            "agent_report_required": false,
            "agent_report_scope": "a freeze may close CONNECT before an application response; proxy outcome and no-post-freeze effects are authoritative",
            "health_failure": health.lock().ok().and_then(|failure| *failure),
            "verdict": "PASS"
        });
        write_b3_case_result(&iteration_evidence, &result)?;
        iterations.push(result);
    }
    write_b3_case_result(
        &evidence,
        &json!({
            "case": "FREEZE_RESOLVE_RACE",
            "controlled_orderings": 2,
            "genuine_concurrent_iterations": B3_RACE_ITERATIONS,
            "iterations": iterations,
            "invariant": "each outcome is Resolved followed by revocation or Revoked, with no effects after freeze"
        }),
    )
}

async fn run_b3_connect_tunnel_revocation(
    root: &Path,
    config: &Config,
    sandbox: &Helper,
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/connect_tunnel_revocation");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "connect_tunnel_revocation\n")
        .map_err(|error| error.to_string())?;
    let before = b3_counters(config)?;
    let table = Arc::new(AttributionTable::new());
    let mut execution = prepare_b3_execution(
        config,
        &evidence,
        sandbox,
        enforcer,
        &table,
        "tunnel-revocation",
        0,
    )
    .await?;
    let observations = Arc::new(Mutex::new(Vec::new()));
    let dns = Arc::new(AtomicUsize::new(0));
    outbound.store(0, Ordering::SeqCst);
    let health = Arc::new(Mutex::new(None));
    let proxy = start_b3_proxy(
        config,
        b3_attributor(
            config,
            enforcer,
            Arc::clone(&table),
            Arc::clone(&observations),
            Arc::clone(&dns),
            Arc::clone(&outbound),
            Arc::clone(&health),
            None,
        )?,
        Arc::clone(&dns),
    )
    .await?;
    sandbox
        .call(SandboxRequest::Start {
            id: execution.execution.id,
        })
        .await
        .map_err(|error| error.to_string())?;
    wait_b3_observations(&observations, 1, Duration::from_secs(10)).await?;
    let established =
        wait_b3_report_lines(execution.pid, "b3-report.jsonl", 1, Duration::from_secs(10)).await?;
    let observation = observations
        .lock()
        .map_err(|_| "B3 observation lock poisoned".to_owned())?
        .first()
        .cloned()
        .ok_or("CONNECT tunnel omitted Resolve")?;
    if observation.outcome != ObservedResolveOutcome::Resolved
        || observation.resolved_execution != Some(execution.execution.id)
        || outbound.load(Ordering::SeqCst) != 1
        || !established.contains("\"phase\":\"established\"")
        || !established.contains("\"ok\":true")
    {
        return Err("CONNECT tunnel was not established through the exact Execution".to_owned());
    }
    table.revoke_key(execution.binding);
    enforcer
        .call(EnforcerRequest::Freeze {
            tag: execution.execution.id.tag(),
        })
        .await
        .map_err(|error| error.to_string())?;
    let effects_at_freeze = (dns.load(Ordering::SeqCst), outbound.load(Ordering::SeqCst));
    let closed =
        wait_b3_report_lines(execution.pid, "b3-report.jsonl", 2, Duration::from_secs(5)).await?;
    tokio::time::sleep(Duration::from_millis(25)).await;
    let effects_after_freeze = (dns.load(Ordering::SeqCst), outbound.load(Ordering::SeqCst));
    if effects_at_freeze != effects_after_freeze
        || !closed.contains("proxy closed the tunnel")
        || !closed.contains("\"phase\":\"closed\"")
    {
        return Err("revocation did not close the established CONNECT tunnel exactly".to_owned());
    }
    proxy.stop().await?;
    let cleanup = execution.execution.cleanup(Some(&table)).await;
    if !cleanup.is_empty() {
        return Err(format!("CONNECT tunnel cleanup failed: {cleanup:?}"));
    }
    let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
    write_b3_accounting(&evidence, before, after, 1)?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case": "CONNECT_TUNNEL_REVOCATION",
            "execution_id": execution.execution.id,
            "binding": execution.binding,
            "observation": observation,
            "report_before_revocation": established,
            "report_after_revocation": closed,
            "effects_at_freeze": {"dns": effects_at_freeze.0, "outbound": effects_at_freeze.1},
            "effects_after_freeze": {"dns": effects_after_freeze.0, "outbound": effects_after_freeze.1},
            "tunnel_closed_by_revocation": true,
            "health_failure": health.lock().ok().and_then(|failure| *failure)
        }),
    )
}

fn mutate_b3_durable_record(
    original: &[u8],
    tag: &str,
    field: B3Field,
) -> Result<(Vec<u8>, BindingKey, BindingKey), String> {
    let mut state: Value = serde_json::from_slice(original).map_err(|error| error.to_string())?;
    let binding_value = state
        .get_mut("executions")
        .and_then(Value::as_object_mut)
        .and_then(|executions| executions.get_mut(tag))
        .and_then(|execution| execution.get_mut("binding"))
        .ok_or_else(|| format!("durable state omitted binding for {tag}"))?;
    let before: BindingKey =
        serde_json::from_value(binding_value.clone()).map_err(|error| error.to_string())?;
    let after = mutate_b3_binding(before, field);
    *binding_value = serde_json::to_value(after).map_err(|error| error.to_string())?;
    Ok((
        serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
        before,
        after,
    ))
}

async fn run_b3_backend_generation(
    root: &Path,
    config: &Config,
    config_yaml: &str,
    binary: &Path,
    sandbox: &Helper,
    enforcer: Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    let evidence = root.join("cases/backend_generation");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    fs::write(root.join("current-case.txt"), "backend_generation\n")
        .map_err(|error| error.to_string())?;
    let matrix_evidence = root.join("cases/binding_mismatch_matrix");
    let state_path = config.runtime.state_dir.join("cgroup-bpf/state.json");

    // Leave one exact durable record behind through a controlled Enforcer stop. The helper's
    // production Drop path freezes the record before it exits; the Sandbox then removes the
    // paused subject so recovery can classify the record without live traffic.
    let table = Arc::new(AttributionTable::new());
    let durable_source = evidence.join("durable-source");
    fs::create_dir_all(&durable_source).map_err(|error| error.to_string())?;
    let prepared = prepare_b3_execution(
        config,
        &durable_source,
        sandbox,
        &enforcer,
        &table,
        "frozen-teardown",
        0,
    )
    .await?;
    let old_id = prepared.execution.id;
    let old_binding = prepared.binding;
    drop(prepared);
    drop(enforcer);
    sandbox
        .call(SandboxRequest::Kill { tag: old_id.tag() })
        .await
        .map_err(|error| error.to_string())?;
    sandbox
        .call(SandboxRequest::Destroy { tag: old_id.tag() })
        .await
        .map_err(|error| error.to_string())?;
    table.revoke_key(old_binding);
    if !table.remove_key(old_binding, old_id) {
        return Err("controlled restart could not release the old live binding".to_owned());
    }
    let original = fs::read(&state_path).map_err(|error| error.to_string())?;
    let original_value: Value =
        serde_json::from_slice(&original).map_err(|error| error.to_string())?;
    let old_generation = original_value
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or("durable state omitted its backend generation")?;
    let mut durable_results = Vec::new();
    for field in [
        B3Field::CgroupId,
        B3Field::ExecutionNonce,
        B3Field::BackendGeneration,
    ] {
        let cell_evidence = matrix_evidence.join(format!(
            "{}-{}",
            B3Boundary::DurableRecord.name(),
            field.name()
        ));
        fs::create_dir_all(&cell_evidence).map_err(|error| error.to_string())?;
        let before_counters = b3_counters(config)?;
        let (mutated, before, after) =
            mutate_b3_durable_record(&original, &old_id.tag().to_string(), field)?;
        fs::write(&state_path, &mutated).map_err(|error| error.to_string())?;
        let rejected = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
        let error = match rejected.hello(config_yaml) {
            Err(error) => error.to_string(),
            Ok(response) => {
                let failure = json!({
                    "boundary": B3Boundary::DurableRecord,
                    "field": field,
                    "binding_before": before,
                    "binding_after": after,
                    "startup_refused": false,
                    "unexpected_response": format!("{response:?}"),
                    "verdict": "FAIL"
                });
                fs::write(
                    cell_evidence.join("result.json"),
                    serde_json::to_vec_pretty(&failure).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                fs::write(cell_evidence.join("verdict.txt"), "FAIL\n")
                    .map_err(|error| error.to_string())?;
                drop(rejected);
                return Err(format!(
                    "production accepted a durable-record {} mismatch; B3 requires a production fix",
                    field.name()
                ));
            }
        };
        drop(rejected);
        let preserved = fs::read(&state_path).map_err(|error| error.to_string())? == mutated;
        if !preserved {
            return Err(format!(
                "durable record {} was changed during typed refusal",
                field.name()
            ));
        }
        fs::write(&state_path, &original).map_err(|error| error.to_string())?;
        let after_counters = b3_counters(config)?;
        write_b3_accounting(&cell_evidence, before_counters, after_counters, 0)?;
        let result = json!({
            "boundary": B3Boundary::DurableRecord,
            "field": field,
            "binding_before": before,
            "binding_after": after,
            "startup_refused": true,
            "refusal": error,
            "mismatched_record_preserved_byte_for_byte": preserved,
            "original_record_restored_byte_for_byte": fs::read(&state_path).map_err(|error| error.to_string())? == original,
            "production_code_modified": false,
            "verdict": "PASS"
        });
        write_b3_case_result(&cell_evidence, &result)?;
        durable_results.push(result);
    }

    let current = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
    let swept = current
        .hello(config_yaml)
        .map_err(|error| format!("valid backend-generation recovery failed: {error}"))?;
    current
        .ensure_running()
        .map_err(|error| error.to_string())?;
    let recovered_state: Value =
        serde_json::from_slice(&fs::read(&state_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let new_generation = recovered_state
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or("recovered state omitted generation")?;
    if new_generation <= old_generation {
        return Err(format!(
            "backend generation did not advance: old={old_generation}, new={new_generation}"
        ));
    }

    let mut generation_results = Vec::new();
    for (index, stale) in [false, true].into_iter().enumerate() {
        let run_evidence = evidence.join(if stale {
            "stale-old-generation"
        } else {
            "fresh"
        });
        fs::create_dir_all(&run_evidence).map_err(|error| error.to_string())?;
        let before = b3_counters(config)?;
        let lifecycle_table = Arc::new(AttributionTable::new());
        let mut execution = prepare_b3_execution(
            config,
            &run_evidence,
            sandbox,
            &current,
            &lifecycle_table,
            "backend-generation",
            0,
        )
        .await?;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let dns = Arc::new(AtomicUsize::new(0));
        outbound.store(0, Ordering::SeqCst);
        let health = Arc::new(Mutex::new(None));
        let candidate = b3_candidate_attributor(
            config,
            &current,
            Arc::clone(&lifecycle_table),
            Arc::clone(&health),
        )?;
        let inner: Arc<dyn ConnectionAttributor> = if stale {
            Arc::new(B3FaultAttributor {
                inner: candidate,
                config_state: state_path.clone(),
                bpftool: config.runtime.bpftool.clone(),
                expected: execution.binding,
                cell: B3MatrixCell {
                    boundary: B3Boundary::Tuple,
                    field: B3Field::BackendGeneration,
                    covered_by_b2: true,
                },
                evidence: run_evidence.clone(),
            })
        } else {
            candidate
        };
        let proxy = start_b3_proxy(
            config,
            b3_recording_wrapper(
                config,
                inner,
                Arc::clone(&observations),
                Arc::clone(&dns),
                Arc::clone(&outbound),
                Arc::clone(&health),
            ),
            Arc::clone(&dns),
        )
        .await?;
        sandbox
            .call(SandboxRequest::Start {
                id: execution.execution.id,
            })
            .await
            .map_err(|error| error.to_string())?;
        wait_b3_observations(&observations, 1, Duration::from_secs(10)).await?;
        let report =
            read_b3_report(execution.pid, "b3-report.jsonl", Duration::from_secs(10)).await?;
        proxy.stop().await?;
        let observation = observations
            .lock()
            .map_err(|_| "B3 observation lock poisoned".to_owned())?
            .first()
            .cloned()
            .ok_or("backend-generation case omitted Resolve")?;
        let valid = if stale {
            observation.outcome == ObservedResolveOutcome::IdentityMismatch
                && observation.mismatch == Some(ResolveMismatch::BackendGeneration)
                && observation.resolved_execution.is_none()
        } else {
            observation.outcome == ObservedResolveOutcome::Resolved
                && observation.resolved_execution == Some(execution.execution.id)
                && execution.binding.backend_generation == new_generation
        };
        if !valid || health.lock().ok().and_then(|failure| *failure).is_some() {
            return Err(format!(
                "backend-generation subcase {index} returned the wrong result"
            ));
        }
        let cleanup = execution.execution.cleanup(Some(&lifecycle_table)).await;
        if !cleanup.is_empty() {
            return Err(format!(
                "backend-generation subcase cleanup failed: {cleanup:?}"
            ));
        }
        let after = wait_b3_empty(config, Duration::from_secs(2)).await?;
        write_b3_accounting(&run_evidence, before, after, 1)?;
        let result = json!({
            "stale_old_generation": stale,
            "execution_id": execution.execution.id,
            "binding": execution.binding,
            "observation": observation,
            "agent_report": report,
            "verdict": "PASS"
        });
        write_b3_case_result(&run_evidence, &result)?;
        generation_results.push(result);
    }

    fs::write(
        matrix_evidence.join("durable-record.json"),
        serde_json::to_vec_pretty(&durable_results).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(matrix_evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    write_b3_case_result(
        &evidence,
        &json!({
            "case": "BACKEND_GENERATION",
            "old_generation": old_generation,
            "new_generation": new_generation,
            "generation_advanced": true,
            "startup_swept": swept,
            "durable_record_matrix": durable_results,
            "fresh_and_stale_generation_results": generation_results
        }),
    )?;
    drop(current);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuple_byte_order_changes_only_the_source_port() {
        let peer: SocketAddr = "10.201.0.1:40000".parse().unwrap();
        let local: SocketAddr = "10.200.255.1:15001".parse().unwrap();

        let (queried_peer, queried_local) =
            qualification_query(Case::TupleByteOrder, peer, local).unwrap();

        assert_eq!(queried_peer.ip(), peer.ip());
        assert_eq!(queried_peer.port(), 40000_u16.swap_bytes());
        assert_ne!(queried_peer.port(), peer.port());
        assert_eq!(queried_local, local);
    }

    #[test]
    fn tuple_byte_order_rejects_a_byte_symmetric_source_port() {
        let peer: SocketAddr = "10.201.0.1:39835".parse().unwrap();
        let local: SocketAddr = "10.200.255.1:15001".parse().unwrap();

        let error = qualification_query(Case::TupleByteOrder, peer, local).unwrap_err();

        assert!(error.contains("byte-symmetric"));
    }

    #[test]
    fn concurrent_source_ports_are_all_changed_by_byte_swap() {
        let local: SocketAddr = "10.200.255.1:15001".parse().unwrap();
        let mut queried = Vec::new();
        for port in 40_000..40_004 {
            let peer = SocketAddr::new("10.201.0.1".parse().unwrap(), port);
            let (queried_peer, queried_local) =
                qualification_query(Case::TupleByteOrder, peer, local).unwrap();
            assert_ne!(queried_peer.port(), port);
            assert_eq!(queried_peer.ip(), peer.ip());
            assert_eq!(queried_local, local);
            queried.push(queried_peer.port());
        }
        queried.sort_unstable();
        queried.dedup();
        assert_eq!(queried.len(), 4);
    }

    #[test]
    fn wrong_destination_preserves_the_source_and_changes_the_proxy_port() {
        let peer: SocketAddr = "10.201.0.1:40000".parse().unwrap();
        let local: SocketAddr = "10.200.255.1:15001".parse().unwrap();

        let (queried_peer, queried_local) =
            qualification_query(Case::WrongDestination, peer, local).unwrap();

        assert_eq!(queried_peer, peer);
        assert_eq!(queried_local.ip(), local.ip());
        assert_ne!(queried_local.port(), local.port());
    }

    #[test]
    fn timeout_bounds_reject_early_and_late_results() {
        assert!(!timeout_duration_is_bounded(1_899, 2_000, 250));
        assert!(timeout_duration_is_bounded(1_900, 2_000, 250));
        assert!(timeout_duration_is_bounded(2_250, 2_000, 250));
        assert!(!timeout_duration_is_bounded(2_251, 2_000, 250));
    }

    #[test]
    fn socket_tuple_encoding_matches_candidate_a_abi() {
        let peer: SocketAddr = "10.201.0.1:40000".parse().unwrap();
        let local: SocketAddr = "10.200.255.1:15001".parse().unwrap();

        let encoded = encode_socket_tuple(peer, local).unwrap();

        assert_eq!(&encoded[0..4], &[10, 201, 0, 1]);
        assert_eq!(&encoded[4..8], &[10, 200, 255, 1]);
        assert_eq!(&encoded[8..10], &40_000_u16.to_ne_bytes());
        assert_eq!(&encoded[10..12], &15_001_u16.to_ne_bytes());
        assert_eq!(&encoded[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn counter_dump_is_decoded_by_native_endian_key_and_value() {
        let index = C_PUBLISHED;
        let expected = 17_u64;
        let dump = json!([{
            "key": index.to_ne_bytes(),
            "value": expected.to_ne_bytes()
        }]);

        assert_eq!(counter_value(&dump, index).unwrap(), expected);
        assert!(counter_value(&dump, C_UNPUBLISHED).is_err());
    }

    #[test]
    fn b3_single_field_mutations_change_exactly_one_binding_component() {
        let binding = BindingKey {
            cgroup_id: 17,
            execution_nonce: ExecutionNonce::from_bytes([0x11; 16]),
            backend_generation: 23,
        };

        let cgroup = mutate_b3_binding(binding, B3Field::CgroupId);
        assert_ne!(cgroup.cgroup_id, binding.cgroup_id);
        assert_eq!(cgroup.execution_nonce, binding.execution_nonce);
        assert_eq!(cgroup.backend_generation, binding.backend_generation);

        let nonce = mutate_b3_binding(binding, B3Field::ExecutionNonce);
        assert_eq!(nonce.cgroup_id, binding.cgroup_id);
        assert_ne!(nonce.execution_nonce, binding.execution_nonce);
        assert_eq!(nonce.backend_generation, binding.backend_generation);

        let generation = mutate_b3_binding(binding, B3Field::BackendGeneration);
        assert_eq!(generation.cgroup_id, binding.cgroup_id);
        assert_eq!(generation.execution_nonce, binding.execution_nonce);
        assert_ne!(generation.backend_generation, binding.backend_generation);
    }

    #[test]
    fn b3_old_and_mixed_bindings_have_the_required_shapes() {
        let binding = BindingKey {
            cgroup_id: 17,
            execution_nonce: ExecutionNonce::from_bytes([0x11; 16]),
            backend_generation: 23,
        };

        let old = mutate_b3_binding(binding, B3Field::OldComplete);
        assert_ne!(old.cgroup_id, binding.cgroup_id);
        assert_ne!(old.execution_nonce, binding.execution_nonce);
        assert_ne!(old.backend_generation, binding.backend_generation);

        let mixed = mutate_b3_binding(binding, B3Field::Mixed);
        assert_ne!(mixed.cgroup_id, binding.cgroup_id);
        assert_ne!(mixed.execution_nonce, binding.execution_nonce);
        assert_eq!(mixed.backend_generation, binding.backend_generation);
    }

    #[test]
    fn b3_boundary_classifier_keeps_boundary_specific_denials() {
        let tuple_nonce = B3MatrixCell {
            boundary: B3Boundary::Tuple,
            field: B3Field::ExecutionNonce,
            covered_by_b2: true,
        };
        let cookie_nonce = B3MatrixCell {
            boundary: B3Boundary::Cookie,
            field: B3Field::ExecutionNonce,
            covered_by_b2: false,
        };
        let policy_nonce = B3MatrixCell {
            boundary: B3Boundary::Policy,
            field: B3Field::ExecutionNonce,
            covered_by_b2: false,
        };
        let live_nonce = B3MatrixCell {
            boundary: B3Boundary::LiveBinding,
            field: B3Field::ExecutionNonce,
            covered_by_b2: false,
        };

        assert_eq!(
            b3_expected_mismatch(tuple_nonce),
            (
                ObservedResolveOutcome::IdentityMismatch,
                Some(ResolveMismatch::ExecutionNonce)
            )
        );
        assert_eq!(
            b3_expected_mismatch(cookie_nonce),
            (
                ObservedResolveOutcome::IdentityMismatch,
                Some(ResolveMismatch::Cookie)
            )
        );
        assert_eq!(
            b3_expected_mismatch(policy_nonce),
            (
                ObservedResolveOutcome::IdentityMismatch,
                Some(ResolveMismatch::Policy)
            )
        );
        assert_eq!(
            b3_expected_mismatch(live_nonce),
            (ObservedResolveOutcome::NotFound, None)
        );
    }
}
