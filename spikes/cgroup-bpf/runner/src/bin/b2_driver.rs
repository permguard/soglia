// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Diagnostic B2 driver over the production helpers, proxy and Candidate-A object.
//!
//! This is qualification code, not a second backend. It drives the public production lifecycle
//! protocol one operation at a time so every boundary can be observed, and injects at most one
//! named fault per negative case without changing production code.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
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
use soglia_supervisor::helpers::{
    CandidateAAttributor, Helper, HelperError, ResolveHealthFailure, ResolverClient,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const TIMEOUT_EARLY_TOLERANCE_MS: u64 = 100;
const SINGLE_TIMEOUT_LATE_TOLERANCE_MS: u64 = 100;
const CONCURRENT_TIMEOUT_LATE_TOLERANCE_MS: u64 = 250;
const C_TUPLE_INSERT_FAILED: u32 = 2;
const C_PUBLISHED: u32 = 3;
const C_UNPUBLISHED: u32 = 4;

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
            let started = Instant::now();
            let resolved = self.inner.resolve(peer, local).await;
            let (outcome, mismatch, _) = observed_result(&resolved);
            let observation = ConcurrentResolveObservation {
                peer,
                local,
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
    run_concurrent_timeout_case(&evidence, &config, &enforcer, Arc::clone(&outbound)).await?;
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
    enforcer: &Helper,
    outbound: Arc<AtomicUsize>,
) -> Result<(), String> {
    const CONCURRENT: usize = 4;
    let case_dir = evidence.join("cases/concurrent_timeout");
    fs::create_dir_all(&case_dir).map_err(|error| error.to_string())?;
    fs::write(evidence.join("current-case.txt"), "concurrent_timeout\n")
        .map_err(|error| error.to_string())?;
    fs::write(
        case_dir.join("scope.json"),
        serde_json::to_vec_pretty(&json!({
            "case": "CONCURRENT_TIMEOUT",
            "connections": CONCURRENT,
            "origin": "qualification host outside the executions cgroup subtree",
            "expected_tuple_publication": false,
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

    let observations = Arc::new(Mutex::new(Vec::new()));
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
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..CONCURRENT {
        clients.spawn(async move {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(&[b'x'; 61]).await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<(), io::Error>(())
        });
    }

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
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), proxy_task)
        .await
        .map_err(|_| "concurrent-timeout proxy did not stop".to_owned())?
        .map_err(|error| error.to_string())?;
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    dump_maps(config, &case_dir, "post-case")?;
    let tuple_insert_failed =
        counter_value_from_evidence(&case_dir, "post-case", C_TUPLE_INSERT_FAILED)?;
    fs::write(
        case_dir.join("counter-invariant.json"),
        serde_json::to_vec_pretty(&json!({
            "counter": "C_TUPLE_INSERT_FAILED",
            "index": C_TUPLE_INSERT_FAILED,
            "value": tuple_insert_failed,
            "expected": 0,
            "holds": tuple_insert_failed == 0
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    let observations = observations
        .lock()
        .map_err(|_| "concurrent observation lock poisoned".to_owned())?;
    fs::write(
        case_dir.join("resolve.json"),
        serde_json::to_vec_pretty(&*observations).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let result = if observations.len() != CONCURRENT {
        Err(format!(
            "observed {} of {CONCURRENT} concurrent Resolve calls",
            observations.len()
        ))
    } else if observations.iter().any(|observation| {
        observation.outcome != ObservedResolveOutcome::Timeout
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
        Err("a concurrent Resolve violated timeout, no-read, no-effect or health bounds".to_owned())
    } else if tuple_insert_failed != 0 {
        Err(format!(
            "C_TUPLE_INSERT_FAILED is {tuple_insert_failed}, expected 0"
        ))
    } else if health_failure
        .lock()
        .map_err(|_| "health observation lock poisoned".to_owned())?
        .is_some()
    {
        Err("concurrent timeout changed runtime health".to_owned())
    } else {
        Ok(())
    };
    drop(observations);
    if let Err(error) = &result {
        fs::write(case_dir.join("verdict.txt"), "FAIL\n").map_err(|write| write.to_string())?;
        fs::write(case_dir.join("failure.txt"), format!("{error}\n"))
            .map_err(|write| write.to_string())?;
    } else {
        enforcer
            .call(EnforcerRequest::Health)
            .await
            .map_err(|error| format!("post-concurrency backend health: {error}"))?;
        fs::write(case_dir.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    }
    result
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
    let concurrent_dir = evidence.join("cases/concurrent_timeout");
    let concurrent =
        counter_value_from_evidence(&concurrent_dir, "post-case", C_TUPLE_INSERT_FAILED)?;
    observations.push(json!({
        "case": "CONCURRENT_TIMEOUT",
        "stage": "post-case",
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
}
