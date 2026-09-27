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

use serde::Serialize;
use serde_json::{Value, json};
use soglia_core::config::Config;
use soglia_core::helper::{EnforcerRequest, HelperResponse, SandboxRequest};
use soglia_core::{BindingKey, ExecutionId, ExecutionNonce};
use soglia_proxy::attribution::{AttributionTable, Binding, ConnectionAttributor};
use soglia_proxy::egress::{EgressLimits, EgressProxy};
use soglia_proxy::policy::DestinationPolicy;
use soglia_proxy::resolver::{Resolution, Resolver};
use soglia_supervisor::helpers::{CandidateAAttributor, Helper, HelperError, ResolverClient};
use tokio::net::TcpListener;
use tokio::sync::watch;

const CASES: [Case; 8] = [
    Case::Positive,
    Case::WrongPid,
    Case::WrongCgroup,
    Case::NonceMismatch,
    Case::GenerationMismatch,
    Case::TupleByteOrder,
    Case::MissingCookie,
    Case::IpOnly,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Case {
    Positive,
    WrongPid,
    WrongCgroup,
    NonceMismatch,
    GenerationMismatch,
    TupleByteOrder,
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

#[derive(Serialize)]
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
    resolved_execution: Option<ExecutionId>,
    channel_loss: Option<String>,
}

struct ObservingAttributor {
    inner: Arc<dyn ConnectionAttributor>,
    case: Case,
    evidence: PathBuf,
    state: PathBuf,
    bpftool: PathBuf,
    dns: Arc<AtomicUsize>,
    outbound: Arc<AtomicUsize>,
    channel_loss: Arc<Mutex<Option<String>>>,
}

impl ConnectionAttributor for ObservingAttributor {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Option<Binding>> + Send + 'a>> {
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
                    return None;
                }
            }

            let (queried_peer, queried_local) = if self.case == Case::TupleByteOrder {
                (
                    SocketAddr::new(peer.ip(), peer.port().swap_bytes()),
                    SocketAddr::new(local.ip(), local.port().swap_bytes()),
                )
            } else {
                (peer, local)
            };
            if self.case == Case::TupleByteOrder {
                let _ = fs::write(
                    self.evidence.join("fault-injection.json"),
                    serde_json::to_vec_pretty(&json!({
                        "actor": "b2_driver qualification wrapper",
                        "fault": "TUPLE_BYTE_ORDER",
                        "original": {"peer": peer, "local": local},
                        "injected": {"peer": queried_peer, "local": queried_local},
                        "production_code_modified": false
                    }))
                    .unwrap_or_default(),
                );
            }
            let resolved = self.inner.resolve(queried_peer, queried_local).await;
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
                resolved_execution: resolved.as_ref().map(|binding| binding.id),
                channel_loss: self
                    .channel_loss
                    .lock()
                    .ok()
                    .and_then(|value| value.clone()),
            };
            let _ = fs::write(
                self.evidence.join("resolve.json"),
                serde_json::to_vec_pretty(&observation).unwrap_or_default(),
            );
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

    for case in CASES {
        let case_dir = evidence.join("cases").join(case.name());
        fs::create_dir_all(&case_dir).map_err(|error| error.to_string())?;
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
                "production_code_modified": false
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
        fs::write(case_dir.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())?;
    }
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
        fs::write(case_dir.join("verdict.txt"), "PASS\n")
            .map_err(|error| error.to_string())?;
    }
    fs::write(evidence.join("current-case.txt"), "complete\n")
        .map_err(|error| error.to_string())?;
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
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
        let channel_loss = Arc::new(Mutex::new(None));
        let resolver: ResolverClient = enforcer
            .resolver_client()
            .map_err(|error| error.to_string())?;
        let loss = Arc::clone(&channel_loss);
        let production: Arc<dyn ConnectionAttributor> = Arc::new(CandidateAAttributor::new(
            resolver,
            Arc::clone(&table),
            Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
            1,
            Arc::new(move |reason| {
                if let Ok(mut observed) = loss.lock() {
                    *observed = Some(reason);
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
            channel_loss,
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
        let observation: Value = serde_json::from_slice(
            &fs::read(evidence.join("resolve.json")).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let resolved = observation
            .get("resolved_execution")
            .and_then(Value::as_str);
        let recv_q = observation
            .get("recv_q_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let dns_at_resolve = observation
            .get("dns_when_resolve_returned")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        let outbound_at_resolve = observation
            .get("outbound_when_resolve_returned")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if recv_q == 0 || dns_at_resolve != 0 || outbound_at_resolve != 0 {
            return Err("pre-Resolve no-read/no-effect observation failed".to_owned());
        }
        if case == Case::Positive {
            let expected = id.to_string();
            if resolved != Some(expected.as_str()) {
                return Err("positive Resolve did not return the correct ExecutionId".to_owned());
            }
            wait_for_count(&dns, 1, Duration::from_secs(2)).await?;
            wait_for_count(&outbound, 1, Duration::from_secs(2)).await?;
        } else {
            if resolved.is_some() {
                return Err("negative case resolved an Execution".to_owned());
            }
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
    let owned_net = fs::metadata(Path::new("/run/netns").join(id.tag().netns_name()))
        .map_err(|error| error.to_string())?;
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
            "netns": {"agent_inode": std::os::unix::fs::MetadataExt::ino(&agent_net),
                      "owned_inode": std::os::unix::fs::MetadataExt::ino(&owned_net),
                      "matches": std::os::unix::fs::MetadataExt::ino(&agent_net) == std::os::unix::fs::MetadataExt::ino(&owned_net)}
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
