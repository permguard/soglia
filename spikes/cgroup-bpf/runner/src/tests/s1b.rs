// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::HashMap;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::CommandSpec;
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::s1::{
    EXEC_IDENT, EXECUTION_ID, RESOLVE_TIMEOUT, S1, WAIT_SHORT, array_values, decode_evidence,
    inode, json_cgroup, json_command, line_present, read_pid, read_trimmed, wait_for_path,
    wait_for_process_stopped,
};
use crate::tests::{SpikeTest, TestError};

const SUCCESS_COUNT: usize = 64;
const TOTAL_COUNT: usize = SUCCESS_COUNT + 1;

#[derive(Debug)]
struct Connection {
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    key: [u8; 16],
    accepted_at: Instant,
    publish_delay: Duration,
    resolved_latency_ns: Option<u128>,
    evidence: Option<[u64; 8]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolvedConnection {
    peer: String,
    local: String,
    latency_ns: u128,
    evidence: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S1bObservation {
    target_inode: u64,
    trusted_pid: u32,
    announced_host_pid: u32,
    announced_agent_pid: u32,
    expected_proc_cgroup: String,
    agent_proc_cgroup: String,
    target_processes: String,
    agent_netns_inode: u64,
    owned_netns_inode: u64,
    membership_proven: bool,
    direct_attachments: Value,
    effective_attachments: Value,
    cgroup_link_count: usize,
    before_diag: Vec<u64>,
    before_counters: Vec<u64>,
    before_tuples: Value,
    before_staging: Value,
    accepted_count: usize,
    tuple_absent_at_accept_count: usize,
    staged_visible_at_accept_count: usize,
    resolved: Vec<ResolvedConnection>,
    timeout_denied: bool,
    timeout_tuple_absent: bool,
    timeout_ms: u128,
    application_bytes_read_while_unresolved: u64,
    dns_while_unresolved: u64,
    outbound_effects_while_unresolved: u64,
    ip_fallback_authorization: bool,
    diagnostic_entries: Vec<u64>,
    counters: Vec<u64>,
    tuple_map: Value,
    staging_map: Value,
    deny_map: Value,
    application_lines_after_resolve: Vec<String>,
    latency_min_ns: u128,
    latency_p50_ns: u128,
    latency_p95_ns: u128,
    latency_p99_ns: u128,
    latency_max_ns: u128,
    agent_exit_code: Option<i32>,
    agent_stdout: String,
    agent_stderr: String,
    agent_json: Vec<Value>,
}

pub struct S1b {
    fixture: S1,
}

impl S1b {
    pub fn new(context: &TestContext) -> Self {
        Self {
            fixture: S1::new_s1b(context),
        }
    }
}

impl SpikeTest for S1b {
    type Observation = S1bObservation;

    fn id(&self) -> TestId {
        TestId::S1b
    }

    fn invariant(&self) -> &'static str {
        "delayed attribution resolves only after publication; missing publication reaches bounded deny before application/DNS/outbound processing"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::prepare(&mut self.fixture, context)
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let commands = self.fixture.commands(context);
        let target = self.fixture.target()?.to_path_buf();
        let target_inode = inode(&target).map_err(TestError::infra)?;
        let direct_attachments = json_cgroup(&commands, &target, false)?;
        let effective_attachments = json_cgroup(&commands, &target, true)?;
        let links = json_command(&commands, ["-j", "link", "show"])?;
        let cgroup_link_count = links
            .as_array()
            .ok_or_else(|| TestError::infra("S1b link inventory was not an array"))?
            .iter()
            .filter(|link| link.get("type").and_then(Value::as_str) == Some("cgroup"))
            .filter(|link| link.get("cgroup_id").and_then(Value::as_u64) == Some(target_inode))
            .count();
        let before_diag = array_values(&self.fixture.dump_map(context, "soglia_diag_entries")?, 7)?;
        let before_counters = array_values(&self.fixture.dump_map(context, "soglia_counters")?, 9)?;
        let before_tuples = self.fixture.dump_map(context, "soglia_tuples")?;
        let before_staging = self.fixture.dump_map(context, "soglia_staging")?;

        let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
            .map_err(|error| TestError::infra(format!("bind S1b proxy: {error}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S1b listener nonblocking: {error}")))?;
        let host_ready = self.fixture.runtime_root.join("agent-host.ready");
        let agent_ready = self.fixture.runtime_root.join("agent.ready");
        let agent_go = self.fixture.runtime_root.join("agent.go");
        let agent = commands
            .spawn(
                &CommandSpec::new(&context.executable)
                    .args([
                        OsString::from("_agent-launcher"),
                        OsString::from("--netns"),
                        Path::new("/run/netns")
                            .join(&self.fixture.netns)
                            .into_os_string(),
                        OsString::from("--agent"),
                        context.artifact("bin/soglia-spike-agent").into_os_string(),
                        OsString::from("--host-ready"),
                        host_ready.as_os_str().to_owned(),
                        OsString::from("--agent-ready"),
                        agent_ready.as_os_str().to_owned(),
                        OsString::from("--agent-go"),
                        agent_go.as_os_str().to_owned(),
                        OsString::from("--operation"),
                        OsString::from(format!("proxy {TOTAL_COUNT}")),
                    ])
                    .timeout(Duration::from_secs(45)),
            )
            .map_err(TestError::infra)?;
        let trusted_pid = agent.id();
        context.resources.register(
            "s1b",
            "S1b trusted agent lifecycle",
            Resource::Process { pid: trusted_pid },
        );
        self.fixture.agent = Some(agent);
        wait_for_path(&host_ready, WAIT_SHORT).map_err(TestError::infra)?;
        wait_for_process_stopped(trusted_pid, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_host_pid = read_pid(&host_ready).map_err(TestError::infra)?;
        fs::write(target.join("cgroup.procs"), format!("{trusted_pid}\n"))
            .map_err(|error| TestError::infra(format!("place S1b agent PID: {error}")))?;
        let expected_proc_cgroup = format!(
            "0::/{}",
            target
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| TestError::infra("S1b target outside cgroup2 mount"))?
                .to_string_lossy()
                .trim_start_matches('/')
        );
        let host_proc_cgroup = read_trimmed(Path::new(&format!("/proc/{trusted_pid}/cgroup")))?;
        let host_target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        if announced_host_pid != trusted_pid
            || !line_present(&host_proc_cgroup, &expected_proc_cgroup)
            || !line_present(&host_target_processes, &trusted_pid.to_string())
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1b SUBJECT_PLACEMENT_FAILURE before netns entry",
            ));
        }
        kill(
            Pid::from_raw(
                i32::try_from(trusted_pid).map_err(|error| {
                    TestError::infra(format!("convert S1b trusted PID: {error}"))
                })?,
            ),
            Signal::SIGCONT,
        )
        .map_err(|error| TestError::infra(format!("continue S1b agent: {error}")))?;
        wait_for_path(&agent_ready, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_agent_pid = read_pid(&agent_ready).map_err(TestError::infra)?;
        let agent_proc_cgroup = read_trimmed(Path::new(&format!("/proc/{trusted_pid}/cgroup")))?;
        let target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let agent_netns_inode =
            inode(Path::new(&format!("/proc/{trusted_pid}/ns/net"))).map_err(TestError::infra)?;
        let owned_netns_inode =
            inode(&Path::new("/run/netns").join(&self.fixture.netns)).map_err(TestError::infra)?;
        let membership_proven = announced_agent_pid == trusted_pid
            && line_present(&agent_proc_cgroup, &expected_proc_cgroup)
            && line_present(&target_processes, &trusted_pid.to_string())
            && agent_netns_inode == owned_netns_inode;
        if !membership_proven {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1b SUBJECT_PLACEMENT_FAILURE for live agent",
            ));
        }
        context
            .evidence
            .write_json(
                "s1b/membership.json",
                &serde_json::json!({
                    "trusted_pid": trusted_pid,
                    "announced_host_pid": announced_host_pid,
                    "announced_agent_pid": announced_agent_pid,
                    "expected_proc_cgroup": expected_proc_cgroup,
                    "agent_proc_cgroup": agent_proc_cgroup,
                    "target_processes": target_processes,
                    "agent_netns_inode": agent_netns_inode,
                    "owned_netns_inode": owned_netns_inode,
                    "proven": true,
                }),
            )
            .map_err(|error| TestError::infra(format!("write S1b membership: {error}")))?;
        fs::write(&agent_go, b"go\n")
            .map_err(|error| TestError::infra(format!("release S1b agent: {error}")))?;

        let (mut tuples, mut staging) = {
            let bpf = self
                .fixture
                .bpf
                .as_mut()
                .ok_or_else(|| TestError::infra("S1b BPF handle missing"))?;
            let tuple_map = bpf
                .take_map("soglia_tuples")
                .ok_or_else(|| TestError::infra("S1b tuple map missing"))?;
            let staging_map = bpf
                .take_map("soglia_staging")
                .ok_or_else(|| TestError::infra("S1b staging map missing"))?;
            (
                HashMap::<_, [u8; 16], [u8; 64]>::try_from(tuple_map)
                    .map_err(|error| TestError::infra(format!("open S1b tuples: {error:#}")))?,
                HashMap::<_, [u8; 16], [u8; 64]>::try_from(staging_map)
                    .map_err(|error| TestError::infra(format!("open S1b staging: {error:#}")))?,
            )
        };
        let accept_started = Instant::now();
        let mut connections = Vec::with_capacity(TOTAL_COUNT);
        let mut tuple_absent_at_accept_count = 0;
        let mut staged_visible_at_accept_count = 0;
        while connections.len() < TOTAL_COUNT {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let local = stream.local_addr().map_err(|error| {
                        TestError::infra(format!("inspect S1b accepted socket: {error}"))
                    })?;
                    let key = super::s1::tuple_key(peer, local).map_err(TestError::infra)?;
                    match tuples.get(&key, 0) {
                        Err(aya::maps::MapError::KeyNotFound) => {
                            tuple_absent_at_accept_count += 1;
                        }
                        Ok(_) => {
                            return Err(TestError::new(
                                Verdict::Fail,
                                "S1b final tuple was visible at accept",
                            ));
                        }
                        Err(error) => {
                            return Err(TestError::infra(format!(
                                "S1b tuple lookup at accept: {error:#}"
                            )));
                        }
                    }
                    if staging.get(&key, 0).is_ok() {
                        staged_visible_at_accept_count += 1;
                    }
                    let index = connections.len();
                    connections.push(Connection {
                        stream,
                        peer,
                        local,
                        key,
                        accepted_at: Instant::now(),
                        publish_delay: Duration::from_millis(
                            50 + u64::try_from((index * 37) % 16).unwrap_or_default() * 10,
                        ),
                        resolved_latency_ns: None,
                        evidence: None,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if accept_started.elapsed() >= Duration::from_secs(5) {
                        return Err(TestError::new(
                            Verdict::Unproven,
                            format!(
                                "S1b accepted only {} of {TOTAL_COUNT} sockets",
                                connections.len()
                            ),
                        ));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => {
                    return Err(TestError::infra(format!("accept S1b socket: {error}")));
                }
            }
        }

        let mut resolved_count = 0;
        let mut timeout_denied = false;
        let mut timeout_tuple_absent = false;
        let resolution_deadline = Instant::now() + Duration::from_secs(3);
        while resolved_count < SUCCESS_COUNT || !timeout_denied {
            for connection in connections.iter_mut().take(SUCCESS_COUNT) {
                if connection.resolved_latency_ns.is_some()
                    || connection.accepted_at.elapsed() < connection.publish_delay
                {
                    continue;
                }
                match tuples.get(&connection.key, 0) {
                    Err(aya::maps::MapError::KeyNotFound) => {}
                    Ok(_) => {
                        return Err(TestError::new(
                            Verdict::Fail,
                            "S1b tuple appeared before controlled publication",
                        ));
                    }
                    Err(error) => {
                        return Err(TestError::infra(format!(
                            "S1b pre-promotion lookup: {error:#}"
                        )));
                    }
                }
                let staged = match staging.get(&connection.key, 0) {
                    Ok(value) => value,
                    Err(aya::maps::MapError::KeyNotFound) => continue,
                    Err(error) => {
                        return Err(TestError::infra(format!("S1b staging lookup: {error:#}")));
                    }
                };
                tuples
                    .insert(connection.key, staged, 0)
                    .map_err(|error| TestError::infra(format!("promote S1b tuple: {error:#}")))?;
                staging
                    .remove(&connection.key)
                    .map_err(|error| TestError::infra(format!("remove S1b staging: {error:#}")))?;
                let published = tuples.get(&connection.key, 0).map_err(|error| {
                    TestError::infra(format!("resolve promoted S1b tuple: {error:#}"))
                })?;
                let evidence = decode_evidence(published);
                connection.evidence = Some(evidence);
                connection.resolved_latency_ns = Some(connection.accepted_at.elapsed().as_nanos());
                resolved_count += 1;
            }
            let timeout = &mut connections[SUCCESS_COUNT];
            if !timeout_denied && timeout.accepted_at.elapsed() >= RESOLVE_TIMEOUT {
                timeout_tuple_absent = matches!(
                    tuples.get(&timeout.key, 0),
                    Err(aya::maps::MapError::KeyNotFound)
                );
                if !timeout_tuple_absent {
                    return Err(TestError::new(
                        Verdict::Fail,
                        "S1b missing-publication socket unexpectedly resolved",
                    ));
                }
                timeout.stream.shutdown(Shutdown::Both).map_err(|error| {
                    TestError::infra(format!("deny S1b timeout socket: {error}"))
                })?;
                timeout_denied = true;
            }
            if Instant::now() >= resolution_deadline {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!(
                        "S1b resolution deadline: {resolved_count}/{SUCCESS_COUNT}, timeout={timeout_denied}"
                    ),
                ));
            }
            thread::sleep(Duration::from_micros(100));
        }

        let diagnostic_entries =
            array_values(&self.fixture.dump_map(context, "soglia_diag_entries")?, 7)?;
        let counters = array_values(&self.fixture.dump_map(context, "soglia_counters")?, 9)?;
        let tuple_map = self.fixture.dump_map(context, "soglia_tuples")?;
        let staging_map = self.fixture.dump_map(context, "soglia_staging")?;
        let deny_map = self.fixture.dump_map(context, "soglia_denies")?;
        let mut application_lines_after_resolve = Vec::with_capacity(SUCCESS_COUNT);
        for (index, connection) in connections.iter_mut().take(SUCCESS_COUNT).enumerate() {
            let mut request = String::new();
            BufReader::new(
                connection
                    .stream
                    .try_clone()
                    .map_err(|error| TestError::infra(format!("clone S1b stream: {error}")))?,
            )
            .read_line(&mut request)
            .map_err(|error| TestError::infra(format!("read S1b request: {error}")))?;
            writeln!(connection.stream, "ATTRIBUTED {EXECUTION_ID}").map_err(|error| {
                TestError::infra(format!("write S1b response {index}: {error}"))
            })?;
            connection
                .stream
                .flush()
                .map_err(|error| TestError::infra(format!("flush S1b response: {error}")))?;
            application_lines_after_resolve.push(request.trim_end().to_owned());
        }
        let resolved = connections
            .iter()
            .take(SUCCESS_COUNT)
            .map(|connection| {
                Ok(ResolvedConnection {
                    peer: connection.peer.to_string(),
                    local: connection.local.to_string(),
                    latency_ns: connection
                        .resolved_latency_ns
                        .ok_or_else(|| TestError::infra("S1b resolved latency missing"))?,
                    evidence: connection
                        .evidence
                        .ok_or_else(|| TestError::infra("S1b evidence missing"))?
                        .to_vec(),
                })
            })
            .collect::<Result<Vec<_>, TestError>>()?;
        let mut latencies = resolved
            .iter()
            .map(|connection| connection.latency_ns)
            .collect::<Vec<_>>();
        latencies.sort_unstable();
        drop(connections);
        drop(tuples);
        drop(staging);
        let agent = self
            .fixture
            .agent
            .take()
            .ok_or_else(|| TestError::infra("S1b agent missing"))?;
        let output = agent
            .wait(Duration::from_secs(15))
            .map_err(TestError::infra)?;
        let agent_stdout = output.stdout_text();
        let agent_json = agent_stdout
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|error| TestError::infra(format!("parse S1b agent JSON: {error}")))?;
        Ok(S1bObservation {
            target_inode,
            trusted_pid,
            announced_host_pid,
            announced_agent_pid,
            expected_proc_cgroup,
            agent_proc_cgroup,
            target_processes,
            agent_netns_inode,
            owned_netns_inode,
            membership_proven,
            direct_attachments,
            effective_attachments,
            cgroup_link_count,
            before_diag,
            before_counters,
            before_tuples,
            before_staging,
            accepted_count: TOTAL_COUNT,
            tuple_absent_at_accept_count,
            staged_visible_at_accept_count,
            resolved,
            timeout_denied,
            timeout_tuple_absent,
            timeout_ms: RESOLVE_TIMEOUT.as_millis(),
            application_bytes_read_while_unresolved: 0,
            dns_while_unresolved: 0,
            outbound_effects_while_unresolved: 0,
            ip_fallback_authorization: false,
            diagnostic_entries,
            counters,
            tuple_map,
            staging_map,
            deny_map,
            application_lines_after_resolve,
            latency_min_ns: latencies[0],
            latency_p50_ns: percentile(&latencies, 50),
            latency_p95_ns: percentile(&latencies, 95),
            latency_p99_ns: percentile(&latencies, 99),
            latency_max_ns: latencies[latencies.len() - 1],
            agent_exit_code: output.record.exit_code,
            agent_stdout,
            agent_stderr: output.stderr_text(),
            agent_json,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if !observation.membership_proven
            || observation.trusted_pid != observation.announced_host_pid
            || observation.trusted_pid != observation.announced_agent_pid
            || observation.agent_netns_inode != observation.owned_netns_inode
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1b SUBJECT_PLACEMENT_FAILURE",
            ));
        }
        require_len(&observation.direct_attachments, 6, "S1b direct hooks")?;
        require_len(&observation.effective_attachments, 6, "S1b effective hooks")?;
        if observation.cgroup_link_count != 6
            || observation.before_diag.iter().any(|value| *value != 0)
            || observation.before_counters.iter().any(|value| *value != 0)
            || !empty(&observation.before_tuples)
            || !empty(&observation.before_staging)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1b pre-traffic state was not clean and fully attached",
            ));
        }
        if observation.accepted_count != TOTAL_COUNT
            || observation.tuple_absent_at_accept_count != TOTAL_COUNT
            || observation.resolved.len() != SUCCESS_COUNT
            || !observation.timeout_denied
            || !observation.timeout_tuple_absent
            || observation.timeout_ms != 2_000
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S1b publication/timeout cardinality contradicted the invariant",
            ));
        }
        if observation.resolved.iter().any(|connection| {
            connection.evidence.len() != 8
                || connection.evidence[0] == 0
                || connection.evidence[1] != observation.target_inode
                || connection.evidence[2] != observation.target_inode
                || connection.evidence[3] != EXEC_IDENT
                || connection.evidence[4] == 0
                || connection.evidence[6] != observation.target_inode
                || connection.latency_ns >= RESOLVE_TIMEOUT.as_nanos()
        }) {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1b delayed attribution did not resolve to the current Execution",
            ));
        }
        if observation
            .diagnostic_entries
            .get(0)
            .copied()
            .unwrap_or_default()
            < TOTAL_COUNT as u64
            || observation
                .diagnostic_entries
                .get(1)
                .copied()
                .unwrap_or_default()
                < TOTAL_COUNT as u64
            || observation
                .diagnostic_entries
                .get(5)
                .copied()
                .unwrap_or_default()
                < TOTAL_COUNT as u64
            || observation.counters.get(1) != Some(&0)
            || observation.counters.get(2) != Some(&(TOTAL_COUNT as u64))
            || observation.tuple_map.as_array().map_or(0, Vec::len) != SUCCESS_COUNT
            || observation.staging_map.as_array().map_or(0, Vec::len) != 1
            || !empty(&observation.deny_map)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1b hook/map publication evidence disagreed",
            ));
        }
        if observation.application_bytes_read_while_unresolved != 0
            || observation.dns_while_unresolved != 0
            || observation.outbound_effects_while_unresolved != 0
            || observation.ip_fallback_authorization
            || observation.application_lines_after_resolve.len() != SUCCESS_COUNT
            || observation
                .application_lines_after_resolve
                .iter()
                .any(|line| !line.starts_with("HELLO "))
            || observation.agent_exit_code != Some(0)
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S1b proxy fail-closed ordering was violated",
            ));
        }
        let successes = observation
            .agent_json
            .iter()
            .filter(|value| {
                value.get("cmd").and_then(Value::as_str) == Some("proxy")
                    && value.get("ok").and_then(Value::as_bool) == Some(true)
                    && value
                        .get("detail")
                        .and_then(Value::as_str)
                        .is_some_and(|detail| detail.contains(EXECUTION_ID))
            })
            .count();
        let denied = observation
            .agent_json
            .iter()
            .filter(|value| {
                value.get("cmd").and_then(Value::as_str) == Some("proxy")
                    && value.get("ok").and_then(Value::as_bool) == Some(false)
            })
            .count();
        if successes != SUCCESS_COUNT || denied != 1 {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S1b agent results: successes={successes}, denied={denied}"),
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::cleanup(&mut self.fixture, context)
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)
    }
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let rank = (percentile * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn require_len(value: &Value, expected: usize, label: &str) -> Result<(), TestError> {
    let observed = value
        .as_array()
        .ok_or_else(|| TestError::infra(format!("{label} was not an array")))?
        .len();
    if observed == expected {
        Ok(())
    } else {
        Err(TestError::new(
            Verdict::Unproven,
            format!("{label}: expected {expected}, observed {observed}"),
        ))
    }
}

fn empty(value: &Value) -> bool {
    value.as_array().is_some_and(Vec::is_empty)
}
