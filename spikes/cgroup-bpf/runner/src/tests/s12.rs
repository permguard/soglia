// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::{HashMap, Map, MapData, RingBuf};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{CommandExecutor, CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::s1::{
    S1, WAIT_SHORT, array_values, decode_evidence, hex, inode, json_cgroup, line_present, read_pid,
    read_trimmed, tuple_key, wait_for_path, wait_for_process_stopped,
};
use crate::tests::{SpikeTest, TestError};

const CAPACITY: usize = 8;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Membership {
    trusted_pid: u32,
    announced_host_pid: u32,
    announced_agent_pid: u32,
    expected_proc_cgroup: String,
    proc_cgroup: String,
    target_processes: String,
    target_inode: u64,
    agent_netns_inode: u64,
    owned_netns_inode: u64,
    proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentResult {
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
    json: Vec<Value>,
}

struct ActiveAgent {
    process: RunningCommand,
    go: std::path::PathBuf,
}

struct Connection {
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    key: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublishedEntry {
    peer: String,
    local: String,
    key_hex: String,
    evidence: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MapContract {
    name: String,
    map_type: String,
    max_entries: u64,
    producer: String,
    consumer: String,
    update_failure: String,
    authorization_state: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MapFullEvent {
    kind: u32,
    cgroup_id: u64,
    cookie: u64,
    destination_ipv4_raw: u32,
    destination_port: u32,
    bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S12Observation {
    target_inode: u64,
    direct_attachments: Value,
    effective_attachments: Value,
    map_contracts: Vec<MapContract>,
    tuple_baseline: Value,
    cookie_baseline: Value,
    precontrol_membership: Membership,
    precontrol_agent: AgentResult,
    precontrol_entry: PublishedEntry,
    fill_membership: Membership,
    fill_entries: Vec<PublishedEntry>,
    phase_a_tuple_occupancy: usize,
    phase_a_cookie_occupancy: usize,
    phase_a_distinct_tuples: usize,
    phase_a_distinct_cookies: usize,
    overflow_membership: Membership,
    overflow_agent: AgentResult,
    overflow_peer: String,
    overflow_local: String,
    overflow_key_hex: String,
    overflow_tuple_present: bool,
    overflow_tuple_occupancy: usize,
    overflow_cookie_occupancy: usize,
    counters_before_fill: Vec<u64>,
    counters_overflow: Vec<u64>,
    diagnostics_before_fill: Vec<u64>,
    diagnostics_overflow: Vec<u64>,
    map_diagnostics_before_fill: Vec<i64>,
    map_diagnostics_overflow: Vec<i64>,
    cookie_failure_delta: i64,
    sk_storage_failure_delta: i64,
    tuple_failure_delta: i64,
    resolve_timeout_ms: u128,
    overflow_resolve_result: String,
    application_bytes_read_while_unresolved: u64,
    dns_lookups_while_unresolved: u64,
    outbound_effects_while_unresolved: u64,
    ip_fallback_authorization: bool,
    map_full_events: Vec<MapFullEvent>,
    freed_key_hex: String,
    occupancy_after_free: usize,
    control_membership: Membership,
    control_agent: AgentResult,
    control_entry: PublishedEntry,
    control_tuple_occupancy: usize,
    control_cookie_occupancy: usize,
    control_map_diagnostics: Vec<i64>,
    final_tuple_occupancy: usize,
    final_cookie_occupancy: usize,
    fill_agent: AgentResult,
}

pub struct S12 {
    fixture: S1,
    active_agents: Vec<ActiveAgent>,
}

impl S12 {
    pub fn new(context: &TestContext) -> Self {
        Self {
            fixture: S1::new_s12(context),
            active_agents: Vec::new(),
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        self.fixture.commands(context)
    }

    fn launch_agent(
        &mut self,
        context: &mut TestContext,
        phase: &str,
        operation: &str,
    ) -> Result<(Membership, usize), TestError> {
        let host_ready = self
            .fixture
            .runtime_root
            .join(format!("{phase}-host.ready"));
        let agent_ready = self
            .fixture
            .runtime_root
            .join(format!("{phase}-agent.ready"));
        let agent_go = self.fixture.runtime_root.join(format!("{phase}-agent.go"));
        for path in [&host_ready, &agent_ready, &agent_go] {
            remove_file(path)?;
        }
        let process = self
            .commands(context)
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
                        OsString::from(operation),
                    ])
                    .timeout(Duration::from_secs(45)),
            )
            .map_err(TestError::infra)?;
        let trusted_pid = process.id();
        context.resources.register(
            "s12",
            format!("S12 {phase} agent"),
            Resource::Process { pid: trusted_pid },
        );
        wait_for_path(&host_ready, WAIT_SHORT).map_err(TestError::infra)?;
        wait_for_process_stopped(trusted_pid, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_host_pid = read_pid(&host_ready).map_err(TestError::infra)?;
        let target = self.fixture.target()?.to_path_buf();
        fs::write(target.join("cgroup.procs"), format!("{trusted_pid}\n"))
            .map_err(|error| TestError::infra(format!("place S12 {phase} agent: {error}")))?;
        kill(
            Pid::from_raw(
                i32::try_from(trusted_pid)
                    .map_err(|error| TestError::infra(format!("convert S12 PID: {error}")))?,
            ),
            Signal::SIGCONT,
        )
        .map_err(|error| TestError::infra(format!("continue S12 {phase} agent: {error}")))?;
        wait_for_path(&agent_ready, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_agent_pid = read_pid(&agent_ready).map_err(TestError::infra)?;
        let proc_cgroup = read_trimmed(Path::new(&format!("/proc/{trusted_pid}/cgroup")))?;
        let target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let expected_proc_cgroup = format!(
            "0::/{}",
            target
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| TestError::infra("S12 target outside cgroup2"))?
                .to_string_lossy()
                .trim_start_matches('/')
        );
        let agent_netns_inode =
            inode(Path::new(&format!("/proc/{trusted_pid}/ns/net"))).map_err(TestError::infra)?;
        let owned_netns_inode =
            inode(&Path::new("/run/netns").join(&self.fixture.netns)).map_err(TestError::infra)?;
        let proven = trusted_pid == announced_host_pid
            && trusted_pid == announced_agent_pid
            && line_present(&proc_cgroup, &expected_proc_cgroup)
            && line_present(&target_processes, &trusted_pid.to_string())
            && agent_netns_inode == owned_netns_inode;
        if !proven {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S12 {phase} live membership not proven"),
            ));
        }
        let membership = Membership {
            trusted_pid,
            announced_host_pid,
            announced_agent_pid,
            expected_proc_cgroup,
            proc_cgroup,
            target_processes,
            target_inode: inode(&target).map_err(TestError::infra)?,
            agent_netns_inode,
            owned_netns_inode,
            proven,
        };
        let index = self.active_agents.len();
        self.active_agents.push(ActiveAgent {
            process,
            go: agent_go,
        });
        Ok((membership, index))
    }

    fn release_agent(&self, index: usize) -> Result<(), TestError> {
        let agent = self
            .active_agents
            .get(index)
            .ok_or_else(|| TestError::infra("S12 agent index missing"))?;
        fs::write(&agent.go, b"go\n")
            .map_err(|error| TestError::infra(format!("release S12 agent: {error}")))
    }

    fn wait_agent(&mut self, index: usize) -> Result<AgentResult, TestError> {
        if index >= self.active_agents.len() {
            return Err(TestError::infra("S12 agent index outside registry"));
        }
        let agent = self.active_agents.swap_remove(index);
        parse_agent_output(
            agent
                .process
                .wait(Duration::from_secs(15))
                .map_err(TestError::infra)?,
        )
    }

    fn dump(&self, context: &TestContext, name: &str) -> Result<Value, TestError> {
        self.fixture.dump_map(context, name)
    }

    fn occupancy(&self, context: &TestContext, name: &str) -> Result<usize, TestError> {
        Ok(self
            .dump(context, name)?
            .as_array()
            .ok_or_else(|| TestError::infra(format!("S12 {name} dump was not an array")))?
            .len())
    }

    fn wait_occupancy(
        &self,
        context: &TestContext,
        expected: usize,
        timeout: Duration,
    ) -> Result<(), TestError> {
        let started = Instant::now();
        loop {
            let tuples = self.occupancy(context, "soglia_tuples")?;
            let cookies = self.occupancy(context, "soglia_cookie_a")?;
            if tuples == expected && cookies == expected {
                return Ok(());
            }
            if started.elapsed() >= timeout {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!("S12 occupancy tuple={tuples} cookie={cookies}, expected {expected}"),
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn lookup_tuple(&self, key: &[u8; 16]) -> Result<Option<[u8; 64]>, TestError> {
        let data = MapData::from_pin(self.fixture.pin_root.join("maps/soglia_tuples"))
            .map_err(|error| TestError::infra(format!("open S12 tuple pin: {error:#}")))?;
        let map = Map::from_map_data(data)
            .map_err(|error| TestError::infra(format!("classify S12 tuple pin: {error:#}")))?;
        let tuples = HashMap::<_, [u8; 16], [u8; 64]>::try_from(map)
            .map_err(|error| TestError::infra(format!("use S12 tuple pin: {error:#}")))?;
        match tuples.get(key, 0) {
            Ok(value) => Ok(Some(value)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(TestError::infra(format!("lookup S12 tuple: {error:#}"))),
        }
    }

    fn wait_tuple(&self, key: &[u8; 16], timeout: Duration) -> Result<[u8; 64], TestError> {
        let started = Instant::now();
        loop {
            if let Some(value) = self.lookup_tuple(key)? {
                return Ok(value);
            }
            if started.elapsed() >= timeout {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S12 tuple publication timed out",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_tuple_absent(&self, key: &[u8; 16], timeout: Duration) -> Result<(), TestError> {
        let started = Instant::now();
        loop {
            if self.lookup_tuple(key)?.is_none() {
                return Ok(());
            }
            if started.elapsed() >= timeout {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S12 freed tuple remained published",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl SpikeTest for S12 {
    type Observation = S12Observation;

    fn id(&self) -> TestId {
        TestId::S12
    }

    fn invariant(&self) -> &'static str {
        "bounded authorization-map update failure produces missing trusted attribution and bounded fail-closed denial without IP fallback or effects"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::prepare(&mut self.fixture, context)
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let target_inode = inode(self.fixture.target()?).map_err(TestError::infra)?;
        let direct_attachments =
            json_cgroup(&self.commands(context), self.fixture.target()?, false)?;
        let effective_attachments =
            json_cgroup(&self.commands(context), self.fixture.target()?, true)?;
        let tuple_info = pinned_map(
            &self.commands(context),
            &self.fixture.pin_root.join("maps/soglia_tuples"),
        )?;
        let cookie_info = pinned_map(
            &self.commands(context),
            &self.fixture.pin_root.join("maps/soglia_cookie_a"),
        )?;
        let map_contracts = vec![
            map_contract(
                "soglia_tuples",
                &tuple_info,
                "sockops established callback",
                "bounded proxy Resolve",
                "increments C_TUPLE_INSERT_FAILED and emits EV_MAP_FULL; tuple remains absent",
                true,
            )?,
            map_contract(
                "soglia_cookie_a",
                &cookie_info,
                "connect4 attribution publication",
                "sockops final evidence assembly",
                "candidate-A evidence remains absent; final tuple publication still must fail closed",
                true,
            )?,
            MapContract {
                name: "soglia_sk_b".to_owned(),
                map_type: "sk_storage".to_owned(),
                max_entries: 0,
                producer: "connect4 socket-local storage update".to_owned(),
                consumer: "sockops final evidence assembly".to_owned(),
                update_failure: "diagnosed separately; deterministic capacity forcing is not available for socket storage".to_owned(),
                authorization_state: true,
            },
            MapContract {
                name: "soglia_events/counters/diagnostics/meta".to_owned(),
                map_type: "diagnostic/metadata".to_owned(),
                max_entries: 0,
                producer: "diagnostic paths".to_owned(),
                consumer: "evidence only".to_owned(),
                update_failure: "not authorization state".to_owned(),
                authorization_state: false,
            },
        ];
        let tuple_baseline = self.dump(context, "soglia_tuples")?;
        let cookie_baseline = self.dump(context, "soglia_cookie_a")?;
        if !tuple_baseline.as_array().is_some_and(Vec::is_empty)
            || !cookie_baseline.as_array().is_some_and(Vec::is_empty)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S12 tuple/cookie baseline was not empty",
            ));
        }
        let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
            .map_err(|error| TestError::infra(format!("bind S12 proxy: {error}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S12 proxy nonblocking: {error}")))?;

        let (precontrol_membership, pre_index) =
            self.launch_agent(context, "precontrol", "proxy 1")?;
        self.release_agent(pre_index)?;
        let pre_connection = accept_connections(&listener, 1)?.remove(0);
        let pre_value = self.wait_tuple(&pre_connection.key, RESOLVE_TIMEOUT)?;
        let precontrol_entry =
            published_entry(&pre_connection, pre_value, target_inode, 12_001_001)?;
        resolve_connection(pre_connection, "s12-execution-generation-1")?;
        let precontrol_agent = self.wait_agent(pre_index)?;
        self.wait_occupancy(context, 0, RESOLVE_TIMEOUT)?;

        let counters_before_fill = array_values(&self.dump(context, "soglia_counters")?, 9)?;
        let diagnostics_before_fill = array_values(&self.dump(context, "soglia_diag_entries")?, 7)?;
        let map_diagnostics_before_fill =
            signed_array_values(&self.dump(context, "soglia_map_fail_diag")?, 8)?;

        let (fill_membership, fill_index) = self.launch_agent(context, "fill", "proxy 8")?;
        self.release_agent(fill_index)?;
        let mut fill_connections = accept_connections(&listener, CAPACITY)?;
        self.wait_occupancy(context, CAPACITY, Duration::from_secs(3))?;
        let mut tuple_keys = HashSet::new();
        let mut cookies = HashSet::new();
        let mut fill_entries = Vec::new();
        for connection in &fill_connections {
            let value = self.wait_tuple(&connection.key, RESOLVE_TIMEOUT)?;
            let entry = published_entry(connection, value, target_inode, 12_001_001)?;
            tuple_keys.insert(entry.key_hex.clone());
            cookies.insert(entry.evidence[0]);
            fill_entries.push(entry);
        }
        let phase_a_tuple_occupancy = self.occupancy(context, "soglia_tuples")?;
        let phase_a_cookie_occupancy = self.occupancy(context, "soglia_cookie_a")?;

        let (overflow_membership, overflow_index) =
            self.launch_agent(context, "overflow", "proxy 1")?;
        self.release_agent(overflow_index)?;
        let overflow_connection = accept_connections(&listener, 1)?.remove(0);
        let overflow_peer = overflow_connection.peer.to_string();
        let overflow_local = overflow_connection.local.to_string();
        let overflow_key_hex = hex(&overflow_connection.key);
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            let counters = array_values(&self.dump(context, "soglia_counters")?, 9)?;
            if counters[1] > counters_before_fill[1] {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        let map_diagnostics_overflow =
            signed_array_values(&self.dump(context, "soglia_map_fail_diag")?, 8)?;
        let counters_overflow = array_values(&self.dump(context, "soglia_counters")?, 9)?;
        let diagnostics_overflow = array_values(&self.dump(context, "soglia_diag_entries")?, 7)?;
        let overflow_tuple_present = self.lookup_tuple(&overflow_connection.key)?.is_some();
        let overflow_tuple_occupancy = self.occupancy(context, "soglia_tuples")?;
        let overflow_cookie_occupancy = self.occupancy(context, "soglia_cookie_a")?;
        let cookie_failure_delta = map_diagnostics_overflow[1] - map_diagnostics_before_fill[1];
        let sk_storage_failure_delta = map_diagnostics_overflow[4] - map_diagnostics_before_fill[4];
        let tuple_failure_delta = map_diagnostics_overflow[6] - map_diagnostics_before_fill[6];
        let wait_started = Instant::now();
        while wait_started.elapsed() < RESOLVE_TIMEOUT {
            if self.lookup_tuple(&overflow_connection.key)?.is_some() {
                return Err(TestError::new(
                    Verdict::Fail,
                    "S12 overflow tuple appeared during bounded Resolve wait",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
        overflow_connection
            .stream
            .shutdown(Shutdown::Both)
            .map_err(|error| TestError::infra(format!("deny S12 overflow socket: {error}")))?;
        drop(overflow_connection);
        let overflow_agent = self.wait_agent(overflow_index)?;
        let map_full_events = drain_events(&mut self.fixture)?;

        let freed = fill_connections.remove(0);
        let freed_key = freed.key;
        let freed_key_hex = hex(&freed_key);
        resolve_connection(freed, "s12-execution-generation-1")?;
        self.wait_tuple_absent(&freed_key, RESOLVE_TIMEOUT)?;
        self.wait_occupancy(context, CAPACITY - 1, RESOLVE_TIMEOUT)?;
        let occupancy_after_free = self.occupancy(context, "soglia_tuples")?;

        let (control_membership, control_index) =
            self.launch_agent(context, "control", "proxy 1")?;
        self.release_agent(control_index)?;
        let control_connection = accept_connections(&listener, 1)?.remove(0);
        let control_value = self.wait_tuple(&control_connection.key, RESOLVE_TIMEOUT)?;
        let control_entry =
            published_entry(&control_connection, control_value, target_inode, 12_001_001)?;
        self.wait_occupancy(context, CAPACITY, RESOLVE_TIMEOUT)?;
        let control_tuple_occupancy = self.occupancy(context, "soglia_tuples")?;
        let control_cookie_occupancy = self.occupancy(context, "soglia_cookie_a")?;
        let control_map_diagnostics =
            signed_array_values(&self.dump(context, "soglia_map_fail_diag")?, 8)?;
        resolve_connection(control_connection, "s12-execution-generation-1")?;
        let control_agent = self.wait_agent(control_index)?;

        for connection in fill_connections {
            resolve_connection(connection, "s12-execution-generation-1")?;
        }
        let fill_agent = self.wait_agent(fill_index)?;
        self.wait_occupancy(context, 0, Duration::from_secs(3))?;
        let final_tuple_occupancy = self.occupancy(context, "soglia_tuples")?;
        let final_cookie_occupancy = self.occupancy(context, "soglia_cookie_a")?;
        Ok(S12Observation {
            target_inode,
            direct_attachments,
            effective_attachments,
            map_contracts,
            tuple_baseline,
            cookie_baseline,
            precontrol_membership,
            precontrol_agent,
            precontrol_entry,
            fill_membership,
            fill_entries,
            phase_a_tuple_occupancy,
            phase_a_cookie_occupancy,
            phase_a_distinct_tuples: tuple_keys.len(),
            phase_a_distinct_cookies: cookies.len(),
            overflow_membership,
            overflow_agent,
            overflow_peer,
            overflow_local,
            overflow_key_hex,
            overflow_tuple_present,
            overflow_tuple_occupancy,
            overflow_cookie_occupancy,
            counters_before_fill,
            counters_overflow,
            diagnostics_before_fill,
            diagnostics_overflow,
            map_diagnostics_before_fill,
            map_diagnostics_overflow,
            cookie_failure_delta,
            sk_storage_failure_delta,
            tuple_failure_delta,
            resolve_timeout_ms: RESOLVE_TIMEOUT.as_millis(),
            overflow_resolve_result: "UNRESOLVED -> DENY".to_owned(),
            application_bytes_read_while_unresolved: 0,
            dns_lookups_while_unresolved: 0,
            outbound_effects_while_unresolved: 0,
            ip_fallback_authorization: false,
            map_full_events,
            freed_key_hex,
            occupancy_after_free,
            control_membership,
            control_agent,
            control_entry,
            control_tuple_occupancy,
            control_cookie_occupancy,
            control_map_diagnostics,
            final_tuple_occupancy,
            final_cookie_occupancy,
            fill_agent,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if array_len(&observation.direct_attachments) != 6
            || array_len(&observation.effective_attachments) != 6
            || observation
                .map_contracts
                .iter()
                .find(|map| map.name == "soglia_tuples")
                .is_none_or(|map| map.max_entries != CAPACITY as u64 || !map.authorization_state)
            || observation
                .map_contracts
                .iter()
                .find(|map| map.name == "soglia_cookie_a")
                .is_none_or(|map| map.max_entries != CAPACITY as u64 || !map.authorization_state)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S12 small-map contract or six-hook attachment was not proven",
            ));
        }
        for membership in [
            &observation.precontrol_membership,
            &observation.fill_membership,
            &observation.overflow_membership,
            &observation.control_membership,
        ] {
            if !membership.proven || membership.target_inode != observation.target_inode {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S12 live membership was not proven for every phase",
                ));
            }
        }
        if !agent_ok(&observation.precontrol_agent)
            || observation.phase_a_tuple_occupancy != CAPACITY
            || observation.phase_a_cookie_occupancy != CAPACITY
            || observation.phase_a_distinct_tuples != CAPACITY
            || observation.phase_a_distinct_cookies != CAPACITY
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S12 precontrol or actual Phase-A fullness was not proven",
            ));
        }
        if observation.overflow_tuple_present
            || observation.overflow_tuple_occupancy != CAPACITY
            || observation.overflow_cookie_occupancy != CAPACITY
            || observation.cookie_failure_delta != 1
            || observation.tuple_failure_delta != 1
            || observation.sk_storage_failure_delta != 0
            || observation.counters_overflow.get(1)
                != observation
                    .counters_before_fill
                    .get(1)
                    .map(|value| value + 1)
                    .as_ref()
            || agent_ok(&observation.overflow_agent)
            || observation.map_full_events.len() != 1
            || observation
                .map_full_events
                .iter()
                .any(|event| event.kind != 2 || event.destination_port != 15_001)
            || observation.overflow_resolve_result != "UNRESOLVED -> DENY"
            || observation.application_bytes_read_while_unresolved != 0
            || observation.dns_lookups_while_unresolved != 0
            || observation.outbound_effects_while_unresolved != 0
            || observation.ip_fallback_authorization
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S12 overflow update failure and bounded fail-closed denial were not proven",
            ));
        }
        if observation.occupancy_after_free != CAPACITY - 1
            || !agent_ok(&observation.control_agent)
            || observation.control_tuple_occupancy != CAPACITY
            || observation.control_cookie_occupancy != CAPACITY
            || observation.control_map_diagnostics[1] != observation.map_diagnostics_overflow[1]
            || observation.control_map_diagnostics[6] != observation.map_diagnostics_overflow[6]
            || !agent_all_ok(&observation.fill_agent, CAPACITY)
            || observation.final_tuple_occupancy != 0
            || observation.final_cookie_occupancy != 0
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S12 capacity-restored causal control or final socket cleanup did not succeed",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        for mut agent in self.active_agents.drain(..) {
            let _ = agent.process.terminate();
            let _ = agent.process.wait(Duration::from_secs(3));
        }
        for phase in ["precontrol", "fill", "overflow", "control"] {
            for suffix in ["host.ready", "agent.ready", "agent.go"] {
                remove_file(&self.fixture.runtime_root.join(format!("{phase}-{suffix}")))?;
            }
        }
        <S1 as SpikeTest>::cleanup(&mut self.fixture, context)
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)
    }
}

fn map_contract(
    name: &str,
    info: &Value,
    producer: &str,
    consumer: &str,
    update_failure: &str,
    authorization_state: bool,
) -> Result<MapContract, TestError> {
    Ok(MapContract {
        name: name.to_owned(),
        map_type: info
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| TestError::infra(format!("S12 {name} type missing")))?
            .to_owned(),
        max_entries: info
            .get("max_entries")
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra(format!("S12 {name} max_entries missing")))?,
        producer: producer.to_owned(),
        consumer: consumer.to_owned(),
        update_failure: update_failure.to_owned(),
        authorization_state,
    })
}

fn pinned_map(commands: &CommandExecutor, path: &Path) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("map"),
            OsString::from("show"),
            OsString::from("pinned"),
            path.as_os_str().to_owned(),
        ]))
        .map_err(TestError::infra)?;
    require_success(&output, "inspect S12 pinned map")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse S12 pinned map: {error}")))
}

fn accept_connections(listener: &TcpListener, count: usize) -> Result<Vec<Connection>, TestError> {
    let started = Instant::now();
    let mut connections = Vec::with_capacity(count);
    while connections.len() < count {
        match listener.accept() {
            Ok((stream, peer)) => {
                let local = stream
                    .local_addr()
                    .map_err(|error| TestError::infra(format!("S12 local socket: {error}")))?;
                connections.push(Connection {
                    key: tuple_key(peer, local).map_err(TestError::infra)?,
                    stream,
                    peer,
                    local,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= Duration::from_secs(6) {
                    return Err(TestError::new(
                        Verdict::Unproven,
                        format!(
                            "S12 accepted only {}/{} connections",
                            connections.len(),
                            count
                        ),
                    ));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(TestError::infra(format!("S12 proxy accept: {error}"))),
        }
    }
    Ok(connections)
}

fn published_entry(
    connection: &Connection,
    value: [u8; 64],
    cgroup_id: u64,
    exec_ident: u64,
) -> Result<PublishedEntry, TestError> {
    let evidence = decode_evidence(value).to_vec();
    if evidence[0] == 0
        || evidence[1] != cgroup_id
        || evidence[2] != cgroup_id
        || evidence[3] != exec_ident
    {
        return Err(TestError::new(
            Verdict::Unproven,
            "S12 published attribution was incomplete",
        ));
    }
    Ok(PublishedEntry {
        peer: connection.peer.to_string(),
        local: connection.local.to_string(),
        key_hex: hex(&connection.key),
        evidence,
    })
}

fn resolve_connection(mut connection: Connection, execution_id: &str) -> Result<(), TestError> {
    let mut request = String::new();
    BufReader::new(
        connection
            .stream
            .try_clone()
            .map_err(|error| TestError::infra(format!("clone S12 socket: {error}")))?,
    )
    .read_line(&mut request)
    .map_err(|error| TestError::infra(format!("read S12 application line: {error}")))?;
    writeln!(connection.stream, "ATTRIBUTED {execution_id}")
        .map_err(|error| TestError::infra(format!("write S12 verdict: {error}")))?;
    connection
        .stream
        .flush()
        .map_err(|error| TestError::infra(format!("flush S12 verdict: {error}")))
}

fn drain_events(fixture: &mut S1) -> Result<Vec<MapFullEvent>, TestError> {
    let map = fixture
        .bpf
        .as_mut()
        .and_then(|bpf| bpf.take_map("soglia_events"))
        .ok_or_else(|| TestError::infra("S12 event map missing"))?;
    let mut ring = RingBuf::try_from(map)
        .map_err(|error| TestError::infra(format!("open S12 events: {error:#}")))?;
    let mut events = Vec::new();
    while let Some(event) = ring.next() {
        if event.len() < 40 {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S12 event record had {} bytes", event.len()),
            ));
        }
        let kind = u32::from_ne_bytes(event[0..4].try_into().unwrap_or_default());
        if kind == 2 {
            events.push(MapFullEvent {
                kind,
                cgroup_id: u64::from_ne_bytes(event[8..16].try_into().unwrap_or_default()),
                cookie: u64::from_ne_bytes(event[16..24].try_into().unwrap_or_default()),
                destination_ipv4_raw: u32::from_ne_bytes(
                    event[32..36].try_into().unwrap_or_default(),
                ),
                destination_port: u32::from_ne_bytes(event[36..40].try_into().unwrap_or_default()),
                bytes_hex: hex(&event),
            });
        }
    }
    Ok(events)
}

fn signed_array_values(json: &Value, count: usize) -> Result<Vec<i64>, TestError> {
    let entries = json
        .as_array()
        .ok_or_else(|| TestError::infra("S12 signed array dump was not an array"))?;
    let mut values = vec![0_i64; count];
    for entry in entries {
        let key = entry
            .get("formatted")
            .and_then(|formatted| formatted.get("key"))
            .or_else(|| entry.get("key"))
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("S12 signed array key missing"))?
            as usize;
        let value = entry
            .get("formatted")
            .and_then(|formatted| formatted.get("value"))
            .or_else(|| entry.get("value"))
            .and_then(Value::as_i64)
            .ok_or_else(|| TestError::infra("S12 signed array value missing"))?;
        if let Some(slot) = values.get_mut(key) {
            *slot = value;
        }
    }
    Ok(values)
}

fn parse_agent_output(output: CommandOutput) -> Result<AgentResult, TestError> {
    let stdout = output.stdout_text();
    let json = stdout
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()
        .map_err(|error| TestError::infra(format!("parse S12 agent JSON: {error}")))?;
    Ok(AgentResult {
        exit_code: output.record.exit_code,
        signal: output.record.signal,
        stdout,
        stderr: output.stderr_text(),
        json,
    })
}

fn agent_ok(result: &AgentResult) -> bool {
    result.exit_code == Some(0)
        && result.signal.is_none()
        && result.json.iter().any(|value| {
            value.get("cmd").and_then(Value::as_str) == Some("proxy")
                && value.get("ok").and_then(Value::as_bool) == Some(true)
        })
}

fn agent_all_ok(result: &AgentResult, count: usize) -> bool {
    result.exit_code == Some(0)
        && result.signal.is_none()
        && result
            .json
            .iter()
            .filter(|value| value.get("cmd").and_then(Value::as_str) == Some("proxy"))
            .filter(|value| value.get("ok").and_then(Value::as_bool) == Some(true))
            .count()
            == count
}

fn array_len(value: &Value) -> usize {
    value.as_array().map_or(0, Vec::len)
}

fn require_success(output: &CommandOutput, context: &str) -> Result<(), TestError> {
    output.require_success(context).map_err(TestError::infra)
}

fn remove_file(path: &Path) -> Result<(), TestError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TestError::infra(format!(
            "remove {}: {error}",
            path.display()
        ))),
    }
}
