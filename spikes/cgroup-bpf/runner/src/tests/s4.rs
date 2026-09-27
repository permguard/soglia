// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::{Map, MapData, RingBuf};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{CommandExecutor, CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::s1::{
    S1, WAIT_SHORT, array_values, inode, json_cgroup, line_present, read_pid, read_trimmed,
    wait_for_path, wait_for_process_stopped,
};
use crate::tests::{SpikeTest, TestError};

const DIRECT_TARGET: &str = "10.201.0.2:16001";
const EXECUTION_ID: &str = "s4-execution-generation-1";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PhaseSnapshot {
    direct_attachments: Value,
    effective_attachments: Value,
    diagnostic_entries: Vec<u64>,
    counters: Vec<u64>,
    deny_map: Value,
    tuple_map: Value,
    cookie_map: Value,
    event_hex: Vec<String>,
    event_kinds: Vec<u32>,
    event_reasons: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForeignTraceRecord {
    sequence_ns: u64,
    who: u32,
    destination_ipv4_raw: u32,
    destination_port: u32,
    rewritten: u32,
    bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForeignObservation {
    ancestor_cgroup: String,
    ancestor_inode: u64,
    program_before: Value,
    program_after: Value,
    program_id: u64,
    program_tag: String,
    attach_type: String,
    attach_mode: String,
    ancestor_direct: Value,
    foreign_rewrite_attached: bool,
    trace: Vec<ForeignTraceRecord>,
    invocation_ordering_claim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S4Observation {
    execution_id: String,
    target_inode: u64,
    nft_before: Value,
    nft_during: Value,
    nft_after: Value,
    nft_temporary_rule: String,
    nft_temporary_rule_handle: u64,
    nft_relaxation_demonstrated: bool,
    nft_restoration_exact: bool,
    normal_direct_membership: Membership,
    normal_direct_result: AgentResult,
    normal_direct_listener_accepted: bool,
    normal_proxy_membership: Membership,
    normal_proxy_result: AgentResult,
    normal_proxy_peer: String,
    normal_proxy_tuple_visible_before_application_read: bool,
    normal_proxy_application_line: String,
    normal_phase: PhaseSnapshot,
    deny_membership: Membership,
    deny_result: AgentResult,
    deny_listener_accepted: bool,
    deny_proxy_involvement: bool,
    deny_phase: PhaseSnapshot,
    exposure_membership: Membership,
    exposure_result: AgentResult,
    exposure_listener_accepted: bool,
    exposure_peer: String,
    exposure_proxy_involvement: bool,
    exposure_phase: PhaseSnapshot,
    namespace_constraints_retained: bool,
    host_constraints_retained: bool,
    foreign: Option<ForeignObservation>,
}

pub struct S4 {
    test_id: TestId,
    fixture: S1,
    active_agent: Option<RunningCommand>,
    nft_rule_handle: Option<u64>,
    foreign_root: Option<std::path::PathBuf>,
    foreign_attached: bool,
    foreign_before: Option<Value>,
}

impl S4 {
    pub fn new(context: &TestContext) -> Self {
        Self {
            test_id: TestId::S4,
            fixture: S1::new_s4(context),
            active_agent: None,
            nft_rule_handle: None,
            foreign_root: None,
            foreign_attached: false,
            foreign_before: None,
        }
    }

    pub fn new_s9(context: &TestContext) -> Self {
        let foreign_root = Path::new("/sys/fs/bpf/soglia-spike-runner")
            .join(&context.run_id)
            .join("s9-foreign");
        Self {
            test_id: TestId::S9,
            fixture: S1::new_s9(context),
            active_agent: None,
            nft_rule_handle: None,
            foreign_root: Some(foreign_root),
            foreign_attached: false,
            foreign_before: None,
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        self.fixture.commands(context)
    }

    fn launch_agent(
        &mut self,
        context: &mut TestContext,
        operation: &str,
    ) -> Result<Membership, TestError> {
        for name in ["agent-host.ready", "agent.ready", "agent.go"] {
            remove_file(&self.fixture.runtime_root.join(name))?;
        }
        let host_ready = self.fixture.runtime_root.join("agent-host.ready");
        let agent_ready = self.fixture.runtime_root.join("agent.ready");
        let agent_go = self.fixture.runtime_root.join("agent.go");
        let agent = self
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
                    .timeout(Duration::from_secs(20)),
            )
            .map_err(TestError::infra)?;
        let trusted_pid = agent.id();
        context.resources.register(
            self.fixture.scope,
            format!("S4 controlled agent for {operation}"),
            Resource::Process { pid: trusted_pid },
        );
        self.active_agent = Some(agent);
        wait_for_path(&host_ready, WAIT_SHORT).map_err(TestError::infra)?;
        wait_for_process_stopped(trusted_pid, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_host_pid = read_pid(&host_ready).map_err(TestError::infra)?;
        let target = self.fixture.target()?.to_path_buf();
        fs::write(target.join("cgroup.procs"), format!("{trusted_pid}\n"))
            .map_err(|error| TestError::infra(format!("place S4 agent: {error}")))?;
        kill(
            Pid::from_raw(
                i32::try_from(trusted_pid)
                    .map_err(|error| TestError::infra(format!("convert S4 PID: {error}")))?,
            ),
            Signal::SIGCONT,
        )
        .map_err(|error| TestError::infra(format!("continue S4 agent: {error}")))?;
        wait_for_path(&agent_ready, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_agent_pid = read_pid(&agent_ready).map_err(TestError::infra)?;
        let proc_cgroup = read_trimmed(Path::new(&format!("/proc/{trusted_pid}/cgroup")))?;
        let target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let expected_proc_cgroup = format!(
            "0::/{}",
            target
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| TestError::infra("S4 target outside cgroup2"))?
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
                "S4 live agent membership was not proven before traffic",
            ));
        }
        Ok(Membership {
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
        })
    }

    fn release_agent(&mut self) -> Result<(), TestError> {
        fs::write(self.fixture.runtime_root.join("agent.go"), b"go\n")
            .map_err(|error| TestError::infra(format!("release S4 agent: {error}")))
    }

    fn wait_agent(&mut self) -> Result<AgentResult, TestError> {
        let output = self
            .active_agent
            .take()
            .ok_or_else(|| TestError::infra("S4 active agent missing"))?
            .wait(Duration::from_secs(12))
            .map_err(TestError::infra)?;
        parse_agent_output(output)
    }

    fn snapshot(&mut self, context: &TestContext) -> Result<PhaseSnapshot, TestError> {
        let target = self.fixture.target()?;
        let commands = self.commands(context);
        let direct_attachments = json_cgroup(&commands, target, false)?;
        let effective_attachments = json_cgroup(&commands, target, true)?;
        let diagnostic_entries =
            array_values(&self.fixture.dump_map(context, "soglia_diag_entries")?, 7)?;
        let counters = array_values(&self.fixture.dump_map(context, "soglia_counters")?, 9)?;
        let deny_map = self.fixture.dump_map(context, "soglia_denies")?;
        let tuple_map = self.fixture.dump_map(context, "soglia_tuples")?;
        let cookie_map = self.fixture.dump_map(context, "soglia_cookie_a")?;
        let events_map = self
            .fixture
            .bpf
            .as_mut()
            .and_then(|bpf| bpf.take_map("soglia_events"))
            .ok_or_else(|| TestError::infra("S4 event map missing"))?;
        let mut events = RingBuf::try_from(events_map)
            .map_err(|error| TestError::infra(format!("open S4 event ring: {error:#}")))?;
        let mut event_hex = Vec::new();
        let mut event_kinds = Vec::new();
        let mut event_reasons = Vec::new();
        while let Some(event) = events.next() {
            event_hex.push(hex(&event));
            if event.len() >= 8 {
                event_kinds.push(u32::from_ne_bytes(
                    event[0..4].try_into().unwrap_or_default(),
                ));
                event_reasons.push(u32::from_ne_bytes(
                    event[4..8].try_into().unwrap_or_default(),
                ));
            }
        }
        Ok(PhaseSnapshot {
            direct_attachments,
            effective_attachments,
            diagnostic_entries,
            counters,
            deny_map,
            tuple_map,
            cookie_map,
            event_hex,
            event_kinds,
            event_reasons,
        })
    }

    fn nft_ruleset(&self, context: &TestContext) -> Result<Value, TestError> {
        let output = self
            .commands(context)
            .run(&CommandSpec::new("ip").args([
                "netns",
                "exec",
                self.fixture.netns.as_str(),
                "nft",
                "-j",
                "list",
                "ruleset",
            ]))
            .map_err(TestError::infra)?;
        require_success(&output, "capture S4 namespace nft ruleset")?;
        serde_json::from_slice(&output.stdout)
            .map_err(|error| TestError::infra(format!("parse S4 nft JSON: {error}")))
    }

    fn add_nft_relaxation(&mut self, context: &TestContext) -> Result<u64, TestError> {
        let commands = self.commands(context);
        let output = commands
            .run(&CommandSpec::new("ip").args([
                "netns",
                "exec",
                self.fixture.netns.as_str(),
                "nft",
                "add",
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
                "ct",
                "state",
                "new",
                "accept",
                "comment",
                "s4-direct-exposure",
            ]))
            .map_err(TestError::infra)?;
        require_success(&output, "add exact S4 nft relaxation")?;
        let listing = commands
            .run(&CommandSpec::new("ip").args([
                "netns",
                "exec",
                self.fixture.netns.as_str(),
                "nft",
                "-a",
                "list",
                "chain",
                "inet",
                "soglia",
                "output",
            ]))
            .map_err(TestError::infra)?;
        require_success(&listing, "identify exact S4 nft relaxation")?;
        let handle = listing
            .stdout_text()
            .lines()
            .find(|line| line.contains("s4-direct-exposure"))
            .and_then(|line| line.rsplit_once("# handle "))
            .and_then(|(_, value)| value.trim().parse::<u64>().ok())
            .ok_or_else(|| TestError::infra("S4 temporary nft handle missing"))?;
        self.nft_rule_handle = Some(handle);
        Ok(handle)
    }

    fn restore_nft(&mut self, context: &TestContext) -> Result<(), TestError> {
        let Some(handle) = self.nft_rule_handle.take() else {
            return Ok(());
        };
        let output = self
            .commands(context)
            .run(&CommandSpec::new("ip").args([
                OsString::from("netns"),
                OsString::from("exec"),
                OsString::from(&self.fixture.netns),
                OsString::from("nft"),
                OsString::from("delete"),
                OsString::from("rule"),
                OsString::from("inet"),
                OsString::from("soglia"),
                OsString::from("output"),
                OsString::from("handle"),
                OsString::from(handle.to_string()),
            ]))
            .map_err(TestError::infra)?;
        require_success(&output, "restore exact S4 nft rule")
    }

    fn attach_foreign_allow(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        let Some(root) = self.foreign_root.clone() else {
            return Ok(());
        };
        fs::create_dir_all(&root)
            .map_err(|error| TestError::infra(format!("create S9 foreign pin root: {error}")))?;
        let commands = self.commands(context);
        let loaded = commands
            .run(
                &CommandSpec::new("bpftool")
                    .args([
                        OsString::from("prog"),
                        OsString::from("loadall"),
                        context.artifact("bpf/foreign.o").into_os_string(),
                        root.as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(30)),
            )
            .map_err(TestError::infra)?;
        require_success(&loaded, "load S9 foreign object")?;
        let allow = root.join("foreign_allow");
        let rewrite = root.join("foreign_rewrite");
        let before = pinned_program(&commands, &allow)?;
        let map_id = before
            .get("map_ids")
            .and_then(Value::as_array)
            .and_then(|ids| ids.first())
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("S9 foreign_trace map ID missing"))?;
        let trace = root.join("foreign_trace");
        let pinned = commands
            .run(&CommandSpec::new("bpftool").args([
                OsString::from("map"),
                OsString::from("pin"),
                OsString::from("id"),
                OsString::from(map_id.to_string()),
                trace.as_os_str().to_owned(),
            ]))
            .map_err(TestError::infra)?;
        require_success(&pinned, "pin S9 foreign trace map")?;
        let ancestor = self
            .fixture
            .executions
            .as_ref()
            .ok_or_else(|| TestError::infra("S9 ancestor cgroup missing"))?;
        let attached = commands
            .run(&CommandSpec::new("bpftool").args([
                OsString::from("cgroup"),
                OsString::from("attach"),
                ancestor.as_os_str().to_owned(),
                OsString::from("cgroup_inet4_connect"),
                OsString::from("pinned"),
                allow.as_os_str().to_owned(),
                OsString::from("multi"),
            ]))
            .map_err(TestError::infra)?;
        require_success(&attached, "attach S9 foreign ancestor allow")?;
        self.foreign_attached = true;
        self.foreign_before = Some(before);
        for pin in [allow, rewrite, trace] {
            context.resources.register(
                "s9",
                "S9 synthetic foreign pin",
                Resource::BpfPin { path: pin },
            );
        }
        Ok(())
    }

    fn observe_foreign(&self, context: &TestContext) -> Result<ForeignObservation, TestError> {
        let root = self
            .foreign_root
            .as_ref()
            .ok_or_else(|| TestError::infra("S9 foreign root missing"))?;
        let commands = self.commands(context);
        let program_before = self
            .foreign_before
            .clone()
            .ok_or_else(|| TestError::infra("S9 foreign baseline missing"))?;
        let program_after = pinned_program(&commands, &root.join("foreign_allow"))?;
        let program_id = program_before
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("S9 foreign program ID missing"))?;
        let program_tag = program_before
            .get("tag")
            .and_then(Value::as_str)
            .ok_or_else(|| TestError::infra("S9 foreign program tag missing"))?
            .to_owned();
        let ancestor = self
            .fixture
            .executions
            .as_ref()
            .ok_or_else(|| TestError::infra("S9 ancestor cgroup missing"))?;
        let ancestor_direct = json_cgroup(&commands, ancestor, false)?;
        let map = MapData::from_pin(root.join("foreign_trace"))
            .map_err(|error| TestError::infra(format!("open S9 foreign trace pin: {error:#}")))?;
        let map = Map::from_map_data(map)
            .map_err(|error| TestError::infra(format!("classify S9 foreign trace: {error:#}")))?;
        let mut ring = RingBuf::try_from(map)
            .map_err(|error| TestError::infra(format!("read S9 foreign trace: {error:#}")))?;
        let mut trace = Vec::new();
        while let Some(record) = ring.next() {
            if record.len() != 24 {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!("S9 foreign trace record has {} bytes", record.len()),
                ));
            }
            trace.push(ForeignTraceRecord {
                sequence_ns: u64::from_ne_bytes(record[0..8].try_into().unwrap_or_default()),
                who: u32::from_ne_bytes(record[8..12].try_into().unwrap_or_default()),
                destination_ipv4_raw: u32::from_ne_bytes(
                    record[12..16].try_into().unwrap_or_default(),
                ),
                destination_port: u32::from_ne_bytes(record[16..20].try_into().unwrap_or_default()),
                rewritten: u32::from_ne_bytes(record[20..24].try_into().unwrap_or_default()),
                bytes_hex: hex(&record),
            });
        }
        Ok(ForeignObservation {
            ancestor_cgroup: ancestor.to_string_lossy().into_owned(),
            ancestor_inode: inode(ancestor).map_err(TestError::infra)?,
            program_before,
            program_after,
            program_id,
            program_tag,
            attach_type: "cgroup_inet4_connect".to_owned(),
            attach_mode: "legacy_multi".to_owned(),
            foreign_rewrite_attached: ancestor_direct
                .as_array()
                .ok_or_else(|| TestError::infra("S9 ancestor attachment JSON invalid"))?
                .iter()
                .any(|program| {
                    program.get("name").and_then(Value::as_str) == Some("foreign_rewrite")
                }),
            ancestor_direct,
            trace,
            invocation_ordering_claim: "no relative ancestor/child order is inferred from bpftool listings; ring records establish only stimulus chronology and unconditional foreign ALLOW observations".to_owned(),
        })
    }

    fn detach_foreign_allow(&mut self, context: &TestContext) -> Result<(), TestError> {
        let Some(root) = self.foreign_root.clone() else {
            return Ok(());
        };
        if self.foreign_attached {
            let ancestor = self
                .fixture
                .executions
                .as_ref()
                .ok_or_else(|| TestError::infra("S9 ancestor missing during detach"))?;
            let detached = self
                .commands(context)
                .run(&CommandSpec::new("bpftool").args([
                    OsString::from("cgroup"),
                    OsString::from("detach"),
                    ancestor.as_os_str().to_owned(),
                    OsString::from("cgroup_inet4_connect"),
                    OsString::from("pinned"),
                    root.join("foreign_allow").into_os_string(),
                ]))
                .map_err(TestError::infra)?;
            require_success(&detached, "detach S9 foreign ancestor allow")?;
            self.foreign_attached = false;
        }
        for name in ["foreign_trace", "foreign_allow", "foreign_rewrite"] {
            remove_file(&root.join(name))?;
        }
        match fs::remove_dir(&root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(TestError::infra(format!(
                "remove S9 foreign root {}: {error}",
                root.display()
            ))),
        }
    }
}

impl SpikeTest for S4 {
    type Observation = S4Observation;

    fn id(&self) -> TestId {
        self.test_id
    }

    fn invariant(&self) -> &'static str {
        if self.test_id == TestId::S9 {
            "foreign ancestor ALLOW plus child Soglia DENY remains fail-closed, while the same path establishes with the child permissive control"
        } else {
            "with only the exact nft destination barrier relaxed, cgroup/connect4 prevents direct IPv4 establishment and the no-deny control exposes the same path"
        }
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if self.test_id == TestId::S9 {
            self.fixture.prepare_topology(context)?;
            self.attach_foreign_allow(context)?;
            self.fixture.load_bpf_now(context)
        } else {
            <S1 as SpikeTest>::prepare(&mut self.fixture, context)
        }
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let target_inode = inode(self.fixture.target()?).map_err(TestError::infra)?;
        let nft_before = self.nft_ruleset(context)?;
        let direct_listener = TcpListener::bind((Ipv4Addr::new(10, 201, 0, 2), 16_001))
            .map_err(|error| TestError::infra(format!("bind S4 direct listener: {error}")))?;
        direct_listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S4 direct listener: {error}")))?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
            .map_err(|error| TestError::infra(format!("bind S4 proxy listener: {error}")))?;
        proxy_listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S4 proxy listener: {error}")))?;

        let normal_direct_membership =
            self.launch_agent(context, &format!("direct {DIRECT_TARGET}"))?;
        self.release_agent()?;
        let normal_direct_result = self.wait_agent()?;
        let normal_direct_listener_accepted = accept_now(&direct_listener)?.is_some();

        let normal_proxy_membership = self.launch_agent(context, "proxy 1")?;
        self.release_agent()?;
        let (mut proxy_stream, normal_proxy_peer) =
            accept_bounded(&proxy_listener, Duration::from_secs(5))?.ok_or_else(|| {
                TestError::new(Verdict::Unproven, "S4 normal proxy path did not establish")
            })?;
        let tuple_visible = wait_for_nonempty_map(
            &self.fixture,
            context,
            "soglia_tuples",
            Duration::from_secs(2),
        )?;
        let mut normal_proxy_application_line = String::new();
        BufReader::new(
            proxy_stream
                .try_clone()
                .map_err(|error| TestError::infra(format!("clone S4 proxy stream: {error}")))?,
        )
        .read_line(&mut normal_proxy_application_line)
        .map_err(|error| TestError::infra(format!("read S4 proxy application: {error}")))?;
        writeln!(proxy_stream, "ATTRIBUTED {EXECUTION_ID}")
            .map_err(|error| TestError::infra(format!("write S4 proxy result: {error}")))?;
        proxy_stream
            .flush()
            .map_err(|error| TestError::infra(format!("flush S4 proxy result: {error}")))?;
        let normal_phase = self.snapshot(context)?;
        drop(proxy_stream);
        let normal_proxy_result = self.wait_agent()?;

        self.fixture.reload_bpf(context, "bpf/soglia-diag.o")?;
        let nft_temporary_rule_handle = self.add_nft_relaxation(context)?;
        let nft_during = self.nft_ruleset(context)?;
        let deny_membership = self.launch_agent(context, &format!("direct {DIRECT_TARGET}"))?;
        self.release_agent()?;
        let deny_result = self.wait_agent()?;
        let deny_listener_accepted = accept_now(&direct_listener)?.is_some();
        let deny_proxy_involvement = accept_now(&proxy_listener)?.is_some();
        let deny_phase = self.snapshot(context)?;

        self.fixture
            .reload_bpf(context, "bpf/soglia-direct-control.o")?;
        let exposure_membership = self.launch_agent(context, &format!("direct {DIRECT_TARGET}"))?;
        self.release_agent()?;
        let exposure_result = self.wait_agent()?;
        let exposure = accept_bounded(&direct_listener, Duration::from_secs(2))?;
        let (exposure_listener_accepted, exposure_peer) = exposure
            .map(|(_, peer)| (true, peer.to_string()))
            .unwrap_or((false, String::new()));
        let exposure_proxy_involvement = accept_now(&proxy_listener)?.is_some();
        let exposure_phase = self.snapshot(context)?;

        self.restore_nft(context)?;
        let nft_after = self.nft_ruleset(context)?;
        let nft_restoration_exact = nft_before == nft_after;
        let nft_relaxation_demonstrated = nft_during != nft_before
            && contains_json_string(&nft_during, "s4-direct-exposure")
            && !contains_json_string(&nft_before, "s4-direct-exposure")
            && !contains_json_string(&nft_after, "s4-direct-exposure");
        let foreign = if self.test_id == TestId::S9 {
            Some(self.observe_foreign(context)?)
        } else {
            None
        };

        Ok(S4Observation {
            execution_id: EXECUTION_ID.to_owned(),
            target_inode,
            nft_before,
            nft_during,
            nft_after,
            nft_temporary_rule:
                "ip daddr 10.201.0.2 tcp dport 16001 ct state new accept comment s4-direct-exposure"
                    .to_owned(),
            nft_temporary_rule_handle,
            nft_relaxation_demonstrated,
            nft_restoration_exact,
            normal_direct_membership,
            normal_direct_result,
            normal_direct_listener_accepted,
            normal_proxy_membership,
            normal_proxy_result,
            normal_proxy_peer: normal_proxy_peer.to_string(),
            normal_proxy_tuple_visible_before_application_read: tuple_visible,
            normal_proxy_application_line: normal_proxy_application_line.trim_end().to_owned(),
            normal_phase,
            deny_membership,
            deny_result,
            deny_listener_accepted,
            deny_proxy_involvement,
            deny_phase,
            exposure_membership,
            exposure_result,
            exposure_listener_accepted,
            exposure_peer,
            exposure_proxy_involvement,
            exposure_phase,
            namespace_constraints_retained: true,
            host_constraints_retained: true,
            foreign,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if !observation.nft_relaxation_demonstrated || !observation.nft_restoration_exact {
            return Err(TestError::new(
                Verdict::Unproven,
                "S4 exact nft relaxation/restoration was not demonstrated",
            ));
        }
        for membership in [
            &observation.normal_direct_membership,
            &observation.normal_proxy_membership,
            &observation.deny_membership,
            &observation.exposure_membership,
        ] {
            if !membership.proven || membership.target_inode != observation.target_inode {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S4 live subject placement changed or was not proven",
                ));
            }
        }
        for phase in [
            &observation.normal_phase,
            &observation.deny_phase,
            &observation.exposure_phase,
        ] {
            let expected_effective = if observation.foreign.is_some() { 7 } else { 6 };
            if array_len(&phase.direct_attachments) != 6
                || array_len(&phase.effective_attachments) != expected_effective
            {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S4 did not observe six direct/effective hooks in every phase",
                ));
            }
        }
        if agent_ok(&observation.normal_direct_result, "direct")
            || observation.normal_direct_listener_accepted
            || observation
                .normal_phase
                .diagnostic_entries
                .get(1)
                .copied()
                .unwrap_or(0)
                < 2
            || observation.normal_phase.counters.get(4) != Some(&0)
            || !agent_ok(&observation.normal_proxy_result, "proxy")
            || !observation.normal_proxy_tuple_visible_before_application_read
            || observation.normal_proxy_application_line != "HELLO 0"
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S4 normal control did not isolate nft denial while retaining the proxy path",
            ));
        }
        if agent_ok(&observation.deny_result, "direct")
            || observation.deny_listener_accepted
            || observation.deny_proxy_involvement
            || observation.deny_phase.diagnostic_entries.get(1) != Some(&1)
            || observation.deny_phase.counters.get(4) != Some(&1)
            || array_len(&observation.deny_phase.deny_map) != 1
            || !observation
                .deny_phase
                .tuple_map
                .as_array()
                .is_some_and(Vec::is_empty)
            || !observation
                .deny_phase
                .cookie_map
                .as_array()
                .is_some_and(Vec::is_empty)
            || observation.deny_phase.event_kinds != [1]
            || observation.deny_phase.event_reasons != [3]
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S4 denial could not be attributed uniquely to cgroup/connect4",
            ));
        }
        if !agent_ok(&observation.exposure_result, "direct")
            || !observation.exposure_listener_accepted
            || observation.exposure_proxy_involvement
            || observation.exposure_phase.diagnostic_entries.get(1) != Some(&1)
            || observation.exposure_phase.counters.get(4) != Some(&0)
            || !observation
                .exposure_phase
                .deny_map
                .as_array()
                .is_some_and(Vec::is_empty)
            || !observation.namespace_constraints_retained
            || !observation.host_constraints_retained
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S4 negative control did not causally expose the same direct path",
            ));
        }
        if let Some(foreign) = observation.foreign.as_ref() {
            let before_id = foreign.program_before.get("id").and_then(Value::as_u64);
            let after_id = foreign.program_after.get("id").and_then(Value::as_u64);
            let before_tag = foreign.program_before.get("tag").and_then(Value::as_str);
            let after_tag = foreign.program_after.get("tag").and_then(Value::as_str);
            let ancestor = foreign
                .ancestor_direct
                .as_array()
                .ok_or_else(|| TestError::infra("S9 ancestor attachment JSON invalid"))?;
            let foreign_active = ancestor.iter().any(|program| {
                program.get("id").and_then(Value::as_u64) == Some(foreign.program_id)
                    && program.get("name").and_then(Value::as_str) == Some("foreign_allow")
                    && program.get("attach_flags").and_then(Value::as_str) == Some("multi")
            });
            let every_phase_composed = [
                &observation.normal_phase,
                &observation.deny_phase,
                &observation.exposure_phase,
            ]
            .iter()
            .all(|phase| {
                phase
                    .effective_attachments
                    .as_array()
                    .is_some_and(|programs| {
                        programs
                            .iter()
                            .filter(|program| {
                                program.get("id").and_then(Value::as_u64)
                                    == Some(foreign.program_id)
                                    && program.get("name").and_then(Value::as_str)
                                        == Some("foreign_allow")
                            })
                            .count()
                            == 1
                            && programs
                                .iter()
                                .filter(|program| {
                                    program.get("name").and_then(Value::as_str)
                                        == Some("soglia_connect4")
                                })
                                .count()
                                == 1
                    })
            });
            let direct_records = foreign
                .trace
                .iter()
                .filter(|record| record.destination_port == 16_001)
                .count();
            let proxy_records = foreign
                .trace
                .iter()
                .filter(|record| record.destination_port == 15_001)
                .count();
            if foreign.attach_type != "cgroup_inet4_connect"
                || foreign.attach_mode != "legacy_multi"
                || foreign.foreign_rewrite_attached
                || !foreign_active
                || !every_phase_composed
                || before_id != after_id
                || before_tag != after_tag
                || before_id != Some(foreign.program_id)
                || before_tag != Some(foreign.program_tag.as_str())
                || foreign.trace.len() != 4
                || foreign
                    .trace
                    .iter()
                    .any(|record| record.who != 2 || record.rewritten != 0)
                || direct_records != 3
                || proxy_records != 1
            {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S9 foreign ancestor ALLOW identity, composition, or causal trace was not proven",
                ));
            }
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if let Some(mut agent) = self.active_agent.take() {
            let _ = agent.terminate();
            let _ = agent.wait(Duration::from_secs(3));
        }
        if self.nft_rule_handle.is_some()
            && Path::new("/run/netns").join(&self.fixture.netns).exists()
        {
            self.restore_nft(context)?;
        }
        self.detach_foreign_allow(context)?;
        <S1 as SpikeTest>::cleanup(&mut self.fixture, context)
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)
    }
}

fn parse_agent_output(output: CommandOutput) -> Result<AgentResult, TestError> {
    let stdout = output.stdout_text();
    let json = stdout
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()
        .map_err(|error| TestError::infra(format!("parse S4 agent JSON: {error}")))?;
    Ok(AgentResult {
        exit_code: output.record.exit_code,
        signal: output.record.signal,
        stdout,
        stderr: output.stderr_text(),
        json,
    })
}

fn agent_ok(result: &AgentResult, command: &str) -> bool {
    result.exit_code == Some(0)
        && result.signal.is_none()
        && result.json.iter().any(|value| {
            value
                .get("cmd")
                .and_then(Value::as_str)
                .is_some_and(|observed| {
                    observed == command || observed.starts_with(&format!("{command} "))
                })
                && value.get("ok").and_then(Value::as_bool) == Some(true)
        })
}

fn accept_now(
    listener: &TcpListener,
) -> Result<Option<(std::net::TcpStream, std::net::SocketAddr)>, TestError> {
    match listener.accept() {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(TestError::infra(format!("S4 listener accept: {error}"))),
    }
}

fn accept_bounded(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<Option<(std::net::TcpStream, std::net::SocketAddr)>, TestError> {
    let started = Instant::now();
    loop {
        if let Some(value) = accept_now(listener)? {
            return Ok(Some(value));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_nonempty_map(
    fixture: &S1,
    context: &TestContext,
    name: &str,
    timeout: Duration,
) -> Result<bool, TestError> {
    let started = Instant::now();
    loop {
        if fixture
            .dump_map(context, name)?
            .as_array()
            .is_some_and(|entries| !entries.is_empty())
        {
            return Ok(true);
        }
        if started.elapsed() >= timeout {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn require_success(output: &CommandOutput, context: &str) -> Result<(), TestError> {
    output.require_success(context).map_err(TestError::infra)
}

fn pinned_program(commands: &CommandExecutor, path: &Path) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("prog"),
            OsString::from("show"),
            OsString::from("pinned"),
            path.as_os_str().to_owned(),
        ]))
        .map_err(TestError::infra)?;
    require_success(&output, "inspect pinned foreign program")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse pinned foreign program: {error}")))
}

fn array_len(value: &Value) -> usize {
    value.as_array().map_or(0, Vec::len)
}

fn contains_json_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value.contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_json_string(value, needle)),
        Value::Object(values) => values
            .values()
            .any(|value| contains_json_string(value, needle)),
        _ => false,
    }
}

fn remove_file(path: &Path) -> Result<(), TestError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TestError::infra(format!(
            "remove S4 marker {}: {error}",
            path.display()
        ))),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
