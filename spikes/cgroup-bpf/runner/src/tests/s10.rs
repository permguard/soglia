// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
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
    S1, WAIT_SHORT, array_values, hex, inode, json_cgroup, line_present, read_pid, read_trimmed,
    wait_for_path, wait_for_process_stopped,
};
use crate::tests::{SpikeTest, TestError};

const ORIGINAL: &str = "10.200.255.1:15001";
const REWRITTEN_PORT: u32 = 16_001;
const OBSERVE_COMMENT: &str = "s10-rewrite-observe";
const EXPOSURE_COMMENT: &str = "s10-rewrite-exposure";

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
    child_direct: Value,
    child_effective: Value,
    diagnostic_entries: Vec<u64>,
    port_diagnostics: Vec<u64>,
    counters: Vec<u64>,
    deny_map: Value,
    tuple_map: Value,
    cookie_map: Value,
    events_hex: Vec<String>,
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
pub struct S10Observation {
    ancestor_cgroup: String,
    ancestor_inode: u64,
    child_cgroup: String,
    child_inode: u64,
    foreign_program_before: Value,
    foreign_program_after: Value,
    foreign_program_id: u64,
    foreign_program_tag: String,
    foreign_attach_type: String,
    foreign_attach_mode: String,
    ancestor_direct: Value,
    initial_child_direct: Value,
    initial_child_effective: Value,
    foreign_allow_attached: bool,
    rewrite_configuration: Value,
    nft_before: Value,
    nft_exposed: Value,
    nft_after: Value,
    nft_exposure_rule: String,
    nft_exposure_handle: u64,
    nft_restoration_exact: bool,
    case_a_membership: Membership,
    case_a_agent: AgentResult,
    case_a_original_accept: bool,
    case_a_rewritten_accept: bool,
    case_a_observe_packets: u64,
    case_a_phase: PhaseSnapshot,
    case_b_membership: Membership,
    case_b_agent: AgentResult,
    case_b_original_accept: bool,
    case_b_rewritten_accept: bool,
    case_b_rewritten_peer: String,
    case_b_observe_packets: u64,
    case_b_phase: PhaseSnapshot,
    normal_membership: Membership,
    normal_agent: AgentResult,
    normal_original_accept: bool,
    normal_rewritten_accept: bool,
    normal_observe_packets: u64,
    normal_phase: PhaseSnapshot,
    normal_composition_observed: String,
    foreign_trace: Vec<ForeignTraceRecord>,
    invocation_ordering_claim: String,
}

pub struct S10 {
    fixture: S1,
    active_agent: Option<RunningCommand>,
    foreign_root: PathBuf,
    foreign_attached: bool,
    foreign_before: Option<Value>,
    exposure_handle: Option<u64>,
}

impl S10 {
    pub fn new(context: &TestContext) -> Self {
        Self {
            fixture: S1::new_s10(context),
            active_agent: None,
            foreign_root: Path::new("/sys/fs/bpf/soglia-spike-runner")
                .join(&context.run_id)
                .join("s10-foreign"),
            foreign_attached: false,
            foreign_before: None,
            exposure_handle: None,
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        self.fixture.commands(context)
    }

    fn attach_foreign_rewrite(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        fs::create_dir_all(&self.foreign_root)
            .map_err(|error| TestError::infra(format!("create S10 foreign root: {error}")))?;
        let commands = self.commands(context);
        let loaded = commands
            .run(
                &CommandSpec::new("bpftool")
                    .args([
                        OsString::from("prog"),
                        OsString::from("loadall"),
                        context.artifact("bpf/foreign-s10.o").into_os_string(),
                        self.foreign_root.as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(30)),
            )
            .map_err(TestError::infra)?;
        require_success(&loaded, "load S10 foreign object")?;
        let rewrite = self.foreign_root.join("foreign_rewrite");
        let before = pinned_program(&commands, &rewrite)?;
        let map_ids = before
            .get("map_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| TestError::infra("S10 foreign program map IDs missing"))?;
        let mut map_id = None;
        for id in map_ids.iter().filter_map(Value::as_u64) {
            let info = map_by_id(&commands, id)?;
            if info.get("name").and_then(Value::as_str) == Some("foreign_trace")
                && info.get("type").and_then(Value::as_str) == Some("ringbuf")
            {
                map_id = Some(id);
                break;
            }
        }
        let map_id = map_id.ok_or_else(|| TestError::infra("S10 foreign trace map ID missing"))?;
        let trace = self.foreign_root.join("foreign_trace");
        let pinned = commands
            .run(&CommandSpec::new("bpftool").args([
                OsString::from("map"),
                OsString::from("pin"),
                OsString::from("id"),
                OsString::from(map_id.to_string()),
                trace.as_os_str().to_owned(),
            ]))
            .map_err(TestError::infra)?;
        require_success(&pinned, "pin S10 foreign trace")?;
        let ancestor = self
            .fixture
            .executions
            .as_ref()
            .ok_or_else(|| TestError::infra("S10 ancestor cgroup missing"))?;
        let attached = commands
            .run(&CommandSpec::new("bpftool").args([
                OsString::from("cgroup"),
                OsString::from("attach"),
                ancestor.as_os_str().to_owned(),
                OsString::from("cgroup_inet4_connect"),
                OsString::from("pinned"),
                rewrite.as_os_str().to_owned(),
                OsString::from("multi"),
            ]))
            .map_err(TestError::infra)?;
        require_success(&attached, "attach S10 foreign ancestor rewrite")?;
        self.foreign_attached = true;
        self.foreign_before = Some(before);
        for pin in [self.foreign_root.join("foreign_allow"), rewrite, trace] {
            context.resources.register(
                "s10",
                "S10 synthetic foreign pin",
                Resource::BpfPin { path: pin },
            );
        }
        Ok(())
    }

    fn launch_agent(&mut self, context: &mut TestContext) -> Result<Membership, TestError> {
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
                        OsString::from(format!("direct {ORIGINAL}")),
                    ])
                    .timeout(Duration::from_secs(20)),
            )
            .map_err(TestError::infra)?;
        let trusted_pid = agent.id();
        context.resources.register(
            "s10",
            "S10 controlled agent",
            Resource::Process { pid: trusted_pid },
        );
        self.active_agent = Some(agent);
        wait_for_path(&host_ready, WAIT_SHORT).map_err(TestError::infra)?;
        wait_for_process_stopped(trusted_pid, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_host_pid = read_pid(&host_ready).map_err(TestError::infra)?;
        let target = self.fixture.target()?.to_path_buf();
        fs::write(target.join("cgroup.procs"), format!("{trusted_pid}\n"))
            .map_err(|error| TestError::infra(format!("place S10 agent: {error}")))?;
        kill(
            Pid::from_raw(
                i32::try_from(trusted_pid)
                    .map_err(|error| TestError::infra(format!("convert S10 PID: {error}")))?,
            ),
            Signal::SIGCONT,
        )
        .map_err(|error| TestError::infra(format!("continue S10 agent: {error}")))?;
        wait_for_path(&agent_ready, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_agent_pid = read_pid(&agent_ready).map_err(TestError::infra)?;
        let proc_cgroup = read_trimmed(Path::new(&format!("/proc/{trusted_pid}/cgroup")))?;
        let target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let expected_proc_cgroup = format!(
            "0::/{}",
            target
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| TestError::infra("S10 target outside cgroup2"))?
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
                "S10 live agent membership was not proven before traffic",
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

    fn release_agent(&self) -> Result<(), TestError> {
        fs::write(self.fixture.runtime_root.join("agent.go"), b"go\n")
            .map_err(|error| TestError::infra(format!("release S10 agent: {error}")))
    }

    fn wait_agent(&mut self) -> Result<AgentResult, TestError> {
        let output = self
            .active_agent
            .take()
            .ok_or_else(|| TestError::infra("S10 active agent missing"))?
            .wait(Duration::from_secs(12))
            .map_err(TestError::infra)?;
        parse_agent_output(output)
    }

    fn snapshot(
        &mut self,
        context: &TestContext,
        drain_events: bool,
    ) -> Result<PhaseSnapshot, TestError> {
        let commands = self.commands(context);
        let child_direct = json_cgroup(&commands, self.fixture.target()?, false)?;
        let child_effective = json_cgroup(&commands, self.fixture.target()?, true)?;
        let diagnostic_entries =
            array_values(&self.fixture.dump_map(context, "soglia_diag_entries")?, 7)?;
        let port_diagnostics =
            array_values(&self.fixture.dump_map(context, "soglia_port_diag")?, 12)?;
        let counters = array_values(&self.fixture.dump_map(context, "soglia_counters")?, 9)?;
        let deny_map = self.fixture.dump_map(context, "soglia_denies")?;
        let tuple_map = self.fixture.dump_map(context, "soglia_tuples")?;
        let cookie_map = self.fixture.dump_map(context, "soglia_cookie_a")?;
        let mut events_hex = Vec::new();
        if drain_events {
            let events_map = self
                .fixture
                .bpf
                .as_mut()
                .and_then(|bpf| bpf.take_map("soglia_events"))
                .ok_or_else(|| TestError::infra("S10 event map missing"))?;
            let mut events = RingBuf::try_from(events_map)
                .map_err(|error| TestError::infra(format!("open S10 event ring: {error:#}")))?;
            while let Some(event) = events.next() {
                events_hex.push(hex(&event));
            }
        }
        Ok(PhaseSnapshot {
            child_direct,
            child_effective,
            diagnostic_entries,
            port_diagnostics,
            counters,
            deny_map,
            tuple_map,
            cookie_map,
            events_hex,
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
        require_success(&output, "capture S10 nft ruleset")?;
        serde_json::from_slice(&output.stdout)
            .map_err(|error| TestError::infra(format!("parse S10 nft JSON: {error}")))
    }

    fn add_exposure(&mut self, context: &TestContext) -> Result<u64, TestError> {
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
                EXPOSURE_COMMENT,
            ]))
            .map_err(TestError::infra)?;
        require_success(&output, "add exact S10 nft exposure")?;
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
        require_success(&listing, "identify exact S10 nft exposure")?;
        let handle = listing
            .stdout_text()
            .lines()
            .find(|line| line.contains(EXPOSURE_COMMENT))
            .and_then(|line| line.rsplit_once("# handle "))
            .and_then(|(_, value)| value.trim().parse::<u64>().ok())
            .ok_or_else(|| TestError::infra("S10 nft exposure handle missing"))?;
        self.exposure_handle = Some(handle);
        Ok(handle)
    }

    fn restore_nft(&mut self, context: &TestContext) -> Result<(), TestError> {
        let Some(handle) = self.exposure_handle.take() else {
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
        require_success(&output, "restore exact S10 nft exposure")
    }

    fn foreign_trace(&self) -> Result<Vec<ForeignTraceRecord>, TestError> {
        let map = MapData::from_pin(self.foreign_root.join("foreign_trace"))
            .map_err(|error| TestError::infra(format!("open S10 foreign trace: {error:#}")))?;
        let map = Map::from_map_data(map)
            .map_err(|error| TestError::infra(format!("classify S10 foreign trace: {error:#}")))?;
        let mut ring = RingBuf::try_from(map)
            .map_err(|error| TestError::infra(format!("read S10 foreign trace: {error:#}")))?;
        let mut trace = Vec::new();
        while let Some(record) = ring.next() {
            if record.len() != 24 {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!("S10 foreign trace record has {} bytes", record.len()),
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
        Ok(trace)
    }

    fn detach_foreign(&mut self, context: &TestContext) -> Result<(), TestError> {
        if self.foreign_attached {
            let ancestor = self
                .fixture
                .executions
                .as_ref()
                .ok_or_else(|| TestError::infra("S10 ancestor missing during detach"))?;
            let output = self
                .commands(context)
                .run(&CommandSpec::new("bpftool").args([
                    OsString::from("cgroup"),
                    OsString::from("detach"),
                    ancestor.as_os_str().to_owned(),
                    OsString::from("cgroup_inet4_connect"),
                    OsString::from("pinned"),
                    self.foreign_root.join("foreign_rewrite").into_os_string(),
                ]))
                .map_err(TestError::infra)?;
            require_success(&output, "detach S10 foreign rewrite")?;
            self.foreign_attached = false;
        }
        for name in ["foreign_trace", "foreign_allow", "foreign_rewrite"] {
            remove_file(&self.foreign_root.join(name))?;
        }
        match fs::remove_dir(&self.foreign_root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(TestError::infra(format!(
                "remove S10 foreign root {}: {error}",
                self.foreign_root.display()
            ))),
        }
    }
}

impl SpikeTest for S10 {
    type Observation = S10Observation;

    fn id(&self) -> TestId {
        TestId::S10
    }

    fn invariant(&self) -> &'static str {
        "an empirically proven ancestor destination rewrite cannot bypass the normal nft final-destination barrier, while one exact nft exposure causally opens the same rewritten path"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        self.fixture.prepare_topology(context)?;
        self.attach_foreign_rewrite(context)?;
        self.fixture.load_bpf_now(context)
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let commands = self.commands(context);
        let ancestor = self
            .fixture
            .executions
            .as_ref()
            .ok_or_else(|| TestError::infra("S10 ancestor missing"))?
            .to_path_buf();
        let ancestor_inode = inode(&ancestor).map_err(TestError::infra)?;
        let child = self.fixture.target()?.to_path_buf();
        let child_inode = inode(&child).map_err(TestError::infra)?;
        let ancestor_direct = json_cgroup(&commands, &ancestor, false)?;
        let initial_child_direct = json_cgroup(&commands, &child, false)?;
        let initial_child_effective = json_cgroup(&commands, &child, true)?;
        let foreign_program_before = self
            .foreign_before
            .clone()
            .ok_or_else(|| TestError::infra("S10 foreign identity baseline missing"))?;
        let foreign_program_id = foreign_program_before
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("S10 foreign program ID missing"))?;
        let foreign_program_tag = foreign_program_before
            .get("tag")
            .and_then(Value::as_str)
            .ok_or_else(|| TestError::infra("S10 foreign program tag missing"))?
            .to_owned();
        let foreign_allow_attached = contains_program(&ancestor_direct, "foreign_allow");

        let nft_before = self.nft_ruleset(context)?;
        let original_listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
            .map_err(|error| TestError::infra(format!("bind S10 original listener: {error}")))?;
        let rewritten_listener = TcpListener::bind((Ipv4Addr::new(10, 201, 0, 2), 16_001))
            .map_err(|error| TestError::infra(format!("bind S10 rewritten listener: {error}")))?;
        original_listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S10 original nonblocking: {error}")))?;
        rewritten_listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S10 rewritten nonblocking: {error}")))?;

        let case_a_membership = self.launch_agent(context)?;
        self.release_agent()?;
        let case_a_agent = self.wait_agent()?;
        let case_a_original_accept = accept_now(&original_listener)?.is_some();
        let case_a_rewritten_accept = accept_now(&rewritten_listener)?.is_some();
        let case_a_phase = self.snapshot(context, false)?;
        let nft_after_a = self.nft_ruleset(context)?;
        let case_a_observe_packets = counter_packets(&nft_after_a, OBSERVE_COMMENT)?;

        let nft_exposure_handle = self.add_exposure(context)?;
        let nft_exposed = self.nft_ruleset(context)?;
        let case_b_membership = self.launch_agent(context)?;
        self.release_agent()?;
        let rewritten = accept_bounded(&rewritten_listener, Duration::from_secs(5))?;
        let (case_b_rewritten_accept, case_b_rewritten_peer) = rewritten
            .map(|(_, peer)| (true, peer.to_string()))
            .unwrap_or((false, String::new()));
        let case_b_original_accept = accept_now(&original_listener)?.is_some();
        let case_b_agent = self.wait_agent()?;
        let case_b_phase = self.snapshot(context, false)?;
        let nft_after_b = self.nft_ruleset(context)?;
        let case_b_observe_packets = counter_packets(&nft_after_b, OBSERVE_COMMENT)?;

        self.restore_nft(context)?;
        let nft_after = self.nft_ruleset(context)?;
        let nft_restoration_exact = stable_nft(&nft_before) == stable_nft(&nft_after)
            && !contains_json_string(&nft_after, EXPOSURE_COMMENT);

        self.fixture.reload_bpf(context, "bpf/soglia-diag.o")?;
        let normal_membership = self.launch_agent(context)?;
        self.release_agent()?;
        let normal_agent = self.wait_agent()?;
        let normal_original_accept = accept_now(&original_listener)?.is_some();
        let normal_rewritten_accept = accept_now(&rewritten_listener)?.is_some();
        let normal_phase = self.snapshot(context, true)?;
        let normal_observe_packets = counter_packets(&self.nft_ruleset(context)?, OBSERVE_COMMENT)?;
        let observed_port = normal_phase.port_diagnostics.get(2).copied().unwrap_or(0);
        let normal_composition_observed = match observed_port {
            15_001 => "child_saw_original_then_foreign_rewrite_observed",
            16_001 => "foreign_rewrite_then_child_saw_rewritten",
            value => {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!("S10 normal child observed unexpected destination port {value}"),
                ));
            }
        }
        .to_owned();

        let foreign_trace = self.foreign_trace()?;
        let foreign_program_after =
            pinned_program(&commands, &self.foreign_root.join("foreign_rewrite"))?;
        Ok(S10Observation {
            ancestor_cgroup: ancestor.to_string_lossy().into_owned(),
            ancestor_inode,
            child_cgroup: child.to_string_lossy().into_owned(),
            child_inode,
            foreign_program_before,
            foreign_program_after,
            foreign_program_id,
            foreign_program_tag,
            foreign_attach_type: "cgroup_inet4_connect".to_owned(),
            foreign_attach_mode: "legacy_multi".to_owned(),
            ancestor_direct,
            initial_child_direct,
            initial_child_effective,
            foreign_allow_attached,
            rewrite_configuration: serde_json::json!({
                "original_ipv4": "10.200.255.1",
                "original_port": 15001,
                "rewritten_ipv4": "10.201.0.2",
                "rewritten_port": REWRITTEN_PORT,
                "object": "bpf/foreign-s10.o",
            }),
            nft_before,
            nft_exposed,
            nft_after,
            nft_exposure_rule: format!(
                "ip daddr 10.201.0.2 tcp dport 16001 ct state new accept comment {EXPOSURE_COMMENT}"
            ),
            nft_exposure_handle,
            nft_restoration_exact,
            case_a_membership,
            case_a_agent,
            case_a_original_accept,
            case_a_rewritten_accept,
            case_a_observe_packets,
            case_a_phase,
            case_b_membership,
            case_b_agent,
            case_b_original_accept,
            case_b_rewritten_accept,
            case_b_rewritten_peer,
            case_b_observe_packets,
            case_b_phase,
            normal_membership,
            normal_agent,
            normal_original_accept,
            normal_rewritten_accept,
            normal_observe_packets,
            normal_phase,
            normal_composition_observed,
            foreign_trace,
            invocation_ordering_claim:
                "characterized only from Soglia port diagnostics and foreign causal events; no bpftool list-order inference"
                    .to_owned(),
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        let before_id = observation
            .foreign_program_before
            .get("id")
            .and_then(Value::as_u64);
        let after_id = observation
            .foreign_program_after
            .get("id")
            .and_then(Value::as_u64);
        let before_tag = observation
            .foreign_program_before
            .get("tag")
            .and_then(Value::as_str);
        let after_tag = observation
            .foreign_program_after
            .get("tag")
            .and_then(Value::as_str);
        if observation.foreign_allow_attached
            || observation.foreign_attach_type != "cgroup_inet4_connect"
            || observation.foreign_attach_mode != "legacy_multi"
            || before_id != Some(observation.foreign_program_id)
            || after_id != before_id
            || before_tag != Some(observation.foreign_program_tag.as_str())
            || after_tag != before_tag
            || !contains_program(&observation.ancestor_direct, "foreign_rewrite")
            || array_len(&observation.initial_child_direct) != 6
            || array_len(&observation.initial_child_effective) != 7
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 foreign rewrite identity or ancestor/child composition was not proven",
            ));
        }
        for membership in [
            &observation.case_a_membership,
            &observation.case_b_membership,
            &observation.normal_membership,
        ] {
            if !membership.proven || membership.target_inode != observation.child_inode {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S10 live subject placement was not proven for every attempt",
                ));
            }
        }
        if !observation.nft_restoration_exact
            || contains_json_string(&observation.nft_before, EXPOSURE_COMMENT)
            || !contains_json_string(&observation.nft_exposed, EXPOSURE_COMMENT)
            || contains_json_string(&observation.nft_after, EXPOSURE_COMMENT)
            || !contains_json_string(&observation.nft_before, OBSERVE_COMMENT)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 exact nft exposure and structural restoration was not proven",
            ));
        }
        if agent_ok(&observation.case_a_agent)
            || observation.case_a_original_accept
            || observation.case_a_rewritten_accept
            || observation.case_a_observe_packets < 1
            || observation.case_a_phase.diagnostic_entries.get(1) != Some(&1)
            || observation.case_a_phase.counters.get(4) != Some(&0)
            || array_len(&observation.case_a_phase.deny_map) != 0
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 case A did not isolate nft as the normal final barrier",
            ));
        }
        if !agent_ok(&observation.case_b_agent)
            || observation.case_b_original_accept
            || !observation.case_b_rewritten_accept
            || observation.case_b_observe_packets <= observation.case_a_observe_packets
            || observation.case_b_phase.diagnostic_entries.get(1) != Some(&2)
            || observation.case_b_phase.counters.get(4) != Some(&0)
            || array_len(&observation.case_b_phase.deny_map) != 0
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 case B did not causally expose the same rewritten path",
            ));
        }
        if agent_ok(&observation.normal_agent)
            || observation.normal_original_accept
            || observation.normal_rewritten_accept
            || observation.normal_phase.diagnostic_entries.get(1) != Some(&1)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 normal Soglia composition unexpectedly established or was not observed",
            ));
        }
        let observed_port = observation
            .normal_phase
            .port_diagnostics
            .get(2)
            .copied()
            .unwrap_or(0);
        if observed_port == 15_001
            && (observation.normal_phase.counters.get(4) != Some(&0)
                || array_len(&observation.normal_phase.deny_map) != 0)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 child saw original destination but recorded an unexplained BPF deny",
            ));
        }
        if observed_port == 16_001
            && (observation.normal_phase.counters.get(4) != Some(&1)
                || array_len(&observation.normal_phase.deny_map) != 1)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 child saw rewritten destination without its expected normal BPF deny",
            ));
        }
        if observation.foreign_trace.len() != 3
            || observation.foreign_trace.iter().any(|record| {
                record.who != 3
                    || record.destination_ipv4_raw != u32::from_ne_bytes([10, 200, 255, 1])
                    || record.destination_port != 15_001
                    || record.rewritten != 1
            })
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S10 foreign ring evidence did not prove all three controlled rewrites",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if let Some(mut agent) = self.active_agent.take() {
            let _ = agent.terminate();
            let _ = agent.wait(Duration::from_secs(3));
        }
        if self.exposure_handle.is_some()
            && Path::new("/run/netns").join(&self.fixture.netns).exists()
        {
            self.restore_nft(context)?;
        }
        self.detach_foreign(context)?;
        <S1 as SpikeTest>::cleanup(&mut self.fixture, context)
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        if self.foreign_root.exists() {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S10 foreign bpffs root remains after cleanup",
            ));
        }
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)
    }
}

fn parse_agent_output(output: CommandOutput) -> Result<AgentResult, TestError> {
    let stdout = output.stdout_text();
    let json = stdout
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()
        .map_err(|error| TestError::infra(format!("parse S10 agent JSON: {error}")))?;
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
            value
                .get("cmd")
                .and_then(Value::as_str)
                .is_some_and(|command| command == format!("direct {ORIGINAL}"))
                && value.get("ok").and_then(Value::as_bool) == Some(true)
        })
}

fn accept_now(
    listener: &TcpListener,
) -> Result<Option<(std::net::TcpStream, std::net::SocketAddr)>, TestError> {
    match listener.accept() {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(TestError::infra(format!("S10 listener accept: {error}"))),
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
    require_success(&output, "inspect S10 pinned foreign program")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse S10 pinned program: {error}")))
}

fn map_by_id(commands: &CommandExecutor, id: u64) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("map"),
            OsString::from("show"),
            OsString::from("id"),
            OsString::from(id.to_string()),
        ]))
        .map_err(TestError::infra)?;
    require_success(&output, "inspect S10 foreign map")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse S10 foreign map: {error}")))
}

fn counter_packets(value: &Value, comment: &str) -> Result<u64, TestError> {
    fn packets(value: &Value) -> Option<u64> {
        match value {
            Value::Object(object) => object
                .get("packets")
                .and_then(Value::as_u64)
                .or_else(|| object.values().find_map(packets)),
            Value::Array(values) => values.iter().find_map(packets),
            _ => None,
        }
    }
    fn find(value: &Value, comment: &str) -> Option<u64> {
        match value {
            Value::Object(object) => {
                if object.get("comment").and_then(Value::as_str) == Some(comment) {
                    packets(value)
                } else {
                    object.values().find_map(|value| find(value, comment))
                }
            }
            Value::Array(values) => values.iter().find_map(|value| find(value, comment)),
            _ => None,
        }
    }
    find(value, comment)
        .ok_or_else(|| TestError::infra(format!("nft counter for {comment} missing")))
}

fn stable_nft(value: &Value) -> Value {
    let mut value = value.clone();
    fn normalize(value: &mut Value) {
        match value {
            Value::Object(object) => {
                if object.contains_key("packets") && object.contains_key("bytes") {
                    object.insert("packets".to_owned(), Value::from(0));
                    object.insert("bytes".to_owned(), Value::from(0));
                }
                object.values_mut().for_each(normalize);
            }
            Value::Array(values) => values.iter_mut().for_each(normalize),
            _ => {}
        }
    }
    normalize(&mut value);
    value
}

fn contains_program(value: &Value, name: &str) -> bool {
    value.as_array().is_some_and(|programs| {
        programs
            .iter()
            .any(|program| program.get("name").and_then(Value::as_str) == Some(name))
    })
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
