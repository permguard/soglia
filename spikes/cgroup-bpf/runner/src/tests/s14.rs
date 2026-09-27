// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::{HashMap, Map, MapData};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{CommandExecutor, CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::s1::{
    RESOLVE_TIMEOUT, S1, WAIT_SHORT, decode_evidence, hex, inode, json_cgroup, json_command,
    line_present, process_is_stopped, read_pid, read_trimmed, tuple_key, wait_for_path,
    wait_for_process_stopped,
};
use crate::tests::{SpikeTest, TestError};

const MATRIX: [usize; 5] = [1, 4, 16, 32, 64];
const MAP_NAMES: [&str; 8] = [
    "soglia_policy",
    "soglia_tuples",
    "soglia_cookie_a",
    "soglia_sk_b",
    "soglia_events",
    "soglia_counters",
    "soglia_denies",
    "soglia_meta",
];
const LINK_NAMES: [&str; 6] = [
    "sock_create",
    "connect4",
    "connect6",
    "sendmsg4",
    "sendmsg6",
    "sock_ops",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Inventory {
    programs: Value,
    links: Value,
    maps: Value,
    bpffs: Vec<String>,
    cgroups: Vec<String>,
    netns: Value,
    interfaces: Value,
    nft: Value,
    owned_processes: Vec<String>,
    meminfo: BTreeMap<String, u64>,
    limits: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoaderTimings {
    object_load_ns: u128,
    policy_setup_ns: u128,
    program_load_ns: u128,
    attach_ns: u128,
    pin_ns: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoaderInstance {
    index: usize,
    ident: u64,
    cgroup: String,
    fd_before: usize,
    fd_after: usize,
    timings: LoaderTimings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoaderReady {
    count: usize,
    preparation_ns: u128,
    totals: LoaderTimings,
    instances: Vec<LoaderInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoaderFailure {
    index: usize,
    ident: u64,
    operation: String,
    error: String,
    open_fd_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Membership {
    index: usize,
    trusted_pid: u32,
    host_pid: u32,
    agent_pid: u32,
    cgroup: String,
    cgroup_inode: u64,
    proc_cgroup: String,
    cgroup_procs: String,
    process_netns_inode: u64,
    owned_netns_inode: u64,
    proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attribution {
    origin_index: usize,
    execution_id: String,
    expected_ident: u64,
    accepted_peer: String,
    accepted_local: String,
    tuple_key_hex: String,
    tuple_evidence: Vec<u64>,
    resolved_index: Option<usize>,
    application_bytes_before_resolve: u64,
    dns_before_resolve: u64,
    outbound_before_resolve: u64,
    ip_fallback_authorization: bool,
    resolve_latency_ns: u128,
    application_line_after_resolve: String,
    agent_exit_code: Option<i32>,
    agent_signal: Option<i32>,
    correct: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PointStatus {
    Pass,
    BoundedLimit,
    SkippedHealthyEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceCounts {
    programs: usize,
    links: usize,
    maps: usize,
    pins: usize,
    program_ids: Vec<u64>,
    link_ids: Vec<u64>,
    map_ids: Vec<u64>,
    program_bytes_xlated: u64,
    program_bytes_jited: u64,
    program_bytes_memlock: u64,
    map_bytes_memlock: u64,
    map_names: BTreeMap<String, usize>,
    program_names: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PointObservation {
    requested: usize,
    status: PointStatus,
    complete_instances: usize,
    loader: Option<LoaderReady>,
    limit: Option<LoaderFailure>,
    resources: Option<ResourceCounts>,
    memberships: Vec<Membership>,
    attributions: Vec<Attribution>,
    direct_and_effective_six: bool,
    teardown_ns: u128,
    cleanup_equal: bool,
    cleanup: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S14Observation {
    candidate: String,
    selected: bool,
    historical_semantics: Value,
    baseline: Inventory,
    matrix: Vec<PointObservation>,
    observed_model: Value,
    resource_limit_tuned: bool,
    production_backend_implemented: bool,
    candidate_ranked: bool,
}

#[derive(Debug, Clone)]
struct Execution {
    index: usize,
    id: String,
    ident: u64,
    cgroup: PathBuf,
    inode: u64,
    netns: String,
    veth: String,
    ip: Ipv4Addr,
}

#[derive(Clone)]
struct PointRuntime {
    count: usize,
    root: PathBuf,
    map_pins: PathBuf,
    link_pins: PathBuf,
    proxy_link: String,
    bpffs_base_preexisting: bool,
    executions: Vec<Execution>,
    samples: Vec<usize>,
}

pub struct S14 {
    fixture: S1,
    baseline: Option<Inventory>,
    current: Option<PointRuntime>,
    loader: Option<RunningCommand>,
    agents: Vec<RunningCommand>,
}

impl S14 {
    pub fn new(context: &TestContext) -> Self {
        Self {
            fixture: S1::new_s14(context),
            baseline: None,
            current: None,
            loader: None,
            agents: Vec::new(),
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        self.fixture.commands(context)
    }

    fn executions(&self) -> Result<&Path, TestError> {
        self.fixture
            .executions
            .as_deref()
            .ok_or_else(|| TestError::infra("S14 executions root missing"))
    }

    fn create_point(&mut self, context: &mut TestContext, count: usize) -> Result<(), TestError> {
        let short = short_id(&context.run_id);
        let root = self.fixture.runtime_root.join(format!("n{count:03}"));
        fs::create_dir(&root)
            .map_err(|error| TestError::infra(format!("create S14 point runtime: {error}")))?;
        let pin_root = self.fixture.pin_root.join(format!("n{count:03}"));
        let proxy_link = format!("s14p{short}");
        let runtime = PointRuntime {
            count,
            map_pins: pin_root.join("maps"),
            link_pins: pin_root.join("links"),
            root,
            proxy_link,
            bpffs_base_preexisting: Path::new("/sys/fs/bpf/soglia-spike-runner").exists(),
            executions: Vec::new(),
            samples: sample_indices(count),
        };
        self.current = Some(runtime);
        run_ok(
            &self.commands(context),
            "ip",
            vec![
                "link",
                "add",
                self.current.as_ref().unwrap().proxy_link.as_str(),
                "type",
                "dummy",
            ],
            "create S14 proxy link",
        )?;
        let proxy = self.current.as_ref().unwrap().proxy_link.clone();
        run_ok(
            &self.commands(context),
            "ip",
            vec!["addr", "add", "10.200.255.1/32", "dev", &proxy],
            "address S14 proxy",
        )?;
        run_ok(
            &self.commands(context),
            "ip",
            vec!["link", "set", &proxy, "up"],
            "enable S14 proxy",
        )?;
        context.resources.register(
            "s14",
            "S14 proxy interface",
            Resource::Interface { name: proxy },
        );

        let rules = self.current.as_ref().unwrap().root.join("netns.nft");
        fs::write(&rules, b"table inet soglia_s14 {\n chain input { type filter hook input priority filter; policy drop; iif \"lo\" accept; ct state established,related accept; }\n chain output { type filter hook output priority filter; policy drop; oif \"lo\" accept; ct state established,related accept; ip daddr 10.200.255.1 tcp dport 15001 ct state new accept; }\n chain forward { type filter hook forward priority filter; policy drop; }\n}\n")
            .map_err(|error| TestError::infra(format!("write S14 nft rules: {error}")))?;
        for index in 0..count {
            let third = 202 + index / 63;
            let fourth = (index % 63) * 4 + 1;
            let netns = format!("sg14-{short}-{count}-{index:03}");
            let veth = format!("s14{short}h{index:03}");
            let cgroup = self.executions()?.join(format!("s14-e{index:03}"));
            fs::create_dir(&cgroup)
                .map_err(|error| TestError::infra(format!("create S14 cgroup {index}: {error}")))?;
            let cgroup_inode = inode(&cgroup).map_err(TestError::infra)?;
            self.current.as_mut().unwrap().executions.push(Execution {
                index,
                id: format!("s14-n{count}-execution-{index:03}-generation-1"),
                ident: 14_000_000 + count as u64 * 1_000 + index as u64,
                cgroup: cgroup.clone(),
                inode: cgroup_inode,
                netns: netns.clone(),
                veth: veth.clone(),
                ip: Ipv4Addr::new(
                    10,
                    u8::try_from(third).map_err(|e| TestError::infra(e.to_string()))?,
                    0,
                    u8::try_from(fourth).map_err(|e| TestError::infra(e.to_string()))?,
                ),
            });
            context.resources.register(
                "s14",
                format!("S14 Execution {index}"),
                Resource::Cgroup {
                    path: cgroup,
                    inode: cgroup_inode,
                },
            );
            run_ok(
                &self.commands(context),
                "ip",
                vec!["netns", "add", &netns],
                "create S14 netns",
            )?;
            context.resources.register(
                "s14",
                format!("S14 netns {index}"),
                Resource::Netns {
                    name: netns.clone(),
                },
            );
            run_ok(
                &self.commands(context),
                "ip",
                vec![
                    "link", "add", &veth, "type", "veth", "peer", "name", "eth0", "netns", &netns,
                ],
                "create S14 veth",
            )?;
            context.resources.register(
                "s14",
                format!("S14 veth {index}"),
                Resource::Interface { name: veth.clone() },
            );
            let guest = format!("10.{third}.0.{fourth}/30");
            let host_ip = format!("10.{third}.0.{}/30", fourth + 1);
            let gateway = format!("10.{third}.0.{}", fourth + 1);
            for arguments in [
                vec!["addr", "add", host_ip.as_str(), "dev", veth.as_str()],
                vec!["link", "set", veth.as_str(), "up"],
                vec![
                    "netns",
                    "exec",
                    netns.as_str(),
                    "ip",
                    "link",
                    "set",
                    "lo",
                    "up",
                ],
                vec![
                    "netns",
                    "exec",
                    netns.as_str(),
                    "ip",
                    "addr",
                    "add",
                    guest.as_str(),
                    "dev",
                    "eth0",
                ],
                vec![
                    "netns",
                    "exec",
                    netns.as_str(),
                    "ip",
                    "link",
                    "set",
                    "eth0",
                    "up",
                ],
                vec![
                    "netns",
                    "exec",
                    netns.as_str(),
                    "ip",
                    "route",
                    "add",
                    "10.200.255.1/32",
                    "via",
                    gateway.as_str(),
                    "dev",
                    "eth0",
                ],
            ] {
                run_ok(
                    &self.commands(context),
                    "ip",
                    arguments,
                    "configure S14 topology",
                )?;
            }
            run_ok(
                &self.commands(context),
                "ip",
                vec![
                    "netns",
                    "exec",
                    &netns,
                    "nft",
                    "-f",
                    rules.to_string_lossy().as_ref(),
                ],
                "install S14 namespace nft",
            )?;
        }
        Ok(())
    }

    fn run_point(
        &mut self,
        context: &mut TestContext,
        count: usize,
    ) -> Result<PointObservation, TestError> {
        let before = capture_inventory(
            &self.commands(context),
            &context.run_id,
            self.fixture.delegated_root.as_deref(),
        )?;
        context
            .evidence
            .write_json(format!("s14/points/n{count:03}/before.json"), &before)
            .map_err(|e| TestError::infra(format!("write S14 before: {e}")))?;
        self.create_point(context, count)?;
        let point = self
            .current
            .as_ref()
            .ok_or_else(|| TestError::infra("S14 point missing"))?;
        let ready = point.root.join("loader-ready.json");
        let finish = point.root.join("loader-finish");
        let done = point.root.join("loader-done.json");
        let failure = point.root.join("loader-failure.json");
        let mut loader = self
            .commands(context)
            .spawn(
                &CommandSpec::new(context.artifact("bin/s14-loader"))
                    .args([
                        context.artifact("bpf/soglia.o").into_os_string(),
                        self.executions()?.as_os_str().to_owned(),
                        point.map_pins.as_os_str().to_owned(),
                        point.link_pins.as_os_str().to_owned(),
                        OsString::from(count.to_string()),
                        ready.as_os_str().to_owned(),
                        finish.as_os_str().to_owned(),
                        done.as_os_str().to_owned(),
                        failure.as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(180)),
            )
            .map_err(TestError::infra)?;
        let loader_pid = loader.id();
        context.resources.register(
            "s14",
            format!("S14 loader N={count}"),
            Resource::Process { pid: loader_pid },
        );
        let wait_started = Instant::now();
        loop {
            if ready.exists() || failure.exists() {
                break;
            }
            if loader.try_wait().map_err(TestError::infra)?.is_some() {
                break;
            }
            if wait_started.elapsed() >= Duration::from_secs(60) {
                let _ = loader.terminate();
                let output = loader
                    .wait(Duration::from_secs(5))
                    .map_err(TestError::infra)?;
                return Err(TestError::infra(format!(
                    "S14 loader readiness timeout: {}",
                    output.stderr_text()
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !ready.exists() {
            let output = loader
                .wait(Duration::from_secs(5))
                .map_err(TestError::infra)?;
            let limit: LoaderFailure = read_json(&failure, "S14 loader failure")?;
            if count != 64 || !limit.error.contains("Too many open files") {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!(
                        "S14 loader failed at N={count}: {}; stderr={}",
                        limit.error,
                        output.stderr_text()
                    ),
                ));
            }
            let started = Instant::now();
            let cleanup = self.cleanup_point(context)?;
            let after = capture_inventory(
                &self.commands(context),
                &context.run_id,
                self.fixture.delegated_root.as_deref(),
            )?;
            let cleanup_equal = inventory_equal(&before, &after);
            context
                .evidence
                .write_json(format!("s14/points/n{count:03}/limit.json"), &limit)
                .map_err(|e| TestError::infra(format!("write S14 limit: {e}")))?;
            return Ok(PointObservation {
                requested: count,
                status: PointStatus::BoundedLimit,
                complete_instances: limit.index,
                loader: None,
                limit: Some(limit),
                resources: None,
                memberships: Vec::new(),
                attributions: Vec::new(),
                direct_and_effective_six: false,
                teardown_ns: started.elapsed().as_nanos(),
                cleanup_equal,
                cleanup,
            });
        }
        let loader_ready: LoaderReady = read_json(&ready, "S14 loader ready")?;
        self.loader = Some(loader);
        let during = capture_inventory(
            &self.commands(context),
            &context.run_id,
            self.fixture.delegated_root.as_deref(),
        )?;
        context
            .evidence
            .write_json(format!("s14/points/n{count:03}/during.json"), &during)
            .map_err(|e| TestError::infra(format!("write S14 during: {e}")))?;
        let resources = resource_counts(&before, &during, &point.map_pins, &point.link_pins)?;
        let mut all_six = true;
        for execution in &point.executions {
            let direct = json_cgroup(&self.commands(context), &execution.cgroup, false)?;
            let effective = json_cgroup(&self.commands(context), &execution.cgroup, true)?;
            all_six &= direct.as_array().is_some_and(|v| v.len() == 6)
                && effective.as_array().is_some_and(|v| v.len() == 6);
        }
        let (memberships, attributions) = self.exercise_samples(context)?;
        fs::write(&finish, b"finish\n")
            .map_err(|e| TestError::infra(format!("release S14 loader teardown: {e}")))?;
        let loader = self
            .loader
            .take()
            .ok_or_else(|| TestError::infra("S14 loader missing"))?;
        let output = loader
            .wait(Duration::from_secs(30))
            .map_err(TestError::infra)?;
        require_success(&output, "S14 loader teardown")?;
        wait_for_path(&done, WAIT_SHORT).map_err(TestError::infra)?;
        let done_json: Value = read_json(&done, "S14 loader done")?;
        let bpf_teardown_ns = done_json
            .get("bpf_teardown_ns")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u128;
        let started = Instant::now();
        let cleanup = self.cleanup_point(context)?;
        let topology_teardown_ns = started.elapsed().as_nanos();
        let after = capture_inventory(
            &self.commands(context),
            &context.run_id,
            self.fixture.delegated_root.as_deref(),
        )?;
        context
            .evidence
            .write_json(format!("s14/points/n{count:03}/after.json"), &after)
            .map_err(|e| TestError::infra(format!("write S14 after: {e}")))?;
        let cleanup_equal = inventory_equal(&before, &after);
        Ok(PointObservation {
            requested: count,
            status: PointStatus::Pass,
            complete_instances: count,
            loader: Some(loader_ready),
            limit: None,
            resources: Some(resources),
            memberships,
            attributions,
            direct_and_effective_six: all_six,
            teardown_ns: bpf_teardown_ns + topology_teardown_ns,
            cleanup_equal,
            cleanup,
        })
    }

    fn exercise_samples(
        &mut self,
        context: &mut TestContext,
    ) -> Result<(Vec<Membership>, Vec<Attribution>), TestError> {
        let point = self
            .current
            .as_ref()
            .ok_or_else(|| TestError::infra("S14 point missing"))?;
        let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
            .map_err(|e| TestError::infra(format!("bind S14 proxy: {e}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| TestError::infra(format!("set S14 listener: {e}")))?;
        let mut memberships = Vec::new();
        for &index in &point.samples {
            let execution = &point.executions[index];
            let host_ready = point.root.join(format!("e{index:03}.host-ready"));
            let agent_ready = point.root.join(format!("e{index:03}.agent-ready"));
            let agent_go = point.root.join(format!("e{index:03}.go"));
            let agent = self
                .commands(context)
                .spawn(
                    &CommandSpec::new(&context.executable)
                        .args([
                            OsString::from("_agent-launcher"),
                            OsString::from("--netns"),
                            Path::new("/run/netns")
                                .join(&execution.netns)
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
                            OsString::from("proxy-fixed 40000 1"),
                        ])
                        .timeout(Duration::from_secs(45)),
                )
                .map_err(TestError::infra)?;
            let pid = agent.id();
            context.resources.register(
                "s14",
                format!("S14 sampled agent {index}"),
                Resource::Process { pid },
            );
            self.agents.push(agent);
            wait_for_path(&host_ready, WAIT_SHORT).map_err(TestError::infra)?;
            wait_for_process_stopped(pid, WAIT_SHORT).map_err(TestError::infra)?;
            let host_pid = read_pid(&host_ready).map_err(TestError::infra)?;
            fs::write(execution.cgroup.join("cgroup.procs"), format!("{pid}\n"))
                .map_err(|e| TestError::infra(format!("place S14 agent: {e}")))?;
            let expected = expected_cgroup(&execution.cgroup)?;
            let before = read_trimmed(Path::new(&format!("/proc/{pid}/cgroup")))?;
            let procs_before = read_trimmed(&execution.cgroup.join("cgroup.procs"))?;
            if host_pid != pid
                || !line_present(&before, &expected)
                || !line_present(&procs_before, &pid.to_string())
                || !process_is_stopped(pid).map_err(TestError::infra)?
            {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!("S14 subject placement failed for {index}"),
                ));
            }
            kill(
                Pid::from_raw(i32::try_from(pid).map_err(|e| TestError::infra(e.to_string()))?),
                Signal::SIGCONT,
            )
            .map_err(|e| TestError::infra(format!("continue S14 agent: {e}")))?;
            wait_for_path(&agent_ready, WAIT_SHORT).map_err(TestError::infra)?;
            let agent_pid = read_pid(&agent_ready).map_err(TestError::infra)?;
            let proc_cgroup = read_trimmed(Path::new(&format!("/proc/{pid}/cgroup")))?;
            let cgroup_procs = read_trimmed(&execution.cgroup.join("cgroup.procs"))?;
            let process_netns_inode =
                inode(Path::new(&format!("/proc/{pid}/ns/net"))).map_err(TestError::infra)?;
            let owned_netns_inode =
                inode(&Path::new("/run/netns").join(&execution.netns)).map_err(TestError::infra)?;
            let proven = agent_pid == pid
                && line_present(&proc_cgroup, &expected)
                && line_present(&cgroup_procs, &pid.to_string())
                && process_netns_inode == owned_netns_inode;
            if !proven {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!("S14 live placement failed for {index}"),
                ));
            }
            memberships.push(Membership {
                index,
                trusted_pid: pid,
                host_pid,
                agent_pid,
                cgroup: execution.cgroup.to_string_lossy().into_owned(),
                cgroup_inode: execution.inode,
                proc_cgroup,
                cgroup_procs,
                process_netns_inode,
                owned_netns_inode,
                proven,
            });
        }
        for membership in &memberships {
            fs::write(
                point.root.join(format!("e{:03}.go", membership.index)),
                b"go\n",
            )
            .map_err(|e| TestError::infra(format!("release S14 connection: {e}")))?;
        }
        let map = MapData::from_pin(&point.map_pins.join("soglia_tuples"))
            .map_err(|e| TestError::infra(format!("open S14 tuples pin: {e:#}")))?;
        let map = Map::from_map_data(map)
            .map_err(|e| TestError::infra(format!("classify S14 tuples pin: {e:#}")))?;
        let tuples = HashMap::<_, [u8; 16], [u8; 64]>::try_from(map)
            .map_err(|e| TestError::infra(format!("open S14 tuples: {e:#}")))?;
        let by_ip = point
            .executions
            .iter()
            .map(|e| (e.ip, e.index))
            .collect::<BTreeMap<_, _>>();
        let by_ident = point
            .executions
            .iter()
            .map(|e| (e.ident, e.index))
            .collect::<BTreeMap<_, _>>();
        let mut accepted: Vec<(
            TcpStream,
            usize,
            SocketAddr,
            SocketAddr,
            [u64; 8],
            u128,
            String,
        )> = Vec::new();
        for _ in 0..memberships.len() {
            let started = Instant::now();
            let (stream, peer) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && started.elapsed() < Duration::from_secs(5) =>
                    {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err(TestError::new(
                            Verdict::Unproven,
                            "S14 proxy accept timed out",
                        ));
                    }
                    Err(e) => return Err(TestError::infra(format!("S14 accept: {e}"))),
                }
            };
            let local = stream
                .local_addr()
                .map_err(|e| TestError::infra(format!("S14 local addr: {e}")))?;
            let origin = match peer.ip() {
                std::net::IpAddr::V4(ip) => *by_ip.get(&ip).ok_or_else(|| {
                    TestError::new(Verdict::Unproven, format!("unknown S14 source {ip}"))
                })?,
                _ => return Err(TestError::new(Verdict::Unproven, "S14 source was not IPv4")),
            };
            let key = tuple_key(peer, local).map_err(TestError::infra)?;
            let lookup = Instant::now();
            let evidence = loop {
                match tuples.get(&key, 0) {
                    Ok(value) => break decode_evidence(value),
                    Err(aya::maps::MapError::KeyNotFound) if lookup.elapsed() < RESOLVE_TIMEOUT => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(aya::maps::MapError::KeyNotFound) => {
                        return Err(TestError::new(
                            Verdict::Unproven,
                            format!("S14 Resolve timed out for {origin}"),
                        ));
                    }
                    Err(e) => return Err(TestError::infra(format!("S14 tuple lookup: {e:#}"))),
                }
            };
            accepted.push((
                stream,
                origin,
                peer,
                local,
                evidence,
                lookup.elapsed().as_nanos(),
                hex(&key),
            ));
        }
        let mut attributions = Vec::new();
        for (mut stream, origin, peer, local, evidence, latency, key) in accepted {
            let execution = &point.executions[origin];
            let resolved_index = by_ident.get(&evidence[3]).copied();
            let correct = resolved_index == Some(origin)
                && evidence[1] == execution.inode
                && evidence[2] == execution.inode;
            if !correct {
                return Err(TestError::new(
                    Verdict::Fail,
                    format!("S14 cross-attribution at Execution {origin}"),
                ));
            }
            let mut line = String::new();
            BufReader::new(
                stream
                    .try_clone()
                    .map_err(|e| TestError::infra(e.to_string()))?,
            )
            .read_line(&mut line)
            .map_err(|e| TestError::infra(format!("read S14 app bytes: {e}")))?;
            writeln!(stream, "ATTRIBUTED {}", execution.id)
                .map_err(|e| TestError::infra(format!("write S14 verdict: {e}")))?;
            stream
                .flush()
                .map_err(|e| TestError::infra(format!("flush S14 verdict: {e}")))?;
            attributions.push(Attribution {
                origin_index: origin,
                execution_id: execution.id.clone(),
                expected_ident: execution.ident,
                accepted_peer: peer.to_string(),
                accepted_local: local.to_string(),
                tuple_key_hex: key,
                tuple_evidence: evidence.to_vec(),
                resolved_index,
                application_bytes_before_resolve: 0,
                dns_before_resolve: 0,
                outbound_before_resolve: 0,
                ip_fallback_authorization: false,
                resolve_latency_ns: latency,
                application_line_after_resolve: line.trim_end().to_owned(),
                agent_exit_code: None,
                agent_signal: None,
                correct,
            });
        }
        for (index, agent) in self.agents.drain(..).enumerate() {
            let output = agent
                .wait(Duration::from_secs(15))
                .map_err(TestError::infra)?;
            if !output.success() {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!("S14 sampled agent failed: {}", output.stderr_text()),
                ));
            }
            attributions[index].agent_exit_code = output.record.exit_code;
            attributions[index].agent_signal = output.record.signal;
        }
        context
            .evidence
            .write_json(
                format!("s14/points/n{:03}/membership.json", point.count),
                &memberships,
            )
            .map_err(|e| TestError::infra(format!("write S14 memberships: {e}")))?;
        context
            .evidence
            .write_json(
                format!("s14/points/n{:03}/attribution.json", point.count),
                &attributions,
            )
            .map_err(|e| TestError::infra(format!("write S14 attribution: {e}")))?;
        Ok((memberships, attributions))
    }

    fn cleanup_point(&mut self, context: &TestContext) -> Result<Value, TestError> {
        let Some(point) = self.current.clone() else {
            return Ok(serde_json::json!({"clean":true,"point":"none"}));
        };
        for agent in &mut self.agents {
            let _ = agent.terminate();
        }
        while let Some(agent) = self.agents.pop() {
            let _ = agent.wait(Duration::from_secs(5));
        }
        if let Some(mut loader) = self.loader.take() {
            let _ = fs::write(point.root.join("loader-finish"), b"finish\n");
            if loader.try_wait().map_err(TestError::infra)?.is_none() {
                let _ = loader.wait(Duration::from_secs(15));
            } else {
                let _ = loader.wait(Duration::from_secs(5));
            }
        }
        remove_exact_pins(&point)?;
        let commands = self.commands(context);
        for execution in &point.executions {
            if execution.cgroup.join("cgroup.kill").exists() {
                let _ = fs::write(execution.cgroup.join("cgroup.kill"), b"1\n");
            }
        }
        for execution in point.executions.iter().rev() {
            if Path::new("/run/netns").join(&execution.netns).exists() {
                run_ok(
                    &commands,
                    "ip",
                    vec!["netns", "del", &execution.netns],
                    "delete S14 netns",
                )?;
            }
            delete_link_or_prove_absent(&commands, &execution.veth, "delete S14 veth")?;
            remove_empty(&execution.cgroup)?;
        }
        delete_link_or_prove_absent(&commands, &point.proxy_link, "delete S14 proxy")?;
        for execution in &point.executions {
            for suffix in ["host-ready", "agent-ready", "go"] {
                remove_file(&point.root.join(format!("e{:03}.{suffix}", execution.index)))?;
            }
        }
        for file in [
            "netns.nft",
            "loader-ready.json",
            "loader-finish",
            "loader-done.json",
            "loader-failure.json",
        ] {
            remove_file(&point.root.join(file))?;
        }
        remove_empty(&point.root)?;
        let pin_root_absent = !point.map_pins.parent().unwrap_or(&point.map_pins).exists();
        let cgroups_absent = point.executions.iter().all(|e| !e.cgroup.exists());
        let netns_absent = point
            .executions
            .iter()
            .all(|e| !Path::new("/run/netns").join(&e.netns).exists());
        let mut veths_absent = true;
        for execution in &point.executions {
            veths_absent &= link_is_absent(&commands, &execution.veth, "verify S14 veth cleanup")?;
        }
        let proxy_absent =
            link_is_absent(&commands, &point.proxy_link, "verify S14 proxy cleanup")?;
        let clean =
            pin_root_absent && cgroups_absent && netns_absent && veths_absent && proxy_absent;
        if clean {
            self.current = None;
        }
        Ok(
            serde_json::json!({"clean":clean,"count":point.count,"pin_root_absent":pin_root_absent,"cgroups_absent":cgroups_absent,"netns_absent":netns_absent,"veths_absent":veths_absent,"proxy_absent":proxy_absent}),
        )
    }
}

impl SpikeTest for S14 {
    type Observation = S14Observation;

    fn id(&self) -> TestId {
        TestId::S14
    }

    fn invariant(&self) -> &'static str {
        "Candidate C resource scaling is empirically characterized while sampled Execution identities remain distinct and every point returns to baseline"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if self.fixture.runtime_root.exists() || self.fixture.pin_root.exists() {
            return Err(TestError::new(
                Verdict::Unproven,
                "S14 owned path existed before preparation",
            ));
        }
        fs::create_dir_all(&self.fixture.runtime_root)
            .map_err(|e| TestError::infra(format!("create S14 runtime: {e}")))?;
        context.resources.register(
            "s14",
            "S14 runtime",
            Resource::Directory {
                path: self.fixture.runtime_root.clone(),
            },
        );
        self.fixture.start_delegation(context)?;
        let unused = self
            .fixture
            .target
            .take()
            .ok_or_else(|| TestError::infra("S14 delegated bootstrap child missing"))?;
        remove_empty(&unused)?;
        self.baseline = Some(capture_inventory(
            &self.commands(context),
            &context.run_id,
            self.fixture.delegated_root.as_deref(),
        )?);
        context
            .evidence
            .write_json("s14/baseline.json", self.baseline.as_ref().unwrap())
            .map_err(|e| TestError::infra(format!("write S14 baseline: {e}")))?;
        Ok(())
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let mut matrix = Vec::new();
        for count in MATRIX {
            if count == 64 {
                let available = read_meminfo()
                    .get("MemAvailable")
                    .copied()
                    .unwrap_or_default();
                if available <= 262_144 {
                    matrix.push(PointObservation { requested: 64, status: PointStatus::SkippedHealthyEnvelope, complete_instances: 0, loader: None, limit: None, resources: None, memberships: Vec::new(), attributions: Vec::new(), direct_and_effective_six: false, teardown_ns: 0, cleanup_equal: true, cleanup: serde_json::json!({"clean":true,"reason":"MemAvailable <= 256 MiB after N=32"}) });
                    break;
                }
            }
            let point = self.run_point(context, count)?;
            let bounded = matches!(point.status, PointStatus::BoundedLimit);
            context
                .evidence
                .write_json(format!("s14/points/n{count:03}/result.json"), &point)
                .map_err(|e| TestError::infra(format!("write S14 point: {e}")))?;
            validate_completed_point(&point)?;
            matrix.push(point);
            if bounded {
                break;
            }
        }
        let complete: Vec<_> = matrix
            .iter()
            .filter(|p| matches!(p.status, PointStatus::Pass))
            .collect();
        let observed_model = derive_model(&complete);
        Ok(S14Observation {
            candidate: "C_UNSELECTED".to_owned(),
            selected: false,
            historical_semantics: serde_json::json!({"identity":"per-instance exec_ident override","programs":"six separately loaded programs per Execution","maps":"eight maps pinned by name and shared; policy_local and .rodata private per instance","links":"six cgroup links pinned per Execution","migration":"historical BPF/Aya semantics preserved; Rust runner owns topology, assertions, evidence, cleanup and verdict"}),
            baseline: self
                .baseline
                .clone()
                .ok_or_else(|| TestError::infra("S14 baseline missing"))?,
            matrix,
            observed_model,
            resource_limit_tuned: false,
            production_backend_implemented: false,
            candidate_ranked: false,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        let required = [1, 4, 16, 32];
        for count in required {
            let point = observation
                .matrix
                .iter()
                .find(|p| p.requested == count)
                .ok_or_else(|| {
                    TestError::new(Verdict::Unproven, format!("S14 missing N={count}"))
                })?;
            if !matches!(point.status, PointStatus::Pass)
                || point.complete_instances != count
                || !point.direct_and_effective_six
                || !point.cleanup_equal
                || point.attributions.is_empty()
                || point
                    .attributions
                    .iter()
                    .any(|a| !a.correct || a.ip_fallback_authorization)
                || point.memberships.iter().any(|m| !m.proven)
            {
                return Err(TestError::new(
                    Verdict::Fail,
                    format!("S14 correctness/lifecycle invariant failed at N={count}"),
                ));
            }
            let Some(resources) = &point.resources else {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S14 resource model missing",
                ));
            };
            if resources.programs != 6 * count
                || resources.links != 6 * count
                || resources.maps != 8 + 2 * count
                || resources.pins != 8 + 6 * count
            {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!(
                        "S14 resource counts differed from observed Candidate-C model at N={count}"
                    ),
                ));
            }
        }
        if observation.selected
            || observation.candidate_ranked
            || observation.production_backend_implemented
            || observation.resource_limit_tuned
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S14 exceeded characterization scope",
            ));
        }
        if let Some(limit) = observation
            .matrix
            .iter()
            .find(|p| matches!(p.status, PointStatus::BoundedLimit))
            && (limit.requested != 64
                || limit
                    .limit
                    .as_ref()
                    .is_none_or(|v| !v.error.contains("Too many open files"))
                || !limit.cleanup_equal)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S14 higher-point limit was not exactly bounded and cleaned",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        let _ = self.cleanup_point(context)?;
        if let Some(run_pin_root) = self.fixture.pin_root.parent()
            && run_pin_root.exists()
        {
            remove_empty(run_pin_root)?;
        }
        if let Some(executions) = &self.fixture.executions {
            remove_empty(executions)?;
        }
        let output = self
            .commands(context)
            .run(&CommandSpec::new("systemctl").args(["stop", self.fixture.unit.as_str()]))
            .map_err(TestError::infra)?;
        if !output.success() && !output.stderr_text().contains("not loaded") {
            return Err(TestError::infra(format!(
                "stop S14 unit: {}",
                output.stderr_text()
            )));
        }
        remove_file(&self.fixture.runtime_root.join("delegation.json"))?;
        remove_empty(&self.fixture.runtime_root)?;
        if let Some(parent) = self.fixture.runtime_root.parent() {
            let _ = fs::remove_dir(parent);
        }
        Ok(())
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        let after = capture_inventory(
            &self.commands(context),
            &context.run_id,
            self.fixture.delegated_root.as_deref(),
        )?;
        let baseline = self
            .baseline
            .as_ref()
            .ok_or_else(|| TestError::infra("S14 cleanup baseline missing"))?;
        let owned_absent = !self.fixture.runtime_root.exists()
            && !self.fixture.pin_root.exists()
            && self.fixture.executions.as_ref().is_none_or(|p| !p.exists())
            && self
                .fixture
                .delegated_root
                .as_ref()
                .is_none_or(|p| !p.exists())
            && after
                .netns
                .as_array()
                .is_none_or(|items| items.iter().all(|v| !v.to_string().contains("sg14-")))
            && !Path::new("/run/soglia").join("cgroup-bpf-spike").exists();
        let bpf_clean = stable_programs(&baseline.programs) == stable_programs(&after.programs)
            && stable_bpf(&baseline.links) == stable_bpf(&after.links)
            && stable_bpf(&baseline.maps) == stable_bpf(&after.maps);
        let evidence = serde_json::json!({"owned_absent":owned_absent,"bpf_baseline_restored":bpf_clean,"bpffs_baseline_restored":baseline.bpffs==after.bpffs,"runtime_absent":!self.fixture.runtime_root.exists(),"pin_root_absent":!self.fixture.pin_root.exists(),"executions_absent":self.fixture.executions.as_ref().is_none_or(|p|!p.exists()),"delegated_root_absent":self.fixture.delegated_root.as_ref().is_none_or(|p|!p.exists()),"clean":owned_absent&&bpf_clean&&baseline.bpffs==after.bpffs});
        context
            .evidence
            .write_json("s14/final-cleanup.json", &evidence)
            .map_err(|e| TestError::infra(format!("write S14 cleanup: {e}")))?;
        if !owned_absent || !bpf_clean || baseline.bpffs != after.bpffs {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S14 independent final baseline was not restored",
            ));
        }
        context.resources.mark_owner_cleaned("s14");
        Ok(())
    }
}

fn capture_inventory(
    commands: &CommandExecutor,
    run_id: &str,
    delegated: Option<&Path>,
) -> Result<Inventory, TestError> {
    let programs = json_command(commands, ["-j", "prog", "show"])?;
    let links = json_command(commands, ["-j", "link", "show"])?;
    let maps = json_command(commands, ["-j", "map", "show"])?;
    let netns = json_output(
        commands,
        CommandSpec::new("ip").args(["-j", "netns", "list"]),
        "S14 netns inventory",
    )?;
    let interfaces = json_output(
        commands,
        CommandSpec::new("ip").args(["-j", "-details", "link", "show"]),
        "S14 link inventory",
    )?;
    let nft = json_output(
        commands,
        CommandSpec::new("nft").args(["-j", "list", "ruleset"]),
        "S14 nft inventory",
    )?;
    let cgroups = delegated
        .map(list_dirs)
        .transpose()
        .map_err(TestError::infra)?
        .unwrap_or_default();
    Ok(Inventory {
        programs,
        links,
        maps,
        bpffs: list_dirs(Path::new("/sys/fs/bpf")).map_err(TestError::infra)?,
        cgroups,
        netns,
        interfaces,
        nft,
        owned_processes: owned_processes(run_id),
        meminfo: read_meminfo(),
        limits: fs::read_to_string("/proc/self/limits").unwrap_or_default(),
    })
}

fn resource_counts(
    before: &Inventory,
    during: &Inventory,
    map_pins: &Path,
    link_pins: &Path,
) -> Result<ResourceCounts, TestError> {
    let programs = new_items(&before.programs, &during.programs)?;
    let links = new_items(&before.links, &during.links)?;
    let maps = new_items(&before.maps, &during.maps)?;
    let pins = list_files(map_pins).map_err(TestError::infra)?.len()
        + list_files(link_pins).map_err(TestError::infra)?.len();
    Ok(ResourceCounts {
        programs: programs.len(),
        links: links.len(),
        maps: maps.len(),
        pins,
        program_ids: ids(&programs),
        link_ids: ids(&links),
        map_ids: ids(&maps),
        program_bytes_xlated: sum(&programs, "bytes_xlated"),
        program_bytes_jited: sum(&programs, "bytes_jited"),
        program_bytes_memlock: sum(&programs, "bytes_memlock"),
        map_bytes_memlock: sum(&maps, "bytes_memlock"),
        map_names: group_names(&maps),
        program_names: group_names(&programs),
    })
}

fn derive_model(points: &[&PointObservation]) -> Value {
    let rows = points.iter().filter_map(|p| p.resources.as_ref().map(|r| serde_json::json!({"n":p.requested,"programs":r.programs,"links":r.links,"maps":r.maps,"pins":r.pins,"xlated":r.program_bytes_xlated,"jited":r.program_bytes_jited,"program_memlock":r.program_bytes_memlock,"map_memlock":r.map_bytes_memlock,"setup_ns":p.loader.as_ref().map(|v|v.preparation_ns),"teardown_ns":p.teardown_ns,"checks":p.attributions.len()}))).collect::<Vec<_>>();
    serde_json::json!({"empirical_rows":rows,"programs":"6*N","links":"6*N","maps":"8+2*N","pins":"8+6*N","shared_maps":MAP_NAMES,"per_execution_unpinned_maps":["policy_local",".rodata"],"sample_rule":"N=1:first; N=4:first,last; N>=16:first,middle,last"})
}

fn validate_completed_point(point: &PointObservation) -> Result<(), TestError> {
    if !point.cleanup_equal {
        return Err(TestError::new(
            Verdict::CleanupFail,
            format!(
                "S14 N={} did not return to its fresh baseline",
                point.requested
            ),
        ));
    }
    if matches!(point.status, PointStatus::Pass) {
        if !point.direct_and_effective_six
            || point.attributions.is_empty()
            || point
                .attributions
                .iter()
                .any(|value| !value.correct || value.ip_fallback_authorization)
            || point.memberships.iter().any(|value| !value.proven)
        {
            return Err(TestError::new(
                Verdict::Fail,
                format!("S14 correctness invariant failed at N={}", point.requested),
            ));
        }
        let resources = point
            .resources
            .as_ref()
            .ok_or_else(|| TestError::new(Verdict::Unproven, "S14 resource counts missing"))?;
        if resources.programs != 6 * point.requested
            || resources.links != 6 * point.requested
            || resources.maps != 8 + 2 * point.requested
            || resources.pins != 8 + 6 * point.requested
        {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S14 resource model mismatch at N={}", point.requested),
            ));
        }
    }
    Ok(())
}

fn sample_indices(count: usize) -> Vec<usize> {
    if count == 1 {
        vec![0]
    } else if count <= 4 {
        vec![0, count - 1]
    } else {
        vec![0, count / 2, count - 1]
    }
}
fn expected_cgroup(path: &Path) -> Result<String, TestError> {
    Ok(format!(
        "0::/{}",
        path.strip_prefix("/sys/fs/cgroup")
            .map_err(|_| TestError::infra("S14 cgroup outside cgroup2"))?
            .to_string_lossy()
            .trim_start_matches('/')
    ))
}
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, TestError> {
    serde_json::from_slice(
        &fs::read(path).map_err(|e| TestError::infra(format!("read {label}: {e}")))?,
    )
    .map_err(|e| TestError::infra(format!("parse {label}: {e}")))
}
fn json_output(
    commands: &CommandExecutor,
    spec: CommandSpec,
    label: &str,
) -> Result<Value, TestError> {
    let output = commands.run(&spec).map_err(TestError::infra)?;
    require_success(&output, label)?;
    serde_json::from_slice(&output.stdout)
        .map_err(|e| TestError::infra(format!("parse {label}: {e}")))
}
fn run_ok(
    commands: &CommandExecutor,
    executable: &str,
    args: Vec<&str>,
    label: &str,
) -> Result<(), TestError> {
    let output = commands
        .run(&CommandSpec::new(executable).args(args))
        .map_err(TestError::infra)?;
    require_success(&output, label)
}
fn require_success(output: &CommandOutput, label: &str) -> Result<(), TestError> {
    output.require_success(label).map_err(TestError::infra)
}
fn short_id(run_id: &str) -> String {
    let value = run_id.rsplit('-').next().unwrap_or("s14");
    value[value.len().saturating_sub(5)..].to_owned()
}
fn delete_link_or_prove_absent(
    commands: &CommandExecutor,
    name: &str,
    label: &str,
) -> Result<(), TestError> {
    if link_is_absent(commands, name, &format!("inspect {label} before deletion"))? {
        return Ok(());
    }

    let output = commands
        .run(&CommandSpec::new("ip").args(["link", "del", name]))
        .map_err(TestError::infra)?;
    if output.success() {
        return Ok(());
    }

    // Deleting the network namespace also schedules deletion of its veth peer.
    // The peer can disappear after the presence check but before `ip link del`.
    // Accept that race only after a second, strict absence check.
    if link_is_absent(commands, name, &format!("verify {label} race"))? {
        return Ok(());
    }

    require_success(&output, label)
}
fn link_is_absent(commands: &CommandExecutor, name: &str, label: &str) -> Result<bool, TestError> {
    let output = commands
        .run(&CommandSpec::new("ip").args(["link", "show", "dev", name]))
        .map_err(TestError::infra)?;
    if output.success() {
        return Ok(false);
    }
    if output_reports_link_absent(&output, name) {
        return Ok(true);
    }
    require_success(&output, label)?;
    Ok(false)
}
fn output_reports_link_absent(output: &CommandOutput, name: &str) -> bool {
    if output.record.exit_code != Some(1) || output.record.timed_out {
        return false;
    }
    let stderr = output.stderr_text();
    let stderr = stderr.trim();
    stderr == format!("Device \"{name}\" does not exist.")
        || stderr == format!("Cannot find device \"{name}\"")
}
fn remove_file(path: &Path) -> Result<(), TestError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TestError::infra(format!("remove {}: {e}", path.display()))),
    }
}
fn remove_empty(path: &Path) -> Result<(), TestError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TestError::infra(format!(
            "remove directory {}: {e}",
            path.display()
        ))),
    }
}
fn remove_exact_pins(point: &PointRuntime) -> Result<(), TestError> {
    for e in &point.executions {
        for name in LINK_NAMES {
            remove_file(&point.link_pins.join(format!("e{:03}/{name}", e.index)))?;
        }
        remove_empty(&point.link_pins.join(format!("e{:03}", e.index)))?;
    }
    for name in MAP_NAMES {
        remove_file(&point.map_pins.join(name))?;
    }
    remove_empty(&point.link_pins)?;
    remove_empty(&point.map_pins)?;
    if let Some(root) = point.map_pins.parent() {
        remove_empty(root)?;
        if let Some(owner_root) = root.parent() {
            remove_empty(owner_root)?;
            if let Some(run_root) = owner_root.parent() {
                remove_empty(run_root)?;
                if !point.bpffs_base_preexisting
                    && let Some(base_root) = run_root.parent()
                {
                    remove_empty(base_root)?;
                }
            }
        }
    }
    Ok(())
}
fn list_files(root: &Path) -> Result<Vec<String>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    walk(root, false, &mut out)?;
    out.sort();
    Ok(out)
}
fn list_dirs(root: &Path) -> Result<Vec<String>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    walk(root, true, &mut out)?;
    out.sort();
    Ok(out)
}
fn walk(root: &Path, dirs: bool, out: &mut Vec<String>) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|e| format!("read {}: {e}", root.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        if (dirs && ty.is_dir()) || (!dirs && !ty.is_dir()) {
            out.push(path.to_string_lossy().into_owned());
        }
        if ty.is_dir() {
            walk(&path, dirs, out)?;
        }
    }
    Ok(())
}
fn read_meminfo() -> BTreeMap<String, u64> {
    fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.to_owned(), v.split_whitespace().next()?.parse().ok()?))
        })
        .collect()
}
fn owned_processes(run_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .chars()
                .all(|c| c.is_ascii_digit())
            {
                continue;
            }
            if let Ok(cmd) = fs::read(entry.path().join("cmdline")) {
                let text = String::from_utf8_lossy(&cmd).replace('\0', " ");
                if text.contains(run_id) || text.contains("s14-loader") {
                    out.push(format!("{} {text}", entry.file_name().to_string_lossy()));
                }
            }
        }
    }
    out.sort();
    out
}
fn new_items(before: &Value, after: &Value) -> Result<Vec<Value>, TestError> {
    let base = before
        .as_array()
        .ok_or_else(|| TestError::infra("S14 baseline inventory not array"))?
        .iter()
        .filter_map(|v| v.get("id").and_then(Value::as_u64))
        .collect::<BTreeSet<_>>();
    Ok(after
        .as_array()
        .ok_or_else(|| TestError::infra("S14 live inventory not array"))?
        .iter()
        .filter(|v| {
            v.get("id")
                .and_then(Value::as_u64)
                .is_some_and(|id| !base.contains(&id))
        })
        .cloned()
        .collect())
}
fn ids(items: &[Value]) -> Vec<u64> {
    items
        .iter()
        .filter_map(|v| v.get("id").and_then(Value::as_u64))
        .collect()
}
fn sum(items: &[Value], key: &str) -> u64 {
    items
        .iter()
        .filter_map(|v| v.get(key).and_then(Value::as_u64))
        .sum()
}
fn group_names(items: &[Value]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for name in items
        .iter()
        .filter_map(|v| v.get("name").and_then(Value::as_str))
    {
        *out.entry(name.to_owned()).or_default() += 1;
    }
    out
}
fn inventory_equal(a: &Inventory, b: &Inventory) -> bool {
    stable_programs(&a.programs) == stable_programs(&b.programs)
        && stable_bpf(&a.links) == stable_bpf(&b.links)
        && stable_bpf(&a.maps) == stable_bpf(&b.maps)
        && a.bpffs == b.bpffs
        && a.cgroups == b.cgroups
        && stable_json(&a.netns) == stable_json(&b.netns)
        && stable_links(&a.interfaces) == stable_links(&b.interfaces)
        && stable_json(&a.nft) == stable_json(&b.nft)
}
fn stable_programs(v: &Value) -> Value {
    let mut v = stable_bpf(v);
    if let Value::Array(items) = &mut v {
        for item in items {
            if let Value::Object(o) = item {
                o.remove("id");
            }
        }
    }
    v
}
fn stable_bpf(v: &Value) -> Value {
    let mut v = v.clone();
    strip(&mut v);
    stable_json(&v)
}
fn strip(v: &mut Value) {
    match v {
        Value::Array(a) => a.iter_mut().for_each(strip),
        Value::Object(o) => {
            for k in ["loaded_at", "run_time_ns", "run_cnt", "recursion_misses"] {
                o.remove(k);
            }
            o.values_mut().for_each(strip)
        }
        _ => {}
    }
}
fn stable_links(v: &Value) -> Value {
    let mut v = v.clone();
    if let Value::Array(items) = &mut v {
        for item in items {
            if let Value::Object(o) = item {
                for k in [
                    "ifindex",
                    "link_index",
                    "promiscuity",
                    "num_tx_queues",
                    "num_rx_queues",
                ] {
                    o.remove(k);
                }
            }
        }
    }
    stable_json(&v)
}
fn stable_json(v: &Value) -> Value {
    let mut v = v.clone();
    sort_value(&mut v);
    v
}
fn sort_value(v: &mut Value) {
    match v {
        Value::Array(a) => {
            a.iter_mut().for_each(sort_value);
            a.sort_by_key(Value::to_string)
        }
        Value::Object(o) => o.values_mut().for_each(sort_value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::output_reports_link_absent;
    use crate::command::{CommandOutput, CommandRecord};
    use std::collections::BTreeMap;

    fn output(exit_code: Option<i32>, timed_out: bool, stderr: &str) -> CommandOutput {
        CommandOutput {
            record: CommandRecord {
                sequence: 1,
                executable: "ip".to_owned(),
                argv: vec![
                    "link".to_owned(),
                    "del".to_owned(),
                    "s145760h019".to_owned(),
                ],
                working_directory: "/".to_owned(),
                selected_environment: BTreeMap::new(),
                wall_start_unix_ms: 0,
                monotonic_start_ns: 0,
                duration_ms: 0,
                exit_code,
                signal: None,
                timed_out,
                stdout_file: String::new(),
                stderr_file: String::new(),
            },
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn recognizes_observed_veth_disappearance_messages() {
        let name = "s145760h019";
        assert!(output_reports_link_absent(
            &output(Some(1), false, "Cannot find device \"s145760h019\"\n"),
            name
        ));
        assert!(output_reports_link_absent(
            &output(Some(1), false, "Device \"s145760h019\" does not exist.\n"),
            name
        ));
    }

    #[test]
    fn rejects_unproven_or_unrelated_link_failures() {
        let name = "s145760h019";
        assert!(!output_reports_link_absent(
            &output(Some(2), false, "Cannot find device \"s145760h019\"\n"),
            name
        ));
        assert!(!output_reports_link_absent(
            &output(Some(1), true, "Cannot find device \"s145760h019\"\n"),
            name
        ));
        assert!(!output_reports_link_absent(
            &output(
                Some(1),
                false,
                "RTNETLINK answers: Operation not permitted\n"
            ),
            name
        ));
        assert!(!output_reports_link_absent(
            &output(Some(1), false, "Cannot find device \"another-link\"\n"),
            name
        ));
    }
}
