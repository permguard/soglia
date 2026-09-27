// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps};
use aya::{Ebpf, EbpfLoader};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bpf_inventory::{
    BpfInventory, InventoryAssessment, InventoryClassification, assess as assess_bpf_inventory,
};
use crate::command::{CommandExecutor, CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::{SpikeTest, TestError};

pub(crate) const WAIT_SHORT: Duration = Duration::from_secs(10);
pub(crate) const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const EXECUTION_ID: &str = "s1-execution-e1-generation-1";
pub(crate) const EXEC_IDENT: u64 = 1_001_001;
const MAP_NAMES: [&str; 11] = [
    "soglia_policy",
    "soglia_tuples",
    "soglia_cookie_a",
    "soglia_sk_b",
    "soglia_events",
    "soglia_counters",
    "soglia_denies",
    "soglia_meta",
    "soglia_diag_entries",
    "soglia_port_diag",
    "soglia_map_fail_diag",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct S1Observation {
    unit_properties: String,
    delegated_root: String,
    executions_inode: u64,
    target_cgroup: String,
    pub(crate) target_inode: u64,
    target_initial_processes: String,
    trusted_pid: u32,
    announced_host_pid: u32,
    announced_agent_pid: u32,
    stopped_before_netns: bool,
    host_proc_cgroup: String,
    host_target_processes: String,
    agent_proc_cgroup: String,
    agent_target_processes: String,
    expected_proc_cgroup: String,
    owned_netns_inode: u64,
    agent_netns_inode: u64,
    pub(crate) live_membership_proven: bool,
    pub(crate) direct_attachments: Value,
    pub(crate) effective_attachments: Value,
    cgroup_link_count: usize,
    policy_local: u64,
    before_diag: Vec<u64>,
    before_counters: Vec<u64>,
    pub(crate) before_cookies: Value,
    pub(crate) before_tuples: Value,
    pub(crate) proxy_peer: String,
    proxy_local: String,
    application_bytes_read_before_resolve: u64,
    dns_lookups_before_resolve: u64,
    outbound_effects_before_resolve: u64,
    ip_fallback_authorization: bool,
    tuple_key_hex: String,
    resolve_latency_ns: u128,
    pub(crate) resolved_execution: String,
    pub(crate) tuple_evidence: Vec<u64>,
    diagnostic_entries: Vec<u64>,
    port_diagnostics: Vec<u64>,
    counters: Vec<u64>,
    cookie_map: Value,
    tuple_map: Value,
    deny_map: Value,
    bpf_events_hex: Vec<String>,
    pub(crate) application_line_after_resolve: String,
    pub(crate) agent_exit_code: Option<i32>,
    pub(crate) agent_signal: Option<i32>,
    agent_stdout: String,
    agent_stderr: String,
    agent_json: Vec<Value>,
    ip_veth_cross_check: bool,
}

pub(crate) struct S1 {
    pub(crate) scope: &'static str,
    object: &'static str,
    execution_id: String,
    exec_ident: u64,
    agent_operation: String,
    expected_agent_command: String,
    kill_agent_after_resolve: bool,
    host_allows_direct_target: bool,
    dual_stack_hook_isolation: bool,
    rewrite_final_barrier: bool,
    pub(crate) unit: String,
    pub(crate) runtime_root: PathBuf,
    delegation_ready: PathBuf,
    pub(crate) delegated_root: Option<PathBuf>,
    pub(crate) executions: Option<PathBuf>,
    pub(crate) target: Option<PathBuf>,
    pub(crate) pin_root: PathBuf,
    pub(crate) netns: String,
    host_veth: String,
    proxy_link: String,
    nft_table: String,
    pub(crate) bpf: Option<Ebpf>,
    links: Vec<PinnedLink>,
    pub(crate) agent: Option<RunningCommand>,
    baseline: Option<BpfInventory>,
}

impl S1 {
    pub fn new(context: &TestContext) -> Self {
        Self::new_variant(context, "s1", "bpf/soglia-diag.o")
    }

    pub(crate) fn new_s1b(context: &TestContext) -> Self {
        Self::new_variant(context, "s1b", "bpf/soglia-delay-diag.o")
    }

    fn new_variant(context: &TestContext, scope: &'static str, object: &'static str) -> Self {
        Self::new_named_variant(context, scope, object, scope)
    }

    fn new_named_variant(
        context: &TestContext,
        scope: &'static str,
        object: &'static str,
        topology_name: &'static str,
    ) -> Self {
        let short = short_id(&context.run_id);
        Self {
            scope,
            object,
            execution_id: EXECUTION_ID.to_owned(),
            exec_ident: EXEC_IDENT,
            agent_operation: "proxy 1".to_owned(),
            expected_agent_command: "proxy".to_owned(),
            kill_agent_after_resolve: false,
            host_allows_direct_target: false,
            dual_stack_hook_isolation: false,
            rewrite_final_barrier: false,
            unit: format!("soglia-spike-{topology_name}-{short}.service"),
            runtime_root: Path::new("/run/soglia-spike-runner")
                .join(&context.run_id)
                .join(topology_name),
            delegation_ready: PathBuf::new(),
            delegated_root: None,
            executions: None,
            target: None,
            pin_root: Path::new("/sys/fs/bpf/soglia-spike-runner")
                .join(&context.run_id)
                .join(topology_name),
            netns: format!("sg-{topology_name}-{short}"),
            host_veth: format!("{topology_name}h{}", &short[..short.len().min(7)]),
            proxy_link: format!("{topology_name}p{}", &short[..short.len().min(7)]),
            nft_table: format!("sg_{topology_name}_{}", &short[..short.len().min(8)]),
            bpf: None,
            links: Vec::new(),
            agent: None,
            baseline: None,
        }
    }

    pub(crate) fn new_s3(
        context: &TestContext,
        generation: usize,
        operation: &str,
        expected_agent_command: &str,
        kill_agent_after_resolve: bool,
    ) -> Self {
        let scope = match generation {
            1 => "s3/generation-1",
            2 => "s3/generation-2",
            _ => "s3/generation-3",
        };
        let mut fixture = Self::new_named_variant(context, scope, "bpf/soglia-diag.o", "s3");
        fixture.execution_id = format!("s3-execution-generation-{generation}");
        fixture.exec_ident = 3_001_000 + generation as u64;
        fixture.agent_operation = operation.to_owned();
        fixture.expected_agent_command = expected_agent_command.to_owned();
        fixture.kill_agent_after_resolve = kill_agent_after_resolve;
        fixture
    }

    pub(crate) fn new_s4(context: &TestContext) -> Self {
        let mut fixture =
            Self::new_named_variant(context, "s4", "bpf/soglia-direct-control.o", "s4");
        fixture.execution_id = "s4-execution-generation-1".to_owned();
        fixture.exec_ident = 4_001_001;
        fixture.host_allows_direct_target = true;
        fixture
    }

    pub(crate) fn new_s5(context: &TestContext) -> Self {
        let mut fixture = Self::new_named_variant(context, "s5", "bpf/soglia-diag.o", "s5");
        fixture.execution_id = "s5-execution-generation-1".to_owned();
        fixture.exec_ident = 5_001_001;
        fixture.host_allows_direct_target = true;
        fixture.dual_stack_hook_isolation = true;
        fixture
    }

    pub(crate) fn new_s7(context: &TestContext) -> Self {
        let mut fixture = Self::new_named_variant(context, "s7", "bpf/soglia-diag.o", "s7");
        fixture.execution_id = "s7-execution-generation-1".to_owned();
        fixture.exec_ident = 7_001_001;
        fixture.host_allows_direct_target = true;
        fixture
    }

    pub(crate) fn new_s9(context: &TestContext) -> Self {
        let mut fixture =
            Self::new_named_variant(context, "s9", "bpf/soglia-direct-control.o", "s9");
        fixture.execution_id = "s9-execution-generation-1".to_owned();
        fixture.exec_ident = 9_001_001;
        fixture.host_allows_direct_target = true;
        fixture
    }

    pub(crate) fn new_s10(context: &TestContext) -> Self {
        let mut fixture =
            Self::new_named_variant(context, "s10", "bpf/soglia-direct-control.o", "s10");
        fixture.execution_id = "s10-execution-generation-1".to_owned();
        fixture.exec_ident = 10_001_001;
        fixture.host_allows_direct_target = true;
        fixture.rewrite_final_barrier = true;
        fixture
    }

    pub(crate) fn new_s11(context: &TestContext) -> Self {
        let mut fixture = Self::new_named_variant(context, "s11", "bpf/soglia-diag.o", "s11");
        fixture.execution_id = "s11-execution-generation-1".to_owned();
        fixture.exec_ident = 11_001_001;
        fixture
    }

    pub(crate) fn new_s12(context: &TestContext) -> Self {
        let mut fixture = Self::new_named_variant(context, "s12", "bpf/soglia-small-diag.o", "s12");
        fixture.execution_id = "s12-execution-generation-1".to_owned();
        fixture.exec_ident = 12_001_001;
        fixture
    }

    pub(crate) fn new_s13(context: &TestContext) -> Self {
        let mut fixture = Self::new_named_variant(context, "s13", "bpf/soglia-diag.o", "s13");
        fixture.execution_id = "s13-execution-generation-1".to_owned();
        fixture.exec_ident = 13_001_001;
        fixture
    }

    pub(crate) fn new_s14(context: &TestContext) -> Self {
        let mut fixture = Self::new_named_variant(context, "s14", "bpf/soglia.o", "s14");
        fixture.execution_id = "s14-controller".to_owned();
        fixture.exec_ident = 14_000_000;
        fixture
    }

    pub(crate) fn commands(&self, context: &TestContext) -> CommandExecutor {
        context.test_commands(self.scope)
    }

    pub(crate) fn target(&self) -> Result<&Path, TestError> {
        self.target
            .as_deref()
            .ok_or_else(|| TestError::infra("S1 target cgroup missing"))
    }

    pub(crate) fn start_delegation(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        self.delegation_ready = self.runtime_root.join("delegation.json");
        let output = self
            .commands(context)
            .run(
                &CommandSpec::new("systemd-run")
                    .args([
                        OsString::from(format!(
                            "--unit={}",
                            self.unit.trim_end_matches(".service")
                        )),
                        OsString::from("--property=Delegate=yes"),
                        OsString::from("--collect"),
                        OsString::from("--service-type=exec"),
                        OsString::from("--"),
                        context.executable.as_os_str().to_owned(),
                        OsString::from("_delegation-helper"),
                        OsString::from("--ready"),
                        self.delegation_ready.as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(15)),
            )
            .map_err(TestError::infra)?;
        require_success(&output, "start S1 delegated unit")?;
        context.resources.register(
            self.scope,
            "S1 systemd delegation",
            Resource::SystemdUnit {
                name: self.unit.clone(),
            },
        );
        wait_for_path(&self.delegation_ready, WAIT_SHORT).map_err(TestError::infra)?;
        let record: Value = serde_json::from_slice(
            &fs::read(&self.delegation_ready)
                .map_err(|error| TestError::infra(error.to_string()))?,
        )
        .map_err(|error| TestError::infra(format!("parse S1 delegation: {error}")))?;
        let root = record
            .get("cgroup_root")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| TestError::infra("S1 delegation root missing"))?;
        let executions = root.join("executions");
        let target = executions.join("s1-e1");
        fs::create_dir(&executions)
            .map_err(|error| TestError::infra(format!("create S1 executions: {error}")))?;
        fs::write(
            executions.join("cgroup.subtree_control"),
            b"+memory +pids\n",
        )
        .map_err(|error| TestError::infra(format!("delegate S1 controllers: {error}")))?;
        fs::create_dir(&target)
            .map_err(|error| TestError::infra(format!("create S1 target: {error}")))?;
        for (provenance, path) in [
            ("S1 delegated root", &root),
            ("S1 executions cgroup", &executions),
            ("S1 target cgroup", &target),
        ] {
            context.resources.register(
                self.scope,
                provenance,
                Resource::Cgroup {
                    path: path.clone(),
                    inode: inode(path).map_err(TestError::infra)?,
                },
            );
        }
        self.delegated_root = Some(root);
        self.executions = Some(executions);
        self.target = Some(target);
        Ok(())
    }

    fn create_network(&self, context: &mut TestContext) -> Result<(), TestError> {
        let commands = self.commands(context);
        for (program, arguments) in [
            ("ip", vec!["link", "add", &self.proxy_link, "type", "dummy"]),
            (
                "ip",
                vec!["addr", "add", "10.200.255.1/32", "dev", &self.proxy_link],
            ),
            ("ip", vec!["link", "set", &self.proxy_link, "up"]),
            ("ip", vec!["netns", "add", &self.netns]),
        ] {
            run_ok(&commands, program, arguments, "create S1 network")?;
        }
        run_ok(
            &commands,
            "ip",
            vec![
                "link",
                "add",
                &self.host_veth,
                "type",
                "veth",
                "peer",
                "name",
                "eth0",
                "netns",
                &self.netns,
            ],
            "create S1 veth",
        )?;
        for arguments in [
            vec!["addr", "add", "10.201.0.2/30", "dev", &self.host_veth],
            vec!["link", "set", &self.host_veth, "up"],
            vec![
                "netns",
                "exec",
                &self.netns,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
            vec![
                "netns",
                "exec",
                &self.netns,
                "ip",
                "addr",
                "add",
                "10.201.0.1/30",
                "dev",
                "eth0",
            ],
            vec![
                "netns",
                "exec",
                &self.netns,
                "ip",
                "link",
                "set",
                "eth0",
                "up",
            ],
            vec![
                "netns",
                "exec",
                &self.netns,
                "ip",
                "route",
                "add",
                "10.200.255.1/32",
                "via",
                "10.201.0.2",
                "dev",
                "eth0",
            ],
        ] {
            run_ok(&commands, "ip", arguments, "configure S1 network")?;
        }
        if self.dual_stack_hook_isolation {
            for arguments in [
                vec![
                    "-6",
                    "addr",
                    "add",
                    "fd00:201::2/64",
                    "dev",
                    &self.host_veth,
                    "nodad",
                ],
                vec![
                    "netns",
                    "exec",
                    &self.netns,
                    "ip",
                    "-6",
                    "addr",
                    "add",
                    "fd00:201::1/64",
                    "dev",
                    "eth0",
                    "nodad",
                ],
            ] {
                run_ok(&commands, "ip", arguments, "configure S5 IPv6 network")?;
            }
        }
        context.resources.register(
            self.scope,
            "S1 owned netns",
            Resource::Netns {
                name: self.netns.clone(),
            },
        );
        for name in [&self.host_veth, &self.proxy_link] {
            context.resources.register(
                self.scope,
                "S1 owned interface",
                Resource::Interface { name: name.clone() },
            );
        }

        let namespace_rules = self.runtime_root.join("netns.nft");
        let namespace_policy = if self.rewrite_final_barrier {
            r#"table inet soglia {
 chain input { type filter hook input priority filter; policy drop; iif "lo" accept; ct state established,related accept; }
 chain output { type filter hook output priority filter; policy drop; oif "lo" accept; ct state established,related accept; ip daddr 10.200.255.1 tcp dport 15001 ct state new accept; ip daddr 10.201.0.2 tcp dport 16001 ct state new counter comment "s10-rewrite-observe"; }
 chain forward { type filter hook forward priority filter; policy drop; }
}
"#
        } else if self.dual_stack_hook_isolation {
            r#"table inet soglia {
 chain input { type filter hook input priority filter; policy drop; iif "lo" accept; ct state established,related accept; meta l4proto ipv6-icmp accept; }
 chain output { type filter hook output priority filter; policy drop; oif "lo" accept; ct state established,related accept; meta l4proto ipv6-icmp accept; ip daddr 10.200.255.1 tcp dport 15001 ct state new accept; ip daddr 10.201.0.2 tcp dport 16001 ct state new accept; ip6 daddr fd00:201::2 tcp dport 16002 ct state new accept; ip daddr 10.201.0.2 udp dport 16003 accept; ip6 daddr fd00:201::2 udp dport 16004 accept; }
 chain forward { type filter hook forward priority filter; policy drop; }
}
"#
        } else {
            r#"table inet soglia {
 chain input { type filter hook input priority filter; policy drop; iif "lo" accept; ct state established,related accept; }
 chain output { type filter hook output priority filter; policy drop; oif "lo" accept; ct state established,related accept; ip daddr 10.200.255.1 tcp dport 15001 ct state new accept; }
 chain forward { type filter hook forward priority filter; policy drop; }
}
"#
        };
        fs::write(&namespace_rules, namespace_policy)
            .map_err(|error| TestError::infra(format!("write namespace nft rules: {error}")))?;
        let host_rules = self.runtime_root.join("host.nft");
        let destination_barrier = if self.host_allows_direct_target {
            String::new()
        } else {
            format!(
                " iifname \"{}\" ct state new ip daddr != 10.200.255.1 drop; iifname \"{}\" ct state new tcp dport != 15001 drop;",
                self.host_veth, self.host_veth
            )
        };
        let host_policy = if self.dual_stack_hook_isolation {
            format!(
                "table inet {} {{\n chain input {{ type filter hook input priority filter - 10; policy accept; iifname \"{}\" ip saddr != 10.201.0.1 drop; iifname \"{}\" ip6 saddr != fd00:201::1 drop; iifname \"{}\" ct state invalid drop; }}\n chain forward {{ type filter hook forward priority filter - 10; policy accept; iifname \"{}\" drop; oifname \"{}\" drop; }}\n}}\n",
                self.nft_table,
                self.host_veth,
                self.host_veth,
                self.host_veth,
                self.host_veth,
                self.host_veth,
            )
        } else {
            format!(
                "table inet {} {{\n chain input {{ type filter hook input priority filter - 10; policy accept; iifname \"{}\" ip saddr != 10.201.0.1 drop; iifname \"{}\" ct state invalid drop; iifname \"{}\" ct state new meta l4proto != tcp drop;{} }}\n chain forward {{ type filter hook forward priority filter - 10; policy accept; iifname \"{}\" drop; oifname \"{}\" drop; }}\n}}\n",
                self.nft_table,
                self.host_veth,
                self.host_veth,
                self.host_veth,
                destination_barrier,
                self.host_veth,
                self.host_veth,
            )
        };
        fs::write(&host_rules, host_policy)
            .map_err(|error| TestError::infra(format!("write host nft rules: {error}")))?;
        run_ok(
            &commands,
            "ip",
            vec![
                "netns",
                "exec",
                &self.netns,
                "nft",
                "-f",
                namespace_rules.to_string_lossy().as_ref(),
            ],
            "install S1 namespace nft policy",
        )?;
        run_ok(
            &commands,
            "nft",
            vec!["-f", host_rules.to_string_lossy().as_ref()],
            "install S1 host nft policy",
        )?;
        context.resources.register(
            self.scope,
            "S1 host nft table",
            Resource::NftObject {
                family: "inet".to_owned(),
                table: self.nft_table.clone(),
                object: "table".to_owned(),
            },
        );
        Ok(())
    }

    fn load_bpf(&mut self, context: &mut TestContext) -> Result<u64, TestError> {
        let map_pins = self.pin_root.join("maps");
        let link_pins = self.pin_root.join("links");
        fs::create_dir_all(&map_pins)
            .map_err(|error| TestError::infra(format!("create S1 map pins: {error}")))?;
        fs::create_dir_all(&link_pins)
            .map_err(|error| TestError::infra(format!("create S1 link pins: {error}")))?;
        let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
        let proxy_port = 15_001_u32;
        let direct_ip4 = u32::from_ne_bytes([10, 201, 0, 2]);
        let direct_port = 16_001_u32;
        let mut loader = EbpfLoader::new();
        loader
            .override_global("proxy_ip4", &proxy_ip4, true)
            .override_global("proxy_port", &proxy_port, true)
            .override_global("direct_ip4", &direct_ip4, true)
            .override_global("direct_port", &direct_port, true)
            .override_global("exec_ident", &self.exec_ident, true)
            .default_map_pin_directory(&map_pins);
        let mut bpf = loader
            .load_file(context.artifact(self.object))
            .map_err(|error| TestError::infra(format!("load S1 diagnostic BPF: {error:#}")))?;
        {
            let policy = bpf
                .map_mut("policy_local")
                .ok_or_else(|| TestError::infra("policy_local map missing"))?;
            let mut policy = Array::<_, u64>::try_from(policy)
                .map_err(|error| TestError::infra(format!("open policy_local: {error:#}")))?;
            policy
                .set(0, 1, 0)
                .map_err(|error| TestError::infra(format!("activate policy_local: {error:#}")))?;
        }
        let cgroup = File::open(self.target()?)
            .map_err(|error| TestError::infra(format!("open S1 cgroup: {error}")))?;
        self.links = attach_all(&mut bpf, &cgroup, &link_pins).map_err(TestError::infra)?;
        for path in list_files(&self.pin_root).map_err(TestError::infra)? {
            context.resources.register(
                self.scope,
                "S1 BPF pin",
                Resource::BpfPin {
                    path: PathBuf::from(path),
                },
            );
        }
        let inventory = bpf_inventory(&self.commands(context))?;
        register_owned_bpf_objects(
            context,
            self.scope,
            inode(self.target()?).map_err(TestError::infra)?,
            &inventory,
        )?;
        self.bpf = Some(bpf);
        Ok(1)
    }

    pub(crate) fn dump_map(&self, context: &TestContext, name: &str) -> Result<Value, TestError> {
        let output = self
            .commands(context)
            .run(&CommandSpec::new("bpftool").args([
                OsString::from("-j"),
                OsString::from("map"),
                OsString::from("dump"),
                OsString::from("pinned"),
                self.pin_root.join("maps").join(name).into_os_string(),
            ]))
            .map_err(TestError::infra)?;
        require_success(&output, &format!("dump S1 map {name}"))?;
        serde_json::from_slice(&output.stdout)
            .map_err(|error| TestError::infra(format!("parse S1 map {name}: {error}")))
    }

    pub(crate) fn stop_agent(&mut self) {
        if let Some(mut agent) = self.agent.take() {
            let _ = agent.terminate();
            let _ = agent.wait(Duration::from_secs(5));
        }
    }

    pub(crate) fn reload_bpf(
        &mut self,
        context: &mut TestContext,
        object: &'static str,
    ) -> Result<(), TestError> {
        while let Some(link) = self.links.pop() {
            let fd = link
                .unpin()
                .map_err(|error| TestError::infra(format!("unpin S1 link: {error:#}")))?;
            drop(fd);
        }
        drop(self.bpf.take());
        remove_s1_pins(&self.pin_root).map_err(TestError::infra)?;
        self.object = object;
        self.load_bpf(context)?;
        Ok(())
    }

    pub(crate) fn unload_bpf(&mut self) -> Result<(), TestError> {
        while let Some(link) = self.links.pop() {
            let fd = link
                .unpin()
                .map_err(|error| TestError::infra(format!("unpin S1 link: {error:#}")))?;
            drop(fd);
        }
        drop(self.bpf.take());
        remove_s1_pins(&self.pin_root).map_err(TestError::infra)
    }

    pub(crate) fn prepare_topology(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if self.runtime_root.exists()
            || self.pin_root.exists()
            || Path::new("/run/netns").join(&self.netns).exists()
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1 owned path existed before preparation",
            ));
        }
        fs::create_dir_all(&self.runtime_root)
            .map_err(|error| TestError::infra(format!("create S1 runtime: {error}")))?;
        context.resources.register(
            self.scope,
            "S1 runtime directory",
            Resource::Directory {
                path: self.runtime_root.clone(),
            },
        );
        self.start_delegation(context)?;
        self.baseline = Some(bpf_inventory(&self.commands(context))?);
        self.create_network(context)
    }

    pub(crate) fn load_bpf_now(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        self.load_bpf(context).map(|_| ())
    }
}

impl SpikeTest for S1 {
    type Observation = S1Observation;

    fn id(&self) -> TestId {
        TestId::S1
    }

    fn invariant(&self) -> &'static str {
        "trusted Execution placement -> BPF attribution -> accepted tuple -> bounded Resolve -> correct Execution"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        self.prepare_topology(context)?;
        self.load_bpf_now(context)
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let commands = self.commands(context);
        let unit = commands
            .run(&CommandSpec::new("systemctl").args([
                "show",
                self.unit.as_str(),
                "-p",
                "ActiveState",
                "-p",
                "Delegate",
                "-p",
                "ControlGroup",
                "-p",
                "MainPID",
            ]))
            .map_err(TestError::infra)?;
        require_success(&unit, "inspect S1 delegation")?;
        let target = self.target()?.to_path_buf();
        let target_inode = inode(&target).map_err(TestError::infra)?;
        let target_initial_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let direct_attachments = json_cgroup(&commands, &target, false)?;
        let effective_attachments = json_cgroup(&commands, &target, true)?;
        let links = json_command(&commands, ["-j", "link", "show"])?;
        let cgroup_link_count = links
            .as_array()
            .ok_or_else(|| TestError::infra("bpftool link output was not an array"))?
            .iter()
            .filter(|link| link.get("type").and_then(Value::as_str) == Some("cgroup"))
            .filter(|link| link.get("cgroup_id").and_then(Value::as_u64) == Some(target_inode))
            .count();

        let before_diag_json = self.dump_map(context, "soglia_diag_entries")?;
        let before_counters_json = self.dump_map(context, "soglia_counters")?;
        let before_cookies = self.dump_map(context, "soglia_cookie_a")?;
        let before_tuples = self.dump_map(context, "soglia_tuples")?;
        let before_diag = array_values(&before_diag_json, 7)?;
        let before_counters = array_values(&before_counters_json, 9)?;

        let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
            .map_err(|error| TestError::infra(format!("bind S1 proxy: {error}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S1 proxy nonblocking: {error}")))?;
        let host_ready = self.runtime_root.join("agent-host.ready");
        let agent_ready = self.runtime_root.join("agent.ready");
        let agent_go = self.runtime_root.join("agent.go");
        let agent = commands
            .spawn(
                &CommandSpec::new(&context.executable)
                    .args([
                        OsString::from("_agent-launcher"),
                        OsString::from("--netns"),
                        Path::new("/run/netns").join(&self.netns).into_os_string(),
                        OsString::from("--agent"),
                        context.artifact("bin/soglia-spike-agent").into_os_string(),
                        OsString::from("--host-ready"),
                        host_ready.as_os_str().to_owned(),
                        OsString::from("--agent-ready"),
                        agent_ready.as_os_str().to_owned(),
                        OsString::from("--agent-go"),
                        agent_go.as_os_str().to_owned(),
                        OsString::from("--operation"),
                        OsString::from(&self.agent_operation),
                    ])
                    .timeout(Duration::from_secs(45)),
            )
            .map_err(TestError::infra)?;
        let trusted_pid = agent.id();
        context.resources.register(
            self.scope,
            "S1 trusted agent lifecycle",
            Resource::Process { pid: trusted_pid },
        );
        self.agent = Some(agent);
        wait_for_path(&host_ready, WAIT_SHORT).map_err(TestError::infra)?;
        wait_for_process_stopped(trusted_pid, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_host_pid = read_pid(&host_ready).map_err(TestError::infra)?;
        fs::write(target.join("cgroup.procs"), format!("{trusted_pid}\n"))
            .map_err(|error| TestError::infra(format!("place trusted S1 PID: {error}")))?;
        let expected_proc_cgroup = format!(
            "0::/{}",
            target
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| TestError::infra("S1 target outside cgroup2 mount"))?
                .to_string_lossy()
                .trim_start_matches('/')
        );
        let host_proc_cgroup = read_trimmed(Path::new(&format!("/proc/{trusted_pid}/cgroup")))?;
        let host_target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let stopped_before_netns = process_is_stopped(trusted_pid).map_err(TestError::infra)?;
        let host_placement = announced_host_pid == trusted_pid
            && line_present(&host_proc_cgroup, &expected_proc_cgroup)
            && line_present(&host_target_processes, &trusted_pid.to_string())
            && stopped_before_netns;
        if !host_placement {
            return Err(TestError::new(
                Verdict::Unproven,
                "SUBJECT_PLACEMENT_FAILURE before netns entry",
            ));
        }
        kill(
            Pid::from_raw(
                i32::try_from(trusted_pid).map_err(|error| {
                    TestError::infra(format!("convert trusted S1 PID: {error}"))
                })?,
            ),
            Signal::SIGCONT,
        )
        .map_err(|error| TestError::infra(format!("continue trusted S1 PID: {error}")))?;
        wait_for_path(&agent_ready, WAIT_SHORT).map_err(TestError::infra)?;
        let announced_agent_pid = read_pid(&agent_ready).map_err(TestError::infra)?;
        let agent_proc_cgroup = read_trimmed(Path::new(&format!("/proc/{trusted_pid}/cgroup")))?;
        let agent_target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let agent_netns_inode =
            inode(Path::new(&format!("/proc/{trusted_pid}/ns/net"))).map_err(TestError::infra)?;
        let owned_netns_inode =
            inode(&Path::new("/run/netns").join(&self.netns)).map_err(TestError::infra)?;
        let live_membership_proven = announced_agent_pid == trusted_pid
            && line_present(&agent_proc_cgroup, &expected_proc_cgroup)
            && line_present(&agent_target_processes, &trusted_pid.to_string())
            && agent_netns_inode == owned_netns_inode;
        if !live_membership_proven {
            return Err(TestError::new(
                Verdict::Unproven,
                "SUBJECT_PLACEMENT_FAILURE for live agent",
            ));
        }
        context
            .evidence
            .write_json(
                format!("{}/membership.json", self.scope),
                &serde_json::json!({
                    "trusted_pid": trusted_pid,
                    "announced_host_pid": announced_host_pid,
                    "announced_agent_pid": announced_agent_pid,
                    "expected_proc_cgroup": expected_proc_cgroup,
                    "host_proc_cgroup": host_proc_cgroup,
                    "host_target_processes": host_target_processes,
                    "agent_proc_cgroup": agent_proc_cgroup,
                    "agent_target_processes": agent_target_processes,
                    "agent_netns_inode": agent_netns_inode,
                    "owned_netns_inode": owned_netns_inode,
                    "proven": true,
                }),
            )
            .map_err(|error| TestError::infra(format!("write S1 membership: {error}")))?;

        fs::write(&agent_go, b"go\n")
            .map_err(|error| TestError::infra(format!("release S1 connection: {error}")))?;
        let accept_started = Instant::now();
        let (mut stream, peer) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if accept_started.elapsed() >= Duration::from_secs(5) {
                        return Err(TestError::new(
                            Verdict::Unproven,
                            "S1 proxy did not accept the controlled connection",
                        ));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => {
                    return Err(TestError::infra(format!("accept S1 proxy socket: {error}")));
                }
            }
        };
        let local = stream
            .local_addr()
            .map_err(|error| TestError::infra(format!("inspect S1 local socket: {error}")))?;
        let key = tuple_key(peer, local).map_err(TestError::infra)?;
        let (value, resolve_latency_ns) = {
            let bpf = self
                .bpf
                .as_mut()
                .ok_or_else(|| TestError::infra("S1 BPF handle missing"))?;
            let tuples_map = bpf
                .take_map("soglia_tuples")
                .ok_or_else(|| TestError::infra("S1 tuple map missing"))?;
            let tuples = HashMap::<_, [u8; 16], [u8; 64]>::try_from(tuples_map)
                .map_err(|error| TestError::infra(format!("open S1 tuples: {error:#}")))?;
            let started = Instant::now();
            let value = loop {
                match tuples.get(&key, 0) {
                    Ok(value) => break value,
                    Err(aya::maps::MapError::KeyNotFound)
                        if started.elapsed() < RESOLVE_TIMEOUT =>
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(aya::maps::MapError::KeyNotFound) => {
                        return Err(TestError::new(
                            Verdict::Unproven,
                            "S1 tuple Resolve timed out fail-closed",
                        ));
                    }
                    Err(error) => {
                        return Err(TestError::infra(format!("lookup S1 tuple: {error:#}")));
                    }
                }
            };
            (value, started.elapsed().as_nanos())
        };
        let tuple_evidence = decode_evidence(value).to_vec();
        let diag_json = self.dump_map(context, "soglia_diag_entries")?;
        let port_json = self.dump_map(context, "soglia_port_diag")?;
        let counters_json = self.dump_map(context, "soglia_counters")?;
        let cookie_map = self.dump_map(context, "soglia_cookie_a")?;
        let tuple_map = self.dump_map(context, "soglia_tuples")?;
        let deny_map = self.dump_map(context, "soglia_denies")?;
        let diagnostic_entries = array_values(&diag_json, 7)?;
        let port_diagnostics = array_values(&port_json, 12)?;
        let counters = array_values(&counters_json, 9)?;
        let bpf_events_hex = {
            let bpf = self
                .bpf
                .as_mut()
                .ok_or_else(|| TestError::infra("S1 BPF handle missing"))?;
            let events_map = bpf
                .take_map("soglia_events")
                .ok_or_else(|| TestError::infra("S1 event map missing"))?;
            let mut events = RingBuf::try_from(events_map)
                .map_err(|error| TestError::infra(format!("open S1 events: {error:#}")))?;
            let mut values = Vec::new();
            while let Some(event) = events.next() {
                values.push(hex(&event));
            }
            values
        };
        let mut application_line_after_resolve = String::new();
        BufReader::new(
            stream
                .try_clone()
                .map_err(|error| TestError::infra(format!("clone S1 socket: {error}")))?,
        )
        .read_line(&mut application_line_after_resolve)
        .map_err(|error| TestError::infra(format!("read S1 application line: {error}")))?;
        writeln!(stream, "ATTRIBUTED {}", self.execution_id)
            .map_err(|error| TestError::infra(format!("write S1 proxy verdict: {error}")))?;
        stream
            .flush()
            .map_err(|error| TestError::infra(format!("flush S1 proxy verdict: {error}")))?;
        if self.kill_agent_after_resolve {
            kill(
                Pid::from_raw(
                    i32::try_from(trusted_pid).map_err(|error| {
                        TestError::infra(format!("convert S1 kill PID: {error}"))
                    })?,
                ),
                Signal::SIGKILL,
            )
            .map_err(|error| TestError::infra(format!("kill resolved S1 agent: {error}")))?;
        }
        drop(stream);
        let agent = self
            .agent
            .take()
            .ok_or_else(|| TestError::infra("S1 agent process missing"))?;
        let agent_output = agent
            .wait(Duration::from_secs(15))
            .map_err(TestError::infra)?;
        let agent_stdout = agent_output.stdout_text();
        let agent_json = agent_stdout
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|error| TestError::infra(format!("parse S1 agent JSON: {error}")))?;
        Ok(S1Observation {
            unit_properties: unit.stdout_text(),
            delegated_root: self
                .delegated_root
                .as_ref()
                .map_or_else(String::new, |path| path.to_string_lossy().into_owned()),
            executions_inode: inode(
                self.executions
                    .as_deref()
                    .ok_or_else(|| TestError::infra("S1 executions missing"))?,
            )
            .map_err(TestError::infra)?,
            target_cgroup: target.to_string_lossy().into_owned(),
            target_inode,
            target_initial_processes,
            trusted_pid,
            announced_host_pid,
            announced_agent_pid,
            stopped_before_netns,
            host_proc_cgroup,
            host_target_processes,
            agent_proc_cgroup,
            agent_target_processes,
            expected_proc_cgroup,
            owned_netns_inode,
            agent_netns_inode,
            live_membership_proven,
            direct_attachments,
            effective_attachments,
            cgroup_link_count,
            policy_local: 1,
            before_diag,
            before_counters,
            before_cookies,
            before_tuples,
            proxy_peer: peer.to_string(),
            proxy_local: local.to_string(),
            application_bytes_read_before_resolve: 0,
            dns_lookups_before_resolve: 0,
            outbound_effects_before_resolve: 0,
            ip_fallback_authorization: false,
            tuple_key_hex: hex(&key),
            resolve_latency_ns,
            resolved_execution: self.execution_id.clone(),
            tuple_evidence,
            diagnostic_entries,
            port_diagnostics,
            counters,
            cookie_map,
            tuple_map,
            deny_map,
            bpf_events_hex,
            application_line_after_resolve: application_line_after_resolve.trim_end().to_owned(),
            agent_exit_code: agent_output.record.exit_code,
            agent_signal: agent_output.record.signal,
            agent_stdout,
            agent_stderr: agent_output.stderr_text(),
            agent_json,
            ip_veth_cross_check: peer.ip() == Ipv4Addr::new(10, 201, 0, 1),
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if !observation.unit_properties.contains("ActiveState=active")
            || !observation.unit_properties.contains("Delegate=yes")
        {
            return Err(TestError::new(
                Verdict::Unsupported,
                "S1 delegated unit was not active",
            ));
        }
        if !observation.target_initial_processes.is_empty()
            || !observation.live_membership_proven
            || observation.trusted_pid != observation.announced_host_pid
            || observation.trusted_pid != observation.announced_agent_pid
            || observation.agent_netns_inode != observation.owned_netns_inode
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "SUBJECT_PLACEMENT_FAILURE",
            ));
        }
        require_array_len(&observation.direct_attachments, 6, "S1 direct attachments")?;
        require_array_len(
            &observation.effective_attachments,
            6,
            "S1 effective attachments",
        )?;
        if observation.cgroup_link_count != 6 || observation.policy_local != 1 {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1 six-link or active-policy precondition was not proven",
            ));
        }
        if observation.before_diag.iter().any(|value| *value != 0)
            || observation.before_counters.iter().any(|value| *value != 0)
            || !is_empty_array(&observation.before_cookies)
            || !is_empty_array(&observation.before_tuples)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1 attribution maps were not empty before traffic",
            ));
        }
        let diag = &observation.diagnostic_entries;
        if diag.len() != 7
            || diag[0] != 1
            || diag[1] != 1
            || diag[3] != 1
            || diag[4] != 1
            || diag[5] != 1
            || diag[6] != 1
            || diag[2] == 0
        {
            return Err(TestError::new(Verdict::Unproven, "HOOK_ENTRY_FAILURE"));
        }
        if observation.port_diagnostics.get(9) != Some(&15_001)
            || observation.port_diagnostics.get(10) != Some(&15_001)
            || observation.port_diagnostics.get(11) != Some(&15_001)
            || observation.counters.get(1) != Some(&0)
            || observation.counters.get(2) != Some(&1)
            || is_empty_array(&observation.cookie_map)
            || is_empty_array(&observation.tuple_map)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "ATTRIBUTION_LOGIC_FAILURE",
            ));
        }
        let evidence = &observation.tuple_evidence;
        if evidence.len() != 8
            || evidence[0] == 0
            || evidence[1] != observation.target_inode
            || evidence[2] != observation.target_inode
            || evidence[3] != self.exec_ident
            || evidence[4] == 0
            || evidence[6] != observation.target_inode
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "ATTRIBUTION_LOGIC_FAILURE: A/B/C tuple evidence disagreed",
            ));
        }
        if observation.resolve_latency_ns > RESOLVE_TIMEOUT.as_nanos()
            || observation.resolved_execution != self.execution_id
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "RESOLVE_CORRELATION_FAILURE",
            ));
        }
        if observation.application_bytes_read_before_resolve != 0
            || observation.dns_lookups_before_resolve != 0
            || observation.outbound_effects_before_resolve != 0
            || observation.ip_fallback_authorization
            || !observation.ip_veth_cross_check
            || observation.application_line_after_resolve != "HELLO 0"
            || observation.agent_exit_code != Some(0)
            || !is_empty_array(&observation.deny_map)
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S1 fail-closed proxy ordering or controlled-agent result contradicted the invariant",
            ));
        }
        let proxy_result = observation.agent_json.iter().any(|value| {
            value.get("cmd").and_then(Value::as_str) == Some(self.expected_agent_command.as_str())
                && value.get("ok").and_then(Value::as_bool) == Some(true)
                && value
                    .get("detail")
                    .and_then(Value::as_str)
                    .is_some_and(|detail| detail.contains(&self.execution_id))
        });
        if !proxy_result {
            return Err(TestError::new(
                Verdict::Unproven,
                "S1 agent did not receive the structured attributed response",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if let Some(target) = &self.target
            && target.join("cgroup.kill").exists()
        {
            let _ = fs::write(target.join("cgroup.kill"), b"1\n");
        }
        self.stop_agent();
        while let Some(link) = self.links.pop() {
            match link.unpin() {
                Ok(fd) => drop(fd),
                Err(error) => {
                    return Err(TestError::infra(format!("unpin S1 link: {error:#}")));
                }
            }
        }
        drop(self.bpf.take());
        remove_s1_pins(&self.pin_root).map_err(TestError::infra)?;
        let commands = self.commands(context);
        let nft_present = commands
            .run(&CommandSpec::new("nft").args(["list", "table", "inet", self.nft_table.as_str()]))
            .is_ok_and(|output| output.success());
        if nft_present {
            run_ok(
                &commands,
                "nft",
                vec!["delete", "table", "inet", &self.nft_table],
                "delete S1 nft table",
            )?;
        }
        if link_exists(&commands, &self.host_veth) {
            run_ok(
                &commands,
                "ip",
                vec!["link", "del", &self.host_veth],
                "delete S1 veth",
            )?;
        }
        if Path::new("/run/netns").join(&self.netns).exists() {
            run_ok(
                &commands,
                "ip",
                vec!["netns", "del", &self.netns],
                "delete S1 netns",
            )?;
        }
        if link_exists(&commands, &self.proxy_link) {
            run_ok(
                &commands,
                "ip",
                vec!["link", "del", &self.proxy_link],
                "delete S1 proxy interface",
            )?;
        }
        if let Some(target) = &self.target {
            remove_empty(target).map_err(TestError::infra)?;
        }
        if let Some(executions) = &self.executions {
            remove_empty(executions).map_err(TestError::infra)?;
        }
        let stop = commands
            .run(&CommandSpec::new("systemctl").args(["stop", self.unit.as_str()]))
            .map_err(TestError::infra)?;
        if !stop.success() && !stop.stderr_text().contains("not loaded") {
            return Err(TestError::infra(format!(
                "stop S1 unit: {}",
                stop.stderr_text()
            )));
        }
        remove_file(&self.delegation_ready).map_err(TestError::infra)?;
        for file in [
            "netns.nft",
            "host.nft",
            "agent-host.ready",
            "agent.ready",
            "agent.go",
        ] {
            remove_file(&self.runtime_root.join(file)).map_err(TestError::infra)?;
        }
        remove_empty(&self.runtime_root).map_err(TestError::infra)?;
        if let Some(parent) = self.runtime_root.parent() {
            let _ = fs::remove_dir(parent);
        }
        Ok(())
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        let commands = self.commands(context);
        let after = bpf_inventory(&commands)?;
        let bpf_assessment = self.baseline.as_ref().map_or_else(
            || InventoryAssessment {
                clean: false,
                classification: InventoryClassification::Drift,
                detail: "S1 BPF baseline missing".to_owned(),
                owned_objects_present: Vec::new(),
                links_identical: false,
                maps_identical: false,
                systemd_program_ids_before: Vec::new(),
                systemd_program_ids_after: Vec::new(),
            },
            |baseline| {
                assess_bpf_inventory(baseline, &after, context.resources.entries(), self.scope)
            },
        );
        let bpf_clean = bpf_assessment.clean;
        let nft_absent = commands
            .run(&CommandSpec::new("nft").args(["list", "table", "inet", self.nft_table.as_str()]))
            .is_ok_and(|output| !output.success());
        let unit = commands
            .run(&CommandSpec::new("systemctl").args([
                "show",
                self.unit.as_str(),
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
            ]))
            .map_err(TestError::infra)?;
        let clean = bpf_clean
            && !self.pin_root.exists()
            && !self.runtime_root.exists()
            && !Path::new("/run/netns").join(&self.netns).exists()
            && !link_exists(&commands, &self.host_veth)
            && !link_exists(&commands, &self.proxy_link)
            && nft_absent
            && self.target.as_ref().is_none_or(|path| !path.exists())
            && self.executions.as_ref().is_none_or(|path| !path.exists())
            && self
                .delegated_root
                .as_ref()
                .is_none_or(|path| !path.exists())
            && (unit.stdout_text().contains("LoadState=not-found")
                || unit.stdout_text().contains("ActiveState=inactive"));
        let evidence = serde_json::json!({
            "bpf_inventory_restored": bpf_clean,
            "bpf_inventory_classification": bpf_assessment.classification,
            "bpf_inventory_assessment": bpf_assessment,
            "pin_root_absent": !self.pin_root.exists(),
            "runtime_root_absent": !self.runtime_root.exists(),
            "netns_absent": !Path::new("/run/netns").join(&self.netns).exists(),
            "host_veth_absent": !link_exists(&commands, &self.host_veth),
            "proxy_link_absent": !link_exists(&commands, &self.proxy_link),
            "nft_table_absent": nft_absent,
            "target_absent": self.target.as_ref().is_none_or(|path| !path.exists()),
            "executions_absent": self.executions.as_ref().is_none_or(|path| !path.exists()),
            "delegated_root_absent": self.delegated_root.as_ref().is_none_or(|path| !path.exists()),
            "unit_state": unit.stdout_text(),
            "clean": clean,
        });
        context
            .evidence
            .write_json(format!("{}/cleanup.json", self.scope), &evidence)
            .map_err(|error| TestError::infra(format!("write S1 cleanup: {error}")))?;
        if !clean {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S1 owned resource baseline was not restored",
            ));
        }
        if bpf_assessment.classification == InventoryClassification::ExternalChurn {
            context.add_result_note(bpf_assessment.detail.clone());
        }
        context.resources.mark_owner_cleaned(self.scope);
        Ok(())
    }
}

fn attach_all(bpf: &mut Ebpf, cgroup: &File, root: &Path) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
    links.push(attach_cgroup_sock(
        bpf,
        cgroup,
        "soglia_sock_create",
        &root.join("sock_create"),
    )?);
    for (name, pin) in [
        ("soglia_connect4", "connect4"),
        ("soglia_connect6", "connect6"),
        ("soglia_sendmsg4", "sendmsg4"),
        ("soglia_sendmsg6", "sendmsg6"),
    ] {
        links.push(attach_cgroup_sock_addr(bpf, cgroup, name, &root.join(pin))?);
    }
    links.push(attach_sock_ops(
        bpf,
        cgroup,
        "soglia_sockops",
        &root.join("sock_ops"),
    )?);
    Ok(links)
}

fn attach_cgroup_sock(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<PinnedLink, String> {
    let program: &mut CgroupSock = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:?}"))?;
    let link = program
        .take_link(id)
        .map_err(|error| format!("take {name}: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("fd link {name}: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn attach_cgroup_sock_addr(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<PinnedLink, String> {
    let program: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:?}"))?;
    let link = program
        .take_link(id)
        .map_err(|error| format!("take {name}: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("fd link {name}: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn attach_sock_ops(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<PinnedLink, String> {
    let program: &mut SockOps = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:?}"))?;
    let link = program
        .take_link(id)
        .map_err(|error| format!("take {name}: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("fd link {name}: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn run_ok(
    commands: &CommandExecutor,
    executable: &str,
    arguments: Vec<&str>,
    label: &str,
) -> Result<(), TestError> {
    let output = commands
        .run(&CommandSpec::new(executable).args(arguments))
        .map_err(TestError::infra)?;
    require_success(&output, label)
}

fn require_success(output: &CommandOutput, label: &str) -> Result<(), TestError> {
    output.require_success(label).map_err(TestError::infra)
}

pub(crate) fn json_command<const N: usize>(
    commands: &CommandExecutor,
    arguments: [&str; N],
) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args(arguments))
        .map_err(TestError::infra)?;
    require_success(&output, "S1 bpftool JSON query")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse bpftool JSON: {error}")))
}

pub(crate) fn json_cgroup(
    commands: &CommandExecutor,
    path: &Path,
    effective: bool,
) -> Result<Value, TestError> {
    let mut args = vec![
        OsString::from("-j"),
        OsString::from("cgroup"),
        OsString::from("show"),
        path.as_os_str().to_owned(),
    ];
    if effective {
        args.push(OsString::from("effective"));
    }
    let output = commands
        .run(&CommandSpec::new("bpftool").args(args))
        .map_err(TestError::infra)?;
    require_success(&output, "inspect S1 cgroup attachments")?;
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Array(Vec::new()));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse S1 cgroup JSON: {error}")))
}

fn bpf_inventory(commands: &CommandExecutor) -> Result<BpfInventory, TestError> {
    Ok(BpfInventory {
        programs: json_command(commands, ["-j", "prog", "show"])?,
        links: json_command(commands, ["-j", "link", "show"])?,
        maps: json_command(commands, ["-j", "map", "show"])?,
    })
}

fn register_owned_bpf_objects(
    context: &mut TestContext,
    owner: &str,
    target_inode: u64,
    inventory: &BpfInventory,
) -> Result<(), TestError> {
    let programs = inventory
        .programs
        .as_array()
        .ok_or_else(|| TestError::infra("S1 program inventory was not an array"))?;
    let mut owned_map_ids = std::collections::BTreeSet::new();
    for program in programs.iter().filter(|program| {
        program
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.starts_with("soglia_"))
    }) {
        let id = object_id(program, "S1 program")?;
        let name = program
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        context.resources.register(
            owner,
            format!("S1 BPF program {name}"),
            Resource::BpfObject {
                id,
                object_kind: "prog".to_owned(),
            },
        );
        for map_id in program
            .get("map_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
        {
            owned_map_ids.insert(map_id);
        }
    }
    for link in inventory
        .links
        .as_array()
        .into_iter()
        .flatten()
        .filter(|link| {
            link.get("type").and_then(Value::as_str) == Some("cgroup")
                && link.get("cgroup_id").and_then(Value::as_u64) == Some(target_inode)
        })
    {
        context.resources.register(
            owner,
            "S1 BPF cgroup link",
            Resource::BpfObject {
                id: object_id(link, "S1 link")?,
                object_kind: "link".to_owned(),
            },
        );
    }
    for map in inventory
        .maps
        .as_array()
        .into_iter()
        .flatten()
        .filter(|map| {
            map.get("id")
                .and_then(Value::as_u64)
                .is_some_and(|id| owned_map_ids.contains(&id))
        })
    {
        let name = map.get("name").and_then(Value::as_str).unwrap_or("unknown");
        context.resources.register(
            owner,
            format!("S1 BPF map {name}"),
            Resource::BpfObject {
                id: object_id(map, "S1 map")?,
                object_kind: "map".to_owned(),
            },
        );
    }
    Ok(())
}

fn object_id(value: &Value, label: &str) -> Result<u32, TestError> {
    value
        .get("id")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
        .ok_or_else(|| TestError::infra(format!("{label} ID missing or out of range")))
}

pub(crate) fn array_values(json: &Value, count: usize) -> Result<Vec<u64>, TestError> {
    let entries = json
        .as_array()
        .ok_or_else(|| TestError::infra("bpftool array dump was not an array"))?;
    let mut values = vec![0_u64; count];
    for entry in entries {
        let key = entry
            .get("formatted")
            .and_then(|formatted| formatted.get("key"))
            .or_else(|| entry.get("key"))
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("bpftool array key was not numeric"))?;
        let value = entry
            .get("formatted")
            .and_then(|formatted| formatted.get("value"))
            .or_else(|| entry.get("value"))
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("bpftool array value was not numeric"))?;
        if let Some(slot) =
            values.get_mut(usize::try_from(key).map_err(|error| {
                TestError::infra(format!("convert bpftool array index: {error}"))
            })?)
        {
            *slot = value;
        }
    }
    Ok(values)
}

pub(crate) fn tuple_key(peer: SocketAddr, local: SocketAddr) -> Result<[u8; 16], String> {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        return Err("S1 expected an IPv4 tuple".to_owned());
    };
    let mut key = [0_u8; 16];
    key[0..4].copy_from_slice(&peer.ip().octets());
    key[4..8].copy_from_slice(&local.ip().octets());
    key[8..12].copy_from_slice(&u32::from(peer.port()).to_ne_bytes());
    key[12..16].copy_from_slice(&u32::from(local.port()).to_ne_bytes());
    Ok(key)
}

pub(crate) fn decode_evidence(bytes: [u8; 64]) -> [u64; 8] {
    let mut values = [0_u64; 8];
    for (index, value) in values.iter_mut().enumerate() {
        let start = index * 8;
        *value = u64::from_ne_bytes(bytes[start..start + 8].try_into().unwrap_or_default());
    }
    values
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn wait_for_path(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !path.exists() {
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

pub(crate) fn wait_for_process_stopped(pid: u32, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if process_is_stopped(pid)? {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("process {pid} did not stop before netns entry"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn process_is_stopped(pid: u32) -> Result<bool, String> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| format!("read process {pid} status: {error}"))?;
    Ok(status
        .lines()
        .find(|line| line.starts_with("State:"))
        .is_some_and(|line| line.contains("T (stopped)")))
}

pub(crate) fn read_pid(path: &Path) -> Result<u32, String> {
    fs::read_to_string(path)
        .map_err(|error| format!("read PID from {}: {error}", path.display()))?
        .trim()
        .parse()
        .map_err(|error| format!("parse PID from {}: {error}", path.display()))
}

pub(crate) fn read_trimmed(path: &Path) -> Result<String, TestError> {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .map_err(|error| TestError::infra(format!("read {}: {error}", path.display())))
}

pub(crate) fn line_present(value: &str, expected: &str) -> bool {
    value.lines().any(|line| line.trim() == expected)
}

pub(crate) fn inode(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.ino())
        .map_err(|error| format!("stat {}: {error}", path.display()))
}

fn require_array_len(value: &Value, expected: usize, label: &str) -> Result<(), TestError> {
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

fn is_empty_array(value: &Value) -> bool {
    value.as_array().is_some_and(Vec::is_empty)
}

fn list_files(root: &Path) -> Result<Vec<String>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                pending.push(entry.path());
            } else {
                files.push(entry.path().to_string_lossy().into_owned());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn link_exists(commands: &CommandExecutor, name: &str) -> bool {
    commands
        .run(&CommandSpec::new("ip").args(["link", "show", "dev", name]))
        .is_ok_and(|output| output.success())
}

fn remove_s1_pins(root: &Path) -> Result<(), String> {
    for name in [
        "sock_create",
        "connect4",
        "connect6",
        "sendmsg4",
        "sendmsg6",
        "sock_ops",
    ] {
        remove_file(&root.join("links").join(name))?;
    }
    for name in MAP_NAMES {
        remove_file(&root.join("maps").join(name))?;
    }
    remove_file(&root.join("maps/soglia_staging"))?;
    remove_empty(&root.join("links"))?;
    remove_empty(&root.join("maps"))?;
    remove_empty(root)?;
    if let Some(parent) = root.parent() {
        let _ = fs::remove_dir(parent);
        if let Some(parent) = parent.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
    Ok(())
}

fn remove_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn remove_empty(path: &Path) -> Result<(), String> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove directory {}: {error}", path.display())),
    }
}

fn short_id(run_id: &str) -> String {
    let value = run_id
        .chars()
        .rev()
        .take(12)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    value.replace('-', "")
}
