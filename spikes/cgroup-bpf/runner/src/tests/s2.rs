// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{CommandExecutor, CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::{SpikeTest, TestError};

const EXECUTIONS: usize = 4;
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Membership {
    index: usize,
    execution_id: String,
    cgroup: String,
    cgroup_inode: u64,
    agent_pid: u32,
    netns: String,
    netns_inode: u64,
    ip: String,
    expected_ident: u64,
    proc_cgroup: String,
    cgroup_procs: String,
    independently_proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S2Observation {
    memberships: Vec<Membership>,
    direct_attachments: Vec<Value>,
    effective_attachments: Vec<Value>,
    helper_exit_code: Option<i32>,
    helper_stdout: String,
    helper_stderr: String,
    metrics: BTreeMap<String, u64>,
}

pub struct S2 {
    unit: String,
    runtime: PathBuf,
    ready: PathBuf,
    delegated_root: Option<PathBuf>,
    executions: Option<PathBuf>,
    targets: Vec<PathBuf>,
    pin_root: PathBuf,
    proxy_link: String,
    nft_table: String,
    netns: Vec<String>,
    veth: Vec<String>,
    helper: Option<RunningCommand>,
}

impl S2 {
    pub fn new(context: &TestContext) -> Self {
        let short = short_id(&context.run_id);
        Self {
            unit: format!("soglia-spike-s2-{short}.service"),
            runtime: Path::new("/run/soglia-spike-runner")
                .join(&context.run_id)
                .join("s2"),
            ready: PathBuf::new(),
            delegated_root: None,
            executions: None,
            targets: Vec::new(),
            pin_root: Path::new("/sys/fs/bpf/soglia-spike-runner")
                .join(&context.run_id)
                .join("s2"),
            proxy_link: format!("s2p{}", &short[..short.len().min(7)]),
            nft_table: format!("sg_s2_{}", &short[..short.len().min(8)]),
            // The deliberately migrated S2 stimulus names these namespaces in
            // its trusted Execution mapping. The parent proves they are absent
            // before creation and owns each exact name for this test lifetime.
            netns: (0..EXECUTIONS)
                .map(|index| format!("soglia-s2-e{index}"))
                .collect(),
            veth: (0..EXECUTIONS)
                .map(|index| format!("s2{}{}", index, &short[..short.len().min(6)]))
                .collect(),
            helper: None,
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        context.test_commands("s2")
    }

    fn start_delegation(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        self.ready = self.runtime.join("delegation.json");
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
                        self.ready.as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(15)),
            )
            .map_err(TestError::infra)?;
        require_success(&output, "start S2 delegation")?;
        context.resources.register(
            "s2",
            "S2 delegated unit",
            Resource::SystemdUnit {
                name: self.unit.clone(),
            },
        );
        wait_path(&self.ready, Duration::from_secs(10)).map_err(TestError::infra)?;
        let record: Value = serde_json::from_slice(
            &fs::read(&self.ready).map_err(|error| TestError::infra(error.to_string()))?,
        )
        .map_err(|error| TestError::infra(format!("parse S2 delegation: {error}")))?;
        let root = PathBuf::from(
            record
                .get("cgroup_root")
                .and_then(Value::as_str)
                .ok_or_else(|| TestError::infra("S2 delegation root missing"))?,
        );
        let executions = root.join("executions");
        fs::create_dir(&executions)
            .map_err(|error| TestError::infra(format!("create S2 executions: {error}")))?;
        fs::write(
            executions.join("cgroup.subtree_control"),
            b"+memory +pids\n",
        )
        .map_err(|error| TestError::infra(format!("delegate S2 controllers: {error}")))?;
        for index in 0..EXECUTIONS {
            let target = executions.join(format!("s2-e{index}"));
            fs::create_dir(&target)
                .map_err(|error| TestError::infra(format!("create S2 e{index}: {error}")))?;
            context.resources.register(
                "s2",
                format!("S2 execution e{index}"),
                Resource::Cgroup {
                    path: target.clone(),
                    inode: inode(&target).map_err(TestError::infra)?,
                },
            );
            self.targets.push(target);
        }
        self.delegated_root = Some(root);
        self.executions = Some(executions);
        Ok(())
    }

    fn create_network(&self, context: &mut TestContext) -> Result<(), TestError> {
        let commands = self.commands(context);
        run_ok(
            &commands,
            "ip",
            vec!["link", "add", &self.proxy_link, "type", "dummy"],
            "create S2 proxy link",
        )?;
        run_ok(
            &commands,
            "ip",
            vec!["addr", "add", "10.200.255.1/32", "dev", &self.proxy_link],
            "address S2 proxy link",
        )?;
        run_ok(
            &commands,
            "ip",
            vec!["link", "set", &self.proxy_link, "up"],
            "raise S2 proxy link",
        )?;
        context.resources.register(
            "s2",
            "S2 proxy link",
            Resource::Interface {
                name: self.proxy_link.clone(),
            },
        );
        let namespace_rules = self.runtime.join("netns.nft");
        fs::write(
            &namespace_rules,
            r#"table inet soglia {
 chain input { type filter hook input priority filter; policy drop; iif "lo" accept; ct state established,related accept; }
 chain output { type filter hook output priority filter; policy drop; oif "lo" accept; ct state established,related accept; ip daddr 10.200.255.1 tcp dport 15001 ct state new accept; }
 chain forward { type filter hook forward priority filter; policy drop; }
}
"#,
        )
        .map_err(|error| TestError::infra(format!("write S2 namespace rules: {error}")))?;
        for index in 0..EXECUTIONS {
            let network = index * 4;
            let agent_ip = format!("10.201.0.{}/30", network + 1);
            let host_ip = format!("10.201.0.{}/30", network + 2);
            let gateway = format!("10.201.0.{}", network + 2);
            run_ok(
                &commands,
                "ip",
                vec!["netns", "add", &self.netns[index]],
                "create S2 netns",
            )?;
            run_ok(
                &commands,
                "ip",
                vec![
                    "link",
                    "add",
                    &self.veth[index],
                    "type",
                    "veth",
                    "peer",
                    "name",
                    "eth0",
                    "netns",
                    &self.netns[index],
                ],
                "create S2 veth",
            )?;
            for args in [
                vec!["addr", "add", &host_ip, "dev", &self.veth[index]],
                vec!["link", "set", &self.veth[index], "up"],
                vec![
                    "netns",
                    "exec",
                    &self.netns[index],
                    "ip",
                    "link",
                    "set",
                    "lo",
                    "up",
                ],
                vec![
                    "netns",
                    "exec",
                    &self.netns[index],
                    "ip",
                    "addr",
                    "add",
                    &agent_ip,
                    "dev",
                    "eth0",
                ],
                vec![
                    "netns",
                    "exec",
                    &self.netns[index],
                    "ip",
                    "link",
                    "set",
                    "eth0",
                    "up",
                ],
                vec![
                    "netns",
                    "exec",
                    &self.netns[index],
                    "ip",
                    "route",
                    "add",
                    "10.200.255.1/32",
                    "via",
                    &gateway,
                    "dev",
                    "eth0",
                ],
                vec![
                    "netns",
                    "exec",
                    &self.netns[index],
                    "nft",
                    "-f",
                    namespace_rules.to_string_lossy().as_ref(),
                ],
            ] {
                run_ok(&commands, "ip", args, "configure S2 execution network")?;
            }
            context.resources.register(
                "s2",
                format!("S2 netns e{index}"),
                Resource::Netns {
                    name: self.netns[index].clone(),
                },
            );
            context.resources.register(
                "s2",
                format!("S2 veth e{index}"),
                Resource::Interface {
                    name: self.veth[index].clone(),
                },
            );
        }
        let host_rules = self.runtime.join("host.nft");
        let mut rules = format!(
            "table inet {} {{\n chain input {{ type filter hook input priority filter - 10; policy accept;\n",
            self.nft_table
        );
        for index in 0..EXECUTIONS {
            rules.push_str(&format!(
                "  iifname \"{}\" ip saddr != 10.201.0.{} drop\n",
                self.veth[index],
                index * 4 + 1
            ));
            rules.push_str(&format!(
                "  iifname \"{}\" ct state invalid drop\n  iifname \"{}\" ct state new meta l4proto != tcp drop\n  iifname \"{}\" ct state new ip daddr != 10.200.255.1 drop\n  iifname \"{}\" ct state new tcp dport != 15001 drop\n",
                self.veth[index], self.veth[index], self.veth[index], self.veth[index]
            ));
        }
        rules.push_str(
            " }\n chain forward { type filter hook forward priority filter - 10; policy accept;\n",
        );
        for veth in &self.veth {
            rules.push_str(&format!(
                "  iifname \"{veth}\" drop\n  oifname \"{veth}\" drop\n"
            ));
        }
        rules.push_str(" }\n}\n");
        fs::write(&host_rules, rules)
            .map_err(|error| TestError::infra(format!("write S2 host rules: {error}")))?;
        run_ok(
            &commands,
            "nft",
            vec!["-f", host_rules.to_string_lossy().as_ref()],
            "install S2 host nft policy",
        )?;
        context.resources.register(
            "s2",
            "S2 host nft table",
            Resource::NftObject {
                family: "inet".to_owned(),
                table: self.nft_table.clone(),
                object: "table".to_owned(),
            },
        );
        Ok(())
    }
}

impl SpikeTest for S2 {
    type Observation = S2Observation;

    fn id(&self) -> TestId {
        TestId::S2
    }

    fn invariant(&self) -> &'static str {
        "four live Executions and 132 sockets have zero cross-attribution; missing publication remains fail closed"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if self
            .netns
            .iter()
            .any(|name| Path::new("/run/netns").join(name).exists())
            || self.runtime.exists()
            || self.pin_root.exists()
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S2 exact owned topology name existed before preparation",
            ));
        }
        fs::create_dir_all(&self.runtime)
            .map_err(|error| TestError::infra(format!("create S2 runtime: {error}")))?;
        context.resources.register(
            "s2",
            "S2 runtime",
            Resource::Directory {
                path: self.runtime.clone(),
            },
        );
        self.start_delegation(context)?;
        self.create_network(context)
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let commands = self.commands(context);
        let helper_ready = self.runtime.join("helper.ready");
        let helper_go = self.runtime.join("helper.go");
        let membership_ready = self.runtime.join("membership.ready");
        let membership_captured = self.runtime.join("membership.captured");
        let executions = self
            .executions
            .as_ref()
            .ok_or_else(|| TestError::infra("S2 executions path missing"))?;
        let helper = commands
            .spawn(
                &CommandSpec::new(context.artifact("bin/s2-helper"))
                    .args([
                        context.artifact("bpf/soglia-delay-diag.o").into_os_string(),
                        executions.as_os_str().to_owned(),
                        self.pin_root.join("maps").into_os_string(),
                        self.pin_root.join("links").into_os_string(),
                        context.artifact("bin/soglia-spike-agent").into_os_string(),
                        helper_ready.as_os_str().to_owned(),
                        helper_go.as_os_str().to_owned(),
                        membership_ready.as_os_str().to_owned(),
                        membership_captured.as_os_str().to_owned(),
                        context.evidence.root().as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(60)),
            )
            .map_err(TestError::infra)?;
        context.resources.register(
            "s2",
            "S2 migrated Rust stimulus",
            Resource::Process { pid: helper.id() },
        );
        self.helper = Some(helper);
        wait_path(&helper_ready, Duration::from_secs(15)).map_err(TestError::infra)?;
        let mut direct_attachments = Vec::new();
        let mut effective_attachments = Vec::new();
        for target in &self.targets {
            direct_attachments.push(cgroup_json(&commands, target, false)?);
            effective_attachments.push(cgroup_json(&commands, target, true)?);
        }
        fs::write(&helper_go, b"go\n")
            .map_err(|error| TestError::infra(format!("release S2 helper: {error}")))?;
        wait_path(&membership_ready, Duration::from_secs(15)).map_err(TestError::infra)?;
        let mappings = fs::read_to_string(&membership_ready)
            .map_err(|error| TestError::infra(format!("read S2 mappings: {error}")))?;
        let mut memberships = Vec::new();
        for line in mappings.lines() {
            let fields = parse_fields(line);
            let index = parsed(&fields, "index")?;
            let agent_pid = parsed(&fields, "agent_pid")?;
            let cgroup = PathBuf::from(required(&fields, "cgroup")?);
            let proc_cgroup = fs::read_to_string(format!("/proc/{agent_pid}/cgroup"))
                .map_err(|error| TestError::infra(format!("read S2 agent cgroup: {error}")))?;
            let cgroup_procs = fs::read_to_string(cgroup.join("cgroup.procs"))
                .map_err(|error| TestError::infra(format!("read S2 cgroup.procs: {error}")))?;
            let expected = format!(
                "0::/{}",
                cgroup
                    .strip_prefix("/sys/fs/cgroup")
                    .map_err(|_| TestError::infra("S2 cgroup outside cgroup2"))?
                    .to_string_lossy()
                    .trim_start_matches('/')
            );
            let agent_netns =
                inode(Path::new(&format!("/proc/{agent_pid}/ns/net"))).map_err(TestError::infra)?;
            let netns = required(&fields, "netns")?.to_owned();
            let owned_netns =
                inode(&Path::new("/run/netns").join(&netns)).map_err(TestError::infra)?;
            let cgroup_inode = parsed(&fields, "cgroup_inode")?;
            memberships.push(Membership {
                index,
                execution_id: required(&fields, "execution_id")?.to_owned(),
                cgroup: cgroup.to_string_lossy().into_owned(),
                cgroup_inode,
                agent_pid,
                netns,
                netns_inode: agent_netns,
                ip: required(&fields, "ip")?.to_owned(),
                expected_ident: parsed(&fields, "expected_ident")?,
                independently_proven: proc_cgroup.lines().any(|value| value == expected)
                    && cgroup_procs
                        .lines()
                        .any(|value| value == agent_pid.to_string())
                    && agent_netns == owned_netns
                    && inode(&cgroup).map_err(TestError::infra)? == cgroup_inode,
                proc_cgroup,
                cgroup_procs,
            });
        }
        context
            .evidence
            .write_json("s2/memberships.json", &memberships)
            .map_err(|error| TestError::infra(format!("write S2 memberships: {error}")))?;
        fs::write(&membership_captured, b"captured\n")
            .map_err(|error| TestError::infra(format!("release S2 traffic: {error}")))?;
        let helper = self
            .helper
            .take()
            .ok_or_else(|| TestError::infra("S2 helper missing"))?;
        let output = helper
            .wait(Duration::from_secs(50))
            .map_err(TestError::infra)?;
        let stdout = output.stdout_text();
        let metric_names = [
            "s2_execution_count",
            "s2_connection_count",
            "s2_concurrent_unresolved_peak",
            "s2_successes",
            "s2_bounded_waits",
            "s2_timeouts",
            "s2_unique_socket_cookies",
            "s2_attribution_mismatches",
            "s2_cross_attribution_count",
            "s2_unexpected_tuple_collisions",
            "s2_unexpected_map_errors",
        ];
        let mut metrics = BTreeMap::new();
        for name in metric_names {
            let value = parse_metric(&stdout, name).ok_or_else(|| {
                TestError::new(Verdict::Unproven, format!("S2 metric {name} missing"))
            })?;
            metrics.insert(name.to_owned(), value);
        }
        Ok(S2Observation {
            memberships,
            direct_attachments,
            effective_attachments,
            helper_exit_code: output.record.exit_code,
            helper_stdout: stdout,
            helper_stderr: output.stderr_text(),
            metrics,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if observation.memberships.len() != EXECUTIONS
            || observation
                .memberships
                .iter()
                .any(|membership| !membership.independently_proven)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S2 live Execution membership was not independently proven",
            ));
        }
        for attachments in observation
            .direct_attachments
            .iter()
            .chain(&observation.effective_attachments)
        {
            if attachments.as_array().map_or(0, Vec::len) != 6 {
                return Err(TestError::new(
                    Verdict::Unproven,
                    "S2 did not observe six direct/effective hooks per Execution",
                ));
            }
        }
        let expected = [
            ("s2_execution_count", 4),
            ("s2_connection_count", 132),
            ("s2_concurrent_unresolved_peak", 132),
            ("s2_successes", 128),
            ("s2_bounded_waits", 128),
            ("s2_timeouts", 4),
            ("s2_unique_socket_cookies", 132),
            ("s2_attribution_mismatches", 0),
            ("s2_cross_attribution_count", 0),
            ("s2_unexpected_tuple_collisions", 0),
            ("s2_unexpected_map_errors", 0),
        ];
        for (name, expected) in expected {
            if observation.metrics.get(name) != Some(&expected) {
                return Err(TestError::new(
                    Verdict::Fail,
                    format!("S2 metric {name} did not equal {expected}"),
                ));
            }
        }
        if observation.helper_exit_code != Some(0) {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S2 Rust stimulus failed: {}", observation.helper_stderr),
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if let Some(mut helper) = self.helper.take() {
            let _ = helper.terminate();
            let _ = helper.wait(Duration::from_secs(5));
        }
        for target in &self.targets {
            if target.join("cgroup.kill").exists() {
                let _ = fs::write(target.join("cgroup.kill"), b"1\n");
            }
        }
        remove_known_pins(&self.pin_root).map_err(TestError::infra)?;
        let commands = self.commands(context);
        if commands
            .run(&CommandSpec::new("nft").args(["list", "table", "inet", self.nft_table.as_str()]))
            .is_ok_and(|output| output.success())
        {
            run_ok(
                &commands,
                "nft",
                vec!["delete", "table", "inet", &self.nft_table],
                "delete S2 nft table",
            )?;
        }
        for index in 0..EXECUTIONS {
            if link_exists(&commands, &self.veth[index]) {
                run_ok(
                    &commands,
                    "ip",
                    vec!["link", "del", &self.veth[index]],
                    "delete S2 veth",
                )?;
            }
            if Path::new("/run/netns").join(&self.netns[index]).exists() {
                run_ok(
                    &commands,
                    "ip",
                    vec!["netns", "del", &self.netns[index]],
                    "delete S2 netns",
                )?;
            }
            for suffix in ["host.ready", "agent.ready", "agent.go"] {
                remove_file(&PathBuf::from(format!(
                    "/run/soglia-spike-s2-e{index}-{suffix}"
                )))
                .map_err(TestError::infra)?;
            }
        }
        if link_exists(&commands, &self.proxy_link) {
            run_ok(
                &commands,
                "ip",
                vec!["link", "del", &self.proxy_link],
                "delete S2 proxy link",
            )?;
        }
        for target in self.targets.iter().rev() {
            remove_dir(target).map_err(TestError::infra)?;
        }
        if let Some(executions) = &self.executions {
            remove_dir(executions).map_err(TestError::infra)?;
        }
        let stop = commands
            .run(&CommandSpec::new("systemctl").args(["stop", self.unit.as_str()]))
            .map_err(TestError::infra)?;
        if !stop.success() && !stop.stderr_text().contains("not loaded") {
            return Err(TestError::infra(format!(
                "stop S2 unit: {}",
                stop.stderr_text()
            )));
        }
        for name in [
            "delegation.json",
            "netns.nft",
            "host.nft",
            "helper.ready",
            "helper.go",
            "membership.ready",
            "membership.captured",
        ] {
            remove_file(&self.runtime.join(name)).map_err(TestError::infra)?;
        }
        remove_dir(&self.runtime).map_err(TestError::infra)?;
        if let Some(parent) = self.runtime.parent() {
            let _ = fs::remove_dir(parent);
        }
        Ok(())
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        let commands = self.commands(context);
        let programs = json(&commands, ["-j", "prog", "show"])?;
        let links = json(&commands, ["-j", "link", "show"])?;
        let maps = json(&commands, ["-j", "map", "show"])?;
        let no_soglia = [&programs, &maps].iter().all(|value| {
            value.as_array().is_some_and(|items| {
                items.iter().all(|item| {
                    item.get("name")
                        .and_then(Value::as_str)
                        .is_none_or(|name| !name.starts_with("soglia_"))
                })
            })
        });
        let target_inodes = self
            .targets
            .iter()
            .filter_map(|path| fs::metadata(path).ok().map(|metadata| metadata.ino()))
            .collect::<Vec<_>>();
        let no_owned_links = links.as_array().is_some_and(|items| {
            items.iter().all(|item| {
                item.get("cgroup_id")
                    .and_then(Value::as_u64)
                    .is_none_or(|id| !target_inodes.contains(&id))
            })
        });
        let clean = no_soglia
            && no_owned_links
            && !self.pin_root.exists()
            && !self.runtime.exists()
            && self.targets.iter().all(|path| !path.exists())
            && self.executions.as_ref().is_none_or(|path| !path.exists())
            && self
                .delegated_root
                .as_ref()
                .is_none_or(|path| !path.exists())
            && self
                .netns
                .iter()
                .all(|name| !Path::new("/run/netns").join(name).exists())
            && self.veth.iter().all(|name| !link_exists(&commands, name))
            && !link_exists(&commands, &self.proxy_link);
        context
            .evidence
            .write_json(
                "s2/cleanup.json",
                &serde_json::json!({
                    "no_soglia_programs_or_maps": no_soglia,
                    "no_owned_cgroup_links": no_owned_links,
                    "pin_root_absent": !self.pin_root.exists(),
                    "runtime_absent": !self.runtime.exists(),
                    "targets_absent": self.targets.iter().all(|path| !path.exists()),
                    "netns_absent": self.netns.iter().all(|name| !Path::new("/run/netns").join(name).exists()),
                    "links_absent": self.veth.iter().all(|name| !link_exists(&commands, name)) && !link_exists(&commands, &self.proxy_link),
                    "clean": clean,
                }),
            )
            .map_err(|error| TestError::infra(format!("write S2 cleanup: {error}")))?;
        if !clean {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S2 owned resources were not absent",
            ));
        }
        context.resources.mark_owner_cleaned("s2");
        Ok(())
    }
}

fn parse_metric(stdout: &str, name: &str) -> Option<u64> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))?
        .parse()
        .ok()
}

fn parse_fields(line: &str) -> BTreeMap<&str, &str> {
    line.split_whitespace()
        .filter_map(|field| field.split_once('='))
        .collect()
}

fn required<'a>(fields: &'a BTreeMap<&str, &str>, name: &str) -> Result<&'a str, TestError> {
    fields
        .get(name)
        .copied()
        .ok_or_else(|| TestError::infra(format!("S2 mapping field {name} missing")))
}

fn parsed<T: std::str::FromStr>(fields: &BTreeMap<&str, &str>, name: &str) -> Result<T, TestError> {
    required(fields, name)?
        .parse()
        .map_err(|_| TestError::infra(format!("S2 mapping field {name} has an invalid value")))
}

fn cgroup_json(
    commands: &CommandExecutor,
    target: &Path,
    effective: bool,
) -> Result<Value, TestError> {
    let mut args = vec![
        OsString::from("-j"),
        OsString::from("cgroup"),
        OsString::from("show"),
        target.as_os_str().to_owned(),
    ];
    if effective {
        args.push(OsString::from("effective"));
    }
    let output = commands
        .run(&CommandSpec::new("bpftool").args(args))
        .map_err(TestError::infra)?;
    require_success(&output, "inspect S2 cgroup")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse S2 cgroup JSON: {error}")))
}

fn json<const N: usize>(commands: &CommandExecutor, args: [&str; N]) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args(args))
        .map_err(TestError::infra)?;
    require_success(&output, "S2 bpftool inventory")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse S2 inventory: {error}")))
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

fn wait_path(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !path.exists() {
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn inode(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.ino())
        .map_err(|error| format!("stat {}: {error}", path.display()))
}

fn link_exists(commands: &CommandExecutor, name: &str) -> bool {
    commands
        .run(&CommandSpec::new("ip").args(["link", "show", "dev", name]))
        .is_ok_and(|output| output.success())
}

fn remove_known_pins(root: &Path) -> Result<(), String> {
    for index in 0..EXECUTIONS {
        for name in [
            "sock_create",
            "connect4",
            "connect6",
            "sendmsg4",
            "sendmsg6",
            "sock_ops",
        ] {
            remove_file(&root.join("links").join(format!("e{index}")).join(name))?;
        }
        let _ = fs::remove_dir(root.join("links").join(format!("e{index}")));
    }
    for name in [
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
        "soglia_staging",
    ] {
        remove_file(&root.join("maps").join(name))?;
    }
    let _ = fs::remove_dir(root.join("links"));
    let _ = fs::remove_dir(root.join("maps"));
    let _ = fs::remove_dir(root);
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

fn remove_dir(path: &Path) -> Result<(), String> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove directory {}: {error}", path.display())),
    }
}

fn short_id(run_id: &str) -> String {
    run_id
        .chars()
        .rev()
        .take(12)
        .collect::<String>()
        .chars()
        .rev()
        .filter(|value| *value != '-')
        .collect()
}
