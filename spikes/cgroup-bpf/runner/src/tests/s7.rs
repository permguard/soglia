// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::s1::{
    S1, WAIT_SHORT, array_values, inode, json_cgroup, line_present, read_pid, read_trimmed,
    wait_for_path, wait_for_process_stopped,
};
use crate::tests::{SpikeTest, TestError};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Membership {
    pid: u32,
    target_inode: u64,
    proc_cgroup: String,
    target_processes: String,
    agent_netns_inode: u64,
    owned_netns_inode: u64,
    proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attempt {
    membership: Membership,
    agent_exit_code: Option<i32>,
    agent_signal: Option<i32>,
    agent_json: Vec<Value>,
    listener_accepted: bool,
    accepted_peer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S7Observation {
    loader_pid: u32,
    loader_exit_code: Option<i32>,
    loader_signal: Option<i32>,
    loader_proc_absent: bool,
    before_loss_direct: Value,
    before_loss_effective: Value,
    after_loss_direct: Value,
    after_loss_effective: Value,
    link_pin_count_before: usize,
    link_pin_count_after: usize,
    map_pin_count_before: usize,
    map_pin_count_after: usize,
    pin_set_preserved: bool,
    deny_after_loader_loss: Attempt,
    diagnostic_entries_after_deny: Vec<u64>,
    counters_after_deny: Vec<u64>,
    deny_entries_after_deny: usize,
    after_connect4_unpin_direct: Value,
    after_connect4_unpin_effective: Value,
    path_after_connect4_unpin: Attempt,
    lost_userspace_functionality: Vec<String>,
    retained_kernel_functionality: Vec<String>,
}

pub struct S7 {
    fixture: S1,
    loader: Option<RunningCommand>,
    agent: Option<RunningCommand>,
}

impl S7 {
    pub fn new(context: &TestContext) -> Self {
        Self {
            fixture: S1::new_s7(context),
            loader: None,
            agent: None,
        }
    }

    fn run_attempt(
        &mut self,
        context: &mut TestContext,
        listener: &TcpListener,
    ) -> Result<Attempt, TestError> {
        for name in ["agent-host.ready", "agent.ready", "agent.go"] {
            remove_file(&self.fixture.runtime_root.join(name))?;
        }
        let host_ready = self.fixture.runtime_root.join("agent-host.ready");
        let agent_ready = self.fixture.runtime_root.join("agent.ready");
        let agent_go = self.fixture.runtime_root.join("agent.go");
        let child = self
            .fixture
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
                        OsString::from("direct 10.201.0.2:16001"),
                    ])
                    .timeout(Duration::from_secs(15)),
            )
            .map_err(TestError::infra)?;
        let pid = child.id();
        context.resources.register(
            "s7",
            "S7 controlled direct agent",
            Resource::Process { pid },
        );
        self.agent = Some(child);
        wait_for_path(&host_ready, WAIT_SHORT).map_err(TestError::infra)?;
        wait_for_process_stopped(pid, WAIT_SHORT).map_err(TestError::infra)?;
        if read_pid(&host_ready).map_err(TestError::infra)? != pid {
            return Err(TestError::new(
                Verdict::Unproven,
                "S7 trusted launcher PID mismatch",
            ));
        }
        let target = self.fixture.target()?.to_path_buf();
        fs::write(target.join("cgroup.procs"), format!("{pid}\n"))
            .map_err(|error| TestError::infra(format!("place S7 agent: {error}")))?;
        kill(
            Pid::from_raw(
                i32::try_from(pid)
                    .map_err(|error| TestError::infra(format!("convert S7 PID: {error}")))?,
            ),
            Signal::SIGCONT,
        )
        .map_err(|error| TestError::infra(format!("continue S7 agent: {error}")))?;
        wait_for_path(&agent_ready, WAIT_SHORT).map_err(TestError::infra)?;
        if read_pid(&agent_ready).map_err(TestError::infra)? != pid {
            return Err(TestError::new(
                Verdict::Unproven,
                "S7 actual agent PID mismatch",
            ));
        }
        let relative = target
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| TestError::infra("S7 target outside cgroup2"))?;
        let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
        let proc_cgroup = read_trimmed(Path::new(&format!("/proc/{pid}/cgroup")))?;
        let target_processes = read_trimmed(&target.join("cgroup.procs"))?;
        let agent_netns_inode =
            inode(Path::new(&format!("/proc/{pid}/ns/net"))).map_err(TestError::infra)?;
        let owned_netns_inode =
            inode(&Path::new("/run/netns").join(&self.fixture.netns)).map_err(TestError::infra)?;
        let target_inode = inode(&target).map_err(TestError::infra)?;
        let proven = line_present(&proc_cgroup, &expected)
            && line_present(&target_processes, &pid.to_string())
            && agent_netns_inode == owned_netns_inode;
        if !proven {
            return Err(TestError::new(
                Verdict::Unproven,
                "S7 live membership not proven",
            ));
        }
        fs::write(agent_go, b"go\n")
            .map_err(|error| TestError::infra(format!("release S7 agent: {error}")))?;
        let output = self
            .agent
            .take()
            .ok_or_else(|| TestError::infra("S7 agent missing"))?
            .wait(Duration::from_secs(8))
            .map_err(TestError::infra)?;
        let json = output
            .stdout_text()
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|error| TestError::infra(format!("parse S7 agent JSON: {error}")))?;
        let accepted = match listener.accept() {
            Ok((stream, peer)) => {
                drop(stream);
                (true, peer.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (false, String::new()),
            Err(error) => return Err(TestError::infra(format!("S7 listener accept: {error}"))),
        };
        Ok(Attempt {
            membership: Membership {
                pid,
                target_inode,
                proc_cgroup,
                target_processes,
                agent_netns_inode,
                owned_netns_inode,
                proven,
            },
            agent_exit_code: output.record.exit_code,
            agent_signal: output.record.signal,
            agent_json: json,
            listener_accepted: accepted.0,
            accepted_peer: accepted.1,
        })
    }
}

impl SpikeTest for S7 {
    type Observation = S7Observation;

    fn id(&self) -> TestId {
        TestId::S7
    }

    fn invariant(&self) -> &'static str {
        "pinned links and maps preserve kernel enforcement after abrupt loader loss, while removing only the connect4 pin detaches that gate and exposes the controlled path"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::prepare(&mut self.fixture, context)?;
        self.fixture.unload_bpf()?;
        let output = self
            .fixture
            .commands(context)
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
                "s7-direct-exposure",
            ]))
            .map_err(TestError::infra)?;
        require_success(&output, "expose S7 direct path through namespace nft")
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let ready = self.fixture.runtime_root.join("s7-loader.ready");
        let loader = self
            .fixture
            .commands(context)
            .spawn(
                &CommandSpec::new(context.artifact("bin/s7-loader"))
                    .args([
                        context.artifact("bpf/soglia-diag.o").into_os_string(),
                        self.fixture.target()?.as_os_str().to_owned(),
                        self.fixture.pin_root.join("maps").into_os_string(),
                        self.fixture.pin_root.join("links").into_os_string(),
                        ready.as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(120)),
            )
            .map_err(TestError::infra)?;
        let loader_pid = loader.id();
        context.resources.register(
            "s7",
            "S7 deliberately migrated pinned loader",
            Resource::Process { pid: loader_pid },
        );
        self.loader = Some(loader);
        wait_for_path(&ready, WAIT_SHORT).map_err(TestError::infra)?;
        if read_pid(&ready).map_err(TestError::infra)? != loader_pid {
            return Err(TestError::new(
                Verdict::Unproven,
                "S7 loader announced a different PID",
            ));
        }
        let commands = self.fixture.commands(context);
        let target = self.fixture.target()?.to_path_buf();
        let before_loss_direct = json_cgroup(&commands, &target, false)?;
        let before_loss_effective = json_cgroup(&commands, &target, true)?;
        let before_links = list_names(&self.fixture.pin_root.join("links"))?;
        let before_maps = list_names(&self.fixture.pin_root.join("maps"))?;

        kill(
            Pid::from_raw(
                i32::try_from(loader_pid)
                    .map_err(|error| TestError::infra(format!("convert S7 loader PID: {error}")))?,
            ),
            Signal::SIGKILL,
        )
        .map_err(|error| TestError::infra(format!("kill S7 loader: {error}")))?;
        let loader_output = self
            .loader
            .take()
            .ok_or_else(|| TestError::infra("S7 loader missing"))?
            .wait(Duration::from_secs(5))
            .map_err(TestError::infra)?;
        let loader_proc_absent = !Path::new(&format!("/proc/{loader_pid}")).exists();
        let after_loss_direct = json_cgroup(&commands, &target, false)?;
        let after_loss_effective = json_cgroup(&commands, &target, true)?;
        let after_links = list_names(&self.fixture.pin_root.join("links"))?;
        let after_maps = list_names(&self.fixture.pin_root.join("maps"))?;

        let listener = TcpListener::bind((Ipv4Addr::new(10, 201, 0, 2), 16_001))
            .map_err(|error| TestError::infra(format!("bind S7 listener: {error}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| TestError::infra(format!("set S7 listener: {error}")))?;
        let deny_after_loader_loss = self.run_attempt(context, &listener)?;
        let diagnostic_entries_after_deny = array_values(
            &dump_pinned(context, &self.fixture.pin_root, "soglia_diag_entries")?,
            7,
        )?;
        let counters_after_deny = array_values(
            &dump_pinned(context, &self.fixture.pin_root, "soglia_counters")?,
            9,
        )?;
        let deny_entries_after_deny =
            dump_pinned(context, &self.fixture.pin_root, "soglia_denies")?
                .as_array()
                .map_or(0, Vec::len);

        fs::remove_file(self.fixture.pin_root.join("links/connect4"))
            .map_err(|error| TestError::infra(format!("unpin only S7 connect4: {error}")))?;
        let after_connect4_unpin_direct = json_cgroup(&commands, &target, false)?;
        let after_connect4_unpin_effective = json_cgroup(&commands, &target, true)?;
        let path_after_connect4_unpin = self.run_attempt(context, &listener)?;

        Ok(S7Observation {
            loader_pid,
            loader_exit_code: loader_output.record.exit_code,
            loader_signal: loader_output.record.signal,
            loader_proc_absent,
            before_loss_direct,
            before_loss_effective,
            after_loss_direct,
            after_loss_effective,
            link_pin_count_before: before_links.len(),
            link_pin_count_after: after_links.len(),
            map_pin_count_before: before_maps.len(),
            map_pin_count_after: after_maps.len(),
            pin_set_preserved: before_links == after_links && before_maps == after_maps,
            deny_after_loader_loss,
            diagnostic_entries_after_deny,
            counters_after_deny,
            deny_entries_after_deny,
            after_connect4_unpin_direct,
            after_connect4_unpin_effective,
            path_after_connect4_unpin,
            lost_userspace_functionality: vec![
                "loader-owned unpinned file descriptors".to_owned(),
                "ring-event consumption".to_owned(),
                "policy management".to_owned(),
                "automatic unpin and cleanup".to_owned(),
            ],
            retained_kernel_functionality: vec![
                "execution of pinned programs".to_owned(),
                "retained and writable pinned maps".to_owned(),
            ],
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if observation.loader_exit_code.is_some()
            || observation.loader_signal != Some(9)
            || !observation.loader_proc_absent
            || observation.before_loss_direct != observation.after_loss_direct
            || observation.before_loss_effective != observation.after_loss_effective
            || observation.link_pin_count_before != 6
            || observation.link_pin_count_after != 6
            || observation.map_pin_count_before != 10
            || observation.map_pin_count_after != 10
            || !observation.pin_set_preserved
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S7 pinned kernel identity did not demonstrably survive loader SIGKILL",
            ));
        }
        if !observation.deny_after_loader_loss.membership.proven
            || attempt_ok(&observation.deny_after_loader_loss)
            || observation.deny_after_loader_loss.listener_accepted
            || observation.diagnostic_entries_after_deny.get(1) != Some(&1)
            || observation.counters_after_deny.get(4) != Some(&1)
            || observation.deny_entries_after_deny != 1
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S7 connect4 enforcement did not survive loader loss",
            ));
        }
        let direct = observation
            .after_connect4_unpin_direct
            .as_array()
            .ok_or_else(|| TestError::infra("S7 post-unpin cgroup JSON invalid"))?;
        let effective = observation
            .after_connect4_unpin_effective
            .as_array()
            .ok_or_else(|| TestError::infra("S7 post-unpin effective cgroup JSON invalid"))?;
        if direct.len() != 5
            || effective.len() != 5
            || direct.iter().any(|program| {
                program.get("name").and_then(Value::as_str) == Some("soglia_connect4")
            })
            || effective.iter().any(|program| {
                program.get("name").and_then(Value::as_str) == Some("soglia_connect4")
            })
            || !observation.path_after_connect4_unpin.membership.proven
            || !attempt_ok(&observation.path_after_connect4_unpin)
            || !observation.path_after_connect4_unpin.listener_accepted
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S7 removing only the connect4 pin did not causally expose the path",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if let Some(mut agent) = self.agent.take() {
            let _ = agent.terminate();
            let _ = agent.wait(Duration::from_secs(3));
        }
        if let Some(mut loader) = self.loader.take() {
            let _ = loader.terminate();
            let _ = loader.wait(Duration::from_secs(3));
        }
        remove_file(&self.fixture.runtime_root.join("s7-loader.ready"))?;
        <S1 as SpikeTest>::cleanup(&mut self.fixture, context)
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)
    }
}

fn dump_pinned(context: &TestContext, root: &Path, name: &str) -> Result<Value, TestError> {
    let output = context
        .test_commands("s7")
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("map"),
            OsString::from("dump"),
            OsString::from("pinned"),
            root.join("maps").join(name).into_os_string(),
        ]))
        .map_err(TestError::infra)?;
    require_success(&output, "dump S7 pinned map")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse S7 map: {error}")))
}

fn list_names(path: &Path) -> Result<Vec<String>, TestError> {
    let mut names = fs::read_dir(path)
        .map_err(|error| TestError::infra(format!("read {}: {error}", path.display())))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| TestError::infra(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

fn attempt_ok(attempt: &Attempt) -> bool {
    attempt.agent_exit_code == Some(0)
        && attempt.agent_signal.is_none()
        && attempt.agent_json.iter().any(|value| {
            value.get("cmd").and_then(Value::as_str) == Some("direct 10.201.0.2:16001")
                && value.get("ok").and_then(Value::as_bool) == Some(true)
        })
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
