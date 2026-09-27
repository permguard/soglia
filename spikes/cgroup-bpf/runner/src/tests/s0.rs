// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

const WAIT_READY: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSnapshot {
    programs: Value,
    links: Value,
    maps: Value,
    target_direct: Value,
    target_effective: Value,
    ancestor_direct: Value,
    owned_pins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AncestorObservation {
    mode: String,
    foreign_before: Value,
    child_exit_code: Option<i32>,
    child_signal: Option<i32>,
    child_stderr: String,
    during: KernelSnapshot,
    foreign_after: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S0Observation {
    unit: String,
    unit_properties: String,
    delegation_helper_pid: u64,
    delegated_root: String,
    delegated_root_inode: u64,
    delegated_root_uid: u32,
    delegated_root_gid: u32,
    delegated_root_mode: u32,
    delegated_controllers: String,
    delegated_subtree_control: String,
    delegated_root_processes: String,
    runtime_processes: String,
    executions_inode: u64,
    executions_uid: u32,
    executions_gid: u32,
    executions_mode: u32,
    target_inode: u64,
    target_uid: u32,
    target_gid: u32,
    target_mode: u32,
    target_processes: String,
    baseline: KernelSnapshot,
    six_hook_attached: KernelSnapshot,
    after_six_hook_detach: KernelSnapshot,
    exclusive_ancestor: AncestorObservation,
    multi_ancestor: AncestorObservation,
    final_snapshot: KernelSnapshot,
}

pub struct S0 {
    unit: String,
    runtime_root: PathBuf,
    delegation_ready: PathBuf,
    delegated_root: Option<PathBuf>,
    executions: Option<PathBuf>,
    target: Option<PathBuf>,
    pin_root: PathBuf,
    loader: Option<RunningCommand>,
    foreign_attached: Option<(PathBuf, bool)>,
}

impl S0 {
    pub fn new(context: &TestContext) -> Self {
        let short = context
            .run_id
            .chars()
            .rev()
            .take(12)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        Self {
            unit: format!("soglia-spike-{short}.service"),
            runtime_root: Path::new("/run/soglia-spike-runner")
                .join(&context.run_id)
                .join("s0"),
            delegation_ready: PathBuf::new(),
            delegated_root: None,
            executions: None,
            target: None,
            pin_root: Path::new("/sys/fs/bpf/soglia-spike-runner")
                .join(&context.run_id)
                .join("s0"),
            loader: None,
            foreign_attached: None,
        }
    }

    fn commands<'a>(&self, context: &'a TestContext) -> CommandExecutor {
        context.test_commands("s0")
    }

    fn target(&self) -> Result<&Path, TestError> {
        self.target
            .as_deref()
            .ok_or_else(|| TestError::infra("S0 target cgroup was not established"))
    }

    fn executions(&self) -> Result<&Path, TestError> {
        self.executions
            .as_deref()
            .ok_or_else(|| TestError::infra("S0 executions cgroup was not established"))
    }

    fn snapshot(&self, context: &TestContext) -> Result<KernelSnapshot, TestError> {
        let commands = self.commands(context);
        let target = self.target()?;
        let ancestor = self.executions()?;
        Ok(KernelSnapshot {
            programs: json_command(&commands, ["-j", "prog", "show"])?,
            links: json_command(&commands, ["-j", "link", "show"])?,
            maps: json_command(&commands, ["-j", "map", "show"])?,
            target_direct: json_cgroup(&commands, target, false)?,
            target_effective: json_cgroup(&commands, target, true)?,
            ancestor_direct: json_cgroup(&commands, ancestor, false)?,
            owned_pins: list_files(&self.pin_root).map_err(TestError::infra)?,
        })
    }

    fn start_loader(
        &mut self,
        context: &mut TestContext,
        label: &str,
        connect4_only: bool,
    ) -> Result<(), TestError> {
        let base = self.pin_root.join(label);
        let map_pins = base.join("maps");
        let link_pins = base.join("links");
        let ready = self.runtime_root.join(format!("{label}.ready"));
        let stop = self.runtime_root.join(format!("{label}.stop"));
        let mut arguments = vec![
            OsString::from("_s0-loader"),
            OsString::from("--object"),
            context.artifact("bpf/soglia.o").into_os_string(),
            OsString::from("--cgroup"),
            self.target()?.as_os_str().to_owned(),
            OsString::from("--map-pins"),
            map_pins.as_os_str().to_owned(),
            OsString::from("--link-pins"),
            link_pins.as_os_str().to_owned(),
            OsString::from("--ready"),
            ready.as_os_str().to_owned(),
            OsString::from("--stop"),
            stop.as_os_str().to_owned(),
        ];
        if connect4_only {
            arguments.push(OsString::from("--connect4-only"));
        }
        let running = self
            .commands(context)
            .spawn(
                &CommandSpec::new(&context.executable)
                    .args(arguments)
                    .timeout(Duration::from_secs(300)),
            )
            .map_err(TestError::infra)?;
        context.resources.register(
            "s0",
            format!("{label} loader child"),
            Resource::Process { pid: running.id() },
        );
        self.loader = Some(running);
        wait_for_path(&ready, WAIT_READY).map_err(TestError::infra)?;
        for path in list_files(&base).map_err(TestError::infra)? {
            context.resources.register(
                "s0",
                format!("{label} loader pin"),
                Resource::BpfPin {
                    path: PathBuf::from(path),
                },
            );
        }
        Ok(())
    }

    fn stop_loader(&mut self, label: &str) -> Result<CommandOutput, TestError> {
        fs::write(self.runtime_root.join(format!("{label}.stop")), b"stop\n")
            .map_err(|error| TestError::infra(format!("stop {label} loader: {error}")))?;
        let running = self
            .loader
            .take()
            .ok_or_else(|| TestError::infra("loader process missing"))?;
        running
            .wait(Duration::from_secs(30))
            .map_err(TestError::infra)
    }

    fn load_foreign(
        &mut self,
        context: &mut TestContext,
        mode: &str,
        multi: bool,
    ) -> Result<PathBuf, TestError> {
        let root = self.pin_root.join(format!("foreign-{mode}"));
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
        loaded
            .require_success("load foreign object")
            .map_err(TestError::infra)?;
        let allow = root.join("foreign_allow");
        let mut arguments = vec![
            OsString::from("cgroup"),
            OsString::from("attach"),
            self.executions()?.as_os_str().to_owned(),
            OsString::from("cgroup_inet4_connect"),
            OsString::from("pinned"),
            allow.as_os_str().to_owned(),
        ];
        if multi {
            arguments.push(OsString::from("multi"));
        }
        let attached = commands
            .run(&CommandSpec::new("bpftool").args(arguments))
            .map_err(TestError::infra)?;
        attached
            .require_success("attach foreign ancestor")
            .map_err(TestError::infra)?;
        self.foreign_attached = Some((root.clone(), multi));
        for name in ["foreign_allow", "foreign_rewrite"] {
            context.resources.register(
                "s0",
                format!("foreign {mode} program pin"),
                Resource::BpfPin {
                    path: root.join(name),
                },
            );
        }
        Ok(root)
    }

    fn detach_foreign(&mut self, context: &TestContext) -> Result<(), TestError> {
        let Some((root, _multi)) = self.foreign_attached.take() else {
            return Ok(());
        };
        let allow = root.join("foreign_allow");
        let output = self
            .commands(context)
            .run(&CommandSpec::new("bpftool").args([
                OsString::from("cgroup"),
                OsString::from("detach"),
                self.executions()?.as_os_str().to_owned(),
                OsString::from("cgroup_inet4_connect"),
                OsString::from("pinned"),
                allow.as_os_str().to_owned(),
            ]))
            .map_err(TestError::infra)?;
        output
            .require_success("detach foreign ancestor")
            .map_err(TestError::infra)?;
        remove_exact(&root.join("foreign_allow")).map_err(TestError::infra)?;
        remove_exact(&root.join("foreign_rewrite")).map_err(TestError::infra)?;
        remove_empty(&root).map_err(TestError::infra)
    }

    fn ancestor_case(
        &mut self,
        context: &mut TestContext,
        mode: &str,
        multi: bool,
    ) -> Result<AncestorObservation, TestError> {
        let foreign_root = self.load_foreign(context, mode, multi)?;
        let foreign_before =
            json_pinned_program(&self.commands(context), &foreign_root.join("foreign_allow"))?;
        let base = self.pin_root.join(format!("child-{mode}"));
        let ready = self.runtime_root.join(format!("child-{mode}.ready"));
        let stop = self.runtime_root.join(format!("child-{mode}.stop"));
        let arguments = [
            OsString::from("_s0-loader"),
            OsString::from("--object"),
            context.artifact("bpf/soglia.o").into_os_string(),
            OsString::from("--cgroup"),
            self.target()?.as_os_str().to_owned(),
            OsString::from("--map-pins"),
            base.join("maps").into_os_string(),
            OsString::from("--link-pins"),
            base.join("links").into_os_string(),
            OsString::from("--ready"),
            ready.as_os_str().to_owned(),
            OsString::from("--stop"),
            stop.as_os_str().to_owned(),
            OsString::from("--connect4-only"),
        ];
        let child = self
            .commands(context)
            .spawn(
                &CommandSpec::new(&context.executable)
                    .args(arguments)
                    .timeout(Duration::from_secs(60)),
            )
            .map_err(TestError::infra)?;
        context.resources.register(
            "s0",
            format!("ancestor {mode} child loader"),
            Resource::Process { pid: child.id() },
        );
        let output = if multi {
            wait_for_path(&ready, WAIT_READY).map_err(TestError::infra)?;
            let during = self.snapshot(context)?;
            fs::write(&stop, b"stop\n").map_err(|error| TestError::infra(error.to_string()))?;
            let output = child
                .wait(Duration::from_secs(30))
                .map_err(TestError::infra)?;
            let foreign_after =
                json_pinned_program(&self.commands(context), &foreign_root.join("foreign_allow"))?;
            self.detach_foreign(context)?;
            return Ok(AncestorObservation {
                mode: mode.to_owned(),
                foreign_before,
                child_exit_code: output.record.exit_code,
                child_signal: output.record.signal,
                child_stderr: output.stderr_text(),
                during,
                foreign_after,
            });
        } else {
            child
                .wait(Duration::from_secs(20))
                .map_err(TestError::infra)?
        };
        let during = self.snapshot(context)?;
        let foreign_after =
            json_pinned_program(&self.commands(context), &foreign_root.join("foreign_allow"))?;
        self.detach_foreign(context)?;
        Ok(AncestorObservation {
            mode: mode.to_owned(),
            foreign_before,
            child_exit_code: output.record.exit_code,
            child_signal: output.record.signal,
            child_stderr: output.stderr_text(),
            during,
            foreign_after,
        })
    }
}

impl SpikeTest for S0 {
    type Observation = S0Observation;

    fn id(&self) -> TestId {
        TestId::S0
    }

    fn invariant(&self) -> &'static str {
        "required cgroup/BPF environment, six link attaches, ancestor composition and zero owned residue"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if self.runtime_root.exists() || self.pin_root.exists() {
            return Err(TestError::new(
                Verdict::Unproven,
                "run-owned S0 path existed before preparation",
            ));
        }
        fs::create_dir_all(&self.runtime_root)
            .map_err(|error| TestError::infra(format!("create S0 runtime: {error}")))?;
        fs::set_permissions(&self.runtime_root, fs::Permissions::from_mode(0o700))
            .map_err(|error| TestError::infra(format!("protect S0 runtime: {error}")))?;
        self.delegation_ready = self.runtime_root.join("delegation-ready.json");
        context.resources.register(
            "s0",
            "S0 private runtime",
            Resource::Directory {
                path: self.runtime_root.clone(),
            },
        );
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
        output
            .require_success("start delegated systemd unit")
            .map_err(TestError::infra)?;
        context.resources.register(
            "s0",
            "systemd-run Delegate=yes",
            Resource::SystemdUnit {
                name: self.unit.clone(),
            },
        );
        wait_for_path(&self.delegation_ready, WAIT_READY).map_err(TestError::infra)?;
        let record: Value = serde_json::from_slice(
            &fs::read(&self.delegation_ready)
                .map_err(|error| TestError::infra(error.to_string()))?,
        )
        .map_err(|error| TestError::infra(format!("parse delegation record: {error}")))?;
        let root = record
            .get("cgroup_root")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| TestError::infra("delegation record has no cgroup_root"))?;
        let helper_pid = record
            .get("pid")
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("delegation record has no helper pid"))?;
        let executions = root.join("executions");
        let target = executions.join("s0-probe");
        fs::create_dir(&executions)
            .map_err(|error| TestError::infra(format!("create executions cgroup: {error}")))?;
        fs::write(
            executions.join("cgroup.subtree_control"),
            b"+memory +pids\n",
        )
        .map_err(|error| TestError::infra(format!("enable execution controllers: {error}")))?;
        fs::create_dir(&target)
            .map_err(|error| TestError::infra(format!("create S0 target: {error}")))?;
        let root_inode = inode(&root).map_err(TestError::infra)?;
        let executions_inode = inode(&executions).map_err(TestError::infra)?;
        let target_inode = inode(&target).map_err(TestError::infra)?;
        context.resources.register(
            "s0",
            "delegation helper",
            Resource::Cgroup {
                path: root.clone(),
                inode: root_inode,
            },
        );
        context.resources.register(
            "s0",
            "S0 executions parent",
            Resource::Cgroup {
                path: executions.clone(),
                inode: executions_inode,
            },
        );
        context.resources.register(
            "s0",
            "S0 attach target",
            Resource::Cgroup {
                path: target.clone(),
                inode: target_inode,
            },
        );
        self.delegated_root = Some(root);
        self.executions = Some(executions);
        self.target = Some(target);
        context
            .evidence
            .write_json(
                "s0/delegation.json",
                &serde_json::json!({
                    "helper": record,
                    "helper_pid": helper_pid,
                    "root_metadata": metadata_record(self.delegated_root.as_deref().unwrap())
                        .map_err(TestError::infra)?,
                    "executions_metadata": metadata_record(self.executions.as_deref().unwrap())
                        .map_err(TestError::infra)?,
                    "target_metadata": metadata_record(self.target.as_deref().unwrap())
                        .map_err(TestError::infra)?,
                }),
            )
            .map_err(|error| TestError::infra(format!("write S0 delegation evidence: {error}")))?;
        Ok(())
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let commands = self.commands(context);
        let unit_output = commands
            .run(&CommandSpec::new("systemctl").args([
                "show",
                self.unit.as_str(),
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "Delegate",
                "-p",
                "DelegateControllers",
                "-p",
                "ControlGroup",
                "-p",
                "MainPID",
            ]))
            .map_err(TestError::infra)?;
        unit_output
            .require_success("inspect delegated unit")
            .map_err(TestError::infra)?;
        let delegated_root = self
            .delegated_root
            .as_ref()
            .ok_or_else(|| TestError::infra("delegated root missing"))?
            .clone();
        let runtime = delegated_root.join("runtime");
        let delegation_record: Value = serde_json::from_slice(
            &fs::read(&self.delegation_ready)
                .map_err(|error| TestError::infra(error.to_string()))?,
        )
        .map_err(|error| TestError::infra(format!("parse delegation record: {error}")))?;
        let delegation_helper_pid = delegation_record
            .get("pid")
            .and_then(Value::as_u64)
            .ok_or_else(|| TestError::infra("delegation record has no helper pid"))?;
        let root_metadata = fs::metadata(&delegated_root)
            .map_err(|error| TestError::infra(format!("stat delegated root: {error}")))?;
        let executions_metadata = fs::metadata(self.executions()?)
            .map_err(|error| TestError::infra(format!("stat executions cgroup: {error}")))?;
        let target_metadata = fs::metadata(self.target()?)
            .map_err(|error| TestError::infra(format!("stat target cgroup: {error}")))?;
        let baseline = self.snapshot(context)?;
        self.start_loader(context, "six-hooks", false)?;
        let six_hook_attached = self.snapshot(context)?;
        let stopped = self.stop_loader("six-hooks")?;
        stopped
            .require_success("stop six-hook loader")
            .map_err(TestError::infra)?;
        let after_six_hook_detach = self.snapshot(context)?;
        let exclusive_ancestor = self.ancestor_case(context, "exclusive", false)?;
        let multi_ancestor = self.ancestor_case(context, "multi", true)?;
        let final_snapshot = self.snapshot(context)?;
        Ok(S0Observation {
            unit: self.unit.clone(),
            unit_properties: unit_output.stdout_text(),
            delegation_helper_pid,
            delegated_root: delegated_root.to_string_lossy().into_owned(),
            delegated_root_inode: inode(&delegated_root).map_err(TestError::infra)?,
            delegated_root_uid: root_metadata.uid(),
            delegated_root_gid: root_metadata.gid(),
            delegated_root_mode: root_metadata.mode() & 0o7777,
            delegated_controllers: read_trimmed(&delegated_root.join("cgroup.controllers"))
                .map_err(TestError::infra)?,
            delegated_subtree_control: read_trimmed(&delegated_root.join("cgroup.subtree_control"))
                .map_err(TestError::infra)?,
            delegated_root_processes: read_trimmed(&delegated_root.join("cgroup.procs"))
                .map_err(TestError::infra)?,
            runtime_processes: read_trimmed(&runtime.join("cgroup.procs"))
                .map_err(TestError::infra)?,
            executions_inode: inode(self.executions()?).map_err(TestError::infra)?,
            executions_uid: executions_metadata.uid(),
            executions_gid: executions_metadata.gid(),
            executions_mode: executions_metadata.mode() & 0o7777,
            target_inode: inode(self.target()?).map_err(TestError::infra)?,
            target_uid: target_metadata.uid(),
            target_gid: target_metadata.gid(),
            target_mode: target_metadata.mode() & 0o7777,
            target_processes: read_trimmed(&self.target()?.join("cgroup.procs"))
                .map_err(TestError::infra)?,
            baseline,
            six_hook_attached,
            after_six_hook_detach,
            exclusive_ancestor,
            multi_ancestor,
            final_snapshot,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if !observation.unit_properties.contains("ActiveState=active")
            || !observation.unit_properties.contains("Delegate=yes")
            || !observation
                .unit_properties
                .contains(&format!("MainPID={}", observation.delegation_helper_pid))
        {
            return Err(TestError::new(
                Verdict::Unsupported,
                "systemd delegation was not active with Delegate=yes",
            ));
        }
        if !observation.delegated_root_processes.is_empty()
            || observation.runtime_processes != observation.delegation_helper_pid.to_string()
            || !observation.target_processes.is_empty()
            || !observation.delegated_controllers.contains("memory")
            || !observation.delegated_controllers.contains("pids")
            || !observation.delegated_subtree_control.contains("memory")
            || !observation.delegated_subtree_control.contains("pids")
        {
            return Err(TestError::new(
                Verdict::Unsupported,
                "delegated cgroup topology did not satisfy the required controller and leaf contract",
            ));
        }
        for (label, uid, gid, mode) in [
            (
                "delegated root",
                observation.delegated_root_uid,
                observation.delegated_root_gid,
                observation.delegated_root_mode,
            ),
            (
                "executions cgroup",
                observation.executions_uid,
                observation.executions_gid,
                observation.executions_mode,
            ),
            (
                "target cgroup",
                observation.target_uid,
                observation.target_gid,
                observation.target_mode,
            ),
        ] {
            if uid != 0 || gid != 0 || mode & 0o022 != 0 {
                return Err(TestError::new(
                    Verdict::Unsupported,
                    format!(
                        "{label} ownership/mode is not trusted: uid={uid} gid={gid} mode={mode:o}"
                    ),
                ));
            }
        }
        require_array_len(
            &observation.baseline.target_direct,
            0,
            "baseline target direct",
        )?;
        require_array_len(
            &observation.baseline.target_effective,
            0,
            "baseline target effective",
        )?;
        require_array_len(
            &observation.six_hook_attached.target_direct,
            6,
            "six direct hook attachments",
        )?;
        require_array_len(
            &observation.six_hook_attached.target_effective,
            6,
            "six effective hook attachments",
        )?;
        let cgroup_links = array(&observation.six_hook_attached.links)?
            .iter()
            .filter(|link| link.get("type").and_then(Value::as_str) == Some("cgroup"))
            .filter(|link| {
                link.get("cgroup_id").and_then(Value::as_u64) == Some(observation.target_inode)
            })
            .count();
        if cgroup_links != 6 {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("expected six target bpf_links, observed {cgroup_links}"),
            ));
        }
        if observation.six_hook_attached.owned_pins.len() != 14 {
            return Err(TestError::new(
                Verdict::Unproven,
                format!(
                    "expected 14 map/link pins, observed {}",
                    observation.six_hook_attached.owned_pins.len()
                ),
            ));
        }
        require_array_len(
            &observation.after_six_hook_detach.target_direct,
            0,
            "post-detach target direct",
        )?;
        require_kernel_baseline(
            &observation.baseline,
            &observation.after_six_hook_detach,
            "post-six-hook detach",
        )?;
        if observation.exclusive_ancestor.child_exit_code == Some(0)
            || !observation
                .exclusive_ancestor
                .child_stderr
                .contains("code: 1")
            || !observation
                .exclusive_ancestor
                .child_stderr
                .contains("Operation not permitted")
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "legacy exclusive ancestor did not produce the established EPERM child attach result",
            ));
        }
        require_array_len(
            &observation.exclusive_ancestor.during.target_direct,
            0,
            "exclusive child direct",
        )?;
        require_array_len(
            &observation.exclusive_ancestor.during.target_effective,
            1,
            "exclusive child effective",
        )?;
        if observation.multi_ancestor.child_exit_code != Some(0) {
            return Err(TestError::new(
                Verdict::Unsupported,
                "child link attach did not coexist with legacy multi ancestor",
            ));
        }
        require_array_len(
            &observation.multi_ancestor.during.target_direct,
            1,
            "multi child direct",
        )?;
        require_array_len(
            &observation.multi_ancestor.during.target_effective,
            2,
            "multi child effective",
        )?;
        if observation.exclusive_ancestor.foreign_before
            != observation.exclusive_ancestor.foreign_after
            || observation.multi_ancestor.foreign_before != observation.multi_ancestor.foreign_after
        {
            return Err(TestError::new(
                Verdict::Fail,
                "foreign program identity changed during child attach attempt",
            ));
        }
        require_array_len(
            &observation.final_snapshot.target_direct,
            0,
            "final target direct",
        )?;
        require_array_len(
            &observation.final_snapshot.target_effective,
            0,
            "final target effective",
        )?;
        if !observation.final_snapshot.owned_pins.is_empty() {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S0 pin residue remained before final cleanup",
            ));
        }
        require_kernel_baseline(&observation.baseline, &observation.final_snapshot, "final")?;
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if self.loader.is_some() {
            for label in ["six-hooks", "exclusive", "multi"] {
                let _ = fs::write(self.runtime_root.join(format!("{label}.stop")), b"stop\n");
            }
            if let Some(mut loader) = self.loader.take() {
                let _ = loader.terminate();
                let _ = loader.wait(Duration::from_secs(10));
            }
        }
        if self.foreign_attached.is_some() {
            self.detach_foreign(context)?;
        }
        remove_known_pin_tree(&self.pin_root).map_err(TestError::infra)?;
        if let Some(run_root) = self.pin_root.parent() {
            let _ = fs::remove_dir(run_root);
            if let Some(suite_root) = run_root.parent() {
                let _ = fs::remove_dir(suite_root);
            }
        }
        if let Some(target) = &self.target {
            remove_empty(target).map_err(TestError::infra)?;
        }
        if let Some(executions) = &self.executions {
            remove_empty(executions).map_err(TestError::infra)?;
        }
        let stopped = self
            .commands(context)
            .run(
                &CommandSpec::new("systemctl")
                    .args(["stop", self.unit.as_str()])
                    .timeout(Duration::from_secs(20)),
            )
            .map_err(TestError::infra)?;
        if !stopped.success() && !stopped.stderr_text().contains("not loaded") {
            return Err(TestError::infra(format!(
                "stop delegation unit: {}",
                stopped.stderr_text()
            )));
        }
        remove_file_if_present(&self.delegation_ready).map_err(TestError::infra)?;
        remove_empty(&self.runtime_root).map_err(TestError::infra)?;
        if let Some(parent) = self.runtime_root.parent() {
            let _ = fs::remove_dir(parent);
        }
        Ok(())
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        let unit = self
            .commands(context)
            .run(
                &CommandSpec::new("systemctl")
                    .args([
                        "show",
                        self.unit.as_str(),
                        "-p",
                        "LoadState",
                        "-p",
                        "ActiveState",
                    ])
                    .timeout(Duration::from_secs(10)),
            )
            .map_err(TestError::infra)?;
        let unit_state = unit.stdout_text();
        let root_absent = self
            .delegated_root
            .as_ref()
            .is_none_or(|path| !path.exists());
        let clean = !self.pin_root.exists()
            && !self.runtime_root.exists()
            && self.target.as_ref().is_none_or(|path| !path.exists())
            && self.executions.as_ref().is_none_or(|path| !path.exists())
            && root_absent
            && (unit_state.contains("ActiveState=inactive")
                || unit_state.contains("LoadState=not-found"));
        let observation = serde_json::json!({
            "pin_root_absent": !self.pin_root.exists(),
            "runtime_root_absent": !self.runtime_root.exists(),
            "target_absent": self.target.as_ref().is_none_or(|path| !path.exists()),
            "executions_absent": self.executions.as_ref().is_none_or(|path| !path.exists()),
            "delegated_root_absent": root_absent,
            "unit_state": unit_state,
            "clean": clean,
        });
        context
            .evidence
            .write_json("s0/cleanup.json", &observation)
            .map_err(|error| TestError::infra(format!("write S0 cleanup evidence: {error}")))?;
        if !clean {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S0 owned residue remained after cleanup",
            ));
        }
        context.resources.mark_owner_cleaned("s0");
        Ok(())
    }
}

fn json_command<const N: usize>(
    commands: &CommandExecutor,
    arguments: [&str; N],
) -> Result<Value, TestError> {
    let output = commands
        .run(
            &CommandSpec::new("bpftool")
                .args(arguments)
                .timeout(Duration::from_secs(15)),
        )
        .map_err(TestError::infra)?;
    output
        .require_success("bpftool JSON query")
        .map_err(TestError::infra)?;
    parse_json_or_empty(&output.stdout).map_err(TestError::infra)
}

fn json_cgroup(
    commands: &CommandExecutor,
    path: &Path,
    effective: bool,
) -> Result<Value, TestError> {
    let mut arguments = vec![
        OsString::from("-j"),
        OsString::from("cgroup"),
        OsString::from("show"),
        path.as_os_str().to_owned(),
    ];
    if effective {
        arguments.push(OsString::from("effective"));
    }
    let output = commands
        .run(
            &CommandSpec::new("bpftool")
                .args(arguments)
                .timeout(Duration::from_secs(15)),
        )
        .map_err(TestError::infra)?;
    output
        .require_success("bpftool cgroup query")
        .map_err(TestError::infra)?;
    parse_json_or_empty(&output.stdout).map_err(TestError::infra)
}

fn json_pinned_program(commands: &CommandExecutor, path: &Path) -> Result<Value, TestError> {
    let output = commands
        .run(&CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("prog"),
            OsString::from("show"),
            OsString::from("pinned"),
            path.as_os_str().to_owned(),
        ]))
        .map_err(TestError::infra)?;
    output
        .require_success("inspect pinned program")
        .map_err(TestError::infra)?;
    parse_json_or_empty(&output.stdout).map_err(TestError::infra)
}

fn parse_json_or_empty(bytes: &[u8]) -> Result<Value, String> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Array(Vec::new()));
    }
    serde_json::from_slice(bytes).map_err(|error| format!("parse JSON observation: {error}"))
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !path.exists() {
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn inode(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.ino())
        .map_err(|error| format!("stat {}: {error}", path.display()))
}

fn metadata_record(path: &Path) -> Result<Value, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    Ok(serde_json::json!({
        "path": path,
        "inode": metadata.ino(),
        "uid": metadata.uid(),
        "gid": metadata.gid(),
        "mode": metadata.mode() & 0o7777,
    }))
}

fn read_trimmed(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("read {}: {error}", path.display()))
}

fn list_files(root: &Path) -> Result<Vec<String>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            let file_type = entry.file_type().map_err(|error| error.to_string())?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else {
                files.push(entry.path().to_string_lossy().into_owned());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn array(value: &Value) -> Result<&Vec<Value>, TestError> {
    value
        .as_array()
        .ok_or_else(|| TestError::new(Verdict::Unproven, "expected JSON array observation"))
}

fn require_array_len(value: &Value, expected: usize, label: &str) -> Result<(), TestError> {
    let observed = array(value)?.len();
    if observed == expected {
        Ok(())
    } else {
        Err(TestError::new(
            Verdict::Unproven,
            format!("{label}: expected {expected}, observed {observed}"),
        ))
    }
}

fn require_kernel_baseline(
    baseline: &KernelSnapshot,
    observed: &KernelSnapshot,
    label: &str,
) -> Result<(), TestError> {
    let comparisons = [
        (
            "program inventory",
            stable_bpf_inventory(&baseline.programs) == stable_bpf_inventory(&observed.programs),
        ),
        (
            "link inventory",
            stable_bpf_inventory(&baseline.links) == stable_bpf_inventory(&observed.links),
        ),
        (
            "map inventory",
            stable_bpf_inventory(&baseline.maps) == stable_bpf_inventory(&observed.maps),
        ),
        (
            "target direct attachments",
            baseline.target_direct == observed.target_direct,
        ),
        (
            "target effective attachments",
            baseline.target_effective == observed.target_effective,
        ),
        (
            "ancestor direct attachments",
            baseline.ancestor_direct == observed.ancestor_direct,
        ),
        ("owned pins", baseline.owned_pins == observed.owned_pins),
    ];
    let differences = comparisons
        .into_iter()
        .filter_map(|(name, matches)| (!matches).then_some(name))
        .collect::<Vec<_>>();
    if differences.is_empty() {
        Ok(())
    } else {
        Err(TestError::new(
            Verdict::CleanupFail,
            format!(
                "{label} kernel state did not return to the fresh S0 baseline: {}",
                differences.join(", ")
            ),
        ))
    }
}

fn stable_bpf_inventory(value: &Value) -> Value {
    let mut stable = value.clone();
    remove_volatile_bpf_fields(&mut stable);
    stable
}

fn remove_volatile_bpf_fields(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                remove_volatile_bpf_fields(value);
            }
        }
        Value::Object(object) => {
            // bpftool derives loaded_at while rendering and its value can vary
            // across consecutive reads for pre-existing programs. Runtime BPF
            // statistics are also observation counters, not object identity.
            for key in ["loaded_at", "run_time_ns", "run_cnt", "recursion_misses"] {
                object.remove(key);
            }
            for value in object.values_mut() {
                remove_volatile_bpf_fields(value);
            }
        }
        _ => {}
    }
}

fn remove_exact(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn remove_file_if_present(path: &Path) -> Result<(), String> {
    remove_exact(path)
}

fn remove_empty(path: &Path) -> Result<(), String> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "remove empty directory {}: {error}",
            path.display()
        )),
    }
}

fn remove_known_pin_tree(root: &Path) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    let known_files = [
        "six-hooks/maps/soglia_policy",
        "six-hooks/maps/soglia_tuples",
        "six-hooks/maps/soglia_cookie_a",
        "six-hooks/maps/soglia_sk_b",
        "six-hooks/maps/soglia_events",
        "six-hooks/maps/soglia_counters",
        "six-hooks/maps/soglia_denies",
        "six-hooks/maps/soglia_meta",
        "six-hooks/links/sock_create",
        "six-hooks/links/connect4",
        "six-hooks/links/connect6",
        "six-hooks/links/sendmsg4",
        "six-hooks/links/sendmsg6",
        "six-hooks/links/sock_ops",
        "foreign-exclusive/foreign_allow",
        "foreign-exclusive/foreign_rewrite",
        "foreign-multi/foreign_allow",
        "foreign-multi/foreign_rewrite",
    ];
    for relative in known_files {
        remove_exact(&root.join(relative))?;
    }
    let mut directories = Vec::new();
    collect_directories(root, &mut directories)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        remove_empty(&directory)?;
    }
    remove_empty(root)
}

fn collect_directories(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).map_err(|error| format!("read {}: {error}", root.display()))? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            collect_directories(&entry.path(), output)?;
            output.push(entry.path());
        }
    }
    Ok(())
}
