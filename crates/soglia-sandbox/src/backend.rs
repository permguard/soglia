// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `SandboxBackend` contract and its Phase-0 implementation on runc.
//!
//! A sandbox backend owns the isolation boundary of each Execution: its processes, its cgroup, its
//! filesystem view and its OCI runtime state, and the verified destruction of all of them. Network
//! confinement is the enforcement backend's; the sandbox only joins the network namespace the
//! enforcer created, and proves it did.
//!
//! The container is created, verified and only then started: `runc create` builds it with its init
//! process waiting, the helper proves that process sits in the Soglia network namespace, and `runc
//! start` lets the agent run. The container and its cgroup then persist until the helper deletes
//! them, so the cgroup's counters — an OOM kill, a refused fork — are still there to read when the
//! Execution is torn down.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{WaitOptions, getpid, set_child_subreaper, wait};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soglia_core::config::{AgentConfig, Config};
use soglia_core::helper::{ExitOutcome, RefusalClass};
use soglia_core::id::{ExecutionId, NAME_PREFIX, ResourceTag};
use soglia_core::records;

use crate::bundle::{self, BundleInputs};
use crate::cgroup::{self, Delegation};

/// Where `ip netns` keeps network namespaces; the enforcer creates the Execution's there.
const NETNS_DIR: &str = "/run/netns";
/// How long the OCI runtime may take to report the container created.
const CREATE_DEADLINE: Duration = Duration::from_secs(10);
/// The most agent output relayed to the log.
const MAX_LOGGED_BYTES: usize = 64 * 1024;

/// Why a sandbox operation failed.
#[derive(Debug)]
pub enum SandboxError {
    /// The request contradicts the configuration or the backend's state.
    Refused(String),
    /// A verified uninstall refused with a stable startup-compatible class.
    UninstallRefused {
        /// Stable refusal class.
        class: RefusalClass,
        /// Trusted diagnostic detail.
        reason: String,
    },
    /// A host operation failed.
    Failed(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(reason) => write!(formatter, "refused: {reason}"),
            Self::UninstallRefused { reason, .. } => write!(formatter, "refused: {reason}"),
            Self::Failed(reason) => write!(formatter, "failed: {reason}"),
        }
    }
}

impl std::error::Error for SandboxError {}

impl From<io::Error> for SandboxError {
    fn from(error: io::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

/// The isolation contract of an Execution.
pub trait SandboxBackend {
    /// The backend's name, for logs.
    fn name(&self) -> &'static str;

    /// Checks that the host offers everything the backend's guarantees depend on.
    fn probe_capabilities(&self) -> Result<(), SandboxError>;

    /// Sweeps what a previous run left behind and prepares the delegated cgroup. Runs once, before
    /// any Execution exists. Returns what the sweep removed.
    fn initialize(&mut self) -> Result<Vec<String>, SandboxError>;

    /// Durably reserves an empty cgroup and applies the configured resource limits.
    fn reserve_execution(&mut self, id: ExecutionId, agent: &str) -> Result<u64, SandboxError>;

    /// Creates the container and returns its trusted host PID while the init remains paused.
    fn create_paused(&mut self, id: ExecutionId) -> Result<(i32, u64), SandboxError>;

    /// Releases the already verified paused init process.
    fn start_execution(&mut self, id: ExecutionId) -> Result<(), SandboxError>;

    /// Freezes and kills every process of the Execution, waits until none is left, and says how
    /// the agent ended.
    fn kill_execution(&mut self, tag: &ResourceTag) -> Result<ExitOutcome, SandboxError>;

    /// Removes the Execution's runtime state, bundle and cgroup and verifies that they are gone.
    fn destroy_execution(&mut self, tag: &ResourceTag) -> Result<(), SandboxError>;
}

/// What the sandbox helper records about one Execution before creating any of its resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRecord {
    /// The Execution.
    pub id: ExecutionId,
    /// Its resource tag.
    pub tag: ResourceTag,
    /// The agent it runs.
    pub agent: String,
    /// Last durably completed lifecycle stage.
    pub stage: SandboxStage,
}

/// Durable stages before an agent is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SandboxStage {
    /// The exact empty cgroup and its limits exist.
    CgroupReserved,
    /// `runc create` completed and the init is still paused.
    ContainerCreatedPaused,
    /// `runc start` released the init.
    Started,
}

/// The facts of the configuration the sandbox backend needs.
#[derive(Debug, Clone)]
pub struct SandboxSettings {
    /// The OCI runtime.
    pub runc: PathBuf,
    /// Soglia's own runc state root, so `runc list` shows only Soglia's containers.
    pub runc_root: PathBuf,
    /// Where the sandbox helper's ownership records live.
    pub records: PathBuf,
    /// Where Execution bundles are written.
    pub bundles: PathBuf,
    /// The delegated cgroup subtree.
    pub delegation: Delegation,
    /// The configured agents.
    pub agents: BTreeMap<String, AgentConfig>,
    /// Environment variables Soglia sets in every Execution.
    pub soglia_env: Vec<(String, String)>,
    /// How long a teardown step may wait.
    pub teardown_deadline: Duration,
}

impl SandboxSettings {
    /// The settings a validated configuration implies.
    pub fn from_config(config: &Config) -> Result<Self, SandboxError> {
        let delegation = Delegation::discover(config.cgroup.root.as_deref())?;
        let proxy = format!(
            "http://{}:{}",
            config.network.proxy_address, config.network.proxy_port
        );
        let mut soglia_env: Vec<(String, String)> =
            ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
                .into_iter()
                .map(|key| (key.to_owned(), proxy.clone()))
                .collect();
        for key in ["NO_PROXY", "no_proxy"] {
            soglia_env.push((key.to_owned(), "localhost,127.0.0.1".to_owned()));
        }
        let state = &config.runtime.state_dir;

        Ok(Self {
            runc: config.runtime.runc.clone(),
            runc_root: state.join("runc"),
            records: state.join("sandbox"),
            bundles: state.join("bundles"),
            delegation,
            agents: config.agents.clone(),
            soglia_env,
            teardown_deadline: Duration::from_millis(config.runtime.teardown_timeout_ms),
        })
    }
}

/// A started Execution: its agent's init process, and how that process ended once it has.
struct Live {
    id: ExecutionId,
    agent: String,
    stage: SandboxStage,
    init: Option<i32>,
    exit: Option<i32>,
}

/// The Phase-0 sandbox: one runc container per Execution, in its own cgroup under the delegated
/// subtree, joining the Soglia-owned network namespace.
pub struct RuncSandbox {
    settings: SandboxSettings,
    live: HashMap<ResourceTag, Live>,
}

/// Sandbox resources whose ownership and stopped state were proved before uninstall.
pub struct PreparedSandboxUninstall {
    backend: RuncSandbox,
    records: Vec<(String, SandboxRecord)>,
    fresh: bool,
}

impl PreparedSandboxUninstall {
    /// Exact operations the real uninstall will perform.
    pub fn planned_operations(&self) -> Vec<String> {
        self.records
            .iter()
            .map(|(_, record)| format!("remove sandbox of Execution {}", record.id))
            .collect()
    }

    /// Exact Execution tags proved by the sandbox ownership records.
    pub fn owned_tags(&self) -> std::collections::BTreeSet<String> {
        self.records
            .iter()
            .map(|(_, record)| record.tag.to_string())
            .collect()
    }

    /// Whether no Sandbox-owned state or cgroup directory exists at all.
    pub fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// Removes only the resources named by the records validated by `prepare_uninstall`.
    pub fn execute(self) -> Result<(), SandboxError> {
        for (name, record) in &self.records {
            self.backend.remove(&record.tag)?;
            records::remove(&self.backend.settings.records, name)?;
        }
        for directory in [
            &self.backend.settings.records,
            &self.backend.settings.bundles,
            &self.backend.settings.runc_root,
        ] {
            match fs::remove_dir(directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for cgroup in [
            self.backend.settings.delegation.executions(),
            self.backend.settings.delegation.root().join("runtime"),
        ] {
            cgroup::remove(&cgroup)?;
        }
        Ok(())
    }
}

/// Builds the complete sandbox uninstall plan without changing the host.
pub fn prepare_uninstall(config: &Config) -> Result<PreparedSandboxUninstall, SandboxError> {
    let backend = RuncSandbox::new(SandboxSettings::from_config(config)?);
    let state_root_absent = !config.runtime.state_dir.exists();
    for directory in [
        &config.runtime.state_dir,
        &backend.settings.records,
        &backend.settings.bundles,
        &backend.settings.runc_root,
    ] {
        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(SandboxError::UninstallRefused {
                class: RefusalClass::Unknown,
                reason: format!(
                    "{} is not a root-owned real mode-0700 directory",
                    directory.display()
                ),
            });
        }
    }
    let runtime = backend.settings.delegation.root().join("runtime");
    for cgroup in [backend.settings.delegation.root(), runtime.as_path()] {
        let procs = cgroup.join("cgroup.procs");
        if procs.exists() && !fs::read_to_string(&procs)?.trim().is_empty() {
            return Err(SandboxError::UninstallRefused {
                class: RefusalClass::Infrastructure,
                reason: format!("the Soglia runtime is still active in {}", cgroup.display()),
            });
        }
    }

    let names = match fs::read_dir(&backend.settings.records) {
        Ok(entries) => entries
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let mut planned = Vec::new();
    for name in names {
        if records::is_temporary(&name) || !name.ends_with(".json") {
            return Err(SandboxError::UninstallRefused {
                class: RefusalClass::Unknown,
                reason: format!("unknown entry {name} in the sandbox ownership directory"),
            });
        }
        let record: SandboxRecord = records::read(&backend.settings.records, &name)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidData {
                    SandboxError::UninstallRefused {
                        class: RefusalClass::Incompatible,
                        reason: format!("incompatible sandbox record {name}: {error}"),
                    }
                } else {
                    SandboxError::from(error)
                }
            })?
            .ok_or_else(|| SandboxError::UninstallRefused {
                class: RefusalClass::Unknown,
                reason: format!("sandbox record {name} vanished"),
            })?;
        if name != format!("{}.json", record.tag) || record.id.tag() != record.tag {
            return Err(SandboxError::UninstallRefused {
                class: RefusalClass::Unknown,
                reason: format!("sandbox record {name} has an unknown identity"),
            });
        }
        let cgroup = backend
            .settings
            .delegation
            .execution(&record.tag.to_string());
        if cgroup.join("cgroup.procs").exists()
            && !fs::read_to_string(cgroup.join("cgroup.procs"))?
                .trim()
                .is_empty()
        {
            return Err(SandboxError::UninstallRefused {
                class: RefusalClass::Infrastructure,
                reason: format!("Execution {} still has a process", record.id),
            });
        }
        if let Some(state) = backend.state(&record.tag.container_id()) {
            let status = state
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if !matches!(status, "stopped") {
                return Err(SandboxError::UninstallRefused {
                    class: RefusalClass::Infrastructure,
                    reason: format!(
                        "Execution {} has live or unverifiable runc state {status}",
                        record.id
                    ),
                });
            }
        }
        planned.push((name, record));
    }
    planned.sort_by(|left, right| left.0.cmp(&right.0));
    let expected = planned
        .iter()
        .map(|(_, record)| record.tag.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    for directory in [&backend.settings.bundles, &backend.settings.runc_root] {
        if directory.exists() {
            for entry in fs::read_dir(directory)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if !expected.contains(&name) {
                    return Err(SandboxError::UninstallRefused {
                        class: RefusalClass::Unknown,
                        reason: format!(
                            "unrecorded sandbox resource {}",
                            directory.join(name).display()
                        ),
                    });
                }
            }
        }
    }
    let executions = backend.settings.delegation.executions();
    if executions.exists() {
        for entry in fs::read_dir(&executions)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && !expected.contains(&entry.file_name().to_string_lossy().into_owned())
            {
                return Err(SandboxError::UninstallRefused {
                    class: RefusalClass::Unknown,
                    reason: format!("unrecorded Execution cgroup {}", entry.path().display()),
                });
            }
        }
    }
    if backend.settings.runc_root.exists() {
        let listed = backend.runc(&["list", "--format", "json"])?;
        let containers = serde_json::from_str::<Value>(&listed)
            .map_err(|error| SandboxError::UninstallRefused {
                class: RefusalClass::Infrastructure,
                reason: format!("decode runc container inventory: {error}"),
            })?
            .as_array()
            .cloned()
            .ok_or_else(|| SandboxError::UninstallRefused {
                class: RefusalClass::Infrastructure,
                reason: "runc container inventory is not a JSON array".to_owned(),
            })?;
        for container in containers {
            if let Some(id) = container.get("id").and_then(Value::as_str)
                && !expected.contains(id)
            {
                return Err(SandboxError::UninstallRefused {
                    class: RefusalClass::Unknown,
                    reason: format!("unrecorded runc container {id}"),
                });
            }
        }
    }
    let cgroup_state_absent = !backend.settings.delegation.executions().exists()
        && !backend.settings.delegation.root().join("runtime").exists();
    let fresh = state_root_absent && cgroup_state_absent && planned.is_empty();
    Ok(PreparedSandboxUninstall {
        backend,
        records: planned,
        fresh,
    })
}

impl RuncSandbox {
    /// A backend over `settings`.
    pub fn new(settings: SandboxSettings) -> Self {
        Self {
            settings,
            live: HashMap::new(),
        }
    }

    /// The tags of every Execution this backend started and has not destroyed.
    pub fn live_tags(&self) -> Vec<ResourceTag> {
        self.live.keys().copied().collect()
    }

    fn runc(&self, args: &[&str]) -> io::Result<String> {
        let output = Command::new(&self.settings.runc)
            .arg("--root")
            .arg(&self.settings.runc_root)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }

        Err(io::Error::other(format!(
            "runc {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    fn state(&self, container: &str) -> Option<Value> {
        let text = self.runc(&["state", container]).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn bundle_dir(&self, tag: &ResourceTag) -> PathBuf {
        self.settings.bundles.join(tag.to_string())
    }

    fn publish_live(&self, tag: &ResourceTag, live: &Live) -> Result<(), SandboxError> {
        let record = SandboxRecord {
            id: live.id,
            tag: *tag,
            agent: live.agent.clone(),
            stage: live.stage,
        };
        records::publish(&self.settings.records, &format!("{tag}.json"), &record)?;
        Ok(())
    }

    fn cgroup_inode(&self, tag: &ResourceTag) -> Result<u64, SandboxError> {
        Ok(fs::metadata(self.settings.delegation.execution(&tag.to_string()))?.ino())
    }

    fn prove_membership(&self, tag: &ResourceTag, pid: i32) -> Result<u64, SandboxError> {
        let target = self.settings.delegation.execution(&tag.to_string());
        let expected = self.settings.delegation.oci_path(&tag.to_string());
        let membership = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let exact = membership
            .lines()
            .any(|line| line.strip_prefix("0::") == Some(expected.as_str()));
        let listed = fs::read_to_string(target.join("cgroup.procs"))?
            .split_whitespace()
            .any(|entry| entry.parse::<i32>() == Ok(pid));
        if !exact || !listed {
            return Err(SandboxError::Failed(format!(
                "paused pid {pid} is not a member of the exact Execution cgroup {}",
                target.display()
            )));
        }
        self.cgroup_inode(tag)
    }

    /// Waits until the container is created, then proves its init process sits in the Execution
    /// network namespace. Returns that process's pid. The agent has not run a single instruction
    /// yet: the init process waits for `runc start`.
    fn await_created(&self, tag: &ResourceTag) -> Result<i32, SandboxError> {
        let container = tag.container_id();
        let started = Instant::now();
        let pid = loop {
            if let Some(state) = self.state(&container)
                && state["status"] == "created"
                && let Some(pid) = state["pid"]
                    .as_i64()
                    .and_then(|pid| i32::try_from(pid).ok())
            {
                break pid;
            }
            if started.elapsed() >= CREATE_DEADLINE {
                return Err(SandboxError::Failed(format!(
                    "{container} was not created within {CREATE_DEADLINE:?}"
                )));
            }
            thread::sleep(Duration::from_millis(20));
        };

        // The OCI configuration names the namespace by path; this proves the runtime honoured it.
        let agent = fs::metadata(format!("/proc/{pid}/ns/net"))?;
        let expected = fs::metadata(Path::new(NETNS_DIR).join(tag.netns_name()))?;
        if (agent.dev(), agent.ino()) != (expected.dev(), expected.ino()) {
            return Err(SandboxError::Failed(format!(
                "{container} runs in network namespace {}, not the Soglia namespace {}",
                agent.ino(),
                expected.ino()
            )));
        }

        Ok(pid)
    }

    /// Collects the exit status of every child of the helper that has ended.
    ///
    /// The helper is a child subreaper, so an agent's init process becomes its child once `runc
    /// create` exits. Statuses of tracked init processes are kept; anything else that ended below
    /// the helper is simply reaped. It runs only between the helper's own commands, when no other
    /// child is being waited for.
    fn reap(&mut self) {
        let options = WaitOptions::NOHANG;
        // `wait` is `wait4(-1)`, any child; rustix's `waitpid(None)` would be `wait4(0)`, only the
        // caller's process group, which an agent leaves by starting its own session.
        while let Ok(Some((pid, status))) = wait(options) {
            let pid = pid.as_raw_nonzero().get();
            let code = status
                .exit_status()
                .or_else(|| status.terminating_signal().map(|signal| 128 + signal));
            if let Some(live) = self.live.values_mut().find(|live| live.init == Some(pid)) {
                live.exit = code;
            }
        }
    }

    /// Removes every resource of `tag` and verifies each is gone. Idempotent.
    fn remove(&self, tag: &ResourceTag) -> Result<(), SandboxError> {
        let container = tag.container_id();
        let cgroup = self.settings.delegation.execution(&tag.to_string());
        cgroup::kill(&cgroup, self.settings.teardown_deadline)?;

        if self.state(&container).is_some() {
            self.runc(&["delete", "--force", &container])?;
        }
        if self.settings.runc_root.join(&container).exists() {
            return Err(SandboxError::Failed(format!(
                "the runc state of {container} still exists"
            )));
        }

        let bundle = self.bundle_dir(tag);
        if mounted_below(&bundle)? {
            return Err(SandboxError::Failed(format!(
                "something is still mounted below {}",
                bundle.display()
            )));
        }
        match fs::remove_dir_all(&bundle) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        if bundle.exists() {
            return Err(SandboxError::Failed(format!(
                "{} still exists",
                bundle.display()
            )));
        }

        cgroup::remove(&cgroup)?;

        Ok(())
    }

    fn sweep(&self) -> Result<Vec<String>, SandboxError> {
        let mut swept = Vec::new();
        for entry in fs::read_dir(&self.settings.records)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if records::is_temporary(&name) {
                // An unfinished publication: the resources it announced were never created.
                fs::remove_file(self.settings.records.join(&name))?;
                continue;
            }
            let record: SandboxRecord = records::read(&self.settings.records, &name)?
                .ok_or_else(|| SandboxError::Failed(format!("{name} vanished during the sweep")))?;
            if name != format!("{}.json", record.tag) {
                return Err(SandboxError::Refused(format!(
                    "the record {name} names another Execution; ownership cannot be proven"
                )));
            }
            self.remove(&record.tag)?;
            records::remove(&self.settings.records, &name)?;
            swept.push(format!("sandbox of Execution {}", record.id));
        }

        // Bundles live only in Soglia's own state directory; one without a record is the residue of
        // a start that never got as far as its container.
        for entry in fs::read_dir(&self.settings.bundles)? {
            fs::remove_dir_all(entry?.path())?;
        }

        // Containers and cgroups without a record cannot be proven Soglia's. They are reported,
        // never deleted.
        let mut unrecorded: Vec<String> = Vec::new();
        let listed = self.runc(&["list", "--format", "json"])?;
        if let Ok(Value::Array(containers)) = serde_json::from_str::<Value>(&listed) {
            for container in containers {
                if let Some(id) = container["id"].as_str() {
                    unrecorded.push(format!("container {id}"));
                }
            }
        }
        let executions = self.settings.delegation.executions();
        if executions.exists() {
            for entry in fs::read_dir(&executions)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    unrecorded.push(format!("cgroup {}", entry.path().display()));
                }
            }
        }
        if !unrecorded.is_empty() {
            return Err(SandboxError::Refused(format!(
                "resources with Soglia names but no ownership record exist: {}; remove them after inspection",
                unrecorded.join(", ")
            )));
        }

        Ok(swept)
    }

    /// How the agent of `tag` ended, from its cgroup's counters and its exit status.
    fn outcome(&self, tag: &ResourceTag, before_kill: Option<i32>) -> ExitOutcome {
        let cgroup = self.settings.delegation.execution(&tag.to_string());
        if cgroup::counter(&cgroup, "memory.events", "oom_kill") > 0 {
            return ExitOutcome::MemoryLimit;
        }
        match before_kill {
            None => ExitOutcome::Killed,
            Some(_) if cgroup::counter(&cgroup, "pids.events", "max") > 0 => ExitOutcome::PidsLimit,
            Some(code) => ExitOutcome::Status(code),
        }
    }
}

impl SandboxBackend for RuncSandbox {
    fn name(&self) -> &'static str {
        "runc"
    }

    fn probe_capabilities(&self) -> Result<(), SandboxError> {
        if !rustix::process::geteuid().is_root() {
            return Err(SandboxError::Refused(
                "the sandbox helper must run as root".to_owned(),
            ));
        }
        if !Path::new(cgroup::CGROUP_MOUNT)
            .join("cgroup.controllers")
            .exists()
        {
            return Err(SandboxError::Refused(format!(
                "{} is not a cgroup v2 hierarchy",
                cgroup::CGROUP_MOUNT
            )));
        }
        self.runc(&["--version"])?;

        Ok(())
    }

    fn initialize(&mut self) -> Result<Vec<String>, SandboxError> {
        // Agent init processes are reparented to this process when `runc create` exits, which is how
        // their exit status stays observable.
        set_child_subreaper(Some(getpid())).map_err(io::Error::from)?;
        for directory in [
            &self.settings.records,
            &self.settings.bundles,
            &self.settings.runc_root,
        ] {
            fs::create_dir_all(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let mut required = vec!["memory", "pids"];
        if self
            .settings
            .agents
            .values()
            .any(|agent| agent.limits.cpu_max.is_some())
        {
            required.push("cpu");
        }
        self.settings
            .delegation
            .prepare(&required)
            .map_err(|error| SandboxError::Refused(error.to_string()))?;

        self.sweep()
    }

    fn reserve_execution(
        &mut self,
        id: ExecutionId,
        agent_name: &str,
    ) -> Result<u64, SandboxError> {
        let tag = id.tag();
        let agent = self
            .settings
            .agents
            .get(agent_name)
            .ok_or_else(|| SandboxError::Refused(format!("no agent `{agent_name}` is configured")))?
            .clone();
        if self.live.contains_key(&tag) {
            return Err(SandboxError::Refused(format!("tag {tag} is already live")));
        }
        let record_name = format!("{tag}.json");
        if records::read::<SandboxRecord>(&self.settings.records, &record_name)?.is_some() {
            return Err(SandboxError::Refused(format!(
                "a record for {tag} already exists"
            )));
        }
        let record = SandboxRecord {
            id,
            tag,
            agent: agent_name.to_owned(),
            stage: SandboxStage::CgroupReserved,
        };
        // Recorded before anything is created, so a crash at any later point leaves a record the
        // next start can sweep.
        records::publish(&self.settings.records, &record_name, &record)?;
        self.live.insert(
            tag,
            Live {
                id,
                agent: agent_name.to_owned(),
                stage: SandboxStage::CgroupReserved,
                init: None,
                exit: None,
            },
        );

        let cgroup = self.settings.delegation.execution(&tag.to_string());
        if let Err(error) = fs::create_dir(&cgroup) {
            self.live.remove(&tag);
            records::remove(&self.settings.records, &record_name)?;
            return Err(error.into());
        }
        let provisioned = (|| -> Result<u64, SandboxError> {
            fs::write(cgroup.join("pids.max"), agent.limits.pids_max.to_string())?;
            fs::write(
                cgroup.join("memory.max"),
                agent.limits.memory_max_bytes.to_string(),
            )?;
            fs::write(cgroup.join("memory.swap.max"), "0")?;
            if let Some(cpu) = agent.limits.cpu_max {
                fs::write(
                    cgroup.join("cpu.max"),
                    format!("{} {}", cpu.quota_us, cpu.period_us),
                )?;
            }
            let inode = self.cgroup_inode(&tag)?;
            if !fs::read_to_string(cgroup.join("cgroup.procs"))?
                .trim()
                .is_empty()
            {
                return Err(SandboxError::Failed(format!(
                    "reserved cgroup {} is not empty",
                    cgroup.display()
                )));
            }
            Ok(inode)
        })();
        match provisioned {
            Ok(inode) => Ok(inode),
            Err(error) => {
                let removed = cgroup::remove(&cgroup);
                if removed.is_ok() {
                    self.live.remove(&tag);
                    records::remove(&self.settings.records, &record_name)?;
                    Err(error)
                } else {
                    Err(SandboxError::Failed(format!(
                        "{error}; failed to roll back {}: {}",
                        cgroup.display(),
                        removed.err().map_or_else(
                            || "unknown rollback error".to_owned(),
                            |cleanup| cleanup.to_string()
                        )
                    )))
                }
            }
        }
    }

    fn create_paused(&mut self, id: ExecutionId) -> Result<(i32, u64), SandboxError> {
        let tag = id.tag();
        let live = self
            .live
            .get(&tag)
            .ok_or_else(|| SandboxError::Refused(format!("tag {tag} is not reserved")))?;
        if live.id != id || live.stage != SandboxStage::CgroupReserved {
            return Err(SandboxError::Refused(format!(
                "tag {tag} is not at the reserved stage for this Execution"
            )));
        }
        let agent = self
            .settings
            .agents
            .get(&live.agent)
            .ok_or_else(|| {
                SandboxError::Refused("the recorded agent is not configured".to_owned())
            })?
            .clone();
        let netns = Path::new(NETNS_DIR).join(tag.netns_name());
        if !netns.exists() {
            return Err(SandboxError::Refused(format!(
                "the network namespace of {tag} does not exist; the enforcer prepares it first"
            )));
        }

        let bundle = self.bundle_dir(&tag);
        fs::create_dir(&bundle)?;
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o700))?;
        let cgroups_path = self.settings.delegation.oci_path(&tag.to_string());
        let config = bundle::config(&BundleInputs {
            agent: &agent,
            netns_path: &netns,
            cgroups_path: &cgroups_path,
            soglia_env: &self.settings.soglia_env,
        });
        fs::write(
            bundle.join("config.json"),
            serde_json::to_vec_pretty(&config).map_err(io::Error::other)?,
        )?;

        // The agent's output goes to a pipe relayed, bounded, to the log. `runc create` hands the
        // write end to the agent and exits; the relay ends when the agent does.
        let (output, input) = io::pipe()?;
        let container = tag.container_id();
        let created = Command::new(&self.settings.runc)
            .arg("--root")
            .arg(&self.settings.runc_root)
            .args(["create", "--no-new-keyring", "--bundle"])
            .arg(&bundle)
            .arg(&container)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(input.try_clone()?)
            .stderr(input)
            .status();
        relay_output(id, output);
        let created = created?;
        if !created.success() {
            return Err(SandboxError::Failed(format!(
                "runc create {container} failed ({created}); its output is in the log"
            )));
        }

        let init = self.await_created(&tag)?;
        let inode = self.prove_membership(&tag, init)?;
        if let Some(live) = self.live.get_mut(&tag) {
            live.init = Some(init);
            live.stage = SandboxStage::ContainerCreatedPaused;
        }
        let live = self
            .live
            .get(&tag)
            .ok_or_else(|| SandboxError::Failed("the live reservation vanished".to_owned()))?;
        self.publish_live(&tag, live)?;

        Ok((init, inode))
    }

    fn start_execution(&mut self, id: ExecutionId) -> Result<(), SandboxError> {
        let tag = id.tag();
        let live = self
            .live
            .get(&tag)
            .ok_or_else(|| SandboxError::Refused(format!("tag {tag} is not live")))?;
        if live.id != id || live.stage != SandboxStage::ContainerCreatedPaused {
            return Err(SandboxError::Refused(format!(
                "tag {tag} is not a verified paused container for this Execution"
            )));
        }
        self.runc(&["start", &tag.container_id()])?;
        if let Some(live) = self.live.get_mut(&tag) {
            live.stage = SandboxStage::Started;
        }
        let live = self
            .live
            .get(&tag)
            .ok_or_else(|| SandboxError::Failed("the live container vanished".to_owned()))?;
        self.publish_live(&tag, live)?;

        Ok(())
    }

    fn kill_execution(&mut self, tag: &ResourceTag) -> Result<ExitOutcome, SandboxError> {
        let cgroup = self.settings.delegation.execution(&tag.to_string());
        let deadline = self.settings.teardown_deadline;
        let started_here = self.live.contains_key(tag);
        self.reap();
        let before_kill = self.live.get(tag).and_then(|live| live.exit);

        cgroup::kill(&cgroup, deadline)?;
        if !started_here {
            // Not started by this run: whatever was left in its cgroup is killed all the same.
            return Ok(ExitOutcome::Killed);
        }

        // The cgroup is empty, so the init process is gone; collect its status.
        let started = Instant::now();
        while self
            .live
            .get(tag)
            .is_some_and(|live| live.init.is_some() && live.exit.is_none())
            && started.elapsed() < deadline
        {
            self.reap();
            thread::sleep(Duration::from_millis(10));
        }

        Ok(self.outcome(tag, before_kill))
    }

    fn destroy_execution(&mut self, tag: &ResourceTag) -> Result<(), SandboxError> {
        self.remove(tag)?;
        records::remove(&self.settings.records, &format!("{tag}.json"))?;
        self.live.remove(tag);
        self.reap();

        Ok(())
    }
}

/// `true` when anything is mounted at or below `path`.
fn mounted_below(path: &Path) -> io::Result<bool> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let prefix = path.display().to_string();
    Ok(mountinfo.lines().any(|line| {
        line.split_whitespace()
            .nth(4)
            .is_some_and(|point| point == prefix || point.starts_with(&format!("{prefix}/")))
    }))
}

/// Relays up to [`MAX_LOGGED_BYTES`] of the agent's output to the helper's standard error.
fn relay_output(id: ExecutionId, stream: io::PipeReader) {
    thread::spawn(move || {
        let mut relayed = 0;
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else {
                break;
            };
            relayed += line.len();
            if relayed <= MAX_LOGGED_BYTES {
                eprintln!("{NAME_PREFIX}agent {id}: {line}");
            }
        }
    });
}
