// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::command::{CommandExecutor, CommandOutput, CommandSpec, RunningCommand};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::{SpikeTest, TestError};

const WAIT_STARTUP: Duration = Duration::from_secs(30);
const WAIT_LOSS: Duration = Duration::from_secs(5);
const OBSERVATION_WINDOW: Duration = Duration::from_secs(7);
const INGRESS: &str = "127.0.0.1:18089";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct KernelBaseline {
    programs: Value,
    links: Value,
    maps: Value,
    nft: Value,
    bpffs: Vec<String>,
    netns: Vec<String>,
    interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecutionMembership {
    execution_tag: String,
    cgroup_path: String,
    cgroup_inode: u64,
    cgroup_processes: Vec<u32>,
    proc_cgroups: BTreeMap<u32, String>,
    netns_name: String,
    named_netns_inode: Option<u64>,
    process_netns_inodes: BTreeMap<u32, u64>,
    namespace_nft: String,
    proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcessOutcome {
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S8Observation {
    production_behavior_modified_by_test: bool,
    unit: String,
    unit_inode: u64,
    runtime_pid: u32,
    sandbox_pid: u32,
    enforcer_pid: u32,
    enforcer_parent_pid: u32,
    helper_relationship_proven: bool,
    executions: Vec<ExecutionMembership>,
    pre_loss_443_established: bool,
    kill_signal: i32,
    enforcer_stopped: bool,
    helper_loss_event: String,
    autonomous_detection: bool,
    detection_required_enforcer_rpc: bool,
    detection_upper_bound_ms: u128,
    ingress_close_upper_bound_ms: u128,
    agents_gone_upper_bound_ms: u128,
    tunnel_close_upper_bound_ms: u128,
    runtime_exit_upper_bound_ms: u128,
    post_detection_admission: ProcessOutcome,
    existing_tunnel: ProcessOutcome,
    delayed_outbound: ProcessOutcome,
    existing_http: ProcessOutcome,
    upstream_443: ProcessOutcome,
    upstream_444: ProcessOutcome,
    application_pulse_after_loss: bool,
    outbound_444_after_loss: bool,
    admitted_before: usize,
    admitted_after: usize,
    allowed_before: usize,
    allowed_after: usize,
    agents_absent: bool,
    ingress_closed: bool,
    tunnel_closed: bool,
    retained_host_nft: String,
    bpf_links_after_loss: Value,
    restart_main_pid: u32,
    restart_sweep_line: Option<usize>,
    restart_ready_line: Option<usize>,
    restart_sweep_before_ready: bool,
    restart_execution_count: usize,
    restart_live_agent_count: usize,
    restart_test_netns_count: usize,
    restart_runc_containers: Vec<String>,
    restart_journal: String,
}

pub struct S8 {
    unit: String,
    unit_path: PathBuf,
    state: PathBuf,
    work: PathBuf,
    rootfs: PathBuf,
    config: PathBuf,
    upstream_link: String,
    baseline: Option<KernelBaseline>,
    hosts_before: Option<Vec<u8>>,
    runtime_pid: Option<u32>,
    helper_pids: Vec<u32>,
    execution_pids: Vec<u32>,
    owned_netns: Vec<String>,
    upstream_443: Option<RunningCommand>,
    upstream_444: Option<RunningCommand>,
    curl_tunnel: Option<RunningCommand>,
    curl_delayed: Option<RunningCommand>,
    curl_sleep: Option<RunningCommand>,
}

impl S8 {
    pub fn new(context: &TestContext) -> Self {
        let short = context
            .run_id
            .rsplit('-')
            .next()
            .unwrap_or("run")
            .chars()
            .take(7)
            .collect::<String>();
        let unit = format!("soglia-spike-s8-{short}.service");
        let work = Path::new("/var/tmp/soglia-spike-2/runtime")
            .join(&context.run_id)
            .join("s8");
        Self {
            unit_path: Path::new("/sys/fs/cgroup/system.slice").join(&unit),
            state: Path::new("/run/soglia-spike-runner")
                .join(&context.run_id)
                .join("s8-state"),
            rootfs: work.join("rootfs"),
            config: work.join("soglia.yaml"),
            upstream_link: format!("s8up{short}"),
            unit,
            work,
            baseline: None,
            hosts_before: None,
            runtime_pid: None,
            helper_pids: Vec::new(),
            execution_pids: Vec::new(),
            owned_netns: Vec::new(),
            upstream_443: None,
            upstream_444: None,
            curl_tunnel: None,
            curl_delayed: None,
            curl_sleep: None,
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        context.test_commands("s8")
    }

    fn journal(&self, context: &TestContext) -> Result<String, TestError> {
        let output = self
            .commands(context)
            .run(
                &CommandSpec::new("journalctl")
                    .args([
                        OsString::from("--unit"),
                        OsString::from(&self.unit),
                        OsString::from("--no-pager"),
                        OsString::from("--output=cat"),
                    ])
                    .timeout(Duration::from_secs(5)),
            )
            .map_err(TestError::infra)?;
        require_success(&output, "read S8 journal")?;
        Ok(output.stdout_text())
    }

    fn start_http_request(
        &self,
        context: &TestContext,
        body: &str,
    ) -> Result<RunningCommand, TestError> {
        self.commands(context)
            .spawn(
                &CommandSpec::new("curl")
                    .args([
                        OsString::from("--max-time"),
                        OsString::from("55"),
                        OsString::from("--silent"),
                        OsString::from("--show-error"),
                        OsString::from("--include"),
                        OsString::from("--write-out"),
                        OsString::from("\nS8_HTTP_STATUS=%{http_code}\n"),
                        OsString::from("--request"),
                        OsString::from("POST"),
                        OsString::from("--data-binary"),
                        OsString::from(body),
                        OsString::from(format!("http://{INGRESS}/v1/execute/probe")),
                    ])
                    .timeout(Duration::from_secs(60)),
            )
            .map_err(TestError::infra)
    }

    fn stop_running(command: &mut Option<RunningCommand>) -> Option<ProcessOutcome> {
        let mut running = command.take()?;
        let _ = running.terminate();
        running
            .wait(Duration::from_secs(3))
            .ok()
            .map(process_outcome)
    }
}

impl SpikeTest for S8 {
    type Observation = S8Observation;

    fn id(&self) -> TestId {
        TestId::S8
    }

    fn invariant(&self) -> &'static str {
        "production Enforcer loss is detected autonomously and causes bounded fail-closed cancellation, trusted Execution termination, retained kernel confinement, and sweep-before-readiness restart"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        let commands = self.commands(context);
        let baseline = kernel_baseline(&commands)?;
        self.baseline = Some(baseline.clone());
        if baseline
            .netns
            .iter()
            .any(|name| name.starts_with("soglia-"))
            || baseline
                .interfaces
                .iter()
                .any(|name| name == "soglia0" || name.starts_with("sgh-"))
            || nft_has_soglia_host(&baseline.nft)
            || !baseline.bpffs.is_empty()
            || count_named_programs(&baseline.programs, &["soglia_", "foreign_"]) != 0
            || count_cgroup_links(&baseline.links) != 0
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S8 preflight found unattributed Soglia network/BPF residue",
            ));
        }
        fs::create_dir_all(&self.rootfs)
            .map_err(|error| TestError::infra(format!("create S8 rootfs: {error}")))?;
        for directory in ["proc", "dev", "sys", "tmp"] {
            fs::create_dir_all(self.rootfs.join(directory)).map_err(|error| {
                TestError::infra(format!("create S8 rootfs {directory}: {error}"))
            })?;
        }
        fs::set_permissions(&self.rootfs, fs::Permissions::from_mode(0o755))
            .map_err(|error| TestError::infra(format!("chmod S8 rootfs: {error}")))?;
        let root_agent = self.rootfs.join("agent");
        fs::copy(context.artifact("bin/soglia-spike-agent"), &root_agent)
            .map_err(|error| TestError::infra(format!("install S8 rootfs agent: {error}")))?;
        fs::set_permissions(&root_agent, fs::Permissions::from_mode(0o755))
            .map_err(|error| TestError::infra(format!("chmod S8 agent: {error}")))?;
        let config = format!(
            "runtime:\n  state_dir: {}\n  uid: 990\n  gid: 990\n  max_concurrency: 4\n  max_queue: 2\n  cleanup_failure_threshold: 1\n  teardown_timeout_ms: 3000\ningress:\n  listen: {INGRESS}\n  max_response_bytes: 65536\ncgroup:\n  root: {}\negress:\n  connect_timeout_ms: 1500\n  idle_timeout_ms: 30000\n  allow:\n    - {{ host: allowed.test, ports: [443, 444] }}\nagents:\n  probe:\n    rootfs: {}\n    command: [\"/agent\", \"serve\"]\n    env: {{ AGENT_PORT: \"8080\" }}\n    port: 8080\n    timeout_ms: 30000\n    startup_timeout_ms: 3000\n",
            self.state.display(),
            self.unit_path.display(),
            self.rootfs.display(),
        );
        fs::write(&self.config, config)
            .map_err(|error| TestError::infra(format!("write S8 config: {error}")))?;
        context.resources.register(
            "s8",
            "S8 isolated work directory",
            Resource::Directory {
                path: self.work.clone(),
            },
        );
        context.resources.register(
            "s8",
            "S8 production runtime state",
            Resource::Directory {
                path: self.state.clone(),
            },
        );

        let hosts = fs::read("/etc/hosts")
            .map_err(|error| TestError::infra(format!("read /etc/hosts: {error}")))?;
        let hosts_sha256 = format!("{:x}", Sha256::digest(&hosts));
        self.hosts_before = Some(hosts.clone());
        let mut with_test_host = hosts;
        with_test_host.extend_from_slice(b"\n11.0.0.1 allowed.test # soglia-spike-s8\n");
        fs::write("/etc/hosts", with_test_host)
            .map_err(|error| TestError::infra(format!("write S8 /etc/hosts entry: {error}")))?;
        context.resources.register(
            "s8",
            "exact /etc/hosts restoration record",
            Resource::ModifiedFile {
                path: PathBuf::from("/etc/hosts"),
                expected_sha256: hosts_sha256,
            },
        );

        run_success(
            &commands,
            CommandSpec::new("ip").args([
                OsString::from("link"),
                OsString::from("add"),
                OsString::from(&self.upstream_link),
                OsString::from("type"),
                OsString::from("dummy"),
            ]),
            "create S8 upstream link",
        )?;
        context.resources.register(
            "s8",
            "S8 controlled upstream dummy interface",
            Resource::Interface {
                name: self.upstream_link.clone(),
            },
        );
        run_success(
            &commands,
            CommandSpec::new("ip").args([
                OsString::from("address"),
                OsString::from("add"),
                OsString::from("11.0.0.1/32"),
                OsString::from("dev"),
                OsString::from(&self.upstream_link),
            ]),
            "address S8 upstream link",
        )?;
        run_success(
            &commands,
            CommandSpec::new("ip").args([
                OsString::from("link"),
                OsString::from("set"),
                OsString::from(&self.upstream_link),
                OsString::from("up"),
            ]),
            "enable S8 upstream link",
        )?;

        let agent = context.artifact("bin/soglia-spike-agent");
        self.upstream_443 = Some(
            commands
                .spawn(
                    &CommandSpec::new(&agent)
                        .args([OsString::from("listen4-pulse-hold 11.0.0.1:443 20")])
                        .timeout(Duration::from_secs(30)),
                )
                .map_err(TestError::infra)?,
        );
        self.upstream_444 = Some(
            commands
                .spawn(
                    &CommandSpec::new(&agent)
                        .args([OsString::from("listen4-hold 11.0.0.1:444 20")])
                        .timeout(Duration::from_secs(30)),
                )
                .map_err(TestError::infra)?,
        );
        thread::sleep(Duration::from_millis(200));

        run_success(
            &commands,
            CommandSpec::new("systemd-run")
                .args([
                    OsString::from(format!("--unit={}", self.unit.trim_end_matches(".service"))),
                    OsString::from("--property=Delegate=yes"),
                    OsString::from("--property=Type=simple"),
                    OsString::from("--property=Restart=no"),
                    OsString::from("--"),
                    context.artifact("bin/soglia").into_os_string(),
                    OsString::from("run"),
                    OsString::from("--file"),
                    self.config.as_os_str().to_owned(),
                ])
                .timeout(Duration::from_secs(10)),
            "start S8 production runtime",
        )?;
        context.resources.register(
            "s8",
            "S8 delegated production runtime unit",
            Resource::SystemdUnit {
                name: self.unit.clone(),
            },
        );
        wait_until(WAIT_STARTUP, || tcp_open(INGRESS))
            .map_err(|error| TestError::infra(format!("wait S8 startup.ready: {error}")))?;
        let runtime_pid = systemd_main_pid(&commands, &self.unit)?;
        self.runtime_pid = Some(runtime_pid);
        context.resources.register(
            "s8",
            "S8 production runtime process",
            Resource::Process { pid: runtime_pid },
        );
        let (sandbox, enforcer) = wait_helpers(runtime_pid, WAIT_LOSS)?;
        self.helper_pids.extend([sandbox, enforcer]);
        for (role, pid) in [("sandboxd", sandbox), ("enforcer", enforcer)] {
            context.resources.register(
                "s8",
                format!("S8 production {role} child"),
                Resource::Process { pid },
            );
        }
        let provenance = run_success(
            &commands,
            CommandSpec::new("sha256sum").args([
                context.artifact("bin/soglia").into_os_string(),
                context.artifact("bin/soglia-spike-agent").into_os_string(),
                self.config.as_os_str().to_owned(),
            ]),
            "hash S8 artifacts",
        )?;
        context
            .evidence
            .write_text("s8/raw/provenance.sha256", &provenance.stdout_text())
            .map_err(|error| TestError::infra(format!("write S8 provenance: {error}")))?;
        Ok(())
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let commands = self.commands(context);
        let runtime_pid = self
            .runtime_pid
            .ok_or_else(|| TestError::infra("S8 runtime PID missing"))?;
        let unit_inode = fs::metadata(&self.unit_path)
            .map_err(|error| TestError::infra(format!("stat S8 unit: {error}")))?
            .ino();
        let (sandbox_pid, enforcer_pid) = wait_helpers(runtime_pid, WAIT_LOSS)?;
        let enforcer_parent_pid = proc_parent(enforcer_pid)?;

        self.curl_tunnel = Some(self.start_http_request(
            context,
            "delayed-tunnel-pulse 2500 allowed.test:443 2000 25",
        )?);
        self.curl_delayed =
            Some(self.start_http_request(context, "delayed-tunnel 6500 allowed.test:444 25")?);
        self.curl_sleep = Some(self.start_http_request(context, "sleep 12000")?);

        let executions = wait_memberships(&commands, &self.unit_path, 3, WAIT_LOSS)?;
        for execution in &executions {
            self.execution_pids
                .extend(execution.cgroup_processes.iter().copied());
            self.owned_netns.push(execution.netns_name.clone());
            context.resources.register(
                "s8",
                "S8 production Execution cgroup",
                Resource::Cgroup {
                    path: PathBuf::from(&execution.cgroup_path),
                    inode: execution.cgroup_inode,
                },
            );
            context.resources.register(
                "s8",
                "S8 production Execution network namespace",
                Resource::Netns {
                    name: execution.netns_name.clone(),
                },
            );
        }
        wait_until(WAIT_LOSS, || established_to(&commands, "11.0.0.1:443"))
            .map_err(|error| TestError::infra(format!("wait S8 existing tunnel: {error}")))?;
        let pre_loss_443_established = established_to(&commands, "11.0.0.1:443");
        let journal_before = self.journal(context)?;
        let admitted_before = journal_before.matches("execution.admitted").count();
        let allowed_before = journal_before.matches("egress.allowed").count();

        let loss_started = Instant::now();
        kill(
            Pid::from_raw(
                i32::try_from(enforcer_pid).map_err(|error| {
                    TestError::infra(format!("convert S8 enforcer PID: {error}"))
                })?,
            ),
            Signal::SIGKILL,
        )
        .map_err(|error| TestError::infra(format!("kill S8 enforcer: {error}")))?;
        wait_until(WAIT_LOSS, || process_stopped(enforcer_pid))
            .map_err(|error| TestError::infra(format!("wait S8 enforcer stop: {error}")))?;

        let mut helper_loss_event = String::new();
        wait_until(WAIT_LOSS, || {
            if let Ok(journal) = self.journal(context) {
                if let Some(line) = journal
                    .lines()
                    .find(|line| line.contains("runtime.helper_lost"))
                {
                    helper_loss_event = line.to_owned();
                    return true;
                }
            }
            false
        })
        .map_err(|error| {
            TestError::new(Verdict::Fail, format!("autonomous S8 detection: {error}"))
        })?;
        let detection_upper_bound_ms = loss_started.elapsed().as_millis();
        wait_until(WAIT_LOSS, || !tcp_open(INGRESS))
            .map_err(|error| TestError::new(Verdict::Fail, format!("S8 ingress close: {error}")))?;
        let ingress_close_upper_bound_ms = loss_started.elapsed().as_millis();
        wait_until(WAIT_LOSS, || {
            self.execution_pids.iter().all(|pid| process_stopped(*pid))
        })
        .map_err(|error| TestError::new(Verdict::Fail, format!("S8 agent termination: {error}")))?;
        let agents_gone_upper_bound_ms = loss_started.elapsed().as_millis();
        wait_until(WAIT_LOSS, || !established_to(&commands, "11.0.0.1:443"))
            .map_err(|error| TestError::new(Verdict::Fail, format!("S8 tunnel close: {error}")))?;
        let tunnel_close_upper_bound_ms = loss_started.elapsed().as_millis();
        wait_until(WAIT_LOSS, || process_stopped(runtime_pid))
            .map_err(|error| TestError::new(Verdict::Fail, format!("S8 runtime exit: {error}")))?;
        let runtime_exit_upper_bound_ms = loss_started.elapsed().as_millis();

        let post_detection_admission = process_outcome(
            commands
                .run(
                    &CommandSpec::new("curl")
                        .args([
                            OsString::from("--max-time"),
                            OsString::from("2"),
                            OsString::from("--silent"),
                            OsString::from("--show-error"),
                            OsString::from("--request"),
                            OsString::from("POST"),
                            OsString::from("--data-binary"),
                            OsString::from("sleep 1"),
                            OsString::from(format!("http://{INGRESS}/v1/execute/probe")),
                        ])
                        .timeout(Duration::from_secs(4)),
                )
                .map_err(TestError::infra)?,
        );

        while loss_started.elapsed() < OBSERVATION_WINDOW {
            thread::sleep(Duration::from_millis(25));
        }
        let existing_tunnel = wait_process(&mut self.curl_tunnel, Duration::from_secs(5))?;
        let delayed_outbound = wait_process(&mut self.curl_delayed, Duration::from_secs(5))?;
        let existing_http = wait_process(&mut self.curl_sleep, Duration::from_secs(5))?;
        let upstream_443 = Self::stop_running(&mut self.upstream_443)
            .ok_or_else(|| TestError::infra("S8 upstream 443 process missing"))?;
        let upstream_444 = Self::stop_running(&mut self.upstream_444)
            .ok_or_else(|| TestError::infra("S8 upstream 444 process missing"))?;
        let application_pulse_after_loss = upstream_443.stdout.contains("application_pulse_echoed");
        let outbound_444_after_loss = upstream_444.stdout.contains("accepted");
        let journal_after = self.journal(context)?;
        let admitted_after = journal_after.matches("execution.admitted").count();
        let allowed_after = journal_after.matches("egress.allowed").count();
        let retained_host_nft = command_text(
            &commands,
            CommandSpec::new("nft").args([
                OsString::from("--handle"),
                OsString::from("list"),
                OsString::from("table"),
                OsString::from("inet"),
                OsString::from("soglia_host"),
            ]),
            "read retained S8 host nft table",
        )?;
        let bpf_links_after_loss = command_json(
            &commands,
            CommandSpec::new("bpftool").args([
                OsString::from("-j"),
                OsString::from("link"),
                OsString::from("show"),
            ]),
            "read S8 BPF links after loss",
        )?;
        let agents_absent = self.execution_pids.iter().all(|pid| process_stopped(*pid));
        let ingress_closed = !tcp_open(INGRESS);
        let tunnel_closed = !established_to(&commands, "11.0.0.1:443");

        let restart_epoch = unix_seconds();
        run_success(
            &commands,
            CommandSpec::new("systemctl")
                .args([OsString::from("restart"), OsString::from(&self.unit)]),
            "restart S8 production runtime",
        )?;
        wait_until(WAIT_STARTUP, || tcp_open(INGRESS)).map_err(|error| {
            TestError::new(Verdict::Fail, format!("S8 restart readiness: {error}"))
        })?;
        let restart_main_pid = systemd_main_pid(&commands, &self.unit)?;
        self.runtime_pid = Some(restart_main_pid);
        let restart_journal = journal_since(&commands, &self.unit, restart_epoch)?;
        let restart_sweep_line = restart_journal
            .lines()
            .position(|line| line.contains("startup.swept"));
        let restart_ready_line = restart_journal
            .lines()
            .position(|line| line.contains("startup.ready"));
        let restart_sweep_before_ready = matches!(
            (restart_sweep_line, restart_ready_line),
            (Some(sweep), Some(ready)) if sweep < ready
        );
        let restart_execution_count = execution_directories(&self.unit_path).len();
        let restart_live_agent_count = self
            .execution_pids
            .iter()
            .filter(|pid| !process_stopped(**pid))
            .count();
        let restart_test_netns_count = self
            .owned_netns
            .iter()
            .filter(|name| Path::new("/run/netns").join(name).exists())
            .count();
        let restart_runc_containers = runc_containers(&commands, &self.state)?;

        Ok(S8Observation {
            production_behavior_modified_by_test: false,
            unit: self.unit.clone(),
            unit_inode,
            runtime_pid,
            sandbox_pid,
            enforcer_pid,
            enforcer_parent_pid,
            helper_relationship_proven: enforcer_parent_pid == runtime_pid,
            executions,
            pre_loss_443_established,
            kill_signal: 9,
            enforcer_stopped: process_stopped(enforcer_pid),
            helper_loss_event,
            autonomous_detection: true,
            detection_required_enforcer_rpc: false,
            detection_upper_bound_ms,
            ingress_close_upper_bound_ms,
            agents_gone_upper_bound_ms,
            tunnel_close_upper_bound_ms,
            runtime_exit_upper_bound_ms,
            post_detection_admission,
            existing_tunnel,
            delayed_outbound,
            existing_http,
            upstream_443,
            upstream_444,
            application_pulse_after_loss,
            outbound_444_after_loss,
            admitted_before,
            admitted_after,
            allowed_before,
            allowed_after,
            agents_absent,
            ingress_closed,
            tunnel_closed,
            retained_host_nft,
            bpf_links_after_loss,
            restart_main_pid,
            restart_sweep_line,
            restart_ready_line,
            restart_sweep_before_ready,
            restart_execution_count,
            restart_live_agent_count,
            restart_test_netns_count,
            restart_runc_containers,
            restart_journal,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if observation.production_behavior_modified_by_test
            || !observation.helper_relationship_proven
            || observation.executions.len() < 3
            || observation.executions.iter().any(|entry| !entry.proven)
            || !observation.pre_loss_443_established
            || observation.kill_signal != 9
            || !observation.enforcer_stopped
            || !observation.autonomous_detection
            || observation.detection_required_enforcer_rpc
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S8 did not establish the trusted pre-loss topology and autonomous loss event",
            ));
        }
        if observation.detection_upper_bound_ms > WAIT_LOSS.as_millis()
            || observation.ingress_close_upper_bound_ms > WAIT_LOSS.as_millis()
            || observation.agents_gone_upper_bound_ms > WAIT_LOSS.as_millis()
            || observation.tunnel_close_upper_bound_ms > WAIT_LOSS.as_millis()
            || observation.runtime_exit_upper_bound_ms > WAIT_LOSS.as_millis()
            || observation.post_detection_admission.exit_code == Some(0)
            || observation.application_pulse_after_loss
            || observation.outbound_444_after_loss
            || observation.admitted_after != observation.admitted_before
            || observation.allowed_after != observation.allowed_before
            || !observation.agents_absent
            || !observation.ingress_closed
            || !observation.tunnel_closed
            || observation.retained_host_nft.trim().is_empty()
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S8 production runtime did not remain bounded and fail-closed after Enforcer loss",
            ));
        }
        if !observation.restart_sweep_before_ready
            || observation.restart_execution_count != 0
            || observation.restart_live_agent_count != 0
            || observation.restart_test_netns_count != 0
            || !observation.restart_runc_containers.is_empty()
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S8 restart did not prove sweep-before-readiness and zero live Execution residue",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        for command in [
            &mut self.curl_tunnel,
            &mut self.curl_delayed,
            &mut self.curl_sleep,
            &mut self.upstream_443,
            &mut self.upstream_444,
        ] {
            let _ = Self::stop_running(command);
        }
        let commands = self.commands(context);
        let _ = commands.run(
            &CommandSpec::new("systemctl")
                .args([OsString::from("stop"), OsString::from(&self.unit)])
                .timeout(Duration::from_secs(10)),
        );
        let stopped = wait_until(Duration::from_secs(3), || {
            systemd_active(&commands, &self.unit).is_ok_and(|active| !active)
        })
        .is_ok();
        if !stopped {
            let _ = commands.run(
                &CommandSpec::new("systemctl")
                    .args([
                        OsString::from("kill"),
                        OsString::from("--kill-who=all"),
                        OsString::from("--signal=KILL"),
                        OsString::from(&self.unit),
                    ])
                    .timeout(Duration::from_secs(10)),
            );
            let _ = wait_until(Duration::from_secs(5), || {
                self.runtime_pid
                    .into_iter()
                    .chain(self.helper_pids.iter().copied())
                    .chain(self.execution_pids.iter().copied())
                    .all(process_stopped)
            });
        }
        let containers = runc_containers(&commands, &self.state).unwrap_or_default();
        for container in &containers {
            let _ = commands.run(&CommandSpec::new("runc").args([
                OsString::from("--root"),
                self.state.join("runc").into_os_string(),
                OsString::from("kill"),
                OsString::from(container),
                OsString::from("KILL"),
            ]));
            let _ = commands.run(&CommandSpec::new("runc").args([
                OsString::from("--root"),
                self.state.join("runc").into_os_string(),
                OsString::from("delete"),
                OsString::from("--force"),
                OsString::from(container),
            ]));
        }
        let mut cleanup_netns = self.owned_netns.clone();
        cleanup_netns.extend(containers);
        cleanup_netns.sort();
        cleanup_netns.dedup();
        for netns in cleanup_netns {
            if Path::new("/run/netns").join(&netns).exists() {
                let _ = commands.run(&CommandSpec::new("ip").args([
                    OsString::from("netns"),
                    OsString::from("delete"),
                    OsString::from(netns),
                ]));
            }
        }
        if let (Some(baseline), Ok(current)) = (&self.baseline, interface_names(&commands)) {
            for interface in current
                .into_iter()
                .filter(|name| !baseline.interfaces.contains(name))
            {
                let _ = commands.run(&CommandSpec::new("ip").args([
                    OsString::from("link"),
                    OsString::from("delete"),
                    OsString::from(interface),
                ]));
            }
        }
        if nft_table_present(&commands, "inet", "soglia_host") {
            let _ = commands.run(&CommandSpec::new("nft").args([
                OsString::from("delete"),
                OsString::from("table"),
                OsString::from("inet"),
                OsString::from("soglia_host"),
            ]));
        }
        if interface_present(&commands, &self.upstream_link) {
            let _ = commands.run(&CommandSpec::new("ip").args([
                OsString::from("link"),
                OsString::from("delete"),
                OsString::from(&self.upstream_link),
            ]));
        }
        if let Some(hosts) = self.hosts_before.as_ref() {
            fs::write("/etc/hosts", hosts)
                .map_err(|error| TestError::infra(format!("restore /etc/hosts: {error}")))?;
        }
        let _ = commands.run(
            &CommandSpec::new("systemctl")
                .args([OsString::from("reset-failed"), OsString::from(&self.unit)]),
        );
        let _ = commands.run(
            &CommandSpec::new("systemctl")
                .args([OsString::from("revert"), OsString::from(&self.unit)]),
        );
        let _ = commands.run(&CommandSpec::new("systemctl").args(["daemon-reload"]));
        remove_tree(&self.state)?;
        remove_tree(&self.work)?;
        let _ = wait_until(Duration::from_secs(5), || !self.unit_path.exists());
        let _ = wait_until(Duration::from_secs(5), || {
            self.runtime_pid
                .into_iter()
                .chain(self.helper_pids.iter().copied())
                .chain(self.execution_pids.iter().copied())
                .all(process_stopped)
        });
        context.resources.mark_owner_cleaned("s8");
        Ok(())
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        let commands = self.commands(context);
        let baseline = self
            .baseline
            .as_ref()
            .ok_or_else(|| TestError::infra("S8 baseline missing"))?;
        let final_state = kernel_baseline(&commands)?;
        let hosts_restored = self
            .hosts_before
            .as_ref()
            .is_some_and(|before| fs::read("/etc/hosts").is_ok_and(|actual| actual == *before));
        let processes_absent = self
            .runtime_pid
            .into_iter()
            .chain(self.helper_pids.iter().copied())
            .chain(self.execution_pids.iter().copied())
            .all(process_stopped);
        let unit_absent = !self.unit_path.exists();
        context
            .evidence
            .write_json(
                "s8/cleanup.json",
                &serde_json::json!({
                    "baseline_restored": final_state == *baseline,
                    "hosts_restored": hosts_restored,
                    "processes_absent": processes_absent,
                    "unit_absent": unit_absent,
                    "state_absent": !self.state.exists(),
                    "work_absent": !self.work.exists(),
                    "upstream_link_absent": !interface_present(&commands, &self.upstream_link),
                    "owned_netns_absent": self.owned_netns.iter().all(|name| !Path::new("/run/netns").join(name).exists()),
                    "final": final_state,
                    "baseline": baseline,
                }),
            )
            .map_err(|error| TestError::infra(format!("write S8 cleanup evidence: {error}")))?;
        if final_state != *baseline
            || !hosts_restored
            || !processes_absent
            || !unit_absent
            || self.state.exists()
            || self.work.exists()
            || interface_present(&commands, &self.upstream_link)
            || self
                .owned_netns
                .iter()
                .any(|name| Path::new("/run/netns").join(name).exists())
        {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S8 owned state did not return exactly to its pre-test baseline",
            ));
        }
        Ok(())
    }
}

fn wait_process(
    command: &mut Option<RunningCommand>,
    timeout: Duration,
) -> Result<ProcessOutcome, TestError> {
    let running = command
        .take()
        .ok_or_else(|| TestError::infra("S8 expected process missing"))?;
    running
        .wait(timeout)
        .map(process_outcome)
        .map_err(TestError::infra)
}

fn process_outcome(output: CommandOutput) -> ProcessOutcome {
    ProcessOutcome {
        exit_code: output.record.exit_code,
        signal: output.record.signal,
        timed_out: output.record.timed_out,
        stdout: output.stdout_text(),
        stderr: output.stderr_text(),
    }
}

fn run_success(
    commands: &CommandExecutor,
    spec: CommandSpec,
    context: &str,
) -> Result<CommandOutput, TestError> {
    let output = commands.run(&spec).map_err(TestError::infra)?;
    require_success(&output, context)?;
    Ok(output)
}

fn require_success(output: &CommandOutput, context: &str) -> Result<(), TestError> {
    output.require_success(context).map_err(TestError::infra)
}

fn command_text(
    commands: &CommandExecutor,
    spec: CommandSpec,
    context: &str,
) -> Result<String, TestError> {
    Ok(run_success(commands, spec, context)?.stdout_text())
}

fn command_json(
    commands: &CommandExecutor,
    spec: CommandSpec,
    context: &str,
) -> Result<Value, TestError> {
    let text = command_text(commands, spec, context)?;
    if text.trim().is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    serde_json::from_str(&text)
        .map_err(|error| TestError::infra(format!("parse {context} JSON: {error}")))
}

fn kernel_baseline(commands: &CommandExecutor) -> Result<KernelBaseline, TestError> {
    let mut programs = command_json(
        commands,
        CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("prog"),
            OsString::from("show"),
        ]),
        "S8 program inventory",
    )?;
    normalize_bpf_inventory(&mut programs);
    let mut links = command_json(
        commands,
        CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("link"),
            OsString::from("show"),
        ]),
        "S8 link inventory",
    )?;
    normalize_bpf_inventory(&mut links);
    let mut maps = command_json(
        commands,
        CommandSpec::new("bpftool").args([
            OsString::from("-j"),
            OsString::from("map"),
            OsString::from("show"),
        ]),
        "S8 map inventory",
    )?;
    normalize_bpf_inventory(&mut maps);
    let mut nft = command_json(
        commands,
        CommandSpec::new("nft").args([
            OsString::from("--json"),
            OsString::from("list"),
            OsString::from("ruleset"),
        ]),
        "S8 nft inventory",
    )?;
    normalize_nft_counters(&mut nft);
    Ok(KernelBaseline {
        programs,
        links,
        maps,
        nft,
        bpffs: list_tree(Path::new("/sys/fs/bpf"))?,
        netns: netns_names(commands)?,
        interfaces: interface_names(commands)?,
    })
}

fn normalize_bpf_inventory(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values.iter_mut() {
                normalize_bpf_inventory(value);
            }
            values.sort_by_key(Value::to_string);
        }
        Value::Object(object) => {
            for key in [
                "id",
                "loaded_at",
                "run_time_ns",
                "run_cnt",
                "recursion_misses",
            ] {
                object.remove(key);
            }
            for value in object.values_mut() {
                normalize_bpf_inventory(value);
            }
        }
        _ => {}
    }
}

fn normalize_nft_counters(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                normalize_nft_counters(value);
            }
        }
        Value::Object(object) => {
            if object.contains_key("counter") {
                object.insert("counter".to_owned(), serde_json::json!({}));
            }
            for value in object.values_mut() {
                normalize_nft_counters(value);
            }
        }
        _ => {}
    }
}

fn list_tree(root: &Path) -> Result<Vec<String>, TestError> {
    let mut values = Vec::new();
    visit_tree(root, root, &mut values)?;
    values.sort();
    Ok(values)
}

fn visit_tree(root: &Path, path: &Path, values: &mut Vec<String>) -> Result<(), TestError> {
    for entry in fs::read_dir(path)
        .map_err(|error| TestError::infra(format!("read {}: {error}", path.display())))?
    {
        let entry = entry.map_err(|error| TestError::infra(format!("read tree entry: {error}")))?;
        let child = entry.path();
        values.push(
            child
                .strip_prefix(root)
                .unwrap_or(&child)
                .to_string_lossy()
                .into_owned(),
        );
        if entry
            .file_type()
            .map_err(|error| TestError::infra(format!("type {}: {error}", child.display())))?
            .is_dir()
        {
            visit_tree(root, &child, values)?;
        }
    }
    Ok(())
}

fn netns_names(commands: &CommandExecutor) -> Result<Vec<String>, TestError> {
    let text = command_text(
        commands,
        CommandSpec::new("ip").args([OsString::from("netns"), OsString::from("list")]),
        "S8 netns inventory",
    )?;
    Ok(text
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect())
}

fn interface_names(commands: &CommandExecutor) -> Result<Vec<String>, TestError> {
    let value = command_json(
        commands,
        CommandSpec::new("ip").args([
            OsString::from("--json"),
            OsString::from("link"),
            OsString::from("show"),
        ]),
        "S8 interface inventory",
    )?;
    Ok(value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("ifname").and_then(Value::as_str))
        .map(|name| name.split('@').next().unwrap_or(name).to_owned())
        .collect())
}

fn count_named_programs(value: &Value, prefixes: &[&str]) -> usize {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| prefixes.iter().any(|prefix| name.starts_with(prefix)))
        })
        .count()
}

fn count_cgroup_links(value: &Value) -> usize {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("type").and_then(Value::as_str) == Some("cgroup"))
        .count()
}

fn nft_has_soglia_host(value: &Value) -> bool {
    value.to_string().contains("soglia_host")
}

fn nft_table_present(commands: &CommandExecutor, family: &str, table: &str) -> bool {
    commands
        .run(&CommandSpec::new("nft").args([
            OsString::from("list"),
            OsString::from("table"),
            OsString::from(family),
            OsString::from(table),
        ]))
        .is_ok_and(|output| output.success())
}

fn interface_present(commands: &CommandExecutor, interface: &str) -> bool {
    commands
        .run(&CommandSpec::new("ip").args([
            OsString::from("link"),
            OsString::from("show"),
            OsString::from("dev"),
            OsString::from(interface),
        ]))
        .is_ok_and(|output| output.success())
}

fn systemd_main_pid(commands: &CommandExecutor, unit: &str) -> Result<u32, TestError> {
    let text = command_text(
        commands,
        CommandSpec::new("systemctl").args([
            OsString::from("show"),
            OsString::from("--property=MainPID"),
            OsString::from("--value"),
            OsString::from(unit),
        ]),
        "read S8 systemd MainPID",
    )?;
    text.trim()
        .parse::<u32>()
        .map_err(|error| TestError::infra(format!("parse S8 MainPID: {error}")))
}

fn systemd_active(commands: &CommandExecutor, unit: &str) -> Result<bool, TestError> {
    let output = commands
        .run(
            &CommandSpec::new("systemctl")
                .args([OsString::from("is-active"), OsString::from(unit)]),
        )
        .map_err(TestError::infra)?;
    Ok(output.stdout_text().trim() == "active")
}

fn wait_helpers(runtime_pid: u32, timeout: Duration) -> Result<(u32, u32), TestError> {
    let started = Instant::now();
    loop {
        let mut sandbox = None;
        let mut enforcer = None;
        for child in proc_children(runtime_pid)? {
            let command = proc_cmdline(child).unwrap_or_default();
            if command.contains("__sandboxd") {
                sandbox = Some(child);
            }
            if command.contains("__enforcer") {
                enforcer = Some(child);
            }
        }
        if let (Some(sandbox), Some(enforcer)) = (sandbox, enforcer) {
            return Ok((sandbox, enforcer));
        }
        if started.elapsed() >= timeout {
            return Err(TestError::infra("timed out locating S8 helper children"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn proc_children(pid: u32) -> Result<Vec<u32>, TestError> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let text = fs::read_to_string(&path)
        .map_err(|error| TestError::infra(format!("read {path}: {error}")))?;
    text.split_whitespace()
        .map(|value| {
            value
                .parse()
                .map_err(|error| TestError::infra(format!("parse child PID: {error}")))
        })
        .collect()
}

fn proc_cmdline(pid: u32) -> Result<String, TestError> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|error| TestError::infra(format!("read PID {pid} cmdline: {error}")))?;
    Ok(String::from_utf8_lossy(&bytes).replace('\0', " "))
}

fn proc_parent(pid: u32) -> Result<u32, TestError> {
    let text = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| TestError::infra(format!("read PID {pid} status: {error}")))?;
    text.lines()
        .find_map(|line| line.strip_prefix("PPid:").map(str::trim))
        .ok_or_else(|| TestError::infra("S8 helper PPid missing"))?
        .parse()
        .map_err(|error| TestError::infra(format!("parse S8 helper PPid: {error}")))
}

fn execution_directories(unit: &Path) -> Vec<PathBuf> {
    fs::read_dir(unit.join("executions"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_dir())
                .map(|_| entry.path())
        })
        .collect()
}

fn collect_membership(
    commands: &CommandExecutor,
    unit: &Path,
) -> Result<Vec<ExecutionMembership>, TestError> {
    let mut result = Vec::new();
    for cgroup in execution_directories(unit) {
        let execution_tag = cgroup
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| TestError::infra("S8 non-UTF8 Execution tag"))?
            .to_owned();
        let processes = fs::read_to_string(cgroup.join("cgroup.procs"))
            .map_err(|error| TestError::infra(format!("read S8 cgroup.procs: {error}")))?
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<u32>, _>>()
            .map_err(|error| TestError::infra(format!("parse S8 cgroup PID: {error}")))?;
        let relative = cgroup
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| TestError::infra("S8 cgroup outside cgroup2"))?;
        let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
        let mut proc_cgroups = BTreeMap::new();
        let mut process_netns_inodes = BTreeMap::new();
        for pid in &processes {
            proc_cgroups.insert(
                *pid,
                fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|error| {
                    TestError::infra(format!("read S8 PID {pid} cgroup: {error}"))
                })?,
            );
            process_netns_inodes.insert(
                *pid,
                fs::metadata(format!("/proc/{pid}/ns/net"))
                    .map_err(|error| TestError::infra(format!("stat S8 PID {pid} netns: {error}")))?
                    .ino(),
            );
        }
        let netns_name = format!("soglia-{execution_tag}");
        let named_path = Path::new("/run/netns").join(&netns_name);
        let named_netns_inode = fs::metadata(&named_path)
            .ok()
            .map(|metadata| metadata.ino());
        let namespace_nft = if named_path.exists() {
            command_text(
                commands,
                CommandSpec::new("ip").args([
                    OsString::from("netns"),
                    OsString::from("exec"),
                    OsString::from(&netns_name),
                    OsString::from("nft"),
                    OsString::from("--handle"),
                    OsString::from("list"),
                    OsString::from("ruleset"),
                ]),
                "read S8 Execution nft rules",
            )?
        } else {
            String::new()
        };
        let proven = !processes.is_empty()
            && named_netns_inode.is_some()
            && proc_cgroups
                .values()
                .all(|value| value.lines().any(|line| line == expected))
            && process_netns_inodes
                .values()
                .all(|inode| Some(*inode) == named_netns_inode)
            && !namespace_nft.trim().is_empty();
        result.push(ExecutionMembership {
            execution_tag,
            cgroup_path: cgroup.to_string_lossy().into_owned(),
            cgroup_inode: fs::metadata(&cgroup)
                .map_err(|error| TestError::infra(format!("stat S8 cgroup: {error}")))?
                .ino(),
            cgroup_processes: processes,
            proc_cgroups,
            netns_name,
            named_netns_inode,
            process_netns_inodes,
            namespace_nft,
            proven,
        });
    }
    result.sort_by(|left, right| left.execution_tag.cmp(&right.execution_tag));
    Ok(result)
}

fn wait_memberships(
    commands: &CommandExecutor,
    unit: &Path,
    minimum: usize,
    timeout: Duration,
) -> Result<Vec<ExecutionMembership>, TestError> {
    let started = Instant::now();
    loop {
        let last_detail = match collect_membership(commands, unit) {
            Ok(memberships)
                if memberships.len() >= minimum
                    && memberships.iter().all(|membership| membership.proven) =>
            {
                return Ok(memberships);
            }
            Ok(memberships) => {
                let proven = memberships
                    .iter()
                    .filter(|membership| membership.proven)
                    .count();
                format!(
                    "observed {} Execution cgroups but only {proven} had complete live membership",
                    memberships.len()
                )
            }
            Err(error) => error.detail,
        };
        if started.elapsed() >= timeout {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S8 live Execution identity/topology did not stabilize: {last_detail}"),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn established_to(commands: &CommandExecutor, target: &str) -> bool {
    commands
        .run(&CommandSpec::new("ss").args([
            OsString::from("--no-header"),
            OsString::from("--numeric"),
            OsString::from("--tcp"),
            OsString::from("state"),
            OsString::from("established"),
        ]))
        .is_ok_and(|output| output.success() && output.stdout_text().contains(target))
}

fn tcp_open(address: &str) -> bool {
    address
        .parse::<SocketAddr>()
        .ok()
        .and_then(|address| TcpStream::connect_timeout(&address, Duration::from_millis(50)).ok())
        .is_some()
}

fn process_stopped(pid: u32) -> bool {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
    match stat {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
        Ok(stat) => stat.split_whitespace().nth(2) == Some("Z"),
    }
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if predicate() {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("timed out after {} ms", timeout.as_millis()));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn journal_since(
    commands: &CommandExecutor,
    unit: &str,
    epoch_seconds: u64,
) -> Result<String, TestError> {
    command_text(
        commands,
        CommandSpec::new("journalctl").args([
            OsString::from("--unit"),
            OsString::from(unit),
            OsString::from("--since"),
            OsString::from(format!("@{epoch_seconds}")),
            OsString::from("--no-pager"),
            OsString::from("--output=cat"),
        ]),
        "read S8 restart journal",
    )
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn runc_containers(commands: &CommandExecutor, state: &Path) -> Result<Vec<String>, TestError> {
    let output = commands
        .run(&CommandSpec::new("runc").args([
            OsString::from("--root"),
            state.join("runc").into_os_string(),
            OsString::from("list"),
            OsString::from("--quiet"),
        ]))
        .map_err(TestError::infra)?;
    if !output.success() {
        return Ok(Vec::new());
    }
    Ok(output
        .stdout_text()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn remove_tree(path: &Path) -> Result<(), TestError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TestError::infra(format!(
            "remove owned tree {}: {error}",
            path.display()
        ))),
    }
}
