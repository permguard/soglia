// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Production Candidate-A B6 crash-boundary driver.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};
use soglia_core::config::Config;
use soglia_core::helper::{EnforcerRequest, HelperResponse, SandboxRequest};
use soglia_core::{ExecutionId, ExecutionNonce};
use soglia_supervisor::helpers::Helper;

const HOST_BOUNDARIES: [&str; 4] = [
    "host_intent",
    "host_maps_pinned",
    "host_kernel_validated",
    "host_ready",
];

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ExecutionBoundary {
    Reserved,
    RecordWithoutPolicy,
    Prepared,
    CreatedPaused,
    PolicyActiveBeforeRecord,
    Active,
    PolicyFrozenBeforeRecord,
    SandboxDestroyed,
    PolicyRemovedBeforeRecord,
}

impl ExecutionBoundary {
    const ALL: [Self; 9] = [
        Self::Reserved,
        Self::RecordWithoutPolicy,
        Self::Prepared,
        Self::CreatedPaused,
        Self::PolicyActiveBeforeRecord,
        Self::Active,
        Self::PolicyFrozenBeforeRecord,
        Self::SandboxDestroyed,
        Self::PolicyRemovedBeforeRecord,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Reserved => "01-reserved",
            Self::RecordWithoutPolicy => "02-record-without-policy",
            Self::Prepared => "03-prepared",
            Self::CreatedPaused => "04-created-paused",
            Self::PolicyActiveBeforeRecord => "05-policy-active-before-record",
            Self::Active => "06-active",
            Self::PolicyFrozenBeforeRecord => "07-policy-frozen-before-record",
            Self::SandboxDestroyed => "08-sandbox-destroyed",
            Self::PolicyRemovedBeforeRecord => "09-policy-removed-before-record",
        }
    }

    const fn trace_boundary(self) -> &'static str {
        match self {
            Self::Reserved => "ready_empty",
            Self::RecordWithoutPolicy => "execution_record_without_policy",
            Self::Prepared | Self::CreatedPaused => "prepared_complete",
            Self::PolicyActiveBeforeRecord => "activate_policy_before_record",
            Self::Active => "active_complete",
            Self::PolicyFrozenBeforeRecord => "freeze_policy_before_record",
            Self::SandboxDestroyed => "frozen_complete",
            Self::PolicyRemovedBeforeRecord => "destroy_policy_before_record",
        }
    }
}

#[derive(Debug, Serialize)]
struct RecoveryObservation {
    swept: Vec<String>,
    old_generation: u64,
    new_generation: u64,
    old_kernel_ids: KernelIds,
    old_kernel_ids_absent: bool,
    policy_entries: usize,
    cookie_entries: usize,
    tuple_entries: usize,
    ready_manifest: bool,
    verdict: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct KernelIds {
    maps: Vec<u64>,
    programs: Vec<u64>,
    links: Vec<u64>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("b6-driver: {error}");
        std::process::exit(20);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let binary = PathBuf::from(arguments.next().ok_or("missing production binary")?);
    let config_path = PathBuf::from(arguments.next().ok_or("missing configuration")?);
    let evidence = PathBuf::from(arguments.next().ok_or("missing evidence directory")?);
    let tracer = PathBuf::from(arguments.next().ok_or("missing B6 tracer")?);
    let mode = arguments
        .next()
        .ok_or("missing B6 mode")?
        .into_string()
        .map_err(|_| "B6 mode is not UTF-8")?;
    let case = arguments
        .next()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| "B6 case is not UTF-8".to_owned())
        })
        .transpose()?;
    if arguments.next().is_some() {
        return Err("too many B6 driver arguments".to_owned());
    }
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    let config_yaml = fs::read_to_string(&config_path).map_err(|error| error.to_string())?;
    let config = Config::from_yaml(&config_yaml).map_err(|error| error.to_string())?;
    match mode.as_str() {
        "host-boundaries" => {
            run_host_boundaries(&binary, &config_yaml, &config, &tracer, &evidence)
        }
        "execution-boundaries" => {
            run_execution_boundaries(&binary, &config_yaml, &config, &tracer, &evidence)
        }
        "recovery-interrupted" => {
            run_recovery_interrupted(&binary, &config_yaml, &config, &tracer, &evidence)
        }
        "systemd-host-boundary" => run_systemd_host_boundary(
            &binary,
            &config_yaml,
            &config,
            &tracer,
            &evidence,
            case.as_deref().ok_or("missing systemd host boundary")?,
        ),
        "systemd-execution-boundary" => run_systemd_execution_boundary(
            &binary,
            &config_yaml,
            &config,
            &tracer,
            &evidence,
            case.as_deref().ok_or("missing systemd Execution boundary")?,
        ),
        other => Err(format!("unknown B6 mode: {other}")),
    }
}

fn run_host_boundaries(
    binary: &Path,
    config_yaml: &str,
    config: &Config,
    tracer: &Path,
    root: &Path,
) -> Result<(), String> {
    for boundary in HOST_BOUNDARIES {
        let evidence = root.join(boundary);
        fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
        fs::write(root.join("current-case.txt"), format!("{boundary}\n"))
            .map_err(|error| error.to_string())?;
        let sandbox = start_sandbox(binary, config_yaml)?;
        let enforcer = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
        let enforcer_pid = helper_pid(binary, "__enforcer")?;
        let mut trace = start_trace(
            tracer,
            enforcer_pid,
            state_path(config),
            &config.runtime.bpftool,
            boundary,
            &evidence,
        )?;
        let hello = enforcer.hello(config_yaml);
        fs::write(evidence.join("hello-result.txt"), format!("{hello:?}\n"))
            .map_err(|error| error.to_string())?;
        require_trace_success(&mut trace, boundary)?;
        if enforcer.ensure_running().is_ok() {
            return Err(format!("{boundary}: tracer did not kill the Enforcer"));
        }
        drop(enforcer);
        drop(sandbox);
        recover_and_record(binary, config_yaml, config, &evidence)?;
        pass(&evidence)?;
    }
    fs::write(root.join("current-case.txt"), "complete\n").map_err(|error| error.to_string())?;
    fs::write(root.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

fn run_execution_boundaries(
    binary: &Path,
    config_yaml: &str,
    config: &Config,
    tracer: &Path,
    root: &Path,
) -> Result<(), String> {
    for boundary in ExecutionBoundary::ALL {
        let evidence = root.join(boundary.name());
        fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
        fs::write(
            root.join("current-case.txt"),
            format!("{}\n", boundary.name()),
        )
        .map_err(|error| error.to_string())?;
        run_execution_boundary(
            binary,
            config_yaml,
            config,
            tracer,
            &evidence,
            boundary,
            false,
        )?;
        pass(&evidence)?;
    }
    fs::write(root.join("current-case.txt"), "complete\n").map_err(|error| error.to_string())?;
    fs::write(root.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}

fn run_execution_boundary(
    binary: &Path,
    config_yaml: &str,
    config: &Config,
    tracer: &Path,
    evidence: &Path,
    boundary: ExecutionBoundary,
    systemd_restart: bool,
) -> Result<(), String> {
    let sandbox = start_sandbox(binary, config_yaml)?;
    let enforcer = start_enforcer(binary, config_yaml)?;
    let cgroup_root = config
        .cgroup
        .root
        .as_ref()
        .ok_or("B6 requires an explicit cgroup root")?;
    let id = ExecutionId::generate().map_err(|error| error.to_string())?;
    let nonce = ExecutionNonce::generate().map_err(|error| error.to_string())?;
    let reserved = block_on(sandbox.call(SandboxRequest::Reserve {
        id,
        agent: "b6-hold".to_owned(),
    }))?;
    let HelperResponse::Reserved { cgroup_inode } = reserved else {
        return Err(format!("unexpected reserve response: {reserved:?}"));
    };
    let mut pid = None;
    let mut binding = None;

    if !matches!(boundary, ExecutionBoundary::Reserved) {
        if matches!(boundary, ExecutionBoundary::RecordWithoutPolicy) {
            trace_operation(
                &enforcer,
                binary,
                config,
                tracer,
                evidence,
                boundary.trace_boundary(),
                || {
                    block_on(enforcer.call(EnforcerRequest::Prepare {
                        id,
                        slot: 0,
                        agent: "b6-hold".to_owned(),
                        nonce,
                    }))
                    .map(|_| ())
                },
            )?;
            finish_crashed_case(
                binary,
                config_yaml,
                config,
                sandbox,
                enforcer,
                evidence,
                systemd_restart,
            )?;
            return Ok(());
        }
        block_on(enforcer.call(EnforcerRequest::Prepare {
            id,
            slot: 0,
            agent: "b6-hold".to_owned(),
            nonce,
        }))?;
    }

    if matches!(
        boundary,
        ExecutionBoundary::CreatedPaused
            | ExecutionBoundary::PolicyActiveBeforeRecord
            | ExecutionBoundary::Active
            | ExecutionBoundary::PolicyFrozenBeforeRecord
            | ExecutionBoundary::SandboxDestroyed
            | ExecutionBoundary::PolicyRemovedBeforeRecord
    ) {
        let created = block_on(sandbox.call(SandboxRequest::CreatePaused { id }))?;
        let HelperResponse::CreatedPaused {
            pid: created_pid,
            cgroup_inode: paused_inode,
        } = created
        else {
            return Err(format!("unexpected create-paused response: {created:?}"));
        };
        if paused_inode != cgroup_inode {
            return Err("reserved and paused cgroup identities differ".to_owned());
        }
        pid = Some(created_pid);
        fs::write(
            evidence.join("created-paused.json"),
            serde_json::to_vec_pretty(&json!({
                "pid": created_pid,
                "cgroup_inode": cgroup_inode,
                "proc_cgroup": fs::read_to_string(format!("/proc/{created_pid}/cgroup")).map_err(|error| error.to_string())?,
                "cgroup_procs": fs::read_to_string(cgroup_root.join("executions").join(id.tag().to_string()).join("cgroup.procs")).map_err(|error| error.to_string())?
            }))
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    }

    if matches!(
        boundary,
        ExecutionBoundary::PolicyActiveBeforeRecord
            | ExecutionBoundary::Active
            | ExecutionBoundary::PolicyFrozenBeforeRecord
            | ExecutionBoundary::SandboxDestroyed
            | ExecutionBoundary::PolicyRemovedBeforeRecord
    ) {
        let verified = block_on(enforcer.call(EnforcerRequest::VerifyPlacement {
            id,
            pid: pid.ok_or("created-paused PID is absent")?,
        }))?;
        let HelperResponse::PlacementVerified {
            binding: verified_binding,
        } = verified
        else {
            return Err(format!("unexpected placement response: {verified:?}"));
        };
        binding = Some(verified_binding);
        if matches!(boundary, ExecutionBoundary::PolicyActiveBeforeRecord) {
            trace_operation(
                &enforcer,
                binary,
                config,
                tracer,
                evidence,
                boundary.trace_boundary(),
                || block_on(enforcer.call(EnforcerRequest::Activate { id, binding })).map(|_| ()),
            )?;
            finish_crashed_case(
                binary,
                config_yaml,
                config,
                sandbox,
                enforcer,
                evidence,
                systemd_restart,
            )?;
            return Ok(());
        }
        block_on(enforcer.call(EnforcerRequest::Activate { id, binding }))?;
    }

    if matches!(
        boundary,
        ExecutionBoundary::PolicyFrozenBeforeRecord
            | ExecutionBoundary::SandboxDestroyed
            | ExecutionBoundary::PolicyRemovedBeforeRecord
    ) {
        if matches!(boundary, ExecutionBoundary::PolicyFrozenBeforeRecord) {
            trace_operation(
                &enforcer,
                binary,
                config,
                tracer,
                evidence,
                boundary.trace_boundary(),
                || block_on(enforcer.call(EnforcerRequest::Freeze { tag: id.tag() })).map(|_| ()),
            )?;
            finish_crashed_case(
                binary,
                config_yaml,
                config,
                sandbox,
                enforcer,
                evidence,
                systemd_restart,
            )?;
            return Ok(());
        }
        block_on(enforcer.call(EnforcerRequest::Freeze { tag: id.tag() }))?;
        block_on(sandbox.call(SandboxRequest::Kill { tag: id.tag() }))?;
        block_on(sandbox.call(SandboxRequest::Destroy { tag: id.tag() }))?;
        if cgroup_root
            .join("executions")
            .join(id.tag().to_string())
            .exists()
        {
            return Err("Sandbox destroy left the Execution cgroup".to_owned());
        }
        if matches!(boundary, ExecutionBoundary::PolicyRemovedBeforeRecord) {
            let frozen_record = fs::read(state_path(config)).map_err(|error| error.to_string())?;
            fs::write(evidence.join("durable-frozen-record.json"), &frozen_record)
                .map_err(|error| error.to_string())?;
            fs::write(
                evidence.join("durable-precondition.json"),
                serde_json::to_vec_pretty(&json!({
                    "phase": "FROZEN",
                    "record_present_before_tracer": true,
                    "record_bytes": frozen_record.len(),
                    "destroy_order": ["remove_policy", "remove_execution_record"]
                }))
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            trace_operation(
                &enforcer,
                binary,
                config,
                tracer,
                evidence,
                boundary.trace_boundary(),
                || block_on(enforcer.call(EnforcerRequest::Destroy { tag: id.tag() })).map(|_| ()),
            )?;
            finish_crashed_case(
                binary,
                config_yaml,
                config,
                sandbox,
                enforcer,
                evidence,
                systemd_restart,
            )?;
            return Ok(());
        }
    }

    trace_operation(
        &enforcer,
        binary,
        config,
        tracer,
        evidence,
        boundary.trace_boundary(),
        || block_on(enforcer.call(EnforcerRequest::Health)).map(|_| ()),
    )?;
    fs::write(
        evidence.join("boundary.json"),
        serde_json::to_vec_pretty(&json!({
            "boundary": boundary,
            "execution_id": id,
            "cgroup_inode": cgroup_inode,
            "pid": pid,
            "binding": binding,
            "trace_boundary": boundary.trace_boundary()
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    finish_crashed_case(
        binary,
        config_yaml,
        config,
        sandbox,
        enforcer,
        evidence,
        systemd_restart,
    )
}

fn run_recovery_interrupted(
    binary: &Path,
    config_yaml: &str,
    config: &Config,
    tracer: &Path,
    evidence: &Path,
) -> Result<(), String> {
    fs::write(evidence.join("current-case.txt"), "recovery-interrupted\n")
        .map_err(|error| error.to_string())?;
    let sandbox = start_sandbox(binary, config_yaml)?;
    drop(sandbox);
    let first = start_enforcer(binary, config_yaml)?;
    drop(first);
    let old = read_state(config)?;
    let old_generation = generation(&old)?;
    let enforcer = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
    let enforcer_pid = helper_pid(binary, "__enforcer")?;
    let mut trace = start_trace(
        tracer,
        enforcer_pid,
        state_path(config),
        &config.runtime.bpftool,
        "recovery_interrupted",
        evidence,
    )?;
    let hello = enforcer.hello(config_yaml);
    fs::write(evidence.join("first-recovery.txt"), format!("{hello:?}\n"))
        .map_err(|error| error.to_string())?;
    require_trace_success(&mut trace, "recovery_interrupted")?;
    drop(enforcer);
    recover_and_record(binary, config_yaml, config, evidence)?;
    let recovered = read_state(config)?;
    if generation(&recovered)? <= old_generation {
        return Err("recovery-interrupted did not advance the generation".to_owned());
    }
    pass(evidence)
}

fn finish_crashed_case(
    binary: &Path,
    config_yaml: &str,
    config: &Config,
    sandbox: Helper,
    enforcer: Helper,
    evidence: &Path,
    systemd_restart: bool,
) -> Result<(), String> {
    if enforcer.ensure_running().is_ok() {
        return Err("the boundary tracer left the Enforcer alive".to_owned());
    }
    drop(enforcer);
    drop(sandbox);
    if systemd_restart {
        fs::write(evidence.join("restart-phase.txt"), "RECOVER\n")
            .map_err(|error| error.to_string())?;
        Err("SYSTEMD_RESTART_REQUIRED".to_owned())
    } else {
        recover_and_record(binary, config_yaml, config, evidence)
    }
}

fn start_sandbox(binary: &Path, config_yaml: &str) -> Result<Helper, String> {
    let helper = Helper::spawn(binary, "sandboxd").map_err(|error| error.to_string())?;
    helper
        .hello(config_yaml)
        .map_err(|error| error.to_string())?;
    helper.ensure_running().map_err(|error| error.to_string())?;
    Ok(helper)
}

fn start_enforcer(binary: &Path, config_yaml: &str) -> Result<Helper, String> {
    let helper = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
    helper
        .hello(config_yaml)
        .map_err(|error| error.to_string())?;
    helper.ensure_running().map_err(|error| error.to_string())?;
    Ok(helper)
}

fn trace_operation<F>(
    enforcer: &Helper,
    binary: &Path,
    config: &Config,
    tracer: &Path,
    evidence: &Path,
    boundary: &str,
    operation: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let pid = helper_pid(binary, "__enforcer")?;
    let mut trace = start_trace(
        tracer,
        pid,
        state_path(config),
        &config.runtime.bpftool,
        boundary,
        evidence,
    )?;
    let result = operation();
    fs::write(
        evidence.join("operation-result.txt"),
        format!("{result:?}\n"),
    )
    .map_err(|error| error.to_string())?;
    require_trace_success(&mut trace, boundary)?;
    if enforcer.ensure_running().is_ok() {
        return Err(format!("{boundary}: traced Enforcer survived"));
    }
    Ok(())
}

fn start_trace(
    tracer: &Path,
    pid: i32,
    state: PathBuf,
    bpftool: &Path,
    boundary: &str,
    evidence: &Path,
) -> Result<Child, String> {
    let ready = evidence.join("trace-ready.json");
    let _ = fs::remove_file(&ready);
    let stdout =
        fs::File::create(evidence.join("trace.stdout")).map_err(|error| error.to_string())?;
    let stderr =
        fs::File::create(evidence.join("trace.stderr")).map_err(|error| error.to_string())?;
    let child = Command::new(tracer)
        .arg(pid.to_string())
        .arg(state)
        .arg(bpftool)
        .arg(boundary)
        .arg(&ready)
        .arg(evidence.join("trace-observation.json"))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("start B6 tracer: {error}"))?;
    let started = Instant::now();
    while !ready.is_file() {
        if started.elapsed() >= Duration::from_secs(5) {
            return Err(format!(
                "UNPROVEN: tracer did not seize {pid} for {boundary}"
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(child)
}

fn require_trace_success(child: &mut Child, boundary: &str) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return if status.success() {
                Ok(())
            } else {
                Err(format!("{boundary}: B6 tracer exited {status}"))
            };
        }
        if started.elapsed() >= Duration::from_secs(35) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("UNPROVEN: {boundary} tracer did not complete"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn recover_and_record(
    binary: &Path,
    config_yaml: &str,
    config: &Config,
    evidence: &Path,
) -> Result<(), String> {
    let before = read_state(config)?;
    let old_generation = generation(&before)?;
    let old_ids = kernel_ids(&before);
    let sandbox = start_sandbox(binary, config_yaml)?;
    drop(sandbox);
    let enforcer = Helper::spawn_enforcer(binary).map_err(|error| error.to_string())?;
    let swept = enforcer
        .hello(config_yaml)
        .map_err(|error| error.to_string())?;
    enforcer
        .ensure_running()
        .map_err(|error| error.to_string())?;
    let after = read_state(config)?;
    let new_generation = generation(&after)?;
    let old_kernel_ids_absent = old_ids_absent(config, &old_ids)?;
    let policy_entries = map_entries(config, &after, "soglia_policy")?;
    let cookie_entries = map_entries(config, &after, "soglia_cookie_a")?;
    let tuple_entries = map_entries(config, &after, "soglia_tuples")?;
    let ready_manifest = after.get("phase").and_then(Value::as_str) == Some("READY");
    let valid = new_generation > old_generation
        && old_kernel_ids_absent
        && policy_entries == 0
        && cookie_entries == 0
        && tuple_entries == 0
        && ready_manifest;
    let observation = RecoveryObservation {
        swept,
        old_generation,
        new_generation,
        old_kernel_ids: old_ids,
        old_kernel_ids_absent,
        policy_entries,
        cookie_entries,
        tuple_entries,
        ready_manifest,
        verdict: if valid { "PASS" } else { "FAIL" },
    };
    fs::write(
        evidence.join("recovery.json"),
        serde_json::to_vec_pretty(&observation).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    drop(enforcer);
    if valid {
        Ok(())
    } else {
        Err("B6 recovery did not establish a clean newer READY generation".to_owned())
    }
}

fn helper_pid(binary: &Path, role: &str) -> Result<i32, String> {
    let own = std::process::id();
    let expected = fs::canonicalize(binary).map_err(|error| error.to_string())?;
    let started = Instant::now();
    loop {
        let mut matches = Vec::new();
        let task = fs::read_dir(format!("/proc/{own}/task")).map_err(|error| error.to_string())?;
        for entry in task {
            let tid = entry
                .map_err(|error| error.to_string())?
                .file_name()
                .to_string_lossy()
                .into_owned();
            let children =
                fs::read_to_string(format!("/proc/{own}/task/{tid}/children")).unwrap_or_default();
            for child in children.split_whitespace() {
                let Ok(pid) = child.parse::<i32>() else {
                    continue;
                };
                let exe = fs::read_link(format!("/proc/{pid}/exe")).ok();
                let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                if exe.as_ref().is_some_and(|path| path == &expected)
                    && cmdline
                        .split(|byte| *byte == 0)
                        .any(|argument| argument == role.as_bytes())
                {
                    matches.push(pid);
                }
            }
        }
        matches.sort_unstable();
        matches.dedup();
        if matches.len() == 1 {
            return Ok(matches[0]);
        }
        if started.elapsed() >= Duration::from_secs(2) {
            return Err(format!(
                "expected one direct {role} child, observed {matches:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn block_on<F>(future: F) -> Result<HelperResponse, String>
where
    F: std::future::Future<
            Output = Result<HelperResponse, soglia_supervisor::helpers::HelperError>,
        >,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(future)
        .map_err(|error| error.to_string())
}

fn state_path(config: &Config) -> PathBuf {
    config.runtime.state_dir.join("cgroup-bpf/state.json")
}

fn read_state(config: &Config) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(state_path(config)).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

fn generation(state: &Value) -> Result<u64, String> {
    state
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or("state omitted generation".to_owned())
}

fn kernel_ids(state: &Value) -> KernelIds {
    fn field(state: &Value, name: &str) -> Vec<u64> {
        let mut ids = state
            .get(name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("id").and_then(Value::as_u64))
            .filter(|id| *id != 0)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
    KernelIds {
        maps: field(state, "maps"),
        programs: field(state, "programs"),
        links: field(state, "links"),
    }
}

fn old_ids_absent(config: &Config, old: &KernelIds) -> Result<bool, String> {
    for (kind, ids) in [
        ("prog", &old.programs),
        ("link", &old.links),
        ("map", &old.maps),
    ] {
        let old = ids.iter().copied().collect::<BTreeSet<_>>();
        let output = Command::new(&config.runtime.bpftool)
            .args(["-j", kind, "show"])
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        let values: Vec<Value> =
            serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
        if values
            .iter()
            .filter_map(|value| value.get("id").and_then(Value::as_u64))
            .any(|id| old.contains(&id))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn map_entries(config: &Config, state: &Value, name: &str) -> Result<usize, String> {
    let pin = state
        .get("maps")
        .and_then(Value::as_array)
        .and_then(|maps| {
            maps.iter()
                .find(|map| map.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|map| map.get("pin"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("state omitted {name}"))?;
    let output = Command::new(&config.runtime.bpftool)
        .args(["-j", "map", "dump", "pinned", pin])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let entries: Vec<Value> =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    Ok(entries.len())
}

fn pass(evidence: &Path) -> Result<(), String> {
    fs::write(evidence.join("verdict.txt"), "PASS\n").map_err(|error| error.to_string())
}
