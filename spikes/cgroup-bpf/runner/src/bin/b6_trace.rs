// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Qualification-only ptrace controller for exact B6 durable-state boundaries.

use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nix::sys::ptrace::{self, Options};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use serde::Serialize;
use serde_json::{Value, json};

const TRACE_OPTIONS: Options = Options::PTRACE_O_TRACESYSGOOD
    .union(Options::PTRACE_O_TRACECLONE)
    .union(Options::PTRACE_O_TRACEFORK)
    .union(Options::PTRACE_O_TRACEEXEC);

#[derive(Clone, Debug)]
struct SyscallEntry {
    number: i64,
    arguments: [u64; 6],
}

#[derive(Debug, Serialize)]
struct Observation {
    schema: u32,
    boundary: String,
    root_pid: i32,
    traced_threads: Vec<i32>,
    yama_ptrace_scope: String,
    rename_to_state_succeeded: bool,
    parent_directory_fsync_succeeded: bool,
    state_sha256: String,
    state: Value,
    policy_entries: Value,
    recorded_pin_count: usize,
    existing_recorded_pins: Vec<String>,
    matched_at_boottime_seconds: f64,
    kill_signal: String,
    verdict: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("b6-trace: {error}");
        std::process::exit(20);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let root_pid = parse_pid(args.next().ok_or("missing tracee PID")?)?;
    let state_path = PathBuf::from(args.next().ok_or("missing state path")?);
    let bpftool = PathBuf::from(args.next().ok_or("missing bpftool path")?);
    let boundary = args
        .next()
        .ok_or("missing boundary")?
        .into_string()
        .map_err(|_| "boundary is not UTF-8")?;
    let ready = PathBuf::from(args.next().ok_or("missing ready path")?);
    let evidence = PathBuf::from(args.next().ok_or("missing evidence path")?);
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let parent = state_path.parent().ok_or("state path has no parent")?;
    let yama = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .unwrap_or_else(|error| format!("UNAVAILABLE: {error}"));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut tracees = BTreeSet::new();
    let mut pending: HashMap<Pid, Option<SyscallEntry>> = HashMap::new();
    let options = trace_options_for_boundary(&boundary);
    for tid in task_ids(root_pid)? {
        ptrace::seize(tid, options).map_err(|error| format!("PTRACE_SEIZE {tid}: {error}"))?;
        ptrace::interrupt(tid).map_err(|error| format!("PTRACE_INTERRUPT {tid}: {error}"))?;
        tracees.insert(tid);
        pending.insert(tid, None);
    }
    wait_for_initial_stops(&tracees, deadline)?;
    fs::write(
        &ready,
        serde_json::to_vec_pretty(&json!({
            "status": "SEIZED",
            "root_pid": root_pid.as_raw(),
            "threads": tracees.iter().map(|pid| pid.as_raw()).collect::<Vec<_>>(),
            "yama_ptrace_scope": yama.trim()
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    for tid in &tracees {
        ptrace::syscall(*tid, None).map_err(|error| format!("resume {tid}: {error}"))?;
    }

    let mut renamed = false;
    let mut durable_state = false;
    let mut last_snapshot = String::new();
    loop {
        if Instant::now() >= deadline {
            detach_all(&tracees);
            return Err(format!("UNPROVEN: boundary {boundary} was not observed"));
        }
        let status = waitpid(None, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG))
            .map_err(|error| format!("waitpid: {error}"))?;
        match status {
            WaitStatus::StillAlive => {
                std::thread::sleep(Duration::from_millis(1));
            }
            WaitStatus::PtraceSyscall(tid) => {
                let slot = pending.entry(tid).or_insert(None);
                if let Some(entry) = slot.take() {
                    let result = syscall_result(tid)?;
                    if result == 0
                        && entry.number == libc::SYS_listen
                        && startup_listener_port(&boundary).is_some_and(|port| {
                            listener_has_port(tid, entry.arguments[0], port).unwrap_or(false)
                        })
                    {
                        let port = startup_listener_port(&boundary)
                            .ok_or("startup listener boundary omitted its port")?;
                        return qualify_startup_listener_boundary(
                            root_pid,
                            tid,
                            &tracees,
                            entry.arguments[0],
                            port,
                            yama.trim(),
                            &evidence,
                            deadline,
                        );
                    }
                    if startup_listener_port(&boundary).is_some() {
                        resume(tid)?;
                        continue;
                    }
                    if result == 0 && is_state_rename(tid, &entry, &state_path)? {
                        renamed = true;
                    }
                    if result == 0 && renamed && is_parent_fsync(tid, &entry, parent)? {
                        durable_state = true;
                    }
                    record_snapshot(
                        &state_path,
                        &bpftool,
                        durable_state,
                        &evidence.with_extension("jsonl"),
                        &mut last_snapshot,
                    )?;
                    if boundary_matches(&boundary, &state_path, &bpftool, durable_state)? {
                        let state = read_json(&state_path)?;
                        let traced_state = state.get("state").unwrap_or(&state);
                        let policy_entries = policy_entries(traced_state, &bpftool)?;
                        let state_bytes =
                            fs::read(&state_path).map_err(|error| error.to_string())?;
                        let existing_recorded_pins = existing_pins(traced_state);
                        let observed = Observation {
                            schema: 1,
                            boundary: boundary.clone(),
                            root_pid: root_pid.as_raw(),
                            traced_threads: tracees.iter().map(|pid| pid.as_raw()).collect(),
                            yama_ptrace_scope: yama.trim().to_owned(),
                            rename_to_state_succeeded: renamed,
                            parent_directory_fsync_succeeded: durable_state,
                            state_sha256: sha256(&state_bytes),
                            state,
                            policy_entries,
                            recorded_pin_count: existing_recorded_pins.len(),
                            existing_recorded_pins,
                            matched_at_boottime_seconds: boottime_seconds()?,
                            kill_signal: "SIGKILL".to_owned(),
                            verdict: "MATCHED".to_owned(),
                        };
                        fs::write(
                            &evidence,
                            serde_json::to_vec_pretty(&observed)
                                .map_err(|error| error.to_string())?,
                        )
                        .map_err(|error| error.to_string())?;
                        kill(root_pid, Signal::SIGKILL)
                            .map_err(|error| format!("kill traced Enforcer: {error}"))?;
                        detach_all(&tracees);
                        return Ok(());
                    }
                } else {
                    *slot = Some(read_syscall(tid)?);
                }
                resume(tid)?;
            }
            WaitStatus::PtraceEvent(tid, _, event) => {
                if event == libc_event_clone() || event == libc_event_fork() {
                    let child_raw = ptrace::getevent(tid)
                        .map_err(|error| format!("PTRACE_GETEVENTMSG {tid}: {error}"))?;
                    let child =
                        Pid::from_raw(i32::try_from(child_raw).map_err(|_| "child PID overflow")?);
                    tracees.insert(child);
                    pending.insert(child, None);
                }
                resume(tid)?;
            }
            WaitStatus::Stopped(tid, signal) => {
                let delivered = if matches!(signal, Signal::SIGSTOP | Signal::SIGTRAP) {
                    None
                } else {
                    Some(signal)
                };
                ptrace::syscall(tid, delivered)
                    .map_err(|error| format!("resume stopped {tid}: {error}"))?;
            }
            WaitStatus::Exited(tid, _) | WaitStatus::Signaled(tid, _, _) => {
                tracees.remove(&tid);
                pending.remove(&tid);
                if tid == root_pid {
                    return Err(format!(
                        "UNPROVEN: traced Enforcer exited before boundary {boundary}"
                    ));
                }
            }
            WaitStatus::Continued(_) => {}
        }
    }
}

fn record_snapshot(
    state_path: &Path,
    bpftool: &Path,
    durable: bool,
    evidence: &Path,
    last: &mut String,
) -> Result<(), String> {
    if !state_path.is_file() {
        return Ok(());
    }
    let state = read_json(state_path)?;
    let policies = policy_entries(&state, bpftool)?;
    let snapshot = json!({
        "phase": state.get("phase"),
        "executions": state.get("executions"),
        "policy_entries": policies.as_array().map_or(0, Vec::len),
        "policy_state": first_policy_state(&policies),
        "durable_state_seen": durable,
        "existing_recorded_pin_count": existing_pins(&state).len()
    });
    let encoded = serde_json::to_string(&snapshot).map_err(|error| error.to_string())?;
    if encoded == *last {
        return Ok(());
    }
    *last = encoded.clone();
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(evidence)
        .map_err(|error| error.to_string())?;
    writeln!(output, "{encoded}").map_err(|error| error.to_string())
}

fn parse_pid(value: std::ffi::OsString) -> Result<Pid, String> {
    let raw = value
        .to_string_lossy()
        .parse::<i32>()
        .map_err(|error| format!("invalid PID: {error}"))?;
    Ok(Pid::from_raw(raw))
}

fn task_ids(pid: Pid) -> Result<Vec<Pid>, String> {
    let mut tids = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task")).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let tid = entry
            .file_name()
            .to_string_lossy()
            .parse::<i32>()
            .map_err(|error| error.to_string())?;
        tids.push(Pid::from_raw(tid));
    }
    tids.sort_by_key(|pid| pid.as_raw());
    Ok(tids)
}

fn wait_for_initial_stops(tracees: &BTreeSet<Pid>, deadline: Instant) -> Result<(), String> {
    let mut stopped = BTreeSet::new();
    while stopped.len() != tracees.len() {
        if Instant::now() >= deadline {
            return Err("timed out waiting for initial ptrace stops".to_owned());
        }
        match waitpid(None, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG))
            .map_err(|error| error.to_string())?
        {
            WaitStatus::Stopped(pid, _) | WaitStatus::PtraceEvent(pid, _, _) => {
                stopped.insert(pid);
            }
            WaitStatus::StillAlive => std::thread::sleep(Duration::from_millis(1)),
            status => return Err(format!("unexpected initial ptrace status: {status:?}")),
        }
    }
    Ok(())
}

fn read_syscall(pid: Pid) -> Result<SyscallEntry, String> {
    let line = fs::read_to_string(format!("/proc/{pid}/syscall"))
        .map_err(|error| format!("read syscall for {pid}: {error}"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 7 {
        return Err(format!("unexpected /proc/{pid}/syscall: {line:?}"));
    }
    let number = fields[0]
        .parse::<i64>()
        .map_err(|error| format!("syscall number: {error}"))?;
    let mut arguments = [0_u64; 6];
    for (index, field) in fields[1..7].iter().enumerate() {
        arguments[index] = parse_u64(field)?;
    }
    Ok(SyscallEntry { number, arguments })
}

fn parse_u64(value: &str) -> Result<u64, String> {
    let value = value.trim_start_matches("0x");
    u64::from_str_radix(value, 16).map_err(|error| error.to_string())
}

#[cfg(target_arch = "aarch64")]
fn syscall_result(pid: Pid) -> Result<i64, String> {
    let registers = ptrace::getregs(pid).map_err(|error| error.to_string())?;
    Ok(registers.regs[0] as i64)
}

#[cfg(target_arch = "x86_64")]
fn syscall_result(pid: Pid) -> Result<i64, String> {
    let registers = ptrace::getregs(pid).map_err(|error| error.to_string())?;
    Ok(registers.rax as i64)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("B6 ptrace qualification supports aarch64 and x86_64 only");

fn is_state_rename(pid: Pid, entry: &SyscallEntry, state: &Path) -> Result<bool, String> {
    let destination = if entry.number == libc_sys_rename() {
        Some(entry.arguments[1])
    } else if entry.number == libc_sys_renameat() || entry.number == libc_sys_renameat2() {
        Some(entry.arguments[3])
    } else {
        None
    };
    let Some(destination) = destination else {
        return Ok(false);
    };
    Ok(read_c_string(pid, destination)? == state.as_os_str().as_encoded_bytes())
}

fn is_parent_fsync(pid: Pid, entry: &SyscallEntry, parent: &Path) -> Result<bool, String> {
    if entry.number != libc_sys_fsync() {
        return Ok(false);
    }
    let fd = i32::try_from(entry.arguments[0]).map_err(|_| "fsync fd overflow")?;
    let target = fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .map_err(|error| format!("read fsync fd target: {error}"))?;
    Ok(target == parent)
}

fn read_c_string(pid: Pid, address: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let word_size = std::mem::size_of::<libc::c_long>();
    for offset in (0..4096_usize).step_by(word_size) {
        let address = usize::try_from(address).map_err(|_| "address overflow")? + offset;
        let word = ptrace::read(pid, address as ptrace::AddressType)
            .map_err(|error| format!("PTRACE_PEEKDATA {pid}: {error}"))?;
        for byte in word.to_ne_bytes() {
            if byte == 0 {
                return Ok(bytes);
            }
            bytes.push(byte);
        }
    }
    Err("tracee path exceeds 4096 bytes".to_owned())
}

fn startup_listener_port(boundary: &str) -> Option<u16> {
    boundary
        .strip_prefix("startup_listener_bound:")?
        .parse()
        .ok()
}

fn trace_options_for_boundary(boundary: &str) -> Options {
    if startup_listener_port(boundary).is_some() {
        // The listener is created before Tokio has necessarily spawned its worker threads. Those
        // workers must remain untraced so they can accept the qualification request while the
        // startup thread advances one instruction at a time and cannot reach READY.
        Options::PTRACE_O_TRACESYSGOOD
    } else {
        TRACE_OPTIONS
    }
}

fn listener_has_port(pid: Pid, fd: u64, expected_port: u16) -> Result<bool, String> {
    let fd = i32::try_from(fd).map_err(|_| "listener fd overflow")?;
    let target = fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .map_err(|error| format!("read listener fd target: {error}"))?;
    let target = target.to_string_lossy();
    let inode = target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("listener fd did not name a socket: {target}"))?;
    let tcp = fs::read_to_string(format!("/proc/{pid}/net/tcp"))
        .map_err(|error| format!("read tracee TCP table: {error}"))?;
    for line in tcp.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 || fields[3] != "0A" || fields[9] != inode {
            continue;
        }
        let Some((_, port)) = fields[1].split_once(':') else {
            continue;
        };
        return Ok(u16::from_str_radix(port, 16).ok() == Some(expected_port));
    }
    Ok(false)
}

fn qualify_startup_listener_boundary(
    root_pid: Pid,
    matched_tid: Pid,
    tracees: &BTreeSet<Pid>,
    listener_fd: u64,
    port: u16,
    yama: &str,
    evidence: &Path,
    deadline: Instant,
) -> Result<(), String> {
    for other in tracees
        .iter()
        .copied()
        .filter(|other| *other != matched_tid)
    {
        let _ = ptrace::detach(other, None);
    }

    let (response_tx, response_rx) = mpsc::channel();
    std::thread::spawn(move || {
        loop {
            match startup_admission_probe(port) {
                Ok(response) => {
                    let _ = response_tx.send(response);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    });

    let response = loop {
        if Instant::now() >= deadline {
            let _ = ptrace::detach(matched_tid, None);
            return Err(
                "UNPROVEN: no admission response was observed before startup.ready".to_owned(),
            );
        }
        ptrace::step(matched_tid, None)
            .map_err(|error| format!("single-step startup listener thread: {error}"))?;
        loop {
            match waitpid(
                matched_tid,
                Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG),
            )
            .map_err(|error| format!("wait for startup single-step: {error}"))?
            {
                WaitStatus::StillAlive => std::thread::sleep(Duration::from_micros(100)),
                WaitStatus::Stopped(_, _) | WaitStatus::PtraceEvent(_, _, _) => break,
                status => {
                    return Err(format!(
                        "startup listener thread exited during qualification: {status:?}"
                    ));
                }
            }
        }
        if let Ok(response) = response_rx.try_recv() {
            break response;
        }
    };

    let verdict = if response.0 == 503 { "MATCHED" } else { "FAIL" };
    fs::write(
        evidence,
        serde_json::to_vec_pretty(&json!({
            "schema": 1,
            "boundary": "startup_listener_bound",
            "root_pid": root_pid.as_raw(),
            "matched_tid": matched_tid.as_raw(),
            "listener_fd": listener_fd,
            "listener_port": port,
            "traced_threads": tracees.iter().map(|pid| pid.as_raw()).collect::<Vec<_>>(),
            "yama_ptrace_scope": yama,
            "request": "POST /v1/execute/probe",
            "response_status": response.0,
            "response_head": response.1,
            "matched_at_boottime_seconds": boottime_seconds()?,
            "verdict": verdict
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if response.0 != 503 {
        let _ = ptrace::detach(matched_tid, None);
        return Err(format!(
            "FAIL: pre-READY admission returned HTTP {} instead of 503",
            response.0
        ));
    }

    let release = evidence.with_extension("release");
    while !release.is_file() {
        if Instant::now() >= deadline {
            let _ = ptrace::detach(matched_tid, None);
            return Err("UNPROVEN: startup listener boundary was not released".to_owned());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    ptrace::detach(matched_tid, None)
        .map_err(|error| format!("release startup listener thread: {error}"))
}

fn startup_admission_probe(port: u16) -> Result<(u16, String), String> {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(50))
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|error| error.to_string())?;
    let body = b"sleep 1";
    write!(
        stream,
        "POST /v1/execute/probe HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .map_err(|error| error.to_string())?;
    stream.write_all(body).map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    let head = response.lines().next().unwrap_or_default().to_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("HTTP response omitted status: {head:?}"))?
        .parse::<u16>()
        .map_err(|error| error.to_string())?;
    Ok((status, head))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_boundary_leaves_new_workers_untraced() {
        let listener = trace_options_for_boundary("startup_listener_bound:18116");
        assert!(listener.contains(Options::PTRACE_O_TRACESYSGOOD));
        assert!(!listener.contains(Options::PTRACE_O_TRACECLONE));
        assert!(!listener.contains(Options::PTRACE_O_TRACEFORK));

        let durable = trace_options_for_boundary("host_intent");
        assert!(durable.contains(Options::PTRACE_O_TRACECLONE));
        assert!(durable.contains(Options::PTRACE_O_TRACEFORK));
        assert!(durable.contains(Options::PTRACE_O_TRACEEXEC));
    }
}

fn boundary_matches(
    boundary: &str,
    state_path: &Path,
    bpftool: &Path,
    durable: bool,
) -> Result<bool, String> {
    if !state_path.is_file() {
        return Ok(false);
    }
    let state = read_json(state_path)?;
    if boundary == "uninstall_intent" {
        let recorded = state.get("state").and_then(Value::as_object);
        return Ok(durable
            && state.get("schema").and_then(Value::as_u64) == Some(1)
            && recorded
                .and_then(|value| value.get("phase"))
                .and_then(Value::as_str)
                == Some("READY")
            && recorded
                .and_then(|value| value.get("maps"))
                .and_then(Value::as_array)
                .is_some_and(|maps| maps.len() == 7)
            && recorded
                .and_then(|value| value.get("links"))
                .and_then(Value::as_array)
                .is_some_and(|links| links.len() == 6));
    }
    let phase = state.get("phase").and_then(Value::as_str);
    let maps = state
        .get("maps")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let programs = state
        .get("programs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let links = state
        .get("links")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let map_ids = nonzero_ids(&state, "maps");
    let link_ids = nonzero_ids(&state, "links");
    let executions = state
        .get("executions")
        .and_then(Value::as_object)
        .map_or(0, serde_json::Map::len);
    let policies = policy_entries(&state, bpftool)?;
    let policy_count = policies.as_array().map_or(0, Vec::len);
    let execution_phase = state
        .get("executions")
        .and_then(Value::as_object)
        .and_then(|entries| entries.values().next())
        .and_then(|execution| execution.get("phase"))
        .and_then(Value::as_str);
    let policy_state = first_policy_state(&policies);
    Ok(match boundary {
        "host_intent" => {
            durable
                && phase == Some("INTENT")
                && maps == 7
                && programs == 0
                && links == 6
                && map_ids == 0
                && link_ids == 0
        }
        "host_maps_pinned" => {
            durable
                && phase == Some("INTENT")
                && maps == 7
                && map_ids == 7
                && programs == 0
                && link_ids == 0
        }
        "host_kernel_validated" => {
            durable
                && phase == Some("INTENT")
                && maps == 7
                && map_ids == 7
                && programs == 6
                && link_ids == 6
        }
        "host_ready" => durable && phase == Some("READY") && programs == 6 && link_ids == 6,
        "ready_empty" => phase == Some("READY") && executions == 0 && policy_count == 0,
        "execution_record_without_policy" => {
            durable
                && executions == 1
                && execution_phase == Some("NETWORK_PREPARED_FROZEN")
                && policy_count == 0
        }
        "activate_policy_before_record" => {
            executions == 1
                && execution_phase == Some("NETWORK_PREPARED_FROZEN")
                && policy_state == Some(1)
        }
        "prepared_complete" => {
            executions == 1
                && execution_phase == Some("NETWORK_PREPARED_FROZEN")
                && policy_state == Some(0)
        }
        "active_complete" => {
            executions == 1 && execution_phase == Some("ACTIVE") && policy_state == Some(1)
        }
        "freeze_policy_before_record" => {
            executions == 1 && execution_phase == Some("ACTIVE") && policy_state == Some(0)
        }
        "destroy_policy_before_record" => {
            // The FROZEN record was durably published by the completed Freeze request before this
            // tracer was attached. The observed internal window starts when Destroy removes the
            // policy and ends at its next durable record publication.
            executions == 1 && execution_phase == Some("FROZEN") && policy_count == 0
        }
        "frozen_complete" => {
            executions == 1 && execution_phase == Some("FROZEN") && policy_state == Some(0)
        }
        "recovery_interrupted" => {
            let expected = maps + links;
            let existing = existing_pins(&state).len();
            durable && phase == Some("INTENT") && existing > 0 && existing < expected
        }
        "uninstall_intent" => unreachable!("handled before the host-state decoder"),
        other => return Err(format!("unknown B6 boundary: {other}")),
    })
}

fn existing_pins(state: &Value) -> Vec<String> {
    let mut pins = Vec::new();
    for field in ["maps", "links"] {
        if let Some(entries) = state.get(field).and_then(Value::as_array) {
            for entry in entries {
                if let Some(pin) = entry.get("pin").and_then(Value::as_str)
                    && Path::new(pin).exists()
                {
                    pins.push(pin.to_owned());
                }
            }
        }
    }
    pins.sort();
    pins
}

fn nonzero_ids(state: &Value, field: &str) -> usize {
    state
        .get(field)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry.get("id").and_then(Value::as_u64).unwrap_or(0) != 0)
                .count()
        })
        .unwrap_or(0)
}

fn policy_entries(state: &Value, bpftool: &Path) -> Result<Value, String> {
    let Some(pin) = state
        .get("maps")
        .and_then(Value::as_array)
        .and_then(|maps| {
            maps.iter()
                .find(|map| map.get("name").and_then(Value::as_str) == Some("soglia_policy"))
        })
        .and_then(|map| map.get("pin"))
        .and_then(Value::as_str)
    else {
        return Ok(json!([]));
    };
    if !Path::new(pin).exists() {
        return Ok(json!([]));
    }
    let output = Command::new(bpftool)
        .args(["-j", "map", "dump", "pinned", pin])
        .output()
        .map_err(|error| format!("run bpftool: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "bpftool policy dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())
}

fn first_policy_state(entries: &Value) -> Option<u32> {
    let bytes = entries.as_array()?.first()?.get("value")?.as_array()?;
    let mut state = [0_u8; 4];
    for (target, value) in state.iter_mut().zip(bytes.iter().take(4)) {
        *target = if let Some(number) = value.as_u64() {
            u8::try_from(number).ok()?
        } else {
            u8::from_str_radix(value.as_str()?.trim_start_matches("0x"), 16).ok()?
        };
    }
    Some(u32::from_ne_bytes(state))
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn boottime_seconds() -> Result<f64, String> {
    let uptime = fs::read_to_string("/proc/uptime").map_err(|error| error.to_string())?;
    uptime
        .split_whitespace()
        .next()
        .ok_or("/proc/uptime is empty".to_owned())?
        .parse::<f64>()
        .map_err(|error| error.to_string())
}

fn resume(pid: Pid) -> Result<(), String> {
    ptrace::syscall(pid, None).map_err(|error| format!("resume {pid}: {error}"))
}

fn detach_all(tracees: &BTreeSet<Pid>) {
    for pid in tracees {
        let _ = ptrace::detach(*pid, None);
    }
}

const fn libc_event_clone() -> i32 {
    libc::PTRACE_EVENT_CLONE
}

const fn libc_event_fork() -> i32 {
    libc::PTRACE_EVENT_FORK
}

const fn libc_sys_fsync() -> i64 {
    libc::SYS_fsync
}

#[cfg(target_arch = "x86_64")]
const fn libc_sys_rename() -> i64 {
    libc::SYS_rename
}

#[cfg(target_arch = "aarch64")]
const fn libc_sys_rename() -> i64 {
    -1
}

const fn libc_sys_renameat() -> i64 {
    libc::SYS_renameat
}

const fn libc_sys_renameat2() -> i64 {
    libc::SYS_renameat2
}
