// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end trusted-attribution harness for S1 of the cgroup-BPF spike.
//!
//! EXPERIMENTAL: this is spike machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    borrow::Borrow,
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap, MapData, RingBuf},
    programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps,
        links::{FdLink, PinnedLink},
    },
};

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
    "soglia_staging",
];
const LINK_NAMES: [&str; 6] = [
    "sock_create",
    "connect4",
    "connect6",
    "sendmsg4",
    "sendmsg6",
    "sock_ops",
];
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

struct Config {
    object: PathBuf,
    cgroup: PathBuf,
    map_pin_root: PathBuf,
    link_pin_root: PathBuf,
    netns: String,
    agent: PathBuf,
    execution_id: String,
    execution_ip: Ipv4Addr,
    exec_ident: u64,
    ready_file: PathBuf,
    go_file: PathBuf,
    host_ready_file: PathBuf,
    placement_ready_file: PathBuf,
    placement_captured_file: PathBuf,
    agent_ready_file: PathBuf,
    agent_go_file: PathBuf,
    membership_ready_file: PathBuf,
    membership_captured_file: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let object = next_path(&mut args, "BPF object")?;
        let cgroup = next_path(&mut args, "Execution cgroup")?;
        let map_pin_root = next_path(&mut args, "map pin root")?;
        let link_pin_root = next_path(&mut args, "link pin root")?;
        let netns = next_string(&mut args, "network namespace")?;
        let agent = next_path(&mut args, "agent binary")?;
        let execution_id = next_string(&mut args, "Execution identity")?;
        let execution_ip = next_string(&mut args, "Execution IPv4 address")?
            .parse()
            .map_err(|error| format!("parse Execution IPv4 address: {error}"))?;
        let exec_ident = next_string(&mut args, "candidate-C identity")?
            .parse()
            .map_err(|error| format!("parse candidate-C identity: {error}"))?;
        let ready_file = next_path(&mut args, "ready file")?;
        let go_file = next_path(&mut args, "go file")?;
        let host_ready_file = next_path(&mut args, "host launcher ready file")?;
        let placement_ready_file = next_path(&mut args, "host placement ready file")?;
        let placement_captured_file = next_path(&mut args, "host placement captured file")?;
        let agent_ready_file = next_path(&mut args, "agent ready file")?;
        let agent_go_file = next_path(&mut args, "agent go file")?;
        let membership_ready_file = next_path(&mut args, "membership ready file")?;
        let membership_captured_file = next_path(&mut args, "membership captured file")?;
        if args.next().is_some() {
            return Err("unexpected extra arguments".to_owned());
        }
        Ok(Self {
            object,
            cgroup,
            map_pin_root,
            link_pin_root,
            netns,
            agent,
            execution_id,
            execution_ip,
            exec_ident,
            ready_file,
            go_file,
            host_ready_file,
            placement_ready_file,
            placement_captured_file,
            agent_ready_file,
            agent_go_file,
            membership_ready_file,
            membership_captured_file,
        })
    }
}

fn next_path(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, String> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}"))
}

fn next_string(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<String, String> {
    args.next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| format!("missing or non-UTF-8 {name}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S1 ATTRIBUTION ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    fs::create_dir_all(&config.map_pin_root).map_err(display_error("create map pin root"))?;
    fs::create_dir_all(&config.link_pin_root).map_err(display_error("create link pin root"))?;

    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &config.exec_ident, true)
        .default_map_pin_directory(&config.map_pin_root);

    println!("test=S1");
    println!("object={}", config.object.display());
    println!("cgroup={}", config.cgroup.display());
    println!("netns={}", config.netns);
    println!("execution_id={}", config.execution_id);
    println!("execution_ip={}", config.execution_ip);
    println!("candidate_c_ident={}", config.exec_ident);
    println!("proxy=10.200.255.1:15001");
    println!("resolve_timeout_ms={}", RESOLVE_TIMEOUT.as_millis());

    let mut bpf = loader
        .load_file(&config.object)
        .map_err(|error| format!("load {}: {error:#}", config.object.display()))?;
    let cgroup = File::open(&config.cgroup)
        .map_err(|error| format!("open cgroup {}: {error}", config.cgroup.display()))?;
    let mut links = attach_all(&mut bpf, &cgroup, &config.link_pin_root)?;

    let result = exercise(&mut bpf, &config);
    println!("state=CLEANUP_BEGIN");
    cleanup_links(&mut links);
    drop(bpf);
    remove_pins(&config);
    println!("state=CLEANUP_COMPLETE");
    result
}

fn exercise(bpf: &mut Ebpf, config: &Config) -> Result<(), String> {
    let policy_map = bpf
        .take_map("policy_local")
        .ok_or("policy_local map not found")?;
    let mut policy = Array::<_, u64>::try_from(policy_map)
        .map_err(|error| format!("open policy_local: {error:#}"))?;
    policy
        .set(0, 1, 0)
        .map_err(|error| format!("activate policy_local: {error:#}"))?;
    let policy_state = policy
        .get(&0, 0)
        .map_err(|error| format!("read policy_local: {error:#}"))?;
    println!("policy_local[0]={policy_state}");

    let tuples_map = bpf
        .take_map("soglia_tuples")
        .ok_or("soglia_tuples map not found")?;
    let mut tuples = HashMap::<_, [u8; 16], [u8; 64]>::try_from(tuples_map)
        .map_err(|error| format!("open soglia_tuples: {error:#}"))?;
    let mut staging = bpf
        .take_map("soglia_staging")
        .map(|map| {
            HashMap::<_, [u8; 16], [u8; 64]>::try_from(map)
                .map_err(|error| format!("open soglia_staging: {error:#}"))
        })
        .transpose()?;
    let delayed_publication = staging.is_some();
    println!("delayed_publication_mode={delayed_publication}");
    let events_map = bpf
        .take_map("soglia_events")
        .ok_or("soglia_events map not found")?;
    let mut events =
        RingBuf::try_from(events_map).map_err(|error| format!("open soglia_events: {error:#}"))?;

    let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
        .map_err(|error| format!("bind experimental proxy: {error}"))?;
    println!("proxy_state=LISTENING");
    fs::write(&config.ready_file, b"ready\n")
        .map_err(|error| format!("write ready file {}: {error}", config.ready_file.display()))?;
    println!("state=READY_FOR_KERNEL_SNAPSHOT");
    let snapshot_wait = Instant::now();
    while !config.go_file.exists() {
        if snapshot_wait.elapsed() >= Duration::from_secs(30) {
            return Err("timed out waiting for kernel-snapshot release".to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    }
    println!("state=KERNEL_SNAPSHOT_RELEASED");

    let default_operation = if delayed_publication {
        "proxy 65"
    } else {
        "proxy 1"
    };
    let agent_operation =
        env::var("S1_AGENT_OPERATION").unwrap_or_else(|_| default_operation.into());
    let shell = r#"set -euo pipefail
printf '%s\n' "$$" > "$1"
printf 'host_launcher_pid=%s\n' "$$" >&2
kill -STOP "$$"
exec ip netns exec "$2" "$3" "barrier $4 $5 30" "$6""#;
    let mut child = Command::new("bash")
        .args(["-c", shell, "s1-host-launcher"])
        .arg(&config.host_ready_file)
        .arg(&config.netns)
        .arg(&config.agent)
        .arg(&config.agent_ready_file)
        .arg(&config.agent_go_file)
        .arg(&agent_operation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start stopped host launcher: {error}"))?;

    wait_for_file(&config.host_ready_file, Duration::from_secs(5))?;
    let trusted_pid = child.id();
    let announced_host_pid: u32 = fs::read_to_string(&config.host_ready_file)
        .map_err(|error| format!("read host launcher ready file: {error}"))?
        .trim()
        .parse()
        .map_err(|error| format!("parse announced host launcher PID: {error}"))?;
    wait_for_process_stopped(trusted_pid, Duration::from_secs(5))?;
    fs::write(
        config.cgroup.join("cgroup.procs"),
        format!("{trusted_pid}\n"),
    )
    .map_err(|error| format!("place trusted host PID in Execution cgroup: {error}"))?;

    let expected_membership = config
        .cgroup
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| "target cgroup is outside /sys/fs/cgroup".to_owned())?;
    let expected_line = format!(
        "0::/{}",
        expected_membership
            .to_string_lossy()
            .trim_start_matches('/')
    );
    let host_proc_cgroup = fs::read_to_string(format!("/proc/{trusted_pid}/cgroup"))
        .map_err(|error| format!("read stopped host launcher /proc cgroup: {error}"))?;
    let host_cgroup_procs = fs::read_to_string(config.cgroup.join("cgroup.procs"))
        .map_err(|error| format!("read cgroup.procs after host placement: {error}"))?;
    let cgroup_inode = fs::metadata(&config.cgroup)
        .map_err(|error| format!("stat target cgroup: {error}"))?
        .ino();
    let host_pid_matches = announced_host_pid == trusted_pid;
    let host_in_proc_cgroup = host_proc_cgroup.lines().any(|line| line == expected_line);
    let host_in_cgroup_procs = host_cgroup_procs
        .lines()
        .any(|line| line.trim() == trusted_pid.to_string());
    let host_status = fs::read_to_string(format!("/proc/{trusted_pid}/status"))
        .map_err(|error| format!("read stopped host launcher status: {error}"))?;
    let host_stopped = host_status
        .lines()
        .find(|line| line.starts_with("State:"))
        .is_some_and(|line| line.contains("T (stopped)"));
    let host_placement_correct =
        host_pid_matches && host_in_proc_cgroup && host_in_cgroup_procs && host_stopped;
    println!("trusted_host_pid={trusted_pid}");
    println!("announced_host_pid={announced_host_pid}");
    println!("target_cgroup_inode={cgroup_inode}");
    println!("expected_proc_cgroup_line={expected_line:?}");
    println!("host_launcher_proc_cgroup_begin");
    print!("{host_proc_cgroup}");
    println!("host_launcher_proc_cgroup_end");
    println!("target_cgroup_procs_after_host_move_begin");
    print!("{host_cgroup_procs}");
    println!("target_cgroup_procs_after_host_move_end");
    println!("host_pid_matches_trusted_lifecycle={host_pid_matches}");
    println!("host_pid_in_exact_proc_cgroup={host_in_proc_cgroup}");
    println!("host_pid_in_target_cgroup_procs={host_in_cgroup_procs}");
    println!("host_launcher_stopped_before_netns={host_stopped}");
    println!("host_placement_proven={host_placement_correct}");
    fs::write(
        &config.placement_ready_file,
        format!(
            "pid={trusted_pid}\nstatus={}\n",
            if host_placement_correct {
                "CORRECT"
            } else {
                "WRONG"
            }
        ),
    )
    .map_err(|error| format!("write host placement ready file: {error}"))?;
    wait_for_file(&config.placement_captured_file, Duration::from_secs(30))?;
    if !host_placement_correct {
        println!("S1_DIAGNOSTIC_CLASSIFICATION=SUBJECT_PLACEMENT_FAILURE");
        child
            .kill()
            .map_err(|error| format!("kill misplaced stopped launcher: {error}"))?;
        let output = child
            .wait_with_output()
            .map_err(|error| format!("wait for misplaced stopped launcher: {error}"))?;
        println!("host_launcher_status={}", output.status);
        println!(
            "host_launcher_stderr={:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err("trusted host PID placement was not proven".to_owned());
    }
    let continued = Command::new("kill")
        .args(["-CONT", &trusted_pid.to_string()])
        .status()
        .map_err(|error| format!("continue placed host launcher: {error}"))?;
    if !continued.success() {
        return Err(format!("continue placed host launcher failed: {continued}"));
    }
    println!("state=HOST_PID_PLACED_THEN_RELEASED_TO_NETNS");

    let agent_ready_started = Instant::now();
    while !config.agent_ready_file.exists() {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll pre-connection agent: {error}"))?
        {
            let output = child
                .wait_with_output()
                .map_err(|error| format!("collect pre-connection agent failure: {error}"))?;
            println!("agent_preconnection_status={status}");
            println!("agent_preconnection_stdout_begin");
            print!("{}", String::from_utf8_lossy(&output.stdout));
            println!("agent_preconnection_stdout_end");
            println!("agent_preconnection_stderr_begin");
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            println!("agent_preconnection_stderr_end");
            println!("S1_DIAGNOSTIC_CLASSIFICATION=SUBJECT_PLACEMENT_FAILURE");
            return Err("agent launcher exited before the live-membership barrier".to_owned());
        }
        if agent_ready_started.elapsed() >= Duration::from_secs(5) {
            child
                .kill()
                .map_err(|error| format!("kill stuck pre-connection agent: {error}"))?;
            let output = child
                .wait_with_output()
                .map_err(|error| format!("collect stuck pre-connection agent: {error}"))?;
            println!("agent_preconnection_status={}", output.status);
            println!(
                "agent_preconnection_stdout={:?}",
                String::from_utf8_lossy(&output.stdout)
            );
            println!(
                "agent_preconnection_stderr={:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            println!("S1_DIAGNOSTIC_CLASSIFICATION=SUBJECT_PLACEMENT_FAILURE");
            return Err("agent did not reach the live-membership barrier".to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let announced_pid: u32 = fs::read_to_string(&config.agent_ready_file)
        .map_err(|error| format!("read agent ready file: {error}"))?
        .trim()
        .parse()
        .map_err(|error| format!("parse announced agent PID: {error}"))?;
    let proc_cgroup = fs::read_to_string(format!("/proc/{trusted_pid}/cgroup"))
        .map_err(|error| format!("read trusted agent /proc cgroup: {error}"))?;
    let cgroup_procs = fs::read_to_string(config.cgroup.join("cgroup.procs"))
        .map_err(|error| format!("read target cgroup.procs: {error}"))?;
    let in_proc_cgroup = proc_cgroup.lines().any(|line| line == expected_line);
    let in_cgroup_procs = cgroup_procs
        .lines()
        .any(|line| line.trim() == trusted_pid.to_string());
    let pid_matches = announced_pid == trusted_pid;
    let agent_netns_inode = fs::metadata(format!("/proc/{trusted_pid}/ns/net"))
        .map_err(|error| format!("stat agent netns: {error}"))?
        .ino();
    let owned_netns_inode = fs::metadata(format!("/run/netns/{}", config.netns))
        .map_err(|error| format!("stat owned netns: {error}"))?
        .ino();
    let netns_matches = agent_netns_inode == owned_netns_inode;
    let membership_correct = pid_matches && in_proc_cgroup && in_cgroup_procs && netns_matches;
    println!("trusted_agent_pid={trusted_pid}");
    println!("announced_agent_pid={announced_pid}");
    println!("target_cgroup_inode={cgroup_inode}");
    println!("expected_proc_cgroup_line={expected_line:?}");
    println!("agent_proc_cgroup_begin");
    print!("{proc_cgroup}");
    println!("agent_proc_cgroup_end");
    println!("target_cgroup_procs_begin");
    print!("{cgroup_procs}");
    println!("target_cgroup_procs_end");
    println!("pid_matches_trusted_lifecycle={pid_matches}");
    println!("agent_in_exact_proc_cgroup={in_proc_cgroup}");
    println!("agent_pid_in_target_cgroup_procs={in_cgroup_procs}");
    println!("agent_netns_inode={agent_netns_inode}");
    println!("owned_netns_inode={owned_netns_inode}");
    println!("agent_in_owned_netns={netns_matches}");
    println!("live_membership_proven={membership_correct}");
    fs::write(
        &config.membership_ready_file,
        format!(
            "pid={trusted_pid}\nstatus={}\n",
            if membership_correct {
                "CORRECT"
            } else {
                "WRONG"
            }
        ),
    )
    .map_err(|error| format!("write membership ready file: {error}"))?;
    wait_for_file(&config.membership_captured_file, Duration::from_secs(30))?;
    if !membership_correct {
        println!("S1_DIAGNOSTIC_CLASSIFICATION=SUBJECT_PLACEMENT_FAILURE");
        child
            .kill()
            .map_err(|error| format!("kill misplaced agent: {error}"))?;
        let output = child
            .wait_with_output()
            .map_err(|error| format!("wait for misplaced agent: {error}"))?;
        println!("agent_status={}", output.status);
        println!("agent_stdout={:?}", String::from_utf8_lossy(&output.stdout));
        println!("agent_stderr={:?}", String::from_utf8_lossy(&output.stderr));
        return Err("agent was not in the exact attached Execution cgroup/netns".to_owned());
    }
    println!("state=MEMBERSHIP_PROVEN_BEFORE_CONNECTION");
    wait_for_file(&config.agent_go_file, Duration::from_secs(30))?;
    println!("policy_local_before_connection={policy_state}");

    if let Some(staging) = staging.as_mut() {
        return exercise_delayed_publication(
            &mut tuples,
            staging,
            &mut events,
            listener,
            child,
            config,
        );
    }

    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set listener nonblocking: {error}"))?;
    let accept_started = Instant::now();
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if accept_started.elapsed() >= Duration::from_secs(5) {
                    let output = child.wait_with_output().map_err(|wait_error| {
                        format!("wait failed after accept timeout: {wait_error}")
                    })?;
                    return Err(format!(
                        "proxy accept timeout; agent_status={}; stdout={}; stderr={}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("proxy accept: {error}")),
        }
    };
    let local = stream
        .local_addr()
        .map_err(|error| format!("accepted local address: {error}"))?;
    println!("proxy_state=ACCEPTED peer={peer} local={local}");
    println!("application_bytes_read_before_resolve=0");
    println!("outbound_effects_before_resolve=0");
    println!("ip_fallback_authorization=false");

    let key = tuple_key(peer, local)?;
    println!("tuple_key_hex={}", hex(&key));
    let resolve_started = Instant::now();
    let value = loop {
        match tuples.get(&key, 0) {
            Ok(value) => break value,
            Err(aya::maps::MapError::KeyNotFound)
                if resolve_started.elapsed() < RESOLVE_TIMEOUT =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(aya::maps::MapError::KeyNotFound) => {
                let snapshot = capture_diagnostic_snapshot(config, &mut events)?;
                let classification =
                    if snapshot.diag[0] == 0 || snapshot.diag[1] == 0 || snapshot.diag[2] == 0 {
                        "HOOK_ENTRY_FAILURE"
                    } else if snapshot.cookie_entries == 0
                        || snapshot.tuple_entries == 0
                        || snapshot.port_diag[9] != 15_001
                    {
                        "ATTRIBUTION_LOGIC_FAILURE"
                    } else {
                        "RESOLVE_CORRELATION_FAILURE"
                    };
                println!("S1_DIAGNOSTIC_CLASSIFICATION={classification}");
                return Err(format!(
                    "tuple unresolved after {} ms; timeout deny",
                    RESOLVE_TIMEOUT.as_millis()
                ));
            }
            Err(error) => return Err(format!("lookup tuple: {error:#}")),
        }
    };
    let latency = resolve_started.elapsed();
    let evidence = decode_evidence(value);
    let expected_cgid = fs::metadata(&config.cgroup)
        .map_err(|error| format!("stat cgroup {}: {error}", config.cgroup.display()))?
        .ino();
    println!("resolve_latency_ns={}", latency.as_nanos());
    println!("expected_cgroup_inode={expected_cgid}");
    println!("sock_cookie={}", evidence[0]);
    println!("candidate_a_cgroup={}", evidence[1]);
    println!("candidate_b_cgroup={}", evidence[2]);
    println!("candidate_c_ident={}", evidence[3]);
    println!("candidate_d_netns_cookie={}", evidence[4]);
    println!("publish_ktime_ns={}", evidence[5]);
    println!("sockops_current_cgroup={}", evidence[6]);
    println!("raw_remote_port={}", evidence[7]);
    let snapshot = capture_diagnostic_snapshot(config, &mut events)?;

    let a_resolves = evidence[1] == expected_cgid;
    let b_resolves = evidence[2] == expected_cgid;
    let c_resolves = evidence[3] == config.exec_ident;
    let ip_cross_check = peer.ip() == config.execution_ip;
    println!("candidate_a_resolves_current_execution={a_resolves}");
    println!("candidate_b_resolves_current_execution={b_resolves}");
    println!("candidate_c_resolves_current_execution={c_resolves}");
    println!("candidate_d_recorded_only={}", evidence[4] != 0);
    println!("ip_veth_cross_check={ip_cross_check}");
    println!("ip_veth_used_for_authorization=false");
    if !(a_resolves && b_resolves && c_resolves && ip_cross_check) {
        println!("S1_DIAGNOSTIC_CLASSIFICATION=ATTRIBUTION_LOGIC_FAILURE");
        return Err(
            "trusted attribution candidates or independent IP cross-check disagreed".to_owned(),
        );
    }

    let mut request = String::new();
    BufReader::new(
        stream
            .try_clone()
            .map_err(|error| format!("clone accepted stream: {error}"))?,
    )
    .read_line(&mut request)
    .map_err(|error| format!("read application line after Resolve: {error}"))?;
    println!("application_line_after_resolve={:?}", request.trim_end());
    writeln!(stream, "ATTRIBUTED {}", config.execution_id)
        .map_err(|error| format!("write proxy verdict: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flush proxy verdict: {error}"))?;
    println!("resolve_result={}", config.execution_id);
    println!("diagnostic_tuple_entries={}", snapshot.tuple_entries);

    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for agent: {error}"))?;
    println!("agent_status={}", output.status);
    println!("agent_stdout_begin");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    println!("agent_stdout_end");
    println!("agent_stderr_begin");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    println!("agent_stderr_end");
    if !output.status.success() {
        return Err(format!("agent exited with {}", output.status));
    }
    println!("S1_DIAGNOSTIC_CLASSIFICATION=S1_CHAIN_PROVEN");
    println!("S1_RESULT=PASS");
    Ok(())
}

const S1B_SUCCESS_COUNT: usize = 64;

struct DelayedConnection {
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    key: [u8; 16],
    accepted_at: Instant,
    publish_delay: Duration,
    resolved_latency_ns: Option<u128>,
}

fn exercise_delayed_publication(
    tuples: &mut HashMap<MapData, [u8; 16], [u8; 64]>,
    staging: &mut HashMap<MapData, [u8; 16], [u8; 64]>,
    events: &mut RingBuf<MapData>,
    listener: TcpListener,
    child: Child,
    config: &Config,
) -> Result<(), String> {
    let total = S1B_SUCCESS_COUNT + 1;
    println!("test=S1b");
    println!("s1b_successful_resolve_target={S1B_SUCCESS_COUNT}");
    println!("s1b_timeout_deny_target=1");
    println!("application_bytes_read_while_unresolved=0");
    println!("dns_while_unresolved=0");
    println!("outbound_effects_while_unresolved=0");
    println!("ip_fallback_authorization=false");

    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set S1b listener nonblocking: {error}"))?;
    let accept_started = Instant::now();
    let mut connections = Vec::with_capacity(total);
    while connections.len() < total {
        match listener.accept() {
            Ok((stream, peer)) => {
                let local = stream
                    .local_addr()
                    .map_err(|error| format!("S1b accepted local address: {error}"))?;
                let key = tuple_key(peer, local)?;
                match tuples.get(&key, 0) {
                    Err(aya::maps::MapError::KeyNotFound) => {}
                    Ok(_) => {
                        return Err(format!(
                            "S1b tuple was visible before delayed publication for {peer}"
                        ));
                    }
                    Err(error) => return Err(format!("S1b initial tuple lookup: {error:#}")),
                }
                let staging_visible_at_accept = staging.get(&key, 0).is_ok();
                let index = connections.len();
                let delay_ms = 50 + ((index * 37) % 16) as u64 * 10;
                println!(
                    "s1b_accept index={index} peer={peer} local={local} tuple_visible=false staging_visible={staging_visible_at_accept} planned_publish_delay_ms={delay_ms}"
                );
                connections.push(DelayedConnection {
                    stream,
                    peer,
                    local,
                    key,
                    accepted_at: Instant::now(),
                    publish_delay: Duration::from_millis(delay_ms),
                    resolved_latency_ns: None,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if accept_started.elapsed() >= Duration::from_secs(5) {
                    return Err(format!(
                        "S1b accepted only {} of {total} connections",
                        connections.len()
                    ));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("S1b proxy accept: {error}")),
        }
    }
    println!("s1b_all_connections_accepted={total}");

    let expected_cgid = fs::metadata(&config.cgroup)
        .map_err(|error| format!("stat S1b cgroup {}: {error}", config.cgroup.display()))?
        .ino();
    let mut resolved = 0_usize;
    let mut timeout_denied = false;
    let resolution_deadline = Instant::now() + Duration::from_secs(3);
    while resolved < S1B_SUCCESS_COUNT || !timeout_denied {
        for (index, connection) in connections.iter_mut().take(S1B_SUCCESS_COUNT).enumerate() {
            if connection.resolved_latency_ns.is_some()
                || connection.accepted_at.elapsed() < connection.publish_delay
            {
                continue;
            }
            match tuples.get(&connection.key, 0) {
                Err(aya::maps::MapError::KeyNotFound) => {}
                Ok(_) => {
                    return Err(format!(
                        "S1b tuple appeared before controlled promotion for index {index}"
                    ));
                }
                Err(error) => return Err(format!("S1b pre-promotion tuple lookup: {error:#}")),
            }
            let staged = match staging.get(&connection.key, 0) {
                Ok(value) => value,
                Err(aya::maps::MapError::KeyNotFound) => continue,
                Err(error) => return Err(format!("S1b staging lookup: {error:#}")),
            };
            tuples
                .insert(connection.key, staged, 0)
                .map_err(|error| format!("S1b promote tuple: {error:#}"))?;
            staging
                .remove(&connection.key)
                .map_err(|error| format!("S1b remove promoted staging tuple: {error:#}"))?;
            let published = tuples
                .get(&connection.key, 0)
                .map_err(|error| format!("S1b Resolve after promotion: {error:#}"))?;
            let evidence = decode_evidence(published);
            if evidence[1] != expected_cgid
                || evidence[2] != expected_cgid
                || evidence[3] != config.exec_ident
            {
                return Err(format!(
                    "S1b attribution mismatch at index {index}: A={} B={} C={}",
                    evidence[1], evidence[2], evidence[3]
                ));
            }
            let latency = connection.accepted_at.elapsed().as_nanos();
            connection.resolved_latency_ns = Some(latency);
            resolved += 1;
            println!(
                "s1b_resolve index={index} peer={} local={} latency_ns={latency} tuple_dport=15001 execution={} a_cgid={} b_cgid={} c_ident={} netns_cookie={}",
                connection.peer,
                connection.local,
                config.execution_id,
                evidence[1],
                evidence[2],
                evidence[3],
                evidence[4]
            );
        }

        let timeout = &mut connections[S1B_SUCCESS_COUNT];
        if !timeout_denied && timeout.accepted_at.elapsed() >= RESOLVE_TIMEOUT {
            match tuples.get(&timeout.key, 0) {
                Err(aya::maps::MapError::KeyNotFound) => {}
                Ok(_) => return Err("S1b timeout tuple unexpectedly became visible".to_owned()),
                Err(error) => return Err(format!("S1b timeout tuple lookup: {error:#}")),
            }
            timeout
                .stream
                .shutdown(Shutdown::Both)
                .map_err(|error| format!("S1b close denied timeout socket: {error}"))?;
            timeout_denied = true;
            println!(
                "s1b_timeout peer={} local={} timeout_ms={} decision=DENY application_bytes_read=0 dns=0 outbound_effects=0 ip_fallback=false",
                timeout.peer,
                timeout.local,
                RESOLVE_TIMEOUT.as_millis()
            );
        }
        if Instant::now() >= resolution_deadline {
            return Err(format!(
                "S1b resolution deadline: resolved {resolved}/{S1B_SUCCESS_COUNT}, timeout_denied={timeout_denied}"
            ));
        }
        thread::sleep(Duration::from_micros(100));
    }

    let snapshot = capture_diagnostic_snapshot(config, events)?;
    if snapshot.diag[0] < total as u64
        || snapshot.diag[1] < total as u64
        || snapshot.diag[5] < total as u64
        || snapshot.tuple_entries != S1B_SUCCESS_COUNT
    {
        return Err(format!(
            "S1b hook/publication snapshot disagreed: diag={:?}, tuples={}",
            snapshot.diag, snapshot.tuple_entries
        ));
    }

    for (index, connection) in connections.iter_mut().take(S1B_SUCCESS_COUNT).enumerate() {
        let mut request = String::new();
        BufReader::new(
            connection
                .stream
                .try_clone()
                .map_err(|error| format!("clone S1b accepted stream: {error}"))?,
        )
        .read_line(&mut request)
        .map_err(|error| format!("read S1b application line after Resolve: {error}"))?;
        writeln!(connection.stream, "ATTRIBUTED {}", config.execution_id)
            .map_err(|error| format!("write S1b proxy verdict: {error}"))?;
        connection
            .stream
            .flush()
            .map_err(|error| format!("flush S1b proxy verdict: {error}"))?;
        println!(
            "s1b_application_after_resolve index={index} line={:?}",
            request.trim_end()
        );
    }

    let mut latencies: Vec<u128> = connections
        .iter()
        .take(S1B_SUCCESS_COUNT)
        .filter_map(|connection| connection.resolved_latency_ns)
        .collect();
    latencies.sort_unstable();
    println!("s1b_latency_samples={}", latencies.len());
    println!("s1b_latency_min_ns={}", latencies[0]);
    println!("s1b_latency_p50_ns={}", percentile(&latencies, 50));
    println!("s1b_latency_p95_ns={}", percentile(&latencies, 95));
    println!("s1b_latency_p99_ns={}", percentile(&latencies, 99));
    println!("s1b_latency_max_ns={}", latencies[latencies.len() - 1]);
    println!("s1b_accept_before_publication_count={S1B_SUCCESS_COUNT}");
    println!("s1b_timeout_denies=1");

    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for S1b agent: {error}"))?;
    println!("agent_status={}", output.status);
    println!("agent_stdout_begin");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    println!("agent_stdout_end");
    println!("agent_stderr_begin");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    println!("agent_stderr_end");
    if !output.status.success() {
        return Err(format!("S1b agent exited with {}", output.status));
    }
    println!("S1B_RESULT=PASS");
    Ok(())
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let rank = (percentile * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

struct DiagnosticSnapshot {
    diag: Vec<u64>,
    port_diag: Vec<u64>,
    tuple_entries: usize,
    cookie_entries: usize,
}

fn capture_diagnostic_snapshot<T: Borrow<MapData>>(
    config: &Config,
    events: &mut RingBuf<T>,
) -> Result<DiagnosticSnapshot, String> {
    let diag_json = dump_map(config, "soglia_diag_entries")?;
    let port_diag_json = dump_map(config, "soglia_port_diag")?;
    let counters_json = dump_map(config, "soglia_counters")?;
    let cookies_json = dump_map(config, "soglia_cookie_a")?;
    let tuples_json = dump_map(config, "soglia_tuples")?;
    let _denies_json = dump_map(config, "soglia_denies")?;
    let staging_entries = if config.map_pin_root.join("soglia_staging").exists() {
        dump_map(config, "soglia_staging")?
            .as_array()
            .map_or(0, Vec::len)
    } else {
        0
    };
    let diag = array_values(&diag_json, 7)?;
    let port_diag = array_values(&port_diag_json, 12)?;
    let counters = array_values(&counters_json, 9)?;
    let cookie_entries = cookies_json.as_array().map_or(0, Vec::len);
    let tuple_entries = tuples_json.as_array().map_or(0, Vec::len);
    println!("diag_entry_counts={diag:?}");
    println!("port_diag_values={port_diag:?}");
    println!(
        "port_diag_hex={:?}",
        port_diag
            .iter()
            .map(|value| format!("0x{value:08x}"))
            .collect::<Vec<_>>()
    );
    println!("existing_counters={counters:?}");
    println!("cookie_entry_count={cookie_entries}");
    println!("tuple_entry_count={tuple_entries}");
    println!("staging_entry_count={staging_entries}");
    let mut event_count = 0_u64;
    while let Some(event) = events.next() {
        println!("bpf_event_{}_hex={}", event_count, hex(&event));
        event_count += 1;
    }
    println!("bpf_event_count={event_count}");
    Ok(DiagnosticSnapshot {
        diag,
        port_diag,
        tuple_entries,
        cookie_entries,
    })
}

fn array_values(json: &serde_json::Value, count: usize) -> Result<Vec<u64>, String> {
    let entries = json
        .as_array()
        .ok_or("bpftool array dump was not a JSON array")?;
    let mut values = vec![0_u64; count];
    for entry in entries {
        let key = entry
            .get("formatted")
            .and_then(|formatted| formatted.get("key"))
            .or_else(|| entry.get("key"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("bpftool array entry has no numeric key")? as usize;
        let value = entry
            .get("formatted")
            .and_then(|formatted| formatted.get("value"))
            .or_else(|| entry.get("value"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("bpftool array entry has no numeric value")?;
        if let Some(slot) = values.get_mut(key) {
            *slot = value;
        }
    }
    Ok(values)
}

fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !path.exists() {
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn wait_for_process_stopped(pid: u32, timeout: Duration) -> Result<(), String> {
    let status_path = format!("/proc/{pid}/status");
    let started = Instant::now();
    loop {
        let status = fs::read_to_string(&status_path)
            .map_err(|error| format!("read host launcher status: {error}"))?;
        if status
            .lines()
            .find(|line| line.starts_with("State:"))
            .is_some_and(|line| line.contains("T (stopped)"))
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "host launcher {pid} did not stop before netns entry"
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn dump_map(config: &Config, name: &str) -> Result<serde_json::Value, String> {
    let dump = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(config.map_pin_root.join(name))
        .output()
        .map_err(|error| format!("run {name} diagnostic: {error}"))?;
    println!("{name}_diagnostic_status={}", dump.status);
    println!("{name}_diagnostic_stdout_begin");
    print!("{}", String::from_utf8_lossy(&dump.stdout));
    println!("{name}_diagnostic_stdout_end");
    println!("{name}_diagnostic_stderr_begin");
    eprint!("{}", String::from_utf8_lossy(&dump.stderr));
    println!("{name}_diagnostic_stderr_end");
    if !dump.status.success() {
        return Err(format!("bpftool failed to dump {name}"));
    }
    serde_json::from_slice(&dump.stdout)
        .map_err(|error| format!("parse bpftool JSON for {name}: {error}"))
}

use std::os::unix::fs::MetadataExt as _;

fn tuple_key(peer: SocketAddr, local: SocketAddr) -> Result<[u8; 16], String> {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        return Err("S1 expected an IPv4 accepted tuple".to_owned());
    };
    let mut key = [0_u8; 16];
    key[0..4].copy_from_slice(&peer.ip().octets());
    key[4..8].copy_from_slice(&local.ip().octets());
    key[8..12].copy_from_slice(&u32::from(peer.port()).to_ne_bytes());
    key[12..16].copy_from_slice(&u32::from(local.port()).to_ne_bytes());
    Ok(key)
}

fn decode_evidence(bytes: [u8; 64]) -> [u64; 8] {
    let mut values = [0_u64; 8];
    for (index, value) in values.iter_mut().enumerate() {
        let start = index * 8;
        *value = u64::from_ne_bytes(bytes[start..start + 8].try_into().unwrap_or_default());
    }
    values
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn attach_all(bpf: &mut Ebpf, cgroup: &File, pin_root: &Path) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
    let result = (|| {
        links.push(attach_cgroup_sock(
            bpf,
            cgroup,
            "soglia_sock_create",
            &pin_root.join("sock_create"),
        )?);
        for (program, pin) in [
            ("soglia_connect4", "connect4"),
            ("soglia_connect6", "connect6"),
            ("soglia_sendmsg4", "sendmsg4"),
            ("soglia_sendmsg6", "sendmsg6"),
        ] {
            links.push(attach_cgroup_sock_addr(
                bpf,
                cgroup,
                program,
                &pin_root.join(pin),
            )?);
        }
        links.push(attach_sock_ops(
            bpf,
            cgroup,
            "soglia_sockops",
            &pin_root.join("sock_ops"),
        )?);
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        cleanup_links(&mut links);
        return Err(error);
    }
    println!("attached_links=6");
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
        .ok_or_else(|| format!("program {name} not found"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed {name} link: {error:#}"))?;
    fd_link
        .pin(pin)
        .map_err(|error| format!("pin {name} at {}: {error:#}", pin.display()))
}

fn attach_cgroup_sock_addr(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<PinnedLink, String> {
    let program: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} not found"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed {name} link: {error:#}"))?;
    fd_link
        .pin(pin)
        .map_err(|error| format!("pin {name} at {}: {error:#}", pin.display()))
}

fn attach_sock_ops(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<PinnedLink, String> {
    let program: &mut SockOps = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} not found"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed {name} link: {error:#}"))?;
    fd_link
        .pin(pin)
        .map_err(|error| format!("pin {name} at {}: {error:#}", pin.display()))
}

fn cleanup_links(links: &mut Vec<PinnedLink>) {
    while let Some(link) = links.pop() {
        match link.unpin() {
            Ok(fd_link) => drop(fd_link),
            Err(error) => eprintln!("cleanup link unpin error: {error:#}"),
        }
    }
}

fn remove_pins(config: &Config) {
    remove_file(&config.ready_file);
    remove_file(&config.go_file);
    remove_file(&config.host_ready_file);
    remove_file(&config.placement_ready_file);
    remove_file(&config.placement_captured_file);
    remove_file(&config.agent_ready_file);
    remove_file(&config.agent_go_file);
    remove_file(&config.membership_ready_file);
    remove_file(&config.membership_captured_file);
    for name in MAP_NAMES {
        remove_file(&config.map_pin_root.join(name));
    }
    for name in LINK_NAMES {
        remove_file(&config.link_pin_root.join(name));
    }
    remove_dir(&config.link_pin_root);
    remove_dir(&config.map_pin_root);
    if let Some(parent) = config.link_pin_root.parent() {
        remove_dir(parent);
    }
    if let Some(parent) = config.map_pin_root.parent() {
        remove_dir(parent);
    }
}

fn remove_file(path: &Path) {
    if let Err(error) = fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("cleanup file {}: {error}", path.display());
    }
}

fn remove_dir(path: &Path) {
    if let Err(error) = fs::remove_dir(path)
        && !matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
        )
    {
        eprintln!("cleanup directory {}: {error}", path.display());
    }
}

fn display_error(operation: &'static str) -> impl Fn(std::io::Error) -> String {
    move |error| format!("{operation}: {error}")
}
