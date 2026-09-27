// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! S12 bounded-map exhaustion and fail-closed harness.
//!
//! EXPERIMENTAL: this is spike-only diagnostic machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::MetadataExt as _,
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

const CAPACITY: usize = 8;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
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
const LINK_NAMES: [&str; 6] = [
    "sock_create",
    "connect4",
    "connect6",
    "sendmsg4",
    "sendmsg6",
    "sock_ops",
];

struct Config {
    object: PathBuf,
    cgroup: PathBuf,
    map_pins: PathBuf,
    link_pins: PathBuf,
    netns: String,
    agent: PathBuf,
    execution_id: String,
    exec_ident: u64,
    ready: PathBuf,
    go: PathBuf,
    membership_ready: PathBuf,
    membership_captured: PathBuf,
    overflow_ready: PathBuf,
    control_go: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            object: next_path(&mut args, "BPF object")?,
            cgroup: next_path(&mut args, "Execution cgroup")?,
            map_pins: next_path(&mut args, "map pin root")?,
            link_pins: next_path(&mut args, "link pin root")?,
            netns: next_string(&mut args, "network namespace")?,
            agent: next_path(&mut args, "agent")?,
            execution_id: next_string(&mut args, "Execution id")?,
            exec_ident: next_string(&mut args, "diagnostic identity")?
                .parse()
                .map_err(|error| format!("parse diagnostic identity: {error}"))?,
            ready: next_path(&mut args, "ready marker")?,
            go: next_path(&mut args, "go marker")?,
            membership_ready: next_path(&mut args, "membership ready marker")?,
            membership_captured: next_path(&mut args, "membership captured marker")?,
            overflow_ready: next_path(&mut args, "overflow ready marker")?,
            control_go: next_path(&mut args, "control go marker")?,
        };
        if args.next().is_some() {
            return Err("unexpected extra arguments".to_owned());
        }
        Ok(config)
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

struct Instance {
    bpf: Ebpf,
    links: Vec<PinnedLink>,
    tuples: HashMap<MapData, [u8; 16], [u8; 64]>,
    cookies: HashMap<MapData, u64, u64>,
    counters: Array<MapData, u64>,
    diag: Array<MapData, u64>,
    map_diag: Array<MapData, i64>,
    events: RingBuf<MapData>,
}

struct Agent {
    phase: String,
    pid: u32,
    child: Child,
    host_ready: PathBuf,
    agent_ready: PathBuf,
    agent_go: PathBuf,
}

struct Connection {
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    key: [u8; 16],
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S12 EXHAUSTION ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    fs::create_dir_all(&config.map_pins).map_err(display_error("create map pin root"))?;
    fs::create_dir_all(&config.link_pins).map_err(display_error("create link pin root"))?;
    let expected_cgid = fs::metadata(&config.cgroup)
        .map_err(|error| format!("stat Execution cgroup: {error}"))?
        .ino();
    let mut instance = load_instance(&config)?;
    let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
        .map_err(|error| format!("bind S12 proxy: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set listener nonblocking: {error}"))?;

    println!("test=S12");
    println!("object={}", config.object.display());
    println!("execution_id={}", config.execution_id);
    println!("execution_cgroup={}", config.cgroup.display());
    println!("execution_cgroup_inode={expected_cgid}");
    println!("tuple_capacity={CAPACITY}");
    println!("cookie_capacity={CAPACITY}");
    println!("resolve_timeout_ms={}", RESOLVE_TIMEOUT.as_millis());
    println!("ip_fallback_authorization=false");
    println!("proxy_state=LISTENING");

    fs::write(&config.ready, b"ready\n").map_err(display_error("write ready marker"))?;
    println!("state=READY_FOR_BASELINE_SNAPSHOT");
    wait_for_file(&config.go, Duration::from_secs(30))?;

    if map_count(&config.map_pins.join("soglia_tuples"))? != 0
        || map_count(&config.map_pins.join("soglia_cookie_a"))? != 0
    {
        return Err("tuple/cookie baseline was not empty".to_owned());
    }
    println!("tuple_baseline_occupancy=0");
    println!("cookie_baseline_occupancy=0");

    // Pre-exhaustion application control proves the proxy path before resource pressure.
    let pre = start_and_place_agent(&config, "precontrol", "proxy 1")?;
    release_agent(&pre)?;
    let pre_connection = accept_connections(&listener, 1)?.remove(0);
    let pre_evidence = wait_for_tuple(
        &instance.tuples,
        &pre_connection.key,
        Duration::from_secs(2),
    )?;
    require_complete(&config, expected_cgid, &pre_evidence, "precontrol")?;
    resolve_connection(pre_connection, &config.execution_id, "precontrol")?;
    let pre_output = wait_agent(pre)?;
    println!("precontrol_agent_output={pre_output:?}");
    wait_for_occupancy(&config, 0, 0, Duration::from_secs(2))?;
    println!("pre_exhaustion_proxy_control=PASS");
    let counters_before_fill = array_values(&instance.counters, 9)?;
    let diag_before_fill = array_values(&instance.diag, 7)?;
    let map_diag_before_fill = signed_array_values(&instance.map_diag, 8)?;

    // Phase A: eight distinct live sockets, all retained until after overflow observation.
    let fill = start_and_place_agent(&config, "fill", "proxy 8")?;
    fs::write(
        &config.membership_ready,
        format!("pid={}\nstatus=CORRECT\n", fill.pid),
    )
    .map_err(display_error("write membership marker"))?;
    wait_for_file(&config.membership_captured, Duration::from_secs(30))?;
    release_agent(&fill)?;
    let mut fill_connections = accept_connections(&listener, CAPACITY)?;
    wait_for_counter(
        &instance.counters,
        2,
        counters_before_fill[2] + CAPACITY as u64,
        Duration::from_secs(3),
    )?;
    wait_for_occupancy(&config, CAPACITY, CAPACITY, Duration::from_secs(2))?;

    let mut fill_cookies = HashSet::with_capacity(CAPACITY);
    let mut fill_keys = HashSet::with_capacity(CAPACITY);
    for (index, connection) in fill_connections.iter().enumerate() {
        if !fill_keys.insert(connection.key) {
            return Err("duplicate Phase-A tuple".to_owned());
        }
        let evidence = instance
            .tuples
            .get(&connection.key, 0)
            .map_err(|error| format!("read Phase-A tuple {index}: {error:#}"))?;
        let decoded = require_complete(&config, expected_cgid, &evidence, "phase_a")?;
        if !fill_cookies.insert(decoded[0]) {
            return Err("duplicate Phase-A socket cookie".to_owned());
        }
        println!(
            "phase_a_entry index={index} peer={} local={} tuple_hex={} cookie={} a_cgid={} b_cgid={} c_ident={} publication=SUCCESS resolve_ready=true",
            connection.peer,
            connection.local,
            hex(&connection.key),
            decoded[0],
            decoded[1],
            decoded[2],
            decoded[3]
        );
    }
    println!("phase_a_distinct_tuples={}", fill_keys.len());
    println!("phase_a_distinct_cookies={}", fill_cookies.len());
    println!("phase_a_tuple_occupancy={CAPACITY}");
    println!("phase_a_cookie_occupancy={CAPACITY}");
    println!("phase_a_map_full_proven=true");
    println!("phase_a_application_bytes_read=0");

    // Phase B: one more connection while both bounded maps are proven full.
    let overflow = start_and_place_agent(&config, "overflow", "proxy 1")?;
    release_agent(&overflow)?;
    let overflow_connection = accept_connections(&listener, 1)?.remove(0);
    println!(
        "phase_b_accept peer={} local={} tuple_hex={}",
        overflow_connection.peer,
        overflow_connection.local,
        hex(&overflow_connection.key)
    );
    let failures_before = counters_before_fill[1];
    wait_for_counter(
        &instance.counters,
        1,
        failures_before + 1,
        Duration::from_secs(3),
    )?;
    let map_diag_overflow = signed_array_values(&instance.map_diag, 8)?;
    let counters_overflow = array_values(&instance.counters, 9)?;
    let diag_overflow = array_values(&instance.diag, 7)?;
    let tuple_occupancy = map_count(&config.map_pins.join("soglia_tuples"))?;
    let cookie_occupancy = map_count(&config.map_pins.join("soglia_cookie_a"))?;
    if tuple_occupancy != CAPACITY || cookie_occupancy != CAPACITY {
        return Err(format!(
            "overflow changed occupancy tuple={tuple_occupancy} cookie={cookie_occupancy}"
        ));
    }
    if instance.tuples.get(&overflow_connection.key, 0).is_ok() {
        return Err("overflow tuple unexpectedly exists".to_owned());
    }
    let cookie_fail_delta = map_diag_overflow[1] - map_diag_before_fill[1];
    let sk_fail_delta = map_diag_overflow[4] - map_diag_before_fill[4];
    let tuple_fail_delta = map_diag_overflow[6] - map_diag_before_fill[6];
    if cookie_fail_delta != 1 || tuple_fail_delta != 1 || sk_fail_delta != 0 {
        return Err(format!(
            "map failure diagnostics disagree cookie={cookie_fail_delta} sk={sk_fail_delta} tuple={tuple_fail_delta}"
        ));
    }
    println!("phase_b_cookie_update_result={}", map_diag_overflow[2]);
    println!("phase_b_sk_storage_failures={sk_fail_delta}");
    println!("phase_b_tuple_update_result={}", map_diag_overflow[7]);
    println!("phase_b_tuple_failure_counter={}", counters_overflow[1]);
    println!(
        "phase_b_tuple_publish_success_counter={}",
        counters_overflow[2]
    );
    println!("phase_b_hook_entries={diag_overflow:?}");
    println!(
        "phase_b_hook_entry_delta_since_fill_start={:?}",
        diag_overflow
            .iter()
            .zip(&diag_before_fill)
            .map(|(after, before)| after - before)
            .collect::<Vec<_>>()
    );
    println!("phase_b_tuple_occupancy_before={CAPACITY}");
    println!("phase_b_tuple_occupancy_after={tuple_occupancy}");
    println!("phase_b_cookie_occupancy_after={cookie_occupancy}");
    println!("phase_b_final_tuple_present=false");
    println!("phase_b_application_bytes_read_while_unresolved=0");
    println!("phase_b_dns_while_unresolved=0");
    println!("phase_b_outbound_effects_while_unresolved=0");
    println!("phase_b_ip_fallback_authorization=false");

    let accepted_at = Instant::now();
    while accepted_at.elapsed() < RESOLVE_TIMEOUT {
        if instance.tuples.get(&overflow_connection.key, 0).is_ok() {
            return Err("overflow tuple appeared during bounded wait".to_owned());
        }
        thread::sleep(Duration::from_millis(1));
    }
    overflow_connection
        .stream
        .shutdown(Shutdown::Both)
        .map_err(|error| format!("deny overflow socket: {error}"))?;
    println!("phase_b_resolve_result=UNRESOLVED");
    println!("phase_b_timeout_ms={}", RESOLVE_TIMEOUT.as_millis());
    println!("phase_b_decision=DENY");
    println!("phase_b_connection_established_to_proxy=true");
    drop(overflow_connection);
    let overflow_output = wait_agent(overflow)?;
    println!("phase_b_agent_output={overflow_output:?}");

    let mut map_full_events = 0_u64;
    while let Some(event) = instance.events.next() {
        let bytes: &[u8] = &event;
        println!("phase_b_event_hex={}", hex(bytes));
        if event_u32(bytes, 0) == 2 {
            map_full_events += 1;
            println!("phase_b_event_kind=EV_MAP_FULL");
            println!("phase_b_event_cgid={}", event_u64(bytes, 8));
            println!("phase_b_event_cookie={}", event_u64(bytes, 16));
            println!("phase_b_event_daddr={}", event_u32(bytes, 32));
            println!("phase_b_event_dport={}", event_u32(bytes, 36));
        }
    }
    if map_full_events != 1 {
        return Err(format!(
            "expected one map-full event, observed {map_full_events}"
        ));
    }
    println!("phase_b_map_full_events={map_full_events}");
    println!("phase_b_fail_closed=PASS");

    fs::write(&config.overflow_ready, b"overflow-observed\n")
        .map_err(display_error("write overflow observation marker"))?;
    wait_for_file(&config.control_go, Duration::from_secs(30))?;

    // Causal control: free exactly one known tuple/cookie, then repeat one connection.
    let freed = fill_connections.remove(0);
    let freed_key = freed.key;
    println!("control_freed_tuple_hex={}", hex(&freed_key));
    resolve_connection(freed, &config.execution_id, "free_one")?;
    wait_for_key_absent(&instance.tuples, &freed_key, Duration::from_secs(2))?;
    wait_for_occupancy(&config, CAPACITY - 1, CAPACITY - 1, Duration::from_secs(2))?;
    println!("control_capacity_freed=1");
    println!("control_tuple_occupancy_before_retry={}", CAPACITY - 1);

    let control = start_and_place_agent(&config, "control", "proxy 1")?;
    release_agent(&control)?;
    let control_connection = accept_connections(&listener, 1)?.remove(0);
    let control_evidence = wait_for_tuple(
        &instance.tuples,
        &control_connection.key,
        Duration::from_secs(2),
    )?;
    let decoded = require_complete(&config, expected_cgid, &control_evidence, "control")?;
    wait_for_occupancy(&config, CAPACITY, CAPACITY, Duration::from_secs(2))?;
    let control_counters = array_values(&instance.counters, 9)?;
    let control_map_diag = signed_array_values(&instance.map_diag, 8)?;
    if control_counters[1] != counters_overflow[1]
        || control_map_diag[1] != map_diag_overflow[1]
        || control_map_diag[6] != map_diag_overflow[6]
    {
        return Err("capacity-restored control recorded another map failure".to_owned());
    }
    println!(
        "control_retry peer={} local={} tuple_hex={} cookie={} a_cgid={} b_cgid={} c_ident={} tuple_publication=SUCCESS",
        control_connection.peer,
        control_connection.local,
        hex(&control_connection.key),
        decoded[0],
        decoded[1],
        decoded[2],
        decoded[3]
    );
    resolve_connection(
        control_connection,
        &config.execution_id,
        "capacity_restored",
    )?;
    let control_output = wait_agent(control)?;
    println!("control_agent_output={control_output:?}");
    println!("capacity_restored_control=PASS");

    for connection in fill_connections {
        resolve_connection(connection, &config.execution_id, "phase_a_release")?;
    }
    let fill_output = wait_agent(fill)?;
    println!("fill_agent_output={fill_output:?}");
    wait_for_occupancy(&config, 0, 0, Duration::from_secs(3))?;
    println!("post_connection_tuple_occupancy=0");
    println!("post_connection_cookie_occupancy=0");
    println!("S12_RESULT=PASS");

    println!("state=CLEANUP_BEGIN");
    cleanup_instance(&config, &mut instance);
    cleanup_markers(&config);
    println!("state=CLEANUP_COMPLETE");
    Ok(())
}

fn load_instance(config: &Config) -> Result<Instance, String> {
    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &config.exec_ident, true)
        .default_map_pin_directory(&config.map_pins);
    let mut bpf = loader
        .load_file(&config.object)
        .map_err(|error| format!("load {}: {error:#}", config.object.display()))?;
    let mut policy = Array::<_, u64>::try_from(
        bpf.map_mut("policy_local")
            .ok_or("policy_local map missing")?,
    )
    .map_err(|error| format!("open policy_local: {error:#}"))?;
    policy
        .set(0, 1, 0)
        .map_err(|error| format!("activate policy_local: {error:#}"))?;
    let cgroup = File::open(&config.cgroup)
        .map_err(|error| format!("open cgroup {}: {error}", config.cgroup.display()))?;
    let links = attach_all(&mut bpf, &cgroup, &config.link_pins)?;
    let tuples = HashMap::<_, [u8; 16], [u8; 64]>::try_from(
        bpf.take_map("soglia_tuples")
            .ok_or("soglia_tuples missing")?,
    )
    .map_err(|error| format!("open tuples: {error:#}"))?;
    let cookies = HashMap::<_, u64, u64>::try_from(
        bpf.take_map("soglia_cookie_a")
            .ok_or("soglia_cookie_a missing")?,
    )
    .map_err(|error| format!("open cookies: {error:#}"))?;
    let counters = Array::<_, u64>::try_from(
        bpf.take_map("soglia_counters")
            .ok_or("soglia_counters missing")?,
    )
    .map_err(|error| format!("open counters: {error:#}"))?;
    let diag = Array::<_, u64>::try_from(
        bpf.take_map("soglia_diag_entries")
            .ok_or("soglia_diag_entries missing")?,
    )
    .map_err(|error| format!("open hook diagnostics: {error:#}"))?;
    let map_diag = Array::<_, i64>::try_from(
        bpf.take_map("soglia_map_fail_diag")
            .ok_or("soglia_map_fail_diag missing")?,
    )
    .map_err(|error| format!("open map diagnostics: {error:#}"))?;
    let events = RingBuf::try_from(
        bpf.take_map("soglia_events")
            .ok_or("soglia_events missing")?,
    )
    .map_err(|error| format!("open events: {error:#}"))?;
    Ok(Instance {
        bpf,
        links,
        tuples,
        cookies,
        counters,
        diag,
        map_diag,
        events,
    })
}

fn start_and_place_agent(config: &Config, phase: &str, operation: &str) -> Result<Agent, String> {
    let host_ready = PathBuf::from(format!("/run/soglia-spike-s12-{phase}-host.ready"));
    let agent_ready = PathBuf::from(format!("/run/soglia-spike-s12-{phase}-agent.ready"));
    let agent_go = PathBuf::from(format!("/run/soglia-spike-s12-{phase}-agent.go"));
    let shell = r#"set -euo pipefail
printf '%s\n' "$$" > "$1"
kill -STOP "$$"
exec ip netns exec "$2" "$3" "barrier $4 $5 30" "$6""#;
    let child = Command::new("bash")
        .args(["-c", shell, "s12-host-launcher"])
        .arg(&host_ready)
        .arg(&config.netns)
        .arg(&config.agent)
        .arg(&agent_ready)
        .arg(&agent_go)
        .arg(operation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start {phase} agent: {error}"))?;
    let pid = child.id();
    wait_for_file(&host_ready, Duration::from_secs(5))?;
    wait_for_process_stopped(pid, Duration::from_secs(5))?;
    fs::write(config.cgroup.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(|error| format!("place {phase} PID: {error}"))?;
    verify_membership(config, phase, pid, false)?;
    let continued = Command::new("kill")
        .args(["-CONT", &pid.to_string()])
        .status()
        .map_err(|error| format!("continue {phase} PID: {error}"))?;
    if !continued.success() {
        return Err(format!("continue {phase} PID failed: {continued}"));
    }
    wait_for_file(&agent_ready, Duration::from_secs(5))?;
    let announced: u32 = fs::read_to_string(&agent_ready)
        .map_err(|error| format!("read {phase} agent PID: {error}"))?
        .trim()
        .parse()
        .map_err(|error| format!("parse {phase} agent PID: {error}"))?;
    if announced != pid {
        return Err(format!(
            "{phase} announced PID {announced}, trusted PID {pid}"
        ));
    }
    verify_membership(config, phase, pid, true)?;
    Ok(Agent {
        phase: phase.to_owned(),
        pid,
        child,
        host_ready,
        agent_ready,
        agent_go,
    })
}

fn verify_membership(
    config: &Config,
    phase: &str,
    pid: u32,
    require_netns: bool,
) -> Result<(), String> {
    let relative = config
        .cgroup
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| "Execution cgroup outside cgroupfs".to_owned())?;
    let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
    let proc_cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|error| format!("read {phase} /proc cgroup: {error}"))?;
    let procs = fs::read_to_string(config.cgroup.join("cgroup.procs"))
        .map_err(|error| format!("read {phase} cgroup.procs: {error}"))?;
    let proc_match = proc_cgroup.lines().any(|line| line == expected);
    let procs_match = procs.lines().any(|line| line == pid.to_string());
    let agent_netns = fs::metadata(format!("/proc/{pid}/ns/net"))
        .map_err(|error| format!("stat {phase} process netns: {error}"))?
        .ino();
    let owned_netns = fs::metadata(format!("/run/netns/{}", config.netns))
        .map_err(|error| format!("stat {phase} owned netns: {error}"))?
        .ino();
    let netns_match = !require_netns || agent_netns == owned_netns;
    println!(
        "agent_membership phase={phase} pid={pid} expected={expected} proc_match={proc_match} cgroup_procs_match={procs_match} agent_netns_inode={agent_netns} owned_netns_inode={owned_netns} netns_match={netns_match}"
    );
    if !(proc_match && procs_match && netns_match) {
        return Err(format!("{phase} membership was not proven"));
    }
    Ok(())
}

fn release_agent(agent: &Agent) -> Result<(), String> {
    fs::write(&agent.agent_go, b"go\n")
        .map_err(|error| format!("release {} agent: {error}", agent.phase))
}

fn wait_agent(agent: Agent) -> Result<String, String> {
    let output = agent
        .child
        .wait_with_output()
        .map_err(|error| format!("wait {} agent: {error}", agent.phase))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    println!("agent_phase={} status={}", agent.phase, output.status);
    println!("agent_phase={} stderr={stderr:?}", agent.phase);
    remove_file(&agent.host_ready);
    remove_file(&agent.agent_ready);
    remove_file(&agent.agent_go);
    if !output.status.success() {
        return Err(format!("{} agent failed: {stderr}", agent.phase));
    }
    Ok(stdout)
}

fn accept_connections(listener: &TcpListener, count: usize) -> Result<Vec<Connection>, String> {
    let started = Instant::now();
    let mut connections = Vec::with_capacity(count);
    while connections.len() < count {
        match listener.accept() {
            Ok((stream, peer)) => {
                let local = stream
                    .local_addr()
                    .map_err(|error| format!("accepted local: {error}"))?;
                let key = tuple_key(peer, local)?;
                connections.push(Connection {
                    stream,
                    peer,
                    local,
                    key,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= Duration::from_secs(5) {
                    return Err(format!(
                        "accepted only {}/{} connections",
                        connections.len(),
                        count
                    ));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("proxy accept: {error}")),
        }
    }
    Ok(connections)
}

fn resolve_connection(
    mut connection: Connection,
    execution_id: &str,
    phase: &str,
) -> Result<(), String> {
    let mut request = String::new();
    BufReader::new(
        connection
            .stream
            .try_clone()
            .map_err(|error| format!("clone {phase} socket: {error}"))?,
    )
    .read_line(&mut request)
    .map_err(|error| format!("read {phase} application line: {error}"))?;
    writeln!(connection.stream, "ATTRIBUTED {execution_id}")
        .map_err(|error| format!("write {phase} verdict: {error}"))?;
    connection
        .stream
        .flush()
        .map_err(|error| format!("flush {phase} verdict: {error}"))?;
    println!(
        "application_read phase={phase} after_resolve=true line={:?}",
        request.trim_end()
    );
    Ok(())
}

fn require_complete(
    config: &Config,
    expected_cgid: u64,
    value: &[u8; 64],
    phase: &str,
) -> Result<[u64; 8], String> {
    let evidence = decode_evidence(*value);
    if evidence[0] == 0
        || evidence[1] != expected_cgid
        || evidence[2] != expected_cgid
        || evidence[3] != config.exec_ident
    {
        return Err(format!(
            "{phase} incomplete attribution cookie={} a={} b={} c={} expected_cgid={} expected_ident={}",
            evidence[0], evidence[1], evidence[2], evidence[3], expected_cgid, config.exec_ident
        ));
    }
    Ok(evidence)
}

fn wait_for_tuple(
    tuples: &HashMap<MapData, [u8; 16], [u8; 64]>,
    key: &[u8; 16],
    timeout: Duration,
) -> Result<[u8; 64], String> {
    let started = Instant::now();
    loop {
        match tuples.get(key, 0) {
            Ok(value) => return Ok(value),
            Err(aya::maps::MapError::KeyNotFound) if started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(aya::maps::MapError::KeyNotFound) => {
                return Err("tuple lookup timed out".to_owned());
            }
            Err(error) => return Err(format!("tuple lookup: {error:#}")),
        }
    }
}

fn wait_for_key_absent(
    tuples: &HashMap<MapData, [u8; 16], [u8; 64]>,
    key: &[u8; 16],
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match tuples.get(key, 0) {
            Err(aya::maps::MapError::KeyNotFound) => return Ok(()),
            Ok(_) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(1)),
            Ok(_) => return Err("freed tuple remained published".to_owned()),
            Err(error) => return Err(format!("freed tuple lookup: {error:#}")),
        }
    }
}

fn wait_for_counter(
    counters: &Array<MapData, u64>,
    index: u32,
    expected: u64,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let value = counters
            .get(&index, 0)
            .map_err(|error| format!("read counter {index}: {error:#}"))?;
        if value >= expected {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "counter {index} reached {value}, expected {expected}"
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_occupancy(
    config: &Config,
    tuples: usize,
    cookies: usize,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let tuple_count = map_count(&config.map_pins.join("soglia_tuples"))?;
        let cookie_count = map_count(&config.map_pins.join("soglia_cookie_a"))?;
        if tuple_count == tuples && cookie_count == cookies {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "occupancy tuple={tuple_count}/{tuples} cookie={cookie_count}/{cookies}"
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn map_count(pin: &Path) -> Result<usize, String> {
    let output = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(pin)
        .output()
        .map_err(|error| format!("dump {}: {error}", pin.display()))?;
    if !output.status.success() {
        return Err(format!(
            "dump {} failed: {}",
            pin.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse {} dump: {error}", pin.display()))?;
    Ok(value.as_array().map_or(0, Vec::len))
}

fn array_values(map: &Array<MapData, u64>, count: u32) -> Result<Vec<u64>, String> {
    (0..count)
        .map(|index| {
            map.get(&index, 0)
                .map_err(|error| format!("array[{index}]: {error:#}"))
        })
        .collect()
}

fn signed_array_values(map: &Array<MapData, i64>, count: u32) -> Result<Vec<i64>, String> {
    (0..count)
        .map(|index| {
            map.get(&index, 0)
                .map_err(|error| format!("signed array[{index}]: {error:#}"))
        })
        .collect()
}

fn tuple_key(peer: SocketAddr, local: SocketAddr) -> Result<[u8; 16], String> {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        return Err("S12 expected an IPv4 tuple".to_owned());
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

fn event_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap_or_default())
}

fn event_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap_or_default())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn attach_all(bpf: &mut Ebpf, cgroup: &File, pin_root: &Path) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
    links.push(attach_sock(
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
        links.push(attach_addr(bpf, cgroup, program, &pin_root.join(pin))?);
    }
    links.push(attach_ops(
        bpf,
        cgroup,
        "soglia_sockops",
        &pin_root.join("sock_ops"),
    )?);
    Ok(links)
}

fn attach_sock(
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
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        name,
    )
}

fn attach_addr(
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
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        name,
    )
}

fn attach_ops(bpf: &mut Ebpf, cgroup: &File, name: &str, pin: &Path) -> Result<PinnedLink, String> {
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
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        name,
    )
}

fn pin_link<L: TryInto<FdLink>>(link: L, pin: &Path, name: &str) -> Result<PinnedLink, String>
where
    <L as TryInto<FdLink>>::Error: std::fmt::Debug,
{
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd link {name}: {error:?}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn cleanup_instance(config: &Config, instance: &mut Instance) {
    while let Some(link) = instance.links.pop() {
        if let Err(error) = link.unpin() {
            eprintln!("cleanup link: {error:#}");
        }
    }
    for name in LINK_NAMES {
        remove_file(&config.link_pins.join(name));
    }
    for name in MAP_NAMES {
        remove_file(&config.map_pins.join(name));
    }
    remove_dir(&config.link_pins);
    remove_dir(&config.map_pins);
    if let Some(parent) = config.link_pins.parent() {
        remove_dir(parent);
    }
    if let Some(parent) = config.map_pins.parent() {
        remove_dir(parent);
    }
    let _ = &instance.bpf;
    let _ = &instance.cookies;
}

fn cleanup_markers(config: &Config) {
    for path in [
        &config.ready,
        &config.go,
        &config.membership_ready,
        &config.membership_captured,
        &config.overflow_ready,
        &config.control_go,
    ] {
        remove_file(path);
    }
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
    let started = Instant::now();
    loop {
        let status = fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|error| format!("read stopped PID status: {error}"))?;
        if status
            .lines()
            .find(|line| line.starts_with("State:"))
            .is_some_and(|line| line.contains("T (stopped)"))
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("PID {pid} did not stop"));
        }
        thread::sleep(Duration::from_millis(10));
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
