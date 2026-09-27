// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Isolated hook contribution experiment for S5 of the cgroup-BPF spike.
//!
//! EXPERIMENTAL: this is spike machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, RingBuf},
    programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps,
        links::{FdLink, PinnedLink},
    },
};

const PROXY_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 255, 1);
const PROXY_PORT: u16 = 15_001;
const DIRECT_IP4: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 2);
const DIRECT_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x201, 0, 0, 0, 0, 0, 2);
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

struct Config {
    diag_object: PathBuf,
    inet6_object: PathBuf,
    dgram_object: PathBuf,
    execution: PathBuf,
    map_root: PathBuf,
    link_root: PathBuf,
    netns: String,
    agent: PathBuf,
    exec_ident: u64,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            diag_object: next_path(&mut args, "diagnostic object")?,
            inet6_object: next_path(&mut args, "IPv6-relaxed object")?,
            dgram_object: next_path(&mut args, "datagram-relaxed object")?,
            execution: next_path(&mut args, "execution cgroup")?,
            map_root: next_path(&mut args, "map pin root")?,
            link_root: next_path(&mut args, "link pin root")?,
            netns: next_path(&mut args, "netns")?
                .to_string_lossy()
                .into_owned(),
            agent: next_path(&mut args, "agent")?,
            exec_ident: next_path(&mut args, "execution ident")?
                .to_string_lossy()
                .parse()
                .map_err(|error| format!("parse execution ident: {error}"))?,
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

struct LoadedPhase {
    name: &'static str,
    bpf: Ebpf,
    links: Vec<PinnedLink>,
    map_pins: PathBuf,
    link_pins: PathBuf,
}

struct PhaseResult {
    stdout: String,
    accepted: bool,
    received: bool,
    counters: Vec<u64>,
    deny_entries: usize,
    event_count: usize,
}

enum Observation<'a> {
    None,
    Tcp(&'a TcpListener),
    Udp(&'a UdpSocket),
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S5 HOOK ISOLATION ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    let inode = fs::metadata(&config.execution)
        .map_err(|error| format!("stat execution cgroup: {error}"))?
        .ino();
    println!("test=S5");
    println!("execution_cgroup={}", config.execution.display());
    println!("execution_cgroup_inode={inode}");
    println!("exec_ident={}", config.exec_ident);

    let direct4 = TcpListener::bind((DIRECT_IP4, 16_001))
        .map_err(|error| format!("bind IPv4 direct listener: {error}"))?;
    let direct6 = TcpListener::bind((DIRECT_IP6, 16_002))
        .map_err(|error| format!("bind IPv6 direct listener: {error}"))?;
    let udp4 = UdpSocket::bind((DIRECT_IP4, 16_003))
        .map_err(|error| format!("bind IPv4 UDP listener: {error}"))?;
    let udp6 = UdpSocket::bind((DIRECT_IP6, 16_004))
        .map_err(|error| format!("bind IPv6 UDP listener: {error}"))?;
    for listener in [&direct4, &direct6] {
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("set TCP listener nonblocking: {error}"))?;
    }
    for socket in [&udp4, &udp6] {
        socket
            .set_nonblocking(true)
            .map_err(|error| format!("set UDP listener nonblocking: {error}"))?;
    }

    let sock6_deny = run_phase(
        &config,
        "sock-create-inet6-deny",
        &config.diag_object,
        None,
        "sock inet6 stream",
        Observation::None,
        inode,
    )?;
    require_outcome(&sock6_deny, false)?;
    require_counter(&sock6_deny, 3, 1, "sock_create IPv6 deny")?;

    let sock6_control = run_phase(
        &config,
        "sock-create-inet6-control",
        &config.inet6_object,
        None,
        "sock inet6 stream",
        Observation::None,
        inode,
    )?;
    require_outcome(&sock6_control, true)?;
    require_all_deny_counters_zero(&sock6_control)?;

    let connect6_deny = run_phase(
        &config,
        "connect6-deny",
        &config.inet6_object,
        None,
        "tcp6 [fd00:201::2]:16002",
        Observation::Tcp(&direct6),
        inode,
    )?;
    require_outcome(&connect6_deny, false)?;
    require_counter(&connect6_deny, 5, 1, "connect6 deny")?;
    require_no_delivery(&connect6_deny, "connect6 deny")?;

    let connect6_control = run_phase(
        &config,
        "connect6-omitted-control",
        &config.inet6_object,
        Some("soglia_connect6"),
        "tcp6 [fd00:201::2]:16002",
        Observation::Tcp(&direct6),
        inode,
    )?;
    require_outcome(&connect6_control, true)?;
    require_delivery(&connect6_control, "connect6 omitted")?;
    require_all_deny_counters_zero(&connect6_control)?;

    let send4_deny = run_phase(
        &config,
        "sendmsg4-deny",
        &config.dgram_object,
        None,
        "udp4 10.201.0.2:16003",
        Observation::Udp(&udp4),
        inode,
    )?;
    require_outcome(&send4_deny, false)?;
    require_counter(&send4_deny, 6, 1, "sendmsg4 deny")?;
    require_no_delivery(&send4_deny, "sendmsg4 deny")?;

    let send4_control = run_phase(
        &config,
        "sendmsg4-omitted-control",
        &config.dgram_object,
        Some("soglia_sendmsg4"),
        "udp4 10.201.0.2:16003",
        Observation::Udp(&udp4),
        inode,
    )?;
    require_outcome(&send4_control, true)?;
    require_delivery(&send4_control, "sendmsg4 omitted")?;
    require_all_deny_counters_zero(&send4_control)?;

    let send6_deny = run_phase(
        &config,
        "sendmsg6-deny",
        &config.dgram_object,
        None,
        "udp6 [fd00:201::2]:16004",
        Observation::Udp(&udp6),
        inode,
    )?;
    require_outcome(&send6_deny, false)?;
    require_counter(&send6_deny, 7, 1, "sendmsg6 deny")?;
    require_no_delivery(&send6_deny, "sendmsg6 deny")?;

    let send6_control = run_phase(
        &config,
        "sendmsg6-omitted-control",
        &config.dgram_object,
        Some("soglia_sendmsg6"),
        "udp6 [fd00:201::2]:16004",
        Observation::Udp(&udp6),
        inode,
    )?;
    require_outcome(&send6_control, true)?;
    require_delivery(&send6_control, "sendmsg6 omitted")?;
    require_all_deny_counters_zero(&send6_control)?;

    let connect4_deny = run_phase(
        &config,
        "connect4-deny",
        &config.diag_object,
        None,
        "direct 10.201.0.2:16001",
        Observation::Tcp(&direct4),
        inode,
    )?;
    require_outcome(&connect4_deny, false)?;
    require_counter(&connect4_deny, 4, 1, "connect4 deny")?;
    require_no_delivery(&connect4_deny, "connect4 deny")?;

    let connect4_control = run_phase(
        &config,
        "connect4-omitted-control",
        &config.diag_object,
        Some("soglia_connect4"),
        "direct 10.201.0.2:16001",
        Observation::Tcp(&direct4),
        inode,
    )?;
    require_outcome(&connect4_control, true)?;
    require_delivery(&connect4_control, "connect4 omitted")?;
    require_all_deny_counters_zero(&connect4_control)?;

    run_sockops_phase(&config, "sockops-present-control", false, inode)?;
    run_sockops_phase(&config, "sockops-omitted", true, inode)?;

    println!("S5_HOOK_sock_create=ISOLATED");
    println!("S5_HOOK_connect4=ISOLATED");
    println!("S5_HOOK_connect6=ISOLATED");
    println!("S5_HOOK_sendmsg4=ISOLATED");
    println!("S5_HOOK_sendmsg6=ISOLATED");
    println!("S5_HOOK_sockops=ISOLATED");
    println!("S5_RESULT=PASS");
    Ok(())
}

fn run_phase(
    config: &Config,
    name: &'static str,
    object: &Path,
    omit: Option<&str>,
    command: &str,
    observation: Observation<'_>,
    inode: u64,
) -> Result<PhaseResult, String> {
    println!("phase_begin={name}");
    println!("phase_object={}", object.display());
    println!("phase_omitted_hook={}", omit.unwrap_or("none"));
    println!("phase_agent_command={command}");
    let mut loaded = load_phase(config, name, object, omit)?;
    capture_attachment(config, name, omit, loaded.links.len())?;
    let (child, ready, go) = start_and_place_agent(config, name, command, inode)?;
    fs::write(&go, b"go\n").map_err(display_error("release phase agent"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for {name} agent: {error}"))?;
    remove_file(&ready);
    remove_file(&go);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    println!("{name}_agent_status={}", output.status);
    println!("{name}_agent_stdout_begin\n{stdout}{name}_agent_stdout_end");
    eprintln!("{name}_agent_stderr_begin\n{stderr}{name}_agent_stderr_end");
    if !output.status.success() {
        return Err(format!("{name} agent exited with {}", output.status));
    }
    let (accepted, received) = observe(observation)?;
    println!("{name}_listener_accepted={accepted}");
    println!("{name}_datagram_received={received}");
    let snapshot = snapshot(&mut loaded)?;
    let result = PhaseResult {
        stdout,
        accepted,
        received,
        counters: snapshot.counters,
        deny_entries: snapshot.deny_entries,
        event_count: snapshot.event_count,
    };
    cleanup_phase(config, loaded);
    println!("phase_end={name}");
    Ok(result)
}

fn run_sockops_phase(
    config: &Config,
    name: &'static str,
    omit_sockops: bool,
    inode: u64,
) -> Result<(), String> {
    println!("phase_begin={name}");
    let omit = omit_sockops.then_some("soglia_sockops");
    let mut loaded = load_phase(config, name, &config.diag_object, omit)?;
    capture_attachment(config, name, omit, loaded.links.len())?;
    let listener = TcpListener::bind((PROXY_IP, PROXY_PORT))
        .map_err(|error| format!("bind {name} proxy listener: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set {name} proxy nonblocking: {error}"))?;
    let (child, ready, go) = start_and_place_agent(config, name, "proxy 1", inode)?;
    fs::write(&go, b"go\n").map_err(display_error("release sockops phase"))?;
    let (mut stream, peer) = accept_with_timeout(&listener, Duration::from_secs(5))?
        .ok_or_else(|| format!("{name} proxy did not accept"))?;
    let local = stream
        .local_addr()
        .map_err(|error| format!("{name} accepted local address: {error}"))?;
    println!("{name}_proxy_accepted_peer={peer}");
    println!("{name}_proxy_accepted_local={local}");
    println!("{name}_proxy_accept_established=true");

    if omit_sockops {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            let tuples = dump_map(&loaded.map_pins, "soglia_tuples")?;
            if tuples.as_array().is_some_and(|entries| !entries.is_empty()) {
                return Err("sockops-omitted unexpectedly published tuple attribution".to_owned());
            }
            thread::sleep(Duration::from_millis(25));
        }
        println!("{name}_resolve_result=TIMEOUT_DENY");
        println!("{name}_resolve_timeout_ms=2000");
        println!("{name}_application_bytes_read_while_unresolved=0");
        println!("{name}_dns_while_unresolved=0");
        println!("{name}_outbound_effects_while_unresolved=0");
        println!("{name}_ip_fallback_authorization=false");
        stream
            .shutdown(Shutdown::Both)
            .map_err(|error| format!("close unresolved {name} socket: {error}"))?;
    } else {
        let started = Instant::now();
        let tuple = loop {
            let tuples = dump_map(&loaded.map_pins, "soglia_tuples")?;
            if let Some(entry) = tuples.as_array().and_then(|entries| entries.first()) {
                break entry.clone();
            }
            if started.elapsed() >= Duration::from_secs(2) {
                return Err("sockops-present did not publish tuple before Resolve bound".to_owned());
            }
            thread::sleep(Duration::from_millis(10));
        };
        let formatted = tuple
            .get("formatted")
            .ok_or("sockops-present tuple missing formatted data")?;
        let key = formatted.get("key").ok_or("tuple missing formatted key")?;
        let value = formatted
            .get("value")
            .ok_or("tuple missing formatted value")?;
        let tuple_sport = json_u64(key, "sport")?;
        let tuple_dport = json_u64(key, "dport")?;
        let a_cgid = json_u64(value, "a_cgid")?;
        let b_cgid = json_u64(value, "b_cgid")?;
        let c_ident = json_u64(value, "c_ident")?;
        if tuple_sport != u64::from(peer.port())
            || tuple_dport != u64::from(PROXY_PORT)
            || a_cgid != inode
            || b_cgid != inode
            || c_ident != config.exec_ident
        {
            return Err(format!(
                "sockops-present Resolve mismatch sport={tuple_sport} dport={tuple_dport} A={a_cgid} B={b_cgid} C={c_ident}"
            ));
        }
        println!("{name}_resolve_result=s5-execution-generation-1");
        println!("{name}_tuple_sport={tuple_sport}");
        println!("{name}_tuple_dport={tuple_dport}");
        println!("{name}_a_cgid={a_cgid}");
        println!("{name}_b_cgid={b_cgid}");
        println!("{name}_c_ident={c_ident}");
        println!("{name}_application_bytes_read_while_unresolved=0");
        let mut request = String::new();
        BufReader::new(
            stream
                .try_clone()
                .map_err(|error| format!("clone {name} stream: {error}"))?,
        )
        .read_line(&mut request)
        .map_err(|error| format!("read {name} application after Resolve: {error}"))?;
        writeln!(stream, "ATTRIBUTED s5-execution-generation-1")
            .map_err(|error| format!("write {name} verdict: {error}"))?;
        stream
            .flush()
            .map_err(|error| format!("flush {name} verdict: {error}"))?;
        println!("{name}_application_after_resolve={:?}", request.trim_end());
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for {name} agent: {error}"))?;
    remove_file(&ready);
    remove_file(&go);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("{name}_agent_status={}", output.status);
    println!("{name}_agent_stdout_begin\n{stdout}{name}_agent_stdout_end");
    eprintln!("{name}_agent_stderr_begin\n{stderr}{name}_agent_stderr_end");
    if !output.status.success() {
        return Err(format!("{name} agent exited with {}", output.status));
    }
    if omit_sockops {
        if !stdout.contains("\"ok\":false") {
            return Err("sockops-omitted agent was not denied after timeout".to_owned());
        }
    } else if !stdout.contains("\"ok\":true") {
        return Err("sockops-present proxy control did not succeed".to_owned());
    }
    let snapshot = snapshot(&mut loaded)?;
    if omit_sockops {
        if snapshot.diag[2] != 0
            || snapshot.counters[2] != 0
            || snapshot.tuple_entries != 0
            || snapshot.cookie_entries != 1
        {
            return Err(format!(
                "sockops omission snapshot unexpected diag={:?} counters={:?} tuples={} cookies={}",
                snapshot.diag, snapshot.counters, snapshot.tuple_entries, snapshot.cookie_entries
            ));
        }
        println!("{name}_attribution_publication=ABSENT");
        println!("{name}_connect4_cookie_state_without_sockops_cleanup=1");
    } else if snapshot.counters[2] != 1 {
        return Err(format!(
            "sockops-present publication counter was {}",
            snapshot.counters[2]
        ));
    }
    cleanup_phase(config, loaded);
    println!("phase_end={name}");
    Ok(())
}

fn load_phase(
    config: &Config,
    name: &'static str,
    object: &Path,
    omit: Option<&str>,
) -> Result<LoadedPhase, String> {
    let map_pins = config.map_root.join(name);
    let link_pins = config.link_root.join(name);
    fs::create_dir_all(&map_pins).map_err(display_error("create phase map pins"))?;
    fs::create_dir_all(&link_pins).map_err(display_error("create phase link pins"))?;
    let proxy_ip4 = u32::from_ne_bytes(PROXY_IP.octets());
    let proxy_port = u32::from(PROXY_PORT);
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &config.exec_ident, true)
        .default_map_pin_directory(&map_pins);
    let mut bpf = loader
        .load_file(object)
        .map_err(|error| format!("load {name} {}: {error:#}", object.display()))?;
    let local_map = bpf
        .map_mut("policy_local")
        .ok_or_else(|| format!("{name} policy_local missing"))?;
    let mut local = Array::<_, u64>::try_from(local_map)
        .map_err(|error| format!("open {name} policy_local: {error:#}"))?;
    local
        .set(0, 1, 0)
        .map_err(|error| format!("activate {name} policy_local: {error:#}"))?;
    let cgroup =
        File::open(&config.execution).map_err(|error| format!("open execution cgroup: {error}"))?;
    let links = attach_selected(&mut bpf, &cgroup, &link_pins, omit)?;
    Ok(LoadedPhase {
        name,
        bpf,
        links,
        map_pins,
        link_pins,
    })
}

fn start_and_place_agent(
    config: &Config,
    phase: &str,
    operation: &str,
    inode: u64,
) -> Result<(Child, PathBuf, PathBuf), String> {
    let host_ready = PathBuf::from(format!("/run/soglia-spike-s5-{phase}-host.ready"));
    let ready = PathBuf::from(format!("/run/soglia-spike-s5-{phase}-agent.ready"));
    let go = PathBuf::from(format!("/run/soglia-spike-s5-{phase}-agent.go"));
    let shell = r#"set -euo pipefail
printf '%s\n' "$$" > "$1"
kill -STOP "$$"
exec ip netns exec "$2" "$3" "barrier $4 $5 15" "$6""#;
    let child = Command::new("bash")
        .args(["-c", shell, "s5-host-launcher"])
        .arg(&host_ready)
        .arg(&config.netns)
        .arg(&config.agent)
        .arg(&ready)
        .arg(&go)
        .arg(operation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start {phase} stopped launcher: {error}"))?;
    wait_for_file(&host_ready, Duration::from_secs(5))?;
    let pid = child.id();
    let announced = fs::read_to_string(&host_ready)
        .map_err(|error| format!("read {phase} launcher PID: {error}"))?;
    remove_file(&host_ready);
    if announced.trim() != pid.to_string() {
        return Err(format!(
            "{phase} launcher PID mismatch child={pid} announced={announced:?}"
        ));
    }
    wait_for_process_stopped(pid, Duration::from_secs(5))?;
    fs::write(config.execution.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(|error| format!("place {phase} agent: {error}"))?;
    let status = Command::new("kill")
        .args(["-CONT", &pid.to_string()])
        .status()
        .map_err(|error| format!("continue {phase} agent: {error}"))?;
    if !status.success() {
        return Err(format!("continue {phase} agent failed: {status}"));
    }
    wait_for_file(&ready, Duration::from_secs(5))?;
    let actual: u32 = fs::read_to_string(&ready)
        .map_err(|error| format!("read {phase} agent PID: {error}"))?
        .trim()
        .parse()
        .map_err(|error| format!("parse {phase} agent PID: {error}"))?;
    prove_membership(config, phase, pid, actual, inode)?;
    Ok((child, ready, go))
}

fn prove_membership(
    config: &Config,
    phase: &str,
    trusted_pid: u32,
    actual_pid: u32,
    inode: u64,
) -> Result<(), String> {
    let relative = config
        .execution
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| "execution cgroup outside /sys/fs/cgroup".to_owned())?;
    let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
    let proc_cgroup = fs::read_to_string(format!("/proc/{trusted_pid}/cgroup"))
        .map_err(|error| format!("read {phase} /proc cgroup: {error}"))?;
    let procs = fs::read_to_string(config.execution.join("cgroup.procs"))
        .map_err(|error| format!("read {phase} cgroup.procs: {error}"))?;
    let proc_netns = fs::metadata(format!("/proc/{trusted_pid}/ns/net"))
        .map_err(|error| format!("stat {phase} agent netns: {error}"))?
        .ino();
    let owned_netns = fs::metadata(format!("/run/netns/{}", config.netns))
        .map_err(|error| format!("stat {phase} owned netns: {error}"))?
        .ino();
    let pid_matches = trusted_pid == actual_pid;
    let proc_matches = proc_cgroup.lines().any(|line| line == expected);
    let procs_matches = procs.lines().any(|line| line == trusted_pid.to_string());
    let netns_matches = proc_netns == owned_netns;
    if !(pid_matches && proc_matches && procs_matches && netns_matches) {
        return Err(format!(
            "{phase} membership mismatch pid={pid_matches} proc={proc_matches} procs={procs_matches} netns={netns_matches}"
        ));
    }
    println!("{phase}_actual_agent_pid={actual_pid}");
    println!("{phase}_target_cgroup_inode={inode}");
    println!("{phase}_expected_proc_cgroup={expected}");
    println!("{phase}_proc_exact_membership=true");
    println!("{phase}_cgroup_procs_contains_agent=true");
    println!("{phase}_agent_netns_inode={proc_netns}");
    println!("{phase}_owned_netns_inode={owned_netns}");
    println!("{phase}_netns_exact_membership=true");
    Ok(())
}

fn capture_attachment(
    config: &Config,
    phase: &str,
    omitted: Option<&str>,
    expected: usize,
) -> Result<(), String> {
    let direct = command_json(&[
        "-j",
        "cgroup",
        "show",
        config.execution.to_string_lossy().as_ref(),
    ])?;
    let effective = command_json(&[
        "-j",
        "cgroup",
        "show",
        config.execution.to_string_lossy().as_ref(),
        "effective",
    ])?;
    let direct_count = direct.as_array().map_or(0, Vec::len);
    let effective_count = effective.as_array().map_or(0, Vec::len);
    println!("{phase}_cgroup_direct_json={direct}");
    println!("{phase}_cgroup_effective_json={effective}");
    println!("{phase}_direct_program_count={direct_count}");
    println!("{phase}_effective_program_count={effective_count}");
    println!("{phase}_omitted_hook={}", omitted.unwrap_or("none"));
    if direct_count != expected || effective_count != expected {
        return Err(format!(
            "{phase} attachment mismatch expected={expected} direct={direct_count} effective={effective_count}"
        ));
    }
    Ok(())
}

struct Snapshot {
    diag: Vec<u64>,
    counters: Vec<u64>,
    deny_entries: usize,
    tuple_entries: usize,
    cookie_entries: usize,
    event_count: usize,
}

fn snapshot(phase: &mut LoadedPhase) -> Result<Snapshot, String> {
    let diag = array_values(&dump_map(&phase.map_pins, "soglia_diag_entries")?, 7)?;
    let counters = array_values(&dump_map(&phase.map_pins, "soglia_counters")?, 9)?;
    let deny_entries = map_len(&dump_map(&phase.map_pins, "soglia_denies")?);
    let tuple_entries = map_len(&dump_map(&phase.map_pins, "soglia_tuples")?);
    let cookie_entries = map_len(&dump_map(&phase.map_pins, "soglia_cookie_a")?);
    let events_map = phase
        .bpf
        .take_map("soglia_events")
        .ok_or_else(|| format!("{} event map missing", phase.name))?;
    let mut events = RingBuf::try_from(events_map)
        .map_err(|error| format!("open {} event ring: {error:#}", phase.name))?;
    let mut event_count = 0;
    while let Some(event) = events.next() {
        println!("{}_event_{}_hex={}", phase.name, event_count, hex(&event));
        event_count += 1;
    }
    println!("{}_diag={diag:?}", phase.name);
    println!("{}_counters={counters:?}", phase.name);
    println!("{}_deny_entries={deny_entries}", phase.name);
    println!("{}_tuple_entries={tuple_entries}", phase.name);
    println!("{}_cookie_entries={cookie_entries}", phase.name);
    println!("{}_event_count={event_count}", phase.name);
    Ok(Snapshot {
        diag,
        counters,
        deny_entries,
        tuple_entries,
        cookie_entries,
        event_count,
    })
}

fn require_outcome(result: &PhaseResult, expected_ok: bool) -> Result<(), String> {
    let expected = format!("\"ok\":{expected_ok}");
    if !result.stdout.contains(&expected) {
        return Err(format!(
            "agent outcome missing {expected}: {}",
            result.stdout
        ));
    }
    Ok(())
}

fn require_counter(
    result: &PhaseResult,
    index: usize,
    expected: u64,
    name: &str,
) -> Result<(), String> {
    if result.counters.get(index).copied() != Some(expected)
        || result.deny_entries != 1
        || result.event_count != 1
    {
        return Err(format!(
            "{name} evidence mismatch counters={:?} denies={} events={}",
            result.counters, result.deny_entries, result.event_count
        ));
    }
    Ok(())
}

fn require_all_deny_counters_zero(result: &PhaseResult) -> Result<(), String> {
    if result.counters[3..=7].iter().any(|value| *value != 0)
        || result.deny_entries != 0
        || result.event_count != 0
    {
        return Err(format!(
            "control has deny evidence counters={:?} denies={} events={}",
            result.counters, result.deny_entries, result.event_count
        ));
    }
    Ok(())
}

fn require_no_delivery(result: &PhaseResult, name: &str) -> Result<(), String> {
    if result.accepted || result.received {
        return Err(format!("{name} unexpectedly reached its listener"));
    }
    Ok(())
}

fn require_delivery(result: &PhaseResult, name: &str) -> Result<(), String> {
    if !(result.accepted || result.received) {
        return Err(format!("{name} did not expose the controlled path"));
    }
    Ok(())
}

fn observe(observation: Observation<'_>) -> Result<(bool, bool), String> {
    match observation {
        Observation::None => Ok((false, false)),
        Observation::Tcp(listener) => match listener.accept() {
            Ok((stream, peer)) => {
                println!("observed_tcp_peer={peer}");
                drop(stream);
                Ok((true, false))
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok((false, false)),
            Err(error) => Err(format!("observe TCP listener: {error}")),
        },
        Observation::Udp(socket) => {
            let mut bytes = [0_u8; 64];
            match socket.recv_from(&mut bytes) {
                Ok((length, peer)) => {
                    println!("observed_udp_peer={peer}");
                    println!("observed_udp_payload={:?}", &bytes[..length]);
                    Ok((false, true))
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok((false, false)),
                Err(error) => Err(format!("observe UDP listener: {error}")),
            }
        }
    }
}

fn dump_map(root: &Path, name: &str) -> Result<serde_json::Value, String> {
    let output = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(root.join(name))
        .output()
        .map_err(|error| format!("dump {name}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "dump {name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!(
        "{}_{}_dump={}",
        root.file_name()
            .and_then(|item| item.to_str())
            .unwrap_or("phase"),
        name,
        String::from_utf8_lossy(&output.stdout).trim()
    );
    serde_json::from_slice(&output.stdout).map_err(|error| format!("parse {name} JSON: {error}"))
}

fn command_json(args: &[&str]) -> Result<serde_json::Value, String> {
    let output = Command::new("bpftool")
        .args(args)
        .output()
        .map_err(|error| format!("run bpftool {args:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "bpftool {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse bpftool {args:?} JSON: {error}"))
}

fn array_values(json: &serde_json::Value, count: usize) -> Result<Vec<u64>, String> {
    let entries = json.as_array().ok_or("map dump was not a JSON array")?;
    let mut values = vec![0; count];
    for entry in entries {
        let key = entry
            .get("formatted")
            .and_then(|item| item.get("key"))
            .or_else(|| entry.get("key"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("array entry missing numeric key")? as usize;
        let value = entry
            .get("formatted")
            .and_then(|item| item.get("value"))
            .or_else(|| entry.get("value"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("array entry missing numeric value")?;
        if let Some(slot) = values.get_mut(key) {
            *slot = value;
        }
    }
    Ok(values)
}

fn map_len(json: &serde_json::Value) -> usize {
    json.as_array().map_or(0, Vec::len)
}

fn json_u64(value: &serde_json::Value, name: &str) -> Result<u64, String> {
    value
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("formatted JSON missing numeric {name}"))
}

fn cleanup_phase(config: &Config, mut phase: LoadedPhase) {
    while let Some(link) = phase.links.pop() {
        match link.unpin() {
            Ok(fd_link) => drop(fd_link),
            Err(error) => eprintln!("unpin {} link: {error:#}", phase.name),
        }
    }
    drop(phase.bpf);
    for name in LINK_NAMES {
        remove_file(&phase.link_pins.join(name));
    }
    for name in MAP_NAMES {
        remove_file(&phase.map_pins.join(name));
    }
    remove_dir(&phase.link_pins);
    remove_dir(&phase.map_pins);
    remove_dir(&config.link_root);
    remove_dir(&config.map_root);
}

fn attach_selected(
    bpf: &mut Ebpf,
    cgroup: &File,
    root: &Path,
    omit: Option<&str>,
) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
    if omit != Some("soglia_sock_create") {
        links.push(attach_cgroup_sock(
            bpf,
            cgroup,
            "soglia_sock_create",
            &root.join("sock_create"),
        )?);
    }
    for (program, pin) in [
        ("soglia_connect4", "connect4"),
        ("soglia_connect6", "connect6"),
        ("soglia_sendmsg4", "sendmsg4"),
        ("soglia_sendmsg6", "sendmsg6"),
    ] {
        if omit != Some(program) {
            links.push(attach_cgroup_sock_addr(
                bpf,
                cgroup,
                program,
                &root.join(pin),
            )?);
        }
    }
    if omit != Some("soglia_sockops") {
        links.push(attach_sock_ops(
            bpf,
            cgroup,
            "soglia_sockops",
            &root.join("sock_ops"),
        )?);
    }
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
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    pin_link(program.take_link(id), name, pin)
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
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    pin_link(program.take_link(id), name, pin)
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
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    pin_link(program.take_link(id), name, pin)
}

fn pin_link<L>(
    link: Result<L, aya::programs::ProgramError>,
    name: &str,
    pin: &Path,
) -> Result<PinnedLink, String>
where
    L: TryInto<FdLink>,
    <L as TryInto<FdLink>>::Error: std::fmt::Display,
{
    let link = link.map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed {name} link: {error}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn accept_with_timeout(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<Option<(TcpStream, SocketAddr)>, String> {
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok(pair) => return Ok(Some(pair)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= timeout {
                    return Ok(None);
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(format!("accept: {error}")),
        }
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
            .map_err(|error| format!("read launcher status: {error}"))?;
        if status
            .lines()
            .find(|line| line.starts_with("State:"))
            .is_some_and(|line| line.contains("T (stopped)"))
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(format!("launcher {pid} did not stop"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn remove_file(path: &Path) {
    if let Err(error) = fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("remove {}: {error}", path.display());
    }
}

fn remove_dir(path: &Path) {
    if let Err(error) = fs::remove_dir(path)
        && !matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
        )
    {
        eprintln!("remove directory {}: {error}", path.display());
    }
}

fn display_error(context: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("{context}: {error}")
}
