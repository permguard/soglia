// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Direct IPv4 deny characterization for S4 of the cgroup-BPF spike.
//!
//! EXPERIMENTAL: this is spike machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
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
const DIRECT_IP: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 2);
const DIRECT_PORT: u16 = 16_001;
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
    deny_object: PathBuf,
    control_object: PathBuf,
    execution: PathBuf,
    map_root: PathBuf,
    link_root: PathBuf,
    netns: String,
    agent: PathBuf,
    exec_ident: u64,
    ready: PathBuf,
    go: PathBuf,
    membership_ready: PathBuf,
    membership_captured: PathBuf,
    phase_b_ready: PathBuf,
    phase_b_go: PathBuf,
    phase_c_ready: PathBuf,
    phase_c_go: PathBuf,
    phase_c_observed: PathBuf,
    nft_restored: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            deny_object: next_path(&mut args, "deny BPF object")?,
            control_object: next_path(&mut args, "control BPF object")?,
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
            ready: next_path(&mut args, "ready marker")?,
            go: next_path(&mut args, "go marker")?,
            membership_ready: next_path(&mut args, "membership ready marker")?,
            membership_captured: next_path(&mut args, "membership captured marker")?,
            phase_b_ready: next_path(&mut args, "phase B ready marker")?,
            phase_b_go: next_path(&mut args, "phase B go marker")?,
            phase_c_ready: next_path(&mut args, "phase C ready marker")?,
            phase_c_go: next_path(&mut args, "phase C go marker")?,
            phase_c_observed: next_path(&mut args, "phase C observed marker")?,
            nft_restored: next_path(&mut args, "nft restored marker")?,
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

struct Snapshot {
    diag: Vec<u64>,
    counters: Vec<u64>,
    deny_entries: usize,
    event_count: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S4 DIRECT DENY ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    let inode = fs::metadata(&config.execution)
        .map_err(|error| format!("stat execution cgroup: {error}"))?
        .ino();
    println!("test=S4");
    println!("execution_cgroup={}", config.execution.display());
    println!("execution_cgroup_inode={inode}");
    println!("proxy_target={PROXY_IP}:{PROXY_PORT}");
    println!("direct_target={DIRECT_IP}:{DIRECT_PORT}");

    let proxy_listener = TcpListener::bind((PROXY_IP, PROXY_PORT))
        .map_err(|error| format!("bind proxy listener: {error}"))?;
    let direct_listener = TcpListener::bind((DIRECT_IP, DIRECT_PORT))
        .map_err(|error| format!("bind direct listener: {error}"))?;
    direct_listener
        .set_nonblocking(true)
        .map_err(|error| format!("set direct listener nonblocking: {error}"))?;

    let mut phase_a = load_phase(&config, "phase-a-nft-control", &config.control_object)?;
    fs::write(&config.ready, b"ready\n").map_err(display_error("write ready marker"))?;
    println!("state=PHASE_A_ATTACHED_READY");
    wait_for_file(&config.go, Duration::from_secs(30))?;

    let agent = start_and_place_agent(&config, inode)?;
    let pid = agent.id();
    let membership = prove_membership(&config, pid, inode)?;
    fs::write(&config.membership_ready, membership.as_bytes())
        .map_err(display_error("write membership ready"))?;
    println!("{membership}");
    println!("state=LIVE_MEMBERSHIP_PROVEN_BEFORE_TRAFFIC");
    wait_for_file(&config.membership_captured, Duration::from_secs(30))?;

    let agent_a_go = Path::new("/run/soglia-spike-s4-agent-a.go");
    fs::write(agent_a_go, b"go\n").map_err(display_error("release phase A"))?;
    let (mut proxy_stream, proxy_peer) =
        accept_with_timeout(&proxy_listener, Duration::from_secs(6))?
            .ok_or("phase A proxy path did not establish")?;
    let proxy_local = proxy_stream
        .local_addr()
        .map_err(|error| format!("phase A proxy local address: {error}"))?;
    let mut request = String::new();
    BufReader::new(
        proxy_stream
            .try_clone()
            .map_err(|error| format!("clone phase A proxy stream: {error}"))?,
    )
    .read_line(&mut request)
    .map_err(|error| format!("read phase A proxy request: {error}"))?;
    writeln!(proxy_stream, "ATTRIBUTED s4-execution-generation-1")
        .map_err(|error| format!("write phase A proxy response: {error}"))?;
    proxy_stream
        .flush()
        .map_err(|error| format!("flush phase A proxy response: {error}"))?;
    println!("phase_a_proxy_accepted_peer={proxy_peer}");
    println!("phase_a_proxy_accepted_local={proxy_local}");
    println!("phase_a_proxy_application={:?}", request.trim_end());
    println!("phase_a_proxy_involvement=true");
    wait_for_file(
        Path::new("/run/soglia-spike-s4-agent-b.ready"),
        Duration::from_secs(5),
    )?;
    let phase_a_direct = direct_accept(&direct_listener)?;
    println!("phase_a_direct_listener_accept={phase_a_direct}");
    let a = snapshot(&config, &mut phase_a)?;
    if phase_a_direct || a.counters[4] != 0 || a.diag[1] < 2 {
        return Err(format!(
            "phase A did not isolate nft enforcement: direct_accept={phase_a_direct} diag={:?} counters={:?}",
            a.diag, a.counters
        ));
    }
    cleanup_phase(&config, phase_a);

    let mut phase_b = load_phase(&config, "phase-b-bpf-deny", &config.deny_object)?;
    fs::write(&config.phase_b_ready, b"ready\n").map_err(display_error("write phase B ready"))?;
    println!("state=PHASE_B_BPF_DENY_ATTACHED_READY_FOR_NFT_RELAXATION");
    wait_for_file(&config.phase_b_go, Duration::from_secs(30))?;
    fs::write("/run/soglia-spike-s4-agent-b.go", b"go\n")
        .map_err(display_error("release phase B"))?;
    wait_for_file(
        Path::new("/run/soglia-spike-s4-agent-c.ready"),
        Duration::from_secs(5),
    )?;
    let phase_b_direct = direct_accept(&direct_listener)?;
    println!("phase_b_direct_listener_accept={phase_b_direct}");
    println!("phase_b_proxy_involvement=false");
    let b = snapshot(&config, &mut phase_b)?;
    if phase_b_direct
        || b.diag[1] != 1
        || b.counters[4] != 1
        || b.deny_entries != 1
        || b.event_count != 1
    {
        return Err(format!(
            "phase B denial was not uniquely attributable to BPF: direct_accept={phase_b_direct} diag={:?} counters={:?} denies={} events={}",
            b.diag, b.counters, b.deny_entries, b.event_count
        ));
    }
    cleanup_phase(&config, phase_b);

    let mut phase_c = load_phase(&config, "phase-c-path-control", &config.control_object)?;
    fs::write(&config.phase_c_ready, b"ready\n").map_err(display_error("write phase C ready"))?;
    println!("state=PHASE_C_DIRECT_CONTROL_ATTACHED_READY");
    wait_for_file(&config.phase_c_go, Duration::from_secs(30))?;
    fs::write("/run/soglia-spike-s4-agent-c.go", b"go\n")
        .map_err(display_error("release phase C"))?;
    let (direct_stream, direct_peer) =
        accept_with_timeout(&direct_listener, Duration::from_secs(5))?
            .ok_or("phase C direct path did not establish with nft and BPF controls relaxed")?;
    let direct_local = direct_stream
        .local_addr()
        .map_err(|error| format!("phase C direct local address: {error}"))?;
    println!("phase_c_direct_listener_accept=true");
    println!("phase_c_direct_accepted_peer={direct_peer}");
    println!("phase_c_direct_accepted_local={direct_local}");
    println!("phase_c_proxy_involvement=false");
    drop(direct_stream);
    let output = agent
        .wait_with_output()
        .map_err(|error| format!("wait for S4 agent: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("agent_status={}", output.status);
    println!("agent_stdout_begin\n{stdout}agent_stdout_end");
    eprintln!("agent_stderr_begin\n{stderr}agent_stderr_end");
    if !output.status.success() {
        return Err(format!("S4 agent exited with {}", output.status));
    }
    let outcomes: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains("\"cmd\":\"direct 10.201.0.2:16001\""))
        .collect();
    if outcomes.len() != 3
        || !outcomes[0].contains("\"ok\":false")
        || !outcomes[1].contains("\"ok\":false")
        || !outcomes[2].contains("\"ok\":true")
    {
        return Err(format!("unexpected ordered direct outcomes: {outcomes:?}"));
    }
    let c = snapshot(&config, &mut phase_c)?;
    if c.diag[1] != 1 || c.counters[4] != 0 || c.deny_entries != 0 {
        return Err(format!(
            "phase C BPF control did not expose the direct path: diag={:?} counters={:?} denies={}",
            c.diag, c.counters, c.deny_entries
        ));
    }
    fs::write(&config.phase_c_observed, b"observed\n")
        .map_err(display_error("write phase C observed"))?;
    println!("state=PHASE_C_PATH_EXPOSURE_PROVEN_WAITING_FOR_NFT_RESTORE");
    wait_for_file(&config.nft_restored, Duration::from_secs(30))?;
    cleanup_phase(&config, phase_c);
    println!("S4_RESULT=PASS");
    Ok(())
}

fn load_phase(config: &Config, name: &'static str, object: &Path) -> Result<LoadedPhase, String> {
    let suffix = name.split('-').nth(1).ok_or("invalid phase name")?;
    let map_pins = config.map_root.join(suffix);
    let link_pins = config.link_root.join(suffix);
    fs::create_dir_all(&map_pins).map_err(display_error("create phase map pins"))?;
    fs::create_dir_all(&link_pins).map_err(display_error("create phase link pins"))?;
    let proxy_ip4 = u32::from_ne_bytes(PROXY_IP.octets());
    let direct_ip4 = u32::from_ne_bytes(DIRECT_IP.octets());
    let proxy_port = u32::from(PROXY_PORT);
    let direct_port = u32::from(DIRECT_PORT);
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("direct_ip4", &direct_ip4, true)
        .override_global("direct_port", &direct_port, true)
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
    let links = attach_all(&mut bpf, &cgroup, &link_pins)?;
    println!(
        "phase_loaded name={name} object={} attached_links={} map_pins={} link_pins={}",
        object.display(),
        links.len(),
        map_pins.display(),
        link_pins.display()
    );
    Ok(LoadedPhase {
        name,
        bpf,
        links,
        map_pins,
        link_pins,
    })
}

fn start_and_place_agent(config: &Config, inode: u64) -> Result<Child, String> {
    let host_ready = "/run/soglia-spike-s4-host.ready";
    let shell = r#"set -euo pipefail
printf '%s\n' "$$" > "$1"
kill -STOP "$$"
exec ip netns exec "$2" "$3" \
  "barrier /run/soglia-spike-s4-agent-a.ready /run/soglia-spike-s4-agent-a.go 30" \
  "direct 10.201.0.2:16001" \
  "proxy 1" \
  "barrier /run/soglia-spike-s4-agent-b.ready /run/soglia-spike-s4-agent-b.go 30" \
  "direct 10.201.0.2:16001" \
  "barrier /run/soglia-spike-s4-agent-c.ready /run/soglia-spike-s4-agent-c.go 30" \
  "direct 10.201.0.2:16001""#;
    let child = Command::new("bash")
        .args(["-c", shell, "s4-host-launcher", host_ready])
        .arg(&config.netns)
        .arg(&config.agent)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start stopped S4 launcher: {error}"))?;
    wait_for_file(Path::new(host_ready), Duration::from_secs(5))?;
    let pid = child.id();
    let announced = fs::read_to_string(host_ready)
        .map_err(|error| format!("read stopped launcher PID: {error}"))?;
    if announced.trim() != pid.to_string() {
        return Err(format!(
            "launcher PID mismatch child={pid} announced={announced:?}"
        ));
    }
    wait_for_process_stopped(pid, Duration::from_secs(5))?;
    fs::write(config.execution.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(|error| format!("place S4 agent in execution cgroup: {error}"))?;
    let continued = Command::new("kill")
        .args(["-CONT", &pid.to_string()])
        .status()
        .map_err(|error| format!("continue S4 launcher: {error}"))?;
    if !continued.success() {
        return Err(format!("continue S4 launcher failed: {continued}"));
    }
    wait_for_file(
        Path::new("/run/soglia-spike-s4-agent-a.ready"),
        Duration::from_secs(5),
    )?;
    println!("agent_started pid={pid} expected_cgroup_inode={inode}");
    Ok(child)
}

fn prove_membership(config: &Config, pid: u32, inode: u64) -> Result<String, String> {
    let relative = config
        .execution
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| "execution cgroup outside /sys/fs/cgroup".to_owned())?;
    let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
    let proc_cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|error| format!("read live agent cgroup: {error}"))?;
    let procs = fs::read_to_string(config.execution.join("cgroup.procs"))
        .map_err(|error| format!("read target cgroup.procs: {error}"))?;
    let proc_matches = proc_cgroup.lines().any(|line| line == expected);
    let procs_matches = procs.lines().any(|line| line == pid.to_string());
    let proc_netns = fs::metadata(format!("/proc/{pid}/ns/net"))
        .map_err(|error| format!("stat live agent netns: {error}"))?
        .ino();
    let owned_netns = fs::metadata(format!("/run/netns/{}", config.netns))
        .map_err(|error| format!("stat owned netns: {error}"))?
        .ino();
    if !(proc_matches && procs_matches && proc_netns == owned_netns) {
        return Err(format!(
            "live membership mismatch proc={proc_matches} procs={procs_matches} proc_netns={proc_netns} owned_netns={owned_netns}"
        ));
    }
    Ok(format!(
        "actual_agent_pid={pid}\ntarget_cgroup={}\ntarget_cgroup_inode={inode}\nexpected_proc_cgroup_line={expected}\nproc_exact_membership=true\ncgroup_procs_contains_agent=true\nagent_netns_inode={proc_netns}\nowned_netns_inode={owned_netns}\nnetns_exact_membership=true",
        config.execution.display()
    ))
}

fn snapshot(config: &Config, phase: &mut LoadedPhase) -> Result<Snapshot, String> {
    let diag_json = dump_map(&phase.map_pins, "soglia_diag_entries")?;
    let counters_json = dump_map(&phase.map_pins, "soglia_counters")?;
    let denies_json = dump_map(&phase.map_pins, "soglia_denies")?;
    let tuples_json = dump_map(&phase.map_pins, "soglia_tuples")?;
    let cookies_json = dump_map(&phase.map_pins, "soglia_cookie_a")?;
    let diag = array_values(&diag_json, 7)?;
    let counters = array_values(&counters_json, 9)?;
    let deny_entries = denies_json.as_array().map_or(0, Vec::len);
    let tuple_entries = tuples_json.as_array().map_or(0, Vec::len);
    let cookie_entries = cookies_json.as_array().map_or(0, Vec::len);
    let events_map = phase
        .bpf
        .take_map("soglia_events")
        .ok_or_else(|| format!("{} soglia_events missing", phase.name))?;
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
    let _ = config;
    Ok(Snapshot {
        diag,
        counters,
        deny_entries,
        event_count,
    })
}

fn dump_map(root: &Path, name: &str) -> Result<serde_json::Value, String> {
    let output = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(root.join(name))
        .output()
        .map_err(|error| format!("dump {name}: {error}"))?;
    println!("{name}_dump_status={}", output.status);
    println!(
        "{name}_dump_stdout_begin\n{}{name}_dump_stdout_end",
        String::from_utf8_lossy(&output.stdout)
    );
    if !output.status.success() {
        return Err(format!(
            "dump {name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("parse {name} JSON: {error}"))
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

fn attach_all(bpf: &mut Ebpf, cgroup: &File, root: &Path) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
    links.push(attach_cgroup_sock(
        bpf,
        cgroup,
        "soglia_sock_create",
        &root.join("sock_create"),
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
            &root.join(pin),
        )?);
    }
    links.push(attach_sock_ops(
        bpf,
        cgroup,
        "soglia_sockops",
        &root.join("sock_ops"),
    )?);
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
    let link = program
        .take_link(id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed {name} link: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
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
    let link = program
        .take_link(id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed {name} link: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
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
    let link = program
        .take_link(id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed {name} link: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn accept_with_timeout(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<Option<(std::net::TcpStream, SocketAddr)>, String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set listener nonblocking: {error}"))?;
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
            Err(error) => return Err(format!("listener accept: {error}")),
        }
    }
}

fn direct_accept(listener: &TcpListener) -> Result<bool, String> {
    match listener.accept() {
        Ok((stream, peer)) => {
            println!("unexpected_direct_accept_peer={peer}");
            drop(stream);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("check direct listener: {error}")),
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
