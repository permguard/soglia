// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! S10 ancestor-destination-rewrite / final-nft-barrier characterization.
//!
//! EXPERIMENTAL: this is spike machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, File},
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

const ORIGINAL_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 255, 1);
const ORIGINAL_PORT: u16 = 15_001;
const REWRITTEN_IP: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 2);
const REWRITTEN_PORT: u16 = 16_001;
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
    control_object: PathBuf,
    normal_object: PathBuf,
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
    case_a_observed: PathBuf,
    case_b_go: PathBuf,
    case_b_observed: PathBuf,
    nft_restored: PathBuf,
    normal_ready: PathBuf,
    normal_go: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            control_object: next_path(&mut args, "control object")?,
            normal_object: next_path(&mut args, "normal object")?,
            execution: next_path(&mut args, "execution cgroup")?,
            map_root: next_path(&mut args, "map root")?,
            link_root: next_path(&mut args, "link root")?,
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
            case_a_observed: next_path(&mut args, "case A observed marker")?,
            case_b_go: next_path(&mut args, "case B go marker")?,
            case_b_observed: next_path(&mut args, "case B observed marker")?,
            nft_restored: next_path(&mut args, "nft restored marker")?,
            normal_ready: next_path(&mut args, "normal ready marker")?,
            normal_go: next_path(&mut args, "normal go marker")?,
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
    connect_port: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S10 REWRITE ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    let inode = fs::metadata(&config.execution)
        .map_err(|error| format!("stat execution cgroup: {error}"))?
        .ino();
    println!("test=S10");
    println!("execution_cgroup={}", config.execution.display());
    println!("execution_cgroup_inode={inode}");
    println!("original_destination={ORIGINAL_IP}:{ORIGINAL_PORT}");
    println!("rewritten_destination={REWRITTEN_IP}:{REWRITTEN_PORT}");

    let original_listener = TcpListener::bind((ORIGINAL_IP, ORIGINAL_PORT))
        .map_err(|error| format!("bind original listener: {error}"))?;
    let rewritten_listener = TcpListener::bind((REWRITTEN_IP, REWRITTEN_PORT))
        .map_err(|error| format!("bind rewritten listener: {error}"))?;
    original_listener
        .set_nonblocking(true)
        .map_err(|error| format!("set original listener nonblocking: {error}"))?;
    rewritten_listener
        .set_nonblocking(true)
        .map_err(|error| format!("set rewritten listener nonblocking: {error}"))?;

    let mut control = load_phase(&config, "control", &config.control_object)?;
    fs::write(&config.ready, b"ready\n").map_err(display_error("write ready"))?;
    wait_for_file(&config.go, Duration::from_secs(30))?;

    let agent = start_and_place_agent(&config)?;
    let pid = agent.id();
    let membership = prove_membership(&config, pid, inode)?;
    fs::write(&config.membership_ready, membership.as_bytes())
        .map_err(display_error("write membership ready"))?;
    println!("{membership}");
    wait_for_file(&config.membership_captured, Duration::from_secs(30))?;

    fs::write("/run/soglia-spike-s10-agent-a.go", b"go\n")
        .map_err(display_error("release case A"))?;
    wait_for_file(
        Path::new("/run/soglia-spike-s10-agent-b.ready"),
        Duration::from_secs(6),
    )?;
    let case_a_original_accept = direct_accept(&original_listener)?;
    let case_a_rewritten_accept = direct_accept(&rewritten_listener)?;
    let case_a = snapshot(&mut control, false)?;
    println!("case_a_original_listener_accept={case_a_original_accept}");
    println!("case_a_rewritten_listener_accept={case_a_rewritten_accept}");
    if case_a_original_accept
        || case_a_rewritten_accept
        || case_a.diag[1] != 1
        || case_a.counters[4] != 0
        || case_a.deny_entries != 0
    {
        return Err(format!(
            "case A was not isolated from child denial: original_accept={case_a_original_accept} rewritten_accept={case_a_rewritten_accept} diag={:?} counters={:?} denies={}",
            case_a.diag, case_a.counters, case_a.deny_entries
        ));
    }
    fs::write(&config.case_a_observed, b"observed\n")
        .map_err(display_error("write case A observed"))?;
    wait_for_file(&config.case_b_go, Duration::from_secs(30))?;

    fs::write("/run/soglia-spike-s10-agent-b.go", b"go\n")
        .map_err(display_error("release case B"))?;
    let (rewritten_stream, rewritten_peer) =
        accept_with_timeout(&rewritten_listener, Duration::from_secs(5))?
            .ok_or("case B rewritten listener did not accept")?;
    println!("case_b_rewritten_listener_accept=true");
    println!("case_b_rewritten_peer={rewritten_peer}");
    println!(
        "case_b_rewritten_local={}",
        rewritten_stream
            .local_addr()
            .map_err(|error| format!("case B local address: {error}"))?
    );
    drop(rewritten_stream);
    wait_for_file(
        Path::new("/run/soglia-spike-s10-agent-c.ready"),
        Duration::from_secs(5),
    )?;
    let case_b_original_accept = direct_accept(&original_listener)?;
    let case_b = snapshot(&mut control, true)?;
    println!("case_b_original_listener_accept={case_b_original_accept}");
    if case_b_original_accept
        || case_b.diag[1] != 2
        || case_b.counters[4] != 0
        || case_b.deny_entries != 0
        || case_b.event_count != 0
    {
        return Err(format!(
            "case B child control was not permissive: original_accept={case_b_original_accept} diag={:?} counters={:?} denies={} events={}",
            case_b.diag, case_b.counters, case_b.deny_entries, case_b.event_count
        ));
    }
    fs::write(&config.case_b_observed, b"observed\n")
        .map_err(display_error("write case B observed"))?;
    wait_for_file(&config.nft_restored, Duration::from_secs(30))?;
    cleanup_phase(&config, control);

    let mut normal = load_phase(&config, "normal", &config.normal_object)?;
    fs::write(&config.normal_ready, b"ready\n").map_err(display_error("write normal ready"))?;
    wait_for_file(&config.normal_go, Duration::from_secs(30))?;
    fs::write("/run/soglia-spike-s10-agent-c.go", b"go\n")
        .map_err(display_error("release normal composition"))?;

    let output = agent
        .wait_with_output()
        .map_err(|error| format!("wait for S10 agent: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("agent_status={}", output.status);
    println!("agent_stdout_begin\n{stdout}agent_stdout_end");
    eprintln!("agent_stderr_begin\n{stderr}agent_stderr_end");
    if !output.status.success() {
        return Err(format!("S10 agent exited with {}", output.status));
    }
    let outcomes: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains("\"cmd\":\"direct 10.200.255.1:15001\""))
        .collect();
    if outcomes.len() != 3
        || !outcomes[0].contains("\"ok\":false")
        || !outcomes[1].contains("\"ok\":true")
        || !outcomes[2].contains("\"ok\":false")
    {
        return Err(format!("unexpected ordered S10 outcomes: {outcomes:?}"));
    }
    let normal_original_accept = direct_accept(&original_listener)?;
    let normal_rewritten_accept = direct_accept(&rewritten_listener)?;
    let normal_snapshot = snapshot(&mut normal, true)?;
    println!("normal_original_listener_accept={normal_original_accept}");
    println!("normal_rewritten_listener_accept={normal_rewritten_accept}");
    let observed = normal_snapshot.connect_port;
    let order = if observed == u64::from(ORIGINAL_PORT) {
        "child_saw_original_then_foreign_rewrite_observed"
    } else if observed == u64::from(REWRITTEN_PORT) {
        "foreign_rewrite_then_child_saw_rewritten"
    } else {
        return Err(format!("normal child observed unexpected port {observed}"));
    };
    println!("normal_composition_observed={order}");
    if normal_original_accept || normal_rewritten_accept {
        return Err("normal composition unexpectedly established".to_owned());
    }
    if observed == u64::from(ORIGINAL_PORT)
        && (normal_snapshot.counters[4] != 0 || normal_snapshot.deny_entries != 0)
    {
        return Err(format!(
            "child saw original but recorded deny: counters={:?} denies={}",
            normal_snapshot.counters, normal_snapshot.deny_entries
        ));
    }
    if observed == u64::from(REWRITTEN_PORT)
        && (normal_snapshot.counters[4] != 1 || normal_snapshot.deny_entries != 1)
    {
        return Err(format!(
            "child saw rewritten target without its expected deny: counters={:?} denies={}",
            normal_snapshot.counters, normal_snapshot.deny_entries
        ));
    }
    cleanup_phase(&config, normal);
    println!("S10_HARNESS_RESULT=PASS");
    Ok(())
}

fn load_phase(config: &Config, name: &'static str, object: &Path) -> Result<LoadedPhase, String> {
    let map_pins = config.map_root.join(name);
    let link_pins = config.link_root.join(name);
    fs::create_dir_all(&map_pins).map_err(display_error("create map pins"))?;
    fs::create_dir_all(&link_pins).map_err(display_error("create link pins"))?;
    let original_ip4 = u32::from_ne_bytes(ORIGINAL_IP.octets());
    let rewritten_ip4 = u32::from_ne_bytes(REWRITTEN_IP.octets());
    let original_port = u32::from(ORIGINAL_PORT);
    let rewritten_port = u32::from(REWRITTEN_PORT);
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &original_ip4, true)
        .override_global("proxy_port", &original_port, true)
        .override_global("direct_ip4", &rewritten_ip4, true)
        .override_global("direct_port", &rewritten_port, true)
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
        .map_err(|error| format!("activate {name} policy: {error:#}"))?;
    let cgroup = File::open(&config.execution).map_err(|error| format!("open cgroup: {error}"))?;
    let links = attach_all(&mut bpf, &cgroup, &link_pins)?;
    println!(
        "phase_loaded name={name} object={} links={}",
        object.display(),
        links.len()
    );
    Ok(LoadedPhase {
        name,
        bpf,
        links,
        map_pins,
        link_pins,
    })
}

fn snapshot(phase: &mut LoadedPhase, drain_events: bool) -> Result<Snapshot, String> {
    let diag = array_values(&dump_map(&phase.map_pins, "soglia_diag_entries")?, 7)?;
    let counters = array_values(&dump_map(&phase.map_pins, "soglia_counters")?, 9)?;
    let ports = array_values(&dump_map(&phase.map_pins, "soglia_port_diag")?, 12)?;
    let denies = dump_map(&phase.map_pins, "soglia_denies")?;
    let tuples = dump_map(&phase.map_pins, "soglia_tuples")?;
    let cookies = dump_map(&phase.map_pins, "soglia_cookie_a")?;
    let deny_entries = denies.as_array().map_or(0, Vec::len);
    let mut event_count = 0;
    if drain_events {
        let events_map = phase
            .bpf
            .take_map("soglia_events")
            .ok_or_else(|| format!("{} events map missing", phase.name))?;
        let mut events = RingBuf::try_from(events_map)
            .map_err(|error| format!("open {} events: {error:#}", phase.name))?;
        while let Some(event) = events.next() {
            println!("{}_event_{}_hex={}", phase.name, event_count, hex(&event));
            event_count += 1;
        }
    }
    println!("{}_diag={diag:?}", phase.name);
    println!("{}_counters={counters:?}", phase.name);
    println!("{}_ports={ports:?}", phase.name);
    println!("{}_deny_entries={deny_entries}", phase.name);
    println!(
        "{}_tuple_entries={}",
        phase.name,
        tuples.as_array().map_or(0, Vec::len)
    );
    println!(
        "{}_cookie_entries={}",
        phase.name,
        cookies.as_array().map_or(0, Vec::len)
    );
    println!("{}_event_count={event_count}", phase.name);
    Ok(Snapshot {
        diag,
        counters,
        deny_entries,
        event_count,
        connect_port: ports[2],
    })
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
    serde_json::from_slice(&output.stdout).map_err(|error| format!("parse {name}: {error}"))
}

fn array_values(json: &serde_json::Value, count: usize) -> Result<Vec<u64>, String> {
    let entries = json.as_array().ok_or("map dump was not an array")?;
    let mut values = vec![0; count];
    for entry in entries {
        let key = entry
            .get("formatted")
            .and_then(|item| item.get("key"))
            .or_else(|| entry.get("key"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("array key missing")? as usize;
        let value = entry
            .get("formatted")
            .and_then(|item| item.get("value"))
            .or_else(|| entry.get("value"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("array value missing")?;
        if let Some(slot) = values.get_mut(key) {
            *slot = value;
        }
    }
    Ok(values)
}

fn start_and_place_agent(config: &Config) -> Result<Child, String> {
    let host_ready = "/run/soglia-spike-s10-host.ready";
    let shell = r#"set -euo pipefail
printf '%s\n' "$$" > "$1"
kill -STOP "$$"
exec ip netns exec "$2" "$3" \
  "barrier /run/soglia-spike-s10-agent-a.ready /run/soglia-spike-s10-agent-a.go 30" \
  "direct 10.200.255.1:15001" \
  "barrier /run/soglia-spike-s10-agent-b.ready /run/soglia-spike-s10-agent-b.go 30" \
  "direct 10.200.255.1:15001" \
  "barrier /run/soglia-spike-s10-agent-c.ready /run/soglia-spike-s10-agent-c.go 30" \
  "direct 10.200.255.1:15001""#;
    let child = Command::new("bash")
        .args(["-c", shell, "s10-host-launcher", host_ready])
        .arg(&config.netns)
        .arg(&config.agent)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start S10 agent: {error}"))?;
    wait_for_file(Path::new(host_ready), Duration::from_secs(5))?;
    let pid = child.id();
    wait_for_process_stopped(pid, Duration::from_secs(5))?;
    fs::write(config.execution.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(|error| format!("place S10 agent: {error}"))?;
    let status = Command::new("kill")
        .args(["-CONT", &pid.to_string()])
        .status()
        .map_err(|error| format!("continue agent: {error}"))?;
    if !status.success() {
        return Err(format!("continue agent failed: {status}"));
    }
    wait_for_file(
        Path::new("/run/soglia-spike-s10-agent-a.ready"),
        Duration::from_secs(5),
    )?;
    Ok(child)
}

fn prove_membership(config: &Config, pid: u32, inode: u64) -> Result<String, String> {
    let relative = config
        .execution
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| "execution outside cgroupfs".to_owned())?;
    let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
    let proc_cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|error| format!("read proc cgroup: {error}"))?;
    let procs = fs::read_to_string(config.execution.join("cgroup.procs"))
        .map_err(|error| format!("read cgroup.procs: {error}"))?;
    let proc_netns = fs::metadata(format!("/proc/{pid}/ns/net"))
        .map_err(|error| format!("stat process netns: {error}"))?
        .ino();
    let owned_netns = fs::metadata(format!("/run/netns/{}", config.netns))
        .map_err(|error| format!("stat owned netns: {error}"))?
        .ino();
    let proc_matches = proc_cgroup.lines().any(|line| line == expected);
    let procs_matches = procs.lines().any(|line| line == pid.to_string());
    if !(proc_matches && procs_matches && proc_netns == owned_netns) {
        return Err("live agent membership mismatch".to_owned());
    }
    Ok(format!(
        "actual_agent_pid={pid}\ntarget_cgroup={}\ntarget_cgroup_inode={inode}\nexpected_proc_cgroup_line={expected}\nproc_exact_membership=true\ncgroup_procs_contains_agent=true\nagent_netns_inode={proc_netns}\nowned_netns_inode={owned_netns}\nnetns_exact_membership=true",
        config.execution.display()
    ))
}

fn attach_all(bpf: &mut Ebpf, cgroup: &File, root: &Path) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
    let program: &mut CgroupSock = bpf
        .program_mut("soglia_sock_create")
        .ok_or("sock_create missing")?
        .try_into()
        .map_err(|error| format!("convert sock_create: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load sock_create: {error:#}"))?;
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach sock_create: {error:#}"))?;
    links.push(pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take sock_create: {error:#}"))?,
        &root.join("sock_create"),
    )?);
    for (name, pin) in [
        ("soglia_connect4", "connect4"),
        ("soglia_connect6", "connect6"),
        ("soglia_sendmsg4", "sendmsg4"),
        ("soglia_sendmsg6", "sendmsg6"),
    ] {
        let program: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .ok_or_else(|| format!("{name} missing"))?
            .try_into()
            .map_err(|error| format!("convert {name}: {error:#}"))?;
        program
            .load()
            .map_err(|error| format!("load {name}: {error:#}"))?;
        let id = program
            .attach(cgroup, CgroupAttachMode::Single)
            .map_err(|error| format!("attach {name}: {error:#}"))?;
        links.push(pin_link(
            program
                .take_link(id)
                .map_err(|error| format!("take {name}: {error:#}"))?,
            &root.join(pin),
        )?);
    }
    let program: &mut SockOps = bpf
        .program_mut("soglia_sockops")
        .ok_or("sockops missing")?
        .try_into()
        .map_err(|error| format!("convert sockops: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load sockops: {error:#}"))?;
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach sockops: {error:#}"))?;
    links.push(pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take sockops: {error:#}"))?,
        &root.join("sock_ops"),
    )?);
    Ok(links)
}

fn pin_link<L>(link: L, pin: &Path) -> Result<PinnedLink, String>
where
    L: TryInto<FdLink>,
    <L as TryInto<FdLink>>::Error: std::fmt::Debug,
{
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed link: {error:?}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {}: {error:#}", pin.display()))
}

fn cleanup_phase(config: &Config, mut phase: LoadedPhase) {
    while let Some(link) = phase.links.pop() {
        match link.unpin() {
            Ok(fd) => drop(fd),
            Err(error) => eprintln!("unpin {}: {error:#}", phase.name),
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

fn accept_with_timeout(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<Option<(std::net::TcpStream, SocketAddr)>, String> {
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
            println!("unexpected_accept_peer={peer}");
            drop(stream);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("listener accept: {error}")),
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
