// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Concurrent cross-attribution harness for S2 of the cgroup-BPF spike.
//!
//! EXPERIMENTAL: this is spike machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use soglia_spike_runner::command::{CommandExecutor, CommandSpec, RunningCommand};
use soglia_spike_runner::evidence::EvidenceRecorder;

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap, MapData, RingBuf},
    programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps,
        links::{FdLink, PinnedLink},
    },
};

const EXECUTION_COUNT: usize = 4;
const CONNECTIONS_PER_EXECUTION: usize = 33;
const TIMEOUTS_PER_EXECUTION: usize = 1;
const SOURCE_PORT_BASE: u16 = 40_000;
const TIMEOUT_SOURCE_PORT: u16 = SOURCE_PORT_BASE + CONNECTIONS_PER_EXECUTION as u16 - 1;
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
    object: PathBuf,
    executions: PathBuf,
    map_pin_root: PathBuf,
    link_pin_root: PathBuf,
    agent: PathBuf,
    ready_file: PathBuf,
    go_file: PathBuf,
    membership_ready_file: PathBuf,
    membership_captured_file: PathBuf,
    evidence_root: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            object: next_path(&mut args, "BPF object")?,
            executions: next_path(&mut args, "executions cgroup root")?,
            map_pin_root: next_path(&mut args, "map pin root")?,
            link_pin_root: next_path(&mut args, "link pin root")?,
            agent: next_path(&mut args, "agent binary")?,
            ready_file: next_path(&mut args, "ready file")?,
            go_file: next_path(&mut args, "go file")?,
            membership_ready_file: next_path(&mut args, "membership ready file")?,
            membership_captured_file: next_path(&mut args, "membership captured file")?,
            evidence_root: next_path(&mut args, "evidence root")?,
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

#[derive(Clone)]
struct Execution {
    index: usize,
    id: String,
    cgroup: PathBuf,
    netns: String,
    ip: Ipv4Addr,
    ident: u64,
    inode: u64,
    host_ready: PathBuf,
    agent_ready: PathBuf,
    agent_go: PathBuf,
}

impl Execution {
    fn all(config: &Config) -> Result<Vec<Self>, String> {
        let ips = [
            Ipv4Addr::new(10, 201, 0, 1),
            Ipv4Addr::new(10, 201, 0, 5),
            Ipv4Addr::new(10, 201, 0, 9),
            Ipv4Addr::new(10, 201, 0, 13),
        ];
        (0..EXECUTION_COUNT)
            .map(|index| {
                let cgroup = config.executions.join(format!("s2-e{index}"));
                let inode = fs::metadata(&cgroup)
                    .map_err(|error| format!("stat {}: {error}", cgroup.display()))?
                    .ino();
                Ok(Self {
                    index,
                    id: format!("s2-execution-e{index}-generation-1"),
                    cgroup,
                    netns: format!("soglia-s2-e{index}"),
                    ip: ips[index],
                    ident: 2_001_001 + index as u64,
                    inode,
                    host_ready: PathBuf::from(format!("/run/soglia-spike-s2-e{index}-host.ready")),
                    agent_ready: PathBuf::from(format!(
                        "/run/soglia-spike-s2-e{index}-agent.ready"
                    )),
                    agent_go: PathBuf::from(format!("/run/soglia-spike-s2-e{index}-agent.go")),
                })
            })
            .collect()
    }
}

struct LoadedExecution {
    bpf: Ebpf,
    links: Vec<PinnedLink>,
}

struct LiveAgent {
    execution_index: usize,
    pid: u32,
    child: RunningCommand,
}

struct Connection {
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    key: [u8; 16],
    origin: usize,
    accepted_at: Instant,
    publish_delay: Duration,
    timeout_case: bool,
    resolved: bool,
    cookie: Option<u64>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S2 CONCURRENCY ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    let recorder = EvidenceRecorder::open_existing(&config.evidence_root)
        .map_err(|error| format!("open evidence root: {error}"))?;
    let commands = CommandExecutor::new(recorder, "s2/helper");
    fs::create_dir_all(&config.map_pin_root).map_err(display_error("create map pin root"))?;
    fs::create_dir_all(&config.link_pin_root).map_err(display_error("create link pin root"))?;
    let executions = Execution::all(&config)?;

    println!("test=S2");
    println!("execution_count={EXECUTION_COUNT}");
    println!("connections_per_execution={CONNECTIONS_PER_EXECUTION}");
    println!(
        "connection_count={}",
        EXECUTION_COUNT * CONNECTIONS_PER_EXECUTION
    );
    println!("source_port_range={SOURCE_PORT_BASE}-{TIMEOUT_SOURCE_PORT}");
    println!("same_source_ports_reused_across_netns=true");
    println!("proxy=10.200.255.1:15001");

    let mut loaded = Vec::with_capacity(executions.len());
    for execution in &executions {
        let mut bpf = load_for_execution(&config, execution)?;
        let cgroup = File::open(&execution.cgroup)
            .map_err(|error| format!("open {}: {error}", execution.cgroup.display()))?;
        let link_root = config.link_pin_root.join(format!("e{}", execution.index));
        fs::create_dir_all(&link_root).map_err(display_error("create execution link root"))?;
        let links = attach_all(&mut bpf, &cgroup, &link_root)?;
        println!(
            "execution_loaded index={} id={} cgroup={} inode={} ip={} netns={} ident={} attached_links={}",
            execution.index,
            execution.id,
            execution.cgroup.display(),
            execution.inode,
            execution.ip,
            execution.netns,
            execution.ident,
            links.len()
        );
        loaded.push(LoadedExecution { bpf, links });
    }

    let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
        .map_err(|error| format!("bind S2 proxy: {error}"))?;
    fs::write(&config.ready_file, b"ready\n")
        .map_err(|error| format!("write ready file: {error}"))?;
    println!("state=READY_FOR_ATTACH_SNAPSHOT");
    wait_for_file(&config.go_file, Duration::from_secs(30))?;

    let mut agents = Vec::with_capacity(executions.len());
    for execution in &executions {
        agents.push(start_and_place_agent(&config, execution, &commands)?);
    }
    let mapping = trusted_mapping(&executions, &agents)?;
    fs::write(&config.membership_ready_file, mapping.as_bytes())
        .map_err(|error| format!("write S2 membership ready: {error}"))?;
    println!("trusted_mapping_begin");
    print!("{mapping}");
    println!("trusted_mapping_end");
    println!("state=ALL_MEMBERSHIPS_PROVEN_BEFORE_TRAFFIC");
    wait_for_file(&config.membership_captured_file, Duration::from_secs(30))?;
    for execution in &executions {
        fs::write(&execution.agent_go, b"go\n")
            .map_err(|error| format!("release agent {}: {error}", execution.index))?;
    }

    let result = exercise(
        &config,
        &executions,
        &mut loaded,
        agents,
        listener,
        &commands,
    );
    println!("state=CLEANUP_BEGIN");
    for item in &mut loaded {
        cleanup_links(&mut item.links);
    }
    drop(loaded);
    remove_pins(&config, &executions);
    println!("state=CLEANUP_COMPLETE");
    result
}

fn load_for_execution(config: &Config, execution: &Execution) -> Result<Ebpf, String> {
    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &execution.ident, true)
        .default_map_pin_directory(&config.map_pin_root);
    let mut bpf = loader.load_file(&config.object).map_err(|error| {
        format!(
            "load {} for e{}: {error:#}",
            config.object.display(),
            execution.index
        )
    })?;
    let local_map = bpf
        .map_mut("policy_local")
        .ok_or_else(|| format!("policy_local missing for e{}", execution.index))?;
    let mut local = Array::<_, u64>::try_from(local_map)
        .map_err(|error| format!("open policy_local for e{}: {error:#}", execution.index))?;
    local
        .set(0, 1, 0)
        .map_err(|error| format!("activate policy_local for e{}: {error:#}", execution.index))?;
    Ok(bpf)
}

fn start_and_place_agent(
    config: &Config,
    execution: &Execution,
    commands: &CommandExecutor,
) -> Result<LiveAgent, String> {
    let shell = r#"set -euo pipefail
printf '%s\n' "$$" > "$1"
printf 'host_launcher_pid=%s\n' "$$" >&2
kill -STOP "$$"
exec ip netns exec "$2" "$3" "barrier $4 $5 30" "proxy-fixed 40000 33""#;
    let child = commands
        .spawn(&CommandSpec::new("bash").args([
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(shell),
            std::ffi::OsString::from("s2-host-launcher"),
            execution.host_ready.clone().into_os_string(),
            std::ffi::OsString::from(&execution.netns),
            config.agent.clone().into_os_string(),
            execution.agent_ready.clone().into_os_string(),
            execution.agent_go.clone().into_os_string(),
        ]))
        .map_err(|error| format!("start e{} stopped launcher: {error}", execution.index))?;
    wait_for_file(&execution.host_ready, Duration::from_secs(5))?;
    let pid = child.id();
    let announced: u32 = fs::read_to_string(&execution.host_ready)
        .map_err(|error| format!("read e{} host PID: {error}", execution.index))?
        .trim()
        .parse()
        .map_err(|error| format!("parse e{} host PID: {error}", execution.index))?;
    wait_for_process_stopped(pid, Duration::from_secs(5))?;
    fs::write(execution.cgroup.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(|error| format!("place e{} PID: {error}", execution.index))?;
    verify_cgroup_membership(execution, pid, announced, false)?;
    kill(
        Pid::from_raw(i32::try_from(pid).map_err(|error| error.to_string())?),
        Signal::SIGCONT,
    )
    .map_err(|error| format!("continue e{} launcher: {error}", execution.index))?;
    wait_for_file(&execution.agent_ready, Duration::from_secs(5))?;
    let agent_pid: u32 = fs::read_to_string(&execution.agent_ready)
        .map_err(|error| format!("read e{} agent PID: {error}", execution.index))?
        .trim()
        .parse()
        .map_err(|error| format!("parse e{} agent PID: {error}", execution.index))?;
    verify_cgroup_membership(execution, pid, agent_pid, true)?;
    println!(
        "agent_placement index={} pid={} cgroup_inode={} netns={} status=PROVEN",
        execution.index, pid, execution.inode, execution.netns
    );
    Ok(LiveAgent {
        execution_index: execution.index,
        pid,
        child,
    })
}

fn verify_cgroup_membership(
    execution: &Execution,
    trusted_pid: u32,
    announced_pid: u32,
    require_netns: bool,
) -> Result<(), String> {
    let relative = execution
        .cgroup
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| "S2 cgroup outside /sys/fs/cgroup".to_owned())?;
    let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
    let proc_cgroup = fs::read_to_string(format!("/proc/{trusted_pid}/cgroup"))
        .map_err(|error| format!("read e{} /proc cgroup: {error}", execution.index))?;
    let procs = fs::read_to_string(execution.cgroup.join("cgroup.procs"))
        .map_err(|error| format!("read e{} cgroup.procs: {error}", execution.index))?;
    let pid_matches = trusted_pid == announced_pid;
    let proc_matches = proc_cgroup.lines().any(|line| line == expected);
    let procs_matches = procs.lines().any(|line| line == trusted_pid.to_string());
    let netns_matches = if require_netns {
        fs::metadata(format!("/proc/{trusted_pid}/ns/net"))
            .map_err(|error| format!("stat e{} agent netns: {error}", execution.index))?
            .ino()
            == fs::metadata(format!("/run/netns/{}", execution.netns))
                .map_err(|error| format!("stat e{} owned netns: {error}", execution.index))?
                .ino()
    } else {
        true
    };
    if !(pid_matches && proc_matches && procs_matches && netns_matches) {
        return Err(format!(
            "e{} placement mismatch pid_matches={pid_matches} proc_matches={proc_matches} procs_matches={procs_matches} netns_matches={netns_matches}",
            execution.index
        ));
    }
    Ok(())
}

fn trusted_mapping(executions: &[Execution], agents: &[LiveAgent]) -> Result<String, String> {
    let mut mapping = String::new();
    for execution in executions {
        let agent = agents
            .iter()
            .find(|agent| agent.execution_index == execution.index)
            .ok_or_else(|| format!("missing live agent for e{}", execution.index))?;
        let netns_inode = fs::metadata(format!("/proc/{}/ns/net", agent.pid))
            .map_err(|error| format!("stat e{} live netns: {error}", execution.index))?
            .ino();
        mapping.push_str(&format!(
            "index={} execution_id={} cgroup={} cgroup_inode={} agent_pid={} netns={} netns_inode={} ip={} expected_ident={}\n",
            execution.index,
            execution.id,
            execution.cgroup.display(),
            execution.inode,
            agent.pid,
            execution.netns,
            netns_inode,
            execution.ip,
            execution.ident
        ));
    }
    Ok(mapping)
}

fn exercise(
    config: &Config,
    executions: &[Execution],
    loaded: &mut [LoadedExecution],
    agents: Vec<LiveAgent>,
    listener: TcpListener,
    commands: &CommandExecutor,
) -> Result<(), String> {
    let first = loaded.first_mut().ok_or("no loaded S2 instance")?;
    let tuples_map = first
        .bpf
        .take_map("soglia_tuples")
        .ok_or("soglia_tuples missing")?;
    let mut tuples = HashMap::<_, [u8; 16], [u8; 64]>::try_from(tuples_map)
        .map_err(|error| format!("open shared tuples: {error:#}"))?;
    let staging_map = first
        .bpf
        .take_map("soglia_staging")
        .ok_or("S2 requires soglia_staging")?;
    let mut staging = HashMap::<_, [u8; 16], [u8; 64]>::try_from(staging_map)
        .map_err(|error| format!("open shared staging: {error:#}"))?;
    let events_map = first
        .bpf
        .take_map("soglia_events")
        .ok_or("soglia_events missing")?;
    let mut events =
        RingBuf::try_from(events_map).map_err(|error| format!("open shared events: {error:#}"))?;

    let ip_to_execution: StdHashMap<Ipv4Addr, usize> = executions
        .iter()
        .map(|execution| (execution.ip, execution.index))
        .collect();
    let total = EXECUTION_COUNT * CONNECTIONS_PER_EXECUTION;
    let timeout_total = EXECUTION_COUNT * TIMEOUTS_PER_EXECUTION;
    let success_total = total - timeout_total;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set S2 listener nonblocking: {error}"))?;
    let started = Instant::now();
    let mut connections = Vec::with_capacity(total);
    let mut tuple_keys = HashSet::with_capacity(total);
    let mut port_origins: StdHashMap<u16, HashSet<usize>> = StdHashMap::new();
    while connections.len() < total {
        match listener.accept() {
            Ok((stream, peer)) => {
                let local = stream
                    .local_addr()
                    .map_err(|error| format!("S2 accepted local: {error}"))?;
                let SocketAddr::V4(peer4) = peer else {
                    return Err("S2 accepted non-IPv4 peer".to_owned());
                };
                let origin = *ip_to_execution
                    .get(peer4.ip())
                    .ok_or_else(|| format!("untrusted S2 peer IP {}", peer4.ip()))?;
                if !(SOURCE_PORT_BASE..=TIMEOUT_SOURCE_PORT).contains(&peer4.port()) {
                    return Err(format!("unexpected S2 source port {}", peer4.port()));
                }
                let key = tuple_key(peer, local)?;
                if !tuple_keys.insert(key) {
                    return Err(format!("duplicate complete tuple for {peer}"));
                }
                port_origins.entry(peer4.port()).or_default().insert(origin);
                match tuples.get(&key, 0) {
                    Err(aya::maps::MapError::KeyNotFound) => {}
                    Ok(_) => return Err(format!("tuple visible before S2 promotion for {peer}")),
                    Err(error) => return Err(format!("S2 initial tuple lookup: {error:#}")),
                }
                let staging_visible = staging.get(&key, 0).is_ok();
                let delay_ms = 25 + ((peer4.port() as usize + origin * 13) % 16) as u64 * 10;
                let timeout_case = peer4.port() == TIMEOUT_SOURCE_PORT;
                println!(
                    "s2_accept index={} origin=e{} execution_id={} peer={} local={} tuple_hex={} tuple_visible=false staging_visible={} delay_ms={} timeout_case={}",
                    connections.len(),
                    origin,
                    executions[origin].id,
                    peer,
                    local,
                    hex(&key),
                    staging_visible,
                    delay_ms,
                    timeout_case
                );
                connections.push(Connection {
                    stream,
                    peer,
                    local,
                    key,
                    origin,
                    accepted_at: Instant::now(),
                    publish_delay: Duration::from_millis(delay_ms),
                    timeout_case,
                    resolved: false,
                    cookie: None,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= Duration::from_secs(10) {
                    return Err(format!("S2 accepted only {} of {total}", connections.len()));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("S2 proxy accept: {error}")),
        }
    }
    let reused_ports = port_origins
        .values()
        .filter(|origins| origins.len() == EXECUTION_COUNT)
        .count();
    println!("concurrent_unresolved_peak={total}");
    println!("unique_complete_tuple_count={}", tuple_keys.len());
    println!("source_ports_reused_by_all_executions={reused_ports}");
    if reused_ports != CONNECTIONS_PER_EXECUTION {
        return Err(format!(
            "only {reused_ports}/{CONNECTIONS_PER_EXECUTION} source ports were reused across all Executions"
        ));
    }

    let mut successes = 0_usize;
    let mut timeouts = 0_usize;
    let mut cookies = HashSet::with_capacity(total);
    let deadline = Instant::now() + Duration::from_secs(3);
    while successes < success_total || timeouts < timeout_total {
        for connection in &mut connections {
            if connection.resolved || connection.timeout_case {
                continue;
            }
            if connection.accepted_at.elapsed() < connection.publish_delay {
                continue;
            }
            match tuples.get(&connection.key, 0) {
                Err(aya::maps::MapError::KeyNotFound) => {}
                Ok(_) => {
                    return Err(format!(
                        "S2 tuple appeared before promotion for {}",
                        connection.peer
                    ));
                }
                Err(error) => {
                    println!("s2_unexpected_map_errors=1");
                    return Err(format!("S2 pre-promotion tuple lookup: {error:#}"));
                }
            }
            let staged = match staging.get(&connection.key, 0) {
                Ok(value) => value,
                Err(aya::maps::MapError::KeyNotFound) => continue,
                Err(error) => {
                    println!("s2_unexpected_map_errors=1");
                    return Err(format!("S2 staging lookup: {error:#}"));
                }
            };
            let evidence = decode_evidence(staged);
            let resolved_owner = resolve_owner(executions, &evidence);
            let origin = connection.origin;
            if resolved_owner != Some(origin) {
                println!("s2_attribution_mismatches=1");
                println!(
                    "s2_cross_attribution_count={}",
                    usize::from(resolved_owner.is_some_and(|owner| owner != origin))
                );
                println!(
                    "s2_fail_closed origin=e{} resolved_owner={resolved_owner:?} peer={} cookie={} a={} b={} c={} decision=DENY ip_fallback=false",
                    origin, connection.peer, evidence[0], evidence[1], evidence[2], evidence[3]
                );
                return Err(
                    "S2 attribution evidence did not identify the originating Execution".to_owned(),
                );
            }
            if !cookies.insert(evidence[0]) {
                return Err(format!("duplicate live socket cookie {}", evidence[0]));
            }
            if let Err(error) = tuples.insert(connection.key, staged, 0) {
                println!("s2_unexpected_map_errors=1");
                return Err(format!("S2 promote tuple: {error:#}"));
            }
            if let Err(error) = staging.remove(&connection.key) {
                println!("s2_unexpected_map_errors=1");
                return Err(format!("S2 remove staging tuple: {error:#}"));
            }
            let published = match tuples.get(&connection.key, 0) {
                Ok(value) => value,
                Err(error) => {
                    println!("s2_unexpected_map_errors=1");
                    return Err(format!("S2 Resolve tuple: {error:#}"));
                }
            };
            let tuple_evidence = decode_evidence(published);
            let tuple_owner = resolve_owner(executions, &tuple_evidence);
            if tuple_owner != Some(origin) {
                println!("s2_attribution_mismatches=1");
                println!(
                    "s2_cross_attribution_count={}",
                    usize::from(tuple_owner.is_some())
                );
                return Err(format!(
                    "S2 tuple owner mismatch origin=e{origin} tuple_owner={tuple_owner:?}"
                ));
            }
            connection.resolved = true;
            connection.cookie = Some(evidence[0]);
            successes += 1;
            println!(
                "s2_resolve origin=e{} execution_id={} peer={} local={} cookie={} a_cgid={} b_cgid={} c_ident={} netns_cookie={} tuple_owner=e{} resolve_result={} latency_ns={} ip_cross_check=true ip_used_for_authorization=false",
                origin,
                executions[origin].id,
                connection.peer,
                connection.local,
                evidence[0],
                evidence[1],
                evidence[2],
                evidence[3],
                evidence[4],
                origin,
                executions[origin].id,
                connection.accepted_at.elapsed().as_nanos()
            );
        }

        for connection in &mut connections {
            if !connection.timeout_case || connection.resolved {
                continue;
            }
            if connection.accepted_at.elapsed() < RESOLVE_TIMEOUT {
                continue;
            }
            match tuples.get(&connection.key, 0) {
                Err(aya::maps::MapError::KeyNotFound) => {}
                Ok(_) => {
                    return Err(format!(
                        "S2 timeout tuple became visible for {}",
                        connection.peer
                    ));
                }
                Err(error) => {
                    println!("s2_unexpected_map_errors=1");
                    return Err(format!("S2 timeout tuple lookup: {error:#}"));
                }
            }
            let staged = staging
                .get(&connection.key, 0)
                .map_err(|error| format!("S2 timeout staging evidence missing: {error:#}"))?;
            let evidence = decode_evidence(staged);
            let owner = resolve_owner(executions, &evidence);
            if owner != Some(connection.origin) {
                println!("s2_attribution_mismatches=1");
                println!(
                    "s2_cross_attribution_count={}",
                    usize::from(owner.is_some())
                );
                return Err(format!(
                    "S2 timeout staged owner mismatch origin=e{} owner={owner:?}",
                    connection.origin
                ));
            }
            connection
                .stream
                .shutdown(Shutdown::Both)
                .map_err(|error| format!("S2 close timeout socket: {error}"))?;
            connection.resolved = true;
            connection.cookie = Some(evidence[0]);
            cookies.insert(evidence[0]);
            timeouts += 1;
            println!(
                "s2_timeout origin=e{} execution_id={} peer={} cookie={} staged_owner=e{} timeout_ms={} decision=DENY application_bytes_read=0 dns=0 outbound_effects=0 ip_fallback=false",
                connection.origin,
                executions[connection.origin].id,
                connection.peer,
                evidence[0],
                connection.origin,
                RESOLVE_TIMEOUT.as_millis()
            );
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "S2 resolution deadline successes={successes}/{success_total} timeouts={timeouts}/{timeout_total}"
            ));
        }
        thread::sleep(Duration::from_micros(100));
    }

    println!("application_bytes_read_while_unresolved=0");
    println!("dns_while_unresolved=0");
    println!("outbound_effects_while_unresolved=0");
    println!("ip_fallback_authorization=false");
    capture_maps(config, &mut events, commands)?;

    for connection in &mut connections {
        if connection.timeout_case {
            continue;
        }
        let mut request = String::new();
        BufReader::new(
            connection
                .stream
                .try_clone()
                .map_err(|error| format!("clone S2 stream: {error}"))?,
        )
        .read_line(&mut request)
        .map_err(|error| format!("read S2 application after Resolve: {error}"))?;
        writeln!(
            connection.stream,
            "ATTRIBUTED {}",
            executions[connection.origin].id
        )
        .map_err(|error| format!("write S2 verdict: {error}"))?;
        connection
            .stream
            .flush()
            .map_err(|error| format!("flush S2 verdict: {error}"))?;
    }

    for agent in agents {
        let output = agent
            .child
            .wait(Duration::from_secs(35))
            .map_err(|error| format!("wait e{} agent: {error}", agent.execution_index))?;
        println!(
            "agent_e{}_status_exit={:?} signal={:?}",
            agent.execution_index, output.record.exit_code, output.record.signal
        );
        println!("agent_e{}_stdout_begin", agent.execution_index);
        print!("{}", output.stdout_text());
        println!("agent_e{}_stdout_end", agent.execution_index);
        println!("agent_e{}_stderr_begin", agent.execution_index);
        eprint!("{}", output.stderr_text());
        println!("agent_e{}_stderr_end", agent.execution_index);
        if !output.success() {
            return Err(format!("agent e{} failed", agent.execution_index));
        }
    }

    println!("s2_execution_count={EXECUTION_COUNT}");
    println!("s2_connection_count={total}");
    println!("s2_concurrent_unresolved_peak={total}");
    println!("s2_successes={successes}");
    println!("s2_bounded_waits={successes}");
    println!("s2_timeouts={timeouts}");
    println!("s2_unique_socket_cookies={}", cookies.len());
    println!("s2_attribution_mismatches=0");
    println!("s2_cross_attribution_count=0");
    println!("s2_unexpected_tuple_collisions=0");
    println!("s2_unexpected_map_errors=0");
    println!("S2_RESULT=PASS");
    Ok(())
}

fn resolve_owner(executions: &[Execution], evidence: &[u64; 8]) -> Option<usize> {
    let matches: Vec<_> = executions
        .iter()
        .filter(|execution| {
            evidence[1] == execution.inode
                && evidence[2] == execution.inode
                && evidence[3] == execution.ident
        })
        .map(|execution| execution.index)
        .collect();
    (matches.len() == 1).then_some(matches[0])
}

fn capture_maps(
    config: &Config,
    events: &mut RingBuf<MapData>,
    commands: &CommandExecutor,
) -> Result<(), String> {
    for name in [
        "soglia_diag_entries",
        "soglia_port_diag",
        "soglia_counters",
        "soglia_cookie_a",
        "soglia_tuples",
        "soglia_staging",
        "soglia_denies",
    ] {
        let output = commands
            .run(&CommandSpec::new("bpftool").args([
                std::ffi::OsString::from("-j"),
                std::ffi::OsString::from("map"),
                std::ffi::OsString::from("dump"),
                std::ffi::OsString::from("pinned"),
                config.map_pin_root.join(name).into_os_string(),
            ]))
            .map_err(|error| format!("dump {name}: {error}"))?;
        println!("{name}_snapshot_status={:?}", output.record.exit_code);
        println!("{name}_snapshot_begin");
        print!("{}", String::from_utf8_lossy(&output.stdout));
        println!("{name}_snapshot_end");
        if !output.success() {
            return Err(format!("bpftool failed to dump {name}"));
        }
    }
    let mut count = 0_u64;
    while let Some(event) = events.next() {
        println!("s2_bpf_event_{count}_hex={}", hex(&event));
        count += 1;
    }
    println!("s2_bpf_event_count={count}");
    Ok(())
}

fn tuple_key(peer: SocketAddr, local: SocketAddr) -> Result<[u8; 16], String> {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        return Err("S2 expected IPv4 tuple".to_owned());
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
            return Err(format!("PID {pid} did not stop before netns entry"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn attach_all(bpf: &mut Ebpf, cgroup: &File, pin_root: &Path) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
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
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd link {name}: {error:#}"))?;
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
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd link {name}: {error:#}"))?;
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
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name} link: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd link {name}: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn cleanup_links(links: &mut Vec<PinnedLink>) {
    while let Some(link) = links.pop() {
        match link.unpin() {
            Ok(fd) => drop(fd),
            Err(error) => eprintln!("cleanup S2 link: {error:#}"),
        }
    }
}

fn remove_pins(config: &Config, executions: &[Execution]) {
    for path in [
        &config.ready_file,
        &config.go_file,
        &config.membership_ready_file,
        &config.membership_captured_file,
    ] {
        remove_file(path);
    }
    for execution in executions {
        remove_file(&execution.host_ready);
        remove_file(&execution.agent_ready);
        remove_file(&execution.agent_go);
        let root = config.link_pin_root.join(format!("e{}", execution.index));
        for name in LINK_NAMES {
            remove_file(&root.join(name));
        }
        remove_dir(&root);
    }
    for name in MAP_NAMES {
        remove_file(&config.map_pin_root.join(name));
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
