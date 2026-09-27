// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Candidate-C operational scaling harness for S14 of the cgroup-BPF spike.
//!
//! EXPERIMENTAL: this is measurement machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap as StdHashMap,
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap},
    programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps,
        links::{FdLink, PinnedLink},
    },
};

const MAP_NAMES: [&str; 8] = [
    "soglia_policy",
    "soglia_tuples",
    "soglia_cookie_a",
    "soglia_sk_b",
    "soglia_events",
    "soglia_counters",
    "soglia_denies",
    "soglia_meta",
];
const WAIT: Duration = Duration::from_secs(60);

struct Config {
    object: PathBuf,
    executions: PathBuf,
    map_pins: PathBuf,
    link_pins: PathBuf,
    agent: PathBuf,
    count: usize,
    ready: PathBuf,
    go: PathBuf,
    attribution_ready: PathBuf,
    finish: PathBuf,
    runtime: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            object: next_path(&mut args, "BPF object")?,
            executions: next_path(&mut args, "executions cgroup root")?,
            map_pins: next_path(&mut args, "map pin root")?,
            link_pins: next_path(&mut args, "link pin root")?,
            agent: next_path(&mut args, "agent")?,
            count: next_string(&mut args, "Execution count")?
                .parse()
                .map_err(|error| format!("parse Execution count: {error}"))?,
            ready: next_path(&mut args, "ready marker")?,
            go: next_path(&mut args, "go marker")?,
            attribution_ready: next_path(&mut args, "attribution-ready marker")?,
            finish: next_path(&mut args, "finish marker")?,
            runtime: next_path(&mut args, "runtime directory")?,
        };
        if config.count == 0 {
            return Err("Execution count must be non-zero".to_owned());
        }
        if args.next().is_some() {
            return Err("unexpected extra argument".to_owned());
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

#[derive(Clone)]
struct Execution {
    index: usize,
    id: String,
    ident: u64,
    cgroup: PathBuf,
    inode: u64,
    netns: String,
    ip: Ipv4Addr,
}

impl Execution {
    fn new(config: &Config, index: usize) -> Result<Self, String> {
        let third = (index / 63) as u8;
        let fourth = ((index % 63) * 4 + 1) as u8;
        let cgroup = config.executions.join(format!("s14-e{index:03}"));
        let inode = fs::metadata(&cgroup)
            .map_err(|error| format!("stat {}: {error}", cgroup.display()))?
            .ino();
        Ok(Self {
            index,
            id: format!("s14-n{}-execution-{index:03}-generation-1", config.count),
            ident: 14_000_000 + config.count as u64 * 1_000 + index as u64,
            cgroup,
            inode,
            netns: format!("s14n{}e{index:03}", config.count),
            ip: Ipv4Addr::new(10, 202 + third, 0, fourth),
        })
    }
}

#[derive(Default)]
struct Timings {
    object_load_ns: u128,
    policy_setup_ns: u128,
    program_load_ns: u128,
    attach_ns: u128,
    pin_ns: u128,
}

struct LoadedExecution {
    bpf: Ebpf,
    links: Vec<PinnedLink>,
}

struct LiveAgent {
    execution_index: usize,
    child: Child,
}

struct Accepted {
    stream: TcpStream,
    execution_index: usize,
    peer: SocketAddr,
    local: SocketAddr,
    evidence: [u64; 8],
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S14 SCALING ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    fs::create_dir_all(&config.map_pins).map_err(display_error("create map pins"))?;
    fs::create_dir_all(&config.link_pins).map_err(display_error("create link pins"))?;
    fs::create_dir_all(&config.runtime).map_err(display_error("create runtime directory"))?;
    let executions: Vec<_> = (0..config.count)
        .map(|index| Execution::new(&config, index))
        .collect::<Result<_, _>>()?;

    println!("test=S14");
    println!("candidate=C");
    println!("execution_count={}", config.count);
    println!("shared_map_pin_root={}", config.map_pins.display());
    println!("per_execution_link_pin_root={}", config.link_pins.display());
    println!("sample_rule=N=1:[0];N=4:[0,N-1];N>=16:[0,N/2,N-1]");

    let preparation_started = Instant::now();
    let mut total = Timings::default();
    let mut loaded = Vec::with_capacity(config.count);
    for execution in &executions {
        println!(
            "execution_load_begin index={} open_fd_count={}",
            execution.index,
            open_fd_count()?
        );
        let (item, timings) = load_execution(&config, execution)?;
        total.object_load_ns += timings.object_load_ns;
        total.policy_setup_ns += timings.policy_setup_ns;
        total.program_load_ns += timings.program_load_ns;
        total.attach_ns += timings.attach_ns;
        total.pin_ns += timings.pin_ns;
        println!(
            "execution_prepared index={} id={} ident={} cgroup_inode={} object_load_ns={} policy_setup_ns={} program_load_ns={} attach_ns={} pin_ns={} links={} open_fd_count={}",
            execution.index,
            execution.id,
            execution.ident,
            execution.inode,
            timings.object_load_ns,
            timings.policy_setup_ns,
            timings.program_load_ns,
            timings.attach_ns,
            timings.pin_ns,
            item.links.len(),
            open_fd_count()?
        );
        loaded.push(item);
    }
    let preparation_ns = preparation_started.elapsed().as_nanos();
    println!("object_load_total_ns={}", total.object_load_ns);
    println!("policy_setup_total_ns={}", total.policy_setup_ns);
    println!("program_load_total_ns={}", total.program_load_ns);
    println!("attach_total_ns={}", total.attach_ns);
    println!("pin_total_ns={}", total.pin_ns);
    println!("candidate_preparation_total_ns={preparation_ns}");

    fs::write(&config.ready, b"ready\n").map_err(display_error("write ready marker"))?;
    println!("state=READY_FOR_RESOURCE_SNAPSHOT");
    wait_for_file(&config.go, WAIT)?;

    let sample = sample_indices(config.count);
    println!(
        "sample_indices={}",
        sample
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    let listener = TcpListener::bind((Ipv4Addr::new(10, 200, 255, 1), 15_001))
        .map_err(|error| format!("bind S14 proxy: {error}"))?;
    let mut agents = Vec::with_capacity(sample.len());
    for &index in &sample {
        agents.push(start_and_place_agent(&config, &executions[index])?);
    }
    println!("state=SAMPLED_MEMBERSHIPS_PROVEN_BEFORE_TRAFFIC");
    for &index in &sample {
        fs::write(config.runtime.join(format!("e{index:03}.go")), b"go\n")
            .map_err(display_error("release sampled agent"))?;
    }

    let tuples_map = loaded
        .first_mut()
        .and_then(|item| item.bpf.take_map("soglia_tuples"))
        .ok_or("shared soglia_tuples missing")?;
    let tuples = HashMap::<_, [u8; 16], [u8; 64]>::try_from(tuples_map)
        .map_err(|error| format!("open shared tuple map: {error:#}"))?;
    let ip_to_index: StdHashMap<_, _> = sample
        .iter()
        .map(|&index| (executions[index].ip, index))
        .collect();
    let mut accepted = Vec::with_capacity(sample.len());
    for _ in 0..sample.len() {
        let (stream, peer) = listener
            .accept()
            .map_err(|error| format!("accept sampled agent: {error}"))?;
        let local = stream
            .local_addr()
            .map_err(|error| format!("read proxy local address: {error}"))?;
        let SocketAddr::V4(peer4) = peer else {
            return Err("sampled connection was not IPv4".to_owned());
        };
        let index = *ip_to_index
            .get(peer4.ip())
            .ok_or_else(|| format!("accepted unrecognized source {peer}"))?;
        let key = tuple_key(peer, local)?;
        let evidence = wait_for_tuple(&tuples, &key, Duration::from_secs(2))?;
        let execution = &executions[index];
        let candidate_owner = executions
            .iter()
            .find(|candidate| candidate.ident == evidence[3])
            .map(|candidate| candidate.index);
        if candidate_owner != Some(index) {
            return Err(format!(
                "Candidate-C cross-attribution origin={index} c_ident={} resolved={candidate_owner:?}",
                evidence[3]
            ));
        }
        if evidence[1] != execution.inode || evidence[2] != execution.inode {
            return Err(format!(
                "trusted A/B cross-check mismatch origin={index} inode={} a={} b={}",
                execution.inode, evidence[1], evidence[2]
            ));
        }
        println!(
            "candidate_c_resolve origin_index={} execution_id={} accepted_peer={} accepted_local={} tuple_hex={} c_ident={} resolved_execution={} a_cgid={} b_cgid={} ip_cross_check=true ip_used_for_authorization=false result=PASS",
            index,
            execution.id,
            peer,
            local,
            hex(&key),
            evidence[3],
            execution.id,
            evidence[1],
            evidence[2]
        );
        accepted.push(Accepted {
            stream,
            execution_index: index,
            peer,
            local,
            evidence,
        });
    }
    println!("attribution_checks={}", accepted.len());
    println!("attribution_mismatches=0");
    println!("cross_execution_identity=0");
    println!("fallback_authorization=false");
    fs::write(&config.attribution_ready, b"ready\n")
        .map_err(display_error("write attribution-ready marker"))?;
    println!("state=ATTRIBUTION_PROVEN_CONNECTIONS_HELD");
    wait_for_file(&config.finish, WAIT)?;

    for connection in &mut accepted {
        let mut request = String::new();
        BufReader::new(
            connection
                .stream
                .try_clone()
                .map_err(|error| format!("clone accepted stream: {error}"))?,
        )
        .read_line(&mut request)
        .map_err(|error| format!("read application bytes after Resolve: {error}"))?;
        writeln!(
            connection.stream,
            "ATTRIBUTED {}",
            executions[connection.execution_index].id
        )
        .map_err(|error| format!("write attribution verdict: {error}"))?;
        connection
            .stream
            .flush()
            .map_err(|error| format!("flush attribution verdict: {error}"))?;
        println!(
            "application_released origin_index={} peer={} local={} c_ident={} request_bytes={} after_resolve=true",
            connection.execution_index,
            connection.peer,
            connection.local,
            connection.evidence[3],
            request.len()
        );
    }
    drop(accepted);
    for agent in agents {
        let output = agent
            .child
            .wait_with_output()
            .map_err(|error| format!("wait agent e{}: {error}", agent.execution_index))?;
        println!(
            "agent_e{:03}_status={}",
            agent.execution_index, output.status
        );
        println!(
            "agent_e{:03}_stdout={}",
            agent.execution_index,
            String::from_utf8_lossy(&output.stdout).trim()
        );
        if !output.status.success() {
            return Err(format!("sampled agent e{} failed", agent.execution_index));
        }
    }

    let teardown_started = Instant::now();
    for item in &mut loaded {
        cleanup_links(&mut item.links)?;
    }
    drop(tuples);
    drop(loaded);
    for execution in &executions {
        remove_dir(&config.link_pins.join(format!("e{:03}", execution.index)))?;
    }
    for name in MAP_NAMES {
        remove_file(&config.map_pins.join(name))?;
    }
    remove_dir(&config.link_pins)?;
    remove_dir(&config.map_pins)?;
    let teardown_ns = teardown_started.elapsed().as_nanos();
    println!("candidate_bpf_teardown_ns={teardown_ns}");
    println!("S14_POINT_RESULT=PASS");
    Ok(())
}

fn load_execution(
    config: &Config,
    execution: &Execution,
) -> Result<(LoadedExecution, Timings), String> {
    let mut timings = Timings::default();
    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &execution.ident, true)
        .default_map_pin_directory(&config.map_pins);
    let started = Instant::now();
    let mut bpf = loader
        .load_file(&config.object)
        .map_err(|error| format!("load object for e{}: {error:?}", execution.index))?;
    timings.object_load_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    let local_map = bpf
        .map_mut("policy_local")
        .ok_or_else(|| format!("policy_local missing for e{}", execution.index))?;
    let mut policy = Array::<_, u64>::try_from(local_map)
        .map_err(|error| format!("open policy_local for e{}: {error:#}", execution.index))?;
    policy
        .set(0, 1, 0)
        .map_err(|error| format!("activate policy_local for e{}: {error:#}", execution.index))?;
    timings.policy_setup_ns = started.elapsed().as_nanos();

    let cgroup = File::open(&execution.cgroup)
        .map_err(|error| format!("open {}: {error}", execution.cgroup.display()))?;
    let link_root = config.link_pins.join(format!("e{:03}", execution.index));
    fs::create_dir_all(&link_root).map_err(display_error("create execution link root"))?;
    let (links, program_load_ns, attach_ns, pin_ns) = attach_all(&mut bpf, &cgroup, &link_root)?;
    timings.program_load_ns = program_load_ns;
    timings.attach_ns = attach_ns;
    timings.pin_ns = pin_ns;
    Ok((LoadedExecution { bpf, links }, timings))
}

fn sample_indices(count: usize) -> Vec<usize> {
    if count == 1 {
        vec![0]
    } else if count <= 4 {
        vec![0, count - 1]
    } else {
        vec![0, count / 2, count - 1]
    }
}

fn open_fd_count() -> Result<usize, String> {
    fs::read_dir("/proc/self/fd")
        .map_err(display_error("read /proc/self/fd"))?
        .try_fold(0_usize, |count, entry| {
            entry
                .map(|_| count + 1)
                .map_err(|error| format!("enumerate /proc/self/fd: {error}"))
        })
}

fn start_and_place_agent(config: &Config, execution: &Execution) -> Result<LiveAgent, String> {
    let host_ready = config
        .runtime
        .join(format!("e{:03}.host-ready", execution.index));
    let agent_ready = config
        .runtime
        .join(format!("e{:03}.agent-ready", execution.index));
    let agent_go = config.runtime.join(format!("e{:03}.go", execution.index));
    let shell = r#"set -euo pipefail
printf '%s\n' "$$" > "$1"
kill -STOP "$$"
exec ip netns exec "$2" "$3" "barrier $4 $5 30" "proxy-fixed 40000 1""#;
    let child = Command::new("bash")
        .args(["-c", shell, "s14-host-launcher"])
        .arg(&host_ready)
        .arg(&execution.netns)
        .arg(&config.agent)
        .arg(&agent_ready)
        .arg(&agent_go)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start sampled e{}: {error}", execution.index))?;
    let pid = child.id();
    wait_for_file(&host_ready, Duration::from_secs(5))?;
    wait_for_process_stopped(pid, Duration::from_secs(5))?;
    let announced: u32 = fs::read_to_string(&host_ready)
        .map_err(display_error("read host PID"))?
        .trim()
        .parse()
        .map_err(|error| format!("parse host PID: {error}"))?;
    if announced != pid {
        return Err(format!(
            "trusted host PID mismatch child={pid} announced={announced}"
        ));
    }
    fs::write(execution.cgroup.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(display_error("place sampled agent"))?;
    verify_membership(execution, pid, false)?;
    let status = Command::new("kill")
        .args(["-CONT", &pid.to_string()])
        .status()
        .map_err(display_error("continue sampled agent"))?;
    if !status.success() {
        return Err(format!("continue sampled agent failed: {status}"));
    }
    wait_for_file(&agent_ready, Duration::from_secs(5))?;
    let actual: u32 = fs::read_to_string(&agent_ready)
        .map_err(display_error("read actual agent PID"))?
        .trim()
        .parse()
        .map_err(|error| format!("parse actual agent PID: {error}"))?;
    if actual != pid {
        return Err(format!(
            "actual agent PID mismatch trusted={pid} actual={actual}"
        ));
    }
    verify_membership(execution, pid, true)?;
    println!(
        "membership_proven index={} pid={} cgroup={} cgroup_inode={} netns={} netns_inode={}",
        execution.index,
        pid,
        execution.cgroup.display(),
        execution.inode,
        execution.netns,
        fs::metadata(format!("/proc/{pid}/ns/net"))
            .map_err(display_error("stat process netns"))?
            .ino()
    );
    Ok(LiveAgent {
        execution_index: execution.index,
        child,
    })
}

fn verify_membership(execution: &Execution, pid: u32, require_netns: bool) -> Result<(), String> {
    let relative = execution
        .cgroup
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|_| "S14 cgroup outside /sys/fs/cgroup".to_owned())?;
    let expected = format!("0::/{}", relative.to_string_lossy().trim_start_matches('/'));
    let proc_cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(display_error("read process cgroup"))?;
    let procs = fs::read_to_string(execution.cgroup.join("cgroup.procs"))
        .map_err(display_error("read cgroup.procs"))?;
    let cgroup_ok = proc_cgroup.lines().any(|line| line == expected)
        && procs.lines().any(|line| line == pid.to_string());
    let netns_ok = !require_netns
        || fs::metadata(format!("/proc/{pid}/ns/net"))
            .map_err(display_error("stat process netns"))?
            .ino()
            == fs::metadata(format!("/run/netns/{}", execution.netns))
                .map_err(display_error("stat owned netns"))?
                .ino();
    if !cgroup_ok || !netns_ok {
        return Err(format!(
            "membership mismatch e{} cgroup_ok={cgroup_ok} netns_ok={netns_ok}",
            execution.index
        ));
    }
    Ok(())
}

fn tuple_key(peer: SocketAddr, local: SocketAddr) -> Result<[u8; 16], String> {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        return Err("S14 expected IPv4 tuple".to_owned());
    };
    let mut key = [0_u8; 16];
    key[0..4].copy_from_slice(&peer.ip().octets());
    key[4..8].copy_from_slice(&local.ip().octets());
    key[8..12].copy_from_slice(&u32::from(peer.port()).to_ne_bytes());
    key[12..16].copy_from_slice(&u32::from(local.port()).to_ne_bytes());
    Ok(key)
}

fn wait_for_tuple<T>(
    tuples: &HashMap<T, [u8; 16], [u8; 64]>,
    key: &[u8; 16],
    timeout: Duration,
) -> Result<[u64; 8], String>
where
    T: std::borrow::Borrow<aya::maps::MapData>,
{
    let started = Instant::now();
    loop {
        match tuples.get(key, 0) {
            Ok(bytes) => return Ok(decode_evidence(bytes)),
            Err(aya::maps::MapError::KeyNotFound) if started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(aya::maps::MapError::KeyNotFound) => {
                return Err(format!("Resolve timed out tuple={}", hex(key)));
            }
            Err(error) => return Err(format!("Resolve map lookup: {error:#}")),
        }
    }
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
            .map_err(display_error("read stopped process status"))?;
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

fn attach_all(
    bpf: &mut Ebpf,
    cgroup: &File,
    pin_root: &Path,
) -> Result<(Vec<PinnedLink>, u128, u128, u128), String> {
    let mut links = Vec::with_capacity(6);
    let mut load_ns = 0;
    let mut attach_ns = 0;
    let mut pin_ns = 0;
    let (link, timing) = attach_cgroup_sock(
        bpf,
        cgroup,
        "soglia_sock_create",
        &pin_root.join("sock_create"),
    )?;
    load_ns += timing.0;
    attach_ns += timing.1;
    pin_ns += timing.2;
    links.push(link);
    for (program, pin) in [
        ("soglia_connect4", "connect4"),
        ("soglia_connect6", "connect6"),
        ("soglia_sendmsg4", "sendmsg4"),
        ("soglia_sendmsg6", "sendmsg6"),
    ] {
        let (link, timing) = attach_cgroup_sock_addr(bpf, cgroup, program, &pin_root.join(pin))?;
        load_ns += timing.0;
        attach_ns += timing.1;
        pin_ns += timing.2;
        links.push(link);
    }
    let (link, timing) =
        attach_sock_ops(bpf, cgroup, "soglia_sockops", &pin_root.join("sock_ops"))?;
    load_ns += timing.0;
    attach_ns += timing.1;
    pin_ns += timing.2;
    links.push(link);
    Ok((links, load_ns, attach_ns, pin_ns))
}

fn attach_cgroup_sock(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<(PinnedLink, (u128, u128, u128)), String> {
    let program: &mut CgroupSock = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    let started = Instant::now();
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let load_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let attach_ns = started.elapsed().as_nanos();
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        load_ns,
        attach_ns,
    )
}

fn attach_cgroup_sock_addr(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<(PinnedLink, (u128, u128, u128)), String> {
    let program: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    let started = Instant::now();
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let load_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let attach_ns = started.elapsed().as_nanos();
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        load_ns,
        attach_ns,
    )
}

fn attach_sock_ops(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<(PinnedLink, (u128, u128, u128)), String> {
    let program: &mut SockOps = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} missing"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    let started = Instant::now();
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let load_ns = started.elapsed().as_nanos();
    let started = Instant::now();
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let attach_ns = started.elapsed().as_nanos();
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        load_ns,
        attach_ns,
    )
}

fn pin_link<L>(
    link: L,
    pin: &Path,
    load_ns: u128,
    attach_ns: u128,
) -> Result<(PinnedLink, (u128, u128, u128)), String>
where
    L: TryInto<FdLink>,
    L::Error: std::fmt::Debug,
{
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd link: {error:#?}"))?;
    let started = Instant::now();
    let pinned = fd
        .pin(pin)
        .map_err(|error| format!("pin link: {error:#}"))?;
    let pin_ns = started.elapsed().as_nanos();
    Ok((pinned, (load_ns, attach_ns, pin_ns)))
}

fn cleanup_links(links: &mut Vec<PinnedLink>) -> Result<(), String> {
    while let Some(link) = links.pop() {
        let fd = link
            .unpin()
            .map_err(|error| format!("unpin S14 link: {error:#}"))?;
        drop(fd);
    }
    Ok(())
}

fn remove_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn remove_dir(path: &Path) -> Result<(), String> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove directory {}: {error}", path.display())),
    }
}

fn display_error(operation: &'static str) -> impl Fn(std::io::Error) -> String {
    move |error| format!("{operation}: {error}")
}
