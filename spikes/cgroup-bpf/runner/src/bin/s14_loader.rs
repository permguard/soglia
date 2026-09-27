// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Aya-only Candidate-C loader used by the S14 Rust controller.
//!
//! This deliberately preserves the historical per-Execution object semantics. It does not
//! create topology, launch agents, classify results, or invoke external commands.

#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::Array;
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps};
use aya::{Ebpf, EbpfLoader};
use serde::Serialize;

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

struct Config {
    object: PathBuf,
    executions: PathBuf,
    map_pins: PathBuf,
    link_pins: PathBuf,
    count: usize,
    ready: PathBuf,
    finish: PathBuf,
    done: PathBuf,
    failure: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1).map(PathBuf::from);
        let object = args.next().ok_or("missing BPF object")?;
        let executions = args.next().ok_or("missing executions cgroup")?;
        let map_pins = args.next().ok_or("missing map pin root")?;
        let link_pins = args.next().ok_or("missing link pin root")?;
        let count = args
            .next()
            .and_then(|value| value.into_os_string().into_string().ok())
            .ok_or("missing execution count")?
            .parse::<usize>()
            .map_err(|error| format!("parse execution count: {error}"))?;
        let ready = args.next().ok_or("missing ready record")?;
        let finish = args.next().ok_or("missing finish marker")?;
        let done = args.next().ok_or("missing done record")?;
        let failure = args.next().ok_or("missing failure record")?;
        if count == 0 || args.next().is_some() {
            return Err("invalid S14 loader arguments".to_owned());
        }
        Ok(Self {
            object,
            executions,
            map_pins,
            link_pins,
            count,
            ready,
            finish,
            done,
            failure,
        })
    }
}

#[derive(Default, Serialize)]
struct Timings {
    object_load_ns: u128,
    policy_setup_ns: u128,
    program_load_ns: u128,
    attach_ns: u128,
    pin_ns: u128,
}

impl Timings {
    fn add(&mut self, other: &Self) {
        self.object_load_ns += other.object_load_ns;
        self.policy_setup_ns += other.policy_setup_ns;
        self.program_load_ns += other.program_load_ns;
        self.attach_ns += other.attach_ns;
        self.pin_ns += other.pin_ns;
    }
}

#[derive(Serialize)]
struct InstanceRecord {
    index: usize,
    ident: u64,
    cgroup: String,
    fd_before: usize,
    fd_after: usize,
    timings: Timings,
}

#[derive(Serialize)]
struct ReadyRecord {
    count: usize,
    preparation_ns: u128,
    totals: Timings,
    instances: Vec<InstanceRecord>,
}

#[derive(Serialize)]
struct FailureRecord {
    index: usize,
    ident: u64,
    operation: &'static str,
    error: String,
    open_fd_count: usize,
}

struct LoadedExecution {
    _bpf: Ebpf,
    links: Vec<PinnedLink>,
}

fn main() {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("S14 LOADER ERROR: {error}");
            process::exit(1);
        }
    };
    if let Err(error) = run(&config) {
        eprintln!("S14 LOADER ERROR: {error}");
        process::exit(1);
    }
}

fn run(config: &Config) -> Result<(), String> {
    fs::create_dir_all(&config.map_pins).map_err(display_error("create map pin root"))?;
    fs::create_dir_all(&config.link_pins).map_err(display_error("create link pin root"))?;
    let started = Instant::now();
    let mut totals = Timings::default();
    let mut instances = Vec::with_capacity(config.count);
    let mut loaded = Vec::with_capacity(config.count);
    for index in 0..config.count {
        let ident = 14_000_000 + config.count as u64 * 1_000 + index as u64;
        let cgroup = config.executions.join(format!("s14-e{index:03}"));
        let fd_before = open_fd_count()?;
        let (item, timings) = match load_execution(config, index, ident, &cgroup) {
            Ok(value) => value,
            Err(error) => {
                let record = FailureRecord {
                    index,
                    ident,
                    operation: "EbpfLoader/load/configure/attach/pin",
                    error: error.clone(),
                    open_fd_count: open_fd_count().unwrap_or_default(),
                };
                write_json(&config.failure, &record)?;
                return Err(error);
            }
        };
        let fd_after = open_fd_count()?;
        totals.add(&timings);
        instances.push(InstanceRecord {
            index,
            ident,
            cgroup: cgroup.to_string_lossy().into_owned(),
            fd_before,
            fd_after,
            timings,
        });
        loaded.push(item);
    }
    write_json(
        &config.ready,
        &ReadyRecord {
            count: config.count,
            preparation_ns: started.elapsed().as_nanos(),
            totals,
            instances,
        },
    )?;
    wait_for(&config.finish, Duration::from_secs(120))?;
    let teardown = Instant::now();
    for item in &mut loaded {
        while let Some(link) = item.links.pop() {
            let fd = link
                .unpin()
                .map_err(|error| format!("unpin S14 link: {error:#}"))?;
            drop(fd);
        }
    }
    drop(loaded);
    for index in 0..config.count {
        remove_dir(&config.link_pins.join(format!("e{index:03}")))?;
    }
    for name in MAP_NAMES {
        remove_file(&config.map_pins.join(name))?;
    }
    remove_dir(&config.link_pins)?;
    remove_dir(&config.map_pins)?;
    write_json(
        &config.done,
        &serde_json::json!({"bpf_teardown_ns": teardown.elapsed().as_nanos()}),
    )
}

fn load_execution(
    config: &Config,
    index: usize,
    ident: u64,
    cgroup_path: &Path,
) -> Result<(LoadedExecution, Timings), String> {
    let mut timings = Timings::default();
    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &ident, true)
        .default_map_pin_directory(&config.map_pins);
    let started = Instant::now();
    let mut bpf = loader
        .load_file(&config.object)
        .map_err(|error| format!("load object for e{index}: {error:?}"))?;
    timings.object_load_ns = started.elapsed().as_nanos();

    let started = Instant::now();
    let map = bpf
        .map_mut("policy_local")
        .ok_or_else(|| format!("policy_local missing for e{index}"))?;
    let mut policy = Array::<_, u64>::try_from(map)
        .map_err(|error| format!("open policy_local for e{index}: {error:#}"))?;
    policy
        .set(0, 1, 0)
        .map_err(|error| format!("activate policy_local for e{index}: {error:#}"))?;
    timings.policy_setup_ns = started.elapsed().as_nanos();

    let cgroup = File::open(cgroup_path)
        .map_err(|error| format!("open {}: {error}", cgroup_path.display()))?;
    let root = config.link_pins.join(format!("e{index:03}"));
    fs::create_dir_all(&root).map_err(display_error("create execution link pin root"))?;
    let (links, load, attach, pin) = attach_all(&mut bpf, &cgroup, &root)?;
    timings.program_load_ns = load;
    timings.attach_ns = attach;
    timings.pin_ns = pin;
    Ok((LoadedExecution { _bpf: bpf, links }, timings))
}

fn attach_all(
    bpf: &mut Ebpf,
    cgroup: &File,
    root: &Path,
) -> Result<(Vec<PinnedLink>, u128, u128, u128), String> {
    let mut links = Vec::with_capacity(6);
    let mut load = 0;
    let mut attach = 0;
    let mut pin = 0;
    let item = attach_sock(bpf, cgroup, "soglia_sock_create", &root.join("sock_create"))?;
    load += item.1.0;
    attach += item.1.1;
    pin += item.1.2;
    links.push(item.0);
    for (name, file) in [
        ("soglia_connect4", "connect4"),
        ("soglia_connect6", "connect6"),
        ("soglia_sendmsg4", "sendmsg4"),
        ("soglia_sendmsg6", "sendmsg6"),
    ] {
        let item = attach_addr(bpf, cgroup, name, &root.join(file))?;
        load += item.1.0;
        attach += item.1.1;
        pin += item.1.2;
        links.push(item.0);
    }
    let item = attach_ops(bpf, cgroup, "soglia_sockops", &root.join("sock_ops"))?;
    load += item.1.0;
    attach += item.1.1;
    pin += item.1.2;
    links.push(item.0);
    Ok((links, load, attach, pin))
}

fn attach_sock(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<(PinnedLink, (u128, u128, u128)), String> {
    let program: &mut CgroupSock = bpf
        .program_mut(name)
        .ok_or("missing cgroup sock")?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    let started = Instant::now();
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let load = started.elapsed().as_nanos();
    let started = Instant::now();
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let attach = started.elapsed().as_nanos();
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        load,
        attach,
    )
}

fn attach_addr(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<(PinnedLink, (u128, u128, u128)), String> {
    let program: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .ok_or("missing cgroup addr")?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    let started = Instant::now();
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let load = started.elapsed().as_nanos();
    let started = Instant::now();
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let attach = started.elapsed().as_nanos();
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        load,
        attach,
    )
}

fn attach_ops(
    bpf: &mut Ebpf,
    cgroup: &File,
    name: &str,
    pin: &Path,
) -> Result<(PinnedLink, (u128, u128, u128)), String> {
    let program: &mut SockOps = bpf
        .program_mut(name)
        .ok_or("missing sockops")?
        .try_into()
        .map_err(|error| format!("convert {name}: {error:#}"))?;
    let started = Instant::now();
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let load = started.elapsed().as_nanos();
    let started = Instant::now();
    let id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let attach = started.elapsed().as_nanos();
    pin_link(
        program
            .take_link(id)
            .map_err(|error| format!("take {name}: {error:#}"))?,
        pin,
        load,
        attach,
    )
}

fn pin_link<L>(
    link: L,
    pin: &Path,
    load: u128,
    attach: u128,
) -> Result<(PinnedLink, (u128, u128, u128)), String>
where
    L: TryInto<FdLink>,
    L::Error: std::fmt::Debug,
{
    let link: FdLink = link
        .try_into()
        .map_err(|error| format!("fd link: {error:#?}"))?;
    let started = Instant::now();
    let link = link
        .pin(pin)
        .map_err(|error| format!("pin link: {error:#}"))?;
    Ok((link, (load, attach, started.elapsed().as_nanos())))
}

fn open_fd_count() -> Result<usize, String> {
    fs::read_dir("/proc/self/fd")
        .map_err(display_error("read /proc/self/fd"))?
        .try_fold(0, |count, entry| {
            entry
                .map(|_| count + 1)
                .map_err(display_error("enumerate fd"))
        })
}

fn wait_for(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !path.exists() {
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(display_error("write S14 loader record"))
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

fn display_error(operation: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("{operation}: {error}")
}
