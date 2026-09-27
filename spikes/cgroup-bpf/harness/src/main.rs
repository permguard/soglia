// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Minimal S0.3 loader for the Phase-1 cgroup-BPF spike.
//!
//! EXPERIMENTAL: this is spike machinery, not product code.

use std::{
    env,
    fs::{self, File},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf, EbpfLoader,
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
const WAIT_TIMEOUT: Duration = Duration::from_secs(180);

struct Config {
    object: PathBuf,
    cgroup: PathBuf,
    map_pin_root: PathBuf,
    link_pin_root: PathBuf,
    ready_file: PathBuf,
    stop_file: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            object: args
                .next()
                .map(PathBuf::from)
                .ok_or("missing BPF object path")?,
            cgroup: args
                .next()
                .map(PathBuf::from)
                .ok_or("missing cgroup path")?,
            map_pin_root: args
                .next()
                .map(PathBuf::from)
                .ok_or("missing map pin root")?,
            link_pin_root: args
                .next()
                .map(PathBuf::from)
                .ok_or("missing link pin root")?,
            ready_file: args
                .next()
                .map(PathBuf::from)
                .ok_or("missing ready-file path")?,
            stop_file: args
                .next()
                .map(PathBuf::from)
                .ok_or("missing stop-file path")?,
        };
        if args.next().is_some() {
            return Err("unexpected extra arguments".to_owned());
        }
        Ok(config)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S0.3 HARNESS ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    fs::create_dir_all(&config.map_pin_root).map_err(|error| {
        format!(
            "create map pin root {}: {error}",
            config.map_pin_root.display()
        )
    })?;
    fs::create_dir_all(&config.link_pin_root).map_err(|error| {
        format!(
            "create link pin root {}: {error}",
            config.link_pin_root.display()
        )
    })?;

    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let exec_ident = 0_u64;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &exec_ident, true)
        .default_map_pin_directory(&config.map_pin_root);

    println!("aya_version=0.14.0");
    println!("object={}", config.object.display());
    println!("cgroup={}", config.cgroup.display());
    println!(
        "proxy_ip4=10.200.255.1 network_bytes={:02x?}",
        proxy_ip4.to_ne_bytes()
    );
    println!("proxy_port={proxy_port} host_byte_order");
    println!("exec_ident={exec_ident}");
    println!("map_pin_root={}", config.map_pin_root.display());
    println!("link_pin_root={}", config.link_pin_root.display());

    let mut bpf = loader
        .load_file(&config.object)
        .map_err(|error| format!("load {}: {error:#}", config.object.display()))?;
    let cgroup = File::open(&config.cgroup)
        .map_err(|error| format!("open cgroup {}: {error}", config.cgroup.display()))?;

    let attach_result = attach_all(&mut bpf, &cgroup, &config.link_pin_root);
    let mut links = match attach_result {
        Ok(links) => links,
        Err((error, links)) => {
            cleanup(links, &config.map_pin_root, &config.link_pin_root);
            return Err(error);
        }
    };

    fs::write(&config.ready_file, b"ready\n")
        .map_err(|error| format!("write ready file {}: {error}", config.ready_file.display()))?;
    println!("state=READY all_six_links_pinned");

    let started = Instant::now();
    while !config.stop_file.exists() {
        if started.elapsed() >= WAIT_TIMEOUT {
            eprintln!("wait_timeout_seconds={}", WAIT_TIMEOUT.as_secs());
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    println!("state=CLEANUP_BEGIN");
    while let Some(link) = links.pop() {
        match link.unpin() {
            Ok(fd_link) => drop(fd_link),
            Err(error) => eprintln!("cleanup link unpin error: {error}"),
        }
    }
    drop(bpf);
    remove_map_pins(&config.map_pin_root);
    remove_empty_dir(&config.link_pin_root);
    if let Some(parent) = config.link_pin_root.parent() {
        remove_empty_dir(parent);
        if let Some(parent) = parent.parent() {
            remove_empty_dir(parent);
        }
    }
    remove_empty_dir(&config.map_pin_root);
    if let Some(parent) = config.map_pin_root.parent() {
        remove_empty_dir(parent);
    }
    let _ = fs::remove_file(&config.ready_file);
    let _ = fs::remove_file(&config.stop_file);
    println!("state=CLEANUP_COMPLETE");
    Ok(())
}

fn attach_all(
    bpf: &mut Ebpf,
    cgroup: &File,
    pin_root: &Path,
) -> Result<Vec<PinnedLink>, (String, Vec<PinnedLink>)> {
    let mut links = Vec::with_capacity(6);

    macro_rules! attach {
        ($name:literal, $aya_type:literal, $attach_type:literal, $pin:literal, $function:ident) => {{
            println!(
                "attach program={} aya_type={} expected_attach_type={} mode=Single flags=0 pin={}",
                $name,
                $aya_type,
                $attach_type,
                pin_root.join($pin).display()
            );
            match $function(bpf, cgroup, $name, &pin_root.join($pin)) {
                Ok(link) => {
                    println!("attach program={} result=SUCCESS", $name);
                    links.push(link);
                }
                Err(error) => {
                    eprintln!("attach program={} result=FAIL error={error}", $name);
                    return Err((format!("{name}: {error}", name = $name), links));
                }
            }
        }};
    }

    attach!(
        "soglia_sock_create",
        "CgroupSock",
        "cgroup_inet_sock_create",
        "sock_create",
        attach_cgroup_sock
    );
    attach!(
        "soglia_connect4",
        "CgroupSockAddr",
        "cgroup_inet4_connect",
        "connect4",
        attach_cgroup_sock_addr
    );
    attach!(
        "soglia_connect6",
        "CgroupSockAddr",
        "cgroup_inet6_connect",
        "connect6",
        attach_cgroup_sock_addr
    );
    attach!(
        "soglia_sendmsg4",
        "CgroupSockAddr",
        "cgroup_udp4_sendmsg",
        "sendmsg4",
        attach_cgroup_sock_addr
    );
    attach!(
        "soglia_sendmsg6",
        "CgroupSockAddr",
        "cgroup_udp6_sendmsg",
        "sendmsg6",
        attach_cgroup_sock_addr
    );
    attach!(
        "soglia_sockops",
        "SockOps",
        "cgroup_sock_ops",
        "sock_ops",
        attach_sock_ops
    );
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
        .map_err(|error| format!("convert {name} to CgroupSock: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take link {name}: {error:#}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed BPF link for {name}: {error:#}"))?;
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
        .map_err(|error| format!("convert {name} to CgroupSockAddr: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take link {name}: {error:#}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed BPF link for {name}: {error:#}"))?;
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
        .map_err(|error| format!("convert {name} to SockOps: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load {name}: {error:#}"))?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach {name}: {error:#}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take link {name}: {error:#}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed BPF link for {name}: {error:#}"))?;
    fd_link
        .pin(pin)
        .map_err(|error| format!("pin {name} at {}: {error:#}", pin.display()))
}

fn cleanup(links: Vec<PinnedLink>, map_pin_root: &Path, link_pin_root: &Path) {
    for link in links.into_iter().rev() {
        match link.unpin() {
            Ok(fd_link) => drop(fd_link),
            Err(error) => eprintln!("cleanup link unpin error: {error}"),
        }
    }
    remove_map_pins(map_pin_root);
    remove_empty_dir(link_pin_root);
}

fn remove_map_pins(root: &Path) {
    for name in MAP_NAMES {
        if let Err(error) = fs::remove_file(root.join(name)) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("cleanup map pin {name}: {error}");
            }
        }
    }
}

fn remove_empty_dir(path: &Path) {
    if let Err(error) = fs::remove_dir(path) {
        if !matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
        ) {
            eprintln!("cleanup directory {}: {error}", path.display());
        }
    }
}
