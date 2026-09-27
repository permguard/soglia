// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Loader process used to characterize pinned-link survival in S7.
//!
//! EXPERIMENTAL: this is spike machinery, not product code.

#![forbid(unsafe_code)]

use std::{
    env,
    fs::{self, File},
    path::{Path, PathBuf},
    process, thread,
    time::Duration,
};

use aya::{
    Ebpf, EbpfLoader,
    maps::Array,
    programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps,
        links::{FdLink, PinnedLink},
    },
};

struct Config {
    object: PathBuf,
    cgroup: PathBuf,
    map_pins: PathBuf,
    link_pins: PathBuf,
    ready: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1).map(PathBuf::from);
        let config = Self {
            object: args.next().ok_or("missing object")?,
            cgroup: args.next().ok_or("missing cgroup")?,
            map_pins: args.next().ok_or("missing map pin root")?,
            link_pins: args.next().ok_or("missing link pin root")?,
            ready: args.next().ok_or("missing ready marker")?,
        };
        if args.next().is_some() {
            return Err("unexpected extra argument".to_owned());
        }
        Ok(config)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S7 PINNED LOADER ERROR: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse()?;
    fs::create_dir_all(&config.map_pins).map_err(display_error("create map pins"))?;
    fs::create_dir_all(&config.link_pins).map_err(display_error("create link pins"))?;
    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let exec_ident = 7_001_001_u64;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &exec_ident, true)
        .default_map_pin_directory(&config.map_pins);
    let mut bpf = loader
        .load_file(&config.object)
        .map_err(|error| format!("load {}: {error:#}", config.object.display()))?;
    let local_map = bpf.map_mut("policy_local").ok_or("policy_local missing")?;
    let mut local = Array::<_, u64>::try_from(local_map)
        .map_err(|error| format!("open policy_local: {error:#}"))?;
    local
        .set(0, 1, 0)
        .map_err(|error| format!("activate policy_local: {error:#}"))?;
    let cgroup = File::open(&config.cgroup)
        .map_err(|error| format!("open {}: {error}", config.cgroup.display()))?;
    let links = attach_all(&mut bpf, &cgroup, &config.link_pins)?;
    println!("loader_pid={}", process::id());
    println!("attached_links={}", links.len());
    println!("state=PINNED_READY");
    fs::write(&config.ready, format!("{}\n", process::id()))
        .map_err(display_error("write ready marker"))?;
    loop {
        thread::sleep(Duration::from_secs(60));
        std::hint::black_box((&bpf, &links));
    }
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
        .map_err(|error| format!("take {name}: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("fd link {name}: {error:#}"))?;
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
        .map_err(|error| format!("take {name}: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("fd link {name}: {error:#}"))?;
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
        .map_err(|error| format!("take {name}: {error:#}"))?;
    let fd: FdLink = link
        .try_into()
        .map_err(|error| format!("fd link {name}: {error:#}"))?;
    fd.pin(pin)
        .map_err(|error| format!("pin {name}: {error:#}"))
}

fn display_error(context: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("{context}: {error}")
}
