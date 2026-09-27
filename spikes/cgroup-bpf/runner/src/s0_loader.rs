// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps};
use aya::{Ebpf, EbpfLoader};

use crate::cli::S0LoaderOptions;

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

pub fn run(options: &S0LoaderOptions) -> Result<(), String> {
    fs::create_dir_all(&options.map_pins)
        .map_err(|error| format!("create {}: {error}", options.map_pins.display()))?;
    fs::create_dir_all(&options.link_pins)
        .map_err(|error| format!("create {}: {error}", options.link_pins.display()))?;
    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let exec_ident = 0_u64;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("exec_ident", &exec_ident, true)
        .default_map_pin_directory(&options.map_pins);
    let mut bpf = loader
        .load_file(&options.object)
        .map_err(|error| format!("load {}: {error:#}", options.object.display()))?;
    let cgroup = File::open(&options.cgroup)
        .map_err(|error| format!("open {}: {error}", options.cgroup.display()))?;
    let attached = if options.connect4_only {
        vec![attach_cgroup_sock_addr(
            &mut bpf,
            &cgroup,
            "soglia_connect4",
            &options.link_pins.join("connect4"),
        )]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    } else {
        attach_all(&mut bpf, &cgroup, &options.link_pins)
    };
    let mut links = match attached {
        Ok(links) => links,
        Err(error) => {
            drop(bpf);
            let _ = remove_map_pins(&options.map_pins);
            let _ = remove_empty(&options.link_pins);
            let _ = remove_empty(&options.map_pins);
            return Err(error);
        }
    };
    fs::write(&options.ready, b"ready\n")
        .map_err(|error| format!("write {}: {error}", options.ready.display()))?;
    let started = Instant::now();
    while !options.stop.exists() {
        if started.elapsed() > Duration::from_secs(300) {
            return Err("S0 loader wait timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(20));
    }
    while let Some(link) = links.pop() {
        let fd = link
            .unpin()
            .map_err(|error| format!("unpin link: {error:#}"))?;
        drop(fd);
    }
    drop(bpf);
    remove_map_pins(&options.map_pins)?;
    remove_empty(&options.link_pins)?;
    remove_empty(&options.map_pins)?;
    let _ = fs::remove_file(&options.ready);
    let _ = fs::remove_file(&options.stop);
    Ok(())
}

fn attach_all(bpf: &mut Ebpf, cgroup: &File, root: &Path) -> Result<Vec<PinnedLink>, String> {
    let mut links = Vec::with_capacity(6);
    macro_rules! attach {
        ($expression:expr) => {
            match $expression {
                Ok(link) => links.push(link),
                Err(error) => {
                    for link in links.into_iter().rev() {
                        if let Ok(fd) = link.unpin() {
                            drop(fd);
                        }
                    }
                    return Err(error);
                }
            }
        };
    }
    attach!(attach_cgroup_sock(
        bpf,
        cgroup,
        "soglia_sock_create",
        &root.join("sock_create"),
    ));
    attach!(attach_cgroup_sock_addr(
        bpf,
        cgroup,
        "soglia_connect4",
        &root.join("connect4"),
    ));
    attach!(attach_cgroup_sock_addr(
        bpf,
        cgroup,
        "soglia_connect6",
        &root.join("connect6"),
    ));
    attach!(attach_cgroup_sock_addr(
        bpf,
        cgroup,
        "soglia_sendmsg4",
        &root.join("sendmsg4"),
    ));
    attach!(attach_cgroup_sock_addr(
        bpf,
        cgroup,
        "soglia_sendmsg6",
        &root.join("sendmsg6"),
    ));
    attach!(attach_sock_ops(
        bpf,
        cgroup,
        "soglia_sockops",
        &root.join("sock_ops"),
    ));
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
        // The alternate Display form stops at Aya's outer syscall context for
        // this error. Debug retains the nested OS errno, which S0 must prove.
        .map_err(|error| format!("attach {name}: {error:?}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name}: {error:#}"))?;
    pin_fd_link(
        link.try_into()
            .map_err(|error| format!("fd link {name}: {error:#}"))?,
        name,
        pin,
    )
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
        .map_err(|error| format!("attach {name}: {error:?}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name}: {error:#}"))?;
    pin_fd_link(
        link.try_into()
            .map_err(|error| format!("fd link {name}: {error:#}"))?,
        name,
        pin,
    )
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
        .map_err(|error| format!("attach {name}: {error:?}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take {name}: {error:#}"))?;
    pin_fd_link(
        link.try_into()
            .map_err(|error| format!("fd link {name}: {error:#}"))?,
        name,
        pin,
    )
}

fn pin_fd_link(link: FdLink, name: &str, pin: &Path) -> Result<PinnedLink, String> {
    link.pin(pin)
        .map_err(|error| format!("pin {name} at {}: {error:#}", pin.display()))
}

fn remove_map_pins(root: &Path) -> Result<(), String> {
    for name in MAP_NAMES {
        let path = root.join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove {}: {error}", path.display())),
        }
    }
    Ok(())
}

fn remove_empty(path: &PathBuf) -> Result<(), String> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove directory {}: {error}", path.display())),
    }
}
