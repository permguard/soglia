// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Minimal connect4-only loader for the S0.4 cgroup-BPF experiment.
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
    EbpfLoader,
    programs::{
        CgroupAttachMode, CgroupSockAddr,
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
    link_pin: PathBuf,
    ready_file: PathBuf,
    stop_file: PathBuf,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut args = env::args_os().skip(1);
        let config = Self {
            object: next_path(&mut args, "BPF object")?,
            cgroup: next_path(&mut args, "cgroup")?,
            map_pin_root: next_path(&mut args, "map pin root")?,
            link_pin: next_path(&mut args, "link pin")?,
            ready_file: next_path(&mut args, "ready file")?,
            stop_file: next_path(&mut args, "stop file")?,
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
        .ok_or_else(|| format!("missing {name} path"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("S0.4 CONNECT4 ERROR: {error}");
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
    println!("program=soglia_connect4");
    println!("aya_type=CgroupSockAddr");
    println!("expected_attach_type=cgroup_inet4_connect");
    println!("mode=Single flags=0");
    println!("object={}", config.object.display());
    println!("cgroup={}", config.cgroup.display());
    println!("map_pin_root={}", config.map_pin_root.display());
    println!("link_pin={}", config.link_pin.display());

    let mut bpf = match loader.load_file(&config.object) {
        Ok(bpf) => bpf,
        Err(error) => {
            remove_map_pins(&config.map_pin_root);
            remove_empty_dirs(&config);
            return Err(format!("load {}: {error:#}", config.object.display()));
        }
    };
    let cgroup = match File::open(&config.cgroup) {
        Ok(cgroup) => cgroup,
        Err(error) => {
            cleanup(None, bpf, &config);
            return Err(format!("open cgroup {}: {error}", config.cgroup.display()));
        }
    };
    let pinned_link = match attach_connect4(&mut bpf, &cgroup, &config.link_pin) {
        Ok(link) => link,
        Err(error) => {
            eprintln!("result=FAIL operation=bpf_link_create error={error}");
            cleanup(None, bpf, &config);
            return Err(error);
        }
    };

    println!("result=SUCCESS operation=bpf_link_create");
    if let Err(error) = fs::write(&config.ready_file, b"ready\n") {
        cleanup(Some(pinned_link), bpf, &config);
        return Err(format!(
            "write ready file {}: {error}",
            config.ready_file.display()
        ));
    }
    println!("state=READY");

    let started = Instant::now();
    while !config.stop_file.exists() {
        if started.elapsed() >= WAIT_TIMEOUT {
            eprintln!("wait_timeout_seconds={}", WAIT_TIMEOUT.as_secs());
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    println!("state=CLEANUP_BEGIN");
    cleanup(Some(pinned_link), bpf, &config);
    println!("state=CLEANUP_COMPLETE");
    Ok(())
}

fn attach_connect4(
    bpf: &mut aya::Ebpf,
    cgroup: &File,
    link_pin: &Path,
) -> Result<PinnedLink, String> {
    let program: &mut CgroupSockAddr = bpf
        .program_mut("soglia_connect4")
        .ok_or("program soglia_connect4 not found")?
        .try_into()
        .map_err(|error| format!("convert soglia_connect4: {error:#}"))?;
    program
        .load()
        .map_err(|error| format!("load soglia_connect4: {error:#}"))?;
    let link_id = program
        .attach(cgroup, CgroupAttachMode::Single)
        .map_err(|error| format!("attach soglia_connect4: {error:?}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|error| format!("take soglia_connect4 link: {error:#}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|error| format!("require fd-backed BPF link: {error:#}"))?;
    fd_link
        .pin(link_pin)
        .map_err(|error| format!("pin link at {}: {error:#}", link_pin.display()))
}

fn cleanup(link: Option<PinnedLink>, bpf: aya::Ebpf, config: &Config) {
    if let Some(link) = link {
        match link.unpin() {
            Ok(fd_link) => drop(fd_link),
            Err(error) => eprintln!("cleanup link unpin error: {error}"),
        }
    }
    drop(bpf);
    remove_map_pins(&config.map_pin_root);
    let _ = fs::remove_file(&config.ready_file);
    let _ = fs::remove_file(&config.stop_file);
    remove_empty_dirs(config);
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

fn remove_empty_dirs(config: &Config) {
    remove_empty_dir(&config.map_pin_root);
    if let Some(parent) = config.map_pin_root.parent() {
        remove_empty_dir(parent);
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
