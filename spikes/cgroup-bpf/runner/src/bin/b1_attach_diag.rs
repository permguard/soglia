// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Diagnostic-only loader for the production Candidate-A object.
//!
//! This binary does not implement a backend and is never used by production. It attaches exactly
//! one named production hook to one caller-supplied disposable cgroup so B1 can compare the link
//! flags accepted by the running kernel before the production attachment plan is changed.

use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use aya::programs::links::FdLink;
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps};
use aya::{Ebpf, EbpfLoader};
use serde::Serialize;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Mode {
    Single,
    AllowMultiple,
}

impl Mode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "single" => Ok(Self::Single),
            "allow-multiple" => Ok(Self::AllowMultiple),
            _ => Err(format!("unknown attach mode `{value}`")),
        }
    }

    fn aya(self) -> CgroupAttachMode {
        match self {
            Self::Single => CgroupAttachMode::Single,
            Self::AllowMultiple => CgroupAttachMode::AllowMultiple,
        }
    }
}

#[derive(Serialize)]
struct Observation<'a> {
    hook: &'a str,
    mode: Mode,
    status: &'a str,
    error: Option<String>,
}

struct Options {
    object: PathBuf,
    cgroup: PathBuf,
    pin: PathBuf,
    hook: String,
    mode: Mode,
    ready: PathBuf,
    stop: PathBuf,
}

fn main() -> ExitCode {
    match parse().and_then(|options| run(&options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("b1-attach-diag: {error}");
            ExitCode::from(14)
        }
    }
}

fn parse() -> Result<Options, String> {
    let mut arguments = env::args_os().skip(1);
    let mut next = |name: &str| {
        arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing {name}"))
    };
    let object = next("production object")?;
    let cgroup = next("cgroup")?;
    let pin = next("link pin")?;
    let hook = next("hook")?
        .into_os_string()
        .into_string()
        .map_err(|_| "hook is not valid UTF-8".to_owned())?;
    let mode = next("attach mode")?
        .into_os_string()
        .into_string()
        .map_err(|_| "attach mode is not valid UTF-8".to_owned())?;
    let ready = next("ready path")?;
    let stop = next("stop path")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".to_owned());
    }
    Ok(Options {
        object,
        cgroup,
        pin,
        hook,
        mode: Mode::parse(&mode)?,
        ready,
        stop,
    })
}

fn run(options: &Options) -> Result<(), String> {
    let proxy_ip4 = u32::from_ne_bytes([10, 200, 255, 1]);
    let proxy_port = 15_001_u32;
    let backend_generation = 1_u64;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("proxy_ip4", &proxy_ip4, true)
        .override_global("proxy_port", &proxy_port, true)
        .override_global("backend_generation", &backend_generation, true);
    let mut bpf = loader
        .load_file(&options.object)
        .map_err(|error| format!("load {}: {error:#}", options.object.display()))?;
    let cgroup = File::open(&options.cgroup)
        .map_err(|error| format!("open {}: {error}", options.cgroup.display()))?;

    let link = match attach(&mut bpf, &cgroup, &options.hook, options.mode) {
        Ok(link) => link,
        Err(error) => {
            publish(
                &options.ready,
                &Observation {
                    hook: &options.hook,
                    mode: options.mode,
                    status: "ATTACH_ERROR",
                    error: Some(error),
                },
            )?;
            return Ok(());
        }
    };
    if options.pin.exists() {
        return Err(format!(
            "refusing pre-existing diagnostic pin {}",
            options.pin.display()
        ));
    }
    publish(
        &options.ready,
        &Observation {
            hook: &options.hook,
            mode: options.mode,
            status: "ATTACHED",
            error: None,
        },
    )?;

    let started = Instant::now();
    while !options.stop.exists() {
        if started.elapsed() > Duration::from_secs(120) {
            return Err("timed out waiting for the stop marker".to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    }
    drop(link);
    remove_if_present(&options.ready)?;
    remove_if_present(&options.stop)?;
    Ok(())
}

fn publish(path: &Path, observation: &Observation<'_>) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(observation).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn attach(bpf: &mut Ebpf, cgroup: &File, hook: &str, mode: Mode) -> Result<FdLink, String> {
    match hook {
        "soglia_sock_create" => {
            let program: &mut CgroupSock = program(bpf, hook)?;
            program
                .load()
                .map_err(|error| format!("load {hook}: {error:#}"))?;
            let id = program
                .attach(cgroup, mode.aya())
                .map_err(|error| format!("attach {hook}: {error:?}"))?;
            program
                .take_link(id)
                .map_err(|error| format!("take {hook}: {error:#}"))?
                .try_into()
                .map_err(|error| format!("convert link {hook}: {error:#}"))
        }
        "soglia_connect4" | "soglia_connect6" | "soglia_sendmsg4" | "soglia_sendmsg6" => {
            let program: &mut CgroupSockAddr = program(bpf, hook)?;
            program
                .load()
                .map_err(|error| format!("load {hook}: {error:#}"))?;
            let id = program
                .attach(cgroup, mode.aya())
                .map_err(|error| format!("attach {hook}: {error:?}"))?;
            program
                .take_link(id)
                .map_err(|error| format!("take {hook}: {error:#}"))?
                .try_into()
                .map_err(|error| format!("convert link {hook}: {error:#}"))
        }
        "soglia_sockops" => {
            let program: &mut SockOps = program(bpf, hook)?;
            program
                .load()
                .map_err(|error| format!("load {hook}: {error:#}"))?;
            let id = program
                .attach(cgroup, mode.aya())
                .map_err(|error| format!("attach {hook}: {error:?}"))?;
            program
                .take_link(id)
                .map_err(|error| format!("take {hook}: {error:#}"))?
                .try_into()
                .map_err(|error| format!("convert link {hook}: {error:#}"))
        }
        _ => Err(format!("unknown production hook `{hook}`")),
    }
}

fn program<'a, T>(bpf: &'a mut Ebpf, name: &str) -> Result<&'a mut T, String>
where
    &'a mut T: TryFrom<&'a mut aya::programs::Program>,
    <&'a mut T as TryFrom<&'a mut aya::programs::Program>>::Error: std::fmt::Display,
{
    bpf.program_mut(name)
        .ok_or_else(|| format!("program {name} is absent"))?
        .try_into()
        .map_err(|error| format!("convert {name}: {error}"))
}

fn remove_if_present(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}
