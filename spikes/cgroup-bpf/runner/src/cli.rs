// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

use crate::model::TestId;

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub repository: PathBuf,
    pub evidence_base: PathBuf,
    pub artifacts: PathBuf,
    pub only: Option<TestId>,
    pub from: Option<TestId>,
}

impl RunOptions {
    pub fn authoritative(&self) -> bool {
        self.only.is_none() && self.from.is_none()
    }
}

#[derive(Debug, Clone)]
pub enum Cli {
    Doctor(RunOptions),
    Run(RunOptions),
    DelegationHelper { ready: PathBuf },
    AgentLauncher(AgentLauncherOptions),
    S0Loader(S0LoaderOptions),
}

#[derive(Debug, Clone)]
pub struct AgentLauncherOptions {
    pub netns: PathBuf,
    pub agent: PathBuf,
    pub host_ready: PathBuf,
    pub agent_ready: PathBuf,
    pub agent_go: PathBuf,
    pub operation: String,
}

#[derive(Debug, Clone)]
pub struct S0LoaderOptions {
    pub object: PathBuf,
    pub cgroup: PathBuf,
    pub map_pins: PathBuf,
    pub link_pins: PathBuf,
    pub ready: PathBuf,
    pub stop: PathBuf,
    pub connect4_only: bool,
}

pub fn parse() -> Result<Cli, String> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| usage("missing command"))?
        .to_string_lossy()
        .into_owned();
    let rest: Vec<_> = arguments.collect();
    match command.as_str() {
        "doctor" => Ok(Cli::Doctor(parse_run_options(&rest, false)?)),
        "run" => Ok(Cli::Run(parse_run_options(&rest, true)?)),
        "_delegation-helper" => {
            let ready = value_after(&rest, "--ready")?;
            Ok(Cli::DelegationHelper {
                ready: PathBuf::from(ready),
            })
        }
        "_agent-launcher" => Ok(Cli::AgentLauncher(parse_agent_launcher(&rest)?)),
        "_s0-loader" => Ok(Cli::S0Loader(parse_s0_loader(&rest)?)),
        _ => Err(usage(&format!("unknown command `{command}`"))),
    }
}

fn parse_agent_launcher(arguments: &[std::ffi::OsString]) -> Result<AgentLauncherOptions, String> {
    let known = [
        "--netns",
        "--agent",
        "--host-ready",
        "--agent-ready",
        "--agent-go",
        "--operation",
    ];
    reject_unknown(arguments, &known)?;
    Ok(AgentLauncherOptions {
        netns: PathBuf::from(value_after(arguments, "--netns")?),
        agent: PathBuf::from(value_after(arguments, "--agent")?),
        host_ready: PathBuf::from(value_after(arguments, "--host-ready")?),
        agent_ready: PathBuf::from(value_after(arguments, "--agent-ready")?),
        agent_go: PathBuf::from(value_after(arguments, "--agent-go")?),
        operation: value_after(arguments, "--operation")?,
    })
}

fn parse_run_options(
    arguments: &[std::ffi::OsString],
    allow_selection: bool,
) -> Result<RunOptions, String> {
    let repository = value_after_or(arguments, "--repo", "/soglia");
    let evidence_base = value_after_or(
        arguments,
        "--evidence",
        "/soglia/spikes/cgroup-bpf/evidence/replay",
    );
    let artifacts = value_after_or(arguments, "--artifacts", "/var/tmp/soglia-spike-2");
    let only = optional_test(arguments, "--only")?;
    let from = optional_test(arguments, "--from")?;
    if !allow_selection && (only.is_some() || from.is_some()) {
        return Err("doctor does not accept --only or --from".to_owned());
    }
    if only.is_some() && from.is_some() {
        return Err("--only and --from are mutually exclusive".to_owned());
    }
    reject_unknown(
        arguments,
        &["--repo", "--evidence", "--artifacts", "--only", "--from"],
    )?;
    Ok(RunOptions {
        repository: PathBuf::from(repository),
        evidence_base: PathBuf::from(evidence_base),
        artifacts: PathBuf::from(artifacts),
        only,
        from,
    })
}

fn parse_s0_loader(arguments: &[std::ffi::OsString]) -> Result<S0LoaderOptions, String> {
    reject_unknown(
        arguments,
        &[
            "--object",
            "--cgroup",
            "--map-pins",
            "--link-pins",
            "--ready",
            "--stop",
            "--connect4-only",
        ],
    )?;
    Ok(S0LoaderOptions {
        object: PathBuf::from(value_after(arguments, "--object")?),
        cgroup: PathBuf::from(value_after(arguments, "--cgroup")?),
        map_pins: PathBuf::from(value_after(arguments, "--map-pins")?),
        link_pins: PathBuf::from(value_after(arguments, "--link-pins")?),
        ready: PathBuf::from(value_after(arguments, "--ready")?),
        stop: PathBuf::from(value_after(arguments, "--stop")?),
        connect4_only: arguments.iter().any(|value| value == "--connect4-only"),
    })
}

fn optional_test(arguments: &[std::ffi::OsString], key: &str) -> Result<Option<TestId>, String> {
    if !arguments.iter().any(|value| value == key) {
        return Ok(None);
    }
    let value = value_after(arguments, key)?;
    TestId::parse(&value)
        .map(Some)
        .ok_or_else(|| format!("unknown test `{value}`"))
}

fn value_after(arguments: &[std::ffi::OsString], key: &str) -> Result<String, String> {
    let position = arguments
        .iter()
        .position(|value| value == key)
        .ok_or_else(|| format!("missing {key}"))?;
    arguments
        .get(position + 1)
        .ok_or_else(|| format!("missing value after {key}"))
        .map(|value| value.to_string_lossy().into_owned())
}

fn value_after_or(arguments: &[std::ffi::OsString], key: &str, default: &str) -> String {
    value_after(arguments, key).unwrap_or_else(|_| default.to_owned())
}

fn reject_unknown(arguments: &[std::ffi::OsString], known: &[&str]) -> Result<(), String> {
    let mut index = 0;
    while index < arguments.len() {
        let value = arguments[index].to_string_lossy();
        if value == "--connect4-only" {
            index += 1;
            continue;
        }
        if !known.iter().any(|known| value == *known) {
            return Err(format!("unknown argument `{value}`"));
        }
        index += 2;
    }
    Ok(())
}

fn usage(reason: &str) -> String {
    format!(
        "{reason}\nusage: soglia-spike-runner doctor [options] | run [--only TEST | --from TEST] [options]"
    )
}
