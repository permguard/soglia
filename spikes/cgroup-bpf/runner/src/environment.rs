// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::{CommandExecutor, CommandSpec};
use crate::model::Verdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentObservation {
    pub os: String,
    pub architecture: String,
    pub kernel: String,
    pub distribution: String,
    pub effective_uid: String,
    pub cgroup_v2: bool,
    pub bpffs: bool,
    pub btf: bool,
    pub artifacts: BTreeMap<String, bool>,
    pub tools: BTreeMap<String, bool>,
    pub tool_versions: BTreeMap<String, String>,
    pub rlimit_nofile: String,
    pub free_disk: String,
    pub verdict: Verdict,
    pub detail: String,
}

pub fn probe(
    commands: &CommandExecutor,
    artifacts: &Path,
) -> Result<EnvironmentObservation, String> {
    let uname_s = run_text(commands, "uname", &["-s"])?;
    let architecture = run_text(commands, "uname", &["-m"])?;
    let kernel = run_text(commands, "uname", &["-r"])?;
    let effective_uid = run_text(commands, "id", &["-u"])?;
    let distribution = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let cgroup_v2 = fs::read_to_string("/proc/mounts").is_ok_and(|mounts| {
        mounts
            .lines()
            .any(|line| line.contains(" /sys/fs/cgroup cgroup2 "))
    });
    let bpffs = fs::read_to_string("/proc/mounts").is_ok_and(|mounts| {
        mounts
            .lines()
            .any(|line| line.contains(" /sys/fs/bpf bpf "))
    });
    let btf = Path::new("/sys/kernel/btf/vmlinux").is_file();
    let tool_names = [
        "bpftool",
        "clang",
        "git",
        "ip",
        "nft",
        "runc",
        "systemctl",
        "systemd-run",
    ];
    let tools = tool_names
        .into_iter()
        .map(|tool| (tool.to_owned(), command_exists(commands, tool)))
        .collect::<BTreeMap<_, _>>();
    let version_commands: [(&str, &[&str]); 8] = [
        ("bpftool", &["version"]),
        ("clang", &["--version"]),
        ("git", &["--version"]),
        ("ip", &["-Version"]),
        ("nft", &["--version"]),
        ("runc", &["--version"]),
        ("systemctl", &["--version"]),
        ("systemd-run", &["--version"]),
    ];
    let tool_versions = version_commands
        .into_iter()
        .map(|(tool, arguments)| {
            (
                tool.to_owned(),
                tool_version(commands, tool, arguments).unwrap_or_else(|error| error),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let artifact_names = [
        "bin/soglia-spike-runner",
        "bin/soglia-spike-agent",
        "bin/s2-helper",
        "bin/s5-helper",
        "bin/s7-loader",
        "bin/s14-loader",
        "bin/soglia",
        "bpf/soglia.o",
        "bpf/soglia-relax-inet6.o",
        "bpf/soglia-relax-dgram.o",
        "bpf/soglia-relax-all.o",
        "bpf/soglia-relax-inet6-diag.o",
        "bpf/soglia-relax-dgram-diag.o",
        "bpf/soglia-delay.o",
        "bpf/soglia-delay-diag.o",
        "bpf/soglia-small.o",
        "bpf/soglia-small-diag.o",
        "bpf/soglia-trace.o",
        "bpf/soglia-diag.o",
        "bpf/soglia-direct-control.o",
        "bpf/netns-probe.o",
        "bpf/foreign.o",
        "bpf/foreign-s10.o",
        "bpf/gpl-probe-task-btf.o",
        "bpf/gpl-probe-cgroup-from-id.o",
        "bpf/vmlinux.h",
    ];
    let artifact_state = artifact_names
        .into_iter()
        .map(|name| (name.to_owned(), artifacts.join(name).is_file()))
        .collect::<BTreeMap<_, _>>();
    let rlimit_nofile = fs::read_to_string("/proc/self/limits")
        .unwrap_or_default()
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .unwrap_or_default()
        .to_owned();
    let free_disk = run_text(
        commands,
        "df",
        &["-Pk", artifacts.to_string_lossy().as_ref()],
    )?;
    let missing_tools = tools
        .iter()
        .filter_map(|(name, present)| (!present).then_some(name.as_str()))
        .collect::<Vec<_>>();
    let missing_artifacts = artifact_state
        .iter()
        .filter_map(|(name, present)| (!present).then_some(name.as_str()))
        .collect::<Vec<_>>();
    let (verdict, detail) = if uname_s.trim() != "Linux" {
        (
            Verdict::Unsupported,
            "guest operating system is not Linux".to_owned(),
        )
    } else if effective_uid.trim() != "0" {
        (
            Verdict::InfraError,
            "runner must execute as root".to_owned(),
        )
    } else if !cgroup_v2 || !bpffs || !btf {
        (
            Verdict::Unsupported,
            format!(
                "required kernel substrate missing: cgroup_v2={cgroup_v2} bpffs={bpffs} btf={btf}"
            ),
        )
    } else if !missing_tools.is_empty() {
        (
            Verdict::InfraError,
            format!("required commands missing: {}", missing_tools.join(", ")),
        )
    } else if !missing_artifacts.is_empty() {
        (
            Verdict::InfraError,
            format!(
                "required build artifacts missing: {}",
                missing_artifacts.join(", ")
            ),
        )
    } else {
        (
            Verdict::Pass,
            "required guest substrate and build artifacts are present".to_owned(),
        )
    };
    Ok(EnvironmentObservation {
        os: uname_s.trim().to_owned(),
        architecture: architecture.trim().to_owned(),
        kernel: kernel.trim().to_owned(),
        distribution,
        effective_uid: effective_uid.trim().to_owned(),
        cgroup_v2,
        bpffs,
        btf,
        artifacts: artifact_state,
        tools,
        tool_versions,
        rlimit_nofile,
        free_disk,
        verdict,
        detail,
    })
}

fn tool_version(
    commands: &CommandExecutor,
    command: &str,
    arguments: &[&str],
) -> Result<String, String> {
    let output = commands.run(
        &CommandSpec::new(command)
            .args(arguments.iter().copied())
            .timeout(Duration::from_secs(10)),
    )?;
    output.require_success(&format!("query {command} version"))?;
    let stdout = output.stdout_text();
    let stderr = output.stderr_text();
    let value = if stdout.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    Ok(value.to_owned())
}

fn command_exists(commands: &CommandExecutor, command: &str) -> bool {
    commands
        .run(
            &CommandSpec::new("/usr/bin/env")
                .args(["sh", "-c", "command -v \"$1\"", "sh", command])
                .env("LC_ALL", "C")
                .timeout(Duration::from_secs(5)),
        )
        .is_ok_and(|output| output.success())
}

fn run_text(
    commands: &CommandExecutor,
    executable: &str,
    arguments: &[&str],
) -> Result<String, String> {
    let output = commands.run(
        &CommandSpec::new(executable)
            .args(arguments.iter().copied())
            .env("LC_ALL", "C")
            .timeout(Duration::from_secs(10)),
    )?;
    output.require_success(executable)?;
    Ok(output.stdout_text())
}
