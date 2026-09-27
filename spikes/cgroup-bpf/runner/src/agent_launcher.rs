// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::sched::{CloneFlags, setns};
use nix::sys::signal::{Signal, raise};

use crate::cli::AgentLauncherOptions;

pub fn run(options: &AgentLauncherOptions) -> Result<(), String> {
    let pid = std::process::id();
    fs::write(&options.host_ready, format!("{pid}\n"))
        .map_err(|error| format!("publish stopped launcher PID: {error}"))?;
    raise(Signal::SIGSTOP).map_err(|error| format!("stop launcher before placement: {error}"))?;

    let netns = File::open(&options.netns)
        .map_err(|error| format!("open netns {}: {error}", options.netns.display()))?;
    setns(&netns, CloneFlags::CLONE_NEWNET)
        .map_err(|error| format!("enter netns {}: {error}", options.netns.display()))?;

    let barrier = format!(
        "barrier {} {} 30",
        options.agent_ready.display(),
        options.agent_go.display()
    );
    let error = Command::new(&options.agent)
        .arg(barrier)
        .arg(&options.operation)
        .exec();
    Err(format!(
        "exec agent {} after netns entry: {error}",
        options.agent.display()
    ))
}
