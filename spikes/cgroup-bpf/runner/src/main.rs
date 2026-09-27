// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use soglia_spike_runner::cli::Cli;
use soglia_spike_runner::{agent_launcher, cli, controller, delegation, s0_loader};

fn main() -> ExitCode {
    match entry() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(14)),
        Err(error) => {
            eprintln!("soglia-spike-runner: {error}");
            ExitCode::from(14)
        }
    }
}

fn entry() -> Result<i32, String> {
    match cli::parse()? {
        Cli::Doctor(options) => controller::doctor(options),
        Cli::Run(options) => controller::run(options),
        Cli::DelegationHelper { ready } => delegation::run(&ready).map(|()| 0),
        Cli::AgentLauncher(options) => agent_launcher::run(&options).map(|()| 0),
        Cli::S0Loader(options) => s0_loader::run(&options).map(|()| 0),
    }
}
