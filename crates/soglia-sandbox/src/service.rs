// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia __sandboxd` role: one channel, one request at a time.
//!
//! The protocol mirrors the enforcer's. When the channel closes the Supervisor is gone, so the
//! sandbox helper kills every live Execution — no agent outlives the runtime that was supervising it
//! — and exits. The rest is left to the next start's sweep.

use std::os::unix::net::UnixStream;

use soglia_core::config::Config;
use soglia_core::helper::{Hello, HelperResponse, SandboxRequest};
use soglia_core::ipc::{FrameError, read_frame, write_frame};

use crate::backend::{RuncSandbox, SandboxBackend, SandboxError, SandboxSettings};

/// Serves the sandbox role on `channel` until it closes.
pub fn run(channel: UnixStream) -> Result<(), String> {
    let mut reader = channel
        .try_clone()
        .map_err(|error| format!("cannot use the helper channel: {error}"))?;
    let mut writer = channel;

    let hello: Hello = read_frame(&mut reader).map_err(|error| error.to_string())?;
    let mut backend = match start(&hello) {
        Ok((backend, swept)) => {
            write_frame(&mut writer, &HelperResponse::Ready { swept })
                .map_err(|error| error.to_string())?;
            backend
        }
        Err(reason) => {
            let _ = write_frame(
                &mut writer,
                &HelperResponse::Failed {
                    reason: reason.clone(),
                },
            );
            return Err(reason);
        }
    };

    loop {
        let request: SandboxRequest = match read_frame(&mut reader) {
            Ok(request) => request,
            Err(FrameError::Closed) => {
                kill_all(&mut backend);
                return Ok(());
            }
            Err(error) => {
                kill_all(&mut backend);
                return Err(error.to_string());
            }
        };
        let response = match serve(&mut backend, request) {
            Ok(response) => response,
            Err(error) => HelperResponse::Failed {
                reason: error.to_string(),
            },
        };
        if let Err(error) = write_frame(&mut writer, &response) {
            kill_all(&mut backend);
            return Err(error.to_string());
        }
    }
}

fn start(hello: &Hello) -> Result<(RuncSandbox, Vec<String>), String> {
    let config = Config::from_yaml(&hello.config_yaml).map_err(|error| error.to_string())?;
    let settings = SandboxSettings::from_config(&config).map_err(|error| error.to_string())?;
    let mut backend = RuncSandbox::new(settings);
    backend
        .probe_capabilities()
        .map_err(|error| format!("the {} probe failed: {error}", backend.name()))?;
    let swept = backend
        .initialize()
        .map_err(|error| format!("the {} backend could not start: {error}", backend.name()))?;

    Ok((backend, swept))
}

fn serve(
    backend: &mut RuncSandbox,
    request: SandboxRequest,
) -> Result<HelperResponse, SandboxError> {
    match request {
        SandboxRequest::Start { id, agent } => backend
            .start_execution(id, &agent)
            .map(|()| HelperResponse::Done),
        SandboxRequest::Kill { tag } => backend
            .kill_execution(&tag)
            .map(|outcome| HelperResponse::Exited { outcome }),
        SandboxRequest::Destroy { tag } => backend
            .destroy_execution(&tag)
            .map(|()| HelperResponse::Done),
    }
}

fn kill_all(backend: &mut RuncSandbox) {
    for tag in backend.live_tags() {
        if let Err(error) = backend.kill_execution(&tag) {
            eprintln!("soglia __sandboxd: could not kill {tag}: {error}");
        }
    }
}
