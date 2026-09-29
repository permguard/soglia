// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia __sandboxd` role: one channel, one request at a time.
//!
//! The protocol mirrors the enforcer's. When the channel closes the Supervisor is gone, so the
//! sandbox helper kills every live Execution — no agent outlives the runtime that was supervising it
//! — and exits. The rest is left to the next start's sweep.

use std::os::unix::net::UnixStream;

use soglia_core::config::Config;
use soglia_core::helper::{Hello, HelperFailure, HelperResponse, RefusalClass, SandboxRequest};
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
        Err(failure) => {
            let _ = write_frame(
                &mut writer,
                &HelperResponse::Failed {
                    failure: failure.clone(),
                },
            );
            return Err(failure.detail().to_owned());
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
                failure: sandbox_failure("the Sandbox request failed", error),
            },
        };
        if let Err(error) = write_frame(&mut writer, &response) {
            kill_all(&mut backend);
            return Err(error.to_string());
        }
    }
}

fn start(hello: &Hello) -> Result<(RuncSandbox, Vec<String>), HelperFailure> {
    let config = Config::from_yaml(&hello.config_yaml).map_err(|error| HelperFailure::Refused {
        class: RefusalClass::Incompatible,
        detail: format!("the Sandbox configuration is incompatible: {error}"),
    })?;
    let settings = SandboxSettings::from_config(&config)
        .map_err(|error| sandbox_failure("the Sandbox configuration is incompatible", error))?;
    let mut backend = RuncSandbox::new(settings);
    backend
        .probe_capabilities()
        .map_err(|error| sandbox_failure(&format!("the {} probe failed", backend.name()), error))?;
    let swept = backend.initialize().map_err(|error| {
        sandbox_failure(
            &format!("the {} backend could not start", backend.name()),
            error,
        )
    })?;

    Ok((backend, swept))
}

fn sandbox_failure(context: &str, error: SandboxError) -> HelperFailure {
    let detail = format!("{context}: {error}");
    let class = match error {
        SandboxError::Refused(_) => RefusalClass::Incompatible,
        SandboxError::Failed(_) => RefusalClass::Infrastructure,
    };
    HelperFailure::Refused { class, detail }
}

fn serve(
    backend: &mut RuncSandbox,
    request: SandboxRequest,
) -> Result<HelperResponse, SandboxError> {
    match request {
        SandboxRequest::Reserve { id, agent } => backend
            .reserve_execution(id, &agent)
            .map(|cgroup_inode| HelperResponse::Reserved { cgroup_inode }),
        SandboxRequest::CreatePaused { id } => backend
            .create_paused(id)
            .map(|(pid, cgroup_inode)| HelperResponse::CreatedPaused { pid, cgroup_inode }),
        SandboxRequest::Start { id } => backend.start_execution(id).map(|()| HelperResponse::Done),
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
