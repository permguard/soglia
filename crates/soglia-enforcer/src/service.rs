// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia __enforcer` role: one channel, one request at a time.
//!
//! The channel is the socketpair end the original trusted process handed over as this process's
//! standard input. The first frame is the configuration; the enforcer probes the host, sweeps what a
//! previous run left behind, installs the host policy and only then reports ready. After that it
//! answers requests until the channel closes.
//!
//! When the channel closes the Supervisor is gone. The enforcer freezes every live Execution —
//! strictly more restrictive than what was there — and exits. Everything else is left to the next
//! start's sweep: network policy lives in the kernel, so nothing opens up in the meantime.

use std::os::unix::net::UnixStream;

use soglia_core::config::Config;
use soglia_core::helper::{EnforcerRequest, Hello, HelperResponse};
use soglia_core::ipc::{FrameError, read_frame, write_frame};

use crate::backend::{BackendError, EnforcementBackend, NetnsNftBackend, NetworkSettings};

/// Serves the enforcer role on `channel` until it closes.
pub fn run(channel: UnixStream) -> Result<(), String> {
    let mut reader = channel
        .try_clone()
        .map_err(|error| format!("cannot use the helper channel: {error}"))?;
    let mut writer = channel;

    let hello: Hello = read_frame(&mut reader).map_err(|error| error.to_string())?;
    let started = start(&hello);
    let mut backend = match started {
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
        let request: EnforcerRequest = match read_frame(&mut reader) {
            Ok(request) => request,
            Err(FrameError::Closed) => {
                freeze_all(&mut backend);
                return Ok(());
            }
            Err(error) => {
                // A malformed or unexpected frame ends the conversation: the channel is no longer
                // one this helper can trust to mean what it says.
                freeze_all(&mut backend);
                return Err(error.to_string());
            }
        };
        let response = match serve(&mut backend, request) {
            Ok(()) => HelperResponse::Done,
            Err(error) => HelperResponse::Failed {
                reason: error.to_string(),
            },
        };
        if let Err(error) = write_frame(&mut writer, &response) {
            freeze_all(&mut backend);
            return Err(error.to_string());
        }
    }
}

fn start(hello: &Hello) -> Result<(NetnsNftBackend, Vec<String>), String> {
    let config = Config::from_yaml(&hello.config_yaml).map_err(|error| error.to_string())?;
    let settings = NetworkSettings::from_config(&config).map_err(|error| error.to_string())?;
    let mut backend = NetnsNftBackend::new(settings);
    backend
        .probe_capabilities()
        .map_err(|error| format!("the {} probe failed: {error}", backend.name()))?;
    let swept = backend
        .initialize()
        .map_err(|error| format!("the {} backend could not start: {error}", backend.name()))?;

    Ok((backend, swept))
}

fn serve(backend: &mut NetnsNftBackend, request: EnforcerRequest) -> Result<(), BackendError> {
    match request {
        EnforcerRequest::Prepare { id, slot, agent } => backend.prepare_execution(id, slot, &agent),
        EnforcerRequest::Freeze { tag } => backend.freeze(&tag),
        EnforcerRequest::Destroy { tag } => backend.destroy_execution(&tag),
    }
}

fn freeze_all(backend: &mut NetnsNftBackend) {
    for tag in backend.live_tags() {
        if let Err(error) = backend.freeze(&tag) {
            eprintln!("soglia __enforcer: could not freeze {tag}: {error}");
        }
    }
}
