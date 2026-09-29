// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia __enforcer` role: lifecycle and bounded Resolve channels.
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
use std::sync::{Arc, Mutex, TryLockError};
use std::thread;

use soglia_core::config::{Config, NetworkBackend};
use soglia_core::helper::{
    EnforcerRequest, Hello, HelperFailure, HelperResponse, RefusalClass, ResolveAttempt,
    ResolvePending, ResolveResult, ResolverReply, ResolverRequest,
};
use soglia_core::ipc::{FrameError, read_frame, write_frame};

#[cfg(feature = "cgroup-bpf")]
use crate::backend::CgroupBpfBackend;
use crate::backend::{BackendError, EnforcementBackend, NetnsNftBackend, NetworkSettings};

/// Serves the enforcer role on `channel` until it closes.
pub fn run(channel: UnixStream, resolver_channel: UnixStream) -> Result<(), String> {
    let mut reader = channel
        .try_clone()
        .map_err(|error| format!("cannot use the helper channel: {error}"))?;
    let mut writer = channel;

    let hello: Hello = read_frame(&mut reader).map_err(|error| error.to_string())?;
    let (backend, swept) = match start(&hello) {
        Ok(started) => started,
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
    let backend = Arc::new(Mutex::new(backend));

    let resolver_shutdown = resolver_channel
        .try_clone()
        .map_err(|error| format!("cannot clone the Resolve channel: {error}"))?;
    let resolver_backend = Arc::clone(&backend);
    let (resolver_ready, resolver_started) = std::sync::mpsc::sync_channel(0);
    thread::spawn(move || {
        if resolver_ready.send(()).is_ok() {
            resolve_loop(resolver_backend, resolver_channel);
        }
    });
    resolver_started
        .recv()
        .map_err(|_| "the Resolve worker did not start".to_owned())?;
    // READY is last: the production generation, recovery and independent Resolve worker are live.
    write_frame(&mut writer, &HelperResponse::Ready { swept })
        .map_err(|error| error.to_string())?;

    loop {
        let request: EnforcerRequest = match read_frame(&mut reader) {
            Ok(request) => request,
            Err(FrameError::Closed) => {
                freeze_all(&backend);
                let _ = resolver_shutdown.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
            Err(error) => {
                // A malformed or unexpected frame ends the conversation: the channel is no longer
                // one this helper can trust to mean what it says.
                freeze_all(&backend);
                let _ = resolver_shutdown.shutdown(std::net::Shutdown::Both);
                return Err(error.to_string());
            }
        };
        let response = match backend.lock() {
            Ok(mut backend) => match serve(&mut **backend, request) {
                Ok(response) => response,
                Err(error) => HelperResponse::Failed {
                    failure: error.into_helper_failure("the Enforcer request failed"),
                },
            },
            Err(_) => HelperResponse::Failed {
                failure: HelperFailure::Refused {
                    class: RefusalClass::Infrastructure,
                    detail: "the Enforcer backend lock is poisoned".to_owned(),
                },
            },
        };
        if let Err(error) = write_frame(&mut writer, &response) {
            freeze_all(&backend);
            let _ = resolver_shutdown.shutdown(std::net::Shutdown::Both);
            return Err(error.to_string());
        }
    }
}

fn start(
    hello: &Hello,
) -> Result<(Box<dyn EnforcementBackend + Send>, Vec<String>), HelperFailure> {
    let config = Config::from_yaml(&hello.config_yaml).map_err(|error| HelperFailure::Refused {
        class: RefusalClass::Incompatible,
        detail: format!("the Enforcer configuration is incompatible: {error}"),
    })?;
    let mut backend: Box<dyn EnforcementBackend + Send> = match config.network.backend {
        NetworkBackend::NetnsNft => {
            let settings = NetworkSettings::from_config(&config).map_err(|error| {
                error.into_helper_failure("the netns-nft configuration is incompatible")
            })?;
            Box::new(NetnsNftBackend::new(settings))
        }
        NetworkBackend::CgroupBpf => production_cgroup_backend(&config)?,
    };
    backend.probe_capabilities().map_err(|error| {
        error.into_helper_failure(&format!("the {} probe failed", backend.name()))
    })?;
    let swept = backend.initialize().map_err(|error| {
        error.into_helper_failure(&format!("the {} backend could not start", backend.name()))
    })?;

    Ok((backend, swept))
}

fn serve(
    backend: &mut dyn EnforcementBackend,
    request: EnforcerRequest,
) -> Result<HelperResponse, BackendError> {
    match request {
        EnforcerRequest::Health => backend.health_check().map(|()| HelperResponse::Done),
        EnforcerRequest::Prepare {
            id,
            slot,
            agent,
            nonce,
        } => backend
            .prepare_execution(id, slot, &agent, nonce)
            .map(|()| HelperResponse::Done),
        EnforcerRequest::VerifyPlacement { id, pid } => {
            backend
                .verify_placement(id, pid)
                .map(|binding| match binding {
                    Some(binding) => HelperResponse::PlacementVerified { binding },
                    None => HelperResponse::Done,
                })
        }
        EnforcerRequest::Activate { id, binding } => backend
            .activate_execution(id, binding)
            .map(|()| HelperResponse::Done),
        EnforcerRequest::Freeze { tag } => backend.freeze(&tag).map(|()| HelperResponse::Done),
        EnforcerRequest::Destroy { tag } => backend
            .destroy_execution(&tag)
            .map(|()| HelperResponse::Done),
    }
}

fn resolve_loop(backend: Arc<Mutex<Box<dyn EnforcementBackend + Send>>>, channel: UnixStream) {
    let Ok(mut reader) = channel.try_clone() else {
        std::process::exit(1);
    };
    let mut writer = channel;
    loop {
        let request: ResolverRequest = match read_frame(&mut reader) {
            Ok(request) => request,
            Err(FrameError::Closed) => return,
            Err(error) => {
                eprintln!("soglia __enforcer: Resolve channel failed: {error}");
                std::process::exit(1);
            }
        };
        let ResolverRequest::Resolve { request_id, tuple } = request;
        let attempt = match backend.try_lock() {
            Ok(mut backend) => backend.resolve_once(tuple).unwrap_or_else(|error| {
                eprintln!("soglia __enforcer: Resolve integrity failure: {error}");
                ResolveAttempt::Complete {
                    result: ResolveResult::IntegrityFailure,
                }
            }),
            Err(TryLockError::WouldBlock) => ResolveAttempt::Pending {
                reason: ResolvePending::BackendBusy,
            },
            Err(TryLockError::Poisoned(_)) => {
                eprintln!("soglia __enforcer: Resolve backend lock is poisoned");
                ResolveAttempt::Complete {
                    result: ResolveResult::IntegrityFailure,
                }
            }
        };
        let response = ResolverReply {
            request_id,
            attempt,
        };
        if let Err(error) = write_frame(&mut writer, &response) {
            eprintln!("soglia __enforcer: Resolve response failed: {error}");
            std::process::exit(1);
        }
    }
}

fn freeze_all(backend: &Arc<Mutex<Box<dyn EnforcementBackend + Send>>>) {
    let Ok(mut backend) = backend.lock() else {
        return;
    };
    for tag in backend.live_tags() {
        if let Err(error) = backend.freeze(&tag) {
            eprintln!("soglia __enforcer: could not freeze {tag}: {error}");
        }
    }
}

#[cfg(feature = "cgroup-bpf")]
fn production_cgroup_backend(
    config: &Config,
) -> Result<Box<dyn EnforcementBackend + Send>, HelperFailure> {
    CgroupBpfBackend::from_config(config)
        .map(|backend| Box::new(backend) as Box<dyn EnforcementBackend + Send>)
        .map_err(|error| error.into_helper_failure("the cgroup-bpf configuration is incompatible"))
}

#[cfg(not(feature = "cgroup-bpf"))]
fn production_cgroup_backend(
    _config: &Config,
) -> Result<Box<dyn EnforcementBackend + Send>, HelperFailure> {
    Err(HelperFailure::Refused {
        class: RefusalClass::Unsupported,
        detail:
            "cgroup-bpf was selected but this binary was built without the `cgroup-bpf` feature"
                .to_owned(),
    })
}
