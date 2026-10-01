// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia __enforcer` role: lifecycle and bounded Resolve channels.
//!
//! The channel is the socketpair end the original trusted process handed over as this process's
//! standard input. The first frame is the configuration. The independent Resolve contract is read
//! and validated before the enforcer probes or mutates the host; only then does it sweep what a
//! previous run left behind, install the host policy and report ready. After that it answers
//! requests until the channel closes.
//!
//! When the channel closes the Supervisor is gone. The enforcer freezes every live Execution —
//! strictly more restrictive than what was there — and exits. Everything else is left to the next
//! start's sweep: network policy lives in the kernel, so nothing opens up in the meantime.

use std::collections::VecDeque;
use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use soglia_core::config::{Config, NetworkBackend};
use soglia_core::helper::{
    EnforcerRequest, Hello, HelperFailure, HelperResponse, RESOLVER_PROTOCOL_VERSION, RefusalClass,
    ResolveAttempt, ResolveResult, ResolverHello, ResolverReady, ResolverReply, ResolverRequest,
};
use soglia_core::ipc::{
    FrameError, MAX_RESOLVER_FRAME_BYTES, read_frame, read_frame_limited, write_frame,
    write_frame_limited,
};

#[cfg(feature = "cgroup-bpf")]
use crate::backend::CgroupBpfBackend;
use crate::backend::{
    BackendError, EnforcementBackend, NetnsNftBackend, NetworkSettings, ResolveBackend,
};

struct StartedBackend {
    backend: Box<dyn EnforcementBackend + Send>,
    resolve: Arc<dyn ResolveBackend>,
    swept: Vec<String>,
    resolver_contract: ResolverReady,
}

const RESOLVER_HELLO_TIMEOUT: Duration = Duration::from_secs(1);

/// Serves the enforcer role on `channel` until it closes.
pub fn run(channel: UnixStream, resolver_channel: UnixStream) -> Result<(), String> {
    run_with_start(channel, resolver_channel, RESOLVER_HELLO_TIMEOUT, start)
}

fn run_with_start<F>(
    channel: UnixStream,
    mut resolver_channel: UnixStream,
    resolver_hello_timeout: Duration,
    start_backend: F,
) -> Result<(), String>
where
    F: FnOnce(&Config, ResolverReady) -> Result<StartedBackend, HelperFailure>,
{
    let mut reader = channel
        .try_clone()
        .map_err(|error| format!("cannot use the helper channel: {error}"))?;
    let mut writer = channel;

    let hello: Hello = read_frame(&mut reader).map_err(|error| error.to_string())?;
    let config = match Config::from_yaml(&hello.config_yaml) {
        Ok(config) => config,
        Err(error) => {
            let failure = HelperFailure::Refused {
                class: RefusalClass::Incompatible,
                detail: format!("the Enforcer configuration is incompatible: {error}"),
            };
            let _ = write_frame(
                &mut writer,
                &HelperResponse::Failed {
                    failure: failure.clone(),
                },
            );
            return Err(failure.detail().to_owned());
        }
    };
    let resolver_contract = ResolverReady {
        version: RESOLVER_PROTOCOL_VERSION,
        max_pending_resolves: config.cgroup_bpf.max_pending_resolves,
        resolve_workers: config.cgroup_bpf.resolve_workers,
    };
    if let Err(failure) = validate_resolver_before_start(
        &mut resolver_channel,
        resolver_contract,
        resolver_hello_timeout,
    ) {
        write_frame(
            &mut writer,
            &HelperResponse::Failed {
                failure: failure.clone(),
            },
        )
        .map_err(|error| error.to_string())?;
        // The lifecycle peer now has the typed refusal that selects process status 20. Returning
        // success from this helper role avoids replacing it with an unrelated textual crash.
        return Ok(());
    }
    let started = match start_backend(&config, resolver_contract) {
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
    let backend = Arc::new(Mutex::new(started.backend));

    let resolver_shutdown = resolver_channel
        .try_clone()
        .map_err(|error| format!("cannot clone the Resolve channel: {error}"))?;
    start_resolver_service(resolver_channel, started.resolve, started.resolver_contract)?;
    // READY is last: the production generation, recovery and independent Resolve worker are live.
    write_frame(
        &mut writer,
        &HelperResponse::Ready {
            swept: started.swept,
        },
    )
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
    config: &Config,
    resolver_contract: ResolverReady,
) -> Result<StartedBackend, HelperFailure> {
    let selected_backend = config.network.backend;
    let mut backend: Box<dyn EnforcementBackend + Send> = match selected_backend {
        NetworkBackend::NetnsNft => {
            let settings = NetworkSettings::from_config(config).map_err(|error| {
                error.into_helper_failure("the netns-nft configuration is incompatible")
            })?;
            Box::new(NetnsNftBackend::new(settings))
        }
        NetworkBackend::CgroupBpf => production_cgroup_backend(config)?,
    };
    backend.probe_capabilities().map_err(|error| {
        startup_failure(
            error,
            &format!("the {} probe failed", backend.name()),
            selected_backend,
        )
    })?;
    let swept = backend.initialize().map_err(|error| {
        startup_failure(
            error,
            &format!("the {} backend could not start", backend.name()),
            selected_backend,
        )
    })?;
    let resolve = backend.resolve_view().map_err(|error| {
        startup_failure(error, "the Resolve view could not start", selected_backend)
    })?;
    Ok(StartedBackend {
        backend,
        resolve,
        swept,
        resolver_contract,
    })
}

fn validate_resolver_before_start(
    channel: &mut UnixStream,
    required: ResolverReady,
    timeout: Duration,
) -> Result<(), HelperFailure> {
    channel
        .set_read_timeout(Some(timeout))
        .map_err(|error| HelperFailure::Refused {
            class: RefusalClass::Infrastructure,
            detail: format!("the Resolve v2 handshake timeout could not be installed: {error}"),
        })?;
    let offered = read_frame_limited(channel, MAX_RESOLVER_FRAME_BYTES).map_err(|error| {
        HelperFailure::Refused {
            class: RefusalClass::Incompatible,
            detail: format!("the Resolve v2 handshake is incompatible: {error}"),
        }
    })?;
    channel
        .set_read_timeout(None)
        .map_err(|error| HelperFailure::Refused {
            class: RefusalClass::Infrastructure,
            detail: format!("the Resolve v2 handshake timeout could not be cleared: {error}"),
        })?;
    validate_resolver_contract(offered, required).map_err(|detail| HelperFailure::Refused {
        class: RefusalClass::Incompatible,
        detail,
    })
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

#[derive(Clone, Copy)]
struct ResolveJob {
    request_id: u64,
    tuple: soglia_core::helper::SocketTupleV4,
}

struct ResolveQueue {
    capacity: usize,
    jobs: Mutex<VecDeque<ResolveJob>>,
    available: Condvar,
}

impl ResolveQueue {
    fn try_push(&self, job: ResolveJob) -> Result<(), ResolveJob> {
        let Ok(mut jobs) = self.jobs.lock() else {
            return Err(job);
        };
        if jobs.len() >= self.capacity {
            return Err(job);
        }
        jobs.push_back(job);
        self.available.notify_one();
        Ok(())
    }

    fn pop(&self) -> ResolveJob {
        let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
        loop {
            if let Some(job) = jobs.pop_front() {
                return job;
            }
            jobs = self
                .available
                .wait(jobs)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
}

fn start_resolver_service(
    mut channel: UnixStream,
    backend: Arc<dyn ResolveBackend>,
    contract: ResolverReady,
) -> Result<(), String> {
    let capacity = usize::try_from(contract.max_pending_resolves).unwrap_or(usize::MAX);
    let mut jobs = VecDeque::new();
    jobs.try_reserve(capacity).map_err(|error| {
        format!("the bounded Resolve worker queue could not reserve {capacity} entries: {error}")
    })?;
    let queue = Arc::new(ResolveQueue {
        capacity,
        jobs: Mutex::new(jobs),
        available: Condvar::new(),
    });
    let (completed, replies) = sync_channel(capacity.max(1));
    let outstanding = Arc::new(AtomicUsize::new(0));
    let high_water = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let mut reader = channel
        .try_clone()
        .map_err(|error| format!("cannot clone the Resolve channel: {error}"))?;
    let mut writer = channel
        .try_clone()
        .map_err(|error| format!("cannot clone the Resolve response channel: {error}"))?;

    for worker in 0..contract.resolve_workers {
        let queue = Arc::clone(&queue);
        let backend = Arc::clone(&backend);
        let completed = completed.clone();
        let outstanding = Arc::clone(&outstanding);
        thread::Builder::new()
            .name(format!("soglia-resolve-worker-{worker}"))
            .spawn(move || resolve_worker(queue, backend, completed, outstanding))
            .map_err(|error| format!("Resolve worker {worker} could not start: {error}"))?;
    }
    thread::Builder::new()
        .name("soglia-resolve-replies".to_owned())
        .spawn(move || {
            while let Ok(reply) = replies.recv() {
                if write_frame_limited(&mut writer, &reply, MAX_RESOLVER_FRAME_BYTES).is_err() {
                    std::process::exit(1);
                }
            }
        })
        .map_err(|error| format!("Resolve response writer could not start: {error}"))?;
    thread::Builder::new()
        .name("soglia-resolve-requests".to_owned())
        .spawn(move || {
            let mut last_request_id = 0_u64;
            loop {
                let request: ResolverRequest =
                    match read_frame_limited(&mut reader, MAX_RESOLVER_FRAME_BYTES) {
                        Ok(request) => request,
                        Err(FrameError::Closed) => return,
                        Err(error) => {
                            eprintln!("soglia __enforcer: Resolve channel failed: {error}");
                            std::process::exit(1);
                        }
                    };
                let ResolverRequest::Resolve { request_id, tuple } = request;
                if !accept_request_id(&mut last_request_id, request_id) {
                    eprintln!(
                        "soglia __enforcer: duplicate or late Resolve request id {request_id}"
                    );
                    std::process::exit(1);
                }
                let job = ResolveJob { request_id, tuple };
                let admitted = outstanding
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                        (current < capacity).then_some(current + 1)
                    })
                    .is_ok();
                if admitted {
                    let active = outstanding.load(Ordering::Acquire);
                    let previous = high_water.fetch_max(active, Ordering::Relaxed);
                    if active > previous {
                        eprintln!(
                            "event.name=cgroup_bpf.resolve_worker_occupancy active={active} high_water={active} capacity={capacity} refused_total={}",
                            refused.load(Ordering::Relaxed)
                        );
                    }
                }
                if !admitted {
                    let refused_total = refused.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    eprintln!(
                        "event.name=cgroup_bpf.resolve_worker_queue_full capacity={capacity}"
                    );
                    eprintln!(
                        "event.name=cgroup_bpf.resolve_worker_occupancy active={} high_water={} capacity={capacity} refused_total={refused_total}",
                        outstanding.load(Ordering::Acquire),
                        high_water.load(Ordering::Relaxed)
                    );
                }
                if (!admitted || queue.try_push(job).is_err()) && {
                    if admitted {
                        outstanding.fetch_sub(1, Ordering::AcqRel);
                    }
                    completed
                        .send(ResolverReply {
                            request_id,
                            attempt: ResolveAttempt::QueueFull,
                        })
                        .is_err()
                } {
                    return;
                }
            }
        })
        .map_err(|error| format!("Resolve request reader could not start: {error}"))?;
    write_frame_limited(&mut channel, &contract, MAX_RESOLVER_FRAME_BYTES)
        .map_err(|error| format!("Resolve v2 acknowledgement failed: {error}"))?;
    eprintln!(
        "event.name=cgroup_bpf.resolve_protocol_ready version={} max_pending={} workers={}",
        contract.version, contract.max_pending_resolves, contract.resolve_workers
    );
    Ok(())
}

fn validate_resolver_contract(
    offered: ResolverHello,
    required: ResolverReady,
) -> Result<(), String> {
    if offered.version == required.version
        && offered.max_pending_resolves == required.max_pending_resolves
        && offered.resolve_workers == required.resolve_workers
    {
        Ok(())
    } else {
        Err(format!(
            "Resolve v2 contract mismatch: offered={offered:?} required={required:?}"
        ))
    }
}

fn resolve_worker(
    queue: Arc<ResolveQueue>,
    backend: Arc<dyn ResolveBackend>,
    completed: SyncSender<ResolverReply>,
    outstanding: Arc<AtomicUsize>,
) {
    loop {
        let job = queue.pop();
        let attempt = match execute_resolve(&*backend, job.tuple) {
            ResolveJobOutcome::Attempt(attempt) => attempt,
            ResolveJobOutcome::Panicked => {
                eprintln!("soglia __enforcer: Resolve worker panicked");
                std::process::exit(1);
            }
        };
        let sent = completed
            .send(ResolverReply {
                request_id: job.request_id,
                attempt,
            })
            .is_ok();
        outstanding.fetch_sub(1, Ordering::AcqRel);
        if !sent {
            return;
        }
    }
}

enum ResolveJobOutcome {
    Attempt(ResolveAttempt),
    Panicked,
}

fn execute_resolve(
    backend: &dyn ResolveBackend,
    tuple: soglia_core::helper::SocketTupleV4,
) -> ResolveJobOutcome {
    match catch_unwind(AssertUnwindSafe(|| backend.resolve_once(tuple))) {
        Ok(Ok(attempt)) => ResolveJobOutcome::Attempt(attempt),
        Ok(Err(error)) => {
            eprintln!("soglia __enforcer: Resolve integrity failure: {error}");
            ResolveJobOutcome::Attempt(ResolveAttempt::Complete {
                result: ResolveResult::IntegrityFailure,
            })
        }
        Err(_) => ResolveJobOutcome::Panicked,
    }
}

fn accept_request_id(last: &mut u64, request_id: u64) -> bool {
    if request_id == 0 || request_id <= *last {
        return false;
    }
    *last = request_id;
    true
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
        .map_err(|error| {
            startup_failure(
                error,
                "the cgroup-bpf configuration is incompatible",
                NetworkBackend::CgroupBpf,
            )
        })
}

fn startup_failure(
    error: BackendError,
    context: &str,
    selected_backend: NetworkBackend,
) -> HelperFailure {
    let failure = error.into_helper_failure(context);
    match failure {
        HelperFailure::Refused {
            class: RefusalClass::Unsupported,
            mut detail,
        } if selected_backend == NetworkBackend::CgroupBpf => {
            detail.push_str(
                "; to request the compatibility backend explicitly, set network.backend: netns-nft and restart",
            );
            HelperFailure::Refused {
                class: RefusalClass::Unsupported,
                detail,
            }
        }
        failure => failure,
    }
}

#[cfg(not(feature = "cgroup-bpf"))]
fn production_cgroup_backend(
    _config: &Config,
) -> Result<Box<dyn EnforcementBackend + Send>, HelperFailure> {
    Err(HelperFailure::Refused {
        class: RefusalClass::Unsupported,
        detail: "cgroup-bpf was selected but this binary was built without the `cgroup-bpf` feature; set network.backend: netns-nft explicitly and restart"
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use soglia_core::config::NetworkBackend;
    use soglia_core::helper::{
        Hello, HelperFailure, HelperResponse, RESOLVER_PROTOCOL_VERSION, RefusalClass,
        ResolveAttempt, ResolveResult, ResolverHello, ResolverReady, SocketTupleV4,
    };
    use soglia_core::ipc::{
        MAX_RESOLVER_FRAME_BYTES, read_frame, write_frame, write_frame_limited,
    };

    use super::{
        ResolveJob, ResolveJobOutcome, ResolveQueue, accept_request_id, execute_resolve,
        run_with_start, startup_failure, validate_resolver_contract,
    };
    use crate::backend::{BackendError, ResolveBackend};

    struct Panics;

    impl ResolveBackend for Panics {
        fn resolve_once(&self, _: SocketTupleV4) -> Result<ResolveAttempt, BackendError> {
            panic!("injected worker panic")
        }
    }

    fn tuple() -> SocketTupleV4 {
        SocketTupleV4 {
            source_address: [10, 0, 0, 2],
            destination_address: [10, 0, 0, 1],
            source_port: 40_000,
            destination_port: 15_001,
        }
    }

    fn config_yaml() -> String {
        r#"
runtime:
  uid: 990
  gid: 990
agents:
  probe:
    rootfs: /var/lib/soglia/rootfs/probe
    command: ["/agent"]
"#
        .to_owned()
    }

    fn assert_pre_start_incompatible(
        send_resolver_hello: impl FnOnce(&mut UnixStream),
        timeout: Duration,
    ) {
        let (mut lifecycle_client, lifecycle_server) = UnixStream::pair().unwrap();
        let (mut resolver_client, resolver_server) = UnixStream::pair().unwrap();
        let mutation_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&mutation_called);
        let helper = std::thread::spawn(move || {
            run_with_start(lifecycle_server, resolver_server, timeout, move |_, _| {
                called.store(true, Ordering::Release);
                panic!("the backend must not start after an incompatible Resolve contract")
            })
        });

        write_frame(
            &mut lifecycle_client,
            &Hello {
                config_yaml: config_yaml(),
            },
        )
        .unwrap();
        send_resolver_hello(&mut resolver_client);

        let response: HelperResponse = read_frame(&mut lifecycle_client).unwrap();
        let HelperResponse::Failed { failure } = response else {
            panic!("the pre-start refusal was not carried on the lifecycle channel")
        };
        assert!(matches!(
            failure,
            HelperFailure::Refused {
                class: RefusalClass::Incompatible,
                ..
            }
        ));
        assert_eq!(failure.exit_code(), 20);
        assert!(!mutation_called.load(Ordering::Acquire));
        assert!(helper.join().unwrap().is_ok());
    }

    #[test]
    fn only_cgroup_bpf_startup_unsupported_names_the_compatibility_backend() {
        let cgroup = startup_failure(
            BackendError::Unsupported("kernel capability is absent".to_owned()),
            "probe failed",
            NetworkBackend::CgroupBpf,
        );
        let netns = startup_failure(
            BackendError::Unsupported("kernel capability is absent".to_owned()),
            "probe failed",
            NetworkBackend::NetnsNft,
        );
        assert!(matches!(
            cgroup,
            HelperFailure::Refused {
                class: RefusalClass::Unsupported,
                detail,
            } if detail.contains("network.backend: netns-nft")
        ));
        assert!(matches!(
            netns,
            HelperFailure::Refused {
                class: RefusalClass::Unsupported,
                detail,
            } if !detail.contains("network.backend: netns-nft")
        ));
    }

    #[test]
    fn uninstall_refusals_remain_typed_and_never_name_a_backend_choice() {
        for (error, expected) in [
            (
                BackendError::Incompatible("schema".to_owned()),
                RefusalClass::Incompatible,
            ),
            (
                BackendError::Unknown("ownership".to_owned()),
                RefusalClass::Unknown,
            ),
            (
                BackendError::Unsupported("kernel".to_owned()),
                RefusalClass::Unsupported,
            ),
            (
                BackendError::Failed("host".to_owned()),
                RefusalClass::Infrastructure,
            ),
        ] {
            assert!(matches!(
                error.into_helper_failure("uninstall"),
                HelperFailure::Refused { class, detail }
                    if class == expected && !detail.contains("network.backend: netns-nft")
            ));
        }
    }

    #[test]
    fn duplicate_zero_and_late_request_ids_are_protocol_failures() {
        let mut last = 0;
        assert!(accept_request_id(&mut last, 1));
        assert!(accept_request_id(&mut last, 9));
        assert!(!accept_request_id(&mut last, 9));
        assert!(!accept_request_id(&mut last, 8));
        let mut fresh = 0;
        assert!(!accept_request_id(&mut fresh, 0));
    }

    #[test]
    fn resolver_v2_has_no_implicit_v1_or_capacity_fallback() {
        let required = ResolverReady {
            version: RESOLVER_PROTOCOL_VERSION,
            max_pending_resolves: 64,
            resolve_workers: 4,
        };
        assert!(
            validate_resolver_contract(
                ResolverHello {
                    version: 1,
                    max_pending_resolves: 64,
                    resolve_workers: 4,
                },
                required,
            )
            .is_err()
        );
        assert!(
            validate_resolver_contract(
                ResolverHello {
                    version: RESOLVER_PROTOCOL_VERSION,
                    max_pending_resolves: 65,
                    resolve_workers: 4,
                },
                required,
            )
            .is_err()
        );
    }

    #[test]
    fn a_wrong_resolver_version_is_typed_before_backend_start() {
        assert_pre_start_incompatible(
            |channel| {
                write_frame_limited(
                    channel,
                    &ResolverHello {
                        version: RESOLVER_PROTOCOL_VERSION - 1,
                        max_pending_resolves: 64,
                        resolve_workers: 4,
                    },
                    MAX_RESOLVER_FRAME_BYTES,
                )
                .unwrap();
            },
            Duration::from_secs(1),
        );
    }

    #[test]
    fn a_wrong_pending_limit_is_typed_before_backend_start() {
        assert_pre_start_incompatible(
            |channel| {
                write_frame_limited(
                    channel,
                    &ResolverHello {
                        version: RESOLVER_PROTOCOL_VERSION,
                        max_pending_resolves: 65,
                        resolve_workers: 4,
                    },
                    MAX_RESOLVER_FRAME_BYTES,
                )
                .unwrap();
            },
            Duration::from_secs(1),
        );
    }

    #[test]
    fn a_wrong_worker_limit_is_typed_before_backend_start() {
        assert_pre_start_incompatible(
            |channel| {
                write_frame_limited(
                    channel,
                    &ResolverHello {
                        version: RESOLVER_PROTOCOL_VERSION,
                        max_pending_resolves: 64,
                        resolve_workers: 3,
                    },
                    MAX_RESOLVER_FRAME_BYTES,
                )
                .unwrap();
            },
            Duration::from_secs(1),
        );
    }

    #[test]
    fn a_malformed_resolver_hello_is_typed_before_backend_start() {
        assert_pre_start_incompatible(
            |channel| {
                let body = b"{}";
                channel
                    .write_all(&(body.len() as u32).to_be_bytes())
                    .unwrap();
                channel.write_all(body).unwrap();
                channel.flush().unwrap();
            },
            Duration::from_secs(1),
        );
    }

    #[test]
    fn an_absent_resolver_hello_times_out_before_backend_start() {
        assert_pre_start_incompatible(|_| {}, Duration::from_millis(20));
    }

    #[test]
    fn the_worker_queue_has_an_exact_bound() {
        let queue = ResolveQueue {
            capacity: 1,
            jobs: Mutex::new(VecDeque::new()),
            available: Condvar::new(),
        };
        assert!(
            queue
                .try_push(ResolveJob {
                    request_id: 1,
                    tuple: tuple(),
                })
                .is_ok()
        );
        assert!(
            queue
                .try_push(ResolveJob {
                    request_id: 2,
                    tuple: tuple(),
                })
                .is_err()
        );
    }

    #[test]
    fn a_worker_panic_is_not_converted_to_a_consumable_answer() {
        assert!(matches!(
            execute_resolve(&Panics, tuple()),
            ResolveJobOutcome::Panicked
        ));
    }

    #[test]
    fn a_backend_error_is_an_integrity_failure_not_a_panic() {
        struct Fails;
        impl ResolveBackend for Fails {
            fn resolve_once(&self, _: SocketTupleV4) -> Result<ResolveAttempt, BackendError> {
                Err(BackendError::Failed("injected".to_owned()))
            }
        }
        assert!(matches!(
            execute_resolve(&Fails, tuple()),
            ResolveJobOutcome::Attempt(ResolveAttempt::Complete {
                result: ResolveResult::IntegrityFailure
            })
        ));
    }
}
