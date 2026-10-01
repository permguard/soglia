// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia` executable.
//!
//! One binary, several roles. `soglia run` is the runtime an operator starts; the double-underscore
//! commands are the privileged helper roles the runtime enters by re-executing itself, and are hidden
//! from `--help` because nobody is meant to type them.
//!
//! This is the composition root: the only place that picks concrete implementations.

#![forbid(unsafe_code)]

// Soglia's isolation and enforcement are built from Linux namespaces, cgroups, nftables and runc.
// There is nothing to build for another system: on macOS or Windows, build this in the development
// container (`.devcontainer/` or `dev/linux/run.sh`); only `soglia-core` and `soglia-proxy` build natively.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "this crate builds and runs only on Linux; on macOS or Windows use the development container (.devcontainer/ or dev/linux/run.sh)"
);

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use soglia_core::DeferredComponent;
use soglia_core::helper::{HelperFailure, RefusalClass};

#[derive(Debug)]
enum ProcessError {
    Generic(String),
    StartupRefused {
        context: String,
        failure: HelperFailure,
    },
}

impl ProcessError {
    fn refused(class: RefusalClass, detail: impl Into<String>) -> Self {
        Self::StartupRefused {
            context: "startup refused".to_owned(),
            failure: HelperFailure::Refused {
                class,
                detail: detail.into(),
            },
        }
    }

    fn from_helper(
        context: impl Into<String>,
        error: soglia_supervisor::helpers::HelperError,
    ) -> Self {
        match error {
            soglia_supervisor::helpers::HelperError::Failed(failure) => Self::StartupRefused {
                context: context.into(),
                failure,
            },
            other => Self::Generic(format!("{}: {other}", context.into())),
        }
    }

    const fn exit_code(&self) -> u8 {
        match self {
            Self::Generic(_) => 1,
            Self::StartupRefused { failure, .. } => failure.exit_code(),
        }
    }
}

impl From<String> for ProcessError {
    fn from(reason: String) -> Self {
        Self::Generic(reason)
    }
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generic(reason) => formatter.write_str(reason),
            Self::StartupRefused { context, failure } => {
                write!(formatter, "{context}: {}", failure.detail())
            }
        }
    }
}

#[derive(Parser)]
#[command(
    name = "soglia",
    version,
    about = "Soglia Runtime: trusted execution for AI agents."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the runtime with the given configuration.
    Run {
        /// The configuration file.
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: PathBuf,
    },
    /// Remove only Soglia resources whose ownership can be proved from durable state.
    Uninstall {
        /// Validate and print the exact plan without changing host state.
        #[arg(long)]
        dry_run: bool,
        /// The configuration file used by the installation.
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        file: PathBuf,
    },
    /// The privileged sandbox role, entered by `soglia run`.
    #[command(name = "__sandboxd", hide = true)]
    Sandboxd,
    /// The privileged network-enforcement role, entered by `soglia run`.
    #[command(name = "__enforcer", hide = true)]
    Enforcer,
    /// The CA signing role. Not started in Phase 0.
    #[command(name = "__ca-signer", hide = true)]
    CaSigner,
}

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Run { file } => runtime::run(&file),
        Command::Uninstall { dry_run, file } => runtime::uninstall(&file, dry_run),
        Command::Sandboxd => runtime::sandboxd().map_err(ProcessError::from),
        Command::Enforcer => runtime::enforcer().map_err(ProcessError::from),
        Command::CaSigner => DeferredComponent::CaSigner
            .activate()
            .map_err(|refused| ProcessError::from(refused.to_string())),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let ProcessError::StartupRefused { context, failure } = &error {
                let (hook, errno) = match failure {
                    HelperFailure::Refused { .. } => (None, None),
                    HelperFailure::IncompatibleBpfTopology { hook, errno, .. } => {
                        (Some(hook.as_str()), *errno)
                    }
                };
                if context == "uninstall refused" {
                    tracing::error!(
                        event.name = "uninstall.refused",
                        refusal.class = failure.event_class(),
                        refusal.hook = hook,
                        refusal.errno = errno,
                        "Soglia refused uninstall"
                    );
                } else {
                    tracing::error!(
                        event.name = "startup.refused",
                        refusal.class = failure.event_class(),
                        refusal.hook = hook,
                        refusal.errno = errno,
                        "Soglia refused startup"
                    );
                }
            }
            eprintln!("soglia: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

mod runtime {
    use std::fs;
    use std::net::{IpAddr, SocketAddr};
    #[cfg(feature = "cgroup-bpf")]
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::sync::Arc;
    use std::time::Duration;

    use soglia_core::Config;
    use soglia_core::config::NetworkBackend;
    use soglia_core::helper::{HelperFailure, RefusalClass};
    use soglia_proxy::attribution::{AttributionTable, ConnectionAttributor};
    use soglia_proxy::egress::{EgressLimits, EgressProxy};
    use soglia_proxy::ingress::{self, Executor, IngressLimits};
    use soglia_proxy::policy::DestinationPolicy;
    use soglia_proxy::resolver::SystemResolver;
    use soglia_supervisor::Supervisor;
    use soglia_supervisor::helpers::{CandidateAAttributor, Helper, ResolveHealthFailure};
    use soglia_supervisor::privilege;
    use tokio::net::TcpListener;
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::sync::watch;
    use tracing::{error, info};

    use crate::ProcessError;

    fn read_config(file: &Path) -> Result<(String, Config), ProcessError> {
        let text = fs::read_to_string(file).map_err(|error| {
            ProcessError::refused(
                RefusalClass::Infrastructure,
                format!("cannot read {}: {error}", file.display()),
            )
        })?;
        let config = Config::from_yaml(&text).map_err(|error| {
            ProcessError::refused(RefusalClass::Incompatible, error.to_string())
        })?;
        Ok((text, config))
    }

    /// `soglia run -f <file>`.
    pub fn run(file: &Path) -> Result<(), ProcessError> {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_target(false)
            .init();

        let (text, config) = read_config(file)?;
        let policy =
            DestinationPolicy::new(&config.egress, &config.network, control_addresses(&config))
                .map_err(|error| {
                    ProcessError::refused(RefusalClass::Incompatible, error.to_string())
                })?;
        if !rustix::process::geteuid().is_root() {
            return Err(ProcessError::refused(
                RefusalClass::Unsupported,
                "soglia run starts as root: its helpers need privileges the runtime then drops"
                    .to_owned(),
            ));
        }

        // Soglia's own state directory, and the lock that makes it one instance per directory.
        let state = &config.runtime.state_dir;
        fs::create_dir_all(state).map_err(|error| format!("{}: {error}", state.display()))?;
        fs::set_permissions(state, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("{}: {error}", state.display()))?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(state.join("lock"))
            .map_err(|error| format!("cannot open the instance lock: {error}"))?;
        lock.try_lock()
            .map_err(|_| format!("another soglia is already running on {}", state.display()))?;

        // The helpers start while the process is still root; each gets one end of its own channel.
        let executable = PathBuf::from("/proc/self/exe");
        let sandbox = Helper::spawn(&executable, "sandboxd")
            .map_err(|error| format!("cannot start the sandbox helper: {error}"))?;
        let enforcer = Helper::spawn_enforcer(&executable)
            .map_err(|error| format!("cannot start the enforcer: {error}"))?;
        // Processes are killed before their network is removed, at startup as at teardown.
        for helper in [&sandbox, &enforcer] {
            let swept = helper.hello(&text).map_err(|error| {
                ProcessError::from_helper(format!("the {} did not start", helper.role()), error)
            })?;
            for resource in swept {
                info!(event.name = "startup.swept", helper = helper.role(), resource = %resource, "a resource left by a previous run was removed");
            }
        }
        for helper in [&sandbox, &enforcer] {
            helper.ensure_running().map_err(|error| {
                ProcessError::from_helper(
                    format!("the {} failed the readiness barrier", helper.role()),
                    error,
                )
            })?;
        }

        privilege::drop_to(config.runtime.uid, config.runtime.gid)
            .map_err(|error| format!("cannot drop privileges: {error}"))?;
        enforcer.start_resolver_pipeline().map_err(|error| {
            ProcessError::from_helper(
                "the Enforcer Resolve pipeline did not start after privilege drop".to_owned(),
                error,
            )
        })?;
        info!(
            event.name = "startup.privileges_dropped",
            uid = config.runtime.uid,
            gid = config.runtime.gid,
            "privileges dropped"
        );

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("cannot start the async runtime: {error}"))?;
        let result = runtime.block_on(serve(config, policy, sandbox, enforcer));
        drop(lock);

        result.map_err(ProcessError::from)
    }

    /// `soglia uninstall -f <file>`.
    #[cfg(feature = "cgroup-bpf")]
    pub fn uninstall(file: &Path, dry_run: bool) -> Result<(), ProcessError> {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_target(false)
            .init();
        let (_, config) = read_config(file)?;
        if !rustix::process::geteuid().is_root() {
            return Err(ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure: HelperFailure::Refused {
                    class: RefusalClass::Unsupported,
                    detail: "soglia uninstall must run as root".to_owned(),
                },
            });
        }
        if config.network.backend != NetworkBackend::CgroupBpf {
            return Err(ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure: HelperFailure::Refused {
                    class: RefusalClass::Unsupported,
                    detail: "verified uninstall currently requires network.backend: cgroup-bpf"
                        .to_owned(),
                },
            });
        }

        let state = &config.runtime.state_dir;
        if state.exists() {
            let metadata =
                fs::symlink_metadata(state).map_err(|error| ProcessError::StartupRefused {
                    context: "uninstall refused".to_owned(),
                    failure: HelperFailure::Refused {
                        class: RefusalClass::Infrastructure,
                        detail: format!("cannot inspect {}: {error}", state.display()),
                    },
                })?;
            if !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(ProcessError::StartupRefused {
                    context: "uninstall refused".to_owned(),
                    failure: HelperFailure::Refused {
                        class: RefusalClass::Unknown,
                        detail: format!(
                            "{} is not a root-owned real mode-0700 directory",
                            state.display()
                        ),
                    },
                });
            }
        }
        let lock = if state.exists() && state.join("lock").exists() {
            let lock_path = state.join("lock");
            let metadata =
                fs::symlink_metadata(&lock_path).map_err(|error| ProcessError::StartupRefused {
                    context: "uninstall refused".to_owned(),
                    failure: HelperFailure::Refused {
                        class: RefusalClass::Infrastructure,
                        detail: format!("cannot inspect {}: {error}", lock_path.display()),
                    },
                })?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
            {
                return Err(ProcessError::StartupRefused {
                    context: "uninstall refused".to_owned(),
                    failure: HelperFailure::Refused {
                        class: RefusalClass::Unknown,
                        detail: "the runtime lock identity is not trusted".to_owned(),
                    },
                });
            }
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(|error| ProcessError::StartupRefused {
                    context: "uninstall refused".to_owned(),
                    failure: HelperFailure::Refused {
                        class: RefusalClass::Unknown,
                        detail: format!(
                            "the runtime state exists but its exact lock cannot be opened: {error}"
                        ),
                    },
                })?;
            lock.try_lock().map_err(|_| ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure: HelperFailure::Refused {
                    class: RefusalClass::Infrastructure,
                    detail: format!("the Soglia runtime is still active on {}", state.display()),
                },
            })?;
            Some(lock)
        } else if state.exists() {
            let mut entries =
                fs::read_dir(state).map_err(|error| ProcessError::StartupRefused {
                    context: "uninstall refused".to_owned(),
                    failure: HelperFailure::Refused {
                        class: RefusalClass::Infrastructure,
                        detail: format!("cannot inspect the runtime state root: {error}"),
                    },
                })?;
            if entries.next().is_some() {
                return Err(ProcessError::StartupRefused {
                    context: "uninstall refused".to_owned(),
                    failure: HelperFailure::Refused {
                        class: RefusalClass::Unknown,
                        detail: "the runtime state exists without its exact lock".to_owned(),
                    },
                });
            }
            None
        } else {
            None
        };

        let sandbox = soglia_sandbox::backend::prepare_uninstall(&config).map_err(|error| {
            let failure = match error {
                soglia_sandbox::backend::SandboxError::UninstallRefused { class, reason } => {
                    HelperFailure::Refused {
                        class,
                        detail: reason,
                    }
                }
                soglia_sandbox::backend::SandboxError::Refused(reason) => HelperFailure::Refused {
                    class: RefusalClass::Incompatible,
                    detail: reason,
                },
                soglia_sandbox::backend::SandboxError::Failed(reason) => HelperFailure::Refused {
                    class: RefusalClass::Infrastructure,
                    detail: reason,
                },
            };
            ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure,
            }
        })?;

        let enforcer = soglia_enforcer::cgroup_bpf::CgroupBpfBackend::prepare_uninstall(
            &config,
            &sandbox.owned_tags(),
            sandbox.is_fresh(),
        )
        .map_err(|error| ProcessError::StartupRefused {
            context: "uninstall refused".to_owned(),
            failure: error.into_helper_failure("verified uninstall refused"),
        })?;
        let sandbox_operations = sandbox.planned_operations();
        if dry_run {
            let report = enforcer.dry_run_report();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": 1,
                    "verdict": "PASS",
                    "dry_run": true,
                    "sandbox_operations": sandbox_operations,
                    "enforcer": report,
                }))
                .map_err(|error| error.to_string())?
            );
            drop(lock);
            return Ok(());
        }

        let report = enforcer
            .execute()
            .map_err(|error| ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure: error.into_helper_failure("verified uninstall was interrupted"),
            })?;
        sandbox
            .execute()
            .map_err(|error| ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure: HelperFailure::Refused {
                    class: RefusalClass::Infrastructure,
                    detail: format!("sandbox uninstall was interrupted: {error}"),
                },
            })?;

        if state.exists() {
            if state.join("lock").exists() {
                fs::remove_file(state.join("lock")).map_err(|error| {
                    ProcessError::StartupRefused {
                        context: "uninstall refused".to_owned(),
                        failure: HelperFailure::Refused {
                            class: RefusalClass::Infrastructure,
                            detail: format!("remove the exact runtime lock: {error}"),
                        },
                    }
                })?;
            }
            fs::remove_dir(state).map_err(|error| ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure: HelperFailure::Refused {
                    class: RefusalClass::Infrastructure,
                    detail: format!("remove the empty runtime state root: {error}"),
                },
            })?;
        }
        if state.exists() {
            return Err(ProcessError::StartupRefused {
                context: "uninstall refused".to_owned(),
                failure: HelperFailure::Refused {
                    class: RefusalClass::Infrastructure,
                    detail: "the runtime state root survived verified uninstall".to_owned(),
                },
            });
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": 1,
                "verdict": "PASS",
                "dry_run": false,
                "sandbox_operations": sandbox_operations,
                "enforcer": report,
            }))
            .map_err(|error| error.to_string())?
        );
        drop(lock);
        Ok(())
    }

    /// A build without cgroup-BPF cannot prove or remove Candidate-A objects.
    #[cfg(not(feature = "cgroup-bpf"))]
    pub fn uninstall(_file: &Path, _dry_run: bool) -> Result<(), ProcessError> {
        Err(ProcessError::StartupRefused {
            context: "uninstall refused".to_owned(),
            failure: HelperFailure::Refused {
                class: RefusalClass::Unsupported,
                detail: "this binary was built without cgroup-bpf uninstall support".to_owned(),
            },
        })
    }

    async fn serve(
        config: Config,
        policy: DestinationPolicy,
        sandbox: Helper,
        enforcer: Helper,
    ) -> Result<(), String> {
        let config = Arc::new(config);
        let pool = config.pool().map_err(|error| error.to_string())?;
        let attribution_capacity = config
            .runtime
            .max_concurrency
            .checked_add(config.runtime.cleanup_failure_threshold)
            .ok_or_else(|| "the attribution table capacity overflowed".to_owned())?;
        let attribution = Arc::new(AttributionTable::with_capacity(
            usize::try_from(attribution_capacity).unwrap_or(usize::MAX),
        ));
        let resolver_client =
            if config.network.backend == NetworkBackend::CgroupBpf {
                Some(enforcer.resolver_client().map_err(|error| {
                    format!("the Enforcer Resolve channel is unavailable: {error}")
                })?)
            } else {
                None
            };
        let (fatal, mut lost) = watch::channel(false);
        let (stop, stopped) = watch::channel(false);
        let mut sandbox_exit = sandbox.watch_exit();
        let mut enforcer_exit = enforcer.watch_exit();
        let supervisor = Supervisor::new(
            Arc::clone(&config),
            pool,
            sandbox,
            enforcer,
            Arc::clone(&attribution),
            fatal,
            stop.clone(),
        );
        let connection_attribution: Arc<dyn ConnectionAttributor> = match resolver_client {
            Some(resolver) => {
                let observed = supervisor.clone();
                Arc::new(CandidateAAttributor::new(
                    resolver,
                    Arc::clone(&attribution),
                    Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
                    usize::try_from(config.cgroup_bpf.max_pending_resolves).unwrap_or(usize::MAX),
                    Arc::new(move |failure| match failure {
                        ResolveHealthFailure::Unavailable => observed.helper_exited(
                            "enforcer-resolve",
                            "the authenticated Resolve channel is unavailable",
                        ),
                        ResolveHealthFailure::IntegrityFailure => observed.helper_exited(
                            "enforcer-resolve-integrity",
                            "owned Candidate-A state failed integrity validation",
                        ),
                    }),
                ))
            }
            None => Arc::clone(&attribution) as Arc<dyn ConnectionAttributor>,
        };
        let _enforcer_health =
            supervisor.watch_enforcer_health(Duration::from_secs(1), stopped.clone());

        let proxy_address =
            SocketAddr::from((config.network.proxy_address, config.network.proxy_port));
        let egress_listener = TcpListener::bind(proxy_address)
            .await
            .map_err(|error| format!("cannot bind the egress proxy on {proxy_address}: {error}"))?;
        let ingress_listener = TcpListener::bind(config.ingress.listen)
            .await
            .map_err(|error| {
                format!(
                    "cannot bind the ingress on {}: {error}",
                    config.ingress.listen
                )
            })?;

        let egress = Arc::new(EgressProxy::new_bounded(
            Arc::new(policy),
            connection_attribution,
            Arc::new(SystemResolver),
            EgressLimits::from_config(&config.egress),
            usize::try_from(config.network.max_proxy_connections).unwrap_or(usize::MAX),
        ));
        tokio::spawn(egress.serve(egress_listener, stopped.clone()));
        let limits = IngressLimits {
            max_request_bytes: usize::try_from(config.ingress.max_request_bytes)
                .unwrap_or(usize::MAX),
            max_connections: usize::try_from(config.runtime.max_ingress_connections)
                .unwrap_or(usize::MAX),
        };
        let executor: Arc<dyn Executor> = Arc::new(supervisor.clone());
        tokio::spawn(ingress::serve(ingress_listener, executor, limits, stopped));

        // A helper that died after its successful hello but before readiness must not be hidden by
        // a ready event. The lifecycle watchers started before listener setup and do not need an
        // RPC to observe exit.
        tokio::task::yield_now().await;
        if enforcer_exit.is_finished() {
            let reason = helper_exit_reason(enforcer_exit.await);
            supervisor.helper_exited("enforcer", reason);
            drop(supervisor);
            return Err("the enforcer exited before startup.ready".to_owned());
        }
        if sandbox_exit.is_finished() {
            let reason = helper_exit_reason(sandbox_exit.await);
            supervisor.helper_exited("sandboxd", reason);
            drop(supervisor);
            return Err("sandboxd exited before startup.ready".to_owned());
        }
        if !supervisor.mark_ready() {
            drop(supervisor);
            return Err("the runtime stopped admission before startup.ready".to_owned());
        }
        info!(event.name = "startup.ready", ingress = %config.ingress.listen, egress = %proxy_address, "soglia is ready");

        let mut terminate = signal(SignalKind::terminate()).map_err(|error| error.to_string())?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(|error| error.to_string())?;
        #[derive(Clone, Copy)]
        enum StopReason {
            Signal,
            EnforcerLost,
            SandboxLost,
            HelperRpcLost,
        }
        let stopped_by = tokio::select! {
            _ = terminate.recv() => StopReason::Signal,
            _ = interrupt.recv() => StopReason::Signal,
            exit = &mut enforcer_exit => {
                supervisor.helper_exited("enforcer", helper_exit_reason(exit));
                StopReason::EnforcerLost
            }
            exit = &mut sandbox_exit => {
                supervisor.helper_exited("sandboxd", helper_exit_reason(exit));
                StopReason::SandboxLost
            }
            _ = lost.wait_for(|lost| *lost) => StopReason::HelperRpcLost,
        };
        let helper_lost = !matches!(stopped_by, StopReason::Signal);

        supervisor.stop_admitting();
        stop.send_replace(true);
        if helper_lost {
            // The fail-closed transition already closed sandboxd's channel. Its process exits only
            // after kill-all has finished, so this is the trusted Execution-termination barrier.
            if !matches!(stopped_by, StopReason::SandboxLost)
                && tokio::time::timeout(
                    Duration::from_millis(config.runtime.teardown_timeout_ms),
                    &mut sandbox_exit,
                )
                .await
                .is_err()
            {
                error!(
                    event.name = "shutdown.incomplete",
                    "sandboxd did not finish terminating Executions before the helper-loss deadline"
                );
            }
        } else {
            let grace = Duration::from_millis(config.runtime.teardown_timeout_ms)
                + Duration::from_millis(
                    config
                        .agents
                        .values()
                        .map(|agent| agent.timeout_ms)
                        .max()
                        .unwrap_or(0),
                );
            if !supervisor.drain(grace).await {
                error!(
                    event.name = "shutdown.incomplete",
                    "Executions were still running at shutdown; the helpers kill them"
                );
            }
        }
        // Dropping the Supervisor closes the helper channels; each helper then kills or freezes what
        // is still live and exits, and the next start sweeps the rest.
        drop(supervisor);

        if helper_lost {
            Err("a privileged helper was lost".to_owned())
        } else {
            info!(event.name = "shutdown.done", "soglia stopped");
            Ok(())
        }
    }

    fn helper_exit_reason(
        outcome: Result<
            Result<ExitStatus, soglia_supervisor::helpers::HelperError>,
            tokio::task::JoinError,
        >,
    ) -> String {
        match outcome {
            Ok(Ok(status)) => match (status.code(), status.signal()) {
                (Some(code), _) => format!("child exited with status {code}"),
                (_, Some(signal)) => format!("child exited from signal {signal}"),
                _ => format!("child exited: {status}"),
            },
            Ok(Err(error)) => error.to_string(),
            Err(error) => format!("child watcher failed: {error}"),
        }
    }

    /// Soglia's own addresses the egress proxy must never reach, beyond the pool and the proxy.
    fn control_addresses(config: &Config) -> Vec<IpAddr> {
        let ingress = config.ingress.listen.ip();
        if ingress.is_unspecified() {
            Vec::new()
        } else {
            vec![ingress]
        }
    }

    /// A helper's end of its channel: the socketpair end the original process handed over as the
    /// helper's standard input.
    fn channel_from_stdin() -> std::io::Result<std::os::unix::net::UnixStream> {
        use std::os::fd::AsFd;

        let descriptor = std::io::stdin().as_fd().try_clone_to_owned()?;
        Ok(std::os::unix::net::UnixStream::from(descriptor))
    }

    fn channel_from_stdout() -> std::io::Result<std::os::unix::net::UnixStream> {
        use std::os::fd::AsFd;

        let descriptor = std::io::stdout().as_fd().try_clone_to_owned()?;
        Ok(std::os::unix::net::UnixStream::from(descriptor))
    }

    /// `soglia __sandboxd`.
    pub fn sandboxd() -> Result<(), String> {
        let channel = channel_from_stdin().map_err(|error| error.to_string())?;
        soglia_sandbox::service::run(channel)
    }

    /// `soglia __enforcer`.
    pub fn enforcer() -> Result<(), String> {
        let channel = channel_from_stdin().map_err(|error| error.to_string())?;
        let resolver = channel_from_stdout().map_err(|error| error.to_string())?;
        soglia_enforcer::service::run(channel, resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soglia_core::helper::RefusalClass;

    #[test]
    fn typed_startup_failures_select_stable_process_status() {
        for (class, expected) in [
            (RefusalClass::Incompatible, 20),
            (RefusalClass::Unknown, 21),
            (RefusalClass::Unsupported, 22),
            (RefusalClass::Infrastructure, 23),
        ] {
            let error = ProcessError::StartupRefused {
                context: "test".into(),
                failure: HelperFailure::Refused {
                    class,
                    detail: "diagnostic text does not select the status".into(),
                },
            };
            assert_eq!(error.exit_code(), expected);
        }
        let topology = ProcessError::StartupRefused {
            context: "test".into(),
            failure: HelperFailure::IncompatibleBpfTopology {
                hook: "soglia_connect4".into(),
                errno: Some(1),
                detail: "diagnostic".into(),
            },
        };
        assert_eq!(topology.exit_code(), 24);
        assert_eq!(ProcessError::Generic("crash".into()).exit_code(), 1);
    }

    #[test]
    fn uninstall_has_dry_run_but_no_force_escape_hatch() {
        assert!(
            Cli::try_parse_from(["soglia", "uninstall", "--dry-run", "-f", "/etc/soglia.yaml",])
                .is_ok()
        );
        assert!(
            Cli::try_parse_from(["soglia", "uninstall", "--force", "-f", "/etc/soglia.yaml",])
                .is_err()
        );
    }
}
