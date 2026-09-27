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
        Command::Sandboxd => runtime::sandboxd(),
        Command::Enforcer => runtime::enforcer(),
        Command::CaSigner => DeferredComponent::CaSigner
            .activate()
            .map_err(|refused| refused.to_string()),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("soglia: {reason}");
            ExitCode::FAILURE
        }
    }
}

mod runtime {
    use std::fs;
    use std::net::{IpAddr, SocketAddr};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::sync::Arc;
    use std::time::Duration;

    use soglia_core::Config;
    use soglia_proxy::attribution::AttributionTable;
    use soglia_proxy::egress::{EgressLimits, EgressProxy};
    use soglia_proxy::ingress::{self, Executor, IngressLimits};
    use soglia_proxy::policy::DestinationPolicy;
    use soglia_proxy::resolver::SystemResolver;
    use soglia_supervisor::Supervisor;
    use soglia_supervisor::helpers::Helper;
    use soglia_supervisor::privilege;
    use tokio::net::TcpListener;
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::sync::watch;
    use tracing::{error, info};

    /// `soglia run -f <file>`.
    pub fn run(file: &Path) -> Result<(), String> {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_target(false)
            .init();

        let text = fs::read_to_string(file)
            .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
        let config = Config::from_yaml(&text).map_err(|error| error.to_string())?;
        let policy =
            DestinationPolicy::new(&config.egress, &config.network, control_addresses(&config))
                .map_err(|error| error.to_string())?;
        if !rustix::process::geteuid().is_root() {
            return Err(
                "soglia run starts as root: its helpers need privileges the runtime then drops"
                    .to_owned(),
            );
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
        let enforcer = Helper::spawn(&executable, "enforcer")
            .map_err(|error| format!("cannot start the enforcer: {error}"))?;
        // Processes are killed before their network is removed, at startup as at teardown.
        for helper in [&sandbox, &enforcer] {
            let swept = helper
                .hello(&text)
                .map_err(|error| format!("the {} did not start: {error}", helper.role()))?;
            for resource in swept {
                info!(event.name = "startup.swept", helper = helper.role(), resource = %resource, "a resource left by a previous run was removed");
            }
        }

        privilege::drop_to(config.runtime.uid, config.runtime.gid)
            .map_err(|error| format!("cannot drop privileges: {error}"))?;
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

        result
    }

    async fn serve(
        config: Config,
        policy: DestinationPolicy,
        sandbox: Helper,
        enforcer: Helper,
    ) -> Result<(), String> {
        let config = Arc::new(config);
        let pool = config.pool().map_err(|error| error.to_string())?;
        let attribution = Arc::new(AttributionTable::new());
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

        let egress = Arc::new(EgressProxy::new(
            Arc::new(policy),
            attribution,
            Arc::new(SystemResolver),
            EgressLimits::from_config(&config.egress),
        ));
        tokio::spawn(egress.serve(egress_listener, stopped.clone()));
        let limits = IngressLimits {
            max_request_bytes: usize::try_from(config.ingress.max_request_bytes)
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

    /// `soglia __sandboxd`.
    pub fn sandboxd() -> Result<(), String> {
        let channel = channel_from_stdin().map_err(|error| error.to_string())?;
        soglia_sandbox::service::run(channel)
    }

    /// `soglia __enforcer`.
    pub fn enforcer() -> Result<(), String> {
        let channel = channel_from_stdin().map_err(|error| error.to_string())?;
        soglia_enforcer::service::run(channel)
    }
}
