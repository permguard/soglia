// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The sandbox backend against a real kernel and a real runc, with the real network backend.
//!
//! Privileged and Linux-only, so ignored by default. Run it in the development container:
//!
//! ```sh
//! dev/linux/run.sh --privileged sh -c \
//!   'SOGLIA_TEST_AGENT=$(dev/linux/build-test-agent.sh) cargo test -p soglia-sandbox --test runc -- --ignored'
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use soglia_core::ExecutionId;
use soglia_core::config::Config;
use soglia_core::helper::ExitOutcome;
use soglia_enforcer::backend::{EnforcementBackend, NetnsNftBackend, NetworkSettings};
use soglia_enforcer::system::in_netns;
use soglia_sandbox::backend::{RuncSandbox, SandboxBackend, SandboxSettings};

/// A root filesystem holding only the static test agent and the mount points the sandbox needs.
fn rootfs(label: &str) -> PathBuf {
    let agent =
        std::env::var("SOGLIA_TEST_AGENT").expect("SOGLIA_TEST_AGENT names the built test agent");
    let root = std::env::temp_dir().join(format!("soglia-rootfs-{label}-{}", std::process::id()));
    for directory in ["proc", "dev", "sys", "tmp"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    std::fs::copy(&agent, root.join("agent")).unwrap();
    std::fs::set_permissions(root.join("agent"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    root
}

fn config(rootfs: &Path, state: &Path) -> Config {
    Config::from_yaml(&format!(
        r#"
runtime:
  uid: 990
  gid: 990
  state_dir: {state}
  teardown_timeout_ms: 5000
cgroup:
  root: /sys/fs/cgroup/soglia
agents:
  probe:
    rootfs: {rootfs}
    command: ["/agent"]
    env: {{ AGENT_PORT: "8080" }}
  small:
    rootfs: {rootfs}
    command: ["/agent"]
    env: {{ AGENT_PORT: "8080" }}
    limits: {{ pids_max: 24, memory_max_bytes: 67108864 }}
"#,
        state = state.display(),
        rootfs = rootfs.display(),
    ))
    .unwrap()
}

/// Sends one command to the agent from inside its own network namespace, over loopback.
fn ask(netns: &str, command: &str) -> Option<String> {
    let command = command.to_owned();
    in_netns(netns, move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match TcpStream::connect("127.0.0.1:8080") {
                Ok(stream) => break stream,
                Err(error) if std::time::Instant::now() >= deadline => return Err(error),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: agent\r\nContent-Length: {}\r\n\r\n{command}",
            command.len()
        );
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    })
    .ok()
    .and_then(|response| {
        response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
    })
}

fn gone(path: &Path) -> bool {
    !path.exists()
}

#[test]
#[ignore = "needs root, a delegated cgroup, runc, nftables and iproute2 on Linux"]
fn the_sandbox_isolates_classifies_and_cleans_up() {
    let rootfs = rootfs("sandbox");
    let state = std::env::temp_dir().join(format!("soglia-state-{}", std::process::id()));
    std::fs::create_dir_all(&state).unwrap();
    let config = config(&rootfs, &state);

    let mut network = NetnsNftBackend::new(NetworkSettings::from_config(&config).unwrap());
    network.probe_capabilities().unwrap();
    network.initialize().unwrap();
    let mut sandbox = RuncSandbox::new(SandboxSettings::from_config(&config).unwrap());
    sandbox.probe_capabilities().unwrap();
    sandbox.initialize().unwrap();

    let run = |network: &mut NetnsNftBackend, sandbox: &mut RuncSandbox, slot: u32, agent: &str| {
        let id = ExecutionId::generate().unwrap();
        network.prepare_execution(id, slot, agent).unwrap();
        sandbox.start_execution(id, agent).unwrap();
        id
    };
    let destroy = |network: &mut NetnsNftBackend, sandbox: &mut RuncSandbox, id: ExecutionId| {
        let tag = id.tag();
        network.freeze(&tag).unwrap();
        let outcome = sandbox.kill_execution(&tag).unwrap();
        sandbox.destroy_execution(&tag).unwrap();
        network.destroy_execution(&tag).unwrap();
        assert!(
            gone(&PathBuf::from("/sys/fs/cgroup/soglia/executions").join(tag.to_string())),
            "cgroup"
        );
        assert!(
            gone(&state.join("runc").join(tag.container_id())),
            "runc state"
        );
        assert!(gone(&state.join("bundles").join(tag.to_string())), "bundle");
        assert!(
            gone(&state.join("sandbox").join(format!("{tag}.json"))),
            "sandbox record"
        );
        assert!(
            gone(&PathBuf::from("/run/netns").join(tag.netns_name())),
            "netns"
        );
        assert!(
            gone(&PathBuf::from("/sys/class/net").join(tag.host_veth())),
            "veth"
        );
        outcome
    };

    // Inside, the agent is an unprivileged user with nothing to escalate with.
    let id = run(&mut network, &mut sandbox, 0, "probe");
    let netns = id.tag().netns_name();
    let whoami = ask(&netns, "whoami").expect("the agent answers");
    assert!(whoami.contains("Uid:\t65534"), "{whoami}");
    for set in ["CapEff", "CapPrm", "CapBnd"] {
        assert!(
            whoami.contains(&format!("{set}:\t0000000000000000")),
            "{set}: {whoami}"
        );
    }
    assert!(whoami.contains("NoNewPrivs:\t1"), "{whoami}");
    assert!(whoami.contains("Seccomp:\t2"), "{whoami}");
    let direct = ask(&netns, "connect 1.1.1.1:443").unwrap();
    assert!(
        direct.starts_with("failed"),
        "a direct connection must fail: {direct}"
    );
    assert_eq!(destroy(&mut network, &mut sandbox, id), ExitOutcome::Killed);

    // A crash is reported as the agent's own exit status.
    let id = run(&mut network, &mut sandbox, 1, "probe");
    assert!(ask(&id.tag().netns_name(), "crash").is_none_or(|body| body.is_empty()));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        destroy(&mut network, &mut sandbox, id),
        ExitOutcome::Status(101)
    );

    // memory.max stops the agent and is reported as such (H4).
    let id = run(&mut network, &mut sandbox, 2, "small");
    let _ = ask(&id.tag().netns_name(), "memory");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        destroy(&mut network, &mut sandbox, id),
        ExitOutcome::MemoryLimit
    );

    // pids.max refuses threads and is reported as such (H4).
    let id = run(&mut network, &mut sandbox, 3, "small");
    let _ = ask(&id.tag().netns_name(), "threads");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        destroy(&mut network, &mut sandbox, id),
        ExitOutcome::PidsLimit
    );

    // A crashed run leaves recorded resources; the next start sweeps them.
    let id = run(&mut network, &mut sandbox, 0, "probe");
    drop(sandbox);
    drop(network);
    let mut sandbox = RuncSandbox::new(SandboxSettings::from_config(&config).unwrap());
    let swept = sandbox.initialize().unwrap();
    assert_eq!(swept.len(), 1, "{swept:?}");
    let mut network = NetnsNftBackend::new(NetworkSettings::from_config(&config).unwrap());
    assert_eq!(network.initialize().unwrap().len(), 1);
    assert!(gone(
        &PathBuf::from("/sys/fs/cgroup/soglia/executions").join(id.tag().to_string())
    ));
    assert!(gone(
        &PathBuf::from("/run/netns").join(id.tag().netns_name())
    ));

    // Leave the host as it was found, so another privileged test can start from scratch.
    let run = |program: &str, args: &[&str], input: Option<&str>| {
        soglia_enforcer::system::run(program.as_ref(), args, input).unwrap();
    };
    run("/usr/sbin/ip", &["link", "del", "soglia0"], None);
    run(
        "/usr/sbin/nft",
        &["-f", "-"],
        Some("add table inet soglia_host\ndelete table inet soglia_host\n"),
    );
}
