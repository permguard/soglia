// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Phase-0 acceptance suite: the canonical T1-T10 of `soglia-architecture.md` §34.1.8, and the
//! separate H1-H4 hardening tests of §34.1.9.
//!
//! It starts the real `soglia run` as root and talks to it only through its ingress, the way a caller
//! would. Privileged and Linux-only, so ignored by default; run it in the development container, one
//! test at a time, because every test shares the host:
//!
//! ```sh
//! dev/linux/run.sh --privileged sh -c \
//!   'SOGLIA_TEST_AGENT=$(dev/linux/build-test-agent.sh) cargo test --test phase0 -- --ignored --test-threads=1'
//! ```
//!
//! Destinations "outside" are test services on `11.0.0.1`, a global address on a dummy interface,
//! named through `/etc/hosts`. Whenever the suite checks that a connection is refused, something is
//! really listening at the other end, so a success would be a real bypass rather than an absent
//! service.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const INGRESS: &str = "127.0.0.1:18088";
const STATE: &str = "/run/soglia-phase0";
const EXECUTIONS: &str = "/sys/fs/cgroup/soglia/executions";
const UPSTREAM: &str = "11.0.0.1";

struct Soglia {
    process: Mutex<Child>,
    log: PathBuf,
}

static SOGLIA: OnceLock<Soglia> = OnceLock::new();

fn soglia() -> &'static Soglia {
    SOGLIA.get_or_init(start)
}

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Answers every connection on `address` with `reply`, in the background.
fn serve(address: &str, reply: &'static [u8]) {
    let listener = TcpListener::bind(address).unwrap();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(reply);
            });
        }
    });
}

fn rootfs() -> PathBuf {
    let agent =
        std::env::var("SOGLIA_TEST_AGENT").expect("SOGLIA_TEST_AGENT names the built test agent");
    let root = PathBuf::from("/tmp/soglia-phase0-rootfs");
    for directory in ["proc", "dev", "sys", "tmp"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::copy(agent, root.join("agent")).unwrap();
    fs::set_permissions(root.join("agent"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    root
}

fn config(rootfs: &Path, extra: &str) -> String {
    format!(
        r#"
runtime:
  uid: 990
  gid: 990
  state_dir: {STATE}
  max_concurrency: 2
  max_queue: 1
  teardown_timeout_ms: 5000
ingress:
  listen: {INGRESS}
  max_response_bytes: 65536
cgroup:
  root: /sys/fs/cgroup/soglia
egress:
  connect_timeout_ms: 1000
  allow:
    - {{ host: allowed.test, ports: [80, 443] }}
    - {{ host: loopback.test, ports: [443] }}
    - {{ host: metadata.test, ports: [80] }}
    - {{ host: private.test, ports: [443] }}
    - {{ host: peer.test, ports: [8080] }}
    - {{ host: 10.201.0.1, ports: [8080] }}
agents:
  probe:
    rootfs: {root}
    command: ["/agent"]
    env: {{ AGENT_PORT: "8080" }}
    timeout_ms: 4000
  small:
    rootfs: {root}
    command: ["/agent"]
    env: {{ AGENT_PORT: "8080" }}
    timeout_ms: 8000
    limits: {{ pids_max: 24, memory_max_bytes: 67108864 }}
{extra}"#,
        root = rootfs.display()
    )
}

fn start() -> Soglia {
    // The world outside: a global address on the host, answering on 443 and 80, and names for it.
    if !Path::new("/sys/class/net/upstream0").exists() {
        run("ip", &["link", "add", "upstream0", "type", "dummy"]);
        run(
            "ip",
            &["addr", "add", &format!("{UPSTREAM}/32"), "dev", "upstream0"],
        );
        run("ip", &["link", "set", "upstream0", "up"]);
    }
    serve(&format!("{UPSTREAM}:443"), b"tls-ish upstream");
    serve(
        &format!("{UPSTREAM}:80"),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    // A host service an Execution must not reach directly.
    serve("0.0.0.0:2222", b"host service");
    let hosts = fs::read_to_string("/etc/hosts").unwrap();
    if !hosts.contains("allowed.test") {
        let names = format!(
            "\n{UPSTREAM} allowed.test\n11.0.0.2 blocked.test\n127.0.0.1 loopback.test\n\
             169.254.169.254 metadata.test\n10.9.9.9 private.test\n10.201.0.1 peer.test\n"
        );
        fs::OpenOptions::new()
            .append(true)
            .open("/etc/hosts")
            .unwrap()
            .write_all(names.as_bytes())
            .unwrap();
    }

    let directory = PathBuf::from("/tmp/soglia-phase0");
    fs::create_dir_all(&directory).unwrap();
    let file = directory.join("soglia.yaml");
    fs::write(&file, config(&rootfs(), "")).unwrap();
    let log = directory.join("soglia.log");
    let process = Command::new(env!("CARGO_BIN_EXE_soglia"))
        .args(["run", "-f"])
        .arg(&file)
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let soglia = Soglia {
        process: Mutex::new(process),
        log,
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(INGRESS).is_err() {
        if let Ok(Some(status)) = soglia.process.lock().unwrap().try_wait() {
            panic!("soglia exited ({status}):\n{}", soglia.log_tail());
        }
        assert!(
            Instant::now() < deadline,
            "soglia never became ready:\n{}",
            soglia.log_tail()
        );
        thread::sleep(Duration::from_millis(100));
    }

    soglia
}

impl Soglia {
    fn log_tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

/// What the ingress answered.
#[derive(Debug)]
struct Answer {
    status: u16,
    execution: Option<String>,
    body: String,
}

/// One invocation through the ingress, exactly as a caller would make it.
fn invoke(agent: &str, command: &str) -> Answer {
    let soglia = soglia();
    let mut stream = TcpStream::connect(INGRESS).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let request = format!(
        "POST /v1/execute/{agent} HTTP/1.1\r\nHost: soglia\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{command}",
        command.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no HTTP response: {response:?}\n{}", soglia.log_tail()));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap();
    let execution = head
        .lines()
        .find_map(|line| line.strip_prefix("soglia-execution-id: "))
        .map(ToOwned::to_owned);

    Answer {
        status,
        execution,
        body: body.to_owned(),
    }
}

fn entries(directory: &str, prefix: &str) -> Vec<String> {
    fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(prefix))
                .collect()
        })
        .unwrap_or_default()
}

/// Every resource an Execution owns, anywhere Soglia puts one.
fn leftovers() -> Vec<String> {
    let mut left = Vec::new();
    for name in entries(EXECUTIONS, "") {
        if Path::new(EXECUTIONS).join(&name).is_dir() {
            left.push(format!("cgroup {name}"));
        }
    }
    left.extend(
        entries("/run/netns", "soglia-")
            .into_iter()
            .map(|name| format!("netns {name}")),
    );
    left.extend(
        entries("/sys/class/net", "sgh-")
            .into_iter()
            .map(|name| format!("veth {name}")),
    );
    let containers = run(
        "runc",
        &["--root", &format!("{STATE}/runc"), "list", "--quiet"],
    );
    left.extend(
        containers
            .lines()
            .filter(|line| !line.is_empty())
            .map(|id| format!("container {id}")),
    );
    left.extend(
        entries(&format!("{STATE}/bundles"), "")
            .into_iter()
            .map(|name| format!("bundle {name}")),
    );
    left.extend(
        entries(&format!("{STATE}/sandbox"), "")
            .into_iter()
            .map(|name| format!("sandbox record {name}")),
    );
    left.extend(
        entries(&format!("{STATE}/net"), "")
            .into_iter()
            .filter(|name| name != "host.json")
            .map(|name| format!("net record {name}")),
    );
    for set in ["exec_src", "exec_ingress"] {
        let listed = run("nft", &["list", "set", "inet", "soglia_host", set]);
        if listed.contains("elements") {
            left.push(format!("nft {set}: {listed}"));
        }
    }
    for pid in entries("/proc", "") {
        if pid.bytes().all(|byte| byte.is_ascii_digit())
            && fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|cmdline| cmdline.starts_with(b"/agent\0"))
        {
            left.push(format!("agent process {pid}"));
        }
    }
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    left.extend(
        mounts
            .lines()
            .filter(|line| line.contains(&format!("{STATE}/bundles/")))
            .map(|line| format!("mount {line}")),
    );
    left
}

/// A response has been released, so its Execution must already be gone: no polling.
fn assert_gone(context: &str) {
    let left = leftovers();
    assert!(
        left.is_empty(),
        "{context}: resources remain after the response: {left:#?}"
    );
}

// ----------------------------------------------------------------------------------------------
// T1-T10: the canonical Phase-0 acceptance gate.
// ----------------------------------------------------------------------------------------------

#[test]
#[ignore = "privileged; see the module documentation"]
fn t01_an_invocation_runs_in_a_fresh_sandbox_and_answers_after_teardown() {
    let answer = invoke("probe", "echo hello");
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(answer.body, "hello");
    assert!(answer.execution.is_some());
    assert_gone("T1");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t02_an_allowed_destination_is_reachable_through_the_proxy() {
    let tunnel = invoke("probe", "proxy-connect allowed.test:443");
    assert_eq!(tunnel.status, 200, "{tunnel:?}");
    assert!(
        tunnel.body.starts_with("HTTP/1.1 200"),
        "CONNECT: {}",
        tunnel.body
    );
    let plain = invoke("probe", "proxy-get http://allowed.test/");
    assert!(
        plain.body.starts_with("HTTP/1.1 200"),
        "GET: {}",
        plain.body
    );
    assert_gone("T2");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t03_a_denied_destination_is_refused_by_the_proxy() {
    let answer = invoke("probe", "proxy-connect blocked.test:443");
    assert!(answer.body.starts_with("HTTP/1.1 403"), "{}", answer.body);
    let port = invoke("probe", "proxy-connect allowed.test:8443");
    assert!(port.body.starts_with("HTTP/1.1 403"), "{}", port.body);
    assert_gone("T3");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t04_a_direct_socket_to_the_internet_cannot_be_established() {
    // Something listens on the upstream address, so "connected" would be a real bypass.
    for target in [format!("{UPSTREAM}:443"), "1.1.1.1:443".to_owned()] {
        let answer = invoke("probe", &format!("connect {target}"));
        assert!(
            answer.body.starts_with("failed"),
            "{target}: {}",
            answer.body
        );
    }
    assert_gone("T4");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t05_a_direct_socket_to_a_host_service_cannot_be_established() {
    for target in [
        "10.200.255.1:2222",
        "10.200.255.1:18088",
        "127.0.0.1:18088",
        "10.201.0.0:2222",
    ] {
        let answer = invoke("probe", &format!("connect {target}"));
        assert!(
            answer.body.starts_with("failed"),
            "{target}: {}",
            answer.body
        );
    }
    assert_gone("T5");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t06_after_success_nothing_of_the_execution_remains() {
    let answer = invoke("probe", "whoami");
    assert_eq!(answer.status, 200);
    assert_gone("T6");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t07_after_a_crash_or_a_timeout_nothing_of_the_execution_remains() {
    let crash = invoke("probe", "crash");
    assert_eq!(crash.status, 502, "{crash:?}");
    assert_gone("T7 crash");

    let timeout = invoke("probe", "sleep 6000");
    assert_eq!(timeout.status, 504, "{timeout:?}");
    assert_gone("T7 timeout");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t08_sequential_invocations_get_distinct_executions_and_fresh_sandboxes() {
    let first = invoke("probe", "touch");
    assert_eq!(first.body, "touched");
    let second = invoke("probe", "tmp");
    assert_eq!(second.status, 200);
    assert!(
        !second.body.contains("marker"),
        "the second sandbox saw the first one's file"
    );
    assert_ne!(first.execution, second.execution);
    assert!(first.execution.is_some() && second.execution.is_some());
    assert_gone("T8");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t09_the_concurrency_limit_and_queue_hold() {
    soglia();
    let most = Arc::new(AtomicUsize::new(0));
    let watching = Arc::new(Mutex::new(true));
    let watcher = {
        let most = Arc::clone(&most);
        let watching = Arc::clone(&watching);
        thread::spawn(move || {
            while *watching.lock().unwrap() {
                most.fetch_max(entries("/run/netns", "soglia-").len(), Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
            }
        })
    };

    let callers: Vec<_> = (0..4)
        .map(|index| {
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(index * 50));
                invoke("probe", "sleep 1500").status
            })
        })
        .collect();
    let mut statuses: Vec<u16> = callers
        .into_iter()
        .map(|caller| caller.join().unwrap())
        .collect();
    *watching.lock().unwrap() = false;
    watcher.join().unwrap();
    statuses.sort_unstable();

    // Two run, one waits in the queue of one, one is refused.
    assert_eq!(statuses, vec![200, 200, 200, 503]);
    let most = most.load(Ordering::SeqCst);
    assert!((1..=2).contains(&most), "{most} Executions existed at once");
    assert_gone("T9");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn t10_later_phase_components_are_not_part_of_the_path() {
    // T1-T9 ran without them; asking for one refuses to start rather than pretending.
    let directory = PathBuf::from("/tmp/soglia-phase0-t10");
    fs::create_dir_all(&directory).unwrap();
    for feature in [
        "trust_fabric",
        "pic",
        "ifc",
        "credential_anchor",
        "ca_signer",
        "grpc",
        "cgroup_bpf",
    ] {
        let file = directory.join(format!("{feature}.yaml"));
        fs::write(
            &file,
            config(
                Path::new("/tmp/soglia-phase0-rootfs"),
                &format!("features:\n  {feature}: true\n"),
            ),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_soglia"))
            .args(["run", "-f"])
            .arg(&file)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{feature}");
        let expected = if feature == "cgroup_bpf" {
            "UnsupportedInThisBuild"
        } else {
            "DisabledInPhase0"
        };
        assert!(stderr.contains(expected), "{feature}: {stderr}");
    }
    let signer = Command::new(env!("CARGO_BIN_EXE_soglia"))
        .arg("__ca-signer")
        .output()
        .unwrap();
    assert!(!signer.status.success());
    assert!(String::from_utf8_lossy(&signer.stderr).contains("DisabledInPhase0"));
}

// ----------------------------------------------------------------------------------------------
// H1-H4: Phase-0 hardening, separate from the canonical gate.
// ----------------------------------------------------------------------------------------------

#[test]
#[ignore = "privileged; see the module documentation"]
fn h1_an_allowed_name_resolving_to_a_forbidden_address_is_denied() {
    for target in [
        "loopback.test:443",
        "metadata.test:80",
        "private.test:443",
        "peer.test:8080",
    ] {
        let answer = invoke("probe", &format!("proxy-connect {target}"));
        assert!(
            answer.body.starts_with("HTTP/1.1 403"),
            "{target}: {}",
            answer.body
        );
    }
    assert_gone("H1");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn h2_ipv6_is_disabled_and_unusable() {
    assert_eq!(invoke("probe", "ipv6").body, "1");
    for target in ["[::1]:8080", "[2001:4860:4860::8888]:443", "[fe80::1]:22"] {
        let answer = invoke("probe", &format!("connect {target}"));
        assert!(
            answer.body.starts_with("failed"),
            "{target}: {}",
            answer.body
        );
    }
    assert_gone("H2");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn h3_one_execution_cannot_reach_another() {
    soglia();
    // The first Execution takes slot 0, 10.201.0.1, and stays up while the second probes it.
    let first = thread::spawn(|| invoke("probe", "sleep 2500"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while entries("/run/netns", "soglia-").is_empty() {
        assert!(
            Instant::now() < deadline,
            "the first Execution never appeared"
        );
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(300));

    let direct = invoke("probe", "connect 10.201.0.1:8080");
    assert!(direct.body.starts_with("failed"), "direct: {}", direct.body);
    for target in ["peer.test:8080", "10.201.0.1:8080"] {
        let proxied = invoke("probe", &format!("proxy-connect {target}"));
        assert!(
            proxied.body.starts_with("HTTP/1.1 403"),
            "{target}: {}",
            proxied.body
        );
    }
    assert_eq!(first.join().unwrap().status, 200);
    assert_gone("H3");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn h4_resource_exhaustion_fails_the_execution_and_cleans_up() {
    let memory = invoke("small", "memory");
    assert_eq!(memory.status, 502, "{memory:?}");
    assert!(memory.body.contains("memory limit"), "{}", memory.body);
    assert_gone("H4 memory");

    let threads = invoke("small", "threads");
    assert_eq!(threads.status, 502, "{threads:?}");
    assert!(threads.body.contains("process limit"), "{}", threads.body);
    assert_gone("H4 pids");
}

#[test]
#[ignore = "privileged; see the module documentation"]
fn z_shutdown_is_clean() {
    let soglia = soglia();
    let pid = soglia.process.lock().unwrap().id().to_string();
    run("kill", &["-TERM", &pid]);
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = soglia.process.lock().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "soglia did not stop:\n{}",
            soglia.log_tail()
        );
        thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success(), "{status}:\n{}", soglia.log_tail());
    assert_gone("shutdown");

    // Leave the host as it was found, so another privileged test can start from scratch.
    run("ip", &["link", "del", "soglia0"]);
    run("ip", &["link", "del", "upstream0"]);
    let _ = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut nft| {
            nft.stdin
                .take()
                .map(|mut input| {
                    input.write_all(b"add table inet soglia_host\ndelete table inet soglia_host\n")
                })
                .transpose()?;
            nft.wait()
        });
    let _ = fs::remove_dir_all(STATE);
}
