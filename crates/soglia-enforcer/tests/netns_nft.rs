// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The network backend against a real kernel.
//!
//! Privileged and Linux-only, so ignored by default. Run it in the development container:
//!
//! ```sh
//! dev/linux/run.sh --privileged cargo test -p soglia-enforcer --test netns_nft -- --ignored
//! ```
//!
//! It installs host-wide objects (`soglia0`, `inet soglia_host`), so it is one sequential test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use soglia_core::ExecutionId;
use soglia_core::net::ExecutionPool;
use soglia_enforcer::backend::{EnforcementBackend, NetnsNftBackend, NetworkSettings};
use soglia_enforcer::rules::ProxyEndpoint;
use soglia_enforcer::system::{self, in_netns};

const PROXY: Ipv4Addr = Ipv4Addr::new(10, 200, 255, 1);
const PROXY_PORT: u16 = 15001;
const AGENT_PORT: u16 = 8080;
const DEADLINE: Duration = Duration::from_millis(700);

fn settings(records: PathBuf) -> NetworkSettings {
    NetworkSettings {
        ip: "/usr/sbin/ip".into(),
        nft: "/usr/sbin/nft".into(),
        records,
        pool: ExecutionPool::new("10.201.0.0/29".parse().unwrap()).unwrap(),
        proxy: ProxyEndpoint {
            address: PROXY,
            port: PROXY_PORT,
        },
        // The test runs as root, so root plays the Supervisor for the ingress direction.
        supervisor_uid: 0,
        agent_ports: BTreeMap::from([("echo".to_owned(), AGENT_PORT)]),
    }
}

/// `true` when a TCP connection to `target` can be established from inside `netns`. Refusal,
/// unreachability and timeout all count as "no": only an established connection is a "yes".
fn connects_from(netns: &str, target: SocketAddr) -> bool {
    in_netns(netns, move || {
        Ok(TcpStream::connect_timeout(&target, DEADLINE).is_ok())
    })
    .unwrap()
}

fn ip(args: &[&str]) -> String {
    system::run("/usr/sbin/ip".as_ref(), args, None).unwrap()
}

fn nft(batch: &str) {
    system::run("/usr/sbin/nft".as_ref(), &["-f", "-"], Some(batch)).unwrap();
}

/// Serves one-byte answers on `listener` forever, in the background.
fn answer(listener: TcpListener) {
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.write_all(b"k");
        }
    });
}

fn records_dir() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("soglia-enforcer-test-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
#[ignore = "needs root, nftables and iproute2 on Linux"]
fn the_network_backend_confines_attributes_and_cleans_up() {
    assert!(system::is_root(), "run this test as root");
    let records = records_dir();
    let mut backend = NetnsNftBackend::new(settings(records.clone()));
    backend.probe_capabilities().unwrap();
    backend.initialize().unwrap();

    // The proxy endpoint, listening on the host, and another host port it must not reach.
    answer(TcpListener::bind(SocketAddrV4::new(PROXY, PROXY_PORT)).unwrap());
    answer(TcpListener::bind(SocketAddrV4::new(PROXY, 2222)).unwrap());

    let id = ExecutionId::generate().unwrap();
    let tag = id.tag();
    let netns = tag.netns_name();
    let veth = tag.host_veth();
    backend
        .prepare_execution(
            id,
            1,
            "echo",
            soglia_core::ExecutionNonce::generate().unwrap(),
        )
        .unwrap();
    let host_end: Ipv4Addr = "10.201.0.2".parse().unwrap();
    let execution: Ipv4Addr = "10.201.0.3".parse().unwrap();
    let proxy = SocketAddr::from((PROXY, PROXY_PORT));

    // IPv6 is off inside the Execution namespace: no address, and the sysctl reads 1.
    let ipv6 = in_netns(&netns, || {
        std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
    })
    .unwrap();
    assert_eq!(ipv6.trim(), "1");
    let addresses = ip(&["-n", &netns, "-6", "addr", "show"]);
    assert!(!addresses.contains("inet6"), "{addresses}");

    // Egress: the proxy endpoint and nothing else.
    assert!(connects_from(&netns, proxy), "the proxy must be reachable");
    assert!(
        !connects_from(&netns, SocketAddr::from((PROXY, 2222))),
        "another host port"
    );
    assert!(
        !connects_from(&netns, SocketAddr::from((host_end, 22))),
        "the host end"
    );
    assert!(
        !connects_from(&netns, "1.1.1.1:443".parse().unwrap()),
        "the Internet"
    );

    // Ingress: the agent listener, from the host, and only that port.
    let agent = in_netns(&netns, move || {
        TcpListener::bind(SocketAddrV4::new(execution, AGENT_PORT))
    })
    .unwrap();
    answer(agent);
    let other = in_netns(&netns, move || {
        TcpListener::bind(SocketAddrV4::new(execution, 9090))
    })
    .unwrap();
    answer(other);
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::from((execution, AGENT_PORT)), DEADLINE)
            .expect("the host reaches the agent listener");
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).unwrap();
    assert!(
        TcpStream::connect_timeout(&SocketAddr::from((execution, 9090)), DEADLINE).is_err(),
        "another port inside the Execution"
    );

    // Anti-spoofing: an address inside the namespace that Soglia did not assign is dropped on the
    // host. `rp_filter` is turned off and a return route added, so the nftables rule is the only
    // thing that can stop it; binding the address in the set first proves the path works otherwise.
    let spoofed = "10.201.0.7";
    let host_end_text = host_end.to_string();
    let proxy_route = format!("{PROXY}/32");
    ip(&[
        "-n",
        &netns,
        "addr",
        "add",
        &format!("{spoofed}/32"),
        "dev",
        "eth0",
    ]);
    ip(&[
        "-n",
        &netns,
        "route",
        "replace",
        &proxy_route,
        "via",
        &host_end_text,
        "dev",
        "eth0",
        "src",
        spoofed,
    ]);
    ip(&["route", "add", &format!("{spoofed}/32"), "dev", &veth]);
    system::set_sysctl(&format!("net/ipv4/conf/{veth}/rp_filter"), "0").unwrap();
    system::set_sysctl("net/ipv4/conf/all/rp_filter", "0").unwrap();
    let element = format!("inet soglia_host exec_src {{ \"{veth}\" . {spoofed} }}");
    nft(&format!("add element {element}\n"));
    assert!(
        connects_from(&netns, proxy),
        "control: a bound source reaches the proxy"
    );
    nft(&format!("delete element {element}\n"));
    assert!(
        !connects_from(&netns, proxy),
        "a source Soglia did not assign is dropped"
    );
    ip(&[
        "-n",
        &netns,
        "route",
        "replace",
        &proxy_route,
        "via",
        &host_end_text,
        "dev",
        "eth0",
        "src",
        &execution.to_string(),
    ]);
    assert!(
        connects_from(&netns, proxy),
        "the assigned source still works"
    );

    // Freeze: nothing moves any more.
    backend.freeze(&tag).unwrap();
    assert!(
        !connects_from(&netns, proxy),
        "a frozen Execution reaches nothing"
    );

    // Destroy: every resource is gone, and destroying again is not an error.
    backend.destroy_execution(&tag).unwrap();
    assert!(!system::netns_exists(&netns));
    assert!(!system::interface_exists(&veth));
    assert!(!records.join(format!("{tag}.json")).exists());
    backend.destroy_execution(&tag).unwrap();

    // Sweep: a recorded Execution left behind by a crashed run is removed at the next start.
    let crashed = ExecutionId::generate().unwrap();
    backend
        .prepare_execution(
            crashed,
            2,
            "echo",
            soglia_core::ExecutionNonce::generate().unwrap(),
        )
        .unwrap();
    drop(backend);
    let mut restarted = NetnsNftBackend::new(settings(records.clone()));
    let swept = restarted.initialize().unwrap();
    assert_eq!(swept.len(), 1, "{swept:?}");
    assert!(!system::netns_exists(&crashed.tag().netns_name()));
    assert!(!system::interface_exists(&crashed.tag().host_veth()));

    // An unrecorded resource with a Soglia name is refused, never deleted.
    ip(&["netns", "add", "soglia-ffffffffff"]);
    let mut again = NetnsNftBackend::new(settings(records));
    let refused = again.initialize().unwrap_err().to_string();
    assert!(refused.contains("soglia-ffffffffff"), "{refused}");
    assert!(system::netns_exists("soglia-ffffffffff"));
    ip(&["netns", "del", "soglia-ffffffffff"]);

    // Leave the host as it was found, so another privileged test can start from scratch.
    remove_host_objects();
}

fn remove_host_objects() {
    if system::interface_exists("soglia0") {
        ip(&["link", "del", "soglia0"]);
    }
    nft("add table inet soglia_host\ndelete table inet soglia_host\n");
}
