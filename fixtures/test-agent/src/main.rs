// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The agent the Phase-0 acceptance suite runs inside an Execution.
//!
//! It serves HTTP on `AGENT_PORT` and treats the request body as one command. Each command probes one
//! property of the sandbox from the inside and answers what it saw; the test decides whether that is
//! what the architecture requires. Nothing here is trusted by Soglia.
//!
//! | Command                     | What it does                                                    |
//! | --------------------------- | --------------------------------------------------------------- |
//! | `echo <text>`               | Answers `<text>`                                                |
//! | `connect <addr:port>`       | Opens a TCP connection directly, bypassing the proxy            |
//! | `proxy-connect <host:port>` | Sends `CONNECT` to the egress proxy and answers its status line |
//! | `proxy-get <url>`           | Sends an absolute-form `GET` through the proxy                  |
//! | `whoami`                    | Answers uid, capabilities, `NoNewPrivs` and seccomp mode        |
//! | `sleep <ms>`                | Answers after sleeping                                          |
//! | `crash`                     | Exits without answering                                         |
//! | `memory`                    | Allocates until the kernel stops it                             |
//! | `threads`                   | Starts threads until `pids.max` refuses one, then exits         |
//! | `touch`                     | Creates `/tmp/marker`                                           |
//! | `tmp`                       | Lists `/tmp`                                                    |
//! | `ipv6`                      | Answers `net.ipv6.conf.all.disable_ipv6` as the agent sees it   |

#![forbid(unsafe_code)]

// Soglia's isolation and enforcement are built from Linux namespaces, cgroups, nftables and runc.
// There is nothing to build for another system: on macOS or Windows, build this in the development
// container (`.devcontainer/` or `dev/linux/run.sh`); only `soglia-core` and `soglia-proxy` build natively.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "this crate builds and runs only on Linux; on macOS or Windows use the development container (.devcontainer/ or dev/linux/run.sh)"
);

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_millis(1500);

fn main() {
    let port: u16 = std::env::var("AGENT_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(8080);
    let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) else {
        std::process::exit(2);
    };
    for stream in listener.incoming().flatten() {
        handle(stream);
    }
}

fn handle(mut stream: TcpStream) {
    let Some(body) = read_request(&stream) else {
        return;
    };
    let answer = run(body.trim());
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
        answer.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn read_request(stream: &TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream);
    let mut length = 0_usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0_u8; length.min(1 << 16)];
    reader.read_exact(&mut body).ok()?;
    String::from_utf8(body).ok()
}

fn run(command: &str) -> String {
    let (verb, argument) = command.split_once(' ').unwrap_or((command, ""));
    match verb {
        "echo" => argument.to_owned(),
        "connect" => connect(argument),
        "proxy-connect" => proxy_connect(argument),
        "proxy-get" => proxy_get(argument),
        "whoami" => whoami(),
        "sleep" => {
            let millis = argument.parse().unwrap_or(0);
            std::thread::sleep(Duration::from_millis(millis));
            "slept".to_owned()
        }
        "crash" => std::process::exit(101),
        "memory" => memory(),
        "threads" => threads(),
        "touch" => match std::fs::write("/tmp/marker", b"here") {
            Ok(()) => "touched".to_owned(),
            Err(error) => format!("failed: {error}"),
        },
        "tmp" => match std::fs::read_dir("/tmp") {
            Ok(entries) => entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(","),
            Err(error) => format!("failed: {error}"),
        },
        "ipv6" => std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|error| format!("unavailable: {error}")),
        _ => format!("unknown command `{verb}`"),
    }
}

fn connect(target: &str) -> String {
    let Some(address) = target.to_socket_addrs().ok().and_then(|mut all| all.next()) else {
        return format!("failed: `{target}` is not an address");
    };
    match TcpStream::connect_timeout(&address, DEADLINE) {
        Ok(_) => "connected".to_owned(),
        Err(error) => format!("failed: {error}"),
    }
}

fn proxy() -> Result<TcpStream, String> {
    let url = std::env::var("HTTPS_PROXY").map_err(|_| "no HTTPS_PROXY".to_owned())?;
    let authority = url.trim_start_matches("http://").trim_end_matches('/');
    let address: SocketAddr = authority
        .parse()
        .map_err(|_| format!("HTTPS_PROXY `{url}` is not an address"))?;
    let stream =
        TcpStream::connect_timeout(&address, DEADLINE).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

fn status_line(stream: &TcpStream) -> String {
    let mut line = String::new();
    let _ = BufReader::new(stream).read_line(&mut line);
    line.trim_end().to_owned()
}

fn proxy_connect(target: &str) -> String {
    match proxy() {
        Ok(mut stream) => {
            let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
            if stream.write_all(request.as_bytes()).is_err() {
                return "failed: write".to_owned();
            }
            status_line(&stream)
        }
        Err(error) => format!("failed: {error}"),
    }
}

fn proxy_get(url: &str) -> String {
    let host = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default();
    match proxy() {
        Ok(mut stream) => {
            let request =
                format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            if stream.write_all(request.as_bytes()).is_err() {
                return "failed: write".to_owned();
            }
            let mut response = String::new();
            let _ = stream.take(4096).read_to_string(&mut response);
            response.lines().next().unwrap_or_default().to_owned()
        }
        Err(error) => format!("failed: {error}"),
    }
}

fn whoami() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .filter(|line| {
            [
                "Uid:",
                "Gid:",
                "CapEff:",
                "CapPrm:",
                "CapBnd:",
                "NoNewPrivs:",
                "Seccomp:",
            ]
            .iter()
            .any(|key| line.starts_with(key))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn memory() -> String {
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    loop {
        // Touch every page so the memory is really charged to the cgroup.
        blocks.push(vec![1_u8; 16 << 20]);
        if blocks.len() > 4096 {
            return "the memory limit never stopped the allocation".to_owned();
        }
    }
}

fn threads() -> String {
    let mut started = 0_u32;
    loop {
        let spawned =
            std::thread::Builder::new().spawn(|| std::thread::sleep(Duration::from_secs(3600)));
        if spawned.is_err() {
            // `pids.max` refused a thread: that is the limit this command exists to reach.
            std::process::exit(3);
        }
        started += 1;
        if started > 100_000 {
            return "pids.max never refused a thread".to_owned();
        }
    }
}
