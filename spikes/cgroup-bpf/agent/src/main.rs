// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The agent the Phase-1 spike runs inside an Execution. EXPERIMENTAL: test only.
//!
//! Every argument is one command; they run in order and each prints one JSON line per result on
//! standard output, which the harness reads through the runc output pipe. Nothing it reports is
//! trusted by the harness as identity: it only says what the kernel answered to each operation.
//!
//! `serve` instead answers HTTP on `AGENT_PORT`, for the Phase-0 runtime (S8a): the request body is
//! one command, and the answer is its result.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{
    Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream, UdpSocket,
};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use nix::{getsockopt_impl, libc, sockopt_impl};
use rustix::net::{AddressFamily, SocketType};

sockopt_impl!(
    NetnsCookie,
    GetOnly,
    nix::libc::SOL_SOCKET,
    nix::libc::SO_NETNS_COOKIE,
    u64
);

sockopt_impl!(
    SocketCookie,
    GetOnly,
    nix::libc::SOL_SOCKET,
    nix::libc::SO_COOKIE,
    u64
);

const PROXY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 200, 255, 1), 15001);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let started = Instant::now();
    for command in args {
        if command == "serve" {
            serve();
            return;
        }
        run(&command, started);
    }
}

fn print(line: String) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn quote(text: &str) -> String {
    let escaped: String = text
        .chars()
        .map(|c| match c {
            '"' => "\\\"".to_owned(),
            '\\' => "\\\\".to_owned(),
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
            c => c.to_string(),
        })
        .collect();
    format!("\"{escaped}\"")
}

fn outcome(command: &str, result: Result<String, std::io::Error>, extra: &str) -> String {
    match result {
        Ok(detail) => format!(
            "{{\"cmd\":{},\"ok\":true,\"detail\":{}{extra}}}",
            quote(command),
            quote(&detail)
        ),
        Err(error) => format!(
            "{{\"cmd\":{},\"ok\":false,\"errno\":{},\"error\":{}{extra}}}",
            quote(command),
            error.raw_os_error().unwrap_or(-1),
            quote(&error.to_string())
        ),
    }
}

fn errno(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

fn addr4(text: &str) -> SocketAddrV4 {
    text.parse()
        .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}

fn run(command: &str, started: Instant) {
    let words: Vec<&str> = command.split_whitespace().collect();
    let arg = |i: usize| words.get(i).copied().unwrap_or("");
    let num = |i: usize, default: u64| arg(i).parse().unwrap_or(default);
    match arg(0) {
        "barrier" => barrier(command, arg(1), arg(2), num(3, 30)),
        "proxy" => proxy(num(1, 1) as usize, 0),
        "proxy-http" => proxy_http(arg(1), arg(2).parse().ok()),
        "netns-cookie" => netns_cookie(),
        "b5-probe-report" => b5_probe_report(arg(1), arg(2), num(3, 5)),
        "b5-inherited-fd-report" => b5_inherited_fd_report(arg(1)),
        "proxy-fixed" => proxy_fixed(num(1, 40_000) as u16, num(2, 1) as usize, None),
        "proxy-fixed-report" => proxy_fixed(
            num(1, 40_000) as u16,
            num(2, 1) as usize,
            Some((arg(3), num(4, 10))),
        ),
        "proxy-hold" => proxy(num(1, 1) as usize, num(2, 5)),
        "proxy-port" => proxy_port(num(1, 40000) as u16, arg(2) == "rst", num(3, 1)),
        "proxy-connect-report" => proxy_connect_report(
            arg(1),
            num(2, 40_000) as u16,
            arg(3),
            arg(4),
            num(5, 10),
            num(6, 1) as usize,
        ),
        "proxy-connect-many-report" => proxy_connect_many_report(
            arg(1),
            num(2, 40_000) as u16,
            num(3, 1) as usize,
            arg(4),
            num(5, 2),
        ),
        "proxy-capacity-report" => proxy_capacity_report(
            arg(1),
            num(2, 40_000) as u16,
            num(3, 4) as usize,
            arg(4),
            num(5, 30),
        ),
        "proxy-preconnect-report" => {
            proxy_preconnect_report(arg(1), num(2, 41_000) as u16, arg(3), num(4, 30))
        }
        "proxy-reuse-report" => {
            proxy_reuse_report(arg(1), num(2, 40_000) as u16, arg(3), num(4, 30), num(5, 5))
        }
        "hold-proxy" => hold_proxy(num(1, 30)),
        "listen4-once" => print(outcome(
            command,
            listen4_once(addr4(arg(1)), num(2, 2500)),
            "",
        )),
        "listen4-hold" => print(outcome(command, listen4_hold(addr4(arg(1)), num(2, 5)), "")),
        "listen4-pulse-hold" => print(outcome(
            command,
            listen4_pulse_hold(addr4(arg(1)), num(2, 5)),
            "",
        )),
        "direct" => print(outcome(command, direct(addr4(arg(1))), "")),
        "direct-loop" => {
            for i in 0..num(3, 10) {
                let at = started.elapsed().as_millis();
                print(outcome(
                    command,
                    direct(addr4(arg(1))),
                    &format!(",\"i\":{i},\"at_ms\":{at}"),
                ));
                thread::sleep(Duration::from_millis(num(2, 200)));
            }
        }
        "direct-flood" => direct_flood(addr4(arg(1)), num(2, 1000), None, 0),
        "direct-flood-report" => direct_flood(addr4(arg(1)), num(2, 1000), Some(arg(3)), num(4, 5)),
        "sock" => print(outcome(command, sock(arg(1), arg(2)), "")),
        "udp4" => print(outcome(command, udp4(addr4(arg(1)), false), "")),
        "udp4c" => print(outcome(command, udp4(addr4(arg(1)), true), "")),
        "udp6" => print(outcome(command, udp6(arg(1)), "")),
        "tcp6" => print(outcome(command, tcp6(arg(1)), "")),
        "mapped" => print(outcome(command, mapped(addr4(arg(1))), "")),
        "raw" => print(outcome(
            command,
            rustix::net::socket(
                AddressFamily::INET,
                SocketType::RAW,
                Some(rustix::net::ipproto::ICMP),
            )
            .map(|_| "created".to_owned())
            .map_err(errno),
            "",
        )),
        "packet" => print(outcome(
            command,
            rustix::net::socket(AddressFamily::PACKET, SocketType::RAW, None)
                .map(|_| "created".to_owned())
                .map_err(errno),
            "",
        )),
        "netlink-route" => netlink_route(command),
        "unix" => print(outcome(command, unix(), "")),
        "sleep" => thread::sleep(Duration::from_millis(num(1, 100))),
        other => print(format!("{{\"cmd\":{},\"unknown\":true}}", quote(other))),
    }
}

/// Runs one B5 socket-boundary stimulus, records it while the process is still alive, then keeps
/// the process available long enough for the privileged harness to inspect its cgroup/netns state.
fn b5_probe_report(case: &str, report: &str, hold_secs: u64) {
    let started = Instant::now();
    let result = match case {
        "fd_table" => b5_fd_table(),
        "ipv6_stream" => sock("inet6", "stream"),
        "ipv4_datagram" => sock("inet", "dgram"),
        "ipv6_datagram" => sock("inet6", "dgram"),
        "direct_ipv4" => direct("10.201.0.2:16001".parse().unwrap()),
        "foreign_rewrite" => direct(PROXY),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown B5 probe {other}"),
        )),
    };
    let line = outcome(
        case,
        result,
        &format!(",\"elapsed_ms\":{}", started.elapsed().as_millis()),
    );
    let write = fs::write(report, format!("{line}\n"));
    print(match write {
        Ok(()) => line,
        Err(error) => outcome(case, Err(error), ",\"stage\":\"report\""),
    });
    thread::sleep(Duration::from_secs(hold_secs));
}

fn b5_fd_table() -> std::io::Result<String> {
    let mut descriptors = Vec::new();
    let mut sockets = Vec::new();
    for fd in 0..64 {
        let path = format!("/proc/self/fd/{fd}");
        match fs::read_link(&path) {
            Ok(target) => {
                let target = target.to_string_lossy().into_owned();
                if target.starts_with("socket:[") {
                    sockets.push(fd);
                }
                descriptors.push(format!("{fd}={target}"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(format!(
        "descriptors=[{}] sockets=[{}]",
        descriptors.join(","),
        sockets
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    ))
}

/// Characterizes a deliberately inherited socket created before entering the Execution netns.
/// Production never invokes this command; it is the negative control proving why passing socket
/// descriptors across the boundary would be unsafe.
fn b5_inherited_fd_report(report: &str) {
    let stdin = std::io::stdin();
    let inherited_cookie = nix::sys::socket::getsockopt(&stdin, NetnsCookie).ok();
    let current_cookie = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None)
        .map_err(errno)
        .and_then(|fd| {
            nix::sys::socket::getsockopt(&fd, NetnsCookie)
                .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
        })
        .ok();
    let stdin_target = fs::read_link("/proc/self/fd/0")
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|error| format!("unreadable:{error}"));
    let different = inherited_cookie
        .zip(current_cookie)
        .is_some_and(|(inherited, current)| inherited != current);
    let line = format!(
        "{{\"cmd\":\"b5-inherited-fd-report\",\"ok\":true,\"stdin_target\":{},\"inherited_netns_cookie\":{},\"current_netns_cookie\":{},\"external_to_current_netns\":{different}}}",
        quote(&stdin_target),
        inherited_cookie.map_or_else(|| "null".to_owned(), |value| value.to_string()),
        current_cookie.map_or_else(|| "null".to_owned(), |value| value.to_string()),
    );
    let _ = fs::write(report, format!("{line}\n"));
    print(line);
}

/// Reads the stable identity of the network namespace from a socket created by this agent.
fn netns_cookie() {
    let result = (|| {
        let fd =
            rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).map_err(errno)?;
        nix::sys::socket::getsockopt(&fd, NetnsCookie)
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
    })();
    match result {
        Ok(cookie) => print(format!(
            "{{\"cmd\":\"netns-cookie\",\"ok\":true,\"supported\":true,\"cookie\":{cookie}}}"
        )),
        Err(error) if error.raw_os_error() == Some(nix::libc::ENOPROTOOPT) => print(format!(
            "{{\"cmd\":\"netns-cookie\",\"ok\":true,\"supported\":false,\"errno\":{}}}",
            nix::libc::ENOPROTOOPT
        )),
        Err(error) => print(outcome("netns-cookie", Err(error), "")),
    }
}

/// One syntactically valid CONNECT request, used to prove that the production proxy does not parse
/// application bytes before Candidate-A Resolve completes.
fn proxy_http(target: &str, source_port: Option<u16>) {
    let result = (|| -> std::io::Result<String> {
        let mut stream = if let Some(source_port) = source_port {
            let fd = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None)
                .map_err(errno)?;
            rustix::net::sockopt::set_socket_reuseaddr(&fd, true).map_err(errno)?;
            rustix::net::bind(&fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, source_port))
                .map_err(errno)?;
            rustix::net::connect(&fd, &PROXY).map_err(errno)?;
            TcpStream::from(OwnedFd::from(fd))
        } else {
            TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT)?
        };
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        stream.write_all(request.as_bytes())?;
        let mut line = String::new();
        let read = BufReader::new(stream).read_line(&mut line)?;
        if read == 0 {
            return Err(std::io::Error::from_raw_os_error(104));
        }
        Ok(line.trim().to_owned())
    })();
    print(outcome("proxy-http", result, ""));
}

/// Announces this exact agent PID, then waits for the trusted harness to release one operation.
fn barrier(command: &str, ready: &str, go: &str, timeout_secs: u64) {
    let result = wait_at_barrier(ready, go, timeout_secs);
    print(outcome(command, result, ""));
}

fn wait_at_barrier(ready: &str, go: &str, timeout_secs: u64) -> std::io::Result<String> {
    (|| {
        fs::write(ready, format!("{}\n", std::process::id()))?;
        let started = Instant::now();
        while !Path::new(go).exists() {
            if started.elapsed() >= Duration::from_secs(timeout_secs) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "trusted harness did not release the diagnostic barrier",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(format!("released pid={}", std::process::id()))
    })()
}

/// One connection to the proxy: say hello, read the proxy's one-line verdict, optionally hold.
fn hello(stream: &mut TcpStream, i: usize) -> std::io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(format!("HELLO {i}\n").as_bytes())?;
    let mut line = String::new();
    let read = BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    if read == 0 {
        return Err(std::io::Error::from_raw_os_error(104)); // closed without a verdict
    }
    Ok(line.trim().to_owned())
}

fn proxy(count: usize, hold_secs: u64) {
    let workers: Vec<_> = (0..count)
        .map(|i| {
            thread::spawn(move || {
                let connected = TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT);
                let local = connected
                    .as_ref()
                    .ok()
                    .and_then(|s| s.local_addr().ok())
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let result = connected.and_then(|mut stream| {
                    let verdict = hello(&mut stream, i)?;
                    if hold_secs > 0 {
                        thread::sleep(Duration::from_secs(hold_secs));
                    }
                    Ok(verdict)
                });
                print(outcome(
                    "proxy",
                    result,
                    &format!(",\"i\":{i},\"local\":{}", quote(&local)),
                ));
            })
        })
        .collect();
    for worker in workers {
        let _ = worker.join();
    }
}

/// Concurrent proxy connections using a deterministic source-port range. Distinct network
/// namespaces can deliberately reuse the same range to exercise the complete tuple key.
fn proxy_fixed(first_port: u16, count: usize, report: Option<(&str, u64)>) {
    let workers: Vec<_> = (0..count)
        .map(|i| {
            thread::spawn(move || {
                let port = first_port.saturating_add(i as u16);
                let connected = (|| -> std::io::Result<TcpStream> {
                    let fd = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None)
                        .map_err(errno)?;
                    rustix::net::sockopt::set_socket_reuseaddr(&fd, true).map_err(errno)?;
                    rustix::net::bind(&fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
                        .map_err(errno)?;
                    rustix::net::connect(&fd, &PROXY).map_err(errno)?;
                    Ok(TcpStream::from(OwnedFd::from(fd)))
                })();
                let line = match connected {
                    Ok(mut stream) => {
                        let local = stream
                            .local_addr()
                            .map(|address| address.to_string())
                            .unwrap_or_default();
                        outcome(
                            "proxy-fixed",
                            hello(&mut stream, i),
                            &format!(
                                ",\"i\":{i},\"source_port\":{port},\"local\":{},\"status\":\"connected\"",
                                quote(&local)
                            ),
                        )
                    }
                    Err(error) => {
                        let status = if error.kind() == std::io::ErrorKind::TimedOut {
                            "timed_out"
                        } else {
                            "refused"
                        };
                        outcome(
                            "proxy-fixed",
                            Err(error),
                            &format!(
                                ",\"i\":{i},\"source_port\":{port},\"local\":\"\",\"status\":{}",
                                quote(status)
                            ),
                        )
                    }
                };
                print(line.clone());
                line
            })
        })
        .collect();
    let mut outcomes = Vec::with_capacity(count);
    for worker in workers {
        if let Ok(outcome) = worker.join() {
            outcomes.push(outcome);
        }
    }
    if let Some((path, hold_secs)) = report {
        let result = fs::write(path, format!("{}\n", outcomes.join("\n")))
            .map(|()| format!("recorded {} client outcomes", outcomes.len()));
        print(outcome("proxy-fixed-report", result, ""));
        thread::sleep(Duration::from_secs(hold_secs));
    }
}

/// Sequential connections from one fixed source port, closed with FIN or RST.
fn proxy_port(port: u16, rst: bool, count: u64) {
    for i in 0..count {
        let result = (|| -> std::io::Result<(String, String)> {
            let fd = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None)
                .map_err(errno)?;
            rustix::net::sockopt::set_socket_reuseaddr(&fd, true).map_err(errno)?;
            rustix::net::bind(&fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
                .map_err(errno)?;
            rustix::net::connect(&fd, &PROXY).map_err(errno)?;
            if rst {
                rustix::net::sockopt::set_socket_linger(&fd, Some(Duration::ZERO))
                    .map_err(errno)?;
            }
            let mut stream = TcpStream::from(OwnedFd::from(fd));
            let local = stream.local_addr()?.to_string();
            let verdict = hello(&mut stream, i as usize)?;
            Ok((local, verdict))
        })();
        let local = result.as_ref().map(|(l, _)| l.clone()).unwrap_or_default();
        print(outcome(
            "proxy-port",
            result.map(|(_, v)| v),
            &format!(
                ",\"i\":{i},\"close\":{},\"local\":{}",
                quote(if rst { "rst" } else { "fin" }),
                quote(&local)
            ),
        ));
    }
}

fn connect_from_port(port: u16) -> std::io::Result<TcpStream> {
    let fd = socket_from_port(port)?;
    rustix::net::connect(&fd, &PROXY).map_err(errno)?;
    Ok(TcpStream::from(fd))
}

fn socket_from_port(port: u16) -> std::io::Result<OwnedFd> {
    let fd = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).map_err(errno)?;
    rustix::net::sockopt::set_socket_reuseaddr(&fd, true).map_err(errno)?;
    rustix::net::bind(&fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).map_err(errno)?;
    Ok(fd)
}

fn socket_cookie<F: std::os::fd::AsFd>(fd: &F) -> std::io::Result<u64> {
    nix::sys::socket::getsockopt(fd, SocketCookie)
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
}

fn wait_gate(path: &str, timeout_secs: u64) -> std::io::Result<()> {
    let started = Instant::now();
    while !Path::new(path).exists() {
        if started.elapsed() >= Duration::from_secs(timeout_secs) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("qualification gate {path} did not appear"),
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn establish_connect(stream: &mut TcpStream, target: &str) -> std::io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    )?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut status = String::new();
    if reader.read_line(&mut status)? == 0 {
        return Err(std::io::Error::from_raw_os_error(104));
    }
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
    }
    Ok(status.trim().to_owned())
}

fn append_report(path: &str, line: &str) -> std::io::Result<()> {
    let mut output = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(output, "{line}")?;
    output.flush()
}

/// Opens deterministic Candidate-A connections and persists their lifecycle while the process is
/// still alive, so the trusted harness can correlate kernel state with FIN, RST and agent kill.
fn proxy_connect_report(
    target: &str,
    first_port: u16,
    mode: &str,
    report: &str,
    hold_secs: u64,
    count: usize,
) {
    let _ = fs::remove_file(report);
    for index in 0..count {
        let port = first_port.saturating_add(index as u16);
        let started = Instant::now();
        let mut stream = match connect_from_port(port) {
            Ok(stream) => stream,
            Err(error) => {
                let line = outcome(
                    "proxy-connect-report",
                    Err(error),
                    &format!(
                        ",\"i\":{index},\"source_port\":{port},\"mode\":{} ,\"phase\":\"connect\"",
                        quote(mode)
                    ),
                );
                let _ = append_report(report, &line);
                print(line);
                thread::sleep(Duration::from_secs(hold_secs));
                continue;
            }
        };
        let local = stream
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_default();
        let established = establish_connect(&mut stream, target);
        let established_ok = established.is_ok();
        let established_line = outcome(
            "proxy-connect-report",
            established,
            &format!(
                ",\"i\":{index},\"source_port\":{port},\"local\":{},\"proxy_destination\":{},\"mode\":{},\"phase\":\"established\",\"elapsed_ms\":{}",
                quote(&local),
                quote(&PROXY.to_string()),
                quote(mode),
                started.elapsed().as_millis()
            ),
        );
        let _ = append_report(report, &established_line);
        print(established_line);
        if !established_ok {
            thread::sleep(Duration::from_secs(hold_secs));
            continue;
        }
        match mode {
            "fin" => {
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
            "rst" => {
                let _ = rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO));
            }
            "hold" => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(hold_secs)));
                let mut byte = [0_u8; 1];
                let result = match stream.read(&mut byte) {
                    Ok(0) => Ok("proxy closed the tunnel".to_owned()),
                    Ok(read) => Ok(format!("proxy sent {read} byte(s)")),
                    Err(error) => Err(error),
                };
                let line = outcome(
                    "proxy-connect-report",
                    result,
                    &format!(
                        ",\"i\":{index},\"source_port\":{port},\"mode\":\"hold\",\"phase\":\"closed\",\"elapsed_ms\":{}",
                        started.elapsed().as_millis()
                    ),
                );
                let _ = append_report(report, &line);
                print(line);
                thread::sleep(Duration::from_secs(hold_secs));
            }
            "close" => {}
            _ => {
                let line = outcome(
                    "proxy-connect-report",
                    Err(std::io::Error::from_raw_os_error(22)),
                    &format!(",\"mode\":{} ,\"phase\":\"mode\"", quote(mode)),
                );
                let _ = append_report(report, &line);
                print(line);
            }
        }
        drop(stream);
        if mode != "hold" {
            thread::sleep(Duration::from_secs(hold_secs));
        }
    }
}

/// Opens overlapping valid CONNECT tunnels from a deterministic source-port range.
fn proxy_connect_many_report(
    target: &str,
    first_port: u16,
    count: usize,
    report: &str,
    hold_secs: u64,
) {
    let _ = fs::remove_file(report);
    let workers: Vec<_> = (0..count)
        .map(|index| {
            let target = target.to_owned();
            let report = report.to_owned();
            thread::spawn(move || {
                let port = first_port.saturating_add(index as u16);
                let started = Instant::now();
                let result = (|| -> std::io::Result<String> {
                    let mut stream = connect_from_port(port)?;
                    let local = stream.local_addr()?.to_string();
                    let status = establish_connect(&mut stream, &target)?;
                    let line = outcome(
                        "proxy-connect-many-report",
                        Ok(format!("{status}; local={local}")),
                        &format!(
                            ",\"i\":{index},\"source_port\":{port},\"elapsed_ms\":{}",
                            started.elapsed().as_millis()
                        ),
                    );
                    append_report(&report, &line)?;
                    thread::sleep(Duration::from_secs(hold_secs));
                    Ok(line)
                })();
                match result {
                    Ok(line) => line,
                    Err(error) => {
                        let line = outcome(
                            "proxy-connect-many-report",
                            Err(error),
                            &format!(
                                ",\"i\":{index},\"source_port\":{port},\"elapsed_ms\":{}",
                                started.elapsed().as_millis()
                            ),
                        );
                        let _ = append_report(&report, &line);
                        line
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        if let Ok(line) = worker.join() {
            print(line);
        }
    }
}

/// Keeps exactly `count` resolved sockets live, then exposes the next socket's cookie before the
/// harness releases its connect. This makes the production cookie-map-full boundary deterministic.
fn proxy_capacity_report(
    target: &str,
    first_port: u16,
    count: usize,
    report: &str,
    timeout_secs: u64,
) {
    let _ = fs::remove_file(report);
    for suffix in [
        "ready",
        "plus",
        "plus-ready",
        "connect",
        "plus-done",
        "release",
    ] {
        let _ = fs::remove_file(format!("{report}.{suffix}"));
    }
    let result = (|| -> std::io::Result<String> {
        let mut sockets = Vec::with_capacity(count);
        for index in 0..count {
            let port = first_port.saturating_add(index as u16);
            let mut stream = connect_from_port(port)?;
            let cookie = socket_cookie(&stream)?;
            let status = establish_connect(&mut stream, target)?;
            append_report(
                report,
                &format!(
                    "{{\"cmd\":\"proxy-capacity-report\",\"ok\":true,\"phase\":\"base_resolved\",\"i\":{index},\"source_port\":{port},\"cookie\":{cookie},\"detail\":{}}}",
                    quote(&status)
                ),
            )?;
            sockets.push(stream);
        }
        fs::write(format!("{report}.ready"), b"ready\n")?;
        wait_gate(&format!("{report}.plus"), timeout_secs)?;

        let plus_port = first_port.saturating_add(count as u16);
        let fd = socket_from_port(plus_port)?;
        let plus_cookie = socket_cookie(&fd)?;
        append_report(
            report,
            &format!(
                "{{\"cmd\":\"proxy-capacity-report\",\"ok\":true,\"phase\":\"plus_prepared\",\"source_port\":{plus_port},\"cookie\":{plus_cookie}}}"
            ),
        )?;
        fs::write(format!("{report}.plus-ready"), b"ready\n")?;
        wait_gate(&format!("{report}.connect"), timeout_secs)?;
        let started = Instant::now();
        let connected = rustix::net::connect(&fd, &PROXY).map_err(errno);
        let (ok, error, errno) = match connected {
            Ok(()) => {
                let mut stream = TcpStream::from(fd);
                let result = establish_connect(&mut stream, target);
                sockets.push(stream);
                match result {
                    Ok(detail) => (true, detail, 0),
                    Err(error) => (false, error.to_string(), error.raw_os_error().unwrap_or(-1)),
                }
            }
            Err(error) => (false, error.to_string(), error.raw_os_error().unwrap_or(-1)),
        };
        append_report(
            report,
            &format!(
                "{{\"cmd\":\"proxy-capacity-report\",\"ok\":{ok},\"phase\":\"plus_result\",\"source_port\":{plus_port},\"cookie\":{plus_cookie},\"errno\":{errno},\"elapsed_ms\":{},\"detail\":{}}}",
                started.elapsed().as_millis(),
                quote(&error)
            ),
        )?;
        fs::write(format!("{report}.plus-done"), b"done\n")?;
        wait_gate(&format!("{report}.release"), timeout_secs)?;
        drop(sockets);
        Ok(format!(
            "completed {count} base sockets and one capacity probe"
        ))
    })();
    print(outcome("proxy-capacity-report", result, ""));
}

/// Binds one socket and publishes its nonzero cookie before the harness injects a duplicate key.
fn proxy_preconnect_report(target: &str, port: u16, report: &str, timeout_secs: u64) {
    let _ = fs::remove_file(report);
    for suffix in ["ready", "connect", "done", "release"] {
        let _ = fs::remove_file(format!("{report}.{suffix}"));
    }
    let result = (|| -> std::io::Result<String> {
        let fd = socket_from_port(port)?;
        let cookie = socket_cookie(&fd)?;
        if cookie == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SO_COOKIE returned zero",
            ));
        }
        append_report(
            report,
            &format!(
                "{{\"cmd\":\"proxy-preconnect-report\",\"ok\":true,\"phase\":\"prepared\",\"source_port\":{port},\"cookie\":{cookie}}}"
            ),
        )?;
        fs::write(format!("{report}.ready"), b"ready\n")?;
        wait_gate(&format!("{report}.connect"), timeout_secs)?;
        let started = Instant::now();
        let connected = rustix::net::connect(&fd, &PROXY).map_err(errno);
        let (ok, detail, errno) = match connected {
            Ok(()) => {
                let mut stream = TcpStream::from(fd);
                match establish_connect(&mut stream, target) {
                    Ok(detail) => (true, detail, 0),
                    Err(error) => (false, error.to_string(), error.raw_os_error().unwrap_or(-1)),
                }
            }
            Err(error) => (false, error.to_string(), error.raw_os_error().unwrap_or(-1)),
        };
        append_report(
            report,
            &format!(
                "{{\"cmd\":\"proxy-preconnect-report\",\"ok\":{ok},\"phase\":\"connect_result\",\"source_port\":{port},\"cookie\":{cookie},\"errno\":{errno},\"elapsed_ms\":{},\"detail\":{}}}",
                started.elapsed().as_millis(),
                quote(&detail)
            ),
        )?;
        fs::write(format!("{report}.done"), b"done\n")?;
        wait_gate(&format!("{report}.release"), timeout_secs)?;
        Ok("duplicate-cookie probe completed".to_owned())
    })();
    print(outcome("proxy-preconnect-report", result, ""));
}

/// Holds the first socket until the harness has installed and observed a cookie-mismatched tuple,
/// then reuses the same source port only after the harness removes that owned injection.
fn proxy_reuse_report(target: &str, port: u16, report: &str, timeout_secs: u64, hold_secs: u64) {
    let _ = fs::remove_file(report);
    let close_gate = format!("{report}.close");
    let second_gate = format!("{report}.second");
    let first_closed = format!("{report}.first-closed");
    let _ = fs::remove_file(&close_gate);
    let _ = fs::remove_file(&second_gate);
    let _ = fs::remove_file(&first_closed);
    let wait = |path: &str| -> std::io::Result<()> {
        let started = Instant::now();
        while !Path::new(path).exists() {
            if started.elapsed() >= Duration::from_secs(timeout_secs) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("qualification gate {path} did not appear"),
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    };
    let first = (|| -> std::io::Result<String> {
        let mut stream = connect_from_port(port)?;
        let status = establish_connect(&mut stream, target)?;
        append_report(
            report,
            &format!(
                "{{\"cmd\":\"proxy-reuse-report\",\"ok\":true,\"iteration\":1,\"phase\":\"established\",\"source_port\":{port},\"detail\":{}}}",
                quote(&status)
            ),
        )?;
        wait(&close_gate)?;
        drop(stream);
        fs::write(&first_closed, b"closed\n")?;
        wait(&second_gate)?;
        let mut second = connect_from_port(port)?;
        let second_status = establish_connect(&mut second, target)?;
        append_report(
            report,
            &format!(
                "{{\"cmd\":\"proxy-reuse-report\",\"ok\":true,\"iteration\":2,\"phase\":\"established\",\"source_port\":{port},\"detail\":{}}}",
                quote(&second_status)
            ),
        )?;
        Ok(format!("{status}; {second_status}"))
    })();
    print(outcome("proxy-reuse-report", first, ""));
    thread::sleep(Duration::from_secs(hold_secs));
}

fn hold_proxy(secs: u64) {
    let started = Instant::now();
    let result = (|| -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT)?;
        let verdict = hello(&mut stream, 0)?;
        stream.set_read_timeout(Some(Duration::from_secs(secs)))?;
        let mut buffer = [0_u8; 64];
        let how = match stream.read(&mut buffer) {
            Ok(0) => "peer closed".to_owned(),
            Ok(n) => format!("peer sent {n} bytes"),
            Err(error) => format!("read ended: {error}"),
        };
        Ok(format!("{verdict}; {how}"))
    })();
    print(outcome(
        "hold-proxy",
        result,
        &format!(",\"held_ms\":{}", started.elapsed().as_millis()),
    ));
}

fn direct(target: SocketAddrV4) -> std::io::Result<String> {
    TcpStream::connect_timeout(&SocketAddr::V4(target), CONNECT_TIMEOUT).map(|_| "connected".into())
}

fn listen4_once(target: SocketAddrV4, timeout_ms: u64) -> std::io::Result<String> {
    let listener = TcpListener::bind(target)?;
    listener.set_nonblocking(true)?;
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                drop(stream);
                return Ok(format!("accepted {peer}"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= Duration::from_millis(timeout_ms) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "listener accepted no connection",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
}

fn listen4_hold(target: SocketAddrV4, hold_secs: u64) -> std::io::Result<String> {
    let listener = TcpListener::bind(target)?;
    let (stream, peer) = listener.accept()?;
    thread::sleep(Duration::from_secs(hold_secs));
    drop(stream);
    Ok(format!("accepted {peer} and held {hold_secs}s"))
}

/// Accepts a tunnel, proves one application byte crossed it in both directions, then keeps the
/// connection open so helper-loss diagnostics can distinguish traffic from mere TCP liveness.
fn listen4_pulse_hold(target: SocketAddrV4, hold_secs: u64) -> std::io::Result<String> {
    let listener = TcpListener::bind(target)?;
    let (mut stream, peer) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte)?;
    stream.write_all(&byte)?;
    print(format!(
        "{{\"event\":\"application_pulse_echoed\",\"peer\":{},\"byte\":{}}}",
        quote(&peer.to_string()),
        byte[0]
    ));
    thread::sleep(Duration::from_secs(hold_secs));
    Ok(format!(
        "accepted {peer}, echoed one application byte, and held {hold_secs}s"
    ))
}

fn direct_flood(target: SocketAddrV4, count: u64, report: Option<&str>, hold_secs: u64) {
    let mut by_errno: std::collections::BTreeMap<i32, u64> = Default::default();
    let started = Instant::now();
    for _ in 0..count {
        let code = match TcpStream::connect_timeout(&SocketAddr::V4(target), CONNECT_TIMEOUT) {
            Ok(_) => 0,
            Err(error) => error.raw_os_error().unwrap_or(-1),
        };
        *by_errno.entry(code).or_default() += 1;
    }
    let counts: Vec<String> = by_errno
        .iter()
        .map(|(k, v)| format!("\"{k}\":{v}"))
        .collect();
    let line = format!(
        "{{\"cmd\":\"direct-flood\",\"attempts\":{count},\"by_errno\":{{{}}},\"ms\":{}}}",
        counts.join(","),
        started.elapsed().as_millis()
    );
    if let Some(path) = report {
        let _ = fs::write(path, format!("{line}\n"));
    }
    print(line);
    thread::sleep(Duration::from_secs(hold_secs));
}

fn sock(family: &str, kind: &str) -> std::io::Result<String> {
    let family = match family {
        "inet" => AddressFamily::INET,
        "inet6" => AddressFamily::INET6,
        "packet" => AddressFamily::PACKET,
        "netlink" => AddressFamily::NETLINK,
        "unix" => AddressFamily::UNIX,
        _ => return Err(std::io::Error::from_raw_os_error(22)),
    };
    let kind = match kind {
        "stream" => SocketType::STREAM,
        "dgram" => SocketType::DGRAM,
        "raw" => SocketType::RAW,
        _ => return Err(std::io::Error::from_raw_os_error(22)),
    };
    rustix::net::socket(family, kind, None)
        .map(|_| "created".to_owned())
        .map_err(errno)
}

fn udp4(target: SocketAddrV4, connected: bool) -> std::io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    if connected {
        socket.connect(target)?;
        socket.send(b"probe")?;
        return Ok("connected and sent".into());
    }
    socket.send_to(b"probe", target)?;
    Ok("sent".into())
}

fn udp6(target: &str) -> std::io::Result<String> {
    let target: SocketAddrV6 = target
        .parse()
        .map_err(|_| std::io::Error::from_raw_os_error(22))?;
    let socket = UdpSocket::bind("[::]:0")?;
    socket.send_to(b"probe", target)?;
    Ok("sent".into())
}

fn tcp6(target: &str) -> std::io::Result<String> {
    let target: SocketAddrV6 = target
        .parse()
        .map_err(|_| std::io::Error::from_raw_os_error(22))?;
    TcpStream::connect_timeout(&SocketAddr::V6(target), CONNECT_TIMEOUT).map(|_| "connected".into())
}

fn mapped(target: SocketAddrV4) -> std::io::Result<String> {
    let v6 = SocketAddrV6::new(target.ip().to_ipv6_mapped(), target.port(), 0, 0);
    TcpStream::connect_timeout(&SocketAddr::V6(v6), CONNECT_TIMEOUT).map(|_| "connected".into())
}

/// Opens a NETLINK_ROUTE socket and asks the kernel to add a route: creating the socket needs no
/// privilege, changing the routing table needs CAP_NET_ADMIN in the namespace.
fn netlink_route(command: &str) {
    // rustix spells NETLINK_ROUTE, the default netlink protocol, as `None`.
    let created = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None);
    let fd = match created {
        Ok(fd) => fd,
        Err(error) => {
            print(outcome(command, Err(errno(error)), ",\"stage\":\"socket\""));
            return;
        }
    };
    let mut message: Vec<u8> = Vec::new();
    let length: u32 = 16 + 12 + 8 + 8;
    message.extend_from_slice(&length.to_ne_bytes());
    message.extend_from_slice(&24_u16.to_ne_bytes()); // RTM_NEWROUTE
    message.extend_from_slice(&(0x1_u16 | 0x4 | 0x400 | 0x200).to_ne_bytes()); // REQUEST|ACK|CREATE|EXCL
    message.extend_from_slice(&1_u32.to_ne_bytes()); // seq
    message.extend_from_slice(&0_u32.to_ne_bytes()); // pid
    message.extend_from_slice(&[2, 32, 0, 0, 254, 3, 253, 1]); // AF_INET /32 main boot link unicast
    message.extend_from_slice(&0_u32.to_ne_bytes()); // rtm_flags
    message.extend_from_slice(&8_u16.to_ne_bytes());
    message.extend_from_slice(&1_u16.to_ne_bytes()); // RTA_DST
    message.extend_from_slice(&[11, 0, 0, 9]);
    message.extend_from_slice(&8_u16.to_ne_bytes());
    message.extend_from_slice(&4_u16.to_ne_bytes()); // RTA_OIF
    message.extend_from_slice(&1_u32.to_ne_bytes()); // lo
    if let Err(error) = rustix::net::send(&fd, &message, rustix::net::SendFlags::empty()) {
        print(outcome(command, Err(errno(error)), ",\"stage\":\"send\""));
        return;
    }
    let mut buffer = [0_u8; 256];
    match rustix::net::recv(&fd, &mut buffer, rustix::net::RecvFlags::empty()) {
        Ok((read, _)) if read >= 20 => {
            let kind = u16::from_ne_bytes([buffer[4], buffer[5]]);
            let code = i32::from_ne_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
            let result = if kind == 2 && code != 0 {
                Err(std::io::Error::from_raw_os_error(-code))
            } else {
                Ok(format!("kernel answered type {kind} code {code}"))
            };
            print(outcome(command, result, ",\"stage\":\"ack\""));
        }
        Ok(_) => print(outcome(
            command,
            Err(std::io::Error::from_raw_os_error(71)),
            ",\"stage\":\"ack\"",
        )),
        Err(error) => print(outcome(command, Err(errno(error)), ",\"stage\":\"recv\"")),
    }
}

fn unix() -> std::io::Result<String> {
    let (mut a, mut b) = std::os::unix::net::UnixStream::pair()?;
    a.write_all(b"x")?;
    let mut one = [0_u8; 1];
    b.read_exact(&mut one)?;
    Ok("socketpair works".into())
}

/// HTTP for the Phase-0 runtime: one command per request body.
fn serve() {
    let port = std::env::var("AGENT_PORT").unwrap_or_else(|_| "8080".into());
    let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{port}")) else {
        return;
    };
    for stream in listener.incoming().flatten() {
        thread::spawn(move || answer(stream));
    }
}

fn answer(mut stream: TcpStream) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut length = 0_usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0_u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let command = String::from_utf8_lossy(&body).to_string();
    let words: Vec<&str> = command.split_whitespace().collect();
    let result = match words.first().copied() {
        // `tunnel <host:port> <secs>`: CONNECT through the Soglia egress proxy and hold it.
        Some("tunnel") => tunnel(
            words.get(1).copied().unwrap_or(""),
            words.get(2).and_then(|s| s.parse().ok()).unwrap_or(30),
        ),
        Some("delayed-tunnel") => {
            let delay = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            thread::sleep(Duration::from_millis(delay));
            tunnel(
                words.get(2).copied().unwrap_or(""),
                words.get(3).and_then(|s| s.parse().ok()).unwrap_or(30),
            )
        }
        Some("delayed-tunnel-pulse") => {
            let delay = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            thread::sleep(Duration::from_millis(delay));
            tunnel_pulse(
                words.get(2).copied().unwrap_or(""),
                words.get(3).and_then(|s| s.parse().ok()).unwrap_or(0),
                words.get(4).and_then(|s| s.parse().ok()).unwrap_or(30),
            )
        }
        Some("sleep") => {
            let millis = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            thread::sleep(Duration::from_millis(millis));
            format!("{{\"slept_ms\":{millis}}}")
        }
        Some("proxy-fixed-report") => {
            let first_port = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(40_000);
            let count = words.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
            let report = words.get(3).copied().unwrap_or("/tmp/proxy-fixed.jsonl");
            let hold_secs = words.get(4).and_then(|s| s.parse().ok()).unwrap_or(10);
            proxy_fixed(first_port, count, Some((report, hold_secs)));
            format!("{{\"proxy_fixed_count\":{count}}}")
        }
        Some("b7-churn-report") => {
            let target = words.get(1).copied().unwrap_or("allowed.test:443");
            let count = words.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
            let report = words.get(3).copied().unwrap_or("/tmp/b7-churn.json");
            b7_churn_report(target, count, report)
        }
        Some("b7-rate-report") => {
            let target = words.get(1).copied().unwrap_or("allowed.test:443");
            let rate = words.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
            let duration = words.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
            let report = words.get(4).copied().unwrap_or("/tmp/b7-rate.json");
            b7_rate_report(target, rate, duration, report)
        }
        Some("delayed-b7-live-report") => {
            let delay_ms = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(30_000);
            let target = words.get(2).copied().unwrap_or("allowed.test:443");
            let count = words.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
            let hold_secs = words.get(4).and_then(|s| s.parse().ok()).unwrap_or(3);
            let report = words.get(5).copied().unwrap_or("/tmp/b7-live.json");
            thread::sleep(Duration::from_millis(delay_ms));
            b7_live_report(target, count, hold_secs, report)
        }
        Some("b7-burst-report") => {
            let target = words.get(1).copied().unwrap_or("allowed.test:443");
            let count = words.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
            let report = words.get(3).copied().unwrap_or("/tmp/b7-burst.json");
            b7_burst_report(target, count, report)
        }
        Some("delayed-proxy-fixed-report") => {
            let delay_ms = words.get(1).and_then(|s| s.parse().ok()).unwrap_or(3_000);
            let first_port = words.get(2).and_then(|s| s.parse().ok()).unwrap_or(40_000);
            let count = words.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
            let report = words.get(4).copied().unwrap_or("/tmp/proxy-fixed.jsonl");
            let hold_secs = words.get(5).and_then(|s| s.parse().ok()).unwrap_or(10);
            thread::sleep(Duration::from_millis(delay_ms));
            proxy_fixed(first_port, count, Some((report, hold_secs)));
            format!("{{\"proxy_fixed_count\":{count},\"continued\":true}}")
        }
        _ => format!("{{\"unknown\":{}}}", quote(&command)),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{result}",
        result.len()
    );
}

/// Runs a bounded sequence of complete proxy handshakes and emits aggregate, non-secret
/// qualification measurements. The production proxy and Candidate-A resolver remain unchanged.
fn b7_churn_report(target: &str, count: usize, report: &str) -> String {
    b7_connection_workload(target, count, None, report, "churn")
}

/// Runs complete proxy handshakes at a monotonic-clock rate for the declared B7 interval.
fn b7_rate_report(target: &str, rate: usize, duration_secs: u64, report: &str) -> String {
    let count = rate.saturating_mul(duration_secs as usize);
    b7_connection_workload(target, count, Some(rate), report, "rate")
}

fn b7_live_report(target: &str, count: usize, hold_secs: u64, report: &str) -> String {
    let started = Instant::now();
    let mut sockets = Vec::with_capacity(count);
    let mut failed = 0_usize;
    let mut latencies = Vec::with_capacity(count);
    for _ in 0..count {
        let attempt = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT)
            .and_then(|mut stream| establish_connect(&mut stream, target).map(|_| stream))
        {
            Ok(stream) => sockets.push(stream),
            Err(_) => failed += 1,
        }
        latencies.push(u64::try_from(attempt.elapsed().as_micros()).unwrap_or(u64::MAX));
    }
    let value = format!(
        "{{\"kind\":\"live\",\"requested\":{count},\"succeeded\":{},\"failed\":{failed},\"elapsed_ms\":{},\"max_us\":{}}}",
        sockets.len(),
        started.elapsed().as_millis(),
        latencies.into_iter().max().unwrap_or(0)
    );
    let _ = fs::write(report, format!("{value}\n"));
    thread::sleep(Duration::from_secs(hold_secs));
    value
}

fn b7_burst_report(target: &str, count: usize, report: &str) -> String {
    let started = Instant::now();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    // Open every socket before sending or reading application bytes.  This makes all requests
    // simultaneously live without consuming one task from the Execution's pids.max per socket.
    let mut streams: Vec<(Instant, TcpStream, bool)> = Vec::with_capacity(count);
    for _ in 0..count {
        let attempt = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT) {
            Ok(stream) => streams.push((attempt, stream, false)),
            Err(_) => {}
        }
    }
    for (_, stream, written) in &mut streams {
        *written = stream.write_all(request.as_bytes()).is_ok();
    }
    let mut succeeded = 0_usize;
    let mut max_us = 0_u64;
    for (attempt, stream, written) in streams {
        let result = (|| -> std::io::Result<()> {
            if !written {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "burst request write failed",
                ));
            }
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut reader = BufReader::new(stream);
            let mut status = String::new();
            if reader.read_line(&mut status)? == 0 {
                return Err(std::io::Error::from_raw_os_error(104));
            }
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                    break;
                }
            }
            if !status.contains(" 200 ") {
                return Err(std::io::Error::other(status.trim().to_owned()));
            }
            Ok(())
        })();
        max_us = max_us.max(
            u64::try_from(attempt.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        if result.is_ok() {
            succeeded += 1;
        } else {
        }
    }
    let failed = count.saturating_sub(succeeded);
    let value = format!(
        "{{\"kind\":\"burst\",\"strategy\":\"open-all-write-all-read-all\",\"requested\":{count},\"succeeded\":{succeeded},\"failed\":{failed},\"elapsed_ms\":{},\"max_us\":{max_us}}}",
        started.elapsed().as_millis()
    );
    let _ = fs::write(report, format!("{value}\n"));
    value
}

fn b7_connection_workload(
    target: &str,
    count: usize,
    rate: Option<usize>,
    report: &str,
    kind: &str,
) -> String {
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(count);
    let mut succeeded = 0_usize;
    let mut failed = 0_usize;
    for index in 0..count {
        if let Some(rate) = rate.filter(|rate| *rate > 0) {
            let due = Duration::from_secs_f64(index as f64 / rate as f64);
            if let Some(delay) = due.checked_sub(started.elapsed()) {
                thread::sleep(delay);
            }
        }
        let attempt = Instant::now();
        let result = TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT)
            .and_then(|mut stream| establish_connect(&mut stream, target));
        latencies.push(u64::try_from(attempt.elapsed().as_micros()).unwrap_or(u64::MAX));
        if result.is_ok() {
            succeeded += 1;
        } else {
            failed += 1;
        }
    }
    latencies.sort_unstable();
    let percentile = |numerator: usize| -> u64 {
        if latencies.is_empty() {
            return 0;
        }
        let index = (latencies.len().saturating_sub(1) * numerator) / 100;
        latencies[index]
    };
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let value = format!(
        "{{\"kind\":{},\"requested\":{count},\"succeeded\":{succeeded},\"failed\":{failed},\"elapsed_ms\":{elapsed_ms},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"max_us\":{}}}",
        quote(kind),
        percentile(50),
        percentile(95),
        percentile(99),
        latencies.last().copied().unwrap_or(0)
    );
    let _ = fs::write(report, format!("{value}\n"));
    value
}

fn tunnel(target: &str, secs: u64) -> String {
    let started = Instant::now();
    let result = (|| -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT)?;
        write!(
            stream,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut status = String::new();
        reader.read_line(&mut status)?;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                break;
            }
        }
        stream.set_read_timeout(Some(Duration::from_secs(secs)))?;
        let mut buffer = [0_u8; 64];
        let how = match stream.read(&mut buffer) {
            Ok(0) => "tunnel closed by the proxy".to_owned(),
            Ok(n) => format!("tunnel carried {n} bytes"),
            Err(error) => format!("tunnel read ended: {error}"),
        };
        Ok(format!("{}; {how}", status.trim()))
    })();
    outcome(
        "tunnel",
        result,
        &format!(",\"held_ms\":{}", started.elapsed().as_millis()),
    )
}

fn tunnel_pulse(target: &str, pulse_delay_ms: u64, secs: u64) -> String {
    let started = Instant::now();
    let result = (|| -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(PROXY), CONNECT_TIMEOUT)?;
        write!(
            stream,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut status = String::new();
        reader.read_line(&mut status)?;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                break;
            }
        }
        thread::sleep(Duration::from_millis(pulse_delay_ms));
        stream.write_all(b"P")?;
        let mut echoed = [0_u8; 1];
        stream.read_exact(&mut echoed)?;
        if echoed != *b"P" {
            return Err(std::io::Error::other(
                "the tunnel returned the wrong pulse byte",
            ));
        }
        stream.set_read_timeout(Some(Duration::from_secs(secs)))?;
        let mut buffer = [0_u8; 64];
        let how = match stream.read(&mut buffer) {
            Ok(0) => "tunnel closed by the peer".to_owned(),
            Ok(n) => format!("tunnel carried {n} more bytes"),
            Err(error) => format!("tunnel read ended: {error}"),
        };
        Ok(format!(
            "{}; post-delay application pulse echoed; {how}",
            status.trim()
        ))
    })();
    outcome(
        "tunnel-pulse",
        result,
        &format!(",\"held_ms\":{}", started.elapsed().as_millis()),
    )
}
