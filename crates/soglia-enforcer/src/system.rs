// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The host operations the enforcer performs: running `ip` and `nft`, entering a network namespace,
//! and reading and writing network sysctls.
//!
//! Executables are run by absolute path with an empty environment, never through a shell, so no
//! argument is ever interpreted by anything but the program it was written for.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

/// Where `ip netns` keeps its namespaces.
pub const NETNS_DIR: &str = "/run/netns";

/// Runs `program` with `args`, feeding `stdin` if given, and returns its standard output.
pub fn run(program: &Path, args: &[&str], stdin: Option<&str>) -> io::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", program.display())))?;

    if let Some(input) = stdin
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(input.as_bytes())?;
        // Dropping the pipe closes it, so the program sees the end of its input.
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    Err(io::Error::other(format!(
        "{} {} failed ({}): {}",
        program.display(),
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Runs `work` on a thread that has entered the network namespace `name`.
///
/// Only that thread changes namespace, and it ends with `work`, so the enforcer itself never
/// leaves the host namespace. A program `work` starts inherits the thread's namespace.
pub fn in_netns<T, F>(name: &str, work: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send,
    T: Send,
{
    let path = netns_path(name);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let namespace = File::open(&path)?;
                move_into_link_name_space(namespace.as_fd(), Some(LinkNameSpaceType::Network))?;
                work()
            })
            .join()
            .map_err(|_| io::Error::other("the namespace worker panicked"))?
    })
}

/// The bind mount `ip netns` keeps for the namespace `name`.
pub fn netns_path(name: &str) -> PathBuf {
    Path::new(NETNS_DIR).join(name)
}

/// `true` while a network interface of this name exists in the enforcer's namespace.
pub fn interface_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

/// `true` while the named network namespace is still mounted.
pub fn netns_exists(name: &str) -> bool {
    netns_path(name).exists()
}

/// The entries of `directory` whose name starts with `prefix`.
pub fn entries_with_prefix(directory: &Path, prefix: &str) -> io::Result<Vec<String>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut names = Vec::new();
    for entry in entries {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with(prefix) {
            names.push(name);
        }
    }
    names.sort();

    Ok(names)
}

/// Sets a network sysctl in the calling thread's namespace and reads it back.
///
/// A missing entry is reported as `Ok(false)`: for IPv6 it means the kernel offers no IPv6 at all,
/// which is the outcome disabling it is for.
pub fn set_sysctl(path: &str, value: &str) -> io::Result<bool> {
    let full = Path::new("/proc/sys").join(path);
    match fs::write(&full, value) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("{}: {error}", full.display()),
            ));
        }
    }
    let read = fs::read_to_string(&full)?;
    if read.trim() != value {
        return Err(io::Error::other(format!(
            "{} reads {:?} after being set to {value:?}",
            full.display(),
            read.trim()
        )));
    }

    Ok(true)
}

/// `true` when the process runs with an effective uid of 0.
pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}
