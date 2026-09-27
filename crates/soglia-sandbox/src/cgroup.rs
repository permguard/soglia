// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The cgroup v2 subtree delegated to Soglia, and the Execution cgroups inside it.
//!
//! Soglia never creates a top-level cgroup that competes with systemd. It works inside a subtree
//! delegated to it — a systemd unit or scope with `Delegate=yes`, or the cgroup namespace root of a
//! development container — and it verifies at startup that the delegation and every controller it
//! needs are really there, failing closed otherwise.
//!
//! cgroup v2 lets a cgroup with controllers enabled for its children hold no processes itself, so
//! Soglia's own processes move to a `runtime` leaf and every Execution gets a cgroup under
//! `executions`:
//!
//! ```text
//! <delegated root>/
//!   runtime/            Soglia's own processes
//!   executions/
//!     <tag>/            one Execution
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

/// Where the cgroup v2 hierarchy is mounted.
pub const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// The delegated subtree.
#[derive(Debug, Clone)]
pub struct Delegation {
    root: PathBuf,
}

impl Delegation {
    /// The configured root, or the cgroup this process runs in.
    pub fn discover(configured: Option<&Path>) -> io::Result<Self> {
        let root = match configured {
            Some(root) => root.to_path_buf(),
            None => {
                let membership = fs::read_to_string("/proc/self/cgroup")?;
                let path = membership
                    .lines()
                    .find_map(|line| line.strip_prefix("0::"))
                    .ok_or_else(|| {
                        io::Error::other("this process is not in a cgroup v2 hierarchy")
                    })?;
                // After a previous start moved Soglia into its `runtime` leaf, the delegated root
                // is that leaf's parent.
                let path = path.strip_suffix("/runtime").unwrap_or(path);
                Path::new(CGROUP_MOUNT).join(path.trim_start_matches('/'))
            }
        };
        if !root.starts_with(CGROUP_MOUNT) {
            return Err(io::Error::other(format!(
                "{} is not inside {CGROUP_MOUNT}",
                root.display()
            )));
        }

        Ok(Self { root })
    }

    /// The delegated root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The parent of every Execution cgroup.
    pub fn executions(&self) -> PathBuf {
        self.root.join("executions")
    }

    /// The cgroup of one Execution.
    pub fn execution(&self, tag: &str) -> PathBuf {
        self.executions().join(tag)
    }

    /// An Execution cgroup as the OCI runtime names it: relative to the cgroup mount.
    pub fn oci_path(&self, tag: &str) -> String {
        let relative = self
            .execution(tag)
            .strip_prefix(CGROUP_MOUNT)
            .map(Path::to_path_buf)
            .unwrap_or_default();
        format!("/{}", relative.display())
    }

    /// Verifies the delegation, moves Soglia's processes into the `runtime` leaf and enables the
    /// `required` controllers for Executions. Fails closed on anything missing.
    pub fn prepare(&self, required: &[&str]) -> io::Result<()> {
        let available =
            fs::read_to_string(self.root.join("cgroup.controllers")).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "{} is not a usable cgroup v2 directory: {error}",
                        self.root.display()
                    ),
                )
            })?;
        let available: Vec<&str> = available.split_whitespace().collect();
        let missing: Vec<&&str> = required
            .iter()
            .filter(|controller| !available.contains(controller))
            .collect();
        if !missing.is_empty() {
            return Err(io::Error::other(format!(
                "the delegated cgroup {} lacks the controllers {missing:?}; delegate them to Soglia",
                self.root.display()
            )));
        }

        // Every process in the delegated root belongs to Soglia's unit: move them to the leaf.
        let runtime = self.root.join("runtime");
        create_dir(&runtime)?;
        let procs = fs::read_to_string(self.root.join("cgroup.procs"))?;
        for pid in procs.split_whitespace() {
            match fs::write(runtime.join("cgroup.procs"), pid) {
                // A process that exited meanwhile has nothing left to move.
                Err(error) if error.raw_os_error() == Some(3) => {}
                other => other?,
            }
        }

        let enable: String = required
            .iter()
            .map(|controller| format!("+{controller} "))
            .collect();
        fs::write(self.root.join("cgroup.subtree_control"), enable.trim()).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot enable {required:?} below {}: {error}; is the subtree delegated to Soglia?",
                    self.root.display()
                ),
            )
        })?;
        create_dir(&self.executions())?;
        fs::write(
            self.executions().join("cgroup.subtree_control"),
            enable.trim(),
        )?;

        // cgroup.kill is how an Execution is destroyed as a whole; without it there is no teardown
        // Soglia can verify.
        let probe = self.executions().join(".probe");
        create_dir(&probe)?;
        let has_kill = probe.join("cgroup.kill").exists();
        fs::remove_dir(&probe)?;
        if !has_kill {
            return Err(io::Error::other(
                "this kernel has no cgroup.kill (Linux 5.14 or later is required)",
            ));
        }

        Ok(())
    }
}

/// `true` while the cgroup exists.
pub fn exists(cgroup: &Path) -> bool {
    cgroup.join("cgroup.procs").exists()
}

/// Freezes and then kills every process in `cgroup`, and waits until none is left.
pub fn kill(cgroup: &Path, deadline: Duration) -> io::Result<()> {
    if !exists(cgroup) {
        return Ok(());
    }
    // Freezing first stops the processes from forking while they are being killed.
    fs::write(cgroup.join("cgroup.freeze"), "1")?;
    fs::write(cgroup.join("cgroup.kill"), "1")?;
    wait_until_empty(cgroup, deadline)
}

/// Waits until `cgroup` holds no process, or fails at `deadline`.
pub fn wait_until_empty(cgroup: &Path, deadline: Duration) -> io::Result<()> {
    let started = Instant::now();
    loop {
        if !exists(cgroup) || !populated(cgroup)? {
            return Ok(());
        }
        if started.elapsed() >= deadline {
            return Err(io::Error::other(format!(
                "{} still holds processes after {deadline:?}",
                cgroup.display()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Removes an empty `cgroup` and verifies that it is gone. An absent cgroup is not an error.
pub fn remove(cgroup: &Path) -> io::Result<()> {
    match fs::remove_dir(cgroup) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(io::Error::new(
                error.kind(),
                format!("cannot remove {}: {error}", cgroup.display()),
            ));
        }
        _ => {}
    }
    if cgroup.exists() {
        return Err(io::Error::other(format!(
            "{} still exists",
            cgroup.display()
        )));
    }

    Ok(())
}

/// A counter from a flat `key value` file such as `memory.events`.
pub fn counter(cgroup: &Path, file: &str, key: &str) -> u64 {
    fs::read_to_string(cgroup.join(file))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let (name, value) = line.split_once(' ')?;
                (name == key).then(|| value.trim().parse().ok()).flatten()
            })
        })
        .unwrap_or(0)
}

fn populated(cgroup: &Path) -> io::Result<bool> {
    let events = fs::read_to_string(cgroup.join("cgroup.events"))?;
    Ok(events.lines().any(|line| line == "populated 1"))
}

fn create_dir(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_root_must_be_inside_the_cgroup_mount() {
        assert!(Delegation::discover(Some(Path::new("/tmp/soglia"))).is_err());
        let delegation = Delegation::discover(Some(Path::new(
            "/sys/fs/cgroup/soglia.slice/soglia.service",
        )))
        .unwrap();
        assert_eq!(
            delegation.execution("0123456789"),
            Path::new("/sys/fs/cgroup/soglia.slice/soglia.service/executions/0123456789")
        );
        assert_eq!(
            delegation.oci_path("0123456789"),
            "/soglia.slice/soglia.service/executions/0123456789"
        );
    }

    #[test]
    fn counters_are_read_from_flat_keyed_files() {
        let directory = std::env::temp_dir().join(format!("soglia-cgroup-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("memory.events"),
            "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n",
        )
        .unwrap();
        assert_eq!(counter(&directory, "memory.events", "oom_kill"), 1);
        assert_eq!(counter(&directory, "memory.events", "max"), 3);
        assert_eq!(counter(&directory, "memory.events", "absent"), 0);
        assert_eq!(counter(&directory, "missing.events", "max"), 0);
        fs::remove_dir_all(&directory).unwrap();
    }
}
