// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde::Serialize;

#[derive(Serialize)]
struct ReadyRecord {
    cgroup_relative: String,
    cgroup_root: String,
    runtime_leaf: String,
    pid: u32,
    subtree_control: String,
}

pub fn run(ready: &Path) -> Result<(), String> {
    let relative = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("read /proc/self/cgroup: {error}"))?
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("unified cgroup membership missing")?
        .to_owned();
    let root = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let runtime = root.join("runtime");
    fs::create_dir(&runtime).map_err(|error| format!("create {}: {error}", runtime.display()))?;
    fs::write(
        runtime.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .map_err(|error| format!("move helper into runtime leaf: {error}"))?;
    fs::write(root.join("cgroup.subtree_control"), b"+memory +pids\n")
        .map_err(|error| format!("enable delegated controllers: {error}"))?;
    let subtree_control = fs::read_to_string(root.join("cgroup.subtree_control"))
        .map_err(|error| format!("read delegated controllers: {error}"))?;
    let record = ReadyRecord {
        cgroup_relative: relative,
        cgroup_root: root.to_string_lossy().into_owned(),
        runtime_leaf: runtime.to_string_lossy().into_owned(),
        pid: std::process::id(),
        subtree_control,
    };
    let bytes = serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?;
    fs::write(ready, bytes).map_err(|error| format!("publish {}: {error}", ready.display()))?;
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
