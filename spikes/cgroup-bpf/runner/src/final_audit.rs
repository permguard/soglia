// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::command::{CommandExecutor, CommandSpec};
use crate::resources::{Resource, ResourceRegistry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAudit {
    pub sequence: Option<u64>,
    pub owner: String,
    pub resource: String,
    pub registry_marked_cleaned: bool,
    pub cleanup_satisfied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalCleanupObservation {
    pub run_id: String,
    pub runtime_root: PathBuf,
    pub bpffs_root: PathBuf,
    pub registry_entries: usize,
    pub registry_live_entries: usize,
    pub root_cleanup_attempts: Vec<String>,
    pub checks: Vec<ResourceAudit>,
    pub pass: bool,
    pub detail: String,
}

pub fn audit(
    commands: &CommandExecutor,
    resources: &ResourceRegistry,
    run_id: &str,
) -> FinalCleanupObservation {
    let runtime_root = Path::new("/run/soglia-spike-runner").join(run_id);
    let bpffs_root = Path::new("/sys/fs/bpf/soglia-spike-runner").join(run_id);
    let root_cleanup_attempts = [&runtime_root, &bpffs_root]
        .into_iter()
        .map(|path| match std::fs::remove_dir(path) {
            Ok(()) => format!("removed empty exact run root {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                format!("exact run root already absent {}", path.display())
            }
            Err(error) => format!(
                "exact non-recursive run root removal {} failed: {error}",
                path.display()
            ),
        })
        .collect::<Vec<_>>();
    let mut checks = resources
        .entries()
        .iter()
        .map(|entry| {
            let (cleanup_satisfied, detail) = resource_clean(commands, &entry.resource);
            ResourceAudit {
                sequence: Some(entry.sequence),
                owner: entry.owner.clone(),
                resource: format!("{:?}", entry.resource),
                registry_marked_cleaned: entry.cleaned,
                cleanup_satisfied,
                detail,
            }
        })
        .collect::<Vec<_>>();
    for (name, path) in [
        ("run runtime root", runtime_root.as_path()),
        ("run bpffs root", bpffs_root.as_path()),
    ] {
        checks.push(ResourceAudit {
            sequence: None,
            owner: "controller".to_owned(),
            resource: path.display().to_string(),
            registry_marked_cleaned: true,
            cleanup_satisfied: !path.exists(),
            detail: format!("{name} exists={}", path.exists()),
        });
    }
    let registry_live_entries = resources.live().count();
    let failed = checks
        .iter()
        .filter(|check| !check.registry_marked_cleaned || !check.cleanup_satisfied)
        .count();
    let pass = registry_live_entries == 0 && failed == 0;
    FinalCleanupObservation {
        run_id: run_id.to_owned(),
        runtime_root,
        bpffs_root,
        registry_entries: resources.entries().len(),
        registry_live_entries,
        root_cleanup_attempts,
        checks,
        pass,
        detail: if pass {
            "every registered resource and both run-owned roots were independently proven absent"
                .to_owned()
        } else {
            format!(
                "global cleanup audit failed: {failed} physical/registry checks failed; {registry_live_entries} registry entries remained live"
            )
        },
    }
}

fn resource_clean(commands: &CommandExecutor, resource: &Resource) -> (bool, String) {
    match resource {
        Resource::Process { pid } => path_absent(Path::new(&format!("/proc/{pid}"))),
        Resource::SystemdUnit { name } => {
            let spec = CommandSpec::new("systemctl")
                .args(["show", name, "--property=LoadState", "--value"])
                .timeout(Duration::from_secs(10));
            match commands.run(&spec) {
                Ok(output) => {
                    let state = output.stdout_text().trim().to_owned();
                    let absent = state.is_empty() || state == "not-found";
                    (absent, format!("systemd LoadState={state:?}"))
                }
                Err(error) => (false, format!("systemd absence check failed: {error}")),
            }
        }
        Resource::Cgroup { path, .. }
        | Resource::BpfPin { path }
        | Resource::UnixSocket { path }
        | Resource::Directory { path }
        | Resource::OwnershipRecord { path } => path_absent(path),
        Resource::ModifiedFile {
            path,
            expected_sha256,
        } => match std::fs::read(path) {
            Ok(bytes) => {
                let actual = format!("{:x}", Sha256::digest(bytes));
                (
                    actual == *expected_sha256,
                    format!(
                        "{} expected_sha256={} actual_sha256={actual}",
                        path.display(),
                        expected_sha256
                    ),
                )
            }
            Err(error) => (
                false,
                format!("read restored file {}: {error}", path.display()),
            ),
        },
        Resource::Netns { name } => path_absent(&Path::new("/run/netns").join(name)),
        Resource::Interface { name } => command_object_absent(
            commands,
            CommandSpec::new("ip")
                .args(["-j", "link", "show", "dev", name])
                .timeout(Duration::from_secs(10)),
            "interface",
        ),
        Resource::NftObject {
            family,
            table,
            object,
        } => command_object_absent(
            commands,
            CommandSpec::new("nft")
                .args(["-j", "list", "table", family, table])
                .timeout(Duration::from_secs(10)),
            &format!("nft object {object}"),
        ),
        Resource::BpfObject { id, object_kind } => command_object_absent(
            commands,
            CommandSpec::new("bpftool")
                .args(["-j", object_kind, "show", "id", &id.to_string()])
                .timeout(Duration::from_secs(10)),
            "BPF object",
        ),
        Resource::RuncContainer { id } => command_object_absent(
            commands,
            CommandSpec::new("runc")
                .args(["state", id])
                .timeout(Duration::from_secs(10)),
            "runc container",
        ),
    }
}

fn path_absent(path: &Path) -> (bool, String) {
    let exists = path.exists();
    (!exists, format!("{} exists={exists}", path.display()))
}

fn command_object_absent(
    commands: &CommandExecutor,
    spec: CommandSpec,
    kind: &str,
) -> (bool, String) {
    match commands.run(&spec) {
        Ok(output) => (
            !output.success(),
            format!(
                "{kind} query exit={:?} signal={:?} timeout={}",
                output.record.exit_code, output.record.signal, output.record.timed_out
            ),
        ),
        Err(error) => (false, format!("{kind} absence check failed: {error}")),
    }
}
