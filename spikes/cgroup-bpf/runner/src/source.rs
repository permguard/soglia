// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::command::{CommandExecutor, CommandSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceObservation {
    pub repository_commit: String,
    pub dirty_status: String,
    pub hashes: BTreeMap<String, String>,
}

pub fn collect(
    commands: &CommandExecutor,
    repository: &Path,
    artifacts: &Path,
    runner: &Path,
) -> Result<SourceObservation, String> {
    let commit = git(commands, repository, &["rev-parse", "HEAD"])?;
    let dirty_status = git(commands, repository, &["status", "--short"])?;
    let mut hashes = BTreeMap::new();
    let spike = repository.join("spikes/cgroup-bpf");
    for path in source_files(&spike)? {
        let relative = path.strip_prefix(repository).unwrap_or(&path);
        hashes.insert(format!("source:{}", relative.display()), sha256(&path)?);
    }
    for path in artifact_files(artifacts)? {
        let relative = path.strip_prefix(artifacts).unwrap_or(&path);
        hashes.insert(format!("artifact:{}", relative.display()), sha256(&path)?);
    }
    hashes.insert(
        "runner:executed-binary".to_owned(),
        sha256(&runner.to_path_buf())?,
    );
    Ok(SourceObservation {
        repository_commit: commit.trim().to_owned(),
        dirty_status,
        hashes,
    })
}

fn source_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files, true)?;
    files.sort();
    Ok(files)
}

fn artifact_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for directory in [root.join("bin"), root.join("bpf")] {
        collect_files(&directory, root, &mut files, false)?;
    }
    files.sort();
    Ok(files)
}

fn collect_files(
    directory: &Path,
    root: &Path,
    files: &mut Vec<PathBuf>,
    exclude_generated: bool,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("read source directory {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if exclude_generated
            && relative.components().next().is_some_and(|component| {
                component.as_os_str() == "target" || component.as_os_str() == "evidence"
            })
        {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        if kind.is_dir() {
            collect_files(&path, root, files, exclude_generated)?;
        } else if kind.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn git(
    commands: &CommandExecutor,
    repository: &Path,
    arguments: &[&str],
) -> Result<String, String> {
    let output = commands.run(
        &CommandSpec::new("git")
            .args(arguments.iter().copied())
            .cwd(repository)
            .timeout(Duration::from_secs(10)),
    )?;
    output.require_success("git source observation")?;
    Ok(output.stdout_text())
}

fn sha256(path: &PathBuf) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}
