// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::evidence::{EvidenceRecorder, unix_ms};
use crate::journal::RunJournal;

#[derive(Debug, Clone)]
pub struct CommandSpec {
    executable: PathBuf,
    argv: Vec<OsString>,
    cwd: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    timeout: Duration,
}

impl CommandSpec {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            argv: Vec::new(),
            cwd: PathBuf::from("/"),
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.argv.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn cwd(mut self, directory: impl Into<PathBuf>) -> Self {
        self.cwd = directory.into();
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub sequence: u64,
    pub executable: String,
    pub argv: Vec<String>,
    pub working_directory: String,
    pub selected_environment: BTreeMap<String, String>,
    pub wall_start_unix_ms: u128,
    pub monotonic_start_ns: u128,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout_file: String,
    pub stderr_file: String,
}

#[derive(Debug)]
pub struct CommandOutput {
    pub record: CommandRecord,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.record.exit_code == Some(0) && !self.record.timed_out
    }

    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn require_success(&self, context: &str) -> Result<(), String> {
        if self.success() {
            return Ok(());
        }
        Err(format!(
            "{context}: exit={:?} signal={:?} timeout={} stderr={}",
            self.record.exit_code,
            self.record.signal,
            self.record.timed_out,
            self.stderr_text().trim()
        ))
    }
}

#[derive(Debug, Clone)]
pub struct CommandExecutor {
    evidence: EvidenceRecorder,
    scope: PathBuf,
    sequence: Arc<AtomicU64>,
    monotonic_origin: Instant,
    journal: Option<RunJournal>,
}

pub struct RunningCommand {
    executor: CommandExecutor,
    child: std::process::Child,
    stdout_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    stderr_reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    sequence: u64,
    executable: String,
    argv: Vec<String>,
    working_directory: String,
    selected_environment: BTreeMap<String, String>,
    wall_start_unix_ms: u128,
    monotonic_start_ns: u128,
    started: Instant,
}

impl CommandExecutor {
    pub fn new(evidence: EvidenceRecorder, scope: impl Into<PathBuf>) -> Self {
        Self {
            evidence,
            scope: scope.into(),
            sequence: Arc::new(AtomicU64::new(0)),
            monotonic_origin: Instant::now(),
            journal: None,
        }
    }

    pub fn with_journal(mut self, journal: RunJournal) -> Self {
        self.journal = Some(journal);
        self
    }

    pub fn with_scope(&self, scope: impl Into<PathBuf>) -> Self {
        Self {
            evidence: self.evidence.clone(),
            scope: scope.into(),
            sequence: Arc::clone(&self.sequence),
            monotonic_origin: self.monotonic_origin,
            journal: self.journal.clone(),
        }
    }

    pub fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, String> {
        self.spawn(spec)?.wait(spec.timeout)
    }

    pub fn spawn(&self, spec: &CommandSpec) -> Result<RunningCommand, String> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let wall_start_unix_ms = unix_ms();
        let monotonic_start_ns = self.monotonic_origin.elapsed().as_nanos();
        let started = Instant::now();
        let executable = display(&spec.executable);
        let argv = spec
            .argv
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        if let Some(journal) = &self.journal {
            journal.command_started(
                sequence,
                &self.scope,
                executable.clone(),
                argv.clone(),
                wall_start_unix_ms,
            );
        }
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.argv)
            .current_dir(&spec.cwd)
            .envs(&spec.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            let detail = format!(
                "spawn {}: {error}",
                spec.executable.as_os_str().to_string_lossy()
            );
            if let Some(journal) = &self.journal {
                journal.command_spawn_failed(sequence, &detail);
            }
            detail
        })?;
        let stdout = child.stdout.take().ok_or("command stdout pipe missing")?;
        let stderr = child.stderr.take().ok_or("command stderr pipe missing")?;
        let stdout_reader = thread::spawn(move || read_all(stdout));
        let stderr_reader = thread::spawn(move || read_all(stderr));
        Ok(RunningCommand {
            executor: self.clone(),
            child,
            stdout_reader,
            stderr_reader,
            sequence,
            executable,
            argv,
            working_directory: display(&spec.cwd),
            selected_environment: spec
                .environment
                .iter()
                .map(|(key, value)| {
                    (
                        key.to_string_lossy().into_owned(),
                        value.to_string_lossy().into_owned(),
                    )
                })
                .collect(),
            wall_start_unix_ms,
            monotonic_start_ns,
            started,
        })
    }
}

impl RunningCommand {
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, String> {
        self.child
            .try_wait()
            .map_err(|error| format!("wait for command: {error}"))
    }

    pub fn terminate(&mut self) -> Result<(), String> {
        self.child
            .kill()
            .map_err(|error| format!("terminate command: {error}"))
    }

    pub fn wait(mut self, timeout: Duration) -> Result<CommandOutput, String> {
        let (status, timed_out) = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break (status, false),
                Ok(None) if self.started.elapsed() < timeout => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    let status = self
                        .child
                        .wait()
                        .map_err(|error| format!("wait after timeout: {error}"))?;
                    break (status, true);
                }
                Err(error) => return Err(format!("wait for command: {error}")),
            }
        };
        let stdout = self
            .stdout_reader
            .join()
            .map_err(|_| "stdout reader panicked".to_owned())?
            .map_err(|error| format!("read command stdout: {error}"))?;
        let stderr = self
            .stderr_reader
            .join()
            .map_err(|_| "stderr reader panicked".to_owned())?
            .map_err(|error| format!("read command stderr: {error}"))?;
        let stem = format!("{:04}", self.sequence);
        let stdout_file = self
            .executor
            .scope
            .join("commands")
            .join(format!("{stem}.stdout"));
        let stderr_file = self
            .executor
            .scope
            .join("commands")
            .join(format!("{stem}.stderr"));
        let record_file = self
            .executor
            .scope
            .join("commands")
            .join(format!("{stem}.json"));
        let record = CommandRecord {
            sequence: self.sequence,
            executable: self.executable,
            argv: self.argv,
            working_directory: self.working_directory,
            selected_environment: self.selected_environment,
            wall_start_unix_ms: self.wall_start_unix_ms,
            monotonic_start_ns: self.monotonic_start_ns,
            duration_ms: self.started.elapsed().as_millis(),
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            stdout_file: stdout_file.to_string_lossy().into_owned(),
            stderr_file: stderr_file.to_string_lossy().into_owned(),
        };
        if let Some(journal) = &self.executor.journal {
            journal.command_finished(&record);
        }
        self.executor
            .evidence
            .write_bytes(&stdout_file, &stdout)
            .map_err(|error| format!("write command stdout evidence: {error}"))?;
        self.executor
            .evidence
            .write_bytes(&stderr_file, &stderr)
            .map_err(|error| format!("write command stderr evidence: {error}"))?;
        self.executor
            .evidence
            .write_json(record_file, &record)
            .map_err(|error| format!("write command record: {error}"))?;
        Ok(CommandOutput {
            record,
            stdout,
            stderr,
        })
    }
}

fn read_all(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn display(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}
