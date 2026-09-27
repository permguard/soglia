// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::CommandRecord;
use crate::evidence::{EvidenceRecorder, unix_ms};
use crate::model::{TestId, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunOutcome {
    Interrupted,
    InfrastructureFailure,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastCommand {
    pub sequence: u64,
    pub scope: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub status: String,
    pub started_unix_ms: u128,
    pub finished_unix_ms: Option<u128>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunState {
    pub run_id: String,
    pub authoritative: bool,
    pub terminal: bool,
    pub outcome: RunOutcome,
    pub verdict: Option<Verdict>,
    pub phase: String,
    pub current_test: Option<TestId>,
    pub last_command: Option<LastCommand>,
    pub owned_resources: Value,
    pub detail: String,
    pub started_unix_ms: u128,
    pub updated_unix_ms: u128,
}

#[derive(Debug, Clone)]
pub struct RunJournal {
    evidence: EvidenceRecorder,
    state: Arc<Mutex<RunState>>,
}

impl RunJournal {
    pub fn create(
        evidence: EvidenceRecorder,
        run_id: &str,
        authoritative: bool,
    ) -> Result<Self, String> {
        let now = unix_ms();
        let journal = Self {
            evidence,
            state: Arc::new(Mutex::new(RunState {
                run_id: run_id.to_owned(),
                authoritative,
                terminal: false,
                // This value is deliberately durable before any fallible setup. If the
                // process or VM disappears, the last state cannot be mistaken for PASS.
                outcome: RunOutcome::Interrupted,
                verdict: None,
                phase: "INITIALIZING".to_owned(),
                current_test: None,
                last_command: None,
                owned_resources: Value::Array(Vec::new()),
                detail: "runner has not reached a terminal checkpoint".to_owned(),
                started_unix_ms: now,
                updated_unix_ms: now,
            })),
        };
        journal.persist()?;
        Ok(journal)
    }

    pub fn set_phase(&self, phase: impl Into<String>, current_test: Option<TestId>) {
        self.update(|state| {
            state.phase = phase.into();
            state.current_test = current_test;
        });
    }

    pub fn command_started(
        &self,
        sequence: u64,
        scope: &Path,
        executable: String,
        argv: Vec<String>,
        started_unix_ms: u128,
    ) {
        self.update(|state| {
            state.last_command = Some(LastCommand {
                sequence,
                scope: scope.to_string_lossy().into_owned(),
                executable,
                argv,
                status: "RUNNING".to_owned(),
                started_unix_ms,
                finished_unix_ms: None,
                exit_code: None,
                signal: None,
                timed_out: false,
                detail: String::new(),
            });
        });
    }

    pub fn command_spawn_failed(&self, sequence: u64, detail: &str) {
        self.update(|state| {
            if let Some(command) = state
                .last_command
                .as_mut()
                .filter(|command| command.sequence == sequence)
            {
                command.status = "SPAWN_FAILED".to_owned();
                command.finished_unix_ms = Some(unix_ms());
                command.detail = detail.to_owned();
            }
        });
    }

    pub fn command_finished(&self, record: &CommandRecord) {
        self.update(|state| {
            if let Some(command) = state
                .last_command
                .as_mut()
                .filter(|command| command.sequence == record.sequence)
            {
                command.status = "FINISHED".to_owned();
                command.finished_unix_ms = Some(unix_ms());
                command.exit_code = record.exit_code;
                command.signal = record.signal;
                command.timed_out = record.timed_out;
            }
        });
    }

    pub fn resources<T: Serialize + ?Sized>(&self, resources: &T) {
        let value = serde_json::to_value(resources)
            .unwrap_or_else(|error| serde_json::json!({"serialization_error": error.to_string()}));
        self.update(|state| state.owned_resources = value);
    }

    pub fn finish(&self, verdict: Verdict, detail: impl Into<String>) {
        self.update(|state| {
            state.terminal = true;
            state.outcome = RunOutcome::Complete;
            state.verdict = Some(verdict);
            state.phase = "COMPLETE".to_owned();
            state.current_test = None;
            state.detail = detail.into();
        });
    }

    pub fn infrastructure_failure(&self, detail: impl Into<String>) {
        self.update(|state| {
            state.terminal = true;
            state.outcome = RunOutcome::InfrastructureFailure;
            state.verdict = Some(Verdict::InfraError);
            state.detail = detail.into();
        });
    }

    fn update(&self, change: impl FnOnce(&mut RunState)) {
        if let Ok(mut state) = self.state.lock() {
            change(&mut state);
            state.updated_unix_ms = unix_ms();
        }
        // State persistence is best effort here because command/resource registration APIs
        // intentionally cannot discard an already-created kernel resource on an I/O error.
        // The controller performs checked writes at every phase boundary and terminal path.
        let _ = self.persist();
    }

    pub fn persist(&self) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "run-state journal mutex poisoned".to_owned())?
            .clone();
        self.evidence
            .write_json("state.json", &state)
            .map_err(|error| format!("write run-state journal: {error}"))
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> RunState {
        self.state.lock().map_or_else(
            |_| panic!("run-state journal mutex poisoned"),
            |state| state.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{RunJournal, RunOutcome};
    use crate::evidence::EvidenceRecorder;
    use crate::model::{TestId, Verdict};

    #[test]
    fn initial_checkpoint_is_durably_interrupted() -> Result<(), Box<dyn std::error::Error>> {
        let base = std::env::temp_dir().join(format!(
            "soglia-run-journal-{}-{}",
            std::process::id(),
            crate::evidence::unix_ms()
        ));
        let recorder = EvidenceRecorder::create(&base, "test-run")?;
        let journal = RunJournal::create(recorder.clone(), "test-run", true)?;
        let state = journal.snapshot();
        assert!(!state.terminal);
        assert_eq!(state.outcome, RunOutcome::Interrupted);
        assert_eq!(state.phase, "INITIALIZING");
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(recorder.root().join("state.json"))?)?;
        assert_eq!(persisted["outcome"], "INTERRUPTED");
        assert_eq!(persisted["authoritative"], true);
        fs::remove_dir_all(base)?;
        Ok(())
    }

    #[test]
    fn infrastructure_checkpoint_preserves_phase_command_and_resources()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = std::env::temp_dir().join(format!(
            "soglia-run-journal-infra-{}-{}",
            std::process::id(),
            crate::evidence::unix_ms()
        ));
        let recorder = EvidenceRecorder::create(&base, "test-run")?;
        let journal = RunJournal::create(recorder.clone(), "test-run", true)?;
        journal.set_phase("S1.EXECUTE", Some(TestId::S1));
        journal.command_started(
            22,
            Path::new("source"),
            "git".to_owned(),
            vec!["status".to_owned()],
            123,
        );
        journal.resources(&serde_json::json!([{
            "owner": "s1",
            "provenance": "unit test",
            "resource": {"kind": "bpf_object", "id": 42, "object_kind": "prog"}
        }]));
        journal.infrastructure_failure("controlled infrastructure failure");
        journal.persist()?;

        let state = journal.snapshot();
        assert!(state.terminal);
        assert_eq!(state.outcome, RunOutcome::InfrastructureFailure);
        assert_eq!(state.verdict, Some(Verdict::InfraError));
        assert_eq!(state.phase, "S1.EXECUTE");
        assert_eq!(state.current_test, Some(TestId::S1));
        assert_eq!(
            state.last_command.as_ref().map(|command| command.sequence),
            Some(22)
        );
        assert_eq!(state.owned_resources[0]["resource"]["id"], 42);

        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(recorder.root().join("state.json"))?)?;
        assert_eq!(persisted["outcome"], "INFRASTRUCTURE_FAILURE");
        assert_eq!(persisted["verdict"], "INFRA_ERROR");
        assert_eq!(persisted["phase"], "S1.EXECUTE");
        assert_eq!(persisted["last_command"]["sequence"], 22);
        assert_eq!(persisted["owned_resources"][0]["resource"]["id"], 42);
        fs::remove_dir_all(base)?;
        Ok(())
    }
}
