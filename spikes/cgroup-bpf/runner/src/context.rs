// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::cli::RunOptions;
use crate::command::CommandExecutor;
use crate::evidence::EvidenceRecorder;
use crate::journal::RunJournal;
use crate::resources::ResourceRegistry;

pub struct TestContext {
    pub options: RunOptions,
    pub run_id: String,
    pub authoritative: bool,
    pub evidence: EvidenceRecorder,
    pub journal: RunJournal,
    pub commands: CommandExecutor,
    pub resources: ResourceRegistry,
    pub cancelled: Arc<AtomicBool>,
    pub executable: PathBuf,
    pub(crate) result_notes: Vec<String>,
}

impl TestContext {
    pub fn test_commands(&self, test: &str) -> CommandExecutor {
        self.commands.with_scope(test)
    }

    pub fn artifact(&self, relative: &str) -> PathBuf {
        self.options.artifacts.join(relative)
    }

    pub fn add_result_note(&mut self, note: impl Into<String>) {
        self.result_notes.push(note.into());
    }

    pub fn take_result_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.result_notes)
    }
}
