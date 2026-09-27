// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::evidence::unix_ms;
use crate::journal::RunJournal;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    Process {
        pid: u32,
    },
    SystemdUnit {
        name: String,
    },
    Cgroup {
        path: PathBuf,
        inode: u64,
    },
    Netns {
        name: String,
    },
    Interface {
        name: String,
    },
    NftObject {
        family: String,
        table: String,
        object: String,
    },
    BpfPin {
        path: PathBuf,
    },
    BpfObject {
        id: u32,
        object_kind: String,
    },
    RuncContainer {
        id: String,
    },
    UnixSocket {
        path: PathBuf,
    },
    Directory {
        path: PathBuf,
    },
    OwnershipRecord {
        path: PathBuf,
    },
    ModifiedFile {
        path: PathBuf,
        expected_sha256: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub sequence: u64,
    pub owner: String,
    pub provenance: String,
    pub registered_unix_ms: u128,
    pub cleaned: bool,
    pub resource: Resource,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceRegistry {
    entries: Vec<ResourceEntry>,
    #[serde(skip)]
    journal: Option<RunJournal>,
}

impl Default for ResourceRegistry {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            journal: None,
        }
    }
}

impl ResourceRegistry {
    pub fn with_journal(journal: RunJournal) -> Self {
        Self {
            entries: Vec::new(),
            journal: Some(journal),
        }
    }

    pub fn register(
        &mut self,
        owner: impl Into<String>,
        provenance: impl Into<String>,
        resource: Resource,
    ) -> u64 {
        let sequence = self.entries.len() as u64 + 1;
        self.entries.push(ResourceEntry {
            sequence,
            owner: owner.into(),
            provenance: provenance.into(),
            registered_unix_ms: unix_ms(),
            cleaned: false,
            resource,
        });
        self.persist();
        sequence
    }

    pub fn mark_owner_cleaned(&mut self, owner: &str) {
        for entry in self.entries.iter_mut().filter(|entry| entry.owner == owner) {
            entry.cleaned = true;
        }
        self.persist();
    }

    pub fn live(&self) -> impl Iterator<Item = &ResourceEntry> {
        self.entries.iter().filter(|entry| !entry.cleaned)
    }

    pub fn entries(&self) -> &[ResourceEntry] {
        &self.entries
    }

    fn persist(&self) {
        if let Some(journal) = &self.journal {
            journal.resources(&self.entries);
        }
    }
}
