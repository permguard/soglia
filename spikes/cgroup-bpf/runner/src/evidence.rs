// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

pub fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

pub fn new_run_id() -> String {
    format!("replay-{}-{}", unix_ms(), std::process::id())
}

#[derive(Debug, Clone)]
pub struct EvidenceRecorder {
    root: PathBuf,
}

impl EvidenceRecorder {
    pub fn create(base: &Path, run_id: &str) -> io::Result<Self> {
        let root = base.join(run_id);
        fs::create_dir_all(root.join("final"))?;
        Ok(Self { root })
    }

    pub fn open_existing(root: &Path) -> io::Result<Self> {
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("evidence root {} does not exist", root.display()),
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn test_root(&self, test: &str) -> io::Result<PathBuf> {
        let root = self.root.join(test);
        fs::create_dir_all(root.join("commands"))?;
        fs::create_dir_all(root.join("raw"))?;
        Ok(root)
    }

    pub fn write_json<T: Serialize + ?Sized>(
        &self,
        relative: impl AsRef<Path>,
        value: &T,
    ) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
        self.write_bytes(relative, &bytes)
    }

    pub fn write_text(&self, relative: impl AsRef<Path>, value: &str) -> io::Result<()> {
        self.write_bytes(relative, value.as_bytes())
    }

    pub fn write_bytes(&self, relative: impl AsRef<Path>, value: &[u8]) -> io::Result<()> {
        let path = self.root.join(relative.as_ref());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut file = File::create(&temporary)?;
        file.write_all(value)?;
        file.sync_all()?;
        fs::rename(temporary, path)
    }
}
