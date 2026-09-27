// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Ownership records: how Soglia proves, after a crash, which resources are its own.
//!
//! A record is published before the resource it describes is created, and it is published
//! atomically: the complete record is written to a temporary name, flushed, and renamed into place.
//! A reader therefore sees either no record or a whole one — a half-written file is never a valid
//! ownership marker. Temporary files carry a leading dot and a `.tmp` suffix, and are never read as
//! records.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Publishes `record` as `directory/name`, atomically.
pub fn publish<T: Serialize>(directory: &Path, name: &str, record: &T) -> io::Result<PathBuf> {
    check_name(name)?;
    let body = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
    let final_path = directory.join(name);
    let temporary = directory.join(format!(".{name}.tmp"));

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(&body)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &final_path)?;
    // Make the rename itself durable where the file system needs it; on tmpfs this is a no-op.
    File::open(directory)?.sync_all()?;

    Ok(final_path)
}

/// Reads the record `directory/name`, or `None` when there is none.
pub fn read<T: DeserializeOwned>(directory: &Path, name: &str) -> io::Result<Option<T>> {
    check_name(name)?;
    match fs::read(directory.join(name)) {
        Ok(body) => serde_json::from_slice(&body)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Removes the record `directory/name`. A record that is already gone is not an error.
pub fn remove(directory: &Path, name: &str) -> io::Result<()> {
    check_name(name)?;
    match fs::remove_file(directory.join(name)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// `true` for the temporary name of an unfinished publication.
pub fn is_temporary(file_name: &str) -> bool {
    file_name.starts_with('.') && file_name.ends_with(".tmp")
}

/// A record name is one plain path component; nothing may escape the record directory.
fn check_name(name: &str) -> io::Result<()> {
    let plain = !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if plain {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{name}` is not a valid record name"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Owned {
        netns: String,
        veth: String,
    }

    fn scratch(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "soglia-records-{label}-{}",
            crate::id::ExecutionId::generate().unwrap()
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn a_published_record_reads_back_and_leaves_no_temporary() {
        let directory = scratch("publish");
        let record = Owned {
            netns: "soglia-0123456789".into(),
            veth: "sgh-0123456789".into(),
        };
        publish(&directory, "net.json", &record).unwrap();

        assert_eq!(read::<Owned>(&directory, "net.json").unwrap(), Some(record));
        let names: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["net.json".to_owned()]);

        remove(&directory, "net.json").unwrap();
        assert_eq!(read::<Owned>(&directory, "net.json").unwrap(), None);
        // Removing what is already gone is idempotent.
        remove(&directory, "net.json").unwrap();
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn republishing_replaces_the_whole_record() {
        let directory = scratch("replace");
        publish(
            &directory,
            "net.json",
            &Owned {
                netns: "a".into(),
                veth: "b".into(),
            },
        )
        .unwrap();
        publish(
            &directory,
            "net.json",
            &Owned {
                netns: "c".into(),
                veth: "d".into(),
            },
        )
        .unwrap();
        assert_eq!(
            read::<Owned>(&directory, "net.json").unwrap(),
            Some(Owned {
                netns: "c".into(),
                veth: "d".into()
            })
        );
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_corrupt_record_is_an_error_not_an_absence() {
        let directory = scratch("corrupt");
        fs::write(directory.join("net.json"), b"{\"netns\":").unwrap();
        let refused = read::<Owned>(&directory, "net.json").unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn names_cannot_escape_the_directory() {
        let directory = scratch("names");
        for bad in ["", "../net.json", "a/b", ".net.json.tmp", "net json"] {
            assert!(publish(&directory, bad, &1).is_err(), "{bad:?}");
        }
        assert!(is_temporary(".net.json.tmp"));
        assert!(!is_temporary("net.json"));
        fs::remove_dir_all(&directory).unwrap();
    }
}
