// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Dropping from root to the Supervisor's unprivileged user, and proving it happened.
//!
//! The drop runs after the privileged helpers have started and before the async runtime exists, so
//! the process has exactly one thread and the per-thread credential calls change the whole process.
//! That is checked, not assumed. Afterwards the process is not dumpable — another process of the same
//! user cannot attach to it and take its helper channels — and it cannot gain privileges again.

use std::fs;
use std::io;

use rustix::process::{DumpableBehavior, Gid, Uid, set_dumpable_behavior};
use rustix::thread::{set_no_new_privs, set_thread_groups, set_thread_res_gid, set_thread_res_uid};

/// Drops to `uid`:`gid` with no supplementary groups, and verifies the result.
pub fn drop_to(uid: u32, gid: u32) -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    if field(&status, "Threads:") != Some("1") {
        return Err(io::Error::other(
            "privileges must be dropped while the process has a single thread",
        ));
    }

    let group = Gid::from_raw_unchecked(gid);
    let user = Uid::from_raw_unchecked(uid);
    set_thread_groups(&[])?;
    set_thread_res_gid(group, group, group)?;
    set_thread_res_uid(user, user, user)?;
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    set_no_new_privs(true)?;

    verify(uid, gid)
}

fn verify(uid: u32, gid: u32) -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    let all_equal = |key: &str, expected: u32| {
        field(&status, key).is_some_and(|ids| {
            let ids: Vec<&str> = ids.split_whitespace().collect();
            ids.len() == 4 && ids.iter().all(|id| *id == expected.to_string())
        })
    };
    let checks = [
        (all_equal("Uid:", uid), "every uid is the Supervisor's"),
        (all_equal("Gid:", gid), "every gid is the Supervisor's"),
        (
            field(&status, "Groups:").is_none_or(str::is_empty),
            "no supplementary group remains",
        ),
        (
            field(&status, "CapEff:") == Some("0000000000000000"),
            "no effective capability remains",
        ),
        (
            field(&status, "CapPrm:") == Some("0000000000000000"),
            "no permitted capability remains",
        ),
        (
            field(&status, "NoNewPrivs:") == Some("1"),
            "no_new_privs is set",
        ),
    ];
    for (holds, what) in checks {
        if !holds {
            return Err(io::Error::other(format!(
                "the privilege drop could not be verified: expected that {what}"
            )));
        }
    }

    Ok(())
}

fn field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .map(str::trim)
}
