// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia __sandboxd` role: the isolation boundary of every Execution.
//!
//! The sandbox helper creates each Execution's cgroup under the subtree delegated to Soglia, writes
//! its OCI bundle, starts its agent with runc inside the network namespace the enforcer prepared,
//! proves the agent really runs in that namespace, and destroys everything again, verifying each
//! step. It runs privileged and answers only the requests of the helper protocol.

#![forbid(unsafe_code)]

// Soglia's isolation and enforcement are built from Linux namespaces, cgroups, nftables and runc.
// There is nothing to build for another system: on macOS or Windows, build this in the development
// container (`.devcontainer/` or `dev/linux/run.sh`); only `soglia-core` and `soglia-proxy` build natively.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "this crate builds and runs only on Linux; on macOS or Windows use the development container (.devcontainer/ or dev/linux/run.sh)"
);

pub mod backend;
pub mod bundle;
pub mod cgroup;
pub mod service;
