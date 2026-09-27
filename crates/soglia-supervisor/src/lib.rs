// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Soglia Supervisor: the unprivileged coordinator of every Execution.
//!
//! It admits invocations, allocates each Execution's identity, address and concurrency slot, asks the
//! privileged helpers to create and destroy its resources in order, attributes its connections for
//! the egress proxy, and releases a response only after its Execution is verifiably gone.

#![forbid(unsafe_code)]

// Soglia's isolation and enforcement are built from Linux namespaces, cgroups, nftables and runc.
// There is nothing to build for another system: on macOS or Windows, build this in the development
// container (`.devcontainer/` or `dev/linux/run.sh`); only `soglia-core` and `soglia-proxy` build natively.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "this crate builds and runs only on Linux; on macOS or Windows use the development container (.devcontainer/ or dev/linux/run.sh)"
);

pub mod forward;
pub mod helpers;
pub mod privilege;
pub mod slots;
pub mod supervisor;

pub use supervisor::Supervisor;
