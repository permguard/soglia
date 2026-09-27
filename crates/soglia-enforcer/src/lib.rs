// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `soglia __enforcer` role: the network confinement of every Execution.
//!
//! The enforcer creates and owns each Execution's network namespace, veth pair, addresses, routes
//! and nftables policy, and the host-side anti-spoofing that makes an Execution's address a
//! trustworthy identity. It runs privileged, answers only the requests of the helper protocol, and
//! derives every resource name and address from the configuration it was started with.

#![forbid(unsafe_code)]

// Soglia's isolation and enforcement are built from Linux namespaces, cgroups, nftables and runc.
// There is nothing to build for another system: on macOS or Windows, build this in the development
// container (`.devcontainer/` or `dev/linux/run.sh`); only `soglia-core` and `soglia-proxy` build natively.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "this crate builds and runs only on Linux; on macOS or Windows use the development container (.devcontainer/ or dev/linux/run.sh)"
);

pub mod backend;
pub mod rules;
pub mod service;
pub mod system;
