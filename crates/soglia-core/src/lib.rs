// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The contracts every Soglia component shares.
//!
//! Configuration, Execution identity and lifecycle, the Execution address pool, ownership records,
//! helper-channel framing and the explicitly disabled components of later phases live here, so the
//! runtime, the privileged helpers and the proxy agree on one vocabulary without depending on each
//! other.

#![forbid(unsafe_code)]

// Portable on purpose: this crate is plain logic over the standard library, so it builds and tests
// natively on a developer's machine. Anything that touches the kernel belongs in a Linux-only crate.

pub mod config;
pub mod helper;
pub mod id;
pub mod ipc;
pub mod net;
pub mod phase;
pub mod records;
pub mod unavailable;

pub use config::Config;
pub use id::{ExecutionId, ResourceTag};
pub use phase::ExecutionPhase;
pub use unavailable::{DeferredComponent, Unavailable};
