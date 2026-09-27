// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Soglia proxy: the only way into an Execution and the only way out of it.
//!
//! The ingress direction carries an invocation from a caller to a fresh Execution and releases the
//! response only after the Execution is destroyed. The egress direction carries the Execution's own
//! connections to allowed destinations, after attributing them to the Execution from trusted
//! network facts and validating every address a destination resolves to.

#![forbid(unsafe_code)]

pub mod attribution;
pub mod egress;
pub mod ingress;
pub mod policy;
pub mod resolver;
pub mod tunnel;
