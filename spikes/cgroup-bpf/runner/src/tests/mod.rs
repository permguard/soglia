// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::context::TestContext;
use crate::model::{TestId, Verdict};

pub mod s0;
pub mod s1;
pub mod s10;
pub mod s11;
pub mod s12;
pub mod s13;
pub mod s14;
pub mod s1b;
pub mod s2;
pub mod s3;
pub mod s4;
pub mod s5;
pub mod s6;
pub mod s7;
pub mod s8;

#[derive(Debug, Clone)]
pub struct TestError {
    pub verdict: Verdict,
    pub detail: String,
}

impl TestError {
    pub fn new(verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            verdict,
            detail: detail.into(),
        }
    }

    pub fn infra(detail: impl Into<String>) -> Self {
        Self::new(Verdict::InfraError, detail)
    }
}

pub trait SpikeTest {
    type Observation: Serialize;

    fn id(&self) -> TestId;
    fn invariant(&self) -> &'static str;
    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError>;
    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError>;
    fn verify(
        &self,
        context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError>;
    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError>;
    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError>;
}
