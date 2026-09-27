// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    Unproven,
    Unsupported,
    InfraError,
    CleanupFail,
    NotExecuted,
}

impl Verdict {
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Pass => 0,
            Self::Fail => 10,
            Self::Unproven => 11,
            Self::CleanupFail => 12,
            Self::InfraError => 13,
            Self::Unsupported => 15,
            Self::NotExecuted => 14,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Unproven => "UNPROVEN",
            Self::Unsupported => "UNSUPPORTED",
            Self::InfraError => "INFRA_ERROR",
            Self::CleanupFail => "CLEANUP_FAIL",
            Self::NotExecuted => "NOT_EXECUTED",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TestId {
    #[serde(rename = "s0")]
    S0,
    #[serde(rename = "s1")]
    S1,
    #[serde(rename = "s1b")]
    S1b,
    #[serde(rename = "s2")]
    S2,
    #[serde(rename = "s3")]
    S3,
    #[serde(rename = "s4")]
    S4,
    #[serde(rename = "s5")]
    S5,
    #[serde(rename = "s6")]
    S6,
    #[serde(rename = "s7")]
    S7,
    #[serde(rename = "s8")]
    S8,
    #[serde(rename = "s9")]
    S9,
    #[serde(rename = "s10")]
    S10,
    #[serde(rename = "s11")]
    S11,
    #[serde(rename = "s12")]
    S12,
    #[serde(rename = "s13")]
    S13,
    #[serde(rename = "s14")]
    S14,
}

impl TestId {
    pub const ALL: [Self; 16] = [
        Self::S0,
        Self::S1,
        Self::S1b,
        Self::S2,
        Self::S3,
        Self::S4,
        Self::S5,
        Self::S6,
        Self::S7,
        Self::S8,
        Self::S9,
        Self::S10,
        Self::S11,
        Self::S12,
        Self::S13,
        Self::S14,
    ];

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|id| id.as_str() == value)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S0 => "s0",
            Self::S1 => "s1",
            Self::S1b => "s1b",
            Self::S2 => "s2",
            Self::S3 => "s3",
            Self::S4 => "s4",
            Self::S5 => "s5",
            Self::S6 => "s6",
            Self::S7 => "s7",
            Self::S8 => "s8",
            Self::S9 => "s9",
            Self::S10 => "s10",
            Self::S11 => "s11",
            Self::S12 => "s12",
            Self::S13 => "s13",
            Self::S14 => "s14",
        }
    }
}

impl fmt::Display for TestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test: TestId,
    pub authoritative: bool,
    pub verdict: Verdict,
    pub invariant: String,
    pub detail: String,
    pub cleanup: Verdict,
    pub started_unix_ms: u128,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub authoritative: bool,
    pub verdict: Verdict,
    pub results: Vec<TestResult>,
    pub stopped_at: Option<TestId>,
    pub evidence_root: String,
}
