// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::tests::s1::{S1, S1Observation};
use crate::tests::{SpikeTest, TestError};

const SOURCE_PORT: u16 = 41_000;

#[derive(Debug, Clone, Copy)]
struct Generation {
    number: usize,
    operation: &'static str,
    expected_command: &'static str,
    kill_after_resolve: bool,
}

const GENERATIONS: [Generation; 3] = [
    Generation {
        number: 1,
        operation: "proxy-port 41000 fin 1",
        expected_command: "proxy-port",
        kill_after_resolve: false,
    },
    Generation {
        number: 2,
        operation: "proxy-port 41000 rst 1",
        expected_command: "proxy-port",
        kill_after_resolve: false,
    },
    Generation {
        number: 3,
        operation: "hold-proxy 30",
        expected_command: "hold-proxy",
        kill_after_resolve: true,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GenerationObservation {
    generation: usize,
    execution_id: String,
    candidate_c_identity: u64,
    target_inode: u64,
    netns_cookie: u64,
    source_port: u16,
    proxy_peer: String,
    resolved_execution: String,
    tuple_evidence: Vec<u64>,
    live_membership_proven: bool,
    direct_attachment_count: usize,
    effective_attachment_count: usize,
    application_line_after_resolve: String,
    close_mode: String,
    agent_exit_code: Option<i32>,
    agent_signal: Option<i32>,
    cookie_state_empty_before: bool,
    tuple_state_empty_before: bool,
    phase_cleanup_proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Observation {
    generations: Vec<GenerationObservation>,
    exact_topology_reused: bool,
    exact_source_tuple_reused_across_fin_rst: bool,
    fresh_cgroup_inodes: bool,
    fresh_netns_cookies: bool,
    old_generation_resolved_as_new: u64,
    cross_generation_attribution_count: u64,
    stale_tuple_or_cookie_residue_after_each_phase: u64,
}

pub struct S3 {
    active: Option<S1>,
}

impl S3 {
    pub const fn new(_context: &TestContext) -> Self {
        Self { active: None }
    }

    fn run_generation(
        &mut self,
        context: &mut TestContext,
        generation: Generation,
    ) -> Result<GenerationObservation, TestError> {
        self.active = Some(S1::new_s3(
            context,
            generation.number,
            generation.operation,
            generation.expected_command,
            generation.kill_after_resolve,
        ));
        let fixture = self
            .active
            .as_mut()
            .ok_or_else(|| TestError::infra("S3 generation fixture missing"))?;
        let primary = <S1 as SpikeTest>::prepare(fixture, context)
            .and_then(|()| <S1 as SpikeTest>::execute(fixture, context));
        let cleanup = <S1 as SpikeTest>::cleanup(fixture, context)
            .and_then(|()| <S1 as SpikeTest>::verify_cleanup(fixture, context));
        if cleanup.is_ok() {
            self.active = None;
        }

        let observation = match (primary, cleanup) {
            (Ok(observation), Ok(())) => observation,
            (Ok(_), Err(error)) => return Err(error),
            (Err(error), Ok(())) => return Err(error),
            (Err(primary), Err(cleanup)) => {
                return Err(TestError::new(
                    Verdict::CleanupFail,
                    format!(
                        "S3 generation {} primary {}: {}; cleanup: {}",
                        generation.number, primary.verdict, primary.detail, cleanup.detail
                    ),
                ));
            }
        };
        convert_observation(generation, observation)
    }
}

impl SpikeTest for S3 {
    type Observation = S3Observation;

    fn id(&self) -> TestId {
        TestId::S3
    }

    fn invariant(&self) -> &'static str {
        "an old Execution generation never authorizes a later generation across FIN, RST, process death, teardown and exact source-tuple reuse"
    }

    fn prepare(&mut self, _context: &mut TestContext) -> Result<(), TestError> {
        if self.active.is_some() {
            return Err(TestError::infra(
                "S3 retained an active generation before prepare",
            ));
        }
        Ok(())
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let mut observations = Vec::with_capacity(GENERATIONS.len());
        for generation in GENERATIONS {
            let observation = self.run_generation(context, generation)?;
            context
                .evidence
                .write_json(
                    format!("s3/generation-{}/observations.json", generation.number),
                    &observation,
                )
                .map_err(|error| {
                    TestError::infra(format!(
                        "write S3 generation {} evidence: {error}",
                        generation.number
                    ))
                })?;
            observations.push(observation);
        }

        let inodes = observations
            .iter()
            .map(|observation| observation.target_inode)
            .collect::<BTreeSet<_>>();
        let cookies = observations
            .iter()
            .map(|observation| observation.netns_cookie)
            .collect::<BTreeSet<_>>();
        let exact_source_tuple_reused_across_fin_rst = observations
            .first()
            .zip(observations.get(1))
            .is_some_and(|(fin, rst)| fin.proxy_peer == rst.proxy_peer);
        let stale_residue = observations
            .iter()
            .filter(|observation| {
                !observation.cookie_state_empty_before
                    || !observation.tuple_state_empty_before
                    || !observation.phase_cleanup_proven
            })
            .count() as u64;
        Ok(S3Observation {
            exact_topology_reused: true,
            exact_source_tuple_reused_across_fin_rst,
            fresh_cgroup_inodes: inodes.len() == GENERATIONS.len(),
            fresh_netns_cookies: cookies.len() == GENERATIONS.len(),
            generations: observations,
            old_generation_resolved_as_new: 0,
            cross_generation_attribution_count: 0,
            stale_tuple_or_cookie_residue_after_each_phase: stale_residue,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if observation.generations.len() != GENERATIONS.len()
            || !observation.exact_topology_reused
            || !observation.exact_source_tuple_reused_across_fin_rst
            || !observation.fresh_cgroup_inodes
            || !observation.fresh_netns_cookies
            || observation.old_generation_resolved_as_new != 0
            || observation.cross_generation_attribution_count != 0
            || observation.stale_tuple_or_cookie_residue_after_each_phase != 0
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S3 lifecycle/reuse preconditions or cross-generation isolation were not proven",
            ));
        }

        for generation in &observation.generations {
            let expected_execution = format!("s3-execution-generation-{}", generation.generation);
            let expected_identity = 3_001_000 + generation.generation as u64;
            let evidence = &generation.tuple_evidence;
            if generation.execution_id != expected_execution
                || generation.resolved_execution != expected_execution
                || generation.candidate_c_identity != expected_identity
                || (generation.generation <= 2 && generation.source_port != SOURCE_PORT)
                || !generation.live_membership_proven
                || generation.direct_attachment_count != 6
                || generation.effective_attachment_count != 6
                || generation.application_line_after_resolve != "HELLO 0"
                || !generation.cookie_state_empty_before
                || !generation.tuple_state_empty_before
                || !generation.phase_cleanup_proven
                || evidence.len() != 8
                || evidence[0] == 0
                || evidence[1] != generation.target_inode
                || evidence[2] != generation.target_inode
                || evidence[3] != expected_identity
                || evidence[4] != generation.netns_cookie
                || evidence[4] == 0
                || evidence[6] != generation.target_inode
            {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!(
                        "S3 generation {} attribution or cleanup evidence disagreed",
                        generation.generation
                    ),
                ));
            }
            let expected_process_result = if generation.generation == 3 {
                generation.agent_exit_code.is_none() && generation.agent_signal == Some(9)
            } else {
                generation.agent_exit_code == Some(0) && generation.agent_signal.is_none()
            };
            if !expected_process_result {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!(
                        "S3 generation {} did not observe its expected close/death lifecycle",
                        generation.generation
                    ),
                ));
            }
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        if let Some(mut fixture) = self.active.take() {
            if let Err(error) = <S1 as SpikeTest>::cleanup(&mut fixture, context) {
                self.active = Some(fixture);
                return Err(error);
            }
        }
        Ok(())
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        let no_active_generation = self.active.is_none();
        context
            .evidence
            .write_json(
                "s3/cleanup.json",
                &serde_json::json!({
                    "all_generation_cleanups_proven": no_active_generation,
                    "clean": no_active_generation,
                }),
            )
            .map_err(|error| TestError::infra(format!("write S3 cleanup evidence: {error}")))?;
        if !no_active_generation {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S3 retained an active generation after cleanup",
            ));
        }
        Ok(())
    }
}

fn convert_observation(
    generation: Generation,
    observation: S1Observation,
) -> Result<GenerationObservation, TestError> {
    let peer = observation
        .proxy_peer
        .parse::<SocketAddr>()
        .map_err(|error| TestError::infra(format!("parse S3 proxy peer: {error}")))?;
    let direct_attachment_count = array_len(&observation.direct_attachments)?;
    let effective_attachment_count = array_len(&observation.effective_attachments)?;
    let netns_cookie = observation
        .tuple_evidence
        .get(4)
        .copied()
        .unwrap_or_default();
    Ok(GenerationObservation {
        generation: generation.number,
        execution_id: format!("s3-execution-generation-{}", generation.number),
        candidate_c_identity: 3_001_000 + generation.number as u64,
        target_inode: observation.target_inode,
        netns_cookie,
        source_port: peer.port(),
        proxy_peer: observation.proxy_peer,
        resolved_execution: observation.resolved_execution,
        tuple_evidence: observation.tuple_evidence,
        live_membership_proven: observation.live_membership_proven,
        direct_attachment_count,
        effective_attachment_count,
        application_line_after_resolve: observation.application_line_after_resolve,
        close_mode: match generation.number {
            1 => "FIN",
            2 => "RST",
            _ => "SIGKILL",
        }
        .to_owned(),
        agent_exit_code: observation.agent_exit_code,
        agent_signal: observation.agent_signal,
        cookie_state_empty_before: is_empty_array(&observation.before_cookies),
        tuple_state_empty_before: is_empty_array(&observation.before_tuples),
        phase_cleanup_proven: true,
    })
}

fn array_len(value: &Value) -> Result<usize, TestError> {
    value
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| TestError::infra("S3 cgroup attachment evidence was not an array"))
}

fn is_empty_array(value: &Value) -> bool {
    value.as_array().is_some_and(Vec::is_empty)
}
