// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::CommandSpec;
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::resources::Resource;
use crate::tests::s1::{S1, inode, json_cgroup};
use crate::tests::{SpikeTest, TestError};

const PHASES: [&str; 12] = [
    "sock-create-inet6-deny",
    "sock-create-inet6-control",
    "connect6-deny",
    "connect6-omitted-control",
    "sendmsg4-deny",
    "sendmsg4-omitted-control",
    "sendmsg6-deny",
    "sendmsg6-omitted-control",
    "connect4-deny",
    "connect4-omitted-control",
    "sockops-present-control",
    "sockops-omitted",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HookResult {
    hook: String,
    deny_phase: String,
    control_phase: String,
    deny_counter_index: Option<usize>,
    deny_observed: bool,
    control_exposed_path: bool,
    membership_proven: bool,
    expected_attachment_counts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S5Observation {
    execution_id: String,
    target_inode: u64,
    helper_exit_code: Option<i32>,
    helper_signal: Option<i32>,
    helper_stdout: String,
    helper_stderr: String,
    hooks: Vec<HookResult>,
    sockops_present_resolve: String,
    sockops_omitted_resolve: String,
    sockops_omitted_timeout_ms: u64,
    sockops_omitted_application_reads: u64,
    sockops_omitted_dns: u64,
    sockops_omitted_outbound_effects: u64,
    sockops_omitted_ip_fallback: bool,
    sockops_omitted_tuple_entries: u64,
    sockops_omitted_cookie_entries: u64,
    direct_attachments_after_helper: Value,
    effective_attachments_after_helper: Value,
    helper_pin_root_empty: bool,
}

pub struct S5 {
    fixture: S1,
}

impl S5 {
    pub fn new(context: &TestContext) -> Self {
        Self {
            fixture: S1::new_s5(context),
        }
    }
}

impl SpikeTest for S5 {
    type Observation = S5Observation;

    fn id(&self) -> TestId {
        TestId::S5
    }

    fn invariant(&self) -> &'static str {
        "each of the six cgroup-BPF hooks has a causally isolated contribution, and missing sockops attribution remains fail-closed"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::prepare(&mut self.fixture, context)?;
        self.fixture.unload_bpf()
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let target = self.fixture.target()?.to_path_buf();
        let target_inode = inode(&target).map_err(TestError::infra)?;
        let helper = self
            .fixture
            .commands(context)
            .spawn(
                &CommandSpec::new(context.artifact("bin/s5-helper"))
                    .args([
                        context.artifact("bpf/soglia-diag.o").into_os_string(),
                        context
                            .artifact("bpf/soglia-relax-inet6-diag.o")
                            .into_os_string(),
                        context
                            .artifact("bpf/soglia-relax-dgram-diag.o")
                            .into_os_string(),
                        target.as_os_str().to_owned(),
                        self.fixture.pin_root.join("maps").into_os_string(),
                        self.fixture.pin_root.join("links").into_os_string(),
                        OsString::from(&self.fixture.netns),
                        context.artifact("bin/soglia-spike-agent").into_os_string(),
                        OsString::from("5001001"),
                        context.evidence.root().as_os_str().to_owned(),
                    ])
                    .timeout(Duration::from_secs(90)),
            )
            .map_err(TestError::infra)?;
        context.resources.register(
            "s5",
            "S5 deliberately migrated Rust hook-isolation stimulus",
            Resource::Process { pid: helper.id() },
        );
        let output = helper
            .wait(Duration::from_secs(90))
            .map_err(TestError::infra)?;
        if !output.success() {
            return Err(TestError::new(
                Verdict::Unproven,
                format!(
                    "S5 migrated stimulus did not complete: exit={:?} signal={:?} stderr={}",
                    output.record.exit_code,
                    output.record.signal,
                    output.stderr_text().trim()
                ),
            ));
        }
        let stdout = output.stdout_text();
        let fields = parse_fields(&stdout);
        let hooks = verify_helper_semantics(&stdout, &fields, target_inode)?;
        let direct_attachments_after_helper =
            json_cgroup(&self.fixture.commands(context), &target, false)?;
        let effective_attachments_after_helper =
            json_cgroup(&self.fixture.commands(context), &target, true)?;
        let helper_pin_root_empty = directory_empty(&self.fixture.pin_root)?;
        Ok(S5Observation {
            execution_id: "s5-execution-generation-1".to_owned(),
            target_inode,
            helper_exit_code: output.record.exit_code,
            helper_signal: output.record.signal,
            helper_stdout: stdout,
            helper_stderr: output.stderr_text(),
            hooks,
            sockops_present_resolve: required(&fields, "sockops-present-control_resolve_result")?
                .to_owned(),
            sockops_omitted_resolve: required(&fields, "sockops-omitted_resolve_result")?
                .to_owned(),
            sockops_omitted_timeout_ms: parse_u64(&fields, "sockops-omitted_resolve_timeout_ms")?,
            sockops_omitted_application_reads: parse_u64(
                &fields,
                "sockops-omitted_application_bytes_read_while_unresolved",
            )?,
            sockops_omitted_dns: parse_u64(&fields, "sockops-omitted_dns_while_unresolved")?,
            sockops_omitted_outbound_effects: parse_u64(
                &fields,
                "sockops-omitted_outbound_effects_while_unresolved",
            )?,
            sockops_omitted_ip_fallback: parse_bool(
                &fields,
                "sockops-omitted_ip_fallback_authorization",
            )?,
            sockops_omitted_tuple_entries: parse_u64(&fields, "sockops-omitted_tuple_entries")?,
            sockops_omitted_cookie_entries: parse_u64(&fields, "sockops-omitted_cookie_entries")?,
            direct_attachments_after_helper,
            effective_attachments_after_helper,
            helper_pin_root_empty,
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if observation.helper_exit_code != Some(0)
            || observation.helper_signal.is_some()
            || observation.hooks.len() != 6
            || observation.hooks.iter().any(|hook| {
                !hook.deny_observed
                    || !hook.control_exposed_path
                    || !hook.membership_proven
                    || !hook.expected_attachment_counts
            })
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S5 did not causally isolate every required hook",
            ));
        }
        if observation.sockops_present_resolve != "s5-execution-generation-1"
            || observation.sockops_omitted_resolve != "TIMEOUT_DENY"
            || observation.sockops_omitted_timeout_ms != 2_000
            || observation.sockops_omitted_application_reads != 0
            || observation.sockops_omitted_dns != 0
            || observation.sockops_omitted_outbound_effects != 0
            || observation.sockops_omitted_ip_fallback
            || observation.sockops_omitted_tuple_entries != 0
            || observation.sockops_omitted_cookie_entries != 1
        {
            return Err(TestError::new(
                Verdict::Fail,
                "S5 sockops omission did not remain bounded and fail-closed",
            ));
        }
        if !observation
            .direct_attachments_after_helper
            .as_array()
            .is_some_and(Vec::is_empty)
            || !observation
                .effective_attachments_after_helper
                .as_array()
                .is_some_and(Vec::is_empty)
            || !observation.helper_pin_root_empty
        {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S5 phase-local BPF state remained after the helper completed",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        remove_known_helper_residue(&self.fixture.pin_root)?;
        <S1 as SpikeTest>::cleanup(&mut self.fixture, context)
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)
    }
}

fn verify_helper_semantics(
    stdout: &str,
    fields: &BTreeMap<String, String>,
    target_inode: u64,
) -> Result<Vec<HookResult>, TestError> {
    for phase in PHASES {
        if parse_u64(fields, &format!("{phase}_target_cgroup_inode"))? != target_inode
            || !parse_bool(fields, &format!("{phase}_proc_exact_membership"))?
            || !parse_bool(fields, &format!("{phase}_cgroup_procs_contains_agent"))?
            || !parse_bool(fields, &format!("{phase}_netns_exact_membership"))?
        {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S5 {phase} live membership was not proven"),
            ));
        }
        let omitted = phase.contains("omitted");
        let expected = if omitted { 5 } else { 6 };
        if parse_u64(fields, &format!("{phase}_direct_program_count"))? != expected
            || parse_u64(fields, &format!("{phase}_effective_program_count"))? != expected
        {
            return Err(TestError::new(
                Verdict::Unproven,
                format!("S5 {phase} attachment set disagreed"),
            ));
        }
    }

    let pairs = [
        (
            "sock_create",
            "sock-create-inet6-deny",
            "sock-create-inet6-control",
            Some(3),
            false,
        ),
        (
            "connect4",
            "connect4-deny",
            "connect4-omitted-control",
            Some(4),
            true,
        ),
        (
            "connect6",
            "connect6-deny",
            "connect6-omitted-control",
            Some(5),
            true,
        ),
        (
            "sendmsg4",
            "sendmsg4-deny",
            "sendmsg4-omitted-control",
            Some(6),
            true,
        ),
        (
            "sendmsg6",
            "sendmsg6-deny",
            "sendmsg6-omitted-control",
            Some(7),
            true,
        ),
        (
            "sockops",
            "sockops-omitted",
            "sockops-present-control",
            None,
            true,
        ),
    ];
    let mut results = Vec::new();
    for (hook, deny, control, counter_index, control_delivery) in pairs {
        let deny_ok = output_ok(stdout, deny)?;
        let control_ok = output_ok(stdout, control)?;
        let deny_observed = if hook == "sockops" {
            !deny_ok
                && required(fields, "sockops-omitted_resolve_result")? == "TIMEOUT_DENY"
                && parse_u64(fields, "sockops-omitted_tuple_entries")? == 0
        } else {
            let counters = parse_array(fields, &format!("{deny}_counters"))?;
            !deny_ok
                && counter_index.is_some_and(|index| counters.get(index) == Some(&1))
                && parse_u64(fields, &format!("{deny}_deny_entries"))? == 1
                && parse_u64(fields, &format!("{deny}_event_count"))? == 1
        };
        let control_exposed_path = control_ok
            && if control_delivery {
                if hook.starts_with("sendmsg") {
                    parse_bool(fields, &format!("{control}_datagram_received"))?
                } else if hook == "sockops" {
                    required(fields, "sockops-present-control_resolve_result")?
                        == "s5-execution-generation-1"
                } else {
                    parse_bool(fields, &format!("{control}_listener_accepted"))?
                }
            } else {
                let counters = parse_array(fields, &format!("{control}_counters"))?;
                counters
                    .get(3..=7)
                    .is_some_and(|values| values.iter().all(|value| *value == 0))
            };
        results.push(HookResult {
            hook: hook.to_owned(),
            deny_phase: deny.to_owned(),
            control_phase: control.to_owned(),
            deny_counter_index: counter_index,
            deny_observed,
            control_exposed_path,
            membership_proven: true,
            expected_attachment_counts: true,
        });
    }
    Ok(results)
}

fn output_ok(stdout: &str, phase: &str) -> Result<bool, TestError> {
    let start = format!("{phase}_agent_stdout_begin\n");
    let end = format!("{phase}_agent_stdout_end");
    let body = stdout
        .split_once(&start)
        .and_then(|(_, remainder)| remainder.split_once(&end))
        .map(|(body, _)| body)
        .ok_or_else(|| TestError::infra(format!("S5 {phase} agent output missing")))?;
    let values = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TestError::infra(format!("parse S5 {phase} agent JSON: {error}")))?;
    values
        .last()
        .and_then(|value| value.get("ok"))
        .and_then(Value::as_bool)
        .ok_or_else(|| TestError::infra(format!("S5 {phase} agent outcome missing")))
}

fn parse_fields(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn required<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, TestError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| TestError::infra(format!("S5 field {key} missing")))
}

fn parse_u64(fields: &BTreeMap<String, String>, key: &str) -> Result<u64, TestError> {
    required(fields, key)?
        .parse()
        .map_err(|error| TestError::infra(format!("parse S5 field {key}: {error}")))
}

fn parse_bool(fields: &BTreeMap<String, String>, key: &str) -> Result<bool, TestError> {
    required(fields, key)?
        .parse()
        .map_err(|error| TestError::infra(format!("parse S5 field {key}: {error}")))
}

fn parse_array(fields: &BTreeMap<String, String>, key: &str) -> Result<Vec<u64>, TestError> {
    serde_json::from_str(required(fields, key)?)
        .map_err(|error| TestError::infra(format!("parse S5 field {key}: {error}")))
}

fn directory_empty(path: &std::path::Path) -> Result<bool, TestError> {
    if !path.exists() {
        return Ok(true);
    }
    fs::read_dir(path)
        .map_err(|error| TestError::infra(format!("read S5 pin root: {error}")))?
        .next()
        .map_or(Ok(true), |entry| {
            entry
                .map(|_| false)
                .map_err(|error| TestError::infra(error.to_string()))
        })
}

fn remove_known_helper_residue(root: &std::path::Path) -> Result<(), TestError> {
    const LINKS: [&str; 6] = [
        "sock_create",
        "connect4",
        "connect6",
        "sendmsg4",
        "sendmsg6",
        "sock_ops",
    ];
    const MAPS: [&str; 11] = [
        "soglia_policy",
        "soglia_tuples",
        "soglia_cookie_a",
        "soglia_sk_b",
        "soglia_events",
        "soglia_counters",
        "soglia_denies",
        "soglia_meta",
        "soglia_diag_entries",
        "soglia_port_diag",
        "soglia_staging",
    ];
    for phase in PHASES {
        for name in LINKS {
            remove_if_present(&root.join("links").join(phase).join(name))?;
        }
        for name in MAPS {
            remove_if_present(&root.join("maps").join(phase).join(name))?;
        }
        remove_dir_if_empty(&root.join("links").join(phase))?;
        remove_dir_if_empty(&root.join("maps").join(phase))?;
    }
    remove_dir_if_empty(&root.join("links"))?;
    remove_dir_if_empty(&root.join("maps"))?;
    Ok(())
}

fn remove_if_present(path: &std::path::Path) -> Result<(), TestError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TestError::infra(format!(
            "remove {}: {error}",
            path.display()
        ))),
    }
}

fn remove_dir_if_empty(path: &std::path::Path) -> Result<(), TestError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(TestError::infra(format!(
            "remove {}: {error}",
            path.display()
        ))),
    }
}
