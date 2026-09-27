// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::tests::s1::json_command;
use crate::tests::{SpikeTest, TestError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct KernelSnapshot {
    programs: Value,
    links: Value,
    maps: Value,
    bpffs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceSource {
    test: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnforcementRow {
    property: String,
    primary_observed_enforcement: String,
    other_observed_constraint: String,
    negative_or_isolation_evidence: String,
    source_tests: Vec<String>,
    proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S6Observation {
    runtime_mutations: u64,
    candidate_selected: bool,
    production_code_modified: bool,
    sources: Vec<EvidenceSource>,
    rows: Vec<EnforcementRow>,
    reserved_s7_loader_loss_established: bool,
    reserved_s8_helper_death_established: bool,
    reserved_s9_s10_foreign_order_established: bool,
}

pub struct S6 {
    baseline: Option<KernelSnapshot>,
}

impl S6 {
    pub const fn new(_context: &TestContext) -> Self {
        Self { baseline: None }
    }
}

impl SpikeTest for S6 {
    type Observation = S6Observation;

    fn id(&self) -> TestId {
        TestId::S6
    }

    fn invariant(&self) -> &'static str {
        "the enforcement-layer table is derived only from structured S1-S5 evidence and distinguishes primary enforcement, defense-in-depth, topology and unestablished later properties"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        for test in ["s1", "s1b", "s2", "s3", "s4", "s5"] {
            let path = context.evidence.root().join(test).join("observations.json");
            if !path.is_file() {
                return Err(TestError::new(
                    Verdict::Unproven,
                    format!(
                        "S6 requires same-run structured {test} observations; run diagnostic mode from S0"
                    ),
                ));
            }
        }
        self.baseline = Some(kernel_snapshot(context)?);
        Ok(())
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let mut evidence = std::collections::BTreeMap::new();
        let mut sources = Vec::new();
        for test in ["s1", "s1b", "s2", "s3", "s4", "s5"] {
            let relative = format!("{test}/observations.json");
            let path = context.evidence.root().join(&relative);
            let bytes = fs::read(&path)
                .map_err(|error| TestError::infra(format!("read S6 source {relative}: {error}")))?;
            let value = serde_json::from_slice::<Value>(&bytes).map_err(|error| {
                TestError::infra(format!("parse S6 source {relative}: {error}"))
            })?;
            sources.push(EvidenceSource {
                test: test.to_owned(),
                path: relative,
                sha256: hex(&Sha256::digest(&bytes)),
            });
            evidence.insert(test, value);
        }

        let s1 = evidence["s1"].clone();
        let s1b = evidence["s1b"].clone();
        let s2 = evidence["s2"].clone();
        let s3 = evidence["s3"].clone();
        let s4 = evidence["s4"].clone();
        let s5 = evidence["s5"].clone();
        let placement = bool_at(&s1, "/live_membership_proven")?;
        let resolve = string_at(&s1, "/resolved_execution")? == "s1-execution-e1-generation-1"
            && u64_at(&s1, "/application_bytes_read_before_resolve")? == 0
            && !bool_at(&s1, "/ip_fallback_authorization")?;
        let delayed_fail_closed = bool_at(&s1b, "/timeout_denied")?
            && u64_at(&s1b, "/application_bytes_read_while_unresolved")? == 0
            && u64_at(&s1b, "/dns_while_unresolved")? == 0
            && u64_at(&s1b, "/outbound_effects_while_unresolved")? == 0
            && !bool_at(&s1b, "/ip_fallback_authorization")?;
        let concurrent_isolation = u64_at(&s2, "/metrics/s2_connection_count")? == 132
            && u64_at(&s2, "/metrics/s2_cross_attribution_count")? == 0
            && u64_at(&s2, "/metrics/s2_attribution_mismatches")? == 0
            && u64_at(&s2, "/metrics/s2_timeouts")? == 4;
        let lifecycle_isolation = u64_at(&s3, "/old_generation_resolved_as_new")? == 0
            && u64_at(&s3, "/cross_generation_attribution_count")? == 0
            && u64_at(&s3, "/stale_tuple_or_cookie_residue_after_each_phase")? == 0;
        let nft_and_bpf = bool_at(&s4, "/nft_relaxation_demonstrated")?
            && bool_at(&s4, "/nft_restoration_exact")?
            && !bool_at(&s4, "/deny_listener_accepted")?
            && bool_at(&s4, "/exposure_listener_accepted")?;
        let hook = |name: &str| -> Result<bool, TestError> {
            s5.pointer("/hooks")
                .and_then(Value::as_array)
                .and_then(|hooks| {
                    hooks
                        .iter()
                        .find(|hook| hook.get("hook").and_then(Value::as_str) == Some(name))
                })
                .map(|hook| {
                    Ok(bool_at(hook, "/deny_observed")?
                        && bool_at(hook, "/control_exposed_path")?
                        && bool_at(hook, "/membership_proven")?
                        && bool_at(hook, "/expected_attachment_counts")?)
                })
                .transpose()?
                .ok_or_else(|| TestError::infra(format!("S6 S5 hook {name} missing")))
        };
        let sockops_fail_closed = hook("sockops")?
            && string_at(&s5, "/sockops_omitted_resolve")? == "TIMEOUT_DENY"
            && u64_at(&s5, "/sockops_omitted_application_reads")? == 0
            && !bool_at(&s5, "/sockops_omitted_ip_fallback")?;

        let rows = vec![
            row(
                "Live process belongs to the current Execution",
                "trusted launcher/runtime placement into the delegated cgroup",
                "owned netns entry checked independently by inode",
                "live PID, /proc cgroup, cgroup.procs and netns inode agree",
                &["s1", "s2"],
                placement,
            ),
            row(
                "IPv6 stream socket creation is rejected early",
                "cgroup-BPF sock_create",
                "connect6 remains an independent later gate",
                "relaxing only IPv6 stream creation makes socket creation succeed",
                &["s5"],
                hook("sock_create")?,
            ),
            row(
                "Direct IPv4 TCP is rejected early",
                "cgroup-BPF connect4",
                "namespace nft output policy remains the final destination barrier",
                "exact nft relaxation still denies with BPF; omitting only connect4 exposes the listener",
                &["s4", "s5"],
                nft_and_bpf && hook("connect4")?,
            ),
            row(
                "IPv6 TCP connect is rejected",
                "cgroup-BPF connect6",
                "sock_create is the earlier independent gate",
                "with creation relaxed, omitting only connect6 exposes the IPv6 listener",
                &["s5"],
                hook("connect6")?,
            ),
            row(
                "IPv4 UDP emission is rejected",
                "cgroup-BPF sendmsg4",
                "sock_create and namespace nft are separate gates",
                "with datagram creation relaxed, omitting only sendmsg4 delivers the datagram",
                &["s5"],
                hook("sendmsg4")?,
            ),
            row(
                "IPv6 UDP emission is rejected",
                "cgroup-BPF sendmsg6",
                "sock_create and namespace nft are separate gates",
                "with datagram creation relaxed, omitting only sendmsg6 delivers the datagram",
                &["s5"],
                hook("sendmsg6")?,
            ),
            row(
                "Only the proxy destination is reachable normally",
                "namespace nft output chain",
                "connect4 is earlier IPv4 defense; route/forward policy constrains topology",
                "BPF-permissive normal control is blocked until one exact nft exception is added",
                &["s4"],
                nft_and_bpf,
            ),
            row(
                "Candidate A/B state is captured for admitted IPv4 proxy connect",
                "cgroup-BPF connect4",
                "sockops later consumes it",
                "sockops omission retains one cookie but publishes no final tuple",
                &["s5"],
                sockops_fail_closed && u64_at(&s5, "/sockops_omitted_cookie_entries")? == 1,
            ),
            row(
                "Accepted tuple becomes resolvable",
                "cgroup-BPF sockops publishes; proxy correlates",
                "IP remains a cross-check only",
                "omitting only sockops leaves established TCP without tuple publication",
                &["s1", "s5"],
                resolve && sockops_fail_closed,
            ),
            row(
                "Missing/delayed attribution does not authorize",
                "proxy bounded Resolve",
                "BPF maps provide evidence but do not authorize",
                "missing publication times out without read, DNS, effect or IP fallback",
                &["s1b", "s5"],
                delayed_fail_closed && sockops_fail_closed,
            ),
            row(
                "Concurrent sockets are not cross-attributed",
                "per-socket/per-instance evidence plus proxy tuple correlation",
                "source IP is not authorization",
                "132 sockets across four Executions produce zero cross-attribution",
                &["s2"],
                concurrent_isolation,
            ),
            row(
                "Old lifecycle state does not authorize a new generation",
                "sockops close cleanup plus runner-owned Execution teardown",
                "map teardown removes remaining test state",
                "FIN/RST reuse and SIGKILL generations show zero cross-generation attribution/residue",
                &["s3", "s5"],
                lifecycle_isolation,
            ),
        ];
        let observation = S6Observation {
            runtime_mutations: 0,
            candidate_selected: false,
            production_code_modified: false,
            sources,
            rows,
            reserved_s7_loader_loss_established: false,
            reserved_s8_helper_death_established: false,
            reserved_s9_s10_foreign_order_established: false,
        };
        context
            .evidence
            .write_text("s6/enforcement-layer-table.md", &render_table(&observation))
            .map_err(|error| TestError::infra(format!("write S6 table: {error}")))?;
        Ok(observation)
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if observation.runtime_mutations != 0
            || observation.candidate_selected
            || observation.production_code_modified
            || observation.sources.len() != 6
            || observation.rows.len() != 12
            || observation.rows.iter().any(|row| !row.proven)
            || observation.reserved_s7_loader_loss_established
            || observation.reserved_s8_helper_death_established
            || observation.reserved_s9_s10_foreign_order_established
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S6 synthesis included an unproven row or exceeded S1-S5 evidence",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, _context: &mut TestContext) -> Result<(), TestError> {
        Ok(())
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        let final_snapshot = kernel_snapshot(context)?;
        let clean = self.baseline.as_ref() == Some(&final_snapshot);
        context
            .evidence
            .write_json(
                "s6/cleanup.json",
                &serde_json::json!({"read_only_kernel_baseline_equal": clean, "clean": clean}),
            )
            .map_err(|error| TestError::infra(format!("write S6 cleanup: {error}")))?;
        if !clean {
            return Err(TestError::new(
                Verdict::CleanupFail,
                "S6 read-only kernel/bpffs baseline changed",
            ));
        }
        Ok(())
    }
}

fn kernel_snapshot(context: &TestContext) -> Result<KernelSnapshot, TestError> {
    let commands = context.test_commands("s6");
    Ok(KernelSnapshot {
        programs: stable(json_command(&commands, ["-j", "prog", "show"])?),
        links: stable(json_command(&commands, ["-j", "link", "show"])?),
        maps: stable(json_command(&commands, ["-j", "map", "show"])?),
        bpffs: walk_paths(Path::new("/sys/fs/bpf"))?,
    })
}

fn walk_paths(root: &Path) -> Result<Vec<String>, TestError> {
    let mut pending = vec![root.to_path_buf()];
    let mut paths = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| TestError::infra(format!("read {}: {error}", directory.display())))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TestError::infra(error.to_string()))?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            paths.push(path.to_string_lossy().into_owned());
            if entry
                .file_type()
                .map_err(|error| TestError::infra(error.to_string()))?
                .is_dir()
            {
                pending.push(path);
            }
        }
    }
    paths.sort();
    Ok(paths)
}

fn stable(mut value: Value) -> Value {
    strip_volatile(&mut value);
    value
}

fn strip_volatile(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(strip_volatile),
        Value::Object(values) => {
            for key in ["loaded_at", "run_time_ns", "run_cnt", "recursion_misses"] {
                values.remove(key);
            }
            values.values_mut().for_each(strip_volatile);
        }
        _ => {}
    }
}

fn row(
    property: &str,
    primary: &str,
    other: &str,
    isolation: &str,
    sources: &[&str],
    proven: bool,
) -> EnforcementRow {
    EnforcementRow {
        property: property.to_owned(),
        primary_observed_enforcement: primary.to_owned(),
        other_observed_constraint: other.to_owned(),
        negative_or_isolation_evidence: isolation.to_owned(),
        source_tests: sources.iter().map(|source| (*source).to_owned()).collect(),
        proven,
    }
}

fn render_table(observation: &S6Observation) -> String {
    let mut markdown = String::from(
        "<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->\n<!-- SPDX-License-Identifier: Apache-2.0 -->\n\n# S6 actual enforcement-layer table\n\nThis table is generated only from structured observations in this same replay. It selects no attribution candidate.\n\n| Property | Primary observed enforcement | Other observed constraint / defense | Negative or isolation evidence | Sources |\n| --- | --- | --- | --- | --- |\n",
    );
    for row in &observation.rows {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            row.property,
            row.primary_observed_enforcement,
            row.other_observed_constraint,
            row.negative_or_isolation_evidence,
            row.source_tests.join(", ")
        ));
    }
    markdown.push_str("\nLater properties remain explicitly unestablished: loader loss (S7), helper death (S8), and foreign ancestor execution/order (S9/S10).\n");
    markdown
}

fn bool_at(value: &Value, pointer: &str) -> Result<bool, TestError> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| TestError::infra(format!("S6 boolean {pointer} missing")))
}

fn u64_at(value: &Value, pointer: &str) -> Result<u64, TestError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| TestError::infra(format!("S6 number {pointer} missing")))
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, TestError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| TestError::infra(format!("S6 string {pointer} missing")))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
