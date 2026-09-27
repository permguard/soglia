// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{CommandExecutor, CommandOutput, CommandSpec};
use crate::context::TestContext;
use crate::model::{TestId, Verdict};
use crate::tests::s1::{S1, S1Observation, json_cgroup};
use crate::tests::{SpikeTest, TestError};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LifecycleInventory {
    owned_cgroups: Vec<String>,
    owned_processes: Vec<String>,
    runc_containers: Value,
    netns: String,
    links: Value,
    nft: Value,
    bpffs_paths: Vec<String>,
    bpf_programs: Value,
    bpf_links: Value,
    bpf_maps: Value,
    runtime_paths: Vec<String>,
    owned_program_ids: Vec<u64>,
    owned_map_ids: Vec<u64>,
    owned_link_ids: Vec<u64>,
    owned_netns: Vec<String>,
    owned_interfaces: Vec<String>,
    owned_nft_tables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S11Observation {
    baseline: LifecycleInventory,
    lifecycle: S1Observation,
    live: LifecycleInventory,
    live_child_direct: Value,
    live_child_effective: Value,
    expected_resource_classes_created: bool,
    teardown_model: Vec<String>,
    failure_control_reused: Vec<String>,
}

pub struct S11 {
    fixture: S1,
    baseline: Option<LifecycleInventory>,
}

impl S11 {
    pub fn new(context: &TestContext) -> Self {
        Self {
            fixture: S1::new_s11(context),
            baseline: None,
        }
    }

    fn commands(&self, context: &TestContext) -> CommandExecutor {
        self.fixture.commands(context)
    }
}

impl SpikeTest for S11 {
    type Observation = S11Observation;

    fn id(&self) -> TestId {
        TestId::S11
    }

    fn invariant(&self) -> &'static str {
        "a representative attributed Execution lifecycle creates every owned resource class and trusted teardown leaves zero Soglia-owned residue"
    }

    fn prepare(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        let baseline = capture_inventory(
            &self.commands(context),
            &context.run_id,
            &self.fixture.runtime_root,
        )?;
        context
            .evidence
            .write_json("s11/baseline.json", &baseline)
            .map_err(|error| TestError::infra(format!("write S11 baseline: {error}")))?;
        if has_owned_residue(&baseline, &context.run_id) {
            return Err(TestError::new(
                Verdict::Unproven,
                "S11 fresh baseline already contained Soglia-owned residue",
            ));
        }
        self.baseline = Some(baseline);
        <S1 as SpikeTest>::prepare(&mut self.fixture, context)
    }

    fn execute(&mut self, context: &mut TestContext) -> Result<Self::Observation, TestError> {
        let lifecycle = <S1 as SpikeTest>::execute(&mut self.fixture, context)?;
        <S1 as SpikeTest>::verify(&self.fixture, context, &lifecycle)?;
        let live = capture_inventory(
            &self.commands(context),
            &context.run_id,
            &self.fixture.runtime_root,
        )?;
        let target = self.fixture.target()?.to_path_buf();
        let live_child_direct = json_cgroup(&self.commands(context), &target, false)?;
        let live_child_effective = json_cgroup(&self.commands(context), &target, true)?;
        let expected_resource_classes_created = lifecycle.live_membership_proven
            && lifecycle.resolved_execution == "s11-execution-generation-1"
            && live
                .owned_cgroups
                .iter()
                .any(|path| path == &target.to_string_lossy())
            && live
                .owned_netns
                .iter()
                .any(|name| name == &self.fixture.netns)
            && live.owned_interfaces.len() == 2
            && live.owned_nft_tables.len() == 1
            && live.owned_program_ids.len() == 6
            && live.owned_link_ids.len() == 6
            && !live.owned_map_ids.is_empty()
            && live
                .bpffs_paths
                .iter()
                .any(|path| path.contains(&context.run_id) && path.contains("/s11/"));
        context
            .evidence
            .write_json("s11/live.json", &live)
            .map_err(|error| TestError::infra(format!("write S11 live inventory: {error}")))?;
        Ok(S11Observation {
            baseline: self
                .baseline
                .clone()
                .ok_or_else(|| TestError::infra("S11 baseline missing"))?,
            lifecycle,
            live,
            live_child_direct,
            live_child_effective,
            expected_resource_classes_created,
            teardown_model: [
                "prevent new effects and kill/reap Execution processes",
                "drop BPF links and map handles",
                "remove exact nft table and network interfaces/netns",
                "remove child and delegated cgroups",
                "remove pins and runtime ownership paths",
                "independently compare fresh post-state with baseline",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            failure_control_reused: [
                "S3 generation reuse checks",
                "S7 loader death and pin cleanup checks",
                "S8 autonomous enforcer-loss cleanup checks",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        })
    }

    fn verify(
        &self,
        _context: &TestContext,
        observation: &Self::Observation,
    ) -> Result<(), TestError> {
        if !observation.expected_resource_classes_created
            || observation
                .live_child_direct
                .as_array()
                .is_none_or(|programs| programs.len() != 6)
            || observation
                .live_child_effective
                .as_array()
                .is_none_or(|programs| programs.len() != 6)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S11 representative lifecycle did not prove every expected owned resource class",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::cleanup(&mut self.fixture, context)
    }

    fn verify_cleanup(&self, context: &mut TestContext) -> Result<(), TestError> {
        <S1 as SpikeTest>::verify_cleanup(&self.fixture, context)?;
        let after = capture_inventory(
            &self.commands(context),
            &context.run_id,
            &self.fixture.runtime_root,
        )?;
        context
            .evidence
            .write_json("s11/after.json", &after)
            .map_err(|error| TestError::infra(format!("write S11 after inventory: {error}")))?;
        let baseline = self
            .baseline
            .as_ref()
            .ok_or_else(|| TestError::infra("S11 cleanup baseline missing"))?;
        let comparison = serde_json::json!({
            "owned_residue_absent": !has_owned_residue(&after, &context.run_id),
            "runc_baseline_equal": stable_json(&baseline.runc_containers) == stable_json(&after.runc_containers),
            "netns_baseline_equal": baseline.netns == after.netns,
            "host_link_structure_equal": stable_links(&baseline.links) == stable_links(&after.links),
            "host_nft_structure_equal": stable_nft(&baseline.nft) == stable_nft(&after.nft),
            "bpffs_baseline_equal": baseline.bpffs_paths == after.bpffs_paths,
            "bpf_program_identity_equal": stable_programs(&baseline.bpf_programs) == stable_programs(&after.bpf_programs),
            "bpf_link_identity_equal": stable_bpf(&baseline.bpf_links) == stable_bpf(&after.bpf_links),
            "bpf_map_identity_equal": stable_bpf(&baseline.bpf_maps) == stable_bpf(&after.bpf_maps),
            "runtime_baseline_equal": baseline.runtime_paths == after.runtime_paths,
            "external_churn_policy": "whole-host differences are recorded but only exact Soglia ownership absence is security-gating",
        });
        context
            .evidence
            .write_json("s11/comparison.json", &comparison)
            .map_err(|error| TestError::infra(format!("write S11 comparison: {error}")))?;
        if has_owned_residue(&after, &context.run_id) {
            return Err(TestError::new(
                Verdict::Fail,
                "S11 independent post-teardown audit found Soglia-owned residue",
            ));
        }
        if baseline.bpffs_paths != after.bpffs_paths
            || baseline.runtime_paths != after.runtime_paths
            || stable_nft(&baseline.nft) != stable_nft(&after.nft)
        {
            return Err(TestError::new(
                Verdict::Unproven,
                "S11 security-relevant bpffs/runtime/nft baseline was not restored",
            ));
        }
        context.resources.mark_owner_cleaned("s11");
        Ok(())
    }
}

fn capture_inventory(
    commands: &CommandExecutor,
    run_id: &str,
    runtime_root: &Path,
) -> Result<LifecycleInventory, TestError> {
    let runc_output = commands
        .run(&CommandSpec::new("runc").args(["list", "--format", "json"]))
        .map_err(TestError::infra)?;
    let runc_containers = if runc_output.success() {
        serde_json::from_slice(&runc_output.stdout)
            .map_err(|error| TestError::infra(format!("parse S11 runc inventory: {error}")))?
    } else if runc_output
        .stderr_text()
        .contains("open /run/runc: no such file or directory")
    {
        Value::Array(Vec::new())
    } else {
        return Err(TestError::infra(format!(
            "S11 runc inventory failed: exit={:?} signal={:?} stderr={}",
            runc_output.record.exit_code,
            runc_output.record.signal,
            runc_output.stderr_text()
        )));
    };
    let links = json_output(
        commands,
        CommandSpec::new("ip").args(["-j", "-details", "link", "show"]),
        "S11 link inventory",
    )?;
    let nft = json_output(
        commands,
        CommandSpec::new("nft").args(["-j", "list", "ruleset"]),
        "S11 nft inventory",
    )?;
    let bpf_programs = json_output(
        commands,
        CommandSpec::new("bpftool").args(["-j", "prog", "show"]),
        "S11 BPF program inventory",
    )?;
    let bpf_links = json_output(
        commands,
        CommandSpec::new("bpftool").args(["-j", "link", "show"]),
        "S11 BPF link inventory",
    )?;
    let bpf_maps = json_output(
        commands,
        CommandSpec::new("bpftool").args(["-j", "map", "show"]),
        "S11 BPF map inventory",
    )?;
    let netns_output = commands
        .run(&CommandSpec::new("ip").args(["netns", "list"]))
        .map_err(TestError::infra)?;
    require_success(&netns_output, "S11 netns inventory")?;
    let netns = netns_output.stdout_text();
    let owned_program_ids = bpf_programs
        .as_array()
        .into_iter()
        .flatten()
        .filter(|program| {
            program
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("soglia_") || name.starts_with("foreign_"))
        })
        .filter_map(|program| program.get("id").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    let owned_map_ids = bpf_maps
        .as_array()
        .into_iter()
        .flatten()
        .filter(|map| {
            map.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("soglia_") || name == "policy_local")
        })
        .filter_map(|map| map.get("id").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    let owned_link_ids = bpf_links
        .as_array()
        .into_iter()
        .flatten()
        .filter(|link| {
            link.get("prog_id")
                .and_then(Value::as_u64)
                .is_some_and(|id| owned_program_ids.contains(&id))
        })
        .filter_map(|link| link.get("id").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    let owned_netns = netns
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.starts_with("sg-s11-"))
        .map(str::to_owned)
        .collect();
    let owned_interfaces = links
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|link| link.get("ifname").and_then(Value::as_str))
        .filter(|name| name.starts_with("s11h") || name.starts_with("s11p"))
        .map(str::to_owned)
        .collect();
    let owned_nft_tables = nft_table_names(&nft)
        .into_iter()
        .filter(|name| name.starts_with("sg_s11_"))
        .collect();
    let cgroup_root = Path::new("/sys/fs/cgroup/system.slice");
    let owned_cgroups = collect_paths(cgroup_root, 5, |path| {
        path.to_string_lossy().contains("soglia-spike-s11-")
    })?;
    let owned_processes = collect_owned_processes(runtime_root)?;
    let bpffs_paths = collect_paths(Path::new("/sys/fs/bpf"), 8, |_| true)?;
    let runtime_parent = runtime_root
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/run/soglia-spike-runner"));
    let runtime_paths = collect_paths(runtime_parent, 4, |path| {
        path.to_string_lossy().contains(run_id)
    })?;
    Ok(LifecycleInventory {
        owned_cgroups,
        owned_processes,
        runc_containers,
        netns,
        links,
        nft,
        bpffs_paths,
        bpf_programs,
        bpf_links,
        bpf_maps,
        runtime_paths,
        owned_program_ids,
        owned_map_ids,
        owned_link_ids,
        owned_netns,
        owned_interfaces,
        owned_nft_tables,
    })
}

fn has_owned_residue(inventory: &LifecycleInventory, run_id: &str) -> bool {
    !inventory.owned_cgroups.is_empty()
        || !inventory.owned_processes.is_empty()
        || !inventory.owned_program_ids.is_empty()
        || !inventory.owned_map_ids.is_empty()
        || !inventory.owned_link_ids.is_empty()
        || !inventory.owned_netns.is_empty()
        || !inventory.owned_interfaces.is_empty()
        || !inventory.owned_nft_tables.is_empty()
        || inventory
            .bpffs_paths
            .iter()
            .any(|path| path.contains(run_id))
        || inventory
            .runtime_paths
            .iter()
            .any(|path| path.contains(run_id))
}

fn collect_owned_processes(runtime_root: &Path) -> Result<Vec<String>, TestError> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")
        .map_err(|error| TestError::infra(format!("read /proc for S11: {error}")))?
    {
        let entry =
            entry.map_err(|error| TestError::infra(format!("read /proc entry: {error}")))?;
        if !entry
            .file_name()
            .to_string_lossy()
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            continue;
        }
        let Ok(bytes) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let command = String::from_utf8_lossy(&bytes).replace('\0', " ");
        if command.contains("soglia-spike-agent")
            || command.contains(runtime_root.to_string_lossy().as_ref())
        {
            processes.push(format!("{} {command}", entry.file_name().to_string_lossy()));
        }
    }
    processes.sort();
    Ok(processes)
}

fn collect_paths(
    root: &Path,
    depth: usize,
    include: impl Fn(&Path) -> bool + Copy,
) -> Result<Vec<String>, TestError> {
    fn visit(
        root: &Path,
        depth: usize,
        include: impl Fn(&Path) -> bool + Copy,
        paths: &mut Vec<String>,
    ) -> Result<(), TestError> {
        if depth == 0 || !root.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(root)
            .map_err(|error| TestError::infra(format!("read {}: {error}", root.display())))?
        {
            let entry = entry.map_err(|error| TestError::infra(error.to_string()))?;
            let path = entry.path();
            if include(&path) {
                paths.push(path.to_string_lossy().into_owned());
            }
            if entry
                .file_type()
                .map_err(|error| TestError::infra(error.to_string()))?
                .is_dir()
            {
                visit(&path, depth - 1, include, paths)?;
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    visit(root, depth, include, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn nft_table_names(value: &Value) -> Vec<String> {
    fn visit(value: &Value, names: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                if let Some(name) = object
                    .get("table")
                    .and_then(Value::as_object)
                    .and_then(|table| table.get("name"))
                    .and_then(Value::as_str)
                {
                    names.push(name.to_owned());
                }
                object.values().for_each(|value| visit(value, names));
            }
            Value::Array(values) => values.iter().for_each(|value| visit(value, names)),
            _ => {}
        }
    }
    let mut names = Vec::new();
    visit(value, &mut names);
    names.sort();
    names.dedup();
    names
}

fn json_output(
    commands: &CommandExecutor,
    spec: CommandSpec,
    label: &str,
) -> Result<Value, TestError> {
    let output = commands.run(&spec).map_err(TestError::infra)?;
    require_success(&output, label)?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| TestError::infra(format!("parse {label}: {error}")))
}

fn require_success(output: &CommandOutput, context: &str) -> Result<(), TestError> {
    output.require_success(context).map_err(TestError::infra)
}

fn stable_json(value: &Value) -> Value {
    value.clone()
}

fn stable_programs(value: &Value) -> Value {
    let mut programs = value.as_array().cloned().unwrap_or_default();
    for program in &mut programs {
        if let Value::Object(object) = program {
            for key in [
                "id",
                "loaded_at",
                "run_time_ns",
                "run_cnt",
                "recursion_misses",
            ] {
                object.remove(key);
            }
        }
    }
    programs.sort_by_key(Value::to_string);
    Value::Array(programs)
}

fn stable_bpf(value: &Value) -> Value {
    let mut entries = value.as_array().cloned().unwrap_or_default();
    for entry in &mut entries {
        strip_keys(
            entry,
            &[
                "id",
                "prog_id",
                "map_ids",
                "loaded_at",
                "run_time_ns",
                "run_cnt",
            ],
        );
    }
    entries.sort_by_key(Value::to_string);
    Value::Array(entries)
}

fn stable_links(value: &Value) -> Value {
    let mut entries = value.as_array().cloned().unwrap_or_default();
    for entry in &mut entries {
        strip_keys(
            entry,
            &[
                "ifindex",
                "link_index",
                "master",
                "promiscuity",
                "num_tx_queues",
                "num_rx_queues",
            ],
        );
    }
    entries.sort_by_key(Value::to_string);
    Value::Array(entries)
}

fn stable_nft(value: &Value) -> Value {
    let mut value = value.clone();
    strip_keys(&mut value, &["handle", "packets", "bytes"]);
    value
}

fn strip_keys(value: &mut Value, keys: &[&str]) {
    match value {
        Value::Object(object) => {
            for key in keys {
                object.remove(*key);
            }
            object
                .values_mut()
                .for_each(|value| strip_keys(value, keys));
        }
        Value::Array(values) => values.iter_mut().for_each(|value| strip_keys(value, keys)),
        _ => {}
    }
}
