// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::resources::{Resource, ResourceEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfInventory {
    pub programs: Value,
    pub links: Value,
    pub maps: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InventoryClassification {
    Clean,
    ExternalChurn,
    Drift,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryAssessment {
    pub clean: bool,
    pub classification: InventoryClassification,
    pub detail: String,
    pub owned_objects_present: Vec<String>,
    pub links_identical: bool,
    pub maps_identical: bool,
    pub systemd_program_ids_before: Vec<u64>,
    pub systemd_program_ids_after: Vec<u64>,
}

#[must_use]
pub fn assess(
    before: &BpfInventory,
    after: &BpfInventory,
    registry: &[ResourceEntry],
    owner: &str,
) -> InventoryAssessment {
    let links_identical = strict_inventory(&before.links) == strict_inventory(&after.links);
    let maps_identical = strict_inventory(&before.maps) == strict_inventory(&after.maps);
    let owned_objects_present = owned_objects_present(after, registry, owner);
    let after_has_soglia = contains_program_prefix(&after.programs, "soglia_");

    let before_programs = stable_array(&before.programs);
    let after_programs = stable_array(&after.programs);
    let exact_programs = before_programs == after_programs;
    let systemd_program_ids_before = program_ids(&before.programs, "sd_");
    let systemd_program_ids_after = program_ids(&after.programs, "sd_");

    let external_churn = !exact_programs
        && non_systemd_programs(&before_programs) == non_systemd_programs(&after_programs)
        && systemd_programs_without_ids(&before_programs)
            == systemd_programs_without_ids(&after_programs);

    let clean = (exact_programs || external_churn)
        && links_identical
        && maps_identical
        && owned_objects_present.is_empty()
        && !after_has_soglia;
    let classification = if !clean {
        InventoryClassification::Drift
    } else if external_churn {
        InventoryClassification::ExternalChurn
    } else {
        InventoryClassification::Clean
    };
    let detail = match classification {
        InventoryClassification::Clean => {
            "host BPF inventory unchanged and all registered test-owned objects absent".to_owned()
        }
        InventoryClassification::ExternalChurn => format!(
            "EXTERNAL_CHURN: systemd sd_* program IDs changed {systemd_program_ids_before:?} -> {systemd_program_ids_after:?}; the complete stable sd_* object multiset excluding IDs, all non-systemd programs, links and maps are unchanged; all registered test-owned objects are absent"
        ),
        InventoryClassification::Drift => format!(
            "unclassified BPF inventory drift: program_exact={exact_programs} systemd_replacement={external_churn} links_identical={links_identical} maps_identical={maps_identical} after_has_soglia={after_has_soglia} owned_present={owned_objects_present:?}"
        ),
    };

    InventoryAssessment {
        clean,
        classification,
        detail,
        owned_objects_present,
        links_identical,
        maps_identical,
        systemd_program_ids_before,
        systemd_program_ids_after,
    }
}

fn owned_objects_present(
    inventory: &BpfInventory,
    registry: &[ResourceEntry],
    owner: &str,
) -> Vec<String> {
    let program_ids = ids(&inventory.programs);
    let link_ids = ids(&inventory.links);
    let map_ids = ids(&inventory.maps);
    let mut present = registry
        .iter()
        .filter(|entry| entry.owner == owner)
        .filter_map(|entry| match &entry.resource {
            Resource::BpfObject { id, object_kind } => {
                let found = match object_kind.as_str() {
                    "prog" => program_ids.contains(&u64::from(*id)),
                    "link" => link_ids.contains(&u64::from(*id)),
                    "map" => map_ids.contains(&u64::from(*id)),
                    _ => true,
                };
                found.then(|| format!("{object_kind}:{id} ({})", entry.provenance))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    present.sort();
    present
}

fn ids(value: &Value) -> BTreeSet<u64> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("id").and_then(Value::as_u64))
        .collect()
}

fn program_ids(value: &Value, prefix: &str) -> Vec<u64> {
    let mut ids = value
        .as_array()
        .into_iter()
        .flatten()
        .filter(|program| {
            program
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with(prefix))
        })
        .filter_map(|program| program.get("id").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

fn contains_program_prefix(value: &Value, prefix: &str) -> bool {
    value.as_array().is_none_or(|programs| {
        programs.iter().any(|program| {
            program
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with(prefix))
        })
    })
}

fn stable_array(value: &Value) -> Vec<Value> {
    let mut values = value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![serde_json::json!({"invalid_inventory": value})]);
    values.iter_mut().for_each(strip_volatile);
    values.sort_by_key(Value::to_string);
    values
}

fn strict_inventory(value: &Value) -> Vec<Value> {
    let mut values = value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![serde_json::json!({"invalid_inventory": value})]);
    values.sort_by_key(Value::to_string);
    values
}

fn non_systemd_programs(programs: &[Value]) -> Vec<Value> {
    programs
        .iter()
        .filter(|program| {
            !program
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("sd_"))
        })
        .cloned()
        .collect()
}

fn systemd_programs_without_ids(programs: &[Value]) -> Vec<Value> {
    let mut systemd = programs
        .iter()
        .filter(|program| {
            program
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("sd_"))
        })
        .cloned()
        .collect::<Vec<_>>();
    for program in &mut systemd {
        if let Value::Object(object) = program {
            object.remove("id");
        }
    }
    systemd.sort_by_key(Value::to_string);
    systemd
}

fn strip_volatile(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values.iter_mut() {
                strip_volatile(value);
            }
            values.sort_by_key(Value::to_string);
        }
        Value::Object(object) => {
            for key in ["loaded_at", "run_time_ns", "run_cnt", "recursion_misses"] {
                object.remove(key);
            }
            object.values_mut().for_each(strip_volatile);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{BpfInventory, InventoryClassification, assess};

    const PROGRAMS_BEFORE: &str = include_str!("../testdata/bpf-inventory-s1-0078.json");
    const PROGRAMS_AFTER: &str = include_str!("../testdata/bpf-inventory-s1-0117.json");
    const LINKS_BEFORE: &str = include_str!("../testdata/bpf-inventory-s1-0079.json");
    const LINKS_AFTER: &str = include_str!("../testdata/bpf-inventory-s1-0118.json");
    const MAPS_BEFORE: &str = include_str!("../testdata/bpf-inventory-s1-0080.json");
    const MAPS_AFTER: &str = include_str!("../testdata/bpf-inventory-s1-0119.json");

    fn real_inventory() -> (BpfInventory, BpfInventory) {
        let parse = |text: &str| serde_json::from_str(text).unwrap_or(Value::Null);
        (
            BpfInventory {
                programs: parse(PROGRAMS_BEFORE),
                links: parse(LINKS_BEFORE),
                maps: parse(MAPS_BEFORE),
            },
            BpfInventory {
                programs: parse(PROGRAMS_AFTER),
                links: parse(LINKS_AFTER),
                maps: parse(MAPS_AFTER),
            },
        )
    }

    #[test]
    fn real_systemd_replacement_is_external_churn_and_clean() {
        let (before, after) = real_inventory();
        let assessment = assess(&before, &after, &[], "s1");
        assert!(assessment.clean);
        assert_eq!(
            assessment.classification,
            InventoryClassification::ExternalChurn
        );
        assert_eq!(
            assessment.systemd_program_ids_before,
            (162..=173).collect::<Vec<_>>()
        );
        assert_eq!(
            assessment.systemd_program_ids_after,
            (184..=195).collect::<Vec<_>>()
        );
    }

    #[test]
    fn extra_soglia_program_is_not_clean() {
        let (before, mut after) = real_inventory();
        if let Some(programs) = after.programs.as_array_mut() {
            programs.push(
                json!({"id":999,"type":"cgroup_sock_addr","name":"soglia_connect4","tag":"bad"}),
            );
        }
        assert!(!assess(&before, &after, &[], "s1").clean);
    }

    #[test]
    fn extra_cgroup_link_is_not_clean() {
        let (before, mut after) = real_inventory();
        if let Some(links) = after.links.as_array_mut() {
            links.push(json!({"id":999,"type":"cgroup","prog_id":999,"cgroup_id":42}));
        }
        assert!(!assess(&before, &after, &[], "s1").clean);
    }

    #[test]
    fn changed_systemd_tag_is_not_clean() {
        let (before, mut after) = real_inventory();
        if let Some(program) = after.programs.as_array_mut().and_then(|programs| {
            programs
                .iter_mut()
                .find(|program| program.get("name").and_then(Value::as_str) == Some("sd_devices"))
        }) {
            program["tag"] = json!("changed-tag");
        }
        assert!(!assess(&before, &after, &[], "s1").clean);
    }

    #[test]
    fn unknown_new_program_is_not_clean() {
        let (before, mut after) = real_inventory();
        if let Some(programs) = after.programs.as_array_mut() {
            programs
                .push(json!({"id":999,"type":"tracepoint","name":"unknown_new","tag":"abcdef"}));
        }
        assert!(!assess(&before, &after, &[], "s1").clean);
    }

    #[test]
    fn missing_non_owned_program_is_not_clean() {
        let (before, mut after) = real_inventory();
        if let Some(programs) = after.programs.as_array_mut() {
            programs.retain(|program| program.get("id").and_then(Value::as_u64) != Some(2));
        }
        assert!(!assess(&before, &after, &[], "s1").clean);
    }
}
