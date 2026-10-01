// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Production Candidate-A cgroup-BPF enforcement and attribution.
//!
//! One object and six links are shared by the complete `executions/` subtree. Per-Execution policy
//! is frozen by default and becomes active only after the Enforcer independently proves the paused
//! init's placement. All durable records and pin paths are derived from trusted configuration.

use std::collections::{BTreeMap, BTreeSet, HashMap as StdHashMap};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::{Array, HashMap, Map as AyaMap, MapData, MapError, MapInfo, RingBuf, loaded_maps};
use aya::programs::links::{FdLink, LinkError, PinnedLink};
use aya::programs::{
    CgroupAttachMode, CgroupSock, CgroupSockAddr, ProgramError, SockOps, loaded_links,
    loaded_programs,
};
use aya::{Ebpf, EbpfLoader};
use libbpf_rs::query::LinkTypeInfo;
use libbpf_rs::{
    ErrorKind as LibbpfErrorKind, Link, MapCore, MapHandle, ProgramAttachType, ProgramHandle,
    ProgramType,
};
use name_to_handle_at::{
    AT_EMPTY_PATH, FileHandle as LinuxFileHandle, name_to_handle_at, open_by_handle_at,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soglia_core::config::Config;
use soglia_core::helper::{
    ResolveAttempt, ResolveMismatch, ResolvePending, ResolveResult, SocketTupleV4,
};
use soglia_core::id::{BindingKey, ExecutionId, ExecutionNonce, ResourceTag};
use soglia_core::records;

use crate::backend::{
    BackendError, EnforcementBackend, NetnsNftBackend, NetworkSettings, PreparedNetworkUninstall,
};
use crate::system;

const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/soglia-cgroup-bpf.o"));
const STATE_FILE: &str = "state.json";
const UNINSTALL_FILE: &str = "uninstall.json";
const UNINSTALL_SCHEMA: u32 = 1;
const STATE_SCHEMA: u32 = 3;
const BPF_ABI: u32 = 2;
const META_MAGIC: u64 = 0x534f_474c_4941_4250;
const POLICY_FROZEN: u32 = 0;
const POLICY_ACTIVE: u32 = 1;
const BPF_NOEXIST: u64 = 1;
const COUNTER_COUNT: usize = 26;
const DENY_REASON_COUNT: u32 = 9;
const RING_EVENT_WIDTH: usize = 56;
// Target release can become visible asynchronously after systemd removes the old cgroup. These
// production constants are intentionally not configuration knobs: every supported environment is
// qualified against the same bounded convergence contract.
const TARGET_RELEASED_DETACH_TIMEOUT: Duration = Duration::from_secs(5);
const TARGET_RELEASED_POLL_INTERVAL: Duration = Duration::from_millis(10);
// rustix 1.1 does not yet name Linux 6.8's STATX_MNT_ID_UNIQUE bit. Keep the numeric ABI value
// local and require the kernel to echo it in stx_mask; a reusable STATX_MNT_ID is never accepted.
const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;
const PROGRAMS: [ProgramSpec; 6] = [
    ProgramSpec::single("soglia_sock_create", "sock_create"),
    ProgramSpec::single("soglia_connect4", "connect4"),
    ProgramSpec::single("soglia_connect6", "connect6"),
    ProgramSpec::single("soglia_sendmsg4", "sendmsg4"),
    ProgramSpec::single("soglia_sendmsg6", "sendmsg6"),
    ProgramSpec::single("soglia_sockops", "sock_ops"),
];
const MAPS: [&str; 7] = [
    "soglia_meta",
    "soglia_policy",
    "soglia_cookie_a",
    "soglia_tuples",
    "soglia_counters",
    "soglia_denies",
    "soglia_events",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionAttachMode {
    Single,
}

impl ProductionAttachMode {
    const fn aya(self) -> CgroupAttachMode {
        match self {
            Self::Single => CgroupAttachMode::Single,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgramSpec {
    symbol: &'static str,
    pin: &'static str,
    mode: ProductionAttachMode,
}

impl ProgramSpec {
    const fn single(symbol: &'static str, pin: &'static str) -> Self {
        Self {
            symbol,
            pin,
            mode: ProductionAttachMode::Single,
        }
    }
}

/// A production cgroup-BPF backend composed with the existing namespace/veth/nft barrier.
pub struct CgroupBpfBackend {
    network: NetnsNftBackend,
    settings: Settings,
    bpf: Option<Ebpf>,
    tuple_consumer: Option<MapHandle>,
    links: Vec<PinnedLink>,
    state: Option<HostState>,
    live: StdHashMap<ResourceTag, ExecutionState>,
    cookie_high_water: usize,
    tuple_high_water: usize,
    ring_events_consumed: u64,
    health_sequence: u64,
}

#[derive(Clone)]
struct Settings {
    state_dir: PathBuf,
    configured_pin_root: PathBuf,
    executions: PathBuf,
    bpftool: PathBuf,
    proxy_ip: std::net::Ipv4Addr,
    proxy_port: u16,
    policy_capacity: u32,
    socket_capacity: u32,
    ring_bytes: u32,
    required_controllers: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostState {
    schema: u32,
    abi: u32,
    phase: ManifestPhase,
    state_id: ExecutionNonce,
    generation: u64,
    object_sha256: String,
    config_sha256: String,
    attachment_target: PathBuf,
    attachment_inode: u64,
    attachment_handle: AttachmentHandle,
    pin_root: PathBuf,
    maps: Vec<MapManifest>,
    programs: Vec<ProgramManifest>,
    links: Vec<LinkManifest>,
    ancestor_bpf: Vec<AttachmentFingerprint>,
    resource_envelope: ResourceEnvelope,
    executions: BTreeMap<String, ExecutionState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentHandle {
    handle_type: i32,
    handle: Vec<u8>,
    mount_id_unique: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ManifestPhase {
    Intent,
    Ready,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UninstallIntent {
    schema: u32,
    state: HostState,
}

enum GenerationClassification {
    Fresh {
        pin_root: NoRecordPinRoot,
    },
    Recorded {
        state: Box<HostState>,
        target_released: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoRecordPinRoot {
    Absent,
    Empty,
}

/// A complete uninstall plan whose ownership predicates were checked before mutation.
pub struct PreparedCgroupBpfUninstall {
    backend: CgroupBpfBackend,
    generation: GenerationClassification,
    network: PreparedNetworkUninstall,
}

/// Machine-readable result of a dry-run or completed cgroup-BPF uninstall.
#[derive(Debug, Serialize)]
pub struct CgroupBpfUninstallReport {
    /// Ownership classification used for the operation.
    pub classification: &'static str,
    /// Whether this was a validation-only run.
    pub dry_run: bool,
    /// Exact operation descriptions derived from trusted records.
    pub operations: Vec<String>,
    /// Whether final absence was independently verified.
    pub absence_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapManifest {
    name: String,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    pin: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramManifest {
    symbol: String,
    id: u32,
    kernel_name: String,
    program_type: String,
    tag: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkManifest {
    name: String,
    id: u32,
    program_id: u32,
    link_type: String,
    target_inode: u64,
    pin: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordedLinkInfo {
    link_id: u32,
    program_id: u32,
    attach_type: u32,
    cgroup_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfflineHandleObservation {
    Stale,
    Openable,
    Error(Option<i32>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplacementTargetState {
    recorded_inode: u64,
    current_inode: u64,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    has_processes: bool,
    has_children: bool,
    controllers_ready: bool,
    below_current_unit: bool,
    old_inode_is_live: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentFingerprint {
    program_id: u32,
    name: String,
    program_type: String,
    tag: String,
    attach_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceEnvelope {
    memlock_soft: Option<u64>,
    memlock_hard: Option<u64>,
    nofile_soft: Option<u64>,
    nofile_hard: Option<u64>,
    enforcer_fds_before_load: usize,
    policy_capacity: u32,
    tracked_socket_capacity: u32,
    ring_buffer_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CgroupAttachment {
    id: u32,
    name: String,
    attach_type: String,
    #[serde(default)]
    attach_flags: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionState {
    id: ExecutionId,
    tag: ResourceTag,
    slot: u32,
    cgroup_inode: u64,
    binding: BindingKey,
    phase: ExecutionPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ExecutionPhase {
    NetworkPreparedFrozen,
    Active,
    Frozen,
}

impl CgroupBpfBackend {
    /// Derives every root, capacity and endpoint from a validated configuration.
    pub fn from_config(config: &Config) -> Result<Self, BackendError> {
        let network = NetnsNftBackend::new(NetworkSettings::from_config(config)?);
        let delegated = delegated_root(config.cgroup.root.as_deref())?;
        let mut required_controllers = vec!["memory", "pids"];
        if config
            .agents
            .values()
            .any(|agent| agent.limits.cpu_max.is_some())
        {
            required_controllers.push("cpu");
        }
        let policy_capacity = config
            .runtime
            .max_concurrency
            .checked_add(config.runtime.cleanup_failure_threshold)
            .ok_or_else(|| BackendError::Refused("policy capacity overflow".to_owned()))?;
        Ok(Self {
            network,
            settings: Settings {
                state_dir: config.runtime.state_dir.join("cgroup-bpf"),
                configured_pin_root: config.cgroup_bpf.pin_root.clone(),
                executions: delegated.join("executions"),
                bpftool: config.runtime.bpftool.clone(),
                proxy_ip: config.network.proxy_address,
                proxy_port: config.network.proxy_port,
                policy_capacity,
                socket_capacity: config.cgroup_bpf.max_tracked_sockets,
                ring_bytes: config.cgroup_bpf.ring_buffer_bytes,
                required_controllers,
            },
            tuple_consumer: None,
            bpf: None,
            links: Vec::new(),
            state: None,
            live: StdHashMap::new(),
            cookie_high_water: 0,
            tuple_high_water: 0,
            ring_events_consumed: 0,
            health_sequence: 0,
        })
    }

    /// Validates the complete cgroup-BPF and network uninstall plan without mutating it.
    pub fn prepare_uninstall(
        config: &Config,
        sandbox_tags: &BTreeSet<String>,
        sandbox_fresh: bool,
    ) -> Result<PreparedCgroupBpfUninstall, BackendError> {
        let backend = Self::from_config(config)?;
        validate_private_directory_if_present(&config.runtime.state_dir)?;
        validate_private_directory_if_present(&backend.settings.state_dir)?;
        validate_private_directory_if_present(&backend.settings.configured_pin_root)?;
        let generation = backend.classify_generation(true, Some(sandbox_tags))?;
        if let GenerationClassification::Recorded { state, .. } = &generation
            && state
                .executions
                .keys()
                .any(|tag| !sandbox_tags.contains(tag))
        {
            return Err(BackendError::Unknown(
                "UNKNOWN BPF Execution record has no matching Sandbox ownership record".to_owned(),
            ));
        }
        let network = backend.network.prepare_uninstall()?;
        validate_fresh_uninstall_state(&generation, sandbox_fresh, network.is_fresh())?;
        Ok(PreparedCgroupBpfUninstall {
            backend,
            generation,
            network,
        })
    }

    /// Every Execution whose frozen/active state this generation owns.
    pub fn live_tags(&self) -> Vec<ResourceTag> {
        self.live.keys().copied().collect()
    }

    fn state_path(&self) -> PathBuf {
        self.settings.state_dir.join(STATE_FILE)
    }

    fn object_hash() -> String {
        hex(&Sha256::digest(OBJECT))
    }

    fn config_hash(&self) -> String {
        let input = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.settings.executions.display(),
            self.settings.bpftool.display(),
            self.settings.proxy_ip,
            self.settings.proxy_port,
            self.settings.policy_capacity,
            self.settings.socket_capacity,
            self.settings.ring_bytes,
            self.settings.required_controllers.join(",")
        );
        hex(&Sha256::digest(input.as_bytes()))
    }

    fn publish_state(&self, state: &HostState) -> Result<(), BackendError> {
        records::publish(&self.settings.state_dir, STATE_FILE, state)?;
        fs::set_permissions(self.state_path(), fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn update_execution(&mut self, execution: ExecutionState) -> Result<(), BackendError> {
        let tag = execution.tag;
        let mut snapshot =
            self.state.as_ref().cloned().ok_or_else(|| {
                BackendError::Failed("the BPF generation is not ready".to_owned())
            })?;
        snapshot
            .executions
            .insert(tag.to_string(), execution.clone());
        self.publish_state(&snapshot)?;
        self.state = Some(snapshot);
        self.live.insert(tag, execution);
        Ok(())
    }

    fn remove_execution_record(&mut self, tag: &ResourceTag) -> Result<(), BackendError> {
        let mut snapshot =
            self.state.as_ref().cloned().ok_or_else(|| {
                BackendError::Failed("the BPF generation is not ready".to_owned())
            })?;
        snapshot.executions.remove(&tag.to_string());
        self.publish_state(&snapshot)?;
        self.state = Some(snapshot);
        self.live.remove(tag);
        Ok(())
    }

    fn uninstall_path(&self) -> PathBuf {
        self.settings.state_dir.join(UNINSTALL_FILE)
    }

    fn recorded_state(&self, uninstall: bool) -> Result<Option<HostState>, BackendError> {
        validate_state_file(&self.state_path())?;
        validate_state_file(&self.uninstall_path())?;
        let recorded: Option<HostState> = records::read(&self.settings.state_dir, STATE_FILE)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidData {
                    BackendError::Incompatible(format!(
                        "INCOMPATIBLE cgroup-BPF ownership record: {error}"
                    ))
                } else {
                    BackendError::from(error)
                }
            })?;
        let intent: Option<UninstallIntent> =
            records::read(&self.settings.state_dir, UNINSTALL_FILE).map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidData {
                    BackendError::Incompatible(format!(
                        "INCOMPATIBLE cgroup-BPF uninstall record: {error}"
                    ))
                } else {
                    BackendError::from(error)
                }
            })?;
        select_recorded_state(recorded, intent, uninstall)
    }

    fn classify_generation(
        &self,
        uninstall: bool,
        sandbox_tags: Option<&BTreeSet<String>>,
    ) -> Result<GenerationClassification, BackendError> {
        let recorded = self.recorded_state(uninstall)?;
        let Some(mut state) = recorded else {
            let pin_root = validate_no_record_pin_state(&self.settings.configured_pin_root)?;
            return Ok(GenerationClassification::Fresh { pin_root });
        };
        require_bpffs_mount()?;
        let pin_entries = directory_entries(&self.settings.configured_pin_root)?;
        if state.schema != STATE_SCHEMA
            || state.abi != BPF_ABI
            || state.object_sha256 != Self::object_hash()
            || state.config_sha256 != self.config_hash()
        {
            return Err(BackendError::Incompatible(
                "INCOMPATIBLE cgroup-BPF ownership state; kernel objects were left untouched"
                    .to_owned(),
            ));
        }
        if state.attachment_target != self.settings.executions {
            return Err(BackendError::Unknown(
                "UNKNOWN cgroup-BPF attachment target; kernel objects were left untouched"
                    .to_owned(),
            ));
        }
        let expected_pin_root = self
            .settings
            .configured_pin_root
            .join(format!("{}-g{}", state.state_id, state.generation));
        if state.generation == 0 || state.pin_root != expected_pin_root {
            return Err(BackendError::Unknown(
                "UNKNOWN cgroup-BPF ownership paths; kernel objects were left untouched".to_owned(),
            ));
        }
        let actual_roots = pin_entries.into_iter().collect::<BTreeSet<_>>();
        let expected_roots = BTreeSet::from([state.pin_root.clone()]);
        let roots_match = match state.phase {
            ManifestPhase::Ready => actual_roots == expected_roots,
            ManifestPhase::Intent => actual_roots.is_subset(&expected_roots),
        };
        if !roots_match {
            return Err(BackendError::Unknown(
                "UNKNOWN cgroup-BPF generation exists outside the recorded pin root".to_owned(),
            ));
        }
        self.validate_manifest_structure(&state)?;
        self.validate_recorded_pins(&state)?;
        self.validate_recovery_policy(&state)?;
        let current_inode = match fs::metadata(&self.settings.executions) {
            Ok(metadata) => Some(metadata.ino()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let target_released = target_release_required(state.attachment_inode, current_inode);
        if target_released {
            self.validate_target_released(&state, current_inode)?;
        } else {
            if let Some(current) =
                self.validate_attachment_inventory(&state, state.phase == ManifestPhase::Ready)?
            {
                state.ancestor_bpf = current;
                self.publish_state(&state)?;
            }
            if let Some(tags) = sandbox_tags {
                validate_owned_uninstall_children(&self.settings.executions, tags)?;
            } else if has_child_cgroup(&self.settings.executions)? {
                return Err(BackendError::Unknown(
                    "Execution cgroups remain after the mandatory Sandbox sweep".to_owned(),
                ));
            }
        }
        Ok(GenerationClassification::Recorded {
            state: Box::new(state),
            target_released,
        })
    }

    fn classify_and_recover(&self) -> Result<(ExecutionNonce, u64, Vec<String>), BackendError> {
        let generation = self.classify_generation(false, None)?;
        let GenerationClassification::Recorded {
            mut state,
            target_released,
        } = generation
        else {
            return Ok((ExecutionNonce::generate()?, 1, Vec::new()));
        };
        if state.phase == ManifestPhase::Ready {
            // Durable recovery intent precedes every unlink. A crash after any individual unlink
            // therefore resumes from an explicitly owned subset, never from a silently damaged
            // READY inventory.
            state.phase = ManifestPhase::Intent;
            self.publish_state(&state)?;
        }
        if target_released {
            self.detach_released_links(&state)?;
        }
        self.remove_recorded_pins(&state)?;
        self.verify_recorded_objects_absent(&state)?;
        let next = state
            .generation
            .checked_add(1)
            .ok_or_else(|| BackendError::Refused("backend generation exhausted".to_owned()))?;
        let classification = if target_released {
            "TargetReleased cgroup-BPF generation"
        } else {
            "cgroup-BPF generation"
        };
        Ok((
            state.state_id,
            next,
            vec![format!("{classification} {}", state.generation)],
        ))
    }

    fn expected_pins(state: &HostState) -> BTreeSet<PathBuf> {
        state
            .maps
            .iter()
            .map(|entry| entry.pin.clone())
            .chain(state.links.iter().map(|entry| entry.pin.clone()))
            .collect()
    }

    fn validate_manifest_structure(&self, state: &HostState) -> Result<(), BackendError> {
        validate_attachment_handle_structure(&state.attachment_handle)?;
        let expected_maps: BTreeSet<(String, PathBuf)> = MAPS
            .iter()
            .map(|name| ((*name).to_owned(), state.pin_root.join("maps").join(name)))
            .collect();
        let maps: BTreeSet<(String, PathBuf)> = state
            .maps
            .iter()
            .map(|map| (map.name.clone(), map.pin.clone()))
            .collect();
        let expected_links: BTreeSet<(String, PathBuf)> = PROGRAMS
            .iter()
            .map(|program| {
                (
                    program.pin.to_owned(),
                    state.pin_root.join("links").join(program.pin),
                )
            })
            .collect();
        let links: BTreeSet<(String, PathBuf)> = state
            .links
            .iter()
            .map(|link| (link.name.clone(), link.pin.clone()))
            .collect();
        let programs: BTreeSet<String> = state
            .programs
            .iter()
            .map(|program| program.symbol.clone())
            .collect();
        let expected_programs: BTreeSet<String> = PROGRAMS
            .iter()
            .map(|program| program.symbol.to_owned())
            .collect();
        let programs_valid = state.programs.is_empty()
            || (state.programs.len() == PROGRAMS.len() && programs == expected_programs);
        let map_ids: BTreeSet<u32> = state.maps.iter().map(|map| map.id).collect();
        let maps_published = map_ids.len() == MAPS.len() && !map_ids.contains(&0);
        if state.maps.len() != MAPS.len()
            || maps != expected_maps
            || state.links.len() != PROGRAMS.len()
            || links != expected_links
            || !programs_valid
            || (state.phase == ManifestPhase::Ready && state.programs.len() != PROGRAMS.len())
            || (state.phase == ManifestPhase::Ready && !maps_published)
            || (state.phase == ManifestPhase::Intent
                && !intent_inventory_shape_valid(&state.maps, &state.programs, &state.links))
            || state.links.iter().any(|link| {
                link.target_inode != state.attachment_inode
                    || match state.phase {
                        ManifestPhase::Ready => link.link_type != "Cgroup",
                        ManifestPhase::Intent => {
                            !link.link_type.is_empty() && link.link_type != "Cgroup"
                        }
                    }
            })
        {
            return Err(BackendError::Unknown(
                "UNKNOWN ownership manifest structure; no kernel object was changed".to_owned(),
            ));
        }
        let mut cgroups = BTreeSet::new();
        for (key, execution) in &state.executions {
            if key != &execution.tag.to_string()
                || execution.id.tag() != execution.tag
                || execution.binding.cgroup_id != execution.cgroup_inode
                || execution.binding.backend_generation != state.generation
                || !cgroups.insert(execution.cgroup_inode)
            {
                return Err(BackendError::Unknown(
                    "UNKNOWN per-Execution ownership record; no kernel object was changed"
                        .to_owned(),
                ));
            }
        }
        if !state.programs.is_empty() {
            let program_ids: BTreeSet<u32> =
                state.programs.iter().map(|program| program.id).collect();
            let link_ids: BTreeSet<u32> = state.links.iter().map(|link| link.id).collect();
            if program_ids.len() != PROGRAMS.len()
                || link_ids.len() != PROGRAMS.len()
                || state.links.iter().any(|link| {
                    expected_link_contract(&link.name).is_none_or(|(spec, _)| {
                        state
                            .programs
                            .iter()
                            .find(|program| program.symbol == spec.symbol)
                            .is_none_or(|program| program.id != link.program_id)
                    })
                })
            {
                return Err(BackendError::Unknown(
                    "UNKNOWN program/link ownership relationship; no kernel object was changed"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_recovery_policy(&self, state: &HostState) -> Result<(), BackendError> {
        let policy_pin = state.pin_root.join("maps/soglia_policy");
        let policy_exists = match fs::symlink_metadata(&policy_pin) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                eprintln!(
                    "event.name=cgroup_bpf.recovery_policy_unverifiable path={:?} error={error:?}",
                    policy_pin
                );
                return Err(unknown_execution_record());
            }
        };
        if !policy_exists {
            // Recovery publishes INTENT before removing any pin. A crash during that cleanup can
            // therefore leave a trusted partial inventory after the policy map has already gone;
            // at that point no kernel policy remains to compare with the durable records.
            return validate_recovery_policy_snapshot(state.phase, state.executions.values(), None);
        }

        let data = MapData::from_pin(&policy_pin).map_err(|error| {
            eprintln!(
                "event.name=cgroup_bpf.recovery_policy_unverifiable path={:?} error={error:#}",
                policy_pin
            );
            unknown_execution_record()
        })?;
        let policies =
            HashMap::<_, u64, [u8; 40]>::try_from(AyaMap::HashMap(data)).map_err(|error| {
                eprintln!("event.name=cgroup_bpf.recovery_policy_unverifiable error={error:#}");
                unknown_execution_record()
            })?;
        let mut snapshot = BTreeMap::new();
        for entry in policies.iter() {
            let (cgroup_id, value) = entry.map_err(|error| {
                eprintln!("event.name=cgroup_bpf.recovery_policy_unverifiable error={error:#}");
                unknown_execution_record()
            })?;
            if value[4..8] != [0_u8; 4] {
                return Err(unknown_execution_record());
            }
            let Some((policy_state, binding)) = decode_policy(&value) else {
                return Err(unknown_execution_record());
            };
            snapshot.insert(cgroup_id, (policy_state, binding));
        }
        validate_recovery_policy_snapshot(state.phase, state.executions.values(), Some(&snapshot))
    }

    fn cgroup_attachments(&self, effective: bool) -> Result<Vec<CgroupAttachment>, BackendError> {
        self.cgroup_attachments_at(&self.settings.executions, effective)
    }

    fn cgroup_attachments_at(
        &self,
        cgroup: &Path,
        effective: bool,
    ) -> Result<Vec<CgroupAttachment>, BackendError> {
        let target = cgroup.to_str().ok_or_else(|| {
            BackendError::Refused("the attachment target is not valid UTF-8".to_owned())
        })?;
        let output = if effective {
            system::run(
                &self.settings.bpftool,
                &["-j", "cgroup", "show", target, "effective"],
                None,
            )?
        } else {
            system::run(
                &self.settings.bpftool,
                &["-j", "cgroup", "show", target],
                None,
            )?
        };
        if output.trim().is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&output).map_err(|error| {
            BackendError::Failed(format!("decode bpftool cgroup inventory: {error}"))
        })
    }

    fn require_empty_direct_target(&self) -> Result<(), BackendError> {
        let direct = self.cgroup_attachments(false)?;
        if direct.is_empty() {
            Ok(())
        } else {
            Err(BackendError::Refused(format!(
                "the executions cgroup has {} unrecorded direct BPF attachment(s)",
                direct.len()
            )))
        }
    }

    fn program_fingerprint(
        &self,
        attachment: &CgroupAttachment,
    ) -> Result<AttachmentFingerprint, BackendError> {
        let id = attachment.id.to_string();
        let output = system::run(
            &self.settings.bpftool,
            &["-j", "prog", "show", "id", &id],
            None,
        )?;
        let value: serde_json::Value = serde_json::from_str(&output).map_err(|error| {
            BackendError::Failed(format!("decode bpftool program {}: {error}", attachment.id))
        })?;
        let program = value
            .as_array()
            .and_then(|programs| programs.first())
            .unwrap_or(&value);
        let field = |name: &str| {
            program
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    BackendError::Failed(format!(
                        "bpftool program {} omitted {name}",
                        attachment.id
                    ))
                })
        };
        let reported_id = program
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                BackendError::Failed(format!(
                    "bpftool program {} omitted a valid id",
                    attachment.id
                ))
            })?;
        if reported_id != attachment.id || field("name")? != attachment.name {
            return Err(BackendError::Unknown(
                "cgroup and program inventory identities disagree".to_owned(),
            ));
        }
        Ok(AttachmentFingerprint {
            program_id: reported_id,
            name: attachment.name.clone(),
            program_type: field("type")?,
            tag: field("tag")?,
            attach_type: attachment.attach_type.clone(),
        })
    }

    fn foreign_effective_fingerprint(
        &self,
        owned: &BTreeSet<u32>,
    ) -> Result<Vec<AttachmentFingerprint>, BackendError> {
        self.foreign_effective_fingerprint_at(&self.settings.executions, owned)
    }

    fn foreign_effective_fingerprint_at(
        &self,
        cgroup: &Path,
        owned: &BTreeSet<u32>,
    ) -> Result<Vec<AttachmentFingerprint>, BackendError> {
        let mut fingerprint = self
            .cgroup_attachments_at(cgroup, true)?
            .into_iter()
            .filter(|attachment| !owned.contains(&attachment.id))
            .map(|attachment| self.program_fingerprint(&attachment))
            .collect::<Result<Vec<_>, _>>()?;
        fingerprint.sort();
        Ok(fingerprint)
    }

    fn validate_attachment_inventory(
        &self,
        state: &HostState,
        require_complete: bool,
    ) -> Result<Option<Vec<AttachmentFingerprint>>, BackendError> {
        let direct = self.cgroup_attachments(false)?;
        if require_complete && direct.len() != PROGRAMS.len() {
            return Err(BackendError::Unknown(format!(
                "direct production attachment count is {}, expected {}",
                direct.len(),
                PROGRAMS.len()
            )));
        }
        let owned: BTreeSet<u32> = state.programs.iter().map(|program| program.id).collect();
        for attachment in &direct {
            let program = state
                .programs
                .iter()
                .find(|program| program.id == attachment.id)
                .ok_or_else(|| {
                    BackendError::Unknown(
                        "unrecorded direct BPF attachment exists on executions".to_owned(),
                    )
                })?;
            let expected_type = expected_attach_type(&program.symbol).ok_or_else(|| {
                BackendError::Failed(format!("unknown production symbol {}", program.symbol))
            })?;
            if attachment.name != program.kernel_name
                || attachment.attach_type != expected_type
                || attachment.attach_flags.as_deref() != Some("multi")
            {
                return Err(BackendError::Unknown(format!(
                    "direct attachment for {} does not match its recorded identity",
                    program.symbol
                )));
            }
        }
        let effective = self.cgroup_attachments(true)?;
        if require_complete {
            for program in &state.programs {
                let expected_type = expected_attach_type(&program.symbol).ok_or_else(|| {
                    BackendError::Failed(format!("unknown production symbol {}", program.symbol))
                })?;
                if !effective.iter().any(|attachment| {
                    attachment.id == program.id
                        && attachment.name == program.kernel_name
                        && attachment.attach_type == expected_type
                }) {
                    return Err(BackendError::Unknown(format!(
                        "{} is not effective on the production subtree",
                        program.symbol
                    )));
                }
            }
        }
        let current = self.foreign_effective_fingerprint(&owned)?;
        if current != state.ancestor_bpf {
            if systemd_external_churn(&state.ancestor_bpf, &current) {
                eprintln!(
                    "event.name=cgroup_bpf.external_churn owner=systemd classification=EXTERNAL_CHURN"
                );
                return Ok(Some(current));
            }
            return Err(BackendError::Unknown(
                "non-owned ancestor BPF inventory changed".to_owned(),
            ));
        }
        Ok(None)
    }

    fn validate_recorded_pins(&self, state: &HostState) -> Result<(), BackendError> {
        let actual = recursive_files(&state.pin_root, state.phase == ManifestPhase::Intent)?;
        let expected = Self::expected_pins(state);
        let inventory_matches = match state.phase {
            ManifestPhase::Ready => actual == expected,
            ManifestPhase::Intent => actual.is_subset(&expected),
        };
        if !inventory_matches {
            return Err(BackendError::Unknown(
                "UNKNOWN pin inventory; no recorded BPF object was changed".to_owned(),
            ));
        }
        for map in state.maps.iter().filter(|map| actual.contains(&map.pin)) {
            let info = MapInfo::from_pin(&map.pin).map_err(|error| {
                BackendError::Failed(format!("inspect {}: {error:#}", map.pin.display()))
            })?;
            let id_matches = map.id == 0 || info.id() == map.id;
            let shape_matches = if map.key_size == 0 {
                expected_map_shape(&map.name, &self.settings).is_some_and(
                    |(key, value, capacity)| {
                        info.key_size() == key
                            && info.value_size() == value
                            && info.max_entries() == capacity
                    },
                )
            } else {
                info.key_size() == map.key_size
                    && info.value_size() == map.value_size
                    && info.max_entries() == map.max_entries
            };
            if !id_matches || !shape_matches {
                return Err(BackendError::Refused(format!(
                    "UNKNOWN map identity at {}; no object was changed",
                    map.pin.display()
                )));
            }
        }
        if let Some(meta) = state
            .maps
            .iter()
            .find(|map| map.name == "soglia_meta" && actual.contains(&map.pin))
        {
            let map = MapHandle::from_pinned_path(&meta.pin).map_err(|error| {
                BackendError::Failed(format!("open {}: {error:#}", meta.pin.display()))
            })?;
            let value = map
                .lookup(&0_u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .map_err(|error| BackendError::Failed(format!("read metadata map: {error:#}")))?;
            if value.as_deref()
                != Some(metadata_value(state.state_id, state.generation)?.as_slice())
            {
                return Err(BackendError::Unknown(
                    "UNKNOWN cgroup-BPF generation metadata; no object was changed".to_owned(),
                ));
            }
        }
        for link in state.links.iter().filter(|link| actual.contains(&link.pin)) {
            let observed = inspect_recorded_link(link)?;
            validate_recorded_link_identity(link, observed)?;
        }
        for program in &state.programs {
            let link_pin_exists = state
                .links
                .iter()
                .any(|link| link.program_id == program.id && actual.contains(&link.pin));
            match validate_recorded_program(program) {
                Ok(()) => {}
                Err(error) => {
                    if state.phase != ManifestPhase::Intent
                        || link_pin_exists
                        || !recorded_program_is_absent(program)
                    {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_target_released(
        &self,
        state: &HostState,
        current_inode: Option<u64>,
    ) -> Result<(), BackendError> {
        validate_offline_attachment_handle(&state.attachment_handle)?;
        let actual = recursive_files(&state.pin_root, state.phase == ManifestPhase::Intent)?;
        let complete = actual == Self::expected_pins(state)
            && state.programs.len() == PROGRAMS.len()
            && state.links.len() == PROGRAMS.len()
            && state.maps.iter().all(|map| map.id != 0)
            && state.programs.iter().all(|program| program.id != 0)
            && state
                .links
                .iter()
                .all(|link| link.id != 0 && link.program_id != 0 && link.link_type == "Cgroup");
        if state.phase == ManifestPhase::Ready && !complete {
            return Err(BackendError::Unknown(
                "UNKNOWN released-target inventory is incomplete; no object was changed".to_owned(),
            ));
        }

        let observable_links = state
            .links
            .iter()
            .filter(|link| actual.contains(&link.pin))
            .collect::<Vec<_>>();
        self.observe_released_links(&observable_links, state.attachment_inode)?;
        if let Some(current_inode) = current_inode {
            let target = self.replacement_target_state(state, current_inode)?;
            validate_replacement_target(target)?;

            let direct = self.cgroup_attachments(false)?;
            if !direct.is_empty() {
                return Err(BackendError::Unknown(
                    "UNKNOWN replacement target has a direct BPF attachment; no object was changed"
                        .to_owned(),
                ));
            }
            let owned: BTreeSet<u32> = state.programs.iter().map(|program| program.id).collect();
            let effective = self.cgroup_attachments(true)?;
            if effective
                .iter()
                .any(|attachment| owned.contains(&attachment.id))
            {
                return Err(BackendError::Unknown(
                    "UNKNOWN old production program is effective on the replacement target; no object was changed"
                        .to_owned(),
                ));
            }
            let current_ancestors = self.foreign_effective_fingerprint(&owned)?;
            if current_ancestors != state.ancestor_bpf
                && !systemd_external_churn(&state.ancestor_bpf, &current_ancestors)
            {
                return Err(BackendError::Unknown(
                    "UNKNOWN non-owned ancestor BPF inventory changed during released-target recovery"
                        .to_owned(),
                ));
            }
        }

        eprintln!(
            "event.name=cgroup_bpf.target_released result=PASS recorded_cgroup_id={} current_cgroup_id={} target_absent={} detach_timeout_ms={} poll_interval_ms={}",
            state.attachment_inode,
            current_inode.unwrap_or(0),
            current_inode.is_none(),
            TARGET_RELEASED_DETACH_TIMEOUT.as_millis(),
            TARGET_RELEASED_POLL_INTERVAL.as_millis()
        );
        Ok(())
    }

    fn observe_released_links(
        &self,
        links: &[&LinkManifest],
        recorded_cgroup_id: u64,
    ) -> Result<(), BackendError> {
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            let mut observations = Vec::with_capacity(links.len());
            for link in links {
                let observed = inspect_recorded_link(link)?;
                validate_recorded_link_identity(link, observed)?;
                eprintln!(
                    "event.name=cgroup_bpf.target_released_link_observation elapsed_ms={} link={} link_id={} program_id={} attach_type={} cgroup_id={}",
                    elapsed.as_millis(),
                    link.name,
                    observed.link_id,
                    observed.program_id,
                    observed.attach_type,
                    observed.cgroup_id
                );
                validate_released_link_target(observed, recorded_cgroup_id)?;
                observations.push(observed);
            }
            if all_recorded_links_released(&observations, links.len()) {
                return Ok(());
            }
            if elapsed >= TARGET_RELEASED_DETACH_TIMEOUT {
                return Ok(());
            }
            thread::sleep(TARGET_RELEASED_POLL_INTERVAL);
        }
    }

    fn detach_released_links(&self, state: &HostState) -> Result<(), BackendError> {
        for recorded in &state.links {
            if !recorded.pin.exists() {
                if state.phase == ManifestPhase::Intent {
                    continue;
                }
                return Err(BackendError::Unknown(format!(
                    "UNKNOWN recorded link pin {} disappeared before detach",
                    recorded.pin.display()
                )));
            }
            let link = Link::open(&recorded.pin).map_err(|error| {
                BackendError::Unknown(format!(
                    "UNKNOWN recorded link at {} cannot be opened for detach: {error:#}",
                    recorded.pin.display()
                ))
            })?;
            let before = recorded_link_info(recorded, &link)?;
            validate_recorded_link_identity(recorded, before)?;
            validate_released_link_target(before, state.attachment_inode)?;
            if before.cgroup_id == state.attachment_inode {
                link.detach()
                    .map_err(|error| exact_detach_error(&recorded.pin, &error))?;
            }
            let after = recorded_link_info(recorded, &link)?;
            validate_recorded_link_identity(recorded, after)?;
            validate_post_detach_link(after)?;
            eprintln!(
                "event.name=cgroup_bpf.target_released_link_detach link={} link_id={} program_id={} attach_type={} before_cgroup_id={} after_cgroup_id={}",
                recorded.name,
                after.link_id,
                after.program_id,
                after.attach_type,
                before.cgroup_id,
                after.cgroup_id
            );
        }
        Ok(())
    }

    fn replacement_target_state(
        &self,
        state: &HostState,
        current_inode: u64,
    ) -> Result<ReplacementTargetState, BackendError> {
        let target = fs::symlink_metadata(&self.settings.executions).map_err(|error| {
            BackendError::Unknown(format!(
                "UNKNOWN replacement attachment target cannot be inspected: {error}"
            ))
        })?;
        if !target.file_type().is_dir() {
            return Err(BackendError::Unknown(
                "UNKNOWN replacement attachment target is not a real cgroup directory".to_owned(),
            ));
        }
        let current_unit = delegated_root(None).map_err(|error| {
            BackendError::Unknown(format!(
                "UNKNOWN current systemd unit cgroup cannot be established: {error}"
            ))
        })?;
        let parent = self.settings.executions.parent().ok_or_else(|| {
            BackendError::Unknown(
                "UNKNOWN replacement attachment target has no delegated parent".to_owned(),
            )
        })?;
        let parent_metadata = fs::metadata(parent)?;
        let unit_metadata = fs::metadata(&current_unit)?;
        let below_current_unit = parent_metadata.dev() == unit_metadata.dev()
            && parent_metadata.ino() == unit_metadata.ino();
        let old_inode_is_live =
            cgroup_id_is_live(Path::new("/sys/fs/cgroup"), state.attachment_inode).map_err(
                |error| {
                    BackendError::Unknown(format!(
                        "UNKNOWN old attachment target identity could not be resolved: {error}"
                    ))
                },
            )?;
        let controllers = fs::read_to_string(self.settings.executions.join("cgroup.controllers"))?;
        let subtree = fs::read_to_string(self.settings.executions.join("cgroup.subtree_control"))?;
        let controllers: BTreeSet<&str> = controllers.split_whitespace().collect();
        let subtree: BTreeSet<&str> = subtree.split_whitespace().collect();
        let controllers_ready = self
            .settings
            .required_controllers
            .iter()
            .all(|controller| controllers.contains(controller) && subtree.contains(controller));
        Ok(ReplacementTargetState {
            recorded_inode: state.attachment_inode,
            current_inode,
            owner_uid: target.uid(),
            owner_gid: target.gid(),
            mode: target.mode() & 0o777,
            has_processes: !fs::read_to_string(self.settings.executions.join("cgroup.procs"))?
                .trim()
                .is_empty(),
            has_children: has_child_cgroup(&self.settings.executions)?,
            controllers_ready,
            below_current_unit,
            old_inode_is_live,
        })
    }

    fn verify_recorded_objects_absent(&self, state: &HostState) -> Result<(), BackendError> {
        if Self::expected_pins(state).iter().any(|pin| pin.exists()) || state.pin_root.exists() {
            return Err(BackendError::Failed(
                "a recorded BPF pin survived recovery cleanup".to_owned(),
            ));
        }
        let started = Instant::now();
        loop {
            let surviving = recorded_kernel_objects_present(state)?;
            if surviving.is_empty() {
                return Ok(());
            }
            let elapsed = started.elapsed();
            eprintln!(
                "event.name=cgroup_bpf.recovery_cleanup_observation elapsed_ms={} surviving={}",
                elapsed.as_millis(),
                surviving.join(",")
            );
            if elapsed >= TARGET_RELEASED_DETACH_TIMEOUT {
                return Err(BackendError::Failed(format!(
                    "recorded BPF kernel objects survived recovery cleanup: {}",
                    surviving.join(", ")
                )));
            }
            thread::sleep(TARGET_RELEASED_POLL_INTERVAL);
        }
    }

    fn remove_recorded_pins(&self, state: &HostState) -> Result<(), BackendError> {
        for link in &state.links {
            remove_file_if_present(&link.pin)?;
        }
        for map in &state.maps {
            remove_file_if_present(&map.pin)?;
        }
        remove_empty_tree(&state.pin_root)?;
        Ok(())
    }

    fn load_production_object(&self, generation: u64) -> Result<Ebpf, BackendError> {
        let proxy_ip4 = u32::from_ne_bytes(self.settings.proxy_ip.octets());
        let proxy_port = u32::from(self.settings.proxy_port);
        let mut loader = EbpfLoader::new();
        loader
            .override_global("proxy_ip4", &proxy_ip4, true)
            .override_global("proxy_port", &proxy_port, true)
            .override_global("backend_generation", &generation, true)
            .map_max_entries("soglia_policy", self.settings.policy_capacity)
            .map_max_entries("soglia_denies", self.settings.policy_capacity)
            .map_max_entries("soglia_cookie_a", self.settings.socket_capacity)
            .map_max_entries("soglia_tuples", self.settings.socket_capacity)
            .map_max_entries("soglia_events", self.settings.ring_bytes);
        loader
            .load(OBJECT)
            .map_err(|error| BackendError::Failed(format!("load production BPF object: {error:#}")))
    }

    fn probe_attach_topology(&self) -> Result<(), BackendError> {
        let probe = self.settings.executions.join(format!(
            ".soglia-attach-probe-{}",
            ExecutionNonce::generate()?
        ));
        fs::create_dir(&probe).map_err(|error| {
            BackendError::Failed(format!("create disposable BPF probe cgroup: {error}"))
        })?;
        let result = self.run_attach_probe(&probe);
        let cleanup = self.wait_for_no_probe_residue(&probe).and_then(|()| {
            fs::remove_dir(&probe).map_err(BackendError::from)?;
            if probe.exists() {
                Err(BackendError::Failed(
                    "disposable BPF probe cgroup remained".to_owned(),
                ))
            } else {
                Ok(())
            }
        });
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(cleanup)) => Err(BackendError::Failed(format!(
                "the attach probe passed but cleanup failed: {cleanup}"
            ))),
            (Err(error), Err(cleanup)) => Err(BackendError::Failed(format!(
                "{error}; disposable attach-probe cleanup failed: {cleanup}"
            ))),
        }
    }

    fn require_no_probe_residue(&self, probe: &Path) -> Result<(), BackendError> {
        if !self.cgroup_attachments_at(probe, false)?.is_empty() {
            return Err(BackendError::Failed(
                "the disposable attach probe left a direct attachment behind".to_owned(),
            ));
        }
        for kind in ["prog", "map"] {
            let output = system::run(&self.settings.bpftool, &["-j", kind, "show"], None)?;
            let values: Vec<serde_json::Value> =
                serde_json::from_str(&output).map_err(|error| {
                    BackendError::Failed(format!("decode bpftool {kind} inventory: {error}"))
                })?;
            if values.iter().any(|value| {
                value
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| name.starts_with("soglia_"))
            }) {
                return Err(BackendError::Failed(format!(
                    "a production BPF {kind} survived disposable probe cleanup"
                )));
            }
        }
        Ok(())
    }

    fn wait_for_no_probe_residue(&self, probe: &Path) -> Result<(), BackendError> {
        let started = Instant::now();
        loop {
            match self.require_no_probe_residue(probe) {
                Ok(()) => return Ok(()),
                Err(_) if started.elapsed() < Duration::from_secs(2) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn run_attach_probe(&self, probe: &Path) -> Result<(), BackendError> {
        let baseline = self.foreign_effective_fingerprint(&BTreeSet::new())?;
        let mut bpf = self.load_production_object(1)?;
        let target = File::open(probe)?;
        let links = attach_all(&mut bpf, &target)?;
        let programs = collect_programs(&bpf)?;
        let owned: BTreeSet<u32> = programs.iter().map(|program| program.id).collect();
        let direct = self.cgroup_attachments_at(probe, false)?;
        if direct.len() != PROGRAMS.len() {
            return Err(BackendError::Refused(format!(
                "the attach probe produced {} direct links, expected {}",
                direct.len(),
                PROGRAMS.len()
            )));
        }
        for program in &programs {
            let attach_type = expected_attach_type(&program.symbol).ok_or_else(|| {
                BackendError::Failed(format!("unknown production symbol {}", program.symbol))
            })?;
            if !direct.iter().any(|attachment| {
                attachment.id == program.id
                    && attachment.name == program.kernel_name
                    && attachment.attach_type == attach_type
                    && attachment.attach_flags.as_deref() == Some("multi")
            }) {
                return Err(BackendError::Refused(format!(
                    "the attach probe did not observe {} as a direct multi-compatible link",
                    program.symbol
                )));
            }
        }
        let effective = self.cgroup_attachments_at(probe, true)?;
        for program in &programs {
            if !effective
                .iter()
                .any(|attachment| attachment.id == program.id)
            {
                return Err(BackendError::Refused(format!(
                    "the attach probe did not observe {} in the effective inventory",
                    program.symbol
                )));
            }
        }
        let during_foreign = self.foreign_effective_fingerprint_at(probe, &owned)?;
        require_same_external_inventory(&baseline, &during_foreign, "during attach probe")?;
        drop(links);
        drop(bpf);
        self.wait_for_no_probe_residue(probe)?;
        let after = self.foreign_effective_fingerprint_at(probe, &BTreeSet::new())?;
        require_same_external_inventory(&during_foreign, &after, "after attach probe cleanup")?;
        eprintln!(
            "event.name=cgroup_bpf.attach_probe result=PASS mode=single hooks={} effective=true",
            PROGRAMS.len()
        );
        Ok(())
    }

    fn load_generation(
        &mut self,
        state_id: ExecutionNonce,
        generation: u64,
        ancestor_bpf: Vec<AttachmentFingerprint>,
    ) -> Result<(), BackendError> {
        let attachment_inode = fs::metadata(&self.settings.executions)?.ino();
        let attachment_handle = capture_attachment_handle(&self.settings.executions)?;
        let pin_root = self
            .settings
            .configured_pin_root
            .join(format!("{}-g{generation}", state_id));
        if fs::symlink_metadata(&pin_root).is_ok() {
            return Err(BackendError::Refused(format!(
                "new generation pin root {} already exists",
                pin_root.display()
            )));
        }
        let map_root = pin_root.join("maps");
        let link_root = pin_root.join("links");

        let mut state = HostState {
            schema: STATE_SCHEMA,
            abi: BPF_ABI,
            phase: ManifestPhase::Intent,
            state_id,
            generation,
            object_sha256: Self::object_hash(),
            config_sha256: self.config_hash(),
            attachment_target: self.settings.executions.clone(),
            attachment_inode,
            attachment_handle,
            pin_root: pin_root.clone(),
            maps: MAPS
                .iter()
                .map(|name| MapManifest {
                    name: (*name).to_owned(),
                    id: 0,
                    key_size: 0,
                    value_size: 0,
                    max_entries: 0,
                    pin: map_root.join(name),
                })
                .collect(),
            programs: Vec::new(),
            links: PROGRAMS
                .iter()
                .map(|program| LinkManifest {
                    name: program.pin.to_owned(),
                    id: 0,
                    program_id: 0,
                    link_type: String::new(),
                    target_inode: attachment_inode,
                    pin: link_root.join(program.pin),
                })
                .collect(),
            ancestor_bpf,
            resource_envelope: resource_envelope(&self.settings)?,
            executions: BTreeMap::new(),
        };
        let installation = self.publish_state(&state).and_then(|()| {
            self.install_generation(
                &mut state,
                &map_root,
                &link_root,
                attachment_inode,
                state_id,
                generation,
            )
        });
        let (bpf, tuple_consumer, links) = match installation {
            Ok(resources) => resources,
            Err(error) => {
                return match self.rollback_failed_generation(&state) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(BackendError::Failed(format!(
                        "{error}; synchronous generation rollback was not verified: {cleanup}"
                    ))),
                };
            }
        };
        self.state = Some(state);
        self.bpf = Some(bpf);
        self.tuple_consumer = Some(tuple_consumer);
        self.links = links;
        eprintln!(
            "event.name=cgroup_bpf.ready generation={generation} programs={} links={} maps={} policy_capacity={} socket_capacity={} ring_bytes={}",
            PROGRAMS.len(),
            PROGRAMS.len(),
            MAPS.len(),
            self.settings.policy_capacity,
            self.settings.socket_capacity,
            self.settings.ring_bytes
        );
        Ok(())
    }

    fn install_generation(
        &self,
        state: &mut HostState,
        map_root: &Path,
        link_root: &Path,
        attachment_inode: u64,
        state_id: ExecutionNonce,
        generation: u64,
    ) -> Result<(Ebpf, MapHandle, Vec<PinnedLink>), BackendError> {
        fs::create_dir(&state.pin_root)?;
        fs::set_permissions(&state.pin_root, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(map_root)?;
        fs::create_dir(link_root)?;

        let mut bpf = self.load_production_object(generation)?;
        initialize_metadata(&mut bpf, state_id, generation)?;
        pin_maps(&bpf, map_root)?;
        let tuple_consumer = MapHandle::from_pinned_path(map_root.join("soglia_tuples"))
            .map_err(|error| BackendError::Failed(format!("open tuple consumer: {error:#}")))?;
        state.maps = collect_maps(&bpf, map_root)?;
        self.publish_state(state)?;
        let target = File::open(&self.settings.executions)?;
        let unpinned_links = attach_all(&mut bpf, &target)?;
        state.programs = collect_programs(&bpf)?;
        state.links = collect_links(&unpinned_links, link_root, attachment_inode)?;
        if let Some(current) = self.validate_attachment_inventory(state, true)? {
            state.ancestor_bpf = current;
        }
        self.publish_state(state)?;
        let links = pin_links(unpinned_links, link_root)?;
        if state.maps.len() != MAPS.len()
            || state.programs.len() != PROGRAMS.len()
            || state.links.len() != PROGRAMS.len()
        {
            return Err(BackendError::Failed(
                "production object inventory is not exactly seven maps, six programs and six links"
                    .to_owned(),
            ));
        }
        state.phase = ManifestPhase::Ready;
        self.publish_state(state)?;
        Ok((bpf, tuple_consumer, links))
    }

    fn rollback_failed_generation(&self, state: &HostState) -> Result<(), BackendError> {
        self.remove_recorded_pins(state)?;
        let owned_ids: BTreeSet<u32> = state.programs.iter().map(|program| program.id).collect();
        let direct = self.cgroup_attachments(false)?;
        if direct.iter().any(|attachment| {
            owned_ids.contains(&attachment.id) || attachment.name.starts_with("soglia_")
        }) {
            return Err(BackendError::Failed(
                "a test-owned direct attachment survived synchronous rollback".to_owned(),
            ));
        }
        if state.pin_root.exists() {
            return Err(BackendError::Failed(format!(
                "{} survived synchronous rollback",
                state.pin_root.display()
            )));
        }
        records::remove(&self.settings.state_dir, STATE_FILE)?;
        remove_file_if_present(&self.settings.state_dir.join(format!(".{STATE_FILE}.tmp")))?;
        File::open(&self.settings.state_dir)?.sync_all()?;
        if self.state_path().exists() {
            return Err(BackendError::Failed(
                "the INTENT record survived synchronous rollback".to_owned(),
            ));
        }
        eprintln!(
            "event.name=cgroup_bpf.generation_rollback result=PASS generation={}",
            state.generation
        );
        Ok(())
    }

    fn rollback_startup_directories(
        &self,
        state_dir_existed: bool,
        pin_root_existed: bool,
    ) -> Result<(), BackendError> {
        if !state_dir_existed {
            match fs::remove_dir(&self.settings.state_dir) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !pin_root_existed {
            match fs::remove_dir(&self.settings.configured_pin_root) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn bpf_mut(&mut self) -> Result<&mut Ebpf, BackendError> {
        self.bpf
            .as_mut()
            .ok_or_else(|| BackendError::Failed("the BPF generation is unavailable".to_owned()))
    }

    fn set_policy(
        &mut self,
        binding: BindingKey,
        state: u32,
        flags: u64,
    ) -> Result<(), BackendError> {
        let map = self
            .bpf_mut()?
            .map_mut("soglia_policy")
            .ok_or_else(|| BackendError::Failed("soglia_policy is absent".to_owned()))?;
        let mut policies = HashMap::<_, u64, [u8; 40]>::try_from(map)
            .map_err(|error| BackendError::Failed(format!("open policy map: {error:#}")))?;
        policies
            .insert(binding.cgroup_id, encode_policy(state, binding), flags)
            .map_err(|error| BackendError::Failed(format!("update policy map: {error:#}")))
    }

    fn remove_policy(&mut self, binding: BindingKey) -> Result<(), BackendError> {
        self.require_policy(binding, POLICY_FROZEN)?;
        let map = self
            .bpf_mut()?
            .map_mut("soglia_policy")
            .ok_or_else(|| BackendError::Failed("soglia_policy is absent".to_owned()))?;
        let mut policies = HashMap::<_, u64, [u8; 40]>::try_from(map)
            .map_err(|error| BackendError::Failed(format!("open policy map: {error:#}")))?;
        policies
            .remove(&binding.cgroup_id)
            .map_err(|error| BackendError::Failed(format!("remove policy: {error:#}")))
    }

    fn policy(&mut self, binding: BindingKey) -> Result<Option<(u32, BindingKey)>, BackendError> {
        let map = self
            .bpf_mut()?
            .map("soglia_policy")
            .ok_or_else(|| BackendError::Failed("soglia_policy is absent".to_owned()))?;
        let policies = HashMap::<_, u64, [u8; 40]>::try_from(map)
            .map_err(|error| BackendError::Failed(format!("open policy map: {error:#}")))?;
        match policies.get(&binding.cgroup_id, 0) {
            Ok(value) => decode_policy(&value)
                .map(Some)
                .ok_or_else(|| BackendError::Failed("policy value has an invalid ABI".to_owned())),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(BackendError::Failed(format!("lookup policy: {error:#}"))),
        }
    }

    fn require_policy(&mut self, binding: BindingKey, state: u32) -> Result<(), BackendError> {
        if self.policy(binding)? == Some((state, binding)) {
            Ok(())
        } else {
            Err(BackendError::Refused(
                "the policy does not contain the exact expected BindingKey and state".to_owned(),
            ))
        }
    }

    fn sweep_binding(&mut self, binding: BindingKey) -> Result<(), BackendError> {
        for (name, value_size) in [("soglia_cookie_a", 32_usize), ("soglia_tuples", 48_usize)] {
            let key_size = if name == "soglia_cookie_a" { 8 } else { 16 };
            let map = self
                .bpf_mut()?
                .map_mut(name)
                .ok_or_else(|| BackendError::Failed(format!("{name} is absent")))?;
            if key_size == 8 && value_size == 32 {
                let mut entries = HashMap::<_, [u8; 8], [u8; 32]>::try_from(map)
                    .map_err(|error| BackendError::Failed(format!("open {name}: {error:#}")))?;
                let keys = entries
                    .iter()
                    .filter_map(|entry| match entry {
                        Ok((key, value)) if decode_binding(&value) == Some(binding) => {
                            Some(Ok(key))
                        }
                        Ok(_) => None,
                        Err(error) => Some(Err(error)),
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| {
                        BackendError::Failed(format!("enumerate {name}: {error:#}"))
                    })?;
                for key in keys {
                    cleanup_map_delete(entries.remove(&key), name)?;
                }
                for entry in entries.iter() {
                    let (_, value) = entry.map_err(|error| {
                        BackendError::Failed(format!("verify {name}: {error:#}"))
                    })?;
                    if decode_binding(&value) == Some(binding) {
                        return Err(BackendError::Failed(format!(
                            "{name} retained the destroyed BindingKey"
                        )));
                    }
                }
            } else {
                let mut entries = HashMap::<_, [u8; 16], [u8; 48]>::try_from(map)
                    .map_err(|error| BackendError::Failed(format!("open {name}: {error:#}")))?;
                let keys = entries
                    .iter()
                    .filter_map(|entry| match entry {
                        Ok((key, value)) if decode_binding(&value[8..40]) == Some(binding) => {
                            Some(Ok(key))
                        }
                        Ok(_) => None,
                        Err(error) => Some(Err(error)),
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| {
                        BackendError::Failed(format!("enumerate {name}: {error:#}"))
                    })?;
                for key in keys {
                    cleanup_map_delete(entries.remove(&key), name)?;
                }
                for entry in entries.iter() {
                    let (_, value) = entry.map_err(|error| {
                        BackendError::Failed(format!("verify {name}: {error:#}"))
                    })?;
                    if decode_binding(&value[8..40]) == Some(binding) {
                        return Err(BackendError::Failed(format!(
                            "{name} retained the destroyed BindingKey"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    fn remove_deny_counter(&mut self, binding: BindingKey) -> Result<(), BackendError> {
        let map = self
            .bpf_mut()?
            .map_mut("soglia_denies")
            .ok_or_else(|| BackendError::Failed("soglia_denies is absent".to_owned()))?;
        let mut denies = HashMap::<_, [u8; 32], u64>::try_from(map)
            .map_err(|error| BackendError::Failed(format!("open deny map: {error:#}")))?;
        let key = encode_binding(binding);
        cleanup_map_delete(denies.remove(&key), "deny counter")?;
        match denies.get(&key, 0) {
            Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Ok(_) => Err(BackendError::Failed(
                "deny counter remained after exact removal".to_owned(),
            )),
            Err(error) => Err(BackendError::Failed(format!(
                "verify deny counter removal: {error:#}"
            ))),
        }
    }

    fn lookup_cookie(&mut self, cookie: u64) -> Result<Option<BindingKey>, BackendError> {
        let map = self
            .bpf_mut()?
            .map("soglia_cookie_a")
            .ok_or_else(|| BackendError::Failed("soglia_cookie_a is absent".to_owned()))?;
        let entries = HashMap::<_, u64, [u8; 32]>::try_from(map)
            .map_err(|error| BackendError::Failed(format!("open cookie map: {error:#}")))?;
        match entries.get(&cookie, 0) {
            Ok(value) => decode_binding(&value)
                .map(Some)
                .ok_or_else(|| BackendError::Failed("cookie value has an invalid ABI".to_owned())),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(BackendError::Failed(format!("lookup cookie: {error:#}"))),
        }
    }

    fn update_occupancy(&mut self) -> Result<(usize, usize), BackendError> {
        let cookie_count = {
            let map = self
                .bpf_mut()?
                .map("soglia_cookie_a")
                .ok_or_else(|| BackendError::Failed("soglia_cookie_a is absent".to_owned()))?;
            let entries = HashMap::<_, u64, [u8; 32]>::try_from(map)
                .map_err(|error| BackendError::Failed(format!("open cookie map: {error:#}")))?;
            entries
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| BackendError::Failed(format!("enumerate cookie map: {error:#}")))?
                .len()
        };
        let tuple_count = {
            let map = self
                .bpf_mut()?
                .map("soglia_tuples")
                .ok_or_else(|| BackendError::Failed("soglia_tuples is absent".to_owned()))?;
            let entries = HashMap::<_, [u8; 16], [u8; 48]>::try_from(map)
                .map_err(|error| BackendError::Failed(format!("open tuple map: {error:#}")))?;
            entries
                .iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| BackendError::Failed(format!("enumerate tuple map: {error:#}")))?
                .len()
        };
        let changed = cookie_count > self.cookie_high_water || tuple_count > self.tuple_high_water;
        self.cookie_high_water = self.cookie_high_water.max(cookie_count);
        self.tuple_high_water = self.tuple_high_water.max(tuple_count);
        if changed {
            eprintln!(
                "event.name=cgroup_bpf.occupancy cookie={cookie_count} cookie_high_water={} tuple={tuple_count} tuple_high_water={} capacity={}",
                self.cookie_high_water, self.tuple_high_water, self.settings.socket_capacity
            );
        }
        Ok((cookie_count, tuple_count))
    }

    fn read_counters(&mut self) -> Result<[u64; COUNTER_COUNT], BackendError> {
        let map = self
            .bpf_mut()?
            .map("soglia_counters")
            .ok_or_else(|| BackendError::Failed("soglia_counters is absent".to_owned()))?;
        let counters = Array::<_, u64>::try_from(map)
            .map_err(|error| BackendError::Failed(format!("open counter map: {error:#}")))?;
        if counters.len() != u32::try_from(COUNTER_COUNT).unwrap_or(u32::MAX) {
            return Err(BackendError::Failed(format!(
                "counter map has {} entries, expected {COUNTER_COUNT}",
                counters.len()
            )));
        }
        let mut snapshot = [0_u64; COUNTER_COUNT];
        for (index, value) in snapshot.iter_mut().enumerate() {
            *value = counters
                .get(&u32::try_from(index).unwrap_or(u32::MAX), 0)
                .map_err(|error| {
                    BackendError::Failed(format!("read counter {index}: {error:#}"))
                })?;
        }
        Ok(snapshot)
    }

    fn drain_ring_events(&mut self) -> Result<u64, BackendError> {
        let drain_limit = ring_drain_limit(self.settings.ring_bytes);
        let map = self
            .bpf_mut()?
            .map_mut("soglia_events")
            .ok_or_else(|| BackendError::Failed("soglia_events is absent".to_owned()))?;
        let mut events = RingBuf::try_from(map)
            .map_err(|error| BackendError::Failed(format!("open event ring: {error:#}")))?;
        let mut drained = 0_u64;
        for _ in 0..drain_limit {
            let Some(event) = events.next() else {
                break;
            };
            validate_ring_event(&event)?;
            drained = drained.saturating_add(1);
        }
        self.ring_events_consumed = self.ring_events_consumed.saturating_add(drained);
        Ok(drained)
    }

    fn emit_health_snapshot(
        &mut self,
        state: &HostState,
        cookie_count: usize,
        tuple_count: usize,
    ) -> Result<(), BackendError> {
        let drained = self.drain_ring_events()?;
        let counters = self.read_counters()?;
        let active = self
            .live
            .values()
            .filter(|execution| execution.phase == ExecutionPhase::Active)
            .count();
        let prepared = self
            .live
            .values()
            .filter(|execution| execution.phase == ExecutionPhase::NetworkPreparedFrozen)
            .count();
        let frozen = self
            .live
            .values()
            .filter(|execution| execution.phase == ExecutionPhase::Frozen)
            .count();
        let ancestor_fingerprint = hex(&Sha256::digest(
            serde_json::to_vec(&state.ancestor_bpf).map_err(|error| {
                BackendError::Failed(format!("encode ancestor fingerprint: {error}"))
            })?,
        ));
        self.health_sequence = self.health_sequence.saturating_add(1);
        eprintln!(
            "event.name=cgroup_bpf.health sequence={} generation={} programs={} links={} maps={} policy_active={active} policy_prepared={prepared} policy_frozen={frozen} policy_capacity={} cookie={cookie_count} cookie_high_water={} tuple={tuple_count} tuple_high_water={} socket_capacity={} ring_drained={drained} ring_consumed_total={} ring_dropped={} cookie_insert_failed={} tuple_insert_failed={} published={} unpublished={} sock_create_deny={} connect4_deny={} connect6_deny={} sendmsg4_deny={} sendmsg6_deny={} cookie_miss={} sock_create_entry={} connect4_entry={} connect6_entry={} sendmsg4_entry={} sendmsg6_entry={} sockops_entry={} deny_not_active={} deny_not_tcp={} deny_not_proxy={} deny_ipv6={} deny_family={} deny_udp={} deny_cookie_full={} deny_tuple_full={} deny_cookie_missing={} ancestor_fingerprint={ancestor_fingerprint}",
            self.health_sequence,
            state.generation,
            state.programs.len(),
            state.links.len(),
            state.maps.len(),
            self.settings.policy_capacity,
            self.cookie_high_water,
            self.tuple_high_water,
            self.settings.socket_capacity,
            self.ring_events_consumed,
            counters[0],
            counters[1],
            counters[2],
            counters[3],
            counters[4],
            counters[5],
            counters[6],
            counters[7],
            counters[8],
            counters[9],
            counters[10],
            counters[11],
            counters[12],
            counters[13],
            counters[14],
            counters[15],
            counters[16],
            counters[17],
            counters[18],
            counters[19],
            counters[20],
            counters[21],
            counters[22],
            counters[23],
            counters[24],
            counters[25]
        );
        Ok(())
    }

    fn consume_tuple(
        &mut self,
        tuple: SocketTupleV4,
    ) -> Result<Option<(u64, BindingKey)>, BackendError> {
        let key = encode_tuple(tuple);
        let value = self
            .tuple_consumer
            .as_ref()
            .ok_or_else(|| BackendError::Failed("the tuple consumer is unavailable".to_owned()))?
            .lookup_and_delete(&key)
            .map_err(|error| {
                BackendError::Failed(format!("consume tuple atomically: {error:#}"))
            })?;
        let Some(value) = value else {
            return Ok(None);
        };
        if value.len() != 48 {
            return Err(BackendError::Failed(format!(
                "tuple value has width {}, expected 48",
                value.len()
            )));
        }
        let cookie =
            u64::from_ne_bytes(value[0..8].try_into().map_err(|_| {
                BackendError::Failed("tuple cookie has the wrong width".to_owned())
            })?);
        let binding = decode_binding(&value[8..40]).ok_or_else(|| {
            BackendError::Failed("tuple contains an invalid BindingKey".to_owned())
        })?;
        Ok(Some((cookie, binding)))
    }
}

impl PreparedCgroupBpfUninstall {
    /// Returns the exact plan without changing host state.
    pub fn dry_run_report(&self) -> CgroupBpfUninstallReport {
        let (classification, mut operations) = match &self.generation {
            GenerationClassification::Fresh { pin_root } => {
                ("FRESH", fresh_pin_root_operations(*pin_root))
            }
            GenerationClassification::Recorded {
                state,
                target_released,
            } => (
                if *target_released {
                    "TARGET_RELEASED"
                } else {
                    "KNOWN_COMPATIBLE"
                },
                vec![format!(
                    "remove recorded cgroup-BPF generation {}",
                    state.generation
                )],
            ),
        };
        operations.extend(self.network.planned_operations());
        CgroupBpfUninstallReport {
            classification,
            dry_run: true,
            operations,
            absence_verified: false,
        }
    }

    /// Executes the previously validated exact plan and verifies final absence.
    pub fn execute(self) -> Result<CgroupBpfUninstallReport, BackendError> {
        let PreparedCgroupBpfUninstall {
            backend,
            generation,
            network,
        } = self;
        let (classification, mut operations) = match generation {
            GenerationClassification::Fresh { pin_root } => {
                remove_prepared_empty_pin_root(&backend.settings.configured_pin_root, pin_root)?;
                ("FRESH", fresh_pin_root_operations(pin_root))
            }
            GenerationClassification::Recorded {
                mut state,
                target_released,
            } => {
                let classification = if target_released {
                    "TARGET_RELEASED"
                } else {
                    "KNOWN_COMPATIBLE"
                };
                state.phase = ManifestPhase::Intent;
                let intent = UninstallIntent {
                    schema: UNINSTALL_SCHEMA,
                    state: (*state).clone(),
                };
                records::publish(&backend.settings.state_dir, UNINSTALL_FILE, &intent)?;
                fs::set_permissions(backend.uninstall_path(), fs::Permissions::from_mode(0o600))?;
                backend.publish_state(&state)?;
                if target_released {
                    backend.detach_released_links(&state)?;
                }
                backend.remove_recorded_pins(&state)?;
                backend.verify_recorded_objects_absent(&state)?;
                if verify_external_inventory_on_target(
                    target_released,
                    backend.settings.executions.exists(),
                )? {
                    let owned: BTreeSet<u32> =
                        state.programs.iter().map(|program| program.id).collect();
                    let external = backend.foreign_effective_fingerprint(&owned)?;
                    require_same_external_inventory(
                        &state.ancestor_bpf,
                        &external,
                        "after verified uninstall",
                    )?;
                }
                (
                    classification,
                    vec![format!(
                        "remove recorded cgroup-BPF generation {}",
                        state.generation
                    )],
                )
            }
        };

        operations.extend(network.planned_operations());
        backend.network.execute_uninstall(&network)?;
        records::remove(&backend.settings.state_dir, STATE_FILE)?;
        remove_file_if_present(
            &backend
                .settings
                .state_dir
                .join(format!(".{STATE_FILE}.tmp")),
        )?;
        records::remove(&backend.settings.state_dir, UNINSTALL_FILE)?;
        remove_file_if_present(
            &backend
                .settings
                .state_dir
                .join(format!(".{UNINSTALL_FILE}.tmp")),
        )?;
        for directory in [
            &backend.settings.state_dir,
            &backend.settings.configured_pin_root,
        ] {
            match fs::remove_dir(directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if backend.state_path().exists()
            || backend.uninstall_path().exists()
            || backend.settings.state_dir.exists()
            || backend.settings.configured_pin_root.exists()
        {
            return Err(BackendError::Failed(
                "verified uninstall left cgroup-BPF state or pins behind".to_owned(),
            ));
        }
        Ok(CgroupBpfUninstallReport {
            classification,
            dry_run: false,
            operations,
            absence_verified: true,
        })
    }
}

fn validate_ring_event(event: &[u8]) -> Result<u32, BackendError> {
    if event.len() != RING_EVENT_WIDTH {
        return Err(BackendError::Failed(format!(
            "ring event has width {}, expected {RING_EVENT_WIDTH}",
            event.len()
        )));
    }
    let reason =
        u32::from_ne_bytes(event[0..4].try_into().map_err(|_| {
            BackendError::Failed("ring event reason has the wrong width".to_owned())
        })?);
    if !(1..=DENY_REASON_COUNT).contains(&reason) {
        return Err(BackendError::Failed(format!(
            "ring event contains invalid deny reason {reason}"
        )));
    }
    Ok(reason)
}

fn verify_external_inventory_on_target(
    target_released: bool,
    target_exists: bool,
) -> Result<bool, BackendError> {
    if target_exists {
        Ok(true)
    } else if target_released {
        Ok(false)
    } else {
        Err(BackendError::Failed(
            "the known-compatible cgroup-BPF target vanished during verified uninstall".to_owned(),
        ))
    }
}

fn ring_drain_limit(ring_bytes: u32) -> usize {
    usize::try_from(ring_bytes)
        .unwrap_or(usize::MAX)
        .checked_div(RING_EVENT_WIDTH)
        .unwrap_or(0)
        .max(1)
}

/// A cleanup key may disappear after it was observed: sockops owns socket-state expiry, and a deny
/// counter is created lazily. Aya reports an absent key from `HashMap::remove` as the raw delete
/// syscall's `ENOENT`, not as `MapError::KeyNotFound`. No other syscall or errno is benign.
fn cleanup_map_delete(result: Result<(), MapError>, resource: &str) -> Result<(), BackendError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if map_delete_was_already_absent(&error) => Ok(()),
        Err(error) => Err(BackendError::Failed(format!(
            "remove from {resource}: {error:#}"
        ))),
    }
}

fn map_delete_was_already_absent(error: &MapError) -> bool {
    matches!(
        error,
        MapError::SyscallError(aya::sys::SyscallError { call, io_error })
            if *call == "bpf_map_delete_elem"
                && io_error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error())
    )
}

fn recorded_kernel_objects_present(state: &HostState) -> Result<Vec<String>, BackendError> {
    let mut program_ids = BTreeSet::new();
    for info in loaded_programs() {
        match info {
            Ok(info) => {
                program_ids.insert(info.id());
            }
            Err(error) if program_disappeared_during_inventory(&error) => {}
            Err(error) => {
                return Err(BackendError::Failed(format!(
                    "enumerate programs after recovery: {error:#}"
                )));
            }
        }
    }
    let mut map_ids = BTreeSet::new();
    for info in loaded_maps() {
        match info {
            Ok(info) => {
                map_ids.insert(info.id());
            }
            Err(error) if map_disappeared_during_inventory(&error) => {}
            Err(error) => {
                return Err(BackendError::Failed(format!(
                    "enumerate maps after recovery: {error:#}"
                )));
            }
        }
    }
    let mut link_ids = BTreeSet::new();
    for info in loaded_links() {
        match info {
            Ok(info) => {
                link_ids.insert(info.id());
            }
            Err(error) if link_disappeared_during_inventory(&error) => {}
            Err(error) => {
                return Err(BackendError::Failed(format!(
                    "enumerate links after recovery: {error:#}"
                )));
            }
        }
    }

    let mut surviving = Vec::new();
    surviving.extend(
        state
            .programs
            .iter()
            .filter(|program| program_ids.contains(&program.id))
            .map(|program| format!("program:{}", program.id)),
    );
    surviving.extend(
        state
            .maps
            .iter()
            .filter(|map| map_ids.contains(&map.id))
            .map(|map| format!("map:{}", map.id)),
    );
    surviving.extend(
        state
            .links
            .iter()
            .filter(|link| link_ids.contains(&link.id))
            .map(|link| format!("link:{}", link.id)),
    );
    Ok(surviving)
}

/// Aya inventories kernel objects in two syscalls: it obtains the next ID and then opens that ID.
/// Recovery has just removed the recorded objects, so an object may legitimately disappear between
/// those calls. Only `ENOENT` from the exact get-FD-by-ID syscall is benign; every other inventory
/// error still makes cleanup unproven.
fn program_disappeared_during_inventory(error: &ProgramError) -> bool {
    matches!(
        error,
        ProgramError::SyscallError(error)
            if syscall_reports_absent(error, "bpf_prog_get_fd_by_id")
    )
}

fn map_disappeared_during_inventory(error: &MapError) -> bool {
    matches!(
        error,
        MapError::SyscallError(error)
            if syscall_reports_absent(error, "bpf_map_get_fd_by_id")
    )
}

fn link_disappeared_during_inventory(error: &LinkError) -> bool {
    matches!(
        error,
        LinkError::SyscallError(error)
            if syscall_reports_absent(error, "bpf_link_get_fd_by_id")
    )
}

fn syscall_reports_absent(error: &aya::sys::SyscallError, expected_call: &str) -> bool {
    error.call == expected_call
        && error.io_error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error())
}

impl EnforcementBackend for CgroupBpfBackend {
    fn name(&self) -> &'static str {
        "cgroup-bpf"
    }

    fn live_tags(&self) -> Vec<ResourceTag> {
        CgroupBpfBackend::live_tags(self)
    }

    fn probe_capabilities(&self) -> Result<(), BackendError> {
        if !system::is_root() {
            return Err(BackendError::Unsupported(
                "the enforcer must run as root".to_owned(),
            ));
        }
        self.network.probe_capabilities()?;
        system::run(&self.settings.bpftool, &["version"], None).map_err(|error| {
            BackendError::Unsupported(format!("bpftool is unavailable: {error}"))
        })?;
        let target = fs::metadata(&self.settings.executions).map_err(|error| {
            BackendError::Unsupported(format!(
                "the delegated executions cgroup is not ready: {error}"
            ))
        })?;
        if !target.is_dir() {
            return Err(BackendError::Unsupported(
                "the delegated executions target is not a directory".to_owned(),
            ));
        }
        capture_attachment_handle(&self.settings.executions)?;
        require_bpffs_mount()?;
        if !Path::new("/sys/kernel/btf/vmlinux").is_file() {
            return Err(BackendError::Unsupported(
                "kernel BTF is unavailable".to_owned(),
            ));
        }
        Ok(())
    }

    fn initialize(&mut self) -> Result<Vec<String>, BackendError> {
        let started = Instant::now();
        let state_dir_existed = self.settings.state_dir.exists();
        let pin_root_existed = self.settings.configured_pin_root.exists();
        ensure_private_directory(&self.settings.state_dir)?;
        ensure_private_directory(&self.settings.configured_pin_root)?;
        let mut swept = self.network.initialize()?;
        let bpf_result = (|| {
            let (state_id, generation, recovered) = self.classify_and_recover()?;
            swept.extend(recovered);
            self.require_empty_direct_target()?;
            let ancestor_bpf = self.foreign_effective_fingerprint(&BTreeSet::new())?;
            self.probe_attach_topology()?;
            self.load_generation(state_id, generation, ancestor_bpf)
        })();
        match bpf_result {
            Ok(()) => {
                let state = self.state.as_ref().ok_or_else(|| {
                    BackendError::Failed("startup completed without durable state".to_owned())
                })?;
                eprintln!(
                    "event.name=cgroup_bpf.startup result=PASS generation={} duration_ms={} swept={} readiness=READY",
                    state.generation,
                    started.elapsed().as_millis(),
                    swept.len()
                );
                Ok(swept)
            }
            Err(error) => {
                let network = self.network.rollback_initialization();
                let directories =
                    self.rollback_startup_directories(state_dir_existed, pin_root_existed);
                match (network, directories) {
                    (Ok(()), Ok(())) => Err(error),
                    (network, directories) => Err(BackendError::Failed(format!(
                        "{error}; synchronous startup rollback was not verified (network={network:?}, directories={directories:?})"
                    ))),
                }
            }
        }
    }

    fn health_check(&mut self) -> Result<(), BackendError> {
        self.network.health_check()?;
        let mut state = self
            .state
            .clone()
            .ok_or_else(|| BackendError::Failed("the BPF generation has no state".to_owned()))?;
        if state.phase != ManifestPhase::Ready
            || self.bpf.is_none()
            || self.tuple_consumer.is_none()
            || self.links.len() != PROGRAMS.len()
        {
            return Err(BackendError::Failed(
                "the production BPF generation is not fully ready".to_owned(),
            ));
        }
        if fs::metadata(&state.attachment_target)?.ino() != state.attachment_inode {
            return Err(BackendError::Refused(
                "the production attachment target identity changed".to_owned(),
            ));
        }
        self.validate_recorded_pins(&state)?;
        if let Some(current) = self.validate_attachment_inventory(&state, true)? {
            state.ancestor_bpf = current;
            self.publish_state(&state)?;
            self.state = Some(state.clone());
        }
        if state.executions.len() != self.live.len()
            || state
                .executions
                .values()
                .any(|execution| self.live.get(&execution.tag) != Some(execution))
        {
            return Err(BackendError::Failed(
                "durable and live Execution ownership inventories differ".to_owned(),
            ));
        }
        for execution in state.executions.values() {
            let expected = match execution.phase {
                ExecutionPhase::Active => POLICY_ACTIVE,
                ExecutionPhase::NetworkPreparedFrozen | ExecutionPhase::Frozen => POLICY_FROZEN,
            };
            self.require_policy(execution.binding, expected)?;
        }
        let (cookie_count, tuple_count) = self.update_occupancy()?;
        self.emit_health_snapshot(&state, cookie_count, tuple_count)?;
        Ok(())
    }

    fn prepare_execution(
        &mut self,
        id: ExecutionId,
        slot: u32,
        agent: &str,
        nonce: ExecutionNonce,
    ) -> Result<(), BackendError> {
        let tag = id.tag();
        if self.live.contains_key(&tag) {
            return Err(BackendError::Refused(format!("tag {tag} is already live")));
        }
        let cgroup = self.settings.executions.join(tag.to_string());
        let metadata = fs::metadata(&cgroup).map_err(|error| {
            BackendError::Refused(format!("reserved cgroup {}: {error}", cgroup.display()))
        })?;
        if !fs::read_to_string(cgroup.join("cgroup.procs"))?
            .trim()
            .is_empty()
        {
            return Err(BackendError::Refused(
                "the reserved cgroup is not empty".to_owned(),
            ));
        }
        let generation = self
            .state
            .as_ref()
            .ok_or_else(|| BackendError::Failed("the BPF generation is not ready".to_owned()))?
            .generation;
        let binding = BindingKey {
            cgroup_id: metadata.ino(),
            execution_nonce: nonce,
            backend_generation: generation,
        };
        let execution = ExecutionState {
            id,
            tag,
            slot,
            cgroup_inode: metadata.ino(),
            binding,
            phase: ExecutionPhase::NetworkPreparedFrozen,
        };
        self.update_execution(execution)?;
        if let Err(error) = self.set_policy(binding, POLICY_FROZEN, BPF_NOEXIST) {
            return match self.remove_execution_record(&tag) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(BackendError::Failed(format!(
                    "{error}; failed to roll back the ownership record: {cleanup}"
                ))),
            };
        }
        if let Err(error) = self.network.prepare_execution(id, slot, agent, nonce) {
            let freeze = self.network.freeze(&tag);
            let destroy = self.network.destroy_execution(&tag);
            if freeze.is_ok() && destroy.is_ok() {
                self.remove_policy(binding)?;
                self.remove_execution_record(&tag)?;
                return Err(error);
            }
            return Err(BackendError::Failed(format!(
                "{error}; network rollback was not verified (freeze={freeze:?}, destroy={destroy:?})"
            )));
        }
        Ok(())
    }

    fn verify_placement(
        &mut self,
        id: ExecutionId,
        pid: i32,
    ) -> Result<Option<BindingKey>, BackendError> {
        let mut state = self
            .state
            .clone()
            .ok_or_else(|| BackendError::Failed("the BPF generation has no state".to_owned()))?;
        self.validate_recorded_pins(&state)?;
        if let Some(current) = self.validate_attachment_inventory(&state, true)? {
            state.ancestor_bpf = current;
            self.publish_state(&state)?;
            self.state = Some(state.clone());
        }
        let tag = id.tag();
        let execution = self
            .live
            .get(&tag)
            .filter(|execution| execution.id == id)
            .cloned()
            .ok_or_else(|| {
                BackendError::Refused("the Execution has no frozen BPF record".to_owned())
            })?;
        if execution.phase != ExecutionPhase::NetworkPreparedFrozen {
            return Err(BackendError::Refused(
                "the Execution is not at the frozen activation stage".to_owned(),
            ));
        }
        let cgroup = self.settings.executions.join(tag.to_string());
        if fs::metadata(&cgroup)?.ino() != execution.cgroup_inode {
            return Err(BackendError::Refused(
                "the Execution cgroup inode changed".to_owned(),
            ));
        }
        let relative = cgroup
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| BackendError::Refused("the cgroup is outside cgroup v2".to_owned()))?;
        let expected = format!("/{}", relative.display());
        let membership = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let exact = membership
            .lines()
            .any(|line| line.strip_prefix("0::") == Some(expected.as_str()));
        let listed = fs::read_to_string(cgroup.join("cgroup.procs"))?
            .split_whitespace()
            .any(|entry| entry.parse::<i32>() == Ok(pid));
        if !exact || !listed {
            return Err(BackendError::Refused(format!(
                "paused pid {pid} is not in the exact Execution cgroup"
            )));
        }
        let agent_net = fs::metadata(format!("/proc/{pid}/ns/net"))?;
        let expected_net = fs::metadata(Path::new(system::NETNS_DIR).join(tag.netns_name()))?;
        if (agent_net.dev(), agent_net.ino()) != (expected_net.dev(), expected_net.ino()) {
            return Err(BackendError::Refused(
                "paused pid is not in the owned network namespace".to_owned(),
            ));
        }
        Ok(Some(execution.binding))
    }

    fn activate_execution(
        &mut self,
        id: ExecutionId,
        binding: Option<BindingKey>,
    ) -> Result<(), BackendError> {
        let tag = id.tag();
        let execution = self
            .live
            .get(&tag)
            .filter(|execution| execution.id == id)
            .cloned()
            .ok_or_else(|| {
                BackendError::Refused("the Execution has no frozen BPF record".to_owned())
            })?;
        if execution.phase != ExecutionPhase::NetworkPreparedFrozen
            || binding != Some(execution.binding)
        {
            return Err(BackendError::Refused(
                "activation does not carry the exact verified BindingKey".to_owned(),
            ));
        }
        self.require_policy(execution.binding, POLICY_FROZEN)?;
        self.set_policy(execution.binding, POLICY_ACTIVE, 0)?;
        let mut active = execution;
        active.phase = ExecutionPhase::Active;
        self.live.insert(tag, active.clone());
        self.update_execution(active)
    }

    fn resolve_once(&mut self, tuple: SocketTupleV4) -> Result<ResolveAttempt, BackendError> {
        if tuple.destination_address != self.settings.proxy_ip.octets()
            || tuple.destination_port != self.settings.proxy_port
        {
            return Ok(ResolveAttempt::Complete {
                result: ResolveResult::NotFound,
            });
        }
        let Some((cookie, binding)) = self.consume_tuple(tuple)? else {
            return Ok(ResolveAttempt::Pending {
                reason: ResolvePending::TupleAbsent,
            });
        };

        // Structural integrity is checked before any semantic mismatch or revocation outcome.
        if cookie == 0 {
            return Err(BackendError::Failed(
                "tuple contains an invalid zero socket cookie".to_owned(),
            ));
        }
        let generation = self
            .state
            .as_ref()
            .map(|state| state.generation)
            .unwrap_or(0);
        if generation == 0 {
            return Err(BackendError::Failed(
                "the live backend generation is unavailable".to_owned(),
            ));
        }
        let execution = {
            let mut correlated = self.live.values().filter(|execution| {
                execution.binding.cgroup_id == binding.cgroup_id
                    || execution.binding.execution_nonce == binding.execution_nonce
            });
            let first = correlated.next().cloned();
            if correlated.next().is_some() {
                return Err(BackendError::Failed(
                    "multiple live ownership records correlate with one tuple".to_owned(),
                ));
            }
            first
        };
        let cookie_binding = self.lookup_cookie(cookie)?;
        let policy = self.policy(binding)?;
        if let Some((state, _)) = policy
            && state != POLICY_ACTIVE
            && state != POLICY_FROZEN
        {
            return Err(BackendError::Failed(format!(
                "policy contains invalid state {state}"
            )));
        }

        let result =
            classify_resolve_snapshot(binding, generation, execution, cookie_binding, policy);
        Ok(ResolveAttempt::Complete { result })
    }

    fn freeze(&mut self, tag: &ResourceTag) -> Result<(), BackendError> {
        let started = Instant::now();
        let execution = self
            .live
            .get(tag)
            .cloned()
            .ok_or_else(|| BackendError::Refused(format!("no BPF record exists for {tag}")))?;
        let expected = match execution.phase {
            ExecutionPhase::Active => POLICY_ACTIVE,
            ExecutionPhase::NetworkPreparedFrozen | ExecutionPhase::Frozen => POLICY_FROZEN,
        };
        self.require_policy(execution.binding, expected)?;
        if expected == POLICY_ACTIVE {
            self.set_policy(execution.binding, POLICY_FROZEN, 0)?;
        }
        let mut frozen = execution;
        frozen.phase = ExecutionPhase::Frozen;
        self.live.insert(*tag, frozen.clone());
        self.network.freeze(tag)?;
        self.update_execution(frozen)?;
        eprintln!(
            "event.name=cgroup_bpf.freeze result=PASS correlation={tag} duration_ms={}",
            started.elapsed().as_millis()
        );
        Ok(())
    }

    fn destroy_execution(&mut self, tag: &ResourceTag) -> Result<(), BackendError> {
        let started = Instant::now();
        let execution = self
            .live
            .get(tag)
            .cloned()
            .ok_or_else(|| BackendError::Refused(format!("no BPF record exists for {tag}")))?;
        if execution.phase != ExecutionPhase::Frozen {
            return Err(BackendError::Refused(
                "destroy requires an exact frozen BPF record".to_owned(),
            ));
        }
        self.require_policy(execution.binding, POLICY_FROZEN)?;
        let cgroup = self.settings.executions.join(tag.to_string());
        if cgroup.exists() {
            return Err(BackendError::Refused(
                "Sandbox must remove the empty cgroup before BPF destroy".to_owned(),
            ));
        }
        self.sweep_binding(execution.binding)?;
        self.remove_deny_counter(execution.binding)?;
        self.remove_policy(execution.binding)?;
        if self.policy(execution.binding)?.is_some() {
            return Err(BackendError::Failed(
                "policy remained after exact removal".to_owned(),
            ));
        }
        self.network.destroy_execution(tag)?;
        self.remove_execution_record(tag)?;
        eprintln!(
            "event.name=cgroup_bpf.destroy result=PASS correlation={tag} duration_ms={}",
            started.elapsed().as_millis()
        );
        Ok(())
    }
}

impl Drop for CgroupBpfBackend {
    fn drop(&mut self) {
        let bindings: Vec<BindingKey> = self.live.values().map(|value| value.binding).collect();
        for binding in bindings {
            if self.policy(binding).ok().flatten() == Some((POLICY_ACTIVE, binding)) {
                let _ = self.set_policy(binding, POLICY_FROZEN, 0);
            }
        }
        // Pins intentionally keep this exact early-deny generation alive for S13 recovery.
    }
}

fn unknown_execution_record() -> BackendError {
    BackendError::Unknown(
        "UNKNOWN per-Execution ownership record; no kernel object was changed".to_owned(),
    )
}

fn validate_recovery_policy_snapshot<'a>(
    phase: ManifestPhase,
    executions: impl Iterator<Item = &'a ExecutionState>,
    policies: Option<&BTreeMap<u64, (u32, BindingKey)>>,
) -> Result<(), BackendError> {
    let Some(policies) = policies else {
        return if phase == ManifestPhase::Intent {
            Ok(())
        } else {
            Err(unknown_execution_record())
        };
    };

    let mut recorded = BTreeMap::new();
    for execution in executions {
        if recorded
            .insert(execution.binding.cgroup_id, execution)
            .is_some()
        {
            return Err(unknown_execution_record());
        }
    }
    for (cgroup_id, (state, binding)) in policies {
        if (*state != POLICY_FROZEN && *state != POLICY_ACTIVE)
            || binding.cgroup_id != *cgroup_id
            || recorded
                .get(cgroup_id)
                .is_none_or(|execution| execution.binding != *binding)
        {
            return Err(unknown_execution_record());
        }
    }
    for (cgroup_id, execution) in recorded
        .iter()
        .filter(|(cgroup_id, _)| !policies.contains_key(cgroup_id))
    {
        // These are the two owned record-without-policy windows: prepare publishes the
        // NetworkPreparedFrozen record before inserting policy, while destroy removes frozen
        // policy before deleting its record. Neither record has kernel authorization.
        if !matches!(
            execution.phase,
            ExecutionPhase::NetworkPreparedFrozen | ExecutionPhase::Frozen
        ) {
            return Err(unknown_execution_record());
        }
        eprintln!(
            "event.name=cgroup_bpf.recovery_record_without_policy cgroup_id={cgroup_id} phase={:?}",
            execution.phase
        );
    }
    Ok(())
}

fn delegated_root(configured: Option<&Path>) -> Result<PathBuf, BackendError> {
    if let Some(root) = configured {
        return Ok(root.to_path_buf());
    }
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| BackendError::Unsupported("not in a cgroup v2 hierarchy".to_owned()))?;
    let path = path.strip_suffix("/runtime").unwrap_or(path);
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

fn expected_link_contract(name: &str) -> Option<(&'static ProgramSpec, ProgramAttachType)> {
    let program = PROGRAMS.iter().find(|program| program.pin == name)?;
    let attach_type = match program.pin {
        "sock_create" => ProgramAttachType::CgroupInetSockCreate,
        "connect4" => ProgramAttachType::CgroupInet4Connect,
        "connect6" => ProgramAttachType::CgroupInet6Connect,
        "sendmsg4" => ProgramAttachType::CgroupUdp4Sendmsg,
        "sendmsg6" => ProgramAttachType::CgroupUdp6Sendmsg,
        "sock_ops" => ProgramAttachType::CgroupSockOps,
        _ => return None,
    };
    Some((program, attach_type))
}

fn expected_program_contract(symbol: &str) -> Option<(ProgramType, &'static str)> {
    match symbol {
        "soglia_sock_create" => Some((ProgramType::CgroupSock, "BPF_PROG_TYPE_CGROUP_SOCK")),
        "soglia_connect4" | "soglia_connect6" | "soglia_sendmsg4" | "soglia_sendmsg6" => Some((
            ProgramType::CgroupSockAddr,
            "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
        )),
        "soglia_sockops" => Some((ProgramType::SockOps, "BPF_PROG_TYPE_SOCK_OPS")),
        _ => None,
    }
}

fn capture_attachment_handle(path: &Path) -> Result<AttachmentHandle, BackendError> {
    let target = File::open(path).map_err(|error| {
        BackendError::Unsupported(format!(
            "the cgroup attachment target cannot be opened for a durable handle: {error}"
        ))
    })?;
    let (handle, _) =
        name_to_handle_at(&target, Path::new(""), AT_EMPTY_PATH).map_err(|error| {
            BackendError::Unsupported(format!(
                "the cgroup attachment target has no supported durable handle: {error}"
            ))
        })?;
    let mount_id_unique = unique_mount_id(&target).map_err(|error| {
        BackendError::Unsupported(format!(
            "the cgroup attachment target has no unique mount identity: {error}"
        ))
    })?;
    let recorded = AttachmentHandle {
        handle_type: handle.handle_type,
        handle: handle.handle,
        mount_id_unique,
    };
    validate_attachment_handle_structure(&recorded).map_err(|_| {
        BackendError::Unsupported(
            "the cgroup attachment target returned a malformed durable handle".to_owned(),
        )
    })?;
    validate_live_attachment_handle(path, &recorded)?;
    Ok(recorded)
}

fn validate_attachment_handle_structure(handle: &AttachmentHandle) -> Result<(), BackendError> {
    if handle.handle_type == 0
        || handle.handle.is_empty()
        || handle.handle.len() > 128
        || handle.mount_id_unique == 0
    {
        return Err(BackendError::Unknown(
            "UNKNOWN cgroup attachment handle structure; no object was changed".to_owned(),
        ));
    }
    Ok(())
}

fn current_cgroup2_mount() -> Result<(File, u64), io::Error> {
    let mount = File::open("/sys/fs/cgroup")?;
    let mount_id = unique_mount_id(&mount)?;
    Ok((mount, mount_id))
}

fn unique_mount_id(file: &File) -> Result<u64, io::Error> {
    let requested = rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
    let stat = rustix::fs::statx(
        file,
        Path::new(""),
        rustix::fs::AtFlags::EMPTY_PATH | rustix::fs::AtFlags::NO_AUTOMOUNT,
        requested,
    )?;
    if stat.stx_mask & STATX_MNT_ID_UNIQUE == 0 || stat.stx_mnt_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "STATX_MNT_ID_UNIQUE is unavailable",
        ));
    }
    Ok(stat.stx_mnt_id)
}

fn linux_file_handle(recorded: &AttachmentHandle) -> LinuxFileHandle {
    LinuxFileHandle {
        handle_type: recorded.handle_type,
        handle: recorded.handle.clone(),
    }
}

fn validate_live_attachment_handle(
    path: &Path,
    recorded: &AttachmentHandle,
) -> Result<(), BackendError> {
    let (mount, mount_id) = current_cgroup2_mount().map_err(|error| {
        BackendError::Unsupported(format!("the cgroup2 mount cannot be identified: {error}"))
    })?;
    if mount_id != recorded.mount_id_unique {
        return Err(BackendError::Unsupported(
            "the attachment handle belongs to a different cgroup2 mount".to_owned(),
        ));
    }
    let opened = open_by_handle_at(&mount, &linux_file_handle(recorded), 0).map_err(|error| {
        BackendError::Unsupported(format!(
            "the live cgroup attachment handle cannot be opened: {error}"
        ))
    })?;
    let reopened = File::from(opened);
    let expected = fs::metadata(path)?;
    let actual = reopened.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(BackendError::Unsupported(
            "the live cgroup attachment handle resolved to a different object".to_owned(),
        ));
    }
    Ok(())
}

fn validate_offline_attachment_handle(recorded: &AttachmentHandle) -> Result<(), BackendError> {
    validate_attachment_handle_structure(recorded)?;
    let (mount, mount_id) = current_cgroup2_mount().map_err(|error| {
        BackendError::Unknown(format!(
            "UNKNOWN cgroup2 mount identity cannot be established: {error}; no object was changed"
        ))
    })?;
    if mount_id != recorded.mount_id_unique {
        return Err(BackendError::Unknown(
            "UNKNOWN cgroup2 mount identity changed; no object was changed".to_owned(),
        ));
    }
    let observation = match open_by_handle_at(&mount, &linux_file_handle(recorded), 0) {
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::STALE.raw_os_error()) => {
            OfflineHandleObservation::Stale
        }
        Ok(_) => OfflineHandleObservation::Openable,
        Err(error) => OfflineHandleObservation::Error(error.raw_os_error()),
    };
    validate_offline_handle_observation(observation)
}

fn validate_offline_handle_observation(
    observation: OfflineHandleObservation,
) -> Result<(), BackendError> {
    match observation {
        OfflineHandleObservation::Stale => Ok(()),
        OfflineHandleObservation::Openable => Err(BackendError::Unknown(
            "UNKNOWN recorded attachment handle is still openable; no object was changed"
                .to_owned(),
        )),
        OfflineHandleObservation::Error(errno) => Err(BackendError::Unknown(format!(
            "UNKNOWN recorded attachment handle did not return ESTALE (errno={errno:?}); no object was changed"
        ))),
    }
}

fn inspect_recorded_link(link: &LinkManifest) -> Result<RecordedLinkInfo, BackendError> {
    let pinned = Link::open(&link.pin).map_err(|error| {
        BackendError::Unknown(format!(
            "UNKNOWN recorded link at {} cannot be opened: {error:#}; no object was changed",
            link.pin.display()
        ))
    })?;
    recorded_link_info(link, &pinned)
}

fn recorded_link_info(
    link: &LinkManifest,
    pinned: &Link,
) -> Result<RecordedLinkInfo, BackendError> {
    let info = pinned.info().map_err(|error| {
        BackendError::Unknown(format!(
            "UNKNOWN recorded link at {} cannot be inspected: {error:#}; no object was changed",
            link.pin.display()
        ))
    })?;
    let LinkTypeInfo::Cgroup(cgroup) = info.info else {
        return Err(BackendError::Unknown(format!(
            "UNKNOWN link type at {}; no object was changed",
            link.pin.display()
        )));
    };
    Ok(RecordedLinkInfo {
        link_id: info.id,
        program_id: info.prog_id,
        attach_type: cgroup.attach_type as u32,
        cgroup_id: cgroup.cgroup_id,
    })
}

fn validate_recorded_link_identity(
    link: &LinkManifest,
    observed: RecordedLinkInfo,
) -> Result<(), BackendError> {
    let Some((_, attach_type)) = expected_link_contract(&link.name) else {
        return Err(BackendError::Unknown(
            "UNKNOWN link name in the ownership manifest; no object was changed".to_owned(),
        ));
    };
    if link.id == 0
        || link.program_id == 0
        || observed.link_id != link.id
        || observed.program_id != link.program_id
        || observed.attach_type != attach_type as u32
    {
        return Err(BackendError::Unknown(format!(
            "UNKNOWN link identity at {}; no object was changed",
            link.pin.display()
        )));
    }
    Ok(())
}

fn validate_released_link_target(
    observed: RecordedLinkInfo,
    recorded_cgroup_id: u64,
) -> Result<(), BackendError> {
    if recorded_cgroup_id == 0
        || (observed.cgroup_id != recorded_cgroup_id && observed.cgroup_id != 0)
    {
        return Err(BackendError::Unknown(
            "UNKNOWN recorded BPF link targets another cgroup; no object was changed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_post_detach_link(observed: RecordedLinkInfo) -> Result<(), BackendError> {
    if observed.cgroup_id != 0 {
        return Err(BackendError::Unknown(
            "UNKNOWN recorded BPF link remained attached after exact detach".to_owned(),
        ));
    }
    Ok(())
}

fn exact_detach_error(pin: &Path, error: &libbpf_rs::Error) -> BackendError {
    BackendError::Unknown(format!(
        "UNKNOWN exact detach failed for {}: {error:#}",
        pin.display()
    ))
}

fn validate_recorded_program(program: &ProgramManifest) -> Result<(), BackendError> {
    let Some((expected_type, manifest_type)) = expected_program_contract(&program.symbol) else {
        return Err(BackendError::Unknown(
            "UNKNOWN program name in the ownership manifest; no object was changed".to_owned(),
        ));
    };
    let handle = ProgramHandle::from_prog_id(program.id).map_err(|error| {
        BackendError::Unknown(format!(
            "UNKNOWN recorded program {} cannot be opened: {error:#}; no object was changed",
            program.id
        ))
    })?;
    let kernel_name = handle.name().to_str().unwrap_or("");
    if program.id == 0
        || handle.id() != program.id
        || program.kernel_name != program.symbol
        || kernel_name.is_empty()
        || !program.symbol.starts_with(kernel_name)
        || program.program_type != manifest_type
        || handle.prog_type() != expected_type
        || u64::from_be_bytes(handle.tag()) != program.tag
    {
        return Err(BackendError::Unknown(format!(
            "UNKNOWN program identity for {}; no object was changed",
            program.symbol
        )));
    }
    Ok(())
}

fn recorded_program_is_absent(program: &ProgramManifest) -> bool {
    matches!(
        ProgramHandle::from_prog_id(program.id),
        Err(error) if error.kind() == LibbpfErrorKind::NotFound
    )
}

fn intent_inventory_shape_valid(
    maps: &[MapManifest],
    programs: &[ProgramManifest],
    links: &[LinkManifest],
) -> bool {
    let map_ids = maps.iter().map(|map| map.id).collect::<BTreeSet<_>>();
    let maps_unpublished = maps.iter().all(|map| map.id == 0);
    let maps_published = map_ids.len() == MAPS.len() && !map_ids.contains(&0);
    let links_unpublished = links
        .iter()
        .all(|link| link.id == 0 && link.program_id == 0 && link.link_type.is_empty());
    let links_published = links
        .iter()
        .all(|link| link.id != 0 && link.program_id != 0 && link.link_type == "Cgroup");

    if programs.is_empty() {
        links_unpublished && (maps_unpublished || maps_published)
    } else {
        programs.len() == PROGRAMS.len() && maps_published && links_published
    }
}

fn validate_replacement_target(target: ReplacementTargetState) -> Result<(), BackendError> {
    if target.recorded_inode == 0
        || target.current_inode == target.recorded_inode
        || target.owner_uid != 0
        || target.owner_gid != 0
        || target.mode != 0o755
        || target.has_processes
        || target.has_children
        || !target.controllers_ready
        || !target.below_current_unit
        || target.old_inode_is_live
    {
        return Err(BackendError::Unknown(
            "UNKNOWN replacement attachment target failed the released-target contract; no object was changed"
                .to_owned(),
        ));
    }
    Ok(())
}

fn all_recorded_links_released(observations: &[RecordedLinkInfo], expected: usize) -> bool {
    observations.len() == expected && observations.iter().all(|link| link.cgroup_id == 0)
}

fn cgroup_id_is_live(root: &Path, id: u64) -> io::Result<bool> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() && metadata.ino() == id {
            return Ok(true);
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}

fn binding_mismatch(observed: BindingKey, expected: BindingKey) -> Option<ResolveMismatch> {
    if observed == expected {
        return None;
    }
    let differences = [
        (
            observed.cgroup_id != expected.cgroup_id,
            ResolveMismatch::CgroupId,
        ),
        (
            observed.execution_nonce != expected.execution_nonce,
            ResolveMismatch::ExecutionNonce,
        ),
        (
            observed.backend_generation != expected.backend_generation,
            ResolveMismatch::BackendGeneration,
        ),
    ];
    let mut mismatches = differences
        .into_iter()
        .filter_map(|(different, reason)| different.then_some(reason));
    let first = mismatches.next()?;
    if mismatches.next().is_some() {
        Some(ResolveMismatch::Multiple)
    } else {
        Some(first)
    }
}

fn classify_resolve_snapshot(
    binding: BindingKey,
    generation: u64,
    execution: Option<ExecutionState>,
    cookie_binding: Option<BindingKey>,
    policy: Option<(u32, BindingKey)>,
) -> ResolveResult {
    if binding.backend_generation != generation {
        return ResolveResult::IdentityMismatch {
            reason: ResolveMismatch::BackendGeneration,
        };
    }
    let Some(execution) = execution else {
        return ResolveResult::IdentityMismatch {
            reason: ResolveMismatch::OwnershipRecord,
        };
    };
    if let Some(reason) = binding_mismatch(binding, execution.binding) {
        return ResolveResult::IdentityMismatch { reason };
    }
    if execution.phase != ExecutionPhase::Active {
        return ResolveResult::Revoked { binding };
    }
    if cookie_binding != Some(binding) {
        return ResolveResult::IdentityMismatch {
            reason: ResolveMismatch::Cookie,
        };
    }
    match policy {
        Some((POLICY_ACTIVE, policy_binding)) if policy_binding == binding => {
            ResolveResult::Resolved { binding }
        }
        Some((POLICY_FROZEN, policy_binding)) if policy_binding == binding => {
            ResolveResult::Revoked { binding }
        }
        Some((POLICY_ACTIVE, _)) | Some((POLICY_FROZEN, _)) | None => {
            ResolveResult::IdentityMismatch {
                reason: ResolveMismatch::Policy,
            }
        }
        Some(_) => unreachable!("invalid policy state was rejected before classification"),
    }
}

fn encode_binding(binding: BindingKey) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[0..8].copy_from_slice(&binding.cgroup_id.to_ne_bytes());
    value[8..24].copy_from_slice(&binding.execution_nonce.bytes());
    value[24..32].copy_from_slice(&binding.backend_generation.to_ne_bytes());
    value
}

fn decode_binding(value: &[u8]) -> Option<BindingKey> {
    let cgroup_id = u64::from_ne_bytes(value.get(0..8)?.try_into().ok()?);
    let execution_nonce = ExecutionNonce::from_bytes(value.get(8..24)?.try_into().ok()?);
    let backend_generation = u64::from_ne_bytes(value.get(24..32)?.try_into().ok()?);
    Some(BindingKey {
        cgroup_id,
        execution_nonce,
        backend_generation,
    })
}

fn encode_policy(state: u32, binding: BindingKey) -> [u8; 40] {
    let mut value = [0_u8; 40];
    value[0..4].copy_from_slice(&state.to_ne_bytes());
    value[8..40].copy_from_slice(&encode_binding(binding));
    value
}

fn decode_policy(value: &[u8; 40]) -> Option<(u32, BindingKey)> {
    let state = u32::from_ne_bytes(value[0..4].try_into().ok()?);
    Some((state, decode_binding(&value[8..40])?))
}

fn encode_tuple(tuple: SocketTupleV4) -> [u8; 16] {
    let mut key = [0_u8; 16];
    key[0..4].copy_from_slice(&tuple.source_address);
    key[4..8].copy_from_slice(&tuple.destination_address);
    key[8..10].copy_from_slice(&tuple.source_port.to_ne_bytes());
    key[10..12].copy_from_slice(&tuple.destination_port.to_ne_bytes());
    key
}

fn initialize_metadata(
    bpf: &mut Ebpf,
    state_id: ExecutionNonce,
    generation: u64,
) -> Result<(), BackendError> {
    let value = metadata_value(state_id, generation)?;
    let map = bpf
        .map_mut("soglia_meta")
        .ok_or_else(|| BackendError::Failed("soglia_meta is absent".to_owned()))?;
    let mut meta = Array::<_, [u8; 40]>::try_from(map)
        .map_err(|error| BackendError::Failed(format!("open metadata map: {error:#}")))?;
    meta.set(0, value, 0)
        .map_err(|error| BackendError::Failed(format!("initialize metadata: {error:#}")))
}

fn metadata_value(state_id: ExecutionNonce, generation: u64) -> Result<[u8; 40], BackendError> {
    let bytes = state_id.bytes();
    let mut value = [0_u8; 40];
    value[0..8].copy_from_slice(&META_MAGIC.to_ne_bytes());
    value[8..12].copy_from_slice(&STATE_SCHEMA.to_ne_bytes());
    value[12..16].copy_from_slice(&BPF_ABI.to_ne_bytes());
    value[16..24].copy_from_slice(
        &u64::from_ne_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| BackendError::Failed("state id has the wrong width".to_owned()))?,
        )
        .to_ne_bytes(),
    );
    value[24..32].copy_from_slice(
        &u64::from_ne_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| BackendError::Failed("state id has the wrong width".to_owned()))?,
        )
        .to_ne_bytes(),
    );
    value[32..40].copy_from_slice(&generation.to_ne_bytes());
    Ok(value)
}

fn attach_all(bpf: &mut Ebpf, cgroup: &File) -> Result<Vec<FdLink>, BackendError> {
    let mut links = Vec::with_capacity(PROGRAMS.len());
    links.push(attach_cgroup_sock(bpf, cgroup, PROGRAMS[0])?);
    for program in &PROGRAMS[1..5] {
        links.push(attach_cgroup_sock_addr(bpf, cgroup, *program)?);
    }
    links.push(attach_sock_ops(bpf, cgroup, PROGRAMS[5])?);
    Ok(links)
}

fn attach_cgroup_sock(
    bpf: &mut Ebpf,
    cgroup: &File,
    spec: ProgramSpec,
) -> Result<FdLink, BackendError> {
    let name = spec.symbol;
    let program: &mut CgroupSock = bpf
        .program_mut(name)
        .ok_or_else(|| BackendError::Failed(format!("program {name} is absent")))?
        .try_into()
        .map_err(|error| BackendError::Failed(format!("convert {name}: {error:#}")))?;
    program
        .load()
        .map_err(|error| BackendError::Failed(format!("load {name}: {error:#}")))?;
    let id = program
        .attach(cgroup, spec.mode.aya())
        .map_err(|error| classify_attach_error(name, error))?;
    program
        .take_link(id)
        .map_err(|error| BackendError::Failed(format!("take {name}: {error:#}")))?
        .try_into()
        .map_err(|error| BackendError::Failed(format!("convert link {name}: {error:#}")))
}

fn attach_cgroup_sock_addr(
    bpf: &mut Ebpf,
    cgroup: &File,
    spec: ProgramSpec,
) -> Result<FdLink, BackendError> {
    let name = spec.symbol;
    let program: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .ok_or_else(|| BackendError::Failed(format!("program {name} is absent")))?
        .try_into()
        .map_err(|error| BackendError::Failed(format!("convert {name}: {error:#}")))?;
    program
        .load()
        .map_err(|error| BackendError::Failed(format!("load {name}: {error:#}")))?;
    let id = program
        .attach(cgroup, spec.mode.aya())
        .map_err(|error| classify_attach_error(name, error))?;
    program
        .take_link(id)
        .map_err(|error| BackendError::Failed(format!("take {name}: {error:#}")))?
        .try_into()
        .map_err(|error| BackendError::Failed(format!("convert link {name}: {error:#}")))
}

fn attach_sock_ops(
    bpf: &mut Ebpf,
    cgroup: &File,
    spec: ProgramSpec,
) -> Result<FdLink, BackendError> {
    let name = spec.symbol;
    let program: &mut SockOps = bpf
        .program_mut(name)
        .ok_or_else(|| BackendError::Failed(format!("program {name} is absent")))?
        .try_into()
        .map_err(|error| BackendError::Failed(format!("convert {name}: {error:#}")))?;
    program
        .load()
        .map_err(|error| BackendError::Failed(format!("load {name}: {error:#}")))?;
    let id = program
        .attach(cgroup, spec.mode.aya())
        .map_err(|error| classify_attach_error(name, error))?;
    program
        .take_link(id)
        .map_err(|error| BackendError::Failed(format!("take {name}: {error:#}")))?
        .try_into()
        .map_err(|error| BackendError::Failed(format!("convert link {name}: {error:#}")))
}

fn classify_attach_error(name: &str, error: ProgramError) -> BackendError {
    if let ProgramError::SyscallError(syscall) = &error
        && syscall.call == "bpf_link_create"
        && syscall.io_error.raw_os_error() == Some(1)
    {
        return BackendError::IncompatibleBpfTopology {
            hook: name.to_owned(),
            errno: syscall.io_error.raw_os_error(),
        };
    }
    BackendError::Failed(format!("attach {name}: {error:?}"))
}

fn collect_maps(bpf: &Ebpf, root: &Path) -> Result<Vec<MapManifest>, BackendError> {
    let mut maps = Vec::new();
    for name in MAPS {
        let _map = bpf
            .map(name)
            .ok_or_else(|| BackendError::Failed(format!("map {name} is absent")))?;
        let pin = root.join(name);
        let info = MapInfo::from_pin(&pin)
            .map_err(|error| BackendError::Failed(format!("map {name} info: {error:#}")))?;
        maps.push(MapManifest {
            name: name.to_owned(),
            id: info.id(),
            key_size: info.key_size(),
            value_size: info.value_size(),
            max_entries: info.max_entries(),
            pin,
        });
    }
    Ok(maps)
}

fn pin_maps(bpf: &Ebpf, root: &Path) -> Result<(), BackendError> {
    for name in MAPS {
        bpf.map(name)
            .ok_or_else(|| BackendError::Failed(format!("map {name} is absent")))?
            .pin(root.join(name))
            .map_err(|error| BackendError::Failed(format!("pin map {name}: {error:#}")))?;
    }
    Ok(())
}

fn pin_links(links: Vec<FdLink>, root: &Path) -> Result<Vec<PinnedLink>, BackendError> {
    links
        .into_iter()
        .zip(PROGRAMS)
        .map(|(link, program)| {
            link.pin(root.join(program.pin)).map_err(|error| {
                BackendError::Failed(format!("pin link {}: {error:#}", program.pin))
            })
        })
        .collect()
}

fn collect_programs(bpf: &Ebpf) -> Result<Vec<ProgramManifest>, BackendError> {
    PROGRAMS
        .iter()
        .map(|program| {
            let symbol = program.symbol;
            let info = bpf
                .program(symbol)
                .ok_or_else(|| BackendError::Failed(format!("program {symbol} is absent")))?
                .info()
                .map_err(|error| {
                    BackendError::Failed(format!("program {symbol} info: {error:#}"))
                })?;
            let reported_name = info.name_as_str().unwrap_or("");
            if reported_name.is_empty() || !symbol.starts_with(reported_name) {
                return Err(BackendError::Refused(format!(
                    "program {symbol} reported the incompatible kernel name {reported_name:?}"
                )));
            }
            Ok(ProgramManifest {
                symbol: symbol.to_owned(),
                id: info.id(),
                // `bpf_prog_info.name` is limited to BPF_OBJ_NAME_LEN, while bpftool can recover
                // the full ELF/BTF symbol. The full production symbol remains the canonical name;
                // the truncated kernel field was checked as its exact prefix above.
                kernel_name: symbol.to_owned(),
                program_type: format!("{:?}", info.program_type()),
                tag: info.tag(),
            })
        })
        .collect()
}

fn collect_links(
    links: &[FdLink],
    root: &Path,
    target_inode: u64,
) -> Result<Vec<LinkManifest>, BackendError> {
    links
        .iter()
        .zip(PROGRAMS)
        .map(|(link, program)| {
            let name = program.pin;
            let info = link
                .info()
                .map_err(|error| BackendError::Failed(format!("link {name} info: {error:#}")))?;
            Ok(LinkManifest {
                name: name.to_owned(),
                id: info.id(),
                program_id: info.program_id(),
                link_type: format!(
                    "{:?}",
                    info.link_type()
                        .map_err(|error| BackendError::Failed(format!("link type: {error:#}")))?
                ),
                target_inode,
                pin: root.join(name),
            })
        })
        .collect()
}

fn directory_entries(path: &Path) -> io::Result<Vec<PathBuf>> {
    match fs::read_dir(path) {
        Ok(entries) => entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn require_bpffs_mount() -> Result<(), BackendError> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    if mountinfo.lines().any(|line| {
        line.split(" - ")
            .nth(1)
            .is_some_and(|tail| tail.starts_with("bpf "))
    }) {
        Ok(())
    } else {
        Err(BackendError::Unsupported("bpffs is not mounted".to_owned()))
    }
}

fn validate_fresh_uninstall_state(
    generation: &GenerationClassification,
    sandbox_fresh: bool,
    network_fresh: bool,
) -> Result<(), BackendError> {
    if matches!(generation, GenerationClassification::Fresh { .. })
        && (!sandbox_fresh || !network_fresh)
    {
        return Err(BackendError::Unknown(
            "UNKNOWN Soglia resources exist without a complete cgroup-BPF ownership record"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_no_record_pin_state(path: &Path) -> Result<NoRecordPinRoot, BackendError> {
    let exists = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if exists {
        // Classification is also the source of truth for uninstall dry-run.  Validate trust here,
        // not only immediately before removal, so dry-run and execution cannot disagree about an
        // unrecorded empty root.
        validate_private_directory_if_present(path)?;
    }
    if !directory_entries(path)?.is_empty() {
        Err(BackendError::Unknown(format!(
            "UNKNOWN cgroup-BPF state: {} contains pins without a trusted record",
            path.display()
        )))
    } else if exists {
        Ok(NoRecordPinRoot::Empty)
    } else {
        Ok(NoRecordPinRoot::Absent)
    }
}

fn fresh_pin_root_operations(pin_root: NoRecordPinRoot) -> Vec<String> {
    match pin_root {
        NoRecordPinRoot::Absent => Vec::new(),
        NoRecordPinRoot::Empty => {
            vec!["remove empty cgroup-BPF pin root left by interrupted startup".to_owned()]
        }
    }
}

fn remove_prepared_empty_pin_root(
    path: &Path,
    prepared: NoRecordPinRoot,
) -> Result<(), BackendError> {
    match prepared {
        NoRecordPinRoot::Absent => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(BackendError::Unknown(format!(
                "UNKNOWN cgroup-BPF state: {} appeared after uninstall validation",
                path.display()
            ))),
            Err(error) => Err(BackendError::Unknown(format!(
                "UNKNOWN cgroup-BPF state: could not revalidate absent {}: {error}",
                path.display()
            ))),
        },
        NoRecordPinRoot::Empty => {
            validate_private_directory_if_present(path)?;
            remove_exact_empty_pin_root(path)
        }
    }
}

fn remove_exact_empty_pin_root(path: &Path) -> Result<(), BackendError> {
    fs::remove_dir(path).map_err(|error| {
        BackendError::Unknown(format!(
            "UNKNOWN cgroup-BPF state: exact removal of empty {} failed: {error}",
            path.display()
        ))
    })?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(BackendError::Unknown(format!(
            "UNKNOWN cgroup-BPF state: {} reappeared after exact removal",
            path.display()
        ))),
        Err(error) => Err(BackendError::Unknown(format!(
            "UNKNOWN cgroup-BPF state: could not verify absence of {}: {error}",
            path.display()
        ))),
    }
}

fn target_release_required(recorded_inode: u64, current_inode: Option<u64>) -> bool {
    current_inode != Some(recorded_inode)
}

fn same_recorded_generation(left: &HostState, right: &HostState) -> bool {
    left.schema == right.schema
        && left.abi == right.abi
        && left.state_id == right.state_id
        && left.generation == right.generation
        && left.object_sha256 == right.object_sha256
        && left.config_sha256 == right.config_sha256
        && left.attachment_target == right.attachment_target
        && left.attachment_inode == right.attachment_inode
        && left.pin_root == right.pin_root
}

fn select_recorded_state(
    recorded: Option<HostState>,
    intent: Option<UninstallIntent>,
    uninstall: bool,
) -> Result<Option<HostState>, BackendError> {
    let Some(intent) = intent else {
        return Ok(recorded);
    };
    if !uninstall {
        return Err(BackendError::Unknown(
            "an interrupted verified uninstall must be resumed with `soglia uninstall`".to_owned(),
        ));
    }
    if intent.schema != UNINSTALL_SCHEMA || intent.state.phase != ManifestPhase::Intent {
        return Err(BackendError::Incompatible(
            "INCOMPATIBLE cgroup-BPF uninstall record".to_owned(),
        ));
    }
    if let Some(current) = recorded
        && !same_recorded_generation(&current, &intent.state)
    {
        return Err(BackendError::Unknown(
            "UNKNOWN uninstall and ownership records identify different generations".to_owned(),
        ));
    }
    Ok(Some(intent.state))
}

fn resource_envelope(settings: &Settings) -> Result<ResourceEnvelope, BackendError> {
    let memlock = rustix::process::getrlimit(rustix::process::Resource::Memlock);
    let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    Ok(ResourceEnvelope {
        memlock_soft: memlock.current,
        memlock_hard: memlock.maximum,
        nofile_soft: nofile.current,
        nofile_hard: nofile.maximum,
        enforcer_fds_before_load: fs::read_dir("/proc/self/fd")?.count(),
        policy_capacity: settings.policy_capacity,
        tracked_socket_capacity: settings.socket_capacity,
        ring_buffer_bytes: settings.ring_bytes,
    })
}

fn ensure_private_directory(path: &Path) -> Result<(), BackendError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
        return Err(BackendError::Unknown(format!(
            "{} is not a root-owned real directory",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o777 != 0o700 {
        return Err(BackendError::Unknown(format!(
            "{} could not be restricted to mode 0700",
            path.display()
        )));
    }
    Ok(())
}

fn validate_private_directory_if_present(path: &Path) -> Result<(), BackendError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(BackendError::Unknown(format!(
            "{} is not a root-owned real mode-0700 directory",
            path.display()
        )));
    }
    Ok(())
}

fn validate_state_file(path: &Path) -> Result<(), BackendError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(BackendError::Unknown(format!(
            "{} is not a singly-linked root-owned mode-0600 regular file",
            path.display()
        )));
    }
    Ok(())
}

fn expected_map_shape(name: &str, settings: &Settings) -> Option<(u32, u32, u32)> {
    match name {
        "soglia_meta" => Some((4, 40, 1)),
        "soglia_policy" => Some((8, 40, settings.policy_capacity)),
        "soglia_cookie_a" => Some((8, 32, settings.socket_capacity)),
        "soglia_tuples" => Some((16, 48, settings.socket_capacity)),
        "soglia_counters" => Some((4, 8, COUNTER_COUNT as u32)),
        "soglia_denies" => Some((32, 8, settings.policy_capacity)),
        "soglia_events" => Some((0, 0, settings.ring_bytes)),
        _ => None,
    }
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn has_child_cgroup(executions: &Path) -> Result<bool, BackendError> {
    for entry in fs::read_dir(executions)? {
        if entry?.file_type()?.is_dir() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_owned_uninstall_children(
    executions: &Path,
    sandbox_tags: &BTreeSet<String>,
) -> Result<(), BackendError> {
    for entry in fs::read_dir(executions)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !sandbox_tags.contains(&name) {
            return Err(BackendError::Unknown(format!(
                "UNKNOWN Execution cgroup {} has no matching Sandbox record",
                entry.path().display()
            )));
        }
        if !fs::read_to_string(entry.path().join("cgroup.procs"))?
            .trim()
            .is_empty()
        {
            return Err(BackendError::Failed(format!(
                "Execution cgroup {} is not stopped",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn recursive_files(root: &Path, allow_partial: bool) -> Result<BTreeSet<PathBuf>, BackendError> {
    let mut files = BTreeSet::new();
    for directory in [root.join("maps"), root.join("links")] {
        for path in directory_entries(&directory)? {
            if path.is_dir() {
                return Err(BackendError::Unknown(format!(
                    "unexpected directory below {}",
                    directory.display()
                )));
            }
            files.insert(path);
        }
    }
    let allowed = BTreeSet::from([root.join("maps"), root.join("links")]);
    let actual: BTreeSet<PathBuf> = directory_entries(root)?.into_iter().collect();
    if (!allow_partial && actual != allowed) || (allow_partial && !actual.is_subset(&allowed)) {
        return Err(BackendError::Unknown(format!(
            "unexpected entry below {}",
            root.display()
        )));
    }
    Ok(files)
}

fn remove_empty_tree(root: &Path) -> Result<(), BackendError> {
    for directory in [root.join("links"), root.join("maps"), root.to_path_buf()] {
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if root.exists() {
        return Err(BackendError::Failed(format!(
            "{} remained after owned pin cleanup",
            root.display()
        )));
    }
    Ok(())
}

fn expected_attach_type(symbol: &str) -> Option<&'static str> {
    match symbol {
        "soglia_sock_create" => Some("cgroup_inet_sock_create"),
        "soglia_connect4" => Some("cgroup_inet4_connect"),
        "soglia_connect6" => Some("cgroup_inet6_connect"),
        "soglia_sendmsg4" => Some("cgroup_udp4_sendmsg"),
        "soglia_sendmsg6" => Some("cgroup_udp6_sendmsg"),
        "soglia_sockops" => Some("cgroup_sock_ops"),
        _ => None,
    }
}

fn require_same_external_inventory(
    before: &[AttachmentFingerprint],
    after: &[AttachmentFingerprint],
    stage: &str,
) -> Result<(), BackendError> {
    if before == after {
        return Ok(());
    }
    if systemd_external_churn(before, after) {
        eprintln!(
            "event.name=cgroup_bpf.external_churn owner=systemd classification=EXTERNAL_CHURN stage={stage:?}"
        );
        return Ok(());
    }
    Err(BackendError::Unknown(format!(
        "non-owned effective BPF inventory changed {stage}"
    )))
}

fn systemd_external_churn(
    before: &[AttachmentFingerprint],
    after: &[AttachmentFingerprint],
) -> bool {
    type StableIdentity = (String, String, String, String);
    fn grouped(entries: &[AttachmentFingerprint]) -> BTreeMap<StableIdentity, Vec<u32>> {
        let mut groups: BTreeMap<StableIdentity, Vec<u32>> = BTreeMap::new();
        for entry in entries {
            groups
                .entry((
                    entry.name.clone(),
                    entry.program_type.clone(),
                    entry.tag.clone(),
                    entry.attach_type.clone(),
                ))
                .or_default()
                .push(entry.program_id);
        }
        for ids in groups.values_mut() {
            ids.sort_unstable();
        }
        groups
    }

    let before = grouped(before);
    let after = grouped(after);
    if before.keys().collect::<Vec<_>>() != after.keys().collect::<Vec<_>>() {
        return false;
    }
    let mut changed = false;
    for (identity, before_ids) in &before {
        let Some(after_ids) = after.get(identity) else {
            return false;
        };
        if before_ids != after_ids {
            if !identity.0.starts_with("sd_") {
                return false;
            }
            changed = true;
        }
    }
    changed
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use soglia_core::helper::{HelperFailure, RefusalClass};

    fn test_binding(cgroup_id: u64, nonce_byte: u8, backend_generation: u64) -> BindingKey {
        BindingKey {
            cgroup_id,
            execution_nonce: ExecutionNonce::from_bytes([nonce_byte; 16]),
            backend_generation,
        }
    }

    fn test_execution(binding: BindingKey) -> ExecutionState {
        test_execution_in_phase(binding, ExecutionPhase::Active)
    }

    fn test_execution_in_phase(binding: BindingKey, phase: ExecutionPhase) -> ExecutionState {
        let id = ExecutionId::generate().unwrap();
        ExecutionState {
            id,
            tag: id.tag(),
            slot: 0,
            cgroup_inode: binding.cgroup_id,
            binding,
            phase,
        }
    }

    fn assert_unknown_execution_record(result: Result<(), BackendError>) {
        assert!(matches!(
            result,
            Err(BackendError::Unknown(reason))
                if reason == "UNKNOWN per-Execution ownership record; no kernel object was changed"
        ));
    }

    fn released_target() -> ReplacementTargetState {
        ReplacementTargetState {
            recorded_inode: 41,
            current_inode: 42,
            owner_uid: 0,
            owner_gid: 0,
            mode: 0o755,
            has_processes: false,
            has_children: false,
            controllers_ready: true,
            below_current_unit: true,
            old_inode_is_live: false,
        }
    }

    fn recorded_attachment_handle() -> AttachmentHandle {
        AttachmentHandle {
            handle_type: 254,
            handle: vec![1, 2, 3, 4, 5, 6, 7, 8],
            mount_id_unique: 19,
        }
    }

    fn serializable_host_state() -> HostState {
        HostState {
            schema: STATE_SCHEMA,
            abi: BPF_ABI,
            phase: ManifestPhase::Ready,
            state_id: ExecutionNonce::from_bytes([7; 16]),
            generation: 1,
            object_sha256: "object".to_owned(),
            config_sha256: "config".to_owned(),
            attachment_target: PathBuf::from("/sys/fs/cgroup/test/executions"),
            attachment_inode: 41,
            attachment_handle: recorded_attachment_handle(),
            pin_root: PathBuf::from("/sys/fs/bpf/soglia/test"),
            maps: Vec::new(),
            programs: Vec::new(),
            links: Vec::new(),
            ancestor_bpf: Vec::new(),
            resource_envelope: ResourceEnvelope {
                memlock_soft: None,
                memlock_hard: None,
                nofile_soft: None,
                nofile_hard: None,
                enforcer_fds_before_load: 0,
                policy_capacity: 1,
                tracked_socket_capacity: 1,
                ring_buffer_bytes: 4096,
            },
            executions: BTreeMap::new(),
        }
    }

    fn recorded_connect4_link() -> LinkManifest {
        LinkManifest {
            name: "connect4".to_owned(),
            id: 11,
            program_id: 21,
            link_type: "Cgroup".to_owned(),
            target_inode: 41,
            pin: PathBuf::from("/sys/fs/bpf/soglia/test/links/connect4"),
        }
    }

    fn released_connect4_info() -> RecordedLinkInfo {
        RecordedLinkInfo {
            link_id: 11,
            program_id: 21,
            attach_type: ProgramAttachType::CgroupInet4Connect as u32,
            cgroup_id: 0,
        }
    }

    fn intent_maps(published: bool) -> Vec<MapManifest> {
        MAPS.iter()
            .enumerate()
            .map(|(index, name)| MapManifest {
                name: (*name).to_owned(),
                id: if published { 100 + index as u32 } else { 0 },
                key_size: 0,
                value_size: 0,
                max_entries: 0,
                pin: PathBuf::from(format!("/sys/fs/bpf/soglia/test/maps/{name}")),
            })
            .collect()
    }

    fn intent_programs() -> Vec<ProgramManifest> {
        PROGRAMS
            .iter()
            .enumerate()
            .map(|(index, program)| ProgramManifest {
                symbol: program.symbol.to_owned(),
                id: 200 + index as u32,
                kernel_name: program.symbol.to_owned(),
                program_type: "test".to_owned(),
                tag: 300 + index as u64,
            })
            .collect()
    }

    fn intent_links(published: bool) -> Vec<LinkManifest> {
        PROGRAMS
            .iter()
            .enumerate()
            .map(|(index, program)| LinkManifest {
                name: program.pin.to_owned(),
                id: if published { 400 + index as u32 } else { 0 },
                program_id: if published { 200 + index as u32 } else { 0 },
                link_type: if published { "Cgroup" } else { "" }.to_owned(),
                target_inode: 41,
                pin: PathBuf::from(format!("/sys/fs/bpf/soglia/test/links/{}", program.pin)),
            })
            .collect()
    }

    #[test]
    fn target_released_accepts_only_phase_valid_intent_inventory_shapes() {
        let unpublished_maps = intent_maps(false);
        let published_maps = intent_maps(true);
        let unpublished_links = intent_links(false);
        let published_links = intent_links(true);
        let programs = intent_programs();

        assert!(intent_inventory_shape_valid(
            &unpublished_maps,
            &[],
            &unpublished_links
        ));
        assert!(intent_inventory_shape_valid(
            &published_maps,
            &[],
            &unpublished_links
        ));
        assert!(intent_inventory_shape_valid(
            &published_maps,
            &programs,
            &published_links
        ));

        let mut partial_maps = published_maps.clone();
        partial_maps[0].id = 0;
        assert!(!intent_inventory_shape_valid(
            &partial_maps,
            &[],
            &unpublished_links
        ));

        let mut partial_links = published_links.clone();
        partial_links[0].id = 0;
        partial_links[0].program_id = 0;
        partial_links[0].link_type.clear();
        assert!(!intent_inventory_shape_valid(
            &published_maps,
            &programs,
            &partial_links
        ));
        assert!(!intent_inventory_shape_valid(
            &published_maps,
            &programs[..PROGRAMS.len() - 1],
            &published_links
        ));
        assert!(!intent_inventory_shape_valid(
            &published_maps,
            &[],
            &published_links
        ));
    }

    #[test]
    fn target_released_requires_every_replacement_target_predicate() {
        assert!(validate_replacement_target(released_target()).is_ok());

        for invalid in [
            ReplacementTargetState {
                recorded_inode: 0,
                ..released_target()
            },
            ReplacementTargetState {
                current_inode: 41,
                ..released_target()
            },
            ReplacementTargetState {
                owner_uid: 1000,
                ..released_target()
            },
            ReplacementTargetState {
                owner_gid: 1000,
                ..released_target()
            },
            ReplacementTargetState {
                mode: 0o775,
                ..released_target()
            },
            ReplacementTargetState {
                has_processes: true,
                ..released_target()
            },
            ReplacementTargetState {
                has_children: true,
                ..released_target()
            },
            ReplacementTargetState {
                controllers_ready: false,
                ..released_target()
            },
            ReplacementTargetState {
                below_current_unit: false,
                ..released_target()
            },
            ReplacementTargetState {
                old_inode_is_live: true,
                ..released_target()
            },
        ] {
            assert!(matches!(
                validate_replacement_target(invalid),
                Err(BackendError::Unknown(_))
            ));
        }
    }

    #[test]
    fn target_released_accepts_old_or_detached_links_for_crash_resume() {
        assert_eq!(TARGET_RELEASED_DETACH_TIMEOUT, Duration::from_secs(5));
        assert_eq!(TARGET_RELEASED_POLL_INTERVAL, Duration::from_millis(10));
        let released = released_connect4_info();
        let mut attached = released;
        attached.cgroup_id = 41;
        let mut retargeted = released;
        retargeted.cgroup_id = 42;
        assert!(!all_recorded_links_released(&[attached], 1));
        assert!(!all_recorded_links_released(&[released, attached], 2));
        assert!(all_recorded_links_released(&[released, released], 2));
        assert!(!all_recorded_links_released(&[released], 2));
        assert!(validate_released_link_target(attached, 41).is_ok());
        assert!(validate_released_link_target(released, 41).is_ok());
        assert!(matches!(
            validate_released_link_target(retargeted, 41),
            Err(BackendError::Unknown(_))
        ));
        for observed in [attached, released] {
            assert!(validate_released_link_target(observed, 41).is_ok());
        }
    }

    #[test]
    fn target_released_requires_a_well_formed_durable_handle() {
        assert_eq!(STATE_SCHEMA, 3);
        assert!(validate_attachment_handle_structure(&recorded_attachment_handle()).is_ok());
        for invalid in [
            AttachmentHandle {
                handle_type: 0,
                ..recorded_attachment_handle()
            },
            AttachmentHandle {
                handle: Vec::new(),
                ..recorded_attachment_handle()
            },
            AttachmentHandle {
                handle: vec![0; 129],
                ..recorded_attachment_handle()
            },
            AttachmentHandle {
                mount_id_unique: 0,
                ..recorded_attachment_handle()
            },
        ] {
            assert!(matches!(
                validate_attachment_handle_structure(&invalid),
                Err(BackendError::Unknown(_))
            ));
        }
    }

    #[test]
    fn schema_two_state_is_not_implicitly_migrated() {
        let mut previous = serde_json::to_value(serializable_host_state()).unwrap();
        previous["schema"] = serde_json::json!(2);
        previous
            .as_object_mut()
            .unwrap()
            .remove("attachment_handle");
        assert!(serde_json::from_value::<HostState>(previous).is_err());
    }

    #[test]
    fn uninstall_intent_is_the_only_authority_for_an_interrupted_resume() {
        let ready = serializable_host_state();
        let mut interrupted = ready.clone();
        interrupted.phase = ManifestPhase::Intent;
        let intent = UninstallIntent {
            schema: UNINSTALL_SCHEMA,
            state: interrupted.clone(),
        };
        let resumed = select_recorded_state(Some(ready.clone()), Some(intent.clone()), true)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.phase, ManifestPhase::Intent);
        assert!(matches!(
            select_recorded_state(Some(ready.clone()), Some(intent.clone()), false),
            Err(BackendError::Unknown(_))
        ));

        let mut wrong_generation = intent.clone();
        wrong_generation.state.generation += 1;
        assert!(matches!(
            select_recorded_state(Some(ready), Some(wrong_generation), true),
            Err(BackendError::Unknown(_))
        ));
        let mut wrong_schema = intent;
        wrong_schema.schema += 1;
        assert!(matches!(
            select_recorded_state(None, Some(wrong_schema), true),
            Err(BackendError::Incompatible(_))
        ));
    }

    #[test]
    fn uninstall_fresh_requires_every_owned_subsystem_to_be_absent() {
        let fresh = GenerationClassification::Fresh {
            pin_root: NoRecordPinRoot::Absent,
        };
        assert!(validate_fresh_uninstall_state(&fresh, true, true).is_ok());
        assert!(matches!(
            validate_fresh_uninstall_state(&fresh, false, true),
            Err(BackendError::Unknown(_))
        ));
        assert!(matches!(
            validate_fresh_uninstall_state(&fresh, true, false),
            Err(BackendError::Unknown(_))
        ));
    }

    #[test]
    fn startup_and_uninstall_share_the_empty_unrecorded_pin_root_rule() {
        let root = std::env::temp_dir().join(format!(
            "soglia-uninstall-unrecorded-pins-{}",
            ExecutionId::generate().unwrap()
        ));
        assert_eq!(
            validate_no_record_pin_state(&root).unwrap(),
            NoRecordPinRoot::Absent
        );
        fs::create_dir(&root).unwrap();
        assert_eq!(
            validate_no_record_pin_state(&root).unwrap(),
            NoRecordPinRoot::Empty
        );
        fs::write(root.join("unexpected-pin"), "pin").unwrap();
        assert!(matches!(
            validate_no_record_pin_state(&root),
            Err(BackendError::Unknown(_))
        ));
        fs::remove_file(root.join("unexpected-pin")).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn an_untrusted_empty_pin_root_is_unknown_during_classification() {
        let root = std::env::temp_dir().join(format!(
            "soglia-uninstall-untrusted-empty-pins-{}",
            ExecutionId::generate().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            validate_no_record_pin_state(&root),
            Err(BackendError::Unknown(_))
        ));
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn uninstall_removes_only_the_prevalidated_empty_pin_root() {
        let root = std::env::temp_dir().join(format!(
            "soglia-uninstall-unrecorded-pins-{}",
            ExecutionId::generate().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        remove_exact_empty_pin_root(&root).unwrap();
        assert!(!root.exists());

        fs::create_dir(&root).unwrap();
        fs::write(root.join("racing-pin"), "pin").unwrap();
        assert!(matches!(
            remove_exact_empty_pin_root(&root),
            Err(BackendError::Unknown(_))
        ));
        assert!(root.join("racing-pin").is_file());
        fs::remove_file(root.join("racing-pin")).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn uninstall_rejects_a_pin_root_that_appears_after_absent_validation() {
        let root = std::env::temp_dir().join(format!(
            "soglia-uninstall-unrecorded-pins-{}",
            ExecutionId::generate().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        assert!(matches!(
            remove_prepared_empty_pin_root(&root, NoRecordPinRoot::Absent),
            Err(BackendError::Unknown(_))
        ));
        assert!(root.is_dir());
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn uninstall_routes_a_missing_or_replaced_target_to_target_released() {
        assert!(target_release_required(41, None));
        assert!(target_release_required(41, Some(42)));
        assert!(!target_release_required(41, Some(41)));
    }

    #[test]
    fn uninstall_queries_effective_inventory_only_on_a_live_target() {
        assert!(verify_external_inventory_on_target(false, true).unwrap());
        assert!(verify_external_inventory_on_target(true, true).unwrap());
        assert!(!verify_external_inventory_on_target(true, false).unwrap());
        assert!(matches!(
            verify_external_inventory_on_target(false, false),
            Err(BackendError::Failed(_))
        ));
    }

    #[test]
    fn uninstall_accepts_only_empty_children_named_by_sandbox_records() {
        let root = std::env::temp_dir().join(format!(
            "soglia-uninstall-children-{}",
            ExecutionId::generate().unwrap()
        ));
        let child = root.join("0123456789");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("cgroup.procs"), "").unwrap();
        let owned = BTreeSet::from(["0123456789".to_owned()]);
        assert!(validate_owned_uninstall_children(&root, &owned).is_ok());
        assert!(matches!(
            validate_owned_uninstall_children(&root, &BTreeSet::new()),
            Err(BackendError::Unknown(_))
        ));
        fs::write(child.join("cgroup.procs"), "123\n").unwrap();
        assert!(matches!(
            validate_owned_uninstall_children(&root, &owned),
            Err(BackendError::Failed(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn observability_counter_layout_is_a_versioned_bpf_abi() {
        let settings = Settings {
            state_dir: PathBuf::from("/run/soglia-test"),
            configured_pin_root: PathBuf::from("/sys/fs/bpf/soglia-test"),
            executions: PathBuf::from("/sys/fs/cgroup/soglia-test/executions"),
            bpftool: PathBuf::from("/usr/sbin/bpftool"),
            proxy_ip: "10.200.255.1".parse().unwrap(),
            proxy_port: 15_001,
            policy_capacity: 4,
            socket_capacity: 64,
            ring_bytes: 4096,
            required_controllers: vec!["memory", "pids"],
        };
        assert_eq!(BPF_ABI, 2);
        assert_eq!(COUNTER_COUNT, 26);
        assert_eq!(
            expected_map_shape("soglia_counters", &settings),
            Some((4, 8, 26))
        );
    }

    #[test]
    fn ring_events_accept_only_the_fixed_non_secret_reason_abi() {
        for reason in 1..=DENY_REASON_COUNT {
            let mut event = [0_u8; RING_EVENT_WIDTH];
            event[0..4].copy_from_slice(&reason.to_ne_bytes());
            assert_eq!(validate_ring_event(&event).unwrap(), reason);
        }
        assert!(validate_ring_event(&[0; RING_EVENT_WIDTH - 1]).is_err());
        for reason in [0, DENY_REASON_COUNT + 1] {
            let mut event = [0_u8; RING_EVENT_WIDTH];
            event[0..4].copy_from_slice(&reason.to_ne_bytes());
            assert!(validate_ring_event(&event).is_err());
        }
    }

    #[test]
    fn ring_drain_is_bounded_by_the_configured_ring_capacity() {
        assert_eq!(ring_drain_limit(4096), 4096 / RING_EVENT_WIDTH);
        assert_eq!(ring_drain_limit(RING_EVENT_WIDTH as u32), 1);
        assert_eq!(ring_drain_limit(0), 1);
    }

    #[test]
    fn target_released_requires_exactly_estale_from_the_old_handle() {
        assert!(validate_offline_handle_observation(OfflineHandleObservation::Stale).is_ok());
        for observation in [
            OfflineHandleObservation::Openable,
            OfflineHandleObservation::Error(Some(2)),
            OfflineHandleObservation::Error(None),
        ] {
            assert!(matches!(
                validate_offline_handle_observation(observation),
                Err(BackendError::Unknown(_))
            ));
        }
    }

    #[test]
    fn target_released_requires_zero_after_exact_detach() {
        assert!(validate_post_detach_link(released_connect4_info()).is_ok());
        let mut attached = released_connect4_info();
        attached.cgroup_id = 41;
        assert!(matches!(
            validate_post_detach_link(attached),
            Err(BackendError::Unknown(_))
        ));
        let error = libbpf_rs::Error::from_raw_os_error(1);
        assert!(matches!(
            exact_detach_error(Path::new("/sys/fs/bpf/soglia/test"), &error),
            BackendError::Unknown(_)
        ));
    }

    #[test]
    fn target_released_rejects_every_recorded_link_identity_mismatch() {
        let manifest = recorded_connect4_link();
        assert!(validate_recorded_link_identity(&manifest, released_connect4_info()).is_ok());

        let mut mismatches = Vec::new();
        let mut wrong_link = released_connect4_info();
        wrong_link.link_id += 1;
        mismatches.push(wrong_link);
        let mut wrong_program = released_connect4_info();
        wrong_program.program_id += 1;
        mismatches.push(wrong_program);
        let mut wrong_attach = released_connect4_info();
        wrong_attach.attach_type = ProgramAttachType::CgroupInet6Connect as u32;
        mismatches.push(wrong_attach);
        for mismatch in mismatches {
            assert!(matches!(
                validate_recorded_link_identity(&manifest, mismatch),
                Err(BackendError::Unknown(_))
            ));
        }
    }

    #[test]
    fn real_recovery_refusals_keep_their_class_across_the_helper_boundary() {
        let unknown = unknown_execution_record()
            .into_helper_failure("the cgroup-bpf backend could not start");
        assert!(matches!(
            unknown,
            HelperFailure::Refused {
                class: RefusalClass::Unknown,
                ..
            }
        ));

        let incompatible = BackendError::Incompatible(
            "INCOMPATIBLE cgroup-BPF ownership state; kernel objects were left untouched".into(),
        )
        .into_helper_failure("the cgroup-bpf backend could not start");
        assert!(matches!(
            incompatible,
            HelperFailure::Refused {
                class: RefusalClass::Incompatible,
                ..
            }
        ));
    }

    #[test]
    fn recovery_accepts_exact_active_and_frozen_policy_bindings() {
        let active = test_binding(41, 1, 7);
        let frozen = test_binding(42, 2, 7);
        let executions = [test_execution(active), test_execution(frozen)];
        let policies =
            BTreeMap::from([(41, (POLICY_ACTIVE, active)), (42, (POLICY_FROZEN, frozen))]);

        assert!(
            validate_recovery_policy_snapshot(
                ManifestPhase::Ready,
                executions.iter(),
                Some(&policies),
            )
            .is_ok()
        );
    }

    #[test]
    fn recovery_rejects_a_durable_nonce_that_disagrees_with_policy() {
        let policy_binding = test_binding(41, 1, 7);
        let execution = test_execution(test_binding(41, 2, 7));
        let policies = BTreeMap::from([(41, (POLICY_ACTIVE, policy_binding))]);

        assert_unknown_execution_record(validate_recovery_policy_snapshot(
            ManifestPhase::Ready,
            std::iter::once(&execution),
            Some(&policies),
        ));
    }

    #[test]
    fn recovery_rejects_a_durable_cgroup_that_disagrees_with_policy() {
        let policy_binding = test_binding(41, 1, 7);
        let execution = test_execution(test_binding(42, 1, 7));
        let policies = BTreeMap::from([(41, (POLICY_ACTIVE, policy_binding))]);

        assert_unknown_execution_record(validate_recovery_policy_snapshot(
            ManifestPhase::Ready,
            std::iter::once(&execution),
            Some(&policies),
        ));
    }

    #[test]
    fn recovery_rejects_a_durable_generation_that_disagrees_with_policy() {
        let policy_binding = test_binding(41, 1, 7);
        let execution = test_execution(test_binding(41, 1, 8));
        let policies = BTreeMap::from([(41, (POLICY_FROZEN, policy_binding))]);

        assert_unknown_execution_record(validate_recovery_policy_snapshot(
            ManifestPhase::Ready,
            std::iter::once(&execution),
            Some(&policies),
        ));
    }

    #[test]
    fn recovery_accepts_a_prepare_crash_after_the_record_and_before_policy() {
        let execution = test_execution_in_phase(
            test_binding(41, 1, 7),
            ExecutionPhase::NetworkPreparedFrozen,
        );
        let policies = BTreeMap::new();

        assert!(
            validate_recovery_policy_snapshot(
                ManifestPhase::Ready,
                std::iter::once(&execution),
                Some(&policies),
            )
            .is_ok()
        );
    }

    #[test]
    fn recovery_accepts_a_destroy_crash_after_policy_and_before_record_removal() {
        let execution = test_execution_in_phase(test_binding(41, 1, 7), ExecutionPhase::Frozen);
        let policies = BTreeMap::new();

        assert!(
            validate_recovery_policy_snapshot(
                ManifestPhase::Ready,
                std::iter::once(&execution),
                Some(&policies),
            )
            .is_ok()
        );
    }

    #[test]
    fn recovery_rejects_an_active_record_without_policy() {
        let execution = test_execution(test_binding(41, 1, 7));
        let policies = BTreeMap::new();

        assert_unknown_execution_record(validate_recovery_policy_snapshot(
            ManifestPhase::Ready,
            std::iter::once(&execution),
            Some(&policies),
        ));
    }

    #[test]
    fn recovery_rejects_an_orphan_policy_entry() {
        let binding = test_binding(41, 1, 7);
        let execution = test_execution(binding);
        let policies = BTreeMap::from([
            (41, (POLICY_ACTIVE, binding)),
            (42, (POLICY_FROZEN, test_binding(42, 2, 7))),
        ]);

        assert_unknown_execution_record(validate_recovery_policy_snapshot(
            ManifestPhase::Ready,
            std::iter::once(&execution),
            Some(&policies),
        ));
    }

    #[test]
    fn recovery_allows_intent_after_the_policy_map_was_removed() {
        let execution = test_execution(test_binding(41, 1, 7));

        assert!(
            validate_recovery_policy_snapshot(
                ManifestPhase::Intent,
                std::iter::once(&execution),
                None,
            )
            .is_ok()
        );
        assert_unknown_execution_record(validate_recovery_policy_snapshot(
            ManifestPhase::Ready,
            std::iter::once(&execution),
            None,
        ));
    }

    #[test]
    fn recovery_rejects_an_invalid_policy_state() {
        let binding = test_binding(41, 1, 7);
        let execution = test_execution(binding);
        let policies = BTreeMap::from([(41, (u32::MAX, binding))]);

        assert_unknown_execution_record(validate_recovery_policy_snapshot(
            ManifestPhase::Ready,
            std::iter::once(&execution),
            Some(&policies),
        ));
    }

    fn syscall_error(call: &'static str, errno: rustix::io::Errno) -> aya::sys::SyscallError {
        aya::sys::SyscallError {
            call,
            io_error: io::Error::from_raw_os_error(errno.raw_os_error()),
        }
    }

    fn map_syscall_error(call: &'static str, errno: rustix::io::Errno) -> MapError {
        MapError::SyscallError(syscall_error(call, errno))
    }

    #[test]
    fn cleanup_delete_accepts_only_delete_enoent() {
        let absent = map_syscall_error("bpf_map_delete_elem", rustix::io::Errno::NOENT);
        assert!(map_delete_was_already_absent(&absent));
        assert!(cleanup_map_delete(Err(absent), "test map").is_ok());

        let denied = map_syscall_error("bpf_map_delete_elem", rustix::io::Errno::PERM);
        assert!(!map_delete_was_already_absent(&denied));
        assert!(matches!(
            cleanup_map_delete(Err(denied), "test map"),
            Err(BackendError::Failed(reason)) if reason.contains("bpf_map_delete_elem")
        ));

        let wrong_call = map_syscall_error("bpf_map_lookup_elem", rustix::io::Errno::NOENT);
        assert!(!map_delete_was_already_absent(&wrong_call));
        assert!(!map_delete_was_already_absent(&MapError::KeyNotFound));
    }

    #[test]
    fn recovery_inventory_accepts_only_get_fd_by_id_enoent() {
        assert!(program_disappeared_during_inventory(
            &ProgramError::SyscallError(syscall_error(
                "bpf_prog_get_fd_by_id",
                rustix::io::Errno::NOENT,
            )),
        ));
        assert!(map_disappeared_during_inventory(&MapError::SyscallError(
            syscall_error("bpf_map_get_fd_by_id", rustix::io::Errno::NOENT,)
        ),));
        assert!(link_disappeared_during_inventory(&LinkError::SyscallError(
            syscall_error("bpf_link_get_fd_by_id", rustix::io::Errno::NOENT,)
        ),));

        assert!(!link_disappeared_during_inventory(
            &LinkError::SyscallError(syscall_error(
                "bpf_link_get_fd_by_id",
                rustix::io::Errno::PERM,
            )),
        ));
        assert!(!link_disappeared_during_inventory(
            &LinkError::SyscallError(syscall_error(
                "bpf_obj_get_info_by_fd",
                rustix::io::Errno::NOENT,
            )),
        ));
        assert!(!link_disappeared_during_inventory(&LinkError::InvalidLink,));
    }

    #[test]
    fn mismatch_diagnostics_follow_only_a_failed_whole_binding_comparison() {
        let expected = BindingKey {
            cgroup_id: 41,
            execution_nonce: ExecutionNonce::generate().unwrap(),
            backend_generation: 7,
        };
        assert_eq!(binding_mismatch(expected, expected), None);

        let different_nonce = BindingKey {
            execution_nonce: ExecutionNonce::generate().unwrap(),
            ..expected
        };
        assert_eq!(
            binding_mismatch(different_nonce, expected),
            Some(ResolveMismatch::ExecutionNonce)
        );
        assert_eq!(
            binding_mismatch(
                BindingKey {
                    backend_generation: 8,
                    ..expected
                },
                expected
            ),
            Some(ResolveMismatch::BackendGeneration)
        );
        assert_eq!(
            binding_mismatch(
                BindingKey {
                    cgroup_id: 42,
                    execution_nonce: different_nonce.execution_nonce,
                    ..expected
                },
                expected
            ),
            Some(ResolveMismatch::Multiple)
        );
    }

    #[test]
    fn a_stale_tuple_cannot_resolve_after_the_same_four_tuple_is_reused() {
        let stale = BindingKey {
            cgroup_id: 41,
            execution_nonce: ExecutionNonce::generate().unwrap(),
            backend_generation: 7,
        };
        let current = BindingKey {
            execution_nonce: ExecutionNonce::generate().unwrap(),
            ..stale
        };
        let id = ExecutionId::generate().unwrap();
        let current_execution = ExecutionState {
            id,
            tag: id.tag(),
            slot: 0,
            cgroup_inode: current.cgroup_id,
            binding: current,
            phase: ExecutionPhase::Active,
        };
        let result = classify_resolve_snapshot(
            stale,
            current.backend_generation,
            Some(current_execution),
            Some(stale),
            Some((POLICY_ACTIVE, current)),
        );
        assert_eq!(
            result,
            ResolveResult::IdentityMismatch {
                reason: ResolveMismatch::ExecutionNonce
            }
        );
    }

    #[test]
    fn production_attach_plan_is_exactly_six_single_links() {
        assert_eq!(PROGRAMS.len(), 6);
        assert!(
            PROGRAMS
                .iter()
                .all(|program| program.mode == ProductionAttachMode::Single)
        );
        assert_eq!(
            PROGRAMS.map(|program| program.symbol),
            [
                "soglia_sock_create",
                "soglia_connect4",
                "soglia_connect6",
                "soglia_sendmsg4",
                "soglia_sendmsg6",
                "soglia_sockops",
            ]
        );
    }

    #[test]
    fn exclusive_ancestor_eperm_is_a_typed_topology_refusal() {
        let error = ProgramError::SyscallError(aya::sys::SyscallError {
            call: "bpf_link_create",
            io_error: io::Error::from_raw_os_error(1),
        });
        assert!(matches!(
            classify_attach_error("soglia_connect4", error),
            BackendError::IncompatibleBpfTopology {
                hook,
                errno: Some(1)
            } if hook == "soglia_connect4"
        ));
    }

    #[test]
    fn non_topology_attach_errors_are_not_reclassified() {
        let error = ProgramError::SyscallError(aya::sys::SyscallError {
            call: "bpf_link_create",
            io_error: io::Error::from_raw_os_error(22),
        });
        assert!(matches!(
            classify_attach_error("soglia_connect4", error),
            BackendError::Failed(_)
        ));
    }

    #[test]
    fn recovery_ignores_cgroup_control_files_but_rejects_child_cgroups() {
        let root = std::env::temp_dir().join(format!(
            "soglia-cgroup-recovery-test-{}",
            ExecutionNonce::generate().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("cgroup.procs"), b"").unwrap();
        assert!(!has_child_cgroup(&root).unwrap());

        fs::create_dir(root.join("execution-child")).unwrap();
        assert!(has_child_cgroup(&root).unwrap());

        fs::remove_dir(root.join("execution-child")).unwrap();
        fs::remove_file(root.join("cgroup.procs")).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn candidate_a_abi_round_trips_the_indivisible_binding_and_tuple() {
        let binding = BindingKey {
            cgroup_id: 14_196,
            execution_nonce: ExecutionNonce::generate().unwrap(),
            backend_generation: 9,
        };
        assert_eq!(decode_binding(&encode_binding(binding)), Some(binding));
        assert_eq!(
            decode_policy(&encode_policy(POLICY_ACTIVE, binding)),
            Some((POLICY_ACTIVE, binding))
        );
        let tuple = SocketTupleV4 {
            source_address: [10, 201, 0, 3],
            destination_address: [10, 200, 255, 1],
            source_port: 51_234,
            destination_port: 15_001,
        };
        let bytes = encode_tuple(tuple);
        assert_eq!(&bytes[0..4], &[10, 201, 0, 3]);
        assert_eq!(&bytes[4..8], &[10, 200, 255, 1]);
        assert_eq!(&bytes[10..12], &15_001_u16.to_ne_bytes());
    }

    fn ancestor(id: u32, name: &str, tag: &str) -> AttachmentFingerprint {
        AttachmentFingerprint {
            program_id: id,
            name: name.to_owned(),
            program_type: "cgroup_skb".to_owned(),
            tag: tag.to_owned(),
            attach_type: "cgroup_inet_egress".to_owned(),
        }
    }

    #[test]
    fn only_stable_systemd_id_replacement_is_external_churn() {
        let before = vec![
            ancestor(10, "sd_fw_egress", "same"),
            ancestor(20, "foreign_allow", "foreign"),
        ];
        let after = vec![
            ancestor(11, "sd_fw_egress", "same"),
            ancestor(20, "foreign_allow", "foreign"),
        ];
        assert!(systemd_external_churn(&before, &after));

        let mut changed_tag = after.clone();
        changed_tag[0].tag = "changed".to_owned();
        assert!(!systemd_external_churn(&before, &changed_tag));

        let mut changed_foreign = after;
        changed_foreign[1].program_id = 21;
        assert!(!systemd_external_churn(&before, &changed_foreign));

        let mut unknown = before.clone();
        unknown.push(ancestor(30, "unknown", "unknown"));
        assert!(!systemd_external_churn(&before, &unknown));
    }
}
