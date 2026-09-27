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

use aya::maps::{Array, HashMap, MapError, MapInfo};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, ProgramError, SockOps};
use aya::{Ebpf, EbpfLoader};
use libbpf_rs::{MapCore, MapHandle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soglia_core::config::Config;
use soglia_core::helper::SocketTupleV4;
use soglia_core::id::{BindingKey, ExecutionId, ExecutionNonce, ResourceTag};
use soglia_core::records;

use crate::backend::{BackendError, EnforcementBackend, NetnsNftBackend, NetworkSettings};
use crate::system;

const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/soglia-cgroup-bpf.o"));
const STATE_FILE: &str = "state.json";
const STATE_SCHEMA: u32 = 2;
const BPF_ABI: u32 = 1;
const META_MAGIC: u64 = 0x534f_474c_4941_4250;
const POLICY_FROZEN: u32 = 0;
const POLICY_ACTIVE: u32 = 1;
const BPF_NOEXIST: u64 = 1;
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
    resolve_timeout: Duration,
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
    pin_root: PathBuf,
    maps: Vec<MapManifest>,
    programs: Vec<ProgramManifest>,
    links: Vec<LinkManifest>,
    ancestor_bpf: Vec<AttachmentFingerprint>,
    resource_envelope: ResourceEnvelope,
    executions: BTreeMap<String, ExecutionState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ManifestPhase {
    Intent,
    Ready,
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
                resolve_timeout: Duration::from_millis(config.cgroup_bpf.resolve_timeout_ms),
            },
            tuple_consumer: None,
            bpf: None,
            links: Vec::new(),
            state: None,
            live: StdHashMap::new(),
            cookie_high_water: 0,
            tuple_high_water: 0,
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
            "{}:{}:{}:{}:{}:{}:{}",
            self.settings.executions.display(),
            self.settings.bpftool.display(),
            self.settings.proxy_ip,
            self.settings.proxy_port,
            self.settings.policy_capacity,
            self.settings.socket_capacity,
            self.settings.ring_bytes
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

    fn classify_and_recover(&self) -> Result<(ExecutionNonce, u64, Vec<String>), BackendError> {
        validate_state_file(&self.state_path())?;
        let recorded: Option<HostState> = records::read(&self.settings.state_dir, STATE_FILE)?;
        let pin_entries = directory_entries(&self.settings.configured_pin_root)?;
        let Some(mut state) = recorded else {
            if !pin_entries.is_empty() {
                return Err(BackendError::Refused(format!(
                    "UNKNOWN cgroup-BPF state: {} contains pins without a trusted record",
                    self.settings.configured_pin_root.display()
                )));
            }
            return Ok((ExecutionNonce::generate()?, 1, Vec::new()));
        };
        if state.schema != STATE_SCHEMA
            || state.abi != BPF_ABI
            || state.object_sha256 != Self::object_hash()
            || state.config_sha256 != self.config_hash()
            || state.attachment_target != self.settings.executions
        {
            return Err(BackendError::Refused(
                "INCOMPATIBLE cgroup-BPF ownership state; kernel objects were left untouched"
                    .to_owned(),
            ));
        }
        let expected_pin_root = self
            .settings
            .configured_pin_root
            .join(format!("{}-g{}", state.state_id, state.generation));
        if state.generation == 0 || state.pin_root != expected_pin_root {
            return Err(BackendError::Refused(
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
            return Err(BackendError::Refused(
                "UNKNOWN cgroup-BPF generation exists outside the recorded pin root".to_owned(),
            ));
        }
        let current_inode = fs::metadata(&self.settings.executions)?.ino();
        if current_inode != state.attachment_inode {
            return Err(BackendError::Refused(
                "INCOMPATIBLE attachment-target inode; kernel objects were left untouched"
                    .to_owned(),
            ));
        }
        self.validate_manifest_structure(&state)?;
        self.validate_recorded_pins(&state)?;
        if let Some(current) =
            self.validate_attachment_inventory(&state, state.phase == ManifestPhase::Ready)?
        {
            state.ancestor_bpf = current;
            self.publish_state(&state)?;
        }
        if has_child_cgroup(&self.settings.executions)? {
            return Err(BackendError::Refused(
                "Execution cgroups remain after the mandatory Sandbox sweep".to_owned(),
            ));
        }
        if state.phase == ManifestPhase::Ready {
            // Durable recovery intent precedes every unlink. A crash after any individual unlink
            // therefore resumes from an explicitly owned subset, never from a silently damaged
            // READY inventory.
            state.phase = ManifestPhase::Intent;
            self.publish_state(&state)?;
        }
        self.remove_recorded_pins(&state)?;
        let next = state
            .generation
            .checked_add(1)
            .ok_or_else(|| BackendError::Refused("backend generation exhausted".to_owned()))?;
        Ok((
            state.state_id,
            next,
            vec![format!("cgroup-BPF generation {}", state.generation)],
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
        if state.maps.len() != MAPS.len()
            || maps != expected_maps
            || state.links.len() != PROGRAMS.len()
            || links != expected_links
            || !programs_valid
            || (state.phase == ManifestPhase::Ready && state.programs.len() != PROGRAMS.len())
            || state
                .links
                .iter()
                .any(|link| link.target_inode != state.attachment_inode)
        {
            return Err(BackendError::Refused(
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
                return Err(BackendError::Refused(
                    "UNKNOWN per-Execution ownership record; no kernel object was changed"
                        .to_owned(),
                ));
            }
        }
        Ok(())
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
            return Err(BackendError::Refused(
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
            return Err(BackendError::Refused(format!(
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
                    BackendError::Refused(
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
                return Err(BackendError::Refused(format!(
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
                    return Err(BackendError::Refused(format!(
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
            return Err(BackendError::Refused(
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
            return Err(BackendError::Refused(
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
                return Err(BackendError::Refused(
                    "UNKNOWN cgroup-BPF generation metadata; no object was changed".to_owned(),
                ));
            }
        }
        for link in state.links.iter().filter(|link| actual.contains(&link.pin)) {
            let pinned = PinnedLink::from_pin(&link.pin).map_err(|error| {
                BackendError::Failed(format!("inspect {}: {error:#}", link.pin.display()))
            })?;
            let fd: FdLink = pinned.into();
            let info = fd.info().map_err(|error| {
                BackendError::Failed(format!("inspect {}: {error:#}", link.pin.display()))
            })?;
            if link.id == 0
                || link.program_id == 0
                || info.id() != link.id
                || info.program_id() != link.program_id
            {
                return Err(BackendError::Refused(format!(
                    "UNKNOWN link identity at {}; no object was changed",
                    link.pin.display()
                )));
            }
        }
        Ok(())
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
            Ok(value) => Ok(decode_binding(&value)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(BackendError::Failed(format!("lookup cookie: {error:#}"))),
        }
    }

    fn update_occupancy(&mut self) -> Result<(), BackendError> {
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
        Ok(())
    }

    fn policy_is_active(&mut self, binding: BindingKey) -> Result<bool, BackendError> {
        Ok(self.policy(binding)? == Some((POLICY_ACTIVE, binding)))
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

impl EnforcementBackend for CgroupBpfBackend {
    fn name(&self) -> &'static str {
        "cgroup-bpf"
    }

    fn live_tags(&self) -> Vec<ResourceTag> {
        CgroupBpfBackend::live_tags(self)
    }

    fn probe_capabilities(&self) -> Result<(), BackendError> {
        if !system::is_root() {
            return Err(BackendError::Refused(
                "the enforcer must run as root".to_owned(),
            ));
        }
        self.network.probe_capabilities()?;
        system::run(&self.settings.bpftool, &["version"], None)
            .map_err(|error| BackendError::Refused(format!("bpftool is unavailable: {error}")))?;
        let target = fs::metadata(&self.settings.executions).map_err(|error| {
            BackendError::Refused(format!(
                "the delegated executions cgroup is not ready: {error}"
            ))
        })?;
        if !target.is_dir() {
            return Err(BackendError::Refused(
                "the delegated executions target is not a directory".to_owned(),
            ));
        }
        let bpffs = fs::read_to_string("/proc/self/mountinfo")?;
        if !bpffs.lines().any(|line| {
            line.split(" - ")
                .nth(1)
                .is_some_and(|tail| tail.starts_with("bpf "))
        }) {
            return Err(BackendError::Refused("bpffs is not mounted".to_owned()));
        }
        if !Path::new("/sys/kernel/btf/vmlinux").is_file() {
            return Err(BackendError::Refused(
                "kernel BTF is unavailable".to_owned(),
            ));
        }
        Ok(())
    }

    fn initialize(&mut self) -> Result<Vec<String>, BackendError> {
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
            Ok(()) => Ok(swept),
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
        self.update_occupancy()?;
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

    fn resolve(&mut self, tuple: SocketTupleV4) -> Result<Option<BindingKey>, BackendError> {
        if tuple.destination_address != self.settings.proxy_ip.octets()
            || tuple.destination_port != self.settings.proxy_port
        {
            return Ok(None);
        }
        let deadline = Instant::now() + self.settings.resolve_timeout;
        loop {
            if let Some((cookie, binding)) = self.consume_tuple(tuple)? {
                let generation = self
                    .state
                    .as_ref()
                    .map(|state| state.generation)
                    .unwrap_or(0);
                let record_matches = binding.backend_generation == generation
                    && self.live.values().any(|execution| {
                        execution.binding == binding && execution.phase == ExecutionPhase::Active
                    });
                let cookie_matches = self.lookup_cookie(cookie)? == Some(binding);
                let policy_matches = self.policy_is_active(binding)?;
                if record_matches && cookie_matches && policy_matches {
                    return Ok(Some(binding));
                }
                return Err(BackendError::Refused(
                    "tuple, cookie, policy and ownership record disagree".to_owned(),
                ));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn freeze(&mut self, tag: &ResourceTag) -> Result<(), BackendError> {
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
        self.update_execution(frozen)
    }

    fn destroy_execution(&mut self, tag: &ResourceTag) -> Result<(), BackendError> {
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
        self.remove_execution_record(tag)
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

fn delegated_root(configured: Option<&Path>) -> Result<PathBuf, BackendError> {
    if let Some(root) = configured {
        return Ok(root.to_path_buf());
    }
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| BackendError::Refused("not in a cgroup v2 hierarchy".to_owned()))?;
    let path = path.strip_suffix("/runtime").unwrap_or(path);
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
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
        return Err(BackendError::Refused(format!(
            "{} is not a root-owned real directory",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o777 != 0o700 {
        return Err(BackendError::Refused(format!(
            "{} could not be restricted to mode 0700",
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
        return Err(BackendError::Refused(format!(
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
        "soglia_counters" => Some((4, 8, 11)),
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

fn recursive_files(root: &Path, allow_partial: bool) -> Result<BTreeSet<PathBuf>, BackendError> {
    let mut files = BTreeSet::new();
    for directory in [root.join("maps"), root.join("links")] {
        for path in directory_entries(&directory)? {
            if path.is_dir() {
                return Err(BackendError::Refused(format!(
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
        return Err(BackendError::Refused(format!(
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
    Err(BackendError::Refused(format!(
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

    fn map_syscall_error(call: &'static str, errno: rustix::io::Errno) -> MapError {
        MapError::SyscallError(aya::sys::SyscallError {
            call,
            io_error: io::Error::from_raw_os_error(errno.raw_os_error()),
        })
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
