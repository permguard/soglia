// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `EnforcementBackend` contract and its Phase-0 implementations.
//!
//! A backend owns the trusted transport boundary of each Execution: its network confinement, the
//! anti-spoofing that makes its address attributable, and the teardown of both. It does not parse
//! HTTP and it does not implement PIC.
//!
//! `CgroupBpfBackend` is the production default. `NetnsNftBackend` remains an explicit
//! compatibility choice; an unavailable default refuses startup rather than silently changing
//! enforcement.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use soglia_core::config::Config;
use soglia_core::helper::{HelperFailure, RefusalClass, ResolveAttempt, SocketTupleV4};
use soglia_core::id::{BindingKey, ExecutionId, ExecutionNonce, ResourceTag};
use soglia_core::net::{ExecutionPool, SlotAddresses};
#[cfg(not(feature = "cgroup-bpf"))]
use soglia_core::unavailable::DeferredComponent;
use soglia_core::unavailable::Unavailable;

use crate::rules::ProxyEndpoint;

#[cfg(feature = "cgroup-bpf")]
pub use crate::cgroup_bpf::CgroupBpfBackend;

/// Why a backend operation failed.
#[derive(Debug)]
pub enum BackendError {
    /// The backend is not available in this build.
    Unavailable(Unavailable),
    /// The request contradicts the configuration or the backend's state.
    Refused(String),
    /// Durable state is incompatible with this binary's schema, ABI, object or configuration.
    Incompatible(String),
    /// Ownership cannot be proven from the exact durable and kernel identities.
    Unknown(String),
    /// A required kernel or environment capability is absent.
    Unsupported(String),
    /// The kernel rejected the production cgroup-BPF attachment topology.
    IncompatibleBpfTopology {
        /// Production program whose link could not be attached.
        hook: String,
        /// Linux errno returned by `BPF_LINK_CREATE`, when available.
        errno: Option<i32>,
    },
    /// A host operation failed.
    Failed(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(formatter, "{reason}"),
            Self::Refused(reason) => write!(formatter, "refused: {reason}"),
            Self::Incompatible(reason) => write!(formatter, "refused: {reason}"),
            Self::Unknown(reason) => write!(formatter, "refused: {reason}"),
            Self::Unsupported(reason) => write!(formatter, "refused: {reason}"),
            Self::IncompatibleBpfTopology { hook, errno } => write!(
                formatter,
                "refused: INCOMPATIBLE_BPF_TOPOLOGY hook={hook} errno={errno:?}"
            ),
            Self::Failed(reason) => write!(formatter, "failed: {reason}"),
        }
    }
}

impl BackendError {
    /// Preserves the trusted classification while adding operation context to diagnostics.
    pub fn into_helper_failure(self, context: &str) -> HelperFailure {
        let detail = format!("{context}: {self}");
        match self {
            Self::Unavailable(_) | Self::Unsupported(_) => HelperFailure::Refused {
                class: RefusalClass::Unsupported,
                detail,
            },
            Self::Refused(_) | Self::Incompatible(_) => HelperFailure::Refused {
                class: RefusalClass::Incompatible,
                detail,
            },
            Self::Unknown(_) => HelperFailure::Refused {
                class: RefusalClass::Unknown,
                detail,
            },
            Self::IncompatibleBpfTopology { hook, errno } => {
                HelperFailure::IncompatibleBpfTopology {
                    hook,
                    errno,
                    detail,
                }
            }
            Self::Failed(_) => HelperFailure::Refused {
                class: RefusalClass::Infrastructure,
                detail,
            },
        }
    }
}

impl std::error::Error for BackendError {}

impl From<std::io::Error> for BackendError {
    fn from(error: std::io::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

/// The network-enforcement contract of an Execution.
pub trait EnforcementBackend {
    /// The backend's name, for logs.
    fn name(&self) -> &'static str;

    /// Exact tags whose policy/resources this backend currently owns.
    fn live_tags(&self) -> Vec<ResourceTag>;

    /// Checks that the host offers everything the backend's guarantees depend on.
    fn probe_capabilities(&self) -> Result<(), BackendError>;

    /// Sweeps what a previous run left behind and installs the host-wide policy. Runs once, before
    /// any Execution exists. Returns what the sweep removed.
    fn initialize(&mut self) -> Result<Vec<String>, BackendError>;

    /// Revalidates the backend's security-critical owned state while it is live.
    fn health_check(&mut self) -> Result<(), BackendError>;

    /// Creates and configures the network of a new Execution.
    fn prepare_execution(
        &mut self,
        id: ExecutionId,
        slot: u32,
        agent: &str,
        nonce: ExecutionNonce,
    ) -> Result<(), BackendError>;

    /// Independently proves a paused init's exact cgroup membership while policy remains frozen.
    fn verify_placement(
        &mut self,
        id: ExecutionId,
        pid: i32,
    ) -> Result<Option<BindingKey>, BackendError>;

    /// Activates only the exact identity already returned by placement verification.
    fn activate_execution(
        &mut self,
        id: ExecutionId,
        binding: Option<BindingKey>,
    ) -> Result<(), BackendError>;

    /// Creates the immutable, thread-safe view used only by stateless Resolve workers.
    fn resolve_view(&mut self) -> Result<Arc<dyn ResolveBackend>, BackendError>;

    /// Denies every packet of the Execution from now on.
    fn freeze(&mut self, tag: &ResourceTag) -> Result<(), BackendError>;

    /// Removes every network resource of the Execution and verifies that it is gone.
    fn destroy_execution(&mut self, tag: &ResourceTag) -> Result<(), BackendError>;
}

/// Immutable view used by the fixed Resolve worker pool.
pub trait ResolveBackend: Send + Sync {
    /// Makes one non-blocking attempt to consume and validate a canonical proxy tuple.
    fn resolve_once(&self, tuple: SocketTupleV4) -> Result<ResolveAttempt, BackendError>;
}

struct UnavailableResolveBackend;

impl ResolveBackend for UnavailableResolveBackend {
    fn resolve_once(&self, _: SocketTupleV4) -> Result<ResolveAttempt, BackendError> {
        Err(BackendError::Refused(
            "Candidate-A Resolve is unavailable on this backend".to_owned(),
        ))
    }
}

/// The cgroup-BPF backend is a feature-gated production component.
#[cfg(not(feature = "cgroup-bpf"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct CgroupBpfBackend;

#[cfg(not(feature = "cgroup-bpf"))]
impl CgroupBpfBackend {
    fn refuse<T>(&self) -> Result<T, BackendError> {
        Err(BackendError::Unavailable(
            DeferredComponent::CgroupBpfBackend
                .activate()
                .err()
                .unwrap_or(Unavailable::UnsupportedInThisBuild(
                    DeferredComponent::CgroupBpfBackend,
                )),
        ))
    }
}

#[cfg(not(feature = "cgroup-bpf"))]
impl EnforcementBackend for CgroupBpfBackend {
    fn name(&self) -> &'static str {
        "cgroup-bpf"
    }

    fn live_tags(&self) -> Vec<ResourceTag> {
        Vec::new()
    }

    fn probe_capabilities(&self) -> Result<(), BackendError> {
        self.refuse()
    }

    fn initialize(&mut self) -> Result<Vec<String>, BackendError> {
        self.refuse()
    }

    fn health_check(&mut self) -> Result<(), BackendError> {
        self.refuse()
    }

    fn prepare_execution(
        &mut self,
        _: ExecutionId,
        _: u32,
        _: &str,
        _: ExecutionNonce,
    ) -> Result<(), BackendError> {
        self.refuse()
    }

    fn verify_placement(
        &mut self,
        _: ExecutionId,
        _: i32,
    ) -> Result<Option<BindingKey>, BackendError> {
        self.refuse()
    }

    fn activate_execution(
        &mut self,
        _: ExecutionId,
        _: Option<BindingKey>,
    ) -> Result<(), BackendError> {
        self.refuse()
    }

    fn resolve_view(&mut self) -> Result<Arc<dyn ResolveBackend>, BackendError> {
        self.refuse()
    }

    fn freeze(&mut self, _: &ResourceTag) -> Result<(), BackendError> {
        self.refuse()
    }

    fn destroy_execution(&mut self, _: &ResourceTag) -> Result<(), BackendError> {
        self.refuse()
    }
}

/// What the enforcer records about one Execution before creating any of its resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetRecord {
    /// The Execution.
    pub id: ExecutionId,
    /// Its resource tag.
    pub tag: ResourceTag,
    /// Its pool slot.
    pub slot: u32,
    /// The two ends of its link.
    pub addresses: SlotAddresses,
    /// The port of its agent listener.
    pub agent_port: u16,
}

impl NetRecord {
    /// The record's file name.
    pub fn file_name(tag: &ResourceTag) -> String {
        format!("{tag}.json")
    }
}

/// What the enforcer records about the host-wide objects it owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecord {
    /// The dummy interface that carries the proxy address.
    pub dummy: String,
    /// The proxy address on it.
    pub proxy_address: Ipv4Addr,
}

/// The name of the host record.
pub const HOST_RECORD: &str = "host.json";
/// The dummy interface that carries the egress proxy address.
pub const PROXY_INTERFACE: &str = "soglia0";

/// The facts of the configuration the network backend needs.
#[derive(Debug, Clone)]
pub struct NetworkSettings {
    /// The iproute2 executable.
    pub ip: PathBuf,
    /// The nftables executable.
    pub nft: PathBuf,
    /// Where the enforcer's ownership records live.
    pub records: PathBuf,
    /// The Execution address pool.
    pub pool: ExecutionPool,
    /// The egress proxy endpoint.
    pub proxy: ProxyEndpoint,
    /// The only user allowed to open connections toward an Execution.
    pub supervisor_uid: u32,
    /// The listener port of every configured agent.
    pub agent_ports: BTreeMap<String, u16>,
}

impl NetworkSettings {
    /// The settings a validated configuration implies.
    pub fn from_config(config: &Config) -> Result<Self, BackendError> {
        let pool = config
            .pool()
            .map_err(|error| BackendError::Refused(error.to_string()))?;

        Ok(Self {
            ip: config.runtime.ip.clone(),
            nft: config.runtime.nft.clone(),
            records: config.runtime.state_dir.join("net"),
            pool,
            proxy: ProxyEndpoint {
                address: config.network.proxy_address,
                port: config.network.proxy_port,
            },
            supervisor_uid: config.runtime.uid,
            agent_ports: config
                .agents
                .iter()
                .map(|(name, agent)| (name.clone(), agent.port))
                .collect(),
        })
    }
}

/// The Phase-0 backend: a Soglia-owned network namespace, veth pair and nftables policy per
/// Execution.
pub struct NetnsNftBackend {
    settings: NetworkSettings,
    live: HashMap<ResourceTag, NetRecord>,
}

/// Network resources whose ownership was proved before an uninstall mutation.
#[cfg(feature = "cgroup-bpf")]
pub(crate) struct PreparedNetworkUninstall {
    records: Vec<(String, NetRecord)>,
    host: Option<HostRecord>,
    fresh: bool,
}

#[cfg(feature = "cgroup-bpf")]
impl PreparedNetworkUninstall {
    pub(crate) fn planned_operations(&self) -> Vec<String> {
        let mut operations = self
            .records
            .iter()
            .map(|(_, record)| format!("remove network of Execution {}", record.id))
            .collect::<Vec<_>>();
        if self.host.is_some() {
            operations.push("remove host nft table and proxy interface".to_owned());
        }
        operations
    }

    pub(crate) fn is_fresh(&self) -> bool {
        self.fresh
    }
}

impl NetnsNftBackend {
    /// A backend over `settings`.
    pub fn new(settings: NetworkSettings) -> Self {
        Self {
            settings,
            live: HashMap::new(),
        }
    }

    /// Checks a request against the configuration and the live Executions, and derives its record.
    pub fn plan(&self, id: ExecutionId, slot: u32, agent: &str) -> Result<NetRecord, BackendError> {
        let agent_port =
            *self.settings.agent_ports.get(agent).ok_or_else(|| {
                BackendError::Refused(format!("no agent `{agent}` is configured"))
            })?;
        let addresses = self
            .settings
            .pool
            .slot(slot)
            .ok_or_else(|| BackendError::Refused(format!("slot {slot} is outside the pool")))?;
        let tag = id.tag();
        if self.live.contains_key(&tag) {
            return Err(BackendError::Refused(format!("tag {tag} is already live")));
        }
        if self.live.values().any(|record| record.slot == slot) {
            return Err(BackendError::Refused(format!(
                "slot {slot} is already in use"
            )));
        }

        Ok(NetRecord {
            id,
            tag,
            slot,
            addresses,
            agent_port,
        })
    }

    /// The tags of every Execution this backend created and has not destroyed.
    pub fn live_tags(&self) -> Vec<ResourceTag> {
        self.live.keys().copied().collect()
    }

    fn records(&self) -> &std::path::Path {
        &self.settings.records
    }
}

mod linux {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use soglia_core::records;

    use super::*;
    use crate::rules;
    use crate::system::{self, entries_with_prefix, in_netns, interface_exists, netns_exists};

    impl NetnsNftBackend {
        /// Proves the complete network-removal plan without changing host state.
        #[cfg(feature = "cgroup-bpf")]
        pub(crate) fn prepare_uninstall(&self) -> Result<PreparedNetworkUninstall, BackendError> {
            let records_directory_absent = !self.records().exists();
            let mut planned = Vec::new();
            let entries = match fs::read_dir(self.records()) {
                Ok(entries) => entries
                    .map(|entry| {
                        entry.map(|entry| entry.file_name().to_string_lossy().into_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            for name in entries {
                if records::is_temporary(&name) || (!name.ends_with(".json") && name != HOST_RECORD)
                {
                    return Err(BackendError::Unknown(format!(
                        "UNKNOWN entry {name} in the network ownership directory"
                    )));
                }
                if name == HOST_RECORD {
                    continue;
                }
                let record: NetRecord = records::read(self.records(), &name)
                    .map_err(|error| {
                        if error.kind() == std::io::ErrorKind::InvalidData {
                            BackendError::Incompatible(format!(
                                "INCOMPATIBLE network record {name}: {error}"
                            ))
                        } else {
                            BackendError::from(error)
                        }
                    })?
                    .ok_or_else(|| {
                        BackendError::Unknown(format!("UNKNOWN network record {name} vanished"))
                    })?;
                let expected_addresses = self.settings.pool.slot(record.slot).ok_or_else(|| {
                    BackendError::Unknown(format!(
                        "UNKNOWN slot in network ownership record {name}"
                    ))
                })?;
                let configured_port = self
                    .settings
                    .agent_ports
                    .values()
                    .any(|port| *port == record.agent_port);
                if NetRecord::file_name(&record.tag) != name
                    || record.id.tag() != record.tag
                    || record.addresses != expected_addresses
                    || !configured_port
                {
                    return Err(BackendError::Unknown(format!(
                        "UNKNOWN identity in network ownership record {name}"
                    )));
                }
                planned.push((name, record));
            }

            let host: Option<HostRecord> =
                records::read(self.records(), HOST_RECORD).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::InvalidData {
                        BackendError::Incompatible(format!(
                            "INCOMPATIBLE host-network record: {error}"
                        ))
                    } else {
                        BackendError::from(error)
                    }
                })?;
            let expected_host = HostRecord {
                dummy: PROXY_INTERFACE.to_owned(),
                proxy_address: self.settings.proxy.address,
            };
            if host.as_ref().is_some_and(|record| record != &expected_host) {
                return Err(BackendError::Unknown(
                    "UNKNOWN host-network ownership record".to_owned(),
                ));
            }
            Self::validate_unrecorded_host_network(
                host.is_some(),
                interface_exists(PROXY_INTERFACE),
                self.host_table_exists()?,
            )?;

            let expected_veth = planned
                .iter()
                .map(|(_, record)| record.tag.host_veth())
                .collect::<std::collections::BTreeSet<_>>();
            let expected_netns = planned
                .iter()
                .map(|(_, record)| record.tag.netns_name())
                .collect::<std::collections::BTreeSet<_>>();
            let actual_veth = entries_with_prefix(Path::new("/sys/class/net"), "sgh-")?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            let actual_netns = entries_with_prefix(Path::new(system::NETNS_DIR), "soglia-")?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            if !actual_veth.is_subset(&expected_veth) || !actual_netns.is_subset(&expected_netns) {
                return Err(BackendError::Unknown(
                    "UNKNOWN network resource exists without an exact ownership record".to_owned(),
                ));
            }
            planned.sort_by(|left, right| left.0.cmp(&right.0));
            let fresh = records_directory_absent
                && planned.is_empty()
                && host.is_none()
                && actual_veth.is_empty()
                && actual_netns.is_empty();
            Ok(PreparedNetworkUninstall {
                records: planned,
                host,
                fresh,
            })
        }

        #[cfg(feature = "cgroup-bpf")]
        pub(super) fn validate_unrecorded_host_network(
            has_record: bool,
            interface_exists: bool,
            table_exists: bool,
        ) -> Result<(), BackendError> {
            if !has_record && interface_exists {
                return Err(BackendError::Unknown(format!(
                    "UNKNOWN {PROXY_INTERFACE} exists without its ownership record"
                )));
            }
            if !has_record && table_exists {
                return Err(BackendError::Unknown(format!(
                    "UNKNOWN nft table inet {} exists without its ownership record",
                    rules::HOST_TABLE
                )));
            }
            Ok(())
        }

        /// Applies a plan that was completely validated before the first mutation.
        #[cfg(feature = "cgroup-bpf")]
        pub(crate) fn execute_uninstall(
            &self,
            plan: &PreparedNetworkUninstall,
        ) -> Result<(), BackendError> {
            for (name, record) in &plan.records {
                // The complete recorded host table is removed below. Leaving its individual
                // elements in place until then makes a crash between records safely resumable.
                self.remove(record, false)?;
                records::remove(self.records(), name)?;
            }
            if plan.host.is_some() {
                self.nft(&format!(
                    "add table inet {}\ndelete table inet {}\n",
                    rules::HOST_TABLE,
                    rules::HOST_TABLE
                ))?;
                if interface_exists(PROXY_INTERFACE) {
                    self.ip(&["link", "del", PROXY_INTERFACE])?;
                }
                if interface_exists(PROXY_INTERFACE) {
                    return Err(BackendError::Failed(format!(
                        "{PROXY_INTERFACE} survived uninstall"
                    )));
                }
                records::remove(self.records(), HOST_RECORD)?;
            }
            match fs::remove_dir(self.records()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(())
        }
        fn ip(&self, args: &[&str]) -> Result<(), BackendError> {
            system::run(&self.settings.ip, args, None)?;
            Ok(())
        }

        fn nft(&self, batch: &str) -> Result<(), BackendError> {
            system::run(&self.settings.nft, &["-f", "-"], Some(batch))?;
            Ok(())
        }

        #[cfg(feature = "cgroup-bpf")]
        fn host_table_exists(&self) -> Result<bool, BackendError> {
            let output = system::run(&self.settings.nft, &["-j", "list", "tables"], None)?;
            let value: serde_json::Value = serde_json::from_str(&output).map_err(|error| {
                BackendError::Failed(format!("decode nft table inventory: {error}"))
            })?;
            let entries = value
                .get("nftables")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    BackendError::Failed("nft table inventory has no nftables array".to_owned())
                })?;
            Ok(entries.iter().any(|entry| {
                entry.get("table").is_some_and(|table| {
                    table.get("family").and_then(serde_json::Value::as_str) == Some("inet")
                        && table.get("name").and_then(serde_json::Value::as_str)
                            == Some(rules::HOST_TABLE)
                })
            }))
        }

        fn nft_in(&self, netns: &str, batch: &str) -> Result<(), BackendError> {
            let nft = self.settings.nft.clone();
            let batch = batch.to_owned();
            in_netns(netns, move || system::run(&nft, &["-f", "-"], Some(&batch)))?;
            Ok(())
        }

        /// Creates every resource of `record`. On failure the caller removes what was created.
        fn create(&self, record: &NetRecord) -> Result<(), BackendError> {
            let netns = record.tag.netns_name();
            let veth = record.tag.host_veth();
            let SlotAddresses { host, execution } = record.addresses;
            let host_cidr = format!("{host}/31");
            let execution_cidr = format!("{execution}/31");
            let proxy_route = format!("{}/32", self.settings.proxy.address);
            let host_address = host.to_string();

            self.ip(&["netns", "add", &netns])?;
            // IPv6 is disabled before any interface enters the namespace, so none ever gets an
            // IPv6 address, not even a link-local one.
            in_netns(&netns, || {
                for path in [
                    "net/ipv6/conf/all/disable_ipv6",
                    "net/ipv6/conf/default/disable_ipv6",
                    "net/ipv6/conf/lo/disable_ipv6",
                ] {
                    system::set_sysctl(path, "1")?;
                }
                Ok(())
            })?;
            self.ip(&[
                "link", "add", &veth, "type", "veth", "peer", "name", "eth0", "netns", &netns,
            ])?;
            system::set_sysctl(&format!("net/ipv6/conf/{veth}/disable_ipv6"), "1")?;
            system::set_sysctl(&format!("net/ipv4/conf/{veth}/rp_filter"), "1")?;
            self.ip(&["addr", "add", &host_cidr, "dev", &veth])?;
            self.ip(&["link", "set", &veth, "up"])?;
            self.ip(&["-n", &netns, "addr", "add", &execution_cidr, "dev", "eth0"])?;
            self.ip(&["-n", &netns, "link", "set", "lo", "up"])?;
            self.ip(&["-n", &netns, "link", "set", "eth0", "up"])?;
            self.ip(&[
                "-n",
                &netns,
                "route",
                "add",
                &proxy_route,
                "via",
                &host_address,
                "dev",
                "eth0",
            ])?;
            self.nft_in(
                &netns,
                &rules::execution_table(&record.addresses, record.agent_port, self.settings.proxy),
            )?;
            // Last: until these elements exist, the host drops everything the veth carries.
            self.nft(&rules::bind_elements(
                &record.tag,
                &record.addresses,
                record.agent_port,
            ))
        }

        /// Removes every resource of `record` and verifies each is gone. Idempotent: a resource that
        /// is already absent is not a failure.
        fn remove(&self, record: &NetRecord, host_elements: bool) -> Result<(), BackendError> {
            let netns = record.tag.netns_name();
            let veth = record.tag.host_veth();

            if host_elements {
                self.nft(&rules::unbind_elements(
                    &record.tag,
                    &record.addresses,
                    record.agent_port,
                ))?;
            }
            if interface_exists(&veth) {
                self.ip(&["link", "del", &veth])?;
            }
            if netns_exists(&netns) {
                self.ip(&["netns", "del", &netns])?;
            }
            if interface_exists(&veth) {
                return Err(BackendError::Failed(format!("{veth} still exists")));
            }
            if netns_exists(&netns) {
                return Err(BackendError::Failed(format!("{netns} still exists")));
            }

            Ok(())
        }

        fn sweep(&self) -> Result<Vec<String>, BackendError> {
            let mut swept = Vec::new();
            for name in entries_with_prefix(self.records(), "")? {
                if records::is_temporary(&name) {
                    // An unfinished publication: the resource it announced was never created.
                    fs::remove_file(self.records().join(&name))?;
                    continue;
                }
                if name == HOST_RECORD || !name.ends_with(".json") {
                    continue;
                }
                let record: NetRecord = records::read(self.records(), &name)?.ok_or_else(|| {
                    BackendError::Failed(format!("the record {name} vanished during the sweep"))
                })?;
                if NetRecord::file_name(&record.tag) != name {
                    return Err(BackendError::Refused(format!(
                        "the record {name} names another Execution; ownership cannot be proven"
                    )));
                }
                // The host table is rebuilt right after the sweep, which drops every element.
                self.remove(&record, false)?;
                records::remove(self.records(), &name)?;
                swept.push(format!("network of Execution {}", record.id));
            }

            // Anything that still carries a Soglia name has no record, so Soglia cannot prove it
            // owns it. It is reported, never deleted.
            let mut unrecorded = entries_with_prefix(Path::new("/sys/class/net"), "sgh-")?;
            unrecorded.extend(entries_with_prefix(
                Path::new(system::NETNS_DIR),
                "soglia-",
            )?);
            if !unrecorded.is_empty() {
                return Err(BackendError::Refused(format!(
                    "resources with a Soglia name but no ownership record exist: {}; remove them after inspection",
                    unrecorded.join(", ")
                )));
            }

            Ok(swept)
        }

        fn install_host(&self) -> Result<(), BackendError> {
            let recorded: Option<HostRecord> = records::read(self.records(), HOST_RECORD)?;
            if interface_exists(PROXY_INTERFACE) {
                if recorded.is_none() {
                    return Err(BackendError::Refused(format!(
                        "{PROXY_INTERFACE} exists but Soglia has no record of creating it"
                    )));
                }
                self.ip(&["link", "del", PROXY_INTERFACE])?;
            }
            let record = HostRecord {
                dummy: PROXY_INTERFACE.to_owned(),
                proxy_address: self.settings.proxy.address,
            };
            records::publish(self.records(), HOST_RECORD, &record)?;
            let address = format!("{}/32", self.settings.proxy.address);
            self.ip(&["link", "add", PROXY_INTERFACE, "type", "dummy"])?;
            system::set_sysctl(
                &format!("net/ipv6/conf/{PROXY_INTERFACE}/disable_ipv6"),
                "1",
            )?;
            self.ip(&["addr", "add", &address, "dev", PROXY_INTERFACE])?;
            self.ip(&["link", "set", PROXY_INTERFACE, "up"])?;

            self.nft(&rules::host_table(
                self.settings.proxy,
                self.settings.supervisor_uid,
            ))
        }

        /// Rolls back only the host-wide resources created by `initialize` in this process.
        /// Per-Execution sweep results are deliberately not recreated.
        #[cfg(feature = "cgroup-bpf")]
        pub(crate) fn rollback_initialization(&self) -> Result<(), BackendError> {
            if !self.live.is_empty() {
                return Err(BackendError::Failed(
                    "cannot roll back host initialization with live Executions".to_owned(),
                ));
            }
            let expected = HostRecord {
                dummy: PROXY_INTERFACE.to_owned(),
                proxy_address: self.settings.proxy.address,
            };
            let recorded: Option<HostRecord> = records::read(self.records(), HOST_RECORD)?;
            if recorded.as_ref() != Some(&expected) {
                return Err(BackendError::Refused(
                    "host network rollback lacks the exact trusted ownership record".to_owned(),
                ));
            }
            self.nft(&format!(
                "add table inet {}\ndelete table inet {}\n",
                rules::HOST_TABLE,
                rules::HOST_TABLE
            ))?;
            if interface_exists(PROXY_INTERFACE) {
                self.ip(&["link", "del", PROXY_INTERFACE])?;
            }
            if interface_exists(PROXY_INTERFACE) {
                return Err(BackendError::Failed(format!(
                    "{PROXY_INTERFACE} survived host initialization rollback"
                )));
            }
            records::remove(self.records(), HOST_RECORD)?;
            match fs::remove_dir(self.records()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(())
        }
    }

    impl EnforcementBackend for NetnsNftBackend {
        fn name(&self) -> &'static str {
            "netns-nft"
        }

        fn live_tags(&self) -> Vec<ResourceTag> {
            NetnsNftBackend::live_tags(self)
        }

        fn probe_capabilities(&self) -> Result<(), BackendError> {
            if !system::is_root() {
                return Err(BackendError::Refused(
                    "the enforcer must run as root".to_owned(),
                ));
            }
            system::run(&self.settings.nft, &["--version"], None)?;
            system::run(&self.settings.ip, &["-V"], None)?;

            Ok(())
        }

        fn initialize(&mut self) -> Result<Vec<String>, BackendError> {
            fs::create_dir_all(self.records())?;
            fs::set_permissions(self.records(), fs::Permissions::from_mode(0o700))?;
            let swept = self.sweep()?;
            self.install_host()?;

            Ok(swept)
        }

        fn health_check(&mut self) -> Result<(), BackendError> {
            self.probe_capabilities()?;
            if !interface_exists(PROXY_INTERFACE) {
                return Err(BackendError::Failed(format!(
                    "the owned proxy interface {PROXY_INTERFACE} disappeared"
                )));
            }
            Ok(())
        }

        fn prepare_execution(
            &mut self,
            id: ExecutionId,
            slot: u32,
            agent: &str,
            _nonce: ExecutionNonce,
        ) -> Result<(), BackendError> {
            let record = self.plan(id, slot, agent)?;
            let name = NetRecord::file_name(&record.tag);
            if records::read::<NetRecord>(self.records(), &name)?.is_some() {
                return Err(BackendError::Refused(format!(
                    "a record for {} already exists",
                    record.tag
                )));
            }
            // Recorded before anything is created, so a crash at any later point leaves a record the
            // next start can sweep.
            records::publish(self.records(), &name, &record)?;
            self.live.insert(record.tag, record.clone());

            if let Err(error) = self.create(&record) {
                if let Err(cleanup) = self.remove(&record, false) {
                    return Err(BackendError::Failed(format!(
                        "{error}; failed to roll back the partial network: {cleanup}"
                    )));
                }
                records::remove(self.records(), &name)?;
                self.live.remove(&record.tag);
                return Err(error);
            }
            Ok(())
        }

        fn verify_placement(
            &mut self,
            id: ExecutionId,
            _pid: i32,
        ) -> Result<Option<BindingKey>, BackendError> {
            if !self.live.contains_key(&id.tag()) {
                return Err(BackendError::Refused(format!(
                    "Execution {id} has no prepared network"
                )));
            }
            Ok(None)
        }

        fn activate_execution(
            &mut self,
            id: ExecutionId,
            binding: Option<BindingKey>,
        ) -> Result<(), BackendError> {
            if binding.is_some() || !self.live.contains_key(&id.tag()) {
                return Err(BackendError::Refused(
                    "netns-nft activation received a mismatched identity".to_owned(),
                ));
            }
            Ok(())
        }

        fn resolve_view(&mut self) -> Result<Arc<dyn ResolveBackend>, BackendError> {
            Ok(Arc::new(UnavailableResolveBackend))
        }

        fn freeze(&mut self, tag: &ResourceTag) -> Result<(), BackendError> {
            let netns = tag.netns_name();
            if !netns_exists(&netns) {
                // No namespace, no traffic: nothing is left to deny.
                return Ok(());
            }
            self.nft_in(&netns, &rules::freeze_execution())
        }

        fn destroy_execution(&mut self, tag: &ResourceTag) -> Result<(), BackendError> {
            let name = NetRecord::file_name(tag);
            let record = match self.live.get(tag) {
                Some(record) => record.clone(),
                None => match records::read::<NetRecord>(self.records(), &name)? {
                    Some(record) => record,
                    // Neither live nor recorded: nothing of it exists.
                    None => return Ok(()),
                },
            };
            self.remove(&record, true)?;
            records::remove(self.records(), &name)?;
            self.live.remove(tag);

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> NetnsNftBackend {
        NetnsNftBackend::new(NetworkSettings {
            ip: "/usr/sbin/ip".into(),
            nft: "/usr/sbin/nft".into(),
            records: "/run/soglia/net".into(),
            pool: ExecutionPool::new("10.201.0.0/30".parse().unwrap()).unwrap(),
            proxy: ProxyEndpoint {
                address: "10.200.255.1".parse().unwrap(),
                port: 15001,
            },
            supervisor_uid: 990,
            agent_ports: BTreeMap::from([("echo".to_owned(), 8080)]),
        })
    }

    #[test]
    fn a_plan_is_derived_from_configuration_not_from_the_request() {
        let backend = backend();
        let id = ExecutionId::generate().unwrap();
        let record = backend.plan(id, 1, "echo").unwrap();
        assert_eq!(record.tag, id.tag());
        assert_eq!(
            record.addresses.execution,
            "10.201.0.3".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(record.agent_port, 8080);
    }

    #[test]
    fn a_plan_outside_the_configuration_is_refused() {
        let backend = backend();
        let id = ExecutionId::generate().unwrap();
        assert!(matches!(
            backend.plan(id, 2, "echo"),
            Err(BackendError::Refused(_))
        ));
        assert!(matches!(
            backend.plan(id, 0, "shell"),
            Err(BackendError::Refused(_))
        ));
    }

    #[test]
    fn a_live_slot_or_tag_is_not_planned_twice() {
        let mut backend = backend();
        let id = ExecutionId::generate().unwrap();
        let record = backend.plan(id, 0, "echo").unwrap();
        backend.live.insert(record.tag, record);
        assert!(backend.plan(id, 1, "echo").is_err(), "same tag");
        assert!(
            backend
                .plan(ExecutionId::generate().unwrap(), 0, "echo")
                .is_err(),
            "same slot"
        );
    }

    #[test]
    fn uninstall_refusals_preserve_every_stable_class() {
        for (error, expected) in [
            (
                BackendError::Incompatible("schema".to_owned()),
                RefusalClass::Incompatible,
            ),
            (
                BackendError::Unknown("ownership".to_owned()),
                RefusalClass::Unknown,
            ),
            (
                BackendError::Unsupported("kernel".to_owned()),
                RefusalClass::Unsupported,
            ),
            (
                BackendError::Failed("host".to_owned()),
                RefusalClass::Infrastructure,
            ),
        ] {
            assert!(matches!(
                error.into_helper_failure("uninstall"),
                HelperFailure::Refused { class, .. } if class == expected
            ));
        }
        assert!(matches!(
            BackendError::IncompatibleBpfTopology {
                hook: "connect4".to_owned(),
                errno: Some(1),
            }
            .into_helper_failure("uninstall"),
            HelperFailure::IncompatibleBpfTopology { hook, errno, .. }
                if hook == "connect4" && errno == Some(1)
        ));
    }

    #[test]
    fn generic_unsupported_failure_does_not_name_a_backend_choice() {
        let failure = BackendError::Unsupported("kernel capability is absent".to_owned())
            .into_helper_failure("backend operation failed");
        assert!(matches!(
            failure,
            HelperFailure::Refused {
                class: RefusalClass::Unsupported,
                detail,
            } if !detail.contains("network.backend: netns-nft")
        ));
    }

    #[test]
    #[cfg(feature = "cgroup-bpf")]
    fn uninstall_rejects_an_unrecorded_host_nft_table() {
        assert!(matches!(
            NetnsNftBackend::validate_unrecorded_host_network(false, false, true),
            Err(BackendError::Unknown(reason))
                if reason.contains("nft table inet soglia_host")
        ));
        assert!(NetnsNftBackend::validate_unrecorded_host_network(false, false, false).is_ok());
        assert!(NetnsNftBackend::validate_unrecorded_host_network(true, true, true).is_ok());
    }

    #[test]
    #[cfg(not(feature = "cgroup-bpf"))]
    fn the_cgroup_bpf_skeleton_refuses_everything() {
        let mut skeleton = CgroupBpfBackend;
        let tag: ResourceTag = "0123456789".parse().unwrap();
        let unsupported = |result: Result<(), BackendError>| {
            matches!(
                result,
                Err(BackendError::Unavailable(
                    Unavailable::UnsupportedInThisBuild(DeferredComponent::CgroupBpfBackend)
                ))
            )
        };
        assert!(unsupported(skeleton.probe_capabilities()));
        assert!(unsupported(skeleton.initialize().map(|_| ())));
        assert!(unsupported(skeleton.prepare_execution(
            ExecutionId::generate().unwrap(),
            0,
            "echo",
            ExecutionNonce::generate().unwrap()
        )));
        assert!(unsupported(skeleton.freeze(&tag)));
        assert!(unsupported(skeleton.destroy_execution(&tag)));
    }
}
