// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `EnforcementBackend` contract and its Phase-0 implementations.
//!
//! A backend owns the trusted transport boundary of each Execution: its network confinement, the
//! anti-spoofing that makes its address attributable, and the teardown of both. It does not parse
//! HTTP and it does not implement PIC.
//!
//! `NetnsNftBackend` is the active backend. `CgroupBpfBackend` is a skeleton that refuses every
//! operation with `UnsupportedInThisBuild`: it can be selected by nobody, and it never allows.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use soglia_core::config::Config;
use soglia_core::id::{ExecutionId, ResourceTag};
use soglia_core::net::{ExecutionPool, SlotAddresses};
use soglia_core::unavailable::{DeferredComponent, Unavailable};

use crate::rules::ProxyEndpoint;

/// Why a backend operation failed.
#[derive(Debug)]
pub enum BackendError {
    /// The backend is not available in this build.
    Unavailable(Unavailable),
    /// The request contradicts the configuration or the backend's state.
    Refused(String),
    /// A host operation failed.
    Failed(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(formatter, "{reason}"),
            Self::Refused(reason) => write!(formatter, "refused: {reason}"),
            Self::Failed(reason) => write!(formatter, "failed: {reason}"),
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

    /// Checks that the host offers everything the backend's guarantees depend on.
    fn probe_capabilities(&self) -> Result<(), BackendError>;

    /// Sweeps what a previous run left behind and installs the host-wide policy. Runs once, before
    /// any Execution exists. Returns what the sweep removed.
    fn initialize(&mut self) -> Result<Vec<String>, BackendError>;

    /// Creates and configures the network of a new Execution.
    fn prepare_execution(
        &mut self,
        id: ExecutionId,
        slot: u32,
        agent: &str,
    ) -> Result<(), BackendError>;

    /// Denies every packet of the Execution from now on.
    fn freeze(&mut self, tag: &ResourceTag) -> Result<(), BackendError>;

    /// Removes every network resource of the Execution and verifies that it is gone.
    fn destroy_execution(&mut self, tag: &ResourceTag) -> Result<(), BackendError>;
}

/// The cgroup-BPF backend: not carried by this build.
#[derive(Debug, Default, Clone, Copy)]
pub struct CgroupBpfBackend;

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

impl EnforcementBackend for CgroupBpfBackend {
    fn name(&self) -> &'static str {
        "cgroup-bpf"
    }

    fn probe_capabilities(&self) -> Result<(), BackendError> {
        self.refuse()
    }

    fn initialize(&mut self) -> Result<Vec<String>, BackendError> {
        self.refuse()
    }

    fn prepare_execution(&mut self, _: ExecutionId, _: u32, _: &str) -> Result<(), BackendError> {
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
        fn ip(&self, args: &[&str]) -> Result<(), BackendError> {
            system::run(&self.settings.ip, args, None)?;
            Ok(())
        }

        fn nft(&self, batch: &str) -> Result<(), BackendError> {
            system::run(&self.settings.nft, &["-f", "-"], Some(batch))?;
            Ok(())
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
    }

    impl EnforcementBackend for NetnsNftBackend {
        fn name(&self) -> &'static str {
            "netns-nft"
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

        fn prepare_execution(
            &mut self,
            id: ExecutionId,
            slot: u32,
            agent: &str,
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

            self.create(&record)
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
            "echo"
        )));
        assert!(unsupported(skeleton.freeze(&tag)));
        assert!(unsupported(skeleton.destroy_execution(&tag)));
    }
}
