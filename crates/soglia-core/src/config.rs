// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `soglia.yaml`: what an operator configures, and the checks it must pass before anything starts.
//!
//! Unknown fields are rejected everywhere. A misspelt security setting that is silently ignored is
//! worse than one that stops the runtime, because the operator believes it is in force.
//!
//! Durations are whole milliseconds and sizes whole bytes, and the field names say so. Every
//! executable Soglia runs is configured by absolute path, so nothing depends on `PATH`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::net::{Cidr, ExecutionPool};
use crate::unavailable::{DeferredComponent, Unavailable};

/// Environment variables Soglia sets inside every Execution, which an agent entry may not override.
pub const RESERVED_ENV: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// The whole configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Runtime-wide settings.
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// The ingress listener.
    #[serde(default)]
    pub ingress: IngressConfig,
    /// The Execution network model.
    #[serde(default)]
    pub network: NetworkConfig,
    /// What Executions may reach through the egress proxy.
    #[serde(default)]
    pub egress: EgressConfig,
    /// Where Execution cgroups are created.
    #[serde(default)]
    pub cgroup: CgroupConfig,
    /// Candidate-A production cgroup-BPF limits and recovery roots.
    #[serde(default)]
    pub cgroup_bpf: CgroupBpfConfig,
    /// Components of later phases. Enabling any of them fails validation in this build.
    #[serde(default)]
    pub features: Features,
    /// The agents this runtime can execute, by name.
    pub agents: BTreeMap<String, AgentConfig>,
}

/// Runtime-wide settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeConfig {
    /// Where ownership records and runtime state live. Soglia owns this directory exclusively.
    pub state_dir: PathBuf,
    /// The uid the Supervisor, ingress and egress proxy run as after the privileged helpers start.
    pub uid: u32,
    /// The gid the Supervisor, ingress and egress proxy run as.
    pub gid: u32,
    /// How many Executions may exist at once.
    pub max_concurrency: u32,
    /// How many invocations may wait for a slot before new ones are refused.
    pub max_queue: u32,
    /// Cleanup failures after which no new Execution is admitted.
    pub cleanup_failure_threshold: u32,
    /// How long one teardown may take before it counts as failed, in milliseconds.
    pub teardown_timeout_ms: u64,
    /// The OCI runtime.
    pub runc: PathBuf,
    /// The nftables executable.
    pub nft: PathBuf,
    /// The iproute2 executable.
    pub ip: PathBuf,
    /// The bpftool executable used for exact cgroup attachment inventory.
    pub bpftool: PathBuf,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("/run/soglia"),
            uid: 0,
            gid: 0,
            max_concurrency: 4,
            max_queue: 16,
            cleanup_failure_threshold: 1,
            teardown_timeout_ms: 10_000,
            runc: PathBuf::from("/usr/sbin/runc"),
            nft: PathBuf::from("/usr/sbin/nft"),
            ip: PathBuf::from("/usr/sbin/ip"),
            bpftool: PathBuf::from("/usr/sbin/bpftool"),
        }
    }
}

/// The ingress listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IngressConfig {
    /// Where callers reach Soglia.
    pub listen: SocketAddr,
    /// The largest request body forwarded to an agent.
    pub max_request_bytes: u64,
    /// The largest agent response buffered for the caller.
    pub max_response_bytes: u64,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8088)),
            max_request_bytes: 1 << 20,
            max_response_bytes: 4 << 20,
        }
    }
}

/// The Execution network model.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    /// The network enforcement and attribution backend.
    pub backend: NetworkBackend,
    /// The IPv4 range Execution links are carved from.
    pub execution_pool: Cidr,
    /// The only address an Execution may connect to: the egress proxy.
    pub proxy_address: Ipv4Addr,
    /// The egress proxy port.
    pub proxy_port: u16,
    /// Private or internal ranges the egress proxy may reach, which it otherwise refuses.
    pub internal_allow: Vec<Cidr>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            backend: NetworkBackend::NetnsNft,
            execution_pool: Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 201, 0, 0)), 16)
                .unwrap_or_else(|_| unreachable!("the default pool is a valid range")),
            proxy_address: Ipv4Addr::new(10, 200, 255, 1),
            proxy_port: 15001,
            internal_allow: Vec::new(),
        }
    }
}

/// The explicitly selected network enforcement backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkBackend {
    /// Network namespace, veth and nftables with source-address attribution.
    #[default]
    NetnsNft,
    /// The composite namespace/nftables backend with Candidate-A cgroup-BPF attribution.
    CgroupBpf,
}

/// Production Candidate-A map, Resolve and pinning limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CgroupBpfConfig {
    /// Maximum simultaneously tracked socket cookies and tuples.
    pub max_tracked_sockets: u32,
    /// Maximum tuple-publication wait before Resolve denies.
    pub resolve_timeout_ms: u64,
    /// Bounded diagnostic ring-buffer size.
    pub ring_buffer_bytes: u32,
    /// Root below bpffs owned by this Soglia instance.
    pub pin_root: PathBuf,
}

impl Default for CgroupBpfConfig {
    fn default() -> Self {
        Self {
            max_tracked_sockets: 4096,
            resolve_timeout_ms: 2_000,
            ring_buffer_bytes: 64 * 1024,
            pin_root: PathBuf::from("/sys/fs/bpf/soglia"),
        }
    }
}

/// What Executions may reach through the egress proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EgressConfig {
    /// Destinations, by exact host name or IP literal, with the ports allowed for each.
    pub allow: Vec<EgressRule>,
    /// How long a connection to a destination may take to open, in milliseconds.
    pub connect_timeout_ms: u64,
    /// How long a proxied connection may stay silent, in milliseconds.
    pub idle_timeout_ms: u64,
    /// The largest plain-HTTP request body the proxy forwards.
    pub max_request_bytes: u64,
    /// The largest plain-HTTP response body the proxy relays.
    pub max_response_bytes: u64,
    /// The most bytes one `CONNECT` tunnel may carry, both directions together.
    pub max_tunnel_bytes: u64,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            connect_timeout_ms: 5_000,
            idle_timeout_ms: 30_000,
            max_request_bytes: 1 << 20,
            max_response_bytes: 16 << 20,
            max_tunnel_bytes: 256 << 20,
        }
    }
}

/// One allowed destination.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    /// An exact host name or an IP literal.
    pub host: String,
    /// The ports allowed on that host.
    pub ports: Vec<u16>,
}

/// Where Execution cgroups are created.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CgroupConfig {
    /// The delegated cgroup v2 root. When unset, it is discovered from Soglia's own cgroup.
    pub root: Option<PathBuf>,
}

/// Components of later phases.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Features {
    /// Permguard Trust Fabric integration.
    pub trust_fabric: bool,
    /// PIC continuation and virtual authority.
    pub pic: bool,
    /// Information-flow control.
    pub ifc: bool,
    /// The Credential Anchor.
    pub credential_anchor: bool,
    /// The CA signer and TLS interception.
    pub ca_signer: bool,
    /// gRPC mediation.
    pub grpc: bool,
    /// The cgroup-BPF enforcement backend.
    pub cgroup_bpf: bool,
}

impl Features {
    fn requested(&self) -> Vec<DeferredComponent> {
        [
            (self.trust_fabric, DeferredComponent::TrustFabricClient),
            (self.pic, DeferredComponent::PicContinuation),
            (self.ifc, DeferredComponent::Ifc),
            (self.credential_anchor, DeferredComponent::CredentialAnchor),
            (self.ca_signer, DeferredComponent::CaSigner),
            (self.grpc, DeferredComponent::GrpcProxy),
            // Kept only as a compatibility trap: backend selection is explicit in `network`.
            (self.cgroup_bpf, DeferredComponent::CgroupBpfBackend),
        ]
        .into_iter()
        .filter_map(|(enabled, component)| enabled.then_some(component))
        .collect()
    }
}

/// One agent the runtime can execute.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// The read-only root filesystem the agent runs in.
    pub rootfs: PathBuf,
    /// The entry point and its arguments; the entry point is an absolute path inside the rootfs.
    pub command: Vec<String>,
    /// Extra environment variables.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The port the agent's HTTP listener binds inside its Execution.
    #[serde(default = "default_agent_port")]
    pub port: u16,
    /// The path the invocation is forwarded to.
    #[serde(default = "default_invoke_path")]
    pub invoke_path: String,
    /// The uid the agent runs as. Never 0.
    #[serde(default = "default_nobody")]
    pub uid: u32,
    /// The gid the agent runs as. Never 0.
    #[serde(default = "default_nobody")]
    pub gid: u32,
    /// How long one invocation may run, from creation to the end of the response, in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// How long the agent's listener may take to answer after start, in milliseconds.
    #[serde(default = "default_startup_timeout_ms")]
    pub startup_timeout_ms: u64,
    /// Resource limits.
    #[serde(default)]
    pub limits: Limits,
    /// Writable, size-limited tmpfs mounts; everything else is read-only.
    #[serde(default = "default_tmpfs")]
    pub tmpfs: Vec<TmpfsMount>,
}

/// Resource limits of one Execution.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// `pids.max` of the Execution cgroup.
    pub pids_max: u32,
    /// `memory.max` of the Execution cgroup, in bytes. Swap is disabled.
    pub memory_max_bytes: u64,
    /// `cpu.max` of the Execution cgroup, as quota and period in microseconds.
    pub cpu_max: Option<CpuMax>,
    /// `RLIMIT_NOFILE` of the agent.
    pub nofile: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pids_max: 128,
            memory_max_bytes: 256 << 20,
            cpu_max: Some(CpuMax {
                quota_us: 100_000,
                period_us: 100_000,
            }),
            nofile: 1024,
        }
    }
}

/// A CPU bandwidth limit.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuMax {
    /// Microseconds of CPU time per period.
    pub quota_us: u64,
    /// The period, in microseconds.
    pub period_us: u64,
}

/// A writable tmpfs mount inside the Execution.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TmpfsMount {
    /// Where it is mounted, as an absolute path inside the rootfs.
    pub path: String,
    /// Its size limit.
    pub size_bytes: u64,
}

fn default_agent_port() -> u16 {
    8080
}

fn default_invoke_path() -> String {
    "/".to_owned()
}

fn default_nobody() -> u32 {
    65534
}

fn default_timeout_ms() -> u64 {
    30_000
}

fn default_startup_timeout_ms() -> u64 {
    5_000
}

fn default_tmpfs() -> Vec<TmpfsMount> {
    vec![TmpfsMount {
        path: "/tmp".to_owned(),
        size_bytes: 16 << 20,
    }]
}

/// Why a configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file could not be read.
    Read(String),
    /// The YAML is malformed or carries an unknown field.
    Parse(String),
    /// A value is out of bounds or contradicts another.
    Invalid(String),
    /// A component of a later phase was enabled.
    Unavailable(Unavailable),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(reason) => write!(formatter, "cannot read the configuration: {reason}"),
            Self::Parse(reason) => write!(formatter, "the configuration is malformed: {reason}"),
            Self::Invalid(reason) => write!(formatter, "the configuration is invalid: {reason}"),
            Self::Unavailable(reason) => write!(formatter, "the configuration asks for {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads, parses and validates a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| ConfigError::Read(format!("{}: {error}", path.display())))?;

        Self::from_yaml(&text)
    }

    /// Parses and validates a configuration.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let config: Self =
            serde_norway::from_str(text).map_err(|error| ConfigError::Parse(error.to_string()))?;
        config.validate()?;

        Ok(config)
    }

    /// The Execution address pool.
    pub fn pool(&self) -> Result<ExecutionPool, ConfigError> {
        ExecutionPool::new(self.network.execution_pool)
            .map_err(|error| ConfigError::Invalid(error.to_string()))
    }

    /// Every structural check that does not need the host.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // A later-phase component is refused by the component itself, so the reason is its own.
        if let Some(component) = self.features.requested().into_iter().next() {
            component.activate().map_err(ConfigError::Unavailable)?;
        }

        self.validate_runtime()?;
        self.validate_ingress()?;
        self.validate_network()?;
        self.validate_egress()?;
        if let Some(root) = &self.cgroup.root {
            require_absolute("cgroup.root", root)?;
        }
        self.validate_cgroup_bpf()?;
        if self.agents.is_empty() {
            return invalid("at least one agent must be configured");
        }
        for (name, agent) in &self.agents {
            validate_agent(name, agent)?;
        }

        Ok(())
    }

    fn validate_runtime(&self) -> Result<(), ConfigError> {
        let runtime = &self.runtime;
        require_absolute("runtime.state_dir", &runtime.state_dir)?;
        require_absolute("runtime.runc", &runtime.runc)?;
        require_absolute("runtime.nft", &runtime.nft)?;
        require_absolute("runtime.ip", &runtime.ip)?;
        require_absolute("runtime.bpftool", &runtime.bpftool)?;
        if runtime.uid == 0 || runtime.gid == 0 {
            return invalid("runtime.uid and runtime.gid must name an unprivileged user, not root");
        }
        if runtime.max_concurrency == 0 {
            return invalid("runtime.max_concurrency must be at least 1");
        }
        if runtime.cleanup_failure_threshold == 0 {
            return invalid("runtime.cleanup_failure_threshold must be at least 1");
        }
        if runtime.teardown_timeout_ms == 0 {
            return invalid("runtime.teardown_timeout_ms must be positive");
        }

        Ok(())
    }

    fn validate_ingress(&self) -> Result<(), ConfigError> {
        if self.ingress.max_request_bytes == 0 || self.ingress.max_response_bytes == 0 {
            return invalid("ingress byte limits must be positive");
        }

        Ok(())
    }

    fn validate_network(&self) -> Result<(), ConfigError> {
        let network = &self.network;
        let pool = self.pool()?;
        let proxy = IpAddr::V4(network.proxy_address);
        if network.proxy_address.is_unspecified()
            || network.proxy_address.is_loopback()
            || network.proxy_address.is_broadcast()
            || network.proxy_address.is_multicast()
        {
            return invalid("network.proxy_address must be a unicast, non-loopback address");
        }
        if pool.contains(proxy) {
            return invalid("network.proxy_address must lie outside network.execution_pool");
        }
        if network.proxy_port == 0 {
            return invalid("network.proxy_port must be set");
        }
        // Execution slots are never reused while quarantined, so the pool must outlast the
        // concurrency limit plus the failures that stop admission.
        let needed = u64::from(self.runtime.max_concurrency)
            + u64::from(self.runtime.cleanup_failure_threshold);
        if u64::from(pool.slot_count()) < needed {
            return invalid(
                "network.execution_pool is too small for max_concurrency plus the cleanup-failure threshold",
            );
        }
        let pool_range = pool.range();
        for range in &network.internal_allow {
            if range.overlaps(&pool_range) {
                return invalid(format!(
                    "network.internal_allow entry {range} overlaps the Execution pool"
                ));
            }
            if range.contains(proxy) {
                return invalid(format!(
                    "network.internal_allow entry {range} contains the proxy address"
                ));
            }
        }

        Ok(())
    }

    fn validate_egress(&self) -> Result<(), ConfigError> {
        let egress = &self.egress;
        if egress.connect_timeout_ms == 0 || egress.idle_timeout_ms == 0 {
            return invalid("egress timeouts must be positive");
        }
        if egress.max_request_bytes == 0
            || egress.max_response_bytes == 0
            || egress.max_tunnel_bytes == 0
        {
            return invalid("egress byte limits must be positive");
        }
        for rule in &egress.allow {
            if rule.host.is_empty() {
                return invalid("an egress.allow entry has an empty host");
            }
            if rule.ports.is_empty() || rule.ports.contains(&0) {
                return invalid(format!(
                    "egress.allow entry `{}` needs one or more non-zero ports",
                    rule.host
                ));
            }
        }

        Ok(())
    }

    fn validate_cgroup_bpf(&self) -> Result<(), ConfigError> {
        let bpf = &self.cgroup_bpf;
        require_absolute("cgroup_bpf.pin_root", &bpf.pin_root)?;
        if bpf.max_tracked_sockets == 0 || bpf.max_tracked_sockets > 262_144 {
            return invalid(
                "cgroup_bpf.max_tracked_sockets must be between 1 and the implementation ceiling 262144",
            );
        }
        if bpf.resolve_timeout_ms == 0 || bpf.resolve_timeout_ms > 2_000 {
            return invalid("cgroup_bpf.resolve_timeout_ms must be between 1 and 2000");
        }
        if bpf.ring_buffer_bytes < 4096
            || bpf.ring_buffer_bytes > 16 * 1024 * 1024
            || !bpf.ring_buffer_bytes.is_power_of_two()
        {
            return invalid(
                "cgroup_bpf.ring_buffer_bytes must be a power of two between 4096 and 16777216",
            );
        }
        let policy_capacity = self
            .runtime
            .max_concurrency
            .checked_add(self.runtime.cleanup_failure_threshold)
            .ok_or_else(|| {
                ConfigError::Invalid(
                    "max_concurrency plus cleanup_failure_threshold overflows".to_owned(),
                )
            })?;
        if policy_capacity == 0 {
            return invalid("the cgroup-BPF policy capacity must be positive");
        }
        if policy_capacity > 65_536 {
            return invalid(
                "the cgroup-BPF policy capacity exceeds the implementation ceiling 65536",
            );
        }
        Ok(())
    }
}

fn validate_agent(name: &str, agent: &AgentConfig) -> Result<(), ConfigError> {
    let valid_name = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid_name {
        return invalid(format!(
            "agent name `{name}` must be 1-32 characters of [a-z0-9-]"
        ));
    }
    require_absolute(&format!("agents.{name}.rootfs"), &agent.rootfs)?;
    match agent.command.first() {
        Some(entry) if entry.starts_with('/') => {}
        _ => {
            return invalid(format!(
                "agents.{name}.command must start with an absolute path inside the rootfs"
            ));
        }
    }
    if agent.port == 0 {
        return invalid(format!("agents.{name}.port must be set"));
    }
    if !agent.invoke_path.starts_with('/') {
        return invalid(format!("agents.{name}.invoke_path must start with `/`"));
    }
    if agent.uid == 0 || agent.gid == 0 {
        return invalid(format!("agents.{name} must not run as root"));
    }
    if agent.timeout_ms == 0 || agent.startup_timeout_ms == 0 {
        return invalid(format!("agents.{name} timeouts must be positive"));
    }
    for key in agent.env.keys() {
        if RESERVED_ENV.contains(&key.as_str()) {
            return invalid(format!(
                "agents.{name}.env may not set `{key}`; Soglia sets it"
            ));
        }
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return invalid(format!("agents.{name}.env has an invalid variable name"));
        }
    }
    let limits = &agent.limits;
    if limits.pids_max == 0 || limits.memory_max_bytes == 0 || limits.nofile == 0 {
        return invalid(format!("agents.{name}.limits must all be positive"));
    }
    if let Some(cpu) = limits.cpu_max
        && (cpu.quota_us == 0 || cpu.period_us == 0)
    {
        return invalid(format!("agents.{name}.limits.cpu_max must be positive"));
    }
    let mut seen = BTreeSet::new();
    for mount in &agent.tmpfs {
        if !mount.path.starts_with('/') || mount.path == "/" || mount.path.contains("..") {
            return invalid(format!(
                "agents.{name}.tmpfs path `{}` must be an absolute path below `/`",
                mount.path
            ));
        }
        if mount.size_bytes == 0 {
            return invalid(format!("agents.{name}.tmpfs `{}` needs a size", mount.path));
        }
        if !seen.insert(mount.path.as_str()) {
            return invalid(format!("agents.{name}.tmpfs mounts `{}` twice", mount.path));
        }
    }

    Ok(())
}

fn require_absolute(field: &str, path: &Path) -> Result<(), ConfigError> {
    if path.is_absolute() {
        Ok(())
    } else {
        invalid(format!("{field} must be an absolute path"))
    }
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(reason.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
runtime:
  uid: 990
  gid: 990
agents:
  echo:
    rootfs: /var/lib/soglia/rootfs/echo
    command: ["/agent"]
"#;

    fn with(extra: &str) -> Result<Config, ConfigError> {
        Config::from_yaml(&format!("{MINIMAL}{extra}"))
    }

    #[test]
    fn a_minimal_configuration_takes_the_defaults() {
        let config = Config::from_yaml(MINIMAL).unwrap();
        assert_eq!(config.runtime.max_concurrency, 4);
        assert_eq!(config.runtime.cleanup_failure_threshold, 1);
        assert_eq!(config.runtime.bpftool, PathBuf::from("/usr/sbin/bpftool"));
        assert_eq!(config.network.proxy_port, 15001);
        assert_eq!(config.network.backend, NetworkBackend::NetnsNft);
        let echo = &config.agents["echo"];
        assert_eq!(echo.port, 8080);
        assert_eq!(echo.uid, 65534);
        assert_eq!(echo.limits.pids_max, 128);
        assert_eq!(echo.tmpfs[0].path, "/tmp");
        assert!(config.egress.allow.is_empty());
    }

    #[test]
    fn unknown_fields_are_refused() {
        let refused = with("unexpected: true\n").unwrap_err();
        assert!(matches!(refused, ConfigError::Parse(_)), "{refused}");

        let nested = Config::from_yaml(
            "runtime:\n  uid: 990\n  gid: 990\n  max_concurency: 2\nagents:\n  echo:\n    rootfs: /r\n    command: [\"/a\"]\n",
        )
        .unwrap_err();
        assert!(matches!(nested, ConfigError::Parse(_)), "{nested}");
    }

    #[test]
    fn enabling_a_later_phase_component_is_refused_by_that_component() {
        for (feature, component, unsupported) in [
            ("trust_fabric", DeferredComponent::TrustFabricClient, false),
            ("pic", DeferredComponent::PicContinuation, false),
            ("ifc", DeferredComponent::Ifc, false),
            (
                "credential_anchor",
                DeferredComponent::CredentialAnchor,
                false,
            ),
            ("ca_signer", DeferredComponent::CaSigner, false),
            ("grpc", DeferredComponent::GrpcProxy, false),
            ("cgroup_bpf", DeferredComponent::CgroupBpfBackend, true),
        ] {
            let refused = with(&format!("features:\n  {feature}: true\n")).unwrap_err();
            let expected = if unsupported {
                Unavailable::UnsupportedInThisBuild(component)
            } else {
                Unavailable::DisabledInPhase0(component)
            };
            assert_eq!(refused, ConfigError::Unavailable(expected), "{feature}");
        }
    }

    #[test]
    fn the_runtime_never_runs_as_root() {
        let refused =
            Config::from_yaml("agents:\n  echo:\n    rootfs: /r\n    command: [\"/a\"]\n")
                .unwrap_err();
        assert!(matches!(refused, ConfigError::Invalid(_)), "{refused}");
    }

    #[test]
    fn an_agent_never_runs_as_root() {
        let refused = Config::from_yaml(
            "runtime:\n  uid: 990\n  gid: 990\nagents:\n  echo:\n    rootfs: /r\n    command: [\"/a\"]\n    uid: 0\n",
        )
        .unwrap_err();
        assert!(matches!(refused, ConfigError::Invalid(_)), "{refused}");
    }

    #[test]
    fn the_proxy_address_is_outside_the_pool() {
        let refused = with("network:\n  proxy_address: 10.201.0.9\n").unwrap_err();
        assert!(refused.to_string().contains("outside"), "{refused}");
    }

    #[test]
    fn internal_ranges_may_not_open_the_pool_or_the_proxy() {
        let pool = with("network:\n  internal_allow: [\"10.0.0.0/8\"]\n").unwrap_err();
        assert!(pool.to_string().contains("pool"), "{pool}");

        let proxy = with(
            "network:\n  execution_pool: 10.201.0.0/16\n  proxy_address: 192.168.7.1\n  internal_allow: [\"192.168.0.0/16\"]\n",
        )
        .unwrap_err();
        assert!(proxy.to_string().contains("proxy"), "{proxy}");

        assert!(with("network:\n  internal_allow: [\"172.16.0.0/12\"]\n").is_ok());
    }

    #[test]
    fn the_pool_outlasts_the_concurrency_limit() {
        let refused = with("network:\n  execution_pool: 10.201.0.0/30\n").unwrap_err();
        assert!(refused.to_string().contains("too small"), "{refused}");
    }

    #[test]
    fn soglia_owns_the_proxy_variables() {
        let refused = Config::from_yaml(
            "runtime:\n  uid: 990\n  gid: 990\nagents:\n  echo:\n    rootfs: /r\n    command: [\"/a\"]\n    env:\n      HTTPS_PROXY: http://elsewhere\n",
        )
        .unwrap_err();
        assert!(refused.to_string().contains("HTTPS_PROXY"), "{refused}");
    }

    #[test]
    fn paths_and_names_are_checked() {
        for agent in [
            "  Echo:\n    rootfs: /r\n    command: [\"/a\"]\n",
            "  echo:\n    rootfs: relative\n    command: [\"/a\"]\n",
            "  echo:\n    rootfs: /r\n    command: [\"a\"]\n",
            "  echo:\n    rootfs: /r\n    command: []\n",
            "  echo:\n    rootfs: /r\n    command: [\"/a\"]\n    invoke_path: run\n",
            "  echo:\n    rootfs: /r\n    command: [\"/a\"]\n    tmpfs: [{path: /, size_bytes: 1}]\n",
            "  echo:\n    rootfs: /r\n    command: [\"/a\"]\n    tmpfs: [{path: /tmp/../etc, size_bytes: 1}]\n",
        ] {
            let text = format!("runtime:\n  uid: 990\n  gid: 990\nagents:\n{agent}");
            assert!(Config::from_yaml(&text).is_err(), "{agent}");
        }
    }

    #[test]
    fn egress_rules_need_ports() {
        assert!(with("egress:\n  allow:\n    - host: api.example.com\n      ports: []\n").is_err());
        assert!(
            with("egress:\n  allow:\n    - host: api.example.com\n      ports: [0]\n").is_err()
        );
        let config =
            with("egress:\n  allow:\n    - host: api.example.com\n      ports: [443]\n").unwrap();
        assert_eq!(config.egress.allow[0].ports, vec![443]);
    }

    #[test]
    fn cgroup_bpf_limits_are_bounded_and_explicit_selection_is_accepted() {
        let config = with("network:\n  backend: cgroup-bpf\n").unwrap();
        assert_eq!(config.network.backend, NetworkBackend::CgroupBpf);

        let mut too_many_sockets = Config::from_yaml(MINIMAL).unwrap();
        too_many_sockets.cgroup_bpf.max_tracked_sockets = 262_145;
        assert!(too_many_sockets.validate().is_err());

        let mut too_large_ring = Config::from_yaml(MINIMAL).unwrap();
        too_large_ring.cgroup_bpf.ring_buffer_bytes = 32 * 1024 * 1024;
        assert!(too_large_ring.validate().is_err());

        let mut too_many_policies = Config::from_yaml(MINIMAL).unwrap();
        too_many_policies.runtime.max_concurrency = 65_536;
        assert!(too_many_policies.validate().is_err());
    }
}
