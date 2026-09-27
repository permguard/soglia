// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The egress destination policy.
//!
//! An allow-listed host name is not enough to connect: the name decides whether the destination
//! may be asked for at all, and the addresses it resolves to decide whether it may be reached. The
//! proxy resolves once and connects to an address this policy already validated, so there is no
//! second resolution between the decision and `connect()`:
//!
//! ```text
//! canonicalize host -> check host + port -> resolve once -> validate every candidate
//!   -> any candidate forbidden: deny the whole destination
//!   -> otherwise connect to a validated SocketAddr
//! ```
//!
//! Denying the whole destination when one candidate is forbidden is deliberately conservative for
//! V0.1: a name that resolves to both a public and a loopback address is not a name to trust.

pub mod address;
pub mod host;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use soglia_core::config::{EgressConfig, NetworkConfig};
use soglia_core::net::{Cidr, ExecutionPool};

pub use address::{AddressClass, classify};
pub use host::{Host, InvalidHost, canonicalize};

/// A destination the policy allows the Execution to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The canonical host.
    pub host: Host,
    /// The port.
    pub port: u16,
}

/// Why a destination was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The host is malformed or ambiguous.
    InvalidHost(InvalidHost),
    /// The host and port are not on the allow-list.
    NotAllowed {
        /// The canonical host.
        host: String,
        /// The port.
        port: u16,
    },
    /// The host resolved to nothing.
    NoAddresses {
        /// The canonical host.
        host: String,
    },
    /// The host resolved to an address the proxy may not reach, so the whole destination is refused.
    ForbiddenAddress {
        /// The canonical host.
        host: String,
        /// The offending address.
        address: IpAddr,
        /// Why it is forbidden.
        reason: String,
    },
}

impl fmt::Display for Denial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost(invalid) => write!(formatter, "{invalid}"),
            Self::NotAllowed { host, port } => {
                write!(formatter, "{host}:{port} is not an allowed destination")
            }
            Self::NoAddresses { host } => write!(formatter, "{host} resolved to no address"),
            Self::ForbiddenAddress {
                host,
                address,
                reason,
            } => write!(
                formatter,
                "{host} resolved to {address}, which is {reason}; the destination is refused"
            ),
        }
    }
}

impl std::error::Error for Denial {}

/// Why a policy could not be built from its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "the egress policy is invalid: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

/// What the egress proxy may connect to.
#[derive(Debug, Clone)]
pub struct DestinationPolicy {
    allowed: BTreeMap<Host, BTreeSet<u16>>,
    internal_allow: Vec<Cidr>,
    pool: ExecutionPool,
    control: Vec<IpAddr>,
    /// Test builds only: lets the proxy tests reach a destination they host on loopback. The field
    /// does not exist outside `cfg(test)`, so no shipped binary can carry this exception.
    #[cfg(test)]
    loopback_for_tests: bool,
}

impl DestinationPolicy {
    /// Builds the policy.
    ///
    /// `control` lists Soglia's own host and control addresses, which are refused like the
    /// Execution pool whatever the configuration says.
    pub fn new(
        egress: &EgressConfig,
        network: &NetworkConfig,
        control: Vec<IpAddr>,
    ) -> Result<Self, PolicyError> {
        let pool = ExecutionPool::new(network.execution_pool)
            .map_err(|error| PolicyError(error.to_string()))?;

        let mut allowed: BTreeMap<Host, BTreeSet<u16>> = BTreeMap::new();
        for rule in &egress.allow {
            let host = canonicalize(&rule.host).map_err(|error| PolicyError(error.to_string()))?;
            allowed
                .entry(host)
                .or_default()
                .extend(rule.ports.iter().copied());
        }

        let forbidden = address::forbidden_ranges();
        for range in &network.internal_allow {
            if let Some((_, reason)) = forbidden
                .iter()
                .find(|(blocked, _)| blocked.overlaps(range))
            {
                return Err(PolicyError(format!(
                    "network.internal_allow entry {range} overlaps {reason}, which cannot be allowed"
                )));
            }
        }

        let mut control = control;
        control.push(IpAddr::V4(network.proxy_address));

        Ok(Self {
            allowed,
            internal_allow: network.internal_allow.clone(),
            pool,
            control,
            #[cfg(test)]
            loopback_for_tests: false,
        })
    }

    /// Test builds only: the same policy, able to reach loopback destinations.
    #[cfg(test)]
    pub(crate) fn allowing_loopback_for_tests(mut self) -> Self {
        self.loopback_for_tests = true;
        self
    }

    /// Checks the host and port an Execution asked for against the allow-list.
    pub fn authorize(&self, presented_host: &str, port: u16) -> Result<Target, Denial> {
        let host = canonicalize(presented_host).map_err(Denial::InvalidHost)?;
        let allowed = self
            .allowed
            .get(&host)
            .is_some_and(|ports| ports.contains(&port));
        if !allowed {
            return Err(Denial::NotAllowed {
                host: host.to_string(),
                port,
            });
        }

        Ok(Target { host, port })
    }

    /// Validates every address `target` resolved to and returns the ones to connect to.
    ///
    /// For an IP-literal target, pass that address. If any candidate is forbidden the whole
    /// destination is refused. Mapped IPv6 addresses come back as the IPv4 address they carry.
    pub fn validate(
        &self,
        target: &Target,
        resolved: &[IpAddr],
    ) -> Result<Vec<SocketAddr>, Denial> {
        let host = target.host.to_string();
        if resolved.is_empty() {
            return Err(Denial::NoAddresses { host });
        }

        let mut candidates: Vec<SocketAddr> = Vec::with_capacity(resolved.len());
        for &address in resolved {
            let address = address.to_canonical();
            if let Err(reason) = self.check_address(address) {
                return Err(Denial::ForbiddenAddress {
                    host,
                    address,
                    reason,
                });
            }
            let candidate = SocketAddr::new(address, target.port);
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }

        Ok(candidates)
    }

    fn check_address(&self, address: IpAddr) -> Result<(), String> {
        #[cfg(test)]
        if self.loopback_for_tests && address.is_loopback() {
            return Ok(());
        }
        if self.pool.contains(address) {
            return Err("in the Execution address pool".to_owned());
        }
        if self.control.contains(&address) {
            return Err("a Soglia control address".to_owned());
        }
        match classify(address) {
            AddressClass::Global => Ok(()),
            AddressClass::Forbidden(reason) => Err(reason.to_owned()),
            AddressClass::Internal(reason) => {
                if self
                    .internal_allow
                    .iter()
                    .any(|range| range.contains(address))
                {
                    Ok(())
                } else {
                    Err(format!("{reason}, not listed in network.internal_allow"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soglia_core::config::EgressRule;

    fn policy(internal_allow: &[&str]) -> DestinationPolicy {
        let egress = EgressConfig {
            allow: vec![
                EgressRule {
                    host: "API.example.com".into(),
                    ports: vec![443],
                },
                EgressRule {
                    host: "api.example.com.".into(),
                    ports: vec![8443],
                },
                EgressRule {
                    host: "10.20.0.5".into(),
                    ports: vec![80],
                },
            ],
            ..EgressConfig::default()
        };
        let network = NetworkConfig {
            internal_allow: internal_allow
                .iter()
                .map(|range| range.parse().unwrap())
                .collect(),
            ..NetworkConfig::default()
        };

        DestinationPolicy::new(&egress, &network, vec!["192.168.50.10".parse().unwrap()]).unwrap()
    }

    fn addresses(list: &[&str]) -> Vec<IpAddr> {
        list.iter()
            .map(|address| address.parse().unwrap())
            .collect()
    }

    #[test]
    fn the_allow_list_matches_canonical_host_and_exact_port() {
        let policy = policy(&[]);
        assert!(policy.authorize("api.example.com", 443).is_ok());
        assert!(policy.authorize("Api.Example.Com.", 8443).is_ok());
        assert!(matches!(
            policy.authorize("api.example.com", 80),
            Err(Denial::NotAllowed { .. })
        ));
        assert!(matches!(
            policy.authorize("other.example.com", 443),
            Err(Denial::NotAllowed { .. })
        ));
        assert!(matches!(
            policy.authorize("127.1", 443),
            Err(Denial::InvalidHost(_))
        ));
    }

    #[test]
    fn global_candidates_are_returned_in_order_without_duplicates() {
        let policy = policy(&[]);
        let target = policy.authorize("api.example.com", 443).unwrap();
        let candidates = policy
            .validate(
                &target,
                &addresses(&["93.184.216.34", "2606:2800:220:1::1", "93.184.216.34"]),
            )
            .unwrap();
        assert_eq!(
            candidates,
            vec![
                "93.184.216.34:443".parse().unwrap(),
                "[2606:2800:220:1::1]:443".parse().unwrap()
            ]
        );
    }

    #[test]
    fn one_forbidden_candidate_refuses_the_whole_destination() {
        let policy = policy(&[]);
        let target = policy.authorize("api.example.com", 443).unwrap();
        for bad in [
            "127.0.0.1",
            "169.254.169.254",
            "10.201.0.3",
            "10.200.255.1",
            "192.168.50.10",
            "10.1.1.1",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.201.0.3",
        ] {
            let refused = policy
                .validate(&target, &addresses(&["93.184.216.34", bad]))
                .unwrap_err();
            assert!(
                matches!(refused, Denial::ForbiddenAddress { .. }),
                "{bad}: {refused}"
            );
        }
        assert!(matches!(
            policy.validate(&target, &[]),
            Err(Denial::NoAddresses { .. })
        ));
    }

    #[test]
    fn internal_ranges_open_only_when_configured() {
        let closed = policy(&[]);
        let target = closed.authorize("10.20.0.5", 80).unwrap();
        assert!(
            closed
                .validate(&target, &addresses(&["10.20.0.5"]))
                .is_err()
        );

        let open = policy(&["10.20.0.0/16"]);
        let target = open.authorize("10.20.0.5", 80).unwrap();
        assert_eq!(
            open.validate(&target, &addresses(&["10.20.0.5"])).unwrap(),
            vec!["10.20.0.5:80".parse().unwrap()]
        );
        // Opening an internal range never opens the pool, the proxy or loopback.
        let target = open.authorize("api.example.com", 443).unwrap();
        assert!(open.validate(&target, &addresses(&["10.201.0.1"])).is_err());
        assert!(open.validate(&target, &addresses(&["127.0.0.1"])).is_err());
    }

    #[test]
    fn a_mapped_address_is_connected_as_ipv4() {
        let policy = policy(&[]);
        let target = policy.authorize("api.example.com", 443).unwrap();
        assert_eq!(
            policy
                .validate(&target, &addresses(&["::ffff:93.184.216.34"]))
                .unwrap(),
            vec!["93.184.216.34:443".parse().unwrap()]
        );
    }

    #[test]
    fn forbidden_ranges_cannot_be_allowed_by_configuration() {
        for range in [
            "127.0.0.0/8",
            "169.254.0.0/16",
            "fe80::/10",
            "0.0.0.0/0",
            "::/0",
        ] {
            let network = NetworkConfig {
                internal_allow: vec![range.parse().unwrap()],
                ..NetworkConfig::default()
            };
            assert!(
                DestinationPolicy::new(&EgressConfig::default(), &network, Vec::new()).is_err(),
                "{range}"
            );
        }
    }

    #[test]
    fn a_malformed_rule_host_is_a_configuration_error() {
        let egress = EgressConfig {
            allow: vec![EgressRule {
                host: "0x7f.1".into(),
                ports: vec![443],
            }],
            ..EgressConfig::default()
        };
        assert!(DestinationPolicy::new(&egress, &NetworkConfig::default(), Vec::new()).is_err());
    }
}
