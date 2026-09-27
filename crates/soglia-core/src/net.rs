// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Address ranges and the Execution address pool.
//!
//! Each Execution gets one point-to-point /31 link out of the pool: the even address is the host
//! end, the odd address is the Execution end. The Execution address is what the egress proxy sees
//! as the peer of every connection the Execution opens, so a slot is handed out again only after the
//! Execution that held it is completely destroyed.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A network range: an address with every host bit zero, and a prefix length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// A range from its network address and prefix length.
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, InvalidCidr> {
        let invalid = || InvalidCidr(format!("{network}/{prefix}"));
        let bits = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > bits {
            return Err(invalid());
        }
        // Strict: `10.0.0.1/8` is a typo for either `10.0.0.1/32` or `10.0.0.0/8`, and guessing
        // which one was meant is how an allow-list grows by accident.
        if mask(network, prefix) != network {
            return Err(invalid());
        }

        Ok(Self { network, prefix })
    }

    /// The network address.
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// `true` when `address` lies in this range. Addresses of the other family never do.
    pub fn contains(&self, address: IpAddr) -> bool {
        same_family(self.network, address) && mask(address, self.prefix) == self.network
    }

    /// `true` when the two ranges share at least one address.
    pub fn overlaps(&self, other: &Cidr) -> bool {
        if !same_family(self.network, other.network) {
            return false;
        }
        let shorter = self.prefix.min(other.prefix);

        mask(self.network, shorter) == mask(other.network, shorter)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

impl fmt::Debug for Cidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Cidr({self})")
    }
}

impl FromStr for Cidr {
    type Err = InvalidCidr;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidCidr(text.to_owned());
        let (address, prefix) = text.split_once('/').ok_or_else(invalid)?;
        // `u8::from_str` accepts a leading `+`; a prefix is digits and nothing else.
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let network = address.parse::<IpAddr>().map_err(|_| invalid())?;
        let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;

        Self::new(network, prefix)
    }
}

impl TryFrom<String> for Cidr {
    type Error = InvalidCidr;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<Cidr> for String {
    fn from(cidr: Cidr) -> Self {
        cidr.to_string()
    }
}

/// A string that is not a well-formed range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCidr(String);

impl fmt::Display for InvalidCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "`{}` is not a range in `address/prefix` form with every host bit zero",
            self.0
        )
    }
}

impl std::error::Error for InvalidCidr {}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn mask(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let kept = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4(Ipv4Addr::from(bits & kept))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let kept = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6(Ipv6Addr::from(bits & kept))
        }
    }
}

/// The two ends of one Execution's point-to-point link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotAddresses {
    /// The host end, on the Soglia-owned `sgh-*` interface.
    pub host: Ipv4Addr,
    /// The Execution end, on `eth0` inside the Execution network namespace.
    pub execution: Ipv4Addr,
}

/// The IPv4 range Execution links are carved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionPool {
    base: u32,
    slots: u32,
}

impl ExecutionPool {
    /// The pool over `range`, which must be IPv4 and hold at least two /31 slots.
    pub fn new(range: Cidr) -> Result<Self, InvalidCidr> {
        let IpAddr::V4(network) = range.network() else {
            return Err(InvalidCidr(format!(
                "{range}: the Execution pool is IPv4-only"
            )));
        };
        if range.prefix() > 30 {
            return Err(InvalidCidr(format!(
                "{range}: the Execution pool needs at least two /31 slots"
            )));
        }
        let addresses = 1_u64 << (32 - u32::from(range.prefix()));

        Ok(Self {
            base: u32::from(network),
            // At most 2^31 slots, which fits a u32.
            slots: u32::try_from(addresses / 2).unwrap_or(u32::MAX),
        })
    }

    /// How many Executions the pool can address at once.
    pub fn slot_count(&self) -> u32 {
        self.slots
    }

    /// The addresses of slot `index`, when the pool has one.
    pub fn slot(&self, index: u32) -> Option<SlotAddresses> {
        if index >= self.slots {
            return None;
        }
        let host = self.base + 2 * index;

        Some(SlotAddresses {
            host: Ipv4Addr::from(host),
            execution: Ipv4Addr::from(host + 1),
        })
    }

    /// `true` when `address` belongs to the pool, host or Execution end alike.
    pub fn contains(&self, address: IpAddr) -> bool {
        let IpAddr::V4(v4) = address else {
            return false;
        };
        let value = u32::from(v4);

        value >= self.base && u64::from(value - self.base) < 2 * u64::from(self.slots)
    }

    /// The pool as a range.
    pub fn range(&self) -> Cidr {
        let size = 2 * u64::from(self.slots);
        let prefix = 32 - size.trailing_zeros();
        Cidr {
            network: IpAddr::V4(Ipv4Addr::from(self.base)),
            prefix: u8::try_from(prefix).unwrap_or(32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    #[test]
    fn ranges_parse_strictly() {
        assert_eq!(cidr("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(cidr("fc00::/7").to_string(), "fc00::/7");
        for bad in [
            "10.0.0.1/8",
            "10.0.0.0",
            "10.0.0.0/33",
            "10.0.0.0/+8",
            "10.0.0.0/",
            "::/129",
            "example.com/8",
            " 10.0.0.0/8",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn containment_respects_family_and_prefix() {
        let private = cidr("10.0.0.0/8");
        assert!(private.contains("10.255.0.1".parse().unwrap()));
        assert!(!private.contains("11.0.0.1".parse().unwrap()));
        assert!(!private.contains("::ffff:10.0.0.1".parse().unwrap()));
        assert!(cidr("0.0.0.0/0").contains("203.0.113.9".parse().unwrap()));
        assert!(cidr("fe80::/10").contains("fe80::1".parse().unwrap()));
    }

    #[test]
    fn overlap_is_symmetric() {
        let wide = cidr("10.0.0.0/8");
        let narrow = cidr("10.201.0.0/16");
        let apart = cidr("192.168.0.0/16");
        assert!(wide.overlaps(&narrow) && narrow.overlaps(&wide));
        assert!(!wide.overlaps(&apart) && !apart.overlaps(&wide));
        assert!(!wide.overlaps(&cidr("::/0")));
    }

    #[test]
    fn the_pool_hands_out_point_to_point_pairs() {
        let pool = ExecutionPool::new(cidr("10.201.0.0/16")).unwrap();
        assert_eq!(pool.slot_count(), 32_768);
        assert_eq!(
            pool.slot(0).unwrap(),
            SlotAddresses {
                host: "10.201.0.0".parse().unwrap(),
                execution: "10.201.0.1".parse().unwrap(),
            }
        );
        assert_eq!(
            pool.slot(1).unwrap().execution,
            "10.201.0.3".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            pool.slot(32_767).unwrap().execution,
            "10.201.255.255".parse::<Ipv4Addr>().unwrap()
        );
        assert!(pool.slot(32_768).is_none());
        assert_eq!(pool.range(), cidr("10.201.0.0/16"));
    }

    #[test]
    fn pool_membership_covers_both_ends_and_nothing_else() {
        let pool = ExecutionPool::new(cidr("10.201.0.0/30")).unwrap();
        assert_eq!(pool.slot_count(), 2);
        for inside in ["10.201.0.0", "10.201.0.1", "10.201.0.2", "10.201.0.3"] {
            assert!(pool.contains(inside.parse().unwrap()), "{inside}");
        }
        for outside in ["10.201.0.4", "10.200.255.255", "::1"] {
            assert!(!pool.contains(outside.parse().unwrap()), "{outside}");
        }
    }

    #[test]
    fn the_pool_is_ipv4_with_room_for_two_executions() {
        assert!(ExecutionPool::new(cidr("fd00::/64")).is_err());
        assert!(ExecutionPool::new(cidr("10.201.0.0/31")).is_err());
    }
}
