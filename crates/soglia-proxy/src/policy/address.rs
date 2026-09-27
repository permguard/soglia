// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What kind of address a destination resolved to.
//!
//! Three outcomes. `Forbidden` ranges can never be reached through the egress proxy: loopback,
//! link-local and cloud metadata, multicast, documentation and reserved space, and the transition
//! formats that embed another address. `Internal` ranges are private networks: refused by default,
//! reachable only when configuration names them. Everything else is `Global`.
//!
//! IPv4-mapped IPv6 addresses are classified as the IPv4 address they carry, so `::ffff:127.0.0.1`
//! is loopback.

use std::net::IpAddr;

use soglia_core::net::Cidr;

/// The class of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// Publicly routable.
    Global,
    /// A private or internal range, reachable only when configuration allows it.
    Internal(&'static str),
    /// Never reachable through the egress proxy.
    Forbidden(&'static str),
}

const FORBIDDEN_V4: [(&str, &str); 12] = [
    ("0.0.0.0/8", "the unspecified \"this network\" range"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local, including cloud metadata"),
    ("192.0.0.0/24", "IETF protocol assignments"),
    ("192.0.2.0/24", "documentation"),
    ("192.88.99.0/24", "the deprecated 6to4 relay anycast range"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved space and broadcast"),
    // Duplicated narrower entries keep the reason precise where it matters most.
    ("169.254.169.254/32", "the cloud metadata service"),
    ("255.255.255.255/32", "broadcast"),
];

const INTERNAL_V4: [(&str, &str); 5] = [
    ("10.0.0.0/8", "private network"),
    ("172.16.0.0/12", "private network"),
    ("192.168.0.0/16", "private network"),
    ("100.64.0.0/10", "shared address space (CGNAT)"),
    ("198.18.0.0/15", "benchmarking network"),
];

const FORBIDDEN_V6: [(&str, &str); 14] = [
    ("::/128", "the unspecified address"),
    ("::1/128", "loopback"),
    ("::/96", "IPv4-compatible addresses"),
    ("64:ff9b::/96", "NAT64, which embeds an IPv4 address"),
    ("64:ff9b:1::/48", "local-use NAT64"),
    ("100::/64", "the discard prefix"),
    ("2001::/32", "Teredo, which embeds an IPv4 address"),
    ("2001:10::/28", "deprecated ORCHID"),
    ("2001:20::/28", "ORCHIDv2"),
    ("2001:db8::/32", "documentation"),
    ("2002::/16", "6to4, which embeds an IPv4 address"),
    ("3fff::/20", "documentation"),
    ("fe80::/10", "link-local"),
    ("fec0::/10", "deprecated site-local"),
];

const INTERNAL_V6: [(&str, &str); 1] = [(
    "fc00::/7",
    "unique local addresses, including cloud metadata",
)];

/// The IPv6 global unicast space; the rest of IPv6 is unallocated or special.
const GLOBAL_V6: &str = "2000::/3";

/// The ranges that can never be opened by configuration.
pub fn forbidden_ranges() -> Vec<(Cidr, &'static str)> {
    FORBIDDEN_V4
        .iter()
        .chain(FORBIDDEN_V6.iter())
        .map(|(range, reason)| (parse(range), *reason))
        .chain([(parse("ff00::/8"), "multicast")])
        .collect()
}

/// Classifies one address.
pub fn classify(address: IpAddr) -> AddressClass {
    let address = match address {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };

    match address {
        IpAddr::V4(_) => {
            // The narrow entries come last in the table but say more, so they are checked first.
            for (range, reason) in FORBIDDEN_V4.iter().rev() {
                if parse(range).contains(address) {
                    return AddressClass::Forbidden(reason);
                }
            }
            for (range, reason) in INTERNAL_V4 {
                if parse(range).contains(address) {
                    return AddressClass::Internal(reason);
                }
            }
            AddressClass::Global
        }
        IpAddr::V6(_) => {
            for (range, reason) in FORBIDDEN_V6 {
                if parse(range).contains(address) {
                    return AddressClass::Forbidden(reason);
                }
            }
            if parse("ff00::/8").contains(address) {
                return AddressClass::Forbidden("multicast");
            }
            for (range, reason) in INTERNAL_V6 {
                if parse(range).contains(address) {
                    return AddressClass::Internal(reason);
                }
            }
            if parse(GLOBAL_V6).contains(address) {
                AddressClass::Global
            } else {
                AddressClass::Forbidden("reserved or unallocated IPv6 space")
            }
        }
    }
}

/// The tables above are literals, and `every_table_entry_is_a_valid_range` proves each of them
/// parses, so a failure here is a programming error caught by the tests, never a run-time input.
fn parse(range: &str) -> Cidr {
    range
        .parse()
        .unwrap_or_else(|_| unreachable!("the address tables hold valid ranges"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(address: &str) -> AddressClass {
        classify(address.parse().unwrap())
    }

    #[test]
    fn every_table_entry_is_a_valid_range() {
        for (range, _) in FORBIDDEN_V4
            .iter()
            .chain(INTERNAL_V4.iter())
            .chain(FORBIDDEN_V6.iter())
            .chain(INTERNAL_V6.iter())
        {
            assert!(range.parse::<Cidr>().is_ok(), "{range}");
        }
        assert!(GLOBAL_V6.parse::<Cidr>().is_ok());
    }

    #[test]
    fn loopback_link_local_and_metadata_are_forbidden_in_both_families() {
        for address in [
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "169.254.1.1",
            "::1",
            "::",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                matches!(class(address), AddressClass::Forbidden(_)),
                "{address}"
            );
        }
        assert_eq!(
            class("169.254.169.254"),
            AddressClass::Forbidden("the cloud metadata service")
        );
    }

    #[test]
    fn private_ranges_are_internal_not_forbidden() {
        for address in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "fd00::1",
            "fd00:ec2::254",
        ] {
            assert!(
                matches!(class(address), AddressClass::Internal(_)),
                "{address}"
            );
        }
        assert_eq!(
            class("::ffff:10.0.0.1"),
            AddressClass::Internal("private network")
        );
    }

    #[test]
    fn embedded_address_formats_and_special_space_are_forbidden() {
        for address in [
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "2001:0:4136:e378::1",
            "::7f00:1",
            "ff02::1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.10",
            "2001:db8::1",
            "4000::1",
        ] {
            assert!(
                matches!(class(address), AddressClass::Forbidden(_)),
                "{address}"
            );
        }
    }

    #[test]
    fn public_addresses_are_global() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert_eq!(class(address), AddressClass::Global, "{address}");
        }
    }
}
