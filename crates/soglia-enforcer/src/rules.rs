// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The nftables policy of the Phase-0 network model, as native `nft -f -` batches.
//!
//! Two tables, both owned by the enforcer:
//!
//! * `inet soglia` inside each Execution network namespace. The namespace is fresh and holds nothing
//!   else, so this table can use `accept`: default drop, loopback, replies, new TCP out only to the
//!   egress proxy, new TCP in only from the host end to the agent listener. It dies with the
//!   namespace.
//! * `inet soglia_host` on the host. It shares the host with other people's tables, and an `accept`
//!   there does not stop another table from dropping the packet — but a `drop` there is final. So it
//!   holds only drop rules. Its chains are static; each Execution adds and removes only its own set
//!   elements, so no Execution's change can touch another's policy.
//!
//! Every batch is applied with one `nft -f -`, so each policy transition is atomic.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use soglia_core::id::{HOST_VETH_PREFIX, ResourceTag};
use soglia_core::net::SlotAddresses;

/// The host table's name.
pub const HOST_TABLE: &str = "soglia_host";
/// The Execution table's name, inside each Execution network namespace.
pub const EXECUTION_TABLE: &str = "soglia";

/// The egress proxy endpoint every Execution may reach, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyEndpoint {
    /// The proxy address, on the host dummy interface.
    pub address: Ipv4Addr,
    /// The proxy port.
    pub port: u16,
}

/// The host table, created once at startup when no Execution is live.
///
/// `supervisor_uid` is the only user allowed to open connections toward an Execution: that is the
/// trusted ingress direction, and the Supervisor is the only process meant to use it.
pub fn host_table(proxy: ProxyEndpoint, supervisor_uid: u32) -> String {
    let wildcard = format!("{HOST_VETH_PREFIX}*");
    let ProxyEndpoint { address, port } = proxy;
    let mut batch = String::new();
    // `add` then `delete` makes the delete safe when the table is absent, and the whole batch is one
    // transaction, so there is no moment without the table once it has been installed.
    let _ = writeln!(batch, "add table inet {HOST_TABLE}");
    let _ = writeln!(batch, "delete table inet {HOST_TABLE}");
    let _ = write!(
        batch,
        r#"table inet {HOST_TABLE} {{
    set exec_src {{
        type ifname . ipv4_addr
    }}
    set exec_ingress {{
        type ipv4_addr . inet_service
    }}
    chain prerouting {{
        type filter hook prerouting priority raw; policy accept;
        iifname "{wildcard}" meta nfproto ipv6 drop
        iifname "{wildcard}" iifname . ip saddr != @exec_src drop
    }}
    chain input {{
        type filter hook input priority filter - 10; policy accept;
        iifname "{wildcard}" ct state invalid drop
        iifname "{wildcard}" ct state new meta l4proto != tcp drop
        iifname "{wildcard}" ct state new ip daddr != {address} drop
        iifname "{wildcard}" ct state new tcp dport != {port} drop
        iifname != "{wildcard}" ip daddr {address} drop
    }}
    chain forward {{
        type filter hook forward priority filter - 10; policy accept;
        iifname "{wildcard}" drop
        oifname "{wildcard}" drop
    }}
    chain output {{
        type filter hook output priority filter - 10; policy accept;
        oifname "{wildcard}" meta nfproto ipv6 drop
        oifname "{wildcard}" ct state invalid drop
        oifname "{wildcard}" ct state new meta l4proto != tcp drop
        oifname "{wildcard}" ct state new meta skuid != {supervisor_uid} drop
        oifname "{wildcard}" ct state new ip daddr . tcp dport != @exec_ingress drop
    }}
}}
"#
    );

    batch
}

/// The set elements that make one Execution's link usable from the host side.
pub fn bind_elements(tag: &ResourceTag, slot: &SlotAddresses, agent_port: u16) -> String {
    let veth = tag.host_veth();
    let execution = slot.execution;
    format!(
        "add element inet {HOST_TABLE} exec_src {{ \"{veth}\" . {execution} }}\n\
         add element inet {HOST_TABLE} exec_ingress {{ {execution} . {agent_port} }}\n"
    )
}

/// Removes one Execution's set elements, whether or not they are still there.
///
/// `delete element` fails on an absent element, so each is added first in the same transaction:
/// the batch is idempotent and still touches nothing but this Execution's own elements.
pub fn unbind_elements(tag: &ResourceTag, slot: &SlotAddresses, agent_port: u16) -> String {
    let add = bind_elements(tag, slot, agent_port);
    let delete = add.replace("add element", "delete element");
    format!("{add}{delete}")
}

/// The Execution table, inside the Execution network namespace.
pub fn execution_table(slot: &SlotAddresses, agent_port: u16, proxy: ProxyEndpoint) -> String {
    let SlotAddresses { host, execution } = *slot;
    let ProxyEndpoint { address, port } = proxy;
    format!(
        r#"table inet {EXECUTION_TABLE} {{
    chain input {{
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        ip saddr {host} ip daddr {execution} tcp dport {agent_port} ct state new accept
    }}
    chain output {{
        type filter hook output priority filter; policy drop;
        oif "lo" accept
        ct state established,related accept
        ip daddr {address} tcp dport {port} ct state new accept
    }}
    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}
}}
"#
    )
}

/// Denies every packet of the Execution: the rules go, the drop policies stay.
pub fn freeze_execution() -> String {
    format!("flush table inet {EXECUTION_TABLE}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag() -> ResourceTag {
        "0123456789".parse().unwrap()
    }

    fn slot() -> SlotAddresses {
        SlotAddresses {
            host: "10.201.0.0".parse().unwrap(),
            execution: "10.201.0.1".parse().unwrap(),
        }
    }

    fn proxy() -> ProxyEndpoint {
        ProxyEndpoint {
            address: "10.200.255.1".parse().unwrap(),
            port: 15001,
        }
    }

    #[test]
    fn the_host_table_holds_only_drops() {
        let batch = host_table(proxy(), 990);
        for line in batch.lines().map(str::trim) {
            let is_rule = line.contains("iifname") || line.contains("oifname");
            if is_rule {
                assert!(
                    line.ends_with(" drop"),
                    "a host rule must end in drop: {line}"
                );
            }
            assert!(
                !line.contains("accept") || line.contains("policy accept"),
                "{line}"
            );
        }
        assert!(batch.contains("iifname \"sgh-*\" iifname . ip saddr != @exec_src drop"));
        assert!(batch.contains("ct state new ip daddr != 10.200.255.1 drop"));
        assert!(batch.contains("ct state new tcp dport != 15001 drop"));
        assert!(batch.contains("meta skuid != 990 drop"));
        assert!(batch.contains("iifname \"sgh-*\" drop\n        oifname \"sgh-*\" drop"));
        assert!(batch.contains("iifname \"sgh-*\" meta nfproto ipv6 drop"));
    }

    #[test]
    fn the_host_table_replaces_itself_in_one_transaction() {
        let batch = host_table(proxy(), 990);
        let lines: Vec<&str> = batch.lines().collect();
        assert_eq!(lines[0], "add table inet soglia_host");
        assert_eq!(lines[1], "delete table inet soglia_host");
        assert_eq!(lines[2], "table inet soglia_host {");
    }

    #[test]
    fn the_execution_table_admits_only_the_proxy_out_and_the_host_end_in() {
        let batch = execution_table(&slot(), 8080, proxy());
        assert_eq!(batch.matches("policy drop").count(), 3);
        assert!(batch.contains("ip daddr 10.200.255.1 tcp dport 15001 ct state new accept"));
        assert!(batch.contains(
            "ip saddr 10.201.0.0 ip daddr 10.201.0.1 tcp dport 8080 ct state new accept"
        ));
        // No IPv6 rule accepts anything: IPv6 falls to the drop policies.
        assert!(!batch.contains("ip6"));
        let accepts: Vec<&str> = batch
            .lines()
            .filter(|line| line.contains(" accept"))
            .collect();
        assert_eq!(accepts.len(), 6, "{accepts:?}");
    }

    #[test]
    fn set_elements_are_keyed_to_the_execution_veth_and_address() {
        assert_eq!(
            bind_elements(&tag(), &slot(), 8080),
            "add element inet soglia_host exec_src { \"sgh-0123456789\" . 10.201.0.1 }\n\
             add element inet soglia_host exec_ingress { 10.201.0.1 . 8080 }\n"
        );
    }

    #[test]
    fn unbinding_is_idempotent_and_touches_only_this_execution() {
        let batch = unbind_elements(&tag(), &slot(), 8080);
        let lines: Vec<&str> = batch.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("add element") && lines[1].starts_with("add element"));
        assert!(lines[2].starts_with("delete element") && lines[3].starts_with("delete element"));
        assert!(lines.iter().all(|line| line.contains("10.201.0.1")));
        assert!(!batch.contains("flush") && !batch.contains("delete table"));
    }

    #[test]
    fn freezing_keeps_the_drop_policies() {
        assert_eq!(freeze_execution(), "flush table inet soglia\n");
    }
}
