// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Canonical destination hosts.
//!
//! An allow-list compares names, so every name must have exactly one spelling before it is
//! compared. Anything that has more than one reading — a numeric form a resolver might treat as an
//! address, a non-ASCII label, an unbracketed IPv6 literal — is refused rather than interpreted.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

/// A destination host in its one canonical spelling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Host {
    /// A DNS name: lowercase ASCII labels, no trailing dot.
    Name(String),
    /// An IP literal.
    Ip(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => formatter.write_str(name),
            Self::Ip(IpAddr::V6(v6)) => write!(formatter, "[{v6}]"),
            Self::Ip(ip) => write!(formatter, "{ip}"),
        }
    }
}

/// Why a host was refused before any policy was consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidHost {
    /// The host as it was presented.
    pub presented: String,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl fmt::Display for InvalidHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "host `{}` is refused: {}",
            self.presented, self.reason
        )
    }
}

impl std::error::Error for InvalidHost {}

/// Canonicalizes a host as it appears in a URI authority or a `CONNECT` target, without its port.
///
/// IPv6 literals must be bracketed and carry no zone. IPv4 literals must be strict dotted quads.
/// Names are lowercased and lose one trailing dot.
pub fn canonicalize(presented: &str) -> Result<Host, InvalidHost> {
    let refuse = |reason| InvalidHost {
        presented: presented.to_owned(),
        reason,
    };

    if let Some(inner) = presented.strip_prefix('[') {
        let literal = inner
            .strip_suffix(']')
            .ok_or_else(|| refuse("an IPv6 literal must be closed with `]`"))?;
        if literal.contains('%') {
            return Err(refuse("an IPv6 zone identifier is not accepted"));
        }
        return literal
            .parse::<Ipv6Addr>()
            .map(|v6| Host::Ip(IpAddr::V6(v6)))
            .map_err(|_| refuse("not a valid IPv6 literal"));
    }
    if presented.contains(':') {
        return Err(refuse("an IPv6 literal must be bracketed"));
    }
    if !presented.is_ascii() {
        return Err(refuse("non-ASCII host names are not accepted in Phase 0"));
    }
    // The standard parser accepts only four decimal octets without leading zeros, which is the one
    // spelling of an IPv4 literal that every resolver agrees on.
    if let Ok(v4) = presented.parse::<Ipv4Addr>() {
        return Ok(Host::Ip(IpAddr::V4(v4)));
    }

    let lowered = presented.to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    if name.is_empty() {
        return Err(refuse("the host is empty"));
    }
    if name.len() > MAX_NAME {
        return Err(refuse("the host name is longer than 253 characters"));
    }

    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err(refuse("the host name has an empty label"));
        }
        if label.len() > MAX_LABEL {
            return Err(refuse("a label is longer than 63 characters"));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(refuse("a label may contain only letters, digits and `-`"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(refuse("a label may not start or end with `-`"));
        }
    }

    // `127.1`, `2130706433` and `0x7f.1` are not names: some resolvers read them as addresses. A real
    // top-level label is never all digits and never a hexadecimal number.
    let last = labels.last().copied().unwrap_or_default();
    if last.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refuse(
            "a numeric host that is not a strict IPv4 literal is ambiguous",
        ));
    }
    if labels.iter().any(|label| label.starts_with("0x")) {
        return Err(refuse("a hexadecimal label is ambiguous"));
    }

    Ok(Host::Name(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_have_one_spelling() {
        assert_eq!(
            canonicalize("API.Example.COM.").unwrap(),
            Host::Name("api.example.com".into())
        );
        assert_eq!(
            canonicalize("localhost").unwrap(),
            Host::Name("localhost".into())
        );
        assert_eq!(
            canonicalize("xn--bcher-kva.example").unwrap().to_string(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn literals_are_strict() {
        assert_eq!(
            canonicalize("203.0.113.9").unwrap(),
            Host::Ip("203.0.113.9".parse().unwrap())
        );
        assert_eq!(
            canonicalize("[2001:db8::1]").unwrap(),
            Host::Ip("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            canonicalize("[::ffff:127.0.0.1]").unwrap().to_string(),
            "[::ffff:127.0.0.1]"
        );
    }

    #[test]
    fn ambiguous_or_malformed_hosts_are_refused() {
        for bad in [
            "",
            ".",
            "127.1",
            "2130706433",
            "0x7f.0.0.1",
            "0x7f000001.example",
            "017.0.0.1",
            "1.2.3.4.5",
            "::1",
            "[::1",
            "[fe80::1%eth0]",
            "[not-an-address]",
            "exa mple.com",
            "under_score.example",
            "-leading.example",
            "trailing-.example",
            "double..dot.example",
            "bücher.example",
            "user@example.com",
        ] {
            assert!(canonicalize(bad).is_err(), "{bad:?} must be refused");
        }
        let long_label = format!("{}.example", "a".repeat(64));
        assert!(canonicalize(&long_label).is_err());
    }
}
