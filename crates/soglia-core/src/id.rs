// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Execution identity and the names of the resources an Execution owns.
//!
//! An [`ExecutionId`] is 128 random bits. Kernel objects cannot carry a name that long — an
//! interface name is at most 15 bytes — so each Execution also has a [`ResourceTag`], the first 40
//! bits of its identifier, and every resource it owns is named from that tag with a fixed Soglia
//! prefix. The Supervisor never lets two live Executions share a tag.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Prefix of every network namespace and runc container Soglia creates.
pub const NAME_PREFIX: &str = "soglia-";
/// Prefix of the host-side end of every Execution veth pair.
pub const HOST_VETH_PREFIX: &str = "sgh-";

const ID_BYTES: usize = 16;
const TAG_BYTES: usize = 5;

/// The identity of one Execution.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExecutionId([u8; ID_BYTES]);

impl ExecutionId {
    /// A new identifier from the operating system's random source.
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0_u8; ID_BYTES];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;

        Ok(Self(bytes))
    }

    /// The short tag the Execution's resources are named from.
    pub fn tag(&self) -> ResourceTag {
        let mut prefix = [0_u8; TAG_BYTES];
        prefix.copy_from_slice(&self.0[..TAG_BYTES]);

        ResourceTag(prefix)
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl fmt::Debug for ExecutionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ExecutionId({self})")
    }
}

impl FromStr for ExecutionId {
    type Err = InvalidId;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_hex::<ID_BYTES>(text).map(Self)
    }
}

impl TryFrom<String> for ExecutionId {
    type Error = InvalidId;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<ExecutionId> for String {
    fn from(id: ExecutionId) -> Self {
        id.to_string()
    }
}

/// The short name an Execution's kernel and runtime resources are derived from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ResourceTag([u8; TAG_BYTES]);

impl ResourceTag {
    /// The network namespace, as `ip netns` names it.
    pub fn netns_name(&self) -> String {
        format!("{NAME_PREFIX}{self}")
    }

    /// The host-side end of the Execution's veth pair.
    pub fn host_veth(&self) -> String {
        format!("{HOST_VETH_PREFIX}{self}")
    }

    /// The runc container identifier.
    pub fn container_id(&self) -> String {
        format!("{NAME_PREFIX}{self}")
    }
}

impl fmt::Display for ResourceTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl fmt::Debug for ResourceTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ResourceTag({self})")
    }
}

impl FromStr for ResourceTag {
    type Err = InvalidId;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_hex::<TAG_BYTES>(text).map(Self)
    }
}

impl TryFrom<String> for ResourceTag {
    type Error = InvalidId;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<ResourceTag> for String {
    fn from(tag: ResourceTag) -> Self {
        tag.to_string()
    }
}

/// A string that is not a well-formed identifier or tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidId(String);

impl fmt::Display for InvalidId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "`{}` is not a lowercase hexadecimal identifier of the expected length",
            self.0
        )
    }
}

impl std::error::Error for InvalidId {}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }

    Ok(())
}

/// Strict parsing: exactly `2 * N` lowercase hexadecimal digits, nothing else.
fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], InvalidId> {
    let invalid = || InvalidId(text.to_owned());
    let digits = text.as_bytes();
    if digits.len() != 2 * N {
        return Err(invalid());
    }

    let mut out = [0_u8; N];
    let (pairs, _) = digits.as_chunks::<2>();
    for (index, pair) in pairs.iter().enumerate() {
        let high = hex_value(pair[0]).ok_or_else(invalid)?;
        let low = hex_value(pair[1]).ok_or_else(invalid)?;
        out[index] = (high << 4) | low;
    }

    Ok(out)
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identifiers_differ_and_round_trip() {
        let first = ExecutionId::generate().unwrap();
        let second = ExecutionId::generate().unwrap();
        assert_ne!(first, second);

        let text = first.to_string();
        assert_eq!(text.len(), 32);
        assert_eq!(text.parse::<ExecutionId>().unwrap(), first);
    }

    #[test]
    fn the_tag_is_the_identifier_prefix() {
        let id: ExecutionId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert_eq!(id.tag().to_string(), "0123456789");
    }

    #[test]
    fn resource_names_fit_the_kernel_limits() {
        let tag: ResourceTag = "0123456789".parse().unwrap();
        assert_eq!(tag.netns_name(), "soglia-0123456789");
        assert_eq!(tag.host_veth(), "sgh-0123456789");
        assert_eq!(tag.container_id(), "soglia-0123456789");
        // IFNAMSIZ is 16 including the terminating NUL.
        assert!(tag.host_veth().len() <= 15);
    }

    #[test]
    fn parsing_is_strict() {
        for bad in [
            "",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789abcdef0123456789abcdeg",
            " 0123456789abcdef0123456789abcde",
        ] {
            assert!(
                bad.parse::<ExecutionId>().is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!("012345678".parse::<ResourceTag>().is_err());
        assert!("../etc/pw".parse::<ResourceTag>().is_err());
    }

    #[test]
    fn identifiers_serialize_as_strings() {
        let id: ExecutionId = "00112233445566778899aabbccddeeff".parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"00112233445566778899aabbccddeeff\"");
        assert_eq!(serde_json::from_str::<ExecutionId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<ResourceTag>("\"soglia\"").is_err());
    }
}
