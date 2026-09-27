// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which Execution a connection came from.
//!
//! The egress proxy never asks the agent who it is. It reads the peer address of the socket it
//! accepted and looks it up here. The address is trustworthy because Soglia assigned it to exactly
//! one Execution veth and the host drops traffic from that veth with any other source address.
//!
//! A binding is revoked when its Execution starts tearing down: from then on the address attributes
//! nothing and every open tunnel of that Execution is told to close. The address is removed, and so
//! becomes reusable, only after the Execution has been completely destroyed.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;

use soglia_core::ExecutionId;
use tokio::sync::watch;

/// The attribution of one open connection.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The Execution the connection came from.
    pub id: ExecutionId,
    revoked: watch::Receiver<bool>,
}

impl Binding {
    /// `true` once the Execution has started tearing down.
    pub fn is_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    /// Resolves when the Execution starts tearing down, or when the table forgets it.
    pub async fn revoked(&mut self) {
        // An error means the sender is gone, which only happens once the binding was removed: the
        // Execution no longer exists, so the connection must close either way.
        let _ = self.revoked.wait_for(|revoked| *revoked).await;
    }
}

struct Entry {
    id: ExecutionId,
    revoked: watch::Sender<bool>,
}

/// Why an address could not be bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The address still attributes another Execution.
    InUse(IpAddr),
    /// The table's lock is poisoned; nothing is attributed any more.
    Poisoned,
}

impl fmt::Display for BindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse(address) => write!(formatter, "{address} is still bound to an Execution"),
            Self::Poisoned => formatter.write_str("the attribution table is poisoned"),
        }
    }
}

impl std::error::Error for BindError {}

/// The Execution address of every live Execution.
#[derive(Default)]
pub struct AttributionTable {
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

impl AttributionTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attributes `address` to `id`. The address must not be bound, revoked or not.
    pub fn bind(&self, address: IpAddr, id: ExecutionId) -> Result<(), BindError> {
        let mut entries = self.entries.lock().map_err(|_| BindError::Poisoned)?;
        if entries.contains_key(&address) {
            return Err(BindError::InUse(address));
        }
        let (revoked, _) = watch::channel(false);
        entries.insert(address, Entry { id, revoked });

        Ok(())
    }

    /// The live Execution behind `address`, if any. A revoked binding attributes nothing.
    ///
    /// A poisoned table attributes nothing either: failing closed is the only safe reading of a
    /// table whose last writer panicked.
    pub fn lookup(&self, address: IpAddr) -> Option<Binding> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(&address)?;
        if *entry.revoked.borrow() {
            return None;
        }

        Some(Binding {
            id: entry.id,
            revoked: entry.revoked.subscribe(),
        })
    }

    /// Stops attributing `address` and tells every open connection of its Execution to close.
    /// The address stays reserved until [`Self::remove`].
    pub fn revoke(&self, address: IpAddr) {
        if let Ok(entries) = self.entries.lock()
            && let Some(entry) = entries.get(&address)
        {
            entry.revoked.send_replace(true);
        }
    }

    /// Releases `address`, once its Execution `id` is completely destroyed.
    ///
    /// Only a revoked binding of that same Execution is released, so a stale caller can neither
    /// release a live binding nor another Execution's.
    pub fn remove(&self, address: IpAddr, id: ExecutionId) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        let releasable = entries
            .get(&address)
            .is_some_and(|entry| entry.id == id && *entry.revoked.borrow());
        if releasable {
            entries.remove(&address);
        }

        releasable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_bound_address_attributes_its_execution() {
        let table = AttributionTable::new();
        let id = ExecutionId::generate().unwrap();
        table.bind(address("10.201.0.1"), id).unwrap();

        assert_eq!(table.lookup(address("10.201.0.1")).unwrap().id, id);
        assert!(table.lookup(address("10.201.0.3")).is_none());
        assert_eq!(
            table.bind(address("10.201.0.1"), ExecutionId::generate().unwrap()),
            Err(BindError::InUse(address("10.201.0.1")))
        );
    }

    #[test]
    fn a_revoked_address_attributes_nothing_but_stays_reserved() {
        let table = AttributionTable::new();
        let id = ExecutionId::generate().unwrap();
        table.bind(address("10.201.0.1"), id).unwrap();
        let open = table.lookup(address("10.201.0.1")).unwrap();

        table.revoke(address("10.201.0.1"));
        assert!(open.is_revoked());
        assert!(table.lookup(address("10.201.0.1")).is_none());
        // Not reusable until removed.
        assert!(
            table
                .bind(address("10.201.0.1"), ExecutionId::generate().unwrap())
                .is_err()
        );
    }

    #[test]
    fn only_a_revoked_binding_of_the_same_execution_is_released() {
        let table = AttributionTable::new();
        let id = ExecutionId::generate().unwrap();
        let other = ExecutionId::generate().unwrap();
        table.bind(address("10.201.0.1"), id).unwrap();

        assert!(
            !table.remove(address("10.201.0.1"), id),
            "a live binding is not released"
        );
        table.revoke(address("10.201.0.1"));
        assert!(
            !table.remove(address("10.201.0.1"), other),
            "another Execution cannot release it"
        );
        assert!(table.remove(address("10.201.0.1"), id));
        assert!(table.bind(address("10.201.0.1"), other).is_ok());
    }

    #[tokio::test]
    async fn an_open_connection_learns_of_the_revocation() {
        let table = AttributionTable::new();
        let id = ExecutionId::generate().unwrap();
        table.bind(address("10.201.0.1"), id).unwrap();
        let mut open = table.lookup(address("10.201.0.1")).unwrap();

        table.revoke(address("10.201.0.1"));
        tokio::time::timeout(Duration::from_secs(1), open.revoked())
            .await
            .expect("the revocation is observed");
    }
}
