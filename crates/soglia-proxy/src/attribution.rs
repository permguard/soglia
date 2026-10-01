// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which Execution a connection came from.
//!
//! The egress proxy never asks the agent who it is. `NetnsNftBackend` resolves the kernel peer
//! address protected by veth anti-spoofing. Candidate A resolves the accepted peer/local tuple over
//! the privileged Enforcer channel and indexes the complete cgroup/nonce/generation binding. The
//! two mechanisms never fall back to each other.
//!
//! A binding is revoked when its Execution starts tearing down: from then on the address attributes
//! nothing and every open tunnel of that Execution is told to close. The address is removed, and so
//! becomes reusable, only after the Execution has been completely destroyed.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;

use soglia_core::helper::ResolveMismatch;
use soglia_core::{BindingKey, ExecutionId};
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

/// The typed result of resolving one accepted connection before reading application bytes.
#[derive(Debug, Clone)]
pub enum AttributionResult {
    /// The connection belongs to this live, revocable Execution.
    Resolved(Binding),
    /// No trusted attribution state exists.
    NotFound,
    /// Trusted Candidate-A state exists but one boundary disagrees.
    IdentityMismatch(ResolveMismatch),
    /// The binding exists but teardown has already revoked it.
    Revoked,
    /// Tuple publication did not complete within the configured bound.
    Timeout,
    /// The bounded Supervisor-side Resolve queue had no capacity.
    QueueFull,
    /// The authenticated Enforcer Resolve channel is broken or unresponsive.
    Unavailable,
    /// Owned state could not be decoded or verified safely.
    IntegrityFailure,
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
    /// A complete Candidate-A identity still attributes another Execution.
    BindingInUse(BindingKey),
    /// The configured table capacity is already occupied.
    Capacity { capacity: usize },
    /// The table's lock is poisoned; nothing is attributed any more.
    Poisoned,
}

impl fmt::Display for BindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse(address) => write!(formatter, "{address} is still bound to an Execution"),
            Self::BindingInUse(binding) => {
                write!(formatter, "Candidate-A binding {binding:?} is still in use")
            }
            Self::Capacity { capacity } => {
                write!(
                    formatter,
                    "the attribution table capacity {capacity} is exhausted"
                )
            }
            Self::Poisoned => formatter.write_str("the attribution table is poisoned"),
        }
    }
}

impl std::error::Error for BindError {}

/// The Execution address of every live Execution.
pub struct AttributionTable {
    entries: Mutex<HashMap<IpAddr, Entry>>,
    bindings: Mutex<HashMap<BindingKey, Entry>>,
    capacity: usize,
}

impl Default for AttributionTable {
    fn default() -> Self {
        Self::with_capacity(4096)
    }
}

/// Resolves an accepted socket before the proxy reads application bytes.
pub trait ConnectionAttributor: Send + Sync {
    /// Resolve `peer` and `local` to one live, revocable Execution binding.
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>>;
}

impl AttributionTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty table with one shared bound for either backend's identity space.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            bindings: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Attributes `address` to `id`. The address must not be bound, revoked or not.
    pub fn bind(&self, address: IpAddr, id: ExecutionId) -> Result<(), BindError> {
        let mut entries = self.entries.lock().map_err(|_| BindError::Poisoned)?;
        if entries.contains_key(&address) {
            return Err(BindError::InUse(address));
        }
        if entries.len() >= self.capacity {
            return Err(BindError::Capacity {
                capacity: self.capacity,
            });
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
        match self.lookup_result(address) {
            AttributionResult::Resolved(binding) => Some(binding),
            _ => None,
        }
    }

    /// Resolves an address while preserving absence, revocation and integrity failure.
    pub fn lookup_result(&self, address: IpAddr) -> AttributionResult {
        let Ok(entries) = self.entries.lock() else {
            return AttributionResult::IntegrityFailure;
        };
        let Some(entry) = entries.get(&address) else {
            return AttributionResult::NotFound;
        };
        if *entry.revoked.borrow() {
            return AttributionResult::Revoked;
        }

        AttributionResult::Resolved(Binding {
            id: entry.id,
            revoked: entry.revoked.subscribe(),
        })
    }

    /// Attributes one indivisible Candidate-A identity to an Execution.
    pub fn bind_key(&self, binding: BindingKey, id: ExecutionId) -> Result<(), BindError> {
        let mut entries = self.bindings.lock().map_err(|_| BindError::Poisoned)?;
        if entries.contains_key(&binding) {
            return Err(BindError::BindingInUse(binding));
        }
        if entries.len() >= self.capacity {
            return Err(BindError::Capacity {
                capacity: self.capacity,
            });
        }
        let (revoked, _) = watch::channel(false);
        entries.insert(binding, Entry { id, revoked });
        Ok(())
    }

    /// Resolves only an exact whole Candidate-A key; partial fields are never indexed.
    pub fn lookup_key(&self, binding: BindingKey) -> Option<Binding> {
        match self.lookup_key_result(binding) {
            AttributionResult::Resolved(binding) => Some(binding),
            _ => None,
        }
    }

    /// Resolves a complete Candidate-A identity without collapsing absence and revocation.
    pub fn lookup_key_result(&self, binding: BindingKey) -> AttributionResult {
        let Ok(entries) = self.bindings.lock() else {
            return AttributionResult::IntegrityFailure;
        };
        let Some(entry) = entries.get(&binding) else {
            return AttributionResult::NotFound;
        };
        if *entry.revoked.borrow() {
            return AttributionResult::Revoked;
        }
        AttributionResult::Resolved(Binding {
            id: entry.id,
            revoked: entry.revoked.subscribe(),
        })
    }

    /// Revokes an exact Candidate-A binding.
    pub fn revoke_key(&self, binding: BindingKey) {
        if let Ok(entries) = self.bindings.lock()
            && let Some(entry) = entries.get(&binding)
        {
            entry.revoked.send_replace(true);
        }
    }

    /// Releases only the revoked exact Candidate-A binding of `id`.
    pub fn remove_key(&self, binding: BindingKey, id: ExecutionId) -> bool {
        let Ok(mut entries) = self.bindings.lock() else {
            return false;
        };
        let releasable = entries
            .get(&binding)
            .is_some_and(|entry| entry.id == id && *entry.revoked.borrow());
        if releasable {
            entries.remove(&binding);
        }
        releasable
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

impl ConnectionAttributor for AttributionTable {
    fn resolve<'a>(
        &'a self,
        peer: SocketAddr,
        _local: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = AttributionResult> + Send + 'a>> {
        Box::pin(async move { self.lookup_result(peer.ip()) })
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

    #[test]
    fn candidate_a_lookup_requires_the_complete_binding_key() {
        let table = AttributionTable::new();
        let id = ExecutionId::generate().unwrap();
        let key = BindingKey {
            cgroup_id: 91,
            execution_nonce: soglia_core::ExecutionNonce::generate().unwrap(),
            backend_generation: 3,
        };
        table.bind_key(key, id).unwrap();
        assert_eq!(table.lookup_key(key).unwrap().id, id);
        assert!(
            table
                .lookup_key(BindingKey {
                    backend_generation: 4,
                    ..key
                })
                .is_none()
        );

        assert!(matches!(
            table.lookup_key_result(BindingKey {
                backend_generation: 4,
                ..key
            }),
            AttributionResult::NotFound
        ));
        table.revoke_key(key);
        assert!(matches!(
            table.lookup_key_result(key),
            AttributionResult::Revoked
        ));
    }

    #[test]
    fn either_attribution_index_refuses_entries_beyond_its_bound() {
        let ip_table = AttributionTable::with_capacity(1);
        ip_table
            .bind(address("10.201.0.1"), ExecutionId::generate().unwrap())
            .unwrap();
        assert_eq!(
            ip_table.bind(address("10.201.0.2"), ExecutionId::generate().unwrap()),
            Err(BindError::Capacity { capacity: 1 })
        );

        let key_table = AttributionTable::with_capacity(1);
        let first = BindingKey {
            cgroup_id: 1,
            execution_nonce: soglia_core::ExecutionNonce::generate().unwrap(),
            backend_generation: 1,
        };
        key_table
            .bind_key(first, ExecutionId::generate().unwrap())
            .unwrap();
        assert_eq!(
            key_table.bind_key(
                BindingKey {
                    cgroup_id: 2,
                    ..first
                },
                ExecutionId::generate().unwrap(),
            ),
            Err(BindError::Capacity { capacity: 1 })
        );
    }
}
