// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which Execution holds which pool slot and resource tag.
//!
//! A slot and a tag are handed out only when free, released only after their Execution has been
//! destroyed and verified, and quarantined forever — for the life of the process — when that
//! verification fails. A quarantined slot is never reused: its address may still be live somewhere.

use std::collections::{BTreeSet, HashSet};

use soglia_core::ResourceTag;

/// The slots and tags of every Execution.
#[derive(Debug)]
pub struct Slots {
    free: BTreeSet<u32>,
    tags: HashSet<ResourceTag>,
    quarantined: BTreeSet<u32>,
}

impl Slots {
    /// Every slot of a pool with `count` slots, all free.
    pub fn new(count: u32) -> Self {
        Self {
            free: (0..count).collect(),
            tags: HashSet::new(),
            quarantined: BTreeSet::new(),
        }
    }

    /// `true` when `tag` belongs to a live or quarantined Execution.
    pub fn tag_in_use(&self, tag: &ResourceTag) -> bool {
        self.tags.contains(tag)
    }

    /// Reserves the lowest free slot for `tag`, which must not be in use.
    pub fn reserve(&mut self, tag: ResourceTag) -> Option<u32> {
        if self.tags.contains(&tag) {
            return None;
        }
        let slot = self.free.pop_first()?;
        self.tags.insert(tag);

        Some(slot)
    }

    /// Returns the slot and tag of a destroyed Execution.
    pub fn release(&mut self, slot: u32, tag: &ResourceTag) {
        if self.quarantined.contains(&slot) {
            return;
        }
        self.tags.remove(tag);
        self.free.insert(slot);
    }

    /// Takes the slot and tag of an Execution whose teardown could not be verified out of use.
    pub fn quarantine(&mut self, slot: u32) {
        self.free.remove(&slot);
        self.quarantined.insert(slot);
    }

    /// How many slots are quarantined.
    pub fn quarantined(&self) -> usize {
        self.quarantined.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(text: &str) -> ResourceTag {
        text.parse().unwrap()
    }

    #[test]
    fn slots_are_handed_out_lowest_first_and_come_back_on_release() {
        let mut slots = Slots::new(2);
        assert_eq!(slots.reserve(tag("0000000001")), Some(0));
        assert_eq!(slots.reserve(tag("0000000002")), Some(1));
        assert_eq!(
            slots.reserve(tag("0000000003")),
            None,
            "the pool is exhausted"
        );

        slots.release(0, &tag("0000000001"));
        assert!(!slots.tag_in_use(&tag("0000000001")));
        assert_eq!(slots.reserve(tag("0000000003")), Some(0));
    }

    #[test]
    fn a_live_tag_is_not_reserved_twice() {
        let mut slots = Slots::new(4);
        assert_eq!(slots.reserve(tag("0000000001")), Some(0));
        assert_eq!(slots.reserve(tag("0000000001")), None);
    }

    #[test]
    fn a_quarantined_slot_and_tag_never_come_back() {
        let mut slots = Slots::new(2);
        let failed = tag("0000000001");
        let slot = slots.reserve(failed).unwrap();
        slots.quarantine(slot);
        slots.release(slot, &failed);
        assert!(slots.tag_in_use(&failed));
        assert_eq!(slots.quarantined(), 1);
        assert_eq!(slots.reserve(tag("0000000002")), Some(1));
        assert_eq!(slots.reserve(tag("0000000003")), None);
    }
}
