// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! In-memory multicast group tracking for the [SoftNPU] backend.
//!
//! Sidecar-lite handles packet replication via port bitmaps in the P4
//! pipeline, so this module only needs to track group membership for
//! the `AsicMulticastOps` contract.
//!
//! [SoftNPU]: https://github.com/oxidecomputer/softnpu

use std::collections::{HashMap, HashSet};

use aal::{AsicError, AsicResult};

/// Sidecar-lite replication table that holds the baked underlay/external
/// port bitmaps for an underlay multicast group.
pub const MCAST_REPLICATION_V6_TABLE: &str =
    "ingress.mcast.mcast_replication_v6";

/// Sidecar-lite action that writes the external and underlay port bitmaps
/// (and replication id) for a [`MCAST_REPLICATION_V6_TABLE`] entry.
pub const SET_PORT_BITMAP_ACTION: &str = "set_port_bitmap";

/// A replication table entry's group references, recorded so that a later
/// membership change can recompute port bitmaps.
///
/// On the production sidecar, the replication table holds a group identifier,
/// and the replication engine tracks membership live, so a port addition needs
/// no table rewrite. The SoftNPU pipeline, instead, bakes a generic port bitmap
/// data structure into the table entry at write time, so each membership change
/// must rewrite every entry that references the affected group.
#[derive(Clone, Copy, Debug)]
struct ReplEntryRef {
    external_grp: u16,
    underlay_grp: u16,
    rid: u16,
}

/// A replication entry refreshed against current membership, ready to be
/// rewritten into the SoftNPU pipeline.
#[derive(Clone, Debug)]
pub struct RefreshedReplEntry {
    /// Match keyset bytes identifying the table entry (the underlay group's
    /// destination address).
    pub keyset: Vec<u8>,
    pub external_bitmap: u128,
    pub underlay_bitmap: u128,
    pub rid: u16,
}

pub struct McGroupData {
    groups: HashMap<u16, HashSet<u16>>,
    /// Replication table entries keyed on their matched keyset, recorded at
    /// table-write time so membership changes can refresh bitmaps.
    repl_entries: HashMap<Vec<u8>, ReplEntryRef>,
}

fn no_group(group_id: u16) -> AsicError {
    AsicError::InvalidArg(format!("no such multicast group: {group_id}"))
}

impl McGroupData {
    /// Get the list of multicast domains.
    pub fn domains(&self) -> Vec<u16> {
        self.groups.keys().copied().collect()
    }

    /// Build a 128-bit port bitmap for a group. Bit N is set if port N
    /// is a member. Returns zero for unknown groups.
    pub fn port_bitmap(&self, group_id: u16) -> u128 {
        match self.groups.get(&group_id) {
            Some(ports) => {
                let mut bitmap: u128 = 0;
                for &port in ports {
                    bitmap |= 1u128 << port;
                }
                bitmap
            }
            None => 0,
        }
    }

    /// Get the number of ports in a multicast domain.
    pub fn domain_port_count(&self, group_id: u16) -> AsicResult<usize> {
        match self.groups.get(&group_id) {
            Some(g) => Ok(g.len()),
            None => Err(no_group(group_id)),
        }
    }

    /// Add a port to a multicast domain. Port must be < 128 to fit
    /// in sidecar-lite's 128-bit replication bitmap.
    pub fn domain_port_add(
        &mut self,
        group_id: u16,
        port: u16,
        _rid: u16,
        _level1_excl_id: u16,
    ) -> AsicResult<()> {
        if port >= 128 {
            return Err(AsicError::InvalidArg(format!(
                "port {port} exceeds softnpu 128-port bitmap limit"
            )));
        }
        let group = match self.groups.get_mut(&group_id) {
            Some(g) => Ok(g),
            None => Err(no_group(group_id)),
        }?;

        match group.insert(port) {
            true => Ok(()),
            false => Err(AsicError::InvalidArg(format!(
                "multicast group {group_id} already contains port {port}"
            ))),
        }
    }

    /// Remove a port from a multicast domain.
    pub fn domain_port_remove(
        &mut self,
        group_id: u16,
        port: u16,
    ) -> AsicResult<()> {
        let group = match self.groups.get_mut(&group_id) {
            Some(g) => Ok(g),
            None => Err(no_group(group_id)),
        }?;

        match group.remove(&port) {
            true => Ok(()),
            false => Err(AsicError::InvalidArg(format!(
                "multicast group {group_id} doesn't contain port {port}"
            ))),
        }
    }

    /// Create a multicast domain.
    #[allow(clippy::map_entry)]
    pub fn domain_create(&mut self, group_id: u16) -> AsicResult<()> {
        if self.groups.contains_key(&group_id) {
            Err(AsicError::InvalidArg(format!(
                "multicast group {group_id} already exists"
            )))
        } else {
            self.groups.insert(group_id, HashSet::new());
            Ok(())
        }
    }

    /// Destroy a multicast domain.
    pub fn domain_destroy(&mut self, group_id: u16) -> AsicResult<()> {
        match self.groups.remove(&group_id) {
            Some(_) => Ok(()),
            None => Err(no_group(group_id)),
        }
    }

    /// Get the total number of multicast domains.
    pub fn domains_count(&self) -> usize {
        self.groups.len()
    }

    /// Record a replication table entry's group references at table-write
    /// time so a later membership change can refresh its bitmaps.
    pub fn record_repl_entry(
        &mut self,
        keyset: Vec<u8>,
        external_grp: u16,
        underlay_grp: u16,
        rid: u16,
    ) {
        self.repl_entries
            .insert(keyset, ReplEntryRef { external_grp, underlay_grp, rid });
    }

    /// Forget a replication table entry when it is removed from the pipeline.
    pub fn forget_repl_entry(&mut self, keyset: &[u8]) {
        self.repl_entries.remove(keyset);
    }

    /// Forget every tracked replication entry when the replication table is
    /// cleared, so a later membership change for a reused group identifier
    /// cannot resurrect a stale bitmap from a forgotten keyset.
    pub fn clear_repl_entries(&mut self) {
        self.repl_entries.clear();
    }

    /// Recompute the bitmaps for every replication entry that references
    /// `group_id` in either its external or underlay slot.
    ///
    /// This closes the impedance mismatch between the sidecar's production
    /// replication engine and SoftNPU's snapshot-at-write-time bitmaps.
    ///
    /// # Returns
    ///
    /// The refreshed [`RefreshedReplEntry`] values for the caller to rewrite
    /// into the SoftNPU pipeline.
    pub fn refresh_params_for_group(
        &self,
        group_id: u16,
    ) -> Vec<RefreshedReplEntry> {
        self.repl_entries
            .iter()
            .filter(|(_, e)| {
                e.external_grp == group_id || e.underlay_grp == group_id
            })
            .map(|(keyset, e)| RefreshedReplEntry {
                keyset: keyset.clone(),
                external_bitmap: self.port_bitmap(e.external_grp),
                underlay_bitmap: self.port_bitmap(e.underlay_grp),
                rid: e.rid,
            })
            .collect()
    }

    /// Validate that the current group count does not exceed the limit.
    pub fn set_max_nodes(
        &mut self,
        max_nodes: u32,
        _max_link_aggregated_nodes: u32,
    ) -> AsicResult<()> {
        let total = self.domains_count();
        if total as u32 > max_nodes {
            return Err(AsicError::InvalidArg(format!(
                "number of multicast groups {total} exceeds max nodes {max_nodes}"
            )));
        }

        Ok(())
    }
}

pub fn init() -> McGroupData {
    McGroupData { groups: HashMap::new(), repl_entries: HashMap::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_lifecycle() {
        let mut group_data = init();

        // Create group, add ports.
        group_data.domain_create(100).unwrap();
        group_data.domain_port_add(100, 1, 0, 0).unwrap();
        group_data.domain_port_add(100, 5, 0, 0).unwrap();

        assert_eq!(group_data.domain_port_count(100).unwrap(), 2);
        assert_eq!(group_data.domains_count(), 1);

        // Remove a port.
        group_data.domain_port_remove(100, 1).unwrap();
        assert_eq!(group_data.domain_port_count(100).unwrap(), 1);

        // Destroy group.
        group_data.domain_destroy(100).unwrap();
        assert_eq!(group_data.domains_count(), 0);
    }

    #[test]
    fn duplicate_group_rejected() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        assert!(group_data.domain_create(1).is_err());
    }

    #[test]
    fn duplicate_port_rejected() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        group_data.domain_port_add(1, 5, 0, 0).unwrap();
        assert!(group_data.domain_port_add(1, 5, 0, 0).is_err());
    }

    #[test]
    fn remove_nonexistent_port_rejected() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        assert!(group_data.domain_port_remove(1, 99).is_err());
    }

    #[test]
    fn operations_on_missing_group_rejected() {
        let mut group_data = init();
        assert!(group_data.domain_port_add(42, 1, 0, 0).is_err());
        assert!(group_data.domain_port_remove(42, 1).is_err());
        assert!(group_data.domain_port_count(42).is_err());
        assert!(group_data.domain_destroy(42).is_err());
    }

    #[test]
    fn port_bitmap_empty_group() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        assert_eq!(group_data.port_bitmap(1), 0);
    }

    #[test]
    fn port_bitmap_populated() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        group_data.domain_port_add(1, 0, 0, 0).unwrap();
        group_data.domain_port_add(1, 3, 0, 0).unwrap();
        group_data.domain_port_add(1, 7, 0, 0).unwrap();

        let bm = group_data.port_bitmap(1);
        assert_eq!(bm & (1 << 0), 1 << 0);
        assert_eq!(bm & (1 << 3), 1 << 3);
        assert_eq!(bm & (1 << 7), 1 << 7);
        assert_eq!(bm & (1 << 1), 0);
    }

    #[test]
    fn port_bitmap_unknown_group_returns_zero() {
        let group_data = init();
        assert_eq!(group_data.port_bitmap(999), 0);
    }

    #[test]
    fn port_bitmap_high_port() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        group_data.domain_port_add(1, 127, 0, 0).unwrap();

        let bm = group_data.port_bitmap(1);
        assert_eq!(bm & (1u128 << 127), 1u128 << 127);
    }

    #[test]
    fn port_add_rejects_ports_above_127() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        // Port 128 is out of range for a 128-bit bitmap.
        assert!(group_data.domain_port_add(1, 128, 0, 0).is_err());
    }

    #[test]
    fn set_max_nodes_validates() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        group_data.domain_create(2).unwrap();

        assert!(group_data.set_max_nodes(1, 0).is_err());
        assert!(group_data.set_max_nodes(2, 0).is_ok());
        assert!(group_data.set_max_nodes(100, 0).is_ok());
    }

    #[test]
    fn domains_returns_created_group_ids() {
        let mut group_data = init();
        group_data.domain_create(10).unwrap();
        group_data.domain_create(20).unwrap();
        group_data.domain_create(30).unwrap();

        let mut ids = group_data.domains();
        ids.sort();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn port_bitmap_reflects_removal() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        group_data.domain_port_add(1, 0, 0, 0).unwrap();
        group_data.domain_port_add(1, 3, 0, 0).unwrap();

        group_data.domain_port_remove(1, 0).unwrap();

        let bm = group_data.port_bitmap(1);
        assert_eq!(bm & (1 << 0), 0);
        assert_eq!(bm & (1 << 3), 1 << 3);
    }

    #[test]
    fn refresh_recomputes_bitmap_after_membership_change() {
        let mut group_data = init();
        // Underlay group 65533 with one member, recorded as a replication
        // entry keyed by the underlay destination address bytes.
        group_data.domain_create(65533).unwrap();
        group_data.domain_port_add(65533, 1, 0, 0).unwrap();
        // ff04::1, an admin-scoped IPv6 multicast destination, matching the
        // 128-bit key of the sidecar-lite replication table.
        let keyset = std::net::Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1)
            .octets()
            .to_vec();
        group_data.record_repl_entry(keyset.clone(), 0, 65533, 65533);

        // Refreshed against current membership @ only port 1.
        let initial = group_data.refresh_params_for_group(65533);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].underlay_bitmap, 1u128 << 1);

        // A later member add must surface in a fresh refresh.
        group_data.domain_port_add(65533, 2, 0, 0).unwrap();
        group_data.domain_port_add(65533, 3, 0, 0).unwrap();
        let refreshed = group_data.refresh_params_for_group(65533);
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].keyset, keyset);
        assert_eq!(refreshed[0].rid, 65533);
        assert_eq!(
            refreshed[0].underlay_bitmap,
            (1u128 << 1) | (1u128 << 2) | (1u128 << 3)
        );
    }

    #[test]
    fn refresh_skips_unrelated_groups_and_forgotten_entries() {
        let mut group_data = init();
        group_data.domain_create(100).unwrap();
        group_data.domain_create(200).unwrap();
        group_data.domain_port_add(100, 4, 0, 0).unwrap();

        // These are opaque single-byte keysets standing in for distinct
        // replication entries (not any real address).
        let key_a = vec![0xaa];
        let key_b = vec![0xbb];

        group_data.record_repl_entry(key_a.clone(), 0, 100, 7);
        group_data.record_repl_entry(key_b, 0, 200, 8);

        // Only the entry referencing group 100 is refreshed.
        let refreshed = group_data.refresh_params_for_group(100);
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].keyset, key_a);

        // After forgetting it, the group has no entries to refresh.
        group_data.forget_repl_entry(&key_a);
        assert!(group_data.refresh_params_for_group(100).is_empty());
    }

    #[test]
    fn refresh_matches_external_slot() {
        let mut group_data = init();
        group_data.domain_create(50).unwrap();
        group_data.domain_port_add(50, 9, 0, 0).unwrap();
        // Group 50 sits in the external slot here, not the underlay slot.
        group_data.record_repl_entry(vec![0xcc], 50, 0, 1);

        let refreshed = group_data.refresh_params_for_group(50);
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].external_bitmap, 1u128 << 9);
        assert_eq!(refreshed[0].underlay_bitmap, 0);
    }

    #[test]
    fn clear_repl_entries_drops_all_tracked_entries() {
        let mut group_data = init();
        group_data.domain_create(100).unwrap();
        group_data.domain_create(200).unwrap();
        group_data.domain_port_add(100, 4, 0, 0).unwrap();
        group_data.domain_port_add(200, 5, 0, 0).unwrap();
        group_data.record_repl_entry(vec![0xaa], 0, 100, 7);
        group_data.record_repl_entry(vec![0xbb], 0, 200, 8);

        // Both entries are tracked before the clear.
        assert_eq!(group_data.refresh_params_for_group(100).len(), 1);
        assert_eq!(group_data.refresh_params_for_group(200).len(), 1);

        group_data.clear_repl_entries();

        // After clearing, no keyset survives to be resurrected, even though the
        // group memberships themselves are untouched.
        assert!(group_data.refresh_params_for_group(100).is_empty());
        assert!(group_data.refresh_params_for_group(200).is_empty());
        assert_eq!(group_data.domain_port_count(100).unwrap(), 1);
        assert_eq!(group_data.domain_port_count(200).unwrap(), 1);
    }

    #[test]
    fn groups_are_independent() {
        let mut group_data = init();
        group_data.domain_create(1).unwrap();
        group_data.domain_create(2).unwrap();
        group_data.domain_port_add(1, 5, 0, 0).unwrap();
        group_data.domain_port_add(2, 5, 0, 0).unwrap();

        group_data.domain_port_remove(1, 5).unwrap();

        assert_eq!(group_data.domain_port_count(1).unwrap(), 0);
        assert_eq!(group_data.domain_port_count(2).unwrap(), 1);
        assert_eq!(group_data.port_bitmap(2) & (1 << 5), 1 << 5);
    }
}
