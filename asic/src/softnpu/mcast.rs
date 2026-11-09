// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! [sidecar-lite] handles packet replication via port bitmaps in the P4
//! pipeline. This module tracks group membership for the `AsicMulticastOps`
//! contract.
//!
//! [sidecar-lite]: https://github.com/oxidecomputer/sidecar-lite

use std::collections::{HashMap, hash_map::Entry};

use aal::{AsicError, AsicResult};

/// The sidecar-lite replication table that holds underlay/external
/// port bitmaps for an underlay multicast group.
pub const MCAST_REPLICATION_V6_TABLE: &str =
    "ingress.mcast.mcast_replication_v6";

/// The sidecar-lite action that writes the external and underlay port bitmaps
/// (and replication id) for a [`MCAST_REPLICATION_V6_TABLE`] entry.
pub const SET_PORT_BITMAP_ACTION: &str = "set_port_bitmap";

/// The number of ports a group's bitmap can contain, matching sidecar-lite's
/// `bit<128>` port bitmaps.
const PORT_BITMAP_WIDTH: u16 = u128::BITS as u16;

/// Multicast group membership, defined as a port bitmap per group.
///
/// SoftNPU has no replication engine to inherently support group membership,
/// so we track it here instead. The bitmaps get resolved when dpd writes a
/// replication entry, and dpd rewrites that entry after each membership change.
#[derive(Default)]
pub struct McGroupData {
    groups: HashMap<u16, u128>,
}

fn no_group(group_id: u16) -> AsicError {
    AsicError::Missing(format!("no such multicast group: {group_id}"))
}

impl McGroupData {
    /// Get the list of multicast domains.
    pub fn domains(&self) -> Vec<u16> {
        self.groups.keys().copied().collect()
    }

    /// Build a 128-bit port bitmap for a group. Bit N is set if port N
    /// is a member.
    ///
    /// Returns zero for unknown groups.
    pub fn port_bitmap(&self, group_id: u16) -> u128 {
        self.groups.get(&group_id).copied().unwrap_or(0)
    }

    /// Get the number of ports in a multicast domain.
    pub fn domain_port_count(&self, group_id: u16) -> AsicResult<usize> {
        self.groups
            .get(&group_id)
            .map(|ports| ports.count_ones() as usize)
            .ok_or_else(|| no_group(group_id))
    }

    /// List the ports in a multicast domain (in ascending order).
    pub fn domain_port_list(&self, group_id: u16) -> AsicResult<Vec<u16>> {
        let ports =
            self.groups.get(&group_id).ok_or_else(|| no_group(group_id))?;
        Ok((0..PORT_BITMAP_WIDTH)
            .filter(|&port| *ports & (1u128 << port) != 0)
            .collect())
    }

    /// Add a port to a multicast domain. Port must be < 128 to fit
    /// within sidecar-lite's 128-bit replication bitmap.
    pub fn domain_port_add(
        &mut self,
        group_id: u16,
        port: u16,
        _rid: u16,
        _level1_excl_id: u16,
    ) -> AsicResult<()> {
        if port >= PORT_BITMAP_WIDTH {
            return Err(AsicError::InvalidArg(format!(
                "port {port} exceeds softnpu 128-port bitmap limit"
            )));
        }

        let ports =
            self.groups.get_mut(&group_id).ok_or_else(|| no_group(group_id))?;
        let bit = 1u128 << port;
        if *ports & bit != 0 {
            return Err(AsicError::Exists(format!(
                "multicast group {group_id} already contains port {port}"
            )));
        }
        *ports |= bit;
        Ok(())
    }

    /// Remove a port from a multicast domain.
    pub fn domain_port_remove(
        &mut self,
        group_id: u16,
        port: u16,
    ) -> AsicResult<()> {
        let ports =
            self.groups.get_mut(&group_id).ok_or_else(|| no_group(group_id))?;
        let bit = 1u128.checked_shl(u32::from(port)).unwrap_or(0);
        if *ports & bit == 0 {
            return Err(AsicError::Missing(format!(
                "multicast group {group_id} doesn't contain port {port}"
            )));
        }
        *ports &= !bit;
        Ok(())
    }

    /// Create a multicast domain.
    pub fn domain_create(&mut self, group_id: u16) -> AsicResult<()> {
        match self.groups.entry(group_id) {
            Entry::Occupied(_) => Err(AsicError::Exists(format!(
                "multicast group {group_id} already exists"
            ))),
            Entry::Vacant(vacant) => {
                vacant.insert(0);
                Ok(())
            }
        }
    }

    /// Destroy a multicast domain.
    pub fn domain_destroy(&mut self, group_id: u16) -> AsicResult<()> {
        self.groups.remove(&group_id).ok_or_else(|| no_group(group_id))?;
        Ok(())
    }

    /// Get the total number of multicast domains.
    pub fn domains_count(&self) -> usize {
        self.groups.len()
    }

    /// Validate that the current group count does not exceed the limit.
    pub fn set_max_nodes(&self, max_nodes: u32) -> AsicResult<()> {
        let total = self.domains_count();
        if total > usize::try_from(max_nodes).unwrap_or(usize::MAX) {
            return Err(AsicError::InvalidArg(format!(
                "number of multicast groups {total} exceeds max nodes {max_nodes}"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_lifecycle() {
        let mut group_data = McGroupData::default();

        // Create group, add ports.
        group_data.domain_create(100).unwrap();
        group_data.domain_port_add(100, 1, 0, 0).unwrap();
        group_data.domain_port_add(100, 5, 0, 0).unwrap();

        assert_eq!(group_data.domain_port_count(100).unwrap(), 2);
        assert_eq!(group_data.domain_port_list(100).unwrap(), vec![1, 5]);
        assert_eq!(group_data.domains_count(), 1);

        // Remove a port.
        group_data.domain_port_remove(100, 1).unwrap();
        assert_eq!(group_data.domain_port_count(100).unwrap(), 1);
        assert_eq!(group_data.domain_port_list(100).unwrap(), vec![5]);

        // Destroy group.
        group_data.domain_destroy(100).unwrap();
        assert_eq!(group_data.domains_count(), 0);
    }

    #[test]
    fn duplicate_group_rejected() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        assert!(matches!(
            group_data.domain_create(1),
            Err(AsicError::Exists(_))
        ));
    }

    #[test]
    fn duplicate_port_rejected() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        group_data.domain_port_add(1, 5, 0, 0).unwrap();
        assert!(matches!(
            group_data.domain_port_add(1, 5, 0, 0),
            Err(AsicError::Exists(_))
        ));
    }

    #[test]
    fn remove_nonexistent_port_rejected() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        assert!(matches!(
            group_data.domain_port_remove(1, 99),
            Err(AsicError::Missing(_))
        ));
    }

    #[test]
    fn operations_on_missing_group_rejected() {
        let mut group_data = McGroupData::default();
        assert!(matches!(
            group_data.domain_port_add(404, 1, 0, 0),
            Err(AsicError::Missing(_))
        ));
        assert!(matches!(
            group_data.domain_port_remove(404, 1),
            Err(AsicError::Missing(_))
        ));
        assert!(matches!(
            group_data.domain_port_count(404),
            Err(AsicError::Missing(_))
        ));
        assert!(matches!(
            group_data.domain_port_list(404),
            Err(AsicError::Missing(_))
        ));
        assert!(matches!(
            group_data.domain_destroy(404),
            Err(AsicError::Missing(_))
        ));
    }

    #[test]
    fn port_bitmap_zero_for_empty_or_unknown_group() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        assert_eq!(group_data.port_bitmap(1), 0);
        assert_eq!(group_data.port_bitmap(999), 0);
    }

    #[test]
    fn port_bitmap_tracks_membership() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        group_data.domain_port_add(1, 0, 0, 0).unwrap();
        group_data.domain_port_add(1, 3, 0, 0).unwrap();
        group_data.domain_port_add(1, 7, 0, 0).unwrap();
        assert_eq!(group_data.port_bitmap(1), (1 << 0) | (1 << 3) | (1 << 7));

        group_data.domain_port_remove(1, 0).unwrap();
        assert_eq!(group_data.port_bitmap(1), (1 << 3) | (1 << 7));
    }

    #[test]
    fn port_bitmap_high_port() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        group_data.domain_port_add(1, 127, 0, 0).unwrap();

        let bm = group_data.port_bitmap(1);
        assert_eq!(bm & (1u128 << 127), 1u128 << 127);
    }

    #[test]
    fn port_list_covers_bitmap_range() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        assert!(group_data.domain_port_list(1).unwrap().is_empty());
        group_data.domain_port_add(1, 127, 0, 0).unwrap();
        group_data.domain_port_add(1, 0, 0, 0).unwrap();
        assert_eq!(group_data.domain_port_list(1).unwrap(), vec![0, 127]);
    }

    #[test]
    fn port_add_rejects_ports_above_127() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        // Port 128 is out of range for a 128-bit bitmap.
        assert!(matches!(
            group_data.domain_port_add(1, 128, 0, 0),
            Err(AsicError::InvalidArg(_))
        ));
    }

    #[test]
    fn set_max_nodes_validates() {
        let mut group_data = McGroupData::default();
        group_data.domain_create(1).unwrap();
        group_data.domain_create(2).unwrap();

        assert!(matches!(
            group_data.set_max_nodes(1),
            Err(AsicError::InvalidArg(_))
        ));
        assert!(group_data.set_max_nodes(2).is_ok());
        assert!(group_data.set_max_nodes(100).is_ok());
    }
}
