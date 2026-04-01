// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! In-memory multicast group tracking for the [softnpu] backend.
//!
//! Sidecar-lite handles packet replication via port bitmaps in the P4
//! pipeline, so this module only needs to track group membership for
//! the `AsicMulticastOps` contract.
//!
//! [softnpu]: https://github.com/oxidecomputer/softnpu

use std::collections::{HashMap, HashSet};

use aal::{AsicError, AsicResult};

pub struct McGroupData {
    groups: HashMap<u16, HashSet<u16>>,
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
    McGroupData { groups: HashMap::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_lifecycle() {
        let mut mc = init();

        // Create group, add ports.
        mc.domain_create(100).unwrap();
        mc.domain_port_add(100, 1, 0, 0).unwrap();
        mc.domain_port_add(100, 5, 0, 0).unwrap();

        assert_eq!(mc.domain_port_count(100).unwrap(), 2);
        assert_eq!(mc.domains_count(), 1);

        // Remove a port.
        mc.domain_port_remove(100, 1).unwrap();
        assert_eq!(mc.domain_port_count(100).unwrap(), 1);

        // Destroy group.
        mc.domain_destroy(100).unwrap();
        assert_eq!(mc.domains_count(), 0);
    }

    #[test]
    fn duplicate_group_rejected() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        assert!(mc.domain_create(1).is_err());
    }

    #[test]
    fn duplicate_port_rejected() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        mc.domain_port_add(1, 5, 0, 0).unwrap();
        assert!(mc.domain_port_add(1, 5, 0, 0).is_err());
    }

    #[test]
    fn remove_nonexistent_port_rejected() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        assert!(mc.domain_port_remove(1, 99).is_err());
    }

    #[test]
    fn operations_on_missing_group_rejected() {
        let mut mc = init();
        assert!(mc.domain_port_add(42, 1, 0, 0).is_err());
        assert!(mc.domain_port_remove(42, 1).is_err());
        assert!(mc.domain_port_count(42).is_err());
        assert!(mc.domain_destroy(42).is_err());
    }

    #[test]
    fn port_bitmap_empty_group() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        assert_eq!(mc.port_bitmap(1), 0);
    }

    #[test]
    fn port_bitmap_populated() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        mc.domain_port_add(1, 0, 0, 0).unwrap();
        mc.domain_port_add(1, 3, 0, 0).unwrap();
        mc.domain_port_add(1, 7, 0, 0).unwrap();

        let bm = mc.port_bitmap(1);
        assert_eq!(bm & (1 << 0), 1 << 0);
        assert_eq!(bm & (1 << 3), 1 << 3);
        assert_eq!(bm & (1 << 7), 1 << 7);
        assert_eq!(bm & (1 << 1), 0);
    }

    #[test]
    fn port_bitmap_unknown_group_returns_zero() {
        let mc = init();
        assert_eq!(mc.port_bitmap(999), 0);
    }

    #[test]
    fn port_bitmap_high_port() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        mc.domain_port_add(1, 127, 0, 0).unwrap();

        let bm = mc.port_bitmap(1);
        assert_eq!(bm & (1u128 << 127), 1u128 << 127);
    }

    #[test]
    fn port_bitmap_ignores_ports_above_127() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        // Port 128 is out of range for a 128-bit bitmap.
        assert!(mc.domain_port_add(1, 128, 0, 0).is_err());
    }

    #[test]
    fn set_max_nodes_validates() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        mc.domain_create(2).unwrap();

        assert!(mc.set_max_nodes(1, 0).is_err());
        assert!(mc.set_max_nodes(2, 0).is_ok());
        assert!(mc.set_max_nodes(100, 0).is_ok());
    }

    #[test]
    fn domains_returns_created_group_ids() {
        let mut mc = init();
        mc.domain_create(10).unwrap();
        mc.domain_create(20).unwrap();
        mc.domain_create(30).unwrap();

        let mut ids = mc.domains();
        ids.sort();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn port_bitmap_reflects_removal() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        mc.domain_port_add(1, 0, 0, 0).unwrap();
        mc.domain_port_add(1, 3, 0, 0).unwrap();

        mc.domain_port_remove(1, 0).unwrap();

        let bm = mc.port_bitmap(1);
        assert_eq!(bm & (1 << 0), 0);
        assert_eq!(bm & (1 << 3), 1 << 3);
    }

    #[test]
    fn groups_are_independent() {
        let mut mc = init();
        mc.domain_create(1).unwrap();
        mc.domain_create(2).unwrap();
        mc.domain_port_add(1, 5, 0, 0).unwrap();
        mc.domain_port_add(2, 5, 0, 0).unwrap();

        mc.domain_port_remove(1, 5).unwrap();

        assert_eq!(mc.domain_port_count(1).unwrap(), 0);
        assert_eq!(mc.domain_port_count(2).unwrap(), 1);
        assert_eq!(mc.port_bitmap(2) & (1 << 5), 1 << 5);
    }
}
