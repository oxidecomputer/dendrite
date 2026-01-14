// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

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

    /// Get the number of ports in a multicast domain.
    pub fn domain_port_count(&self, group_id: u16) -> AsicResult<usize> {
        match self.groups.get(&group_id) {
            Some(g) => Ok(g.len()),
            None => Err(no_group(group_id)),
        }
    }

    /// Add a port to a multicast domain.
    pub fn domain_port_add(
        &mut self,
        group_id: u16,
        port: u16,
        _rid: u16,
        _level1_excl_id: u16,
    ) -> AsicResult<()> {
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

    /// Set the maximum number of nodes in a multicast group.
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
