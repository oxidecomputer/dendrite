// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use slog::{debug, trace};
use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::types::{DpdError, DpdResult};
use crate::Switch;
use common::nat::InternalTarget;
use oxnet::Ipv4Net;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExtSubnetEntry {
    pub subnet: Ipv4Net,
    pub tgt: InternalTarget,
}

impl fmt::Display for ExtSubnetEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}", self.subnet, self.tgt)
    }
}
pub struct ExtSubnetData {
    mappings: BTreeMap<Ipv4Net, ExtSubnetEntry>,
}

/// Paginates through `ExtSubnetEntry`
pub fn get_mappings(
    switch: &Switch,
    last_subnet: Option<Ipv4Net>,
    mut max: usize,
) -> Vec<ExtSubnetEntry> {
    max = std::cmp::min(max, 64);
    let all = switch.ext_subnet.lock().unwrap();
    let subnet = last_subnet
        .unwrap_or(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap());

    all.mappings
        .values()
        .filter(|e| e.subnet > subnet)
        .take(max)
        .cloned()
        .collect()
}

/// Find the target, if any, of the provided external subnet
pub fn get_mapping(
    switch: &Switch,
    subnet: Ipv4Net,
) -> DpdResult<InternalTarget> {
    let all = switch.ext_subnet.lock().unwrap();
    match all.mappings.get(&subnet) {
        Some(e) => Ok(e.tgt),
        None => Err(DpdError::Missing("no mapping".into())),
    }
}

/// Map the provided external subnet to the internal address/vni.
pub fn set_mapping(
    switch: &Switch,
    subnet: Ipv4Net,
    tgt: InternalTarget,
) -> DpdResult<()> {
    let new_entry = ExtSubnetEntry { subnet, tgt };
    trace!(switch.log, "adding external subnet entry {}", new_entry);

    let mut all = switch.ext_subnet.lock().unwrap();
    if let Some(e) = all.mappings.get_mut(&subnet) {
        if e == &new_entry {
            // entry already exists
            return Ok(());
        } else {
            return Err(DpdError::Exists("conflicting mapping".into()));
        }
    }
    all.mappings.insert(subnet, new_entry);

    /*
    match nat::add_ipv4_entry(switch, nat_ip, low, high, tgt) {
        Err(e) => {
            error!(switch.log, "failed to add nat entry {}: {:?}", full, e);
            Err(e)
        }
        _ => {
            debug!(switch.log, "added nat entry {}", full);
            entries.insert(idx, new_entry);
            Ok(())
        }
    }
        */
    Ok(())
}

/// If a mapping exists for this external subnet, delete it.
pub fn clear_mapping(switch: &Switch, subnet: Ipv4Net) -> DpdResult<()> {
    let mut all = switch.ext_subnet.lock().unwrap();
    trace!(switch.log, "clearing external subnet mapping {subnet}");
    let ent = all.mappings.remove(&subnet);
    if ent.is_some() {
        // delete from table
    }
    Ok(())
}

pub fn reset(switch: &Switch) -> DpdResult<()> {
    let mut all = switch.ext_subnet.lock().unwrap();

    debug!(switch.log, "resetting external subnet table");
    all.mappings.clear();
    /*
    if let Err(e) = nat::reset_ipv6(switch) {
        error!(switch.log, "failed to reset ipv6 nat table: {:?}", e);
    */
    Ok(())
}

pub fn init() -> ExtSubnetData {
    ExtSubnetData {
        mappings: BTreeMap::new(),
    }
}
