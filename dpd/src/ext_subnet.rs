// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use slog::{debug, error, trace};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::table::extsub;
use crate::types::{DpdError, DpdResult};
use crate::Switch;
use common::ext_subnet::ExtSubnetEntry;
use common::network::InstanceTarget;
use oxnet::Ipv4Net;

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
) -> DpdResult<InstanceTarget> {
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
    tgt: InstanceTarget,
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
    match extsub::add_entry(switch, subnet, tgt) {
        Err(e) => {
            error!(
                switch.log,
                "failed to add external subnet entry {} -> {:?}: {:?}",
                subnet,
                tgt,
                e
            );
            Err(e)
        }
        _ => {
            debug!(
                switch.log,
                "added external subnet entry {} -> {:?}", subnet, tgt
            );
            all.mappings.insert(subnet, new_entry);
            Ok(())
        }
    }
}

/// If a mapping exists for this external subnet, delete it.
pub fn clear_mapping(switch: &Switch, subnet: Ipv4Net) -> DpdResult<()> {
    let mut all = switch.ext_subnet.lock().unwrap();
    trace!(switch.log, "clearing external subnet mapping {subnet}");

    let Some(ent) = all.mappings.get(&subnet) else {
        return Ok(());
    };

    match extsub::delete_entry(switch, subnet) {
        Err(e) => {
            error!(
                switch.log,
                "failed to delete external subnet entry {} -> {:?}: {:?}",
                subnet,
                ent,
                e
            );
            Err(e)
        }
        _ => {
            debug!(
                switch.log,
                "deleted external subnet entry {} -> {:?}", subnet, ent
            );
            all.mappings.remove(&subnet);
            Ok(())
        }
    }
}

pub fn reset(switch: &Switch) -> DpdResult<()> {
    let mut all = switch.ext_subnet.lock().unwrap();

    debug!(switch.log, "resetting external subnet table");
    all.mappings.clear();
    if let Err(e) = extsub::reset(switch) {
        error!(switch.log, "failed to reset external subnet table: {:?}", e);
    }
    Ok(())
}

pub fn init() -> ExtSubnetData {
    ExtSubnetData {
        mappings: BTreeMap::new(),
    }
}
