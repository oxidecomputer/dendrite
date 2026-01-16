// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use slog::{debug, error, trace};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::Switch;
use crate::table::{attached_subnet_v4, attached_subnet_v6};
use crate::types::{DpdError, DpdResult};
use common::attached_subnet::AttachedSubnetEntry;
use common::network::InstanceTarget;
use oxnet::IpNet;

pub struct AttachedSubnetData {
    mappings: BTreeMap<IpNet, AttachedSubnetEntry>,
}

/// Paginates through `AttachedSubnetEntry`
pub fn get_mappings(
    switch: &Switch,
    last_subnet: Option<IpNet>,
    mut max: usize,
) -> Vec<AttachedSubnetEntry> {
    max = std::cmp::min(max, 64);
    let all = switch.attached_subnet.lock().unwrap();
    let subnet = last_subnet
        .unwrap_or(IpNet::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0).unwrap());

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
    subnet: IpNet,
) -> DpdResult<InstanceTarget> {
    let all = switch.attached_subnet.lock().unwrap();
    match all.mappings.get(&subnet) {
        Some(e) => Ok(e.tgt),
        None => Err(DpdError::Missing("no mapping".into())),
    }
}

/// Map the provided external subnet to the internal address/vni.
pub fn set_mapping(
    switch: &Switch,
    subnet: IpNet,
    tgt: InstanceTarget,
) -> DpdResult<()> {
    let new_entry = AttachedSubnetEntry { subnet, tgt };
    trace!(switch.log, "adding external subnet entry {}", new_entry);

    let mut all = switch.attached_subnet.lock().unwrap();
    if let Some(e) = all.mappings.get_mut(&subnet) {
        if e == &new_entry {
            // entry already exists
            return Ok(());
        } else {
            return Err(DpdError::Exists("conflicting mapping".into()));
        }
    }
    match match subnet {
        IpNet::V4(subnet) => attached_subnet_v4::add_entry(switch, subnet, tgt),
        IpNet::V6(subnet) => attached_subnet_v6::add_entry(switch, subnet, tgt),
    } {
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
pub fn clear_mapping(switch: &Switch, subnet: IpNet) -> DpdResult<()> {
    let mut all = switch.attached_subnet.lock().unwrap();
    trace!(switch.log, "clearing external subnet mapping {subnet}");

    let Some(ent) = all.mappings.get(&subnet) else {
        return Ok(());
    };

    match match subnet {
        IpNet::V4(subnet) => attached_subnet_v4::delete_entry(switch, subnet),
        IpNet::V6(subnet) => attached_subnet_v6::delete_entry(switch, subnet),
    } {
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
    let mut all = switch.attached_subnet.lock().unwrap();

    debug!(switch.log, "resetting external subnet table");
    all.mappings.clear();
    if let Err(e) = attached_subnet_v4::reset(switch) {
        error!(
            switch.log,
            "failed to reset external ipv4 subnet table: {:?}", e
        );
    }
    if let Err(e) = attached_subnet_v6::reset(switch) {
        error!(
            switch.log,
            "failed to reset external ipv6 subnet table: {:?}", e
        );
    }
    Ok(())
}

pub fn init() -> AttachedSubnetData {
    AttachedSubnetData {
        mappings: BTreeMap::new(),
    }
}
