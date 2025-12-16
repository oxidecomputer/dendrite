// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use slog::{debug, error, trace};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Switch;
use crate::table::extsub_ipv4;
use crate::table::extsub_ipv6;
use crate::types::{DpdError, DpdResult};
use common::ext_subnet::{ExtSubnetIpv4Entry, ExtSubnetIpv6Entry};
use common::network::InstanceTarget;
use oxnet::{Ipv4Net, Ipv6Net};

pub struct ExtSubnetData {
    v4_subnets: BTreeMap<Ipv4Net, ExtSubnetIpv4Entry>,
    v6_subnets: BTreeMap<Ipv6Net, ExtSubnetIpv6Entry>,
}

/// Paginates through `ExtSubnetIpv4Entry`
pub fn get_ipv4_mappings(
    switch: &Switch,
    last_subnet: Option<Ipv4Net>,
    mut max: usize,
) -> Vec<ExtSubnetIpv4Entry> {
    max = std::cmp::min(max, 64);
    let all = switch.ext_subnet.lock().unwrap();
    let subnet = last_subnet
        .unwrap_or(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap());

    all.v4_subnets
        .values()
        .filter(|e| e.subnet > subnet)
        .take(max)
        .cloned()
        .collect()
}

/// Find the target, if any, of the provided external subnet
pub fn get_ipv4_mapping(
    switch: &Switch,
    subnet: Ipv4Net,
) -> DpdResult<InstanceTarget> {
    let all = switch.ext_subnet.lock().unwrap();
    match all.v4_subnets.get(&subnet) {
        Some(e) => Ok(e.tgt),
        None => Err(DpdError::Missing("no mapping".into())),
    }
}

/// Map the provided external subnet to the internal address/vni.
pub fn set_ipv4_mapping(
    switch: &Switch,
    subnet: Ipv4Net,
    tgt: InstanceTarget,
) -> DpdResult<()> {
    let new_entry = ExtSubnetIpv4Entry { subnet, tgt };
    trace!(switch.log, "adding external subnet entry {}", new_entry);

    let mut all = switch.ext_subnet.lock().unwrap();
    if let Some(e) = all.v4_subnets.get_mut(&subnet) {
        if e == &new_entry {
            // entry already exists
            return Ok(());
        } else {
            return Err(DpdError::Exists("conflicting mapping".into()));
        }
    }
    match extsub_ipv4::add_entry(switch, subnet, tgt) {
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
            all.v4_subnets.insert(subnet, new_entry);
            Ok(())
        }
    }
}

/// If a mapping exists for this external subnet, delete it.
pub fn clear_ipv4_mapping(switch: &Switch, subnet: Ipv4Net) -> DpdResult<()> {
    let mut all = switch.ext_subnet.lock().unwrap();
    trace!(switch.log, "clearing external subnet mapping {subnet}");

    let Some(ent) = all.v4_subnets.get(&subnet) else {
        return Ok(());
    };

    match extsub_ipv4::delete_entry(switch, subnet) {
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
            all.v4_subnets.remove(&subnet);
            Ok(())
        }
    }
}

/// Paginates through `ExtSubnetIpv6Entry`
pub fn get_ipv6_mappings(
    switch: &Switch,
    last_subnet: Option<Ipv6Net>,
    mut max: usize,
) -> Vec<ExtSubnetIpv6Entry> {
    max = std::cmp::min(max, 64);
    let all = switch.ext_subnet.lock().unwrap();
    let subnet = last_subnet.unwrap_or(
        Ipv6Net::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap(),
    );

    all.v6_subnets
        .values()
        .filter(|e| e.subnet > subnet)
        .take(max)
        .cloned()
        .collect()
}

/// Find the target, if any, of the provided external subnet
pub fn get_ipv6_mapping(
    switch: &Switch,
    subnet: Ipv6Net,
) -> DpdResult<InstanceTarget> {
    let all = switch.ext_subnet.lock().unwrap();
    match all.v6_subnets.get(&subnet) {
        Some(e) => Ok(e.tgt),
        None => Err(DpdError::Missing("no mapping".into())),
    }
}

/// Map the provided external subnet to the internal address/vni.
pub fn set_ipv6_mapping(
    switch: &Switch,
    subnet: Ipv6Net,
    tgt: InstanceTarget,
) -> DpdResult<()> {
    let new_entry = ExtSubnetIpv6Entry { subnet, tgt };
    trace!(switch.log, "adding external subnet entry {}", new_entry);

    let mut all = switch.ext_subnet.lock().unwrap();
    if let Some(e) = all.v6_subnets.get_mut(&subnet) {
        if e == &new_entry {
            // entry already exists
            return Ok(());
        } else {
            return Err(DpdError::Exists("conflicting mapping".into()));
        }
    }
    match extsub_ipv6::add_entry(switch, subnet, tgt) {
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
            all.v6_subnets.insert(subnet, new_entry);
            Ok(())
        }
    }
}

/// If a mapping exists for this external subnet, delete it.
pub fn clear_ipv6_mapping(switch: &Switch, subnet: Ipv6Net) -> DpdResult<()> {
    let mut all = switch.ext_subnet.lock().unwrap();
    trace!(switch.log, "clearing external subnet mapping {subnet}");

    let Some(ent) = all.v6_subnets.get(&subnet) else {
        return Ok(());
    };

    match extsub_ipv6::delete_entry(switch, subnet) {
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
            all.v6_subnets.remove(&subnet);
            Ok(())
        }
    }
}

pub fn reset(switch: &Switch) -> DpdResult<()> {
    let mut all = switch.ext_subnet.lock().unwrap();

    debug!(switch.log, "resetting external subnet table");
    all.v4_subnets.clear();
    if let Err(e) = extsub_ipv4::reset(switch) {
        error!(
            switch.log,
            "failed to reset external ipv4 subnet table: {:?}", e
        );
    }
    all.v6_subnets.clear();
    if let Err(e) = extsub_ipv6::reset(switch) {
        error!(
            switch.log,
            "failed to reset external ipv6 subnet table: {:?}", e
        );
    }
    Ok(())
}

pub fn init() -> ExtSubnetData {
    ExtSubnetData {
        v4_subnets: BTreeMap::new(),
        v6_subnets: BTreeMap::new(),
    }
}
