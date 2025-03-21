// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Bound;

use chrono::prelude::*;
use slog::debug;

use crate::api_server;
use crate::types::{DpdError, DpdResult};
use crate::{table, Switch};
use common::network::MacAddr;

#[derive(Clone)]
pub struct ArpEntry {
    pub tag: String,
    pub mac: MacAddr,
    pub update: chrono::DateTime<chrono::Utc>,
}

pub struct ArpData {
    v4: BTreeMap<u32, ArpEntry>,
    v6: BTreeMap<u128, ArpEntry>,
}

pub fn add_entry_ipv4(
    switch: &Switch,
    tag: impl ToString,
    ip: Ipv4Addr,
    mac: MacAddr,
) -> DpdResult<()> {
    let mut arp_data = switch.arp.lock().unwrap();
    let idx: u32 = ip.into();

    if let Some(e) = arp_data.v4.get_mut(&idx) {
        if e.mac != mac {
            debug!(
                switch.log,
                "ipv4 arp entry {} changing from {} to {}", ip, e.mac, mac
            );
            table::arp_ipv4::update_entry(switch, ip, mac)?;
            e.mac = mac
        }
        e.update = Utc::now();
    } else {
        debug!(switch.log, "new ipv4 arp entry {} -> {}", ip, mac);
        table::arp_ipv4::add_entry(switch, ip, mac)?;
        let e = ArpEntry {
            tag: tag.to_string(),
            mac,
            update: Utc::now(),
        };
        arp_data.v4.insert(idx, e);
    }
    Ok(())
}

pub fn add_entry_ipv6(
    switch: &Switch,
    tag: impl ToString,
    ip: Ipv6Addr,
    mac: MacAddr,
) -> DpdResult<()> {
    let mut arp_data = switch.arp.lock().unwrap();
    let idx: u128 = ip.into();

    if let Some(e) = arp_data.v6.get_mut(&idx) {
        if e.mac != mac {
            debug!(
                switch.log,
                "ipv6 arp entry {} changing from {} to {}", ip, e.mac, mac
            );
            table::neighbor_ipv6::update_entry(switch, ip, mac)?;
            e.mac = mac
        } else {
            debug!(switch.log, "ipv6 arp entry {} confirming as {}", ip, mac);
        }

        e.update = Utc::now();
    } else {
        debug!(switch.log, "new ipv6 arp entry {} -> {}", ip, mac);
        table::neighbor_ipv6::add_entry(switch, ip, mac)?;
        let e = ArpEntry {
            tag: tag.to_string(),
            mac,
            update: Utc::now(),
        };
        arp_data.v6.insert(idx, e);
    }
    Ok(())
}

pub fn get_entry_ipv4(switch: &Switch, ip: Ipv4Addr) -> DpdResult<ArpEntry> {
    let arp_data = switch.arp.lock().unwrap();
    let idx: u32 = ip.into();

    match arp_data.v4.get(&idx) {
        Some(e) => Ok(e.clone()),
        None => Err(DpdError::Missing("no matching entry".into())),
    }
}

pub fn get_entry_ipv6(switch: &Switch, ip: Ipv6Addr) -> DpdResult<ArpEntry> {
    let arp_data = switch.arp.lock().unwrap();
    let idx: u128 = ip.into();

    match arp_data.v6.get(&idx) {
        Some(e) => Ok(e.clone()),
        None => Err(DpdError::Missing("no matching entry".into())),
    }
}

pub fn delete_entry_ipv4(switch: &Switch, ip: Ipv4Addr) -> DpdResult<()> {
    let mut arp_data = switch.arp.lock().unwrap();
    let idx: u32 = ip.into();

    debug!(switch.log, "deleting ipv4 arp entry {}", ip);
    match arp_data.v4.remove(&idx) {
        Some(r) => {
            debug!(switch.log, "deleted ipv4 arp entry {} -> {}", ip, r.mac);
            table::arp_ipv4::delete_entry(switch, ip)?;
            Ok(())
        }
        None => Err(DpdError::Missing("no matching entry".into())),
    }
}

pub fn delete_entry_ipv6(switch: &Switch, ip: Ipv6Addr) -> DpdResult<()> {
    let mut arp_data = switch.arp.lock().unwrap();
    let idx: u128 = ip.into();

    debug!(switch.log, "deleting ipv6 neighbor entry {}", ip);
    match arp_data.v6.remove(&idx) {
        Some(r) => {
            debug!(
                switch.log,
                "deleted ipv6 neighbor entry {} -> {}", ip, r.mac
            );
            table::neighbor_ipv6::delete_entry(switch, ip)?;
            Ok(())
        }
        None => Err(DpdError::Missing("no matching entry".into())),
    }
}

pub fn get_range_ipv4(
    switch: &Switch,
    last: Option<&Ipv4Addr>,
    mut max: u32,
) -> DpdResult<Vec<api_server::ArpEntry>> {
    if max > 32 {
        max = 32
    };

    let lower_bound = match last {
        None => Bound::Unbounded,
        Some(last) => Bound::Excluded(u32::from(*last)),
    };

    let arp_data = switch.arp.lock().unwrap();
    let rval = arp_data
        .v4
        .range((lower_bound, Bound::Unbounded))
        .take(usize::try_from(max).expect("invalid usize"))
        .map(|(ip, entry)| api_server::ArpEntry {
            tag: entry.tag.clone(),
            ip: IpAddr::V4((*ip).into()),
            mac: entry.mac,
            update: entry.update.to_rfc3339(),
        })
        .collect();

    Ok(rval)
}

pub fn get_range_ipv6(
    switch: &Switch,
    last: Option<&Ipv6Addr>,
    mut max: u32,
) -> DpdResult<Vec<api_server::ArpEntry>> {
    max = std::cmp::max(max, 32);

    let lower_bound = match last {
        None => Bound::Unbounded,
        Some(last) => Bound::Excluded(u128::from(*last)),
    };

    let arp_data = switch.arp.lock().unwrap();
    let rval = arp_data
        .v6
        .range((lower_bound, Bound::Unbounded))
        .take(usize::try_from(max).expect("invalid usize"))
        .map(|(ip, entry)| api_server::ArpEntry {
            tag: entry.tag.clone(),
            ip: IpAddr::V6((*ip).into()),
            mac: entry.mac,
            update: entry.update.to_rfc3339(),
        })
        .collect();

    Ok(rval)
}

pub fn reset_ipv4_tag(switch: &Switch, tag: &str) {
    debug!(switch.log, "resetting ipv4 arp table for tag {}", tag);

    let delete: Vec<Ipv4Addr> = {
        let arp_data = switch.arp.lock().unwrap();
        arp_data
            .v4
            .iter()
            .filter(|(_, entry)| entry.tag.as_str() == tag)
            .map(|(ip, _)| (*ip).into())
            .collect()
    };

    for ip in delete {
        let _ = delete_entry_ipv4(switch, ip);
    }
}

pub fn reset_ipv4(switch: &Switch) -> DpdResult<()> {
    debug!(switch.log, "resetting ipv4 arp table");

    let mut arp_data = switch.arp.lock().unwrap();
    arp_data.v4 = BTreeMap::new();
    table::arp_ipv4::reset(switch)?;
    Ok(())
}

pub fn reset_ipv6_tag(switch: &Switch, tag: &str) {
    debug!(switch.log, "resetting ipv6 arp table for tag {}", tag);

    let delete: Vec<Ipv6Addr> = {
        let arp_data = switch.arp.lock().unwrap();
        arp_data
            .v6
            .iter()
            .filter(|(_, entry)| entry.tag.as_str() == tag)
            .map(|(ip, _)| (*ip).into())
            .collect()
    };

    for ip in delete {
        let _ = delete_entry_ipv6(switch, ip);
    }
}

pub fn reset_ipv6(switch: &Switch) -> DpdResult<()> {
    debug!(switch.log, "resetting ipv6 neighbor table");

    let mut arp_data = switch.arp.lock().unwrap();
    arp_data.v6 = BTreeMap::new();
    table::neighbor_ipv6::reset(switch)?;
    Ok(())
}

pub fn init() -> ArpData {
    ArpData {
        v4: BTreeMap::new(),
        v6: BTreeMap::new(),
    }
}
