// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use slog::{debug, error, trace};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Bound;

use crate::table::nat;
use crate::types::{DpdError, DpdResult};
use crate::Switch;
use common::nat::{Ipv4Nat, Ipv6Nat, NatTarget};

trait PortRange {
    fn low(&self) -> u16;
    fn high(&self) -> u16;
}

#[derive(PartialEq)]
pub(crate) struct Ipv6NatEntry {
    pub low: u16,
    pub high: u16,
    pub tgt: NatTarget,
}

impl PortRange for Ipv6NatEntry {
    fn low(&self) -> u16 {
        self.low
    }
    fn high(&self) -> u16 {
        self.high
    }
}

impl fmt::Display for Ipv6NatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}-{}] -> {}", self.low, self.high, self.tgt)
    }
}

#[derive(Clone, PartialEq)]
pub(crate) struct Ipv4NatEntry {
    pub low: u16,
    pub high: u16,
    pub tgt: NatTarget,
}

impl PortRange for Ipv4NatEntry {
    fn low(&self) -> u16 {
        self.low
    }
    fn high(&self) -> u16 {
        self.high
    }
}

impl fmt::Display for Ipv4NatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}-{}] -> {}", self.low, self.high, self.tgt)
    }
}
pub struct NatData {
    ipv6_mappings: BTreeMap<Ipv6Addr, Vec<Ipv6NatEntry>>,
    ipv4_mappings: BTreeMap<Ipv4Addr, Vec<Ipv4NatEntry>>,
    ipv4_generation: i64,
}

fn ipv6_entry(ipv6: Ipv6Addr, e: &Ipv6NatEntry) -> String {
    format!("{ipv6}/{e}")
}

fn ipv4_entry(ipv4: Ipv4Addr, e: &Ipv4NatEntry) -> String {
    format!("{ipv4}/{e}")
}

fn overlaps<T: PortRange>(e: &T, low: u16, high: u16) -> bool {
    let elow = e.low();
    let ehigh = e.high();

    (elow >= low && elow <= high)
        || (ehigh >= low && ehigh <= high)
        || (elow <= low && ehigh >= high)
}

/// find index of first mapping that overlaps with supplied port range
fn find_first_mapping<T: PortRange>(
    entries: &[T],
    low: u16,
    high: u16,
) -> Option<usize> {
    entries.iter().position(|e| overlaps(e, low, high))
}

/// find indices of all mappings that overlap with supplied port range
fn find_mappings<T: PortRange>(
    entries: &[T],
    low: u16,
    high: u16,
) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, e)| overlaps(*e, low, high))
        .map(|(i, _)| i)
        .collect()
}

fn find_space<T: PortRange>(
    entries: &[T],
    low: u16,
    high: u16,
) -> Option<usize> {
    let len = entries.len();

    for (idx, e) in entries.iter().enumerate() {
        if overlaps(e, low, high) {
            return None;
        }
        if e.low() >= high && (idx == len - 1 || entries[idx + 1].low() >= high)
        {
            return Some(idx);
        }
    }
    Some(len)
}

#[test]
fn test_mapping() {
    use super::MacAddr;
    use common::nat::Vni;

    let dummy_target = NatTarget {
        internal_ip: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        inner_mac: MacAddr::new(0, 0, 0, 0, 0, 0),
        vni: Vni::new(0).unwrap(),
    };

    let entries = vec![
        Ipv4NatEntry {
            low: 1,
            high: 4,
            tgt: dummy_target,
        },
        Ipv4NatEntry {
            low: 7,
            high: 10,
            tgt: dummy_target,
        },
        Ipv4NatEntry {
            low: 12,
            high: 18,
            tgt: dummy_target,
        },
    ];

    assert_eq!(find_first_mapping(&entries, 2, 2), Some(0));
    assert_eq!(find_first_mapping(&entries, 4, 5), Some(0));
    assert_eq!(find_first_mapping(&entries, 5, 6), None);
    assert_eq!(find_first_mapping(&entries, 5, 7), Some(1));
    assert_eq!(find_first_mapping(&entries, 2, 6), Some(0));
    assert_eq!(find_first_mapping(&entries, 5, 5), None);
    assert_eq!(find_first_mapping(&entries, 5, 20), Some(1));
    assert_eq!(find_first_mapping(&entries, 12, 12), Some(2));
    assert_eq!(find_first_mapping(&entries, 18, 18), Some(2));
    assert_eq!(find_first_mapping(&entries, 19, 19), None);
    assert_eq!(find_first_mapping(&entries, 19, 40), None);
    assert_eq!(find_first_mapping(&entries, 0, 0), None);
    assert_eq!(find_first_mapping(&entries, 0, 2), Some(0));
    assert_eq!(find_space(&entries, 0, 0), Some(0));
    assert_eq!(find_space(&entries, 0, 1), None);
    assert_eq!(find_space(&entries, 11, 11), Some(2));
    assert_eq!(find_space(&entries, 19, 32), Some(3));
    assert_eq!(find_space(&entries, 0, 2), None);
    assert_eq!(find_space(&entries, 3, 5), None);
    assert_eq!(find_space(&entries, 3, 8), None);
}

pub fn get_ipv6_addrs_range(
    switch: &Switch,
    last_addr: Option<Ipv6Addr>,
    mut max: usize,
) -> Vec<Ipv6Addr> {
    max = std::cmp::min(max, 64);
    let nat = switch.nat.lock().unwrap();

    let range = match last_addr {
        Some(a) => (Bound::Excluded(a), Bound::Unbounded),
        None => (Bound::Unbounded, Bound::Unbounded),
    };

    nat.ipv6_mappings
        .range(range)
        .take(max)
        .map(|(ip, _)| *ip)
        .collect()
}

/// Paginates through `Ipv6Nat` using `last_port` as the starting offset
pub fn get_ipv6_mappings_range(
    switch: &Switch,
    external: Ipv6Addr,
    last_port: Option<u16>,
    mut max: usize,
) -> Vec<Ipv6Nat> {
    max = std::cmp::min(max, 64);
    let nat = switch.nat.lock().unwrap();
    let mappings = match nat.ipv6_mappings.get(&external) {
        Some(m) => m,
        None => return Vec::new(),
    };

    let port = match last_port {
        None => 0,
        Some(l) => l + 1,
    };

    let mut entries = Vec::new();

    for m in mappings {
        if m.low >= port {
            entries.push(Ipv6Nat {
                external,
                low: m.low,
                high: m.high,
                target: m.tgt,
            });
            if entries.len() >= max {
                break;
            }
        }
    }
    entries
}

/// Find the first `NatTarget` where its `Ipv6NatEntry` matches the provided
/// `Ipv6Addr` and overlaps with the provided port range
pub fn get_ipv6_mapping(
    switch: &Switch,
    nat_ip: Ipv6Addr,
    low: u16,
    high: u16,
) -> DpdResult<NatTarget> {
    let nat = switch.nat.lock().unwrap();
    if let Some(v) = nat.ipv6_mappings.get(&nat_ip) {
        if let Some(idx) = find_first_mapping(v, low, high) {
            return Ok(v[idx].tgt);
        }
    }
    Err(DpdError::Missing("no mapping".into()))
}

pub fn set_ipv6_mapping(
    switch: &Switch,
    nat_ip: Ipv6Addr,
    low: u16,
    high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let new_entry = Ipv6NatEntry { low, high, tgt };
    let full = ipv6_entry(nat_ip, &new_entry);
    trace!(switch.log, "adding nat entry {}", full);

    if high < low {
        return Err(DpdError::Invalid("invalid port range".into()));
    }

    let mut nat = switch.nat.lock().unwrap();
    let (entries, idx) = match nat.ipv6_mappings.get_mut(&nat_ip) {
        Some(e) => {
            if e.iter().any(|entry| *entry == new_entry) {
                // entry already exists
                return Ok(());
            }
            match find_space(e, low, high) {
                Some(i) => (e, i),
                None => {
                    trace!(
                        switch.log,
                        "unable to add nat entry {}: conflicting mapping",
                        full
                    );
                    return Err(DpdError::Exists("conflicting mapping".into()));
                }
            }
        }
        None => {
            nat.ipv6_mappings.insert(nat_ip, Vec::new());
            (nat.ipv6_mappings.get_mut(&nat_ip).unwrap(), 0)
        }
    };

    match nat::add_ipv6_entry(switch, nat_ip, low, high, tgt) {
        Err(e) => {
            error!(switch.log, "failed to add {}: {:?}", full, e);
            Err(e)
        }
        _ => {
            debug!(switch.log, "added nat entry {}", full);
            entries.insert(idx, new_entry);
            Ok(())
        }
    }
}

/// Find the first `NatTarget` where its `Ipv6NatEntry` matches the provided
/// `Ipv6Addr` and overlaps with the provided port range, then remove it.
pub fn clear_ipv6_mapping(
    switch: &Switch,
    nat_ip: Ipv6Addr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let mut nat = switch.nat.lock().unwrap();
    trace!(switch.log, "clearing nat entry {}/{}-{}", nat_ip, low, high);

    if let Some(mappings) = nat.ipv6_mappings.get_mut(&nat_ip) {
        if let Some(idx) = find_first_mapping(mappings, low, high) {
            let ent = mappings.remove(idx);
            if mappings.is_empty() {
                nat.ipv6_mappings.remove(&nat_ip);
            }
            let full = ipv6_entry(nat_ip, &ent);
            return match nat::delete_ipv6_entry(
                switch, nat_ip, ent.low, ent.high,
            ) {
                Err(e) => {
                    error!(switch.log, "failed to clear {}: {:?}", full, e);
                    Err(e)
                }
                _ => {
                    debug!(switch.log, "cleared nat entry {}", full);
                    Ok(())
                }
            };
        }
    }

    Ok(())
}

pub fn get_ipv4_addrs_range(
    switch: &Switch,
    last_addr: Option<Ipv4Addr>,
    mut max: usize,
) -> Vec<Ipv4Addr> {
    max = std::cmp::min(max, 64);
    let nat = switch.nat.lock().unwrap();

    let range = match last_addr {
        Some(a) => (Bound::Excluded(a), Bound::Unbounded),
        None => (Bound::Unbounded, Bound::Unbounded),
    };

    nat.ipv4_mappings
        .range(range)
        .take(max)
        .map(|(ip, _)| *ip)
        .collect()
}

/// Paginates through `Ipv4Nat` using `last_port` as the starting offset
pub fn get_ipv4_mappings_range(
    switch: &Switch,
    external: Ipv4Addr,
    last_port: Option<u16>,
    mut max: usize,
) -> Vec<Ipv4Nat> {
    max = std::cmp::min(max, 64);
    let nat = switch.nat.lock().unwrap();
    let mappings = match nat.ipv4_mappings.get(&external) {
        Some(m) => m,
        None => return Vec::new(),
    };

    let port = match last_port {
        None => 0,
        Some(l) => l + 1,
    };

    let mut entries = Vec::new();

    for m in mappings {
        if m.low >= port {
            entries.push(Ipv4Nat {
                external,
                low: m.low,
                high: m.high,
                target: m.tgt,
            });
            if entries.len() >= max {
                break;
            }
        }
    }
    entries
}

/// Find the first `NatTarget` where its `Ipv4NatEntry` matches the provided
/// `Ipv4Addr` and overlaps with the provided port range
pub fn get_ipv4_mapping(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
) -> DpdResult<NatTarget> {
    let nat = switch.nat.lock().unwrap();
    if let Some(v) = nat.ipv4_mappings.get(&nat_ip) {
        if let Some(idx) = find_first_mapping(v, low, high) {
            return Ok(v[idx].tgt);
        }
    }
    Err(DpdError::Missing("no mapping".into()))
}

pub fn set_ipv4_mapping(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let new_entry = Ipv4NatEntry { low, high, tgt };
    let full = ipv4_entry(nat_ip, &new_entry);
    trace!(switch.log, "adding nat entry {}", full);

    if high < low {
        return Err(DpdError::Invalid("invalid port range".into()));
    }

    let mut nat = switch.nat.lock().unwrap();
    let (entries, idx) = match nat.ipv4_mappings.get_mut(&nat_ip) {
        Some(e) => {
            if e.iter().any(|entry| *entry == new_entry) {
                // entry already exists
                return Ok(());
            }
            match find_space(e, low, high) {
                Some(i) => (e, i),
                None => {
                    error!(
                        switch.log,
                        "unable to add {}: conflicting mapping", full
                    );
                    return Err(DpdError::Exists("conflicting mapping".into()));
                }
            }
        }
        None => {
            nat.ipv4_mappings.insert(nat_ip, Vec::new());
            (nat.ipv4_mappings.get_mut(&nat_ip).unwrap(), 0)
        }
    };

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
}

/// Find the first `NatTarget` where its `Ipv4NatEntry` matches the provided
/// `Ipv4Addr` and overlaps with the provided port range, then remove it.
pub fn clear_ipv4_mapping(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let mut nat = switch.nat.lock().unwrap();
    trace!(
        switch.log,
        "clearing nat entry covering {}/{}-{}",
        nat_ip,
        low,
        high
    );

    if let Some(mappings) = nat.ipv4_mappings.get_mut(&nat_ip) {
        if let Some(idx) = find_first_mapping(mappings, low, high) {
            let ent = mappings.remove(idx);
            if mappings.is_empty() {
                nat.ipv4_mappings.remove(&nat_ip);
            }
            let full = ipv4_entry(nat_ip, &ent);
            return match nat::delete_ipv4_entry(
                switch, nat_ip, ent.low, ent.high,
            ) {
                Err(e) => {
                    error!(switch.log, "failed to clear {}: {:?}", full, e);
                    Err(e)
                }
                _ => {
                    debug!(switch.log, "cleared nat entry {}", full);
                    Ok(())
                }
            };
        }
    }

    Ok(())
}

/// Deletes any `Ipv4NatEntry` where each entry matches the provided
/// `Ipv4Addr` and overlaps with the provided port range
pub fn clear_overlapping_ipv4_mappings(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let mut nat = switch.nat.lock().unwrap();
    trace!(
        switch.log,
        "clearing all nat entries overlapping with {}/{}-{}",
        nat_ip,
        low,
        high
    );

    if let Some(mappings) = nat.ipv4_mappings.get_mut(&nat_ip) {
        let mut mappings_to_delete = find_mappings(mappings, low, high);
        // delete starting with the last index first, or you'll end up shifting the
        // collection underneath you
        mappings_to_delete.reverse();
        for idx in mappings_to_delete {
            let ent = mappings.remove(idx);
            let full = ipv4_entry(nat_ip, &ent);
            match nat::delete_ipv4_entry(switch, nat_ip, ent.low, ent.high) {
                Err(e) => {
                    error!(switch.log, "failed to clear {}: {:?}", full, e);
                    return Err(e);
                }
                _ => {
                    debug!(switch.log, "cleared nat entry {}", full);
                }
            };
        }
        if mappings.is_empty() {
            nat.ipv4_mappings.remove(&nat_ip);
        }
    }

    Ok(())
}

pub fn reset_ipv6(switch: &Switch) -> DpdResult<()> {
    let mut nat = switch.nat.lock().unwrap();

    debug!(switch.log, "resetting ipv6 nat tables");
    nat.ipv6_mappings.clear();
    if let Err(e) = nat::reset_ipv6(switch) {
        error!(switch.log, "failed to reset ipv6 nat table: {:?}", e);
        Err(e)
    } else {
        Ok(())
    }
}

pub fn reset_ipv4(switch: &Switch) -> DpdResult<()> {
    let mut nat = switch.nat.lock().unwrap();

    debug!(switch.log, "resetting ipv4 nat tables");
    nat.ipv4_mappings.clear();
    if let Err(e) = nat::reset_ipv4(switch) {
        error!(switch.log, "failed to reset ipv4 nat table: {:?}", e);
        Err(e)
    } else {
        Ok(())
    }
}

pub fn set_ipv4_nat_generation(switch: &Switch, gen: i64) {
    let mut nat = switch.nat.lock().unwrap();

    debug!(switch.log, "setting nat generation");
    nat.ipv4_generation = gen;
}

pub fn get_ipv4_nat_generation(switch: &Switch) -> i64 {
    let nat = switch.nat.lock().unwrap();

    debug!(switch.log, "fetching nat generation");
    nat.ipv4_generation
}

pub fn init() -> NatData {
    NatData {
        ipv6_mappings: BTreeMap::new(),
        ipv4_mappings: BTreeMap::new(),
        ipv4_generation: 0,
    }
}
