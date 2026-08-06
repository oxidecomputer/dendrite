// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use slog::{debug, error, trace};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Bound;
use std::sync::{Mutex, MutexGuard};

use crate::Switch;
use crate::table;
use crate::table::nat::{NatAddress, add_entry, delete_entry};
use crate::types::{DpdError, DpdResult};
use common::network::NatTarget;

/// An inclusive range of ports, guaranteed by construction to have
/// `low <= high`.
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct PortRange {
    low: u16,
    high: u16,
}

#[derive(Debug)]
pub(crate) struct InvalidPortRange;

impl From<InvalidPortRange> for DpdError {
    fn from(_: InvalidPortRange) -> Self {
        DpdError::Invalid("invalid port range".into())
    }
}

impl PortRange {
    fn new(low: u16, high: u16) -> Result<Self, InvalidPortRange> {
        if low <= high {
            Ok(PortRange { low, high })
        } else {
            Err(InvalidPortRange)
        }
    }

    fn overlaps(self, other: PortRange) -> bool {
        self.low <= other.high && self.high >= other.low
    }

    pub(crate) fn low(self) -> u16 {
        self.low
    }

    pub(crate) fn high(self) -> u16 {
        self.high
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}-{}]", self.low, self.high)
    }
}

#[derive(Clone, PartialEq)]
pub(crate) struct NatEntry {
    pub l4_ports: PortRange,
    pub tgt: NatTarget,
}

impl fmt::Display for NatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.l4_ports, self.tgt)
    }
}

/// find index of first mapping that overlaps with supplied port range
fn find_first_mapping(
    mut ranges: impl Iterator<Item = PortRange>,
    range_to_find: PortRange,
) -> Option<usize> {
    ranges.position(|e| e.overlaps(range_to_find))
}

/// find indices of all mappings that overlap with supplied port range
fn find_mappings(
    ranges: impl Iterator<Item = PortRange>,
    range_to_find: PortRange,
) -> Vec<usize> {
    ranges
        .enumerate()
        .filter(|(_, e)| e.overlaps(range_to_find))
        .map(|(i, _)| i)
        .collect()
}

fn find_space(
    ranges: impl ExactSizeIterator<Item = PortRange>,
    candidate_range: PortRange,
) -> Option<usize> {
    let len = ranges.len();
    let iter = ranges.enumerate();

    for (idx, e) in iter {
        if e.overlaps(candidate_range) {
            return None;
        }
        if e.low >= candidate_range.high {
            return Some(idx);
        }
    }
    Some(len)
}

#[test]
fn test_mapping() {
    let entries = [
        PortRange::new(1, 4).unwrap(),
        PortRange::new(7, 10).unwrap(),
        PortRange::new(12, 18).unwrap(),
    ];

    let first_mapping = |low, high| {
        find_first_mapping(
            entries.iter().copied(),
            PortRange::new(low, high).unwrap(),
        )
    };
    let space = |low, high| {
        find_space(entries.iter().copied(), PortRange::new(low, high).unwrap())
    };

    assert_eq!(first_mapping(2, 2), Some(0));
    assert_eq!(first_mapping(4, 5), Some(0));
    assert_eq!(first_mapping(5, 6), None);
    assert_eq!(first_mapping(5, 7), Some(1));
    assert_eq!(first_mapping(2, 6), Some(0));
    assert_eq!(first_mapping(5, 5), None);
    assert_eq!(first_mapping(5, 20), Some(1));
    assert_eq!(first_mapping(12, 12), Some(2));
    assert_eq!(first_mapping(18, 18), Some(2));
    assert_eq!(first_mapping(19, 19), None);
    assert_eq!(first_mapping(19, 40), None);
    assert_eq!(first_mapping(0, 0), None);
    assert_eq!(first_mapping(0, 2), Some(0));
    assert_eq!(space(0, 0), Some(0));
    assert_eq!(space(0, 1), None);
    assert_eq!(space(5, 8), None);
    assert_eq!(space(11, 11), Some(2));
    assert_eq!(space(19, 32), Some(3));
    assert_eq!(space(0, 2), None);
    assert_eq!(space(3, 5), None);
    assert_eq!(space(3, 8), None);
}

type NatMappings<A> = BTreeMap<A, Vec<NatEntry>>;

pub struct NatData {
    ipv4: NatMappings<Ipv4Addr>,
    ipv6: NatMappings<Ipv6Addr>,
    generation: i64,
}

/// Ties an address family to its NAT table inside `NatData`.
pub(crate) trait NatFamily: NatAddress {
    fn mappings(data: &mut NatData) -> &mut NatMappings<Self>;
}

impl NatFamily for Ipv4Addr {
    fn mappings(data: &mut NatData) -> &mut NatMappings<Ipv4Addr> {
        &mut data.ipv4
    }
}

impl NatFamily for Ipv6Addr {
    fn mappings(data: &mut NatData) -> &mut NatMappings<Ipv6Addr> {
        &mut data.ipv6
    }
}

pub struct Nat(Mutex<NatData>);

impl Nat {
    pub(crate) fn new() -> Self {
        Nat(Mutex::new(NatData {
            ipv4: BTreeMap::new(),
            ipv6: BTreeMap::new(),
            generation: 0,
        }))
    }

    fn lock(&self) -> MutexGuard<'_, NatData> {
        self.0.lock().unwrap()
    }
}

pub(crate) fn generation(switch: &Switch) -> i64 {
    let data = switch.nat.lock();
    trace!(switch.log, "fetching nat generation");
    data.generation
}

pub(crate) fn set_generation(switch: &Switch, generation: i64) {
    let mut data = switch.nat.lock();
    trace!(switch.log, "setting nat generation {generation}");
    data.generation = generation;
}

pub(crate) fn get_addrs_range<A: NatFamily>(
    switch: &Switch,
    last_addr: Option<A>,
    max: usize,
) -> Vec<A> {
    let max = max.min(64);

    let range = match last_addr {
        Some(a) => (Bound::Excluded(a), Bound::Unbounded),
        None => (Bound::Unbounded, Bound::Unbounded),
    };

    let mut data = switch.nat.lock();
    A::mappings(&mut data).range(range).take(max).map(|(ip, _)| *ip).collect()
}

/// Paginates through the mappings for one address, using `last_port` as
/// the starting offset
pub(crate) fn get_mappings_range<A: NatFamily>(
    switch: &Switch,
    external: A,
    last_port: Option<u16>,
    max: usize,
) -> Vec<A::Reservation> {
    let max = max.min(64);

    let port = match last_port {
        None => 0,
        Some(l) => l + 1,
    };

    let mut data = switch.nat.lock();
    A::mappings(&mut data)
        .get(&external)
        .map(|entries| {
            entries
                .iter()
                .filter(|e| e.l4_ports.low >= port)
                .take(max)
                .map(|e| external.reservation(e.l4_ports, e.tgt))
                .collect()
        })
        .unwrap_or_default()
}

/// Find the first `NatTarget` where its `NatEntry` overlaps with the
/// provided port range
pub(crate) fn get_mapping<A: NatFamily>(
    switch: &Switch,
    nat_ip: A,
    low: u16,
    high: u16,
) -> DpdResult<NatTarget> {
    let range = PortRange::new(low, high)?;
    let mut data = switch.nat.lock();
    if let Some(v) = A::mappings(&mut data).get(&nat_ip)
        && let Some(idx) =
            find_first_mapping(v.iter().map(|e| e.l4_ports), range)
    {
        return Ok(v[idx].tgt);
    }
    Err(DpdError::Missing("no mapping".into()))
}

pub(crate) fn add_mapping<A: NatFamily>(
    switch: &Switch,
    nat_ip: A,
    low: u16,
    high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let l4_ports = PortRange::new(low, high)?;
    let new_entry = NatEntry { l4_ports, tgt };
    let full = format!("{nat_ip}/{new_entry}");
    trace!(switch.log, "adding nat entry {}", full);

    let mut data = switch.nat.lock();
    let entries = A::mappings(&mut data).entry(nat_ip).or_default();
    if entries.contains(&new_entry) {
        // entry already exists
        return Ok(());
    }
    let Some(idx) = find_space(entries.iter().map(|e| e.l4_ports), l4_ports)
    else {
        error!(switch.log, "unable to add {}: conflicting mapping", full);
        return Err(DpdError::Exists("conflicting mapping".into()));
    };

    match add_entry(switch, nat_ip, l4_ports, tgt) {
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

pub(crate) fn set_mapping(
    switch: &Switch,
    nat_ip: IpAddr,
    low: u16,
    high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    match nat_ip {
        IpAddr::V4(ip) => add_mapping(switch, ip, low, high, tgt),
        IpAddr::V6(ip) => add_mapping(switch, ip, low, high, tgt),
    }
}

/// Find the first `NatEntry` that overlaps with the provided port range,
/// then remove it.
pub(crate) fn remove_mapping<A: NatFamily>(
    switch: &Switch,
    nat_ip: A,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let range = PortRange::new(low, high)?;
    trace!(switch.log, "clearing nat entry covering {}/{}", nat_ip, range);

    let mut data = switch.nat.lock();
    let mappings = A::mappings(&mut data);
    if let Some(entries) = mappings.get_mut(&nat_ip)
        && let Some(idx) =
            find_first_mapping(entries.iter().map(|e| e.l4_ports), range)
    {
        let ent = entries.remove(idx);
        if entries.is_empty() {
            mappings.remove(&nat_ip);
        }
        let full = format!("{nat_ip}/{ent}");
        return match delete_entry(switch, nat_ip, ent.l4_ports) {
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

    Ok(())
}

pub(crate) fn clear_mapping(
    switch: &Switch,
    nat_ip: IpAddr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    match nat_ip {
        IpAddr::V4(ip) => remove_mapping(switch, ip, low, high),
        IpAddr::V6(ip) => remove_mapping(switch, ip, low, high),
    }
}

pub(crate) fn reset<A: NatFamily>(switch: &Switch) -> DpdResult<()> {
    let mut data = switch.nat.lock();
    table::nat::reset::<A>(switch)?;
    A::mappings(&mut data).clear();

    Ok(())
}

/// Deletes any `NatEntry` that overlaps with the provided port range
pub(crate) fn remove_overlapping_mappings<A: NatFamily>(
    switch: &Switch,
    nat_ip: A,
    l4_ports: PortRange,
) -> DpdResult<()> {
    trace!(
        switch.log,
        "clearing all nat entries overlapping with {}/{}", nat_ip, l4_ports
    );

    let mut data = switch.nat.lock();
    let mappings = A::mappings(&mut data);
    if let Some(entries) = mappings.get_mut(&nat_ip) {
        let mut mappings_to_delete =
            find_mappings(entries.iter().map(|e| e.l4_ports), l4_ports);
        // delete starting with the last index first, or you'll end up shifting the
        // collection underneath you
        mappings_to_delete.reverse();
        for idx in mappings_to_delete {
            let ent = entries.remove(idx);
            let full = format!("{nat_ip}/{ent}");
            match delete_entry(switch, nat_ip, ent.l4_ports) {
                Err(e) => {
                    error!(switch.log, "failed to clear {}: {:?}", full, e);
                    return Err(e);
                }
                _ => {
                    debug!(switch.log, "cleared nat entry {}", full);
                }
            };
        }
        if entries.is_empty() {
            mappings.remove(&nat_ip);
        }
    }

    Ok(())
}

pub(crate) fn clear_overlapping_mappings(
    switch: &Switch,
    nat_ip: IpAddr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let l4_ports = PortRange::new(low, high)?;
    match nat_ip {
        IpAddr::V4(ip) => remove_overlapping_mappings(switch, ip, l4_ports),
        IpAddr::V6(ip) => remove_overlapping_mappings(switch, ip, l4_ports),
    }
}
