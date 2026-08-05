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

use crate::Switch;
use crate::table::nat;
use crate::types::{DpdError, DpdResult};
use common::nat::{Ipv4Nat, Ipv6Nat};
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
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}-{}]", self.low, self.high)
    }
}

#[test]
fn test_port_range_creation() {
    assert!(PortRange::new(0, 0).is_ok());
    assert!(PortRange::new(0, u16::MAX).is_ok());
    assert!(PortRange::new(u16::MAX, u16::MAX).is_ok());
    assert!(PortRange::new(1, 0).is_err());
    assert!(PortRange::new(22, 1500).is_err());
    assert!(PortRange::new(u16::MAX, 0).is_err());
}

#[test]
fn test_port_range_overlaps() {
    let range = |low, high| PortRange::new(low, high).unwrap();

    // identical ranges
    assert!(range(10, 20).overlaps(range(10, 20)));
    // single-port ranges
    assert!(range(10, 10).overlaps(range(10, 10)));
    assert!(!range(10, 10).overlaps(range(11, 11)));
    // partial overlap on either end
    assert!(range(10, 20).overlaps(range(15, 25)));
    assert!(range(15, 25).overlaps(range(10, 20)));
    // one shared port only
    assert!(range(10, 20).overlaps(range(20, 30)));
    assert!(range(20, 30).overlaps(range(10, 20)));
    // one range contained in the other
    assert!(range(10, 20).overlaps(range(12, 18)));
    assert!(range(12, 18).overlaps(range(10, 20)));
    // disjoint but adjacent ranges
    assert!(!range(10, 20).overlaps(range(21, 30)));
    assert!(!range(21, 30).overlaps(range(10, 20)));
    assert!(!range(0, 5).overlaps(range(100, 200)));
}

#[derive(PartialEq)]
pub(crate) struct Ipv6NatEntry {
    pub ports: PortRange,
    pub tgt: NatTarget,
}

impl fmt::Display for Ipv6NatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.ports, self.tgt)
    }
}

#[derive(Clone, PartialEq)]
pub(crate) struct Ipv4NatEntry {
    pub ports: PortRange,
    pub tgt: NatTarget,
}

impl fmt::Display for Ipv4NatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.ports, self.tgt)
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

/// find index of first mapping that overlaps with supplied port range
fn find_first_mapping(
    mut ranges: impl Iterator<Item = PortRange>,
    range: PortRange,
) -> Option<usize> {
    ranges.position(|e| e.overlaps(range))
}

/// find indices of all mappings that overlap with supplied port range
fn find_mappings(
    ranges: impl Iterator<Item = PortRange>,
    range: PortRange,
) -> Vec<usize> {
    ranges
        .enumerate()
        .filter(|(_, e)| e.overlaps(range))
        .map(|(i, _)| i)
        .collect()
}

fn find_space(
    ranges: impl ExactSizeIterator<Item = PortRange>,
    range: PortRange,
) -> Option<usize> {
    let len = ranges.len();
    let mut iter = ranges.enumerate().peekable();

    while let Some((idx, e)) = iter.next() {
        if e.overlaps(range) {
            return None;
        }
        if e.low >= range.high
            && iter.peek().is_none_or(|(_, next)| next.low >= range.high)
        {
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
    assert_eq!(space(11, 11), Some(2));
    assert_eq!(space(19, 32), Some(3));
    assert_eq!(space(0, 2), None);
    assert_eq!(space(3, 5), None);
    assert_eq!(space(3, 8), None);
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

    nat.ipv6_mappings.range(range).take(max).map(|(ip, _)| *ip).collect()
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
        if m.ports.low >= port {
            entries.push(Ipv6Nat {
                external,
                low: m.ports.low,
                high: m.ports.high,
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
    let range = PortRange::new(low, high)?;
    let nat = switch.nat.lock().unwrap();
    if let Some(v) = nat.ipv6_mappings.get(&nat_ip)
        && let Some(idx) = find_first_mapping(v.iter().map(|e| e.ports), range)
    {
        return Ok(v[idx].tgt);
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
    let ports = PortRange::new(low, high)?;
    let new_entry = Ipv6NatEntry { ports, tgt };
    let full = ipv6_entry(nat_ip, &new_entry);
    trace!(switch.log, "adding nat entry {}", full);

    let mut nat = switch.nat.lock().unwrap();
    let (entries, idx) = match nat.ipv6_mappings.get_mut(&nat_ip) {
        Some(e) => {
            if e.contains(&new_entry) {
                // entry already exists
                return Ok(());
            }
            match find_space(e.iter().map(|x| x.ports), ports) {
                Some(i) => (e, i),
                None => {
                    trace!(
                        switch.log,
                        "unable to add nat entry {}: conflicting mapping", full
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
    let range = PortRange::new(low, high)?;
    let mut nat = switch.nat.lock().unwrap();
    trace!(switch.log, "clearing nat entry {}/{}-{}", nat_ip, low, high);

    if let Some(mappings) = nat.ipv6_mappings.get_mut(&nat_ip)
        && let Some(idx) =
            find_first_mapping(mappings.iter().map(|e| e.ports), range)
    {
        let ent = mappings.remove(idx);
        if mappings.is_empty() {
            nat.ipv6_mappings.remove(&nat_ip);
        }
        let full = ipv6_entry(nat_ip, &ent);
        return match nat::delete_ipv6_entry(
            switch,
            nat_ip,
            ent.ports.low,
            ent.ports.high,
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

    nat.ipv4_mappings.range(range).take(max).map(|(ip, _)| *ip).collect()
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
        if m.ports.low >= port {
            entries.push(Ipv4Nat {
                external,
                low: m.ports.low,
                high: m.ports.high,
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
    let range = PortRange::new(low, high)?;
    let nat = switch.nat.lock().unwrap();
    if let Some(v) = nat.ipv4_mappings.get(&nat_ip)
        && let Some(idx) = find_first_mapping(v.iter().map(|e| e.ports), range)
    {
        return Ok(v[idx].tgt);
    }
    Err(DpdError::Missing("no mapping".into()))
}

pub fn set_mapping(
    switch: &Switch,
    nat_ip: IpAddr,
    low: u16,
    high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    match nat_ip {
        IpAddr::V4(nat_ip) => set_ipv4_mapping(switch, nat_ip, low, high, tgt),
        IpAddr::V6(nat_ip) => set_ipv6_mapping(switch, nat_ip, low, high, tgt),
    }
}

pub fn set_ipv4_mapping(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let ports = PortRange::new(low, high)?;
    let new_entry = Ipv4NatEntry { ports, tgt };
    let full = ipv4_entry(nat_ip, &new_entry);
    trace!(switch.log, "adding nat entry {}", full);

    let mut nat = switch.nat.lock().unwrap();
    let (entries, idx) = match nat.ipv4_mappings.get_mut(&nat_ip) {
        Some(e) => {
            if e.contains(&new_entry) {
                // entry already exists
                return Ok(());
            }
            match find_space(e.iter().map(|x| x.ports), ports) {
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

pub fn clear_mapping(
    switch: &Switch,
    nat_ip: IpAddr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    match nat_ip {
        IpAddr::V4(nat_ip) => clear_ipv4_mapping(switch, nat_ip, low, high),
        IpAddr::V6(nat_ip) => clear_ipv6_mapping(switch, nat_ip, low, high),
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
    let range = PortRange::new(low, high)?;
    let mut nat = switch.nat.lock().unwrap();
    trace!(
        switch.log,
        "clearing nat entry covering {}/{}-{}", nat_ip, low, high
    );

    if let Some(mappings) = nat.ipv4_mappings.get_mut(&nat_ip)
        && let Some(idx) =
            find_first_mapping(mappings.iter().map(|e| e.ports), range)
    {
        let ent = mappings.remove(idx);
        if mappings.is_empty() {
            nat.ipv4_mappings.remove(&nat_ip);
        }
        let full = ipv4_entry(nat_ip, &ent);
        return match nat::delete_ipv4_entry(
            switch,
            nat_ip,
            ent.ports.low,
            ent.ports.high,
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

    Ok(())
}

pub fn clear_overlapping_mappings(
    switch: &Switch,
    nat_ip: IpAddr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    match nat_ip {
        IpAddr::V4(nat_ip) => {
            clear_overlapping_mappings_v4(switch, nat_ip, low, high)
        }
        IpAddr::V6(nat_ip) => {
            clear_overlapping_mappings_v6(switch, nat_ip, low, high)
        }
    }
}

/// Deletes any `Ipv4NatEntry` where each entry matches the provided
/// `Ipv4Addr` and overlaps with the provided port range
pub fn clear_overlapping_mappings_v4(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let range = PortRange::new(low, high)?;
    let mut nat = switch.nat.lock().unwrap();
    trace!(
        switch.log,
        "clearing all nat entries overlapping with {}/{}-{}", nat_ip, low, high
    );

    if let Some(mappings) = nat.ipv4_mappings.get_mut(&nat_ip) {
        let mut mappings_to_delete =
            find_mappings(mappings.iter().map(|e| e.ports), range);
        // delete starting with the last index first, or you'll end up shifting the
        // collection underneath you
        mappings_to_delete.reverse();
        for idx in mappings_to_delete {
            let ent = mappings.remove(idx);
            let full = ipv4_entry(nat_ip, &ent);
            match nat::delete_ipv4_entry(
                switch,
                nat_ip,
                ent.ports.low,
                ent.ports.high,
            ) {
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

pub fn clear_overlapping_mappings_v6(
    switch: &Switch,
    nat_ip: Ipv6Addr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let range = PortRange::new(low, high)?;
    let mut nat = switch.nat.lock().unwrap();
    trace!(
        switch.log,
        "clearing all nat entries overlapping with {}/{}-{}", nat_ip, low, high
    );

    if let Some(mappings) = nat.ipv6_mappings.get_mut(&nat_ip) {
        let mut mappings_to_delete =
            find_mappings(mappings.iter().map(|e| e.ports), range);
        // delete starting with the last index first, or you'll end up shifting the
        // collection underneath you
        mappings_to_delete.reverse();
        for idx in mappings_to_delete {
            let ent = mappings.remove(idx);
            let full = ipv6_entry(nat_ip, &ent);
            match nat::delete_ipv6_entry(
                switch,
                nat_ip,
                ent.ports.low,
                ent.ports.high,
            ) {
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
            nat.ipv6_mappings.remove(&nat_ip);
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

pub fn set_nat_generation(switch: &Switch, generation: i64) {
    let mut nat = switch.nat.lock().unwrap();

    debug!(switch.log, "setting nat generation");
    nat.ipv4_generation = generation;
}

pub fn get_nat_generation(switch: &Switch) -> i64 {
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
