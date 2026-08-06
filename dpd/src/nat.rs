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
use crate::table::nat::NatFamily;
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
    assert!(PortRange::new(22, 1500).is_ok());
    assert!(PortRange::new(u16::MAX, u16::MAX).is_ok());
    assert!(PortRange::new(1, 0).is_err());
    assert!(PortRange::new(1500, 22).is_err());
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

#[derive(Clone, PartialEq)]
pub(crate) struct NatEntry {
    pub ports: PortRange,
    pub tgt: NatTarget,
}

impl fmt::Display for NatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.ports, self.tgt)
    }
}

/// The NAT mappings for a single IP address family, kept in sync with the
/// corresponding p4 table.
struct NatMap<A: NatFamily + Ord> {
    mappings: BTreeMap<A, Vec<NatEntry>>,
}

impl<A: NatFamily + Ord> NatMap<A> {
    fn new() -> Self {
        NatMap { mappings: BTreeMap::new() }
    }

    fn get_addrs_range(&self, last_addr: Option<A>, max: usize) -> Vec<A> {
        let max = max.min(64);

        let range = match last_addr {
            Some(a) => (Bound::Excluded(a), Bound::Unbounded),
            None => (Bound::Unbounded, Bound::Unbounded),
        };

        self.mappings.range(range).take(max).map(|(ip, _)| *ip).collect()
    }

    /// Paginates through the mappings for one address, using `last_port` as
    /// the starting offset
    fn get_mappings_range(
        &self,
        external: A,
        last_port: Option<u16>,
        max: usize,
    ) -> Vec<NatEntry> {
        let max = max.min(64);

        let port = match last_port {
            None => 0,
            Some(l) => l + 1,
        };

        self.mappings
            .get(&external)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.ports.low >= port)
                    .take(max)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find the first `NatTarget` where its `NatEntry` overlaps with the
    /// provided port range
    fn get_mapping(&self, nat_ip: A, range: PortRange) -> DpdResult<NatTarget> {
        if let Some(v) = self.mappings.get(&nat_ip)
            && let Some(idx) =
                find_first_mapping(v.iter().map(|e| e.ports), range)
        {
            return Ok(v[idx].tgt);
        }
        Err(DpdError::Missing("no mapping".into()))
    }

    fn add_mapping(
        &mut self,
        switch: &Switch,
        nat_ip: A,
        ports: PortRange,
        tgt: NatTarget,
    ) -> DpdResult<()> {
        let new_entry = NatEntry { ports, tgt };
        let full = format!("{nat_ip}/{new_entry}");
        trace!(switch.log, "adding nat entry {}", full);

        let entries = self.mappings.entry(nat_ip).or_default();
        if entries.contains(&new_entry) {
            // entry already exists
            return Ok(());
        }
        let Some(idx) = find_space(entries.iter().map(|e| e.ports), ports)
        else {
            error!(switch.log, "unable to add {}: conflicting mapping", full);
            return Err(DpdError::Exists("conflicting mapping".into()));
        };

        match nat_ip.add_entry(switch, ports.low, ports.high, tgt) {
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

    /// Find the first `NatEntry` that overlaps with the provided port range,
    /// then remove it.
    fn remove_mapping(
        &mut self,
        switch: &Switch,
        nat_ip: A,
        range: PortRange,
    ) -> DpdResult<()> {
        trace!(switch.log, "clearing nat entry covering {}/{}", nat_ip, range);

        if let Some(entries) = self.mappings.get_mut(&nat_ip)
            && let Some(idx) =
                find_first_mapping(entries.iter().map(|e| e.ports), range)
        {
            let ent = entries.remove(idx);
            if entries.is_empty() {
                self.mappings.remove(&nat_ip);
            }
            let full = format!("{nat_ip}/{ent}");
            return match nat_ip.delete_entry(
                switch,
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

    /// Deletes any `NatEntry` that overlaps with the provided port range
    fn remove_overlapping_mappings(
        &mut self,
        switch: &Switch,
        nat_ip: A,
        range: PortRange,
    ) -> DpdResult<()> {
        trace!(
            switch.log,
            "clearing all nat entries overlapping with {}/{}", nat_ip, range
        );

        if let Some(entries) = self.mappings.get_mut(&nat_ip) {
            let mut mappings_to_delete =
                find_mappings(entries.iter().map(|e| e.ports), range);
            // delete starting with the last index first, or you'll end up shifting the
            // collection underneath you
            mappings_to_delete.reverse();
            for idx in mappings_to_delete {
                let ent = entries.remove(idx);
                let full = format!("{nat_ip}/{ent}");
                match nat_ip.delete_entry(switch, ent.ports.low, ent.ports.high)
                {
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
                self.mappings.remove(&nat_ip);
            }
        }

        Ok(())
    }

    fn reset(&mut self, switch: &Switch) -> DpdResult<()> {
        self.mappings.clear();
        A::reset(switch)
    }
}

pub struct NatData {
    ipv6: NatMap<Ipv6Addr>,
    ipv4: NatMap<Ipv4Addr>,
    ipv4_generation: i64,
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
    max: usize,
) -> Vec<Ipv6Addr> {
    switch.nat.lock().unwrap().ipv6.get_addrs_range(last_addr, max)
}

/// Paginates through `Ipv6Nat` using `last_port` as the starting offset
pub fn get_ipv6_mappings_range(
    switch: &Switch,
    external: Ipv6Addr,
    last_port: Option<u16>,
    max: usize,
) -> Vec<Ipv6Nat> {
    switch
        .nat
        .lock()
        .unwrap()
        .ipv6
        .get_mappings_range(external, last_port, max)
        .into_iter()
        .map(|m| Ipv6Nat {
            external,
            low: m.ports.low,
            high: m.ports.high,
            target: m.tgt,
        })
        .collect()
}

/// Find the first `NatTarget` where its `NatEntry` matches the provided
/// `Ipv6Addr` and overlaps with the provided port range
pub fn get_ipv6_mapping(
    switch: &Switch,
    nat_ip: Ipv6Addr,
    low: u16,
    high: u16,
) -> DpdResult<NatTarget> {
    let range = PortRange::new(low, high)?;
    switch.nat.lock().unwrap().ipv6.get_mapping(nat_ip, range)
}

pub fn set_ipv6_mapping(
    switch: &Switch,
    nat_ip: Ipv6Addr,
    low: u16,
    high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let ports = PortRange::new(low, high)?;
    switch.nat.lock().unwrap().ipv6.add_mapping(switch, nat_ip, ports, tgt)
}

/// Find the first `NatTarget` where its `NatEntry` matches the provided
/// `Ipv6Addr` and overlaps with the provided port range, then remove it.
pub fn clear_ipv6_mapping(
    switch: &Switch,
    nat_ip: Ipv6Addr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let range = PortRange::new(low, high)?;
    switch.nat.lock().unwrap().ipv6.remove_mapping(switch, nat_ip, range)
}

pub fn get_ipv4_addrs_range(
    switch: &Switch,
    last_addr: Option<Ipv4Addr>,
    max: usize,
) -> Vec<Ipv4Addr> {
    switch.nat.lock().unwrap().ipv4.get_addrs_range(last_addr, max)
}

/// Paginates through `Ipv4Nat` using `last_port` as the starting offset
pub fn get_ipv4_mappings_range(
    switch: &Switch,
    external: Ipv4Addr,
    last_port: Option<u16>,
    max: usize,
) -> Vec<Ipv4Nat> {
    switch
        .nat
        .lock()
        .unwrap()
        .ipv4
        .get_mappings_range(external, last_port, max)
        .into_iter()
        .map(|m| Ipv4Nat {
            external,
            low: m.ports.low,
            high: m.ports.high,
            target: m.tgt,
        })
        .collect()
}

/// Find the first `NatTarget` where its `NatEntry` matches the provided
/// `Ipv4Addr` and overlaps with the provided port range
pub fn get_ipv4_mapping(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
) -> DpdResult<NatTarget> {
    let range = PortRange::new(low, high)?;
    switch.nat.lock().unwrap().ipv4.get_mapping(nat_ip, range)
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
    switch.nat.lock().unwrap().ipv4.add_mapping(switch, nat_ip, ports, tgt)
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

/// Find the first `NatTarget` where its `NatEntry` matches the provided
/// `Ipv4Addr` and overlaps with the provided port range, then remove it.
pub fn clear_ipv4_mapping(
    switch: &Switch,
    nat_ip: Ipv4Addr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let range = PortRange::new(low, high)?;
    switch.nat.lock().unwrap().ipv4.remove_mapping(switch, nat_ip, range)
}

pub fn clear_overlapping_mappings(
    switch: &Switch,
    nat_ip: IpAddr,
    low: u16,
    high: u16,
) -> DpdResult<()> {
    let range = PortRange::new(low, high)?;
    let mut nat = switch.nat.lock().unwrap();
    match nat_ip {
        IpAddr::V4(nat_ip) => {
            nat.ipv4.remove_overlapping_mappings(switch, nat_ip, range)
        }
        IpAddr::V6(nat_ip) => {
            nat.ipv6.remove_overlapping_mappings(switch, nat_ip, range)
        }
    }
}

pub fn reset_ipv6(switch: &Switch) -> DpdResult<()> {
    switch.nat.lock().unwrap().ipv6.reset(switch)
}

pub fn reset_ipv4(switch: &Switch) -> DpdResult<()> {
    switch.nat.lock().unwrap().ipv4.reset(switch)
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
    NatData { ipv6: NatMap::new(), ipv4: NatMap::new(), ipv4_generation: 0 }
}
