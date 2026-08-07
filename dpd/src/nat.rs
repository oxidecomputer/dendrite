// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use slog::{debug, error, trace};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Bound;
use std::sync::{Mutex, MutexGuard};

use crate::Switch;
use crate::table;
use crate::table::nat::{NatAddress, add_entry, delete_entry};
use crate::types::{DpdError, DpdResult};
use common::nat::{Ipv4Nat, Ipv6Nat};
use common::network::NatTarget;
use dpd_types::nat::{
    Ipv4NatFailure, Ipv6NatFailure, NatTag, NatTaggedApplyResultV4,
    NatTaggedApplyResultV6,
};

/// An inclusive range of l4_ports, guaranteed by construction to have
/// `low <= high`.
#[derive(Clone, Copy, Debug, PartialEq)]
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

#[derive(Clone, Debug)]
pub(crate) struct NatEntry {
    pub l4_ports: PortRange,
    pub tgt: NatTarget,
    /// Set when the entry was created via the tagged apply API.
    pub tag: Option<NatTag>,
}

// The tag does not participate in entry identity: the classic per-entry
// API is tag-oblivious, so creating an entry identical to a tagged one
// remains an idempotent no-op.
impl PartialEq for NatEntry {
    fn eq(&self, other: &Self) -> bool {
        self.l4_ports == other.l4_ports && self.tgt == other.tgt
    }
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

/// One NAT mapping in validated, family-neutral form.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Mapping<A> {
    external: A,
    l4_ports: PortRange,
    target: NatTarget,
}

impl<A: NatAddress> Mapping<A> {
    fn new(
        external: A,
        low: u16,
        high: u16,
        target: NatTarget,
    ) -> DpdResult<Self> {
        let l4_ports = PortRange::new(low, high).map_err(|_| {
            DpdError::Invalid(format!(
                "invalid port range {low}-{high} for {external}"
            ))
        })?;
        Ok(Mapping { external, l4_ports, target })
    }
}

/// The classification of a tagged apply request against current state.
struct Plan<A> {
    unchanged: Vec<Mapping<A>>,
    to_add: Vec<Mapping<A>>,
    to_remove: Vec<Mapping<A>>,
    /// Requested mappings that conflict with entries not carrying this tag,
    /// with the reason; these are reported as failures without being applied.
    conflicts: Vec<(Mapping<A>, String)>,
}

impl<A> Plan<A> {
    fn new() -> Self {
        Self {
            unchanged: Vec::new(),
            to_add: Vec::new(),
            to_remove: Vec::new(),
            conflicts: Vec::new(),
        }
    }
}

/// The per-entry results of executing a plan, in family-neutral form;
/// converted into the API result types by the public entry points.
struct ApplyOutcome<A> {
    unchanged: Vec<Mapping<A>>,
    added: Vec<Mapping<A>>,
    removed: Vec<Mapping<A>>,
    add_failures: Vec<(Mapping<A>, String)>,
    remove_failures: Vec<(Mapping<A>, String)>,
}

/// Classify a complete requested set of NAT mappings for `tag` against
/// the current state, without modifying anything.
///
/// Mapping identity is the full (external, l4_ports, target) triple.  Each
/// requested mapping is classified as `unchanged` (identical entry
/// carrying this tag) or `to_add`.  A requested mapping that overlaps an
/// entry carrying this tag replaces it (the existing entry lands in
/// `to_remove`).  Any overlap with an entry *not* carrying this tag
/// (untagged entries included) lands the requested mapping in
/// `conflicts` without affecting the rest of the request.  An internally
/// overlapping request fails wholesale.
fn make_plan<A: NatAddress>(
    mappings: &NatMappings<A>,
    tag: &NatTag,
    requested: &[Mapping<A>],
) -> DpdResult<Plan<A>> {
    // Sorted by (address, low port), two requested ranges on the same
    // address overlap iff an adjacent pair does.
    let mut ranges: Vec<(A, PortRange)> =
        requested.iter().map(|m| (m.external, m.l4_ports)).collect();
    ranges
        .sort_unstable_by_key(|&(external, l4_ports)| (external, l4_ports.low));
    for w in ranges.windows(2) {
        let (ext_a, a) = w[0];
        let (ext_b, b) = w[1];
        if ext_a == ext_b && a.overlaps(b) {
            return Err(DpdError::Invalid(format!(
                "requested entries overlap on {ext_a}: {a} and {b}"
            )));
        }
    }

    let mut plan = Plan::new();
    let mut keep = BTreeSet::new();

    for &req in requested {
        let Some(entries) = mappings.get(&req.external) else {
            plan.to_add.push(req);
            continue;
        };
        let overlapping =
            find_mappings(entries.iter().map(|e| e.l4_ports), req.l4_ports);
        let foreign = overlapping
            .iter()
            .copied()
            .find(|&i| entries[i].tag.as_ref() != Some(tag));
        if let Some(i) = foreign {
            plan.conflicts.push((
                req,
                format!(
                    "requested entry {}/{} conflicts with existing \
                     entry {}/{} not carrying tag {}",
                    req.external,
                    req.l4_ports,
                    req.external,
                    entries[i].l4_ports,
                    tag
                ),
            ));
            continue;
        }
        // Every overlap carries this tag.  Current entries never
        // overlap one another, so an entry identical to the request is
        // necessarily the only overlap.
        let identical = overlapping.iter().copied().find(|&i| {
            entries[i].l4_ports == req.l4_ports && entries[i].tgt == req.target
        });
        if let Some(i) = identical {
            keep.insert((req.external, i));
            plan.unchanged.push(req);
            continue;
        }
        // Any remaining overlaps carry this tag but are not identical:
        // those entries are replaced by the requested one (removed in
        // the sweep below).
        plan.to_add.push(req);
    }

    // Every entry carrying this tag that was not matched above is
    // removed.
    for (external, entries) in mappings {
        for (i, e) in entries.iter().enumerate() {
            if e.tag.as_ref() == Some(tag) && !keep.contains(&(*external, i)) {
                plan.to_remove.push(Mapping {
                    external: *external,
                    l4_ports: e.l4_ports,
                    target: e.tgt,
                });
            }
        }
    }

    Ok(plan)
}

/// Execute the removals and additions from a plan, updating the
/// in-memory mappings entry-by-entry as each ASIC operation succeeds.
/// Removals precede additions: entries are keyed by (address, port
/// range), so retargeting is delete-then-create.  Every scheduled
/// operation is attempted; per-entry failures are reported rather than
/// short-circuiting.
fn apply_plan<A: NatAddress>(
    switch: &Switch,
    mappings: &mut NatMappings<A>,
    tag: &NatTag,
    plan: Plan<A>,
) -> ApplyOutcome<A> {
    let mut outcome = ApplyOutcome {
        unchanged: plan.unchanged,
        added: Vec::new(),
        removed: Vec::new(),
        add_failures: plan.conflicts,
        remove_failures: Vec::new(),
    };

    for req in plan.to_remove {
        let Mapping { external, l4_ports, .. } = req;
        match delete_entry(switch, external, l4_ports) {
            Ok(()) => {
                let entries = mappings.get_mut(&external).unwrap();
                entries.retain(|e| e.l4_ports != l4_ports);
                if entries.is_empty() {
                    mappings.remove(&external);
                }
                debug!(
                    switch.log,
                    "removed tagged nat entry {}/{}", external, l4_ports
                );
                outcome.removed.push(req);
            }
            Err(e) => {
                error!(
                    switch.log,
                    "failed to remove tagged nat entry {}/{}: {:?}",
                    external,
                    l4_ports,
                    e
                );
                outcome.remove_failures.push((req, e.to_string()));
            }
        }
    }

    for req in plan.to_add {
        let Mapping { external, l4_ports, target } = req;
        let entries = mappings.entry(external).or_default();
        // Re-check for space at apply time: a failed removal may still
        // occupy the requested range.
        let Some(idx) =
            find_space(entries.iter().map(|e| e.l4_ports), l4_ports)
        else {
            // No space implies an overlapping entry exists.
            let i = find_first_mapping(
                entries.iter().map(|e| e.l4_ports),
                l4_ports,
            )
            .unwrap();
            outcome.add_failures.push((
                req,
                format!(
                    "requested entry {}/{} conflicts with entry {}/{} \
                     still present after a failed removal",
                    external, l4_ports, external, entries[i].l4_ports
                ),
            ));
            continue;
        };
        match add_entry(switch, external, l4_ports, target) {
            Ok(()) => {
                entries.insert(
                    idx,
                    NatEntry { l4_ports, tgt: target, tag: Some(tag.clone()) },
                );
                debug!(
                    switch.log,
                    "added tagged nat entry {}/{}", external, l4_ports
                );
                outcome.added.push(req);
            }
            Err(e) => {
                error!(
                    switch.log,
                    "failed to add tagged nat entry {}/{}: {:?}",
                    external,
                    l4_ports,
                    e
                );
                if entries.is_empty() {
                    mappings.remove(&external);
                }
                outcome.add_failures.push((req, e.to_string()));
            }
        }
    }

    outcome
}

impl From<Mapping<Ipv4Addr>> for Ipv4Nat {
    fn from(m: Mapping<Ipv4Addr>) -> Self {
        Ipv4Nat {
            external: m.external,
            low: m.l4_ports.low,
            high: m.l4_ports.high,
            target: m.target,
        }
    }
}

impl From<Mapping<Ipv6Addr>> for Ipv6Nat {
    fn from(m: Mapping<Ipv6Addr>) -> Self {
        Ipv6Nat {
            external: m.external,
            low: m.l4_ports.low,
            high: m.l4_ports.high,
            target: m.target,
        }
    }
}

impl From<ApplyOutcome<Ipv4Addr>> for NatTaggedApplyResultV4 {
    fn from(outcome: ApplyOutcome<Ipv4Addr>) -> Self {
        let failure = |(req, error): (Mapping<_>, _)| Ipv4NatFailure {
            entry: req.into(),
            error,
        };
        NatTaggedApplyResultV4 {
            unchanged: outcome
                .unchanged
                .into_iter()
                .map(Ipv4Nat::from)
                .collect(),
            added: outcome.added.into_iter().map(Ipv4Nat::from).collect(),
            removed: outcome.removed.into_iter().map(Ipv4Nat::from).collect(),
            add_failures: outcome
                .add_failures
                .into_iter()
                .map(failure)
                .collect(),
            remove_failures: outcome
                .remove_failures
                .into_iter()
                .map(failure)
                .collect(),
        }
    }
}

impl From<ApplyOutcome<Ipv6Addr>> for NatTaggedApplyResultV6 {
    fn from(outcome: ApplyOutcome<Ipv6Addr>) -> Self {
        let failure = |(req, error): (Mapping<_>, _)| Ipv6NatFailure {
            entry: req.into(),
            error,
        };
        NatTaggedApplyResultV6 {
            unchanged: outcome
                .unchanged
                .into_iter()
                .map(Ipv6Nat::from)
                .collect(),
            added: outcome.added.into_iter().map(Ipv6Nat::from).collect(),
            removed: outcome.removed.into_iter().map(Ipv6Nat::from).collect(),
            add_failures: outcome
                .add_failures
                .into_iter()
                .map(failure)
                .collect(),
            remove_failures: outcome
                .remove_failures
                .into_iter()
                .map(failure)
                .collect(),
        }
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

/// Paginates through the entries carrying `tag`, using the
/// `(address, low port)` of the last entry returned as the starting
/// offset.
///
/// The walk crosses external addresses, scanning past entries not
/// carrying `tag` until the page is full or the map is exhausted.
pub(crate) fn get_mappings_by_tag_range<A: NatFamily>(
    switch: &Switch,
    tag: &NatTag,
    last: Option<(A, u16)>,
    max: usize,
) -> Vec<A::Reservation> {
    let max = max.min(64);

    let start = match last {
        Some((ip, _)) => Bound::Included(ip),
        None => Bound::Unbounded,
    };

    let mut data = switch.nat.lock();
    let mut results = Vec::new();
    for (external, entries) in
        A::mappings(&mut data).range((start, Bound::Unbounded))
    {
        for e in entries {
            if let Some(last) = last
                && (*external, e.l4_ports.low) <= last
            {
                continue;
            }
            if e.tag.as_ref() != Some(tag) {
                continue;
            }
            results.push(external.reservation(e.l4_ports, e.tgt));
            if results.len() >= max {
                return results;
            }
        }
    }
    results
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
    let new_entry = NatEntry { l4_ports, tgt, tag: None };
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

/// Apply `requested` as the complete desired set of NAT entries for
/// `tag` in one address family, diffing it against current state and
/// converging.
///
/// The whole operation runs under a single acquisition of the NAT lock,
/// so it is atomic with respect to the individual create/delete
/// operations.  Validation failures fail the request with nothing
/// applied; conflicts with entries not carrying this tag and ASIC
/// failures while converging are reported per-entry in the result.  An
/// apply that matches current state performs zero ASIC operations.
pub(crate) fn apply_tagged_mappings_v4(
    switch: &Switch,
    tag: &NatTag,
    requested: &[Ipv4Nat],
) -> DpdResult<NatTaggedApplyResultV4> {
    let req = requested
        .iter()
        .map(|e| Mapping::new(e.external, e.low, e.high, e.target))
        .collect::<DpdResult<Vec<_>>>()?;

    let mut data = switch.nat.lock();
    let plan = make_plan(&data.ipv4, tag, &req)?;
    Ok(apply_plan(switch, &mut data.ipv4, tag, plan).into())
}

/// IPv6 flavor of [`apply_tagged_mappings_v4`].
pub(crate) fn apply_tagged_mappings_v6(
    switch: &Switch,
    tag: &NatTag,
    requested: &[Ipv6Nat],
) -> DpdResult<NatTaggedApplyResultV6> {
    let req = requested
        .iter()
        .map(|e| Mapping::new(e.external, e.low, e.high, e.target))
        .collect::<DpdResult<Vec<_>>>()?;

    let mut data = switch.nat.lock();
    let plan = make_plan(&data.ipv6, tag, &req)?;
    Ok(apply_plan(switch, &mut data.ipv6, tag, plan).into())
}

#[cfg(test)]
mod tagged_tests {
    use super::*;
    use common::network::{MacAddr, Vni};

    const TAG: &str = "test-tag";

    fn tgt(vni: u32) -> NatTarget {
        NatTarget {
            internal_ip: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            inner_mac: MacAddr::new(2, 4, 6, 8, 10, 12),
            vni: Vni::new(vni).unwrap(),
        }
    }

    fn ip(octet: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, octet)
    }

    fn pr(low: u16, high: u16) -> PortRange {
        PortRange::new(low, high).unwrap()
    }

    fn entry(
        low: u16,
        high: u16,
        tgt: NatTarget,
        tag: Option<&str>,
    ) -> NatEntry {
        NatEntry {
            l4_ports: pr(low, high),
            tgt,
            tag: tag.map(|t| t.parse().unwrap()),
        }
    }

    fn mapping<A: NatAddress>(
        external: A,
        low: u16,
        high: u16,
        target: NatTarget,
    ) -> Mapping<A> {
        Mapping::new(external, low, high, target).unwrap()
    }

    fn plan(
        map: &NatMappings<Ipv4Addr>,
        requested: &[Mapping<Ipv4Addr>],
    ) -> DpdResult<Plan<Ipv4Addr>> {
        make_plan(map, &TAG.parse().unwrap(), requested)
    }

    #[test]
    fn test_tag_excluded_from_entry_equality() {
        // Entry identity must remain (ports, tgt): an untagged create
        // identical to a tagged entry must stay a no-op via `contains`.
        assert_eq!(entry(1, 2, tgt(1), None), entry(1, 2, tgt(1), Some(TAG)));
        assert_ne!(entry(1, 2, tgt(1), None), entry(1, 2, tgt(2), None));
        assert_ne!(entry(1, 2, tgt(1), None), entry(1, 3, tgt(1), None));
        assert!([entry(1, 2, tgt(1), Some(TAG))].contains(&entry(
            1,
            2,
            tgt(1),
            None
        )));
    }

    #[test]
    fn test_plan_empty_to_n() {
        let map = NatMappings::new();
        let requested = vec![
            mapping(ip(1), 100, 200, tgt(1)),
            mapping(ip(2), 100, 200, tgt(1)),
        ];
        let p = plan(&map, &requested).unwrap();
        assert_eq!(p.to_add, requested);
        assert!(p.unchanged.is_empty());
        assert!(p.to_remove.is_empty());
    }

    #[test]
    fn test_plan_identical_is_all_unchanged() {
        let map = NatMappings::from([
            (ip(1), vec![entry(100, 200, tgt(1), Some(TAG))]),
            (ip(2), vec![entry(300, 400, tgt(2), Some(TAG))]),
        ]);
        let requested = vec![
            mapping(ip(1), 100, 200, tgt(1)),
            mapping(ip(2), 300, 400, tgt(2)),
        ];
        let p = plan(&map, &requested).unwrap();
        assert_eq!(p.unchanged, requested);
        // Zero table operations: nothing to add or remove.
        assert!(p.to_add.is_empty());
        assert!(p.to_remove.is_empty());
    }

    #[test]
    fn test_plan_add_remove_retarget() {
        let map = NatMappings::from([(
            ip(1),
            vec![
                entry(100, 200, tgt(1), Some(TAG)),
                entry(300, 400, tgt(1), Some(TAG)),
                entry(500, 600, tgt(1), Some(TAG)),
            ],
        )]);
        let requested = vec![
            // unchanged
            mapping(ip(1), 100, 200, tgt(1)),
            // retarget: same range, new target
            mapping(ip(1), 300, 400, tgt(2)),
            // new entry; 500-600 is absent and should be removed
            mapping(ip(1), 700, 800, tgt(1)),
        ];
        let p = plan(&map, &requested).unwrap();
        assert_eq!(p.unchanged, vec![mapping(ip(1), 100, 200, tgt(1))]);
        assert_eq!(
            p.to_add,
            vec![
                mapping(ip(1), 300, 400, tgt(2)),
                mapping(ip(1), 700, 800, tgt(1))
            ]
        );
        assert_eq!(
            p.to_remove,
            vec![
                mapping(ip(1), 300, 400, tgt(1)),
                mapping(ip(1), 500, 600, tgt(1))
            ]
        );
    }

    #[test]
    fn test_plan_conflicts() {
        // Identical entry carrying a different tag.
        let map = NatMappings::from([(
            ip(1),
            vec![entry(100, 200, tgt(1), Some("other-tag"))],
        )]);
        let p = plan(&map, &[mapping(ip(1), 100, 200, tgt(1))]).unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert_eq!(p.conflicts[0].0, mapping(ip(1), 100, 200, tgt(1)));
        assert!(p.to_add.is_empty());

        // Identical untagged entry: without adoption, any entry not
        // carrying this tag is a conflict.
        let map =
            NatMappings::from([(ip(1), vec![entry(100, 200, tgt(1), None)])]);
        let p = plan(&map, &[mapping(ip(1), 100, 200, tgt(1))]).unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert!(p.to_add.is_empty());
        assert!(p.unchanged.is_empty());

        // Overlapping range against an untagged entry.
        let p = plan(&map, &[mapping(ip(1), 150, 250, tgt(1))]).unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert!(p.to_add.is_empty());

        // Same key, different target, against an untagged entry.
        let p = plan(&map, &[mapping(ip(1), 100, 200, tgt(2))]).unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert!(p.to_add.is_empty());

        // Overlapping range against an entry carrying a foreign tag.
        let map = NatMappings::from([(
            ip(1),
            vec![entry(100, 200, tgt(1), Some("other-tag"))],
        )]);
        let p = plan(&map, &[mapping(ip(1), 150, 250, tgt(1))]).unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert!(p.to_add.is_empty());

        // Intra-request overlap fails wholesale.
        assert!(matches!(
            plan(
                &NatMappings::new(),
                &[
                    mapping(ip(1), 100, 200, tgt(1)),
                    mapping(ip(1), 200, 300, tgt(1))
                ]
            ),
            Err(DpdError::Invalid(_))
        ));
    }

    #[test]
    fn test_plan_conflict_does_not_block_others() {
        // One conflicting entry must not affect the classification of the
        // rest of the request or the removal sweep.
        let map = NatMappings::from([(
            ip(1),
            vec![
                entry(100, 200, tgt(1), Some("other-tag")),
                entry(300, 400, tgt(1), Some(TAG)),
            ],
        )]);
        let requested = vec![
            // conflict: carries other-tag
            mapping(ip(1), 100, 200, tgt(1)),
            // new entry
            mapping(ip(2), 100, 200, tgt(1)),
        ];
        let p = plan(&map, &requested).unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert_eq!(p.conflicts[0].0, mapping(ip(1), 100, 200, tgt(1)));
        assert_eq!(p.to_add, vec![mapping(ip(2), 100, 200, tgt(1))]);
        // The tagged entry absent from the request is still removed.
        assert_eq!(p.to_remove, vec![mapping(ip(1), 300, 400, tgt(1))]);
    }

    #[test]
    fn test_plan_two_tags_coexist() {
        let map = NatMappings::from([(
            ip(1),
            vec![
                entry(100, 200, tgt(1), Some(TAG)),
                entry(300, 400, tgt(1), Some("other-tag")),
                entry(500, 600, tgt(1), None),
            ],
        )]);

        // An empty apply for TAG removes only TAG's entry, leaving the
        // foreign-tagged and untagged entries alone.
        let p = plan(&map, &[]).unwrap();
        assert_eq!(p.to_remove, vec![mapping(ip(1), 100, 200, tgt(1))]);
        assert!(p.to_add.is_empty());

        // An identical apply for TAG touches nothing.
        let p = plan(&map, &[mapping(ip(1), 100, 200, tgt(1))]).unwrap();
        assert_eq!(p.unchanged, vec![mapping(ip(1), 100, 200, tgt(1))]);
        assert!(p.to_remove.is_empty());
        assert!(p.to_add.is_empty());
    }

    #[test]
    fn test_plan_ipv6() {
        let ip6 = |o: u16| Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, o);
        let entry6 = |low, high, tgt, tag: Option<&str>| NatEntry {
            l4_ports: pr(low, high),
            tgt,
            tag: tag.map(|t| t.parse().unwrap()),
        };
        let map = NatMappings::from([
            (ip6(1), vec![entry6(100, 200, tgt(1), Some(TAG))]),
            (ip6(2), vec![entry6(100, 200, tgt(1), None)]),
        ]);
        let requested = vec![
            mapping(ip6(1), 100, 200, tgt(1)),
            mapping(ip6(3), 100, 200, tgt(1)),
        ];
        let p = make_plan(&map, &TAG.parse().unwrap(), &requested).unwrap();
        assert_eq!(p.unchanged, vec![mapping(ip6(1), 100, 200, tgt(1))]);
        assert_eq!(p.to_add, vec![mapping(ip6(3), 100, 200, tgt(1))]);
        assert!(p.to_remove.is_empty());
        // The untagged entry on ip6(2) is not touched.
        assert!(p.conflicts.is_empty());
    }
}
