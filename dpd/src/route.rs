// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

// IPv4 route lookup and target selection happens in two steps.  Each route may
// have multiple targets, with the intention of distributing outgoing packets
// evenly and deterministically across those targets.
//
// Targets are stored in the route_data table, with each routes targets being
// stored in sequential slots.  Each slot contains a single (port, nexthop_ip,
// vlan_id) tuple.  The mapping of routes to clusters of targets is stored in
// the route_index table.  Each entry in this table includes an (index,
// slot_count) tuple.
//
// A simple route_index table is shown below.  The single target for the
// 192.168.1.1 subnet is stored at slot 1 in the route_data table.  The four
// targets for the 10.10.10.1 subnet are stored in slots 2, 3, 4, and 5 of the
// the route data table.
//
//  subnet            (index, slots)
//  ----------------------------
//  192.168.1.1/24    (1, 1)
//  10.10.10.1/20     (2, 4)
//
// The corresponding route_table would look something like:
//
//  index    (port, nexthop, vlan)
//  ------------------------------
//  1        (1, 172.16.10.1, 1)
//  2        (1, 172.16.10.1, 2)
//  3        (2, 172.17.11.1, 0)
//  4        (3, 172.17.12.1, 0)
//  5        (4, 172.17.13.1, 0)
//
// When a packet is headed for an address in the 10.10.10.1 subnet, the sidecar
// code will look up the address in the route_index file and find that there
// are 4 potential targets, starting at index 2.  It will then use a hash of
// the packet's flow info to choose an offset between 0 and 3, add that to the
// base index of 2, and forward the packet to target in the chosen slot.
//
// Adding or removing a target to a route's set of targets is a 4 step process.
//     1. Allocate a range in the route_data for the new set of targets
//     2. Populate that space with the new targets
//     3. Update the route_index table to point at the new range
//     4. Free the original range
//
// If we were to add a new target to the 192.168.1.1/24 route above and there
// was free space starting at slot 6, the two tables would go through the
// following transitions:
//
// Add the new entries in route_data slots 6 and 7:
//
//  subnet            (index, slots)       index    (port, nexthop, vlan)
//  --------------------------------       ------------------------------
//  192.168.1.1/24    (1, 1)               1        (1, 172.16.10.1, 1)
//  10.10.10.1/20     (2, 4)               2        (1, 172.16.10.1, 2)
//                                         3        (2, 172.17.11.1, 0)
//                                         4        (3, 172.17.12.1, 0)
//                                         5        (4, 172.17.13.1, 0)
//                                         6        (1, 172.17.10.1, 1)
//                                         7        (5, 172.17.14.1, 0)
//
// Update the route_index table to point at the new entries:
//
//  subnet            (index, slots)       index    (port, nexthop, vlan)
//  --------------------------------       ------------------------------
//  192.168.1.1/24    (6, 2)               1        (1, 172.16.10.1, 1)
//  10.10.10.1/20     (2, 4)               2        (1, 172.16.10.1, 2)
//                                         3        (2, 172.17.11.1, 0)
//                                         4        (3, 172.17.12.1, 0)
//                                         5        (4, 172.17.13.1, 0)
//                                         6        (1, 172.17.10.1, 1)
//                                         7        (5, 172.17.14.1, 0)
//
// Free the old route_data entry:
//
//  subnet            (index, slots)       index    (port, nexthop, vlan)
//  --------------------------------       ------------------------------
//  192.168.1.1/24    (6, 2)               1        -
//  10.10.10.1/20     (2, 4)               2        (1, 172.16.10.1, 2)
//                                         3        (2, 172.17.11.1, 0)
//                                         4        (3, 172.17.12.1, 0)
//                                         5        (4, 172.17.13.1, 0)
//                                         6        (1, 172.17.10.1, 1)
//                                         7        (5, 172.17.14.1, 0)
//
//
// Still todo:
//    - Implement this multipath support for IPv6.  This should be a simple
//      copy-and-paste of the IPv4 implementation.  This is currently blocked on
//      a lack of Tofino resources.  Replacing IPv6's single table with the two
//      tables needed for this mechanism causes us to exceed the available
//      stage count.
//    - Add an API for deleting a single IPv6 target.  Since we don't support
//      IPv6 multipath yet, this isn't strictly needed.  However, it would be
//      nice to push out the full API at once to avoid bumping the version in
//      the future.
//    - Re-implement the "entry replace" support, which was removed a year+ ago
//      because nobody was using it.  This will let us update the route_index
//      table in a single step.  We currently have to delete the old entry and
//      then insert the new entry.
//    - There is a lot of almost-duplicated code throughout the stack to support
//      both IPv4 and IPv6 routes.  We should look at using traits and/or
//      generics to coalesce common functionality into shared implementations.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv6Addr};
use std::ops::Bound;

use dpd_types::link::LinkId;
use dpd_types::route::Ipv4Route;
use dpd_types::route::Ipv6Route;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;

use crate::freemap;
use crate::types::{DpdError, DpdResult};
use crate::{Switch, table};
use common::ports::PortId;
use common::table::TableType;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};

// These are the largest numbers of targets supported for a single route
const MAX_TARGETS_IPV4: usize = 32;
const MAX_TARGETS_IPV6: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    tag: String,
    port_id: PortId,
    link_id: LinkId,
    tgt_ip: IpAddr,
    vlan_id: Option<u16>,
}

impl From<&Route> for dpd_types::route::Route {
    fn from(r: &Route) -> Self {
        match r.tgt_ip {
            IpAddr::V4(tgt_ip) => dpd_types::route::Route::V4(Ipv4Route {
                tag: r.tag.clone(),
                port_id: r.port_id,
                link_id: r.link_id,
                tgt_ip,
                vlan_id: r.vlan_id,
            }),
            IpAddr::V6(tgt_ip) => dpd_types::route::Route::V6(Ipv6Route {
                tag: r.tag.clone(),
                port_id: r.port_id,
                link_id: r.link_id,
                tgt_ip,
                vlan_id: r.vlan_id,
            }),
        }
    }
}

impl From<&Route> for Ipv4Route {
    fn from(r: &Route) -> Self {
        match r.tgt_ip {
            IpAddr::V4(tgt_ip) => Ipv4Route {
                tag: r.tag.clone(),
                port_id: r.port_id,
                link_id: r.link_id,
                tgt_ip,
                vlan_id: r.vlan_id,
            },
            IpAddr::V6(_) => panic!("can't convert v6 route to v4"),
        }
    }
}

impl From<Route> for Ipv4Route {
    fn from(r: Route) -> Self {
        (&r).into()
    }
}

impl From<&Route> for Ipv6Route {
    fn from(r: &Route) -> Self {
        match r.tgt_ip {
            IpAddr::V6(tgt_ip) => Ipv6Route {
                tag: r.tag.clone(),
                port_id: r.port_id,
                link_id: r.link_id,
                tgt_ip,
                vlan_id: r.vlan_id,
            },
            IpAddr::V4(_) => panic!("can't convert v4 route to v6"),
        }
    }
}

impl From<Route> for Ipv6Route {
    fn from(r: Route) -> Self {
        (&r).into()
    }
}

impl From<&Ipv4Route> for Route {
    fn from(r: &Ipv4Route) -> Self {
        Route {
            tag: r.tag.clone(),
            port_id: r.port_id,
            link_id: r.link_id,
            tgt_ip: IpAddr::V4(r.tgt_ip),
            vlan_id: r.vlan_id,
        }
    }
}

impl From<Ipv4Route> for Route {
    fn from(r: Ipv4Route) -> Self {
        (&r).into()
    }
}

impl From<&Ipv6Route> for Route {
    fn from(r: &Ipv6Route) -> Self {
        Route {
            tag: r.tag.clone(),
            port_id: r.port_id,
            link_id: r.link_id,
            tgt_ip: IpAddr::V6(r.tgt_ip),
            vlan_id: r.vlan_id,
        }
    }
}

impl From<Ipv6Route> for Route {
    fn from(r: Ipv6Route) -> Self {
        (&r).into()
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct NextHop {
    asic_port_id: u16,
    route: Route,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RouteEntry {
    is_ipv4: bool,
    index: u16,
    slots: u8,
    targets: Vec<NextHop>,
}

impl RouteEntry {
    fn targets(&self) -> Vec<Route> {
        self.targets.iter().map(|target| target.route.clone()).collect()
    }
}

pub struct RouteData {
    v4: BTreeMap<IpNet, RouteEntry>,
    v6: BTreeMap<IpNet, RouteEntry>,
    v4_freemap: freemap::FreeMap,
    v6_freemap: freemap::FreeMap,
}

impl RouteData {
    pub fn insert(
        &mut self,
        subnet: impl Into<IpNet>,
        entry: RouteEntry,
    ) -> Option<RouteEntry> {
        let subnet: IpNet = subnet.into();
        if subnet.is_ipv4() {
            self.v4.insert(subnet, entry)
        } else {
            self.v6.insert(subnet, entry)
        }
    }

    pub fn get(&self, subnet: impl Into<IpNet>) -> Option<&RouteEntry> {
        let subnet: IpNet = subnet.into();
        if subnet.is_ipv4() {
            self.v4.get(&subnet)
        } else {
            self.v6.get(&subnet)
        }
    }

    pub fn remove(&mut self, subnet: impl Into<IpNet>) -> Option<RouteEntry> {
        let subnet: IpNet = subnet.into();
        if subnet.is_ipv4() {
            self.v4.remove(&subnet)
        } else {
            self.v6.remove(&subnet)
        }
    }

    fn freemap_mut(&mut self, is_ipv4: bool) -> &mut freemap::FreeMap {
        if is_ipv4 { &mut self.v4_freemap } else { &mut self.v6_freemap }
    }
}

// Remove all the data for a given route from both the route_data and
// route_index tables.
//
// Because this may be called from the error-recovery path of a failed add-target
// operation, not all of the target slots may yet be populated.  Thus we require
// the caller to explicitly indicate which slots need to be cleared.
fn cleanup_route(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Option<IpNet>,
    entry: RouteEntry,
) -> DpdResult<()> {
    // Remove the subnet -> index mapping first, so nobody can reach the
    // entries we delete below.
    match subnet {
        Some(IpNet::V4(subnet)) => {
            table::route_ipv4::delete_route_index(switch, &subnet)
        }
        Some(IpNet::V6(subnet)) => {
            table::route_ipv6::delete_route_index(switch, &subnet)
        }
        None => Ok(()),
    }?;

    let all_clear = entry
        .targets
        .iter()
        .enumerate()
        .map(|(idx, _hop)| {
            let x = entry.index + idx as u16;
            if entry.is_ipv4 {
                table::route_ipv4::delete_route_target(switch, x)
            } else {
                table::route_ipv6::delete_route_target(switch, x)
            }
        })
        .all(|rval| rval.is_ok());

    // If all of the entries were removed, we can release the table space back
    // to the FreeMap.  If something went wrong, and there's really no reason it
    // should, then this table space will be leaked.
    //
    // A reserve-resident entry (degraded-mode survivor of a failed
    // `reserve_two_swap`) is unwound via `release_reserve_in_place` —
    // the reserve is owned as a unit, separately from the user pool.
    if all_clear {
        let freemap = route_data.freemap_mut(entry.is_ipv4);
        if freemap.is_reserve_idx(entry.index) {
            freemap.release_reserve_in_place();
        } else {
            freemap.free(entry.index, entry.slots as u16);
        }
    }
    Ok(())
}

// Attempt to add the new index to the route_index table.
//
// If that fails, free all resources associated with the new set of targets and
fn finalize_route(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    entry: Option<RouteEntry>,
) -> DpdResult<()> {
    let Some(entry) = entry else { return Ok(()) };

    match match subnet {
        IpNet::V4(subnet) => table::route_ipv4::add_route_index(
            switch,
            &subnet,
            entry.index,
            entry.slots,
        ),
        IpNet::V6(subnet) => table::route_ipv6::add_route_index(
            switch,
            &subnet,
            entry.index,
            entry.slots,
        ),
    } {
        Ok(_) => {
            route_data.insert(subnet, entry);
            Ok(())
        }
        Err(_) => cleanup_route(switch, route_data, None, entry),
    }
}

/// Categorizes a target-set replacement so `replace_route_targets` can dispatch
/// to the right execution path.
enum RouteTargetUpdate {
    /// `new` is a strict subset of `old` (any positive delta).  Safe to
    /// compact in place without ever calling `FreeMap::alloc`.  `removed`
    /// lists the indices into `old.targets` that should be evicted, in
    /// decreasing order — that ordering keeps the invariant that, at each
    /// iteration, the current tail slot holds either a survivor (to be
    /// pulled into a lower position) or the slot being evicted.
    ShrinkInPlace { removed: Vec<u16> },
    /// `new.len() <= old.len()` but `new` is not a subset.  Stage the new
    /// targets via the FreeMap's reserve region, atomically flip
    /// `route_index`, then move out of the reserve.  Always satisfiable
    /// regardless of user-pool fragmentation.
    Swap,
    /// `new.len() > old.len()`, or there is no existing entry.  Allocate
    /// fresh space from the user pool, write, and flip `route_index`.
    /// `TableFull` here is a legitimate "no room" condition.
    Alloc,
}

/// Decide how to apply `new` on top of `old`.  See `RouteTargetUpdate` for the
/// meaning of each variant.
fn classify_update(
    old: Option<&RouteEntry>,
    new: &[NextHop],
) -> RouteTargetUpdate {
    let Some(old) = old else {
        return RouteTargetUpdate::Alloc;
    };
    if new.len() > old.targets.len() {
        return RouteTargetUpdate::Alloc;
    }
    let mut removed: Vec<u16> = old
        .targets
        .iter()
        .enumerate()
        .filter(|(_, hop)| !new.contains(hop))
        .map(|(i, _)| i as u16)
        .collect();
    if old.targets.len() - removed.len() == new.len() {
        removed.sort_unstable_by(|a, b| b.cmp(a));
        RouteTargetUpdate::ShrinkInPlace { removed }
    } else {
        RouteTargetUpdate::Swap
    }
}

/// Write one route_target entry at `base + offset` for each `target`,
/// dispatching on the subnet's family and the target's nexthop family.
fn write_targets_at(
    switch: &Switch,
    subnet_is_ipv4: bool,
    base: u16,
    targets: &[NextHop],
) -> DpdResult<()> {
    for (offset, target) in targets.iter().enumerate() {
        let idx = base + offset as u16;
        write_one_target(switch, subnet_is_ipv4, idx, target)?;
    }
    Ok(())
}

fn write_one_target(
    switch: &Switch,
    subnet_is_ipv4: bool,
    idx: u16,
    target: &NextHop,
) -> DpdResult<()> {
    match target.route.tgt_ip {
        IpAddr::V4(tgt_ip) => table::route_ipv4::add_route_target(
            switch,
            idx,
            target.asic_port_id,
            tgt_ip,
            target.route.vlan_id,
        ),
        IpAddr::V6(tgt_ip) => {
            if subnet_is_ipv4 {
                table::route_ipv4::add_route_target_v6(
                    switch,
                    idx,
                    target.asic_port_id,
                    tgt_ip,
                    target.route.vlan_id,
                )
            } else {
                table::route_ipv6::add_route_target(
                    switch,
                    idx,
                    target.asic_port_id,
                    tgt_ip,
                    target.route.vlan_id,
                )
            }
        }
    }
}

/// Delete one route_target entry at `idx`, dispatching on subnet family.
fn delete_one_target_at(
    switch: &Switch,
    subnet_is_ipv4: bool,
    idx: u16,
) -> DpdResult<()> {
    if subnet_is_ipv4 {
        table::route_ipv4::delete_route_target(switch, idx)
    } else {
        table::route_ipv6::delete_route_target(switch, idx)
    }
}

/// Delete `count` consecutive route_target entries starting at `base`.
fn delete_targets_at(
    switch: &Switch,
    subnet_is_ipv4: bool,
    base: u16,
    count: u16,
) -> DpdResult<()> {
    for offset in 0..count {
        delete_one_target_at(switch, subnet_is_ipv4, base + offset)?;
    }
    Ok(())
}

/// Add a route_index entry for `subnet` pointing at `[index, index + slots)`.
fn add_route_index_for(
    switch: &Switch,
    subnet: IpNet,
    index: u16,
    slots: u8,
) -> DpdResult<()> {
    match subnet {
        IpNet::V4(v4) => {
            table::route_ipv4::add_route_index(switch, &v4, index, slots)
        }
        IpNet::V6(v6) => {
            table::route_ipv6::add_route_index(switch, &v6, index, slots)
        }
    }
}

/// Delete the route_index entry for `subnet`.
fn delete_route_index_for(switch: &Switch, subnet: IpNet) -> DpdResult<()> {
    match subnet {
        IpNet::V4(v4) => table::route_ipv4::delete_route_index(switch, &v4),
        IpNet::V6(v6) => table::route_ipv6::delete_route_index(switch, &v6),
    }
}

/// Take the route off the dataplane: remove the in-core entry for `subnet`
/// and delete the on-chip `route_index`.  On success the caller owns the
/// previous `RouteEntry` (or `None` if the subnet had none).  On failure
/// of the on-chip delete the in-core mirror is restored.
///
/// Every path that mutates a subnet's slot reservation should start here.
/// It gives the caller sole ownership of the old entry and guarantees
/// the dataplane can't reach the slots while they're in flight.
fn unhook_route(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
) -> DpdResult<Option<RouteEntry>> {
    let old_entry = route_data.remove(subnet);
    if old_entry.is_some()
        && let Err(e) = delete_route_index_for(switch, subnet)
    {
        debug!(
            switch.log,
            "unhook_route: route_index delete failed for {subnet}: {e:?}"
        );
        if let Some(old) = old_entry.as_ref() {
            route_data.insert(subnet, old.clone());
        }
        return Err(e);
    }
    Ok(old_entry)
}

// Update the set of targets associated with a route.
//
// This routine can be used to either add or remove a route - all it knows is
// that it is replacing the current set with the newly provided set.
//
// On success, the new data will be in the tables and the old data will be
// freed.  On failure, the new data will be freed and the tables will still
// contain the old data.  In either case, there should be nothing for the
// calling routine to do but pass the DpdResult back up the stack.
//
// The function dispatches on the shape of the requested change (see
// `RouteTargetUpdate`).  Subset removals take a shrink-in-place path that never
// calls `FreeMap::alloc`; everything else falls through to the
// alloc-then-swap path.
fn replace_route_targets(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    targets: Vec<NextHop>,
) -> DpdResult<()> {
    debug!(switch.log, "replacing targets for {subnet} with: {targets:?}");

    // Take ownership of the old in-core entry and remove the on-chip
    // route_index in one step.  After this returns Ok, the subnet is gone
    // from both the in-core BTreeMap and the dataplane's LPM table; each
    // branch below is responsible for either reinstalling the old entry
    // (on early failure) or installing a new one (on success).
    let old_entry = unhook_route(switch, route_data, subnet)?;

    if targets.is_empty() {
        return delete_route_entirely(switch, route_data, old_entry);
    }

    match classify_update(old_entry.as_ref(), &targets) {
        RouteTargetUpdate::ShrinkInPlace { removed } => {
            // ShrinkInPlace is only returned when old_entry is Some.
            let old = old_entry.expect("subset removal requires existing route");
            shrink_in_place(switch, route_data, subnet, old, targets, removed)
        }
        RouteTargetUpdate::Swap => {
            // Swap is only returned when old_entry is Some.
            let old =
                old_entry.expect("swap dispatch requires existing route");
            reserve_two_swap(switch, route_data, subnet, old, targets)
        }
        RouteTargetUpdate::Alloc => {
            alloc_then_swap(switch, route_data, subnet, old_entry, targets)
        }
    }
}

// Free a route's slot reservation after it has been unhooked.  The
// route_index is already gone (via `unhook_route`); we just have to tear
// down the on-chip slot entries and return the FreeMap range.
fn delete_route_entirely(
    switch: &Switch,
    route_data: &mut RouteData,
    old_entry: Option<RouteEntry>,
) -> DpdResult<()> {
    if let Some(entry) = old_entry {
        return cleanup_route(switch, route_data, None, entry);
    }
    Ok(())
}

// Allocate a fresh slot reservation, write the new targets there, then add
// `route_index` pointing at it.  Caller has already unhooked any pre-existing
// route (the in-core entry and on-chip route_index are gone for `subnet`);
// `old_entry` carries the previous slot reservation that we still need to
// free on success or restore on failure.
fn alloc_then_swap(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    old_entry: Option<RouteEntry>,
    targets: Vec<NextHop>,
) -> DpdResult<()> {
    let slots = targets.len() as u8;
    let is_ipv4 = subnet.is_ipv4();
    let mut new_entry = match route_data.freemap_mut(is_ipv4).alloc(slots) {
        Ok(index) => RouteEntry {
            is_ipv4,
            index,
            slots,
            targets: Vec::with_capacity(slots as usize),
        },
        Err(e) => {
            debug!(
                switch.log,
                "failed to allocate space for the new target list"
            );
            // Restore the old route_index + in-core entry (or no-op if
            // there was no old entry).
            let _ = finalize_route(switch, route_data, subnet, old_entry);
            return Err(e);
        }
    };

    // Insert all the entries into the table
    let mut idx = new_entry.index;

    for target in targets {
        if let Err(e) = write_one_target(switch, is_ipv4, idx, &target) {
            debug!(switch.log, "failed to insert {target:?} into route table");
            let _ = cleanup_route(switch, route_data, None, new_entry);
            let _ = finalize_route(switch, route_data, subnet, old_entry);
            return Err(e);
        }
        idx += 1;
        new_entry.targets.push(target);
    }

    // Insert the new subnet->index mapping
    match finalize_route(switch, route_data, subnet, Some(new_entry.clone())) {
        Ok(()) => {
            // Finally free all of the table space for the original set of
            // targets
            if let Some(entry) = old_entry {
                let _ = cleanup_route(switch, route_data, None, entry);
            }
            Ok(())
        }
        Err(e) => {
            debug!(switch.log, "failed to update index to new target list");
            // We failed to point at the new set of targets.  Free all of the
            // new data and update the route_index table to point at the
            // original set of targets.
            let _ = cleanup_route(switch, route_data, None, new_entry);
            let _ = finalize_route(switch, route_data, subnet, old_entry);
            Err(e)
        }
    }
}

// Apply a subset-removal update by compacting the existing reservation in
// place.  Four steps:
//
//   1. Delete `route_index` for `subnet`.  The dataplane now misses on this
//      subnet (LPM lookup returns the default action) for the duration of
//      the compaction.  This is the same brief miss window the existing
//      alloc-then-swap path produces.
//
//   2. For each removed slot (in decreasing index order), pull the current
//      tail contents down into the doomed position via delete + add on the
//      route_target slot, and plan the tail slot for release.  The slots
//      are unreachable from the dataplane at this point because step 1
//      removed the index, so per-slot atomicity isn't required.
//
//   3. Re-add `route_index` pointing at `(base, new.len())`.  The dataplane
//      now resumes with the compacted policy.
//
//   4. Delete the now-unreachable tail entries and return their slots to
//      the FreeMap via `commit_release` (a no-op for slots inside the
//      reserve, since the reserve is owned as a unit and gets released
//      by `cleanup_route` when the entry is fully freed).  These deletes
//      are post-commit; failures here leak slots but cannot corrupt
//      forwarding.
//
// The caller has already unhooked the route (route_index gone, in-core
// entry removed); we own `old` outright.  On failure in any step,
// `rollback_shrink` restores the ASIC slot contents and reinstalls the
// original `route_index`; if rollback succeeds we re-insert `old` into the
// in-core mirror; if rollback itself fails we leave the in-core empty
// (matching the now-unknown ASIC state) so the next control-plane update
// rebuilds from scratch.
fn shrink_in_place(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    old: RouteEntry,
    new_targets: Vec<NextHop>,
    removed: Vec<u16>,
) -> DpdResult<()> {
    let base = old.index;
    let is_ipv4 = old.is_ipv4;
    let new_n = new_targets.len() as u8;
    // Mirror of the slot contents under [base, base+old.slots) that we update
    // in lockstep with each successful ASIC operation.  `None` means the
    // slot's ASIC entry is currently deleted.
    let mut live: Vec<Option<NextHop>> =
        old.targets.iter().map(|t| Some(t.clone())).collect();
    let mut current_top = old.slots as u16;
    let mut released: Vec<freemap::TailSlot> =
        Vec::with_capacity(removed.len());

    // Step 1: compact in decreasing-removed-index order via delete + add.
    // Slots are unreachable from the dataplane (route_index was deleted by
    // the dispatcher's `unhook_route`).
    for &removed_idx in &removed {
        let tail_idx = current_top - 1;
        if removed_idx != tail_idx {
            let tail_contents = live[tail_idx as usize]
                .as_ref()
                .expect("tail slot is live at this point")
                .clone();
            if let Err(e) = delete_one_target_at(
                switch,
                is_ipv4,
                base + removed_idx,
            ) {
                debug!(
                    switch.log,
                    "shrink-in-place compact delete failed at slot {}: {e:?}",
                    base + removed_idx
                );
                drop(released);
                restore_after_shrink_failure(
                    switch, route_data, subnet, is_ipv4, base, &live, old,
                );
                return Err(e);
            }
            live[removed_idx as usize] = None;
            if let Err(e) = write_one_target(
                switch,
                is_ipv4,
                base + removed_idx,
                &tail_contents,
            ) {
                debug!(
                    switch.log,
                    "shrink-in-place compact add failed at slot {}: {e:?}",
                    base + removed_idx
                );
                drop(released);
                restore_after_shrink_failure(
                    switch, route_data, subnet, is_ipv4, base, &live, old,
                );
                return Err(e);
            }
            live[removed_idx as usize] = Some(tail_contents);
        }
        let plan = route_data
            .freemap_mut(is_ipv4)
            .plan_release_last(base, current_top)
            .expect("current_top > 0 throughout step 1");
        released.push(plan);
        current_top -= 1;
    }

    // Step 2: install the route_index pointing at the compacted range.
    if let Err(e) = add_route_index_for(switch, subnet, base, new_n) {
        debug!(
            switch.log,
            "shrink-in-place index re-add failed for {subnet}: {e:?}"
        );
        drop(released);
        restore_after_shrink_failure(
            switch, route_data, subnet, is_ipv4, base, &live, old,
        );
        return Err(e);
    }

    // Step 3: drop the now-unreachable tail entries and release the slots.
    // Best effort; failures past the commit point are leaks, not correctness
    // bugs.  Mirrors `cleanup_route`'s `all_clear` posture.
    let mut all_clear = true;
    for slot in &released {
        if delete_one_target_at(switch, is_ipv4, slot.idx()).is_err() {
            all_clear = false;
        }
    }
    if all_clear {
        let freemap = route_data.freemap_mut(is_ipv4);
        for slot in released {
            // `commit_release` is a no-op for slots that fall in the
            // reserve — the reserve is owned as a unit, and per-slot
            // accounting inside it isn't tracked.  The reserve as a
            // whole gets released later by `cleanup_route` when this
            // (degraded-mode) entry is fully freed.
            freemap.commit_release(slot);
        }
    } else {
        warn!(
            switch.log,
            "shrink-in-place tail cleanup partially failed for {subnet}; \
             leaking slots in the FreeMap's accounting"
        );
        // Dropping `released` without committing leaves the slots claimed in
        // the FreeMap's accounting, which matches what's still allocated on
        // the ASIC.
    }

    let prev = route_data.insert(
        subnet,
        RouteEntry {
            is_ipv4,
            index: base,
            slots: new_n,
            targets: new_targets,
        },
    );
    debug_assert!(
        prev.is_none(),
        "shrink_in_place insert for {subnet} replaced an unexpected \
         existing entry"
    );
    Ok(())
}

// Try to restore the original ASIC slot contents and reinstall the original
// `route_index`; if that succeeds re-insert `old` into the in-core mirror;
// if rollback itself fails leave the in-core empty so the next update
// rebuilds.  Consumes `old`.
fn restore_after_shrink_failure(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    is_ipv4: bool,
    base: u16,
    live: &[Option<NextHop>],
    old: RouteEntry,
) {
    if rollback_shrink(switch, is_ipv4, subnet, base, &old.targets, live, old.slots) {
        route_data.insert(subnet, old);
    } else {
        error!(
            switch.log,
            "shrink-in-place rollback failed for {subnet}; in-core entry \
             stays cleared and ASIC state may diverge until the next \
             control-plane update on this subnet rebuilds it"
        );
    }
}

/// Walk the live mirror against the original target set and restore any
/// drifted position via delete (if a stale entry is present) + add (with the
/// original contents).  Then reinstall the original `route_index` so the
/// dataplane resumes with the pre-shrink policy.  Returns `true` if every
/// rewrite + index-readd succeeded, `false` otherwise.
fn rollback_shrink(
    switch: &Switch,
    is_ipv4: bool,
    subnet: IpNet,
    base: u16,
    original: &[NextHop],
    live: &[Option<NextHop>],
    original_slots: u8,
) -> bool {
    let mut failure_encountered = false;
    for (i, orig) in original.iter().enumerate() {
        let needs_restore = match &live[i] {
            Some(c) => c != orig,
            None => true,
        };
        if !needs_restore {
            continue;
        }
        if live[i].is_some() {
            failure_encountered |=
                delete_one_target_at(switch, is_ipv4, base + i as u16)
                    .is_err();
        }
        failure_encountered |=
            write_one_target(switch, is_ipv4, base + i as u16, orig).is_err();
    }
    failure_encountered |=
        add_route_index_for(switch, subnet, base, original_slots).is_err();
    !failure_encountered
}

// Apply a same-or-smaller non-subset replace by staging the new target set
// in the FreeMap's reserve region, swapping `route_index` to point at it,
// then migrating out into a freshly-allocated user-pool region.  Two swaps,
// each implemented as add (and an internal delete) on the route_index — the
// caller has already unhooked the route (route_index gone, in-core empty),
// so this function picks back up from "route is off the dataplane."
//
//   Swap 1: write new targets into the reserve, add a route_index pointing
//   at the reserve.  Then tear down the old slot range.
//
//   Swap 2: allocate `new.len()` slots from the (now-replenished) user
//   pool, delete the route_index (was pointing at reserve), write the
//   targets at the final location, add a route_index pointing there.  Then
//   clean up the reserve copies and return the reserve to availability.
//
// The reserve is fixed-size and never enters the user-pool freelist, so
// Swap 1's writes cannot fail on fragmentation.  Swap 2 can fail if the
// user pool is genuinely out of room; in that case we leave the route live
// in the reserve (degraded mode) and return Err.  The reserve stays held
// until a subsequent op on this subnet unwinds it — `cleanup_route`
// dispatches reserve-resident entries to `release_reserve_in_place`, so
// any path that fully tears down the old slots (`alloc_then_swap`,
// `delete_route_entirely`) recovers automatically.
//
// If `take_reserve` returns `None` (a prior op left a route in the reserve),
// fall back to `alloc_then_swap` with the owned `old` entry.  That path
// doesn't touch the reserve and will unwind the in-reserve route through
// `cleanup_route` → `release_reserve_in_place`.
fn reserve_two_swap(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    old: RouteEntry,
    new_targets: Vec<NextHop>,
) -> DpdResult<()> {
    let is_ipv4 = old.is_ipv4;
    let new_n = new_targets.len() as u8;

    let Some(reserve) = route_data.freemap_mut(is_ipv4).take_reserve() else {
        debug!(
            switch.log,
            "reserve unavailable for {subnet}; falling back to alloc-then-swap"
        );
        return alloc_then_swap(
            switch,
            route_data,
            subnet,
            Some(old),
            new_targets,
        );
    };
    let reserve_base = reserve.base();

    // Swap 1.  Caller already deleted route_index via unhook_route.
    // Step 1.1: stage new targets in the reserve.
    if let Err(e) =
        write_targets_at(switch, is_ipv4, reserve_base, &new_targets)
    {
        debug!(switch.log, "reserve swap-1 write failed: {e:?}");
        let _ =
            delete_targets_at(switch, is_ipv4, reserve_base, new_n as u16);
        // Restore the old route: reinstall route_index on the ASIC and
        // put the old entry back into the in-core mirror.
        let _ = add_route_index_for(switch, subnet, old.index, old.slots);
        route_data.insert(subnet, old);
        route_data.freemap_mut(is_ipv4).return_reserve(reserve);
        return Err(e);
    }
    // Step 1.2: install the route_index pointing at the reserve.
    if let Err(e) =
        add_route_index_for(switch, subnet, reserve_base, new_n)
    {
        debug!(switch.log, "reserve swap-1 index re-add failed: {e:?}");
        let _ =
            delete_targets_at(switch, is_ipv4, reserve_base, new_n as u16);
        let _ = add_route_index_for(switch, subnet, old.index, old.slots);
        route_data.insert(subnet, old);
        route_data.freemap_mut(is_ipv4).return_reserve(reserve);
        return Err(e);
    }

    // Past the swap-1 commit: dataplane is now serving the new policy
    // from the reserve.  Tear down the old slot range; failures are
    // leaks.  This consumes `old`.
    let _ = cleanup_route(switch, route_data, None, old);

    // Swap 2.
    // Step 2.1: alloc final location from the (now-replenished) user pool.
    let final_idx = match route_data.freemap_mut(is_ipv4).alloc(new_n) {
        Ok(idx) => idx,
        Err(e) => {
            debug!(
                switch.log,
                "reserve swap-2 alloc failed for {subnet}; \
                 leaving route in reserve (degraded)"
            );
            // The reserve stays held; route is correctly programmed
            // there.  Install the reserve-resident entry into the
            // (now-empty) in-core mirror.
            drop(reserve);
            let prev = route_data.insert(
                subnet,
                RouteEntry {
                    is_ipv4,
                    index: reserve_base,
                    slots: new_n,
                    targets: new_targets,
                },
            );
            debug_assert!(
                prev.is_none(),
                "degraded-mode insert for {subnet} replaced an \
                 unexpected existing entry"
            );
            return Err(e);
        }
    };

    // Step 2.2: take the route off the dataplane (was pointing at reserve).
    if let Err(e) = delete_route_index_for(switch, subnet) {
        debug!(
            switch.log,
            "reserve swap-2 index delete failed for {subnet}: {e:?}"
        );
        // Reserve route_index still installed; free the alloc and stay
        // in degraded mode.
        route_data.freemap_mut(is_ipv4).free(final_idx, new_n);
        drop(reserve);
        let prev = route_data.insert(
            subnet,
            RouteEntry {
                is_ipv4,
                index: reserve_base,
                slots: new_n,
                targets: new_targets,
            },
        );
        debug_assert!(
            prev.is_none(),
            "degraded-mode insert for {subnet} replaced an unexpected \
             existing entry"
        );
        return Err(e);
    }
    // Step 2.3: write new targets at the final location.
    if let Err(e) =
        write_targets_at(switch, is_ipv4, final_idx, &new_targets)
    {
        debug!(
            switch.log,
            "reserve swap-2 write failed for {subnet}; \
             restoring reserve-resident route (degraded)"
        );
        let _ = delete_targets_at(switch, is_ipv4, final_idx, new_n as u16);
        route_data.freemap_mut(is_ipv4).free(final_idx, new_n);
        let _ = add_route_index_for(switch, subnet, reserve_base, new_n);
        drop(reserve);
        let prev = route_data.insert(
            subnet,
            RouteEntry {
                is_ipv4,
                index: reserve_base,
                slots: new_n,
                targets: new_targets,
            },
        );
        debug_assert!(
            prev.is_none(),
            "degraded-mode insert for {subnet} replaced an unexpected \
             existing entry"
        );
        return Err(e);
    }
    // Step 2.4: install the route_index pointing at the final location.
    if let Err(e) = add_route_index_for(switch, subnet, final_idx, new_n) {
        debug!(
            switch.log,
            "reserve swap-2 index re-add failed for {subnet}; \
             restoring reserve-resident route (degraded)"
        );
        let _ = delete_targets_at(switch, is_ipv4, final_idx, new_n as u16);
        route_data.freemap_mut(is_ipv4).free(final_idx, new_n);
        let _ = add_route_index_for(switch, subnet, reserve_base, new_n);
        drop(reserve);
        let prev = route_data.insert(
            subnet,
            RouteEntry {
                is_ipv4,
                index: reserve_base,
                slots: new_n,
                targets: new_targets,
            },
        );
        debug_assert!(
            prev.is_none(),
            "degraded-mode insert for {subnet} replaced an unexpected \
             existing entry"
        );
        return Err(e);
    }

    // Both swaps committed.  Clean up the reserve copies and release.
    let _ = delete_targets_at(switch, is_ipv4, reserve_base, new_n as u16);
    route_data.freemap_mut(is_ipv4).return_reserve(reserve);

    let prev = route_data.insert(
        subnet,
        RouteEntry {
            is_ipv4,
            index: final_idx,
            slots: new_n,
            targets: new_targets,
        },
    );
    debug_assert!(
        prev.is_none(),
        "successful reserve_two_swap insert for {subnet} replaced an \
         unexpected existing entry"
    );
    Ok(())
}

fn add_route_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    route: Route,
    asic_port_id: u16,
) -> DpdResult<()> {
    info!(switch.log, "adding route {subnet} -> {:?}", route.tgt_ip);

    // Verify that the slot freelist has been initialized
    let max_targets;
    if subnet.is_ipv4() {
        max_targets = MAX_TARGETS_IPV4;
        route_data
            .v4_freemap
            .maybe_init(switch.table_size(TableType::RouteFwdIpv4)? as u16);
    } else {
        max_targets = MAX_TARGETS_IPV6;
        route_data
            .v6_freemap
            .maybe_init(switch.table_size(TableType::RouteFwdIpv6)? as u16);
    }

    // Get the old set of targets that we'll be adding to
    let mut targets =
        route_data.get(subnet).map_or(Vec::new(), |e| e.targets.clone());
    // Add the new target
    targets.push(NextHop { asic_port_id, route });

    if targets.len() > max_targets {
        Err(DpdError::InvalidRoute(format!(
            "exceeded limit of {max_targets} targets for one route"
        )))
    } else {
        replace_route_targets(switch, route_data, subnet, targets)
    }
}

// Add a new multi-path target to an exiting route, or create a new route with
// just this single target.
async fn add_route(
    switch: &Switch,
    subnet: IpNet,
    route: Route,
) -> DpdResult<()> {
    let asic_port_id =
        switch.link_asic_port_id(route.port_id, route.link_id)?;

    let mut route_data = switch.routes.lock().await;

    // Adding the same route multiple times is a harmless no-op
    if let Some(entry) = route_data.get(subnet)
        && entry.targets.iter().any(|hop| hop.route == route)
    {
        return Ok(());
    }
    add_route_locked(switch, &mut route_data, subnet, route, asic_port_id)
}

// Create a new single-path route.
//
// If there is already an existing route, this call will replace it (if the
// replace flag is set) or return an Exists() error (if the replace flag is not
// set).  If there is no existing route, the replace flag is not examined.  That
// is, it is not an error to "replace" a non- existent route.
async fn set_route(
    switch: &Switch,
    subnet: IpNet,
    route: Route,
    replace: bool,
) -> DpdResult<()> {
    let asic_port_id =
        switch.link_asic_port_id(route.port_id, route.link_id)?;

    let mut route_data = switch.routes.lock().await;
    if let Some(entry) = route_data.get(subnet) {
        // setting the same route multiple times is a harmless no-op
        if entry.targets.len() == 1 && entry.targets[0].route == route {
            Ok(())
        } else if !replace {
            Err(DpdError::Exists("route {cidr} already exists".into()))
        } else {
            info!(switch.log, "replacing subnet {subnet}");
            let target = vec![NextHop { asic_port_id, route }];
            replace_route_targets(switch, &mut route_data, subnet, target)
        }
    } else {
        add_route_locked(switch, &mut route_data, subnet, route, asic_port_id)
    }
}

// Remove a single target from a route.
//
// If this route has multiple targets, this call will remove at most one of
// them.  If the route only has a single target, this call will remove the
// entire route.
fn delete_route_target_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    route: Route,
) -> DpdResult<()> {
    info!(switch.log, "deleting route {subnet} -> {}", route.tgt_ip);

    // Get set of targets remaining after we remove this entry
    let entry = route_data.get(subnet).ok_or({
        debug!(switch.log, "No such route");
        DpdError::Missing("no such route".into())
    })?;
    let targets: Vec<NextHop> = entry
        .targets
        .iter()
        .filter(|t| t.route.tgt_ip != route.tgt_ip)
        .cloned()
        .collect();
    if targets.len() == entry.targets.len() {
        debug!(switch.log, "target not found");
        Err(DpdError::Missing("no such route".into()))
    } else {
        replace_route_targets(switch, route_data, subnet, targets)
    }
}

pub async fn add_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
    route: Ipv4Route,
) -> DpdResult<()> {
    add_route(switch, IpNet::V4(subnet), route.into()).await
}

pub async fn add_route_ipv4_over_ipv6(
    switch: &Switch,
    subnet: Ipv4Net,
    route: Ipv6Route,
) -> DpdResult<()> {
    add_route(switch, IpNet::V4(subnet), route.into()).await
}

pub async fn add_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
    route: Ipv6Route,
) -> DpdResult<()> {
    add_route(switch, IpNet::V6(subnet), route.into()).await
}

pub async fn set_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
    route: Ipv4Route,
    replace: bool,
) -> DpdResult<()> {
    set_route(switch, IpNet::V4(subnet), route.into(), replace).await
}

pub async fn set_route_ipv4_over_ipv6(
    switch: &Switch,
    subnet: Ipv4Net,
    route: Ipv6Route,
    replace: bool,
) -> DpdResult<()> {
    set_route(switch, IpNet::V4(subnet), route.into(), replace).await
}

pub async fn set_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
    route: Ipv6Route,
    replace: bool,
) -> DpdResult<()> {
    set_route(switch, IpNet::V6(subnet), route.into(), replace).await
}

pub async fn get_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
) -> DpdResult<Vec<dpd_types::route::Route>> {
    let route_data = switch.routes.lock().await;
    match route_data.get(IpNet::V4(subnet)) {
        None => Err(DpdError::Missing("no such route".into())),
        Some(entry) => {
            Ok(entry.targets.iter().map(|t| (&t.route).into()).collect())
        }
    }
}

pub async fn get_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
) -> DpdResult<Vec<Ipv6Route>> {
    let route_data = switch.routes.lock().await;
    match route_data.get(IpNet::V6(subnet)) {
        None => Err(DpdError::Missing("no such route".into())),
        Some(entry) => {
            Ok(entry.targets.iter().map(|t| (&t.route).into()).collect())
        }
    }
}

fn delete_route_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
) -> DpdResult<()> {
    // Get set of targets remaining after we remove this entry
    let entry = route_data
        .remove(subnet)
        .ok_or(DpdError::Missing("no such route".into()))?;

    cleanup_route(switch, route_data, Some(subnet), entry)
}

// Delete a route and all of its targets
pub async fn delete_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;

    delete_route_locked(switch, &mut route_data, IpNet::V4(subnet))
}

// Delete a route and all of its targets
pub async fn delete_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;

    delete_route_locked(switch, &mut route_data, IpNet::V6(subnet))
}

// Delete a specific target from a route, removing the route if this is the last
// target.
pub async fn delete_route_target_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
    port_id: PortId,
    link_id: LinkId,
    tgt_ip: IpAddr,
) -> DpdResult<()> {
    let route =
        Route { tag: String::new(), port_id, link_id, tgt_ip, vlan_id: None };

    let mut route_data = switch.routes.lock().await;
    delete_route_target_locked(
        switch,
        &mut route_data,
        IpNet::V4(subnet),
        route,
    )
}

// Delete a specific target from a route, removing the route if this is the last
// target.
pub async fn delete_route_target_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
    port_id: PortId,
    link_id: LinkId,
    tgt_ip: Ipv6Addr,
) -> DpdResult<()> {
    let route = Route {
        tag: String::new(),
        port_id,
        link_id,
        tgt_ip: IpAddr::V6(tgt_ip),
        vlan_id: None,
    };

    let mut route_data = switch.routes.lock().await;
    delete_route_target_locked(
        switch,
        &mut route_data,
        IpNet::V6(subnet),
        route,
    )
}

pub async fn get_range_ipv4(
    switch: &Switch,
    last: Option<Ipv4Net>,
    max: u32,
) -> DpdResult<Vec<dpd_types::route::Ipv4Routes>> {
    let route_data = switch.routes.lock().await;
    let lower = match last {
        None => Bound::Unbounded,
        Some(last) => Bound::Excluded(IpNet::V4(last)),
    };

    let mut routes = Vec::new();
    for (subnet, target_list) in route_data
        .v4
        .range((lower, Bound::Unbounded))
        .take(usize::try_from(max).expect("invalid usize"))
    {
        routes.push(dpd_types::route::Ipv4Routes {
            cidr: match subnet {
                IpNet::V4(n) => *n,
                IpNet::V6(_) => {
                    panic!(
                        "only v4 subnets should be found in the v4 route data"
                    )
                }
            },
            targets: target_list.targets().iter().map(|r| r.into()).collect(),
        })
    }

    Ok(routes)
}

pub async fn get_range_ipv6(
    switch: &Switch,
    last: Option<Ipv6Net>,
    max: u32,
) -> DpdResult<Vec<dpd_types::route::Ipv6Routes>> {
    let route_data = switch.routes.lock().await;
    let lower = match last {
        None => Bound::Unbounded,
        Some(last) => Bound::Excluded(IpNet::V6(last)),
    };

    let mut routes = Vec::new();
    for (subnet, target_list) in route_data
        .v6
        .range((lower, Bound::Unbounded))
        .take(usize::try_from(max).expect("invalid usize"))
    {
        routes.push(dpd_types::route::Ipv6Routes {
            cidr: match subnet {
                IpNet::V6(n) => *n,
                IpNet::V4(_) => {
                    panic!(
                        "only v6 subnets should be found in the v6 route data"
                    )
                }
            },
            targets: target_list.targets().iter().map(|r| r.into()).collect(),
        })
    }

    Ok(routes)
}

async fn reset_tag(switch: &Switch, tag: &str, ipv4: bool) {
    let mut route_data = switch.routes.lock().await;

    debug!(switch.log, "Resetting routes with tag: {tag}");

    // Iterate over all the routes, building a list of targets for each route
    // with the appropriately tagged entries removed.  If that list of targets
    // is different than the original, then mark this route for updating.  We
    // perform any updates after scanning everything to avoid updating the
    // route_data BTreeMap while we're iterating over it.
    let mut to_replace = BTreeMap::new();
    let data = if ipv4 { &route_data.v4 } else { &route_data.v6 };
    for (subnet, entry) in data {
        let new_targets: Vec<NextHop> = entry
            .targets
            .iter()
            .filter(|t| t.route.tag != tag)
            .cloned()
            .collect();
        if new_targets.len() != entry.targets.len() {
            to_replace.insert(*subnet, new_targets);
        }
    }

    for (subnet, targets) in to_replace {
        debug!(switch.log, "new subnets for {subnet}: {targets:?}");
        let _ = replace_route_targets(switch, &mut route_data, subnet, targets);
    }
}

pub async fn reset_ipv4_tag(switch: &Switch, tag: &str) {
    reset_tag(switch, tag, true).await
}

pub async fn reset_ipv6_tag(switch: &Switch, tag: &str) {
    reset_tag(switch, tag, false).await
}

pub async fn reset(switch: &Switch) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;
    route_data.v4 = BTreeMap::new();
    route_data.v4_freemap.reset();
    table::route_ipv4::reset(switch)?;

    route_data.v6 = BTreeMap::new();
    route_data.v6_freemap.reset();
    table::route_ipv6::reset(switch)?;

    Ok(())
}

pub fn init(log: &slog::Logger) -> RouteData {
    RouteData {
        v4: BTreeMap::new(),
        v6: BTreeMap::new(),
        v4_freemap: freemap::FreeMap::new(
            log,
            "route_ipv4",
            MAX_TARGETS_IPV4 as u16,
        ),
        v6_freemap: freemap::FreeMap::new(
            log,
            "route_ipv6",
            MAX_TARGETS_IPV6 as u16,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const FAKE_ASIC_PORT: u16 = 1;

    fn fake_port_id() -> PortId {
        common::ports::RearPort::new(0).unwrap().into()
    }

    fn make_route(tgt_ip: IpAddr) -> Route {
        Route {
            tag: "test".into(),
            port_id: fake_port_id(),
            link_id: LinkId(0),
            tgt_ip,
            vlan_id: None,
        }
    }

    fn make_switch() -> Switch {
        // The asic stub locates its bfrt artifacts by walking up from the
        // running binary path, which fails for `cargo test` because the test
        // executable doesn't end in "dpd". Pin the P4 directory explicitly so
        // the test runs from a workspace checkout regardless of host.
        let p4_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("target/proto/opt/oxide/dendrite/sidecar");
        // SAFETY: set_var is unsafe wrt concurrent access; tests in this
        // module all compute the same value and don't race meaningfully.
        unsafe { std::env::set_var("P4_DIR", &p4_dir) };

        let log = common::logging::init(
            "route-test",
            &None,
            common::logging::LogFormat::Human,
        )
        .expect("test logger");
        let mut switch =
            Switch::new(log, "sidecar", crate::config::Config::default())
                .expect("construct stub switch");
        table::init(&mut switch).expect("init tables");
        switch
    }

    /// Total size to use for the per-family FreeMap in tests that exercise
    /// "table full" / "table fragmented" behavior.  Picked to keep the
    /// reserve carve-off (`MAX_TARGETS_IPV{4,6} = 32`) meaningful while
    /// leaving enough user-pool slots to install a small victim plus a
    /// handful of fillers.
    const TEST_FREEMAP_SIZE: u16 = 64;

    /// Pre-initialize the per-family FreeMap to `TEST_FREEMAP_SIZE` so
    /// subsequent `add_route_locked` calls don't enlarge it to the stub
    /// table's full size.  `maybe_init` is idempotent — once we set the
    /// geometry, the production code path is a no-op.  Must be called
    /// before any `add_route_locked` invocation in the test.
    fn shrink_test_freemap(rd: &mut RouteData, is_ipv4: bool) {
        rd.freemap_mut(is_ipv4).maybe_init(TEST_FREEMAP_SIZE);
    }

    /// Install one entry per target onto `victim`. Callers use this against
    /// an empty table, so any failure is a bug in the test setup.
    fn install_victim(
        switch: &Switch,
        rd: &mut RouteData,
        victim: IpNet,
        targets: impl IntoIterator<Item = IpAddr>,
    ) {
        for tgt in targets {
            add_route_locked(
                switch,
                rd,
                victim,
                make_route(tgt),
                FAKE_ASIC_PORT,
            )
            .expect("victim add must succeed on an empty table");
        }
    }

    /// Install single-target fillers (CIDRs generated by `cidr_at(i)` for
    /// `i = 0, 1, ...`) until any add returns [`DpdError::TableFull`],
    /// returning the CIDRs that were accepted.
    fn fill_table(
        switch: &Switch,
        rd: &mut RouteData,
        filler: IpAddr,
        mut cidr_at: impl FnMut(u32) -> IpNet,
    ) -> Vec<IpNet> {
        let mut fillers = Vec::new();
        for i in 0u32.. {
            let cidr = cidr_at(i);
            match add_route_locked(
                switch,
                rd,
                cidr,
                make_route(filler),
                FAKE_ASIC_PORT,
            ) {
                Ok(_) => fillers.push(cidr),
                Err(DpdError::TableFull(_)) => break,
                Err(e) => panic!("unexpected filler add error: {e:?}"),
            }
        }
        fillers
    }

    /// Delete every other entry in `fillers` so the freemap is left with
    /// size-1 free spans separated by surviving entries — spans that
    /// `reclaim()` cannot coalesce into anything wider.
    fn fragment(switch: &Switch, rd: &mut RouteData, fillers: &[IpNet]) {
        assert!(
            fillers.len() >= 2,
            "table did not accept enough fillers: got {}",
            fillers.len(),
        );
        for f in fillers.iter().step_by(2) {
            delete_route_locked(switch, rd, *f).expect("delete filler");
        }
    }

    fn v6_filler_cidr(i: u32) -> IpNet {
        format!("3fff:beef:{i:x}::/64").parse::<Ipv6Net>().unwrap().into()
    }

    fn v4_filler_cidr(i: u32) -> IpNet {
        format!("172.17.{}.{}/32", (i >> 8) & 0xff, i & 0xff)
            .parse::<Ipv4Net>()
            .unwrap()
            .into()
    }

    /// Deleting a target must succeed when the v6 forwarding table is full.
    ///
    /// Setup mirrors the simplest "no fragmentation, just no room" scenario:
    ///   1. Install one 2-target victim route.
    ///   2. Install 1-target filler routes until any add returns TableFull.
    ///      The fillers consume bin[1] from the victim's growth phase and
    ///      then the freelist tail, leaving the freemap with no spans of
    ///      any size when the loop exits.
    ///   3. Delete one of the victim's two targets.
    #[tokio::test]
    async fn delete_target_succeeds_on_full_table_v6() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let t1: Ipv6Addr = "2001:db8::55:1".parse().unwrap();
        let t2: Ipv6Addr = "2001:db8::55:2".parse().unwrap();
        let filler: Ipv6Addr = "2001:db8::55:ff".parse().unwrap();

        {
            let mut rd = switch.routes.lock().await;
            shrink_test_freemap(&mut rd, false);
            install_victim(
                &switch,
                &mut rd,
                victim.into(),
                [t1.into(), t2.into()],
            );
            fill_table(&switch, &mut rd, filler.into(), v6_filler_cidr);
        }

        delete_route_target_ipv6(
            &switch,
            victim,
            fake_port_id(),
            LinkId(0),
            t2,
        )
        .await
        .expect("delete-target must succeed on a full table");
    }

    /// Deleting a target must succeed when the v6 forwarding table is full
    /// AND fragmented into size-1 free spans separated by live routes.
    ///
    /// Setup:
    ///   1. Install one 4-target victim. K=4 (not 2) so the deletion's
    ///      alloc(3) cannot be satisfied by the size-1 spans we create in
    ///      step 3.
    ///   2. Install 1-target filler routes until the table is full.
    ///   3. Delete every other filler in installation order. Each freed
    ///      slot lands in recycle_bins[1]; because surviving fillers (or
    ///      the victim) occupy the positions between them, those size-1
    ///      spans are pairwise non-adjacent and reclaim() cannot coalesce
    ///      them into anything wider.
    ///   4. Delete one of the victim's four targets.
    #[tokio::test]
    async fn delete_target_succeeds_on_fragmented_table_v6() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let targets: [Ipv6Addr; 4] = [
            "2001:db8::55:1".parse().unwrap(),
            "2001:db8::55:2".parse().unwrap(),
            "2001:db8::55:3".parse().unwrap(),
            "2001:db8::55:4".parse().unwrap(),
        ];
        let filler: Ipv6Addr = "2001:db8::55:ff".parse().unwrap();

        {
            let mut rd = switch.routes.lock().await;
            shrink_test_freemap(&mut rd, false);
            install_victim(
                &switch,
                &mut rd,
                victim.into(),
                targets.iter().map(|a| IpAddr::from(*a)),
            );
            let fillers =
                fill_table(&switch, &mut rd, filler.into(), v6_filler_cidr);
            fragment(&switch, &mut rd, &fillers);
        }

        delete_route_target_ipv6(
            &switch,
            victim,
            fake_port_id(),
            LinkId(0),
            targets[3],
        )
        .await
        .expect("delete-target must succeed on a fragmented table");
    }

    /// IPv4 analog of [`delete_target_succeeds_on_full_table_v6`].
    #[tokio::test]
    async fn delete_target_succeeds_on_full_table_v4() {
        let switch = make_switch();
        let victim: Ipv4Net = "172.16.0.0/32".parse().unwrap();
        let t1 = Ipv4Addr::new(10, 0, 0, 1);
        let t2 = Ipv4Addr::new(10, 0, 0, 2);
        let filler = Ipv4Addr::new(10, 0, 0, 255);

        {
            let mut rd = switch.routes.lock().await;
            shrink_test_freemap(&mut rd, true);
            install_victim(
                &switch,
                &mut rd,
                victim.into(),
                [t1.into(), t2.into()],
            );
            fill_table(&switch, &mut rd, filler.into(), v4_filler_cidr);
        }

        delete_route_target_ipv4(
            &switch,
            victim,
            fake_port_id(),
            LinkId(0),
            t2.into(),
        )
        .await
        .expect("delete-target must succeed on a full table");
    }

    /// IPv4 analog of [`delete_target_succeeds_on_fragmented_table_v6`].
    #[tokio::test]
    async fn delete_target_succeeds_on_fragmented_table_v4() {
        let switch = make_switch();
        let victim: Ipv4Net = "172.16.0.0/32".parse().unwrap();
        let targets: [Ipv4Addr; 4] = [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            Ipv4Addr::new(10, 0, 0, 4),
        ];
        let filler = Ipv4Addr::new(10, 0, 0, 255);

        {
            let mut rd = switch.routes.lock().await;
            shrink_test_freemap(&mut rd, true);
            install_victim(
                &switch,
                &mut rd,
                victim.into(),
                targets.iter().map(|a| IpAddr::from(*a)),
            );
            let fillers =
                fill_table(&switch, &mut rd, filler.into(), v4_filler_cidr);
            fragment(&switch, &mut rd, &fillers);
        }

        delete_route_target_ipv4(
            &switch,
            victim,
            fake_port_id(),
            LinkId(0),
            targets[3].into(),
        )
        .await
        .expect("delete-target must succeed on a fragmented table");
    }

    /// Install three NextHops that all share one `tgt_ip` (distinguished by
    /// `tag`) plus one survivor with a different `tgt_ip`.  A single
    /// `delete_route_target_ipv6` call then removes all three sharing the
    /// `tgt_ip` in one shot (delta=3), exercising the multi-target
    /// subset-removal path through `shrink_in_place` on a full table.
    #[tokio::test]
    async fn delete_target_succeeds_on_full_table_multi_v6() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let shared_tgt: Ipv6Addr = "2001:db8::55:1".parse().unwrap();
        let survivor: Ipv6Addr = "2001:db8::55:2".parse().unwrap();
        let filler: Ipv6Addr = "2001:db8::55:ff".parse().unwrap();

        {
            let mut rd = switch.routes.lock().await;
            shrink_test_freemap(&mut rd, false);
            for tag in ["a", "b", "c"] {
                add_route_locked(
                    &switch,
                    &mut rd,
                    victim.into(),
                    Route {
                        tag: tag.into(),
                        port_id: fake_port_id(),
                        link_id: LinkId(0),
                        tgt_ip: shared_tgt.into(),
                        vlan_id: None,
                    },
                    FAKE_ASIC_PORT,
                )
                .expect("victim add must succeed on an empty table");
            }
            add_route_locked(
                &switch,
                &mut rd,
                victim.into(),
                make_route(survivor.into()),
                FAKE_ASIC_PORT,
            )
            .expect("survivor add must succeed on an empty table");
            fill_table(&switch, &mut rd, filler.into(), v6_filler_cidr);
        }

        delete_route_target_ipv6(
            &switch,
            victim,
            fake_port_id(),
            LinkId(0),
            shared_tgt,
        )
        .await
        .expect("multi-target delete must succeed on a full table");
    }

    /// Same shape as the multi-target full-table test but against a
    /// fragmented freemap — the shrink-in-place path must succeed without
    /// calling `FreeMap::alloc`, regardless of fragmentation.
    #[tokio::test]
    async fn delete_target_succeeds_on_fragmented_table_multi_v6() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let shared_tgt: Ipv6Addr = "2001:db8::55:1".parse().unwrap();
        let survivor: Ipv6Addr = "2001:db8::55:2".parse().unwrap();
        let filler: Ipv6Addr = "2001:db8::55:ff".parse().unwrap();

        {
            let mut rd = switch.routes.lock().await;
            shrink_test_freemap(&mut rd, false);
            for tag in ["a", "b", "c"] {
                add_route_locked(
                    &switch,
                    &mut rd,
                    victim.into(),
                    Route {
                        tag: tag.into(),
                        port_id: fake_port_id(),
                        link_id: LinkId(0),
                        tgt_ip: shared_tgt.into(),
                        vlan_id: None,
                    },
                    FAKE_ASIC_PORT,
                )
                .expect("victim add must succeed on an empty table");
            }
            add_route_locked(
                &switch,
                &mut rd,
                victim.into(),
                make_route(survivor.into()),
                FAKE_ASIC_PORT,
            )
            .expect("survivor add must succeed on an empty table");
            let fillers =
                fill_table(&switch, &mut rd, filler.into(), v6_filler_cidr);
            fragment(&switch, &mut rd, &fillers);
        }

        delete_route_target_ipv6(
            &switch,
            victim,
            fake_port_id(),
            LinkId(0),
            shared_tgt,
        )
        .await
        .expect("multi-target delete must succeed on a fragmented table");
    }

    /// Growing an existing route on a full table is a legitimate TableFull
    /// condition; the alloc-then-swap path should surface that, not paper
    /// over it.
    #[tokio::test]
    async fn add_target_fails_on_full_table_v6() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let t1: Ipv6Addr = "2001:db8::55:1".parse().unwrap();
        let new_tgt: Ipv6Addr = "2001:db8::55:99".parse().unwrap();
        let filler: Ipv6Addr = "2001:db8::55:ff".parse().unwrap();

        let mut rd = switch.routes.lock().await;
        shrink_test_freemap(&mut rd, false);
        install_victim(&switch, &mut rd, victim.into(), [t1.into()]);
        fill_table(&switch, &mut rd, filler.into(), v6_filler_cidr);

        // Grow: replace the 1-target set with a 2-target set (old + new).
        // Going through replace_route_targets directly avoids the public
        // APIs' link_asic_port_id lookup, which isn't wired up under the
        // stub harness.
        let new_targets: Vec<NextHop> = [t1, new_tgt]
            .iter()
            .map(|ip| NextHop {
                asic_port_id: FAKE_ASIC_PORT,
                route: make_route(IpAddr::from(*ip)),
            })
            .collect();
        match replace_route_targets(
            &switch,
            &mut rd,
            victim.into(),
            new_targets,
        ) {
            Err(DpdError::TableFull(_)) => {}
            other => panic!("expected TableFull, got {other:?}"),
        }
    }

    /// Replace a multi-target route with a single non-subset target on a
    /// full table.  Exercises the reserve_two_swap path through
    /// `RouteTargetUpdate::Swap` with a smaller new size that is not a
    /// subset of old.
    #[tokio::test]
    async fn non_subset_smaller_replace_succeeds_on_full_table_v6() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let old_tgts: [Ipv6Addr; 3] = [
            "2001:db8::55:1".parse().unwrap(),
            "2001:db8::55:2".parse().unwrap(),
            "2001:db8::55:3".parse().unwrap(),
        ];
        let replacement: Ipv6Addr = "2001:db8::aa:1".parse().unwrap();
        let filler: Ipv6Addr = "2001:db8::ff:1".parse().unwrap();

        let mut rd = switch.routes.lock().await;
        shrink_test_freemap(&mut rd, false);
        install_victim(
            &switch,
            &mut rd,
            victim.into(),
            old_tgts.iter().map(|a| IpAddr::from(*a)),
        );
        fill_table(&switch, &mut rd, filler.into(), v6_filler_cidr);

        let new_hops = vec![NextHop {
            asic_port_id: FAKE_ASIC_PORT,
            route: make_route(IpAddr::from(replacement)),
        }];
        replace_route_targets(&switch, &mut rd, victim.into(), new_hops)
            .expect("non-subset smaller replace must succeed on full table");
    }

    /// Replace a multi-target route with an entirely new same-size set
    /// (no shared targets) on a full table.  Exercises the reserve path
    /// for the same-size non-subset case, where alloc_then_swap would
    /// TableFull.  Calls `replace_route_targets` directly since no public
    /// API installs an N-target replacement in one shot.
    #[tokio::test]
    async fn non_subset_same_size_replace_succeeds_on_full_table_v6() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let old_tgts: [Ipv6Addr; 3] = [
            "2001:db8::55:1".parse().unwrap(),
            "2001:db8::55:2".parse().unwrap(),
            "2001:db8::55:3".parse().unwrap(),
        ];
        let new_tgts: [Ipv6Addr; 3] = [
            "2001:db8::aa:1".parse().unwrap(),
            "2001:db8::aa:2".parse().unwrap(),
            "2001:db8::aa:3".parse().unwrap(),
        ];
        let filler: Ipv6Addr = "2001:db8::ff:1".parse().unwrap();

        {
            let mut rd = switch.routes.lock().await;
            shrink_test_freemap(&mut rd, false);
            install_victim(
                &switch,
                &mut rd,
                victim.into(),
                old_tgts.iter().map(|a| IpAddr::from(*a)),
            );
            fill_table(&switch, &mut rd, filler.into(), v6_filler_cidr);

            let new_hops: Vec<NextHop> = new_tgts
                .iter()
                .map(|ip| NextHop {
                    asic_port_id: FAKE_ASIC_PORT,
                    route: make_route(IpAddr::from(*ip)),
                })
                .collect();
            replace_route_targets(&switch, &mut rd, victim.into(), new_hops)
                .expect(
                    "same-size non-subset replace must succeed on full table",
                );
        }
    }

    /// Regression: when a route lives in the reserve (degraded mode after
    /// a failed reserve_two_swap swap-2), a subsequent subset removal must
    /// not release the reserve.  Without this property, a later
    /// reserve_two_swap on a different subnet would `take_reserve` and
    /// overwrite the still-live degraded-mode entry.
    ///
    /// Degraded mode is hard to induce through the normal API (the swap-2
    /// alloc almost always succeeds because cleanup_route just freed the
    /// old slot range), so we synthesize the state directly: take the
    /// reserve, drop the handle, and install an entry pointing into the
    /// reserve.
    #[tokio::test]
    async fn shrink_on_reserve_resident_entry_keeps_reserve_held() {
        let switch = make_switch();
        let victim: Ipv6Net = "3fff:dead::/64".parse().unwrap();
        let t1: Ipv6Addr = "2001:db8::55:1".parse().unwrap();
        let t2: Ipv6Addr = "2001:db8::55:2".parse().unwrap();
        let t3: Ipv6Addr = "2001:db8::55:3".parse().unwrap();

        let mut rd = switch.routes.lock().await;
        shrink_test_freemap(&mut rd, false);

        // Synthesize a degraded-mode state: claim the reserve and forget
        // the handle, mirroring what reserve_two_swap does when swap-2
        // fails.
        let handle = rd
            .freemap_mut(false)
            .take_reserve()
            .expect("reserve available at start");
        let reserve_base = handle.base();
        drop(handle);

        // Write the entries onto the ASIC and install the in-core entry
        // pointing into the reserve, again mirroring degraded mode.
        let targets: Vec<NextHop> = [t1, t2, t3]
            .iter()
            .map(|ip| NextHop {
                asic_port_id: FAKE_ASIC_PORT,
                route: make_route(IpAddr::from(*ip)),
            })
            .collect();
        for (i, hop) in targets.iter().enumerate() {
            write_one_target(&switch, false, reserve_base + i as u16, hop)
                .expect("ASIC write into reserve");
        }
        table::route_ipv6::add_route_index(
            &switch,
            &victim,
            reserve_base,
            targets.len() as u8,
        )
        .expect("install route_index pointing at reserve");
        rd.insert(
            victim,
            RouteEntry {
                is_ipv4: false,
                index: reserve_base,
                slots: targets.len() as u8,
                targets: targets.clone(),
            },
        );

        // Sanity check: a second take_reserve fails because the reserve
        // is held (in degraded mode by our synthesized entry).
        assert!(
            rd.freemap_mut(false).take_reserve().is_none(),
            "reserve must already be held by synthesized degraded entry"
        );

        // Perform a subset removal (drop t3).  This dispatches through
        // shrink_in_place.
        let new_targets: Vec<NextHop> = [t1, t2]
            .iter()
            .map(|ip| NextHop {
                asic_port_id: FAKE_ASIC_PORT,
                route: make_route(IpAddr::from(*ip)),
            })
            .collect();
        replace_route_targets(&switch, &mut rd, victim.into(), new_targets)
            .expect("subset removal must succeed on reserve-resident entry");

        // After the shrink, the reserve must still be held: the entry is
        // smaller but still occupies reserve slots, so a new take_reserve
        // must not succeed and hand the reserve to a colliding op.
        assert!(
            rd.freemap_mut(false).take_reserve().is_none(),
            "reserve must remain held after shrink_in_place on a \
             reserve-resident entry"
        );
    }
}
