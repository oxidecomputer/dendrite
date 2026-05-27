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

/// Per-subnet-family dispatch over the on-chip `route_target` and
/// `route_index` tables.  Internal route helpers (`replace_route_targets`,
/// `shrink_in_place`, etc.) take `&dyn RouteTableOps` rather than `&Switch`
/// so tests can supply an implementation that records calls without
/// invoking the ASIC.  Production code passes `&Switch`, whose impl below
/// dispatches to the live `table::route_ipv{4,6}` functions.
trait RouteTableOps {
    /// Logger to use for the routing subsystem's messages.
    fn log(&self) -> &slog::Logger;

    /// Write `target` into slot `idx` of the `route_target` table for
    /// `subnet`.  Production dispatches on `(subnet, target.route.tgt_ip)`:
    /// an IPv4 target always goes to the v4 table; a v6 target goes to
    /// `route_ipv4::add_route_target_v6` when the subnet is v4, otherwise
    /// to the v6 table.
    fn add_target(
        &self,
        subnet: IpNet,
        idx: u16,
        target: &NextHop,
    ) -> DpdResult<()>;

    /// Delete slot `idx` of the `route_target` table for `subnet`.
    fn delete_target(&self, subnet: IpNet, idx: u16) -> DpdResult<()>;

    /// Install a `route_index` entry pointing at `[index, index + slots)`
    /// of the family inferred from `subnet`.
    fn add_index(&self, subnet: IpNet, index: u16, slots: u8) -> DpdResult<()>;

    /// Delete the `route_index` entry for `subnet`.
    fn delete_index(&self, subnet: IpNet) -> DpdResult<()>;
}

impl RouteTableOps for Switch {
    fn log(&self) -> &slog::Logger {
        &self.log
    }

    fn add_target(
        &self,
        subnet: IpNet,
        idx: u16,
        target: &NextHop,
    ) -> DpdResult<()> {
        match target.route.tgt_ip {
            IpAddr::V4(tgt_ip) => table::route_ipv4::add_route_target(
                self,
                idx,
                target.asic_port_id,
                tgt_ip,
                target.route.vlan_id,
            ),
            IpAddr::V6(tgt_ip) => {
                if subnet.is_ipv4() {
                    table::route_ipv4::add_route_target_v6(
                        self,
                        idx,
                        target.asic_port_id,
                        tgt_ip,
                        target.route.vlan_id,
                    )
                } else {
                    table::route_ipv6::add_route_target(
                        self,
                        idx,
                        target.asic_port_id,
                        tgt_ip,
                        target.route.vlan_id,
                    )
                }
            }
        }
    }

    fn delete_target(&self, subnet: IpNet, idx: u16) -> DpdResult<()> {
        if subnet.is_ipv4() {
            table::route_ipv4::delete_route_target(self, idx)
        } else {
            table::route_ipv6::delete_route_target(self, idx)
        }
    }

    fn add_index(&self, subnet: IpNet, index: u16, slots: u8) -> DpdResult<()> {
        match subnet {
            IpNet::V4(v4) => {
                table::route_ipv4::add_route_index(self, &v4, index, slots)
            }
            IpNet::V6(v6) => {
                table::route_ipv6::add_route_index(self, &v6, index, slots)
            }
        }
    }

    fn delete_index(&self, subnet: IpNet) -> DpdResult<()> {
        match subnet {
            IpNet::V4(v4) => table::route_ipv4::delete_route_index(self, &v4),
            IpNet::V6(v6) => table::route_ipv6::delete_route_index(self, &v6),
        }
    }
}

// Remove all the data for a given route from both the route_data and
// route_index tables.
//
// Because this may be called from the error-recovery path of a failed add-target
// operation, not all of the target slots may yet be populated.  Thus we require
// the caller to explicitly indicate which slots need to be cleared.
fn cleanup_route(
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
    delete_index: bool,
    entry: RouteEntry,
) -> DpdResult<()> {
    // Remove the subnet -> index mapping first, so nobody can reach the
    // entries we delete below.
    if delete_index {
        ops.delete_index(subnet)?;
    }

    let all_clear = entry
        .targets
        .iter()
        .enumerate()
        .map(|(idx, _hop)| ops.delete_target(subnet, entry.index + idx as u16))
        .all(|rval| rval.is_ok());

    // If all of the entries were removed, we can release the table space back
    // to the FreeMap.  If something went wrong, and there's really no reason it
    // should, then this table space will be leaked.
    if all_clear {
        route_data
            .freemap_mut(entry.is_ipv4)
            .free(entry.index, entry.slots as u16);
    }
    Ok(())
}

// Attempt to add the new index to the route_index table.
//
// If that fails, free all resources associated with the new set of targets and
fn finalize_route(
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
    entry: Option<RouteEntry>,
) -> DpdResult<()> {
    let Some(entry) = entry else { return Ok(()) };

    match ops.add_index(subnet, entry.index, entry.slots) {
        Ok(_) => {
            route_data.insert(subnet, entry);
            Ok(())
        }
        Err(_) => cleanup_route(ops, route_data, subnet, false, entry),
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
    /// Anything else (new target set is not a subset of the old set, or
    /// no old set exists).  Allocate fresh space from the user pool,
    /// write, and flip `route_index`.  `TableFull` here is a legitimate
    /// "no room" condition for grow/new and a fragmentation condition
    /// for non-subset same-or-smaller replaces.
    Alloc,
    /// `new` and `old` denote the same set (same length, no removals).
    /// The dispatcher short-circuits before unhooking so the dataplane
    /// sees no LPM miss for an idempotent replace.
    NoOp,
}

/// Decide how to apply `new` on top of `old`.  See `RouteTargetUpdate` for the
/// meaning of each variant.
//
// Note: subset detection compares `NextHop`s by structural equality, so
// `old`/`new` sets that contain duplicate `NextHop`s (same port + same
// `Route`) will be conservatively classified as `Alloc` even when they
// represent a valid shrink.  `add_route_locked` rejects exact duplicates
// upstream, so this is a fallback rather than a reachable case in practice.
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
        if removed.is_empty() {
            RouteTargetUpdate::NoOp
        } else {
            removed.sort_unstable_by(|a, b| b.cmp(a));
            RouteTargetUpdate::ShrinkInPlace { removed }
        }
    } else {
        RouteTargetUpdate::Alloc
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
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
) -> DpdResult<Option<RouteEntry>> {
    let Some(old) = route_data.remove(subnet) else {
        return Ok(None);
    };
    if let Err(e) = ops.delete_index(subnet) {
        debug!(
            ops.log(),
            "unhook_route: route_index delete failed for {subnet}: {e:?}"
        );
        route_data.insert(subnet, old);
        return Err(e);
    }
    Ok(Some(old))
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
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
    targets: Vec<NextHop>,
) -> DpdResult<()> {
    debug!(ops.log(), "replacing targets for {subnet} with: {targets:?}");

    // Delete-route path: no classification needed; unhook and free.
    if targets.is_empty() {
        let old_entry = unhook_route(ops, route_data, subnet)?;
        return match old_entry {
            Some(entry) => cleanup_route(ops, route_data, subnet, false, entry),
            None => Ok(()),
        };
    }

    // Classify against the current in-core entry *before* unhooking so that
    // a NoOp replace leaves the dataplane untouched (no LPM miss window).
    match classify_update(route_data.get(subnet), &targets) {
        RouteTargetUpdate::NoOp => Ok(()),
        RouteTargetUpdate::ShrinkInPlace { removed } => {
            let old = unhook_route(ops, route_data, subnet)?
                .expect("subset removal requires existing route");
            // shrink_in_place reconstructs the in-core target vec from the
            // compacted ASIC layout rather than caller-supplied order (see
            // its body for why), so the caller's vec carries no useful
            // information past this point.
            drop(targets);
            shrink_in_place(ops, route_data, subnet, old, removed)
        }
        RouteTargetUpdate::Alloc => {
            let old_entry = unhook_route(ops, route_data, subnet)?;
            alloc_then_swap(ops, route_data, subnet, old_entry, targets)
        }
    }
}

// Allocate a fresh slot reservation, write the new targets there, then add
// `route_index` pointing at it.  Caller has already unhooked any pre-existing
// route (the in-core entry and on-chip route_index are gone for `subnet`);
// `old_entry` carries the previous slot reservation that we still need to
// free on success or restore on failure.
fn alloc_then_swap(
    ops: &dyn RouteTableOps,
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
                ops.log(),
                "failed to allocate space for the new target list"
            );
            // Restore the old route_index + in-core entry (or no-op if
            // there was no old entry).
            let _ = finalize_route(ops, route_data, subnet, old_entry);
            return Err(e);
        }
    };

    // Insert all the entries into the table
    let mut idx = new_entry.index;

    for target in targets {
        if let Err(e) = ops.add_target(subnet, idx, &target) {
            debug!(ops.log(), "failed to insert {target:?} into route table");
            let _ = cleanup_route(ops, route_data, subnet, false, new_entry);
            let _ = finalize_route(ops, route_data, subnet, old_entry);
            return Err(e);
        }
        idx += 1;
        new_entry.targets.push(target);
    }

    // Insert the new subnet->index mapping
    match finalize_route(ops, route_data, subnet, Some(new_entry.clone())) {
        Ok(()) => {
            // Finally free all of the table space for the original set of
            // targets
            if let Some(entry) = old_entry {
                let _ = cleanup_route(ops, route_data, subnet, false, entry);
            }
            Ok(())
        }
        Err(e) => {
            debug!(ops.log(), "failed to update index to new target list");
            // We failed to point at the new set of targets.  Free all of the
            // new data and update the route_index table to point at the
            // original set of targets.
            let _ = cleanup_route(ops, route_data, subnet, false, new_entry);
            let _ = finalize_route(ops, route_data, subnet, old_entry);
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
//      the FreeMap via `commit_release`.  These deletes are post-commit;
//      failures here leak slots but cannot corrupt forwarding.
//
// The caller has already unhooked the route (route_index gone, in-core
// entry removed); we own `old` outright.  On failure in any step,
// `rollback_shrink` restores the ASIC slot contents and reinstalls the
// original `route_index`; if rollback succeeds we re-insert `old` into the
// in-core mirror; if rollback itself fails we leave the in-core empty
// (matching the now-unknown ASIC state) so the next control-plane update
// rebuilds from scratch.
fn shrink_in_place(
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
    old: RouteEntry,
    removed: Vec<u16>,
) -> DpdResult<()> {
    let base = old.index;
    let is_ipv4 = old.is_ipv4;
    let new_n = old.slots - removed.len() as u8;
    // Mirror of the slot contents under [base, base+old.slots) that we update
    // in lockstep with each successful ASIC operation.  `None` means the
    // slot's ASIC entry is currently deleted.  Rollback compares `live`
    // against `old.targets` to find which positions to restore.
    let mut live: Vec<Option<NextHop>> =
        old.targets.iter().map(|t| Some(t.clone())).collect();

    // Step 1: compact in decreasing-removed-index order via delete + add.
    // Slots are unreachable from the dataplane (route_index was deleted by
    // the dispatcher's `unhook_route`).  By construction, the released slots
    // form the contiguous suffix `[base + new_n, base + old.slots)`; there is
    // no per-slot release bookkeeping to do during the loop.
    let mut current_top = old.slots as u16;
    for &removed_idx in &removed {
        let tail_idx = current_top - 1;
        if removed_idx != tail_idx {
            let tail_contents = live[tail_idx as usize]
                .as_ref()
                .expect("tail slot is live at this point")
                .clone();
            if let Err(e) = ops.delete_target(subnet, base + removed_idx) {
                warn!(
                    ops.log(),
                    "shrink-in-place compact delete failed at slot {}: {e:?}",
                    base + removed_idx
                );
                restore_after_shrink_failure(
                    ops, route_data, subnet, &live, old,
                );
                return Err(e);
            }
            live[removed_idx as usize] = None;
            if let Err(e) =
                ops.add_target(subnet, base + removed_idx, &tail_contents)
            {
                warn!(
                    ops.log(),
                    "shrink-in-place compact add failed at slot {}: {e:?}",
                    base + removed_idx
                );
                restore_after_shrink_failure(
                    ops, route_data, subnet, &live, old,
                );
                return Err(e);
            }
            live[removed_idx as usize] = Some(tail_contents);
        }
        current_top -= 1;
    }

    // Step 2: install the route_index pointing at the compacted range.
    if let Err(e) = ops.add_index(subnet, base, new_n) {
        warn!(
            ops.log(),
            "shrink-in-place index re-add failed for {subnet}: {e:?}"
        );
        restore_after_shrink_failure(ops, route_data, subnet, &live, old);
        return Err(e);
    }

    // Step 3: drop the now-unreachable tail entries and release the slots in
    // one bulk free.  Best effort; failures past the commit point are leaks,
    // not correctness bugs.  Mirrors `cleanup_route`'s `all_clear` posture.
    let release_base = base + new_n as u16;
    let release_count = old.slots as u16 - new_n as u16;
    let mut all_clear = true;
    for offset in 0..release_count {
        if ops.delete_target(subnet, release_base + offset).is_err() {
            all_clear = false;
        }
    }
    if all_clear {
        route_data.freemap_mut(is_ipv4).free(release_base, release_count);
    } else {
        warn!(
            ops.log(),
            "shrink-in-place tail cleanup partially failed for {subnet}; \
             leaking slots in the FreeMap's accounting"
        );
        // Skipping the free() call leaves the slots claimed in the FreeMap's
        // accounting, which matches what's still allocated on the ASIC.
    }

    // Build the in-core targets vec from the compacted ASIC layout.
    // Compaction reorders survivors by physical pull-tail-into-hole mechanics,
    // so caller-supplied order need not match what was just programmed on
    // chip.  The in-core mirror's positional contract is "targets[i] is what
    // occupies slot index+i"; honoring that here is what keeps the in-core
    // <-> on-chip alignment that shrink_in_place itself relies on (it
    // rebuilds `live` from `old.targets` on the next call).
    // `live[0..new_n)` is fully populated: each i < new_n is either a
    // survivor in its original position or was overwritten with tail
    // contents during step 1.
    let compacted: Vec<NextHop> = live
        .into_iter()
        .take(new_n as usize)
        .map(|opt| opt.expect("live[0..new_n) is populated post-compaction"))
        .collect();
    let prev = route_data.insert(
        subnet,
        RouteEntry { is_ipv4, index: base, slots: new_n, targets: compacted },
    );
    debug_assert!(
        prev.is_none(),
        "shrink_in_place insert for {subnet} replaced an unexpected \
         existing entry"
    );
    Ok(())
}

// Try to restore the original ASIC slot contents at every position whose
// mirrored state has diverged from `old.targets[i]`, then reinstall the
// original `route_index`; if that succeeds re-insert `old` into the
// in-core mirror; if rollback itself fails leave the in-core empty so the
// next update rebuilds.  Consumes `old`.
fn restore_after_shrink_failure(
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
    live: &[Option<NextHop>],
    old: RouteEntry,
) {
    if rollback_shrink(ops, subnet, &old, live) {
        route_data.insert(subnet, old);
    } else {
        error!(
            ops.log(),
            "shrink-in-place rollback failed for {subnet}; in-core entry \
             stays cleared and ASIC state may diverge until the next \
             control-plane update on this subnet rebuilds it"
        );
    }
}

/// Restore every position whose mirrored slot contents (`live[i]`) no
/// longer match `old.targets[i]` to its pre-shrink contents (a
/// delete-if-present followed by a write of `old.targets[i]`), then
/// reinstall the original `route_index` so the dataplane resumes with
/// the pre-shrink policy.  Returns `true` if every restore + index-readd
/// succeeded, `false` otherwise.  Per-slot failures are logged
/// individually so a divergence postmortem can name the slots involved.
//
// Rollback is O(old.slots) rather than O(touched), but rollback is
// vanishingly rare and `old.slots <= MAX_TARGETS`, so the extra cost is
// negligible and the bookkeeping savings on the hot path are worth it.
fn rollback_shrink(
    ops: &dyn RouteTableOps,
    subnet: IpNet,
    old: &RouteEntry,
    live: &[Option<NextHop>],
) -> bool {
    let base = old.index;
    let mut ok = true;
    for (i, slot_live) in live.iter().enumerate() {
        let orig = &old.targets[i];
        if slot_live.as_ref() == Some(orig) {
            continue;
        }
        let slot = base + i as u16;
        if slot_live.is_some()
            && let Err(e) = ops.delete_target(subnet, slot)
        {
            error!(ops.log(), "rollback delete failed at slot {slot}: {e:?}");
            ok = false;
        }
        if let Err(e) = ops.add_target(subnet, slot, orig) {
            error!(ops.log(), "rollback write failed at slot {slot}: {e:?}");
            ok = false;
        }
    }
    if let Err(e) = ops.add_index(subnet, base, old.slots) {
        error!(
            ops.log(),
            "rollback route_index re-add failed for {subnet}: {e:?}"
        );
        ok = false;
    }
    ok
}

fn add_route_locked(
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
    route: Route,
    asic_port_id: u16,
) -> DpdResult<()> {
    info!(ops.log(), "adding route {subnet} -> {:?}", route.tgt_ip);

    let max_targets =
        if subnet.is_ipv4() { MAX_TARGETS_IPV4 } else { MAX_TARGETS_IPV6 };

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
        replace_route_targets(ops, route_data, subnet, targets)
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
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
    route: Route,
) -> DpdResult<()> {
    info!(ops.log(), "deleting route {subnet} -> {}", route.tgt_ip);

    // Get set of targets remaining after we remove this entry
    let entry = route_data.get(subnet).ok_or({
        debug!(ops.log(), "No such route");
        DpdError::Missing("no such route".into())
    })?;
    let targets: Vec<NextHop> = entry
        .targets
        .iter()
        .filter(|t| t.route.tgt_ip != route.tgt_ip)
        .cloned()
        .collect();
    if targets.len() == entry.targets.len() {
        debug!(ops.log(), "target not found");
        Err(DpdError::Missing("no such route".into()))
    } else {
        replace_route_targets(ops, route_data, subnet, targets)
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
    ops: &dyn RouteTableOps,
    route_data: &mut RouteData,
    subnet: IpNet,
) -> DpdResult<()> {
    // Get set of targets remaining after we remove this entry
    let entry = route_data
        .remove(subnet)
        .ok_or(DpdError::Missing("no such route".into()))?;

    cleanup_route(ops, route_data, subnet, true, entry)
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
        v4_freemap: freemap::FreeMap::new(log, "route_ipv4"),
        v6_freemap: freemap::FreeMap::new(log, "route_ipv6"),
    }
}

/// Size the per-family route_target freemaps to match the on-chip table
/// capacities.  Must be called after `table::init` has populated
/// `switch.tables`, and before any `add_route` can run.
pub async fn init_freemaps(switch: &Switch) -> DpdResult<()> {
    let v4_size = switch.table_size(TableType::RouteFwdIpv4)? as u16;
    let v6_size = switch.table_size(TableType::RouteFwdIpv6)? as u16;
    let mut route_data = switch.routes.lock().await;
    route_data.v4_freemap.maybe_init(v4_size);
    route_data.v6_freemap.maybe_init(v6_size);
    Ok(())
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

    use aal::AsicError;
    use std::cell::Cell;

    /// Total size to use for the per-family FreeMap in tests that exercise
    /// "table full" / "table fragmented" behavior.  Small enough to keep
    /// the fill_table iteration cheap, large enough to install a small
    /// victim plus a handful of fillers.
    const TEST_FREEMAP_SIZE: u16 = 64;

    /// Which on-chip table operation a failpoint applies to.
    #[derive(Clone, Copy)]
    enum Op {
        AddTarget,
        DelTarget,
        AddIndex,
        DelIndex,
    }

    /// In-process implementation of `RouteTableOps` used by the route tests.
    /// Every on-chip operation is a no-op (returning `Ok`) unless the
    /// corresponding failpoint has been armed via [`TestOps::arm`], in which
    /// case the configured call returns a synthetic `Switch(SdeError)` and
    /// the failpoint disarms.  This lets the route state machine run
    /// without any ASIC or P4-runtime presence.
    struct TestOps {
        log: slog::Logger,
        add_target_fail: Cell<Option<u32>>,
        del_target_fail: Cell<Option<u32>>,
        add_index_fail: Cell<Option<u32>>,
        del_index_fail: Cell<Option<u32>>,
    }

    impl TestOps {
        fn new() -> Self {
            let log = common::logging::init(
                "route-test",
                &None,
                common::logging::LogFormat::Human,
            )
            .expect("test logger");
            TestOps {
                log,
                add_target_fail: Cell::new(None),
                del_target_fail: Cell::new(None),
                add_index_fail: Cell::new(None),
                del_index_fail: Cell::new(None),
            }
        }

        fn slot(&self, op: Op) -> &Cell<Option<u32>> {
            match op {
                Op::AddTarget => &self.add_target_fail,
                Op::DelTarget => &self.del_target_fail,
                Op::AddIndex => &self.add_index_fail,
                Op::DelIndex => &self.del_index_fail,
            }
        }

        /// Fail the `(after+1)`-th subsequent call to `op` with a synthetic
        /// SDE error, then disarm.  Tests that need multiple failures on
        /// the same op should re-arm after each fire.
        fn arm(&self, op: Op, after: u32) {
            self.slot(op).set(Some(after));
        }

        fn check(&self, op: Op) -> DpdResult<()> {
            let cell = self.slot(op);
            match cell.get() {
                None => Ok(()),
                Some(0) => {
                    cell.set(None);
                    Err(DpdError::Switch(AsicError::SdeError {
                        ctx: "test failpoint".into(),
                        err: "injected failure".into(),
                    }))
                }
                Some(n) => {
                    cell.set(Some(n - 1));
                    Ok(())
                }
            }
        }
    }

    impl RouteTableOps for TestOps {
        fn log(&self) -> &slog::Logger {
            &self.log
        }

        fn add_target(
            &self,
            _subnet: IpNet,
            _idx: u16,
            _target: &NextHop,
        ) -> DpdResult<()> {
            self.check(Op::AddTarget)
        }

        fn delete_target(&self, _subnet: IpNet, _idx: u16) -> DpdResult<()> {
            self.check(Op::DelTarget)
        }

        fn add_index(
            &self,
            _subnet: IpNet,
            _index: u16,
            _slots: u8,
        ) -> DpdResult<()> {
            self.check(Op::AddIndex)
        }

        fn delete_index(&self, _subnet: IpNet) -> DpdResult<()> {
            self.check(Op::DelIndex)
        }
    }

    /// Build a fresh `(TestOps, RouteData)` pair for a test.  Both freemaps
    /// are eagerly initialized to `TEST_FREEMAP_SIZE` to mirror production,
    /// where `route::init_freemaps` runs after table init.
    fn make_test_ctx() -> (TestOps, RouteData) {
        let ops = TestOps::new();
        let mut rd = init(ops.log());
        rd.v4_freemap.maybe_init(TEST_FREEMAP_SIZE);
        rd.v6_freemap.maybe_init(TEST_FREEMAP_SIZE);
        (ops, rd)
    }

    /// Install one entry per target onto `victim`. Callers use this against
    /// an empty table, so any failure is a bug in the test setup.
    fn install_victim(
        ops: &dyn RouteTableOps,
        rd: &mut RouteData,
        victim: IpNet,
        targets: impl IntoIterator<Item = IpAddr>,
    ) {
        for tgt in targets {
            add_route_locked(ops, rd, victim, make_route(tgt), FAKE_ASIC_PORT)
                .expect("victim add must succeed on an empty table");
        }
    }

    /// Install single-target fillers (CIDRs generated by `cidr_at(i)` for
    /// `i = 0, 1, ...`) until any add returns [`DpdError::TableFull`],
    /// returning the CIDRs that were accepted.
    fn fill_table(
        ops: &dyn RouteTableOps,
        rd: &mut RouteData,
        filler: IpAddr,
        mut cidr_at: impl FnMut(u32) -> IpNet,
    ) -> Vec<IpNet> {
        let mut fillers = Vec::new();
        for i in 0u32.. {
            let cidr = cidr_at(i);
            match add_route_locked(
                ops,
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
    fn fragment(
        ops: &dyn RouteTableOps,
        rd: &mut RouteData,
        fillers: &[IpNet],
    ) {
        assert!(
            fillers.len() >= 2,
            "table did not accept enough fillers: got {}",
            fillers.len(),
        );
        for f in fillers.iter().step_by(2) {
            delete_route_locked(ops, rd, *f).expect("delete filler");
        }
    }

    /// Per-family fixtures used by every test below.  `targets` carries
    /// four distinct addresses so the same fixture works for the 2-target
    /// "full" scenario, the 4-target "fragmented" scenario, and the
    /// "shared tgt_ip with one survivor" multi-target scenario.
    struct FamilyFixtures {
        is_ipv4: bool,
        victim: IpNet,
        targets: [IpAddr; 4],
        filler: IpAddr,
        filler_cidr: fn(u32) -> IpNet,
    }

    fn fixtures_v6() -> FamilyFixtures {
        FamilyFixtures {
            is_ipv4: false,
            victim: "3fff:dead::/64".parse::<Ipv6Net>().unwrap().into(),
            targets: [
                "2001:db8::55:1".parse::<Ipv6Addr>().unwrap().into(),
                "2001:db8::55:2".parse::<Ipv6Addr>().unwrap().into(),
                "2001:db8::55:3".parse::<Ipv6Addr>().unwrap().into(),
                "2001:db8::55:4".parse::<Ipv6Addr>().unwrap().into(),
            ],
            filler: "2001:db8::55:ff".parse::<Ipv6Addr>().unwrap().into(),
            filler_cidr: v6_filler_cidr,
        }
    }

    fn fixtures_v4() -> FamilyFixtures {
        FamilyFixtures {
            is_ipv4: true,
            victim: "172.16.0.0/32".parse::<Ipv4Net>().unwrap().into(),
            targets: [
                Ipv4Addr::new(10, 0, 0, 1).into(),
                Ipv4Addr::new(10, 0, 0, 2).into(),
                Ipv4Addr::new(10, 0, 0, 3).into(),
                Ipv4Addr::new(10, 0, 0, 4).into(),
            ],
            filler: Ipv4Addr::new(10, 0, 0, 255).into(),
            filler_cidr: v4_filler_cidr,
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

    /// Build a Vec<NextHop> from the supplied target IPs using `FAKE_ASIC_PORT`
    /// and the default `make_route` template (empty tag, RearPort(0), no vlan).
    fn next_hops(targets: impl IntoIterator<Item = IpAddr>) -> Vec<NextHop> {
        targets
            .into_iter()
            .map(|ip| NextHop {
                asic_port_id: FAKE_ASIC_PORT,
                route: make_route(ip),
            })
            .collect()
    }

    /// Common post-shrink checks: the in-core entry's tgt_ip set matches
    /// `expected`, and the FreeMap can satisfy a fresh allocation of size
    /// `freed_slots` -- proving the suffix the shrink released was actually
    /// returned to the pool.  The probe consumes the freed span, so callers
    /// should treat it as a terminal assertion.
    fn assert_post_shrink(
        rd: &mut RouteData,
        subnet: IpNet,
        is_ipv4: bool,
        expected: &[IpAddr],
        freed_slots: u16,
    ) {
        use std::collections::BTreeSet;
        let entry = rd.get(subnet).expect("victim must still exist");
        let observed: BTreeSet<IpAddr> =
            entry.targets.iter().map(|t| t.route.tgt_ip).collect();
        let expected_set: BTreeSet<IpAddr> = expected.iter().copied().collect();
        assert_eq!(
            observed, expected_set,
            "in-core target set must match expected"
        );
        if freed_slots > 0 {
            rd.freemap_mut(is_ipv4)
                .alloc(freed_slots)
                .expect("freed slots must be allocatable post-shrink");
        }
    }

    /// Deleting a target must succeed when the forwarding table is full.
    ///
    /// Setup mirrors the simplest "no fragmentation, just no room" scenario:
    ///   1. Install one 2-target victim route.
    ///   2. Install 1-target filler routes until any add returns TableFull.
    ///      The fillers consume bin[1] from the victim's growth phase and
    ///      then the freelist tail, leaving the freemap with no spans of
    ///      any size when the loop exits.
    ///   3. Replace the victim's target set with just the first one,
    ///      i.e. drop the second target.
    fn delete_target_full_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, [f.targets[0], f.targets[1]]);
        fill_table(&ops, &mut rd, f.filler, f.filler_cidr);

        replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[0]]),
        )
        .expect("delete-target must succeed on a full table");
        assert_post_shrink(&mut rd, f.victim, f.is_ipv4, &[f.targets[0]], 1);
    }

    #[test]
    fn delete_target_full() {
        delete_target_full_scenario(fixtures_v6());
        delete_target_full_scenario(fixtures_v4());
    }

    /// Deleting a target must succeed when the forwarding table is full
    /// AND fragmented into size-1 free spans separated by live routes.
    ///
    /// Setup:
    ///   1. Install one 4-target victim. K=4 (not 2) so the alloc-then-swap
    ///      path's alloc(3) would not be satisfied by the size-1 spans
    ///      created in step 3 — shrink-in-place is the only path that can
    ///      win here.
    ///   2. Install 1-target filler routes until the table is full.
    ///   3. Delete every other filler in installation order.  Each freed
    ///      slot lands in recycle_bins[1]; because surviving fillers (or
    ///      the victim) occupy the positions between them, those size-1
    ///      spans are pairwise non-adjacent and reclaim() cannot coalesce
    ///      them into anything wider.
    ///   4. Drop the victim's last target.
    fn delete_target_fragmented_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, f.targets);
        let fillers = fill_table(&ops, &mut rd, f.filler, f.filler_cidr);
        fragment(&ops, &mut rd, &fillers);

        replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops(f.targets[..3].iter().copied()),
        )
        .expect("delete-target must succeed on a fragmented table");
        assert_post_shrink(&mut rd, f.victim, f.is_ipv4, &f.targets[..3], 1);
    }

    #[test]
    fn delete_target_fragmented() {
        delete_target_fragmented_scenario(fixtures_v6());
        delete_target_fragmented_scenario(fixtures_v4());
    }

    /// Install three NextHops that all share one `tgt_ip` (distinguished
    /// by `tag`) plus one survivor with a different `tgt_ip`, then issue a
    /// single replace that drops all three sharing the `tgt_ip` (delta=3).
    /// Exercises the multi-target subset-removal path through
    /// `shrink_in_place`.
    /// Install three NextHops that all share one `tgt_ip` (distinguished by
    /// `tag`) plus one survivor with a different `tgt_ip`, then issue a
    /// single replace that drops all three sharing the `tgt_ip` (delta=3).
    /// Exercises the multi-target subset-removal path through
    /// `shrink_in_place` against either a full or a full+fragmented freemap.
    fn delete_targets_scenario(f: FamilyFixtures, fragmented: bool) {
        let (ops, mut rd) = make_test_ctx();
        let shared_tgt = f.targets[0];
        let survivor = f.targets[1];
        for tag in ["a", "b", "c"] {
            add_route_locked(
                &ops,
                &mut rd,
                f.victim,
                Route {
                    tag: tag.into(),
                    port_id: fake_port_id(),
                    link_id: LinkId(0),
                    tgt_ip: shared_tgt,
                    vlan_id: None,
                },
                FAKE_ASIC_PORT,
            )
            .expect("victim add must succeed on an empty table");
        }
        add_route_locked(
            &ops,
            &mut rd,
            f.victim,
            make_route(survivor),
            FAKE_ASIC_PORT,
        )
        .expect("survivor add must succeed on an empty table");
        let fillers = fill_table(&ops, &mut rd, f.filler, f.filler_cidr);
        if fragmented {
            fragment(&ops, &mut rd, &fillers);
        }

        replace_route_targets(&ops, &mut rd, f.victim, next_hops([survivor]))
            .expect("multi-target delete must succeed");
        assert_post_shrink(&mut rd, f.victim, f.is_ipv4, &[survivor], 3);
    }

    #[test]
    fn delete_targets_full() {
        delete_targets_scenario(fixtures_v6(), false);
        delete_targets_scenario(fixtures_v4(), false);
    }

    #[test]
    fn delete_targets_fragmented() {
        delete_targets_scenario(fixtures_v6(), true);
        delete_targets_scenario(fixtures_v4(), true);
    }

    /// Growing an existing route on a full table is a legitimate TableFull
    /// condition; the alloc-then-swap path should surface that, not paper
    /// over it.
    fn add_target_fails_full_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, [f.targets[0]]);
        fill_table(&ops, &mut rd, f.filler, f.filler_cidr);

        // Grow: replace the 1-target set with a 2-target set (old + new).
        match replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[0], f.targets[1]]),
        ) {
            Err(DpdError::TableFull(_)) => {}
            other => panic!("expected TableFull, got {other:?}"),
        }
    }

    #[test]
    fn add_target_fails_full() {
        add_target_fails_full_scenario(fixtures_v6());
        add_target_fails_full_scenario(fixtures_v4());
    }

    /// After a shrink, the in-core `RouteEntry.targets` must reflect the
    /// physical compacted ASIC layout — not the caller-supplied order.
    /// Install [t0,t1,t2,t3], replace with [t3,t0] (caller order intentionally
    /// different from the natural compaction order).  Compaction processes
    /// removed=[2,1] in decreasing order: slot 2 <- live[3]=t3, slot 1 <-
    /// live[2]=t3 (the just-moved tail).  After step 3 drops the released
    /// tail, the live window is [t0, t3] — that's what in-core must reflect.
    fn shrink_preserves_compacted_order_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, f.targets);

        replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[3], f.targets[0]]),
        )
        .expect("shrink must succeed on an empty table");

        let entry = rd.get(f.victim).expect("victim must still exist");
        let observed: Vec<IpAddr> =
            entry.targets.iter().map(|t| t.route.tgt_ip).collect();
        assert_eq!(
            observed,
            vec![f.targets[0], f.targets[3]],
            "in-core targets must match the compacted ASIC layout, \
             not the caller-supplied order"
        );
    }

    #[test]
    fn shrink_preserves_compacted_order() {
        shrink_preserves_compacted_order_scenario(fixtures_v6());
        shrink_preserves_compacted_order_scenario(fixtures_v4());
    }

    /// Exercise the `removed_idx == tail_idx` branch (skip the copy) for
    /// every iteration: shrink [t0,t1,t2,t3] to [t2] by removing
    /// {3, 1, 0}.  Compaction order: j=0 tail=3=removed (skip), j=1 tail=2
    /// removed=1 (copy t2 -> slot 1), j=2 tail=1 removed=0 (copy live[1]=t2
    /// -> slot 0).  Expected in-core: [t2].
    fn shrink_to_single_non_zero_survivor_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, f.targets);

        replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[2]]),
        )
        .expect("shrink to single survivor must succeed");

        let entry = rd.get(f.victim).expect("victim must still exist");
        let observed: Vec<IpAddr> =
            entry.targets.iter().map(|t| t.route.tgt_ip).collect();
        assert_eq!(observed, vec![f.targets[2]]);
    }

    #[test]
    fn shrink_to_single_non_zero_survivor() {
        shrink_to_single_non_zero_survivor_scenario(fixtures_v6());
        shrink_to_single_non_zero_survivor_scenario(fixtures_v4());
    }

    /// An identity replace (new target set equals old target set) must
    /// short-circuit: classification returns `NoOp` and the dispatcher
    /// returns without unhooking.  We assert that the in-core `RouteEntry`
    /// is byte-for-byte identical to its pre-call state and that the
    /// FreeMap's bookkeeping is undisturbed.  The index check is the
    /// strongest signal: any alloc-then-swap path would have moved the
    /// reservation to a new base.
    fn identity_replace_is_noop_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, f.targets);
        let before = rd.get(f.victim).expect("victim installed").clone();

        replace_route_targets(&ops, &mut rd, f.victim, next_hops(f.targets))
            .expect("identity replace must succeed");

        let after = rd.get(f.victim).expect("victim must still exist");
        assert_eq!(
            &before, after,
            "identity replace must leave the in-core entry untouched"
        );
        // The original reservation must still be claimed.  `FreeMap::alloc`
        // checks the per-size recycle bin before the freelist, so if we *had*
        // taken alloc-then-swap, the old span would now sit in
        // `recycle_bins[before.slots]` and this probe would return
        // `before.index`.  A return value other than `before.index` is
        // therefore proof that the old reservation was never freed.
        let probe = rd
            .freemap_mut(f.is_ipv4)
            .alloc(before.slots)
            .expect("freemap must still have room for a fresh allocation");
        assert_ne!(
            probe, before.index,
            "identity replace must not have freed the original reservation"
        );
    }

    #[test]
    fn identity_replace_is_noop() {
        identity_replace_is_noop_scenario(fixtures_v6());
        identity_replace_is_noop_scenario(fixtures_v4());
    }

    /// A same-length, non-subset replace (one target swapped for another)
    /// must take the alloc-then-swap path: the new set isn't ⊆ old, so
    /// shrink-in-place doesn't apply.  Verifies the dispatcher routes
    /// correctly and that the resulting in-core entry reflects the new
    /// target set.  Run against an empty freemap so the alloc itself is
    /// uncontested — we're testing dispatch, not allocation pressure.
    fn same_size_non_subset_replace_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, [f.targets[0], f.targets[1]]);
        let before_index = rd.get(f.victim).expect("victim installed").index;

        replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[0], f.targets[2]]),
        )
        .expect("same-size non-subset replace must succeed");

        let entry = rd.get(f.victim).expect("victim must still exist");
        use std::collections::BTreeSet;
        let observed: BTreeSet<IpAddr> =
            entry.targets.iter().map(|t| t.route.tgt_ip).collect();
        let expected: BTreeSet<IpAddr> =
            [f.targets[0], f.targets[2]].into_iter().collect();
        assert_eq!(observed, expected, "in-core target set must match new set");
        assert_ne!(
            entry.index, before_index,
            "alloc-then-swap must have moved the reservation to a new base"
        );
    }

    #[test]
    fn same_size_non_subset_replace() {
        same_size_non_subset_replace_scenario(fixtures_v6());
        same_size_non_subset_replace_scenario(fixtures_v4());
    }

    /// Growing an existing route on an uncontested table must succeed via
    /// the alloc-then-swap path.  Companion to `add_target_fails_full`,
    /// which covers the same code path under freemap exhaustion.
    fn grow_succeeds_scenario(f: FamilyFixtures) {
        let (ops, mut rd) = make_test_ctx();
        install_victim(&ops, &mut rd, f.victim, [f.targets[0]]);

        replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[0], f.targets[1]]),
        )
        .expect("grow on an uncontested table must succeed");

        let entry = rd.get(f.victim).expect("victim must still exist");
        assert_eq!(entry.slots, 2, "reservation must reflect the new size");
        use std::collections::BTreeSet;
        let observed: BTreeSet<IpAddr> =
            entry.targets.iter().map(|t| t.route.tgt_ip).collect();
        let expected: BTreeSet<IpAddr> =
            [f.targets[0], f.targets[1]].into_iter().collect();
        assert_eq!(observed, expected, "in-core target set must match new set");
    }

    #[test]
    fn grow_succeeds() {
        grow_succeeds_scenario(fixtures_v6());
        grow_succeeds_scenario(fixtures_v4());
    }

    // ----- failure-injection (rollback) tests -----------------------------
    //
    // Drive `shrink_in_place`'s recovery paths by arming `TestOps` failpoints
    // at the call indices that land at the step being tested.  Each test:
    //   1. Builds a fresh `(TestOps, RouteData)` and installs a 4-target
    //      victim; snapshots the resulting `RouteEntry`.
    //   2. Arms one (or two) failpoints.
    //   3. Issues a shrink-style replace and expects `Err(Switch(_))`.
    //   4. Asserts the documented post-failure invariant — for compact-loop
    //      and commit-boundary failures the in-core entry is restored
    //      byte-for-byte and the FreeMap probe shows the original
    //      reservation still claimed; for the rollback-failure case the
    //      in-core entry is absent and the reservation leaks.

    /// Install a 4-target victim and return a snapshot of its `RouteEntry`
    /// for post-failure comparison.
    fn install_for_rollback(
        ops: &dyn RouteTableOps,
        rd: &mut RouteData,
        f: &FamilyFixtures,
    ) -> RouteEntry {
        install_victim(ops, rd, f.victim, f.targets);
        rd.get(f.victim).expect("victim installed").clone()
    }

    /// Assert that a failed shrink restored the in-core entry byte-for-byte
    /// and that the FreeMap still considers the original reservation
    /// claimed.  Uses the same `recycle_bins`-checked-first probe as
    /// `identity_replace_is_noop`.
    fn assert_rolled_back(
        rd: &mut RouteData,
        f: &FamilyFixtures,
        before: &RouteEntry,
    ) {
        let after = rd.get(f.victim).expect("in-core entry must be restored");
        assert_eq!(
            before, after,
            "rollback must restore in-core byte-for-byte"
        );
        let probe = rd
            .freemap_mut(f.is_ipv4)
            .alloc(before.slots)
            .expect("freemap must still have room");
        assert_ne!(
            probe, before.index,
            "rollback must not have freed the original reservation"
        );
    }

    /// The compact loop's first `delete_target` fails.  Nothing was
    /// touched, `touched` is empty, rollback only re-adds the original
    /// `route_index`.
    ///
    /// Drops `t0` rather than `t3` so the compact loop has real work: when
    /// `removed_idx == tail_idx` the loop body short-circuits and no
    /// `delete_target` is called, leaving the failpoint to fire during the
    /// best-effort post-commit tail cleanup (which never surfaces as Err).
    #[test]
    fn rollback_on_compact_delete_failure() {
        let (ops, mut rd) = make_test_ctx();
        let f = fixtures_v6();
        let before = install_for_rollback(&ops, &mut rd, &f);

        ops.arm(Op::DelTarget, 0);
        let err = replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops(f.targets[1..].iter().copied()),
        )
        .expect_err("compact-delete failpoint must surface as Err");
        assert!(matches!(err, DpdError::Switch(_)));

        assert_rolled_back(&mut rd, &f, &before);
    }

    /// The compact loop's first `add_target` fails after the matching
    /// delete succeeded.  `live[idx] = None` and `idx ∈ touched`, so
    /// rollback must skip the delete (no live entry to remove) and
    /// rewrite `original[idx]`.  This is the case that motivates the
    /// `live[]` / `touched[]` distinction.
    #[test]
    fn rollback_on_compact_write_failure() {
        let (ops, mut rd) = make_test_ctx();
        let f = fixtures_v6();
        let before = install_for_rollback(&ops, &mut rd, &f);

        // Drop two targets (indices 0 and 2 of 4) so the compact loop must
        // copy at least once; the first add_target call lands on the copy.
        ops.arm(Op::AddTarget, 0);
        let err = replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[1], f.targets[3]]),
        )
        .expect_err("compact-write failpoint must surface as Err");
        assert!(matches!(err, DpdError::Switch(_)));

        assert_rolled_back(&mut rd, &f, &before);
    }

    /// The compact loop completes successfully but the commit-boundary
    /// `add_index` fails.  Every removed-slot position has been overwritten
    /// with tail contents and is in `touched`; rollback must restore each
    /// and re-add the original `route_index` (the second AddIndex call of
    /// the run).
    #[test]
    fn rollback_on_index_readd_failure() {
        let (ops, mut rd) = make_test_ctx();
        let f = fixtures_v6();
        let before = install_for_rollback(&ops, &mut rd, &f);

        // First AddIndex call = step 2 (the commit).  Second = rollback's
        // index re-add, which must succeed for this test's assertions.
        ops.arm(Op::AddIndex, 0);
        let err = replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops([f.targets[1], f.targets[3]]),
        )
        .expect_err("commit-boundary AddIndex failpoint must surface as Err");
        assert!(matches!(err, DpdError::Switch(_)));

        assert_rolled_back(&mut rd, &f, &before);
    }

    /// Rollback-of-rollback failure: trigger a compact-delete failure, then
    /// also break the rollback's own `add_index` call.  Documented posture
    /// is "in-core entry stays cleared; FreeMap reservation leaks until
    /// the next control-plane update on this subnet."
    ///
    /// Drops `t0` for the same reason as `rollback_on_compact_delete_failure`.
    #[test]
    fn rollback_failure_leaves_in_core_cleared() {
        let (ops, mut rd) = make_test_ctx();
        let f = fixtures_v6();
        let before = install_for_rollback(&ops, &mut rd, &f);

        // Compact delete fails → rollback fires.  AddIndex's only call this
        // run is the rollback's, so arming "fail next" breaks it.
        ops.arm(Op::DelTarget, 0);
        ops.arm(Op::AddIndex, 0);
        let err = replace_route_targets(
            &ops,
            &mut rd,
            f.victim,
            next_hops(f.targets[1..].iter().copied()),
        )
        .expect_err("compact-delete failpoint must surface as Err");
        assert!(matches!(err, DpdError::Switch(_)));

        assert!(
            rd.get(f.victim).is_none(),
            "documented posture: in-core entry stays cleared when rollback fails"
        );
        let probe = rd
            .freemap_mut(f.is_ipv4)
            .alloc(before.slots)
            .expect("freemap must still have room");
        assert_ne!(
            probe, before.index,
            "rollback failure must leak the original reservation"
        );
    }
}
