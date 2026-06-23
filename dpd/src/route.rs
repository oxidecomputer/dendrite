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
//
// TTL handling
// ------------
// Routed packets arriving with TTL==1 (IPv4) or hop_limit==1 (IPv6) must
// not be forwarded normally. The dataplane generates an ICMP time-exceeded
// (v4) or ICMPv6 time-exceeded (v6) response back to the sender. The tree
// enforces this at multiple sites:
//
//   - IPv4 unicast (route_ipv4.rs + sidecar.p4): compound exact-match key
//     `(idx, route_ttl_is_1)` on the route table installs separate actions
//     for the TTL==1 and TTL>1 rows.
//   - IPv6 multicast (sidecar.p4, MulticastRouter6): inline `hop_limit==1`
//     check in the apply block generates time-exceeded after the lookup.
//   - IPv6 unicast (route_ipv6.rs + sidecar.p4): per-prefix `skip_ttl` bit
//     on the `index` action gates an inline `ICMP_ERROR_SETUP` invocation
//     in the apply block (same pattern as v6 multicast).
//
// Service port handling
// ---------------------
// Routes whose target is `PortId::Internal(_)` (the CPU/AUX/PCIe port that
// delivers to dpd userspace) forward packets even when TTL==1, bypassing
// the normal TTL exceeded handling. Delivery to the local switch's
// userspace is not "forwarding" in the RFC sense. The packet has reached
// its destination, so TTL/hop_limit semantics do not apply. Without this,
// external traffic addressed to a switch-internal service that arrives
// with TTL==1 (e.g. after a long path) would get an ICMP time-exceeded
// reply instead of being delivered to the userspace handler.
//
// The discriminator is the type-level `PortId::Internal(_)` variant. The
// runtime `asic_port_id` is an opaque dpd-internal value whose numeric
// mapping to the service port varies by build and model configuration.
//
// v4/v6 encoding asymmetry
// --------------------------
// v4 uses a compound table key `(idx, route_ttl_is_1)` and installs
// different per-target actions per TTL class. This supports ECMP groups
// that mix service-port and non-service-port targets.
//
// v6 uses a per-prefix `skip_ttl` bit on the `index` action plus an
// inline TTL-exceeded branch in the apply block. The bit gates whether
// the inline path or the normal route table runs.
//
// Trade-off in the v6 encoding: v6 ECMP groups cannot mix service-port
// targets with non-service-port targets, because the per-prefix bit
// cannot represent both behaviors simultaneously. `replace_route_targets`
// rejects such mixed sets up front. v4 has no such restriction because
// its compound key discriminates per-target.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv6Addr};
use std::ops::Bound;

use dpd_types::link::LinkId;
use dpd_types::route::Ipv4Route;
use dpd_types::route::Ipv6Route;
use slog::debug;
use slog::info;

use crate::freemap;
use crate::types::{DpdError, DpdResult};
use crate::{Switch, table};
use common::ports::PortId;
use common::table::TableType;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};

// These are the largest numbers of targets supported for a single route
const MAX_TARGETS_IPV4: usize = 32;
const MAX_TARGETS_IPV6: usize = 32;

// IPv4 route indices map to two physical forward-table entries because the
// route table still keys on `(idx, route_ttl_is_1)` and installs distinct
// forwarding vs. ttl_exceeded rows. IPv6 routes map to a single entry.
// TTL=1 is handled inline in the v6 ingress apply block, gated by a
// per-prefix `skip_ttl` bit on the index action.
const ROUTE_FWD_ENTRIES_PER_ROUTE_V4: u32 = 2;
const ROUTE_FWD_ENTRIES_PER_ROUTE_V6: u32 = 1;

/// Convert a P4 forward-table size to freemap size, given the number of
/// physical entries each logical route consumes.
fn freemap_size_from_table(
    table_size: u32,
    entries_per_route: u32,
) -> DpdResult<u16> {
    let logical_routes = table_size / entries_per_route;
    u16::try_from(logical_routes).map_err(|_| {
        DpdError::Invalid(format!(
            "route table size {table_size} exceeds maximum supported"
        ))
    })
}

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
    fn new(log: &slog::Logger, asic_hdl: &asic::Handle) -> DpdResult<Self> {
        let mut v4_freemap = freemap::FreeMap::new(log, "route_ipv4");
        let mut v6_freemap = freemap::FreeMap::new(log, "route_ipv6");

        let v4_table_size =
            table::Table::new(asic_hdl, TableType::RouteFwdIpv4)?.size();
        let v6_table_size =
            table::Table::new(asic_hdl, TableType::RouteFwdIpv6)?.size();

        v4_freemap.maybe_init(freemap_size_from_table(
            v4_table_size,
            ROUTE_FWD_ENTRIES_PER_ROUTE_V4,
        )?);
        v6_freemap.maybe_init_with_low(
            1,
            freemap_size_from_table(
                v6_table_size,
                ROUTE_FWD_ENTRIES_PER_ROUTE_V6,
            )?,
        );

        Ok(RouteData {
            v4: BTreeMap::new(),
            v6: BTreeMap::new(),
            v4_freemap,
            v6_freemap,
        })
    }

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
    if all_clear {
        if entry.is_ipv4 {
            route_data.v4_freemap.free(entry.index, entry.slots as u16);
        } else {
            route_data.v6_freemap.free(entry.index, entry.slots as u16);
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
        IpNet::V6(subnet) => {
            // If any target for this prefix routes to the user-space
            // service port, suppress the dataplane TTL=1 exception so
            // userspace still receives the packet. Mixed sets are
            // rejected upstream, so any/all here are equivalent.
            let skip_ttl = entry
                .targets
                .iter()
                .any(|t| matches!(t.route.port_id, PortId::Internal(_)));
            table::route_ipv6::add_route_index(
                switch,
                &subnet,
                entry.index,
                entry.slots,
                skip_ttl,
            )
        }
    } {
        Ok(_) => {
            route_data.insert(subnet, entry);
            Ok(())
        }
        Err(e) => {
            // `cleanup_route` returns `Ok` unconditionally on
            // best-effort cleanup. Swallowing it here would make the
            // outer call appear to succeed when the LPM install
            // actually failed, leaving dpd's in-memory route state
            // and the P4 tables out of sync. Free the resources but
            // propagate the original error.
            let _ = cleanup_route(switch, route_data, None, entry);
            Err(e)
        }
    }
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
fn replace_route_targets(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    targets: Vec<NextHop>,
) -> DpdResult<()> {
    // Remove the old entry from our in-core and on-chip indexes, but don't free
    // the data yet.
    debug!(switch.log, "replacing targets for {subnet} with: {targets:?}");
    let old_entry = route_data.remove(subnet);
    if let Some(ref old) = old_entry
        && let Err(e) = match subnet {
            IpNet::V4(v4) => table::route_ipv4::delete_route_index(switch, &v4),
            IpNet::V6(v6) => table::route_ipv6::delete_route_index(switch, &v6),
        }
    {
        debug!(
            switch.log,
            "failed to delete route index, restoring internal data"
        );
        route_data.insert(subnet, old.clone());
        return Err(e);
    }

    // If the new set of targets is empty, the route has been deleted and there
    // is no new data to insert in either table.
    if targets.is_empty() {
        if let Some(entry) = old_entry {
            return cleanup_route(switch, route_data, None, entry);
        }
        return Ok(());
    }

    // v6 prefixes drive TTL=1 handling per-prefix via the `skip_ttl` bit
    // on the index action. Mixed sets (some targets routing to the
    // service port, some not) would cause hash-selected non-service
    // targets to silently skip the dataplane TTL exception. Reject up
    // front so the bit's semantics stay coherent across all ECMP members.
    // Discriminate by `PortId::Internal`, which is the type-level CPU
    // port identity. The `asic_port_id` is an opaque dpd-internal
    // value whose mapping to the service port varies by build.
    if subnet.is_ipv6() {
        let any_service = targets
            .iter()
            .any(|t| matches!(t.route.port_id, PortId::Internal(_)));
        let all_service = targets
            .iter()
            .all(|t| matches!(t.route.port_id, PortId::Internal(_)));
        if any_service && !all_service {
            let _ = finalize_route(switch, route_data, subnet, old_entry);
            return Err(DpdError::InvalidRoute(format!(
                "ipv6 prefix {subnet}: ECMP targets cannot mix the \
                 service port with normal egress ports"
            )));
        }
    }

    // Allocate space in the p4 table for the new set of targets.
    let slots = targets.len() as u8;
    let is_ipv4 = subnet.is_ipv4();
    let mut new_entry = match match is_ipv4 {
        true => route_data.v4_freemap.alloc(slots),
        false => route_data.v6_freemap.alloc(slots),
    } {
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
            let _ = finalize_route(switch, route_data, subnet, old_entry);
            return Err(e);
        }
    };

    // Insert all the entries into the table
    let mut idx = new_entry.index;

    for target in targets {
        let is_service = matches!(target.route.port_id, PortId::Internal(_));
        if let Err(e) = match target.route.tgt_ip {
            IpAddr::V4(tgt_ip) => table::route_ipv4::add_route_target(
                switch,
                idx,
                target.asic_port_id,
                tgt_ip,
                target.route.vlan_id,
                is_service,
            ),
            IpAddr::V6(tgt_ip) => {
                if subnet.is_ipv4() {
                    table::route_ipv4::add_route_target_v6(
                        switch,
                        idx,
                        target.asic_port_id,
                        tgt_ip,
                        target.route.vlan_id,
                        is_service,
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
        } {
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

fn add_route_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: IpNet,
    route: Route,
    asic_port_id: u16,
) -> DpdResult<()> {
    info!(switch.log, "adding route {subnet} -> {:?}", route.tgt_ip);

    // Freemap sizing is established during RouteData construction so the
    // delete/recovery paths can safely run before the first add.
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
            Err(DpdError::Exists(format!("route {subnet} already exists")))
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

pub fn init(
    log: &slog::Logger,
    asic_hdl: &asic::Handle,
) -> DpdResult<RouteData> {
    RouteData::new(log, asic_hdl)
}
