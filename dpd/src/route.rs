// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

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
use std::convert::TryInto;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Bound;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;

use crate::api_server::Route;
use crate::api_server::RouteTarget;
use crate::freemap;
use crate::link::LinkId;
use crate::types::{DpdError, DpdResult};
use crate::{table, Switch};
use common::ports::PortId;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};

// These are the largest numbers of targets supported for a single route
const MAX_TARGETS_IPV4: usize = 8;
const MAX_TARGETS_IPV6: usize = 1;

#[derive(Debug, Eq, PartialEq, Clone)]
struct NextHop<T> {
    asic_port_id: u16,
    route: T,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RouteEntry<T: Clone> {
    index: u16,
    slots: u8,
    targets: Vec<NextHop<T>>,
}

impl<T: Clone> RouteEntry<T> {
    pub fn targets(&self) -> Vec<T> {
        self.targets
            .iter()
            .map(|target| target.route.clone())
            .collect()
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
struct VlanId {
    // The switch port out which routed traffic is sent.
    port_id: PortId,
    // The link out which routed traffic is sent.
    link_id: LinkId,
    // Vlan tag - 0 for an untagged network
    vlan_id: u16,
}

impl VlanId {
    pub fn new(
        port_id: PortId,
        link_id: LinkId,
        vlan_id: u16,
    ) -> DpdResult<Self> {
        if vlan_id > 0 {
            common::network::validate_vlan(vlan_id)?;
        }
        Ok(VlanId {
            port_id,
            link_id,
            vlan_id,
        })
    }
}

impl TryFrom<&Ipv4Route> for VlanId {
    type Error = DpdError;
    fn try_from(route: &Ipv4Route) -> DpdResult<Self> {
        VlanId::new(route.port_id, route.link_id, route.vlan_id.unwrap_or(0))
    }
}

impl TryFrom<Ipv4Route> for VlanId {
    type Error = DpdError;
    fn try_from(route: Ipv4Route) -> DpdResult<Self> {
        (&route).try_into()
    }
}

impl TryFrom<&Ipv6Route> for VlanId {
    type Error = DpdError;
    fn try_from(route: &Ipv6Route) -> DpdResult<Self> {
        VlanId::new(route.port_id, route.link_id, route.vlan_id.unwrap_or(0))
    }
}

impl TryFrom<Ipv6Route> for VlanId {
    type Error = DpdError;
    fn try_from(route: Ipv6Route) -> DpdResult<Self> {
        (&route).try_into()
    }
}

pub struct RouteData {
    pub(crate) v4: BTreeMap<Ipv4Net, RouteEntry<Ipv4Route>>,
    pub(crate) v6: BTreeMap<Ipv6Net, Vec<Ipv6Route>>,
    v4_freemap: freemap::FreeMap,
    v6_freemap: freemap::FreeMap,
}

/// A route for an IPv4 subnet.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Route {
    // The client-specific tag for this route.
    pub(crate) tag: String,
    // The switch port out which routed traffic is sent.
    pub(crate) port_id: PortId,
    // The link out which routed traffic is sent.
    pub(crate) link_id: LinkId,
    // Route traffic matching the subnet via this IP.
    pub(crate) tgt_ip: Ipv4Addr,
    // Tag traffic on this route with this vlan ID.
    pub(crate) vlan_id: Option<u16>,
}

// We implement PartialEq for Ipv4Route because we want to exclude the tag and
// vlan_id from any comparisons.  We do this because the tag is a comment
// identifying the originator rather than a semantically meaningful part of the
// route.  The vlan_id is used to modify the traffic on a specific route, rather
// then being part of the route itself.
impl PartialEq for Ipv4Route {
    fn eq(&self, other: &Self) -> bool {
        self.port_id == other.port_id
            && self.link_id == other.link_id
            && self.tgt_ip == other.tgt_ip
    }
}

// See the comment above PartialEq to understand why we implement Hash rather
// then Deriving it.
impl std::hash::Hash for Ipv4Route {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.port_id.hash(state);
        self.link_id.hash(state);
        self.tgt_ip.hash(state);
    }
}

impl fmt::Display for Ipv4Route {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "port: {} link: {} gw: {}  vlan: {:?}",
            self.port_id, self.link_id, self.tgt_ip, self.vlan_id
        )?;
        Ok(())
    }
}

impl From<&Ipv4Route> for RouteTarget {
    fn from(route: &Ipv4Route) -> RouteTarget {
        RouteTarget::V4(route.clone())
    }
}

impl From<Ipv4Route> for RouteTarget {
    fn from(route: Ipv4Route) -> RouteTarget {
        RouteTarget::V4(route)
    }
}

/// A route for an IPv6 subnet.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Route {
    // The client-specific tag for this route.
    pub(crate) tag: String,
    // The switch port out which routed traffic is sent.
    pub(crate) port_id: PortId,
    // The link out which routed traffic is sent.
    pub(crate) link_id: LinkId,
    // Route traffic matching the subnet to this IP.
    pub(crate) tgt_ip: Ipv6Addr,
    // Tag traffic on this route with this vlan ID.
    pub(crate) vlan_id: Option<u16>,
}

// See the comment above the PartialEq for IPv4Route
impl PartialEq for Ipv6Route {
    fn eq(&self, other: &Self) -> bool {
        self.port_id == other.port_id
            && self.link_id == other.link_id
            && self.tgt_ip == other.tgt_ip
    }
}

// See the comment above PartialEq for IPv4Route
impl std::hash::Hash for Ipv6Route {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.port_id.hash(state);
        self.link_id.hash(state);
        self.tgt_ip.hash(state);
    }
}

impl fmt::Display for Ipv6Route {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "port: {} link: {} gw: {}  vlan: {:?}",
            self.port_id, self.link_id, self.tgt_ip, self.vlan_id
        )?;
        Ok(())
    }
}

impl From<&Ipv6Route> for RouteTarget {
    fn from(route: &Ipv6Route) -> RouteTarget {
        RouteTarget::V6(route.clone())
    }
}

impl From<Ipv6Route> for RouteTarget {
    fn from(route: Ipv6Route) -> RouteTarget {
        RouteTarget::V6(route)
    }
}

// Remove all the data for a given route from both the route_data and
// route_index tables.
//
// Because this may be called from the error-recovery path of a failed add-target
// operation, not all of the target slots may yet be populated.  Thus we require
// the caller to explicitly indicate which slots need to be cleared.
fn cleanup_route_ipv4(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Option<Ipv4Net>,
    entry: RouteEntry<Ipv4Route>,
) -> DpdResult<()> {
    // Remove the subnet -> index mapping first, so nobody can reach the
    // entries we delete below.
    if let Some(subnet) = subnet {
        table::route_ipv4::delete_route_index(switch, &subnet)?;
    }

    let all_clear = entry
        .targets
        .iter()
        .enumerate()
        .map(|(idx, _hop)| {
            table::route_ipv4::delete_route_target(
                switch,
                entry.index + idx as u16,
            )
        })
        .all(|rval| rval.is_ok());

    // If all of the entries were removed, we can release the table space back
    // to the FreeMap.  If something went wrong, and there's really no reason it
    // should, then this table space will be leaked.
    if all_clear {
        route_data.v4_freemap.free(entry.index, entry.slots as u16);
    }
    Ok(())
}

// Attempt to add the new index to the route_index table.
//
// If that fails, free all resources associated with the new set of targets and
fn finalize_route_ipv4(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Ipv4Net,
    entry: Option<RouteEntry<Ipv4Route>>,
) -> DpdResult<()> {
    if let Some(entry) = entry {
        match table::route_ipv4::add_route_index(
            switch,
            &subnet,
            entry.index,
            entry.slots,
        ) {
            Ok(_) => {
                route_data.v4.insert(subnet, entry);
                Ok(())
            }
            Err(_) => cleanup_route_ipv4(switch, route_data, None, entry),
        }
    } else {
        Ok(())
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
fn replace_route_targets_ipv4(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Ipv4Net,
    targets: Vec<NextHop<Ipv4Route>>,
) -> DpdResult<()> {
    // Remove the old entry from our in-core and on-chip indexes, but don't free
    // the data yet.
    let old_entry = route_data.v4.remove(&subnet);
    if let Some(ref old) = old_entry {
        if let Err(e) = table::route_ipv4::delete_route_index(switch, &subnet) {
            route_data.v4.insert(subnet, old.clone());
            return Err(e);
        }
    }

    // If the new set of targets is empty, the route has been deleted and there
    // is no new data to insert in either table.
    if targets.is_empty() {
        if let Some(entry) = old_entry {
            return cleanup_route_ipv4(switch, route_data, None, entry);
        }
        return Ok(());
    }

    // Allocate space in the p4 table for the new set of targets.
    let slots = targets.len() as u8;
    let mut new_entry = match route_data.v4_freemap.alloc(slots) {
        Ok(index) => RouteEntry::<Ipv4Route> {
            index,
            slots,
            targets: Vec::with_capacity(slots as usize),
        },
        Err(e) => {
            let _ = finalize_route_ipv4(switch, route_data, subnet, old_entry);
            return Err(e);
        }
    };

    // Insert all the entries into the table
    let mut idx = new_entry.index;
    for target in targets {
        if let Err(e) = table::route_ipv4::add_route_target(
            switch,
            idx,
            target.asic_port_id,
            target.route.tgt_ip,
            target.route.vlan_id,
        ) {
            let _ = cleanup_route_ipv4(switch, route_data, None, new_entry);
            let _ = finalize_route_ipv4(switch, route_data, subnet, old_entry);
            return Err(e);
        }
        idx += 1;
        new_entry.targets.push(target);
    }

    // Insert the new subnet->index mapping
    match finalize_route_ipv4(
        switch,
        route_data,
        subnet,
        Some(new_entry.clone()),
    ) {
        Ok(()) => {
            // Finally free all of the table space for the original set of
            // targets
            if let Some(entry) = old_entry {
                let _ = cleanup_route_ipv4(switch, route_data, None, entry);
            }
            Ok(())
        }
        Err(e) => {
            // We failed to point at the new set of targets.  Free all of the
            // new data and update the route_index table to point at the
            // original set of targets.
            let _ = cleanup_route_ipv4(switch, route_data, None, new_entry);
            let _ = finalize_route_ipv4(switch, route_data, subnet, old_entry);
            Err(e)
        }
    }
}

pub fn add_route_ipv4_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Ipv4Net,
    route: Ipv4Route,
    asic_port_id: u16,
) -> DpdResult<()> {
    info!(switch.log, "adding route {subnet} -> {:?}", route.tgt_ip);

    // Verify that the slot freelist has been initialized
    route_data
        .v4_freemap
        .maybe_init(switch.table_size(table::TableType::RouteFwdIpv4)? as u16);

    // Get the old set of targets that we'll be adding to
    let mut targets = route_data
        .v4
        .get(&subnet)
        .map_or(Vec::new(), |e| e.targets.clone());
    // Add the new target
    targets.push(NextHop::<Ipv4Route> {
        asic_port_id,
        route,
    });

    if targets.len() > MAX_TARGETS_IPV4 {
        Err(DpdError::InvalidRoute(format!(
            "exceeded limit of {MAX_TARGETS_IPV4} targets for one route"
        )))
    } else {
        replace_route_targets_ipv4(switch, route_data, subnet, targets)
    }
}

// Add a new multi-path target to an exiting route, or create a new route with
// just this single target.
pub async fn add_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
    route: Ipv4Route,
) -> DpdResult<()> {
    let asic_port_id =
        switch.link_asic_port_id(route.port_id, route.link_id)?;

    let mut route_data = switch.routes.lock().await;

    // Adding the same route multiple times is a harmless no-op
    if let Some(entry) = route_data.v4.get(&subnet) {
        if entry.targets.iter().any(|hop| hop.route == route) {
            return Ok(());
        }
    }
    add_route_ipv4_locked(switch, &mut route_data, subnet, route, asic_port_id)
}

// Create a new single-path route.
//
// If there is already an existing route, this call will replace it (if the
// replace flag is set) or return an Exists() error (if the replace flag is not
// set).  If there is no existing route, the replace flag is not examined.  That
// is, it is not an error to "replace" a non- existent route.
pub async fn set_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
    route: Ipv4Route,
    replace: bool,
) -> DpdResult<()> {
    let asic_port_id =
        switch.link_asic_port_id(route.port_id, route.link_id)?;

    let mut route_data = switch.routes.lock().await;
    if let Some(entry) = route_data.v4.get(&subnet) {
        // setting the same route multiple times is a harmless no-op
        if entry.targets.len() == 1 && entry.targets[0].route == route {
            Ok(())
        } else if !replace {
            Err(DpdError::Exists("route {cidr} already exists".into()))
        } else {
            info!(switch.log, "replacing subnet {subnet}");
            let target = vec![NextHop::<Ipv4Route> {
                asic_port_id,
                route,
            }];
            replace_route_targets_ipv4(switch, &mut route_data, subnet, target)
        }
    } else {
        add_route_ipv4_locked(
            switch,
            &mut route_data,
            subnet,
            route,
            asic_port_id,
        )
    }
}

// Remove a single target from a route.
//
// If this route has multiple targets, this call will remove at most one of
// them.  If the route only has a single target, this call will remove the
// entire route.
pub(crate) fn delete_route_target_ipv4_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Ipv4Net,
    route: Ipv4Route,
) -> DpdResult<()> {
    info!(switch.log, "deleting route {subnet} -> {}", route.tgt_ip);

    // Get set of targets remaining after we remove this entry
    let entry = route_data
        .v4
        .get(&subnet)
        .ok_or(DpdError::Missing("no such route".into()))?;
    let targets: Vec<NextHop<Ipv4Route>> = entry
        .targets
        .iter()
        .filter(|t| t.route != route)
        .cloned()
        .collect();
    if targets.len() == entry.targets.len() {
        Err(DpdError::Missing("no such route".into()))
    } else {
        replace_route_targets_ipv4(switch, route_data, subnet, targets)
    }
}

pub fn add_route_ipv6_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Ipv6Net,
    route: Ipv6Route,
    asic_port_id: u16,
) -> DpdResult<()> {
    let targets = route_data
        .v6
        .entry(subnet)
        .or_insert_with_key(|_| Vec::new());

    if targets.iter().any(|hop| *hop == route) {
        return Ok(());
    }

    if targets.len() > MAX_TARGETS_IPV6 {
        return Err(DpdError::InvalidRoute(format!(
            "exceeded limit of {MAX_TARGETS_IPV6} target(s) for one route"
        )));
    }

    // If we can add the new entry to the ASIC table, we also add the target to
    // the route's target vector.  If the add fails, and the vector was created
    // just for this new target, we remove the route from the RouteData map.
    match table::route_ipv6::add_route_entry(
        switch,
        &subnet,
        asic_port_id,
        route.tgt_ip,
        route.vlan_id,
    ) {
        Ok(_) => {
            targets.push(route.clone());
            Ok(())
        }
        Err(e) => {
            if targets.is_empty() {
                route_data.v6.remove(&subnet);
            }
            Err(e)
        }
    }
}

pub async fn add_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
    route: Ipv6Route,
) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;
    let asic_port_id =
        switch.link_asic_port_id(route.port_id, route.link_id)?;

    add_route_ipv6_locked(switch, &mut route_data, subnet, route, asic_port_id)
}

pub async fn set_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
    route: Ipv6Route,
    replace: bool,
) -> DpdResult<()> {
    let asic_port_id =
        switch.link_asic_port_id(route.port_id, route.link_id)?;

    let mut route_data = switch.routes.lock().await;
    if let Some(targets) = route_data.v6.get(&subnet) {
        // setting the same route multiple times is a harmless no-op
        if targets.len() == 1 && targets[0] == route {
            return Ok(());
        }

        if !replace {
            return Err(DpdError::Exists("route {cidr} already exists".into()));
        }

        table::route_ipv6::delete_entry(switch, &subnet)?;
        route_data.v6.remove(&subnet);
    }

    add_route_ipv6_locked(switch, &mut route_data, subnet, route, asic_port_id)
}

pub async fn get_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
) -> DpdResult<Vec<Ipv4Route>> {
    let route_data = switch.routes.lock().await;
    match route_data.v4.get(&subnet) {
        None => Err(DpdError::Missing("no such route".into())),
        Some(entry) => {
            Ok(entry.targets.iter().map(|t| t.route.clone()).collect())
        }
    }
}

pub async fn get_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
) -> DpdResult<Vec<Ipv6Route>> {
    let route_data = switch.routes.lock().await;

    match route_data.v6.get(&subnet) {
        None => Err(DpdError::Missing("no such route".into())),
        Some(entry) => Ok(entry.clone()),
    }
}

pub fn delete_route_ipv4_locked(
    switch: &Switch,
    route_data: &mut RouteData,
    subnet: Ipv4Net,
) -> DpdResult<()> {
    // Get set of targets remaining after we remove this entry
    let entry = route_data
        .v4
        .remove(&subnet)
        .ok_or(DpdError::Missing("no such route".into()))?;
    cleanup_route_ipv4(switch, route_data, Some(subnet), entry)
}

// Delete a route and all of its targets
pub async fn delete_route_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;

    delete_route_ipv4_locked(switch, &mut route_data, subnet)
}

// Delete a specific target from a route, removing the route if this is the last
// target.
pub async fn delete_route_target_ipv4(
    switch: &Switch,
    subnet: Ipv4Net,
    port_id: PortId,
    link_id: LinkId,
    tgt_ip: Ipv4Addr,
) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;

    let route = Ipv4Route {
        tag: String::new(),
        port_id,
        link_id,
        tgt_ip,
        vlan_id: None,
    };

    delete_route_target_ipv4_locked(switch, &mut route_data, subnet, route)
}

pub async fn delete_route_ipv6(
    switch: &Switch,
    subnet: Ipv6Net,
) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;

    match route_data.v6.remove(&subnet) {
        Some(routes) => {
            if routes.len() > 1 {
                warn!(switch.log, "found IPv6 route with too many targets. {subnet} -> {routes:?}");
            }
            table::route_ipv6::delete_entry(switch, &subnet)
        }
        None => Err(DpdError::Missing("no such route".into())),
    }
}

pub async fn get_range_ipv4(
    switch: &Switch,
    last: Option<Ipv4Net>,
    max: u32,
) -> DpdResult<Vec<Route>> {
    let route_data = switch.routes.lock().await;
    let lower = match last {
        None => Bound::Unbounded,
        Some(last) => Bound::Excluded(last),
    };

    let mut routes = Vec::new();
    for (subnet, entry) in route_data
        .v4
        .range((lower, Bound::Unbounded))
        .take(usize::try_from(max).expect("invalid usize"))
    {
        routes.push(Route {
            cidr: IpNet::V4(*subnet),
            targets: entry
                .targets()
                .iter()
                .map(|r| RouteTarget::V4(r.clone()))
                .collect(),
        })
    }

    Ok(routes)
}

pub async fn get_range_ipv6(
    switch: &Switch,
    last: Option<Ipv6Net>,
    max: u32,
) -> DpdResult<Vec<Route>> {
    let route_data = switch.routes.lock().await;

    let lower = match last {
        None => Bound::Unbounded,
        Some(last) => Bound::Excluded(last),
    };

    let mut routes = Vec::new();
    for (subnet, target_list) in route_data
        .v6
        .range((lower, Bound::Unbounded))
        .take(usize::try_from(max).expect("invalid usize"))
    {
        for target in target_list {
            routes.push(Route {
                cidr: IpNet::V6(*subnet),
                targets: vec![RouteTarget::V6(target.clone())],
            })
        }
    }

    Ok(routes)
}

pub async fn reset_ipv4_tag(switch: &Switch, tag: &str) {
    let mut route_data = switch.routes.lock().await;

    // Iterate over all the routes, building a list of targets for each route
    // with the appropriately tagged entries removed.  If that list of targets
    // is different than the original, then mark this route for updating.  We
    // perform any updates after scanning everything to avoid updating the
    // route_data BTreeMap while we're iterating over it.
    let mut to_replace = BTreeMap::new();
    for (subnet, entry) in &route_data.v4 {
        let new_targets: Vec<NextHop<Ipv4Route>> = entry
            .targets
            .iter()
            .filter(|t| t.route.tag != tag)
            .cloned()
            .collect();
        debug!(
            switch.log,
            "original subnets for {subnet}: {:?}",
            entry.targets()
        );
        if new_targets.len() != entry.targets.len() {
            debug!(switch.log, "new subnets for {subnet}: {new_targets:?}");
            to_replace.insert(*subnet, new_targets);
        }
    }

    for (subnet, targets) in to_replace {
        let _ = replace_route_targets_ipv4(
            switch,
            &mut route_data,
            subnet,
            targets,
        );
    }
}

pub async fn reset_ipv6_tag(switch: &Switch, tag: &str) {
    let mut route_data = switch.routes.lock().await;

    let mut vlans: Vec<VlanId> = Vec::new();
    // For each route, remove all of the targets associated with this tag
    for targets in route_data.v6.values_mut() {
        let mut target_delete: Vec<usize> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.tag == tag)
            .map(|(idx, _)| idx)
            .collect();
        while let Some(idx) = target_delete.pop() {
            vlans.push(targets.remove(idx).try_into().unwrap());

            // XXX: When we have multipath support at the table level, we
            // will remove the (route, tgt_ip) tuple entry here.  For now, we
            // assume there is only a single target, so the entry gets cleaned
            // up in the delete loop below.
        }
    }

    // Prepare to delete all of the routes that have no remaining targets
    let delete: Vec<Ipv6Net> = route_data
        .v6
        .iter()
        .filter(|(_, targets)| targets.is_empty())
        .map(|(route, _)| *route)
        .collect();

    for subnet in delete {
        let _ = route_data.v6.remove(&subnet);
        // XXX: this should be done automatically by the table code
        if let Err(e) = table::route_ipv6::delete_entry(switch, &subnet) {
            error!(switch.log, "failed to remove route: {e:?}";
			"subnet" => subnet.to_string());
        }
    }
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
