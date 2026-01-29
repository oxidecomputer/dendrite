// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::convert::TryInto;
use std::net::Ipv6Addr;

use crate::Switch;
use crate::table::SERVICE_PORT;
use crate::table::*;
use aal::ActionParse;
use aal::MatchParse;
use aal_macros::*;
use oxnet::Ipv6Net;
use slog::error;
use slog::info;

pub const INDEX_TABLE_NAME: &str =
    "pipe.Ingress.l3_router.router6.lookup_idx.lookup";
pub const FORWARD_TABLE_NAME: &str =
    "pipe.Ingress.l3_router.router6.lookup_idx.route";

// Used for identifying entries in the index->route_data table
#[derive(MatchParse, Hash, Debug)]
struct IndexKey {
    #[match_xlate(type = "value")]
    idx: u16,
    #[match_xlate(name = "route_ttl_is_1", type = "value")]
    route_ttl_is_1: bool,
}

// Route entries stored in the index->route_data table
#[derive(ActionParse, Debug, Clone, Copy)]
enum RouteAction {
    #[action_xlate(name = "forward")]
    Forward { port: u16, nexthop: Ipv6Addr },
    #[action_xlate(name = "forward_vlan")]
    ForwardVlan { port: u16, nexthop: Ipv6Addr, vlan_id: u16 },
    #[action_xlate(name = "ttl_exceeded")]
    TtlExceeded,
}

// Used to identify entries in the route->index table
#[derive(MatchParse, Hash, Debug)]
struct RouteKey {
    #[match_xlate(type = "lpm")]
    dst_addr: Ipv6Net,
}

// Indexes stored in the route->index table
#[derive(ActionParse, Debug)]
enum IndexAction {
    #[action_xlate(name = "index")]
    Index { idx: u16, slots: u8 },
}

/// Add an entry to the route->index table
pub fn add_route_index(
    s: &Switch,
    cidr: &Ipv6Net,
    idx: u16,
    slots: u8,
) -> DpdResult<()> {
    let action_data = IndexAction::Index { idx, slots };

    let match_key = RouteKey { dst_addr: *cidr };

    match s.table_entry_add(TableType::RouteIdxIpv6, &match_key, &action_data) {
        Ok(()) => {
            info!(s.log, "added ipv6 route index";
                "route" => %cidr,
                "index" => %idx,
                "slots" => %slots);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "failed to add ipv6 route index";
                "route" => %cidr,
                "index" => %idx,
                "slots" => %slots,
                "error" => %e);
            Err(e)
        }
    }
}

/// Remove an entry from the route->index table
pub fn delete_route_index(s: &Switch, cidr: &Ipv6Net) -> DpdResult<()> {
    let match_key = RouteKey { dst_addr: *cidr };

    s.table_entry_del(TableType::RouteIdxIpv6, &match_key)
        .map(|_| info!(s.log, "deleted ipv6 index"; "route" => %cidr))
        .map_err(|e| {
            error!(s.log, "failed to delete ipv6 index";
                "route" => %cidr,
                "error" => %e);
            e
        })
}

// Add a target into the route_data table at the given index
pub fn add_route_target(
    s: &Switch,
    idx: u16,
    port: u16,
    nexthop: Ipv6Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = IndexKey { idx, route_ttl_is_1: false };
    let action_data = match vlan_id {
        None => RouteAction::Forward { port, nexthop },
        Some(vlan_id) => {
            common::network::validate_vlan(vlan_id)?;
            RouteAction::ForwardVlan { port, nexthop, vlan_id }
        }
    };

    match s.table_entry_add(TableType::RouteFwdIpv6, &match_key, &action_data) {
        Ok(()) => {
            info!(s.log, "added ipv6 route entry";
                "index" => idx,
                "port" => port,
                "nexthop" => %nexthop,
                "vlan_id" => ?vlan_id);
            add_ttl_entry(s, idx, &match_key, &action_data, port)
        }
        Err(e) => {
            error!(s.log, "failed to add ipv6 route entry";
                "index" => idx,
                "port" => port,
                "nexthop" => %nexthop,
                "error" => %e);
            Err(e)
        }
    }
}

// Add the TTL==1 entry for a route target.
//
// For service port routes, we forward even when TTL==1 (bypassing ICMP TTL exceeded).
// For all other routes, we trigger TTL exceeded handling.
// This matches the P4 behavior: `ttl == 1 && !IS_SERVICE(fwd.port)`.
fn add_ttl_entry(
    s: &Switch,
    idx: u16,
    forward_key: &IndexKey,
    forward_action: &RouteAction,
    port: u16,
) -> DpdResult<()> {
    let ttl_match_key = IndexKey { idx, route_ttl_is_1: true };

    let ttl_action = if port == SERVICE_PORT {
        *forward_action
    } else {
        RouteAction::TtlExceeded
    };

    if let Err(e) =
        s.table_entry_add(TableType::RouteFwdIpv6, &ttl_match_key, &ttl_action)
    {
        error!(s.log, "failed to add ipv6 ttl entry";
            "index" => idx,
            "error" => %e);
        if let Err(cleanup_err) =
            s.table_entry_del(TableType::RouteFwdIpv6, forward_key)
        {
            error!(s.log, "failed to clean up ipv6 route entry";
                "index" => idx,
                "error" => %cleanup_err);
        }
        return Err(e);
    }
    Ok(())
}

// Remove the route data at the given index (both forward and ttl_exceeded entries).
// The main entry (route_ttl_is_1=false) must succeed. The TTL==1 companion entry
// may not exist for routes created before the compound key change, so we only
// log a warning for TTL==1 entry failures instead of returning an error.
pub fn delete_route_target(s: &Switch, idx: u16) -> DpdResult<()> {
    // Delete the main entry first (route_ttl_is_1=false).
    let main_key = IndexKey { idx, route_ttl_is_1: false };
    if let Err(e) = s.table_entry_del(TableType::RouteFwdIpv6, &main_key) {
        error!(s.log, "failed to delete ipv6 route entry";
            "index" => %idx,
            "error" => %e);
        return Err(e);
    }
    info!(s.log, "deleted ipv6 route entry"; "index" => %idx);

    // Delete the TTL==1 companion entry.
    let ttl_key = IndexKey { idx, route_ttl_is_1: true };
    if let Err(e) = s.table_entry_del(TableType::RouteFwdIpv6, &ttl_key) {
        error!(s.log, "failed to delete ipv6 route ttl==1 entry";
            "index" => %idx,
            "error" => %e);
        return Err(e);
    }
    info!(s.log, "deleted ipv6 route ttl==1 entry"; "index" => %idx);

    Ok(())
}

pub fn forward_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<IndexKey, RouteAction>(TableType::RouteFwdIpv6)
}

pub fn index_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<RouteKey, IndexAction>(TableType::RouteIdxIpv6)
}

pub fn forward_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<IndexKey>(force_sync, TableType::RouteFwdIpv6)
}

pub fn index_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<RouteKey>(force_sync, TableType::RouteIdxIpv6)
}

pub fn reset(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::RouteIdxIpv6)
        .map(|_| info!(s.log, "reset ipv6 route-index table"))
        .map_err(|e| {
            error!(s.log, "failed to clear ipv6 route-index table";
                "error" => %e);
            e
        })?;
    s.table_clear(TableType::RouteFwdIpv6)
        .map(|_| info!(s.log, "reset ipv6 route-data table"))
        .map_err(|e| {
            error!(s.log, "failed to clear ipv6 route-data table";
                "error" => %e);
            e
        })
}
