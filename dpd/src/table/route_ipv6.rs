// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::net::Ipv6Addr;

use crate::table::*;
use crate::Switch;
use aal::ActionParse;
use aal::MatchParse;
use aal_macros::*;
use oxnet::Ipv6Net;
use slog::error;
use slog::info;

pub const INDEX_TABLE_NAME: &str =
    "pipe.Ingress.l3_router.Router6.lookup_idx.lookup";
pub const FORWARD_TABLE_NAME: &str =
    "pipe.Ingress.l3_router.Router6.lookup_idx.route";

// Used for indentifying entries in the index->route_data table
#[derive(MatchParse, Hash, Debug)]
struct IndexKey {
    #[match_xlate(type = "value")]
    idx: u16,
}

// Route entries stored in the index->route_data table
#[derive(ActionParse, Debug)]
enum RouteAction {
    #[action_xlate(name = "forward")]
    Forward { port: u16, nexthop: Ipv6Addr },
    #[action_xlate(name = "forward_vlan")]
    ForwardVlan {
        port: u16,
        nexthop: Ipv6Addr,
        vlan_id: u16,
    },
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
    let match_key = IndexKey { idx };
    let action_data = match vlan_id {
        None => RouteAction::Forward { port, nexthop },
        Some(vlan_id) => {
            common::network::validate_vlan(vlan_id)?;
            RouteAction::ForwardVlan {
                port,
                nexthop,
                vlan_id,
            }
        }
    };

    match s.table_entry_add(TableType::RouteFwdIpv6, &match_key, &action_data) {
        Ok(()) => {
            info!(s.log, "added ipv6 route entry";
                "index" => idx,
                "port" => port,
                "nexthop" => %nexthop,
                "vlan_id" => ?vlan_id);
            Ok(())
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

// Remove the route data at the given index
pub fn delete_route_target(s: &Switch, idx: u16) -> DpdResult<()> {
    let match_key = IndexKey { idx };

    s.table_entry_del(TableType::RouteFwdIpv6, &match_key)
        .map(|_| info!(s.log, "deleted ipv6 route entry"; "index" => %idx))
        .map_err(|e| {
            error!(s.log, "failed to delete ipv6 route entry";
                "index" => %idx,
                "error" => %e);
            e
        })
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
