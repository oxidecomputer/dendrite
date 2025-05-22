// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::net::Ipv6Addr;

use slog::error;
use slog::info;

use crate::table::*;
use crate::Switch;
use aal::ActionParse;
use aal::MatchParse;
use aal_macros::*;
use oxnet::Ipv6Net;

pub const TABLE_NAME: &str = "pipe.Ingress.l3_router.Router6.lookup.tbl";

#[derive(MatchParse, Hash)]
struct MatchKey {
    #[match_xlate(type = "lpm")]
    dst_addr: Ipv6Net,
}

#[derive(ActionParse)]
enum Action {
    #[action_xlate(name = "forward")]
    Forward { port: u16, nexthop: Ipv6Addr },
    #[action_xlate(name = "forward_vlan")]
    ForwardVlan {
        port: u16,
        nexthop: Ipv6Addr,
        vlan_id: u16,
    },
}

pub fn add_route_entry(
    s: &Switch,
    cidr: &Ipv6Net,
    port: u16,
    nexthop: Ipv6Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = MatchKey { dst_addr: *cidr };
    let action_data = match vlan_id {
        None => Action::Forward { port, nexthop },
        Some(vlan_id) => {
            common::network::validate_vlan(vlan_id)?;
            Action::ForwardVlan {
                port,
                nexthop,
                vlan_id,
            }
        }
    };

    match s.table_entry_add(TableType::RouteIpv6, &match_key, &action_data) {
        Ok(()) => {
            info!(s.log, "added ipv6 route entry";
		    "route" => %cidr,
		    "port" => port,
		    "nexthop" => %nexthop,
		    "vlan_id" => ?vlan_id);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "failed to add ipv6 route entry";
		    "route" => %cidr,
		    "port" => port,
		    "nexthop" => %nexthop,
		    "error" => %e);
            Err(e)
        }
    }
}

pub fn delete_entry(s: &Switch, cidr: &Ipv6Net) -> DpdResult<()> {
    let match_key = MatchKey { dst_addr: *cidr };

    s.table_entry_del(TableType::RouteIpv6, &match_key)
        .map(|_| info!(s.log, "deleted ipv6 route entry"; "route" => %cidr))
        .map_err(|e| {
            error!(s.log, "failed to delete ipv6 route entry";
		"route" => %cidr,
		"error" => %e);
            e
        })
}

pub fn table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MatchKey, Action>(TableType::RouteIpv6)
}

pub fn counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MatchKey>(force_sync, TableType::RouteIpv6)
}

pub fn reset(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::RouteIpv6)
        .map(|_| info!(s.log, "cleared ipv6 route table"))
        .map_err(|e| {
            error!(s.log, "failed to clear ipv6 route table";
		"error" => %e);
            e
        })
}
