// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Table operations for multicast routing entries (on Ingress to the switch).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Switch, table::*};

use super::{Ipv4MatchKey, Ipv6MatchKey};

use aal::ActionParse;
use aal_macros::*;
use omicron_common::address::UNDERLAY_MULTICAST_SUBNET;
use slog::debug;

#[derive(ActionParse, Debug)]
enum Ipv4Action {
    #[action_xlate(name = "forward")]
    Forward,
    #[action_xlate(name = "forward_vlan")]
    ForwardVLAN { vlan_id: u16 },
}

#[derive(ActionParse, Debug)]
enum Ipv6Action {
    #[action_xlate(name = "forward")]
    Forward,
    #[action_xlate(name = "forward_vlan")]
    ForwardVLAN { vlan_id: u16 },
}

/// Add an IPv4 multicast route entry to the routing table, keyed on
/// `route`, with an optional `vlan_id`.
pub(crate) fn add_ipv4_entry(
    s: &Switch,
    route: Ipv4Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(route);

    let action_data = match vlan_id {
        None => Ipv4Action::Forward,
        Some(vlan_id) => {
            common::network::validate_vlan(vlan_id)?;
            Ipv4Action::ForwardVLAN { vlan_id }
        }
    };

    debug!(s.log, "add multicast route entry {} -> {:?}", route, action_data);

    s.table_entry_add(TableType::RouteIpv4Mcast, &match_key, &action_data)
}

/// Update an IPv4 multicast route entry in the routing table.
pub(crate) fn update_ipv4_entry(
    s: &Switch,
    route: Ipv4Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(route);
    let action_data = match vlan_id {
        None => Ipv4Action::Forward,
        Some(vlan_id) => {
            common::network::validate_vlan(vlan_id)?;
            Ipv4Action::ForwardVLAN { vlan_id }
        }
    };

    debug!(
        s.log,
        "update multicast route entry {} -> {:?}", route, action_data
    );

    s.table_entry_update(TableType::RouteIpv4Mcast, &match_key, &action_data)
}

/// Delete an IPv4 multicast route entry from table, keyed on
/// `route`.
pub(crate) fn del_ipv4_entry(s: &Switch, route: Ipv4Addr) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(route);

    debug!(s.log, "delete multicast route entry {}", match_key);

    s.table_entry_del(TableType::RouteIpv4Mcast, &match_key)
}

/// Dump the IPv4 multicast routing table's contents.
pub(crate) fn ipv4_table_dump(
    s: &Switch,
    from_hardware: bool,
) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, Ipv4Action>(
        TableType::RouteIpv4Mcast,
        from_hardware,
    )
}

/// Fetch the IPv4 multicast routing table's counters.
pub(crate) fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4MatchKey>(force_sync, TableType::RouteIpv4Mcast)
}

/// Reset the IPv4 multicast routing table.
pub(crate) fn reset_ipv4(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::RouteIpv4Mcast)
}

/// Add an IPv6 multicast route entry to the routing table, keyed on
/// `route`, with an optional `vlan_id`.
pub(crate) fn add_ipv6_entry(
    s: &Switch,
    route: Ipv6Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(route);

    // Reserved underlay multicast subnet (ff04::/64) is internal to the rack
    // and doesn't require VLAN tagging. Other admin-local addresses
    // (e.g., ff04:0:0:1::/64) may be used by customer external groups and
    // can receive VLAN tagging.
    let action_data: Ipv6Action = if UNDERLAY_MULTICAST_SUBNET.contains(route) {
        Ipv6Action::Forward
    } else {
        match vlan_id {
            None => Ipv6Action::Forward,
            Some(vlan_id) => {
                common::network::validate_vlan(vlan_id)?;
                Ipv6Action::ForwardVLAN { vlan_id }
            }
        }
    };

    debug!(s.log, "add multicast route entry {} -> {:?}", route, action_data);

    s.table_entry_add(TableType::RouteIpv6Mcast, &match_key, &action_data)
}

/// Update an IPv6 multicast route entry in the routing table.
pub(crate) fn update_ipv6_entry(
    s: &Switch,
    route: Ipv6Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(route);

    // Reserved underlay multicast subnet (ff04::/64) is internal to the rack
    // and doesn't require VLAN tagging. Other admin-local addresses
    // (e.g., ff04:0:0:1::/64) may be used by customer external groups and
    // can receive VLAN tagging.
    let action_data: Ipv6Action = if UNDERLAY_MULTICAST_SUBNET.contains(route) {
        Ipv6Action::Forward
    } else {
        match vlan_id {
            None => Ipv6Action::Forward,
            Some(vlan_id) => {
                common::network::validate_vlan(vlan_id)?;
                Ipv6Action::ForwardVLAN { vlan_id }
            }
        }
    };

    debug!(
        s.log,
        "update multicast route entry {} -> {:?}", route, action_data
    );

    s.table_entry_update(TableType::RouteIpv6Mcast, &match_key, &action_data)
}

/// Delete an IPv6 multicast entry from routing table, keyed on
/// `route`.
pub(crate) fn del_ipv6_entry(s: &Switch, route: Ipv6Addr) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(route);

    debug!(s.log, "delete multicast route entry {}", match_key);

    s.table_entry_del(TableType::RouteIpv6Mcast, &match_key)
}

/// Dump the IPv6 multicast routing table's contents.
pub(crate) fn ipv6_table_dump(
    s: &Switch,
    from_hardware: bool,
) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, Ipv6Action>(
        TableType::RouteIpv6Mcast,
        from_hardware,
    )
}

/// Fetch the IPv6 multicast routing table's counters.
pub(crate) fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6MatchKey>(force_sync, TableType::RouteIpv6Mcast)
}

/// Reset the IPv6 multicast routing table.
pub(crate) fn reset_ipv6(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::RouteIpv6Mcast)
}
