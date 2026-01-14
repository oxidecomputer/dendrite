// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Table operations for multicast routing entries (on Ingress to the switch).
//!
//! Route tables match only on destination address and select the egress action:
//! - `forward`: Forward without VLAN modification
//! - `forward_vlan(vid)`: Add VLAN tag on egress
//!
//! VLAN-based access control (preventing VLAN translation) is handled by NAT
//! ingress tables before encapsulation, not by route tables.

use std::net::{Ipv4Addr, Ipv6Addr};

use aal::ActionParse;
use aal_macros::*;
use omicron_common::address::UNDERLAY_MULTICAST_SUBNET;
use slog::debug;

use super::{Ipv4MatchKey, Ipv6MatchKey};
use crate::{Switch, table::*};

/// IPv4 Table for multicast routing entries.
pub(crate) const IPV4_TABLE_NAME: &str =
    "pipe.Ingress.l3_router.MulticastRouter4.tbl";
/// IPv6 Table for multicast routing entries.
pub(crate) const IPV6_TABLE_NAME: &str =
    "pipe.Ingress.l3_router.MulticastRouter6.tbl";

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

/// Add an IPv4 multicast route entry.
///
/// The action is selected based on VLAN configuration:
/// - No VLAN: `forward` (no VLAN modification on egress)
/// - With VLAN: `forward_vlan(vid)` (add VLAN tag on egress)
pub(crate) fn add_ipv4_entry(
    s: &Switch,
    route: Ipv4Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(route);
    let action = match vlan_id {
        None => Ipv4Action::Forward,
        Some(vid) => {
            common::network::validate_vlan(vid)?;
            Ipv4Action::ForwardVLAN { vlan_id: vid }
        }
    };

    debug!(s.log, "add multicast route entry {match_key} -> {action:?}");
    s.table_entry_add(TableType::RouteIpv4Mcast, &match_key, &action)
}

/// Update an IPv4 multicast route entry.
///
/// Updates the action when VLAN configuration changes. Since the match key
/// is just the destination address, this can be done in place.
pub(crate) fn update_ipv4_entry(
    s: &Switch,
    route: Ipv4Addr,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
) -> DpdResult<()> {
    if old_vlan_id == new_vlan_id {
        return Ok(());
    }

    let match_key = Ipv4MatchKey::new(route);
    let action = match new_vlan_id {
        None => Ipv4Action::Forward,
        Some(vid) => {
            common::network::validate_vlan(vid)?;
            Ipv4Action::ForwardVLAN { vlan_id: vid }
        }
    };

    debug!(
        s.log,
        "update multicast route entry {match_key} -> {action:?}"
    );
    s.table_entry_update(TableType::RouteIpv4Mcast, &match_key, &action)
}

/// Delete an IPv4 multicast route entry.
pub(crate) fn del_ipv4_entry(s: &Switch, route: Ipv4Addr) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(route);
    debug!(s.log, "delete multicast route entry {match_key}");
    s.table_entry_del(TableType::RouteIpv4Mcast, &match_key)
}

/// Dump the IPv4 multicast routing table's contents.
pub(crate) fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, Ipv4Action>(TableType::RouteIpv4Mcast)
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

/// Add an IPv6 multicast route entry.
///
/// The action is selected based on VLAN configuration:
/// - No VLAN: `forward` (no VLAN modification on egress)
/// - With VLAN: `forward_vlan(vid)` (add VLAN tag on egress)
///
/// Reserved underlay multicast subnet (ff04::/64) is internal to the rack
/// and always uses Forward without VLAN tagging, regardless of the vlan_id
/// parameter.
pub(crate) fn add_ipv6_entry(
    s: &Switch,
    route: Ipv6Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(route);

    // Reserved underlay multicast subnet (ff04::/64) is internal to the rack
    // and doesn't require VLAN tagging.
    let action: Ipv6Action = if UNDERLAY_MULTICAST_SUBNET.contains(route) {
        Ipv6Action::Forward
    } else {
        match vlan_id {
            None => Ipv6Action::Forward,
            Some(vid) => {
                common::network::validate_vlan(vid)?;
                Ipv6Action::ForwardVLAN { vlan_id: vid }
            }
        }
    };

    debug!(s.log, "add multicast route entry {match_key} -> {action:?}");
    s.table_entry_add(TableType::RouteIpv6Mcast, &match_key, &action)
}

/// Update an IPv6 multicast route entry.
///
/// Updates the action when VLAN configuration changes. Since the match key
/// is just the destination address, this can be done in place.
pub(crate) fn update_ipv6_entry(
    s: &Switch,
    route: Ipv6Addr,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
) -> DpdResult<()> {
    if old_vlan_id == new_vlan_id {
        return Ok(());
    }

    let match_key = Ipv6MatchKey::new(route);

    // Reserved underlay multicast subnet (ff04::/64) is internal to the rack
    // and doesn't require VLAN tagging.
    let action: Ipv6Action = if UNDERLAY_MULTICAST_SUBNET.contains(route) {
        Ipv6Action::Forward
    } else {
        match new_vlan_id {
            None => Ipv6Action::Forward,
            Some(vid) => {
                common::network::validate_vlan(vid)?;
                Ipv6Action::ForwardVLAN { vlan_id: vid }
            }
        }
    };

    debug!(
        s.log,
        "update multicast route entry {match_key} -> {action:?}"
    );
    s.table_entry_update(TableType::RouteIpv6Mcast, &match_key, &action)
}

/// Delete an IPv6 multicast route entry.
pub(crate) fn del_ipv6_entry(s: &Switch, route: Ipv6Addr) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(route);
    debug!(s.log, "delete multicast route entry {match_key}");
    s.table_entry_del(TableType::RouteIpv6Mcast, &match_key)
}

/// Dump the IPv6 multicast routing table's contents.
pub(crate) fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, Ipv6Action>(TableType::RouteIpv6Mcast)
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
