// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Table operations for multicast NAT entries.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Switch, table::*};

use super::{Ipv4MatchKey, Ipv6MatchKey};

use aal::ActionParse;
use aal_macros::*;
use common::network::{MacAddr, NatTarget};
use slog::debug;

/// IPv4 Table for multicast NAT entries.
pub(crate) const IPV4_TABLE_NAME: &str =
    "pipe.Ingress.nat_ingress.ingress_ipv4_mcast";
/// IPv6 Table for multicast NAT entries.
pub(crate) const IPV6_TABLE_NAME: &str =
    "pipe.Ingress.nat_ingress.ingress_ipv6_mcast";

#[derive(ActionParse, Debug)]
enum Ipv4Action {
    #[action_xlate(name = "mcast_forward_ipv4_to")]
    Forward {
        target: Ipv6Addr,
        inner_mac: MacAddr,
        vni: u32,
    },
}

#[derive(ActionParse, Debug)]
enum Ipv6Action {
    #[action_xlate(name = "mcast_forward_ipv6_to")]
    Forward {
        target: Ipv6Addr,
        inner_mac: MacAddr,
        vni: u32,
    },
}

/// Add a NAT entry for IPv4 multicast traffic, keyed on `ip`.
pub(crate) fn add_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(ip);
    let action_key = Ipv4Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(
        s.log,
        "add ingress mcast entry {} -> {:?}", match_key, action_key
    );

    s.table_entry_add(TableType::NatIngressIpv4Mcast, &match_key, &action_key)
}

/// Update a NAT entry for IPv4 multicast traffic.
pub(crate) fn update_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(ip);
    let action_key = Ipv4Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(
        s.log,
        "update ingress mcast entry {} -> {:?}", match_key, action_key
    );

    s.table_entry_update(
        TableType::NatIngressIpv4Mcast,
        &match_key,
        &action_key,
    )
}

/// Delete a NAT entry for IPv4 multicast traffic, keyed on `ip`.
pub(crate) fn del_ipv4_entry(s: &Switch, ip: Ipv4Addr) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(ip);

    debug!(s.log, "delete ingress mcast entry {}", match_key);

    s.table_entry_del(TableType::NatIngressIpv4Mcast, &match_key)
}

/// Dump the IPv4 NAT table's contents.
pub(crate) fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, Ipv4Action>(TableType::NatIngressIpv4Mcast)
}

/// Fetch the IPv4 NAT table's counters.
pub(crate) fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4MatchKey>(force_sync, TableType::NatIngressIpv4Mcast)
}

/// Reset the Ipv4 NAT table.
pub(crate) fn reset_ipv4(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NatIngressIpv4Mcast)
}

/// Add a NAT entry for IPv6 multicast traffic, keyed on `ip`.
pub(crate) fn add_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(ip);
    let action_key = Ipv6Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(
        s.log,
        "add ingress mcast entry {} -> {:?}", match_key, action_key
    );

    s.table_entry_add(TableType::NatIngressIpv6Mcast, &match_key, &action_key)
}

/// Update a NAT entry for IPv6 multicast traffic.
pub(crate) fn update_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(ip);
    let action_key = Ipv6Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(
        s.log,
        "update ingress mcast entry {} -> {:?}", match_key, action_key
    );

    s.table_entry_update(
        TableType::NatIngressIpv6Mcast,
        &match_key,
        &action_key,
    )
}

/// Delete a NAT entry for IPv6 multicast traffic, keyed on `ip`.
pub(crate) fn del_ipv6_entry(s: &Switch, ip: Ipv6Addr) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(ip);

    debug!(s.log, "delete ingress mcast entry {}", match_key);

    s.table_entry_del(TableType::NatIngressIpv6Mcast, &match_key)
}

/// Dump the IPv6 NAT table's contents.
pub(crate) fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, Ipv6Action>(TableType::NatIngressIpv6Mcast)
}

/// Fetch the IPv6 NAT table's counters.
pub(crate) fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6MatchKey>(force_sync, TableType::NatIngressIpv6Mcast)
}

/// Reset the Ipv6 NAT table.
pub(crate) fn reset_ipv6(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NatIngressIpv6Mcast)
}
