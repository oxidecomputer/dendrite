// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Table operations for multicast NAT entries.
//!
//! The NatIngress tables (`ingress_ipv4_mcast`, `ingress_ipv6_mcast`) only
//! see traffic from customer ports due to the outermost `!hdr.geneve.isValid()`
//! check in the P4 pipeline. Decapsulated Geneve packets never reach these
//! tables, so each group only needs a single entry with an exact VLAN match.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Switch, table::*};

use super::{Ipv4VlanMatchKey, Ipv6VlanMatchKey};
use aal::ActionParse;
use aal_macros::*;
use common::network::{MacAddr, NatTarget};
use slog::debug;

#[derive(ActionParse, Debug)]
enum Ipv4Action {
    #[action_xlate(name = "mcast_forward_ipv4_to")]
    Forward { target: Ipv6Addr, inner_mac: MacAddr, vni: u32 },
}

#[derive(ActionParse, Debug)]
enum Ipv6Action {
    #[action_xlate(name = "mcast_forward_ipv6_to")]
    Forward { target: Ipv6Addr, inner_mac: MacAddr, vni: u32 },
}

/// Add a NAT entry for IPv4 multicast traffic.
///
/// A single entry is added with the exact VLAN match key. For groups without
/// a VLAN, the match key uses `None` for the VLAN field.
pub(crate) fn add_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    if let Some(vlan_id) = vlan_id {
        common::network::validate_vlan(vlan_id)?;
    }

    let match_key = Ipv4VlanMatchKey::new(ip, vlan_id);
    let action_key = Ipv4Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(s.log, "add ingress mcast entry {match_key} -> {action_key:?}");
    s.table_entry_add(TableType::NatIngressIpv4Mcast, &match_key, &action_key)
}

/// Update a NAT entry for IPv4 multicast traffic.
///
/// When VLAN changes, old entry is deleted and a new one added because
/// the VLAN is part of the match key and cannot be updated in place.
pub(crate) fn update_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    new_tgt: NatTarget,
    old_tgt: NatTarget,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
) -> DpdResult<()> {
    if old_vlan_id == new_vlan_id {
        let match_key = Ipv4VlanMatchKey::new(ip, old_vlan_id);
        let action_key = Ipv4Action::Forward {
            target: new_tgt.internal_ip,
            inner_mac: new_tgt.inner_mac,
            vni: new_tgt.vni.as_u32(),
        };

        debug!(
            s.log,
            "update ingress mcast entry {match_key} -> {action_key:?}"
        );
        return s.table_entry_update(
            TableType::NatIngressIpv4Mcast,
            &match_key,
            &action_key,
        );
    }

    del_ipv4_entry_with_tgt(s, ip, old_tgt, old_vlan_id)?;
    if let Err(e) = add_ipv4_entry(s, ip, new_tgt, new_vlan_id) {
        debug!(s.log, "add failed, restoring old NAT entries for {ip}");
        let _ = add_ipv4_entry(s, ip, old_tgt, old_vlan_id);
        return Err(e);
    }
    Ok(())
}

/// Delete a NAT entry for IPv4 multicast traffic.
pub(crate) fn del_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv4VlanMatchKey::new(ip, vlan_id);
    debug!(s.log, "delete ingress mcast entry {match_key}");
    s.table_entry_del(TableType::NatIngressIpv4Mcast, &match_key)
}

/// Delete a NAT entry for IPv4 multicast traffic with rollback support.
///
/// If deletion fails, restores the entry using the provided NAT target.
pub(crate) fn del_ipv4_entry_with_tgt(
    s: &Switch,
    ip: Ipv4Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv4VlanMatchKey::new(ip, vlan_id);
    debug!(s.log, "delete ingress mcast entry {match_key}");
    if let Err(e) =
        s.table_entry_del(TableType::NatIngressIpv4Mcast, &match_key)
    {
        debug!(s.log, "delete failed, restoring entry for {ip}");
        let action_key = Ipv4Action::Forward {
            target: tgt.internal_ip,
            inner_mac: tgt.inner_mac,
            vni: tgt.vni.as_u32(),
        };
        let _ = s.table_entry_add(
            TableType::NatIngressIpv4Mcast,
            &match_key,
            &action_key,
        );
        return Err(e);
    }
    Ok(())
}

/// Dump the IPv4 NAT table's contents.
pub(crate) fn ipv4_table_dump(
    s: &Switch,
    from_hardware: bool,
) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4VlanMatchKey, Ipv4Action>(
        TableType::NatIngressIpv4Mcast,
        from_hardware,
    )
}

/// Fetch the IPv4 NAT table's counters.
pub(crate) fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4VlanMatchKey>(
        force_sync,
        TableType::NatIngressIpv4Mcast,
    )
}

/// Reset the Ipv4 NAT table.
pub(crate) fn reset_ipv4(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NatIngressIpv4Mcast)
}

/// Add a NAT entry for IPv6 multicast traffic.
///
/// A single entry is added with the exact VLAN match key. For groups without
/// a VLAN, the match key uses `None` for the VLAN field.
pub(crate) fn add_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    if let Some(vlan_id) = vlan_id {
        common::network::validate_vlan(vlan_id)?;
    }

    let match_key = Ipv6VlanMatchKey::new(ip, vlan_id);
    let action_key = Ipv6Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(s.log, "add ingress mcast entry {match_key} -> {action_key:?}");
    s.table_entry_add(TableType::NatIngressIpv6Mcast, &match_key, &action_key)
}

/// Update a NAT entry for IPv6 multicast traffic.
///
/// When VLAN changes, old entry is deleted and a new one added because
/// the VLAN is part of the match key and cannot be updated in place.
pub(crate) fn update_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    new_tgt: NatTarget,
    old_tgt: NatTarget,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
) -> DpdResult<()> {
    if old_vlan_id == new_vlan_id {
        let match_key = Ipv6VlanMatchKey::new(ip, old_vlan_id);
        let action_key = Ipv6Action::Forward {
            target: new_tgt.internal_ip,
            inner_mac: new_tgt.inner_mac,
            vni: new_tgt.vni.as_u32(),
        };

        debug!(
            s.log,
            "update ingress mcast entry {match_key} -> {action_key:?}"
        );
        return s.table_entry_update(
            TableType::NatIngressIpv6Mcast,
            &match_key,
            &action_key,
        );
    }

    del_ipv6_entry_with_tgt(s, ip, old_tgt, old_vlan_id)?;
    if let Err(e) = add_ipv6_entry(s, ip, new_tgt, new_vlan_id) {
        debug!(s.log, "add failed, restoring old NAT entries for {ip}");
        let _ = add_ipv6_entry(s, ip, old_tgt, old_vlan_id);
        return Err(e);
    }
    Ok(())
}

/// Delete a NAT entry for IPv6 multicast traffic.
pub(crate) fn del_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv6VlanMatchKey::new(ip, vlan_id);
    debug!(s.log, "delete ingress mcast entry {match_key}");
    s.table_entry_del(TableType::NatIngressIpv6Mcast, &match_key)
}

/// Delete a NAT entry for IPv6 multicast traffic with rollback support.
///
/// If deletion fails, restores the entry using the provided NAT target.
pub(crate) fn del_ipv6_entry_with_tgt(
    s: &Switch,
    ip: Ipv6Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = Ipv6VlanMatchKey::new(ip, vlan_id);
    debug!(s.log, "delete ingress mcast entry {match_key}");
    if let Err(e) =
        s.table_entry_del(TableType::NatIngressIpv6Mcast, &match_key)
    {
        debug!(s.log, "delete failed, restoring entry for {ip}");
        let action_key = Ipv6Action::Forward {
            target: tgt.internal_ip,
            inner_mac: tgt.inner_mac,
            vni: tgt.vni.as_u32(),
        };
        let _ = s.table_entry_add(
            TableType::NatIngressIpv6Mcast,
            &match_key,
            &action_key,
        );
        return Err(e);
    }
    Ok(())
}

/// Dump the IPv6 NAT table's contents.
pub(crate) fn ipv6_table_dump(
    s: &Switch,
    from_hardware: bool,
) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6VlanMatchKey, Ipv6Action>(
        TableType::NatIngressIpv6Mcast,
        from_hardware,
    )
}

/// Fetch the IPv6 NAT table's counters.
pub(crate) fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6VlanMatchKey>(
        force_sync,
        TableType::NatIngressIpv6Mcast,
    )
}

/// Reset the Ipv6 NAT table.
pub(crate) fn reset_ipv6(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NatIngressIpv6Mcast)
}
