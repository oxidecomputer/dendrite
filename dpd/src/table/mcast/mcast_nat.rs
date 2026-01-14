// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Table operations for multicast NAT entries.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Switch, table::*};

use super::{Ipv4VlanMatchKey, Ipv6VlanMatchKey};
use aal::ActionParse;
use aal_macros::*;
use common::{nat::NatTarget, network::MacAddr};
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

/// Add NAT entries for IPv4 multicast traffic.
///
/// For groups with a VLAN, two entries are added:
/// 1. Untagged ingress match -> forward (for decapsulated Geneve packets)
/// 2. Correctly tagged ingress match -> forward (for already-tagged packets)
///
/// This allows both packet types to match, while packets with the wrong VLAN
/// will miss both entries and not be NAT encapsulated.
pub(crate) fn add_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let action_key = Ipv4Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    match vlan_id {
        None => {
            // Untagged only
            let match_key = Ipv4VlanMatchKey::new(ip, None);
            debug!(
                s.log,
                "add ingress mcast entry {} -> {:?}", match_key, action_key
            );
            s.table_entry_add(
                TableType::NatIngressIpv4Mcast,
                &match_key,
                &action_key,
            )
        }
        Some(vid) => {
            common::network::validate_vlan(vid)?;

            // Untagged entry
            let match_key_untagged = Ipv4VlanMatchKey::new(ip, None);
            debug!(
                s.log,
                "add ingress mcast entry {} -> {:?}",
                match_key_untagged,
                action_key
            );
            s.table_entry_add(
                TableType::NatIngressIpv4Mcast,
                &match_key_untagged,
                &action_key,
            )?;

            // Tagged entry
            let match_key_tagged = Ipv4VlanMatchKey::new(ip, Some(vid));
            debug!(
                s.log,
                "add ingress mcast entry {} -> {:?}",
                match_key_tagged,
                action_key
            );
            if let Err(e) = s.table_entry_add(
                TableType::NatIngressIpv4Mcast,
                &match_key_tagged,
                &action_key,
            ) {
                // Rollback untagged entry
                debug!(s.log, "rollback: removing untagged entry");
                let _ = s.table_entry_del(
                    TableType::NatIngressIpv4Mcast,
                    &match_key_untagged,
                );
                return Err(e);
            }
            Ok(())
        }
    }
}

/// Update NAT entries for IPv4 multicast traffic.
///
/// When VLAN changes, old entries are deleted and new ones added because
/// the VLAN is part of the match key and cannot be updated in place.
///
/// # Arguments
///
/// * `new_tgt` - NAT target for the new entries.
/// * `old_tgt` - NAT target for restoring entries on failure. Required when
///   VLAN changes since entries must be deleted and re-added.
pub(crate) fn update_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    new_tgt: NatTarget,
    old_tgt: NatTarget,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
) -> DpdResult<()> {
    if old_vlan_id == new_vlan_id {
        let action_key = Ipv4Action::Forward {
            target: new_tgt.internal_ip,
            inner_mac: new_tgt.inner_mac,
            vni: new_tgt.vni.as_u32(),
        };

        let match_key_untagged = Ipv4VlanMatchKey::new(ip, None);
        debug!(
            s.log,
            "update ingress mcast entry {} -> {:?}",
            match_key_untagged,
            action_key
        );
        s.table_entry_update(
            TableType::NatIngressIpv4Mcast,
            &match_key_untagged,
            &action_key,
        )?;

        if let Some(vid) = old_vlan_id {
            let match_key_tagged = Ipv4VlanMatchKey::new(ip, Some(vid));
            debug!(
                s.log,
                "update ingress mcast entry {} -> {:?}",
                match_key_tagged,
                action_key
            );
            s.table_entry_update(
                TableType::NatIngressIpv4Mcast,
                &match_key_tagged,
                &action_key,
            )?;
        }
        return Ok(());
    }

    del_ipv4_entry_with_tgt(s, ip, old_tgt, old_vlan_id)?;
    if let Err(e) = add_ipv4_entry(s, ip, new_tgt, new_vlan_id) {
        // Restore deleted entries with old target
        debug!(s.log, "add failed, restoring old NAT entries for {ip}");
        let _ = add_ipv4_entry(s, ip, old_tgt, old_vlan_id);
        return Err(e);
    }
    Ok(())
}

/// Delete NAT entries for IPv4 multicast traffic.
///
/// Deletes both entries for VLAN groups (see `add_ipv4_entry` for details).
/// This version does not support rollback on partial failure.
pub(crate) fn del_ipv4_entry(
    s: &Switch,
    ip: Ipv4Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    match vlan_id {
        None => {
            let match_key = Ipv4VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key);
            s.table_entry_del(TableType::NatIngressIpv4Mcast, &match_key)
        }
        Some(vid) => {
            // Untagged
            let match_key_untagged = Ipv4VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key_untagged);
            s.table_entry_del(
                TableType::NatIngressIpv4Mcast,
                &match_key_untagged,
            )?;

            // Tagged
            let match_key_tagged = Ipv4VlanMatchKey::new(ip, Some(vid));
            debug!(s.log, "delete ingress mcast entry {}", match_key_tagged);
            if let Err(e) = s.table_entry_del(
                TableType::NatIngressIpv4Mcast,
                &match_key_tagged,
            ) {
                // Can't rollback without original action
                debug!(s.log, "rollback not possible for untagged entry");
                return Err(e);
            }
            Ok(())
        }
    }
}

/// Delete NAT entries for IPv4 multicast traffic with rollback support.
///
/// Deletes both entries for VLAN groups. If the tagged entry deletion fails
/// after the untagged entry was deleted, attempts to restore the untagged
/// entry using the provided NAT target.
pub(crate) fn del_ipv4_entry_with_tgt(
    s: &Switch,
    ip: Ipv4Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    match vlan_id {
        None => {
            let match_key = Ipv4VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key);
            s.table_entry_del(TableType::NatIngressIpv4Mcast, &match_key)
        }
        Some(vid) => {
            // Delete untagged first
            let match_key_untagged = Ipv4VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key_untagged);
            s.table_entry_del(
                TableType::NatIngressIpv4Mcast,
                &match_key_untagged,
            )?;

            // Delete tagged
            let match_key_tagged = Ipv4VlanMatchKey::new(ip, Some(vid));
            debug!(s.log, "delete ingress mcast entry {}", match_key_tagged);
            if let Err(e) = s.table_entry_del(
                TableType::NatIngressIpv4Mcast,
                &match_key_tagged,
            ) {
                // Rollback: restore the untagged entry
                debug!(
                    s.log,
                    "tagged delete failed, restoring untagged entry for {ip}"
                );
                let action_key = Ipv4Action::Forward {
                    target: tgt.internal_ip,
                    inner_mac: tgt.inner_mac,
                    vni: tgt.vni.as_u32(),
                };
                let _ = s.table_entry_add(
                    TableType::NatIngressIpv4Mcast,
                    &match_key_untagged,
                    &action_key,
                );
                return Err(e);
            }
            Ok(())
        }
    }
}

/// Dump the IPv4 NAT table's contents.
pub(crate) fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4VlanMatchKey, Ipv4Action>(TableType::NatIngressIpv4Mcast)
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

/// Add NAT entries for IPv6 multicast traffic.
///
/// For groups with a VLAN, two entries are added:
/// 1. Untagged ingress match -> forward (for decapsulated Geneve packets)
/// 2. Correctly tagged ingress match -> forward (for already-tagged packets)
///
/// This allows both packet types to match, while packets with the wrong VLAN
/// will miss both entries and not be NAT encapsulated.
pub(crate) fn add_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let action_key = Ipv6Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    match vlan_id {
        None => {
            // Untagged only
            let match_key = Ipv6VlanMatchKey::new(ip, None);
            debug!(
                s.log,
                "add ingress mcast entry {} -> {:?}", match_key, action_key
            );
            s.table_entry_add(
                TableType::NatIngressIpv6Mcast,
                &match_key,
                &action_key,
            )
        }
        Some(vid) => {
            common::network::validate_vlan(vid)?;

            // Untagged entry
            let match_key_untagged = Ipv6VlanMatchKey::new(ip, None);
            debug!(
                s.log,
                "add ingress mcast entry {} -> {:?}",
                match_key_untagged,
                action_key
            );
            s.table_entry_add(
                TableType::NatIngressIpv6Mcast,
                &match_key_untagged,
                &action_key,
            )?;

            // Tagged entry
            let match_key_tagged = Ipv6VlanMatchKey::new(ip, Some(vid));
            debug!(
                s.log,
                "add ingress mcast entry {} -> {:?}",
                match_key_tagged,
                action_key
            );
            if let Err(e) = s.table_entry_add(
                TableType::NatIngressIpv6Mcast,
                &match_key_tagged,
                &action_key,
            ) {
                // Rollback untagged entry
                debug!(s.log, "rollback: removing untagged entry");
                let _ = s.table_entry_del(
                    TableType::NatIngressIpv6Mcast,
                    &match_key_untagged,
                );
                return Err(e);
            }
            Ok(())
        }
    }
}

/// Update NAT entries for IPv6 multicast traffic.
///
/// When VLAN changes, old entries are deleted and new ones added because
/// the VLAN is part of the match key and cannot be updated in place.
///
/// # Arguments
///
/// * `new_tgt` - NAT target for the new entries.
/// * `old_tgt` - NAT target for restoring entries on failure. Required when
///   VLAN changes since entries must be deleted and re-added.
pub(crate) fn update_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    new_tgt: NatTarget,
    old_tgt: NatTarget,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
) -> DpdResult<()> {
    if old_vlan_id == new_vlan_id {
        let action_key = Ipv6Action::Forward {
            target: new_tgt.internal_ip,
            inner_mac: new_tgt.inner_mac,
            vni: new_tgt.vni.as_u32(),
        };

        let match_key_untagged = Ipv6VlanMatchKey::new(ip, None);
        debug!(
            s.log,
            "update ingress mcast entry {} -> {:?}",
            match_key_untagged,
            action_key
        );
        s.table_entry_update(
            TableType::NatIngressIpv6Mcast,
            &match_key_untagged,
            &action_key,
        )?;

        if let Some(vid) = old_vlan_id {
            let match_key_tagged = Ipv6VlanMatchKey::new(ip, Some(vid));
            debug!(
                s.log,
                "update ingress mcast entry {} -> {:?}",
                match_key_tagged,
                action_key
            );
            s.table_entry_update(
                TableType::NatIngressIpv6Mcast,
                &match_key_tagged,
                &action_key,
            )?;
        }
        return Ok(());
    }

    del_ipv6_entry_with_tgt(s, ip, old_tgt, old_vlan_id)?;
    if let Err(e) = add_ipv6_entry(s, ip, new_tgt, new_vlan_id) {
        // Restore deleted entries with old target
        debug!(s.log, "add failed, restoring old NAT entries for {ip}");
        let _ = add_ipv6_entry(s, ip, old_tgt, old_vlan_id);
        return Err(e);
    }
    Ok(())
}

/// Delete NAT entries for IPv6 multicast traffic.
///
/// Deletes both entries for VLAN groups (see `add_ipv6_entry` for details).
/// This version does not support rollback on partial failure.
pub(crate) fn del_ipv6_entry(
    s: &Switch,
    ip: Ipv6Addr,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    match vlan_id {
        None => {
            let match_key = Ipv6VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key);
            s.table_entry_del(TableType::NatIngressIpv6Mcast, &match_key)
        }
        Some(vid) => {
            // Untagged
            let match_key_untagged = Ipv6VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key_untagged);
            s.table_entry_del(
                TableType::NatIngressIpv6Mcast,
                &match_key_untagged,
            )?;

            // Tagged
            let match_key_tagged = Ipv6VlanMatchKey::new(ip, Some(vid));
            debug!(s.log, "delete ingress mcast entry {}", match_key_tagged);
            if let Err(e) = s.table_entry_del(
                TableType::NatIngressIpv6Mcast,
                &match_key_tagged,
            ) {
                // Can't rollback without original action
                debug!(s.log, "rollback not possible for untagged entry");
                return Err(e);
            }
            Ok(())
        }
    }
}

/// Delete NAT entries for IPv6 multicast traffic with rollback support.
///
/// Deletes both entries for VLAN groups. If the tagged entry deletion fails
/// after the untagged entry was deleted, attempts to restore the untagged
/// entry using the provided NAT target.
pub(crate) fn del_ipv6_entry_with_tgt(
    s: &Switch,
    ip: Ipv6Addr,
    tgt: NatTarget,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    match vlan_id {
        None => {
            let match_key = Ipv6VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key);
            s.table_entry_del(TableType::NatIngressIpv6Mcast, &match_key)
        }
        Some(vid) => {
            // Delete untagged first
            let match_key_untagged = Ipv6VlanMatchKey::new(ip, None);
            debug!(s.log, "delete ingress mcast entry {}", match_key_untagged);
            s.table_entry_del(
                TableType::NatIngressIpv6Mcast,
                &match_key_untagged,
            )?;

            // Delete tagged
            let match_key_tagged = Ipv6VlanMatchKey::new(ip, Some(vid));
            debug!(s.log, "delete ingress mcast entry {}", match_key_tagged);
            if let Err(e) = s.table_entry_del(
                TableType::NatIngressIpv6Mcast,
                &match_key_tagged,
            ) {
                // Rollback: restore the untagged entry
                debug!(
                    s.log,
                    "tagged delete failed, restoring untagged entry for {ip}"
                );
                let action_key = Ipv6Action::Forward {
                    target: tgt.internal_ip,
                    inner_mac: tgt.inner_mac,
                    vni: tgt.vni.as_u32(),
                };
                let _ = s.table_entry_add(
                    TableType::NatIngressIpv6Mcast,
                    &match_key_untagged,
                    &action_key,
                );
                return Err(e);
            }
            Ok(())
        }
    }
}

/// Dump the IPv6 NAT table's contents.
pub(crate) fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6VlanMatchKey, Ipv6Action>(TableType::NatIngressIpv6Mcast)
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
