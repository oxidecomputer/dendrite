// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Table operations for multicast replication information.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{mcast::MulticastGroupId, table::*, Switch};

use super::{Ipv4MatchKey, Ipv6MatchKey};

use aal::ActionParse;
use aal_macros::*;
use slog::debug;

/// IPv4 Table for multicast replication entries and group membership.
pub(crate) const IPV4_TABLE_NAME: &str =
    "pipe.Ingress.mcast_ingress.mcast_replication_ipv4";
/// IPv6 Table for multicast replication entries and group membership.
pub(crate) const IPV6_TABLE_NAME: &str =
    "pipe.Ingress.mcast_ingress.mcast_replication_ipv6";

#[derive(ActionParse, Debug)]
enum Ipv4Action {
    #[action_xlate(name = "configure_mcastv4")]
    ConfigureIpv4 {
        mcast_grp_a: MulticastGroupId,
        rid: u16,
        level1_excl_id: u16,
        // This is a `bit<u9>` in the P4 sidecar and tofino doc, but we can't
        // represent that in Rust, so we validate in the caller.
        level2_excl_id: u16,
    },
}

#[derive(ActionParse, Debug)]
enum Ipv6Action {
    #[action_xlate(name = "configure_mcastv6")]
    ConfigureIpv6 {
        mcast_grp_a: MulticastGroupId,
        mcast_grp_b: MulticastGroupId,
        rid: u16,
        level1_excl_id: u16,
        // This is a `bit<u9>` in the P4 sidecar and tofino doc, but we can't
        // represent that in Rust, so we validate in the caller.
        level2_excl_id: u16,
    },
}

/// Add IPv4 multicast entries to the replication table:
/// `dst_addr -> external_mcast_grp, replication_id, level1_excl_id,
/// level2_excl_id`.
pub(crate) fn add_ipv4_entry(
    s: &Switch,
    dst_addr: Ipv4Addr,
    external_mcast_grp: MulticastGroupId,
    replication_id: u16,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    let match_key = Ipv4MatchKey::new(dst_addr);

    let action_data = Ipv4Action::ConfigureIpv4 {
        mcast_grp_a: external_mcast_grp,
        rid: replication_id,
        level1_excl_id,
        level2_excl_id,
    };

    debug!(
        s.log,
        "add mcast_ipv4 entry {} -> {:?}", dst_addr, action_data
    );

    s.table_entry_add(TableType::McastIpv4, &match_key, &action_data)
}

/// Update an IPv4 multicast entries in the replication table.
pub(crate) fn update_ipv4_entry(
    s: &Switch,
    dst_addr: Ipv4Addr,
    external_mcast_grp: MulticastGroupId,
    replication_id: u16,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    let match_key = Ipv4MatchKey::new(dst_addr);
    let action_data = Ipv4Action::ConfigureIpv4 {
        mcast_grp_a: external_mcast_grp,
        rid: replication_id,
        level1_excl_id,
        level2_excl_id,
    };

    debug!(
        s.log,
        "update mcast_ipv4 entry {} -> {:?}", dst_addr, action_data
    );

    // Try to update or add (as it may be new)
    s.table_entry_update(TableType::McastIpv4, &match_key, &action_data)
        .or_else(|_| {
            // If update fails, try to add instead
            s.table_entry_add(TableType::McastIpv4, &match_key, &action_data)
        })
}

/// Delete an IPv4 multicast entries from replication table, keyed on
/// `dst_addr`.
pub(crate) fn del_ipv4_entry(s: &Switch, dst_addr: Ipv4Addr) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(dst_addr);

    debug!(s.log, "delete mcast_ipv4 entry {}", match_key);

    s.table_entry_del(TableType::McastIpv4, &match_key)
}

/// Dump the IPv4 mulicast replication table's contents.
pub(crate) fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, Ipv4Action>(TableType::McastIpv4)
}

/// Fetch the IPv4 multicast table's counters.
pub(crate) fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4MatchKey>(force_sync, TableType::McastIpv4)
}

/// Reset the IPv4 multicast replication table.
pub(crate) fn reset_ipv4(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::McastIpv4)
}

/// Add an IPv6 multicast entries to the replication table:
/// `dst_addr -> underlay_mcast_grp && external_mcast_grp, replication_id,
/// level1_excl_id, level2_excl_id`.
pub(crate) fn add_ipv6_entry(
    s: &Switch,
    dst_addr: Ipv6Addr,
    underlay_mcast_grp: Option<MulticastGroupId>,
    external_mcast_grp: Option<MulticastGroupId>,
    replication_id: u16,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    if underlay_mcast_grp.is_none() && external_mcast_grp.is_none() {
        return Err(DpdError::McastGroupFailure(
            "neither underlay nor external multicast group specified"
                .to_string(),
        ));
    }

    let match_key = Ipv6MatchKey::new(dst_addr);

    let action_data = Ipv6Action::ConfigureIpv6 {
        mcast_grp_a: underlay_mcast_grp.unwrap_or(0),
        mcast_grp_b: external_mcast_grp.unwrap_or(0),
        rid: replication_id,
        level1_excl_id,
        level2_excl_id,
    };

    debug!(
        s.log,
        "add mcast_ipv6 entry {} -> {:?}", dst_addr, action_data
    );

    s.table_entry_add(TableType::McastIpv6, &match_key, &action_data)
}

/// Update an IPv6 multicast entries in the replication table.
pub(crate) fn update_ipv6_entry(
    s: &Switch,
    dst_addr: Ipv6Addr,
    underlay_mcast_grp: Option<MulticastGroupId>,
    external_mcast_grp: Option<MulticastGroupId>,
    replication_id: u16,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    if underlay_mcast_grp.is_none() && external_mcast_grp.is_none() {
        return Err(DpdError::McastGroupFailure(
            "neither underlay nor external multicast group specified"
                .to_string(),
        ));
    }

    let match_key = Ipv6MatchKey::new(dst_addr);

    let action_data = Ipv6Action::ConfigureIpv6 {
        mcast_grp_a: underlay_mcast_grp.unwrap_or(0),
        mcast_grp_b: external_mcast_grp.unwrap_or(0),
        rid: replication_id,
        level1_excl_id,
        level2_excl_id,
    };

    debug!(
        s.log,
        "update mcast_ipv6 entry {} -> {:?}", dst_addr, action_data
    );

    s.table_entry_update(TableType::McastIpv6, &match_key, &action_data)
}

/// Delete an IPv6 multicast entries from replication table, keyed on
/// `dst_addr`.
pub(crate) fn del_ipv6_entry(s: &Switch, dst_addr: Ipv6Addr) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(dst_addr);

    debug!(s.log, "delete mcast_ipv6 entry {}", match_key);

    s.table_entry_del(TableType::McastIpv6, &match_key)
}

/// Dump the IPv6 multicast table's contents.
pub(crate) fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, Ipv6Action>(TableType::McastIpv6)
}

/// Fetch the IPv6 multicast table's counters.
pub(crate) fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6MatchKey>(force_sync, TableType::McastIpv6)
}

/// Reset the IPv6 multicast replication table.
pub(crate) fn reset_ipv6(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::McastIpv6)
}
