// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::{
    convert::TryInto,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{mcast::MulticastGroupId, table::*, Switch};
use aal::{ActionParse, AsicOps, MatchParse};
use aal_macros::*;
use common::{nat::NatTarget, network::MacAddr};
use slog::debug;

pub const IPV4_TABLE_NAME: &str =
    "pipe.Ingress.multicast_ingress.mcast_route_ipv4";
pub const IPV6_TABLE_NAME: &str =
    "pipe.Ingress.multicast_ingress.mcast_route_ipv6";
pub const NAT_INGRESS_TABLE_NAME: &str = "pipe.Egress.nat_ingress.tbl";

#[derive(MatchParse, Hash)]
struct Ipv4MatchKey {
    dst_addr: Ipv4Addr,
}

impl Ipv4MatchKey {
    pub fn new(dst_addr: Ipv4Addr) -> Self {
        Self { dst_addr }
    }
}

impl fmt::Display for Ipv4MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dst_addr)
    }
}

#[derive(MatchParse, Hash)]
struct Ipv6MatchKey {
    dst_addr: Ipv6Addr,
}

impl Ipv6MatchKey {
    pub fn new(dst_addr: Ipv6Addr) -> Self {
        Self { dst_addr }
    }
}

impl fmt::Display for Ipv6MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dst_addr)
    }
}

#[derive(MatchParse, Hash)]
struct NatMatchKey {
    #[match_xlate(name = "mcast_group")]
    group_id: MulticastGroupId,
    #[match_xlate(name = "egress_rid")]
    port: u16,
}

impl NatMatchKey {
    pub fn new(group_id: MulticastGroupId, port: u16) -> Self {
        Self { group_id, port }
    }
}

impl fmt::Display for NatMatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "group_id: {}, port: {}", self.group_id, self.port)
    }
}

#[derive(ActionParse, Debug)]
enum Ipv4Action {
    #[action_xlate(name = "configure_mcastv4")]
    ConfigureIpv4 {
        mcast_grp: MulticastGroupId,
        level1_excl_id: u16,
        // This is a `bit<u9>` in the P4 sidecar and tofino doc, but we can't
        // represent that in Rust, so we validate in the caller.
        level2_excl_id: u16,
    },
    #[action_xlate(name = "drop_mcastv4_no_group")]
    DropIpv4NoGroup,
}

#[derive(ActionParse, Debug)]
enum Ipv6Action {
    #[action_xlate(name = "configure_mcastv6")]
    ConfigureIpv6 {
        mcast_grp: MulticastGroupId,
        level1_excl_id: u16,
        // This is a `bit<u9>` in the P4 sidecar and tofino doc, but we can't
        // represent that in Rust, so we validate in the caller.
        level2_excl_id: u16,
    },
    #[action_xlate(name = "drop_mcastv6_no_group")]
    DropIpv6NoGroup,
}

/// Add an IPv4 multicast entry to the table.
pub fn add_ipv4_entry(
    s: &Switch,
    dst_addr: Ipv4Addr,
    mcast_grp: MulticastGroupId,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    let match_key = Ipv4MatchKey::new(dst_addr);

    let action_data = if !s.asic_hdl.mc_group_exists(mcast_grp) {
        Ipv4Action::DropIpv4NoGroup
    } else {
        Ipv4Action::ConfigureIpv4 {
            mcast_grp,
            level1_excl_id,
            level2_excl_id,
        }
    };

    debug!(
        s.log,
        "add mcast_ipv4 entry {} -> {:?}", dst_addr, action_data
    );

    s.table_entry_add(TableType::McastIpv4, &match_key, &action_data)
}

/// Update an IPv4 multicast entry in the table.
pub fn update_ipv4_entry(
    s: &Switch,
    dst_addr: Ipv4Addr,
    mcast_grp: MulticastGroupId,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    let match_key = Ipv4MatchKey::new(dst_addr);

    let action_data = if !s.asic_hdl.mc_group_exists(mcast_grp) {
        Ipv4Action::DropIpv4NoGroup
    } else {
        Ipv4Action::ConfigureIpv4 {
            mcast_grp,
            level1_excl_id,
            level2_excl_id,
        }
    };

    debug!(
        s.log,
        "update mcast_ipv4 entry {} -> {:?}", dst_addr, action_data
    );

    s.table_entry_update(TableType::McastIpv4, &match_key, &action_data)
}

/// Delete an IPv4 multicast entry from table.
pub fn del_ipv4_entry(s: &Switch, dst_addr: Ipv4Addr) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(dst_addr);

    debug!(s.log, "delete mcast_ipv4 entry {}", match_key);

    s.table_entry_del(TableType::McastIpv4, &match_key)
}

/// Dump the IPv4 multicast table's contents.
pub fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, Ipv4Action>(TableType::McastIpv4)
}

/// Fetch the IPv4 multicast table's counters.
pub fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4MatchKey>(force_sync, TableType::McastIpv4)
}

/// Reset the multicast table.
pub fn reset_ipv4(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::McastIpv4)
}

/// Add an IPv6 multicast entry to the table.
pub fn add_ipv6_entry(
    s: &Switch,
    dst_addr: Ipv6Addr,
    mcast_grp: MulticastGroupId,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    let match_key = Ipv6MatchKey::new(dst_addr);

    let action_data = if !s.asic_hdl.mc_group_exists(mcast_grp) {
        Ipv6Action::DropIpv6NoGroup
    } else {
        Ipv6Action::ConfigureIpv6 {
            mcast_grp,
            level1_excl_id,
            level2_excl_id,
        }
    };

    debug!(
        s.log,
        "add mcast_ipv6 entry {} -> {:?}", dst_addr, action_data
    );

    s.table_entry_add(TableType::McastIpv6, &match_key, &action_data)
}

/// Update an IPv6 multicast entry in the table.
pub fn update_ipv6_entry(
    s: &Switch,
    dst_addr: Ipv6Addr,
    mcast_grp: MulticastGroupId,
    level1_excl_id: u16,
    level2_excl_id: u16,
) -> DpdResult<()> {
    if level2_excl_id > 511 {
        return Err(DpdError::Invalid(
            "`level2 exclusion id` exceeds 9-bit range".to_string(),
        ));
    }

    let match_key = Ipv6MatchKey::new(dst_addr);

    let action_data = if !s.asic_hdl.mc_group_exists(mcast_grp) {
        Ipv6Action::DropIpv6NoGroup
    } else {
        Ipv6Action::ConfigureIpv6 {
            mcast_grp,
            level1_excl_id,
            level2_excl_id,
        }
    };

    debug!(
        s.log,
        "update mcast_ipv6 entry {} -> {:?}", dst_addr, action_data
    );

    s.table_entry_update(TableType::McastIpv6, &match_key, &action_data)
}

/// Delete an IPv6 multicast entry from table.
pub fn del_ipv6_entry(s: &Switch, dst_addr: Ipv6Addr) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(dst_addr);

    debug!(s.log, "delete mcast_ipv6 entry {}", match_key);

    s.table_entry_del(TableType::McastIpv6, &match_key)
}

/// Dump the IPv6 multicast table's contents.
pub fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, Ipv6Action>(TableType::McastIpv6)
}

/// Fetch the IPv6 multicast table's counters.
pub fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6MatchKey>(force_sync, TableType::McastIpv6)
}

/// Reset the multicast table.
pub fn reset_ipv6(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::McastIpv6)
}

#[derive(ActionParse, Debug)]
enum NatAction {
    #[action_xlate(name = "forward_to")]
    Forward { inner_mac: MacAddr, vni: u32 },
}

/// Add a NAT entry for multicast traffic.
pub fn add_nat_entry(
    s: &Switch,
    group_id: MulticastGroupId,
    port: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = NatMatchKey::new(group_id, port);
    let action_key = NatAction::Forward {
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(
        s.log,
        "add ingress mcast entry {} -> {:?}", match_key, action_key
    );

    s.table_entry_add(TableType::NatIngressMcast, &match_key, &action_key)
}

/// Update a NAT entry for multicast traffic.
pub fn update_nat_entry(
    s: &Switch,
    group_id: MulticastGroupId,
    port: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = NatMatchKey::new(group_id, port);
    let action_key = NatAction::Forward {
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(
        s.log,
        "update ingress mcast entry {} -> {:?}", match_key, action_key
    );

    s.table_entry_update(TableType::NatIngressMcast, &match_key, &action_key)
}

/// Delete a NAT entry for multicast traffic.
pub fn del_nat_entry(
    s: &Switch,
    group_id: MulticastGroupId,
    port: u16,
) -> DpdResult<()> {
    let match_key = NatMatchKey::new(group_id, port);

    debug!(s.log, "delete ingress mcast entry {}", match_key);

    s.table_entry_del(TableType::NatIngressMcast, &match_key)
}

/// Dump the NAT table's contents.
pub fn nat_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<NatMatchKey, NatAction>(TableType::NatIngressMcast)
}

/// Fetch the NAT table's counters.
pub fn nat_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<NatMatchKey>(force_sync, TableType::NatIngressMcast)
}

/// Reset the NAT table.
pub fn reset_nat(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NatIngressMcast)
}
