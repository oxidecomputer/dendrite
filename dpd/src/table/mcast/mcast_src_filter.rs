// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Table operations for multicast source filter entries.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{Switch, table::*};

use aal::{ActionParse, MatchParse};
use aal_macros::*;
use oxnet::Ipv4Net;
use slog::debug;

/// IPv4 Table for multicast source filter entries.
pub(crate) const IPV4_TABLE_NAME: &str =
    "pipe.Ingress.mcast_ingress.mcast_source_filter_ipv4";
/// IPv6 Table for multicast source filter entries.
pub(crate) const IPV6_TABLE_NAME: &str =
    "pipe.Ingress.mcast_ingress.mcast_source_filter_ipv6";

#[derive(MatchParse, Hash)]
struct Ipv4MatchKey {
    #[match_xlate(name = "src_addr", type = "lpm")]
    src_addr: Ipv4Net,
    dst_addr: Ipv4Addr,
}

impl Ipv4MatchKey {
    fn new(src_addr: Ipv4Net, dst_addr: Ipv4Addr) -> Self {
        Self { src_addr, dst_addr }
    }
}

impl fmt::Display for Ipv4MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {}", self.src_addr, self.dst_addr)
    }
}

#[derive(MatchParse, Hash)]
struct Ipv6MatchKey {
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
}

impl Ipv6MatchKey {
    fn new(src_addr: Ipv6Addr, dst_addr: Ipv6Addr) -> Self {
        Self { src_addr, dst_addr }
    }
}

impl fmt::Display for Ipv6MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {}", self.src_addr, self.dst_addr)
    }
}

#[derive(ActionParse, Debug)]
enum Ipv4Action {
    #[action_xlate(name = "allow_source_mcastv4")]
    AllowSrc,
}

#[derive(ActionParse, Debug)]
enum Ipv6Action {
    #[action_xlate(name = "allow_source_mcastv6")]
    AllowSrc,
}

/// Add a source filter entry for IPv4 multicast traffic:
/// `src_addr, dst_addr -> allow_source_mcastv4`.
pub(crate) fn add_ipv4_entry(
    s: &Switch,
    src_addr: Ipv4Net,
    dst_addr: Ipv4Addr,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(src_addr, dst_addr);
    let action_data = Ipv4Action::AllowSrc;

    debug!(
        s.log,
        "add source filter entry {} -> {:?}", src_addr, action_data
    );

    s.table_entry_add(TableType::McastIpv4SrcFilter, &match_key, &action_data)
}

/// Delete a source filter entry for IPv4 multicast traffic, keyed on
/// `src_addr, dst_addr`.
pub(crate) fn del_ipv4_entry(
    s: &Switch,
    src_addr: Ipv4Net,
    dst_addr: Ipv4Addr,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(src_addr, dst_addr);

    debug!(
        s.log,
        "delete source filter entry {} -> {}", src_addr, dst_addr
    );

    s.table_entry_del(TableType::McastIpv4SrcFilter, &match_key)
}

/// Dump the IPv4 multicast source filter table's contents.
pub(crate) fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, Ipv4Action>(TableType::McastIpv4SrcFilter)
}

/// Fetch the IPv4 multicast source filter table's counters.
pub(crate) fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4MatchKey>(force_sync, TableType::McastIpv4SrcFilter)
}

/// Reset the IPv4 multicast source filter table.
pub(crate) fn reset_ipv4(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::McastIpv4SrcFilter)
}

/// Add a source filter entry for IPv6 multicast traffic:
/// `src_addr, dst_addr -> allow_source_mcastv6`.
pub(crate) fn add_ipv6_entry(
    s: &Switch,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(src_addr, dst_addr);
    let action_data = Ipv6Action::AllowSrc;

    debug!(
        s.log,
        "add source filter entry {} -> {:?}", src_addr, action_data
    );

    s.table_entry_add(TableType::McastIpv6SrcFilter, &match_key, &action_data)
}

/// Delete a source filter entry for IPv6 multicast traffic, keyed on
/// `src_addr, dst_addr`.
pub(crate) fn del_ipv6_entry(
    s: &Switch,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(src_addr, dst_addr);

    debug!(
        s.log,
        "delete source filter entry {} -> {}", src_addr, dst_addr
    );

    s.table_entry_del(TableType::McastIpv6SrcFilter, &match_key)
}

/// Dump the IPv6 multicast source filter table's contents.
pub(crate) fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, Ipv6Action>(TableType::McastIpv6SrcFilter)
}

/// Fetch the IPv6 multicast source filter table's counters.
pub(crate) fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6MatchKey>(force_sync, TableType::McastIpv6SrcFilter)
}

/// Reset the IPv6 multicast source filter table.
pub(crate) fn reset_ipv6(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::McastIpv6SrcFilter)
}
