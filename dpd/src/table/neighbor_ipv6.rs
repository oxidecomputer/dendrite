// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::net::Ipv6Addr;

use slog::debug;

use aal::{ActionParse, MatchParse};
use aal_macros::*;

use crate::table::*;
use crate::Switch;
use common::network::MacAddr;

pub const TABLE_NAME: &str = "pipe.Ingress.l3_router.Router6.Ndp.tbl";

#[derive(MatchParse, Hash)]
struct MatchKey {
    #[match_xlate(name = "nexthop_ipv6")]
    ip: Ipv6Addr,
}

#[derive(ActionParse, Debug)]
enum Action {
    #[action_xlate(name = "rewrite")]
    Rewrite { dst_mac: MacAddr },
    #[action_xlate(name = "drop")]
    DropPacket,
}

pub fn add_entry(
    s: &Switch,
    tgt_ip: Ipv6Addr,
    tgt_mac: MacAddr,
) -> DpdResult<()> {
    let match_key = MatchKey { ip: tgt_ip };
    let action_data = if tgt_mac.is_null() {
        Action::DropPacket
    } else {
        Action::Rewrite { dst_mac: tgt_mac }
    };

    debug!(s.log, "add neighbor entry {} -> {}", tgt_ip, tgt_mac);
    s.table_entry_add(TableType::NeighborIpv6, &match_key, &action_data)
}

pub fn update_entry(
    s: &Switch,
    tgt_ip: Ipv6Addr,
    tgt_mac: MacAddr,
) -> DpdResult<()> {
    let match_key = MatchKey { ip: tgt_ip };
    let action_data = if tgt_mac.is_null() {
        Action::DropPacket
    } else {
        Action::Rewrite { dst_mac: tgt_mac }
    };

    debug!(s.log, "update neighbor entry {} -> {}", tgt_ip, tgt_mac);
    s.table_entry_update(TableType::NeighborIpv6, &match_key, &action_data)
}

pub fn delete_entry(s: &Switch, tgt_ip: Ipv6Addr) -> DpdResult<()> {
    let match_key = MatchKey { ip: tgt_ip };
    debug!(s.log, "delete neighbor entry {}", tgt_ip);
    s.table_entry_del(TableType::NeighborIpv6, &match_key)
}

pub fn table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MatchKey, Action>(TableType::NeighborIpv6)
}

pub fn counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MatchKey>(force_sync, TableType::NeighborIpv6)
}

pub fn reset(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NeighborIpv6)
}
