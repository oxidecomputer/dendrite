// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::net::Ipv4Addr;

use crate::table::*;
use crate::Switch;
use aal_macros::*;
use common::network::MacAddr;

use aal::{ActionParse, MatchParse};

pub const TABLE_NAME: &str = "pipe.Ingress.l3_router.Router4.Arp.tbl";

#[derive(MatchParse, Hash)]
struct MatchKey {
    #[match_xlate(name = "nexthop_ipv4")]
    ip: Ipv4Addr,
}

#[derive(ActionParse)]
enum Action {
    #[action_xlate(name = "rewrite")]
    Rewrite { dst_mac: MacAddr },
    #[action_xlate(name = "drop")]
    DropPacket,
}

pub fn add_entry(
    s: &Switch,
    tgt_ip: Ipv4Addr,
    tgt_mac: MacAddr,
) -> DpdResult<()> {
    let match_key = MatchKey { ip: tgt_ip };

    let action_data = if tgt_mac.is_null() {
        Action::DropPacket
    } else {
        Action::Rewrite { dst_mac: tgt_mac }
    };
    s.table_entry_add(TableType::ArpIpv4, &match_key, &action_data)
}

pub fn update_entry(
    s: &Switch,
    tgt_ip: Ipv4Addr,
    tgt_mac: MacAddr,
) -> DpdResult<()> {
    let match_key = MatchKey { ip: tgt_ip };

    let action_data = if tgt_mac.is_null() {
        Action::DropPacket
    } else {
        Action::Rewrite { dst_mac: tgt_mac }
    };
    s.table_entry_update(TableType::ArpIpv4, &match_key, &action_data)
}

pub fn delete_entry(s: &Switch, tgt_ip: Ipv4Addr) -> DpdResult<()> {
    let match_key = MatchKey { ip: tgt_ip };
    s.table_entry_del(TableType::ArpIpv4, &match_key)
}

pub fn table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MatchKey, Action>(TableType::ArpIpv4)
}

pub fn counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MatchKey>(force_sync, TableType::ArpIpv4)
}

pub fn reset(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::ArpIpv4)
}
