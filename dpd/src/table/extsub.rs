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
use oxnet::Ipv4Net;

use crate::Switch;
use crate::table::*;
use common::network::{InstanceTarget, MacAddr};

pub const EXT_SUBNET_TABLE_NAME: &str = "pipe.Ingress.filter.external_subnets";

// Used to identify entries in the external subnet table
#[derive(MatchParse, Hash, Debug)]
struct ExtSubnetMatchKey {
    #[match_xlate(type = "lpm", name = "dst_addr")]
    subnet: Ipv4Net,
}

#[derive(ActionParse)]
enum ExtSubnetAction {
    #[action_xlate(name = "forward_extsub_to")]
    Forward {
        target: Ipv6Addr,
        inner_mac: MacAddr,
        vni: u32,
    },
}

pub fn add_entry(
    s: &Switch,
    subnet: Ipv4Net,
    tgt: InstanceTarget,
) -> DpdResult<()> {
    let match_key = ExtSubnetMatchKey { subnet };
    let action_key = ExtSubnetAction::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(
        s.log,
        "add external subnet entry {} -> {:?}", match_key.subnet, tgt
    );

    s.table_entry_add(TableType::ExternalSubnet, &match_key, &action_key)
}

pub fn delete_entry(s: &Switch, subnet: Ipv4Net) -> DpdResult<()> {
    let match_key = ExtSubnetMatchKey { subnet };
    debug!(s.log, "remove external subnet entry {}", match_key.subnet);
    s.table_entry_del(TableType::ExternalSubnet, &match_key)
}

pub fn table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<ExtSubnetMatchKey, ExtSubnetAction>(
        TableType::ExternalSubnet,
    )
}

pub fn counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<ExtSubnetMatchKey>(force_sync, TableType::ExternalSubnet)
}

/// Delete all the external subnet entries
pub fn reset(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::ExternalSubnet)
}
