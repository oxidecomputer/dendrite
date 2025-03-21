// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use slog::debug;

use aal::{ActionParse, MatchParse, MatchRange};
use aal_macros::*;

use crate::table::*;
use crate::Switch;
use common::nat::NatTarget;
use common::network::MacAddr;

pub const IPV4_TABLE_NAME: &str = "pipe.Ingress.nat_ingress.ingress_ipv4";
pub const IPV6_TABLE_NAME: &str = "pipe.Ingress.nat_ingress.ingress_ipv6";

#[derive(MatchParse, Hash)]
struct Ipv6MatchKey {
    dst_addr: Ipv6Addr,

    #[match_xlate(name = "l4_dst_port", type = "range")]
    ports: MatchRange,
}

impl Ipv6MatchKey {
    pub fn new<T>(dst_addr: Ipv6Addr, low: T, high: T) -> Self
    where
        T: std::convert::Into<u64>,
    {
        Ipv6MatchKey {
            dst_addr,
            ports: MatchRange {
                low: low.into(),
                high: high.into(),
            },
        }
    }
}

impl fmt::Display for Ipv6MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({}/{}-{})",
            self.dst_addr, self.ports.low, self.ports.high
        )
    }
}

#[derive(MatchParse, Hash)]
struct Ipv4MatchKey {
    dst_addr: Ipv4Addr,

    #[match_xlate(name = "l4_dst_port", type = "range")]
    ports: MatchRange,
}

impl Ipv4MatchKey {
    pub fn new<T>(dst_addr: Ipv4Addr, low: T, high: T) -> Self
    where
        T: std::convert::Into<u64>,
    {
        Ipv4MatchKey {
            dst_addr,
            ports: MatchRange {
                low: low.into(),
                high: high.into(),
            },
        }
    }
}

impl fmt::Display for Ipv4MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({}/{}-{})",
            self.dst_addr, self.ports.low, self.ports.high
        )
    }
}

#[derive(ActionParse)]
enum Ipv6Action {
    #[action_xlate(name = "forward_ipv6_to")]
    Forward {
        target: Ipv6Addr,
        inner_mac: MacAddr,
        vni: u32,
    },
}

#[derive(ActionParse)]
enum Ipv4Action {
    #[action_xlate(name = "forward_ipv4_to")]
    Forward {
        target: Ipv6Addr,
        inner_mac: MacAddr,
        vni: u32,
    },
}

pub fn add_ipv6_entry(
    s: &Switch,
    nat_ip: Ipv6Addr,
    nat_port_low: u16,
    nat_port_high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(nat_ip, nat_port_low, nat_port_high);
    let action_key = Ipv6Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(s.log, "add nat entry {} -> {:?}", match_key, tgt);

    s.table_entry_add(TableType::NatIngressIpv6, &match_key, &action_key)
}

pub fn delete_ipv6_entry(
    s: &Switch,
    nat_ip: Ipv6Addr,
    nat_port_low: u16,
    nat_port_high: u16,
) -> DpdResult<()> {
    let match_key = Ipv6MatchKey::new(nat_ip, nat_port_low, nat_port_high);
    debug!(s.log, "remove nat entry {}", match_key);
    s.table_entry_del(TableType::NatIngressIpv6, &match_key)
}

pub fn reset_ipv6(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NatIngressIpv6)
}

pub fn add_ipv4_entry(
    s: &Switch,
    nat_ip: Ipv4Addr,
    nat_port_low: u16,
    nat_port_high: u16,
    tgt: NatTarget,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(nat_ip, nat_port_low, nat_port_high);
    let action_key = Ipv4Action::Forward {
        target: tgt.internal_ip,
        inner_mac: tgt.inner_mac,
        vni: tgt.vni.as_u32(),
    };

    debug!(s.log, "add nat entry {} -> {:?}", match_key, tgt);

    s.table_entry_add(TableType::NatIngressIpv4, &match_key, &action_key)
}

pub fn delete_ipv4_entry(
    s: &Switch,
    nat_ip: Ipv4Addr,
    nat_port_low: u16,
    nat_port_high: u16,
) -> DpdResult<()> {
    let match_key = Ipv4MatchKey::new(nat_ip, nat_port_low, nat_port_high);
    debug!(s.log, "remove nat entry {}", match_key);
    s.table_entry_del(TableType::NatIngressIpv4, &match_key)
}

pub fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, Ipv4Action>(TableType::NatIngressIpv4)
}

pub fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, Ipv6Action>(TableType::NatIngressIpv6)
}

pub fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4MatchKey>(force_sync, TableType::NatIngressIpv4)
}

pub fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6MatchKey>(force_sync, TableType::NatIngressIpv6)
}

/// Delete many IPv6 address from the ASIC tables.
pub fn reset_ipv4(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::NatIngressIpv4)
}
