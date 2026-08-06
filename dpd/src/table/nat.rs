// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use dpd_types::table;
use std::convert::TryInto;
use std::fmt;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use slog::{debug, error};

use aal::{ActionParse, MatchParse, MatchRange};
use aal_macros::*;

use crate::Switch;
use crate::table::*;
use common::network::{MacAddr, NatTarget};

/// An IP address family with a NAT ingress table.  Implementors provide the
/// family-specific p4 table and its match key and action types; the table
/// operations are provided methods built on those.
pub(crate) trait NatFamily: Copy + fmt::Display {
    const TABLE: TableType;
    const NAME: &'static str;

    type MatchKey: MatchParse + Hash + fmt::Display;
    type Action: ActionParse;

    fn match_key(self, low: u16, high: u16) -> Self::MatchKey;
    fn action(tgt: NatTarget) -> Self::Action;

    fn add_entry(
        self,
        s: &Switch,
        low: u16,
        high: u16,
        tgt: NatTarget,
    ) -> DpdResult<()> {
        let key = self.match_key(low, high);
        debug!(s.log, "add nat entry {} -> {:?}", key, tgt);
        s.table_entry_add(Self::TABLE, &key, &Self::action(tgt))
    }

    fn delete_entry(self, s: &Switch, low: u16, high: u16) -> DpdResult<()> {
        let key = self.match_key(low, high);
        debug!(s.log, "remove nat entry {}", key);
        s.table_entry_del(Self::TABLE, &key)
    }

    fn table_dump(s: &Switch, from_hardware: bool) -> DpdResult<table::Table> {
        s.table_dump::<Self::MatchKey, Self::Action>(Self::TABLE, from_hardware)
    }

    fn counter_fetch(
        s: &Switch,
        force_sync: bool,
    ) -> DpdResult<Vec<table::TableCounterEntry>> {
        s.counter_fetch::<Self::MatchKey>(force_sync, Self::TABLE)
    }

    fn reset(s: &Switch) -> DpdResult<()> {
        debug!(s.log, "resetting {} nat table", Self::NAME);
        s.table_clear(Self::TABLE).inspect_err(|e| {
            error!(s.log, "failed to reset {} nat table: {:?}", Self::NAME, e);
        })
    }
}

impl NatFamily for Ipv4Addr {
    const TABLE: TableType = TableType::NatIngressIpv4;
    const NAME: &'static str = "ipv4";

    type MatchKey = Ipv4MatchKey;
    type Action = Ipv4Action;

    fn match_key(self, low: u16, high: u16) -> Ipv4MatchKey {
        Ipv4MatchKey::new(self, low, high)
    }

    fn action(tgt: NatTarget) -> Ipv4Action {
        Ipv4Action::Forward {
            target: tgt.internal_ip,
            inner_mac: tgt.inner_mac,
            vni: tgt.vni.as_u32(),
        }
    }
}

impl NatFamily for Ipv6Addr {
    const TABLE: TableType = TableType::NatIngressIpv6;
    const NAME: &'static str = "ipv6";

    type MatchKey = Ipv6MatchKey;
    type Action = Ipv6Action;

    fn match_key(self, low: u16, high: u16) -> Ipv6MatchKey {
        Ipv6MatchKey::new(self, low, high)
    }

    fn action(tgt: NatTarget) -> Ipv6Action {
        Ipv6Action::Forward {
            target: tgt.internal_ip,
            inner_mac: tgt.inner_mac,
            vni: tgt.vni.as_u32(),
        }
    }
}

#[derive(MatchParse, Hash)]
pub(crate) struct Ipv6MatchKey {
    dst_addr: Ipv6Addr,

    #[match_xlate(name = "l4_dst_port", type = "range")]
    ports: MatchRange,
}

impl Ipv6MatchKey {
    fn new<T>(dst_addr: Ipv6Addr, low: T, high: T) -> Self
    where
        T: std::convert::Into<u64>,
    {
        Ipv6MatchKey {
            dst_addr,
            ports: MatchRange { low: low.into(), high: high.into() },
        }
    }
}

impl fmt::Display for Ipv6MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}/{}-{})", self.dst_addr, self.ports.low, self.ports.high)
    }
}

#[derive(MatchParse, Hash)]
pub(crate) struct Ipv4MatchKey {
    dst_addr: Ipv4Addr,

    #[match_xlate(name = "l4_dst_port", type = "range")]
    ports: MatchRange,
}

impl Ipv4MatchKey {
    fn new<T>(dst_addr: Ipv4Addr, low: T, high: T) -> Self
    where
        T: std::convert::Into<u64>,
    {
        Ipv4MatchKey {
            dst_addr,
            ports: MatchRange { low: low.into(), high: high.into() },
        }
    }
}

impl fmt::Display for Ipv4MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}/{}-{})", self.dst_addr, self.ports.low, self.ports.high)
    }
}

#[derive(ActionParse)]
pub(crate) enum Ipv6Action {
    #[action_xlate(name = "forward_ipv6_to")]
    Forward { target: Ipv6Addr, inner_mac: MacAddr, vni: u32 },
}

#[derive(ActionParse)]
pub(crate) enum Ipv4Action {
    #[action_xlate(name = "forward_ipv4_to")]
    Forward { target: Ipv6Addr, inner_mac: MacAddr, vni: u32 },
}
