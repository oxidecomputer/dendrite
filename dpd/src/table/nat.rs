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
use crate::nat::PortRange;
use crate::table::*;
use common::nat::{Ipv4Nat, Ipv6Nat};
use common::network::{MacAddr, NatTarget};

pub(crate) trait NatAddress: Copy + Ord + fmt::Display {
    const TABLE: TableType;
    const NAME: &'static str;

    type MatchKey: MatchParse + Hash + fmt::Display;
    type Action: ActionParse;
    type Reservation;

    fn match_key(self, ports: PortRange) -> Self::MatchKey;
    fn action(tgt: NatTarget) -> Self::Action;
    fn reservation(self, ports: PortRange, tgt: NatTarget)
    -> Self::Reservation;
}

pub(crate) fn add_entry<A: NatAddress>(
    s: &Switch,
    nat_ip: A,
    ports: PortRange,
    tgt: NatTarget,
) -> DpdResult<()> {
    let key = nat_ip.match_key(ports);
    debug!(s.log, "add nat entry {} -> {:?}", key, tgt);
    s.table_entry_add(A::TABLE, &key, &A::action(tgt))
}

pub(crate) fn delete_entry<A: NatAddress>(
    s: &Switch,
    nat_ip: A,
    ports: PortRange,
) -> DpdResult<()> {
    let key = nat_ip.match_key(ports);
    debug!(s.log, "remove nat entry {}", key);
    s.table_entry_del(A::TABLE, &key)
}

pub(super) fn table_dump<A: NatAddress>(
    s: &Switch,
    from_hardware: bool,
) -> DpdResult<table::Table> {
    s.table_dump::<A::MatchKey, A::Action>(A::TABLE, from_hardware)
}

pub(super) fn counter_fetch<A: NatAddress>(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<table::TableCounterEntry>> {
    s.counter_fetch::<A::MatchKey>(force_sync, A::TABLE)
}

pub(crate) fn reset<A: NatAddress>(s: &Switch) -> DpdResult<()> {
    debug!(s.log, "resetting {} nat table", A::NAME);
    s.table_clear(A::TABLE).inspect_err(|e| {
        error!(s.log, "failed to reset {} nat table: {:?}", A::NAME, e);
    })
}

impl NatAddress for Ipv4Addr {
    const TABLE: TableType = TableType::NatIngressIpv4;
    const NAME: &'static str = "ipv4";

    type MatchKey = Ipv4MatchKey;
    type Action = Ipv4Action;
    type Reservation = Ipv4Nat;

    fn match_key(self, ports: PortRange) -> Ipv4MatchKey {
        Ipv4MatchKey::new(self, ports.low(), ports.high())
    }

    fn action(tgt: NatTarget) -> Ipv4Action {
        Ipv4Action::Forward {
            target: tgt.internal_ip,
            inner_mac: tgt.inner_mac,
            vni: tgt.vni.as_u32(),
        }
    }

    fn reservation(self, ports: PortRange, tgt: NatTarget) -> Ipv4Nat {
        Ipv4Nat {
            external: self,
            low: ports.low(),
            high: ports.high(),
            target: tgt,
        }
    }
}

impl NatAddress for Ipv6Addr {
    const TABLE: TableType = TableType::NatIngressIpv6;
    const NAME: &'static str = "ipv6";

    type MatchKey = Ipv6MatchKey;
    type Action = Ipv6Action;
    type Reservation = Ipv6Nat;

    fn match_key(self, ports: PortRange) -> Ipv6MatchKey {
        Ipv6MatchKey::new(self, ports.low(), ports.high())
    }

    fn action(tgt: NatTarget) -> Ipv6Action {
        Ipv6Action::Forward {
            target: tgt.internal_ip,
            inner_mac: tgt.inner_mac,
            vni: tgt.vni.as_u32(),
        }
    }

    fn reservation(self, ports: PortRange, tgt: NatTarget) -> Ipv6Nat {
        Ipv6Nat {
            external: self,
            low: ports.low(),
            high: ports.high(),
            target: tgt,
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
