// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use slog::error;
use slog::info;

use crate::table::*;
use crate::Switch;
use aal::ActionParse;
use aal::MatchMask;
use aal::MatchParse;
use aal_macros::*;

pub const IPV4_TABLE_NAME: &str = "pipe.Ingress.filter.switch_ipv4_addr";
pub const IPV6_TABLE_NAME: &str = "pipe.Ingress.filter.switch_ipv6_addr";

#[derive(MatchParse, Hash)]
struct Ipv4MatchKey {
    #[match_xlate(name = "orig_dst_ipv4")]
    dst_addr: Ipv4Addr,
    #[match_xlate(name = "in_port", type = "mask")]
    port: MatchMask,
}

#[derive(MatchParse, Hash)]
struct Ipv6MatchKey {
    dst_addr: Ipv6Addr,
    #[match_xlate(name = "in_port", type = "mask")]
    port: MatchMask,
}

#[derive(ActionParse)]
enum ActionV4 {
    #[action_xlate(name = "claimv4")]
    ClaimIpv4,
    #[action_xlate(name = "dropv4")]
    DropIpv4,
}

#[derive(ActionParse)]
enum ActionV6 {
    #[action_xlate(name = "claimv6")]
    ClaimIpv6,
    #[action_xlate(name = "dropv6")]
    DropIpv6,
}

// Each switch address consumes two entries in a switch table: one to allow
// traffic on the address's port, and one to drop traffic on all other ports.
// This means that adding and removing an address is a multi-step operation.  If
// the second step of any such update fails, we attempt to roll back the first
// step to leave us in a consistent state.  If the rollback fails, we will panic
// rather than continue in a known-bad state.
//
// If an attempt to repair a failed update also fails, it is very unlikely that
// a second attempt will have any better luck on real hardware.  On the "chaos"
// ASIC, where all errors are injected randomly, it is entirely possible that
// retrying the operation will succeed.  This constant determines how many times
// we will retry before giving up.
#[cfg(feature = "chaos")]
const REPAIR_ATTEMPTS: usize = 20;
#[cfg(not(feature = "chaos"))]
const REPAIR_ATTEMPTS: usize = 3;

fn match_keys_ipv4(ipv4: Ipv4Addr, port: u16) -> (Ipv4MatchKey, Ipv4MatchKey) {
    let claim_key = Ipv4MatchKey {
        dst_addr: ipv4,
        port: MatchMask {
            val: port.into(),
            mask: 0x1ffu16.into(),
        },
    };
    let drop_key = Ipv4MatchKey {
        dst_addr: ipv4,
        port: MatchMask {
            val: port.into(),
            mask: 0u16.into(),
        },
    };
    (claim_key, drop_key)
}

fn match_keys_ipv6(ipv6: Ipv6Addr, port: u16) -> (Ipv6MatchKey, Ipv6MatchKey) {
    let claim_key = Ipv6MatchKey {
        dst_addr: ipv6,
        port: MatchMask {
            val: port.into(),
            mask: 0x1ffu16.into(),
        },
    };
    let drop_key = Ipv6MatchKey {
        dst_addr: ipv6,
        port: MatchMask {
            val: 0u16.into(),
            mask: 0u16.into(),
        },
    };
    (claim_key, drop_key)
}

pub fn loopback_ipv4_add(s: &Switch, ipv4: Ipv4Addr) -> DpdResult<()> {
    let claim_key = Ipv4MatchKey {
        dst_addr: ipv4,
        port: MatchMask {
            val: 0u16.into(),
            mask: 0u16.into(),
        },
    };
    s.table_entry_add(TableType::PortIpv4, &claim_key, &ActionV4::ClaimIpv4)
        .map(|_| info!(s.log, "added ipv4 loopback"; "addr" => %ipv4))
        .inspect_err(|e| {
            error!(s.log, "failed to add ipv4 loopback";
		"addr" => %ipv4,
		"error" => %e);
        })
}

pub fn loopback_ipv4_delete(s: &Switch, ipv4: Ipv4Addr) -> DpdResult<()> {
    let claim_key = Ipv4MatchKey {
        dst_addr: ipv4,
        port: MatchMask {
            val: 0u16.into(),
            mask: 0u16.into(),
        },
    };
    s.table_entry_del(TableType::PortIpv4, &claim_key)
        .map(|_| info!(s.log, "deleted ipv4 loopback"; "addr" => %ipv4))
        .inspect_err(|e| {
            error!(s.log, "failed to delete ipv4 loopback";
		"addr" => %ipv4,
		"error" => %e);
        })
}

pub fn loopback_ipv6_add(s: &Switch, ipv6: Ipv6Addr) -> DpdResult<()> {
    let claim_key = Ipv6MatchKey {
        dst_addr: ipv6,
        port: MatchMask {
            val: 0u16.into(),
            mask: 0u16.into(),
        },
    };
    s.table_entry_add(TableType::PortIpv6, &claim_key, &ActionV6::ClaimIpv6)
        .map(|_| info!(s.log, "added ipv6 loopback"; "addr" => %ipv6))
        .inspect_err(|e| {
            error!(s.log, "failed to add ipv6 loopback";
		"addr" => %ipv6,
		"error" => %e);
        })
}

pub fn loopback_ipv6_delete(s: &Switch, ipv6: Ipv6Addr) -> DpdResult<()> {
    let claim_key = Ipv6MatchKey {
        dst_addr: ipv6,
        port: MatchMask {
            val: 0u16.into(),
            mask: 0u16.into(),
        },
    };
    s.table_entry_del(TableType::PortIpv6, &claim_key)
        .map(|_| info!(s.log, "deleted ipv6 loopback"; "addr" => %ipv6))
        .inspect_err(|e| {
            error!(s.log, "failed to delete ipv6 loopback";
		"addr" => %ipv6,
		"error" => %e);
        })
}

fn endeavour_to_repair(
    s: &Switch,
    msg: String,
    operation: impl Fn() -> DpdResult<()>,
) {
    for x in 0..REPAIR_ATTEMPTS {
        if let Err(e) = operation() {
            error!(s.log, "{msg}.  Repair attempt {x} failed: {e:?}")
        } else {
            if x > 0 {
                error!(s.log, "{msg}.  Repair succeeded after {x} retries")
            }
            return;
        }
    }
    panic!("Repeated repair attempts failed.  Giving up.");
}

fn ipv4_add_work(s: &Switch, port: u16, ipv4: Ipv4Addr) -> DpdResult<()> {
    let (claim_key, drop_key) = match_keys_ipv4(ipv4, port);

    s.table_entry_add(TableType::PortIpv4, &claim_key, &ActionV4::ClaimIpv4)?;
    s.table_entry_add(TableType::PortIpv4, &drop_key, &ActionV4::DropIpv4)
        .inspect_err(|_| {
            endeavour_to_repair(
                s,
                format!("ipv4 address {ipv4} only half added"),
                || s.table_entry_del(TableType::PortIpv4, &claim_key),
            );
        })
}

/// Add one IPv4 address to the ASIC tables.
pub fn ipv4_add(s: &Switch, port: u16, ipv4: Ipv4Addr) -> DpdResult<()> {
    ipv4_add_work(s, port, ipv4)
        .map(|_| {
            info!(s.log, "added ipv4 address";
		"addr" => %ipv4,
		"port" => port)
        })
        .inspect_err(|e| {
            error!(s.log, "failed to add ipv4 address";
		"addr" => %ipv4,
		"port" => port,
		"error" => %e);
        })
}

fn ipv4_delete_work(s: &Switch, port: u16, ipv4: Ipv4Addr) -> DpdResult<()> {
    let (claim_key, drop_key) = match_keys_ipv4(ipv4, port);

    s.table_entry_del(TableType::PortIpv4, &claim_key)?;
    s.table_entry_del(TableType::PortIpv4, &drop_key)
        .inspect_err(|_| {
            endeavour_to_repair(
                s,
                format!("ipv4 address {ipv4} only half deleted"),
                || {
                    s.table_entry_add(
                        TableType::PortIpv4,
                        &claim_key,
                        &ActionV4::ClaimIpv4,
                    )
                },
            );
        })
}

/// Delete one IPv4 address from the ASIC tables.
pub fn ipv4_delete(s: &Switch, port: u16, ipv4: Ipv4Addr) -> DpdResult<()> {
    ipv4_delete_work(s, port, ipv4)
        .map(|_| {
            info!(s.log, "deleted ipv4 address";
		"addr" => %ipv4,
		"port" => port)
        })
        .inspect_err(|e| {
            error!(s.log, "failed to delete ipv4 address";
		"addr" => %ipv4,
		"port" => port,
		"error" => %e);
        })
}

/// Delete many IPv4 address from the ASIC tables.
pub fn ipv4_delete_many<'a>(
    s: &'a Switch,
    port: u16,
    addrs: impl Iterator<Item = Ipv4Addr> + 'a,
) -> DpdResult<()> {
    for addr in addrs {
        let _ = ipv4_delete(s, port, addr);
    }
    Ok(())
}

fn ipv6_add_work(s: &Switch, port: u16, ipv6: Ipv6Addr) -> DpdResult<()> {
    let (claim_key, drop_key) = match_keys_ipv6(ipv6, port);

    s.table_entry_add(TableType::PortIpv6, &claim_key, &ActionV6::ClaimIpv6)?;
    s.table_entry_add(TableType::PortIpv6, &drop_key, &ActionV6::DropIpv6)
        .inspect_err(|_| {
            endeavour_to_repair(
                s,
                format!("ipv6 address {ipv6} only half added"),
                || s.table_entry_del(TableType::PortIpv6, &claim_key),
            );
        })
}

/// Add one IPv6 address to the ASIC tables.
pub fn ipv6_add(s: &Switch, port: u16, ipv6: Ipv6Addr) -> DpdResult<()> {
    ipv6_add_work(s, port, ipv6)
        .map(|_| {
            info!(s.log, "added ipv6 address";
		"addr" => %ipv6,
		"port" => port)
        })
        .inspect_err(|e| {
            error!(s.log, "failed to add ipv6 address";
		"addr" => %ipv6,
		"port" => port,
		"error" => %e);
        })
}

fn ipv6_delete_work(s: &Switch, port: u16, ipv6: Ipv6Addr) -> DpdResult<()> {
    let (claim_key, drop_key) = match_keys_ipv6(ipv6, port);

    s.table_entry_del(TableType::PortIpv6, &claim_key)?;
    s.table_entry_del(TableType::PortIpv6, &drop_key)
        .inspect_err(|_| {
            endeavour_to_repair(
                s,
                format!("ipv6 address {ipv6} only half deleted"),
                || {
                    s.table_entry_add(
                        TableType::PortIpv6,
                        &claim_key,
                        &ActionV6::ClaimIpv6,
                    )
                },
            );
        })
}

/// Delete one IPv6 address from the ASIC tables.
pub fn ipv6_delete(s: &Switch, port: u16, ipv6: Ipv6Addr) -> DpdResult<()> {
    ipv6_delete_work(s, port, ipv6)
        .map(|_| {
            info!(s.log, "deleted ipv6 address";
		"addr" => %ipv6,
		"port" => port)
        })
        .inspect_err(|e| {
            error!(s.log, "failed to delete ipv6 address";
		"addr" => %ipv6,
		"port" => port,
		"error" => %e);
        })
}

pub fn ipv4_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv4MatchKey, ActionV4>(TableType::PortIpv4)
}

pub fn ipv6_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<Ipv6MatchKey, ActionV6>(TableType::PortIpv6)
}

pub fn ipv4_table_clear(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::PortIpv4)
}

pub fn ipv6_table_clear(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::PortIpv6)
}

pub fn ipv4_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv4MatchKey>(force_sync, TableType::PortIpv4)
}

pub fn ipv6_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<Ipv6MatchKey>(force_sync, TableType::PortIpv6)
}

/// Delete many IPv6 address from the ASIC tables.
pub fn ipv6_delete_many<'a>(
    s: &'a Switch,
    port: u16,
    addrs: impl Iterator<Item = Ipv6Addr> + 'a,
) -> DpdResult<()> {
    for addr in addrs {
        let _ = ipv6_delete(s, port, addr);
    }
    Ok(())
}
