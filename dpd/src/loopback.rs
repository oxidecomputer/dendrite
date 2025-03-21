// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use crate::{table, DpdError, DpdResult, Switch};
use aal::AsicError;
use common::ports::{Ipv4Entry, Ipv6Entry};
use slog::debug;
use slog::warn;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The set of configured loopback addresses on the switch.
pub struct LoopbackData {
    pub v4_addrs: BTreeSet<Ipv4Entry>,
    pub v6_addrs: BTreeSet<Ipv6Entry>,
}

/// Initialize loopback data to empty sets of IPv4 and IPv6 addresses.
pub fn init() -> LoopbackData {
    LoopbackData {
        v4_addrs: BTreeSet::new(),
        v6_addrs: BTreeSet::new(),
    }
}

/// Add a loopback IPv4 address to the switch.
pub fn add_loopback_ipv4(switch: &Switch, addr: &Ipv4Entry) -> DpdResult<()> {
    let mut loopback_data = switch.loopback.lock().unwrap();
    if loopback_data.v4_addrs.contains(addr) {
        debug!(switch.log, "loopback entry {} already set", addr.addr);
        return Ok(());
    }
    match table::port_ip::loopback_ipv4_add(switch, addr.addr) {
        Ok(()) => _ = loopback_data.v4_addrs.insert(addr.clone()),
        Err(DpdError::Switch(AsicError::Exists)) => {
            if !loopback_data.v4_addrs.contains(addr) {
                warn!(
                    switch.log,
                    "loopback entry {} was present on ASIC but not in soft state",
                    addr.addr,
                );
                loopback_data.v4_addrs.insert(addr.clone());
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Delete a loopback IPv4 address from the switch.
pub fn delete_loopback_ipv4(switch: &Switch, addr: &Ipv4Addr) -> DpdResult<()> {
    let mut loopback_data = switch.loopback.lock().unwrap();
    let entry = Ipv4Entry {
        addr: *addr,
        tag: "".into(),
    };
    if !loopback_data.v4_addrs.contains(&entry) {
        debug!(switch.log, "loopback entry {} not set", addr);
        return Ok(());
    }
    match table::port_ip::loopback_ipv4_delete(switch, *addr) {
        Ok(()) => _ = loopback_data.v4_addrs.remove(&entry),
        Err(DpdError::Switch(AsicError::Missing(_))) => {
            if loopback_data.v4_addrs.contains(&entry) {
                warn!(
                    switch.log,
                    "loopback entry {} was present in soft state but not on ASIC",
                    addr,
                );
                loopback_data.v4_addrs.remove(&entry);
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Add a loopback IPv6 address to the switch.
pub fn add_loopback_ipv6(switch: &Switch, addr: &Ipv6Entry) -> DpdResult<()> {
    let mut loopback_data = switch.loopback.lock().unwrap();
    if loopback_data.v6_addrs.contains(addr) {
        debug!(switch.log, "loopback entry {} already set", addr.addr);
        return Ok(());
    }

    match table::port_ip::loopback_ipv6_add(switch, addr.addr) {
        Ok(()) => _ = loopback_data.v6_addrs.insert(addr.clone()),
        Err(DpdError::Switch(AsicError::Exists)) => {
            if !loopback_data.v6_addrs.contains(addr) {
                warn!(
                    switch.log,
                    "loopback entry {} was present on ASIC but not in soft state",
                    addr.addr,
                );
                loopback_data.v6_addrs.insert(addr.clone());
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Delete a loopback IPv6 address from the switch.
pub fn delete_loopback_ipv6(switch: &Switch, addr: &Ipv6Addr) -> DpdResult<()> {
    let mut loopback_data = switch.loopback.lock().unwrap();
    let entry = Ipv6Entry {
        addr: *addr,
        tag: "".into(),
    };
    if !loopback_data.v6_addrs.contains(&entry) {
        debug!(switch.log, "loopback entry {} not set", addr);
        return Ok(());
    }

    match table::port_ip::loopback_ipv6_delete(switch, *addr) {
        Ok(()) => _ = loopback_data.v6_addrs.remove(&entry),
        Err(DpdError::Switch(AsicError::Missing(_))) => {
            if loopback_data.v6_addrs.contains(&entry) {
                warn!(
                    switch.log,
                    "loopback entry {} was present in soft state but not on ASIC",
                    addr,
                );
                loopback_data.v6_addrs.remove(&entry);
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}
