// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::{DpdError, DpdResult, Switch, table};
use aal::AsicError;
use common::ports::{Ipv4Entry, Ipv6Entry};
use dpd_types::route::RouterId;
use slog::debug;
use slog::warn;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

/// The set of configured loopback addresses on the switch.
pub struct LoopbackData {
    pub v4_addrs: BTreeSet<Ipv4Entry>,
    v6_addrs: BTreeMap<Ipv6Addr, Ipv6Claim>,
}

/// Initialize loopback data to empty sets of IPv4 and IPv6 addresses.
pub fn init() -> LoopbackData {
    LoopbackData { v4_addrs: BTreeSet::new(), v6_addrs: BTreeMap::new() }
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
    let entry = Ipv4Entry { addr: *addr, tag: "".into() };
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

/// An address has one owner even when several routers use the same switch.
struct Ipv6Claim {
    entry: Ipv6Entry,
    router_id: RouterId,
}

impl LoopbackData {
    pub fn ipv6_addresses(&self, rid: RouterId) -> Vec<Ipv6Entry> {
        self.v6_addrs
            .values()
            .filter(|claim| claim.router_id == rid)
            .map(|claim| claim.entry.clone())
            .collect()
    }

    fn check_ipv6_owner(
        &self,
        addr: Ipv6Addr,
        rid: RouterId,
    ) -> DpdResult<bool> {
        match self.v6_addrs.get(&addr) {
            Some(claim) if claim.router_id != rid => {
                Err(DpdError::Exists(format!(
                    "IPv6 loopback {addr} belongs to router {}, not {rid}",
                    claim.router_id
                )))
            }
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    fn add_ipv6(
        &mut self,
        addr: &Ipv6Entry,
        rid: RouterId,
        install: impl FnOnce() -> DpdResult<()>,
    ) -> DpdResult<()> {
        if self.check_ipv6_owner(addr.addr, rid)? {
            return Ok(());
        }
        // An existing ASIC entry does not prove who owns it. Do not adopt
        // it into soft state when installation reports Exists.
        install()?;
        self.v6_addrs.insert(
            addr.addr,
            Ipv6Claim { entry: addr.clone(), router_id: rid },
        );
        Ok(())
    }

    fn delete_ipv6(
        &mut self,
        addr: Ipv6Addr,
        rid: RouterId,
        remove: impl FnOnce() -> DpdResult<()>,
    ) -> DpdResult<()> {
        if !self.check_ipv6_owner(addr, rid)? {
            return Ok(());
        }
        match remove() {
            Ok(()) | Err(DpdError::Switch(AsicError::Missing(_))) => {
                self.v6_addrs.remove(&addr);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// Add an IPv6 loopback; another router cannot claim the same address.
pub fn add_loopback_ipv6(
    switch: &Switch,
    addr: &Ipv6Entry,
    rid: RouterId,
) -> DpdResult<()> {
    let mut data = switch.loopback.lock().unwrap();
    data.add_ipv6(addr, rid, || {
        table::port_ip::loopback_ipv6_add(switch, addr.addr, rid)
    })
}

/// Delete an IPv6 loopback only if it belongs to the requesting router.
pub fn delete_loopback_ipv6(
    switch: &Switch,
    addr: &Ipv6Addr,
    rid: RouterId,
) -> DpdResult<()> {
    let mut data = switch.loopback.lock().unwrap();
    data.delete_ipv6(*addr, rid, || {
        table::port_ip::loopback_ipv6_delete(switch, *addr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> Ipv6Entry {
        Ipv6Entry { addr: "fd00::1".parse().unwrap(), tag: "test".into() }
    }

    #[test]
    fn ipv6_claims_enforce_ownership_before_writes() {
        let mut data = init();
        let addr = address();
        data.add_ipv6(&addr, RouterId(2), || Ok(())).unwrap();
        data.add_ipv6(&addr, RouterId(2), || {
            panic!("idempotent add wrote ASIC")
        })
        .unwrap();
        for other in [RouterId(0), RouterId(3)] {
            assert!(matches!(
                data.add_ipv6(&addr, other, || panic!(
                    "conflicting add wrote ASIC"
                )),
                Err(DpdError::Exists(_))
            ));
            assert!(matches!(
                data.delete_ipv6(addr.addr, other, || panic!(
                    "wrong-owner delete wrote ASIC"
                )),
                Err(DpdError::Exists(_))
            ));
            assert!(data.ipv6_addresses(other).is_empty());
        }
        assert_eq!(data.ipv6_addresses(RouterId(2))[0].addr, addr.addr);
        data.delete_ipv6(addr.addr, RouterId(2), || Ok(())).unwrap();
        data.delete_ipv6(addr.addr, RouterId(2), || {
            panic!("absent delete wrote ASIC")
        })
        .unwrap();
        data.add_ipv6(&addr, RouterId(3), || Ok(())).unwrap();
        assert!(data.ipv6_addresses(RouterId(2)).is_empty());
        assert_eq!(data.ipv6_addresses(RouterId(3)).len(), 1);
    }

    #[test]
    fn ipv6_default_claim_is_protected_from_named_routers() {
        let mut data = init();
        let addr = address();
        data.add_ipv6(&addr, RouterId(0), || Ok(())).unwrap();
        assert!(
            data.add_ipv6(&addr, RouterId(2), || panic!("wrote ASIC")).is_err()
        );
        assert!(
            data.delete_ipv6(addr.addr, RouterId(2), || panic!("wrote ASIC"))
                .is_err()
        );
        assert_eq!(data.ipv6_addresses(RouterId(0)).len(), 1);
    }

    #[test]
    fn ipv6_failed_writes_preserve_ownership() {
        let mut data = init();
        let addr = address();
        // Includes restart with an ASIC entry whose owner is unknown.
        assert!(
            data.add_ipv6(&addr, RouterId(2), || Err(DpdError::Switch(
                AsicError::Exists
            )))
            .is_err()
        );
        assert!(data.ipv6_addresses(RouterId(2)).is_empty());
        data.add_ipv6(&addr, RouterId(2), || Ok(())).unwrap();
        assert!(
            data.delete_ipv6(addr.addr, RouterId(2), || Err(DpdError::Exists(
                "injected failure".into()
            )))
            .is_err()
        );
        assert_eq!(data.ipv6_addresses(RouterId(2)).len(), 1);
        data.delete_ipv6(addr.addr, RouterId(2), || {
            Err(DpdError::Switch(AsicError::Missing("already removed".into())))
        })
        .unwrap();
        assert!(data.ipv6_addresses(RouterId(2)).is_empty());
    }
}
