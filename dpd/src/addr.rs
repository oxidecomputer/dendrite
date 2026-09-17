// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::hash_map;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ops::Bound;
use std::ops::RangeBounds;

use slog::debug;

use common::ports::PortId;
use dpd_types::link::LinkId;

use crate::DpdError;
use crate::DpdResult;
use crate::Switch;
use crate::table::port_ip;

/// A helper trait for converting to and from [`std::net::IpAddr`].
pub trait IpAddrLike: Sized + Copy + Into<IpAddr> {
    /// Constructs self from an IP address.
    ///
    /// This must not map IPv4 addresses to v6.
    fn from_ip(addr: &IpAddr) -> Option<&Self>;
}

impl IpAddrLike for Ipv4Addr {
    fn from_ip(addr: &IpAddr) -> Option<&Self> {
        match addr {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }
}

impl IpAddrLike for Ipv6Addr {
    fn from_ip(addr: &IpAddr) -> Option<&Self> {
        match addr {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => Some(v6),
        }
    }
}

impl IpAddrLike for IpAddr {
    fn from_ip(addr: &IpAddr) -> Option<&Self> {
        Some(addr)
    }
}

/// The switch has tables containing single-owner IP addresses. This
/// struct abstracts CRUD operations on these addresses while keeping
/// switch tables consistent.
///
/// Global address registrations are shared among "Loopback" and
/// "Link" owners. Link addresses are scoped to a link lifetime,
/// while loopback addresses belong to the switch itself. This is
/// tracked by the [`AddrOwner`] enum. A namespace "tag" is also exposed
/// to help mutually unaware controllers cooperate when reconciling addresses.
///
/// This upholds the following DPD address invariants:
/// - Unicast addresses have exactly one owner across loopback and all links.
/// - Such an address is in this soft state IFF it's in an asic table.
///
/// # Synchronization
///
/// Any method with a `switch` parameter will lock asic tables.
/// Never hold an asic table lock while calling such a method.
//
// Design choice: A single `HashMap<IpAddr, ...>` is sufficient for
// correctness and better for simplicity. However, most common operations
// operate on a single owner. Caching a reverse `mirror` table
// avoids a full table scan in those cases.
//
// These two tables should uphold the following:
// - An address is in global IFF it's in mirror.
// - An address' owner in global is equal to its owner in mirror.
#[derive(Default, Debug)]
pub struct AddrMap {
    global: HashMap<IpAddr, AddrSpec>,
    mirror: HashMap<AddrOwner, BTreeSet<IpAddr>>,
}

impl AddrMap {
    /// Writes this address to switch tables.
    ///
    /// Errs without mutation if this address already
    /// belongs to another owner/tag or if a switch
    /// operation fails.
    ///
    /// Returns Ok(true) if the address was claimed and written
    /// successfully to tables.
    /// Returns Ok(false) if the owner has already claimed and
    /// written this address.
    pub fn try_set(
        &mut self,
        switch: &Switch,
        addr: IpAddr,
        compare_owner: AddrOwner,
        compare_tag: String,
    ) -> DpdResult<bool> {
        match self.global.entry(addr) {
            hash_map::Entry::Occupied(entry) => {
                Self::compare(
                    addr,
                    entry.get(),
                    &compare_owner,
                    Some(&compare_tag),
                )?;
                assert!(
                    self.mirror
                        .get(&compare_owner)
                        .is_some_and(|addrs| addrs.contains(&addr)),
                    "If an address is in global, then the owner has a copy of that address"
                );
                debug!(
                    switch.log,
                    "Table set: address {addr:?} already exists in soft state with config {:?}",
                    entry.get()
                );
                Ok(false)
            }
            hash_map::Entry::Vacant(slot) => {
                Self::set_asic(switch, &addr, &compare_owner)?;
                slot.insert(AddrSpec {
                    tag: compare_tag,
                    owner: compare_owner,
                });
                let newly_added =
                    self.mirror.entry(compare_owner).or_default().insert(addr);
                assert!(
                    newly_added,
                    "If an entry is new to global, it's new to the mirror"
                );
                Ok(true)
            }
        }
    }

    /// Removes this address from switch tables.
    ///
    /// Errs without mutation if this address belongs to
    /// another owner/tag or if a switch operation fails.
    ///
    /// If tag is `None`, only the owner field is checked
    /// before clearing the entry.
    ///
    /// Returns Ok(true) if the address belonging to this owner/tag
    /// was successfully cleared.
    /// Returns Ok(false) if this entry did not exist on the switch.
    pub fn try_clear(
        &mut self,
        switch: &Switch,
        addr: IpAddr,
        compare_owner: &AddrOwner,
        compare_tag: Option<&str>,
    ) -> DpdResult<bool> {
        let hash_map::Entry::Occupied(entry) = self.global.entry(addr) else {
            assert!(
                self.mirror
                    .get(compare_owner)
                    .is_none_or(|addrs| !addrs.contains(&addr)),
                "If an address is not in global, then it must not be in mirror."
            );
            debug!(
                switch.log,
                "Table clear: address {addr:?} does not exist in soft state"
            );
            return Ok(false);
        };

        Self::compare(addr, entry.get(), compare_owner, compare_tag)?;
        Self::clear_asic(switch, &addr, &entry.get().owner)?;

        let removed = entry.remove_entry();
        let removed_mirror = self
            .mirror
            .get_mut(&removed.1.owner)
            .expect("If an owner was in global, it must be in mirror")
            .remove(&removed.0);
        assert!(
            removed_mirror,
            "If an address was in global, it must have been in mirror"
        );

        Ok(true)
    }

    /// Iterates the addresses belonging to this owner for
    /// which `A::from_ip` returns `Some`.
    pub fn iter_by_owner<'a, A: IpAddrLike + 'a>(
        &'a self,
        owner: &'a AddrOwner,
    ) -> impl Iterator<Item = (&'a A, &'a str)> + 'a {
        self.mirror
            .get(owner)
            .into_iter()
            .flat_map(|addrs| addrs.iter())
            .filter_map(move |addr| {
                let spec = self
                    .global
                    .get(addr)
                    .expect("If an address is in mirror, it must be in global");
                assert_eq!(&spec.owner, owner, "Address owners must concur");
                Some((IpAddrLike::from_ip(addr)?, spec.tag.as_str()))
            })
    }

    /// Iterates the addresses belonging to this owner for
    /// which `A::from_ip` returns `Some`.
    ///
    /// Clears from soft state and asic tables all addresses for
    /// which `keep(A, tag)` returns false.
    ///
    /// If `keep` or an asic operation return error, the scan
    /// quits early with no further modifications.
    pub fn try_retain_by_owner<A: IpAddrLike>(
        &mut self,
        switch: &Switch,
        owner: AddrOwner,
        mut keep: impl FnMut(&A, &str) -> DpdResult<bool>,
    ) -> DpdResult<()> {
        let hash_map::Entry::Occupied(mut mirror) = self.mirror.entry(owner)
        else {
            return Ok(());
        };

        let addrs = mirror.get_mut();
        let mut cursor = Bound::Unbounded;
        while let Some(&addr) = addrs.range((cursor, Bound::Unbounded)).next() {
            cursor = Bound::Excluded(addr);

            let Some(user_addr) = A::from_ip(&addr) else {
                continue;
            };

            let hash_map::Entry::Occupied(global) = self.global.entry(addr)
            else {
                panic!("If an addr is in mirror, then it must be in global");
            };
            let spec = global.get();
            assert_eq!(spec.owner, owner);

            if keep(user_addr, &spec.tag)? {
                continue;
            }

            Self::clear_asic(switch, &addr, &spec.owner)?;
            addrs.remove(&addr);
            global.remove();
        }

        if addrs.is_empty() {
            mirror.remove();
        }

        Ok(())
    }

    /// Iterates through the tagged addresses within the
    /// given range belonging to this owner.
    pub fn owner_addr_range<'a>(
        &'a self,
        owner: &'a AddrOwner,
        bounds: impl RangeBounds<IpAddr> + 'a,
    ) -> impl Iterator<Item = (&'a IpAddr, &'a str)> + 'a {
        self.mirror
            .get(owner)
            .map(|set| set.range(bounds))
            .into_iter()
            .flatten()
            .map(|addr| {
                let tag = &self
                    .global
                    .get(addr)
                    .expect("If an address is in mirror, it must be in global")
                    .tag;
                (addr, tag.as_str())
            })
    }

    /// Returns err if the provided tag or owner do not match
    /// the current spec for this address.
    ///
    /// Do not mutate an entry if this fails.
    fn compare(
        addr: IpAddr,
        spec: &AddrSpec,
        owner_filter: &AddrOwner,
        tag_filter: Option<&str>,
    ) -> DpdResult<()> {
        if tag_filter.is_some_and(|t| t != spec.tag) {
            return Err(DpdError::AddrTagConflict {
                addr,
                tag: spec.tag.clone(),
            });
        }

        if owner_filter != &spec.owner {
            return Err(DpdError::AddrOwnerConflict {
                addr,
                owner: spec.owner,
            });
        }

        Ok(())
    }

    /// Adds this entry in the corresponding asic table.
    ///
    /// If the entry already exists, it is updated.
    /// Returns Ok if the entry was added or updated.
    fn set_asic(
        switch: &Switch,
        addr: &IpAddr,
        owner: &AddrOwner,
    ) -> DpdResult<()> {
        match (addr, owner) {
            (IpAddr::V4(v4), AddrOwner::Link { port_id, link_id }) => {
                let asic_id =
                    switch.port_link_to_asic_id(*port_id, *link_id)?;
                port_ip::ipv4_set(switch, asic_id, *v4)
            }
            (IpAddr::V4(v4), AddrOwner::Loopback) => {
                port_ip::loopback_ipv4_set(switch, *v4)
            }
            (IpAddr::V6(v6), AddrOwner::Link { port_id, link_id }) => {
                let asic_id =
                    switch.port_link_to_asic_id(*port_id, *link_id)?;
                port_ip::ipv6_set(switch, asic_id, *v6)
            }
            (IpAddr::V6(v6), AddrOwner::Loopback) => {
                port_ip::loopback_ipv6_set(switch, *v6)
            }
        }
    }

    /// Removes this entry from the corresponding asic table.
    ///
    /// Returns Ok if the entry was cleared or was not found.
    fn clear_asic(
        switch: &Switch,
        addr: &IpAddr,
        owner: &AddrOwner,
    ) -> DpdResult<()> {
        match (addr, owner) {
            (IpAddr::V4(v4), AddrOwner::Link { port_id, link_id }) => {
                let asic_id =
                    switch.port_link_to_asic_id(*port_id, *link_id)?;
                port_ip::ipv4_clear(switch, asic_id, *v4)
            }
            (IpAddr::V4(v4), AddrOwner::Loopback) => {
                port_ip::loopback_ipv4_clear(switch, *v4)
            }
            (IpAddr::V6(v6), AddrOwner::Link { port_id, link_id }) => {
                let asic_id =
                    switch.port_link_to_asic_id(*port_id, *link_id)?;
                port_ip::ipv6_clear(switch, asic_id, *v6)
            }
            (IpAddr::V6(v6), AddrOwner::Loopback) => {
                port_ip::loopback_ipv6_clear(switch, *v6)
            }
        }
    }
}

/// The owner of a globally-tracked IP address.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum AddrOwner {
    Loopback,
    Link { port_id: PortId, link_id: LinkId },
}

/// Metadata attached to a registered address.
/// Mostly used to determine ownership.
#[derive(PartialEq, Eq, Debug)]
struct AddrSpec {
    owner: AddrOwner,
    tag: String,
}
