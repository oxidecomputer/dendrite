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

use aal::AsicId;
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
/// tracked by the [`AsicAddrOwner`] enum. A namespace "tag" is
/// also exposed to help mutually unaware controllers cooperate
/// when reconciling addresses.
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
// ### Design
//
// - A single `HashMap<IpAddr, ...>` is sufficient for
//   correctness and better for simplicity. However, most common
//   operations are scoped to a single owner. Caching a reverse
//   `mirror` table avoids a full map scan in those cases.
// - IPv4 and IPv6 addresses have different tables in the switch, so
//   we could parallelize better by splitting IPv4 and IPv6 soft state
//   behind separate locks. I skipped this to avoid additional
//   complexity, but it's certainly possible if needed.
//
// ### Invariant
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
        owner: AsicAddrOwner,
        compare_tag: String,
    ) -> DpdResult<bool> {
        let owner_id = owner.into();
        match self.global.entry(addr) {
            hash_map::Entry::Occupied(entry) => {
                Self::compare(addr, entry.get(), owner, Some(&compare_tag))?;
                assert!(
                    self.mirror
                        .get(&owner_id)
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
                Self::set_asic(switch, &addr, &owner)?;
                slot.insert(AddrSpec { tag: compare_tag, owner: owner_id });
                let newly_added =
                    self.mirror.entry(owner_id).or_default().insert(addr);
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
        owner: AsicAddrOwner,
        compare_tag: Option<&str>,
    ) -> DpdResult<bool> {
        let hash_map::Entry::Occupied(entry) = self.global.entry(addr) else {
            assert!(
                self.mirror
                    .get(&owner.into())
                    .is_none_or(|addrs| !addrs.contains(&addr)),
                "If an address is not in global, then it must not be in mirror."
            );
            debug!(
                switch.log,
                "Table clear: address {addr:?} does not exist in soft state"
            );
            return Ok(false);
        };

        Self::compare(addr, entry.get(), owner, compare_tag)?;
        Self::clear_asic(switch, &addr, &owner)?;

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
        owner: AsicAddrOwner,
    ) -> impl Iterator<Item = (&'a A, &'a str)> + 'a {
        let owner_id = owner.into();
        self.mirror
            .get(&owner_id)
            .into_iter()
            .flat_map(|addrs| addrs.iter())
            .filter_map(move |addr| {
                let spec = self
                    .global
                    .get(addr)
                    .expect("If an address is in mirror, it must be in global");
                assert_eq!(spec.owner, owner_id, "Address owners must concur");
                Some((IpAddrLike::from_ip(addr)?, spec.tag.as_str()))
            })
    }

    /// Iterates the addresses belonging to this owner for
    /// which `A::from_ip` returns `Some`.
    ///
    /// Clears from soft state and asic tables all addresses for
    /// which `keep(A, tag)` returns false.
    ///
    /// Attempts to clear all matching addresses. On failure, returns
    /// [`DpdError::AddrClear`] with the addresses that could not be deleted.
    pub fn try_retain_by_owner<A: IpAddrLike>(
        &mut self,
        switch: &Switch,
        owner: AsicAddrOwner,
        keep: impl Fn(&A, &str) -> bool,
    ) -> DpdResult<()> {
        let hash_map::Entry::Occupied(mut mirror) =
            self.mirror.entry(owner.into())
        else {
            return Ok(());
        };

        let owner_id = owner.into();
        let addrs = mirror.get_mut();
        let mut errors: Option<Vec<(IpAddr, DpdError)>> = None;
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
            assert_eq!(spec.owner, owner_id);

            if keep(user_addr, &spec.tag) {
                continue;
            }

            match Self::clear_asic(switch, &addr, &owner) {
                Ok(()) => {
                    addrs.remove(&addr);
                    global.remove();
                }
                Err(e) => {
                    errors.get_or_insert_default().push((addr, e));
                }
            }
        }

        if let Some(failed) = errors {
            return Err(DpdError::AddrClear { owner, addrs: failed });
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
        owner: AsicAddrOwner,
        bounds: impl RangeBounds<IpAddr> + 'a,
    ) -> impl Iterator<Item = (&'a IpAddr, &'a str)> + 'a {
        self.mirror
            .get(&owner.into())
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
        owner: AsicAddrOwner,
        tag_filter: Option<&str>,
    ) -> DpdResult<()> {
        if tag_filter.is_some_and(|t| t != spec.tag) {
            return Err(DpdError::AddrTagConflict {
                addr,
                tag: spec.tag.clone(),
            });
        }

        if AddrOwner::from(owner) != spec.owner {
            return Err(DpdError::AddrOwnerConflict { addr, owner });
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
        id: &AsicAddrOwner,
    ) -> DpdResult<()> {
        match (addr, id) {
            (IpAddr::V4(v4), AsicAddrOwner::Link { asic_id, .. }) => {
                port_ip::ipv4_set(switch, *asic_id, *v4)
            }
            (IpAddr::V4(v4), AsicAddrOwner::Loopback) => {
                port_ip::loopback_ipv4_set(switch, *v4)
            }
            (IpAddr::V6(v6), AsicAddrOwner::Link { asic_id, .. }) => {
                port_ip::ipv6_set(switch, *asic_id, *v6)
            }
            (IpAddr::V6(v6), AsicAddrOwner::Loopback) => {
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
        id: &AsicAddrOwner,
    ) -> DpdResult<()> {
        match (addr, id) {
            (IpAddr::V4(v4), AsicAddrOwner::Link { asic_id, .. }) => {
                port_ip::ipv4_clear(switch, *asic_id, *v4)
            }
            (IpAddr::V4(v4), AsicAddrOwner::Loopback) => {
                port_ip::loopback_ipv4_clear(switch, *v4)
            }
            (IpAddr::V6(v6), AsicAddrOwner::Link { asic_id, .. }) => {
                port_ip::ipv6_clear(switch, *asic_id, *v6)
            }
            (IpAddr::V6(v6), AsicAddrOwner::Loopback) => {
                port_ip::loopback_ipv6_clear(switch, *v6)
            }
        }
    }
}

/// Metadata attached to a registered address.
/// Mostly used to determine ownership.
#[derive(PartialEq, Eq, Debug)]
struct AddrSpec {
    owner: AddrOwner,
    tag: String,
}

/// Identifies the owner of an IP address registered on the switch.
///
/// Use [`crate::link::Link::asic_addr_id`] to construct a link ID.
///
/// # Correctness
///
/// The asic_id of a link must be stable across the lifespan of
/// the link. Changing it will yield the switch table equivalent of
/// internally mutating a [`HashMap`] key.
#[derive(Debug, Clone, Copy)]
pub enum AsicAddrOwner {
    Loopback,
    Link { port_id: PortId, link_id: LinkId, asic_id: AsicId },
}

/// The owner of a globally-tracked IP address.
///
/// # Design
///
/// Setting and clearing addresses requires an asic id.
/// We already require [`PortId`] and [`LinkId`], so we
/// could easily derive this from the switch using
/// [`Switch::link_asic_port_id`].
///
/// However, every operation on the switch adds indirection
/// and locking risk. And the caller always knows its asic_id,
/// so this is redundant work.
///
/// Since asic ID is a black box to DPD, I'd rather not make
/// soft state depend on it. So we use [`AsicAddrOwner`] in
/// the API but only store [`AddrOwner`] internally.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum AddrOwner {
    Loopback,
    Link { port_id: PortId, link_id: LinkId },
}

impl crate::link::Link {
    /// Constructs an address ownership ID for this link.
    pub fn asic_addr_id(&self) -> AsicAddrOwner {
        AsicAddrOwner::Link {
            port_id: self.port_id,
            link_id: self.link_id,
            asic_id: self.asic_port_id,
        }
    }
}

impl From<AsicAddrOwner> for AddrOwner {
    fn from(value: AsicAddrOwner) -> Self {
        match value {
            AsicAddrOwner::Loopback => Self::Loopback,
            AsicAddrOwner::Link { port_id, link_id, .. } => {
                Self::Link { port_id, link_id }
            }
        }
    }
}
