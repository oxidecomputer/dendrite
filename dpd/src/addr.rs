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
use std::ops::RangeBounds;
use std::sync::RwLock;

use slog::debug;

use aal::AsicId;
use common::ports::PortId;
use dpd_types::link::LinkId;

use crate::DpdError;
use crate::DpdResult;
use crate::Switch;
use crate::table::port_ip;

// TODO::cory: proptest

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

/// A mutex wrapper for [`AddrMap`].
pub type SyncAddrMap = RwLock<AddrMap>;

/// A switch may have many interfaces and many addresses. An
/// address may belong to exactly one interface, and an interface
/// may have many addresses. This struct abstracts CRUD operations
/// on these addresses while keeping switch tables consistent.
///
/// Link addresses are scoped to a link lifetime, while loopback
/// addresses belong to the switch itself. This is tracked by the
/// [`AsicAddrIface`] enum. A namespace "tag" is also exposed to
/// help mutually unaware controllers cooperate when reconciling
/// addresses. Tags act as a reference count, and entries are only
/// cleared from the asic when the last tag releases an address.
///
/// This upholds the following DPD address invariants:
/// - Unicast addresses belong to exactly one interface.
/// - Such an address is in this soft state IFF it's in an asic table.
///
/// # Synchronization
///
/// Any method with a `switch` parameter will lock asic tables.
/// Never hold an asic table lock while calling such a method.
//
// ### Design
//
// - Using only one of the maps in this struct is simpler and sufficient
//   for correctness. This type design was chosen to avoid full-table scans
//   on common operations and to obviously enforce uniqueness constraints.
// - IPv4 and IPv6 addresses have different tables in the switch, so
//   we could parallelize better by splitting IPv4 and IPv6 soft state
//   behind separate locks. I skipped this to avoid additional
//   complexity, but it's certainly possible if needed.
//
// ### Invariant
//
// These two tables should uphold the following:
// - An address is in global IFF it's in mirror.
// - An address' interface in global is equal to its
//   interface in mirror.
#[derive(Default, Debug)]
pub struct AddrMap {
    addr_to_iface: HashMap<IpAddr, AddrSpec>,
    iface_to_addr: HashMap<AddrIface, BTreeSet<IpAddr>>,
}

impl AddrMap {
    /// Writes this address to switch tables.
    ///
    /// Errs without mutation if this address already
    /// belongs to another interface or if a switch
    /// operation fails.
    ///
    /// Return Ok(true) if this registration updated any config
    /// within the switch.
    /// Returns Ok(false) if the interface was already aware of this
    /// registration.
    pub fn try_set(
        &mut self,
        switch: &Switch,
        addr: IpAddr,
        iface: AsicAddrIface,
        tag: String,
    ) -> DpdResult<bool> {
        let iface_id = iface.into();
        match self.addr_to_iface.entry(addr) {
            hash_map::Entry::Occupied(mut addr_entry) => {
                Self::ensure_equal(addr, &iface_id, addr_entry.get())?;
                debug!(
                    switch.log,
                    "Table set: address {addr:?} already exists in soft state with config {:?}",
                    addr_entry.get()
                );
                let new_tag = addr_entry.get_mut().tags.insert(tag);
                assert!(
                    self.iface_to_addr
                        .get(&iface_id)
                        .is_some_and(|addrs| addrs.contains(&addr)),
                    "If an address exists, then the interface has a copy of that address"
                );
                Ok(new_tag)
            }
            hash_map::Entry::Vacant(addr_slot) => {
                Self::set_asic(switch, &addr, &iface)?;
                addr_slot.insert(AddrSpec {
                    interface: iface_id,
                    tags: std::iter::once(tag).collect(),
                });
                let newly_added = self
                    .iface_to_addr
                    .entry(iface_id)
                    .or_default()
                    .insert(addr);
                assert!(
                    newly_added,
                    "If an entry is new to global, it's new to the mirror"
                );
                Ok(true)
            }
        }
    }

    /// Removes this tag's address claim from the interface.
    /// Removes the address if this was the only tag.
    ///
    /// Errs without mutation if this address belongs to
    /// another interface or if a switch operation fails.
    ///
    /// Return Ok(true) if this cleared any config from the switch.
    /// Returns Ok(false) if this entry didn't exist.
    pub fn try_clear(
        &mut self,
        switch: &Switch,
        addr: IpAddr,
        iface: AsicAddrIface,
        compare_tag: Option<&str>,
    ) -> DpdResult<bool> {
        let hash_map::Entry::Occupied(mut addr_entry) =
            self.addr_to_iface.entry(addr)
        else {
            assert!(
                self.iface_to_addr
                    .get(&iface.into())
                    .is_none_or(|addrs| !addrs.contains(&addr)),
                "If an address is not in global, then it must not be in mirror."
            );
            debug!(
                switch.log,
                "Table clear: address {addr:?} does not exist in soft state"
            );
            return Ok(false);
        };

        Self::ensure_equal(addr, &iface.into(), addr_entry.get())?;
        match compare_tag.map(|t| addr_entry.get_mut().tags.take(t)) {
            None => {
                Self::clear_asic(switch, &addr, &iface)?;
            }
            Some(Some(last)) if addr_entry.get().tags.is_empty() => {
                Self::clear_asic(switch, &addr, &iface).inspect_err(|_| {
                    addr_entry.get_mut().tags.insert(last);
                })?;
            }
            Some(Some(_)) => {
                return Ok(true);
            }
            Some(None) => {
                return Ok(false);
            }
        }

        let removed = addr_entry.remove_entry();
        let hash_map::Entry::Occupied(mut iface_entry) =
            self.iface_to_addr.entry(removed.1.interface)
        else {
            panic!("If an addr exists, its interface must exist");
        };
        let removed_mirror = iface_entry.get_mut().remove(&addr);
        assert!(
            removed_mirror,
            "If an addr exists, it must belong to its interface"
        );

        if iface_entry.get().is_empty() {
            iface_entry.remove_entry();
        }

        Ok(true)
    }

    /// Iterates the tagged addresses belonging to this interface
    /// for which `A::from_ip` returns `Some`.
    pub fn iter_by_iface<'a, A: IpAddrLike + 'a>(
        &'a self,
        iface: AsicAddrIface,
    ) -> impl Iterator<Item = (&'a A, &'a BTreeSet<String>)> + 'a {
        let iface_id = iface.into();
        self.iface_to_addr
            .get(&iface_id)
            .into_iter()
            .flat_map(|addrs| addrs.iter())
            .filter_map(move |addr| {
                let spec = self
                    .addr_to_iface
                    .get(addr)
                    .expect("If an address is in mirror, it must be in global");
                assert_eq!(
                    spec.interface, iface_id,
                    "Address owners must concur"
                );
                Some((IpAddrLike::from_ip(addr)?, &spec.tags))
            })
    }

    /// Iterates the addresses belonging to this interface for
    /// which `A::from_ip` returns `Some`.
    ///
    /// Clears all addresses for which `keep(A, tag)` returns false.
    /// There may be multiple `(A, tag)` tuples if an address has more
    /// than one tag.
    ///
    /// Attempts to clear all matching addresses. On failure, returns
    /// [`DpdError::AddrClear`] with the addresses that could not be deleted.
    pub fn try_retain_by_iface<A: IpAddrLike>(
        &mut self,
        switch: &Switch,
        iface: AsicAddrIface,
        keep: impl Fn(&A, &str) -> bool,
    ) -> DpdResult<()> {
        let hash_map::Entry::Occupied(mut iface_entry) =
            self.iface_to_addr.entry(iface.into())
        else {
            return Ok(());
        };

        let mut errors: Option<Vec<_>> = None;
        iface_entry.get_mut().retain(|addr| {
            let Some(user_addr) = A::from_ip(addr) else {
                return true;
            };

            let hash_map::Entry::Occupied(mut addr_entry) =
                self.addr_to_iface.entry(*addr)
            else {
                panic!("Addr/iface must be registered bidirectionally");
            };
            assert_eq!(addr_entry.get().interface, iface.into());

            let backup = addr_entry.get().tags.clone();
            addr_entry.get_mut().tags.retain(|tag| keep(user_addr, tag));

            if !addr_entry.get().tags.is_empty() {
                return true;
            }

            if let Err(e) = Self::clear_asic(switch, addr, &iface) {
                addr_entry.get_mut().tags = backup;
                errors.get_or_insert_default().push((iface, *addr, e));
                return true;
            }

            addr_entry.remove();
            false
        });

        if iface_entry.get().is_empty() {
            iface_entry.remove();
        }

        if let Some(failed) = errors {
            return Err(DpdError::AddrClear(failed));
        }

        Ok(())
    }

    /// Iterates through the tagged addresses within the
    /// given range belonging to this interface.
    pub fn iface_addr_range<'a>(
        &'a self,
        iface: AsicAddrIface,
        bounds: impl RangeBounds<IpAddr> + 'a,
    ) -> impl Iterator<Item = (&'a IpAddr, &'a BTreeSet<String>)> + 'a {
        self.iface_to_addr
            .get(&iface.into())
            .map(|set| set.range(bounds))
            .into_iter()
            .flatten()
            .map(|addr| {
                let tags = &self
                    .addr_to_iface
                    .get(addr)
                    .expect("If an address is in mirror, it must be in global")
                    .tags;
                (addr, tags)
            })
    }

    /// Returns err if the requested and current interface entries do not match.
    ///
    /// Do not mutate an entry if this fails.
    fn ensure_equal(
        addr: IpAddr,
        request: &AddrIface,
        current: &AddrSpec,
    ) -> DpdResult<()> {
        if request == &current.interface {
            return Ok(());
        }

        let interface = match current.interface {
            AddrIface::Loopback => "loopback".into(),
            AddrIface::Link { port_id, link_id } => {
                format!("{port_id}/{link_id}").into()
            }
        };
        Err(DpdError::AddrIfaceConflict { addr, interface })
    }

    /// Adds this entry in the corresponding asic table.
    ///
    /// If the entry already exists, it is updated.
    /// Returns Ok if the entry was added or updated.
    fn set_asic(
        switch: &Switch,
        addr: &IpAddr,
        id: &AsicAddrIface,
    ) -> DpdResult<()> {
        match (addr, id) {
            (IpAddr::V4(v4), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv4_set(switch, *asic_id, *v4)
            }
            (IpAddr::V4(v4), AsicAddrIface::Loopback) => {
                port_ip::loopback_ipv4_set(switch, *v4)
            }
            (IpAddr::V6(v6), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv6_set(switch, *asic_id, *v6)
            }
            (IpAddr::V6(v6), AsicAddrIface::Loopback) => {
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
        id: &AsicAddrIface,
    ) -> DpdResult<()> {
        match (addr, id) {
            (IpAddr::V4(v4), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv4_clear(switch, *asic_id, *v4)
            }
            (IpAddr::V4(v4), AsicAddrIface::Loopback) => {
                port_ip::loopback_ipv4_clear(switch, *v4)
            }
            (IpAddr::V6(v6), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv6_clear(switch, *asic_id, *v6)
            }
            (IpAddr::V6(v6), AsicAddrIface::Loopback) => {
                port_ip::loopback_ipv6_clear(switch, *v6)
            }
        }
    }
}

/// Metadata attached to a registered address.
#[derive(PartialEq, Eq, Debug)]
struct AddrSpec {
    interface: AddrIface,
    tags: BTreeSet<String>,
}

/// The switch entity to which an IP address uniquely belongs.
///
/// Use [`crate::link::Link::asic_addr_id`] to construct a link ID.
/// Loopback has no asic_id.
///
/// # Correctness
///
/// The asic_id of a link must be stable across the lifespan of
/// the link. Changing it will yield the switch table equivalent of
/// internally mutating a [`HashMap`] key.
#[derive(Debug, Clone, Copy)]
pub enum AsicAddrIface {
    Loopback,
    Link { port_id: PortId, link_id: LinkId, asic_id: AsicId },
}

/// The switch entity to which an IP address uniquely belongs.
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
enum AddrIface {
    Loopback,
    Link { port_id: PortId, link_id: LinkId },
}

impl crate::link::Link {
    /// Constructs an address ownership ID for this link.
    pub fn asic_addr_id(&self) -> AsicAddrIface {
        AsicAddrIface::Link {
            port_id: self.port_id,
            link_id: self.link_id,
            asic_id: self.asic_port_id,
        }
    }
}

impl From<AsicAddrIface> for AddrIface {
    fn from(value: AsicAddrIface) -> Self {
        match value {
            AsicAddrIface::Loopback => Self::Loopback,
            AsicAddrIface::Link { port_id, link_id, .. } => {
                Self::Link { port_id, link_id }
            }
        }
    }
}
