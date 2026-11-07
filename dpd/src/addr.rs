// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! This module defines the mapping by which DPD tracks
//! Address + Interface relations.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::hash_map;
use std::fmt::Display;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::ops::Bound;
use std::ops::RangeBounds;
use std::sync::RwLock;

use slog::debug;

use aal::AsicId;
use common::addr::IpAddrLike;
use common::addr::RouterIfaceIpAddr;
use common::ports::PortId;
use dpd_types::link::LinkId;
use oxnet::UnicastLinkLocalIpv6Addr;

use crate::DpdError;
use crate::DpdResult;
use crate::Switch;
use crate::table::port_ip;

/// A mutex-wrapped [`AddrMap`].
///
/// The fns on this outer struct are convenience wrappers for
/// operations on the inner [`AddrMap`].
///
/// Assume every method other than `get` acquires a lock.
#[derive(Debug, Default)]
pub struct SyncAddrMap(RwLock<AddrMap>);

impl SyncAddrMap {
    /// Returns the inner (lockable) map.
    pub fn get(&self) -> &RwLock<AddrMap> {
        &self.0
    }

    /// Removes all addresses of the declared type belonging to
    /// this interface.
    ///
    /// Only addresses belonging to the named tag are deleted.
    ///
    /// Returns [`DpdError::AddrClear`] if any addresses could not
    /// be deleted.
    pub fn clear_addrs<A: IpAddrLike>(
        &self,
        switch: &Switch,
        iface: AsicAddrIface,
        tag: &OptTag,
    ) -> DpdResult<()> {
        self.0.write().unwrap().try_retain_by_iface::<A>(
            switch,
            iface,
            |_addr, entry_tag| !tag.matches(entry_tag),
        )
    }

    /// Removes the address from switch tables if it exists.
    ///
    /// On success, returns whether anything was actually deleted.
    pub fn clear_addr(
        &self,
        switch: &Switch,
        iface: AsicAddrIface,
        addr: TableIp,
        tag: &OptTag,
    ) -> DpdResult<bool> {
        self.0.write().unwrap().try_clear(switch, addr, iface, tag)
    }
}

/// A switch may have many interfaces and many addresses. An
/// address may belong to exactly one interface, and an interface
/// may have many addresses. This struct abstracts CRUD operations
/// on these addresses while keeping switch tables consistent.
///
/// Link addresses are scoped to a link lifetime, and loopback
/// addresses belong to the switch itself. This is tracked by the
/// [`AsicAddrIface`] enum. A namespace "tag" is also exposed to
/// help mutually unaware controllers cooperate when reconciling
/// addresses. Tags act as a reference count, and entries are only
/// cleared from the asic when the last tag releases an address.
///
/// This upholds the following DPD address invariants:
/// - Unicast addresses belong to exactly one interface.
/// - Such an address is in this soft state IFF it's in an asic table.
/// - A link may have at most one IPv6 link local address.
/// - Otherwise, only [`RouterIfaceIpAddr`] addresses may be registered
///   on an interface.
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
//   we could parallelize better by sharding IPv4 and IPv6 soft state
//   behind separate locks. I skipped this to avoid additional
//   complexity, but it's certainly possible if needed.
//
// ### Invariant
//
// These two tables should uphold the following:
// - An address is in one IFF it's in the other.
// - An address' interface in one is equal to its
//   interface in the other.
#[derive(Default, Debug)]
pub struct AddrMap {
    addr_to_iface: HashMap<TableIp, AddrSpec>,

    // Invariant: If an interface has *a* link local address, it's the
    // first address in this BTreeSet.
    iface_to_addr: HashMap<AddrIface, BTreeSet<TableIp>>,
}

/// An IP address that may be registered in a unicast address table
/// as belonging to an interface.
//
// Don't re-order these variants. The link local invariant depends on
// link local < routable, which is also tested.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum TableIp {
    /// The link local IPv6 address of an interface. Any interface
    /// may have at most one of these.
    LinkLocal(UnicastLinkLocalIpv6Addr),

    /// A valid non-link-local address that may be registered on
    /// an interface. Many of these may exist per interface.
    Router(RouterIfaceIpAddr),
}

impl TableIp {
    /// Attempts to construct a [`TableIp`] or returns `None` if
    /// the address is not supported.
    fn try_new(addr: IpAddr) -> Option<TableIp> {
        if let Some(link_local) = Ipv6Addr::from_ip(addr)
            .and_then(|v6| UnicastLinkLocalIpv6Addr::new(v6).ok())
        {
            return Some(Self::LinkLocal(link_local));
        }
        RouterIfaceIpAddr::try_new(addr).map(TableIp::Router).ok()
    }
}

impl From<TableIp> for IpAddr {
    fn from(value: TableIp) -> Self {
        match value {
            TableIp::LinkLocal(addr) => IpAddr::from(addr),
            TableIp::Router(addr) => *addr.get(),
        }
    }
}

impl From<RouterIfaceIpAddr> for TableIp {
    fn from(value: RouterIfaceIpAddr) -> Self {
        Self::Router(value)
    }
}

impl From<UnicastLinkLocalIpv6Addr> for TableIp {
    fn from(value: UnicastLinkLocalIpv6Addr) -> Self {
        Self::LinkLocal(value)
    }
}

impl Display for TableIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinkLocal(a) => a.fmt(f),
            Self::Router(a) => a.fmt(f),
        }
    }
}

impl TryFrom<&IpAddr> for TableIp {
    type Error = DpdError;

    fn try_from(value: &IpAddr) -> Result<Self, Self::Error> {
        Self::try_new(*value).ok_or_else(|| {
            DpdError::Invalid(format!(
                "Entry {value:?} not permitted in address table"
            ))
        })
    }
}

impl TryFrom<IpAddr> for TableIp {
    type Error = DpdError;

    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&TableIp> for RouterIfaceIpAddr {
    type Error = DpdError;

    fn try_from(value: &TableIp) -> Result<Self, Self::Error> {
        if let TableIp::Router(addr) = value {
            return Ok(*addr);
        }
        Err(DpdError::Invalid(format!("Not a valid router IP addr: {value:?}")))
    }
}

impl AddrMap {
    /// Writes this address to switch tables.
    ///
    /// Errs without mutation if this address already
    /// belongs to another interface or if an asic
    /// operation fails.
    ///
    /// Return Ok(true) if this registration updated any config
    /// within the switch.
    /// Returns Ok(false) if the interface was already aware of this
    /// registration.
    pub fn try_set(
        &mut self,
        switch: &Switch,
        addr: TableIp,
        iface: AsicAddrIface,
        tag: String,
    ) -> DpdResult<bool> {
        let iface_id = iface.into();
        let addr_entry = match self.addr_to_iface.entry(addr) {
            hash_map::Entry::Vacant(empty) => empty,
            hash_map::Entry::Occupied(mut addr_entry) => {
                Self::cmp_iface(addr, &iface_id, addr_entry.get())?;
                debug!(
                    switch.log,
                    "Table set: address {addr:?} already exists in soft state with config {:?}",
                    addr_entry.get()
                );
                let new_tag = addr_entry.get_mut().tags.insert(tag);
                assert!(
                    self.iface_to_addr
                        .get(&iface_id)
                        .is_some_and(|entry| entry.contains(&addr)),
                    "If an address exists, then the interface has a copy of that address"
                );
                return Ok(new_tag);
            }
        };

        let iface_entry = self.iface_to_addr.entry(iface_id);
        if let TableIp::LinkLocal(new_ll) = addr
            && let hash_map::Entry::Occupied(curr) = &iface_entry
            && let Some(old_ll) = Self::link_local(curr.get())
        {
            assert_ne!(
                &new_ll, old_ll,
                "Invariant: Because addr is in iface_to_addr, it should be in addr_to_iface"
            );
            return Err(DpdError::Exists(format!(
                "Cannot set link local address {new_ll:?} to {iface_id:?}. It already has a link local address: {old_ll:?}"
            )));
        }

        Self::set_asic(switch, addr, &iface)?;
        addr_entry.insert(AddrSpec {
            interface: iface_id,
            tags: std::iter::once(tag).collect(),
        });
        let new_addr = iface_entry.or_default().insert(addr);
        assert!(
            new_addr,
            "If an entry is new to the address table, it's new to the interface"
        );
        Ok(true)
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
        addr: TableIp,
        iface: AsicAddrIface,
        compare_tag: &OptTag,
    ) -> DpdResult<bool> {
        let hash_map::Entry::Occupied(mut addr_entry) =
            self.addr_to_iface.entry(addr)
        else {
            assert!(
                self.iface_to_addr
                    .get(&iface.into())
                    .is_none_or(|entry| !entry.contains(&addr)),
                "If an address is not in addr_to_iface, then it must not be in iface_to_addr."
            );
            debug!(
                switch.log,
                "Table clear: address {addr:?} does not exist in soft state"
            );
            return Ok(false);
        };

        Self::cmp_iface(addr, &iface.into(), addr_entry.get())?;
        match compare_tag {
            OptTag::Any => {
                Self::clear_asic(switch, addr, &iface)?;
            }
            OptTag::Tag(t) => {
                let Some(tag) = addr_entry.get_mut().tags.take(&**t) else {
                    return Ok(false);
                };
                if !addr_entry.get().tags.is_empty() {
                    return Ok(true);
                }
                if let Err(e) = Self::clear_asic(switch, addr, &iface) {
                    addr_entry.get_mut().tags.insert(tag);
                    return Err(e);
                }
            }
        }

        let removed = addr_entry.remove_entry();
        let hash_map::Entry::Occupied(mut iface_entry) =
            self.iface_to_addr.entry(removed.1.interface)
        else {
            unreachable!("If an addr exists, its interface must exist");
        };

        let removed = iface_entry.get_mut().remove(&addr);
        assert!(
            removed,
            "Addr was in addr_to_iface, but the reverse map didn't exist"
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
    ) -> impl Iterator<Item = (A, &'a BTreeSet<String>)> + 'a {
        let iface_id = iface.into();
        self.iface_to_addr
            .get(&iface_id)
            .into_iter()
            .flat_map(|addrs| addrs.iter())
            .filter_map(move |addr| {
                let spec = self
                    .addr_to_iface
                    .get(addr)
                    .expect("If an address is in iface_to_addr, it must be in addr_to_iface");
                assert_eq!(spec.interface, iface_id, "Interfaces must concur");
                Some((IpAddrLike::from_ip(IpAddr::from(*addr))?, &spec.tags))
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

        let mut errors = Vec::new();
        iface_entry.get_mut().retain(|addr| {
            let ip = IpAddr::from(*addr);
            let Some(user_addr) = A::from_ip(ip) else {
                return true;
            };

            let hash_map::Entry::Occupied(mut addr_entry) =
                self.addr_to_iface.entry(*addr)
            else {
                panic!("Addr/iface must be registered bidirectionally");
            };
            assert_eq!(addr_entry.get().interface, iface.into());

            let backup = addr_entry.get().tags.clone();
            addr_entry.get_mut().tags.retain(|tag| keep(&user_addr, tag));

            if !addr_entry.get().tags.is_empty() {
                return true;
            }

            if let Err(e) = Self::clear_asic(switch, *addr, &iface) {
                addr_entry.get_mut().tags = backup;
                errors.push((iface, IpAddr::from(*addr), e));
                return true;
            }

            addr_entry.remove();
            false
        });

        if iface_entry.get().is_empty() {
            iface_entry.remove();
        }

        if !errors.is_empty() {
            return Err(DpdError::AddrClear(errors));
        }

        Ok(())
    }

    /// Iterates through the tagged addresses within the
    /// given range belonging to this interface.
    pub fn iface_addr_range<'a>(
        &'a self,
        iface: AsicAddrIface,
        r: impl RangeBounds<IpAddr> + 'a,
    ) -> impl Iterator<Item = (IpAddr, &'a BTreeSet<String>)> + 'a {
        self::map_bound::<_, TableIp>(r.start_bound())
            .and_then(|start| Some((start, self::map_bound(r.end_bound())?)))
            .into_iter()
            .flat_map(move |bounds| {
                self.iface_to_addr
                    .get(&iface.into())
                    .map(|set| set.range(bounds))
                    .into_iter()
                    .flatten()
                    .map(|addr| {
                        let tags = &self
                            .addr_to_iface
                            .get(addr)
                            .expect("If an address is in iface_to_addr, it must be in addr_to_iface")
                            .tags;
                        (IpAddr::from(*addr), tags)
                    })
            })
    }

    /// Retrieves the link local address assigned to this interface
    /// or `None` if no link local has been set.
    pub fn get_link_local(
        &self,
        iface: AsicAddrIface,
    ) -> Option<UnicastLinkLocalIpv6Addr> {
        self.iface_to_addr
            .get(&iface.into())
            .and_then(Self::link_local)
            .copied()
    }

    /// Returns err if the requested and current interface
    /// entries do not match.
    ///
    /// Do not mutate an entry if this fails.
    fn cmp_iface(
        addr: TableIp,
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
        Err(DpdError::AddrIfaceConflict { addr: addr.into(), interface })
    }

    /// Declares this entry in the corresponding asic table.
    /// No error if it already existed.
    fn set_asic(
        switch: &Switch,
        addr: TableIp,
        id: &AsicAddrIface,
    ) -> DpdResult<()> {
        let addr = IpAddr::from(addr);
        match (addr, id) {
            (IpAddr::V4(v4), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv4_set(switch, *asic_id, v4)
            }
            (IpAddr::V4(v4), AsicAddrIface::Loopback) => {
                port_ip::loopback_ipv4_set(switch, v4)
            }
            (IpAddr::V6(v6), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv6_set(switch, *asic_id, v6)
            }
            (IpAddr::V6(v6), AsicAddrIface::Loopback) => {
                port_ip::loopback_ipv6_set(switch, v6)
            }
        }
    }

    /// Removes this entry from the corresponding asic table.
    /// No error if it was not previously present.
    fn clear_asic(
        switch: &Switch,
        addr: TableIp,
        id: &AsicAddrIface,
    ) -> DpdResult<()> {
        let addr = IpAddr::from(addr);
        match (addr, id) {
            (IpAddr::V4(v4), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv4_clear(switch, *asic_id, v4)
            }
            (IpAddr::V4(v4), AsicAddrIface::Loopback) => {
                port_ip::loopback_ipv4_clear(switch, v4)
            }
            (IpAddr::V6(v6), AsicAddrIface::Link { asic_id, .. }) => {
                port_ip::ipv6_clear(switch, *asic_id, v6)
            }
            (IpAddr::V6(v6), AsicAddrIface::Loopback) => {
                port_ip::loopback_ipv6_clear(switch, v6)
            }
        }
    }

    /// Pulls the link local address out of this set or returns None
    /// if there is no link local.
    fn link_local(
        addrs: &BTreeSet<TableIp>,
    ) -> Option<&UnicastLinkLocalIpv6Addr> {
        debug_assert!(
            addrs.iter().skip(1).all(|addr| matches!(addr, TableIp::Router(_))),
            "Invariant: If an interface has a link local, it must be the first in the set"
        );
        if let Some(TableIp::LinkLocal(ll)) = addrs.first() {
            return Some(ll);
        }
        None
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
/// Use [`crate::link::Link::asic_addr_iface`] to construct a link ID.
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
/// soft state depend on it. So we use [`AsicAddrIface`] in
/// the API but only store [`AddrIface`] internally.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum AddrIface {
    Loopback,
    Link { port_id: PortId, link_id: LinkId },
}

/// Clients may use DPD tags to cooperatively namespace CRUD
/// operations and avoid disrupting eachother.
///
/// This type may be used in APIs where tag usage is optional.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptTag<'a> {
    /// The action or result applies only to resources with this tag.
    Tag(Cow<'a, str>),

    /// The action or result applies to this resource regardless of tag(s).
    Any,
}

impl<'a> OptTag<'a> {
    /// Constructs a new [`OptTag`] selector matching only
    /// the given tag string.
    pub const fn exact(tag: &'a str) -> Self {
        Self::Tag(Cow::Borrowed(tag))
    }

    /// Returns true if this tag applies to the given tag str.
    pub fn matches(&self, other: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Tag(tag) => *tag == other,
        }
    }
}

/// Maps a [`Bound`] of type `In` to one of type `Out`.
/// Returns `None` if `TryFrom` fails.
fn map_bound<In, Out>(bound: Bound<In>) -> Option<Bound<Out>>
where
    Out: TryFrom<In>,
{
    match bound {
        Bound::Unbounded => Some(Bound::Unbounded),
        Bound::Included(input) => {
            Some(Bound::Included(Out::try_from(input).ok()?))
        }
        Bound::Excluded(input) => {
            Some(Bound::Excluded(Out::try_from(input).ok()?))
        }
    }
}

impl crate::link::Link {
    /// Constructs an address ownership ID for this link.
    pub fn asic_addr_iface(&self) -> AsicAddrIface {
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

#[cfg(test)]
mod addr_tests {
    use std::collections::BTreeSet;

    use common::addr::RouterIfaceIpAddr;
    use common::test_utils::IpRng;
    use common::test_utils::fname_hash;
    use oxnet::UnicastLinkLocalIpv6Addr;

    use crate::addr::TableIp;

    /// The link local invariant only works if it's ordered ahead
    /// of router addrs. That's guaranteed by rustc, but this verifies
    /// nothing shifts sneakily.
    /// <https://doc.rust-lang.org/std/cmp/trait.Ord.html#derivable>
    #[test]
    fn link_local_sanity_check() -> anyhow::Result<()> {
        let mut addrs = BTreeSet::new();
        let mut rng = IpRng::new(fname_hash!());

        addrs.insert(TableIp::Router(RouterIfaceIpAddr::try_new(
            rng.host_underlay().into(),
        )?));
        addrs.insert(TableIp::LinkLocal(UnicastLinkLocalIpv6Addr::new(
            rng.link_local_ipv6(),
        )?));
        addrs.insert(TableIp::Router(RouterIfaceIpAddr::try_new(
            rng.host_underlay().into(),
        )?));

        assert!(matches!(addrs.first(), Some(TableIp::LinkLocal(_))));
        addrs.pop_last();
        assert!(matches!(addrs.first(), Some(TableIp::LinkLocal(_))));
        addrs.pop_first();
        assert!(matches!(addrs.first(), Some(TableIp::Router(_))));

        Ok(())
    }
}
