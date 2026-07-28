// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Multi-owner tracking for the IP addresses resident on a link.
//!
//! Every address assigned to a link is a shared, refcounted resource: it is
//! programmed into the ASIC once, but may be claimed by multiple clients
//! ("owners"), each identified by a [`Tag`] such as `"omicron"`,
//! `"tfportd"`, or `"cli"`.  [`OwnedAddrs`] maintains the mapping from
//! address to its owner set while enforcing this invariant:
//!
//! > key present <=> owner set non-empty <=> ASIC entry programmed
//!
//! The inner map is private; all mutation goes through methods that take the
//! ASIC operation as a closure and only update the map when that operation
//! succeeds (or when no ASIC operation is required).  ASIC table entries are
//! programmed when the first owner attaches and released when the last owner
//! detaches.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Bound;

use dpd_types::tag::Tag;

use crate::DpdError;

/// The successful outcomes of [`OwnedAddrs::attach`].
///
/// A repeated claim is a success (attach has ensure semantics), but the
/// distinction is reported so that API versions predating address ownership
/// can still present it as a conflict.
#[derive(Debug, PartialEq, Eq)]
pub enum Claimed {
    /// The address was not resident: the ASIC entry was programmed and the
    /// owner recorded as the first owner.
    Programmed,
    /// The address was already resident: the owner was added as an
    /// additional owner.  No ASIC operation was performed.
    CoOwner,
    /// The owner already held a claim on this address; nothing changed.
    AlreadyOwned,
}

/// The successful outcomes of [`OwnedAddrs::detach`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Detached {
    /// The owner was the last one: the ASIC entry was released and the
    /// address removed.
    Released,
    /// Other owners remain: only this owner's claim was removed.  No ASIC
    /// operation was performed.
    OwnerRemoved,
}

/// Why [`OwnedAddrs::detach`] failed.
#[derive(Debug)]
pub(crate) enum DetachError {
    /// The address is not resident on the link.
    NotResident,
    /// The address is resident, but the owner is not among its owners.
    NotOwner,
    /// Releasing the ASIC entry failed; the map is unchanged.
    Asic(DpdError),
}

/// The set of addresses resident on a link, keyed by address, each carrying
/// its non-empty set of owners.
#[derive(Debug, Default)]
pub(crate) struct OwnedAddrs<A> {
    addrs: BTreeMap<A, BTreeSet<Tag>>,
}

impl<A: Copy + Ord> OwnedAddrs<A> {
    pub fn new() -> Self {
        Self { addrs: BTreeMap::new() }
    }

    /// Claim ownership of `addr` for `owner`.
    ///
    /// If the address is not resident, `program` is invoked to create the
    /// ASIC entry; the address is recorded only if it succeeds.  If the
    /// address is already resident under other owners, this owner is added
    /// as a co-owner without touching the ASIC.  A claim the owner already
    /// holds is reported as [`Claimed::AlreadyOwned`] and changes nothing.
    pub fn attach(
        &mut self,
        addr: A,
        owner: &Tag,
        program: impl FnOnce() -> Result<(), DpdError>,
    ) -> Result<Claimed, DpdError> {
        match self.addrs.get_mut(&addr) {
            Some(owners) => {
                if owners.insert(owner.clone()) {
                    Ok(Claimed::CoOwner)
                } else {
                    Ok(Claimed::AlreadyOwned)
                }
            }
            None => {
                program()?;
                self.addrs.insert(addr, BTreeSet::from([owner.clone()]));
                Ok(Claimed::Programmed)
            }
        }
    }

    /// Release `owner`'s claim on `addr`.
    ///
    /// If this is the last claim, `release` is invoked to remove the ASIC
    /// entry; the address is removed only if it succeeds.  Otherwise only
    /// this owner's claim is dropped.
    pub fn detach(
        &mut self,
        addr: A,
        owner: &Tag,
        release: impl FnOnce() -> Result<(), DpdError>,
    ) -> Result<Detached, DetachError> {
        let Some(owners) = self.addrs.get_mut(&addr) else {
            return Err(DetachError::NotResident);
        };
        if !owners.contains(owner) {
            return Err(DetachError::NotOwner);
        }
        if owners.len() == 1 {
            release().map_err(DetachError::Asic)?;
            self.addrs.remove(&addr);
            Ok(Detached::Released)
        } else {
            owners.remove(owner);
            Ok(Detached::OwnerRemoved)
        }
    }

    /// Release `addr` regardless of who owns it, returning the owner set it
    /// had so the caller can restore it on rollback.
    ///
    /// `release` is invoked to remove the ASIC entry; the address is removed
    /// only if it succeeds.
    pub fn force_release(
        &mut self,
        addr: A,
        release: impl FnOnce() -> Result<(), DpdError>,
    ) -> Result<BTreeSet<Tag>, DetachError> {
        if !self.addrs.contains_key(&addr) {
            return Err(DetachError::NotResident);
        }
        release().map_err(DetachError::Asic)?;
        // Presence was checked above and we hold &mut self, so this cannot
        // miss; NotResident keeps the error path total without panicking.
        self.addrs.remove(&addr).ok_or(DetachError::NotResident)
    }

    /// Restore `addr` with the given owner set, programming the ASIC entry if
    /// the address is not already resident.  Used to unwind a `detach` or
    /// `force_release` when a transaction rolls back: an existing owner set
    /// is merged rather than replaced.
    ///
    /// An empty `owners` set is rejected, since recording it would violate
    /// the map invariant.
    pub fn restore(
        &mut self,
        addr: A,
        owners: BTreeSet<Tag>,
        program: impl FnOnce() -> Result<(), DpdError>,
    ) -> Result<(), DpdError> {
        if owners.is_empty() {
            return Err(DpdError::Invalid(
                "cannot restore an address with no owners".to_string(),
            ));
        }
        match self.addrs.get_mut(&addr) {
            Some(existing) => {
                existing.extend(owners);
                Ok(())
            }
            None => {
                program()?;
                self.addrs.insert(addr, owners);
                Ok(())
            }
        }
    }

    /// True if `addr` is resident on the link.
    pub fn contains(&self, addr: &A) -> bool {
        self.addrs.contains_key(addr)
    }

    /// The owner set of `addr`, if resident.
    #[cfg(test)]
    pub fn owners(&self, addr: &A) -> Option<&BTreeSet<Tag>> {
        self.addrs.get(addr)
    }

    /// Iterate over all resident addresses and their owner sets, in address
    /// order.
    pub fn iter(&self) -> impl Iterator<Item = (&A, &BTreeSet<Tag>)> {
        self.addrs.iter()
    }

    /// Iterate over all resident addresses, in address order.
    pub fn addrs(&self) -> impl Iterator<Item = A> + '_ {
        self.addrs.keys().copied()
    }

    /// Iterate over the addresses owned by `owner`, in address order.
    pub fn owned_by<'a>(
        &'a self,
        owner: &'a Tag,
    ) -> impl Iterator<Item = A> + 'a {
        self.addrs
            .iter()
            .filter(move |(_, owners)| owners.contains(owner))
            .map(|(addr, _)| *addr)
    }

    /// Iterate over resident addresses strictly greater than `after` (or all
    /// addresses when `after` is `None`), in address order.  Used for
    /// pagination.
    pub fn iter_after(
        &self,
        after: Option<A>,
    ) -> impl Iterator<Item = (&A, &BTreeSet<Tag>)> {
        let lower = match after {
            Some(a) => Bound::Excluded(a),
            None => Bound::Unbounded,
        };
        self.addrs.range((lower, Bound::Unbounded))
    }

    /// True if no addresses are resident.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::str::FromStr;

    /// Construct a tag for tests.
    fn t(s: &str) -> Tag {
        Tag::from_str(s).unwrap()
    }

    /// A stand-in for the ASIC table: tracks which addresses have a
    /// programmed entry and enforces that programming is never asked to
    /// duplicate an entry nor releasing asked to remove a missing one.
    #[derive(Default)]
    struct FakeAsic(RefCell<BTreeSet<u32>>);

    impl FakeAsic {
        fn program(&self, addr: u32) -> impl FnOnce() -> Result<(), DpdError> {
            move || {
                assert!(
                    self.0.borrow_mut().insert(addr),
                    "asked to program an already-programmed entry"
                );
                Ok(())
            }
        }

        fn release(&self, addr: u32) -> impl FnOnce() -> Result<(), DpdError> {
            move || {
                assert!(
                    self.0.borrow_mut().remove(&addr),
                    "asked to release an entry that is not programmed"
                );
                Ok(())
            }
        }

        fn fail(&self) -> impl FnOnce() -> Result<(), DpdError> {
            || Err(DpdError::Invalid("injected asic failure".to_string()))
        }

        fn programmed(&self, addr: u32) -> bool {
            self.0.borrow().contains(&addr)
        }
    }

    /// Check the central invariant: an address is in the map iff its owner
    /// set is non-empty iff its ASIC entry is programmed.
    fn check_invariant(map: &OwnedAddrs<u32>, asic: &FakeAsic) {
        for (addr, owners) in map.iter() {
            assert!(!owners.is_empty(), "resident address with no owners");
            assert!(asic.programmed(*addr), "resident address not programmed");
        }
        for addr in asic.0.borrow().iter() {
            assert!(map.contains(addr), "programmed entry not in the map");
        }
    }

    #[test]
    fn attach_detach_lifecycle() {
        let asic = FakeAsic::default();
        let mut map = OwnedAddrs::new();

        // First owner programs the ASIC.
        assert_eq!(
            map.attach(1, &t("a"), asic.program(1)).unwrap(),
            Claimed::Programmed
        );
        check_invariant(&map, &asic);

        // Second owner rides along without an ASIC operation.
        assert_eq!(
            map.attach(1, &t("b"), asic.fail()).unwrap(),
            Claimed::CoOwner
        );
        assert_eq!(map.owners(&1).unwrap().len(), 2);
        check_invariant(&map, &asic);

        // Same owner again is an idempotent no-op, and changes nothing.
        assert_eq!(
            map.attach(1, &t("a"), asic.fail()).unwrap(),
            Claimed::AlreadyOwned
        );
        assert_eq!(map.owners(&1).unwrap().len(), 2);
        check_invariant(&map, &asic);

        // Detaching a non-last owner leaves the entry programmed.
        assert_eq!(
            map.detach(1, &t("a"), asic.fail()).unwrap(),
            Detached::OwnerRemoved
        );
        assert!(asic.programmed(1));
        check_invariant(&map, &asic);

        // Detaching the last owner releases the entry.
        assert_eq!(
            map.detach(1, &t("b"), asic.release(1)).unwrap(),
            Detached::Released
        );
        assert!(!asic.programmed(1));
        assert!(map.is_empty());
        check_invariant(&map, &asic);
    }

    #[test]
    fn detach_guards() {
        let asic = FakeAsic::default();
        let mut map = OwnedAddrs::new();
        map.attach(1, &t("a"), asic.program(1)).unwrap();

        // An owner without a claim cannot detach the address.
        assert!(matches!(
            map.detach(1, &t("b"), asic.fail()),
            Err(DetachError::NotOwner)
        ));
        assert!(map.contains(&1));

        // A non-resident address cannot be detached.
        assert!(matches!(
            map.detach(2, &t("a"), asic.fail()),
            Err(DetachError::NotResident)
        ));
        check_invariant(&map, &asic);
    }

    #[test]
    fn asic_failure_leaves_map_unchanged() {
        let asic = FakeAsic::default();
        let mut map = OwnedAddrs::new();

        // Failed program: address not recorded.
        assert!(map.attach(1, &t("a"), asic.fail()).is_err());
        assert!(map.is_empty());

        // Failed release: address and owner retained.
        map.attach(1, &t("a"), asic.program(1)).unwrap();
        assert!(matches!(
            map.detach(1, &t("a"), asic.fail()),
            Err(DetachError::Asic(_))
        ));
        assert!(map.owners(&1).unwrap().contains(&t("a")));
        check_invariant(&map, &asic);
    }

    #[test]
    fn force_release_and_restore() {
        let asic = FakeAsic::default();
        let mut map = OwnedAddrs::new();
        map.attach(1, &t("a"), asic.program(1)).unwrap();
        map.attach(1, &t("b"), asic.fail()).unwrap();

        // Force-release ignores ownership and returns the owner set.
        let owners = map.force_release(1, asic.release(1)).unwrap();
        assert_eq!(owners, BTreeSet::from([t("a"), t("b")]));
        assert!(map.is_empty());
        check_invariant(&map, &asic);

        // Restore rebuilds the complete owner set.
        map.restore(1, owners.clone(), asic.program(1)).unwrap();
        assert_eq!(map.owners(&1), Some(&owners));
        check_invariant(&map, &asic);

        // Restoring on top of a resident address merges owner sets.
        map.restore(1, BTreeSet::from([t("c")]), asic.fail()).unwrap();
        assert_eq!(map.owners(&1).unwrap().len(), 3);
        check_invariant(&map, &asic);

        // An empty owner set may not be restored.
        assert!(map.restore(2, BTreeSet::new(), asic.fail()).is_err());
        check_invariant(&map, &asic);
    }

    #[test]
    fn owner_scoped_views() {
        let asic = FakeAsic::default();
        let mut map = OwnedAddrs::new();
        map.attach(1, &t("a"), asic.program(1)).unwrap();
        map.attach(2, &t("b"), asic.program(2)).unwrap();
        map.attach(2, &t("a"), asic.fail()).unwrap();
        map.attach(3, &t("b"), asic.program(3)).unwrap();

        assert_eq!(map.owned_by(&t("a")).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(map.owned_by(&t("b")).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(map.owned_by(&t("c")).count(), 0);

        // Pagination sees every address exactly once, regardless of owners.
        assert_eq!(
            map.iter_after(Some(1)).map(|(a, _)| *a).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(map.iter_after(None).count(), 3);
    }
}
