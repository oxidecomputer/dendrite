// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

/// This is simple structure for tracking, allocating, and freeing contiguous
/// spans of integers from a pre-defined range.  Currently this is only used for
/// managing the slots in a route_data table.
use std::cmp::Ord;
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::types::DpdError;
use crate::types::DpdResult;

use slog::debug;

/// A Span represents a contiguous range of integers, where the range is closed
/// on the bottom and open on the top.  In other words, a Span{1,4} will include
/// 1, 2, and 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    low: u16,
    high: u16,
}

impl Span {
    /// Create a new Span with the given bounds
    fn new(low: u16, high: u16) -> Self {
        Span { low, high }
    }

    // Return the size of a span
    fn size(&self) -> u16 {
        self.high - self.low
    }

    // Split a span into two smaller spans.  The original span will be truncated
    // at the split point and the returned span will include the split point and
    // everything above it.
    fn split_off(&mut self, split: u16) -> Option<Span> {
        if split >= self.size() {
            None
        } else {
            let new_span = Span::new(self.low + split, self.high);
            self.high = self.low + split;
            Some(new_span)
        }
    }
}

impl PartialOrd for Span {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// In the general case Ord is not well-defined for Spans, as they can be
// overlapping in several different ways.  This implementation produces correct
// results for our specific use case, as we know that spans will be
// non-overlapping.
impl Ord for Span {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.high <= other.low {
            Ordering::Less
        } else if self.low >= other.high {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

/// A FreeMap represents a managed range of integers.  The current
/// implementation assumes that the range starts at 0, but it would be trivial
/// to support arbitrary ranges.
///
/// A FreeMap's creation and initialization are split into two distinct
/// operations, to accomodate dpd's startup requirements.
///
/// The top `reserve_size` slots of the managed range are held aside as a
/// caller-owned scratch region, accessible only via `take_reserve` /
/// `return_reserve`.  They are never handed out by `alloc` and never enter
/// the freelist / recycle bins.
// The total managed range, split into the user-allocatable region and the
// reserve.  Constructed by `maybe_init` once the total table size is known.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    user: Span,
    reserve: Span,
}

// Initialization + reserve ownership rolled into one explicit state.  Replaces
// the prior `Option<Geometry>` + `reserve_in_use: bool` pair, which let
// callers express invalid combinations (reserve_in_use==true on an
// uninitialized FreeMap).  The compiler now enforces that a reserve can only
// be held when the FreeMap is initialized.
enum FreeMapState {
    Uninit,
    Available(Geometry),
    ReserveHeld(Geometry),
}

impl FreeMapState {
    fn geometry(&self) -> Option<Geometry> {
        match self {
            FreeMapState::Uninit => None,
            FreeMapState::Available(g) | FreeMapState::ReserveHeld(g) => {
                Some(*g)
            }
        }
    }
}

pub struct FreeMap {
    // Where debug messages are logged
    log: slog::Logger,
    // Configured reserve size, captured at construction and applied when
    // `maybe_init` computes the `Geometry` inside `state`.
    reserve_size: u16,
    // Initialization + reserve ownership.  See `FreeMapState`.
    state: FreeMapState,
    // Caches of freed ranges, collected by size.  The contents of a bin are not
    // maintained in any deliberate order.
    recycle_bins: BTreeMap<u16, Vec<Span>>,
    // All of the freed ranges that are not included in one of the recycle bins.
    // These ranges are ordered by their offset.
    freelist: Vec<Span>,
}

/// A `#[must_use]` handle representing a planned single-slot release from a
/// caller-owned reservation.  Acquiring a `TailSlot` via `plan_release_last`
/// does not modify FreeMap state; the caller chooses to commit the release
/// via `commit_release` or to drop the handle, leaving the original
/// reservation intact.
#[must_use = "TailSlot must be committed via commit_release or explicitly dropped"]
pub struct TailSlot {
    idx: u16,
}

impl TailSlot {
    pub fn idx(&self) -> u16 {
        self.idx
    }
}

/// A `#[must_use]` handle proving the caller currently owns the FreeMap's
/// reserve region.  Returned by `take_reserve`; consumed by `return_reserve`.
#[must_use = "ReserveHandle must be returned via return_reserve"]
pub struct ReserveHandle {
    base: u16,
}

impl ReserveHandle {
    pub fn base(&self) -> u16 {
        self.base
    }
}

impl FreeMap {
    pub fn new(
        log: &slog::Logger,
        name: impl ToString,
        reserve_size: u16,
    ) -> Self {
        // We can allocate the FreeMap struct immediately, but we can't
        // initialize the freelist until the table metadata has been loaded
        // and we know how big to make it.
        let unit = format!("freemap_{}", name.to_string());
        let log = log.new(slog::o!("unit" => unit));
        debug!(log, "created new freemap");
        FreeMap {
            log,
            reserve_size,
            state: FreeMapState::Uninit,
            recycle_bins: BTreeMap::new(),
            freelist: Vec::new(),
        }
    }

    // Initialize the FreeMap if it hasn't already been initialized.  The
    // user-allocatable pool is `[0, size - reserve_size)`; the reserve sits
    // at `[size - reserve_size, size)`.
    pub fn maybe_init(&mut self, size: u16) {
        if !matches!(self.state, FreeMapState::Uninit) {
            return;
        }
        debug!(
            self.log,
            "initted freemap.  size: {size}, reserve: {}", self.reserve_size
        );
        let user_top = size.saturating_sub(self.reserve_size);
        let geometry = Geometry {
            user: Span::new(0, user_top),
            reserve: Span::new(user_top, size),
        };
        self.state = FreeMapState::Available(geometry);
        self.reset();
    }

    // Create a new freelist and recycle_bins.  This simply throws away any
    // existing data, and it is the caller's responsibility not to free() spans
    // allocated prior to a reset().  No-op if maybe_init has not yet run.
    // A held reserve is implicitly released back to Available.
    pub fn reset(&mut self) {
        let Some(geometry) = self.state.geometry() else {
            return;
        };
        debug!(self.log, "reset freemap");
        self.recycle_bins = BTreeMap::new();
        self.freelist = vec![geometry.user];
        self.state = FreeMapState::Available(geometry);
    }

    // Allocate a range of the given size.  On success, this call returns the
    // start of the allocated range.
    //
    // We first look for a recycled span of the desired size.  We then look
    // through the freelist for any range large enough to satisfy the
    // allocation.  If we still haven't found a range, we move all of the data
    // from the recycle_bins back into the freemap, and coalesce any adjacent
    // ranges.  If we still can't find a range large enough, we return an Error
    // to the caller.
    pub fn alloc(
        &mut self,
        slots: impl std::convert::Into<u16>,
    ) -> DpdResult<u16> {
        let slots: u16 = slots.into();
        // If we already have a span of the right size available, return it
        if let Some(bin) = self.recycle_bins.get_mut(&slots) {
            let span = bin.pop().expect("found an empty bin");
            if bin.is_empty() {
                let _ = self.recycle_bins.remove(&slots);
            }
            #[cfg(not(test))]
            slog::trace!(self.log, "allocated {span:?} from recycle bin");
            return Ok(span.low);
        }

        let mut found = None;
        while found.is_none() {
            // Look for an available span in the free pool.  Ideally we will find a
            // span of exactly the right size.  If not, we'll use the first span we
            // find that is at least large enough.
            for (idx, span) in self.freelist.iter().enumerate() {
                if span.size() >= slots {
                    found = Some(idx);
                }
                if span.size() == slots {
                    break;
                }
            }
            if found.is_none() && !self.reclaim() {
                return Err(DpdError::TableFull("Route2Index".into()));
            }
        }
        let idx = found.unwrap();
        let mut span = self.freelist.remove(idx);
        if let Some(remainder) = span.split_off(slots) {
            self.freelist.push(remainder);
        }
        #[cfg(not(test))]
        slog::trace!(
            self.log,
            "allocated {span:?} from freelist.  remaining: {:?}",
            self.freelist
        );

        Ok(span.low)
    }

    // reclaim all of the spans from the per-size bins, coalesce them as well as
    // we can, and refill the freelist.  If the reclaim attempt failed to
    // recover any free space, return false.
    fn reclaim(&mut self) -> bool {
        let mut reclaim = Vec::new();

        while let Some((_size, mut spans)) = self.recycle_bins.pop_first() {
            reclaim.append(&mut spans);
        }

        if reclaim.is_empty() {
            #[cfg(not(test))]
            slog::trace!(self.log, "no spans to reclaim");
            return false;
        }

        reclaim.sort();
        let mut idx = 0;
        while idx < reclaim.len() - 1 {
            if reclaim[idx].high == reclaim[idx + 1].low {
                reclaim[idx].high = reclaim[idx + 1].high;
                reclaim.remove(idx + 1);
            } else {
                idx += 1;
            }
        }
        self.freelist = reclaim;
        true
    }

    /// Release a user-pool slot range.  The caller is responsible for
    /// ensuring `idx` lies in the user pool, not the reserve — debug
    /// builds assert this.  Reserve-resident entries are released via
    /// `release_reserve_in_place` or `return_reserve` instead.
    pub fn free(&mut self, idx: u16, size: impl std::convert::Into<u16>) {
        let size: u16 = size.into();
        debug_assert!(
            !self.is_reserve_idx(idx),
            "FreeMap::free called with reserve idx {idx}; \
             use release_reserve_in_place or return_reserve"
        );
        let span = Span::new(idx, idx + size);
        #[cfg(not(test))]
        slog::trace!(self.log, "freeing {span:?}");
        let bin = self.recycle_bins.entry(size).or_default();
        (*bin).push(span);
    }

    /// Return `true` if `idx` falls within the reserve region.  Useful for
    /// the route layer to decide between user-pool and reserve handling
    /// without duplicating the geometry math.
    pub fn is_reserve_idx(&self, idx: u16) -> bool {
        self.state
            .geometry()
            .map(|g| idx >= g.reserve.low && idx < g.reserve.high)
            .unwrap_or(false)
    }

    /// Plan to release the last slot of a caller-owned reservation
    /// `[base, base + len)`, shrinking it to `[base, base + len - 1)`.
    ///
    /// The returned `TailSlot` does not modify FreeMap state.  The caller
    /// commits the release via `commit_release` or drops the handle to
    /// keep the original reservation footprint intact.  Returns `None`
    /// when `len == 0`.
    pub fn plan_release_last(&self, base: u16, len: u16) -> Option<TailSlot> {
        len.checked_sub(1).map(|tail| TailSlot { idx: base + tail })
    }

    /// Commit a previously-planned single-slot release.  Slots in the
    /// user pool are returned to the recycle bin; slots inside the
    /// reserve are no-ops, because the reserve is owned as a unit by
    /// whoever is currently holding it and per-slot accounting inside
    /// the reserve isn't tracked.  The reserve as a whole is released
    /// via `release_reserve_in_place` or `return_reserve`.
    pub fn commit_release(&mut self, slot: TailSlot) {
        if self.is_reserve_idx(slot.idx) {
            return;
        }
        self.free(slot.idx, 1u16);
    }

    /// Take exclusive access to the reserve region.  Returns `None` if the
    /// FreeMap has not been initialized, the reserve is already held, or
    /// the reserve span is empty.
    pub fn take_reserve(&mut self) -> Option<ReserveHandle> {
        let FreeMapState::Available(geometry) = self.state else {
            return None;
        };
        if geometry.reserve.size() == 0 {
            return None;
        }
        self.state = FreeMapState::ReserveHeld(geometry);
        Some(ReserveHandle { base: geometry.reserve.low })
    }

    /// Return a previously-taken `ReserveHandle` to availability.  Consuming
    /// the handle is the proof that the caller owned the reserve; the value
    /// of `_handle.base` is implicit in the FreeMap's geometry.
    pub fn return_reserve(&mut self, _handle: ReserveHandle) {
        self.release_reserve_in_place();
    }

    /// Release the reserve without consuming a handle.  Used by paths that
    /// unwind a route living in the reserve (degraded mode) and so don't
    /// have a `ReserveHandle` to return — for instance `cleanup_route`
    /// freeing a reserve-resident `RouteEntry`.  Panics in debug builds
    /// if the reserve isn't currently held; release in any other state
    /// indicates a bug at the call site.
    pub fn release_reserve_in_place(&mut self) {
        match self.state {
            FreeMapState::ReserveHeld(g) => {
                self.state = FreeMapState::Available(g);
            }
            FreeMapState::Available(_) | FreeMapState::Uninit => {
                debug_assert!(
                    false,
                    "release_reserve_in_place called when reserve is not held"
                );
            }
        }
    }

    #[cfg(test)]
    fn first(&self) -> Option<Span> {
        if self.freelist.is_empty() { None } else { Some(self.freelist[0]) }
    }

    #[cfg(test)]
    fn reserve_in_use(&self) -> bool {
        matches!(self.state, FreeMapState::ReserveHeld(_))
    }
}

#[cfg(test)]
fn new_freemap(size: u16) -> FreeMap {
    new_freemap_with_reserve(size, 0)
}

#[cfg(test)]
fn new_freemap_with_reserve(size: u16, reserve: u16) -> FreeMap {
    let log =
        common::logging::init("test", &None, common::logging::LogFormat::Human)
            .unwrap();
    let log = std::sync::Arc::new(log);
    let mut map = FreeMap::new(&log, "test", reserve);
    map.maybe_init(size);
    map
}

// sanity check the Ord implementation for span
#[test]
fn test_ordering() -> anyhow::Result<()> {
    let a = Span::new(0, 5);
    assert_eq!(a.size(), 5);
    let b = Span::new(5, 10);
    let c = Span::new(10, 15);

    assert!(a < b);
    assert!(a < c);
    assert!(b < c);
    assert!(b > a);
    assert!(c > a);
    assert!(c > b);
    assert_eq!(a, a);
    assert_eq!(b, b);
    assert_eq!(c, c);
    Ok(())
}

// sanity check the span-splitting code
#[test]
fn test_split() -> anyhow::Result<()> {
    // Split [0,1,2,3,4] into [0, 1, 2] and [3, 4]
    let mut a = Span::new(0, 5);
    assert_eq!(a.split_off(10), None);

    let high = a.split_off(3).unwrap();
    let expected_low = Span::new(0, 3);
    let expected_high = Span::new(3, 5);

    assert_eq!(a.size(), 3);
    assert_eq!(high.size(), 2);
    assert_eq!(a, expected_low);
    assert_eq!(high, expected_high);
    Ok(())
}

// Test simple allocation.
#[test]
fn test_basic() -> anyhow::Result<()> {
    let mut map = new_freemap(128);

    // The two allocations should always succeed.  The specific indices
    // returned, and the subsequent contents of the freelist are specific to the
    // current implementation.
    let a = map.alloc(1u16)?;
    assert_eq!(a, 0);
    assert_eq!(map.first().unwrap(), Span::new(1, 128));
    let a = map.alloc(1u16)?;
    assert_eq!(a, 1);
    assert_eq!(map.first().unwrap(), Span::new(2, 128));
    Ok(())
}

// Test freeing post-allocation
#[test]
fn test_free() -> anyhow::Result<()> {
    let mut map = new_freemap(128);

    // The first allocation should be the beginning of the initial span
    let a = map.alloc(1u16)?;
    assert_eq!(a, 0);
    assert_eq!(map.first().unwrap(), Span::new(1, 128));
    map.free(a, 1u16);

    // The second allocation should be satisfied from the recycle bin, giving us
    // back the one we just freed
    let a = map.alloc(1u16)?;
    assert_eq!(a, 0);
    Ok(())
}

#[test]
fn test_span() -> anyhow::Result<()> {
    let mut map = new_freemap(128);

    let a = map.alloc(4u16)?;
    assert_eq!(a, 0);
    let b = map.alloc(5u16)?;
    assert_eq!(b, 4);
    map.free(a, 4u16);
    let a = map.alloc(4u16)?;
    assert_eq!(a, 0);
    Ok(())
}

#[test]
fn test_exhaustion() -> anyhow::Result<()> {
    let mut map = new_freemap(128);

    let mut s = Vec::new();
    for _ in 0..128 {
        let idx = map.alloc(1u16).expect("exhausted pool prematurely");
        s.push(idx);
    }
    map.alloc(1u16).unwrap_err();
    map.free(s.pop().unwrap(), 1u16);
    let z = map.alloc(1u16)?;
    assert_eq!(z, 127);

    Ok(())
}

#[test]
fn test_reclaim() -> anyhow::Result<()> {
    let mut map = new_freemap(128);

    let mut s = Vec::new();
    for _ in 0..128 {
        let idx = map.alloc(1u16).expect("exhausted pool prematurely");
        s.push(idx);
    }
    // The pool is empty, so this should fail
    map.alloc(4u16).unwrap_err();

    // Free the spans in reverse order to screw up the order of the recycle bin
    while let Some(idx) = s.pop() {
        map.free(idx, 1u16);
    }

    // The recycle bin is full, so we should be able to coalesce free space to
    // satisfy this allocation
    let a = map.alloc(4u16).expect("post-reclaim alloc should succeed");
    assert_eq!(a, 0);

    Ok(())
}

// The reserve must be carved out of the top of the managed range and never
// handed out by alloc.
#[test]
fn test_reserve_carved_off() -> anyhow::Result<()> {
    let mut map = new_freemap_with_reserve(16, 4);

    // Exhaust the user pool.  Twelve single-slot allocs should succeed; the
    // thirteenth should fail because the reserve is held aside.
    let mut allocated = Vec::new();
    for _ in 0..12 {
        allocated.push(map.alloc(1u16).expect("user-pool alloc"));
    }
    map.alloc(1u16)
        .expect_err("alloc must not return a reserve slot");

    // No allocated index may fall within the reserve.
    for idx in &allocated {
        assert!(*idx < 12, "alloc handed out reserve slot {idx}");
    }
    Ok(())
}

// take_reserve / return_reserve must enforce a single-owner discipline and
// hand out the correct base offset.
#[test]
fn test_reserve_handle_discipline() -> anyhow::Result<()> {
    let mut map = new_freemap_with_reserve(16, 4);

    let handle = map.take_reserve().expect("reserve is available");
    assert_eq!(handle.base(), 12); // 16 - 4
    assert!(map.reserve_in_use());

    // Second take must fail while the handle is outstanding.
    assert!(map.take_reserve().is_none());

    map.return_reserve(handle);
    assert!(!map.reserve_in_use());

    // After return, take must succeed again.
    let handle = map.take_reserve().expect("reserve is available again");
    map.return_reserve(handle);
    Ok(())
}

// A FreeMap with reserve_size == 0 must report no reserve at all.
#[test]
fn test_reserve_zero_size() {
    let mut map = new_freemap_with_reserve(16, 0);
    assert!(map.take_reserve().is_none());
}

// `release_reserve_in_place` releases a held reserve without consuming a
// handle.  Used by paths that don't own a ReserveHandle (e.g. cleanup_route
// unwinding a degraded-mode entry).
#[test]
fn test_release_reserve_in_place() {
    let mut map = new_freemap_with_reserve(16, 4);
    let _handle = map.take_reserve().expect("reserve is available");
    assert!(map.reserve_in_use());

    map.release_reserve_in_place();
    assert!(!map.reserve_in_use());

    // Reserve is available again.
    let _h2 = map.take_reserve().expect("reserve is available again");
}

// commit_release on a TailSlot that lies within the reserve is a no-op:
// the reserve is owned as a unit, and per-slot accounting inside it is
// not tracked.
#[test]
fn test_commit_release_on_reserve_slot_is_noop() {
    let mut map = new_freemap_with_reserve(16, 4);
    let handle = map.take_reserve().expect("reserve is available");
    let reserve_base = handle.base();

    // Synthesize a TailSlot inside the reserve via plan_release_last.
    let slot = map
        .plan_release_last(reserve_base, 4)
        .expect("plan for reserve span");
    map.commit_release(slot);

    // The reserve stays held (commit_release did NOT release it), and the
    // slot did NOT enter the user-pool recycle bins.
    assert!(map.reserve_in_use());
    for _ in 0..12 {
        let idx = map.alloc(1u16).expect("user-pool alloc");
        assert!(idx < reserve_base, "alloc returned reserve idx {idx}");
    }
    map.return_reserve(handle);
}

// plan_release_last describes the tail slot of a reservation but does not
// alter FreeMap state; dropping the handle leaves the original reservation
// intact.
#[test]
fn test_plan_release_last_dropped_is_abort() -> anyhow::Result<()> {
    let mut map = new_freemap(16);

    // Allocate the entire pool as four 4-slot reservations.
    let a = map.alloc(4u16)?;
    let _b = map.alloc(4u16)?;
    let _c = map.alloc(4u16)?;
    let _d = map.alloc(4u16)?;
    map.alloc(1u16).expect_err("pool is fully allocated");

    // Plan to release the tail of `a` and drop the handle without commit.
    {
        let _slot = map
            .plan_release_last(a, 4)
            .expect("plan_release_last for non-empty reservation");
    }

    // Pool should still report full.
    map.alloc(1u16).expect_err("abort must not change FreeMap state");
    Ok(())
}

// commit_release returns the planned tail slot to the recycle bin so that a
// subsequent alloc(1) returns that exact index.
#[test]
fn test_commit_release_returns_tail() -> anyhow::Result<()> {
    let mut map = new_freemap(16);

    let base = map.alloc(4u16)?;
    let _b = map.alloc(4u16)?;
    let _c = map.alloc(4u16)?;
    let _d = map.alloc(4u16)?;
    map.alloc(1u16).expect_err("pool is full");

    let slot = map.plan_release_last(base, 4).expect("plan");
    let tail_idx = slot.idx();
    assert_eq!(tail_idx, base + 3);

    map.commit_release(slot);

    // The recycle bin now holds exactly one size-1 span at tail_idx.
    let reclaimed = map.alloc(1u16)?;
    assert_eq!(reclaimed, tail_idx);
    Ok(())
}

// plan_release_last with len == 0 returns None: a zero-length reservation
// has no tail.
#[test]
fn test_plan_release_last_zero_len() {
    let map = new_freemap(16);
    assert!(map.plan_release_last(0, 0).is_none());
}
