// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

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
pub struct FreeMap {
    // Where debug messages are logged
    log: slog::Logger,
    // Has the FreeMap been initialized yet?
    initted: bool,
    // Size of the range being managed
    size: u16,
    // Caches of freed ranges, collected by size.  The contents of a bin are not
    // maintained in any deliberate order.
    recycle_bins: BTreeMap<u16, Vec<Span>>,
    // All of the freed ranges that are not included in one of the recycle bins.
    // These ranges are ordered by their offset.
    freelist: Vec<Span>,
}

impl FreeMap {
    pub fn new(log: &slog::Logger, name: impl ToString) -> Self {
        // We can allocate the FreeMap struct immediately, but we can't
        // initialize the freelist until the table metadata has been loaded
        // and we know how big to make it.
        let unit = format!("freemap_{}", name.to_string());
        let log = log.new(slog::o!("unit" => unit));
        debug!(log, "created new freemap");
        FreeMap {
            log,
            initted: false,
            size: 0,
            recycle_bins: BTreeMap::new(),
            freelist: Vec::new(),
        }
    }

    // Initialize the FreeMap if it hasn't already been initialized
    pub fn maybe_init(&mut self, size: u16) {
        if !self.initted {
            debug!(self.log, "initted freemap.  size: {size}");
            self.initted = true;
            self.size = size;
            self.reset();
        }
    }

    // Create a new freelist and recycle_bins.  This simply throws away any
    // existing data, and it is the caller's responsibility not to free() spans
    // allocated prior to a reset().
    pub fn reset(&mut self) {
        debug!(self.log, "reset freemap");
        self.recycle_bins = BTreeMap::new();
        self.freelist = vec![Span::new(0, self.size)];
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

    pub fn free(&mut self, idx: u16, size: impl std::convert::Into<u16>) {
        let size: u16 = size.into();
        let span = Span::new(idx, idx + size);
        #[cfg(not(test))]
        slog::trace!(self.log, "freeing {span:?}");
        let bin = self.recycle_bins.entry(size).or_default();
        (*bin).push(span);
    }

    #[cfg(test)]
    fn first(&self) -> Option<Span> {
        if self.freelist.is_empty() {
            None
        } else {
            Some(self.freelist[0])
        }
    }
}

#[cfg(test)]
fn new_freemap(size: u16) -> FreeMap {
    let log =
        common::logging::init("test", &None, common::logging::LogFormat::Human)
            .unwrap();
    let log = std::sync::Arc::new(log);
    let mut map = FreeMap::new(&log, "test");
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
