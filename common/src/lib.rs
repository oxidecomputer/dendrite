// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::sync::Once;
use std::time::Duration;
use std::time::Instant;

pub mod counters;
pub mod logging;
pub mod nat;
pub mod network;
pub mod ports;

#[cfg(target_os = "illumos")]
pub mod illumos;
mod smf;

pub use smf::{is_smf_active, SmfError, SmfResult};

/// The default port on which the Dendrite API server listens.
pub const DEFAULT_DPD_PORT: u16 = 12224;

/// The http error code used when a rollback failure occurs.
pub const ROLLBACK_FAILURE_ERROR_CODE: &str = "rollback failure";

/// Given two arrays, return two vectors containing only the unique items from each array.
pub fn purge_common<T>(a: &[T], b: &[T]) -> (Vec<T>, Vec<T>)
where
    T: std::cmp::Ord + std::clone::Clone,
{
    let set_a = BTreeSet::from_iter(a.to_vec());
    let set_b = BTreeSet::from_iter(b.to_vec());
    let common: BTreeSet<T> = set_a.intersection(&set_b).cloned().collect();

    (
        a.iter().filter(|e| !common.contains(e)).cloned().collect(),
        b.iter().filter(|e| !common.contains(e)).cloned().collect(),
    )
}

#[test]
fn test_purge() {
    use std::net::Ipv4Addr;

    let a = vec!["a", "b", "c", "d"];
    let b = vec!["c", "d", "e", "f"];
    let (mut unique_a, mut unique_b) = purge_common(&a, &b);
    unique_a.sort();
    unique_b.sort();
    assert_eq!(unique_a, vec!["a", "b"]);
    assert_eq!(unique_b, vec!["e", "f"]);

    let a = vec![10, 9, 8, 7, 11, 12, 13];
    let b = vec![12, 9, 7, 4, 6];
    let (mut unique_a, mut unique_b) = purge_common(&a, &b);
    unique_a.sort();
    unique_b.sort();
    assert_eq!(unique_a, vec![8, 10, 11, 13]);
    assert_eq!(unique_b, vec![4, 6]);

    let a = vec!["one", "two", "three", "two", "four", "four"];
    let b = vec!["two", "two", "two", "five"];
    let (mut unique_a, mut unique_b) = purge_common(&a, &b);
    unique_a.sort();
    unique_b.sort();
    assert_eq!(unique_a, vec!["four", "four", "one", "three"]);
    assert_eq!(unique_b, vec!["five"]);

    let a = vec![
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 1, 2),
        Ipv4Addr::new(192, 168, 1, 3),
        Ipv4Addr::new(192, 168, 1, 4),
    ];

    let b = vec![
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 1, 2),
        Ipv4Addr::new(192, 168, 1, 3),
    ];
    let (mut unique_a, mut unique_b) = purge_common(&a, &b);
    unique_a.sort();
    unique_b.sort();
    assert_eq!(unique_a, vec![Ipv4Addr::new(192, 168, 1, 4)]);
    assert_eq!(unique_b, Vec::<Ipv4Addr>::new());
}

/// Return a random interval within a range
pub fn random_interval(min: Duration, max: Duration) -> Duration {
    assert!(min <= max);

    use rand::distributions::Distribution;
    let dist = rand::distributions::Uniform::new(min, max);
    dist.sample(&mut rand::thread_rng())
}

static mut START_OF_DAY: Option<Instant> = None;
static INIT: Once = Once::new();

fn timestamp() -> Duration {
    unsafe {
        INIT.call_once(|| {
            START_OF_DAY = Some(Instant::now());
        });
        Instant::now().duration_since(START_OF_DAY.unwrap())
    }
}
/// Return a timestamp in nanoseconds
pub fn timestamp_ns() -> i64 {
    i64::try_from(timestamp().as_nanos()).unwrap()
}

/// Return a timestamp in milliseconds
pub fn timestamp_ms() -> i64 {
    i64::try_from(timestamp().as_millis()).unwrap()
}
