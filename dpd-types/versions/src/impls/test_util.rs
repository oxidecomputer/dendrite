// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Result comparison and serde round-trip checks for the property tests in
//! [`super::mcast`] and [`super::network`].

use std::fmt::Debug;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Shrink 256 generated value trees until `simplify()` returns false,
/// evaluating each value along the way.
///
/// This uses a deterministic runner, with shrinking being used here to
/// exercise lower range bounds and earlier union arms.
///
/// Calling `current()` reruns each mapping and its checks.
pub(crate) fn shrink_fully<S: Strategy>(strategy: S) {
    let mut runner = TestRunner::deterministic();
    for _ in 0..256 {
        let mut tree = strategy.new_tree(&mut runner).expect("new value tree");
        loop {
            let _ = tree.current();
            if !tree.simplify() {
                break;
            }
        }
    }
}

/// Discard the success value of `res`, keeping the error for comparison.
pub(crate) fn outcome<T, E>(res: &Result<T, E>) -> Result<(), &E> {
    res.as_ref().map(drop)
}

/// Deserialize `T` from the JSON encoding of `candidate`, checking that an
/// accepted value re-serializes to the same JSON and returning its projection
/// under `project`.
///
/// # Errors
///
/// Returns a [`TestCaseError`] if an accepted value does not re-serialize to
/// the original JSON.
pub(crate) fn json_round_trip<T, V>(
    candidate: &impl Serialize,
    project: impl Fn(&T) -> V,
) -> Result<Option<V>, TestCaseError>
where
    T: Serialize + DeserializeOwned + Debug,
{
    let json = serde_json::to_value(candidate).expect("candidate serializes");
    let Ok(decoded) = serde_json::from_value::<T>(json.clone()) else {
        return Ok(None);
    };
    let reencoded =
        serde_json::to_value(&decoded).expect("decoded value serializes");
    prop_assert_eq!(&reencoded, &json, "{:?} does not round-trip", decoded);
    Ok(Some(project(&decoded)))
}
