// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Property-based tests for VNI validation.
//!
//! Properties stated with `iff` hold bidirectionally: the implementation
//! accepts an input if and only if the spec does.

use proptest::prelude::*;
use test_strategy::proptest;

use crate::impls::test_util::{json_round_trip, shrink_fully};
use crate::latest::network::{Vni, VniError, VniParseError};
use crate::v1;

const VNI_BOUND: u32 = 1 << 24;

fn spec_vni(value: u32) -> Result<u32, VniError> {
    if value < VNI_BOUND {
        Ok(value)
    } else {
        Err(VniError::OutOfRange { value })
    }
}

fn vni_candidate_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(Vni::MAX_VNI),
        Just(Vni::MAX_VNI + 1),
        Just(u32::MAX),
        0u32..=Vni::MAX_VNI,
        (Vni::MAX_VNI + 1)..=u32::MAX,
    ]
}

fn valid_vni_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0u32), Just(Vni::MAX_VNI), 0u32..=Vni::MAX_VNI]
}

fn vni_string_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[+-]?[0-9]{1,12}",
        Just(String::new()),
        vni_candidate_strategy().prop_map(|value| value.to_string()),
        prop_oneof![
            Just(u64::from(u32::MAX) + 1),
            Just(u64::MAX),
            any::<u64>(),
        ]
        .prop_map(|value| value.to_string()),
    ]
}

fn check_new(
    value: u32,
    new: impl Fn(u32) -> Result<u32, VniError>,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(new(value), spec_vni(value), "{}", value);
    Ok(())
}

fn check_parse(
    input: &str,
    parse: impl Fn(&str) -> Result<u32, VniParseError>,
) -> Result<(), TestCaseError> {
    match (parse(input), input.parse::<u32>()) {
        (Ok(got), Ok(value)) => {
            prop_assert!(value < VNI_BOUND, "{:?} accepted", input);
            prop_assert_eq!(got, value, "{:?}", input);
        }
        (Err(VniParseError::InvalidInt(echo, _)), Err(_)) => {
            prop_assert_eq!(echo, input);
        }
        (
            Err(VniParseError::Value(VniError::OutOfRange { value: got })),
            Ok(value),
        ) => {
            prop_assert!(value >= VNI_BOUND, "{:?} rejected", input);
            prop_assert_eq!(got, value, "{:?}", input);
        }
        (got, want) => {
            return Err(TestCaseError::fail(format!(
                "{input:?}: got {got:?}, u32 parse {want:?}"
            )));
        }
    }
    Ok(())
}

/// Property: `Vni::new` accepts a value iff it fits in 24 bits
#[proptest]
fn prop_vni_new_matches_spec(#[strategy(vni_candidate_strategy())] value: u32) {
    check_new(value, |v| Vni::new(v).map(Vni::as_u32))?;
    check_new(value, |v| v1::network::Vni::new(v).map(|vni| vni.as_u32()))?;
}

/// Property: `Vni` deserialization round-trips to the constructed value
#[proptest]
fn prop_vni_serde_matches_new(
    #[strategy(vni_candidate_strategy())] value: u32,
) {
    prop_assert_eq!(
        json_round_trip(&value, |vni: &Vni| vni.as_u32())?,
        Vni::new(value).ok().map(Vni::as_u32),
        "{}",
        value
    );
    prop_assert_eq!(
        json_round_trip(&value, |vni: &v1::network::Vni| vni.as_u32())?,
        v1::network::Vni::new(value).ok().map(|vni| vni.as_u32()),
        "{}",
        value
    );
}

/// Property: parsing a `Vni` succeeds iff the input parses as a `u32` that
/// fits in 24 bits
#[proptest]
fn prop_vni_from_str_matches_spec(
    #[strategy(vni_string_strategy())] input: String,
) {
    check_parse(&input, |s| s.parse::<Vni>().map(Vni::as_u32))?;
    check_parse(&input, |s| {
        s.parse::<v1::network::Vni>().map(|vni| vni.as_u32())
    })?;
}

/// Property: converting between the v1 and latest `Vni` preserves the value
#[proptest]
fn prop_vni_conversions_preserve_value(
    #[strategy(valid_vni_strategy())] value: u32,
) {
    let v1_vni = v1::network::Vni::new(value).unwrap();
    let latest = Vni::from(v1_vni);
    prop_assert_eq!(latest.as_u32(), value);
    prop_assert_eq!(v1::network::Vni::from(latest).as_u32(), value);
}

/// Property: every `Arbitrary` `Vni` satisfies `spec_vni`
#[proptest]
fn prop_arbitrary_vni_matches_spec(vni: Vni) {
    prop_assert_eq!(spec_vni(vni.as_u32()), Ok(vni.as_u32()));
}

/// The `Arbitrary` `Vni` generator continues producing valid values at each
/// shrink step.
#[test]
fn vni_generator_stays_valid_while_shrinking() {
    shrink_fully(any::<Vni>());
}
