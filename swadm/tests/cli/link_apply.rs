// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use serial_test::serial;

use crate::cmd;
use crate::cmd::re;
use crate::common;

const LINK: &str = "rear0/0";

/// Tests the `tx-eq` flag in link settings apply. Verifies that
/// every tap of every lane on the resulting 100g link has
/// the same value.
#[test]
#[serial]
#[ignore]
fn apply_tx_eq_all() -> anyhow::Result<()> {
    const VAL: i32 = -1;

    common::delete_link(LINK)?;

    // See tx_eq tests for an output example.
    cmd::swadm(format!(
        "link apply
            --link {LINK}
            --tag test
            --fec rs
            --speed 100g
            --lane 0
            --tx-eq={VAL}"
    ))?;

    cmd::retry(|| {
        cmd::swadm(format!("link serdes get txeq {LINK}"))?
            .strip(&*re::PARENS)
            .try_expectorate("link_apply_tx_eq_all.txt")
    })
}

/// Tests the individual tx eq flags in link settings apply.
/// If one or more taps is explicitly declared, the other taps
/// should default to zero.
#[test]
#[serial]
#[ignore]
fn apply_tx_eq_custom() -> anyhow::Result<()> {
    common::delete_link(LINK)?;

    cmd::swadm(format!(
        "link apply
            --link {LINK}
            --tag test
            --fec rs
            --speed 100g
            --lane 0
            --main=-22
            --post1 5"
    ))?;

    cmd::retry(|| {
        cmd::swadm(format!("link serdes get txeq {LINK}"))?
            .strip(&*re::PARENS)
            .try_expectorate("link_apply_tx_eq_custom.txt")
    })
}

/// Verifies that the `tx-eq` shorthand and explicit
/// tap flags are mutually exclusive.
#[test]
fn tx_eq_exclusive() -> anyhow::Result<()> {
    let out: cmd::Output = cmd::swadm(format!(
        "link apply
            --link {LINK}
            --tag test
            --fec rs
            --speed 100g
            --lane 0
            --main=-22
            --post1 5
            --tx-eq 1"
    ))
    .expect_err("Flags are exclusive")
    .try_into()?;

    out.try_expectorate("link_apply_tx_eq_exclusive.txt")
}
