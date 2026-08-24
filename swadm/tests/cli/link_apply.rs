// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use anyhow::bail;
use serial_test::serial;

use crate::cmd;
use crate::cmd::re;

const LINK: &str = "rear0/0";

/// Tests the `tx-eq` flag in link settings apply. Verifies that
/// every tap of every lane on the resulting 100g link has
/// the same value.
#[test]
#[serial]
#[ignore]
fn apply_tx_eq_all() -> anyhow::Result<()> {
    const VAL: i32 = -1;

    self::delete_link(LINK)?;

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
            .remove(&*re::PARENS)
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
    self::delete_link(LINK)?;

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
            .remove(&*re::PARENS)
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

/// Calls `swadm link delete` and loops until seeing a 404.
///
/// Returns error if the link isn't removed before timeout.
pub fn delete_link(link: &str) -> anyhow::Result<()> {
    // This will fail if the link is already gone, which is fine.
    let _ = cmd::swadm(format!("link delete {link}"));

    cmd::retry(|| {
        let e = match cmd::swadm(format!("link get {link}")) {
            Ok(got) => bail!("Get cmd on deleted link should fail: {got:?}"),
            Err(e) => e,
        };

        cmd::Output::try_from(e)?
            // Remove headers with UUID and timestamp
            .trunc_at("headers:")
            .try_expectorate("delete_link_404.txt")
    })
}
