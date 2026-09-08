// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use anyhow::Context;
use serial_test::serial;

use crate::cmd;
use crate::cmd::re;
use crate::common;

/// Sets some but not all tx eq taps on a port.
/// Unspecified taps default to zero.
//
// Aside: I would prefer different semantics, but
// docs/scripts in other repos expect this behavior.
#[test]
#[serial]
#[ignore]
fn set_partial_taps() -> anyhow::Result<()> {
    let port = "rear0";
    let link = "rear0/0";

    common::create_100g_link(port, link).context("link setup failed")?;

    cmd::swadm(format!("link serdes set txeq {link} --main 19"))?;

    cmd::retry(|| {
        cmd::swadm(format!("link serdes get txeq {link}"))?
            .strip(&*re::PARENS)
            .try_expectorate("tx_eq_partial.txt")
    })
}

/// Sets tx eq when all taps on a link are declared.
#[test]
#[serial]
#[ignore]
fn set_all_taps() -> anyhow::Result<()> {
    let port = "rear0";
    let link = "rear0/0";

    common::create_100g_link(port, link).context("link setup failed")?;

    cmd::swadm(format!(
        "link serdes set tx-eq {link} --pre2=-1 --pre1 0 --main 10 --post1=5 --post2 2"
    ))?;

    cmd::retry(|| {
        cmd::swadm(format!("link serdes get txeq {link}"))?
            .strip(&*re::PARENS)
            .try_expectorate("tx_eq_exact.txt")
    })
}
