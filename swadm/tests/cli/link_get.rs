// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use serial_test::serial;

use crate::cmd;
use crate::common;

/// Creates a broken link and then gets it using
/// both configured and asic variants.
#[test]
#[serial]
#[ignore]
fn get_link() -> anyhow::Result<()> {
    common::delete_link("rear0/0")?;

    // It's arguably a bug that dpd allows this, but creating a link
    // without a FEC parameter will cause an immediate config error.
    // That's an easy way to exercise config/asic divergence.
    cmd::swadm("link create rear0 --speed 100g")?;
    cmd::swadm("link enable rear0/0")?;
    cmd::retry(|| {
        cmd::swadm("link get rear0/0 -v")?
            .try_expectorate("link_get_configured.txt")
    })?;

    let mut e404: cmd::Output = cmd::swadm("link get rear0/0 -v --asic")
        .expect_err("Missing FEC should prevent link creation")
        .try_into()?;
    e404.trunc_at("headers:").try_expectorate("link_get_asic_404.txt")?;

    cmd::swadm("link apply --link rear0/0 --tag test --speed 100g --fec rs")?;
    cmd::retry(|| {
        cmd::swadm("link get rear0/0 -v --asic")?
            .try_expectorate("link_get_asic_success.txt")
    })?;

    Ok(())
}
