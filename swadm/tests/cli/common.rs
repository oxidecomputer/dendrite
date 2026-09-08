// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Common swadm commands shared between multiple tests.

use crate::cmd;

/// Calls `swadm link delete` and loops until seeing a 404.
///
/// Returns error if the link isn't removed before timeout.
pub fn delete_link(link: &str) -> anyhow::Result<()> {
    // This will fail if the link is already gone, which is fine.
    let _ = cmd::swadm(format!("link delete {link}"));

    cmd::retry(|| {
        let e = match cmd::swadm(format!("link get {link}")) {
            Ok(got) => {
                anyhow::bail!("Get cmd on deleted link should fail: {got:?}")
            }
            Err(e) => e,
        };

        cmd::Output::try_from(e)?
            // Remove headers with UUID and timestamp
            .trunc_at("headers:")
            .try_expectorate("delete_link_404.txt")
    })
}

/// Creates the new link and runs a few validations on it.
pub fn create_100g_link(port: &str, link: &str) -> anyhow::Result<()> {
    self::delete_link(link)?;

    cmd::swadm(format!("link create {port} -s 100g --fec rs"))?;
    cmd::swadm(format!("link enable {link}"))?;

    cmd::retry(|| {
        cmd::swadm(format!("link get {link} -v"))?
            .retain_lines(&crate::among!["Port/Link", "State", "Speed"]?)
            .try_expectorate("create_100g_link.txt")
    })
}
