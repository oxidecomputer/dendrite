// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use anyhow::bail;
use serial_test::serial;

use crate::cmd;

const ROUTER: &str = "11111111-2222-4333-8444-555555555555";
const DEFAULT_ROUTER: &str = "00000000-0000-0000-0000-000000000000";
const ENDPOINT: &str = "fd00:1122::1";
const PORT: &str = "rear0";
const LINK: &str = "rear0/0";
const SUBNET: &str = "198.51.100.0/24";
const GW: &str = "192.0.2.1";

/// Creates a router, reads it back, and deletes it.
#[test]
#[serial]
#[ignore]
fn router_create_get_delete() -> anyhow::Result<()> {
    cmd::swadm(format!("router create {ROUTER} --endpoint {ENDPOINT}"))?;

    cmd::swadm(format!("router get {ROUTER}"))?
        .try_expectorate("router_get.txt")?;
    cmd::swadm("router list")?
        .retain_lines(&crate::among![ROUTER]?)
        .try_expectorate("router_list.txt")?;

    cmd::swadm(format!("router delete {ROUTER}"))?;

    let mut out: cmd::Output = cmd::swadm(format!("router get {ROUTER}"))
        .expect_err("Get cmd on deleted router should fail")
        .try_into()?;
    // Remove headers with UUID and timestamp
    out.trunc_at("headers:").try_expectorate("router_get_404.txt")
}

/// Adds a route to a router, and checks that it's listed on that router
/// and not on the default routing table.
#[test]
#[serial]
#[ignore]
fn router_route_add() -> anyhow::Result<()> {
    crate::link_apply::delete_link(LINK)?;

    cmd::swadm(format!("link create {PORT} -s 100g --fec rs"))?;
    cmd::swadm(format!("router create {ROUTER} --endpoint {ENDPOINT}"))?;
    cmd::swadm(format!("route add --router-id {ROUTER} {SUBNET} {LINK} {GW}"))?;

    cmd::swadm(format!("route list v4 --router-id {ROUTER}"))?
        .try_expectorate("router_route_list.txt")?;

    let default = cmd::swadm("route list v4")?;
    if default.as_ref().contains(SUBNET) {
        bail!("Route on a router should not be on the default routing table");
    }
    Ok(())
}

/// A route command without `--router-id` acts on the default routing table.
#[test]
#[serial]
#[ignore]
fn route_default_routing_table() -> anyhow::Result<()> {
    crate::link_apply::delete_link(LINK)?;

    cmd::swadm(format!("link create {PORT} -s 100g --fec rs"))?;
    cmd::swadm(format!("route add {SUBNET} {LINK} {GW}"))?;

    cmd::swadm(format!("route get --router-id {DEFAULT_ROUTER} {SUBNET}"))?
        .try_expectorate("route_get_default.txt")?;

    cmd::swadm(format!("route del {SUBNET}"))?;
    Ok(())
}
