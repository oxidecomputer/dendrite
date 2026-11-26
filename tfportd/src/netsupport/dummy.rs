// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Stand-in for `netsupport.rs` on platforms other than illumos, so the rest of
//! tfportd builds there. `init` fails, so tfportd exits at startup.

use std::net::{IpAddr, Ipv6Addr};

use anyhow::anyhow;

pub fn trigger_resolution(_ifindex: u32, _addr: IpAddr) -> Result<(), String> {
    Err("netsupport is only supported on illumos".to_string())
}

pub fn get_link_local(_name: &str) -> Option<Ipv6Addr> {
    None
}

pub fn get_dhcpv6(_ifname: &str) -> anyhow::Result<Vec<Ipv6Addr>> {
    Err(anyhow!("netsupport is only supported on illumos"))
}

pub fn get_ifindex(_name: &str) -> Option<u32> {
    None
}

pub fn fini() {}

pub fn init() -> anyhow::Result<()> {
    Err(anyhow!("netsupport is only supported on illumos"))
}
