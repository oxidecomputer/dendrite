// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::addr::{AddrMap, AddrOwner};
use crate::{DpdResult, Switch};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// The set of configured loopback addresses on the switch.
#[derive(Default)]
pub struct Loopback {
    /// The global address tracker. Links should clone and use this too.
    pub addrs: Arc<RwLock<AddrMap>>,
}

/// Add a loopback IPv4 address to the switch.
pub fn set_loopback(
    switch: &Switch,
    addr: IpAddr,
    tag: String,
) -> DpdResult<()> {
    switch.loopback.addrs.write().unwrap().try_set(
        switch,
        addr,
        AddrOwner::Loopback,
        tag,
    )?;
    Ok(())
}

pub fn clear_loopback(
    switch: &Switch,
    addr: IpAddr,
    tag: Option<&str>,
) -> DpdResult<()> {
    switch.loopback.addrs.write().unwrap().try_clear(
        switch,
        addr,
        &AddrOwner::Loopback,
        tag,
    )?;
    Ok(())
}
