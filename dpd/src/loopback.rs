// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::addr::AsicAddrOwner;
use crate::{DpdResult, Switch};
use std::net::IpAddr;

/// Add a loopback IPv4 address to the switch.
pub fn set_loopback(
    switch: &Switch,
    addr: IpAddr,
    tag: String,
) -> DpdResult<()> {
    switch.addrs.write().unwrap().try_set(
        switch,
        addr,
        AsicAddrOwner::Loopback,
        tag,
    )?;
    Ok(())
}

pub fn clear_loopback(
    switch: &Switch,
    addr: IpAddr,
    tag: Option<&str>,
) -> DpdResult<()> {
    switch.addrs.write().unwrap().try_clear(
        switch,
        addr,
        AsicAddrOwner::Loopback,
        tag,
    )?;
    Ok(())
}
