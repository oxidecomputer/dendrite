// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::addr::RouterIfaceIpAddr;

use crate::addr::AsicAddrIface;
use crate::addr::OptTag;
use crate::{DpdResult, Switch};

/// Add a loopback IPv4 address to the switch.
pub fn set_loopback(
    switch: &Switch,
    addr: RouterIfaceIpAddr,
    tag: String,
) -> DpdResult<()> {
    switch.addrs.get().write().unwrap().try_set(
        switch,
        addr.into(),
        AsicAddrIface::Loopback,
        tag,
    )?;
    Ok(())
}

pub fn clear_loopback(
    switch: &Switch,
    addr: RouterIfaceIpAddr,
    tag: &OptTag,
) -> DpdResult<()> {
    switch.addrs.get().write().unwrap().try_clear(
        switch,
        addr.into(),
        AsicAddrIface::Loopback,
        tag,
    )?;
    Ok(())
}
