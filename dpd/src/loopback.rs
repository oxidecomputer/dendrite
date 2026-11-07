// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::addr::RouterIfaceIpAddr;

use crate::addr::AsicAddrIface;
use crate::addr::OptTag;
use crate::types::DpdError;
use crate::{DpdResult, Switch};

/// Add a loopback IPv4 address to the switch.
pub fn set_loopback_addr(
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

/// Clears this loopback address from the switch address table.
///
/// If a tag is provided, the address is only deleted if it belongs
/// to that tag.
///
/// Returns error if the address does not currently exist (under that tag).
pub fn delete_loopback_addr(
    switch: &Switch,
    addr: RouterIfaceIpAddr,
    tag: &OptTag,
) -> DpdResult<()> {
    let cleared = switch.addrs.clear_addr(
        switch,
        AsicAddrIface::Loopback,
        addr.into(),
        tag,
    )?;

    if !cleared {
        return Err(DpdError::NoSuchAddress {
            iface: "loopback".into(),
            address: addr.into(),
        });
    }

    Ok(())
}
