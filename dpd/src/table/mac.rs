// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use slog::error;
use slog::info;

use crate::Switch;
use crate::types::*;
use aal::ActionParse;
use aal::MatchParse;
use aal_macros::ActionParse;
use aal_macros::MatchParse;
use common::network::MacAddr;
use common::table::TableType;
use dpd_types::views;

#[derive(MatchParse, Debug, Hash)]
struct MacMatchKey {
    port: u16,
}

#[derive(ActionParse, Debug)]
enum MacAction {
    #[action_xlate(name = "rewrite")]
    Rewrite { mac: MacAddr },
}

fn mac_set_common(
    s: &Switch,
    type_: TableType,
    port: u16,
    mac: MacAddr,
) -> DpdResult<()> {
    let match_key = MacMatchKey { port };
    let action_data = MacAction::Rewrite { mac };

    match s.table_entry_add(type_, &match_key, &action_data) {
        Ok(_) => {
            info!(s.log, "set mac on {port} in table {type_}: {mac}",);
            Ok(())
        }
        Err(e) => {
            error!(
                s.log,
                "set mac on {port} in table {type_}: {mac} failed: {e:?}",
            );
            Err(e)
        }
    }
}

fn mac_clear_common(s: &Switch, type_: TableType, port: u16) -> DpdResult<()> {
    let match_key = MacMatchKey { port };

    match s.table_entry_del(type_, &match_key) {
        Ok(_) => {
            info!(s.log, "cleared mac on {port} in table {type_}",);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "clear mac on {port} in table {type_} failed: {e:?}",);
            Err(e)
        }
    }
}

/// Add a new entry to the MAC table.
///
/// An error is returned if the entry already exists. Use `mac_update` instead.
pub fn mac_set(s: &Switch, port: u16, mac: MacAddr) -> DpdResult<()> {
    mac_set_common(s, TableType::PortMacAddress, port, mac)
}

/// Remove an entry from the MAC table.
pub fn mac_clear(s: &Switch, port: u16) -> DpdResult<()> {
    mac_clear_common(s, TableType::PortMacAddress, port)
}

pub fn table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MacMatchKey, MacAction>(TableType::PortMacAddress)
}

pub fn counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MacMatchKey>(force_sync, TableType::PortMacAddress)
}

/// Remove all entries from the MAC table.
#[cfg(feature = "tofino_asic")]
pub fn reset(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::PortMacAddress)
}

/// Add a new entry to the MAC table.
///
/// An error is returned if the entry already exists. Use `mac_update` instead.
#[cfg(feature = "multicast")]
pub fn mcast_mac_set(s: &Switch, port: u16, mac: MacAddr) -> DpdResult<()> {
    mac_set_common(s, TableType::PortMacAddressMcast, port, mac)
}

/// Remove an entry from the MAC table.
#[cfg(feature = "multicast")]
pub fn mcast_mac_clear(s: &Switch, port: u16) -> DpdResult<()> {
    mac_clear_common(s, TableType::PortMacAddressMcast, port)
}

#[cfg(feature = "multicast")]
pub fn mcast_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MacMatchKey, MacAction>(TableType::PortMacAddressMcast)
}

#[cfg(feature = "multicast")]
pub fn mcast_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MacMatchKey>(force_sync, TableType::PortMacAddressMcast)
}

/// Remove all entries from the MAC table.
#[cfg(feature = "multicast")]
#[cfg(feature = "tofino_asic")]
pub fn mcast_reset(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::PortMacAddressMcast)
}
