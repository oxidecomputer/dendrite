// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;

use slog::{error, info};

use crate::table::*;
use crate::Switch;
use aal::{ActionParse, MatchParse};
use aal_macros::*;
use common::network::MacAddr;

pub const TABLE_NAME: &str = "pipe.Ingress.mac_rewrite.mac_rewrite";

#[derive(MatchParse, Debug, Hash)]
struct MatchKey {
    port: u16,
}

#[derive(ActionParse, Debug)]
enum Action {
    #[action_xlate(name = "rewrite")]
    Rewrite { mac: MacAddr },
}

/// Update an _existing_ entry in the MAC table.
#[allow(dead_code)]
pub fn mac_update(s: &Switch, port: u16, mac: MacAddr) -> DpdResult<()> {
    let match_key = MatchKey { port };
    let action_data = Action::Rewrite { mac };

    match s.table_entry_update(TableType::PortMac, &match_key, &action_data) {
        Ok(_) => {
            info!(s.log, "update mac on {}: {}", port, mac);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "update mac on {}: {} failed: {:?}", port, mac, e);
            Err(e)
        }
    }
}

/// Add a new entry to the MAC table.
///
/// An error is returned if the entry already exists. Use `mac_update` instead.
pub fn mac_set(s: &Switch, port: u16, mac: MacAddr) -> DpdResult<()> {
    let match_key = MatchKey { port };
    let action_data = Action::Rewrite { mac };

    match s.table_entry_add(TableType::PortMac, &match_key, &action_data) {
        Ok(_) => {
            info!(s.log, "set mac on {}: {}", port, mac);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "set mac on {}: {} failed: {:?}", port, mac, e);
            Err(e)
        }
    }
}

/// Remove an entry from the MAC table.
pub fn mac_clear(s: &Switch, port: u16) -> DpdResult<()> {
    let match_key = MatchKey { port };
    match s.table_entry_del(TableType::PortMac, &match_key) {
        Ok(_) => {
            info!(s.log, "cleared mac on {}", port);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "clear mac on {} failed: {:?}", port, e);
            Err(e)
        }
    }
}

pub fn table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MatchKey, Action>(TableType::PortMac)
}

/// Remove all entries from the MAC table.
#[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
pub fn reset(s: &Switch) -> DpdResult<()> {
    info!(s.log, "reset port macs");

    s.table_clear(TableType::PortMac)
}
