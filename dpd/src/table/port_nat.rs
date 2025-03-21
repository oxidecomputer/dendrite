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

pub const TABLE_NAME: &str = "pipe.Ingress.nat_ingress.nat_only";

#[derive(MatchParse, Debug, Hash)]
struct MatchKey {
    in_port: u16,
}

#[derive(ActionParse, Debug)]
enum Action {
    #[action_xlate(name = "nat_only_port")]
    NatDrop,
}

/// Mark a port as "allow nat traffic only"
pub fn nat_only_set(s: &Switch, port: u16) -> DpdResult<()> {
    let match_key = MatchKey { in_port: port };
    let action_data = Action::NatDrop;

    match s.table_entry_add(TableType::NatOnly, &match_key, &action_data) {
        Ok(_) => {
            info!(s.log, "set nat_only on {}", port);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "set nat_only on {} failed: {:?}", port, e);
            Err(e)
        }
    }
}

/// Remove an entry from the NAT-only table.
pub fn nat_only_clear(s: &Switch, port: u16) -> DpdResult<()> {
    let match_key = MatchKey { in_port: port };
    match s.table_entry_del(TableType::NatOnly, &match_key) {
        Ok(_) => {
            info!(s.log, "cleared nat_only on {}", port);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "clear nat_only on {} failed: {:?}", port, e);
            Err(e)
        }
    }
}

pub fn table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MatchKey, Action>(TableType::NatOnly)
}

pub fn counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MatchKey>(force_sync, TableType::NatOnly)
}
