// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use dpd_types::table;
use std::convert::TryInto;

use slog::{error, info};

use crate::Switch;
use crate::table::*;
use aal::{ActionParse, AsicError, MatchParse};
use aal_macros::*;

#[derive(MatchParse, Debug, Hash)]
struct IngressMatchKey {
    #[match_xlate(name = "ingress_port")]
    in_port: u16,
}

#[derive(ActionParse, Debug)]
enum IngressAction {
    #[action_xlate(name = "uplink_port")]
    UplinkPort,
}

#[derive(MatchParse, Debug, Hash)]
struct EgressMatchKey {
    #[match_xlate(name = "ucast_egress_port")]
    out_port: u16,
}

#[derive(ActionParse, Debug)]
enum EgressAction {
    #[action_xlate(name = "guest_traffic_allowed")]
    Allowed,
}

// Both of these tables carry a single, argument-free action, so an entry that
// is already present is already correct.  `uplink_set()` and `uplink_clear()`
// are driven by the link reconciler, which retries them after a failure -
// including a failure that left one of the two tables already converged - so
// they have to treat "the entry is how I want it" as success rather than as an
// error.
fn set_ingress_uplink(s: &Switch, port: u16) -> DpdResult<()> {
    let match_key = IngressMatchKey { in_port: port };
    let action_data = IngressAction::UplinkPort;

    match s.table_entry_add(TableType::UplinkIngress, &match_key, &action_data)
    {
        Ok(_) | Err(DpdError::Switch(AsicError::Exists)) => {
            info!(s.log, "set uplink on {}", port);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "set uplink on {} failed: {:?}", port, e);
            Err(e)
        }
    }
}

fn clear_ingress_uplink(s: &Switch, port: u16) -> DpdResult<()> {
    let match_key = IngressMatchKey { in_port: port };

    match s.table_entry_del(TableType::UplinkIngress, &match_key) {
        Ok(_) | Err(DpdError::Switch(AsicError::Missing(_))) => {
            info!(s.log, "cleared uplink on {}", port);
            Ok(())
        }
        Err(e) => {
            error!(s.log, "clear uplink on {} failed: {:?}", port, e);
            Err(e)
        }
    }
}

/// Designate that a port is meant to be used as an uplink
pub fn uplink_set(s: &Switch, port: u16) -> DpdResult<()> {
    set_ingress_uplink(s, port)?;

    let match_key = EgressMatchKey { out_port: port };
    let action_data = EgressAction::Allowed;

    match s.table_entry_add(TableType::UplinkEgress, &match_key, &action_data) {
        Ok(_) | Err(DpdError::Switch(AsicError::Exists)) => {
            info!(s.log, "set guest_traffic_allowed on {}", port);
            Ok(())
        }
        Err(e) => {
            error!(
                s.log,
                "set guest_traffic_allowed on {} failed: {:?}", port, e
            );
            let _ = clear_ingress_uplink(s, port);
            Err(e)
        }
    }
}

/// Remove an entry from the uplink tables.
pub fn uplink_clear(s: &Switch, port: u16) -> DpdResult<()> {
    clear_ingress_uplink(s, port)?;

    let match_key = EgressMatchKey { out_port: port };
    match s.table_entry_del(TableType::UplinkEgress, &match_key) {
        Ok(_) | Err(DpdError::Switch(AsicError::Missing(_))) => {
            info!(s.log, "cleared guest_traffic_allowed on {}", port);
            Ok(())
        }
        Err(e) => {
            error!(
                s.log,
                "clear guest_traffic_allowed on {} failed: {:?}", port, e
            );
            set_ingress_uplink(s, port)?;
            Err(e)
        }
    }
}

pub fn egress_table_dump(
    s: &Switch,
    from_hardware: bool,
) -> DpdResult<table::Table> {
    s.table_dump::<EgressMatchKey, EgressAction>(
        TableType::UplinkEgress,
        from_hardware,
    )
}

pub fn ingress_table_dump(
    s: &Switch,
    from_hardware: bool,
) -> DpdResult<table::Table> {
    s.table_dump::<IngressMatchKey, IngressAction>(
        TableType::UplinkIngress,
        from_hardware,
    )
}

pub fn egress_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<table::TableCounterEntry>> {
    s.counter_fetch::<EgressMatchKey>(force_sync, TableType::UplinkEgress)
}

pub fn ingress_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<table::TableCounterEntry>> {
    s.counter_fetch::<IngressMatchKey>(force_sync, TableType::UplinkIngress)
}
