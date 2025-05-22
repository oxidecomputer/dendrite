// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Table operations for multicast port MAC entries.

use crate::table::{MacTable, TableType};

/// Table for multicast port MAC entries.
pub const TABLE_NAME: &str = "pipe.Egress.mac_rewrite.mac_rewrite";

/// Table for multicast port MAC entries.
pub struct PortMacTable;

impl MacTable for PortMacTable {
    fn table_type() -> TableType {
        TableType::PortMacMcast
    }

    fn table_name() -> &'static str {
        TABLE_NAME
    }
}
