// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use super::{MacTable, TableType};

// Unicast MAC rewrite table (always present in both MULTICAST and non-MULTICAST P4)
pub const TABLE_NAME: &str = "pipe.Egress.unicast_mac_rewrite.mac_rewrite";

pub struct PortMacTable;

impl MacTable for PortMacTable {
    fn table_type() -> TableType {
        TableType::PortMac
    }

    fn table_name() -> &'static str {
        TABLE_NAME
    }
}
