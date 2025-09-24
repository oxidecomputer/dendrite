// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Table operations for multicast egress entries.

use std::fmt;

use crate::{Switch, table::*};

use aal::{ActionParse, MatchParse};
use aal_macros::*;
use dpd_types::mcast::MulticastGroupId;
use slog::debug;

/// Table for multicast egress entries matching the multicast group ID
/// and setting which ports to possibly decap.
pub(crate) const DECAP_PORTS_TABLE_NAME: &str =
    "pipe.Egress.mcast_egress.tbl_decap_ports";

/// Table for multicast egress entries matching the replication group ID.
pub(crate) const PORT_ID_TABLE_NAME: &str =
    "pipe.Egress.mcast_egress.asic_id_to_port";

#[derive(MatchParse, Hash)]
struct MatchKeyDecapPorts {
    #[match_xlate(name = "egress_rid")]
    mcast_external_grp: MulticastGroupId,
}

impl MatchKeyDecapPorts {
    fn new(mcast_external_grp: MulticastGroupId) -> Self {
        Self { mcast_external_grp }
    }
}

impl fmt::Display for MatchKeyDecapPorts {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "egress_rid={}", self.mcast_external_grp)
    }
}

#[derive(MatchParse, Hash)]
struct MatchKeyPortId {
    #[match_xlate(name = "egress_port")]
    asic_port_id: u16,
}

impl MatchKeyPortId {
    fn new(asic_port_id: u16) -> Self {
        Self { asic_port_id }
    }
}

impl fmt::Display for MatchKeyPortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "egress_port={}", self.asic_port_id)
    }
}

#[derive(ActionParse, Debug)]
enum DecapPortsAction {
    #[action_xlate(name = "set_decap_ports")]
    SetDecapPorts {
        ports_0: u32,
        ports_1: u32,
        ports_2: u32,
        ports_3: u32,
        ports_4: u32,
        ports_5: u32,
        ports_6: u32,
        ports_7: u32,
    },
    #[action_xlate(name = "set_decap_ports_and_vlan")]
    SetDecapPortsAndVlan {
        ports_0: u32,
        ports_1: u32,
        ports_2: u32,
        ports_3: u32,
        ports_4: u32,
        ports_5: u32,
        ports_6: u32,
        ports_7: u32,
        vlan_id: u16,
    },
}

#[derive(ActionParse, Debug)]
enum PortIdAction {
    #[action_xlate(name = "set_port_number")]
    SetPortNumber { port_number: u8 },
}

/// Add a multicast entry to the decap table, keyed on
/// `mcast_external_grp` and setting the port bitmap.
pub(crate) fn add_bitmap_entry(
    s: &Switch,
    mcast_external_grp: MulticastGroupId,
    port_bitmap: &PortBitmap,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = MatchKeyDecapPorts::new(mcast_external_grp);

    let action_data = match vlan_id {
        None => port_bitmap.to_action(),
        Some(vlan_id) => {
            common::network::validate_vlan(vlan_id)?;
            port_bitmap.to_action_vlan(vlan_id)
        }
    };
    debug!(
        s.log,
        "add multicast egress entry for decap {} -> {:?}",
        match_key,
        action_data
    );

    s.table_entry_add(
        TableType::McastEgressDecapPorts,
        &match_key,
        &action_data,
    )
}

/// Update a multicast entry in the decap table, keyed on
/// `mcast_external_grp` and setting the port bitmap.
pub(crate) fn update_bitmap_entry(
    s: &Switch,
    mcast_external_grp: MulticastGroupId,
    port_bitmap: &PortBitmap,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let match_key = MatchKeyDecapPorts::new(mcast_external_grp);
    let action_data = match vlan_id {
        None => port_bitmap.to_action(),
        Some(vlan_id) => {
            common::network::validate_vlan(vlan_id)?;
            port_bitmap.to_action_vlan(vlan_id)
        }
    };

    debug!(
        s.log,
        "update multicast egress entry for decap {} -> {:?}",
        match_key,
        action_data
    );

    s.table_entry_update(
        TableType::McastEgressDecapPorts,
        &match_key,
        &action_data,
    )
}

/// Delete a multicast entry from the decap table, keyed on
/// `mcast_external_grp`.
pub(crate) fn del_bitmap_entry(
    s: &Switch,
    mcast_external_grp: MulticastGroupId,
) -> DpdResult<()> {
    let match_key = MatchKeyDecapPorts::new(mcast_external_grp);

    debug!(
        s.log,
        "delete multicast egress entry for decap {} -> {}",
        match_key,
        mcast_external_grp
    );

    s.table_entry_del(TableType::McastEgressDecapPorts, &match_key)
}

/// Dump the multicast decap table.
pub(crate) fn bitmap_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MatchKeyDecapPorts, DecapPortsAction>(
        TableType::McastEgressDecapPorts,
    )
}

/// Fetch the multicast decap table counters.
pub(crate) fn bitmap_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MatchKeyDecapPorts>(
        force_sync,
        TableType::McastEgressDecapPorts,
    )
}

/// Reset the multicast decap table.
pub(crate) fn reset_bitmap_table(s: &Switch) -> DpdResult<()> {
    s.table_clear(TableType::McastEgressDecapPorts)
}

/// Add a port ID entry to the port ID table for converting ASIC port IDs
/// to port numbers.
pub(crate) fn add_port_mapping_entry(
    s: &Switch,
    asic_port_id: u16,
) -> DpdResult<()> {
    let match_key = MatchKeyPortId::new(asic_port_id);

    let (port, _) = s.asic_id_to_port_link(asic_port_id)?;

    let action_data = PortIdAction::SetPortNumber {
        port_number: port.as_u8(),
    };

    debug!(
        s.log,
        "add port id entry {} -> {:?}", match_key, action_data
    );

    s.table_entry_add(
        TableType::McastEgressPortMapping,
        &match_key,
        &action_data,
    )
}

/// Update a port ID entry in the port ID table for converting ASIC port IDs
/// to port numbers.
#[allow(dead_code)]
pub(crate) fn update_port_mapping_entry(
    s: &Switch,
    asic_port_id: u16,
) -> DpdResult<()> {
    let match_key = MatchKeyPortId::new(asic_port_id);

    let (port, _) = s.asic_id_to_port_link(asic_port_id)?;

    let action_data = PortIdAction::SetPortNumber {
        port_number: port.as_u8(),
    };

    debug!(
        s.log,
        "update port id entry {} -> {:?}", match_key, action_data
    );

    s.table_entry_update(
        TableType::McastEgressPortMapping,
        &match_key,
        &action_data,
    )
}

/// Delete a port ID entry from the port ID table for converting ASIC port IDs
/// to port numbers.
pub(crate) fn del_port_mapping_entry(
    s: &Switch,
    asic_port_id: u16,
) -> DpdResult<()> {
    let match_key = MatchKeyPortId::new(asic_port_id);

    debug!(
        s.log,
        "delete port id entry {} -> {}", match_key, asic_port_id
    );

    s.table_entry_del(TableType::McastEgressPortMapping, &match_key)
}

/// Dump the multicast port mapping table.
pub(crate) fn port_mapping_table_dump(s: &Switch) -> DpdResult<views::Table> {
    s.table_dump::<MatchKeyPortId, PortIdAction>(
        TableType::McastEgressPortMapping,
    )
}

/// Fetch the multicast port mapping table counters.
pub(crate) fn port_mapping_counter_fetch(
    s: &Switch,
    force_sync: bool,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    s.counter_fetch::<MatchKeyPortId>(
        force_sync,
        TableType::McastEgressPortMapping,
    )
}

/// Structure to hold and manipulate the 256-bit port bitmap.
#[derive(Debug, Clone, Default)]
pub(crate) struct PortBitmap {
    // 8 x 32-bit values representing all 256 ports
    ports: [u32; 8],
}

impl PortBitmap {
    /// Create a new empty port bitmap.
    pub(crate) fn new() -> Self {
        Self { ports: [0; 8] }
    }

    /// Add a port to the bitmap.
    pub(crate) fn add_port(&mut self, port: u8) {
        let array_idx = (port >> 5) as usize; // Divide by 32 to get array index
        let bit_pos = port & 0x1F; // Modulo 32 to get bit position
        let mask = 1u32 << bit_pos; // Create mask with the appropriate bit set
        self.ports[array_idx] |= mask; // Set the bit
    }

    /// Remove a port from the bitmap
    #[allow(dead_code)]
    pub(crate) fn remove_port(&mut self, port: u16) {
        let array_idx = (port >> 5) as usize;
        let bit_pos = port & 0x1F;
        let mask = 1u32 << bit_pos;

        self.ports[array_idx] &= !mask; // Clear the bit
    }

    /// Check if a port is in the bitmap
    #[allow(dead_code)]
    fn contains_port(&self, port: u16) -> bool {
        if port >= 256 {
            return false;
        }

        let array_idx = (port >> 5) as usize;
        let bit_pos = port & 0x1F;
        let mask = 1u32 << bit_pos;

        (self.ports[array_idx] & mask) != 0
    }

    /// Convert to an action for the P4 table
    fn to_action(&self) -> DecapPortsAction {
        DecapPortsAction::SetDecapPorts {
            ports_0: self.ports[0],
            ports_1: self.ports[1],
            ports_2: self.ports[2],
            ports_3: self.ports[3],
            ports_4: self.ports[4],
            ports_5: self.ports[5],
            ports_6: self.ports[6],
            ports_7: self.ports[7],
        }
    }

    /// Convert to an action for the P4 table with Vlan ID
    fn to_action_vlan(&self, vlan_id: u16) -> DecapPortsAction {
        DecapPortsAction::SetDecapPortsAndVlan {
            ports_0: self.ports[0],
            ports_1: self.ports[1],
            ports_2: self.ports[2],
            ports_3: self.ports[3],
            ports_4: self.ports[4],
            ports_5: self.ports[5],
            ports_6: self.ports[6],
            ports_7: self.ports[7],
            vlan_id,
        }
    }

    /// Get the raw port bitmap values
    #[allow(dead_code)]
    fn get_port_values(&self) -> &[u32; 8] {
        &self.ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_bitmap() {
        let mut bitmap = PortBitmap::new();
        bitmap.add_port(5);
        bitmap.add_port(10);
        bitmap.add_port(255);

        assert!(bitmap.contains_port(5));
        assert!(bitmap.contains_port(10));
        assert!(bitmap.contains_port(255));
        assert!(!bitmap.contains_port(256));

        bitmap.remove_port(10);
        assert!(!bitmap.contains_port(10));
    }
}
