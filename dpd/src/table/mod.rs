// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::hash::Hash;

use slog::debug;

use crate::types::*;
use crate::views;
use crate::Switch;
use aal::ActionParse;
use aal::MatchParse;
use aal::TableOps;

pub mod arp_ipv4;
pub mod nat;
pub mod neighbor_ipv6;
pub mod port_ip;
pub mod port_mac;
pub mod port_nat;
pub mod route_ipv4;
pub mod route_ipv6;

const NAME_TO_TYPE: [(&str, TableType); 11] = [
    (route_ipv4::INDEX_TABLE_NAME, TableType::RouteIdxIpv4),
    (route_ipv4::FORWARD_TABLE_NAME, TableType::RouteFwdIpv4),
    (route_ipv6::TABLE_NAME, TableType::RouteIpv6),
    (arp_ipv4::TABLE_NAME, TableType::ArpIpv4),
    (neighbor_ipv6::TABLE_NAME, TableType::NeighborIpv6),
    (port_mac::TABLE_NAME, TableType::PortMac),
    (port_ip::IPV4_TABLE_NAME, TableType::PortIpv4),
    (port_ip::IPV6_TABLE_NAME, TableType::PortIpv6),
    (nat::IPV4_TABLE_NAME, TableType::NatIngressIpv4),
    (nat::IPV6_TABLE_NAME, TableType::NatIngressIpv6),
    (port_nat::TABLE_NAME, TableType::NatOnly),
];

/// Basic statistics about p4 table usage
#[derive(Clone, Debug, Default)]
pub struct TableUsage {
    /// Maximum number of entries in the table
    pub size: u32,
    /// Current number of entries in the table
    pub occupancy: u32,
    /// Total number of entries inserted over time
    pub inserts: u64,
    /// Total number of entries deleted over time
    pub deletes: u64,
    /// Number of entries updated in place over time
    pub updates: u64,
    /// Number of inserts failed due to a collision
    pub collisions: u64,
    /// Number of updates failed due to a missing entry
    pub update_misses: u64,
    /// Number of deletes failed due to a missing entry
    pub delete_misses: u64,
    /// Number of inserts that failed due to space exhaustion
    pub exhaustion: u64,
}

impl TableUsage {
    /// Initialize a TableUsage structure with the provided size
    pub fn new(size: u32) -> TableUsage {
        TableUsage {
            size,
            occupancy: 0,
            inserts: 0,
            deletes: 0,
            updates: 0,
            collisions: 0,
            update_misses: 0,
            delete_misses: 0,
            exhaustion: 0,
        }
    }
}

/// A p4 table
pub struct Table {
    /// Name of the table
    pub name: String,
    /// Basic capacity and usage statistics
    pub usage: TableUsage,
    /// asic-specific data
    asic_data: asic::Table,
}

impl Table {
    /// Allocate a new ASIC table with an empty usage structure
    pub fn new(hdl: &asic::Handle, name: &str) -> DpdResult<Self>
    where
        Self: Sized,
    {
        let asic_data = asic::Table::new(hdl, name)?;
        let size = asic_data.size();
        Ok(Table {
            name: name.to_string(),
            usage: TableUsage::new(size as u32),
            asic_data,
        })
    }

    /// Returns the number of entries the table can hold
    pub fn size(&self) -> u32 {
        self.usage.size
    }

    /// Clear all entries from the table in a single operation
    pub fn clear(&mut self, hdl: &asic::Handle) -> DpdResult<()> {
        self.asic_data
            .clear(hdl)
            .map_err(|e| e.into())
            .map(|()| self.usage.occupancy = 0)
    }

    /// Add an entry to the table.  Attempting to add an entry that already
    /// exists will fail.
    pub fn entry_add<M, A>(
        &mut self,
        hdl: &asic::Handle,
        key: &M,
        data: &A,
    ) -> DpdResult<()>
    where
        M: MatchParse + Hash,
        A: ActionParse,
    {
        if self.usage.occupancy == self.usage.size {
            self.usage.exhaustion += 1;
            Err(DpdError::TableFull(self.name.clone()))
        } else {
            self.asic_data
                .entry_add(hdl, key, data)
                .map_err(|e| {
                    if let aal::AsicError::Exists = e {
                        self.usage.collisions += 1;
                    }
                    e.into()
                })
                .map(|_| {
                    self.usage.occupancy += 1;
                    self.usage.inserts += 1;
                })
        }
    }

    /// Update a single entry in the table.  Attempting to update an entry
    /// that doesn't exist will fail, rather than inserting a new entry.
    pub fn entry_update<M, A>(
        &mut self,
        hdl: &asic::Handle,
        key: &M,
        data: &A,
    ) -> DpdResult<()>
    where
        M: MatchParse + Hash,
        A: ActionParse,
    {
        self.asic_data
            .entry_update(hdl, key, data)
            .map_err(|e| {
                self.usage.update_misses += 1;
                e.into()
            })
            .map(|()| self.usage.updates += 1)
    }

    /// Remove a single entry from the table.
    pub fn entry_del<M>(&mut self, hdl: &asic::Handle, key: &M) -> DpdResult<()>
    where
        M: MatchParse + Hash,
    {
        self.asic_data
            .entry_del(hdl, key)
            .map_err(|e| {
                self.usage.delete_misses += 1;
                e.into()
            })
            .map(|()| {
                self.usage.occupancy -= 1;
                self.usage.deletes += 1;
            })
    }

    /// Ask the ASIC-level code to fetch the table contents from the ASIC's
    /// TCAM/SRAM, and parse it into (M, A) pairs.
    pub fn get_entries<M, A>(
        &self,
        hdl: &asic::Handle,
    ) -> DpdResult<Vec<(M, A)>>
    where
        M: MatchParse,
        A: ActionParse,
    {
        self.asic_data
            .get_entries::<M, A>(hdl)
            .map_err(|e| e.into())
    }

    /// Ask the ASIC-level code to fetch the counter data from the ASIC's
    /// TCAM, and parse it into (M, A) pairs.
    pub fn get_counters<M>(
        &self,
        hdl: &asic::Handle,
        force_sync: bool,
    ) -> DpdResult<Vec<(M, aal::CounterData)>>
    where
        M: MatchParse,
    {
        self.asic_data
            .get_counters::<M>(hdl, force_sync)
            .map_err(|e| e.into())
    }
}

pub fn list(switch: &Switch) -> Vec<String> {
    switch
        .tables
        .values()
        .map(|t| t.lock().unwrap().name.to_string())
        .collect()
}

/// Given the name of a table, call into the table-specific code to get the
/// entries stored in the ASIC.
pub fn get_entries(switch: &Switch, name: String) -> DpdResult<views::Table> {
    match TableType::try_from(name.as_str())? {
        TableType::RouteIdxIpv4 => route_ipv4::index_dump(switch),
        TableType::RouteFwdIpv4 => route_ipv4::forward_dump(switch),
        TableType::RouteIpv6 => route_ipv6::table_dump(switch),
        TableType::NeighborIpv6 => neighbor_ipv6::table_dump(switch),
        TableType::ArpIpv4 => arp_ipv4::table_dump(switch),
        TableType::NatIngressIpv4 => nat::ipv4_table_dump(switch),
        TableType::NatIngressIpv6 => nat::ipv6_table_dump(switch),
        TableType::PortIpv4 => port_ip::ipv4_table_dump(switch),
        TableType::PortIpv6 => port_ip::ipv6_table_dump(switch),
        TableType::PortMac => port_mac::table_dump(switch),
        TableType::NatOnly => port_nat::table_dump(switch),
    }
}

/// Given the name of a table, call into the table-specific code to get the
/// counter data stored in the ASIC.
pub fn get_counters(
    switch: &Switch,
    force_sync: bool,
    name: String,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    match TableType::try_from(name.as_str())? {
        TableType::RouteIdxIpv4 => {
            route_ipv4::index_counter_fetch(switch, force_sync)
        }
        TableType::RouteFwdIpv4 => {
            route_ipv4::forward_counter_fetch(switch, force_sync)
        }
        TableType::RouteIpv6 => route_ipv6::counter_fetch(switch, force_sync),
        TableType::NeighborIpv6 => {
            neighbor_ipv6::counter_fetch(switch, force_sync)
        }
        TableType::ArpIpv4 => arp_ipv4::counter_fetch(switch, force_sync),
        TableType::NatIngressIpv4 => {
            nat::ipv4_counter_fetch(switch, force_sync)
        }
        TableType::NatIngressIpv6 => {
            nat::ipv6_counter_fetch(switch, force_sync)
        }
        TableType::PortIpv4 => port_ip::ipv4_counter_fetch(switch, force_sync),
        TableType::PortIpv6 => port_ip::ipv6_counter_fetch(switch, force_sync),
        TableType::NatOnly => port_nat::counter_fetch(switch, force_sync),
        // There is no counter in the PortMac table, as it duplicates data
        // already available in the rmon egress counter.
        _ => Err(DpdError::NoSuchTable(name)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TableType {
    RouteIdxIpv4,
    RouteFwdIpv4,
    RouteIpv6,
    ArpIpv4,
    NeighborIpv6,
    PortMac,
    PortIpv4,
    PortIpv6,
    NatIngressIpv4,
    NatIngressIpv6,
    NatOnly,
}

impl TryFrom<&str> for TableType {
    type Error = DpdError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        let name = name.to_lowercase();
        for (table_name, table_type) in NAME_TO_TYPE {
            if table_name.to_lowercase() == name {
                return Ok(table_type);
            }
        }

        Err(DpdError::NoSuchTable(name.to_string()))
    }
}

pub fn init(switch: &mut Switch) -> anyhow::Result<()> {
    debug!(switch.log, "initializing tables");

    for (name, table_type) in NAME_TO_TYPE {
        switch.table_add(name, table_type)?;
    }

    Ok(())
}
