// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::convert::TryFrom;
use std::hash::Hash;

use common::table;
use slog::debug;

use crate::Switch;
use crate::types::*;
use aal::ActionParse;
use aal::MatchParse;
use aal::TableOps;
use common::table::TableType;
use dpd_types::views;

pub mod arp_ipv4;
pub mod attached_subnet_v4;
pub mod attached_subnet_v6;
pub mod mac;
#[cfg(feature = "multicast")]
pub mod mcast;
pub mod nat;
pub mod neighbor_ipv6;
pub mod port_ip;
pub mod route_ipv4;
pub mod route_ipv6;
pub mod uplink;

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

/// A P4 table.
pub struct Table {
    /// Name of the table
    pub type_: TableType,
    /// Basic capacity and usage statistics
    pub usage: TableUsage,
    /// asic-specific data
    asic_data: asic::Table,
}

impl Table {
    /// Allocate a new ASIC table with an empty usage structure
    pub fn new(hdl: &asic::Handle, type_: TableType) -> DpdResult<Self>
    where
        Self: Sized,
    {
        let asic_data = asic::Table::new(hdl, type_)?;
        let size = asic_data.size();
        Ok(Table { type_, usage: TableUsage::new(size as u32), asic_data })
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
            Err(DpdError::TableFull(self.type_.to_string()))
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
        from_hardware: bool,
    ) -> DpdResult<Vec<(M, A)>>
    where
        M: MatchParse,
        A: ActionParse,
    {
        self.asic_data
            .get_entries::<M, A>(hdl, from_hardware)
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
        self.asic_data.get_counters::<M>(hdl, force_sync).map_err(|e| e.into())
    }
}

pub fn list(switch: &Switch) -> Vec<String> {
    switch.tables.keys().map(|t| t.to_string()).collect()
}

/// Given the name of a table, call into the table-specific code to get the
/// entries stored in the ASIC.
pub fn get_entries(
    switch: &Switch,
    name: String,
    from_hardware: bool,
) -> DpdResult<views::Table> {
    match TableType::try_from(name.as_str())? {
        TableType::RouteIdxIpv4 => {
            route_ipv4::index_dump(switch, from_hardware)
        }
        TableType::RouteFwdIpv4 => {
            route_ipv4::forward_dump(switch, from_hardware)
        }
        TableType::RouteIdxIpv6 => {
            route_ipv6::index_dump(switch, from_hardware)
        }
        TableType::RouteFwdIpv6 => {
            route_ipv6::forward_dump(switch, from_hardware)
        }
        TableType::NeighborIpv6 => {
            neighbor_ipv6::table_dump(switch, from_hardware)
        }
        TableType::ArpIpv4 => arp_ipv4::table_dump(switch, from_hardware),
        TableType::NatIngressIpv4 => {
            nat::ipv4_table_dump(switch, from_hardware)
        }
        TableType::NatIngressIpv6 => {
            nat::ipv6_table_dump(switch, from_hardware)
        }
        TableType::AttachedSubnetIpv4 => {
            attached_subnet_v4::table_dump(switch, from_hardware)
        }
        TableType::AttachedSubnetIpv6 => {
            attached_subnet_v6::table_dump(switch, from_hardware)
        }
        TableType::PortAddrIpv4 => {
            port_ip::ipv4_table_dump(switch, from_hardware)
        }
        TableType::PortAddrIpv6 => {
            port_ip::ipv6_table_dump(switch, from_hardware)
        }
        TableType::PortMacAddress => mac::table_dump(switch, from_hardware),
        TableType::UplinkEgress => {
            uplink::egress_table_dump(switch, from_hardware)
        }
        TableType::UplinkIngress => {
            uplink::ingress_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::McastIpv6 => {
            mcast::mcast_replication::ipv6_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::McastIpv4SrcFilter => {
            mcast::mcast_src_filter::ipv4_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::McastIpv6SrcFilter => {
            mcast::mcast_src_filter::ipv6_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::NatIngressIpv4Mcast => {
            mcast::mcast_nat::ipv4_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::NatIngressIpv6Mcast => {
            mcast::mcast_nat::ipv6_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::RouteIpv4Mcast => {
            mcast::mcast_route::ipv4_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::RouteIpv6Mcast => {
            mcast::mcast_route::ipv6_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::PortMacAddressMcast => {
            mac::mcast_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::McastEgressDecapPorts => {
            mcast::mcast_egress::bitmap_table_dump(switch, from_hardware)
        }
        #[cfg(feature = "multicast")]
        TableType::McastEgressPortMapping => {
            mcast::mcast_egress::port_mapping_table_dump(switch, from_hardware)
        }
        x => Err(DpdError::Other(format!(
            "table {x} has no associated table entries"
        ))),
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
        TableType::RouteIdxIpv6 => {
            route_ipv6::index_counter_fetch(switch, force_sync)
        }
        TableType::RouteFwdIpv6 => {
            route_ipv6::forward_counter_fetch(switch, force_sync)
        }
        TableType::NeighborIpv6 => {
            neighbor_ipv6::counter_fetch(switch, force_sync)
        }
        TableType::ArpIpv4 => arp_ipv4::counter_fetch(switch, force_sync),
        TableType::PortMacAddress => mac::counter_fetch(switch, force_sync),
        TableType::NatIngressIpv4 => {
            nat::ipv4_counter_fetch(switch, force_sync)
        }
        TableType::NatIngressIpv6 => {
            nat::ipv6_counter_fetch(switch, force_sync)
        }
        TableType::PortAddrIpv4 => {
            port_ip::ipv4_counter_fetch(switch, force_sync)
        }
        TableType::PortAddrIpv6 => {
            port_ip::ipv6_counter_fetch(switch, force_sync)
        }
        TableType::AttachedSubnetIpv4 => {
            attached_subnet_v4::counter_fetch(switch, force_sync)
        }
        TableType::AttachedSubnetIpv6 => {
            attached_subnet_v6::counter_fetch(switch, force_sync)
        }
        TableType::UplinkEgress => {
            uplink::egress_counter_fetch(switch, force_sync)
        }
        TableType::UplinkIngress => {
            uplink::ingress_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::McastIpv6 => {
            mcast::mcast_replication::ipv6_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::McastIpv4SrcFilter => {
            mcast::mcast_src_filter::ipv4_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::McastIpv6SrcFilter => {
            mcast::mcast_src_filter::ipv6_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::NatIngressIpv4Mcast => {
            mcast::mcast_nat::ipv4_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::NatIngressIpv6Mcast => {
            mcast::mcast_nat::ipv6_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::RouteIpv4Mcast => {
            mcast::mcast_route::ipv4_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::RouteIpv6Mcast => {
            mcast::mcast_route::ipv6_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::McastEgressDecapPorts => {
            mcast::mcast_egress::bitmap_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::McastEgressPortMapping => {
            mcast::mcast_egress::port_mapping_counter_fetch(switch, force_sync)
        }
        #[cfg(feature = "multicast")]
        TableType::PortMacAddressMcast => {
            mac::mcast_counter_fetch(switch, force_sync)
        }
        x => Err(DpdError::Other(format!(
            "table {x} has no associated counters"
        ))),
    }
}

pub fn init(switch: &mut Switch) -> anyhow::Result<()> {
    debug!(switch.log, "initializing tables");

    for table_type in table::get_table_types() {
        switch.table_add(table_type)?;
    }

    Ok(())
}
