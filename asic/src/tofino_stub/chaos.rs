// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Targeted failure injection is useful for testing error handling
//! in CI. This module exposes helpers for defining and introducing
//! such failures into normal stub operations.
//! Chaotic failures are opt-in.

use rand::random;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::HashMap;

use aal::{AsicError, AsicResult};
use common::table::TableType;

pub use crate::faux_fsm::FsmState;
pub use crate::faux_fsm::FsmType;
pub use crate::faux_fsm::PortFsmState;

/// Chaos that happens according to a probability.
#[derive(Default, Debug, Serialize, Deserialize, Copy, Clone)]
pub struct Chaos {
    /// A probability between 0.0 and 1.0
    pub value: f64,
}

impl Chaos {
    /// Create a new chaos value.
    pub fn new(value: f64) -> Self {
        let mut c = Self::default();
        c.set(value);
        c
    }
    /// Set the chaos value. Panics if value is outside the range [0.0, 1.0].
    pub fn set(&mut self, value: f64) {
        if !(0.0..=1.0).contains(&value) {
            panic!("probability out of range");
        }
        self.value = value;
    }

    /// Get the underlying chaos value.
    pub fn get(&self) -> f64 {
        self.value
    }

    /// Return a chaos error according to the underlying probability value.
    pub fn unfurled(&self, log: &Logger, message: &str) -> AsicResult<()> {
        if self.value >= random() {
            slog::error!(log, "chaos error: {}", message);
            return Err(AsicError::Synthetic(message.into()));
        }
        Ok(())
    }
}

/// A form of chaos that applies to tables.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct TableChaos {
    /// Track a set of chaos probabilities keyed by strings.
    pub values: HashMap<TableType, f64>,
}

/// A convenience function for creating chaos tables.
#[macro_export]
macro_rules! table_chaos {
    ( $( ($entry:expr, $prob:expr) ),* ) => {
        TableChaos {
            values: HashMap::from([
                $( ($entry.into(), $prob) ),*
            ])
        }
    }
}

impl TableChaos {
    fn add_tables(&mut self, ids: Vec<TableType>, prob: f64) {
        for id in ids {
            self.values.insert(id, prob);
        }
    }

    /// Create a new chaos table with all known dendrite table identifiers,
    /// assigning each a uniform chaos value.
    pub fn uniform(v: f64) -> Self {
        let mut tc = TableChaos { values: HashMap::new() };

        tc.add_tables(
            vec![
                TableType::RouteIdxIpv4,
                TableType::RouteFwdIpv4,
                TableType::RouteIdxIpv6,
                TableType::RouteFwdIpv6,
                TableType::ArpIpv4,
                TableType::NeighborIpv6,
                TableType::PortMacAddress,
                TableType::PortAddrIpv4,
                TableType::PortAddrIpv6,
                TableType::NatIngressIpv4,
                TableType::NatIngressIpv6,
                TableType::UplinkIngress,
                TableType::UplinkEgress,
                TableType::AttachedSubnetIpv4,
                TableType::AttachedSubnetIpv6,
            ],
            v,
        );
        #[cfg(feature = "multicast")]
        tc.add_tables(
            vec![
                TableType::RouteIpv4Mcast,
                TableType::RouteIpv6Mcast,
                TableType::McastIpv6,
                TableType::McastIpv4SrcFilter,
                TableType::McastIpv6SrcFilter,
                TableType::NatIngressIpv4Mcast,
                TableType::NatIngressIpv6Mcast,
                TableType::PortMacAddressMcast,
                TableType::McastEgressDecapPorts,
                TableType::McastEgressPortMapping,
            ],
            v,
        );
        tc
    }

    /// Return a chaos error according to the underlying probability value for
    /// the given table `id`.
    pub fn unfurled(
        &self,
        log: &Logger,
        id: TableType,
        message: &str,
    ) -> AsicResult<()> {
        if let Some(value) = self.values.get(&id)
            && *value >= random()
        {
            slog::error!(log, "chaos table error: {}", message);
            return Err(AsicError::Synthetic(message.into()));
        }
        Ok(())
    }
}

#[cfg(feature = "multicast")]
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AsicMulticastConfig {
    pub mc_port_count: Chaos,
    pub mc_port_add: Chaos,
    pub mc_port_remove: Chaos,
    pub mc_group_create: Chaos,
    pub mc_group_destroy: Chaos,
    pub mc_groups_count: Chaos,
    pub mc_set_max_nodes: Chaos,
}

/// The chaos ASIC config contains chaos values for each ASIC operation.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AsicConfig {
    pub port_get_media: Chaos,
    pub port_get_link_up: Chaos,
    pub port_to_asic_id: Chaos,
    pub asic_id_to_port: Chaos,
    pub port_get_lane_cnt: Chaos,
    pub port_kr_get: Chaos,
    pub port_kr_set: Chaos,
    pub port_autoneg_get: Chaos,
    pub port_autoneg_set: Chaos,
    pub port_enable_get: Chaos,
    pub port_enable_set: Chaos,
    pub port_prbs_set: Chaos,
    pub port_prbs_get_err: Chaos,
    pub port_tx_eq_set: Chaos,
    pub port_add: Chaos,
    pub port_delete: Chaos,
    pub register_port_update_handler: Chaos,
    pub connector_avail_channels: Chaos,
    pub get_sidecar_identifiers: Chaos,
    pub table_new: TableChaos,
    pub table_clear: TableChaos,
    pub table_default_set: TableChaos,
    pub table_entry_add: TableChaos,
    pub table_entry_update: TableChaos,
    pub table_entry_del: TableChaos,
    pub table_entry_get: TableChaos,
    #[cfg(feature = "multicast")]
    pub mc_config: AsicMulticastConfig,
}

impl AsicConfig {
    /// The uniform chaos config applies a uniform underlying probability to each
    /// chaos value.
    pub fn uniform(v: f64) -> Self {
        Self {
            port_get_media: Chaos::new(v),
            port_get_link_up: Chaos::new(v),
            port_to_asic_id: Chaos::new(v),
            asic_id_to_port: Chaos::new(v),
            port_get_lane_cnt: Chaos::new(v),
            port_kr_get: Chaos::new(v),
            port_kr_set: Chaos::new(v),
            port_autoneg_get: Chaos::new(v),
            port_autoneg_set: Chaos::new(v),
            port_enable_get: Chaos::new(v),
            port_enable_set: Chaos::new(v),
            port_prbs_set: Chaos::new(v),
            port_prbs_get_err: Chaos::new(v),
            port_tx_eq_set: Chaos::new(v),
            port_add: Chaos::new(v),
            port_delete: Chaos::new(v),
            register_port_update_handler: Chaos::new(v),
            connector_avail_channels: Chaos::new(v),
            get_sidecar_identifiers: Chaos::new(v),
            table_new: TableChaos::uniform(v),
            table_clear: TableChaos::uniform(v),
            table_default_set: TableChaos::uniform(v),
            table_entry_add: TableChaos::uniform(v),
            table_entry_update: TableChaos::uniform(v),
            table_entry_del: TableChaos::uniform(v),
            table_entry_get: TableChaos::uniform(v),
            #[cfg(feature = "multicast")]
            mc_config: AsicMulticastConfig {
                mc_port_count: Chaos::new(v),
                mc_port_add: Chaos::new(v),
                mc_port_remove: Chaos::new(v),
                mc_group_create: Chaos::new(v),
                mc_group_destroy: Chaos::new(v),
                mc_groups_count: Chaos::new(v),
                mc_set_max_nodes: Chaos::new(v),
            },
        }
    }

    /// The uniform get chaos config applies a uniform underlying probability to
    /// each ASIC getter function. Setter functions are initialized with a
    /// default Chaos config that fails with probability zero.
    pub fn uniform_get(v: f64) -> Self {
        Self {
            port_get_media: Chaos::new(v),
            port_get_link_up: Chaos::new(v),
            port_to_asic_id: Chaos::new(v),
            asic_id_to_port: Chaos::new(v),
            port_get_lane_cnt: Chaos::new(v),
            port_kr_get: Chaos::new(v),
            port_autoneg_get: Chaos::new(v),
            port_enable_get: Chaos::new(v),
            connector_avail_channels: Chaos::new(v),
            get_sidecar_identifiers: Chaos::new(v),
            #[cfg(feature = "multicast")]
            mc_config: AsicMulticastConfig {
                mc_port_count: Chaos::new(v),
                mc_groups_count: Chaos::new(v),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// The uniform get chaos config applies a uniform underlying probability to
    /// each ASIC setter function. Getter functions are initialized with a
    /// default Chaos config that fails with probability zero.
    pub fn uniform_set(v: f64) -> Self {
        Self {
            port_kr_set: Chaos::new(v),
            port_autoneg_set: Chaos::new(v),
            port_enable_set: Chaos::new(v),
            port_prbs_set: Chaos::new(v),
            port_prbs_get_err: Chaos::new(v),
            port_tx_eq_set: Chaos::new(v),
            port_add: Chaos::new(v),
            port_delete: Chaos::new(v),
            // TODO this can cause dpd to fail to start
            //table_clear: TableChaos::uniform(v),
            table_default_set: TableChaos::uniform(v),
            table_entry_add: TableChaos::uniform(v),
            table_entry_update: TableChaos::uniform(v),
            table_entry_del: TableChaos::uniform(v),
            #[cfg(feature = "multicast")]
            mc_config: AsicMulticastConfig {
                mc_port_add: Chaos::new(v),
                mc_port_remove: Chaos::new(v),
                mc_group_create: Chaos::new(v),
                mc_group_destroy: Chaos::new(v),
                mc_set_max_nodes: Chaos::new(v),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// A convenience macro for unfurling chaos. The $name should be a regular
/// `Chaos` member of [`AsicConfig`]. The `handle` is a [`Handle`] object.
macro_rules! unfurl {
    ($handle:ident, $name:ident) => {
        $handle.chaos_config.$name.unfurled(&$handle.log, stringify!($name))?
    };
}
pub(crate) use unfurl;

/// A convenience macro for unfurling multicast chaos. The $name should be a
/// regular `Chaos` member of [`AsicMulticastConfigConfig`]. The `handle` is
/// a [`Handle`] object.
#[cfg(feature = "multicast")]
macro_rules! unfurl_mc {
    ($handle:ident, $name:ident) => {
        $handle
            .chaos_config
            .mc_config
            .$name
            .unfurled(&$handle.log, stringify!($name))?
    };
}

#[cfg(feature = "multicast")]
pub(crate) use unfurl_mc;

/// A convenience macro for unfurling tabular chaos. The $name should be a
/// `TableChaos` member of [`AsicConfig`]. The `handle` is a [`Handle`] object.
macro_rules! table_unfurl {
    ($handle:ident, $id: expr, $name:ident) => {
        $handle.chaos_config.$name.unfurled(
            &$handle.log,
            $id,
            stringify!($name),
        )?
    };
}
pub(crate) use table_unfurl;
