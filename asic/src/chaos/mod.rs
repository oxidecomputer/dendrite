// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use rand::random;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;

use aal::{
    AsicError, AsicId, AsicOps, AsicResult, Connector, PortHdl, PortUpdate,
    SidecarIdentifiers,
};
use common::ports::{PortFec, PortId, PortMedia, PortPrbsMode, PortSpeed};

pub use crate::faux_fsm::FsmState;
pub use crate::faux_fsm::PortFsmState;
use crate::Identifiers;

pub mod table;

const CPU_PORT: u16 = 47;

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
    pub values: HashMap<String, f64>,
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
    /// Create a new chaos table with all known dendrite table identifiers,
    /// assigning each a uniform chaos value.
    pub fn uniform(v: f64) -> Self {
        table_chaos!(
            (table::ROUTE_IPV4, v),
            (table::ROUTE_IPV6, v),
            (table::ARP_IPV4, v),
            (table::NEIGHBOR_IPV6, v),
            (table::MAC_REWRITE, v),
            (table::SWITCH_IPV4_ADDR, v),
            (table::SWITCH_IPV6_ADDR, v),
            (table::NAT_INGRESS_IPV4, v),
            (table::NAT_INGRESS_IPV6, v)
        )
    }

    /// Return a chaos error according to the underlying probability value for
    /// the given table `id`.
    pub fn unfurled(
        &self,
        log: &Logger,
        id: &str,
        message: &str,
    ) -> AsicResult<()> {
        if let Some(value) = self.values.get(id) {
            if *value >= random() {
                slog::error!(log, "chaos table error: {}", message);
                return Err(AsicError::Synthetic(message.into()));
            }
        }
        Ok(())
    }
}

/// The chaos ASIC config contains chaos values for each ASIC operation.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AsicConfig {
    pub radix: usize,
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
    pub port_add: Chaos,
    pub port_delete: Chaos,
    pub register_port_update_handler: Chaos,
    pub connector_avail_channels: Chaos,
    pub mc_port_count: Chaos,
    pub mc_port_add: Chaos,
    pub mc_port_remove: Chaos,
    pub mc_group_create: Chaos,
    pub mc_group_destroy: Chaos,
    pub get_sidecar_identifiers: Chaos,
    pub table_new: TableChaos,
    pub table_clear: TableChaos,
    pub table_default_set: TableChaos,
    pub table_entry_add: TableChaos,
    pub table_entry_update: TableChaos,
    pub table_entry_del: TableChaos,
}

impl AsicConfig {
    /// The uniform chaos config applies a uniform underlying probability to each
    /// chaos value.
    pub fn uniform(radix: usize, v: f64) -> Self {
        Self {
            radix,
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
            port_add: Chaos::new(v),
            port_delete: Chaos::new(v),
            register_port_update_handler: Chaos::new(v),
            connector_avail_channels: Chaos::new(v),
            mc_port_count: Chaos::new(v),
            mc_port_add: Chaos::new(v),
            mc_port_remove: Chaos::new(v),
            mc_group_create: Chaos::new(v),
            mc_group_destroy: Chaos::new(v),
            get_sidecar_identifiers: Chaos::new(v),
            table_new: TableChaos::uniform(v),
            table_clear: TableChaos::uniform(v),
            table_default_set: TableChaos::uniform(v),
            table_entry_add: TableChaos::uniform(v),
            table_entry_update: TableChaos::uniform(v),
            table_entry_del: TableChaos::uniform(v),
        }
    }

    /// The uniform get chaos config applies a uniform underlying probability to
    /// each ASIC getter function. Setter functions are initialized with a
    /// default Chaos config that fails with probability zero.
    pub fn uniform_get(radix: usize, v: f64) -> Self {
        Self {
            radix,
            port_get_media: Chaos::new(v),
            port_get_link_up: Chaos::new(v),
            port_to_asic_id: Chaos::new(v),
            asic_id_to_port: Chaos::new(v),
            port_get_lane_cnt: Chaos::new(v),
            port_kr_get: Chaos::new(v),
            port_autoneg_get: Chaos::new(v),
            port_enable_get: Chaos::new(v),
            connector_avail_channels: Chaos::new(v),
            mc_port_count: Chaos::new(v),
            get_sidecar_identifiers: Chaos::new(v),
            ..Default::default()
        }
    }

    /// The uniform get chaos config applies a uniform underlying probability to
    /// each ASIC setter function. Getter functions are initialized with a
    /// default Chaos config that fails with probability zero.
    pub fn uniform_set(radix: usize, v: f64) -> Self {
        Self {
            radix,
            port_kr_set: Chaos::new(v),
            port_autoneg_set: Chaos::new(v),
            port_enable_set: Chaos::new(v),
            port_prbs_set: Chaos::new(v),
            port_add: Chaos::new(v),
            port_delete: Chaos::new(v),
            mc_port_add: Chaos::new(v),
            mc_port_remove: Chaos::new(v),
            mc_group_create: Chaos::new(v),
            mc_group_destroy: Chaos::new(v),
            // TODO this can cause dpd to fail to start
            //table_clear: TableChaos::uniform(v),
            table_default_set: TableChaos::uniform(v),
            table_entry_add: TableChaos::uniform(v),
            table_entry_update: TableChaos::uniform(v),
            table_entry_del: TableChaos::uniform(v),
            ..Default::default()
        }
    }
}

/// Stats object for the chaos ASIC.
#[derive(Clone, Copy, Debug, Default)]
pub struct AsicLinkStats {}

impl AsicLinkStats {
    /// Create new link stats to track the provided link.
    pub fn new(_: PortId, _: u8) -> Self {
        Self {}
    }

    /// Generate a vector of Oximeter Samples, capturing all our metrics
    pub fn get_samples(
        &self,
        _name: &impl oximeter::Target,
    ) -> AsicResult<Vec<oximeter::Sample>> {
        Ok(vec![])
    }

    /// Update statistics.
    pub fn update_stats(
        &mut self,
        _hdl: &Handle,
        _port: PortHdl,
        _fsm_stats: &crate::FsmStats,
    ) -> AsicResult<()> {
        Ok(())
    }

    /// Number of stats per link.
    pub fn stats_per_link() -> usize {
        0
    }
}

/// Chaos ports are simple, they just track whether or not they are enabled.
pub struct Port {
    pub enabled: bool,
}

/// A hanlde for a chaos asic.
pub struct Handle {
    ports: Mutex<HashMap<PortHdl, Port>>,
    config: AsicConfig,
    log: Logger,
}

impl Handle {
    /// Create a new chaos ASIC with the provided logger and config.
    pub fn new(log: &Logger, config: &AsicConfig) -> AsicResult<Self> {
        Ok(Handle {
            ports: Mutex::new(HashMap::new()),
            config: config.clone(),
            log: log.clone(),
        })
    }
    /// Chaos ASICs always report as a model.
    pub fn is_model(&self) -> bool {
        true
    }

    /// Chaos ASIC finisher is a no-op.
    pub fn fini(&self) {}
}

/// A convenience macro for unfurling chaos. The $name should be a regular
/// `Chaos` member of [`AsicConfig`]. The `handle` is a [`Handle`] object.
macro_rules! unfurl {
    ($handle:ident, $name:ident) => {
        $handle
            .config
            .$name
            .unfurled(&$handle.log, stringify!($name))?
    };
}
pub(crate) use unfurl;

/// A convenience macro for unfurling tabular chaos. The $name should be a
/// `TableChaos` member of [`AsicConfig`]. The `handle` is a [`Handle`] object.
macro_rules! table_unfurl {
    ($handle:ident, $id: expr, $name:ident) => {
        $handle
            .config
            .$name
            .unfurled(&$handle.log, $id, stringify!($name))?
    };
}
pub(crate) use table_unfurl;

impl AsicOps for Handle {
    fn port_get_media(&self, port_hdl: PortHdl) -> AsicResult<PortMedia> {
        unfurl!(self, port_get_media);
        Ok(match port_hdl.connector {
            Connector::CPU => PortMedia::CPU,
            Connector::QSFP(_) => PortMedia::Copper,
        })
    }

    fn port_get_link_up(&self, _port_hdl: PortHdl) -> AsicResult<bool> {
        unfurl!(self, port_get_link_up);
        Ok(true)
    }

    fn port_to_asic_id(&self, port_hdl: PortHdl) -> AsicResult<AsicId> {
        unfurl!(self, port_to_asic_id);
        Ok(match port_hdl.connector {
            Connector::CPU => CPU_PORT,
            Connector::QSFP(n) => n as AsicId,
        })
    }

    fn asic_id_to_port(&self, asic_id: AsicId) -> AsicResult<PortHdl> {
        unfurl!(self, asic_id_to_port);
        Ok(match asic_id {
            CPU_PORT => PortHdl::new(Connector::CPU, 0),
            n => PortHdl::new(Connector::QSFP(n as u32), 0),
        })
    }

    fn port_get_lane_cnt(&self, _port_hdl: PortHdl) -> AsicResult<u8> {
        unfurl!(self, port_get_lane_cnt);
        Ok(1)
    }

    fn port_enable_get(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        unfurl!(self, port_enable_get);
        let ports = self.ports.lock().unwrap();
        Ok(get_port(&ports, port_hdl)?.enabled)
    }

    fn port_enable_set(&self, port_hdl: PortHdl, val: bool) -> AsicResult<()> {
        unfurl!(self, port_enable_set);
        let mut ports = self.ports.lock().unwrap();
        get_port_mut(&mut ports, port_hdl)?.enabled = val;
        Ok(())
    }

    fn port_kr_get(&self, _port_hdl: PortHdl) -> AsicResult<bool> {
        unfurl!(self, port_kr_get);
        Ok(false)
    }

    fn port_kr_set(&self, _port_hdl: PortHdl, _kr: bool) -> AsicResult<()> {
        unfurl!(self, port_kr_set);
        Ok(())
    }

    fn port_autoneg_get(&self, _port_hdl: PortHdl) -> AsicResult<bool> {
        unfurl!(self, port_autoneg_get);
        Ok(false)
    }

    fn port_autoneg_set(
        &self,
        _port_hdl: PortHdl,
        _an: bool,
    ) -> AsicResult<()> {
        unfurl!(self, port_autoneg_set);
        Ok(())
    }

    fn port_tx_eq_set(
        &self,
        _port_hdl: PortHdl,
        _settings: &common::ports::TxEq,
    ) -> AsicResult<()> {
        Ok(())
    }

    fn port_prbs_set(
        &self,
        _port_hdl: PortHdl,
        _mode: PortPrbsMode,
    ) -> AsicResult<()> {
        unfurl!(self, port_prbs_set);
        Ok(())
    }

    fn port_add(
        &self,
        connector: Connector,
        _lane: Option<u8>,
        _speed: PortSpeed,
        _fec: PortFec,
    ) -> AsicResult<(PortHdl, AsicId)> {
        unfurl!(self, port_add);
        let mut ports = self.ports.lock().unwrap();
        // Each switch port / connector only supports a single channel, and so a
        // maximum of a single logical MAC. Convert the connector to a PortHdl,
        // and use it as before.
        let port_hdl = PortHdl::new(connector, 0);
        if ports.contains_key(&port_hdl) {
            return Err(AsicError::Exists);
        }
        ports.insert(port_hdl, Port { enabled: true });
        self.port_to_asic_id(port_hdl).map(|id| (port_hdl, id))
    }

    fn port_delete(&self, port_hdl: PortHdl) -> AsicResult<()> {
        unfurl!(self, port_delete);
        let mut ports = self.ports.lock().unwrap();
        if !ports.contains_key(&port_hdl) {
            return Err(AsicError::Missing("no such port".to_string()));
        }
        ports.remove(&port_hdl);
        Ok(())
    }

    fn register_port_update_handler(
        &self,
        _tx_channel: mpsc::UnboundedSender<PortUpdate>,
    ) -> AsicResult<()> {
        unfurl!(self, register_port_update_handler);
        Ok(())
    }

    fn get_connectors(&self) -> Vec<Connector> {
        let mut result = vec![Connector::CPU];
        for i in 1..self.config.radix + 1 {
            result.push(Connector::QSFP(i as u32));
        }
        result
    }

    fn connector_avail_channels(
        &self,
        _connector: Connector,
    ) -> AsicResult<Vec<u8>> {
        unfurl!(self, connector_avail_channels);
        Ok(vec![0])
    }

    fn mc_domains(&self) -> Vec<u16> {
        let len = self.ports.lock().unwrap().len() as u16;
        (0..len).collect()
    }

    fn mc_port_count(&self, _group_id: u16) -> AsicResult<usize> {
        unfurl!(self, mc_port_count);
        Ok(self.ports.lock().unwrap().len())
    }

    fn mc_port_add(&self, _group_id: u16, _port: u16) -> AsicResult<()> {
        unfurl!(self, mc_port_add);
        Err(AsicError::OperationUnsupported)
    }

    fn mc_port_remove(&self, _group_id: u16, _port: u16) -> AsicResult<()> {
        unfurl!(self, mc_port_remove);
        Ok(())
    }

    fn mc_group_create(&self, _group_id: u16) -> AsicResult<()> {
        unfurl!(self, mc_group_create);
        Err(AsicError::OperationUnsupported)
    }

    fn mc_group_destroy(&self, _group_id: u16) -> AsicResult<()> {
        unfurl!(self, mc_group_destroy);
        Ok(())
    }

    fn get_sidecar_identifiers(&self) -> AsicResult<impl SidecarIdentifiers> {
        unfurl!(self, get_sidecar_identifiers);
        Ok(Identifiers::default())
    }
}

fn get_port(
    port_state: &HashMap<PortHdl, Port>,
    port_hdl: PortHdl,
) -> AsicResult<&Port> {
    match port_state.get(&port_hdl) {
        Some(p) => Ok(p),
        None => Err(AsicError::InvalidArg("no such port".to_string())),
    }
}

fn get_port_mut(
    port_state: &mut HashMap<PortHdl, Port>,
    port_hdl: PortHdl,
) -> AsicResult<&mut Port> {
    match port_state.get_mut(&port_hdl) {
        Some(p) => Ok(p),
        None => Err(AsicError::InvalidArg("no such port".to_string())),
    }
}
