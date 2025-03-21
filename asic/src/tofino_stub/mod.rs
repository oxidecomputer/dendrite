// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::sync::Mutex;

use slog::{info, o};
use tokio::sync::mpsc;

use crate::tofino_common::*;
use crate::Identifiers;
use aal::{
    AsicError, AsicOps, AsicResult, Connector, PortHdl, PortUpdate,
    SidecarIdentifiers,
};
use common::ports::{PortFec, PortId, PortMedia, PortPrbsMode, PortSpeed};

pub use crate::faux_fsm::FsmState;
pub use crate::faux_fsm::FsmType;
pub use crate::faux_fsm::PortFsmState;

pub mod multicast;
pub mod ports;
pub mod table;

#[derive(Debug, Default)]
pub struct AsicConfig {}

// Statistics collected for a single port for Oximeter
#[derive(Clone, Copy, Debug)]
pub struct AsicLinkStats {}

impl AsicLinkStats {
    pub fn new(_: PortId, _: u8) -> Self {
        Self {}
    }
}

// All stub ASICs will identify themselves with this static UUID.
const SIDECAR_UUID: &str = "4e5ce3a7-e6c3-6fa6-b03c-869c8fd595d0";

impl AsicLinkStats {
    // Generate a vector of Oximeter Samples, capturing all our metrics
    pub fn get_samples(
        &self,
        _name: &impl oximeter::Target,
    ) -> AsicResult<Vec<oximeter::Sample>> {
        Ok(vec![])
    }

    pub fn update_stats(
        &mut self,
        _hdl: &StubHandle,
        _port: PortHdl,
        _fsm_stats: &crate::FsmStats,
    ) -> AsicResult<()> {
        Ok(())
    }

    pub fn stats_per_link() -> usize {
        0
    }
}

impl AsicOps for StubHandle {
    fn port_get_media(&self, port_hdl: PortHdl) -> AsicResult<PortMedia> {
        ports::get_media(self, port_hdl)
    }

    fn port_get_lane_cnt(&self, port_hdl: PortHdl) -> AsicResult<u8> {
        ports::get_lane_cnt(self, port_hdl)
    }

    fn port_get_link_up(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        ports::get_link_up(self, port_hdl)
    }

    fn port_to_asic_id(&self, port_hdl: PortHdl) -> AsicResult<u16> {
        ports::to_asic_id(self, port_hdl)
    }

    fn asic_id_to_port(&self, asic_id: u16) -> AsicResult<PortHdl> {
        ports::from_asic_id(self, asic_id)
    }

    fn port_enable_get(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        ports::get_enable(self, port_hdl)
    }

    fn port_enable_set(&self, port_hdl: PortHdl, val: bool) -> AsicResult<()> {
        ports::set_enable(self, port_hdl, val)
    }

    fn port_kr_get(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        ports::get_kr_mode(self, port_hdl)
    }

    fn port_kr_set(&self, port_hdl: PortHdl, kr: bool) -> AsicResult<()> {
        info!(self.log, "setting kr on port {} to {}", port_hdl, kr);
        ports::set_kr_mode(self, port_hdl, kr)
    }

    fn port_autoneg_get(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        ports::get_autoneg_mode(self, port_hdl)
    }

    fn port_autoneg_set(&self, port_hdl: PortHdl, an: bool) -> AsicResult<()> {
        info!(self.log, "setting autoneg on port {} to {}", port_hdl, an);
        ports::set_autoneg_mode(self, port_hdl, an)
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
        Err(AsicError::OperationUnsupported)
    }

    fn port_add(
        &self,
        connector: Connector,
        lane: Option<u8>,
        speed: PortSpeed,
        fec: PortFec,
    ) -> AsicResult<(PortHdl, u16)> {
        info!(self.log, "adding port in connector {:?}", connector);
        ports::add_port(self, connector, lane, speed, fec)
    }

    fn port_delete(&self, port_hdl: PortHdl) -> AsicResult<()> {
        info!(self.log, "deleting port {}", port_hdl);
        ports::delete_port(self, port_hdl)
    }

    fn get_connectors(&self) -> Vec<Connector> {
        let phys_ports = self.phys_ports.lock().unwrap();
        phys_ports.connectors.keys().copied().collect()
    }

    fn connector_avail_channels(
        &self,
        connector: Connector,
    ) -> AsicResult<Vec<u8>> {
        let phys_ports = self.phys_ports.lock().unwrap();
        match phys_ports.connectors.get(&connector) {
            Some(connector) => Ok(connector.get_available_channels()),
            None => Err(AsicError::InvalidArg("no such connector".to_string())),
        }
    }

    fn mc_domains(&self) -> Vec<u16> {
        let mc_data = self.mc_data.lock().unwrap();
        mc_data.domains()
    }
    fn mc_port_count(&self, group_id: u16) -> AsicResult<usize> {
        let mc_data = self.mc_data.lock().unwrap();
        mc_data.domain_port_count(group_id)
    }
    fn mc_port_add(&self, group_id: u16, port: u16) -> AsicResult<()> {
        info!(
            self.log,
            "adding port {} to multicast group {}", port, group_id
        );
        let mut mc_data = self.mc_data.lock().unwrap();
        mc_data.domain_port_add(group_id, port)
    }
    fn mc_port_remove(&self, group_id: u16, port: u16) -> AsicResult<()> {
        info!(
            self.log,
            "remvoing port {} from multicast group {}", port, group_id
        );
        let mut mc_data = self.mc_data.lock().unwrap();
        mc_data.domain_port_remove(group_id, port)
    }
    fn mc_group_create(&self, group_id: u16) -> AsicResult<()> {
        info!(self.log, "creating multicast group {}", group_id);
        let mut mc_data = self.mc_data.lock().unwrap();
        mc_data.domain_create(group_id)
    }

    fn mc_group_destroy(&self, group_id: u16) -> AsicResult<()> {
        info!(self.log, "destroying multicast group {}", group_id);
        let mut mc_data = self.mc_data.lock().unwrap();
        mc_data.domain_destroy(group_id)
    }

    fn get_sidecar_identifiers(&self) -> AsicResult<impl SidecarIdentifiers> {
        Ok(Identifiers {
            id: uuid::Uuid::parse_str(SIDECAR_UUID).unwrap(),
            asic_backend: "tofino_stub".to_string(),
            fab: None,
            lot: None,
            wafer: None,
            wafer_loc: None,
        })
    }

    fn register_port_update_handler(
        &self,
        tx_channel: mpsc::UnboundedSender<PortUpdate>,
    ) -> AsicResult<()> {
        let mut tx = self.update_tx.lock().unwrap();
        *tx = Some(tx_channel);
        Ok(())
    }
}

pub struct StubHandle {
    rt: BfRt,
    log: slog::Logger,
    phys_ports: Mutex<ports::PortData>,
    port_state: Mutex<BTreeMap<PortHdl, ports::StubPort>>,
    mc_data: Mutex<multicast::McGroupData>,

    update_tx: Mutex<Option<mpsc::UnboundedSender<PortUpdate>>>,
}

impl StubHandle {
    pub fn new(log: &slog::Logger, _config: &AsicConfig) -> AsicResult<Self> {
        let p4_dir = get_p4_dir()?;
        let rt = BfRt::init(&p4_dir)?;
        let phys_ports = Mutex::new(ports::init()?);
        let port_state = Mutex::new(BTreeMap::new());
        let mc_data = Mutex::new(multicast::init());
        let log = log.new(o!());

        Ok(StubHandle {
            rt,
            log,
            phys_ports,
            port_state,
            mc_data,
            update_tx: Mutex::new(None),
        })
    }

    pub fn is_model(&self) -> bool {
        true
    }

    pub fn fini(&self) {}
}
