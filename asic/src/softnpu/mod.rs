// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;
use std::sync::Mutex;

use slog::{o, Logger};
use tokio::sync::mpsc;
use uuid::Uuid;

pub use crate::faux_fsm::FsmState;
pub use crate::faux_fsm::FsmType;
pub use crate::faux_fsm::PortFsmState;
use crate::Identifiers;

use aal::{
    AsicError, AsicId, AsicOps, AsicResult, Connector, PortHdl, PortUpdate,
    SidecarIdentifiers,
};
use common::ports::{
    PortFec, PortId, PortMedia, PortPrbsMode, PortSpeed, TxEq,
};

use softnpu_lib::ManagementRequest;

pub mod mgmt;
pub mod table;

const CPU_PORT: u16 = 1000;

/// Asic configuration for a SoftNPU ASIC.
#[derive(Debug)]
pub struct AsicConfig {
    /// The type of managment interface to use for talking to the SoftNPU asic.
    pub softnpu_management: mgmt::SoftnpuManagement,

    /// Path to a Unix domain socket to use in conjunction with
    /// `SoftnpuManagement::UDS`.
    pub uds_path: Option<String>,

    /// The number of front ports.
    pub front_ports: u8,

    /// The number of rear ports.
    pub rear_ports: u8,
}

impl Default for AsicConfig {
    fn default() -> Self {
        Self {
            softnpu_management: mgmt::SoftnpuManagement::UART,
            uds_path: None,
            front_ports: 1,
            rear_ports: 1,
        }
    }
}

pub struct Port {
    pub enabled: bool,
    pub tx_eq: i32,
}

// Statistics collected for a single port for Oximeter
#[derive(Clone, Copy, Debug)]
pub struct AsicLinkStats {}

impl AsicLinkStats {
    pub fn new(_: PortId, _: u8) -> Self {
        Self {}
    }
}

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
        _hdl: &Handle,
        _port: PortHdl,
        _fsm_stats: &crate::FsmStats,
    ) -> AsicResult<()> {
        Ok(())
    }

    pub fn stats_per_link() -> usize {
        0
    }
}

pub struct Handle {
    log: Logger,
    ports: Mutex<HashMap<PortHdl, Port>>,
    pub mgmt_config: mgmt::ManagementConfig,

    update_tx: Mutex<Option<mpsc::UnboundedSender<PortUpdate>>>,
}

impl Handle {
    pub fn new(log: &Logger, config: &AsicConfig) -> AsicResult<Self> {
        let log = log.new(o!());

        let mgmt_config = match config.softnpu_management {
            mgmt::SoftnpuManagement::UART => mgmt::ManagementConfig::UART,
            mgmt::SoftnpuManagement::UDS => match &config.uds_path {
                Some(s) => mgmt::ManagementConfig::UDS {
                    socket_path: s.to_string(),
                },
                None => {
                    return Err(AsicError::InvalidArg(
                        "softnpu unix domain socket missing".to_string(),
                    ))
                }
            },
        };

        Ok(Self {
            log,
            ports: Mutex::new(HashMap::new()),
            mgmt_config,
            update_tx: Mutex::new(None),
        })
    }

    pub fn port_tx_eq_get(&self, port_hdl: PortHdl) -> AsicResult<i32> {
        let ports = self.ports.lock().unwrap();
        Ok(get_port(&ports, port_hdl)?.tx_eq)
    }

    pub fn is_model(&self) -> bool {
        true
    }

    pub fn fini(&self) {}
}

impl AsicOps for Handle {
    fn port_get_media(&self, port_hdl: PortHdl) -> AsicResult<PortMedia> {
        Ok(match port_hdl.connector {
            Connector::CPU => PortMedia::CPU,
            Connector::QSFP(_) => PortMedia::Copper,
        })
    }

    fn port_get_link_up(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        let ports = self.ports.lock().unwrap();
        Ok(get_port(&ports, port_hdl)?.enabled)
    }

    fn port_to_asic_id(&self, port_hdl: PortHdl) -> AsicResult<u16> {
        Ok(match port_hdl.connector {
            Connector::CPU => CPU_PORT,
            Connector::QSFP(n) => n as u16,
        })
    }

    fn asic_id_to_port(&self, asic_id: AsicId) -> AsicResult<PortHdl> {
        let connector = match asic_id {
            CPU_PORT => Connector::CPU,
            n => Connector::QSFP(n as u32),
        };
        Ok(PortHdl::new(connector, 0))
    }

    fn port_get_lane_cnt(&self, _port_hdl: PortHdl) -> AsicResult<u8> {
        Ok(1)
    }

    fn port_enable_get(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        let ports = self.ports.lock().unwrap();
        Ok(get_port(&ports, port_hdl)?.enabled)
    }

    fn port_enable_set(
        &self,
        port_hdl: PortHdl,
        enabled: bool,
    ) -> AsicResult<()> {
        {
            let mut ports = self.ports.lock().unwrap();
            get_port_mut(&mut ports, port_hdl)?.enabled = enabled;
        }

        // If dpd has registered a callback handler with us, send updates for
        // both enable and link states.
        let asic_port_id = self.port_to_asic_id(port_hdl)?;
        let tx = self.update_tx.lock().unwrap();
        if let Some(tx) = tx.as_ref() {
            // When a port is enabled in softnpu, it automatically comes online.
            // When switching between enabled and disabled, we send the main body
            // of dpd the PortUpdate events we would expect to see on real hardware.
            let present = PortUpdate::Presence {
                asic_port_id,
                presence: enabled,
            };
            let ena = PortUpdate::Enable {
                asic_port_id,
                enabled,
            };
            let fsm_state = match enabled {
                false => PortFsmState::Idle,
                true => PortFsmState::LinkUp,
            };
            let fsm = PortUpdate::FSM {
                asic_port_id,
                fsm: FsmType::Port.into(),
                state: fsm_state.into(),
            };
            let link = PortUpdate::LinkUp {
                asic_port_id,
                linkup: enabled,
            };

            for event in &[present, ena, fsm, link] {
                if let Err(e) = tx.send(*event) {
                    slog::error!(
                        self.log,
                        "failed to send port update {event:?}: {e:?}"
                    );
                }
            }
        } else {
            slog::debug!(self.log, "no PortUpdate handler registered");
        }
        Ok(())
    }

    fn port_kr_get(&self, _port_hdl: PortHdl) -> AsicResult<bool> {
        Ok(false)
    }

    fn port_kr_set(&self, _port_hdl: PortHdl, _kr: bool) -> AsicResult<()> {
        Ok(())
    }

    fn port_autoneg_get(&self, _port_hdl: PortHdl) -> AsicResult<bool> {
        Ok(false)
    }

    fn port_tx_eq_set(
        &self,
        port_hdl: PortHdl,
        tx_eq: &TxEq,
    ) -> AsicResult<()> {
        let mut ports = self.ports.lock().unwrap();
        get_port_mut(&mut ports, port_hdl)?.tx_eq = tx_eq.main.unwrap_or(0);
        Ok(())
    }

    fn port_autoneg_set(
        &self,
        _port_hdl: PortHdl,
        _an: bool,
    ) -> AsicResult<()> {
        Ok(())
    }

    fn port_prbs_set(
        &self,
        _port_hdl: PortHdl,
        _mode: PortPrbsMode,
    ) -> AsicResult<()> {
        Ok(())
    }

    fn port_add(
        &self,
        connector: Connector,
        lane: Option<u8>,
        _speed: PortSpeed,
        _fec: PortFec,
    ) -> AsicResult<(PortHdl, u16)> {
        if let Some(link_id) = lane {
            if link_id > 0 {
                return Err(AsicError::InvalidArg(
                    "softnpu only supports lane 0".into(),
                ));
            }
        }
        let mut ports = self.ports.lock().unwrap();
        // Each switch port / connector only supports a single channel, and so a
        // maximum of a single logical MAC. Convert the connector to a PortHdl,
        // and use it as before.
        let port_hdl = PortHdl::new(connector, 0);
        if ports.contains_key(&port_hdl) {
            return Err(AsicError::InvalidArg(format!(
                "Port {port_hdl:?} exists"
            )));
        }
        ports.insert(
            port_hdl,
            Port {
                enabled: true,
                tx_eq: 0,
            },
        );
        self.port_to_asic_id(port_hdl).map(|id| (port_hdl, id))
    }

    fn port_delete(&self, port_hdl: PortHdl) -> AsicResult<()> {
        let mut ports = self.ports.lock().unwrap();
        if !ports.contains_key(&port_hdl) {
            return Err(AsicError::InvalidArg(format!(
                "Port {port_hdl:?} does not exist"
            )));
        }
        ports.remove(&port_hdl);
        Ok(())
    }

    fn get_connectors(&self) -> Vec<Connector> {
        let msg = ManagementRequest::RadixRequest;
        crate::softnpu::mgmt::write(msg, &self.mgmt_config);
        let response = crate::softnpu::mgmt::read(
            ManagementRequest::RadixRequest,
            &self.mgmt_config,
        );
        let radix: u16 = response.trim().parse().unwrap();

        let mut result = vec![Connector::CPU];
        for i in 1..radix + 1 {
            result.push(Connector::QSFP(i as u32));
        }
        result
    }

    fn connector_avail_channels(
        &self,
        _connector: Connector,
    ) -> AsicResult<Vec<u8>> {
        Ok(vec![0])
    }

    fn mc_domains(&self) -> Vec<u16> {
        let len = self.ports.lock().unwrap().len() as u16;
        (0..len).collect()
    }

    fn mc_port_count(&self, _group_id: u16) -> AsicResult<usize> {
        Ok(self.ports.lock().unwrap().len())
    }

    fn mc_port_add(&self, _group_id: u16, _port: u16) -> AsicResult<()> {
        Err(AsicError::OperationUnsupported)
    }

    fn mc_port_remove(&self, _group_id: u16, _port: u16) -> AsicResult<()> {
        Ok(())
    }

    fn mc_group_create(&self, _group_id: u16) -> AsicResult<()> {
        Err(AsicError::OperationUnsupported)
    }

    fn mc_group_destroy(&self, _group_id: u16) -> AsicResult<()> {
        Ok(())
    }

    fn get_sidecar_identifiers(&self) -> AsicResult<impl SidecarIdentifiers> {
        Ok(Identifiers {
            id: Uuid::new_v4(),
            asic_backend: "softnpu".to_string(),
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
