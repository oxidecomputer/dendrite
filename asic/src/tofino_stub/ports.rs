// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::convert::TryFrom;

pub use crate::tofino_common::ports::PhysPort;
pub use crate::tofino_common::ports::PortData;
pub use crate::tofino_common::ports::PortId;
pub use crate::tofino_common::ports::TofinoPort;
use crate::tofino_common::ports::CHANNELS_PER_SWITCH_PORT;

use crate::tofino_stub::FsmType;
use crate::tofino_stub::PortFsmState;
use crate::tofino_stub::StubHandle;
use aal::AsicError;
use aal::AsicId;
use aal::AsicResult;
use aal::Connector;
use aal::PortHdl;
use aal::PortUpdate;
use common::ports::PortFec;
use common::ports::PortMedia;
use common::ports::PortPrbsMode;
use common::ports::PortSpeed;

// This is an arbitrary number, but must be at least as large as
// tofino_common::ports::CHANNELS_PER_SWITCH_PORT.  In this case, we've chosen a
// value 2x as large.  This gives us a sparse AsicId space, which might tease
// out any assumptions in the code about AsicId distribution.
const MAX_CHANNELS_PER_PORT: u16 = 8;

// We hardcode the CPU/ETH port to be port 0
const CPU_PORT: u32 = 0;

// Mirroring the real hardware we have 64 QSFP ports: 32 backplane ports and 32
// front ports.
const QSFP_PORT_COUNT: u32 = 64;

pub struct StubPort {
    pub link_up: bool,
    pub enabled: bool,
    pub kr: bool,
    pub autoneg: bool,
}

fn no_port(port_id: PortHdl) -> AsicError {
    AsicError::InvalidArg(format!("no such port: {port_id}"))
}

fn get_port(
    port_state: &BTreeMap<PortHdl, StubPort>,
    port_hdl: PortHdl,
) -> AsicResult<&StubPort> {
    match port_state.get(&port_hdl) {
        Some(p) => Ok(p),
        None => Err(AsicError::InvalidArg("no such port".to_string())),
    }
}

fn get_port_mut(
    port_state: &mut BTreeMap<PortHdl, StubPort>,
    port_hdl: PortHdl,
) -> AsicResult<&mut StubPort> {
    match port_state.get_mut(&port_hdl) {
        Some(p) => Ok(p),
        None => Err(AsicError::InvalidArg("no such port".to_string())),
    }
}

pub fn get_media(hdl: &StubHandle, port_hdl: PortHdl) -> AsicResult<PortMedia> {
    let port_data = hdl.phys_ports.lock().unwrap();
    match port_data.connectors.get(&port_hdl.connector) {
        Some(port) => Ok(port.media),
        None => Err(no_port(port_hdl)),
    }
}

pub fn get_link_up(hdl: &StubHandle, port_hdl: PortHdl) -> AsicResult<bool> {
    let state = hdl.port_state.lock().unwrap();
    let port = get_port(&state, port_hdl)?;
    Ok(port.link_up)
}

pub fn get_enable(hdl: &StubHandle, port_hdl: PortHdl) -> AsicResult<bool> {
    let state = hdl.port_state.lock().unwrap();
    let port = get_port(&state, port_hdl)?;
    Ok(port.enabled)
}

pub fn set_enable(
    hdl: &StubHandle,
    port_hdl: PortHdl,
    enabled: bool,
) -> AsicResult<()> {
    let asic_port_id = to_asic_id(hdl, port_hdl)?;
    {
        let mut state = hdl.port_state.lock().unwrap();
        let port = get_port_mut(&mut state, port_hdl)?;
        port.enabled = enabled;
        port.link_up = enabled;
    }
    // If dpd has registered a callback handler with us, send updates for both
    // enable and link states.
    let tx = hdl.update_tx.lock().unwrap();
    if let Some(tx) = tx.as_ref() {
        // When a port is enabled in the stub, it automatically comes online.
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
                    hdl.log,
                    "failed to send port update {event:?}: {e:?}"
                );
            }
        }
    } else {
        slog::debug!(hdl.log, "no PortUpdate handler registered");
    }
    Ok(())
}

pub fn set_kr_mode(
    hdl: &StubHandle,
    port_hdl: PortHdl,
    kr: bool,
) -> AsicResult<()> {
    let mut state = hdl.port_state.lock().unwrap();
    let port = get_port_mut(&mut state, port_hdl)?;
    port.kr = kr;
    Ok(())
}

pub fn get_kr_mode(hdl: &StubHandle, port_hdl: PortHdl) -> AsicResult<bool> {
    let state = hdl.port_state.lock().unwrap();
    let port = get_port(&state, port_hdl)?;
    Ok(port.kr)
}

pub fn set_autoneg_mode(
    hdl: &StubHandle,
    port_hdl: PortHdl,
    an: bool,
) -> AsicResult<()> {
    let mut state = hdl.port_state.lock().unwrap();
    let port = get_port_mut(&mut state, port_hdl)?;
    port.autoneg = an;
    Ok(())
}

pub fn get_autoneg_mode(
    hdl: &StubHandle,
    port_hdl: PortHdl,
) -> AsicResult<bool> {
    let state = hdl.port_state.lock().unwrap();
    let port = get_port(&state, port_hdl)?;
    Ok(port.autoneg)
}

/// Look up the port_hdl -> asic_id mapping
pub fn to_asic_id(hdl: &StubHandle, port_hdl: PortHdl) -> AsicResult<AsicId> {
    hdl.phys_ports.lock().unwrap().to_asic_id(port_hdl)
}

/// Look up the asic_id -> port_hdl mapping
pub fn from_asic_id(hdl: &StubHandle, asic_id: AsicId) -> AsicResult<PortHdl> {
    hdl.phys_ports.lock().unwrap().from_asic_id(asic_id)
}

/// Return the number of lanes assigned to this port
pub fn get_lane_cnt(hdl: &StubHandle, port_hdl: PortHdl) -> AsicResult<u8> {
    let phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.get_tofino_port(port_hdl)?;
    Ok(u8::try_from(config.channels.len()).unwrap())
}

/// Add a new configured port to a physical port.
pub fn add_port(
    hdl: &StubHandle,
    connector: Connector,
    lane: Option<u8>,
    speed: PortSpeed,
    fec: PortFec,
) -> AsicResult<(PortHdl, AsicId)> {
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let phys_port = phys_ports.get_phys_mut(&connector)?;
    let channels = phys_port.allocate_channels_for(lane, speed)?;

    let port_hdl = PortHdl::new(connector, channels[0]);
    let port_id = phys_ports.to_asic_id(port_hdl)?;

    let cfg = TofinoPort {
        port_id,
        enabled: false,
        kr: false,
        autoneg: false,
        prbs: PortPrbsMode::Mission,
        channels,
        connector: port_hdl.connector,
        channel: port_hdl.channel,
        speed,
        fec,
    };
    phys_ports.add_tofino_port(port_hdl, cfg)?;
    let mut ports = hdl.port_state.lock().unwrap();
    ports.insert(
        port_hdl,
        StubPort {
            link_up: false,
            enabled: false,
            kr: false,
            autoneg: false,
        },
    );
    Ok((port_hdl, port_id))
}

/// Remove a configured port from a physical port, making its channels available
/// for future configurations.
pub fn delete_port(hdl: &StubHandle, port_hdl: PortHdl) -> AsicResult<()> {
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.delete_tofino_port(port_hdl)?;

    let phys_port = phys_ports.get_phys_mut(&port_hdl.connector)?;
    let _ = phys_port.free(&config.channels);
    let mut ports = hdl.port_state.lock().unwrap();
    let _ = ports.remove(&port_hdl);

    Ok(())
}

pub fn init() -> AsicResult<PortData> {
    let mut map_to_asic_id = BTreeMap::new();
    let mut map_from_asic_id = BTreeMap::new();
    let mut connectors = BTreeMap::new();

    // Build the PhysPort structures for each Connector
    let eth_port = Some(CPU_PORT as u16);
    connectors.insert(Connector::CPU, PhysPort::new(Connector::CPU)?);

    for id in 0..QSFP_PORT_COUNT {
        let connector = Connector::QSFP(id);
        let mut phys_port = PhysPort::new(connector)?;
        phys_port.media = PortMedia::Optical;
        connectors.insert(connector, phys_port);
    }

    // Populate the port<->asic_id maps
    for connector in connectors.keys() {
        let port_base_id = match connector {
            Connector::CPU => CPU_PORT as AsicId,
            Connector::QSFP(qsfp) => *qsfp as AsicId * MAX_CHANNELS_PER_PORT,
        };

        for chan in 0..CHANNELS_PER_SWITCH_PORT {
            let asic_id = port_base_id + chan as AsicId;
            map_to_asic_id.insert((*connector, chan), asic_id);
            map_from_asic_id.insert(asic_id, (*connector, chan));
        }
    }

    Ok(PortData {
        eth_port,
        eth_connector_id: None,
        connectors,
        config_ports: BTreeMap::new(),
        map_to_asic_id,
        map_from_asic_id,
    })
}
