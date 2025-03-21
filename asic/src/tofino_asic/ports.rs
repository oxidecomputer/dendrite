// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

#![allow(dead_code)]
#![allow(non_upper_case_globals)]

/// A note on ports:
///
/// The term "port" is overloaded in the Tofino and its SDE.  There are ASIC
/// ports, which are the entities we manage in the tables.  These are represented
/// using the PortId, which maps to the bf_dev_port_t used throughout the SDE.
/// These are divided into "front panel ports", which represent that subset of
/// ASIC ports that are connected to a SERDES, and "internal ports", which are
/// not.
///
/// There are also the external QSFP ports, which may have up to 4 channels.
/// A 100G QSFP port can run at 100G by using all 4 channels.  It may also be
/// divided into 2 50G ports, each using 2 channels, or 4 25G ports, each using
/// 1 channel.  These are represented by a FrontPortHandle, which is a wrapper
/// around the SDE's bf_pal_front_port_handle_t.  This struct includes a
/// connector ID and a channel ID (which the SDE frequently refers to as a
/// 'lane').  (Note: despite the name, these are not the 'front panel ports'
/// mentioned above).
///
/// The bf_pal_port_add() operation, encapsulated within the configure_port()
/// function below, is how we tell Tofino how we intend to use each QSFP port.
///
/// In between the Tofino and the QSFP ports are the MACs.  The relationship
/// between the PortId and FrontPortHandle namespaces is defined by how the QSFP
/// ports are wired to the MACs on the switch PCB.  This mapping can't be
/// determined automatically in software; it has to be provided as part of the
/// platform definition.
use std::collections::BTreeMap;
use std::convert::Into;
use std::convert::TryFrom;
use std::fmt;

use slog::debug;

use aal::AsicId;
use aal::Connector;
use aal::PortHdl;

use crate::tofino_asic::genpd::*;
use crate::tofino_asic::*;

pub use crate::tofino_common::ports::PhysPort;
pub use crate::tofino_common::ports::PortData;
pub use crate::tofino_common::ports::PortId;
pub use crate::tofino_common::ports::TofinoPort;

/// A FrontPortHandle describes a physical QSFP connector and a channel provided
/// by it.  This is how the hardware platform and the admin understand the
/// network.
#[derive(Clone, Copy)]
pub struct FrontPortHandle {
    dev_id: i32,
    fp_hdl: bf_pal_front_port_handle_t,
}

impl FrontPortHandle {
    /// Generate a FrontPortHandle structure
    pub fn new(dev_id: i32, conn_id: u32, chnl_id: u8) -> Self {
        let chnl_id: u32 = chnl_id.into();
        FrontPortHandle {
            dev_id,
            fp_hdl: bf_pal_front_port_handle_t { conn_id, chnl_id },
        }
    }

    /// Get the 16-bit value use by the ASIC to manage this front-panel port
    pub fn get_dev_port(&self) -> AsicResult<PortId> {
        let mut dev_id = 0;
        let mut port = 0;
        unsafe {
            let mut tmp = *self;
            bf_pm_port_front_panel_port_to_dev_port_get(
                tmp.ptr(),
                &mut dev_id,
                &mut port,
            )
            .check_error("translating front port to dev_id")?;
        }
        if dev_id != self.dev_id {
            Err(AsicError::InvalidArg("wrong device".to_string()))
        } else {
            Ok(port as PortId)
        }
    }

    /// Given a 16-bit ASIC ID, determine which front-panel port it maps to
    pub fn from_dev_port(hdl: &Handle, port: PortId) -> AsicResult<Self> {
        let mut fp_hdl = bf_pal_front_port_handle_t {
            conn_id: 0,
            chnl_id: 0,
        };
        unsafe {
            bf_pm_port_dev_port_to_front_panel_port_get(
                hdl.dev_id,
                port as i32,
                &mut fp_hdl,
            )
        }
        .check_error("getting front port handle")?;
        Ok(FrontPortHandle {
            dev_id: hdl.dev_id,
            fp_hdl,
        })
    }

    /// Given a PortHdl, return the front-panel port it maps to
    pub fn from_port_hdl(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<Self> {
        let connector = match port_hdl.connector {
            Connector::CPU => match hdl.eth_connector_id {
                Some(id) => Ok(id),
                None => {
                    Err(AsicError::InvalidArg("no CPU ports found".to_string()))
                }
            },
            Connector::QSFP(c) => Ok(c),
        }?;
        Ok(FrontPortHandle::new(
            hdl.dev_id,
            connector,
            port_hdl.channel,
        ))
    }

    /// Get the first front-panel port.  Whether this is actually "first" in any
    /// meaningful sense in the geographical layout of the system is unknown.  This
    /// is just used as an anchor point when iterating over all of the ports in the
    /// system.
    pub fn get_first(dev_id: i32) -> AsicResult<FrontPortHandle> {
        let mut fp_hdl = bf_pal_front_port_handle_t {
            conn_id: 0,
            chnl_id: 0,
        };

        unsafe { bf_pm_port_front_panel_port_get_first(dev_id, &mut fp_hdl) }
            .check_error("getting first front port handle")?;

        Ok(FrontPortHandle { dev_id, fp_hdl })
    }

    /// Get the next front-panel port according to some consistent, well-known
    /// but opaque algorithm.
    pub fn get_next(&self) -> AsicResult<FrontPortHandle> {
        let mut fp_hdl = bf_pal_front_port_handle_t {
            conn_id: 0,
            chnl_id: 0,
        };

        unsafe {
            // The get_next() routine doesn't modify the old handle, so there is
            // no need for us to take a mutable 'self'.  To satisfy the
            // generated code constraints, make a throw-away copy.
            let mut old = self.fp_hdl;
            bf_pm_port_front_panel_port_get_next(
                self.dev_id,
                &mut old,
                &mut fp_hdl,
            )
        }
        .check_error("getting first front port handle")?;

        Ok(FrontPortHandle {
            dev_id: self.dev_id,
            fp_hdl,
        })
    }

    /// Get a raw pointer to the front_panel structure, so we can pass it as
    /// an argument to the SDE.
    pub fn ptr(&mut self) -> *mut bf_pal_front_port_handle_t {
        &mut self.fp_hdl as *mut bf_pal_front_port_handle_t
    }
}

impl fmt::Debug for FrontPortHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(conn: {} chan: {})",
            self.fp_hdl.conn_id, self.fp_hdl.chnl_id
        )
    }
}

fn speed_to_bf(speed: PortSpeed) -> bf_port_speed_t {
    match speed {
        PortSpeed::Speed0G => bf_port_speed_e_BF_SPEED_NONE,
        PortSpeed::Speed1G => bf_port_speed_e_BF_SPEED_1G,
        PortSpeed::Speed10G => bf_port_speed_e_BF_SPEED_10G,
        PortSpeed::Speed25G => bf_port_speed_e_BF_SPEED_25G,
        PortSpeed::Speed40G => bf_port_speed_e_BF_SPEED_40G,
        PortSpeed::Speed50G => bf_port_speed_e_BF_SPEED_50G,
        PortSpeed::Speed100G => bf_port_speed_e_BF_SPEED_100G,
        PortSpeed::Speed200G => bf_port_speed_e_BF_SPEED_200G,
        PortSpeed::Speed400G => bf_port_speed_e_BF_SPEED_400G,
    }
}

fn media_from_bf(media: bf_media_type_t) -> PortMedia {
    match media {
        bf_media_type_e_BF_MEDIA_TYPE_COPPER => PortMedia::Copper,
        bf_media_type_e_BF_MEDIA_TYPE_OPTICAL => PortMedia::Optical,
        _ => PortMedia::Unknown,
    }
}

fn fec_to_bf(fec: PortFec) -> u32 {
    match fec {
        PortFec::None => bf_fec_type_e_BF_FEC_TYP_NONE,
        PortFec::Firecode => bf_fec_type_e_BF_FEC_TYP_FIRECODE,
        PortFec::RS => bf_fec_type_e_BF_FEC_TYP_REED_SOLOMON,
    }
}

/// Given a PortHdl, return the type of media connected to that port.  There is
/// no option to return "no media attached".  If we don't detect something
/// recognizable, we return "Unknown".
pub fn get_media(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<PortMedia> {
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let port = phys_ports.get_phys_mut(&port_hdl.connector)?;

    // At the platform layer we know what a port's media type is at startup,
    // but the SDE doesn't make that information available to us until the
    // port is configured.  Once a port is configured however, the media type
    // won't change.  So once we know a port's media type, we can cache the
    // result.
    if port.media == PortMedia::Unknown {
        port.media = match port.connector {
            Connector::CPU => PortMedia::CPU,
            Connector::QSFP(c) => {
                let mut fp = FrontPortHandle::new(hdl.dev_id, c, 0);
                let mut tmp = bf_media_type_e_BF_MEDIA_TYPE_OPTICAL;
                match unsafe {
                    bf_pm_port_media_type_get(hdl.dev_id, fp.ptr(), &mut tmp)
                }
                .check_error("getting media type")
                {
                    Ok(_) => media_from_bf(tmp),
                    Err(_) => PortMedia::Unknown,
                }
            }
        };
    }

    Ok(port.media)
}

pub fn get_link_up(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<bool> {
    let phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.get_tofino_port(port_hdl)?;
    let dev = hdl.dev_id;
    let port = config.port_id as i32;

    let mut up = 0;
    match unsafe { bf_port_oper_state_get(dev, port, &mut up) } {
        BF_SUCCESS => match up {
            1 => Ok(true),
            _ => Ok(false),
        },
        e => {
            slog::error!(hdl.log, "failed to get port state: {:?}", e);
            Err(sde_error("getting port link state", e))
        }
    }
}

pub fn get_enable(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<bool> {
    let dev = hdl.dev_id;
    let mut enabled = false;

    let mut fp = FrontPortHandle::from_port_hdl(hdl, port_hdl)?;
    match unsafe { bf_pm_port_is_enabled(dev, fp.ptr(), &mut enabled) } {
        BF_SUCCESS => Ok(enabled),
        e => {
            slog::error!(hdl.log, "failed to get port enable state: {:?}", e);
            Err(sde_error("getting port enable state", e))
        }
    }
}

pub fn set_enable(
    hdl: &Handle,
    port_hdl: PortHdl,
    enable: bool,
) -> AsicResult<()> {
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let dev = hdl.dev_id;
    let config = phys_ports.get_tofino_port_mut(port_hdl)?;
    let mut fp = FrontPortHandle::from_port_hdl(hdl, port_hdl)?;

    match enable {
        true => {
            debug!(hdl.log, "enable {:?}", port_hdl);
            unsafe { bf_pm_port_enable(dev, fp.ptr()) }
                .check_error("enabling port")?;
        }
        false => {
            debug!(hdl.log, "disable {:?}", port_hdl);
            unsafe { bf_pm_port_disable(dev, fp.ptr()) }
                .check_error("disabling port")?;
        }
    };

    config.enabled = enable;
    Ok(())
}

pub fn set_kr_mode(
    hdl: &Handle,
    port_hdl: PortHdl,
    kr: bool,
) -> AsicResult<()> {
    let mut fp = FrontPortHandle::from_port_hdl(hdl, port_hdl)?;
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.get_tofino_port_mut(port_hdl)?;

    debug!(hdl.log, "set_kr_mode {:?}: {}", port_hdl, kr);
    let mode = match kr {
        true => bf_pm_port_kr_mode_policy_e_PM_KR_FORCE_ENABLE,
        false => bf_pm_port_kr_mode_policy_e_PM_KR_FORCE_DISABLE,
    };

    unsafe { bf_pm_port_kr_mode_set(hdl.dev_id, fp.ptr(), mode) }
        .check_error("setting KR mode")?;

    config.kr = kr;
    Ok(())
}

pub fn get_kr_mode(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<bool> {
    let mut fp = FrontPortHandle::from_port_hdl(hdl, port_hdl)?;
    let mut mode = 0;
    unsafe { bf_pm_port_kr_mode_get(hdl.dev_id, fp.ptr(), &mut mode) }
        .check_error("getting KR mode")?;

    // XXX: handle DEFAULT
    match mode {
        bf_pm_port_kr_mode_policy_e_PM_KR_FORCE_ENABLE => Ok(true),
        _ => Ok(false),
    }
}

pub fn set_autoneg_mode(
    hdl: &Handle,
    port_hdl: PortHdl,
    an: bool,
) -> AsicResult<()> {
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.get_tofino_port_mut(port_hdl)?;

    debug!(hdl.log, "set_an_mode {:?}: {}", port_hdl, an);
    let mode = match an {
        true => bf_pm_port_autoneg_policy_e_PM_AN_FORCE_ENABLE,
        false => bf_pm_port_autoneg_policy_e_PM_AN_FORCE_DISABLE,
    };

    let mut fp = FrontPortHandle::from_port_hdl(hdl, port_hdl)?;
    unsafe { bf_pm_port_autoneg_set(hdl.dev_id, fp.ptr(), mode) }
        .check_error("setting AN mode")?;

    config.autoneg = an;
    Ok(())
}

pub fn get_autoneg_mode(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<bool> {
    if port_hdl.is_cpu() {
        return Ok(false);
    }

    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.get_tofino_port_mut(port_hdl)?;

    Ok(config.autoneg)
}

pub fn set_prbs(
    hdl: &Handle,
    port_hdl: PortHdl,
    mode: PortPrbsMode,
) -> AsicResult<()> {
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.get_tofino_port_mut(port_hdl)?;

    if config.enabled && config.prbs == PortPrbsMode::Mission {
        return Err(AsicError::InvalidArg(
            "port must be disabled before switching to PRBS".to_string(),
        ));
    }

    let bf_mode = match mode {
        PortPrbsMode::Mode31 => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_31,
        PortPrbsMode::Mode23 => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_23,
        PortPrbsMode::Mode15 => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_15,
        PortPrbsMode::Mode13 => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_13,
        PortPrbsMode::Mode11 => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_11,
        PortPrbsMode::Mode9 => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_9,
        PortPrbsMode::Mode7 => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_7,
        PortPrbsMode::Mission => bf_port_prbs_mode_e_BF_PORT_PRBS_MODE_NONE,
    };

    let mut fp = FrontPortHandle::from_port_hdl(hdl, port_hdl)?;
    unsafe { bf_pm_port_prbs_mode_set(hdl.dev_id, fp.ptr(), 1, bf_mode) }
        .check_error("setting prbs mode")?;
    config.prbs = mode;
    Ok(())
}

/// Look up the port_hdl -> asic_id mapping
pub fn to_asic_id(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<AsicId> {
    hdl.phys_ports.lock().unwrap().to_asic_id(port_hdl)
}

/// Look up the asic_id -> port_hdl mapping
pub fn from_asic_id(hdl: &Handle, asic_id: AsicId) -> AsicResult<PortHdl> {
    hdl.phys_ports.lock().unwrap().from_asic_id(asic_id)
}

/// Return the number of lanes assigned to this port
pub fn get_lane_cnt(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<u8> {
    let phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.get_tofino_port(port_hdl)?;
    Ok(u8::try_from(config.channels.len()).unwrap())
}

/// Add a new configured port to a physical port.
pub fn add_port(
    hdl: &Handle,
    connector: Connector,
    lane: Option<u8>,
    speed: PortSpeed,
    fec: PortFec,
) -> AsicResult<(PortHdl, AsicId)> {
    // Get the physical switch ports for the ASIC.
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    debug!(
        hdl.log,
        "add_port on connector {connector:?}";
        "lane" => ?lane,
        "speed" => ?speed,
        "fec" => ?fec,
    );

    // Find the physical port for this connector, and channels if available.
    //
    // IMPORTANT: `channels` must be released back to the `phys_port` if any
    // later operations fail, _before_ returning from this function.
    let phys_port = phys_ports.get_phys_mut(&connector)?;
    let channels = phys_port.allocate_channels_for(lane, speed)?;

    // Create a `PortHdl` using the first channel.
    let port_hdl = PortHdl::new(connector, channels[0]);

    // Create Tofino-related handles, needed for calling into the BF SDE.
    let mut fp = match FrontPortHandle::from_port_hdl(hdl, port_hdl) {
        Ok(fp) => fp,
        Err(e) => {
            // Release the channels we acquired above.
            let _ = phys_port.free(&channels);
            return Err(e);
        }
    };
    let port_id = match fp.get_dev_port() {
        Ok(id) => id,
        Err(e) => {
            // Release the channels we acquired above.
            let _ = phys_port.free(&channels);
            return Err(e);
        }
    };
    let dev = hdl.dev_id;

    // Convert to SDE-internal representations of speed and FEC.
    let bf_speed = speed_to_bf(speed);
    let bf_fec = fec_to_bf(fec);

    // Verify with the SDE that the requested channels / speed / FEC are valid.
    if !unsafe {
        bf_pm_port_valid_speed_and_channel(
            dev,
            port_id as i32,
            bf_speed,
            channels.len() as u32,
            bf_fec,
        )
    } {
        let _ = phys_port.free(&channels);
        return Err(AsicError::InvalidArg(
            "invalid port configuration".to_string(),
        ));
    }

    // Actually add the port to the SDE.
    if let Err(e) = unsafe { bf_pm_port_add(dev, fp.ptr(), bf_speed, bf_fec) }
        .check_error("configuring port")
    {
        let _ = phys_port.free(&channels);
        return Err(e);
    }

    // Create and add the configured port data to phys_ports.
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
    Ok((port_hdl, port_id))
}

/// Remove a configured port from a physical port, making its channels available
/// for future configurations.
pub fn delete_port(hdl: &Handle, port_hdl: PortHdl) -> AsicResult<()> {
    let mut phys_ports = hdl.phys_ports.lock().unwrap();
    let config = phys_ports.delete_tofino_port(port_hdl)?;
    let mut fp = FrontPortHandle::from_port_hdl(hdl, port_hdl)?;

    debug!(hdl.log, "delete_port {:?}", port_hdl);
    let phys_port = phys_ports.get_phys_mut(&port_hdl.connector)?;
    if let Err(e) = phys_port.free(&config.channels) {
        slog::error!(
            hdl.log,
            "while freeing channels for {:?}: {:?}",
            port_hdl,
            e
        )
    };

    if let Err(e) = unsafe { bf_pm_port_delete(hdl.dev_id, fp.ptr()) }
        .check_error("deleting port")
    {
        slog::error!(hdl.log, "{:?}", e)
    };

    Ok(())
}

/// Gets a list of all available channels on this connector
pub fn get_avail_channels(
    hdl: &Handle,
    connector: Connector,
) -> AsicResult<Vec<u8>> {
    let phys_ports = hdl.phys_ports.lock().unwrap();
    match phys_ports.connectors.get(&connector) {
        Some(phys_port) => Ok(phys_port.get_available_channels()),
        None => Err(AsicError::InvalidArg("no such connector".to_string())),
    }
}

/// Returns a vector containing all the physical port IDs in the switch
pub fn get_connectors(hdl: &Handle) -> Vec<Connector> {
    let phys_ports = hdl.phys_ports.lock().unwrap();

    phys_ports.connectors.keys().copied().collect()
}

pub fn init(dev_id: i32) -> AsicResult<PortData> {
    let mut map_to_asic_id = BTreeMap::new();
    let mut map_from_asic_id = BTreeMap::new();
    let mut connectors = BTreeMap::new();
    let mut eth_connector_id = None;

    let eth_port = match unsafe { bf_eth_cpu_port_get(dev_id) } {
        -1 => None,
        x if x >= 0 && x < BF_PORT_COUNT as i32 => Some(x as PortId),
        x => panic!("invalid CPU ETH port: {}", x),
    };

    // Iterate over all of the ports the SDE has inventoried, populating our
    // internal list of Connectors and (connector,channel)<->asic_id maps.
    let mut fp = Some(FrontPortHandle::get_first(dev_id)?);
    while let Some(x) = fp {
        let (conn, chan) = (x.fp_hdl.conn_id, x.fp_hdl.chnl_id as u8);
        let asic_id = match x.get_dev_port() {
            Ok(asic_id) => asic_id,
            Err(e) => {
                eprintln!("failed to find asic_id for {conn}/{chan}: {e:?}");
                continue;
            }
        };

        let connector = if Some(asic_id) == eth_port {
            Connector::CPU
        } else {
            Connector::QSFP(conn)
        };

        // When we find the channel 0 for a connector, we add that
        // connector to our internal list.
        if chan == 0 {
            if connector == Connector::CPU {
                eth_connector_id = Some(conn);
            };
            connectors.insert(connector, PhysPort::new(connector)?);
        }

        map_to_asic_id.insert((connector, chan), asic_id);
        map_from_asic_id.insert(asic_id, (connector, chan));

        fp = match x.get_next() {
            Ok(x) => Some(x),
            Err(_) => None,
        }
    }

    let _ = unsafe { bf_pm_port_delete_all(dev_id) };

    Ok(PortData {
        eth_port,
        eth_connector_id,
        connectors,
        config_ports: BTreeMap::new(),
        map_to_asic_id,
        map_from_asic_id,
    })
}
