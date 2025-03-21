// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use slog::{error, info, o};
use tofino::fuse::ChipId;

use crate::tofino_common;
use crate::Identifiers;
use aal::PortUpdate;
use common::ports::*;

mod bf_wrapper;
mod genpd;

mod link_fsm;
pub mod multicast;
pub mod ports;
pub mod qsfp;
mod sde_log;
pub mod serdes;
pub mod stats;
pub mod table;

use aal::{
    AsicError, AsicOps, AsicResult, Connector, PortHdl, SidecarIdentifiers,
};
pub use link_fsm::FsmState;
pub use link_fsm::PortFsmState;

/// There are three generations of the Tofino ASIC, which the SDE refers to as
/// "families".  Tofino1 predates Oxide, but there is a single reference system
/// in the lab.  Tofino3 was cancelled before being released, so we are unlikely
/// to ever run across one.  The sidecar is based on Tofino2, and is thus the
/// only family we expect to encounter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TofinoFamily {
    Tofino1,
    Tofino2,
    Tofino3,
}

/// The following are the Tofino-specific dpd configuration settings.
#[derive(Debug)]
pub struct AsicConfig {
    /// /dev path to the Tofino device.
    pub devpath: Option<String>,

    /// IP interface over which to communicate with the Hubris transceivers task
    /// for controlling QSFP modules.
    pub xcvr_iface: Option<String>,

    /// Revision of the Sidecar board we are managing.
    ///
    /// The default value is "B".
    pub board_rev: String,
}

impl Default for AsicConfig {
    fn default() -> Self {
        Self {
            devpath: None,
            xcvr_iface: None,
            board_rev: String::from("B"),
        }
    }
}

impl AsicOps for Handle {
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
        ports::set_kr_mode(self, port_hdl, kr)
    }

    fn port_autoneg_get(&self, port_hdl: PortHdl) -> AsicResult<bool> {
        ports::get_autoneg_mode(self, port_hdl)
    }

    fn port_autoneg_set(&self, port_hdl: PortHdl, an: bool) -> AsicResult<()> {
        ports::set_autoneg_mode(self, port_hdl, an)
    }

    fn port_prbs_set(
        &self,
        port_hdl: PortHdl,
        mode: PortPrbsMode,
    ) -> AsicResult<()> {
        ports::set_prbs(self, port_hdl, mode)
    }

    fn port_add(
        &self,
        connector: Connector,
        lane: Option<u8>,
        speed: PortSpeed,
        fec: PortFec,
    ) -> AsicResult<(PortHdl, u16)> {
        ports::add_port(self, connector, lane, speed, fec)
    }

    fn port_delete(&self, port_hdl: PortHdl) -> AsicResult<()> {
        ports::delete_port(self, port_hdl)
    }

    fn get_connectors(&self) -> Vec<Connector> {
        ports::get_connectors(self)
    }

    fn connector_avail_channels(
        &self,
        connector: Connector,
    ) -> AsicResult<Vec<u8>> {
        ports::get_avail_channels(self, connector)
    }

    fn mc_domains(&self) -> Vec<u16> {
        multicast::domains(self)
    }

    fn mc_port_count(&self, group_id: u16) -> AsicResult<usize> {
        multicast::domain_port_count(self, group_id)
    }

    fn mc_port_add(&self, group_id: u16, port: u16) -> AsicResult<()> {
        multicast::domain_add_port(self, group_id, port)
    }

    fn mc_port_remove(&self, group_id: u16, port: u16) -> AsicResult<()> {
        multicast::domain_remove_port(self, group_id, port)
    }

    fn mc_group_create(&self, group_id: u16) -> AsicResult<()> {
        multicast::domain_create(self, group_id)
    }

    fn mc_group_destroy(&self, group_id: u16) -> AsicResult<()> {
        multicast::domain_destroy(self, group_id)
    }

    // Ideally we would get some sort of sidecar-level ID from the FRUID.
    // Until/unless that is possible, we will use the chip_id from the tofino
    // fuse on the sidecar.  Embedded within this ID is the fab, lot, wafer id,
    // and location on the wafer.  This should be unique and tied to this board.
    //
    // We also retrieve the fab, lot, wafer, and location from the FRUID
    // indvidually.
    fn get_sidecar_identifiers(&self) -> AsicResult<impl SidecarIdentifiers> {
        let pci = match &self.dev_path {
            Some(path) => tofino::pci::Pci::new(path, tofino::REGISTER_SIZE),
            None => {
                let Ok(Some(tofino)) = tofino::get_tofino() else {
                    return Err(AsicError::AsicMissing);
                };
                tofino.open_pci()
            }
        }
        .map_err(|e| AsicError::Internal(format!("{e:?}")))?;
        let fuse = tofino::fuse::Fuse::read(&pci)
            .map_err(|e| AsicError::Internal(format!("{e:?}")))?;

        let sidecar_id = uuid::Uuid::from_u128(fuse.chip_id as u128);
        let chip_id: ChipId = fuse.chip_id.into();

        Ok(Identifiers {
            id: sidecar_id,
            asic_backend: "tofino_asic".to_string(),
            fab: Some(chip_id.fab),
            lot: Some(chip_id.lot),
            wafer: Some(chip_id.wafer),
            wafer_loc: Some(wafer_loc_from_coords(
                chip_id.xsign,
                chip_id.x,
                chip_id.ysign,
                chip_id.y,
            )),
        })
    }

    fn register_port_update_handler(
        &self,
        tx: tokio::sync::mpsc::UnboundedSender<PortUpdate>,
    ) -> AsicResult<()> {
        bf_wrapper::register_handler(tx)
    }

    /// Update all of the per-lane eq settings for the specified port.
    fn port_tx_eq_set(
        &self,
        port_hdl: PortHdl,
        settings: &TxEq,
    ) -> AsicResult<()> {
        let settings = serdes::TxEqSettings::from(*settings);
        serdes::port_tx_eq_set(self, port_hdl, &settings)
    }
}

pub struct Handle {
    dev_id: genpd::bf_dev_id_t,
    dev_path: Option<String>,
    board_rev: String,
    bf: Mutex<bf_wrapper::BfCommon>,
    rt: tofino_common::BfRt,
    log: slog::Logger,
    phys_ports: Mutex<ports::PortData>,
    domains: Mutex<HashMap<u16, multicast::DomainState>>,
    eth_connector_id: Option<u32>,
}

/// Get the wafer location from the x and y coordinates using the
/// sign and position values.
fn wafer_loc_from_coords(
    x_sign: u8,
    x_pos: u8,
    y_sign: u8,
    y_pos: u8,
) -> (i16, i16) {
    let x = if x_sign == 0 {
        i16::from(x_pos)
    } else {
        -i16::from(x_pos)
    };
    let y = if y_sign == 0 {
        i16::from(y_pos)
    } else {
        -i16::from(y_pos)
    };

    (x, y)
}

fn version_check(
    log: &slog::Logger,
    devpath: &Option<String>,
) -> AsicResult<()> {
    let version = match bf_wrapper::bf_driver_version(devpath) {
        Ok(v) => Ok(v),
        Err(AsicError::Io { err, .. })
            if err.kind() == std::io::ErrorKind::NotFound =>
        {
            Err(AsicError::AsicMissing)
        }
        Err(err) => Err(err),
    }?;
    let required = semver::VersionReq::parse(">=1.0.0").unwrap();
    match required.matches(&version) {
        true => {
            info!(log, "found tofino driver {}", version);
            Ok(())
        }
        false => {
            error!(
                log,
                "found tofino driver {}.  We need {}", version, required
            );
            Err(AsicError::OperationUnsupported)
        }
    }
}

impl Handle {
    pub fn new(log: &slog::Logger, config: &AsicConfig) -> AsicResult<Self> {
        let log = log.new(o!());

        if std::env::var("TOFINO_HOST").is_err() {
            version_check(&log, &config.devpath)?;
        }

        let qsfp_log = log.new(o!("unit" => "qsfp-ffi"));
        qsfp::set_logger(qsfp_log);
        let sde_log = log.new(o!("unit" => "bf-sde"));
        sde_log::set_logger(sde_log);

        let dev_id = 0;

        let p4_dir = tofino_common::get_p4_dir()?;
        let mut bf = bf_wrapper::bf_init(
            &log,
            &config.devpath,
            &p4_dir,
            &config.board_rev,
        )?;
        let rt = tofino_common::BfRt::init(&p4_dir)?;
        let domains = Mutex::new(HashMap::new());
        let phys_ports = ports::init(dev_id)?;
        let eth_connector_id = phys_ports.eth_connector_id;

        // Note: we assume that bf_mc_init() has been called as part of the
        // bf_switch_init() operation.
        bf.mcast_hdl = multicast::create_session()?;

        Ok(Handle {
            dev_id,
            dev_path: config.devpath.clone(),
            board_rev: config.board_rev.to_string(),
            bf: Mutex::new(bf),
            rt,
            log: log.new(o!("unit" => "tofino_asic")),
            phys_ports: Mutex::new(phys_ports),
            domains,
            eth_connector_id,
        })
    }

    pub fn is_model(&self) -> bool {
        let bf = self.bf_get();
        bf.is_sw_model
    }

    pub fn board_rev(&self) -> String {
        self.board_rev.to_string()
    }

    pub fn bf_get(&self) -> MutexGuard<bf_wrapper::BfCommon> {
        self.bf.lock().unwrap()
    }

    pub fn fini(&self) {
        let mut bf = self.bf_get();

        bf_wrapper::bf_fini(&mut bf);
    }

    /// Set the transmit channel used by the SDE to ask about the transceivers.
    pub fn initialize_qsfp_state(
        &self,
        request_tx: tokio::sync::mpsc::Sender<qsfp::SdeTransceiverMessage>,
    ) {
        qsfp::set_simulator(self.is_model());
        qsfp::set_transceiver_tx(request_tx);
    }

    /// Clear the transmit channel used by the SDE to ask about the
    /// transceivers.
    ///
    /// This is useful because the VLAN interface we use to talk to the SP may
    /// disappear or become unusable. In that situation, we want to communicate
    /// to the SDE that its requests will fail.
    pub fn clear_qsfp_state(&self) {
        qsfp::clear_transceiver_tx();
    }
}

pub fn sde_error(ctx: impl ToString, err: bf_status_t) -> AsicError {
    match err {
        bf_wrapper::BF_ALREADY_EXISTS => AsicError::Exists,
        bf_wrapper::BF_OBJECT_NOT_FOUND => AsicError::Missing(ctx.to_string()),
        _ => AsicError::SdeError {
            ctx: ctx.to_string(),
            err: bf_wrapper::bf_error_str(err),
        },
    }
}

pub trait CheckError {
    fn check_error(&self, context: &str) -> AsicResult<()>;
}

impl CheckError for i32 {
    fn check_error(&self, context: &str) -> AsicResult<()> {
        match *self {
            BF_SUCCESS => Ok(()),
            err => Err(sde_error(context, err)),
        }
    }
}

pub trait LogError {
    fn log_error(self, hdl: &Handle) -> Self;
}

impl LogError for AsicResult<()> {
    fn log_error(self, hdl: &Handle) -> AsicResult<()> {
        if let Err(e) = &self {
            slog::error!(hdl.log, "{:?}", e);
        }
        self
    }
}

#[allow(non_camel_case_types)]
pub type bf_status_t = i32;
#[allow(non_camel_case_types)]
pub type pipe_status_t = i32;

/* Constants defined in the bf header files that aren't picked up by bindgen */
pub const BF_SUCCESS: bf_status_t = 0;
pub const BF_INVALID_ARG: bf_status_t = 2;
pub const BF_NOT_FOUND: bf_status_t = 6;
pub const BF_IO_ERROR: bf_status_t = 14;
pub const BF_OTHER: bf_status_t = 15;

pub const PIPE_SUCCESS: pipe_status_t = 0;

pub const BF_MAX_SUBDEV_COUNT: u32 = 2; // Maximum sub-devices (tf3-only?)
pub const BF_SUBDEV_PIPE_COUNT: u32 = 4;
pub const BF_PIPE_COUNT: u32 = BF_MAX_SUBDEV_COUNT * BF_SUBDEV_PIPE_COUNT;
pub const BF_PIPE_PORT_COUNT: u32 = 72; // Ports per pipe
pub const BF_PORT_COUNT: u32 = BF_PIPE_PORT_COUNT * BF_PIPE_COUNT; // total ports
pub const BF_LAG_COUNT: u32 = 256; // LAGs in the ASIC

// Sizes of the port and LAG bitmap arrays in a multicast group
pub const BF_MC_PORT_ARRAY_SIZE: usize = (BF_PORT_COUNT as usize + 7) / 8;
pub const BF_MC_LAG_ARRAY_SIZE: usize = (BF_LAG_COUNT as usize + 7) / 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wafer_location_from_coords() {
        assert_eq!(wafer_loc_from_coords(0, 0, 0, 0), (0, 0));
        assert_eq!(wafer_loc_from_coords(0, 10, 0, 0), (10, 0));
        assert_eq!(wafer_loc_from_coords(1, 10, 0, 0), (-10, 0));
        assert_eq!(wafer_loc_from_coords(0, 0, 1, 0), (0, 0));
        assert_eq!(wafer_loc_from_coords(0, 0, 1, 10), (0, -10));
        assert_eq!(wafer_loc_from_coords(1, 10, 1, 10), (-10, -10));
    }
}
