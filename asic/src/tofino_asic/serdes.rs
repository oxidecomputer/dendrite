// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(clippy::manual_range_contains)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::{From, TryFrom};

use crate::tofino_asic::genpd::*;
use crate::tofino_asic::ports;
use crate::tofino_asic::{CheckError, Handle};
use aal::{AsicError, AsicResult, PortHdl};

/// Signal encoding
#[derive(PartialEq, Deserialize, Serialize, JsonSchema)]
pub enum LaneEncoding {
    /// Pulse Amplitude Modulation 4-level
    Pam4,
    /// Non-Return-to-Zero encoding
    Nrz,
    /// No encoding selected
    None,
}

impl TryFrom<bf_serdes_encoding_mode_t> for LaneEncoding {
    type Error = AsicError;

    fn try_from(mode: bf_serdes_encoding_mode_t) -> Result<Self, AsicError> {
        match mode {
            bf_serdes_encoding_mode_t_BF_SERDES_ENC_MODE_NRZ => {
                Ok(LaneEncoding::Nrz)
            }
            bf_serdes_encoding_mode_t_BF_SERDES_ENC_MODE_PAM4 => {
                Ok(LaneEncoding::Pam4)
            }
            bf_serdes_encoding_mode_t_BF_SERDES_ENC_MODE_NONE => {
                Ok(LaneEncoding::None)
            }
            _ => Err(AsicError::InvalidEncodingMode(mode)),
        }
    }
}

fn port_encoding_mode(dev_id: i32, port_id: u16) -> AsicResult<LaneEncoding> {
    let mut enc_mode = 0;
    unsafe {
        bf_port_encoding_mode_get(dev_id, port_id as i32, &mut enc_mode)
            .check_error("getting lane encoding mode")?;
    }
    LaneEncoding::try_from(enc_mode)
}

// Get the number of lanes configured for this port
fn lane_count(hdl: &Handle, port: PortHdl) -> AsicResult<u32> {
    match hdl
        .phys_ports
        .lock()
        .unwrap()
        .get_tofino_port(port)?
        .channels
        .len()
    {
        n if n < 1 || n > 8 => Err(AsicError::Internal(format!(
            "configured port has {n} lanes"
        ))),
        n => Ok(n as u32),
    }
}

// Get the mac block and initial channel for this port
fn mac_channel(hdl: &Handle, port_id: u16) -> AsicResult<(u32, u32)> {
    let mut mac = 0u32;
    let mut channel = 0u32;

    unsafe {
        lld_sku_map_dev_port_id_to_mac_ch(
            hdl.dev_id,
            port_id as u32,
            &mut mac,
            &mut channel,
        )
        .check_error("getting mac block and channel")?;
    }
    Ok((mac, channel))
}

#[derive(Deserialize, Serialize, JsonSchema)]
enum Polarity {
    Normal,
    Inverted,
}

impl From<bool> for Polarity {
    fn from(p: bool) -> Self {
        match p {
            true => Polarity::Inverted,
            false => Polarity::Normal,
        }
    }
}

/// Mapping of the logical lanes in a link to their physical instantiation in
/// the MAC/serdes interface.
//
// For each lane assigned to the port, this captures the mac block, the logical
// lane within the mac block, the physical rx and tx lanes, and the polarity of
// each.  All of these values are determined by the physical layout of the
// board, should be identical across all sidecars with the same board revision,
// and shouldn't change from run to run.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LaneMap {
    /// MAC block in the tofino ASIC
    mac_block: u32,
    /// logical lane within the mac block for each lane
    logical_lane: Vec<u32>,
    /// Rx logical->physical mapping
    rx_phys: Vec<u32>,
    /// Tx logical->physical mapping
    tx_phys: Vec<u32>,
    /// Rx polarity
    rx_polarity: Vec<Polarity>,
    /// Tx polarity
    tx_polarity: Vec<Polarity>,
}

/// Fetch the logical->physical lane mappings for the given port.
pub fn lane_map_get(hdl: &Handle, port: PortHdl) -> AsicResult<LaneMap> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let lanes = lane_count(hdl, port)?;

    let mut rx_phys = vec![0; 8];
    let mut tx_phys = vec![0; 8];

    unsafe {
        bf_tof2_serdes_lane_map_get(
            hdl.dev_id,
            port_id as i32,
            rx_phys.as_mut_ptr(),
            tx_phys.as_mut_ptr(),
        )
        .check_error("getting lane map")?;
    }
    let (mac_block, channel) = mac_channel(hdl, port_id)?;
    let start = channel as usize;
    let end = start + lanes as usize;
    let rx_phys = rx_phys[start..end].to_vec();
    let tx_phys = tx_phys[start..end].to_vec();
    let logical_lane = (start..end).map(|l| l as u32).collect();

    let mut rx_polarity = Vec::with_capacity(lanes as usize);
    let mut inverted = false;
    for lane in 0..lanes {
        unsafe {
            bf_tof2_serdes_rx_polarity_hw_get(
                hdl.dev_id,
                port_id as i32,
                lane,
                &mut inverted,
            )
            .check_error("fetching rx polarity")?
        };
        rx_polarity.push(inverted.into())
    }

    let mut tx_polarity = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        unsafe {
            bf_tof2_serdes_tx_polarity_hw_get(
                hdl.dev_id,
                port_id as i32,
                lane,
                &mut inverted,
            )
            .check_error("fetching tx polarity")?
        };
        tx_polarity.push(inverted.into());
    }
    Ok(LaneMap {
        mac_block,
        logical_lane,
        rx_phys,
        tx_phys,
        rx_polarity,
        tx_polarity,
    })
}

/// Per-lane Rx signal information
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RxSigInfo {
    /// Rx signal detected
    pub sig_detect: bool,
    /// CDR lock achieved
    pub phy_ready: bool,
    /// Apparent PPM difference between local and remote
    pub ppm: i32,
}

// Fetch the Rx signal information for the given port and logical lane
fn lane_rx_sig_info_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<RxSigInfo> {
    let port_id = ports::to_asic_id(hdl, port)?;

    let mut sig_detect = false;
    let mut phy_ready = false;
    let mut ppm = 0;

    unsafe {
        bf_tof2_serdes_rx_sig_info_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut sig_detect,
            &mut phy_ready,
            &mut ppm,
        )
        .check_error("fetching rx signal info")?
    };

    Ok(RxSigInfo {
        sig_detect,
        phy_ready,
        ppm,
    })
}

/// Collect all of the per-lane rx signal info for the specified port.
///
/// The returned value contains a vector of `RxSigInfo`, indexed by the logical
/// lane ID within the link.
pub fn port_rx_sig_info_get(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<Vec<RxSigInfo>> {
    let lanes = lane_count(hdl, port)?;
    let mut rval = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        rval.push(lane_rx_sig_info_get(hdl, port, lane)?)
    }
    Ok(rval)
}

/// There are two groups of TxEqSettings: the one cached in the software and the
/// one currently set in the hardware.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct TxEqHwSw {
    /// Value cached in software
    pub sw: TxEqSettings,
    /// The value actually in use by the hardware
    pub hw: TxEqSettings,
}

/// Tx equalization settings
#[derive(Clone, Default, Debug, Deserialize, Serialize, JsonSchema)]
pub struct TxEqSettings {
    /// Precursor 2
    pub pre2: i32,
    /// Precursor 1
    pub pre1: i32,
    /// Main
    pub main: i32,
    /// Postcursor 1
    pub post1: i32,
    /// Postcursor 2
    pub post2: i32,
}

impl From<TxEqSettings> for common::ports::TxEq {
    fn from(txeq: TxEqSettings) -> Self {
        common::ports::TxEq {
            pre1: Some(txeq.pre1),
            pre2: Some(txeq.pre2),
            main: Some(txeq.main),
            post2: Some(txeq.post2),
            post1: Some(txeq.post1),
        }
    }
}

impl From<common::ports::TxEq> for TxEqSettings {
    fn from(txeq: common::ports::TxEq) -> Self {
        TxEqSettings {
            pre1: txeq.pre1.unwrap_or(0),
            pre2: txeq.pre2.unwrap_or(0),
            main: txeq.main.unwrap_or(0),
            post2: txeq.post2.unwrap_or(0),
            post1: txeq.post1.unwrap_or(0),
        }
    }
}

// Fetch the currently applied tx eq settings for the specified port and
// logical lane
fn lane_tx_eq_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<TxEqHwSw> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut sw = TxEqSettings::default();
    unsafe {
        bf_tof2_serdes_tx_taps_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut sw.pre2,
            &mut sw.pre1,
            &mut sw.main,
            &mut sw.post1,
            &mut sw.post2,
        )
        .check_error("fetching sw tx eq settings")?;
    }
    let mut hw = TxEqSettings::default();
    unsafe {
        bf_tof2_serdes_tx_taps_hw_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut hw.pre2,
            &mut hw.pre1,
            &mut hw.main,
            &mut hw.post1,
            &mut hw.post2,
        )
        .check_error("fetching hw tx eq settings")?
    };

    Ok(TxEqHwSw { sw, hw })
}

/// Collect all of the per-lane eq settings for the specified port.
///
/// The returned value contains a vector of `TxEqHwSw` structures, indexed by
/// the logical lane ID within the link.
pub fn port_tx_eq_get(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<Vec<TxEqHwSw>> {
    let lanes = lane_count(hdl, port)?;
    let mut rval = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        rval.push(lane_tx_eq_get(hdl, port, lane)?)
    }
    Ok(rval)
}

/// Update the currently applied tx eq settings in both the hardware and the
/// software cache for the specified port and logical lane.
pub fn lane_tx_eq_set(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
    settings: &TxEqSettings,
) -> AsicResult<()> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let lanes = lane_count(hdl, port)?;
    if lane >= lanes {
        return Err(AsicError::InvalidArg("lane is out of range".into()));
    }

    unsafe {
        bf_tof2_serdes_tx_taps_set(
            hdl.dev_id,
            port_id as i32,
            lane,
            settings.pre2,
            settings.pre1,
            settings.main,
            settings.post1,
            settings.post2,
            true,
        )
        .check_error("updating tx eq settings")?;
    };

    Ok(())
}

/// Update all of the per-lane eq settings for the specified port.
pub fn port_tx_eq_set(
    hdl: &Handle,
    port: PortHdl,
    settings: &TxEqSettings,
) -> AsicResult<()> {
    let lanes = lane_count(hdl, port)?;
    for lane in 0..lanes {
        lane_tx_eq_set(hdl, port, lane, settings)?
    }

    let mut fp_hdl = ports::FrontPortHandle::from_port_hdl(hdl, port)?;
    unsafe {
        bf_pm_serdes_tx_eq_override_set(hdl.dev_id, fp_hdl.ptr(), true)
            .check_error("setting tx eq override")?;
    }
    Ok(())
}

/// Rx DFE adaptation information
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct DfeAdaptationState {
    /// DFE complete
    pub adapt_done: bool,
    /// Total DFE attempts
    pub adapt_cnt: u32,
    /// DFE attempts since the last read
    pub readapt_cnt: u32,
    /// Times the signal was lost since the last read
    pub link_lost_cnt: u32,
}

// Fetch the state of the Rx Decision Feedback Equalizer adaptation for the
// specified port and logical lane
fn lane_adapt_state_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<DfeAdaptationState> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut state = DfeAdaptationState::default();

    unsafe {
        bf_tof2_serdes_adapt_counts_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut state.adapt_done,
            &mut state.adapt_cnt,
            &mut state.readapt_cnt,
            &mut state.link_lost_cnt,
        )
        .check_error("fetching adaptations state")?
    };

    Ok(state)
}

/// Collect all of the per-lane adaptation info for the specified port. The
/// returned value contains a vector of DfeAdaptationState, indexed by the logical
/// lane ID within the link.
pub fn port_adapt_state_get(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<Vec<DfeAdaptationState>> {
    let lanes = lane_count(hdl, port)?;
    let mut rval = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        rval.push(lane_adapt_state_get(hdl, port, lane)?)
    }
    Ok(rval)
}

/// Eye height(s) for a single lane in mv
#[derive(Deserialize, Serialize, JsonSchema)]
pub enum SerdesEye {
    Nrz(f32),
    Pam4 { eye1: f32, eye2: f32, eye3: f32 },
}

// Returns the eye height(s) for the requested port and virtual lane
fn lane_eye_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<SerdesEye> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut eye1 = 0.0;
    let mut eye2 = 0.0;
    let mut eye3 = 0.0;

    unsafe {
        bf_tof2_serdes_eye_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut eye1,
            &mut eye2,
            &mut eye3,
        )
        .check_error("fetching eye info")?
    };

    match port_encoding_mode(hdl.dev_id, port_id)? {
        LaneEncoding::Nrz => Ok(SerdesEye::Nrz(eye1)),
        LaneEncoding::Pam4 => Ok(SerdesEye::Pam4 { eye1, eye2, eye3 }),
        _ => Err(AsicError::InvalidArg(
            "eye data only available on NRZ/PAM4 encoded lanes".into(),
        )),
    }
}

/// Collect all of the per-lane eye heights for the specified port.
///
/// The returned value contains a vector of SerdesEye` structs, indexed by the
/// logical lane ID within the link.
pub fn port_eye_get(hdl: &Handle, port: PortHdl) -> AsicResult<Vec<SerdesEye>> {
    let lanes = lane_count(hdl, port)?;
    let mut rval = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        rval.push(lane_eye_get(hdl, port, lane)?)
    }
    Ok(rval)
}

/// Tap values for an NRZ DFE
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct NrzDfe {
    pub tap1: u32,
    pub tap2: u32,
    pub tap3: u32,
}

/// Fetch the DFE tap values for a port and logical lane using an NRZ encoding
pub fn nrz_dfe_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<NrzDfe> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut nrz_dfe = NrzDfe::default();

    if port_encoding_mode(hdl.dev_id, port_id)? != LaneEncoding::Nrz {
        return Err(AsicError::InvalidArg(
            "only supported for NRZ-encoded ports".into(),
        ));
    }

    unsafe {
        bf_tof2_serdes_dfe_nrz_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut nrz_dfe.tap1,
            &mut nrz_dfe.tap2,
            &mut nrz_dfe.tap3,
        )
        .check_error("fetching NRZ DFE info")?
    };

    Ok(nrz_dfe)
}

/// PAM4 DFE values
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct Pam4Dfe {
    pub f0: f32,
    pub f1: f32,
    pub ratio: f32,
}

/// Fetch the DFE values for a port and logical lane using a PAM4 encoding
pub fn pam4_dfe_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<Pam4Dfe> {
    let port_id = ports::to_asic_id(hdl, port)?;

    if port_encoding_mode(hdl.dev_id, port_id)? != LaneEncoding::Pam4 {
        return Err(AsicError::InvalidArg(
            "only supported for PAM4-encoded ports".into(),
        ));
    }

    let mut pam4_dfe = Pam4Dfe::default();
    unsafe {
        bf_tof2_serdes_dfe_pam4_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut pam4_dfe.f0,
            &mut pam4_dfe.f1,
            &mut pam4_dfe.ratio,
        )
        .check_error("fetching PAM4 DFE info")?
    };

    Ok(pam4_dfe)
}

/// CTLE map values
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct Ctle {
    pub map0: u32,
    pub map1: u32,
}

/// Fetch the selected CTLE values for the specified port and logical lane
// XXX: the "selector" value doesn't seem to be documented anywhere.  There are
// some magic constants passed to the Credo firmware.  Without more
// information, there doesn't seem to be much value in this data.
pub fn ctle_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
    ctle_sel: u32,
) -> AsicResult<Ctle> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut ctle = Ctle::default();

    unsafe {
        bf_tof2_serdes_ctle_val_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            ctle_sel,
            &mut ctle.map0,
            &mut ctle.map1,
        )
        .check_error("fetching CTLE values")?
    };

    Ok(ctle)
}

/// Fetch the CTLE override value for the specified port and logical lane
pub fn ctle_override_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<u32> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut ctle_over_val = 0;

    unsafe {
        bf_tof2_serdes_ctle_over_val_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut ctle_over_val,
        )
        .check_error("fetching CTLE override value")?
    };

    Ok(ctle_over_val)
}

/// FFE values for PAM4-encoded link
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct Pam4Ffe {
    pub k1: i32,
    pub k2: i32,
    pub k3: i32,
    pub k4: i32,
    pub s1: i32,
    pub s2: i32,
}

/// Fetch the PAM4 FFE values for the specified port and logical lane
pub fn pam4_ffe_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<Pam4Ffe> {
    let port_id = ports::to_asic_id(hdl, port)?;

    if port_encoding_mode(hdl.dev_id, port_id)? != LaneEncoding::Pam4 {
        return Err(AsicError::InvalidArg(
            "only supported for PAM4-encoded ports".into(),
        ));
    }

    let mut ffe = Pam4Ffe::default();
    unsafe {
        bf_tof2_serdes_ffe_taps_pam4_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut ffe.k1,
            &mut ffe.k2,
            &mut ffe.k3,
            &mut ffe.k4,
            &mut ffe.s1,
            &mut ffe.s2,
        )
        .check_error("fetching PAM4 FFE values")?
    };

    Ok(ffe)
}

/// Signal speed and encoding for a single lane
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct EncSpeed {
    pub encoding: LaneEncoding,
    pub gigabits: u32,
}

// Fetch the current encoding and speed for the specified port and logical lane
fn lane_encoding_speed_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<EncSpeed> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let encoding;
    let mut gigabits = 0;

    unsafe {
        let mut enc = 0;
        bf_tof2_serdes_fw_lane_speed_get(
            hdl.dev_id,
            port_id as i32,
            lane as i32,
            &mut gigabits,
            &mut enc,
        )
        .check_error("fetching lane/speed info")?;
        encoding = LaneEncoding::try_from(enc)?;
    }

    Ok(EncSpeed { encoding, gigabits })
}

/// Collect all of the lane speeds and encodings for the specified port.
///
/// The returned value contains a vector of `EncSpeed`, indexed by the logical lane
/// ID within the link.
pub fn port_encoding_speed_get(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<Vec<EncSpeed>> {
    let lanes = lane_count(hdl, port)?;
    let mut rval = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        rval.push(lane_encoding_speed_get(hdl, port, lane)?)
    }
    Ok(rval)
}

/// Fetch the AN-done status for the specified port and logical lane.
/// Unlike the an_complete field of AnStatus, this bit also includes whether
/// link-training has completed successfully.
pub fn an_done_get(hdl: &Handle, port: PortHdl, lane: u32) -> AsicResult<bool> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut an_done = false;

    unsafe {
        bf_tof2_serdes_an_done_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut an_done,
        )
        .check_error("fetching AN done")?
    };

    Ok(an_done)
}

/// State of a single lane during autonegotiation
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct AnStatus {
    /// Can the link partner perform AN?
    pub lp_an_ability: bool,
    /// Allegedly: is the link up?  In practice, this always seems to be false?
    /// TODO: investigate this
    pub link_status: bool,
    /// Are we capable of AN?
    pub an_ability: bool,
    /// Remote fault detected
    pub remote_fault: bool,
    /// Is autonegotiation complete?
    pub an_complete: bool,
    /// has a base page been received?
    pub page_rcvd: bool,
    /// Is extended page format supported?
    pub ext_np_status: bool,
    /// A fault has been detected via the parallel detection function
    pub parallel_detect_fault: bool,
}

/// Fetch the autonegotiation state of a single port and logical lane
pub fn an_status_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<AnStatus> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut lp_an_ability = 0;
    let mut link_status = 0;
    let mut an_ability = 0;
    let mut remote_fault = 0;
    let mut an_complete = 0;
    let mut page_rcvd = 0;
    let mut ext_np_status = 0;
    let mut parallel_detect_fault = 0;

    unsafe {
        bf_tof2_serdes_an_status_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut lp_an_ability,
            &mut link_status,
            &mut an_ability,
            &mut remote_fault,
            &mut an_complete,
            &mut page_rcvd,
            &mut ext_np_status,
            &mut parallel_detect_fault,
        )
        .check_error("fetching lane AN status")?;
    }
    Ok(AnStatus {
        lp_an_ability: lp_an_ability != 0,
        link_status: link_status != 0,
        an_ability: an_ability != 0,
        remote_fault: remote_fault != 0,
        an_complete: an_complete != 0,
        page_rcvd: page_rcvd != 0,
        ext_np_status: ext_np_status != 0,
        parallel_detect_fault: parallel_detect_fault != 0,
    })
}

/// Fetch the AN base page received from the link partner
pub fn an_lp_base_page_get(hdl: &Handle, port: PortHdl) -> AsicResult<u64> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut base_page = 0;

    unsafe {
        bf_tof2_serdes_an_lp_base_page_get(
            hdl.dev_id,
            port_id as i32,
            &mut base_page,
        )
        .check_error("fetching link-partner base page")?;
    }
    Ok(base_page)
}

/// Set of AN pages sent by our link partner
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct LpPages {
    pub base_page: u64,
    pub next_page1: u64,
    pub next_page2: u64,
}

/// Fetch all the AN pages received from the link partner for this port
pub fn an_lp_pages_get(hdl: &Handle, port: PortHdl) -> AsicResult<LpPages> {
    let port_id = ports::to_asic_id(hdl, port)?;

    let mut lp_pages = LpPages::default();
    unsafe {
        bf_tof2_serdes_an_lp_pages_get(
            hdl.dev_id,
            port_id as i32,
            &mut lp_pages.base_page,
            &mut lp_pages.next_page1,
            &mut lp_pages.next_page2,
        )
        .check_error("fetching link-partner pages")?;
    }
    Ok(lp_pages)
}

/// Highest common denominator resulting when comparing the AN pages for us and
/// our link partner
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct AnHcd {
    pub hcd: u32,
    pub base_r_fec: bool,
    pub rs_fec: bool,
}

/// Fetch the calculated AN HCD for a specified port and logical lane
pub fn an_hcd_get(hdl: &Handle, port: PortHdl, lane: u32) -> AsicResult<AnHcd> {
    let port_id = ports::to_asic_id(hdl, port)?;

    // XXX: this always seems to return all 0s for all fields, even for a link
    // that is up.  This ends up as a bunch of Credo reads, rather than
    // fetching the HCD the SDE calculated as part of autonegotiation.  Without
    // the Credo docs, it's not clear what this means - or if it means anything
    // at all.
    let mut an_hcd = AnHcd::default();
    unsafe {
        bf_tof2_serdes_an_hcd_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut an_hcd.hcd,
            &mut an_hcd.base_r_fec,
            &mut an_hcd.rs_fec,
        )
        .check_error("fetching per-lane HCD decision")?;
    }
    Ok(an_hcd)
}

/// Link-training status for a single lane
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LtStatus {
    /// Readout for frame lock state
    pub readout_state: u32,
    /// Frame lock state
    pub frame_lock: bool,
    /// Local training finished
    pub rx_trained: bool,
    /// Training state readout
    pub readout_training_state: u32,
    /// Link training failed
    pub training_failure: bool,
    /// TX control to send training pattern
    pub tx_training_data_en: bool,
    /// Signal detect for PCS
    pub sig_det: bool,
    /// State machine readout for training arbiter
    pub readout_txstate: u32,
}

pub fn lt_status_get(
    hdl: &Handle,
    port: PortHdl,
    lane: u32,
) -> AsicResult<LtStatus> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut readout_state = 0;
    let mut frame_lock = 0;
    let mut rx_trained = 0;
    let mut readout_training_state = 0;
    let mut training_failure = 0;
    let mut tx_training_data_en = 0;
    let mut sig_det = 0;
    let mut readout_txstate = 0;

    unsafe {
        bf_tof2_serdes_lt_status_get(
            hdl.dev_id,
            port_id as i32,
            lane,
            &mut readout_state,
            &mut frame_lock,
            &mut rx_trained,
            &mut readout_training_state,
            &mut training_failure,
            &mut tx_training_data_en,
            &mut sig_det,
            &mut readout_txstate,
        )
        .check_error("fetching link-training status")?;
    }
    Ok(LtStatus {
        readout_state,
        frame_lock: frame_lock != 0,
        rx_trained: rx_trained != 0,
        readout_training_state,
        training_failure: training_failure != 0,
        tx_training_data_en: tx_training_data_en != 0,
        sig_det: sig_det != 0,
        readout_txstate,
    })
}

/// The combined status of a lane, with respect to the autonegotiation /
/// link-training process.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LaneStatus {
    /// Has a lane successfully completed autoneg and link training?
    pub lane_done: bool,
    /// Detailed autonegotiation status
    pub lane_an_status: AnStatus,
    /// Detailed link-training status
    pub lane_lt_status: LtStatus,
}

/// A collection of the data involved in the autonegiation/link-training process
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct AnLtStatus {
    /// The base and extended pages received from the link partner
    pub lp_pages: LpPages,
    /// The per-lane status
    pub lanes: Vec<LaneStatus>,
}

/// Collect all of the autonegotiation and link training status for this port.
///
/// The returned value contains a vector of `AnLtStatus`, indexed by the logical
/// lane ID within the link.
pub fn an_lt_status_get(hdl: &Handle, port: PortHdl) -> AsicResult<AnLtStatus> {
    let lane_count = lane_count(hdl, port)?;
    let mut lanes = Vec::with_capacity(lane_count as usize);
    for lane in 0..lane_count {
        let lane_done = an_done_get(hdl, port, lane)?;
        let lane_an_status = an_status_get(hdl, port, lane)?;
        let lane_lt_status = lt_status_get(hdl, port, lane)?;
        lanes.push(LaneStatus {
            lane_done,
            lane_an_status,
            lane_lt_status,
        })
    }
    let lp_pages = an_lp_pages_get(hdl, port)?;
    Ok(AnLtStatus { lp_pages, lanes })
}
