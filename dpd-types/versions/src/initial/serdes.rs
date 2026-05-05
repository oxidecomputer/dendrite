// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    pub mac_block: u32,
    /// logical lane within the mac block for each lane
    pub logical_lane: Vec<u32>,
    /// Rx logical->physical mapping
    pub rx_phys: Vec<u32>,
    /// Tx logical->physical mapping
    pub tx_phys: Vec<u32>,
    /// Rx polarity
    pub rx_polarity: Vec<Polarity>,
    /// Tx polarity
    pub tx_polarity: Vec<Polarity>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub enum Polarity {
    Normal,
    Inverted,
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

/// Eye height(s) for a single lane in mv
#[derive(Deserialize, Serialize, JsonSchema)]
pub enum SerdesEye {
    Nrz(f32),
    Pam4 { eye1: f32, eye2: f32, eye3: f32 },
}

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

/// Signal speed and encoding for a single lane
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct EncSpeed {
    pub encoding: LaneEncoding,
    pub gigabits: u32,
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

/// A collection of the data involved in the autonegiation/link-training process
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct AnLtStatus {
    /// The base and extended pages received from the link partner
    pub lp_pages: LpPages,
    /// The per-lane status
    pub lanes: Vec<LaneStatus>,
}

/// Set of AN pages sent by our link partner
#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct LpPages {
    pub base_page: u64,
    pub next_page1: u64,
    pub next_page2: u64,
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

/// Reports the bit-error rate (BER) for a link.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Ber {
    /// Counters of symbol errors per-lane.
    pub symbol_errors: Vec<u64>,
    /// Estimated BER per-lane.
    pub ber: Vec<f32>,
    /// Aggregate BER on the link.
    pub total_ber: f32,
}
