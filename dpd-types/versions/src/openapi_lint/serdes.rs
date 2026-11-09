// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

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
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    Normal,
    Inverted,
}

/// Eye height(s) for a single lane in mv
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SerdesEye {
    Nrz(f32),
    Pam4 { eye1: f32, eye2: f32, eye3: f32 },
}

/// Signal encoding
#[derive(PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
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

impl From<LaneMap> for v1::serdes::LaneMap {
    fn from(new: LaneMap) -> Self {
        Self {
            mac_block: new.mac_block,
            logical_lane: new.logical_lane,
            rx_phys: new.rx_phys,
            tx_phys: new.tx_phys,
            rx_polarity: new.rx_polarity.into_iter().map(Into::into).collect(),
            tx_polarity: new.tx_polarity.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Polarity> for v1::serdes::Polarity {
    fn from(new: Polarity) -> Self {
        match new {
            Polarity::Normal => Self::Normal,
            Polarity::Inverted => Self::Inverted,
        }
    }
}

impl From<SerdesEye> for v1::serdes::SerdesEye {
    fn from(new: SerdesEye) -> Self {
        match new {
            SerdesEye::Nrz(eye) => Self::Nrz(eye),
            SerdesEye::Pam4 { eye1, eye2, eye3 } => {
                Self::Pam4 { eye1, eye2, eye3 }
            }
        }
    }
}

impl From<LaneEncoding> for v1::serdes::LaneEncoding {
    fn from(new: LaneEncoding) -> Self {
        match new {
            LaneEncoding::Pam4 => Self::Pam4,
            LaneEncoding::Nrz => Self::Nrz,
            LaneEncoding::None => Self::None,
        }
    }
}

impl From<EncSpeed> for v1::serdes::EncSpeed {
    fn from(new: EncSpeed) -> Self {
        Self { encoding: new.encoding.into(), gigabits: new.gigabits }
    }
}
