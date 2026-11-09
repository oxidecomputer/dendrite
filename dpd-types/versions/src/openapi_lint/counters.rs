// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::link::LinkId;
use crate::v1::port::PortId;

/**
 * Per-port RS FEC counters
 */
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct FecRsCounters {
    /// Port being tracked
    pub port: String,
    /// symbol errors exceeds threshhold
    pub hi_ser: bool,
    /// All lanes synced and aligned
    pub fec_align_status: bool,
    /// FEC corrected blocks
    pub fec_corr_cnt: u32,
    /// FEC uncorrected blocks
    pub fec_uncorr_cnt: u32,
    /// FEC symbol errors on lane 0
    pub fec_ser_lane_0: u32,
    /// FEC symbol errors on lane 1
    pub fec_ser_lane_1: u32,
    /// FEC symbol errors on lane 2
    pub fec_ser_lane_2: u32,
    /// FEC symbol errors on lane 3
    pub fec_ser_lane_3: u32,
    /// FEC symbol errors on lane 4
    pub fec_ser_lane_4: u32,
    /// FEC symbol errors on lane 5
    pub fec_ser_lane_5: u32,
    /// FEC symbol errors on lane 6
    pub fec_ser_lane_6: u32,
    /// FEC symbol errors on lane 7
    pub fec_ser_lane_7: u32,
}

/// The FEC counters for a specific link, including its link ID.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkFecRsCounters {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The FEC counter data.
    pub counters: FecRsCounters,
}

impl From<FecRsCounters> for v1::counters::FecRSCounters {
    fn from(new: FecRsCounters) -> Self {
        Self {
            port: new.port,
            hi_ser: new.hi_ser,
            fec_align_status: new.fec_align_status,
            fec_corr_cnt: new.fec_corr_cnt,
            fec_uncorr_cnt: new.fec_uncorr_cnt,
            fec_ser_lane_0: new.fec_ser_lane_0,
            fec_ser_lane_1: new.fec_ser_lane_1,
            fec_ser_lane_2: new.fec_ser_lane_2,
            fec_ser_lane_3: new.fec_ser_lane_3,
            fec_ser_lane_4: new.fec_ser_lane_4,
            fec_ser_lane_5: new.fec_ser_lane_5,
            fec_ser_lane_6: new.fec_ser_lane_6,
            fec_ser_lane_7: new.fec_ser_lane_7,
        }
    }
}

impl From<LinkFecRsCounters> for v1::counters::LinkFecRSCounters {
    fn from(new: LinkFecRsCounters) -> Self {
        Self {
            port_id: new.port_id,
            link_id: new.link_id,
            counters: new.counters.into(),
        }
    }
}
