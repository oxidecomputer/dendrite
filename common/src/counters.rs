// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/**
 * High level subset of the RMon counters maintained by the Tofino ASIC
 */
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct RMonCounters {
    pub port: String,
    pub frames_rx_ok: u64,
    pub frames_rx_all: u64,
    pub frames_with_any_error: u64,
    pub octets_rx_in_good_frames: u64,
    pub octets_rx: u64,
    pub fragments_rx: u64,
    pub crc_error_stomped: u64,
    pub frame_too_long: u64,
    pub frames_dropped_buffer_full: u64,
    pub frames_tx_ok: u64,
    pub frames_tx_all: u64,
    pub frames_tx_with_error: u64,
    pub octets_tx_without_error: u64,
    pub octets_tx_total: u64,
}

/**
 * All of the RMon counters maintained by the Tofino ASIC
 */
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct RMonCountersAll {
    pub port: String,
    pub frames_rx_ok: u64,
    pub frames_rx_all: u64,
    pub frames_rx_with_fcs_error: u64,
    pub frames_rx_with_any_error: u64,
    pub octets_rx_in_good_frames: u64,
    pub octets_rx: u64,
    pub frames_rx_with_unicast_addresses: u64,
    pub frames_rx_with_multicast_addresses: u64,
    pub frames_rx_with_broadcast_addresses: u64,
    pub frames_rx_oftype_pause: u64,
    pub frames_rx_with_length_error: u64,
    pub frames_rx_indersized: u64,
    pub frames_rx_oversized: u64,
    pub fragments_rx: u64,
    pub jabber_rx: u64,
    pub priority_pause_frames: u64,
    pub crc_error_stomped: u64,
    pub frame_too_long: u64,
    pub rx_vlan_frames_good: u64,
    pub frames_dropped_buffer_full: u64,
    pub frames_rx_length_lt_64: u64,
    pub frames_rx_length_eq_64: u64,
    pub frames_rx_length_65_127: u64,
    pub frames_rx_length_128_255: u64,
    pub frames_rx_length_256_511: u64,
    pub frames_rx_length_512_1023: u64,
    pub frames_rx_length_1024_1518: u64,
    pub frames_rx_length_1519_2047: u64,
    pub frames_rx_length_2048_4095: u64,
    pub frames_rx_length_4096_8191: u64,
    pub frames_rx_length_8192_9215: u64,
    pub frames_rx_length_9216: u64,
    pub frames_tx_ok: u64,
    pub frames_tx_all: u64,
    pub frames_tx_with_error: u64,
    pub octets_tx_without_error: u64,
    pub octets_tx_total: u64,
    pub frames_tx_unicast: u64,
    pub frames_tx_multicast: u64,
    pub frames_tx_broadcast: u64,
    pub frames_tx_pause: u64,
    pub frames_tx_pri_pause: u64,
    pub frames_tx_vlan: u64,
    pub frames_tx_length_lt_64: u64,
    pub frames_tx_length_eq_64: u64,
    pub frames_tx_length_65_127: u64,
    pub frames_tx_length_128_255: u64,
    pub frames_tx_length_256_511: u64,
    pub frames_tx_length_512_1023: u64,
    pub frames_tx_length_1024_1518: u64,
    pub frames_tx_length_1519_2047: u64,
    pub frames_tx_length_2048_4095: u64,
    pub frames_tx_length_4096_8191: u64,
    pub frames_tx_length_8192_9215: u64,
    pub frames_tx_length_9216: u64,
    pub pri0_framex_tx: u64,
    pub pri1_frames_tx: u64,
    pub pri2_frames_tx: u64,
    pub pri3_frames_tx: u64,
    pub pri4_frames_tx: u64,
    pub pri5_frames_tx: u64,
    pub pri6_frames_tx: u64,
    pub pri7_frames_tx: u64,
    pub pri0_frames_rx: u64,
    pub pri1_frames_rx: u64,
    pub pri2_frames_rx: u64,
    pub pri3_frames_rx: u64,
    pub pri4_frames_rx: u64,
    pub pri5_frames_rx: u64,
    pub pri6_frames_rx: u64,
    pub pri7_frames_rx: u64,
    pub tx_pri0_pause_1us_count: u64,
    pub tx_pri1_pause_1us_count: u64,
    pub tx_pri2_pause_1us_count: u64,
    pub tx_pri3_pause_1us_count: u64,
    pub tx_pri4_pause_1us_count: u64,
    pub tx_pri5_pause_1us_count: u64,
    pub tx_pri6_pause_1us_count: u64,
    pub tx_pri7_pause_1us_count: u64,
    pub rx_pri0_pause_1us_count: u64,
    pub rx_pri1_pause_1us_count: u64,
    pub rx_pri2_pause_1us_count: u64,
    pub rx_pri3_pause_1us_count: u64,
    pub rx_pri4_pause_1us_count: u64,
    pub rx_pri5_pause_1us_count: u64,
    pub rx_pri6_pause_1us_count: u64,
    pub rx_pri7_pause_1us_count: u64,
    pub rx_standard_pause_1us_count: u64,
    pub frames_truncated: u64,
}

/**
 * Per-port PCS counters
 */
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct PcsCounters {
    /// Port being tracked
    pub port: String,
    /// Count of bad sync headers
    pub bad_sync_headers: u32,
    /// Count of errored blocks
    pub errored_blocks: u32,
    /// Count of sync loss detections
    pub sync_loss: u32,
    /// Count of block-lock loss detections
    pub block_lock_loss: u32,
    /// Count of high bit error rate events
    pub hi_ber: u32,
    /// Count of valid error events
    pub valid_errors: u32,
    /// Count of unknown error events
    pub unknown_errors: u32,
    /// Count of invalid error events
    pub invalid_errors: u32,
    /// Bit Inteleaved Parity errors (per lane)
    pub bip_errors_per_pcs_lane: Vec<u32>,
}

/**
 * Per-port RS FEC counters
 */
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct FecRSCounters {
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
