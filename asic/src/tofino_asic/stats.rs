// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use crate::tofino_asic::genpd::*;
use crate::tofino_asic::ports;
use crate::tofino_asic::{CheckError, Handle, PortFsmState};
use crate::FsmStats;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use oximeter::types::{Cumulative, Sample};
use oximeter::{MetricsError, Target};
use strum::{EnumCount, IntoEnumIterator};

use aal::{AsicResult, PortHdl};
use common::counters::*;
use common::ports::PortId;

oximeter::use_timeseries!("switch-data-link.toml");
use switch_data_link::{
    BytesReceived, BytesSent, ErrorsReceived, ErrorsSent, FecCorrectedBlocks,
    FecHighSymbolErrors, FecSymbolErrors, FecSyncAligned, FecUncorrectedBlocks,
    LinkFsm, PacketsReceived, PacketsSent, PcsBadSyncHeaders, PcsBlockLockLoss,
    PcsErroredBlocks, PcsHighBer, PcsInvalidErrors, PcsSyncLoss,
    PcsUnknownErrors, PcsValidErrors, ReceiveBufferFullDrops,
    ReceiveCrcErrorDrops,
};

/// Number of RMON statistics published to oximeter
const RMON_STAT_COUNT: usize = 8;

/// Number of FEC statistics published to oximeter
const FEC_STAT_COUNT: usize = 12;

/// Maximum number of Tx / Rx pairs expected on any port.
const N_LANES: u8 = 8;

/// Number of PCS layer statistics published to oximeter.
const PCS_STAT_COUNT: usize = 8;

/// Statistics collected for a single link for Oximeter
#[derive(Clone, Debug)]
pub struct AsicLinkStats {
    port_id: String,
    link_id: u8,
    start_time: DateTime<Utc>,
    rmon: RMonCounters,
    pcs: PcsCounters,
    fec: FecRSCounters,
    fsm_states: BTreeMap<&'static str, u64>,
}

impl AsicLinkStats {
    /// Construct a new set of ASIC-layer link stats.
    pub fn new(port_id: PortId, link_id: u8) -> Self {
        Self {
            port_id: port_id.to_string(),
            link_id,
            start_time: Utc::now(),
            rmon: Default::default(),
            pcs: Default::default(),
            fec: Default::default(),
            fsm_states: BTreeMap::new(),
        }
    }

    fn packets_received(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PacketsReceived {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.frames_rx_ok,
                ),
            },
        )
    }

    fn bytes_received(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &BytesReceived {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.octets_rx,
                ),
            },
        )
    }

    fn receive_crc_errors(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &ReceiveCrcErrorDrops {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.crc_error_stomped,
                ),
            },
        )
    }

    fn receive_full_errors(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &ReceiveBufferFullDrops {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.frames_dropped_buffer_full,
                ),
            },
        )
    }

    fn errors_received(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &ErrorsReceived {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.frames_with_any_error,
                ),
            },
        )
    }

    fn packets_sent(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PacketsSent {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.frames_tx_ok,
                ),
            },
        )
    }

    fn bytes_sent(&self, target: &impl Target) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &BytesSent {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.octets_tx_without_error,
                ),
            },
        )
    }

    fn errors_sent(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &ErrorsSent {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    self.rmon.frames_tx_with_error,
                ),
            },
        )
    }

    fn fec_high_ser(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &FecHighSymbolErrors {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: self.fec.hi_ser,
            },
        )
    }

    fn fec_sync_aligned(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &FecSyncAligned {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: self.fec.fec_align_status,
            },
        )
    }

    fn fec_corrected(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &FecCorrectedBlocks {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.fec.fec_corr_cnt),
                ),
            },
        )
    }

    fn fec_uncorrected(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &FecUncorrectedBlocks {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.fec.fec_uncorr_cnt),
                ),
            },
        )
    }

    fn fec_ser_by_lane(
        &self,
        target: &impl Target,
        lane: u8,
        count: u32,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &FecSymbolErrors {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                lane,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(count),
                ),
            },
        )
    }

    fn pcs_bad_sync(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsBadSyncHeaders {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.bad_sync_headers),
                ),
            },
        )
    }

    fn pcs_sync_loss(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsSyncLoss {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.sync_loss),
                ),
            },
        )
    }

    fn pcs_block_lock_loss(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsBlockLockLoss {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.block_lock_loss),
                ),
            },
        )
    }

    fn pcs_errored_blocks(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsErroredBlocks {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.errored_blocks),
                ),
            },
        )
    }

    fn pcs_high_ber(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsHighBer {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.hi_ber),
                ),
            },
        )
    }

    fn pcs_invalid_errors(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsInvalidErrors {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.invalid_errors),
                ),
            },
        )
    }

    fn pcs_unknown_errors(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsUnknownErrors {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.unknown_errors),
                ),
            },
        )
    }

    fn pcs_valid_errors(
        &self,
        target: &impl Target,
    ) -> Result<Sample, MetricsError> {
        Sample::new(
            target,
            &PcsValidErrors {
                port_id: self.port_id.clone().into(),
                link_id: self.link_id,
                datum: Cumulative::with_start_time(
                    self.start_time,
                    u64::from(self.pcs.valid_errors),
                ),
            },
        )
    }

    /// Generate a vector of Oximeter Samples, capturing all our metrics
    pub fn get_samples(
        &self,
        target: &impl Target,
    ) -> Result<Vec<Sample>, oximeter::MetricsError> {
        let mut out = Vec::with_capacity(Self::stats_per_link());
        out.push(self.packets_received(target)?);
        out.push(self.bytes_received(target)?);
        out.push(self.receive_crc_errors(target)?);
        out.push(self.receive_full_errors(target)?);
        out.push(self.errors_received(target)?);
        out.push(self.packets_sent(target)?);
        out.push(self.bytes_sent(target)?);
        out.push(self.errors_sent(target)?);
        out.push(self.fec_high_ser(target)?);
        out.push(self.fec_sync_aligned(target)?);
        out.push(self.fec_corrected(target)?);
        out.push(self.fec_uncorrected(target)?);
        for (lane, ser) in (0..N_LANES).zip([
            self.fec.fec_ser_lane_0,
            self.fec.fec_ser_lane_1,
            self.fec.fec_ser_lane_2,
            self.fec.fec_ser_lane_3,
            self.fec.fec_ser_lane_4,
            self.fec.fec_ser_lane_5,
            self.fec.fec_ser_lane_6,
            self.fec.fec_ser_lane_7,
        ]) {
            out.push(self.fec_ser_by_lane(target, lane, ser)?);
        }
        for (state, count) in self.fsm_states.iter() {
            out.push(Sample::new(
                target,
                &LinkFsm {
                    port_id: self.port_id.clone().into(),
                    link_id: self.link_id,
                    state: (*state).into(),
                    datum: Cumulative::with_start_time(self.start_time, *count),
                },
            )?);
        }
        out.push(self.pcs_bad_sync(target)?);
        out.push(self.pcs_sync_loss(target)?);
        out.push(self.pcs_block_lock_loss(target)?);
        out.push(self.pcs_errored_blocks(target)?);
        out.push(self.pcs_high_ber(target)?);
        out.push(self.pcs_invalid_errors(target)?);
        out.push(self.pcs_unknown_errors(target)?);
        out.push(self.pcs_valid_errors(target)?);
        assert_eq!(Self::stats_per_link(), out.len());
        Ok(out)
    }

    /// Updated the per-port statistics with the latest data
    pub fn update_stats(
        &mut self,
        hdl: &Handle,
        port: PortHdl,
        fsm: &FsmStats,
    ) -> AsicResult<()> {
        self.rmon = port_get_rmon_counters(hdl, port)?;
        self.pcs = port_get_pcs_counters(hdl, port)?;
        // Skip for links without RS configured?
        self.fec = port_get_fec_rs_counters(hdl, port)?;
        for state in PortFsmState::iter() {
            self.fsm_states.insert(state.into(), fsm.get(state).into());
        }

        Ok(())
    }

    /// Return the number of stats collected for each link, to allow the caller to pre-allocate
    /// space.
    pub fn stats_per_link() -> usize {
        RMON_STAT_COUNT + FEC_STAT_COUNT + PCS_STAT_COUNT + PortFsmState::COUNT
    }
}

enum RMonCountersAll {
    FramesRxOk = 0,
    FramesRxAll = 1,
    FramesRxWithFCSError = 2,
    FramesRxWithAnyError = 3,
    OctetsRxInGoodFrames = 4,
    OctetsRx = 5,
    FramesRxWithUnicastAddresses = 6,
    FramesRxWithMulticastAddresses = 7,
    FramesRxWithBroadcastAddresses = 8,
    FramesRxoftypePAUSE = 9,
    FramesRxWithLengthError = 10,
    FramesRxUndersized = 11,
    FramesRxOversized = 12,
    FragmentsRx = 13,
    JabberRx = 14,
    PriorityPauseFrames = 15,
    CRCErrorStomped = 16,
    FrameTooLong = 17,
    RxVLANFramesGood = 18,
    FramesDroppedBufferFull = 19,
    FramesRxLengthLt64 = 20,
    FramesRxLengthEq64 = 21,
    FramesRxLength65_127 = 22,
    FramesRxLength128_255 = 23,
    FramesRxLength256_511 = 24,
    FramesRxLength512_1023 = 25,
    FramesRxLength1024_1518 = 26,
    FramesRxLength1519_2047 = 27,
    FramesRxLength2048_4095 = 28,
    FramesRxLength4096_8191 = 29,
    FramesRxLength8192_9215 = 30,
    FramesRxLength9216 = 31,
    FramesTxOk = 32,
    FramesTxAll = 33,
    FramesTxWithError = 34,
    OctetsTxWithoutError = 35,
    OctetsTxTotal = 36,
    FramesTxUnicast = 37,
    FramesTxMulticast = 38,
    FramesTxBroadcast = 39,
    FramesTxPause = 40,
    FramesTxPriPause = 41,
    FramesTxVLAN = 42,
    FramesTxLengthLt64 = 43,
    FramesTxLengthEq64 = 44,
    FramesTxLength65_127 = 45,
    FramesTxLength128_255 = 46,
    FramesTxLength256_511 = 47,
    FramesTxLength512_1023 = 48,
    FramesTxLength1024_1518 = 49,
    FramesTxLength1519_2047 = 50,
    FramesTxLength2048_4095 = 51,
    FramesTxLength4096_8191 = 52,
    FramesTxLength8192_9215 = 53,
    FramesTxLength9216 = 54,
    Pri0FramexTx = 55,
    Pri1FramesTx = 56,
    Pri2FramesTx = 57,
    Pri3FramesTx = 58,
    Pri4FramesTx = 59,
    Pri5FramesTx = 60,
    Pri6FramesTx = 61,
    Pri7FramesTx = 62,
    Pri0FramesRx = 63,
    Pri1FramesRx = 64,
    Pri2FramesRx = 65,
    Pri3FramesRx = 66,
    Pri4FramesRx = 67,
    Pri5FramesRx = 68,
    Pri6FramesRx = 69,
    Pri7FramesRx = 70,
    TxPri0Pause1UsCount = 71,
    TxPri1Pause1USCount = 72,
    TxPri2Pause1USCount = 73,
    TxPri3Pause1USCount = 74,
    TxPri4Pause1USCount = 75,
    TxPri5Pause1USCount = 76,
    TxPri6Pause1USCount = 77,
    TxPri7Pause1USCount = 78,
    RxPri0Pause1UsCount = 79,
    RxPri1Pause1USCount = 80,
    RxPri2Pause1USCount = 81,
    RxPri3Pause1USCount = 82,
    RxPri4Pause1USCount = 83,
    RxPri5Pause1USCount = 84,
    RxPri6Pause1USCount = 85,
    RxPri7Pause1USCount = 86,
    RxStandardPause1USCount = 87,
    FramesTruncated = 88,
}
#[test]
pub fn constants_sanity_check() {
    assert_eq!(
        RMonCountersAll::FramesRxOk as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedOK
    );
    assert_eq!(
        RMonCountersAll::FramesRxAll as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedAll
    );
    assert_eq!(
        RMonCountersAll::FramesRxWithFCSError as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedwithFCSError
    );
    assert_eq!(
        RMonCountersAll::FramesRxWithAnyError as u32,
        bf_rmon_counter_t_bf_mac_stat_FrameswithanyError
    );
    assert_eq!(
        RMonCountersAll::OctetsRxInGoodFrames as u32,
        bf_rmon_counter_t_bf_mac_stat_OctetsReceivedinGoodFrames
    );
    assert_eq!(
        RMonCountersAll::OctetsRx as u32,
        bf_rmon_counter_t_bf_mac_stat_OctetsReceived
    );
    assert_eq!(
        RMonCountersAll::FramesRxWithUnicastAddresses as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedwithUnicastAddresses
    );
    assert_eq!(
        RMonCountersAll::FramesRxWithMulticastAddresses as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedwithMulticastAddresses
    );
    assert_eq!(
        RMonCountersAll::FramesRxWithBroadcastAddresses as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedwithBroadcastAddresses
    );
    assert_eq!(
        RMonCountersAll::FramesRxoftypePAUSE as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedoftypePAUSE
    );
    assert_eq!(
        RMonCountersAll::FramesRxWithLengthError as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedwithLengthError
    );
    assert_eq!(
        RMonCountersAll::FramesRxUndersized as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedUndersized
    );
    assert_eq!(
        RMonCountersAll::FramesRxOversized as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedOversized
    );
    assert_eq!(
        RMonCountersAll::FragmentsRx as u32,
        bf_rmon_counter_t_bf_mac_stat_FragmentsReceived
    );
    assert_eq!(
        RMonCountersAll::JabberRx as u32,
        bf_rmon_counter_t_bf_mac_stat_JabberReceived
    );
    assert_eq!(
        RMonCountersAll::PriorityPauseFrames as u32,
        bf_rmon_counter_t_bf_mac_stat_PriorityPauseFrames
    );
    assert_eq!(
        RMonCountersAll::CRCErrorStomped as u32,
        bf_rmon_counter_t_bf_mac_stat_CRCErrorStomped
    );
    assert_eq!(
        RMonCountersAll::FrameTooLong as u32,
        bf_rmon_counter_t_bf_mac_stat_FrameTooLong
    );
    assert_eq!(
        RMonCountersAll::RxVLANFramesGood as u32,
        bf_rmon_counter_t_bf_mac_stat_RxVLANFramesGood
    );
    assert_eq!(
        RMonCountersAll::FramesDroppedBufferFull as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesDroppedBufferFull
    );
    assert_eq!(
        RMonCountersAll::FramesRxLengthLt64 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_lt_64
    );
    assert_eq!(
        RMonCountersAll::FramesRxLengthEq64 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_eq_64
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength65_127 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_65_127
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength128_255 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_128_255
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength256_511 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_256_511
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength512_1023 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_512_1023
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength1024_1518 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_1024_1518
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength1519_2047 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_1519_2047
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength2048_4095 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_2048_4095
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength4096_8191 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_4096_8191
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength8192_9215 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_8192_9215
    );
    assert_eq!(
        RMonCountersAll::FramesRxLength9216 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesReceivedLength_9216
    );
    assert_eq!(
        RMonCountersAll::FramesTxOk as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedOK
    );
    assert_eq!(
        RMonCountersAll::FramesTxAll as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedAll
    );
    assert_eq!(
        RMonCountersAll::FramesTxWithError as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedwithError
    );
    assert_eq!(
        RMonCountersAll::OctetsTxWithoutError as u32,
        bf_rmon_counter_t_bf_mac_stat_OctetsTransmittedwithouterror
    );
    assert_eq!(
        RMonCountersAll::OctetsTxTotal as u32,
        bf_rmon_counter_t_bf_mac_stat_OctetsTransmittedTotal
    );
    assert_eq!(
        RMonCountersAll::FramesTxUnicast as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedUnicast
    );
    assert_eq!(
        RMonCountersAll::FramesTxMulticast as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedMulticast
    );
    assert_eq!(
        RMonCountersAll::FramesTxBroadcast as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedBroadcast
    );
    assert_eq!(
        RMonCountersAll::FramesTxPause as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedPause
    );
    assert_eq!(
        RMonCountersAll::FramesTxPriPause as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedPriPause
    );
    assert_eq!(
        RMonCountersAll::FramesTxVLAN as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedVLAN
    );
    assert_eq!(
        RMonCountersAll::FramesTxLengthLt64 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_lt_64
    );
    assert_eq!(
        RMonCountersAll::FramesTxLengthEq64 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_eq_64
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength65_127 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_65_127
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength128_255 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_128_255
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength256_511 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_256_511
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength512_1023 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_512_1023
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength1024_1518 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_1024_1518
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength1519_2047 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_1519_2047
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength2048_4095 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_2048_4095
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength4096_8191 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_4096_8191
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength8192_9215 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_8192_9215
    );
    assert_eq!(
        RMonCountersAll::FramesTxLength9216 as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTransmittedLength_9216
    );
    assert_eq!(
        RMonCountersAll::Pri0FramexTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri0FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri1FramesTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri1FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri2FramesTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri2FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri3FramesTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri3FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri4FramesTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri4FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri5FramesTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri5FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri6FramesTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri6FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri7FramesTx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri7FramesTransmitted
    );
    assert_eq!(
        RMonCountersAll::Pri0FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri0FramesReceived
    );
    assert_eq!(
        RMonCountersAll::Pri1FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri1FramesReceived
    );
    assert_eq!(
        RMonCountersAll::Pri2FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri2FramesReceived
    );
    assert_eq!(
        RMonCountersAll::Pri3FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri3FramesReceived
    );
    assert_eq!(
        RMonCountersAll::Pri4FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri4FramesReceived
    );
    assert_eq!(
        RMonCountersAll::Pri5FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri5FramesReceived
    );
    assert_eq!(
        RMonCountersAll::Pri6FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri6FramesReceived
    );
    assert_eq!(
        RMonCountersAll::Pri7FramesRx as u32,
        bf_rmon_counter_t_bf_mac_stat_Pri7FramesReceived
    );
    assert_eq!(
        RMonCountersAll::TxPri0Pause1UsCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri0Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::TxPri1Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri1Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::TxPri2Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri2Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::TxPri3Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri3Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::TxPri4Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri4Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::TxPri5Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri5Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::TxPri6Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri6Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::TxPri7Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_TransmitPri7Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri0Pause1UsCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri0Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri1Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri1Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri2Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri2Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri3Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri3Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri4Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri4Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri5Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri5Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri6Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri6Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxPri7Pause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceivePri7Pause1USCount
    );
    assert_eq!(
        RMonCountersAll::RxStandardPause1USCount as u32,
        bf_rmon_counter_t_bf_mac_stat_ReceiveStandardPause1USCount
    );
    assert_eq!(
        RMonCountersAll::FramesTruncated as u32,
        bf_rmon_counter_t_bf_mac_stat_FramesTruncated
    );
}

fn port_get_rmon_counter_data(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<Vec<u64>> {
    let port_id = ports::to_asic_id(hdl, port)?;
    let mut ctr_array: bf_rmon_counter_array_t = unsafe { std::mem::zeroed() };
    let stats = unsafe {
        let ptr: *mut bf_rmon_counter_array_t = &mut ctr_array;
        bf_port_mac_stats_hw_sync_get(hdl.dev_id, port_id as i32, ptr)
            .check_error("fetching rmon counters")?;
        ctr_array.format.ctr_array.to_vec()
    };
    Ok(stats)
}

/// Fetch the core RMON counters for the given port.  These counters are not reset
/// after being read.
pub fn port_get_rmon_counters(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<RMonCounters> {
    let stats = port_get_rmon_counter_data(hdl, port)?;

    Ok(RMonCounters {
        port: port.to_string(),
        frames_rx_ok: stats[RMonCountersAll::FramesRxOk as usize],
        frames_rx_all: stats[RMonCountersAll::FramesRxAll as usize],
        frames_with_any_error: stats
            [RMonCountersAll::FramesRxWithAnyError as usize],
        octets_rx_in_good_frames: stats
            [RMonCountersAll::OctetsRxInGoodFrames as usize],
        octets_rx: stats[RMonCountersAll::OctetsRx as usize],
        fragments_rx: stats[RMonCountersAll::FragmentsRx as usize],
        crc_error_stomped: stats[RMonCountersAll::CRCErrorStomped as usize],
        frame_too_long: stats[RMonCountersAll::FrameTooLong as usize],
        frames_dropped_buffer_full: stats
            [RMonCountersAll::FramesDroppedBufferFull as usize],
        frames_tx_ok: stats[RMonCountersAll::FramesTxOk as usize],
        frames_tx_all: stats[RMonCountersAll::FramesTxAll as usize],
        frames_tx_with_error: stats
            [RMonCountersAll::FramesTxWithError as usize],
        octets_tx_without_error: stats
            [RMonCountersAll::OctetsTxWithoutError as usize],
        octets_tx_total: stats[RMonCountersAll::OctetsTxTotal as usize],
    })
}

/// Fetch the full set of RMON counters for the given port.  These counters are not reset
/// after being read.
pub fn port_get_rmon_counters_all(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<common::counters::RMonCountersAll> {
    let stats = port_get_rmon_counter_data(hdl, port)?;
    Ok(common::counters::RMonCountersAll {
        port: port.to_string(),
        frames_rx_ok: stats[RMonCountersAll::FramesRxOk as usize],
        frames_rx_all: stats[RMonCountersAll::FramesRxAll as usize],
        frames_rx_with_fcs_error: stats
            [RMonCountersAll::FramesRxWithFCSError as usize],
        frames_rx_with_any_error: stats
            [RMonCountersAll::FramesRxWithAnyError as usize],
        octets_rx_in_good_frames: stats
            [RMonCountersAll::OctetsRxInGoodFrames as usize],
        octets_rx: stats[RMonCountersAll::OctetsRx as usize],
        frames_rx_with_unicast_addresses: stats
            [RMonCountersAll::FramesRxWithUnicastAddresses as usize],
        frames_rx_with_multicast_addresses: stats
            [RMonCountersAll::FramesRxWithMulticastAddresses as usize],
        frames_rx_with_broadcast_addresses: stats
            [RMonCountersAll::FramesRxWithBroadcastAddresses as usize],
        frames_rx_oftype_pause: stats
            [RMonCountersAll::FramesRxoftypePAUSE as usize],
        frames_rx_with_length_error: stats
            [RMonCountersAll::FramesRxWithLengthError as usize],
        frames_rx_indersized: stats
            [RMonCountersAll::FramesRxUndersized as usize],
        frames_rx_oversized: stats[RMonCountersAll::FramesRxOversized as usize],
        fragments_rx: stats[RMonCountersAll::FragmentsRx as usize],
        jabber_rx: stats[RMonCountersAll::JabberRx as usize],
        priority_pause_frames: stats
            [RMonCountersAll::PriorityPauseFrames as usize],
        crc_error_stomped: stats[RMonCountersAll::CRCErrorStomped as usize],
        frame_too_long: stats[RMonCountersAll::FrameTooLong as usize],
        rx_vlan_frames_good: stats[RMonCountersAll::RxVLANFramesGood as usize],
        frames_dropped_buffer_full: stats
            [RMonCountersAll::FramesDroppedBufferFull as usize],
        frames_rx_length_lt_64: stats
            [RMonCountersAll::FramesRxLengthLt64 as usize],
        frames_rx_length_eq_64: stats
            [RMonCountersAll::FramesRxLengthEq64 as usize],
        frames_rx_length_65_127: stats
            [RMonCountersAll::FramesRxLength65_127 as usize],
        frames_rx_length_128_255: stats
            [RMonCountersAll::FramesRxLength128_255 as usize],
        frames_rx_length_256_511: stats
            [RMonCountersAll::FramesRxLength256_511 as usize],
        frames_rx_length_512_1023: stats
            [RMonCountersAll::FramesRxLength512_1023 as usize],
        frames_rx_length_1024_1518: stats
            [RMonCountersAll::FramesRxLength1024_1518 as usize],
        frames_rx_length_1519_2047: stats
            [RMonCountersAll::FramesRxLength1519_2047 as usize],
        frames_rx_length_2048_4095: stats
            [RMonCountersAll::FramesRxLength2048_4095 as usize],
        frames_rx_length_4096_8191: stats
            [RMonCountersAll::FramesRxLength4096_8191 as usize],
        frames_rx_length_8192_9215: stats
            [RMonCountersAll::FramesRxLength8192_9215 as usize],
        frames_rx_length_9216: stats
            [RMonCountersAll::FramesRxLength9216 as usize],
        frames_tx_ok: stats[RMonCountersAll::FramesTxOk as usize],
        frames_tx_all: stats[RMonCountersAll::FramesTxAll as usize],
        frames_tx_with_error: stats
            [RMonCountersAll::FramesTxWithError as usize],
        octets_tx_without_error: stats
            [RMonCountersAll::OctetsTxWithoutError as usize],
        octets_tx_total: stats[RMonCountersAll::OctetsTxTotal as usize],
        frames_tx_unicast: stats[RMonCountersAll::FramesTxUnicast as usize],
        frames_tx_multicast: stats[RMonCountersAll::FramesTxMulticast as usize],
        frames_tx_broadcast: stats[RMonCountersAll::FramesTxBroadcast as usize],
        frames_tx_pause: stats[RMonCountersAll::FramesTxPause as usize],
        frames_tx_pri_pause: stats[RMonCountersAll::FramesTxPriPause as usize],
        frames_tx_vlan: stats[RMonCountersAll::FramesTxVLAN as usize],
        frames_tx_length_lt_64: stats
            [RMonCountersAll::FramesTxLengthLt64 as usize],
        frames_tx_length_eq_64: stats
            [RMonCountersAll::FramesTxLengthEq64 as usize],
        frames_tx_length_65_127: stats
            [RMonCountersAll::FramesTxLength65_127 as usize],
        frames_tx_length_128_255: stats
            [RMonCountersAll::FramesTxLength128_255 as usize],
        frames_tx_length_256_511: stats
            [RMonCountersAll::FramesTxLength256_511 as usize],
        frames_tx_length_512_1023: stats
            [RMonCountersAll::FramesTxLength512_1023 as usize],
        frames_tx_length_1024_1518: stats
            [RMonCountersAll::FramesTxLength1024_1518 as usize],
        frames_tx_length_1519_2047: stats
            [RMonCountersAll::FramesTxLength1519_2047 as usize],
        frames_tx_length_2048_4095: stats
            [RMonCountersAll::FramesTxLength2048_4095 as usize],
        frames_tx_length_4096_8191: stats
            [RMonCountersAll::FramesTxLength4096_8191 as usize],
        frames_tx_length_8192_9215: stats
            [RMonCountersAll::FramesTxLength8192_9215 as usize],
        frames_tx_length_9216: stats
            [RMonCountersAll::FramesTxLength9216 as usize],
        pri0_framex_tx: stats[RMonCountersAll::Pri0FramexTx as usize],
        pri1_frames_tx: stats[RMonCountersAll::Pri1FramesTx as usize],
        pri2_frames_tx: stats[RMonCountersAll::Pri2FramesTx as usize],
        pri3_frames_tx: stats[RMonCountersAll::Pri3FramesTx as usize],
        pri4_frames_tx: stats[RMonCountersAll::Pri4FramesTx as usize],
        pri5_frames_tx: stats[RMonCountersAll::Pri5FramesTx as usize],
        pri6_frames_tx: stats[RMonCountersAll::Pri6FramesTx as usize],
        pri7_frames_tx: stats[RMonCountersAll::Pri7FramesTx as usize],
        pri0_frames_rx: stats[RMonCountersAll::Pri0FramesRx as usize],
        pri1_frames_rx: stats[RMonCountersAll::Pri1FramesRx as usize],
        pri2_frames_rx: stats[RMonCountersAll::Pri2FramesRx as usize],
        pri3_frames_rx: stats[RMonCountersAll::Pri3FramesRx as usize],
        pri4_frames_rx: stats[RMonCountersAll::Pri4FramesRx as usize],
        pri5_frames_rx: stats[RMonCountersAll::Pri5FramesRx as usize],
        pri6_frames_rx: stats[RMonCountersAll::Pri6FramesRx as usize],
        pri7_frames_rx: stats[RMonCountersAll::Pri7FramesRx as usize],
        tx_pri0_pause_1us_count: stats
            [RMonCountersAll::TxPri0Pause1UsCount as usize],
        tx_pri1_pause_1us_count: stats
            [RMonCountersAll::TxPri1Pause1USCount as usize],
        tx_pri2_pause_1us_count: stats
            [RMonCountersAll::TxPri2Pause1USCount as usize],
        tx_pri3_pause_1us_count: stats
            [RMonCountersAll::TxPri3Pause1USCount as usize],
        tx_pri4_pause_1us_count: stats
            [RMonCountersAll::TxPri4Pause1USCount as usize],
        tx_pri5_pause_1us_count: stats
            [RMonCountersAll::TxPri5Pause1USCount as usize],
        tx_pri6_pause_1us_count: stats
            [RMonCountersAll::TxPri6Pause1USCount as usize],
        tx_pri7_pause_1us_count: stats
            [RMonCountersAll::TxPri7Pause1USCount as usize],
        rx_pri0_pause_1us_count: stats
            [RMonCountersAll::RxPri0Pause1UsCount as usize],
        rx_pri1_pause_1us_count: stats
            [RMonCountersAll::RxPri1Pause1USCount as usize],
        rx_pri2_pause_1us_count: stats
            [RMonCountersAll::RxPri2Pause1USCount as usize],
        rx_pri3_pause_1us_count: stats
            [RMonCountersAll::RxPri3Pause1USCount as usize],
        rx_pri4_pause_1us_count: stats
            [RMonCountersAll::RxPri4Pause1USCount as usize],
        rx_pri5_pause_1us_count: stats
            [RMonCountersAll::RxPri5Pause1USCount as usize],
        rx_pri6_pause_1us_count: stats
            [RMonCountersAll::RxPri6Pause1USCount as usize],
        rx_pri7_pause_1us_count: stats
            [RMonCountersAll::RxPri7Pause1USCount as usize],
        rx_standard_pause_1us_count: stats
            [RMonCountersAll::RxStandardPause1USCount as usize],
        frames_truncated: stats[RMonCountersAll::FramesTruncated as usize],
    })
}

/// Fetch the current PCS counters for the given port.  Note: these counters are
/// reset to 0 after reading.
pub fn port_get_pcs_counters(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<PcsCounters> {
    let mut bad_sync_headers = 0u32;
    let mut errored_blocks = 0u32;
    let mut sync_loss = 0u32;
    let mut block_lock_loss = 0u32;
    let mut hi_ber = 0u32;
    let mut valid_errors = 0u32;
    let mut unknown_errors = 0u32;
    let mut invalid_errors = 0u32;
    let mut bip_errors_per_pcs_lane = [0u32; 20];

    let port_id = ports::to_asic_id(hdl, port)?;
    unsafe {
        bf_port_pcs_counters_get(
            hdl.dev_id,
            port_id as i32,
            &mut bad_sync_headers,
            &mut errored_blocks,
            &mut sync_loss,
            &mut block_lock_loss,
            &mut hi_ber,
            &mut valid_errors,
            &mut unknown_errors,
            &mut invalid_errors,
            bip_errors_per_pcs_lane.as_mut_ptr(),
        )
    }
    .check_error("fetching pcs counters")?;
    Ok(PcsCounters {
        port: port.to_string(),
        bad_sync_headers,
        errored_blocks,
        sync_loss,
        block_lock_loss,
        hi_ber,
        valid_errors,
        unknown_errors,
        invalid_errors,
        bip_errors_per_pcs_lane: bip_errors_per_pcs_lane.to_vec(),
    })
}

/// Fetch the current FEC/RS counters for the given port.  Note: these counters are
/// reset to 0 after reading.
pub fn port_get_fec_rs_counters(
    hdl: &Handle,
    port: PortHdl,
) -> AsicResult<FecRSCounters> {
    let mut hi_ser = false;
    let mut fec_align_status = false;
    let mut fec_corr_cnt = 0u32;
    let mut fec_uncorr_cnt = 0u32;
    let mut fec_ser_lane_0 = 0u32;
    let mut fec_ser_lane_1 = 0u32;
    let mut fec_ser_lane_2 = 0u32;
    let mut fec_ser_lane_3 = 0u32;
    let mut fec_ser_lane_4 = 0u32;
    let mut fec_ser_lane_5 = 0u32;
    let mut fec_ser_lane_6 = 0u32;
    let mut fec_ser_lane_7 = 0u32;

    let port_id = ports::to_asic_id(hdl, port)?;
    unsafe {
        bf_port_rs_fec_status_and_counters_get(
            hdl.dev_id,
            port_id as i32,
            &mut hi_ser,
            &mut fec_align_status,
            &mut fec_corr_cnt,
            &mut fec_uncorr_cnt,
            &mut fec_ser_lane_0,
            &mut fec_ser_lane_1,
            &mut fec_ser_lane_2,
            &mut fec_ser_lane_3,
            &mut fec_ser_lane_4,
            &mut fec_ser_lane_5,
            &mut fec_ser_lane_6,
            &mut fec_ser_lane_7,
        )
    }
    .check_error("fetching fec RS stats")?;
    Ok(FecRSCounters {
        port: port.to_string(),
        hi_ser,
        fec_align_status,
        fec_corr_cnt,
        fec_uncorr_cnt,
        fec_ser_lane_0,
        fec_ser_lane_1,
        fec_ser_lane_2,
        fec_ser_lane_3,
        fec_ser_lane_4,
        fec_ser_lane_5,
        fec_ser_lane_6,
        fec_ser_lane_7,
    })
}

/// Fetch the PCS counters for all of the ports on the switch
pub fn port_get_pcs_counters_all(hdl: &Handle) -> AsicResult<Vec<PcsCounters>> {
    let rval = {
        let mut counters = Vec::new();
        let ports = {
            let phys_ports = hdl.phys_ports.lock().unwrap();
            phys_ports.get_tofino_ports()
        };
        for port in ports {
            if !port.is_cpu() {
                counters.push(port_get_pcs_counters(hdl, port)?);
            }
        }
        counters
    };

    Ok(rval)
}

/// Fetch the FEC/RS counters for all of the ports on the switch
pub fn port_get_fec_rs_counters_all(
    hdl: &Handle,
) -> AsicResult<BTreeMap<PortHdl, FecRSCounters>> {
    let rval = {
        let mut counters = BTreeMap::new();
        let ports = {
            let phys_ports = hdl.phys_ports.lock().unwrap();
            phys_ports.get_tofino_ports()
        };
        for port in ports {
            if !port.is_cpu() {
                counters.insert(port, port_get_fec_rs_counters(hdl, port)?);
            }
        }
        counters
    };

    Ok(rval)
}
