// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::fmt;

use crate::tofino_asic::bf_wrapper;
use crate::tofino_asic::genpd;
use crate::tofino_asic::TofinoFamily;
use aal::AsicError;
use aal::AsicResult;

/// The set of finite state machines we track
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsmType {
    Port,
    Media,
    Qsfp,
    QsfpChannel,
}

impl fmt::Display for FsmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsmType::Port => write!(f, "Port"),
            FsmType::Media => write!(f, "Media"),
            FsmType::Qsfp => write!(f, "Qsfp"),
            FsmType::QsfpChannel => write!(f, "QsfpChannel"),
        }
    }
}

impl TryFrom<genpd::bf_fsm_type_t> for FsmType {
    type Error = AsicError;

    fn try_from(t: genpd::bf_fsm_type_t) -> AsicResult<Self> {
        match t {
            genpd::bf_fsm_type_t_BF_FSM_PORT => Ok(FsmType::Port),
            genpd::bf_fsm_type_t_BF_FSM_MEDIA => Ok(FsmType::Media),
            genpd::bf_fsm_type_t_BF_FSM_QSFP => Ok(FsmType::Qsfp),
            genpd::bf_fsm_type_t_BF_FSM_QSFP_CHANNEL => {
                Ok(FsmType::QsfpChannel)
            }
            x => Err(AsicError::InvalidFsmType(x)),
        }
    }
}

/// The possible finite state machine transitions
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsmState {
    Port(PortFsmState),
    Media(MediaFsmState),
    Qsfp(QsfpFsmState),
    QsfpChannel(QsfpChannelFsmState),
}

impl FsmState {
    /// Convert the integral fsm/state pair from the SDE into an FsmState
    /// instance
    pub fn new(fsm: u32, state: u32) -> AsicResult<Self> {
        match FsmType::try_from(fsm)? {
            FsmType::Port => Ok(FsmState::Port(PortFsmState::try_from(state)?)),
            FsmType::Media => {
                Ok(FsmState::Media(MediaFsmState::try_from(state)?))
            }
            FsmType::Qsfp => Ok(FsmState::Qsfp(QsfpFsmState::try_from(state)?)),
            FsmType::QsfpChannel => {
                Ok(FsmState::QsfpChannel(QsfpChannelFsmState::try_from(state)?))
            }
        }
    }

    /// Given an FsmState, return the name of the FSM to which it belongs
    pub fn fsm(&self) -> FsmType {
        match self {
            FsmState::Port(_) => FsmType::Port,
            FsmState::Media(_) => FsmType::Media,
            FsmState::Qsfp(_) => FsmType::Qsfp,
            FsmState::QsfpChannel(_) => FsmType::QsfpChannel,
        }
    }

    /// Given an FsmState, return the name of the state
    pub fn state_name(&self) -> String {
        match self {
            FsmState::Port(state) => state.to_string(),
            FsmState::Media(state) => state.to_string(),
            FsmState::Qsfp(state) => state.to_string(),
            FsmState::QsfpChannel(state) => state.to_string(),
        }
    }
}

/// The individual states in the port-level autoneg/link-training FSM
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    strum::EnumIter,
    strum::IntoStaticStr,
    strum::EnumCount,
)]
pub enum PortFsmState {
    #[default]
    Idle,
    WaitPLLReady,
    WaitSignalOK,
    WaitDFEDone,
    RemoteFault,
    LinkDown,
    LinkUp,
    WaitTestDone,
    BERCheckStart,
    BERCheckDone,
    End,
    WaitAutoNegDone,
    WaitAutoNegLinkTrainingDone,
    MonitorPRBSErrors,
    // There are a collection of tofino3-specific states that we should never
    // see, since the ASIC was cancelled.
    Tofino3States,
    Abort,
    Disabled,
}

impl fmt::Display for PortFsmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Try to convert the port's FSM state from the SDE's bf_pm_fsm_st_t representation to our PortFsmState
impl TryFrom<u32> for PortFsmState {
    type Error = AsicError;

    fn try_from(mut state: u32) -> AsicResult<Self> {
        let family = bf_wrapper::get_asic_family()
            .expect("if the daemon is running, this should succeed");
        if family == TofinoFamily::Tofino1 {
            // The tofino1 has a completely different set of states than later
            // generations. Rather than trying to handle them all faithfully
            // just to support the one reference switch we have, we map them
            // onto 4 tofino2 states.
            //
            // - BF_FSM_ST_IDLE is mapped to BF_PM_FSM_ST_IDLE
            // - BF_FSM_ST_ABORT is mapped to BF_PM_FSM_ST_ABORT
            // - BF_FSM_ST_WAIT_DWN_EVNT is mapped to BF_PM_FSM_ST_LINK_UP
            // - Everything else is mapped to BF_PM_FSM_ST_WAIT_AN_LT_DONE
            //
            // These constants represent the state values of the three specific tofino1
            // states we watch for.
            const BF_FSM_ST_IDLE: u32 = 0;
            const BF_FSM_ST_ABORT: u32 = 33;
            const BF_FSM_ST_WAIT_DWN_EVNT: u32 = 10;

            state = match state {
                BF_FSM_ST_IDLE => genpd::bf_pm_fsm_st_BF_PM_FSM_ST_IDLE,
                BF_FSM_ST_ABORT => genpd::bf_pm_fsm_st_BF_PM_FSM_ST_ABORT,
                BF_FSM_ST_WAIT_DWN_EVNT => {
                    genpd::bf_pm_fsm_st_BF_PM_FSM_ST_LINK_UP
                }
                _ => genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_LT_DONE,
            }
        }

        match state {
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_IDLE => Ok(PortFsmState::Idle),
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_PLL_READY => {
                Ok(PortFsmState::WaitPLLReady)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_SIGNAL_OK => {
                Ok(PortFsmState::WaitSignalOK)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_DFE_DONE => {
                Ok(PortFsmState::WaitDFEDone)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_REMOTE_FAULT => {
                Ok(PortFsmState::RemoteFault)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_LINK_DN => {
                Ok(PortFsmState::LinkDown)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_LINK_UP => {
                Ok(PortFsmState::LinkUp)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_TEST_DONE => {
                Ok(PortFsmState::WaitTestDone)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_BER_CHECK_START => {
                Ok(PortFsmState::BERCheckStart)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_BER_CHECK_DONE => {
                Ok(PortFsmState::BERCheckDone)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_END => Ok(PortFsmState::End),
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_DONE => {
                Ok(PortFsmState::WaitAutoNegDone)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_LT_DONE => {
                Ok(PortFsmState::WaitAutoNegLinkTrainingDone)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_MONITOR_PRBS_ERRORS => {
                Ok(PortFsmState::MonitorPRBSErrors)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_RX_READY
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_TX_RATE_CHG_DONE
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_RX_RATE_CHG_DONE
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_CDR_LOCK
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_BIST_LOCK
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_PACING_CTRL
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_AN_NP_1
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_AN_NP_2
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_AN_NP_3
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_BASE_PG_DONE
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_SELECT_LT_CLAUSE
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_LT_DONE_CL72
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_LT_DONE_CL92
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_LT_DONE_CL136
            | genpd::bf_pm_fsm_st_BF_PM_FSM_ST_WAIT_AN_LT_DONE_CL162 => {
                Ok(PortFsmState::Tofino3States)
            }
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_ABORT => Ok(PortFsmState::Abort),
            genpd::bf_pm_fsm_st_BF_PM_FSM_ST_DISABLED => {
                Ok(PortFsmState::Disabled)
            }
            x => Err(AsicError::InvalidFsmState(x)),
        }
    }
}

impl TryFrom<&u32> for PortFsmState {
    type Error = AsicError;

    fn try_from(state: &u32) -> AsicResult<Self> {
        PortFsmState::try_from(*state)
    }
}

// The set of states the "media" FSM may be in
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediaFsmState {
    #[default]
    Disabled,
    Init,
    MediaDetected,
    WaitSerdesTxInit,
    WaitMediaInit,
    WaitLinkSt,
    IncompatibleMedia,
    HaWaitLinkSt,
    LinkUp,
    LinkDown,
    HaLinkUp,
    HaLinkDown,
    WaitMediaRxLos,
    WaitMediaRxLol,
    SetRxReady,
}

impl fmt::Display for MediaFsmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Try to convert a links's media FSM state from the SDE's pm_intf_fsm_states_t representation to our MediaFsmState
impl TryFrom<u32> for MediaFsmState {
    type Error = AsicError;

    fn try_from(state: u32) -> AsicResult<Self> {
        match state {
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_DISABLED => {
                Ok(MediaFsmState::Disabled)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_INIT => {
                Ok(MediaFsmState::Init)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_MEDIA_DETECTED => {
                Ok(MediaFsmState::MediaDetected)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_WAIT_SERDES_TX_INIT => {
                Ok(MediaFsmState::WaitSerdesTxInit)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_WAIT_MEDIA_INIT => {
                Ok(MediaFsmState::WaitMediaInit)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_WAIT_LINK_ST => {
                Ok(MediaFsmState::WaitLinkSt)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_INCOMPATIBLE_MEDIA => {
                Ok(MediaFsmState::IncompatibleMedia)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_HA_WAIT_LINK_ST => {
                Ok(MediaFsmState::HaWaitLinkSt)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_LINK_UP => {
                Ok(MediaFsmState::LinkUp)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_LINK_DOWN => {
                Ok(MediaFsmState::LinkDown)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_HA_LINK_UP => {
                Ok(MediaFsmState::HaLinkUp)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_HA_LINK_DOWN => {
                Ok(MediaFsmState::HaLinkDown)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_WAIT_MEDIA_RX_LOS => {
                Ok(MediaFsmState::WaitMediaRxLos)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_WAIT_MEDIA_RX_LOL => {
                Ok(MediaFsmState::WaitMediaRxLol)
            }
            genpd::pm_intf_fsm_states_t_PM_INTF_FSM_SET_RX_READY => {
                Ok(MediaFsmState::SetRxReady)
            }
            x => Err(AsicError::InvalidFsmState(x)),
        }
    }
}

/// Possible states for the QSFP FSM
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum QsfpFsmState {
    #[default]
    Idle,
    Removed,
    Inserted,
    WaitTReset,
    WaitTonTxdis,
    WaitLowPwr,
    DpDeactivate,
    ToffLpmode,
    WaitToffLmode,
    Detected,
    WaitTonLpmode,
    Lpmode,
    Update,
    WaitUpdate,
}

impl fmt::Display for QsfpFsmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Try to convert a QSFP FSM state from the SDE's qsfp_fsm_state_t representation to our QsfpFsmState
impl TryFrom<u32> for QsfpFsmState {
    type Error = AsicError;

    fn try_from(state: u32) -> AsicResult<Self> {
        match state {
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_IDLE => Ok(QsfpFsmState::Idle),
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_REMOVED => {
                Ok(QsfpFsmState::Removed)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_INSERTED => {
                Ok(QsfpFsmState::Inserted)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_WAIT_T_RESET => {
                Ok(QsfpFsmState::WaitTReset)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_WAIT_TON_TXDIS => {
                Ok(QsfpFsmState::WaitTonTxdis)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_WAIT_LOWPWR => {
                Ok(QsfpFsmState::WaitLowPwr)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_DP_DEACTIVATE => {
                Ok(QsfpFsmState::DpDeactivate)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_TOFF_LPMODE => {
                Ok(QsfpFsmState::ToffLpmode)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_WAIT_TOFF_LPMODE => {
                Ok(QsfpFsmState::WaitToffLmode)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_DETECTED => {
                Ok(QsfpFsmState::Detected)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_WAIT_TON_LPMODE => {
                Ok(QsfpFsmState::WaitTonLpmode)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_LPMODE => {
                Ok(QsfpFsmState::Lpmode)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_UPDATE => {
                Ok(QsfpFsmState::Update)
            }
            genpd::qsfp_fsm_state_t_QSFP_FSM_ST_WAIT_UPDATE => {
                Ok(QsfpFsmState::WaitUpdate)
            }
            x => Err(AsicError::InvalidFsmState(x)),
        }
    }
}

// The possible states in the per-channel QSFP state machine
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum QsfpChannelFsmState {
    #[default]
    Disabled,
    Enabling,
    Appsel,
    EnaCdr,
    EnaOpticalTx,
    NotifyEnabled,
    Enabled,
    Disabling,
    Rejected,
}

// Try to convert a channel's QSFP FSM state from the SDE's qsfp_fsm_ch_en_state_t representation to our QsfpChannelFsmState
impl TryFrom<u32> for QsfpChannelFsmState {
    type Error = AsicError;

    fn try_from(state: u32) -> AsicResult<Self> {
        match state {
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_DISABLED => {
                Ok(QsfpChannelFsmState::Disabled)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_ENABLING => {
                Ok(QsfpChannelFsmState::Enabling)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_APPSEL => {
                Ok(QsfpChannelFsmState::Appsel)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_ENA_CDR => {
                Ok(QsfpChannelFsmState::EnaCdr)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_ENA_OPTICAL_TX => {
                Ok(QsfpChannelFsmState::EnaOpticalTx)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_NOTIFY_ENABLED => {
                Ok(QsfpChannelFsmState::NotifyEnabled)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_ENABLED => {
                Ok(QsfpChannelFsmState::Enabled)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_DISABLING => {
                Ok(QsfpChannelFsmState::Disabling)
            }
            genpd::qsfp_fsm_ch_en_state_t_QSFP_CH_FSM_ST_REJECTED => {
                Ok(QsfpChannelFsmState::Rejected)
            }
            x => Err(AsicError::InvalidFsmState(x)),
        }
    }
}

impl fmt::Display for QsfpChannelFsmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An FFI-compatible routine that the SDE's C code can call when an FSM
/// transitions from one state to another.
#[no_mangle]
pub extern "C" fn bf_pm_fsm_transition_callback(
    fsm: genpd::bf_fsm_type_t,
    asic_id: u32,
    _from: u32,
    to: u32,
) {
    let asic_port_id = match u16::try_from(asic_id) {
        Ok(asic_id) => asic_id,
        Err(_) => return,
    };
    bf_wrapper::send_port_update(
        "port_fsm_transition_cb()",
        aal::PortUpdate::FSM {
            asic_port_id,
            fsm,
            state: to,
        },
    )
}
