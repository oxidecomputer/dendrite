// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::fmt;

use aal::AsicError;
use aal::AsicResult;

/// The set of finite state machines we track
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsmType {
    Port,
}

impl fmt::Display for FsmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsmType::Port => write!(f, "Port"),
        }
    }
}

impl From<FsmType> for u32 {
    fn from(_t: FsmType) -> Self {
        0
    }
}

impl TryFrom<u32> for FsmType {
    type Error = AsicError;

    fn try_from(t: u32) -> AsicResult<Self> {
        match t {
            0 => Ok(FsmType::Port),
            x => Err(AsicError::InvalidFsmType(x)),
        }
    }
}

/// The possible finite state machine transitions
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsmState {
    Port(PortFsmState),
}

impl FsmState {
    /// Convert the integral fsm/state pair from the SDE into an FsmState
    /// instance
    pub fn new(fsm: u32, state: u32) -> AsicResult<Self> {
        match FsmType::try_from(fsm)? {
            FsmType::Port => Ok(FsmState::Port(PortFsmState::try_from(state)?)),
        }
    }

    /// Given an FsmState, return the name of the FSM to which it belongs
    pub fn fsm(&self) -> FsmType {
        FsmType::Port
    }

    /// Given an FsmState, return the name of the state
    pub fn state_name(&self) -> String {
        match self {
            FsmState::Port(state) => state.to_string(),
        }
    }
}

/// Links in the emulated ASICs don't have a real state machine underlying them.
/// We emulate a 2-state machine just to exercise the code in the main body of
/// dendrite.  Links will transition to the Idle state as they are disabled, and
/// will transition to the LinkUp state when they are enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PortFsmState {
    #[default]
    Idle,
    LinkUp,
}

impl fmt::Display for PortFsmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortFsmState::Idle => write!(f, "Idle"),
            PortFsmState::LinkUp => write!(f, "LinkUp"),
        }
    }
}

impl From<PortFsmState> for u32 {
    fn from(state: PortFsmState) -> Self {
        match state {
            PortFsmState::Idle => 0,
            PortFsmState::LinkUp => 1,
        }
    }
}

impl TryFrom<u32> for PortFsmState {
    type Error = AsicError;

    fn try_from(state: u32) -> Result<Self, AsicError> {
        match state {
            0 => Ok(PortFsmState::Idle),
            1 => Ok(PortFsmState::LinkUp),
            _ => Err(AsicError::InvalidFsmState(state)),
        }
    }
}

impl TryFrom<&u32> for PortFsmState {
    type Error = AsicError;

    fn try_from(state: &u32) -> Result<Self, AsicError> {
        PortFsmState::try_from(*state)
    }
}
