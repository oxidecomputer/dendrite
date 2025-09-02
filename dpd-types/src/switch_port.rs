// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use transceiver_controller::message::LedState;

/// How a switch port is managed.
///
/// The free-side devices in QSFP ports are complex devices, whose operation
/// usually involves coordinated steps through one or more state machines. For
/// example, when bringing up an optical link, a signal from the peer link must
/// be detected; then a signal recovered; equalizer gains set; etc. In
/// `Automatic` mode, all these kinds of steps are managed autonomously by
/// switch driver software. In `Manual` mode, none of these will occur -- a
/// switch port will only change in response to explicit requests from the
/// operator or Oxide control plane.
//
// NOTE: This is the parameter which marks a switch port _visible_ to the BF
// SDE. `Manual` means under our control, `Automatic` means visible to the SDE
// and under its control.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ManagementMode {
    /// A port is managed manually, by either the Oxide control plane or an
    /// operator.
    Manual,
    /// A port is managed automatically by the switch software.
    Automatic,
}

/// The policy by which a port's LED is controlled.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LedPolicy {
    /// The default policy is for the LED to reflect the port's state itself.
    ///
    /// If the port is operating normally, the LED will be solid on. Without a
    /// transceiver, the LED will be solid off. A blinking LED is used to
    /// indicate an unsupported module or other failure on that port.
    Automatic,
    /// The LED is explicitly overridden by client requests.
    Override,
}

/// Information about a QSFP port's LED.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct Led {
    /// The policy by which the LED is controlled.
    pub policy: LedPolicy,
    /// The state of the LED.
    pub state: LedState,
}
