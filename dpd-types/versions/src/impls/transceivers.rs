// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::time::Instant;

use crate::latest::switch_port::ManagementMode;
use crate::latest::transceivers::{
    ElectricalMode, PowerState, QsfpDevice, TransceiverInfo,
};

impl std::fmt::Display for PowerState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PowerState::Off => f.write_str("off"),
            PowerState::Low => f.write_str("low"),
            PowerState::High => f.write_str("high"),
        }
    }
}

impl Default for QsfpDevice {
    fn default() -> Self {
        Self { transceiver: None, management_mode: ManagementMode::Automatic }
    }
}

impl Default for TransceiverInfo {
    fn default() -> Self {
        Self {
            vendor_info: None,
            in_reset: None,
            interrupt_pending: None,
            power_mode: None,
            electrical_mode: ElectricalMode::Single,
            first_seen: Instant::now(),
        }
    }
}
