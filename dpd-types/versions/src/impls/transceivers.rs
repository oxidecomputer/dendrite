// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::time::Instant;

use crate::latest::switch_port::ManagementMode;
use crate::latest::transceivers::{
    ElectricalMode, QsfpDevice, TransceiverInfo,
};

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
