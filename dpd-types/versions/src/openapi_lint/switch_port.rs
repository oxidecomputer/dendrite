// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::Serialize;

use crate::v1;
use crate::v1::port::PortId;

use super::transceivers::QsfpDevice;

/// A physical port on the Sidecar switch.
//
// NOTE: This is the public API view onto `types::SwitchPort`.
#[derive(Clone, Debug, JsonSchema, Serialize)]
#[serde(rename = "SwitchPort")]
pub struct SwitchPortView {
    /// The identifier for the switch port.
    pub port_id: PortId,
    /// Information for QSFP port functionality. This will be empty for non-QSFP
    /// switch ports.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub qsfp_device: Option<QsfpDevice>,
}

impl From<SwitchPortView> for v1::switch_port::SwitchPortView {
    fn from(new: SwitchPortView) -> Self {
        Self {
            port_id: new.port_id,
            qsfp_device: new.qsfp_device.map(Into::into),
        }
    }
}
