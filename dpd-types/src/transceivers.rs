// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::time::Instant;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use transceiver_controller::{PowerMode, VendorInfo};

use crate::switch_port::ManagementMode;

/// A QSFP switch port.
///
/// This includes the hardware controls and information relevant to QSFP ports
/// specifically. For example, these ports are on the front IO panel of the
/// switch, and have LEDs used for status and attention. This includes the state
/// and controls for those LEDs. It also includes information about the
/// free-side QSFP module, should one be plugged in.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct QsfpDevice {
    /// Details about a transceiver module inserted into the switch port.
    ///
    /// If there is no transceiver at all, this will be `None`.
    pub transceiver: Option<Transceiver>,
    /// How the QSFP device is managed.
    ///
    /// See `ManagementMode` for details.
    pub management_mode: ManagementMode,
}

impl Default for QsfpDevice {
    fn default() -> Self {
        Self { transceiver: None, management_mode: ManagementMode::Automatic }
    }
}

/// The cause of a fault on a transceiver.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultReason {
    /// An error occurred accessing the transceiver.
    Failed,
    /// Power was enabled, but did not come up in the requisite time.
    PowerTimeout,
    /// Power was enabled and later lost.
    PowerLost,
    /// The service processor disabled the transceiver.
    ///
    /// The SP is responsible for monitoring the thermal data from the
    /// transceivers, and controlling the fans to compensate. If a module's
    /// thermal data cannot be read, the SP may completely disable the
    /// transceiver to ensure it cannot overheat the Sidecar.
    DisabledBySp,
}

/// The state of a transceiver in a QSFP switch port.
#[derive(Clone, Debug, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "info")]
pub enum Transceiver {
    /// The transceiver could not be managed due to a power fault.
    Faulted(FaultReason),
    /// A transceiver was present, but unsupported and automatically disabled.
    Unsupported,
    /// A transceiver is present and supported.
    Supported(TransceiverInfo),
}

/// Information about a QSFP transceiver.
///
/// This stores the most relevant information about a transceiver module, such
/// as vendor info or power. Each field may be missing, indicating it could not
/// be determined.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct TransceiverInfo {
    /// Vendor and part identifying information.
    ///
    /// The information will not be populated if it could not be read.
    pub vendor_info: Option<VendorInfo>,
    /// True if the module is currently in reset.
    pub in_reset: Option<bool>,
    /// True if there is a pending interrupt on the module.
    pub interrupt_pending: Option<bool>,
    /// The power mode of the transceiver.
    pub power_mode: Option<PowerMode>,
    /// The electrical mode of the transceiver.
    ///
    /// See [`ElectricalMode`] for details.
    pub electrical_mode: ElectricalMode,
    // The instant at which we first saw this transceiver.
    //
    // This is only used to support initially blinking the transceiver to
    // acknowledge insertion.
    #[serde(skip)]
    pub first_seen: Instant,
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

/// The electrical mode of a QSFP-capable port.
///
/// QSFP ports can be broken out into one of several different electrical
/// configurations or modes. This describes how the transmit/receive lanes are
/// grouped into a single, logical link.
///
/// Note that the electrical mode may only be changed if there are no links
/// within the port, _and_ if the inserted QSFP module actually supports this
/// mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub enum ElectricalMode {
    /// All transmit/receive lanes are used for a single link.
    #[default]
    Single,
}
