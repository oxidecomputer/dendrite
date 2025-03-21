// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Code for operating on QSFP transceiver modules.

// Copyright 2025 Oxide Computer

use std::time::Instant;

use crate::switch_port::ManagementMode;
use crate::types::DpdResult;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use transceiver_controller::Identifier;
pub use transceiver_controller::PowerMode;
pub use transceiver_controller::PowerState;
pub use transceiver_controller::VendorInfo;

cfg_if::cfg_if! {
    if #[cfg(feature = "tofino_asic")] {
        mod tofino_impl;
        pub use tofino_impl::*;
    } else {
        mod stub_impl;
    }
}

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
        Self {
            transceiver: None,
            management_mode: ManagementMode::Automatic,
        }
    }
}

impl QsfpDevice {
    /// If this qsfp port has a supported transceiver that provides an MPN,
    /// return it to the caller.  If we have a supported transceiver that hasn't
    /// returned an MPN yet, return Ok(None).  If there is no transceiver
    /// detected at all, return DpdError::Missing.
    pub fn xcvr_mpn(&self) -> DpdResult<Option<String>> {
        #[cfg(feature = "softnpu")]
        {
            Ok(Some("OXIDESOFTNPU".to_string()))
        }

        #[cfg(feature = "tofino_asic")]
        {
            match &self.transceiver {
                Some(Transceiver::Supported(xcvr_info)) => {
                    if let Some(vendor_info) = &xcvr_info.vendor_info {
                        Ok(Some(vendor_info.vendor.part.clone()))
                    } else {
                        Ok(None)
                    }
                }
                // XXX: Is it worth returning different errors for faulted
                // and/or unsupported transceiver?
                _ => Err(crate::DpdError::Missing(
                    "no qsfp xcvr found".to_string(),
                )),
            }
        }

        #[cfg(not(any(feature = "tofino_asic", feature = "softnpu",)))]
        {
            Ok(None)
        }
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
#[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
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
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    #[serde(skip)]
    first_seen: Instant,
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

/// The BF SDE considers all ports except the CPU port as "QSFPs". This is not
/// accurate for the backplane / rear ports, which are completely different
/// electromechanical devices. Nonetheless we present a "QSFP-like" device to
/// the SDE so that it can manage them as if they're QSFP ports. This includes a
/// simple 256-byte memory map, which is mostly scratch space, and the LPMode /
/// ResetL signals as booleans. See the `asic::qsfp` and `dpd::transceivers`
/// modules for more details.
#[derive(Clone, Debug)]
// Allow clippy to pass with tofino_stub
#[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
pub struct FakeQsfpModule {
    pub map: [u8; 256],
    // TODO-cleanup: Make `FixedSideDevice::Backplane` have an
    // `Option<FakeQsfpModule>` instead of this boolean. That necessitates that
    // we have an out-of-band mechanism of detecting if the module is present,
    // other than the link simply disappearing.
    pub present: bool,
    pub lp_mode: bool,
    pub in_reset: bool,
}

impl Default for FakeQsfpModule {
    fn default() -> Self {
        // Almost all data is reported as zero. We explicitly set those values
        // that we wish to report.
        let mut map = [0; 256];

        // Identify ourselves as QSFP+ SFF-8636.
        map[0] = u8::from(Identifier::QsfpPlusSff8636);

        // Compliant to SFF-8636 Rev 2.10a
        map[1] = 0x08;

        // A flat memory model, and no monitoring data is ever ready.
        map[2] = 0b101;

        // Identifier again
        map[128] = map[0];

        // Connector type is non-separable.
        map[130] = 0x23;

        // Cable is copper, assume the 1m part.
        map[146] = 0x01;

        // Transmitter technology is passive copper.
        map[147] = 0b1011_0000;

        // Vendor name, padded with spaces to 16 octets.
        const VENDOR_NAME_LEN: usize = 16;
        const VENDOR_NAME: &[u8] = b"Oxide Comp Co   ";
        map[148..][..VENDOR_NAME_LEN].copy_from_slice(VENDOR_NAME);

        // Vendor OUI.
        map[165..168].copy_from_slice(&[0xa8, 0x40, 0x25]);

        // Part number, truncated to 16 octets.
        map[168..][..VENDOR_NAME_LEN].copy_from_slice(b"HDR-222627-01-EB");

        // Mfg date, assume 2022-01-1 with lot "ab".
        map[212..220].copy_from_slice(b"220101ab");

        let mut self_ = Self {
            map,
            present: true,
            lp_mode: true,
            in_reset: true,
        };

        let (base_sum, ext_sum) = self_.compute_checksums();
        self_.map[Self::CC_BASE_CHECKSUM] = base_sum;
        self_.map[Self::EXTENDED_CHECKSUM] = ext_sum;
        self_
    }
}

impl FakeQsfpModule {
    const CC_BASE_CHECKSUM: usize = 191;
    const EXTENDED_CHECKSUM: usize = 223;

    // Compute the SFF-8636 checksums for `self`.
    //
    // These are the CC_BASE field, byte 191, and the Check Code Extension
    // field, byte 223. Both are defined to be the low-order 8-bits of the sum
    // of the range of data they cover.
    fn compute_checksums(&self) -> (u8, u8) {
        const CC_BASE_RANGE: std::ops::Range<usize> = 128..191;
        const EXT_RANGE: std::ops::Range<usize> = 192..223;
        fn sum<'a>(x: impl Iterator<Item = &'a u8>) -> u8 {
            let sum: u32 = x.copied().map(u32::from).sum();
            (sum & 0xFF) as _
        }
        let base_sum = sum(self.map[CC_BASE_RANGE].iter());
        let ext_sum = sum(self.map[EXT_RANGE].iter());
        (base_sum, ext_sum)
    }

    // Return the base and extended checksums.
    #[cfg(all(test, feature = "tofino_asic"))]
    fn checksums(&self) -> (u8, u8) {
        (
            self.map[Self::CC_BASE_CHECKSUM],
            self.map[Self::EXTENDED_CHECKSUM],
        )
    }
}

#[cfg(all(test, feature = "tofino_asic"))]
mod mpn_test {
    use std::time::Instant;

    use crate::switch_port::ManagementMode;
    use crate::types::DpdError;
    use transceiver_controller::Identifier;

    use super::ElectricalMode;
    use super::QsfpDevice;
    use super::Transceiver;
    use super::TransceiverInfo;

    #[test]
    // If a QsfpDevice is found with a transceiver present, and if the VendorInfo
    // has been sucessfully read from the transceiver, then we would expect
    // xcvr_mpn() to return Ok(Some("name of part")).
    fn test_mpn_present() {
        pub use transceiver_controller::Oui;
        pub use transceiver_controller::Vendor;
        pub use transceiver_controller::VendorInfo;

        let vendor = Vendor {
            name: "name".to_string(),
            oui: Oui([0, 0, 0]),
            part: "part".to_string(),
            revision: "revision".to_string(),
            serial: "serial".to_string(),
            date: None,
        };
        let vendor_info = VendorInfo {
            identifier: Identifier::Soldered,
            vendor,
        };

        let transceiver = Transceiver::Supported(TransceiverInfo {
            vendor_info: Some(vendor_info),
            in_reset: None,
            interrupt_pending: None,
            power_mode: None,
            electrical_mode: ElectricalMode::Single,
            first_seen: Instant::now(),
        });

        let qsfp = QsfpDevice {
            transceiver: Some(transceiver),
            management_mode: ManagementMode::Manual,
        };
        assert_eq!(qsfp.xcvr_mpn().unwrap(), Some("part".to_string()));
    }

    #[test]
    // If a QsfpDevice is found with a transceiver present, but if the VendorInfo
    // has been not yet been sucessfully read from the transceiver, then we would
    // expect xcvr_mpn() to return Ok(None).
    fn test_mpn_missing() {
        let transceiver = Transceiver::Supported(TransceiverInfo {
            vendor_info: None,
            in_reset: None,
            interrupt_pending: None,
            power_mode: None,
            electrical_mode: ElectricalMode::Single,
            first_seen: Instant::now(),
        });

        let qsfp = QsfpDevice {
            transceiver: Some(transceiver),
            management_mode: ManagementMode::Manual,
        };
        assert_eq!(qsfp.xcvr_mpn().unwrap(), None);
    }

    // If a Qsfp port is found without any transceiver detected,
    // then we would expect xcvr_mpn() to return Err(DpdError::Missing).
    #[test]
    fn test_xcvr_missing() {
        let qsfp = QsfpDevice {
            transceiver: None,
            management_mode: ManagementMode::Manual,
        };
        // It would be preferable to use assert_matches! here, but that's still
        // unstable.
        assert!(matches!(qsfp.xcvr_mpn(), Err(DpdError::Missing(_))));
    }
}
