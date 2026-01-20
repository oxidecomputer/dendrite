// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Code for operating on QSFP transceiver modules.

// Copyright 2025 Oxide Computer

use crate::types::DpdResult;
use dpd_types::transceivers::QsfpDevice;
use transceiver_controller::Identifier;
pub use transceiver_controller::PowerState;

cfg_if::cfg_if! {
    if #[cfg(feature = "tofino_asic")] {
        mod tofino_impl;
        pub use tofino_impl::*;
    } else {
        mod stub_impl;
    }
}

/// If this qsfp port has a supported transceiver that provides an MPN,
/// return it to the caller.  If we have a supported transceiver that hasn't
/// returned an MPN yet, return Ok(None).  If there is no transceiver
/// detected at all, return DpdError::Missing.
pub fn qsfp_xcvr_mpn(
    #[allow(unused_variables)] qsfp: &QsfpDevice,
) -> DpdResult<String> {
    #[cfg(feature = "softnpu")]
    {
        Ok("OXIDESOFTNPU".to_string())
    }

    #[cfg(feature = "tofino_asic")]
    {
        use dpd_types::transceivers::Transceiver;

        match &qsfp.transceiver {
            Some(Transceiver::Supported(xcvr_info)) => {
                if let Some(vendor_info) = &xcvr_info.vendor_info {
                    Ok(vendor_info.vendor.part.clone())
                } else {
                    Err(crate::DpdError::Missing(
                        "No vendor data found".to_string(),
                    ))
                }
            }
            Some(Transceiver::Unsupported) => {
                Err(crate::DpdError::UnusableTransceiver)
            }
            Some(Transceiver::Faulted(reason)) => {
                Err(crate::DpdError::Faulted(format!("{reason:?}")))
            }
            None => {
                Err(crate::DpdError::Missing("no qsfp xcvr found".to_string()))
            }
        }
    }

    #[cfg(not(any(feature = "tofino_asic", feature = "softnpu",)))]
    {
        Ok("OXIDEOTHER".to_string())
    }
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

        let mut self_ =
            Self { map, present: true, lp_mode: true, in_reset: true };

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
        (self.map[Self::CC_BASE_CHECKSUM], self.map[Self::EXTENDED_CHECKSUM])
    }
}

#[cfg(all(test, feature = "tofino_asic"))]
mod mpn_test {
    use std::time::Instant;

    use crate::{transceivers::qsfp_xcvr_mpn, types::DpdError};
    use dpd_types::{
        switch_port::ManagementMode,
        transceivers::{ElectricalMode, Transceiver, TransceiverInfo},
    };
    use transceiver_controller::Identifier;

    use super::QsfpDevice;

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
        let vendor_info =
            VendorInfo { identifier: Identifier::Soldered, vendor };

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
        assert_eq!(qsfp_xcvr_mpn(&qsfp).unwrap(), "part".to_string());
    }

    #[test]
    // If a QsfpDevice is found with a transceiver present, but if the VendorInfo
    // has been not yet been sucessfully read from the transceiver, then we would
    // expect xcvr_mpn() to return an error.
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
        assert!(qsfp_xcvr_mpn(&qsfp).is_err());
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
        assert!(matches!(qsfp_xcvr_mpn(&qsfp), Err(DpdError::Missing(_))));
    }
}
