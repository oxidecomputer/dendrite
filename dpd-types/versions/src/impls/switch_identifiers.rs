// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::latest::switch_identifiers::ChipRevision;

impl ChipRevision {
    /// Compute chip revision from device_id and rev_num.
    pub fn from_fuse(device_id: u16, rev_num: u8) -> Self {
        let rev = match device_id {
            0x0100 => "A0".to_string(),
            0x0110 => match rev_num {
                0 => "B0".to_string(),
                2 => "B1".to_string(),
                _ => format!("{:04x}", device_id),
            },
            _ => format!("{:04x}", device_id),
        };
        Self { rev, device_id, rev_num }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_revision_a0() {
        let rev = ChipRevision::from_fuse(0x0100, 0);
        assert_eq!(rev.rev, "A0");
        assert_eq!(rev.device_id, 0x0100);
        assert_eq!(rev.rev_num, 0);
    }

    #[test]
    fn chip_revision_b0() {
        let rev = ChipRevision::from_fuse(0x0110, 0);
        assert_eq!(rev.rev, "B0");
        assert_eq!(rev.device_id, 0x0110);
        assert_eq!(rev.rev_num, 0);
    }

    #[test]
    fn chip_revision_b1() {
        let rev = ChipRevision::from_fuse(0x0110, 2);
        assert_eq!(rev.rev, "B1");
        assert_eq!(rev.device_id, 0x0110);
        assert_eq!(rev.rev_num, 2);
    }

    #[test]
    fn chip_revision_unknown_rev_num() {
        let rev = ChipRevision::from_fuse(0x0110, 5);
        assert_eq!(rev.rev, "0110");
        assert_eq!(rev.device_id, 0x0110);
        assert_eq!(rev.rev_num, 5);
    }

    #[test]
    fn chip_revision_unknown_device_id() {
        let rev = ChipRevision::from_fuse(0x0200, 0);
        assert_eq!(rev.rev, "0200");
        assert_eq!(rev.device_id, 0x0200);
        assert_eq!(rev.rev_num, 0);
    }
}
