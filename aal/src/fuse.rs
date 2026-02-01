// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Fuse data types for Tofino ASICs.
//!
//! TODO: Add `asic_chip_rev` to oximeter timeseries (switch-data-link.toml in
//! omicron) to expose chip revision (A0/B0/B1) in metrics.

use schemars::JsonSchema;
use serde::Serialize;

/// Chip revision derived from device_id and rev_num fuse fields.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct ChipRevision {
    /// Computed revision string (e.g., "A0", "B0", "B1").
    pub rev: String,
    /// Raw device ID from fuse.
    pub device_id: u16,
    /// Raw revision number from fuse.
    pub rev_num: u8,
}

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

/// Part identification from fuse data.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct PartInfo {
    /// Part number (13 bits).
    pub part_num: u16,
    /// Package ID (2 bits).
    pub pkg_id: u8,
    /// Fuse version (2 bits).
    pub version: u8,
}

/// Features disabled via fuse programming.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct DisabledFeatures {
    /// Disabled pipes (4-bit bitmap).
    pub pipes: u8,
    /// Disabled ports (40-bit bitmap).
    pub ports: u64,
    /// Disabled speeds (64-bit bitmap).
    pub speeds: u64,
    /// Disabled MAUs per pipe (21 bits each).
    pub mau: [u32; 4],
    /// Disabled traffic manager memory (32-bit bitmap).
    pub tm_mem: u32,
    /// Buffer sync disabled.
    pub bsync: bool,
    /// Packet generator disabled.
    pub pgen: bool,
    /// Resubmit disabled.
    pub resub: bool,
}

/// Frequency settings from fuse data.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct FrequencySettings {
    /// Frequency disabled.
    pub disabled: bool,
    /// Backplane port speed frequency (2 bits).
    pub bps: u8,
    /// Packet processing speed frequency (2 bits).
    pub pps: u8,
    /// Extended backplane frequency (4 bits).
    pub bps_ext: u8,
    /// Extended packet speed frequency (4 bits).
    pub pps_ext: u8,
    /// PCIe disabled (2 bits).
    pub pcie_dis: u8,
    /// CPU speed disabled (2 bits).
    pub cpu_speed_dis: u8,
}

/// Manufacturing and repair data from fuse.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct ManufacturingData {
    /// Voltage scaling value (12 bits).
    pub voltage_scaling: u16,
    /// PMRO and skew value (12 bits).
    pub pmro_and_skew: u16,
    /// Die rotation.
    pub die_rotation: bool,
    /// Silent spin (2 bits).
    pub silent_spin: u8,
    /// Wafer core repair applied.
    pub wf_core_repair: bool,
    /// Core repair applied.
    pub core_repair: bool,
    /// Tile repair applied.
    pub tile_repair: bool,
    /// Soft pipe disable (4 bits).
    pub soft_pipe_dis: u8,
}

/// Organized fuse data from the Tofino ASIC.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct FuseData {
    /// Chip revision information.
    pub chip_rev: ChipRevision,
    /// Part identification.
    pub part: PartInfo,
    /// Disabled features.
    pub disabled: DisabledFeatures,
    /// Frequency settings.
    pub frequency: FrequencySettings,
    /// Manufacturing and repair data.
    pub manufacturing: ManufacturingData,
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
