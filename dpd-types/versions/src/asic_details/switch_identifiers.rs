// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

use crate::v1;

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

/// Identifiers for a switch.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct SwitchIdentifiers {
    /// Unique identifier for the chip.
    pub sidecar_id: Uuid,
    /// Asic backend (compiler target) responsible for these identifiers.
    pub asic_backend: String,
    /// Fabrication plant identifier.
    pub fab: Option<char>,
    /// Lot identifier.
    pub lot: Option<char>,
    /// Lot number (4-character identifier within the lot).
    pub lotnum: Option<[char; 4]>,
    /// Wafer number within the lot.
    pub wafer: Option<u8>,
    /// The wafer location as (x, y) coordinates on the wafer, represented as
    /// an array due to the lack of tuple support in OpenAPI.
    pub wafer_loc: Option<[i16; 2]>,
    /// The model number of the switch being managed.
    pub model: String,
    /// The revision number of the switch being managed.
    pub revision: u32,
    /// The serial number of the switch being managed.
    pub serial: String,
    /// The slot number of the switch being managed.
    ///
    /// MGS uses u16 for this internally.
    pub slot: u16,
    /// Fuse data from the ASIC, if available.
    pub fuse: Option<FuseData>,
}

impl From<SwitchIdentifiers> for v1::switch_identifiers::SwitchIdentifiers {
    fn from(latest: SwitchIdentifiers) -> Self {
        Self {
            sidecar_id: latest.sidecar_id,
            asic_backend: latest.asic_backend,
            fab: latest.fab,
            lot: latest.lot,
            wafer: latest.wafer,
            wafer_loc: latest.wafer_loc,
            model: latest.model,
            revision: latest.revision,
            serial: latest.serial,
            slot: latest.slot,
        }
    }
}
