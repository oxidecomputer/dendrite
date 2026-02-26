// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

// Re-export fuse types from aal.
pub use aal::{
    ChipRevision, DisabledFeatures, FrequencySettings, FuseData,
    ManufacturingData, PartInfo,
};

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
