// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Fuse data types for Tofino ASICs.
//!
//! Chip revision info is exposed in oximeter metrics via the `asic_lot` field
//! (e.g., "FL1234-B1").
//!
//! TODO: Add a dedicated `asic_chip_rev` field to oximeter timeseries when
//! reconfigurator supports oximeter schema migration. Currently there is no
//! window during online updates where all switches stop producing data, so the
//! old schema cannot be safely updated.

pub use dpd_types::switch_identifiers::{
    ChipRevision, DisabledFeatures, FrequencySettings, FuseData,
    ManufacturingData, PartInfo,
};
