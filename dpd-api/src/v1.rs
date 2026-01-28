// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Types from API version 1 (INITIAL) that changed in later versions.

use dpd_types::route::Ipv4Route;
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents all mappings of an IPv4 subnet to a its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// All RouteTargets associated with this CIDR
    pub targets: Vec<Ipv4Route>,
}

/// Identifiers for a switch.
///
/// Does not include the `lotnum` field, which was added in
/// SWITCH_IDENTIFIERS_LOTNUM.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct SwitchIdentifiers {
    /// Unique identifier for the chip.
    pub sidecar_id: Uuid,
    /// Asic backend (compiler target) responsible for these identifiers.
    pub asic_backend: String,
    /// Fabrication plant identifier.
    pub fab: Option<char>,
    /// Lot identifier.
    pub lot: Option<char>,
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
}

impl From<dpd_types::switch_identifiers::SwitchIdentifiers>
    for SwitchIdentifiers
{
    fn from(latest: dpd_types::switch_identifiers::SwitchIdentifiers) -> Self {
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
