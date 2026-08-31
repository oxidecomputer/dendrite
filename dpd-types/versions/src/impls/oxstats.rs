// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::v10::oxstats::OximeterConfig;
use uuid::Uuid;

impl OximeterConfig {
    /// Generate a unique Oximeter producer ID, based on the switch identifiers.
    pub const fn producer_id(&self) -> Uuid {
        Uuid::from_u128(
            self.sled_identifiers.rack_id.as_u128()
                ^ self.sled_identifiers.sled_id.as_u128()
                ^ self.switch_identifiers.sidecar_id.as_u128(),
        )
    }
}
