// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkHistory {
    /// The timestamp in milliseconds at which this history was collected
    pub timestamp: i64,
    /// The set of historical events recorded
    pub events: Vec<dpd_types::views::LinkEvent>,
}
