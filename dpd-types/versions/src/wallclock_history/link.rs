// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkHistory {
    /// The wallclock time in milliseconds at which this history was collected.
    pub timestamp: i64,
    /// The timestamp in milliseconds at which this history was collected,
    /// relative to the time the switch management daemon started.
    pub relative: i64,
    /// The set of historical events recorded
    pub events: Vec<v1::link::LinkEvent>,
}

impl From<LinkHistory> for v1::link::LinkHistory {
    fn from(history: LinkHistory) -> Self {
        Self { timestamp: history.relative, events: history.events }
    }
}
