// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::counters::{
    FecRSCounters, PcsCounters, RMonCounters, RMonCountersAll,
};
use common::ports::PortId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::link::LinkId;

/// The Physical Coding Sublayer (PCS) counters for a specific link.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkPcsCounters {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The PCS counter data.
    pub counters: PcsCounters,
}

/// The FEC counters for a specific link, including its link ID.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkFecRSCounters {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The FEC counter data.
    pub counters: FecRSCounters,
}

/// The RMON counters (traffic counters) for a specific link.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkRMonCounters {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The RMON counter data.
    pub counters: RMonCounters,
}

/// The complete RMON counters (traffic counters) for a specific link.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkRMonCountersAll {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The RMON counter data.
    pub counters: RMonCountersAll,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CounterSync {
    /// Force a sync of the counters from the ASIC to memory, even if the
    /// default refresh timeout hasn't been reached.
    pub force_sync: bool,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CounterPath {
    pub counter: String,
}
