// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SubnetPath {
    /// The external subnet in CIDR notation being managed
    pub subnet: IpNet,
}

/**
 * Represents a cursor into a paginated request for the contents of the
 * external subnets table.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct AttachedSubnetToken {
    pub cidr: IpNet,
}
