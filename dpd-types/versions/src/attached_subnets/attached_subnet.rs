// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::network::InstanceTarget;

/** represents an external subnet mapping */
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct AttachedSubnetEntry {
    pub subnet: IpNet,
    pub tgt: InstanceTarget,
}
