// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use oxnet::Ipv4Net;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::network::InstanceTarget;

/** represents an external subnet mapping */
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct ExtSubnetEntry {
    pub subnet: Ipv4Net,
    pub tgt: InstanceTarget,
}

impl fmt::Display for ExtSubnetEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}", self.subnet, self.tgt)
    }
}
