// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Attached subnet types changed in API version `MCAST_EXTERNAL_SCOPE`.

use oxnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::network::InstanceTarget;
use crate::v3;

/** represents an external subnet mapping */
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct AttachedSubnetEntry {
    pub subnet: IpNet,
    pub tgt: InstanceTarget,
}

impl From<AttachedSubnetEntry> for v3::attached_subnet::AttachedSubnetEntry {
    fn from(entry: AttachedSubnetEntry) -> Self {
        Self { subnet: entry.subnet, tgt: entry.tgt.into() }
    }
}
