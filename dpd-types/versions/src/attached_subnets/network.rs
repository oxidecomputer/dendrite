// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::network::{MacAddr, Vni};

/** represents an internal target for either NAT or an external subnet mapping */
#[derive(
    Debug, Copy, Clone, Deserialize, Serialize, JsonSchema, Eq, PartialEq,
)]
pub struct InstanceTarget {
    pub internal_ip: Ipv6Addr,
    pub inner_mac: MacAddr,
    pub vni: Vni,
}
