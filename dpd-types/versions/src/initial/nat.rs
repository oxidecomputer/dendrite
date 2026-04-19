// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv4Path {
    pub ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv4PortPath {
    pub ipv4: Ipv4Addr,
    pub low: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv4RangePath {
    pub ipv4: Ipv4Addr,
    pub low: u16,
    pub high: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv6Path {
    pub ipv6: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv6PortPath {
    pub ipv6: Ipv6Addr,
    pub low: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv6RangePath {
    pub ipv6: Ipv6Addr,
    pub low: u16,
    pub high: u16,
}

/**
 * Represents a cursor into a paginated request for all NAT data.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatToken {
    pub port: u16,
}
