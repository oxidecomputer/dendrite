// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use common::ports::PortId;
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::link::LinkId;

/// Selects one of the switch's routing tables.
///
/// Table 0 is the default table, used by all pre-multi-router endpoints.
/// The id is a switch-local table index; mapping any fleet-wide router
/// identity onto it is the caller's responsibility.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(transparent)]
pub struct RouterId(pub u8);

impl std::fmt::Display for RouterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RouterId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u8>().map(RouterId)
    }
}

impl From<u8> for RouterId {
    fn from(id: u8) -> Self {
        RouterId(id)
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterPath {
    /// The routing table being addressed.
    pub router_id: RouterId,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterRoutePathV4 {
    /// The routing table being addressed.
    pub router_id: RouterId,
    /// The IPv4 subnet in CIDR notation whose route entry is addressed.
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterRoutePathV6 {
    /// The routing table being addressed.
    pub router_id: RouterId,
    /// The IPv6 subnet in CIDR notation whose route entry is addressed.
    pub cidr: Ipv6Net,
}

/// Represents a single subnet->target route entry within a routing table.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterRouteTargetIpv4Path {
    /// The routing table being addressed.
    pub router_id: RouterId,
    /// The subnet being routed
    pub cidr: Ipv4Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the route (IPv4 or IPv6)
    pub tgt_ip: IpAddr,
}

/// Represents a single subnet->target route entry within a routing table.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterRouteTargetIpv6Path {
    /// The routing table being addressed.
    pub router_id: RouterId,
    /// The subnet being routed
    pub cidr: Ipv6Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the route
    pub tgt_ip: Ipv6Addr,
}
