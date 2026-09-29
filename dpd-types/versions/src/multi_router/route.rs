// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{IpAddr, Ipv6Addr};

use crate::v1::port::PortId;
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::v1::link::LinkId;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterPath {
    /// The router being addressed.
    pub router_id: Uuid,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterRoutePathV4 {
    /// The router being addressed.
    pub router_id: Uuid,
    /// The IPv4 subnet in CIDR notation whose route entry is addressed.
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterRoutePathV6 {
    /// The router being addressed.
    pub router_id: Uuid,
    /// The IPv6 subnet in CIDR notation whose route entry is addressed.
    pub cidr: Ipv6Net,
}

/// Represents a single subnet->target route entry within a routing table.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterRouteTargetIpv4Path {
    /// The router being addressed.
    pub router_id: Uuid,
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
    /// The router being addressed.
    pub router_id: Uuid,
    /// The subnet being routed
    pub cidr: Ipv6Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the route
    pub tgt_ip: Ipv6Addr,
}
