// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv4Addr;

use common::ports::PortId;
use dpd_types::link::LinkId;
use dpd_types::route::Ipv4Route;
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Represents a new or replacement mapping of a subnet to a single IPv4
/// RouteTarget nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4RouteUpdate {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// A single Route associated with this CIDR
    pub target: Ipv4Route,
    /// Should this route replace any existing route?  If a route exists and
    /// this parameter is false, then the call will fail.
    pub replace: bool,
}

/// Represents a single subnet->target route entry
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouteTargetIpv4Path {
    /// The subnet being routed
    pub cidr: Ipv4Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the IPv4 route
    pub tgt_ip: Ipv4Addr,
}
