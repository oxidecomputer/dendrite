// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;

use crate::v1;
use crate::v1::link::LinkId;
use crate::v4;
use crate::v4::route::RouteTarget;
use common::ports::PortId;
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Represents a new or replacement mapping of an IPv4 subnet to a single
/// RouteTarget nexthop target, which may be either IPv4 or IPv6.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4RouteUpdate {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// A single Route associated with this CIDR
    pub target: RouteTarget,
    /// Should this route replace any existing route?  If a route exists and
    /// this parameter is false, then the call will fail.
    pub replace: bool,
}

impl From<v1::route::Ipv4RouteUpdate> for Ipv4RouteUpdate {
    fn from(old: v1::route::Ipv4RouteUpdate) -> Self {
        Self {
            cidr: old.cidr,
            target: RouteTarget::V4(old.target),
            replace: old.replace,
        }
    }
}

impl From<v4::route::Ipv4OverIpv6RouteUpdate> for Ipv4RouteUpdate {
    fn from(old: v4::route::Ipv4OverIpv6RouteUpdate) -> Self {
        Self {
            cidr: old.cidr,
            target: RouteTarget::V6(old.target),
            replace: old.replace,
        }
    }
}

/// Represents a single subnet->target route entry with an IPv4 or IPv6
/// next hop.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouteTargetIpv4Path {
    /// The subnet being routed
    pub cidr: Ipv4Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the route (IPv4 or IPv6)
    pub tgt_ip: IpAddr,
}

impl From<v1::route::RouteTargetIpv4Path> for RouteTargetIpv4Path {
    fn from(old: v1::route::RouteTargetIpv4Path) -> Self {
        Self {
            cidr: old.cidr,
            port_id: old.port_id,
            link_id: old.link_id,
            tgt_ip: IpAddr::V4(old.tgt_ip),
        }
    }
}
