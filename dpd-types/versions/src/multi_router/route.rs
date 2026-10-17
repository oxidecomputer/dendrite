// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{IpAddr, Ipv6Addr};

use crate::v1;
use crate::v1::port::PortId;
use crate::v6;
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::v1::link::LinkId;

/// The logical router used for backwards compatibility, sharing routing table
/// 0 with the underlay routes. This is to be removed when compatibility in a
/// subsequent version.
pub const DEFAULT_ROUTER: Uuid = Uuid::nil();

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterPath {
    /// The router being addressed.
    pub router_id: Uuid,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RoutePathV4 {
    /// The router being addressed.
    pub router_id: Uuid,
    /// The IPv4 subnet in CIDR notation whose route entry is returned.
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RoutePathV6 {
    /// The router being addressed.
    pub router_id: Uuid,
    /// The IPv6 subnet in CIDR notation whose route entry is returned.
    pub cidr: Ipv6Net,
}

/// Represents a single subnet->target route entry with an IPv4 or IPv6
/// next hop.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouteTargetIpv4Path {
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

/// Represents a single subnet->target route entry
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouteTargetIpv6Path {
    /// The router being addressed.
    pub router_id: Uuid,
    /// The subnet being routed
    pub cidr: Ipv6Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the IPv6 route
    pub tgt_ip: Ipv6Addr,
}

// Paths from earlier versions have no router, and address the default router.

impl From<v1::route::RoutePathV4> for RoutePathV4 {
    fn from(old: v1::route::RoutePathV4) -> Self {
        Self { router_id: DEFAULT_ROUTER, cidr: old.cidr }
    }
}

impl From<v1::route::RoutePathV6> for RoutePathV6 {
    fn from(old: v1::route::RoutePathV6) -> Self {
        Self { router_id: DEFAULT_ROUTER, cidr: old.cidr }
    }
}

impl From<v6::route::RouteTargetIpv4Path> for RouteTargetIpv4Path {
    fn from(old: v6::route::RouteTargetIpv4Path) -> Self {
        Self {
            router_id: DEFAULT_ROUTER,
            cidr: old.cidr,
            port_id: old.port_id,
            link_id: old.link_id,
            tgt_ip: old.tgt_ip,
        }
    }
}

impl From<v1::route::RouteTargetIpv6Path> for RouteTargetIpv6Path {
    fn from(old: v1::route::RouteTargetIpv6Path) -> Self {
        Self {
            router_id: DEFAULT_ROUTER,
            cidr: old.cidr,
            port_id: old.port_id,
            link_id: old.link_id,
            tgt_ip: old.tgt_ip,
        }
    }
}
