// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{Ipv4Addr, Ipv6Addr};

use common::ports::PortId;
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::link::LinkId;

/// A route for an IPv4 subnet.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Route {
    // The client-specific tag for this route.
    pub tag: String,
    // The switch port out which routed traffic is sent.
    pub port_id: PortId,
    // The link out which routed traffic is sent.
    pub link_id: LinkId,
    // Route traffic matching the subnet via this IP.
    pub tgt_ip: Ipv4Addr,
    // Tag traffic on this route with this vlan ID.
    pub vlan_id: Option<u16>,
}

/// A route for an IPv6 subnet.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Route {
    // The client-specific tag for this route.
    pub tag: String,
    // The switch port out which routed traffic is sent.
    pub port_id: PortId,
    // The link out which routed traffic is sent.
    pub link_id: LinkId,
    // Route traffic matching the subnet to this IP.
    pub tgt_ip: Ipv6Addr,
    // Tag traffic on this route with this vlan ID.
    pub vlan_id: Option<u16>,
}

/// Represents a new or replacement mapping of a subnet to a single IPv6
/// RouteTarget nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6RouteUpdate {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv6Net,
    /// A single RouteTarget associated with this CIDR
    pub target: Ipv6Route,
    /// Should this route replace any existing route?  If a route exists and
    /// this parameter is false, then the call will fail.
    pub replace: bool,
}

/// Represents all mappings of an IPv6 subnet to a its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv6Net,
    /// All RouteTargets associated with this CIDR
    pub targets: Vec<Ipv6Route>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RoutePathV4 {
    /// The IPv4 subnet in CIDR notation whose route entry is returned.
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RoutePathV6 {
    /// The IPv6 subnet in CIDR notation whose route entry is returned.
    pub cidr: Ipv6Net,
}

/// Represents a single subnet->target route entry
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouteTargetIpv6Path {
    /// The subnet being routed
    pub cidr: Ipv6Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the IPv4 route
    pub tgt_ip: Ipv6Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of the
 * subnet routing table.  Because we don't (yet) support filtering or arbitrary
 * sorting, it is sufficient to track the last mac address reported.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv4RouteToken {
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv6RouteToken {
    pub cidr: Ipv6Net,
}

/// An object with IPv4 route settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct RouteSettingsV4 {
    pub link_id: u8,
    pub nexthop: Ipv4Addr,
}

/// An object with IPV6 route settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct RouteSettingsV6 {
    pub link_id: u8,
    pub nexthop: Ipv6Addr,
}

/// Represents all mappings of an IPv4 subnet to its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// All RouteTargets associated with this CIDR.
    pub targets: Vec<Ipv4Route>,
}

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
