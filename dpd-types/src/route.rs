// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use common::ports::PortId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::link::LinkId;

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

// We implement PartialEq for Ipv4Route because we want to exclude the tag and
// vlan_id from any comparisons.  We do this because the tag is a comment
// identifying the originator rather than a semantically meaningful part of the
// route.  The vlan_id is used to modify the traffic on a specific route, rather
// then being part of the route itself.
impl PartialEq for Ipv4Route {
    fn eq(&self, other: &Self) -> bool {
        self.port_id == other.port_id
            && self.link_id == other.link_id
            && self.tgt_ip == other.tgt_ip
    }
}

// See the comment above PartialEq to understand why we implement Hash rather
// then Deriving it.
impl std::hash::Hash for Ipv4Route {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.port_id.hash(state);
        self.link_id.hash(state);
        self.tgt_ip.hash(state);
    }
}

impl fmt::Display for Ipv4Route {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "port: {} link: {} gw: {}  vlan: {:?}",
            self.port_id, self.link_id, self.tgt_ip, self.vlan_id
        )?;
        Ok(())
    }
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

// See the comment above the PartialEq for IPv4Route
impl PartialEq for Ipv6Route {
    fn eq(&self, other: &Self) -> bool {
        self.port_id == other.port_id
            && self.link_id == other.link_id
            && self.tgt_ip == other.tgt_ip
    }
}

// See the comment above PartialEq for IPv4Route
impl std::hash::Hash for Ipv6Route {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.port_id.hash(state);
        self.link_id.hash(state);
        self.tgt_ip.hash(state);
    }
}

impl fmt::Display for Ipv6Route {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "port: {} link: {} gw: {}  vlan: {:?}",
            self.port_id, self.link_id, self.tgt_ip, self.vlan_id
        )?;
        Ok(())
    }
}
