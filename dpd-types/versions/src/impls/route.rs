// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use crate::latest::route::{Ipv4Route, Ipv6Route, RouteTarget};

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

impl From<&Ipv4Route> for RouteTarget {
    fn from(route: &Ipv4Route) -> RouteTarget {
        RouteTarget::V4(route.clone())
    }
}

impl From<Ipv4Route> for RouteTarget {
    fn from(route: Ipv4Route) -> RouteTarget {
        RouteTarget::V4(route)
    }
}

impl From<&Ipv6Route> for RouteTarget {
    fn from(route: &Ipv6Route) -> RouteTarget {
        RouteTarget::V6(route.clone())
    }
}

impl From<Ipv6Route> for RouteTarget {
    fn from(route: Ipv6Route) -> RouteTarget {
        RouteTarget::V6(route)
    }
}

impl TryFrom<RouteTarget> for Ipv4Route {
    type Error = dropshot::HttpError;

    fn try_from(target: RouteTarget) -> Result<Self, Self::Error> {
        match target {
            RouteTarget::V4(route) => Ok(route),
            _ => Err(dropshot::HttpError::for_bad_request(
                None,
                "expected an IPv4 route target".to_string(),
            )),
        }
    }
}

impl TryFrom<RouteTarget> for Ipv6Route {
    type Error = dropshot::HttpError;

    fn try_from(target: RouteTarget) -> Result<Self, Self::Error> {
        match target {
            RouteTarget::V6(route) => Ok(route),
            _ => Err(dropshot::HttpError::for_bad_request(
                None,
                "expected an IPv6 route target".to_string(),
            )),
        }
    }
}
