// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::route::{Ipv4Route, Ipv6Route};
use crate::v4;
use crate::v6;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    V4(Ipv4Route),
    V6(Ipv6Route),
}

/// Represents a specific egress port and nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RouteTarget {
    V4(Ipv4Route),
    V6(Ipv6Route),
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// All RouteTargets associated with this CIDR
    pub targets: Vec<Route>,
}

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

impl From<Route> for v4::route::Route {
    fn from(new: Route) -> Self {
        match new {
            Route::V4(route) => Self::V4(route),
            Route::V6(route) => Self::V6(route),
        }
    }
}

impl From<v4::route::RouteTarget> for RouteTarget {
    fn from(old: v4::route::RouteTarget) -> Self {
        match old {
            v4::route::RouteTarget::V4(route) => Self::V4(route),
            v4::route::RouteTarget::V6(route) => Self::V6(route),
        }
    }
}

impl From<Ipv4Routes> for v4::route::Ipv4Routes {
    fn from(new: Ipv4Routes) -> Self {
        Self {
            cidr: new.cidr,
            targets: new.targets.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<v6::route::Ipv4RouteUpdate> for Ipv4RouteUpdate {
    fn from(old: v6::route::Ipv4RouteUpdate) -> Self {
        Self { cidr: old.cidr, target: old.target.into(), replace: old.replace }
    }
}
