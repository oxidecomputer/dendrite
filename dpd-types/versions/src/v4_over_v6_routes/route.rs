// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::v1;
use crate::v1::route::{Ipv4Route, Ipv6Route};
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub enum Route {
    V4(Ipv4Route),
    V6(Ipv6Route),
}

/// Represents a specific egress port and nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
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

// v1 only understood IPv4 next hops, so drop any V6 targets on the way back.
impl From<Ipv4Routes> for v1::route::Ipv4Routes {
    fn from(new: Ipv4Routes) -> Self {
        Self {
            cidr: new.cidr,
            targets: new
                .targets
                .into_iter()
                .filter_map(|r| match r {
                    Route::V4(r) => Some(r),
                    Route::V6(_) => None,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4OverIpv6RouteUpdate {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// A single Route associated with this CIDR
    pub target: Ipv6Route,
    /// Should this route replace any existing route?  If a route exists and
    /// this parameter is false, then the call will fail.
    pub replace: bool,
}
