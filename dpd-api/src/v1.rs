// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use dpd_types::route::Ipv4Route;
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Represents all mappings of an IPv4 subnet to a its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// All RouteTargets associated with this CIDR
    pub targets: Vec<Ipv4Route>,
}
