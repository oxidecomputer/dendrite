// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouterLoopbackIpv6Path {
    /// The router the address is claimed for.
    pub router_id: Uuid,
    pub ipv6: Ipv6Addr,
}
