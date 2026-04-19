// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoopbackIpv4Path {
    pub ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoopbackIpv6Path {
    pub ipv6: Ipv6Addr,
}
