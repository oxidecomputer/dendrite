// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! NAT types changed in API version `MCAST_EXTERNAL_SCOPE`.

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::network::NatTarget;
use crate::v1;

/** represents an IPv6 NAT reservation */
#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Nat {
    pub external: Ipv6Addr,
    pub low: u16,
    pub high: u16,
    pub target: NatTarget,
}

/** represents an IPv4 NAT reservation */
#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Nat {
    pub external: Ipv4Addr,
    pub low: u16,
    pub high: u16,
    pub target: NatTarget,
}

impl From<Ipv6Nat> for v1::nat::Ipv6Nat {
    fn from(nat: Ipv6Nat) -> Self {
        Self {
            external: nat.external,
            low: nat.low,
            high: nat.high,
            target: nat.target.into(),
        }
    }
}

impl From<Ipv4Nat> for v1::nat::Ipv4Nat {
    fn from(nat: Ipv4Nat) -> Self {
        Self {
            external: nat.external,
            low: nat.low,
            high: nat.high,
            target: nat.target.into(),
        }
    }
}
