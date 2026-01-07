// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::network::NatTarget;

/** represents an IPv6 NAT reservation */
#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Nat {
    pub external: Ipv6Addr,
    pub low: u16,
    pub high: u16,
    pub target: NatTarget,
}

impl PartialEq for Ipv6Nat {
    fn eq(&self, other: &Self) -> bool {
        self.external == other.external
            && self.low == other.low
            && self.high == other.high
    }
}

/** represents an IPv4 NAT reservation */
#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Nat {
    pub external: Ipv4Addr,
    pub low: u16,
    pub high: u16,
    pub target: NatTarget,
}

impl PartialEq for Ipv4Nat {
    fn eq(&self, other: &Self) -> bool {
        self.external == other.external
            && self.low == other.low
            && self.high == other.high
    }
}

#[cfg(test)]
mod tests {
    use crate::network::Vni;

    #[test]
    fn test_vni() {
        assert!(Vni::new(u32::MAX).is_none());
        assert!(Vni::new(0).is_some());
        assert!(Vni::new(Vni::MAX_VNI).is_some());
        assert!(Vni::new(Vni::MAX_VNI + 1).is_none());
    }
}
