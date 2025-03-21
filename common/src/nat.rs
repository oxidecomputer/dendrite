// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::network::MacAddr;

/// A Geneve Virtual Network Identifier.
///
/// A Geneve VNI is a 24-bit value used to identify virtual networks
/// encapsulated using the Generic Network Virtualization Encapsulation (Geneve)
/// protocol (RFC 8926).
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
)]
#[serde(try_from = "u32")]
pub struct Vni(u32);

impl Vni {
    const MAX_VNI: u32 = 0x00FF_FFFF;
    const ERR_MSG: &'static str = "VNI out of 24-bit range";

    /// Construct a new VNI, validating that it's a valid 24-bit value.
    pub const fn new(vni: u32) -> Option<Self> {
        // bool.then_some is not const, unforunately
        if vni <= Self::MAX_VNI {
            Some(Self(vni))
        } else {
            None
        }
    }

    /// Return the VNI as a u32.
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

impl core::convert::TryFrom<u32> for Vni {
    type Error = &'static str;

    fn try_from(vni: u32) -> Result<Self, Self::Error> {
        Self::new(vni).ok_or(Self::ERR_MSG)
    }
}

impl core::str::FromStr for Vni {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<u32>().map(Vni::new) {
            Err(_) | Ok(None) => Err(Self::ERR_MSG),
            Ok(Some(vni)) => Ok(vni),
        }
    }
}

impl fmt::Display for Vni {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/** represents an internal NAT target */
#[derive(
    Debug, Copy, Clone, Deserialize, Serialize, JsonSchema, Eq, PartialEq,
)]
pub struct NatTarget {
    pub internal_ip: Ipv6Addr,
    pub inner_mac: MacAddr,
    pub vni: Vni,
}

impl fmt::Display for NatTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.internal_ip, self.inner_mac, self.vni)
    }
}

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
    use super::Vni;

    #[test]
    fn test_vni() {
        assert!(Vni::new(u32::MAX).is_none());
        assert!(Vni::new(0).is_some());
        assert!(Vni::new(Vni::MAX_VNI).is_some());
        assert!(Vni::new(Vni::MAX_VNI + 1).is_none());
    }
}
