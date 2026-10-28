// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Network types modified in API version `MCAST_EXTERNAL_SCOPE`.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::network::{MacAddr, VniError, VniParseError};
use crate::v3;

/// A validated Geneve Virtual Network Identifier.
///
/// A Geneve VNI is a 24-bit value used to identify virtual networks
/// encapsulated using the Generic Network Virtualization Encapsulation (Geneve)
/// protocol (RFC 8926). Any value above the 24-bit maximum of 16777215 is
/// rejected at both construction and deserialization.
// TODO: replace with a validated `Vni` newtype in oxnet, shared with
// `omicron_common::api::external::Vni` and `oxide_vpc::api::Vni`.
// This type checks only the 24-bit width. Reserved system and multicast VNI
// ranges are Omicron policy.
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
#[serde(try_from = "u32", into = "u32")]
pub struct Vni(#[schemars(range(max = 0xFF_FFFF))] u32);

impl Vni {
    /// Maximum Geneve VNI value.
    ///
    /// Virtual Network Identifiers are constrained to 24-bit values per the
    /// Geneve specification ([RFC 8926] §3.4).
    ///
    /// [RFC 8926]: https://www.rfc-editor.org/rfc/rfc8926.html
    pub const MAX_VNI: u32 = 0xFF_FFFF;

    /// Create a validated VNI.
    ///
    /// # Errors
    ///
    /// Returns [`VniError::OutOfRange`] if `value` exceeds [`Vni::MAX_VNI`].
    ///
    /// # Examples
    ///
    /// ```
    /// use dpd_types_versions::latest::network::Vni;
    ///
    /// assert!(Vni::new(77).is_ok());
    /// assert!(Vni::new(Vni::MAX_VNI + 1).is_err());
    /// ```
    pub const fn new(value: u32) -> Result<Self, VniError> {
        if value > Self::MAX_VNI {
            return Err(VniError::OutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Return the inner 24-bit value.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Vni {
    type Error = VniError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> Self {
        vni.0
    }
}

impl FromStr for Vni {
    type Err = VniParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vni = s
            .parse::<u32>()
            .map_err(|e| VniParseError::InvalidInt(s.to_string(), e))?;
        Ok(Self::new(vni)?)
    }
}

impl fmt::Display for Vni {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Represents an internal NAT target.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Deserialize, JsonSchema, Serialize,
)]
pub struct NatTarget {
    pub internal_ip: Ipv6Addr,
    pub inner_mac: MacAddr,
    pub vni: Vni,
}

/** represents an internal target for either NAT or an external subnet mapping */
#[derive(
    Debug, Copy, Clone, Deserialize, Serialize, JsonSchema, Eq, PartialEq,
)]
pub struct InstanceTarget {
    pub internal_ip: Ipv6Addr,
    pub inner_mac: MacAddr,
    pub vni: Vni,
}

const _: () = assert!(Vni::MAX_VNI == v1::network::Vni::MAX_VNI);

impl From<v1::network::Vni> for Vni {
    fn from(vni: v1::network::Vni) -> Self {
        Self(vni.as_u32())
    }
}

impl From<Vni> for v1::network::Vni {
    fn from(vni: Vni) -> Self {
        Self::new(vni.as_u32()).expect("VNI ranges match across versions")
    }
}

impl From<v1::network::NatTarget> for NatTarget {
    fn from(target: v1::network::NatTarget) -> Self {
        Self {
            internal_ip: target.internal_ip,
            inner_mac: target.inner_mac,
            vni: target.vni.into(),
        }
    }
}

impl From<NatTarget> for v1::network::NatTarget {
    fn from(target: NatTarget) -> Self {
        Self {
            internal_ip: target.internal_ip,
            inner_mac: target.inner_mac,
            vni: target.vni.into(),
        }
    }
}

impl From<v3::network::InstanceTarget> for InstanceTarget {
    fn from(target: v3::network::InstanceTarget) -> Self {
        Self {
            internal_ip: target.internal_ip,
            inner_mac: target.inner_mac,
            vni: target.vni.into(),
        }
    }
}

impl From<InstanceTarget> for v3::network::InstanceTarget {
    fn from(target: InstanceTarget) -> Self {
        Self {
            internal_ip: target.internal_ip,
            inner_mac: target.inner_mac,
            vni: target.vni.into(),
        }
    }
}
