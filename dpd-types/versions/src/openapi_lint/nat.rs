// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An external IPv4 address with at least one NAT mapping.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct NatIpv4Address {
    /// The external address. Its mappings are listed by `nat_ipv4_list`.
    pub address: Ipv4Addr,
}

/// An external IPv6 address with at least one NAT mapping.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct NatIpv6Address {
    /// The external address. Its mappings are listed by `nat_ipv6_list`.
    pub address: Ipv6Addr,
}

impl From<NatIpv4Address> for Ipv4Addr {
    fn from(new: NatIpv4Address) -> Self {
        new.address
    }
}

impl From<NatIpv6Address> for Ipv6Addr {
    fn from(new: NatIpv6Address) -> Self {
        new.address
    }
}
