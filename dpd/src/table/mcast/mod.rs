// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Multicast table operations.

use std::{
    convert::TryInto,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use aal::MatchParse;
use aal_macros::*;

pub(crate) mod mcast_egress;
pub(crate) mod mcast_nat;
pub(crate) mod mcast_port_mac;
pub(crate) mod mcast_replication;
pub(crate) mod mcast_route;
pub(crate) mod mcast_src_filter;

#[derive(MatchParse, Hash)]
struct Ipv4MatchKey {
    dst_addr: Ipv4Addr,
}

impl Ipv4MatchKey {
    fn new(dst_addr: Ipv4Addr) -> Self {
        Self { dst_addr }
    }
}

impl fmt::Display for Ipv4MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dst_addr)
    }
}

#[derive(MatchParse, Hash)]
struct Ipv6MatchKey {
    dst_addr: Ipv6Addr,
}

impl Ipv6MatchKey {
    pub(crate) fn new(dst_addr: Ipv6Addr) -> Self {
        Self { dst_addr }
    }
}

impl fmt::Display for Ipv6MatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dst_addr)
    }
}

/// VLAN-aware match key for NAT ingress tables.
///
/// Matches on destination address, VLAN header validity, and VLAN ID to prevent
/// VLAN translation. For groups with a VLAN, two entries are installed (untagged
/// and tagged), packets with a mismatched VLAN miss both and are dropped rather
/// than being translated to another customer's VLAN.
#[derive(MatchParse, Hash)]
pub(super) struct Ipv4VlanMatchKey {
    dst_addr: Ipv4Addr,
    #[match_xlate(name = "$valid")]
    vlan_valid: bool,
    vlan_id: u16,
}

impl Ipv4VlanMatchKey {
    pub(super) fn new(dst_addr: Ipv4Addr, vlan_id: Option<u16>) -> Self {
        match vlan_id {
            Some(id) => Self {
                dst_addr,
                vlan_valid: true,
                vlan_id: id,
            },
            None => Self {
                dst_addr,
                vlan_valid: false,
                vlan_id: 0,
            },
        }
    }
}

impl fmt::Display for Ipv4VlanMatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.vlan_valid {
            write!(f, "{} vlan={}", self.dst_addr, self.vlan_id)
        } else {
            write!(f, "{} untagged", self.dst_addr)
        }
    }
}

/// VLAN-aware match key for NAT ingress tables.
///
/// Matches on destination address, VLAN header validity, and VLAN ID to prevent
/// VLAN translation. For groups with a VLAN, two entries are installed (untagged
/// and tagged), packets with a mismatched VLAN miss both and are dropped rather
/// than being translated to another customer's VLAN.
#[derive(MatchParse, Hash)]
pub(super) struct Ipv6VlanMatchKey {
    dst_addr: Ipv6Addr,
    #[match_xlate(name = "$valid")]
    vlan_valid: bool,
    vlan_id: u16,
}

impl Ipv6VlanMatchKey {
    pub(super) fn new(dst_addr: Ipv6Addr, vlan_id: Option<u16>) -> Self {
        match vlan_id {
            Some(id) => Self {
                dst_addr,
                vlan_valid: true,
                vlan_id: id,
            },
            None => Self {
                dst_addr,
                vlan_valid: false,
                vlan_id: 0,
            },
        }
    }
}

impl fmt::Display for Ipv6VlanMatchKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.vlan_valid {
            write!(f, "{} vlan={}", self.dst_addr, self.vlan_id)
        } else {
            write!(f, "{} untagged", self.dst_addr)
        }
    }
}
