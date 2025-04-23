// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

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
