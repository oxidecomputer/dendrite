// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::network::MacAddr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Represents the mapping of an IP address to a MAC address.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ArpEntry {
    /// A tag used to associate this entry with a client.
    pub tag: String,
    /// The IP address for the entry.
    pub ip: IpAddr,
    /// The MAC address to which `ip` maps.
    pub mac: MacAddr,
    /// The time the entry was updated
    pub update: String,
}

/**
 * Represents a cursor into a paginated request for the contents of an ARP table
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ArpToken {
    pub ip: IpAddr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv4ArpParam {
    pub ip: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv6ArpParam {
    pub ip: Ipv6Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an
 * Ipv4-indexed table.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Token {
    pub ip: Ipv4Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an
 * IPv6-indexed table.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Token {
    pub ip: Ipv6Addr,
}
