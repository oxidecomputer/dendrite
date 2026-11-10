// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv6Addr;

use oxnet::UnicastLinkLocalIpv6Addr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1::{self, link::LinkId, network::MacAddr, port::PortId};

/// The per-link data consumed by tfportd
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct TfportData {
    /// The switch port ID for this link.
    pub port_id: PortId,
    /// The link ID for this link.
    pub link_id: LinkId,
    /// The lower-level ASIC ID used to refer to this object in the switch
    /// driver software.
    pub asic_id: u16,
    /// The MAC address for the link.
    pub mac: MacAddr,
    /// Is ipv6 enabled for this link
    pub ipv6_enabled: bool,
    /// The IPv6 link-local address of the link, if it exists.
    pub link_local: Option<UnicastLinkLocalIpv6Addr>,
}

impl From<TfportData> for v1::link::TfportData {
    fn from(value: TfportData) -> Self {
        v1::link::TfportData {
            port_id: value.port_id,
            link_id: value.link_id,
            asic_id: value.asic_id,
            mac: value.mac,
            ipv6_enabled: value.ipv6_enabled,
            link_local: value.link_local.map(Ipv6Addr::from),
        }
    }
}
