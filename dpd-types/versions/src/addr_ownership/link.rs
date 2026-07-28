// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use common::network::MacAddr;
use common::ports::PortId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tag::Tag;
use crate::v1::link::LinkId;

/// An IPv4 address resident on a link, along with the set of owners that
/// have claimed it.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4OwnedEntry {
    /// The IPv4 address.
    pub addr: Ipv4Addr,
    /// The owners that have claimed this address.
    pub owners: BTreeSet<Tag>,
}

/// An IPv6 address resident on a link, along with the set of owners that
/// have claimed it.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6OwnedEntry {
    /// The IPv6 address.
    pub addr: Ipv6Addr,
    /// The owners that have claimed this address.
    pub owners: BTreeSet<Tag>,
}

/// A request to claim an address on a link for one owner.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddressClaim {
    /// The owner claiming the address.
    pub owner: Tag,
}

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
    /// Every IPv6 link-local address resident on the link, along with the
    /// complete set of owners that have claimed it.  This lets tfportd
    /// identify its own claim rather than assuming any link-local it sees
    /// is one it manages.
    pub link_locals: Vec<Ipv6OwnedEntry>,
}
