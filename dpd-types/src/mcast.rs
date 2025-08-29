// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
};

use common::{nat::NatTarget, ports::PortId};
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::link::LinkId;

/// Type alias for multicast group IDs.
pub type MulticastGroupId = u16;

/// Source filter match key for multicast traffic.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub enum IpSrc {
    /// Exact match for the source IP address.
    Exact(IpAddr),
    /// Subnet match for the source IP address.
    Subnet(Ipv4Net),
}

impl fmt::Display for IpSrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSrc::Exact(ip) => write!(f, "{}", ip),
            IpSrc::Subnet(subnet) => write!(f, "{}", subnet),
        }
    }
}

/// A multicast group configuration for POST requests for internal (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateEntry {
    pub group_ip: Ipv6Addr,
    pub tag: Option<String>,
    pub sources: Option<Vec<IpSrc>>,
    pub members: Vec<MulticastGroupMember>,
}

/// A multicast group configuration for POST requests for external (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateExternalEntry {
    pub group_ip: IpAddr,
    pub tag: Option<String>,
    pub nat_target: NatTarget,
    pub vlan_id: Option<u16>,
    pub sources: Option<Vec<IpSrc>>,
}

/// Represents a multicast replication entry for PUT requests for internal
/// (to the rack) groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateEntry {
    pub tag: Option<String>,
    pub sources: Option<Vec<IpSrc>>,
    pub members: Vec<MulticastGroupMember>,
}

/// A multicast group update entry for PUT requests for external (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    pub tag: Option<String>,
    pub nat_target: NatTarget,
    pub vlan_id: Option<u16>,
    pub sources: Option<Vec<IpSrc>>,
}

/// Response structure for multicast group operations.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupResponse {
    pub group_ip: IpAddr,
    pub external_group_id: Option<MulticastGroupId>,
    pub underlay_group_id: Option<MulticastGroupId>,
    pub tag: Option<String>,
    pub int_fwding: InternalForwarding,
    pub ext_fwding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
    pub members: Vec<MulticastGroupMember>,
}

/// Represents the NAT target for multicast traffic for internal/underlay
/// forwarding.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct InternalForwarding {
    pub nat_target: Option<NatTarget>,
}

/// Represents the forwarding configuration for external multicast traffic.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct ExternalForwarding {
    pub vlan_id: Option<u16>,
}

/// Represents a member of a multicast group.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastGroupMember {
    pub port_id: PortId,
    pub link_id: LinkId,
    pub direction: Direction,
}

/// Direction a multicast group member is reached by.
///
/// `External` group members must have any packet encapsulation removed
/// before packet delivery.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub enum Direction {
    Underlay,
    External,
}
