// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Public types for multicast group management.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use common::{network::NatTarget, ports::PortId};
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::link::LinkId;

/// Type alias for multicast group IDs.
pub type MulticastGroupId = u16;

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

/// Used to identify a multicast group by IP address, the main
/// identifier for a multicast group.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupIpParam {
    pub group_ip: IpAddr,
}

/// Used to identify a multicast group by ID.
///
/// If not provided, it will return all multicast groups.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupIdParam {
    pub group_id: Option<MulticastGroupId>,
}

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

/// A validated admin-scoped IPv6 multicast address.
///
/// Admin-scoped addresses are ff04::/16, ff05::/16, or ff08::/16. These are
/// used for internal/underlay multicast groups.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    JsonSchema,
)]
#[serde(try_from = "Ipv6Addr", into = "Ipv6Addr")]
pub struct AdminScopedIpv6(pub(crate) Ipv6Addr);

impl AdminScopedIpv6 {
    /// Create a new AdminScopedIpv6 if the address is admin-local (ff04::/16).
    pub fn new(addr: Ipv6Addr) -> Result<Self, String> {
        if !Ipv6Net::new_unchecked(addr, 128).is_admin_local_multicast() {
            return Err(format!(
                "Address {} is not admin-local (must be ff04::/16)",
                addr
            ));
        }
        Ok(Self(addr))
    }
}

impl TryFrom<Ipv6Addr> for AdminScopedIpv6 {
    type Error = String;

    fn try_from(addr: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(addr)
    }
}

impl From<AdminScopedIpv6> for Ipv6Addr {
    fn from(admin: AdminScopedIpv6) -> Self {
        admin.0
    }
}

impl From<AdminScopedIpv6> for IpAddr {
    fn from(admin: AdminScopedIpv6) -> Self {
        IpAddr::V6(admin.0)
    }
}

impl fmt::Display for AdminScopedIpv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for AdminScopedIpv6 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: Ipv6Addr =
            s.parse().map_err(|e| format!("invalid IPv6: {e}"))?;
        Self::new(addr)
    }
}

impl fmt::Display for IpSrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSrc::Exact(ip) => write!(f, "{ip}"),
            IpSrc::Subnet(net) => write!(f, "{net}"),
        }
    }
}

/// A multicast group configuration for POST requests for external (to the
/// rack) groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateExternalEntry {
    pub group_ip: IpAddr,
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// A multicast group update entry for PUT requests for external (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Response structure for external multicast group operations. These groups
/// handle IPv4 and non-admin IPv6 multicast via NAT targets.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupExternalResponse {
    pub group_ip: IpAddr,
    pub external_group_id: MulticastGroupId,
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Path parameter for underlay multicast group endpoints.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastUnderlayGroupIpParam {
    pub group_ip: AdminScopedIpv6,
}

/// A multicast group configuration for POST requests for internal (to the
/// rack) groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateUnderlayEntry {
    pub group_ip: AdminScopedIpv6,
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

/// Represents a multicast replication entry for PUT requests for internal
/// (to the rack) groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateUnderlayEntry {
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

/// Response structure for underlay/internal multicast group operations. These
/// groups handle admin-scoped IPv6 multicast with full replication.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUnderlayResponse {
    pub group_ip: AdminScopedIpv6,
    pub external_group_id: MulticastGroupId,
    pub underlay_group_id: MulticastGroupId,
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

/// Unified response type for operations that return mixed group types.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MulticastGroupResponse {
    Underlay(MulticastGroupUnderlayResponse),
    External(MulticastGroupExternalResponse),
}
