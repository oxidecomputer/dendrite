// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Public types for multicast group management.

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
};

use common::{nat::NatTarget, ports::PortId};
use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::link::LinkId;

/// Type alias for multicast group IDs.
pub type MulticastGroupId = u16;

/// Admin-local IPv6 multicast prefix (ff04::/16, scope 4).
///
/// Defined in [RFC 7346] and [RFC 4291].
///
/// [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346.html
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
pub const ADMIN_LOCAL_PREFIX: u16 = 0xFF04;

/// A validated admin-local IPv6 multicast address.
///
/// Admin-local addresses are ff04::/16 (scope 4).
/// These are used for internal/underlay multicast groups.
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
pub struct AdminScopedIpv6(Ipv6Addr);

impl AdminScopedIpv6 {
    /// Create a new AdminScopedIpv6 if the address is admin-local.
    pub fn new(addr: Ipv6Addr) -> Result<Self, Error> {
        if !Ipv6Net::new_unchecked(addr, 128).is_admin_local_multicast() {
            return Err(Error::InvalidIp(addr));
        }
        Ok(Self(addr))
    }
}

impl TryFrom<Ipv6Addr> for AdminScopedIpv6 {
    type Error = Error;

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

/// Source filter match key for multicast traffic.
///
/// For SSM groups, use `Exact` with specific source addresses.
/// For ASM groups with any-source filtering, use `Any`.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub enum IpSrc {
    /// Exact match for the source IP address.
    Exact(IpAddr),
    /// Match any source address (0.0.0.0/0 or ::/0 depending on group IP version).
    Any,
}

impl fmt::Display for IpSrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSrc::Exact(ip) => write!(f, "{ip}"),
            IpSrc::Any => write!(f, "any"),
        }
    }
}

/// A multicast group configuration for POST requests for internal (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateUnderlayEntry {
    pub group_ip: AdminScopedIpv6,
    /// Tag for validating update/delete requests. If a tag is not provided,
    /// one is auto-generated as `{uuid}:{group_ip}`.
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

/// A multicast group configuration for POST requests for external (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateExternalEntry {
    pub group_ip: IpAddr,
    /// Tag for validating update/delete requests. If a tag is not provided,
    /// one is auto-generated as `{uuid}:{group_ip}`.
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Represents a multicast replication entry for PUT requests for internal
/// (to the rack) groups.
///
/// Tag validation is performed via the `tag` query parameter.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateUnderlayEntry {
    pub members: Vec<MulticastGroupMember>,
}

/// A multicast group update entry for PUT requests for external (to the rack)
/// groups.
///
/// Tag validation is performed via the `tag` query parameter.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Response structure for underlay/internal multicast group operations.
/// These groups handle admin-local IPv6 multicast with full replication.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUnderlayResponse {
    pub group_ip: AdminScopedIpv6,
    pub external_group_id: MulticastGroupId,
    pub underlay_group_id: MulticastGroupId,
    /// Tag for validating update/delete requests. Always present and generated
    /// as `{uuid}:{group_ip}` if not provided at creation time.
    pub tag: String,
    pub members: Vec<MulticastGroupMember>,
}

/// Response structure for external multicast group operations.
/// These groups handle IPv4 and non-admin-local IPv6 multicast via NAT targets.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupExternalResponse {
    pub group_ip: IpAddr,
    pub external_group_id: MulticastGroupId,
    /// Tag for validating update/delete requests. Always present and generated
    /// as `{uuid}:{group_ip}` if not provided at creation time.
    pub tag: String,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Unified response type for operations that return mixed group types.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MulticastGroupResponse {
    Underlay(MulticastGroupUnderlayResponse),
    External(MulticastGroupExternalResponse),
}

impl MulticastGroupResponse {
    /// Get the multicast group IP address.
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Underlay(resp) => resp.group_ip.into(),
            Self::External(resp) => resp.group_ip,
        }
    }

    /// Get the tag.
    pub fn tag(&self) -> &str {
        match self {
            Self::Underlay(resp) => &resp.tag,
            Self::External(resp) => &resp.tag,
        }
    }
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

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("Address {0} is not admin-local (must be ff04::/16)")]
    InvalidIp(Ipv6Addr),
}
