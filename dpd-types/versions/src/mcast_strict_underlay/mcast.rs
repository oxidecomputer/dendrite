// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Public types for multicast group management introduced in the
//! `MCAST_STRICT_UNDERLAY` version.

use std::net::{IpAddr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::mcast::{
    ExternalForwarding, InternalForwarding, MulticastGroupId,
    MulticastGroupMember,
};
use crate::v7;
use crate::v7::mcast::IpSrc;

/// A validated underlay multicast IPv6 address.
///
/// Underlay multicast addresses must be within the subnet allocated by Omicron
/// for rack-internal multicast traffic (ff04::/64). This is a subset of the
/// admin-local scope (ff04::/16) defined in RFC 4291.
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
pub struct UnderlayMulticastIpv6(pub(crate) Ipv6Addr);

impl TryFrom<Ipv6Addr> for UnderlayMulticastIpv6 {
    type Error = Error;

    fn try_from(addr: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(addr)
    }
}

impl From<UnderlayMulticastIpv6> for Ipv6Addr {
    fn from(addr: UnderlayMulticastIpv6) -> Self {
        addr.0
    }
}

impl From<UnderlayMulticastIpv6> for v1::mcast::AdminScopedIpv6 {
    fn from(underlay: UnderlayMulticastIpv6) -> Self {
        // UnderlayMulticastIpv6 is a subset of AdminScopedIpv6, so this is safe.
        Self::new(underlay.into())
            .expect("UnderlayMulticastIpv6 is within AdminScopedIpv6 range")
    }
}

impl TryFrom<v1::mcast::AdminScopedIpv6> for UnderlayMulticastIpv6 {
    type Error = String;

    fn try_from(
        admin: v1::mcast::AdminScopedIpv6,
    ) -> Result<Self, Self::Error> {
        UnderlayMulticastIpv6::new(admin.into()).map_err(|e| e.to_string())
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "Address {0} is not in underlay multicast subnet (must be ff04::/64)"
    )]
    InvalidUnderlayMulticastIp(Ipv6Addr),
    #[error("Invalid IPv6 address '{0}': {1}")]
    InvalidIpv6Address(String, std::net::AddrParseError),
}

/// A multicast group configuration for POST requests for internal (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateUnderlayEntry {
    pub group_ip: UnderlayMulticastIpv6,
    /// Tag for validating update/delete requests. If a tag is not provided,
    /// one is auto-generated as `{uuid}:{group_ip}`.
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

/// Represents a multicast replication entry for PUT requests for internal
/// (to the rack) groups.
///
/// Tag validation is performed via the `tag` query parameter.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateUnderlayEntry {
    pub members: Vec<MulticastGroupMember>,
}

impl From<v1::mcast::MulticastGroupUpdateUnderlayEntry>
    for MulticastGroupUpdateUnderlayEntry
{
    fn from(entry: v1::mcast::MulticastGroupUpdateUnderlayEntry) -> Self {
        Self { members: entry.members }
    }
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

impl From<v7::mcast::MulticastGroupUpdateExternalEntry>
    for MulticastGroupUpdateExternalEntry
{
    fn from(entry: v7::mcast::MulticastGroupUpdateExternalEntry) -> Self {
        Self {
            internal_forwarding: entry.internal_forwarding,
            external_forwarding: entry.external_forwarding,
            sources: entry.sources,
        }
    }
}

/// Response structure for underlay/internal multicast group operations.
/// These groups handle admin-local IPv6 multicast with full replication.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUnderlayResponse {
    pub group_ip: UnderlayMulticastIpv6,
    pub external_group_id: MulticastGroupId,
    pub underlay_group_id: MulticastGroupId,
    /// Tag for validating update/delete requests. Always present and generated
    /// as `{uuid}:{group_ip}` if not provided at creation time.
    pub tag: String,
    pub members: Vec<MulticastGroupMember>,
}

impl From<MulticastGroupUnderlayResponse>
    for v1::mcast::MulticastGroupUnderlayResponse
{
    fn from(resp: MulticastGroupUnderlayResponse) -> Self {
        Self {
            group_ip: resp.group_ip.into(),
            external_group_id: resp.external_group_id,
            underlay_group_id: resp.underlay_group_id,
            tag: Some(resp.tag),
            members: resp.members,
        }
    }
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

impl From<MulticastGroupExternalResponse>
    for v7::mcast::MulticastGroupExternalResponse
{
    fn from(resp: MulticastGroupExternalResponse) -> Self {
        Self {
            group_ip: resp.group_ip,
            external_group_id: resp.external_group_id,
            tag: Some(resp.tag),
            internal_forwarding: resp.internal_forwarding,
            external_forwarding: resp.external_forwarding,
            sources: resp.sources,
        }
    }
}

/// Unified response type for operations that return mixed group types.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MulticastGroupResponse {
    Underlay(MulticastGroupUnderlayResponse),
    External(MulticastGroupExternalResponse),
}

impl From<MulticastGroupResponse> for v7::mcast::MulticastGroupResponse {
    fn from(resp: MulticastGroupResponse) -> Self {
        match resp {
            MulticastGroupResponse::Underlay(u) => Self::Underlay(u.into()),
            MulticastGroupResponse::External(e) => Self::External(e.into()),
        }
    }
}

/// Tag for identifying and authorizing multicast group operations.
///
/// Tag format: 1 to 80 ASCII bytes containing alphanumeric characters,
/// hyphens, underscores, colons, or periods. Default format is
/// `{uuid}:{group_ip}`.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct MulticastTag(
    #[schemars(
        length(min = 1, max = 80),
        regex(pattern = r"^[a-zA-Z0-9_.:-]+$")
    )]
    pub String,
);

/// Path parameter for multicast tag-based operations.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastTagPath {
    pub tag: MulticastTag,
}

impl From<v1::misc::TagPath> for MulticastTagPath {
    fn from(path: v1::misc::TagPath) -> Self {
        Self { tag: path.tag.into() }
    }
}

/// Tag for multicast group validation.
///
/// All groups have tags (auto-generated at creation if not provided).
/// The provided tag must match the group's existing tag.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupTagQuery {
    /// Tag that must match the group's existing tag.
    pub tag: MulticastTag,
}

/// Used to identify an underlay multicast group by IPv6 address within
/// the underlay multicast subnet (ff04::/64).
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastUnderlayGroupIpParam {
    pub group_ip: UnderlayMulticastIpv6,
}
