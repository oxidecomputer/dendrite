// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::link::LinkId;
use crate::v1::mcast::{
    ExternalForwarding, InternalForwarding, MulticastGroupId,
};
use crate::v1::port::PortId;
use crate::v7;
use crate::v8;
use crate::v8::mcast::UnderlayMulticastIpv6;

/// Represents a member of a multicast group.
#[derive(
    Clone,
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
    Copy,
    Clone,
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
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Underlay,
    External,
}

/// Source filter match key for multicast traffic.
///
/// For SSM groups, use `Exact` with specific source addresses.
/// For ASM groups with any-source filtering, use `Any`.
#[derive(
    Clone,
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
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum IpSrc {
    /// Exact match for the source IP address.
    Exact(IpAddr),
    /// Match any source address (0.0.0.0/0 or ::/0 depending on group IP version).
    Any,
}

/// A multicast group configuration for POST requests for external (to the
/// rack) groups.
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
    pub group_ip: UnderlayMulticastIpv6,
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

impl From<v1::mcast::MulticastGroupMember> for MulticastGroupMember {
    fn from(old: v1::mcast::MulticastGroupMember) -> Self {
        Self {
            port_id: old.port_id,
            link_id: old.link_id,
            direction: old.direction.into(),
        }
    }
}

impl From<MulticastGroupMember> for v1::mcast::MulticastGroupMember {
    fn from(new: MulticastGroupMember) -> Self {
        Self {
            port_id: new.port_id,
            link_id: new.link_id,
            direction: new.direction.into(),
        }
    }
}

impl From<v1::mcast::Direction> for Direction {
    fn from(old: v1::mcast::Direction) -> Self {
        match old {
            v1::mcast::Direction::Underlay => Self::Underlay,
            v1::mcast::Direction::External => Self::External,
        }
    }
}

impl From<Direction> for v1::mcast::Direction {
    fn from(new: Direction) -> Self {
        match new {
            Direction::Underlay => Self::Underlay,
            Direction::External => Self::External,
        }
    }
}

impl From<v7::mcast::IpSrc> for IpSrc {
    fn from(old: v7::mcast::IpSrc) -> Self {
        match old {
            v7::mcast::IpSrc::Exact(ip) => Self::Exact(ip),
            v7::mcast::IpSrc::Any => Self::Any,
        }
    }
}

impl From<IpSrc> for v7::mcast::IpSrc {
    fn from(new: IpSrc) -> Self {
        match new {
            IpSrc::Exact(ip) => Self::Exact(ip),
            IpSrc::Any => Self::Any,
        }
    }
}

impl From<v7::mcast::MulticastGroupCreateExternalEntry>
    for MulticastGroupCreateExternalEntry
{
    fn from(old: v7::mcast::MulticastGroupCreateExternalEntry) -> Self {
        Self {
            group_ip: old.group_ip,
            tag: old.tag,
            internal_forwarding: old.internal_forwarding,
            external_forwarding: old.external_forwarding,
            sources: old
                .sources
                .map(|sources| sources.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<v8::mcast::MulticastGroupCreateUnderlayEntry>
    for MulticastGroupCreateUnderlayEntry
{
    fn from(old: v8::mcast::MulticastGroupCreateUnderlayEntry) -> Self {
        Self {
            group_ip: old.group_ip,
            tag: old.tag,
            members: old.members.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<v8::mcast::MulticastGroupUpdateUnderlayEntry>
    for MulticastGroupUpdateUnderlayEntry
{
    fn from(old: v8::mcast::MulticastGroupUpdateUnderlayEntry) -> Self {
        Self { members: old.members.into_iter().map(Into::into).collect() }
    }
}

impl From<v8::mcast::MulticastGroupUpdateExternalEntry>
    for MulticastGroupUpdateExternalEntry
{
    fn from(old: v8::mcast::MulticastGroupUpdateExternalEntry) -> Self {
        Self {
            internal_forwarding: old.internal_forwarding,
            external_forwarding: old.external_forwarding,
            sources: old
                .sources
                .map(|sources| sources.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<MulticastGroupUnderlayResponse>
    for v8::mcast::MulticastGroupUnderlayResponse
{
    fn from(new: MulticastGroupUnderlayResponse) -> Self {
        Self {
            group_ip: new.group_ip,
            external_group_id: new.external_group_id,
            underlay_group_id: new.underlay_group_id,
            tag: new.tag,
            members: new.members.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MulticastGroupExternalResponse>
    for v8::mcast::MulticastGroupExternalResponse
{
    fn from(new: MulticastGroupExternalResponse) -> Self {
        Self {
            group_ip: new.group_ip,
            external_group_id: new.external_group_id,
            tag: new.tag,
            internal_forwarding: new.internal_forwarding,
            external_forwarding: new.external_forwarding,
            sources: new
                .sources
                .map(|sources| sources.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<MulticastGroupResponse> for v8::mcast::MulticastGroupResponse {
    fn from(new: MulticastGroupResponse) -> Self {
        match new {
            MulticastGroupResponse::Underlay(u) => Self::Underlay(u.into()),
            MulticastGroupResponse::External(e) => Self::External(e.into()),
        }
    }
}
