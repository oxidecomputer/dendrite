// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;

use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::mcast::{
    ExternalForwarding, InternalForwarding, MulticastGroupId,
    MulticastGroupUnderlayResponse,
};

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
pub enum IpSrc {
    /// Exact match for the source IP address.
    Exact(IpAddr),
    /// Match any source address (0.0.0.0/0 or ::/0 depending on group IP version).
    Any,
}

impl From<v1::mcast::IpSrc> for IpSrc {
    fn from(src: v1::mcast::IpSrc) -> Self {
        match src {
            v1::mcast::IpSrc::Exact(ip) => IpSrc::Exact(ip),
            v1::mcast::IpSrc::Subnet(net) if net.width() == 0 => IpSrc::Any,
            v1::mcast::IpSrc::Subnet(net) => {
                IpSrc::Exact(IpAddr::V4(net.addr()))
            }
        }
    }
}

impl From<IpSrc> for v1::mcast::IpSrc {
    fn from(src: IpSrc) -> Self {
        match src {
            IpSrc::Exact(ip) => v1::mcast::IpSrc::Exact(ip),
            IpSrc::Any => {
                // v1-v4 API only supported IPv4 subnet matching.
                v1::mcast::IpSrc::Subnet(
                    Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                )
            }
        }
    }
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

impl From<v1::mcast::MulticastGroupCreateExternalEntry>
    for MulticastGroupCreateExternalEntry
{
    fn from(entry: v1::mcast::MulticastGroupCreateExternalEntry) -> Self {
        Self {
            group_ip: entry.group_ip,
            tag: entry.tag,
            internal_forwarding: entry.internal_forwarding,
            external_forwarding: entry.external_forwarding,
            sources: entry
                .sources
                .map(|s| s.into_iter().map(Into::into).collect()),
        }
    }
}

/// Response structure for external multicast group operations.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupExternalResponse {
    pub group_ip: IpAddr,
    pub external_group_id: MulticastGroupId,
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

impl From<MulticastGroupExternalResponse>
    for v1::mcast::MulticastGroupExternalResponse
{
    fn from(resp: MulticastGroupExternalResponse) -> Self {
        Self {
            group_ip: resp.group_ip,
            external_group_id: resp.external_group_id,
            tag: resp.tag,
            internal_forwarding: resp.internal_forwarding,
            external_forwarding: resp.external_forwarding,
            sources: resp
                .sources
                .map(|sources| sources.into_iter().map(Into::into).collect()),
        }
    }
}

/// A multicast group update entry for PUT requests for external groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

impl From<v1::mcast::MulticastGroupUpdateExternalEntry>
    for MulticastGroupUpdateExternalEntry
{
    fn from(entry: v1::mcast::MulticastGroupUpdateExternalEntry) -> Self {
        Self {
            tag: entry.tag,
            internal_forwarding: entry.internal_forwarding,
            external_forwarding: entry.external_forwarding,
            sources: entry
                .sources
                .map(|s| s.into_iter().map(Into::into).collect()),
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

impl From<MulticastGroupResponse> for v1::mcast::MulticastGroupResponse {
    fn from(resp: MulticastGroupResponse) -> Self {
        match resp {
            MulticastGroupResponse::Underlay(u) => {
                // v7 underlay is re-exported from v1, so it's the same type.
                Self::Underlay(u)
            }
            MulticastGroupResponse::External(e) => Self::External(e.into()),
        }
    }
}
