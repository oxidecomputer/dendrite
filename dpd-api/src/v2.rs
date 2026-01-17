// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Types from API version 2 (DUAL_STACK_NAT_WORKFLOW) that changed in
//! version 3 (MCAST_SOURCE_FILTER_ANY).
//!
//! Changes in v3:
//! - The `IpSrc` enum changed from `{Exact, Subnet}` to `{Exact, Any}`.

use std::{fmt, net::IpAddr};

use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use dpd_types::mcast::{
    ExternalForwarding, InternalForwarding, MulticastGroupId,
};

// Use v3 underlay response which has Option<String> tag
pub use crate::v3::MulticastGroupUnderlayResponse;

/// Source filter match key for multicast traffic (API versions 1 and 2).
///
/// This is the original `IpSrc` enum that used a single `Subnet` variant
/// (IPv4 only) rather than the `Any` variant added in version 3.
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
            IpSrc::Exact(ip) => write!(f, "{ip}"),
            IpSrc::Subnet(net) => write!(f, "{net}"),
        }
    }
}

/// Convert from v3 IpSrc to v1/v2 IpSrc.
impl From<dpd_types::mcast::IpSrc> for IpSrc {
    fn from(src: dpd_types::mcast::IpSrc) -> Self {
        match src {
            dpd_types::mcast::IpSrc::Exact(ip) => IpSrc::Exact(ip),
            dpd_types::mcast::IpSrc::Any => {
                // v1/v2 API only supported IPv4 subnet matching.
                IpSrc::Subnet(
                    Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                )
            }
        }
    }
}

/// A multicast group configuration for POST requests for external (to the rack)
/// groups (API version 2).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateExternalEntry {
    pub group_ip: IpAddr,
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// A multicast group update entry for PUT requests for external (to the rack)
/// groups (API version 2).
///
/// Tag validation is optional in v2 for backward compatibility.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    /// Tag for validating update requests. Optional in v2. If not provided,
    /// tag validation is skipped.
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Response structure for external multicast group operations (API version 2).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupExternalResponse {
    pub group_ip: IpAddr,
    pub external_group_id: MulticastGroupId,
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Convert from v3 response to v2 response.
impl From<crate::v3::MulticastGroupExternalResponse>
    for MulticastGroupExternalResponse
{
    fn from(resp: crate::v3::MulticastGroupExternalResponse) -> Self {
        Self {
            group_ip: resp.group_ip,
            external_group_id: resp.external_group_id,
            tag: resp.tag,
            internal_forwarding: resp.internal_forwarding,
            external_forwarding: resp.external_forwarding,
            sources: resp
                .sources
                .map(|sources| sources.into_iter().map(IpSrc::from).collect()),
        }
    }
}

/// Convert from v4 response to v2 response (chains through v3).
impl From<dpd_types::mcast::MulticastGroupExternalResponse>
    for MulticastGroupExternalResponse
{
    fn from(resp: dpd_types::mcast::MulticastGroupExternalResponse) -> Self {
        crate::v3::MulticastGroupExternalResponse::from(resp).into()
    }
}

/// Unified response type for operations that return mixed group types
/// (API version 2).
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
}

/// Convert from v3 response to v2 response.
impl From<crate::v3::MulticastGroupResponse> for MulticastGroupResponse {
    fn from(resp: crate::v3::MulticastGroupResponse) -> Self {
        match resp {
            crate::v3::MulticastGroupResponse::Underlay(u) => Self::Underlay(u),
            crate::v3::MulticastGroupResponse::External(e) => {
                Self::External(e.into())
            }
        }
    }
}

/// Convert from v4 response to v2 response (chains through v3).
impl From<dpd_types::mcast::MulticastGroupResponse> for MulticastGroupResponse {
    fn from(resp: dpd_types::mcast::MulticastGroupResponse) -> Self {
        crate::v3::MulticastGroupResponse::from(resp).into()
    }
}

// ============================================================================
// v2 → v3 conversions (for request types)
// ============================================================================

impl From<IpSrc> for dpd_types::mcast::IpSrc {
    fn from(src: IpSrc) -> Self {
        match src {
            IpSrc::Exact(ip) => dpd_types::mcast::IpSrc::Exact(ip),
            IpSrc::Subnet(net) if net.width() == 0 => {
                dpd_types::mcast::IpSrc::Any
            }
            IpSrc::Subnet(net) => {
                dpd_types::mcast::IpSrc::Exact(IpAddr::V4(net.addr()))
            }
        }
    }
}

impl From<MulticastGroupCreateExternalEntry>
    for dpd_types::mcast::MulticastGroupCreateExternalEntry
{
    fn from(entry: MulticastGroupCreateExternalEntry) -> Self {
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

impl From<MulticastGroupUpdateExternalEntry>
    for dpd_types::mcast::MulticastGroupUpdateExternalEntry
{
    fn from(entry: MulticastGroupUpdateExternalEntry) -> Self {
        Self {
            internal_forwarding: entry.internal_forwarding,
            external_forwarding: entry.external_forwarding,
            sources: entry
                .sources
                .map(|s| s.into_iter().map(Into::into).collect()),
        }
    }
}
