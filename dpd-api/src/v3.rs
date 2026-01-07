// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Types from API version 3 that changed in version 4.
//!
//! The `tag` field in response types changed from `Option<String>` to `String`
//! since all groups now have default tags generated at creation time.

use std::net::IpAddr;

use dpd_types::mcast::{
    AdminScopedIpv6, ExternalForwarding, InternalForwarding, IpSrc,
    MulticastGroupId, MulticastGroupMember,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Response structure for underlay/internal multicast group operations
/// (API version 3).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUnderlayResponse {
    pub group_ip: AdminScopedIpv6,
    pub external_group_id: MulticastGroupId,
    pub underlay_group_id: MulticastGroupId,
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

/// Convert from v4 response to v3 response.
impl From<dpd_types::mcast::MulticastGroupUnderlayResponse>
    for MulticastGroupUnderlayResponse
{
    fn from(resp: dpd_types::mcast::MulticastGroupUnderlayResponse) -> Self {
        Self {
            group_ip: resp.group_ip,
            external_group_id: resp.external_group_id,
            underlay_group_id: resp.underlay_group_id,
            tag: Some(resp.tag),
            members: resp.members,
        }
    }
}

/// Response structure for external multicast group operations (API version 3).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupExternalResponse {
    pub group_ip: IpAddr,
    pub external_group_id: MulticastGroupId,
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

/// Convert from v4 response to v3 response.
impl From<dpd_types::mcast::MulticastGroupExternalResponse>
    for MulticastGroupExternalResponse
{
    fn from(resp: dpd_types::mcast::MulticastGroupExternalResponse) -> Self {
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

/// Unified response type for operations that return mixed group types
/// (API version 3).
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

/// Convert from v4 response to v3 response.
impl From<dpd_types::mcast::MulticastGroupResponse> for MulticastGroupResponse {
    fn from(resp: dpd_types::mcast::MulticastGroupResponse) -> Self {
        match resp {
            dpd_types::mcast::MulticastGroupResponse::Underlay(u) => {
                Self::Underlay(u.into())
            }
            dpd_types::mcast::MulticastGroupResponse::External(e) => {
                Self::External(e.into())
            }
        }
    }
}
