// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `MCAST_SOURCE_FILTER_ANY` of the dpd API.
//!
//! This version changed the `IpSrc` enum from `{Exact, Subnet}` to `{Exact, Any}`.
//! External multicast types in this module use the new `IpSrc`.
//!
//! Underlay types were not changed in v5 and are re-exported from v1.

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use dpd_types::mcast::{
    ExternalForwarding, InternalForwarding, IpSrc, MulticastGroupId,
};

// Re-export underlay types from v1 (unchanged in v5)
pub use crate::v1::AdminScopedIpv6;
pub use crate::v1::MulticastGroupCreateUnderlayEntry;
pub use crate::v1::MulticastGroupUnderlayResponse;
pub use crate::v1::MulticastGroupUpdateUnderlayEntry;
pub use crate::v1::MulticastUnderlayGroupIpParam;

// External multicast types changed in v5 (use new IpSrc with Any variant)

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

/// Convert from latest response to v5 response.
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

/// A multicast group update entry for PUT requests for external groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    pub tag: Option<String>,
    pub internal_forwarding: InternalForwarding,
    pub external_forwarding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
}

impl From<MulticastGroupUpdateExternalEntry>
    for dpd_types::mcast::MulticastGroupUpdateExternalEntry
{
    fn from(entry: MulticastGroupUpdateExternalEntry) -> Self {
        Self {
            internal_forwarding: entry.internal_forwarding,
            external_forwarding: entry.external_forwarding,
            sources: entry.sources,
        }
    }
}

// Multicast unified response types

/// Unified response type for operations that return mixed group types.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MulticastGroupResponse {
    Underlay(crate::v1::MulticastGroupUnderlayResponse),
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

/// Convert from latest response to v5 response.
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
