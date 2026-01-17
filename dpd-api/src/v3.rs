// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Types from API version 3 (MCAST_SOURCE_FILTER_ANY) that changed in
//! version 4 (MCAST_STRICT_UNDERLAY).
//!
//! Changes in v4:
//! - The `tag` field in response types changed from `Option<String>` to `String`
//!   since all groups now have default tags generated at creation time.
//! - Tag validation is now required for updates and deletes.
//! - `AdminScopedIpv6` was renamed to `UnderlayMulticastIpv6` and validation
//!   was tightened from ff04::/16 to ff04::/64.

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use dpd_types::mcast::{
    ExternalForwarding, InternalForwarding, IpSrc, MulticastGroupId,
    MulticastGroupMember, UnderlayMulticastIpv6,
};

/// A validated admin-local IPv6 multicast address (API version 3).
///
/// In v3, admin-local addresses are validated against ff04::/16 (scope 4).
/// In v4+, this was renamed to `UnderlayMulticastIpv6` and tightened to
/// ff04::/64 to match Omicron's underlay multicast subnet allocation.
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

impl From<UnderlayMulticastIpv6> for AdminScopedIpv6 {
    fn from(underlay: UnderlayMulticastIpv6) -> Self {
        // UnderlayMulticastIpv6 is a subset of AdminScopedIpv6, so this is safe
        Self(underlay.into())
    }
}

impl TryFrom<AdminScopedIpv6> for UnderlayMulticastIpv6 {
    type Error = String;

    fn try_from(admin: AdminScopedIpv6) -> Result<Self, Self::Error> {
        UnderlayMulticastIpv6::new(admin.0).map_err(|e| e.to_string())
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

/// Convert from API v4 response to v3 response.
impl From<dpd_types::mcast::MulticastGroupUnderlayResponse>
    for MulticastGroupUnderlayResponse
{
    fn from(resp: dpd_types::mcast::MulticastGroupUnderlayResponse) -> Self {
        Self {
            group_ip: resp.group_ip.into(),
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

/// Convert from API v4 response to v3 response.
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

/// Convert from API v4 response to v3 response.
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

/// A multicast group update entry for PUT requests for internal groups
/// (API version 3).
///
/// Tags are optional in v3 for backward compatibility. If not provided,
/// the existing tag is preserved.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateUnderlayEntry {
    /// Tag for validating update requests. Optional in v3. If not provided,
    /// tag validation is skipped.
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

impl From<MulticastGroupUpdateUnderlayEntry>
    for dpd_types::mcast::MulticastGroupUpdateUnderlayEntry
{
    fn from(entry: MulticastGroupUpdateUnderlayEntry) -> Self {
        Self {
            members: entry.members,
        }
    }
}

/// A multicast group update entry for PUT requests for external groups
/// (API version 3).
///
/// Tag validation is optional in v3 for backward compatibility.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    /// Tag for validating update requests. Optional in v3. If not provided,
    /// tag validation is skipped.
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

/// Path parameter for underlay multicast group endpoints (API version 3).
///
/// Uses `AdminScopedIpv6` which accepts the broader ff04::/16 range.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastUnderlayGroupIpParam {
    pub group_ip: AdminScopedIpv6,
}

/// Request body for creating underlay multicast groups (API version 3).
///
/// Uses `AdminScopedIpv6` which accepts the broader ff04::/16 range. In v4+,
/// this was tightened to `UnderlayMulticastIpv6` (ff04::/64).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupCreateUnderlayEntry {
    pub group_ip: AdminScopedIpv6,
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}
