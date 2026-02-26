// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Types from API version 1 (INITIAL) that changed in later versions.
//!
//! - `IpSrc` was changed in v7 (MCAST_SOURCE_FILTER_ANY): `Subnet` -> `Any`
//! - `AdminScopedIpv6` was changed in v8 (MCAST_STRICT_UNDERLAY): ff04::/16 -> ff04::/64
//! - Response `tag` fields were changed in v8: `Option<String>` -> `String`

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use dpd_types::mcast::{
    ExternalForwarding, InternalForwarding, MulticastGroupId,
    MulticastGroupMember, UnderlayMulticastIpv6,
};
use dpd_types::route::Ipv4Route;
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Represents all mappings of an IPv4 subnet to its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// All RouteTargets associated with this CIDR.
    pub targets: Vec<Ipv4Route>,
}

// Multicast types introduced in v1

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
            IpSrc::Exact(ip) => write!(f, "{ip}"),
            IpSrc::Subnet(net) => write!(f, "{net}"),
        }
    }
}

/// Convert from latest IpSrc to v1 IpSrc.
impl From<dpd_types::mcast::IpSrc> for IpSrc {
    fn from(src: dpd_types::mcast::IpSrc) -> Self {
        match src {
            dpd_types::mcast::IpSrc::Exact(ip) => IpSrc::Exact(ip),
            dpd_types::mcast::IpSrc::Any => {
                // v1-v4 API only supported IPv4 subnet matching.
                IpSrc::Subnet(
                    Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                )
            }
        }
    }
}

/// Convert from v1 IpSrc to latest IpSrc.
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

// External multicast types (v1-v6, before IpSrc changed in v7)

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

/// A multicast group update entry for PUT requests for external (to the rack)
/// groups.
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
            sources: entry
                .sources
                .map(|s| s.into_iter().map(Into::into).collect()),
        }
    }
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

/// Convert from v7 response to v1 response.
impl From<crate::v7::MulticastGroupExternalResponse>
    for MulticastGroupExternalResponse
{
    fn from(resp: crate::v7::MulticastGroupExternalResponse) -> Self {
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

/// Convert from latest response to v1 response (chains through v7).
impl From<dpd_types::mcast::MulticastGroupExternalResponse>
    for MulticastGroupExternalResponse
{
    fn from(resp: dpd_types::mcast::MulticastGroupExternalResponse) -> Self {
        crate::v7::MulticastGroupExternalResponse::from(resp).into()
    }
}

// Underlay multicast types (v1-v7, before AdminScopedIpv6 changed in v8)

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

impl From<MulticastGroupUpdateUnderlayEntry>
    for dpd_types::mcast::MulticastGroupUpdateUnderlayEntry
{
    fn from(entry: MulticastGroupUpdateUnderlayEntry) -> Self {
        Self { members: entry.members }
    }
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

/// Convert from latest response to v1 response.
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

// Multicast unified response types

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
}

/// Convert from v7 response to v1 response.
impl From<crate::v7::MulticastGroupResponse> for MulticastGroupResponse {
    fn from(resp: crate::v7::MulticastGroupResponse) -> Self {
        match resp {
            crate::v7::MulticastGroupResponse::Underlay(u) => {
                // v7 underlay is re-exported from v1, so it's the same type
                Self::Underlay(u)
            }
            crate::v7::MulticastGroupResponse::External(e) => {
                Self::External(e.into())
            }
        }
    }
}

/// Convert from latest response to v1 response (chains through v7).
impl From<dpd_types::mcast::MulticastGroupResponse> for MulticastGroupResponse {
    fn from(resp: dpd_types::mcast::MulticastGroupResponse) -> Self {
        crate::v7::MulticastGroupResponse::from(resp).into()
    }
}
