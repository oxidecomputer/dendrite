// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Public types for multicast group management introduced in the
//! `MCAST_STRICT_UNDERLAY` version.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::impls::mcast::IPV6_ADMIN_SCOPED_MULTICAST_PREFIX;
use crate::v1;
use crate::v1::mcast::{
    ExternalForwarding, InternalForwarding, MulticastGroupId,
    MulticastGroupMember,
};
use crate::v7;
use crate::v7::mcast::IpSrc;

/// Underlay multicast subnet (`ff04::/64`).
///
/// See [`UnderlayMulticastIpv6`] for its role.
pub const UNDERLAY_MULTICAST_SUBNET: Ipv6Net = Ipv6Net::new_unchecked(
    Ipv6Addr::new(IPV6_ADMIN_SCOPED_MULTICAST_PREFIX, 0, 0, 0, 0, 0, 0, 0),
    64,
);

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
pub struct UnderlayMulticastIpv6(Ipv6Addr);

impl UnderlayMulticastIpv6 {
    /// Create a new `UnderlayMulticastIpv6` if the address is within the
    /// underlay multicast subnet (`ff04::/64`).
    ///
    /// # Errors
    ///
    /// Returns [`UnderlayMulticastError::InvalidUnderlayMulticastIp`] if
    /// `addr` is outside [`UNDERLAY_MULTICAST_SUBNET`].
    pub fn new(addr: Ipv6Addr) -> Result<Self, UnderlayMulticastError> {
        if !UNDERLAY_MULTICAST_SUBNET.contains(addr) {
            return Err(UnderlayMulticastError::InvalidUnderlayMulticastIp(
                addr,
            ));
        }
        Ok(Self(addr))
    }

    /// Return the inner IPv6 address.
    #[inline]
    pub const fn ip(&self) -> Ipv6Addr {
        self.0
    }
}

impl TryFrom<Ipv6Addr> for UnderlayMulticastIpv6 {
    type Error = UnderlayMulticastError;

    fn try_from(addr: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::new(addr)
    }
}

impl From<UnderlayMulticastIpv6> for Ipv6Addr {
    fn from(addr: UnderlayMulticastIpv6) -> Self {
        addr.0
    }
}

impl From<UnderlayMulticastIpv6> for IpAddr {
    fn from(addr: UnderlayMulticastIpv6) -> Self {
        IpAddr::V6(addr.0)
    }
}

impl fmt::Display for UnderlayMulticastIpv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for UnderlayMulticastIpv6 {
    type Err = UnderlayMulticastParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: Ipv6Addr = s.parse().map_err(|e| {
            UnderlayMulticastParseError::InvalidIpv6(s.to_string(), e)
        })?;
        Ok(Self::new(addr)?)
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

/// Errors raised while validating an underlay multicast address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UnderlayMulticastError {
    /// The address is outside the underlay multicast subnet (`ff04::/64`).
    #[error(
        "Address {0} is not in underlay multicast subnet (must be ff04::/64)"
    )]
    InvalidUnderlayMulticastIp(Ipv6Addr),
}

/// Error returned when parsing an [`UnderlayMulticastIpv6`] from a string.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UnderlayMulticastParseError {
    /// The string could not be parsed as an IPv6 address.
    #[error("Invalid IPv6 address '{0}': {1}")]
    InvalidIpv6(String, std::net::AddrParseError),
    /// The parsed address was outside the underlay multicast subnet.
    #[error(transparent)]
    Value(#[from] UnderlayMulticastError),
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

/// Maximum length for multicast tags.
pub const MAX_TAG_LENGTH: usize = 80;

/// Tag for identifying and authorizing multicast group operations.
///
/// Tag format: 1 to 80 ASCII bytes containing alphanumeric characters,
/// hyphens, underscores, colons, or periods. Default format is
/// `{uuid}:{group_ip}`.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct MulticastTag(
    #[schemars(
        length(min = 1, max = 80),
        regex(pattern = r"^[a-zA-Z0-9_.:-]+$")
    )]
    String,
);

/// Error parsing a multicast tag from a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MulticastTagParseError(pub(crate) String);

impl fmt::Display for MulticastTagParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for MulticastTagParseError {}

impl FromStr for MulticastTag {
    type Err = MulticastTagParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(MulticastTagParseError(
                "tag cannot be empty".to_string(),
            ));
        }
        if s.len() > MAX_TAG_LENGTH {
            return Err(MulticastTagParseError(format!(
                "tag cannot exceed {MAX_TAG_LENGTH} bytes"
            )));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.')
        }) {
            return Err(MulticastTagParseError(
                "tag must contain only ASCII alphanumeric characters, hyphens, \
                 underscores, colons, or periods"
                    .to_string(),
            ));
        }
        Ok(MulticastTag(s.to_string()))
    }
}

impl AsRef<str> for MulticastTag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<MulticastTag> for String {
    fn from(tag: MulticastTag) -> Self {
        tag.0
    }
}

impl TryFrom<String> for MulticastTag {
    type Error = MulticastTagParseError;

    fn try_from(tag: String) -> Result<Self, Self::Error> {
        tag.parse()
    }
}

/// Path parameter for multicast tag-based operations.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastTagPath {
    pub tag: MulticastTag,
}

impl From<v1::misc::TagPath> for MulticastTagPath {
    fn from(path: v1::misc::TagPath) -> Self {
        // Versions before `MCAST_STRICT_UNDERLAY` accept any tag string, and a
        // malformed one matches against no group.
        Self { tag: MulticastTag(path.tag) }
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
