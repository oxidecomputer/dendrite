// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use omicron_common::address::UNDERLAY_MULTICAST_SUBNET;

use crate::latest::mcast::{
    Error, IpSrc, MulticastGroupResponse, MulticastTag, UnderlayMulticastIpv6,
};

/// Maximum length for multicast tags.
pub const MAX_TAG_LENGTH: usize = 80;

/// Error parsing a multicast tag from a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MulticastTagParseError(pub(crate) String);

impl UnderlayMulticastIpv6 {
    /// Create a new UnderlayMulticastIpv6 if the address is within the
    /// underlay multicast subnet (ff04::/64).
    pub fn new(addr: Ipv6Addr) -> Result<Self, Error> {
        if !UNDERLAY_MULTICAST_SUBNET.contains(addr) {
            return Err(Error::InvalidUnderlayMulticastIp(addr));
        }
        Ok(Self(addr))
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
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: Ipv6Addr = s
            .parse()
            .map_err(|e| Error::InvalidIpv6Address(s.to_string(), e))?;
        Self::new(addr)
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

impl From<String> for MulticastTag {
    fn from(tag: String) -> Self {
        MulticastTag(tag)
    }
}

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

impl fmt::Display for IpSrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSrc::Exact(ip) => write!(f, "{ip}"),
            IpSrc::Any => write!(f, "any"),
        }
    }
}
