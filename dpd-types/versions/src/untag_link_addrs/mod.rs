pub mod port;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// An address that may be registered on a link.
//
// This type is only restrictive where DPD has an actual
// reason for enforcement. Here are motivating constraints:
// - DPD manages the IPv6 link local address of a link separately
//   from those configured by sled-agent, so it's an error to
//   use an IPv6 link local address when managing those settings.
// - That is all :)
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    JsonSchema,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
)]
pub enum LinkIpAddr {
    V4(Ipv4Addr),
    V6(LinkIpv6Addr),
}

impl LinkIpAddr {
    /// Constructs a new address or returns error if `addr` is
    /// of a forbidden address category.
    pub const fn try_new(ip: IpAddr) -> Result<Self, LinkAddrError> {
        // weird impl because I think const is worth it
        let v6 = match ip {
            IpAddr::V4(v4) => return Ok(Self::V4(v4)),
            IpAddr::V6(v6) => v6,
        };

        match LinkIpv6Addr::try_new(v6) {
            Ok(v6) => Ok(Self::V6(v6)),
            Err(e) => Err(e),
        }
    }

    pub const fn get(self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4),
            Self::V6(v6) => IpAddr::V6(*v6.get()),
        }
    }
}

impl TryFrom<IpAddr> for LinkIpAddr {
    type Error = LinkAddrError;

    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<LinkIpAddr> for IpAddr {
    fn from(value: LinkIpAddr) -> Self {
        value.get()
    }
}

/// An IPv6 address that may be registered on a link.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    JsonSchema,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
)]
#[repr(transparent)]
pub struct LinkIpv6Addr(Ipv6Addr);

#[derive(Debug, Error)]
pub enum LinkAddrError {
    #[error(
        "Unicast link local IPv6 address registrations are managed separately from this API"
    )]
    UnicastLinkLocalIpv6(Ipv6Addr),
}

impl LinkIpv6Addr {
    /// Constructs a new address or returns error if `addr` is
    /// of a forbidden address category.
    pub const fn try_new(addr: Ipv6Addr) -> Result<Self, LinkAddrError> {
        if addr.is_unicast_link_local() {
            return Err(LinkAddrError::UnicastLinkLocalIpv6(addr));
        }

        Ok(Self(addr))
    }

    pub const fn get(&self) -> &Ipv6Addr {
        &self.0
    }
}

impl TryFrom<Ipv6Addr> for LinkIpv6Addr {
    type Error = LinkAddrError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<LinkIpv6Addr> for Ipv6Addr {
    fn from(value: LinkIpv6Addr) -> Self {
        *value.get()
    }
}
