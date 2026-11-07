// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt::Display;
use std::net::AddrParseError;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

use thiserror::Error;

/// Conversion helpers for [`std::net::IpAddr`] power users.
pub trait IpAddrLike: Sized + Copy + Into<IpAddr> {
    /// Constructs self from an IP address.
    ///
    /// This must not map IPv4 addresses to v6.
    fn from_ip(addr: IpAddr) -> Option<Self>;

    /// Constructs an IP address from self.
    fn to_ip(self) -> IpAddr;
}

impl IpAddrLike for Ipv4Addr {
    fn from_ip(addr: IpAddr) -> Option<Self> {
        match addr {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        }
    }

    fn to_ip(self) -> IpAddr {
        IpAddr::V4(self)
    }
}

impl IpAddrLike for Ipv6Addr {
    fn from_ip(addr: IpAddr) -> Option<Self> {
        match addr {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => Some(v6),
        }
    }

    fn to_ip(self) -> IpAddr {
        IpAddr::V6(self)
    }
}

impl IpAddrLike for IpAddr {
    fn from_ip(addr: IpAddr) -> Option<Self> {
        Some(addr)
    }

    fn to_ip(self) -> IpAddr {
        self
    }
}

impl IpAddrLike for RouterIfaceIpAddr {
    fn from_ip(addr: IpAddr) -> Option<Self> {
        RouterIfaceIpAddr::try_new(addr).ok()
    }

    fn to_ip(self) -> IpAddr {
        *self.get()
    }
}

/// The reasons a conversion involving [`RouterIfaceIpAddr`]
/// may fail.
#[derive(Debug, Error)]
pub enum RouterIfaceIpAddrErr {
    #[error("Forbidden address type 'LocalHost': {0}")]
    LocalHost(IpAddr),

    #[error("Forbidden address type 'Unspecified': {0}")]
    Unspecified(IpAddr),

    #[error("Forbidden address type 'Multicast': {0}")]
    Multicast(IpAddr),

    #[error("Forbidden address type 'Link Local': {0}")]
    LinkLocal(IpAddr),

    #[error("Forbidden address type 'Broadcast': {0}")]
    Broadcast(IpAddr),

    #[error("Forbidden address type 'IPv4 mapped IPv6': {0}")]
    Ipv4MappedV6(IpAddr),

    #[error("IP address could not be parsed: {0}")]
    Parse(#[from] AddrParseError),
}

/// An IP address that may be registered on a loopback
/// or link interface managed by DPD.
///
/// Maybe be any IP address not among the following:
/// - Localhost
/// - Unspecified
/// - Multicast
/// - IPv4 broadcast
/// - IPv6 link local
/// - IPv6 mapped IPv4
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouterIfaceIpAddr(IpAddr);

impl RouterIfaceIpAddr {
    /// Constructs a new checked address or fails if `addr` does
    /// not meet type criteria.
    ///
    /// This was duplicated from a module in [sled agent](https://github.com/oxidecomputer/omicron/blob/4b9fd125ed6c790ee2c86502c6b481b216c7fc4f/sled-agent/types/versions/src/stronger_bgp_unnumbered_types/early_networking.rs#L255)
    ///
    /// Ideally sled-agent can someday just inherit this type.
    pub fn try_new(addr: IpAddr) -> Result<Self, RouterIfaceIpAddrErr> {
        let v4 = Ipv4Addr::from_ip(addr);
        let v6 = Ipv6Addr::from_ip(addr);
        for (forbidden, err) in [
            (addr.is_loopback(), RouterIfaceIpAddrErr::LocalHost(addr)),
            (addr.is_unspecified(), RouterIfaceIpAddrErr::Unspecified(addr)),
            (addr.is_multicast(), RouterIfaceIpAddrErr::Multicast(addr)),
            (
                v4.is_some_and(|a| a.is_broadcast()),
                RouterIfaceIpAddrErr::Broadcast(addr),
            ),
            (
                v6.is_some_and(|a| a.is_unicast_link_local()),
                RouterIfaceIpAddrErr::LinkLocal(addr),
            ),
            (
                v6.is_some_and(|a| a.to_ipv4_mapped().is_some()),
                RouterIfaceIpAddrErr::Ipv4MappedV6(addr),
            ),
        ] {
            if forbidden {
                return Err(err);
            }
        }

        Ok(Self(addr))
    }

    /// Retrieves the inner IP address.
    pub fn get(&self) -> &IpAddr {
        &self.0
    }
}

impl Display for RouterIfaceIpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for RouterIfaceIpAddr {
    type Err = RouterIfaceIpAddrErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s.parse()?)
    }
}

impl From<RouterIfaceIpAddr> for IpAddr {
    fn from(value: RouterIfaceIpAddr) -> Self {
        value.0
    }
}

impl TryFrom<IpAddr> for RouterIfaceIpAddr {
    type Error = RouterIfaceIpAddrErr;

    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}
