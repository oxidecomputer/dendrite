// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use rand::prelude::*;

// Given an IPv6 multicast address, generate the associated synthetic mac
// address
pub fn multicast_mac_addr(ip: Ipv6Addr) -> MacAddr {
    let o = ip.octets();
    MacAddr::new(0x33, 0x33, o[12], o[13], o[14], o[15])
}

/// Generate an IPv6 adddress within the provided `cidr`, using the EUI-64
/// transfrom of `mac`.
pub fn generate_ipv6_addr(cidr: Ipv6Net, mac: MacAddr) -> Ipv6Addr {
    let prefix: u128 = cidr.addr().into();
    let mac = u128::from(u64::from_be_bytes(mac.to_eui64()));
    let mask: u128 = cidr.mask_addr().into();
    let ipv6 = (prefix & mask) | (mac & !mask);
    ipv6.into()
}

/// Generate a link-local IPv6 address using the EUI-64 transform of `mac`.
pub fn generate_ipv6_link_local(mac: MacAddr) -> Ipv6Addr {
    const LINK_LOCAL_PREFIX: Ipv6Net =
        Ipv6Net::new_unchecked(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64);

    generate_ipv6_addr(LINK_LOCAL_PREFIX, mac)
}

/// An EUI-48 MAC address, used for layer-2 addressing.
#[derive(Copy, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
pub struct MacAddr {
    a: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    fn from(a: [u8; 6]) -> Self {
        Self { a }
    }
}

impl MacAddr {
    /// Oxide's Organizationally Unique Identifier.
    pub const OXIDE_OUI: [u8; 3] = [0xa8, 0x40, 0x25];
    pub const ZERO: Self = MacAddr {
        a: [0, 0, 0, 0, 0, 0],
    };

    /// Create a new MAC address from octets in network byte order.
    pub fn new(o0: u8, o1: u8, o2: u8, o3: u8, o4: u8, o5: u8) -> MacAddr {
        MacAddr {
            a: [o0, o1, o2, o3, o4, o5],
        }
    }

    /// Create a new MAC address from a slice of bytes in network byte order.
    ///
    /// # Panics
    ///
    /// Panics if the slice is fewer than 6 octets.
    ///
    /// Note that any further octets are ignored.
    pub fn from_slice(s: &[u8]) -> MacAddr {
        MacAddr::new(s[0], s[1], s[2], s[3], s[4], s[5])
    }

    /// Convert `self` to an array of bytes in network byte order.
    pub fn to_vec(self) -> Vec<u8> {
        vec![
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5],
        ]
    }

    /// Return `true` if `self` is the null MAC address, all zeros.
    pub fn is_null(self) -> bool {
        const EMPTY: MacAddr = MacAddr {
            a: [0, 0, 0, 0, 0, 0],
        };

        self == EMPTY
    }

    /// Generate a random MAC address.
    pub fn random() -> MacAddr {
        let mut rng = rand::thread_rng();
        let mut m = MacAddr { a: [0; 6] };
        for octet in m.a.iter_mut() {
            *octet = rng.gen();
        }
        m
    }

    /// Generate a random MAC address with the Oxide OUI.
    pub fn random_oxide() -> MacAddr {
        let mut rng = rand::thread_rng();
        let mut octets = [0; 6];
        octets[..3].copy_from_slice(&Self::OXIDE_OUI);
        rng.fill(&mut octets[3..]);

        // Ensure that this MAC is appropriate for a _physical_ device. See RFD
        // 174 section 3.2.
        octets[3] &= 0b0111_1111;

        MacAddr { a: octets }
    }

    /// Generate an EUI-64 ID from the mac address, following the process
    /// desribed in RFC 2464, section 4.
    pub fn to_eui64(self) -> [u8; 8] {
        [
            self.a[0] ^ 0x2,
            self.a[1],
            self.a[2],
            0xff,
            0xfe,
            self.a[3],
            self.a[4],
            self.a[5],
        ]
    }
}

#[derive(Error, Debug, Clone)]
pub enum MacError {
    /// Too few octets to be a valid MAC address
    #[error("Too few octets")]
    TooShort,
    /// Too many octets to be a valid MAC address
    #[error("Too many octets")]
    TooLong,
    /// Found an octet with a non-hexadecimal character or invalid separator
    #[error("Invalid octect")]
    InvalidOctet,
}

impl FromStr for MacAddr {
    type Err = MacError;

    fn from_str(s: &str) -> Result<Self, MacError> {
        let v: Vec<&str> = s.split(':').collect();

        match v.len().cmp(&6) {
            std::cmp::Ordering::Less => Err(MacError::TooShort),
            std::cmp::Ordering::Greater => Err(MacError::TooLong),
            std::cmp::Ordering::Equal => {
                let mut m = MacAddr { a: [0u8; 6] };
                for (i, octet) in v.iter().enumerate() {
                    m.a[i] = u8::from_str_radix(octet, 16)
                        .map_err(|_| MacError::InvalidOctet)?;
                }
                Ok(m)
            }
        }
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5]
        )
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> [u8; 6] {
        mac.a
    }
}

impl From<MacAddr> for u64 {
    fn from(mac: MacAddr) -> u64 {
        ((mac.a[0] as u64) << 40)
            | ((mac.a[1] as u64) << 32)
            | ((mac.a[2] as u64) << 24)
            | ((mac.a[3] as u64) << 16)
            | ((mac.a[4] as u64) << 8)
            | (mac.a[5] as u64)
    }
}

impl From<&MacAddr> for u64 {
    fn from(mac: &MacAddr) -> u64 {
        From::from(*mac)
    }
}

impl From<u64> for MacAddr {
    fn from(x: u64) -> Self {
        MacAddr {
            a: [
                ((x >> 40) & 0xff) as u8,
                ((x >> 32) & 0xff) as u8,
                ((x >> 24) & 0xff) as u8,
                ((x >> 16) & 0xff) as u8,
                ((x >> 8) & 0xff) as u8,
                (x & 0xff) as u8,
            ],
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum VlanError {
    /// Not a valid VLAN ID
    #[error("Invalid VLAN tag: {}", .0)]
    InvalidVlan(u16),
}

pub fn validate_vlan(id: impl Into<u16>) -> Result<(), VlanError> {
    let id: u16 = id.into();
    #[allow(clippy::manual_range_contains)]
    if id < 2 || id > 4095 {
        Err(VlanError::InvalidVlan(id))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::generate_ipv6_link_local;
    use super::Ipv6Addr;
    use super::MacAddr;

    #[test]
    fn test_into() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let u: u64 = (&a).into();
        assert_eq!(u, 0x123456789abc);
    }

    #[test]
    fn test_equal() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        assert_eq!(a, b);
    }

    #[test]
    fn test_not_equal() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbb);
        assert_ne!(a, b);
    }

    #[test]
    fn test_parse() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = "12:34:56:78:9a:bc".parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_to_string() {
        let a = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let b = format!("{a}");
        assert_eq!(b, "12:34:56:78:9a:bc");
    }
    #[test]
    fn test_eui64() {
        let expected = [0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE];
        let a = MacAddr::new(0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE);
        let eui = a.to_eui64();
        assert_eq!(eui, expected);
    }

    #[test]
    fn test_generate_ipv6_link_local() {
        let mac = MacAddr::new(0x12, 0x34, 0x56, 0x78, 0xab, 0xcd);
        let addr = generate_ipv6_link_local(mac);
        assert_eq!(
            addr,
            "fe80::1034:56ff:fe78:abcd".parse::<Ipv6Addr>().unwrap()
        );
    }
}
