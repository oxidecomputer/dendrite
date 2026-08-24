// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv6Addr;

use oxnet::Ipv6Net;
use thiserror::Error;

pub use dpd_types::network::{
    InstanceTarget, MacAddr, MacError, NatTarget, Vni,
};

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

#[derive(Error, Debug, Clone)]
pub enum VlanError {
    /// Not a valid VLAN ID
    #[error("Invalid VLAN tag: {}", .0)]
    InvalidVlan(u16),
}

pub fn validate_vlan(id: impl Into<u16>) -> Result<(), VlanError> {
    let id: u16 = id.into();
    #[allow(clippy::manual_range_contains)]
    if id < 2 || id > 4095 { Err(VlanError::InvalidVlan(id)) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::Ipv6Addr;
    use super::MacAddr;
    use super::generate_ipv6_link_local;

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
