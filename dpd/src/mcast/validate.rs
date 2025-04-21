// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::nat::NatTarget;

use super::IpSrc;
use crate::types::{DpdError, DpdResult};

/// Validates if a multicast address is allowed for group creation.
///
/// Returns a [`DpdResult`] indicating whether the address is valid or not.
pub(crate) fn validate_multicast_address(
    addr: IpAddr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    match addr {
        IpAddr::V4(ipv4) => validate_ipv4_multicast(ipv4, sources),
        IpAddr::V6(ipv6) => validate_ipv6_multicast(ipv6, sources),
    }
}

/// Validates the NAT target inner MAC address.
pub(crate) fn validate_nat_target(nat_target: NatTarget) -> DpdResult<()> {
    if !nat_target.inner_mac.is_multicast() {
        return Err(DpdError::Invalid(format!(
            "NAT target inner MAC address {} is not a multicast MAC address",
            nat_target.inner_mac
        )));
    }
    Ok(())
}

/// Check if an IP address is a Source-Specific Multicast (SSM) address.
pub(crate) fn is_ssm(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => in_subnet_v4(ipv4, Ipv4Addr::new(232, 0, 0, 0), 8),
        // Check for Source-Specific Multicast (ff3x::/32)
        // In IPv6 multicast, the second nibble (flag field) indicates SSM when set to 3
        IpAddr::V6(ipv6) => {
            let flag_field = (ipv6.octets()[1] & 0xF0) >> 4;
            flag_field == 3
        }
    }
}

/// Check if an IPv4 address is in a specific subnet.
fn in_subnet_v4(
    addr: Ipv4Addr,
    subnet_prefix: Ipv4Addr,
    prefix_len: u8,
) -> bool {
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    let subnet_bits = u32::from_be_bytes(subnet_prefix.octets()) & mask;
    let addr_bits = u32::from_be_bytes(addr.octets()) & mask;
    subnet_bits == addr_bits
}

/// Check if an IPv6 address is in a specific subnet.
fn in_subnet_v6(
    addr: Ipv6Addr,
    subnet_prefix: Ipv6Addr,
    prefix_len: u8,
) -> bool {
    let addr_segments = addr.segments();
    let subnet_segments = subnet_prefix.segments();

    // Calculate how many complete 16-bit segments are covered by the prefix
    let complete_segments = prefix_len / 16;

    // Check all complete segments match
    for i in 0..complete_segments as usize {
        if addr_segments[i] != subnet_segments[i] {
            return false;
        }
    }

    // If there's a partial segment, check the bits that are covered by the prefix
    if prefix_len % 16 != 0 {
        let segment_idx = complete_segments as usize;
        let remaining_bits = prefix_len % 16;
        let mask = !((1u16 << (16 - remaining_bits)) - 1);

        if (addr_segments[segment_idx] & mask)
            != (subnet_segments[segment_idx] & mask)
        {
            return false;
        }
    }

    true
}

/// Validates IPv4 multicast addresses.
fn validate_ipv4_multicast(
    addr: Ipv4Addr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    // Verify this is actually a multicast address
    if !addr.is_multicast() {
        return Err(DpdError::Invalid(format!(
            "{} is not a multicast address",
            addr
        )));
    }

    // If this is SSM, require sources to be defined
    if is_ssm(addr.into()) {
        if sources.is_none() || sources.unwrap().is_empty() {
            return Err(DpdError::Invalid(format!(
                "{} is a Source-Specific Multicast address and requires at least one source to be defined",
                addr
            )));
        }
        // If we have sources defined for an SSM address, it's valid
        return Ok(());
    } else if sources.is_some() {
        // If this is not SSM but sources are defined, it's invalid
        return Err(DpdError::Invalid(format!(
            "{} is not a Source-Specific Multicast address but sources were provided",
            addr
        )));
    }

    // Define reserved IPv4 multicast subnets
    let reserved_subnets = [
        // Local network control block (link-local)
        (Ipv4Addr::new(224, 0, 0, 0), 24), // 224.0.0.0/24
        // GLOP addressing
        (Ipv4Addr::new(233, 0, 0, 0), 8), // 233.0.0.0/8
        // Administrative scoped addresses
        (Ipv4Addr::new(239, 0, 0, 0), 8), // 239.0.0.0/8 (administratively scoped)
    ];

    // Check reserved subnets
    for (subnet, prefix_len) in &reserved_subnets {
        if in_subnet_v4(addr, *subnet, *prefix_len) {
            return Err(DpdError::Invalid(format!(
                "{} is in the reserved multicast subnet {}/{}",
                addr, subnet, prefix_len
            )));
        }
    }

    // Check specific reserved addresses that may not fall within entire subnets
    let specific_reserved = [
        Ipv4Addr::new(224, 0, 1, 1), // NTP (Network Time Protocol)
        Ipv4Addr::new(224, 0, 1, 129), // Cisco Auto-RP-Announce
        Ipv4Addr::new(224, 0, 1, 130), // Cisco Auto-RP-Discovery
    ];

    if specific_reserved.contains(&addr) {
        return Err(DpdError::Invalid(format!(
            "{} is a specifically reserved multicast address",
            addr
        )));
    }

    Ok(())
}

/// Validates IPv6 multicast addresses.
fn validate_ipv6_multicast(
    addr: Ipv6Addr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    if !addr.is_multicast() {
        return Err(DpdError::Invalid(format!(
            "{} is not a multicast address",
            addr
        )));
    }

    // If this is SSM, require sources to be defined
    if is_ssm(addr.into()) {
        if sources.is_none() || sources.unwrap().is_empty() {
            return Err(DpdError::Invalid(format!(
                "{} is an IPv6 Source-Specific Multicast address (ff3x::/32) and requires at least one source to be defined",
                addr
            )));
        }
        // If we have sources defined for an IPv6 SSM address, it's valid
        return Ok(());
    } else if sources.is_some() {
        // If this is not SSM but sources are defined, it's invalid
        return Err(DpdError::Invalid(format!(
            "{} is not a Source-Specific Multicast address but sources were provided",
            addr
        )));
    }

    // Define reserved IPv6 multicast subnets
    let reserved_subnets = [
        // Link-local scope
        (Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0), 16), // ff02::/16
        // Interface-local scope
        (Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 0), 16), // ff01::/16
        // Node-local scope (deprecated)
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 16), // ff00::/16
    ];

    // Check reserved subnets
    for (subnet, prefix_len) in &reserved_subnets {
        if in_subnet_v6(addr, *subnet, *prefix_len) {
            return Err(DpdError::Invalid(format!(
                "{} is in the reserved multicast subnet {}/{}",
                addr, subnet, prefix_len
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{nat::Vni, network::MacAddr};
    use oxnet::Ipv4Net;

    use std::str::FromStr;

    #[test]
    fn test_ipv4_subnet_check() {
        // Test subnet checks
        assert!(in_subnet_v4(
            Ipv4Addr::new(224, 0, 0, 100),
            Ipv4Addr::new(224, 0, 0, 0),
            24
        ));
        assert!(!in_subnet_v4(
            Ipv4Addr::new(224, 0, 1, 1),
            Ipv4Addr::new(224, 0, 0, 0),
            24
        ));
    }

    #[test]
    fn test_ipv6_subnet_check() {
        // Test subnet checks
        assert!(in_subnet_v6(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1234),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0),
            16
        ));
        assert!(!in_subnet_v6(
            Ipv6Addr::new(0xff03, 0, 0, 0, 0, 0, 0, 0x1234),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0),
            16
        ));
    }

    #[test]
    fn test_ipv4_validation() {
        // These should be allowed
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(224, 1, 0, 1), None).is_ok()
        );
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(224, 2, 2, 3), None).is_ok()
        );
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(231, 1, 2, 3), None).is_ok()
        );

        // These should be rejected
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(224, 0, 0, 1), None).is_err()
        ); // Link-local
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(224, 0, 0, 5), None).is_err()
        ); // Link-local
        assert!(validate_ipv4_multicast(Ipv4Addr::new(192, 168, 1, 1), None)
            .is_err()); // Not multicast
    }

    #[test]
    fn test_ipv6_validation() {
        // These should be allowed
        assert!(validate_ipv6_multicast(
            Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234),
            None
        )
        .is_ok()); // Global
        assert!(validate_ipv6_multicast(
            Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x1111),
            None
        )
        .is_ok()); // Site-local
        assert!(validate_ipv6_multicast(
            Ipv6Addr::new(0xff08, 0, 0, 0, 0, 0, 0, 0x5678),
            None
        )
        .is_ok()); // Organization-local

        // These should be rejected
        assert!(validate_ipv6_multicast(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1),
            None
        )
        .is_err()); // Link-local
        assert!(validate_ipv6_multicast(
            Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 0x2,),
            None
        )
        .is_err()); // Interface-local
        assert!(validate_ipv6_multicast(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1),
            None
        )
        .is_err()); // Not multicast
    }

    #[test]
    fn test_ipv4_ssm_with_sources() {
        // Create test data for source specifications
        let ssm_addr = Ipv4Addr::new(232, 1, 2, 3);
        let non_ssm_addr = Ipv4Addr::new(224, 1, 2, 3);

        // Test with exact source IP
        let exact_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];

        // Test with subnet source specification
        let subnet_sources =
            vec![IpSrc::Subnet(Ipv4Net::from_str("192.168.1.0/24").unwrap())];

        // Test with mixed source specifications
        let mixed_sources = vec![
            IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpSrc::Subnet(Ipv4Net::from_str("10.0.0.0/8").unwrap()),
        ];

        // Empty sources - should fail for SSM
        assert!(validate_ipv4_multicast(ssm_addr, Some(&[])).is_err());

        // SSM address with exact source - should pass
        assert!(validate_ipv4_multicast(ssm_addr, Some(&exact_sources)).is_ok());

        // SSM address with subnet source - should pass
        assert!(
            validate_ipv4_multicast(ssm_addr, Some(&subnet_sources)).is_ok()
        );

        // SSM address with mixed sources - should pass
        assert!(validate_ipv4_multicast(ssm_addr, Some(&mixed_sources)).is_ok());

        // Non-SSM address with sources - should fail as source specs only allowed for SSM
        assert!(validate_ipv4_multicast(non_ssm_addr, Some(&exact_sources))
            .is_err());
        assert!(validate_ipv4_multicast(non_ssm_addr, Some(&subnet_sources))
            .is_err());
        assert!(validate_ipv4_multicast(non_ssm_addr, Some(&mixed_sources))
            .is_err());
    }

    #[test]
    fn test_ipv6_ssm_with_sources() {
        // IPv6 SSM addresses (ff3x::/32)
        let ssm_global = Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234); // Global scope (e)
        let non_ssm_global = Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234); // Non-SSM global

        // Create test sources for IPv6
        let ip6_sources = vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1,
        )))];

        // Empty sources - should fail for SSM
        assert!(validate_ipv6_multicast(ssm_global, Some(&[])).is_err());

        // SSM address with IPv6 source - should pass
        assert!(validate_ipv6_multicast(ssm_global, Some(&ip6_sources)).is_ok());

        // Non-SSM address with IPv6 source - should fail
        assert!(validate_ipv6_multicast(non_ssm_global, Some(&ip6_sources))
            .is_err());
    }

    #[test]
    fn test_is_ssm_function() {
        // Test IPv4 SSM detection
        assert!(is_ssm(IpAddr::V4(Ipv4Addr::new(232, 0, 0, 1))));
        assert!(is_ssm(IpAddr::V4(Ipv4Addr::new(232, 255, 255, 255))));
        assert!(!is_ssm(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(!is_ssm(IpAddr::V4(Ipv4Addr::new(231, 0, 0, 1))));

        // Test IPv6 SSM detection (ff3x::/32)
        assert!(is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff30, 0, 0, 0, 0, 0, 0, 0x1
        )))); // With 0 scope
        assert!(is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff3e, 0, 0, 0, 0, 0, 0, 0x1
        )))); // Global scope (e)
        assert!(is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff35, 0, 0, 0, 0, 0, 0, 0x1
        )))); // Site-local scope (5)

        // Not SSM
        assert!(!is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff0e, 0, 0, 0, 0, 0, 0, 0x1
        )))); // Flag bit not 3
        assert!(!is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff1e, 0, 0, 0, 0, 0, 0, 0x1
        )))); // Flag bit not 3
    }

    #[test]
    fn test_address_validation_integrated() {
        // Test the main validate_multicast_address function

        // Valid IPv4 non-SSM address, no sources
        assert!(validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(224, 1, 0, 1)),
            None
        )
        .is_ok());

        // Valid IPv4 SSM address with sources
        let sources = vec![
            IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpSrc::Subnet(Ipv4Net::from_str("10.0.0.0/8").unwrap()),
        ];
        assert!(validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            Some(&sources)
        )
        .is_ok());

        // Valid IPv6 non-SSM address, no sources
        assert!(validate_multicast_address(
            IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234)),
            None
        )
        .is_ok());

        // Valid IPv6 SSM address with sources
        let ip6_sources = vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1,
        )))];
        assert!(validate_multicast_address(
            IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234)),
            Some(&ip6_sources)
        )
        .is_ok());

        // Error cases

        // Not a multicast address
        assert!(validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            None
        )
        .is_err());

        // IPv4 SSM without sources
        assert!(validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            None
        )
        .is_err());

        // IPv4 non-SSM with sources
        assert!(validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(224, 1, 2, 3)),
            Some(&sources)
        )
        .is_err());

        // IPv6 SSM without sources
        assert!(validate_multicast_address(
            IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234)),
            None
        )
        .is_err());

        // IPv6 non-SSM with sources
        assert!(validate_multicast_address(
            IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234)),
            Some(&ip6_sources)
        )
        .is_err());
    }

    #[test]
    fn test_validate_nat_target() {
        let ucast_nat_target = NatTarget {
            internal_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            // Not a multicast MAC
            inner_mac: MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x01),
            vni: Vni::new(100).unwrap(),
        };

        assert!(validate_nat_target(ucast_nat_target).is_err());

        let mcast_nat_target = NatTarget {
            internal_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            // Multicast MAC
            inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01),
            vni: Vni::new(100).unwrap(),
        };

        assert!(validate_nat_target(mcast_nat_target).is_ok());
    }
}
