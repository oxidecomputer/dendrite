// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::nat::NatTarget;
use oxnet::{Ipv4Net, Ipv6Net};

use super::IpSrc;
use crate::types::{DpdError, DpdResult};

/// Check if an IP address is unicast (emulating the unstable std::net API).
/// For IP addresses, unicast means simply "not multicast".
const fn is_unicast(addr: IpAddr) -> bool {
    !addr.is_multicast()
}

/// Validates if a multicast address is allowed for group creation.
///
/// Returns a [`DpdResult`] indicating whether the address is valid or not.
pub(crate) fn validate_multicast_address(
    addr: IpAddr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    // First validate that source addresses are unicast
    validate_source_addresses(sources)?;

    // Then validate the multicast address itself
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

    let internal_nat_ip = Ipv6Net::new_unchecked(nat_target.internal_ip, 128);

    if !internal_nat_ip.is_admin_scoped_multicast() {
        return Err(DpdError::Invalid(format!(
            "NAT target internal IP address {} is not a valid site/admin-local or org-scoped multicast address",
            nat_target.internal_ip
        )));
    }

    Ok(())
}

/// Check if an IP address is a Source-Specific Multicast (SSM) address.
pub(crate) fn is_ssm(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => {
            let subnet = Ipv4Net::new_unchecked(Ipv4Addr::new(232, 0, 0, 0), 8);
            subnet.contains(ipv4)
        }
        // Check for Source-Specific Multicast (ff3x::/32)
        // In IPv6 multicast, the second nibble (flag field) indicates SSM when set to 3
        IpAddr::V6(ipv6) => {
            let flag_field = (ipv6.octets()[1] & 0xF0) >> 4;
            flag_field == 3
        }
    }
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
        // If sources are defined for an SSM address, it's valid
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
        Ipv4Net::new_unchecked(Ipv4Addr::new(224, 0, 0, 0), 24), // 224.0.0.0/24
        // GLOP addressing
        Ipv4Net::new_unchecked(Ipv4Addr::new(233, 0, 0, 0), 8), // 233.0.0.0/8
        // Administrative scoped addresses
        Ipv4Net::new_unchecked(Ipv4Addr::new(239, 0, 0, 0), 8), // 239.0.0.0/8 (administratively scoped)
    ];

    // Check reserved subnets
    for subnet in &reserved_subnets {
        if subnet.contains(addr) {
            return Err(DpdError::Invalid(format!(
                "{} is in the reserved multicast subnet {}",
                addr, subnet,
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
        // If sources are defined for an IPv6 SSM address, it's valid
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
        Ipv6Net::new_unchecked(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0), 16), // ff02::/16
        // Interface-local scope
        Ipv6Net::new_unchecked(Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 0), 16), // ff01::/16
        // Node-local scope (deprecated)
        Ipv6Net::new_unchecked(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 16), // ff00::/16
    ];

    // Check reserved subnets
    for subnet in &reserved_subnets {
        if subnet.contains(addr) {
            return Err(DpdError::Invalid(format!(
                "{} is in the reserved multicast subnet {}",
                addr, subnet
            )));
        }
    }

    Ok(())
}

/// Validates that IPv6 addresses are not admin-scoped for external group creation.
pub(crate) fn validate_not_admin_scoped_ipv6(addr: IpAddr) -> DpdResult<()> {
    if let IpAddr::V6(ipv6) = addr {
        if oxnet::Ipv6Net::new_unchecked(ipv6, 128).is_admin_scoped_multicast()
        {
            return Err(DpdError::Invalid(format!(
                "{} is an admin-scoped multicast address and must be created via the internal multicast API",
                addr
            )));
        }
    }
    Ok(())
}

/// Validates that source IP addresses are unicast.
pub(crate) fn validate_source_addresses(
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    let sources = match sources {
        Some(sources) => sources,
        None => return Ok(()),
    };

    for source in sources {
        match source {
            IpSrc::Exact(ip) => validate_exact_source_address(*ip)?,
            IpSrc::Subnet(subnet) => validate_ipv4_source_subnet(*subnet)?,
        }
    }
    Ok(())
}

/// Validates a single exact source IP address.
fn validate_exact_source_address(ip: IpAddr) -> DpdResult<()> {
    // First check if it's unicast (excludes multicast)
    if !is_unicast(ip) {
        return Err(DpdError::Invalid(format!(
            "Source IP {} must be a unicast address (multicast addresses are not allowed)",
            ip
        )));
    }

    // Check for other problematic address types
    match ip {
        IpAddr::V4(ipv4) => validate_ipv4_source_address(ipv4),
        IpAddr::V6(ipv6) => validate_ipv6_source_address(ipv6),
    }
}

/// Validates IPv4 source addresses for problematic types.
fn validate_ipv4_source_address(ipv4: Ipv4Addr) -> DpdResult<()> {
    if ipv4.is_loopback() || ipv4.is_broadcast() || ipv4.is_unspecified() {
        return Err(DpdError::Invalid(format!(
            "Source IP {} is not a valid source address (loopback, broadcast, and unspecified addresses are not allowed)",
            ipv4
        )));
    }
    Ok(())
}

/// Validates IPv6 source addresses for problematic types.
fn validate_ipv6_source_address(ipv6: Ipv6Addr) -> DpdResult<()> {
    if ipv6.is_loopback() || ipv6.is_unspecified() {
        return Err(DpdError::Invalid(format!(
            "Source IP {} is not a valid source address (loopback and unspecified addresses are not allowed)",
            ipv6
        )));
    }
    Ok(())
}

/// Validates IPv4 source subnets for problematic address ranges.
fn validate_ipv4_source_subnet(net: Ipv4Net) -> DpdResult<()> {
    let addr = net.addr();

    // Reject subnets that contain multicast addresses
    if addr.is_multicast() {
        return Err(DpdError::Invalid(format!(
            "Source subnet {} contains multicast addresses and cannot be used as a source filter",
            net
        )));
    }

    // Reject subnets with loopback or broadcast addresses
    if addr.is_loopback() || addr.is_broadcast() {
        return Err(DpdError::Invalid(format!(
            "Source subnet {} contains invalid address types (loopback/broadcast) for source filtering",
            net
        )));
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
            // org-scoped multicast
            internal_ip: Ipv6Addr::new(0xff08, 0, 0, 0, 0, 0, 0, 0x1234),
            // Multicast MAC
            inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01),
            vni: Vni::new(100).unwrap(),
        };

        assert!(validate_nat_target(mcast_nat_target).is_ok());
    }

    #[test]
    fn test_validate_source_addresses() {
        // Valid unicast IPv4 sources
        let valid_ipv4_sources = vec![
            IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ];
        assert!(validate_source_addresses(Some(&valid_ipv4_sources)).is_ok());

        // Valid unicast IPv6 sources
        let valid_ipv6_sources = vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
        )))];
        assert!(validate_source_addresses(Some(&valid_ipv6_sources)).is_ok());

        // Valid subnet sources
        let valid_subnet_sources = vec![
            IpSrc::Subnet(Ipv4Net::from_str("192.168.1.0/24").unwrap()),
            IpSrc::Subnet(Ipv4Net::from_str("10.0.0.0/8").unwrap()),
        ];
        assert!(validate_source_addresses(Some(&valid_subnet_sources)).is_ok());

        // Invalid multicast IPv4 source
        let invalid_mcast_ipv4 =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(224, 1, 1, 1)))];
        assert!(validate_source_addresses(Some(&invalid_mcast_ipv4)).is_err());

        // Invalid multicast IPv6 source
        let invalid_mcast_ipv6 = vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
            0xff0e, 0, 0, 0, 0, 0, 0, 1,
        )))];
        assert!(validate_source_addresses(Some(&invalid_mcast_ipv6)).is_err());

        // Invalid broadcast IPv4 source
        let invalid_broadcast =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)))];
        assert!(validate_source_addresses(Some(&invalid_broadcast)).is_err());

        // Invalid loopback IPv4 source
        let invalid_loopback_ipv4 =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))];
        assert!(
            validate_source_addresses(Some(&invalid_loopback_ipv4)).is_err()
        );

        // Invalid loopback IPv6 source
        let invalid_loopback_ipv6 = vec![IpSrc::Exact(IpAddr::V6(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        ))];
        assert!(
            validate_source_addresses(Some(&invalid_loopback_ipv6)).is_err()
        );

        // Invalid multicast subnet
        let invalid_mcast_subnet =
            vec![IpSrc::Subnet(Ipv4Net::from_str("224.0.0.0/24").unwrap())];
        assert!(validate_source_addresses(Some(&invalid_mcast_subnet)).is_err());

        // Invalid loopback subnet
        let invalid_loopback_subnet =
            vec![IpSrc::Subnet(Ipv4Net::from_str("127.0.0.0/8").unwrap())];
        assert!(
            validate_source_addresses(Some(&invalid_loopback_subnet)).is_err()
        );

        // No sources should be valid
        assert!(validate_source_addresses(None).is_ok());

        // Empty sources should be valid
        assert!(validate_source_addresses(Some(&[])).is_ok());
    }

    #[test]
    fn test_address_validation_with_source_validation() {
        // Test that multicast address validation now includes source validation

        // Valid case: SSM address with valid unicast sources
        let valid_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        assert!(validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            Some(&valid_sources)
        )
        .is_ok());

        // Invalid case: SSM address with multicast source (should fail source validation first)
        let invalid_mcast_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(224, 1, 1, 1)))];
        let result = validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            Some(&invalid_mcast_sources),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be a unicast address"));

        // Invalid case: SSM address with loopback source
        let invalid_loopback_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))];
        let result = validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            Some(&invalid_loopback_sources),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("is not a valid source address"));
    }
}
