// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Multicast address validation.
//!
//! Reserved multicast addresses are defined by IANA:
//! <https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml>.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::nat::NatTarget;
use omicron_common::address::{
    IPV4_LINK_LOCAL_MULTICAST_SUBNET, IPV4_SSM_SUBNET,
    IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET, IPV6_LINK_LOCAL_MULTICAST_SUBNET,
    IPV6_RESERVED_SCOPE_MULTICAST_SUBNET, IPV6_SSM_SUBNET,
};
use oxnet::Ipv6Net;

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

    if !internal_nat_ip.is_admin_local_multicast() {
        return Err(DpdError::Invalid(format!(
            "NAT target internal IP address {} is not a valid \
             admin-local multicast address (must be ff04::/16)",
            nat_target.internal_ip
        )));
    }

    Ok(())
}

/// Check if an IP address is a Source-Specific Multicast (SSM) address.
pub(crate) fn is_ssm(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => IPV4_SSM_SUBNET.contains(ipv4),
        IpAddr::V6(ipv6) => IPV6_SSM_SUBNET.contains(ipv6),
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
            "{addr} is not a multicast address",
        )));
    }

    // If this is SSM, require sources to be defined
    if is_ssm(addr.into()) {
        if sources.is_none() || sources.unwrap().is_empty() {
            return Err(DpdError::Invalid(format!(
                "{addr} is a Source-Specific Multicast address and \
                 requires at least one source to be defined",
            )));
        }
        return Ok(());
    }

    // Check reserved subnets
    if IPV4_LINK_LOCAL_MULTICAST_SUBNET.contains(addr) {
        return Err(DpdError::Invalid(format!(
            "{addr} is in the reserved link-local multicast subnet",
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
            "{addr} is not a multicast address",
        )));
    }

    // If this is SSM, require sources to be defined
    if is_ssm(addr.into()) {
        if sources.is_none() || sources.unwrap().is_empty() {
            return Err(DpdError::Invalid(format!(
                "{addr} is an IPv6 Source-Specific Multicast address (ff3x::/32) \
                 and requires at least one source to be defined",
            )));
        }
        return Ok(());
    }

    // Check reserved subnets
    let reserved_subnets = [
        IPV6_LINK_LOCAL_MULTICAST_SUBNET,
        IPV6_INTERFACE_LOCAL_MULTICAST_SUBNET,
        IPV6_RESERVED_SCOPE_MULTICAST_SUBNET,
    ];

    for subnet in &reserved_subnets {
        if subnet.contains(addr) {
            return Err(DpdError::Invalid(format!(
                "{addr} is in the reserved multicast subnet {subnet}",
            )));
        }
    }

    Ok(())
}

/// Validates that IPv6 addresses are not admin-local for external group creation.
pub(crate) fn validate_not_admin_local_ipv6(addr: IpAddr) -> DpdResult<()> {
    if let IpAddr::V6(ipv6) = addr
        && oxnet::Ipv6Net::new_unchecked(ipv6, 128).is_admin_local_multicast()
    {
        return Err(DpdError::Invalid(format!(
            "{addr} is an admin-local multicast address and \
                 must be created via the internal multicast API",
        )));
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
            IpSrc::Any => {} // Any-source is always valid
        }
    }
    Ok(())
}

/// Validates a single exact source IP address.
fn validate_exact_source_address(ip: IpAddr) -> DpdResult<()> {
    // First check if it's unicast (excludes multicast)
    if !is_unicast(ip) {
        return Err(DpdError::Invalid(format!(
            "Source IP {ip} must be a unicast address (multicast addresses are not allowed)",
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
    if ipv4.is_loopback()
        || ipv4.is_broadcast()
        || ipv4.is_unspecified()
        || ipv4.is_link_local()
    {
        return Err(DpdError::Invalid(format!(
            "Source IP {ipv4} is not a valid source address \
             (loopback, broadcast, unspecified, and link-local addresses are not allowed)",
        )));
    }
    Ok(())
}

/// Validates IPv6 source addresses for problematic types.
fn validate_ipv6_source_address(ipv6: Ipv6Addr) -> DpdResult<()> {
    if ipv6.is_loopback()
        || ipv6.is_unspecified()
        || ((ipv6.segments()[0] & 0xffc0) == 0xfe80)
    {
        return Err(DpdError::Invalid(format!(
            "Source IP {ipv6} is not a valid source address \
             (loopback, unspecified, and link-local addresses are not allowed)",
        )));
    }
    Ok(())
}

/// Maximum length for multicast group tags.
///
/// Keep in sync with Omicron's database schema column type for multicast group
/// tags. This is sized to accommodate the auto-generated format
/// `{uuid}:{group_ip}` for both IPv4 and IPv6 group IPs.
const MAX_TAG_LENGTH: usize = 80;

/// Validates tag format for group creation.
///
/// Tags must be 1-80 ASCII bytes containing only alphanumeric characters,
/// hyphens, underscores, colons, or periods.
///
/// This character set is compatible with URL path segments, though colons are
/// RFC 3986 reserved characters and may require percent-encoding in some HTTP
/// client contexts.
///
/// Auto-generated tags use the format `{uuid}:{group_ip}`.
pub(crate) fn validate_tag_format(tag: &str) -> DpdResult<()> {
    if tag.is_empty() {
        return Err(DpdError::Invalid("tag cannot be empty".to_string()));
    }
    if tag.len() > MAX_TAG_LENGTH {
        return Err(DpdError::Invalid(format!(
            "tag cannot exceed {MAX_TAG_LENGTH} bytes"
        )));
    }
    if !tag.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.')
    }) {
        return Err(DpdError::Invalid(
            "tag must contain only ASCII alphanumeric characters, hyphens, \
             underscores, colons, or periods"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validates that the request tag matches the existing group's tag.
///
/// Tags are immutable after group creation. This validation ensures the caller
/// created the group before allowing mutations.
pub(crate) fn validate_tag(
    existing_tag: &str,
    request_tag: &str,
) -> DpdResult<()> {
    if request_tag != existing_tag {
        return Err(DpdError::Invalid(
            "tag mismatch: provided tag does not match the group's tag"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{nat::Vni, network::MacAddr};
    use dpd_types::mcast::ADMIN_LOCAL_PREFIX;

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
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(192, 168, 1, 1), None)
                .is_err()
        ); // Not multicast
    }

    #[test]
    fn test_ipv6_validation() {
        // These should be allowed
        assert!(
            validate_ipv6_multicast(
                Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234),
                None
            )
            .is_ok()
        ); // Global
        assert!(
            validate_ipv6_multicast(
                Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x1111),
                None
            )
            .is_ok()
        ); // Site-local
        assert!(
            validate_ipv6_multicast(
                Ipv6Addr::new(0xff08, 0, 0, 0, 0, 0, 0, 0x5678),
                None
            )
            .is_ok()
        ); // Organization-local

        // These should be rejected
        assert!(
            validate_ipv6_multicast(
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1),
                None
            )
            .is_err()
        ); // Link-local
        assert!(
            validate_ipv6_multicast(
                Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 0x2,),
                None
            )
            .is_err()
        ); // Interface-local
        assert!(
            validate_ipv6_multicast(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1),
                None
            )
            .is_err()
        ); // Not multicast
    }

    #[test]
    fn test_ipv4_ssm_with_sources() {
        let ssm_addr = Ipv4Addr::new(232, 1, 2, 3);
        let asm_addr = Ipv4Addr::new(224, 1, 2, 3);

        let exact_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        let any_source = vec![IpSrc::Any];

        // SSM requires sources
        assert!(validate_ipv4_multicast(ssm_addr, Some(&[])).is_err());
        assert!(validate_ipv4_multicast(ssm_addr, None).is_err());

        // SSM with exact source
        assert!(
            validate_ipv4_multicast(ssm_addr, Some(&exact_sources)).is_ok()
        );

        // SSM with any-source
        assert!(validate_ipv4_multicast(ssm_addr, Some(&any_source)).is_ok());

        // ASM without sources
        assert!(validate_ipv4_multicast(asm_addr, None).is_ok());
        assert!(validate_ipv4_multicast(asm_addr, Some(&[])).is_ok());

        // ASM with sources
        assert!(
            validate_ipv4_multicast(asm_addr, Some(&exact_sources)).is_ok()
        );
        assert!(validate_ipv4_multicast(asm_addr, Some(&any_source)).is_ok());
    }

    #[test]
    fn test_ipv6_ssm_with_sources() {
        let ssm_addr = Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234);
        let asm_addr = Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234);

        let exact_sources = vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1,
        )))];
        let any_source = vec![IpSrc::Any];

        // SSM requires sources
        assert!(validate_ipv6_multicast(ssm_addr, Some(&[])).is_err());
        assert!(validate_ipv6_multicast(ssm_addr, None).is_err());

        // SSM with exact source
        assert!(
            validate_ipv6_multicast(ssm_addr, Some(&exact_sources)).is_ok()
        );

        // SSM with any-source
        assert!(validate_ipv6_multicast(ssm_addr, Some(&any_source)).is_ok());

        // ASM without sources
        assert!(validate_ipv6_multicast(asm_addr, None).is_ok());
        assert!(validate_ipv6_multicast(asm_addr, Some(&[])).is_ok());

        // ASM with sources
        assert!(
            validate_ipv6_multicast(asm_addr, Some(&exact_sources)).is_ok()
        );
        assert!(validate_ipv6_multicast(asm_addr, Some(&any_source)).is_ok());
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
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(224, 1, 0, 1)),
                None
            )
            .is_ok()
        );

        // Valid IPv4 SSM address with sources
        let sources = vec![
            IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpSrc::Any,
        ];
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                Some(&sources)
            )
            .is_ok()
        );

        // Valid IPv6 non-SSM address, no sources
        assert!(
            validate_multicast_address(
                IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234)),
                None
            )
            .is_ok()
        );

        // Valid IPv6 SSM address with sources
        let ip6_sources = vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1,
        )))];
        assert!(
            validate_multicast_address(
                IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234)),
                Some(&ip6_sources)
            )
            .is_ok()
        );

        // Error cases

        // Not a multicast address
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                None
            )
            .is_err()
        );

        // IPv4 SSM without sources
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                None
            )
            .is_err()
        );

        // IPv4 ASM with sources
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(224, 1, 2, 3)),
                Some(&sources)
            )
            .is_ok()
        );

        // IPv6 SSM without sources
        assert!(
            validate_multicast_address(
                IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234)),
                None
            )
            .is_err()
        );

        // IPv6 ASM with sources
        assert!(
            validate_multicast_address(
                IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x1234)),
                Some(&ip6_sources)
            )
            .is_ok()
        );
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
            // admin-local multicast (ff04::/16)
            internal_ip: Ipv6Addr::new(
                ADMIN_LOCAL_PREFIX,
                0,
                0,
                0,
                0,
                0,
                0,
                0x1234,
            ),
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

        // Any-source is valid
        let any_source = vec![IpSrc::Any];
        assert!(validate_source_addresses(Some(&any_source)).is_ok());

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

        // No sources should be valid
        assert!(validate_source_addresses(None).is_ok());

        // Empty sources should be valid
        assert!(validate_source_addresses(Some(&[])).is_ok());
    }

    #[test]
    fn test_address_validation_with_source_validation() {
        // Valid case: SSM address with valid unicast sources
        let valid_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                Some(&valid_sources)
            )
            .is_ok()
        );

        // Invalid case: SSM address with multicast source (should fail source validation first)
        let invalid_mcast_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(224, 1, 1, 1)))];
        let result = validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            Some(&invalid_mcast_sources),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be a unicast address")
        );

        // Invalid case: SSM address with loopback source
        let invalid_loopback_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))];
        let result = validate_multicast_address(
            IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            Some(&invalid_loopback_sources),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("is not a valid source address")
        );
    }

    #[test]
    fn test_validate_tag() {
        // Existing tag matches request tag
        assert!(validate_tag("my-tag", "my-tag").is_ok());

        // Existing tag but request has different tag
        assert!(validate_tag("owner-a", "owner-b").is_err());
        assert!(validate_tag("owner-a", "").is_err());
        assert!(validate_tag("owner-a", "tag/with/slashes").is_err());
    }

    #[test]
    fn test_validate_tag_format() {
        use super::validate_tag_format;

        // Valid tags
        assert!(validate_tag_format("my-tag").is_ok());
        assert!(validate_tag_format("nexus").is_ok());
        assert!(validate_tag_format("a1b2c3").is_ok());
        assert!(validate_tag_format("tag_with_underscore").is_ok());
        assert!(validate_tag_format("tag.with.periods").is_ok());
        assert!(validate_tag_format("tag:with:colons").is_ok());
        assert!(validate_tag_format("mixed-tag_v1.0:test").is_ok());

        // Auto-generated tag format (uuid:ip)
        assert!(
            validate_tag_format(
                "550e8400-e29b-41d4-a716-446655440000:224.1.2.3"
            )
            .is_ok()
        );

        // Tag at exactly MAX_TAG_LENGTH characters is valid
        assert!(validate_tag_format(&"a".repeat(MAX_TAG_LENGTH)).is_ok());

        // Empty tag rejected
        assert!(validate_tag_format("").is_err());

        // Tag exceeding MAX_TAG_LENGTH characters rejected
        assert!(validate_tag_format(&"a".repeat(MAX_TAG_LENGTH + 1)).is_err());

        // Invalid characters rejected
        assert!(validate_tag_format("tag with spaces").is_err());
        assert!(validate_tag_format("tag/with/slashes").is_err());
        assert!(validate_tag_format("tag@with@at").is_err());
        assert!(validate_tag_format("tag#with#hash").is_err());
    }
}
