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

use super::IpSrc;
use crate::types::{DpdError, DpdResult};
use common::network::NatTarget;
use dpd_types::mcast::MulticastTag;
use omicron_common::address::{
    IPV4_LINK_LOCAL_MULTICAST_SUBNET, IPV4_SSM_SUBNET,
    UNDERLAY_MULTICAST_SUBNET,
};

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

/// Validates the NAT target inner MAC and internal IP address.
///
/// NAT targets must use addresses from the reserved underlay multicast subnet
/// (ff04::/64) which is allocated by Omicron for internal multicast routing.
pub(crate) fn validate_nat_target(nat_target: NatTarget) -> DpdResult<()> {
    if !nat_target.inner_mac.is_multicast() {
        return Err(DpdError::Invalid(format!(
            "NAT target inner MAC address {inner_mac} is not a multicast MAC address",
            inner_mac = nat_target.inner_mac
        )));
    }

    if !UNDERLAY_MULTICAST_SUBNET.contains(nat_target.internal_ip) {
        return Err(DpdError::Invalid(format!(
            "NAT target internal IP address {} is not in the reserved \
             underlay multicast subnet (ff04::/64)",
            nat_target.internal_ip
        )));
    }

    Ok(())
}

/// Check if an IP address is a Source-Specific Multicast (SSM) address.
///
/// [RFC 4607 §1] defines IPv6 SSM as ff3x::/32: sixteen disjoint /32 blocks,
/// not the broader ff30::/12 prefix. The second 16-bit segment must therefore
/// be zero. SSM classification gates the sources-required policy in
/// `validate_ipv4_multicast` and `validate_ipv6_multicast`, so treating a
/// [RFC 3306] unicast-prefix-based address such as ff3e:20:1234::1 (with an
/// embedded unicast prefix length (`plen`) of 32) as SSM would reject
/// otherwise-valid ASM group creation for lacking a source. This matches
/// Omicron's `is_ssm_address` and maghemite's `MulticastRouteKey::validate`.
///
/// [RFC 4607 §1]: https://www.rfc-editor.org/rfc/rfc4607#section-1
/// [RFC 3306]: https://www.rfc-editor.org/rfc/rfc3306
pub(crate) fn is_ssm(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => IPV4_SSM_SUBNET.contains(ipv4),
        IpAddr::V6(ipv6) => {
            let segs = ipv6.segments();
            segs[0] & 0xfff0 == 0xff30 && segs[1] == 0
        }
    }
}

/// Check if sources contain an Any variant.
fn contains_any_source(sources: &[IpSrc]) -> bool {
    sources.iter().any(|s| matches!(s, IpSrc::Any))
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

    // If this is SSM, require specific sources (RFC 4607)
    if is_ssm(addr.into()) {
        if sources.is_none() || sources.unwrap().is_empty() {
            return Err(DpdError::Invalid(format!(
                "{addr} is a Source-Specific Multicast address and \
                 requires at least one source to be defined",
            )));
        }
        if contains_any_source(sources.unwrap()) {
            return Err(DpdError::Invalid(format!(
                "{addr} is a Source-Specific Multicast address and \
                 requires specific sources (IpSrc::Any is not allowed)",
            )));
        }

        // The first /24 of the SSM range is reserved (RFC 4607 §4.3):
        // 232.0.0.0 must not be used as a destination and 232.0.0.1
        // through 232.0.0.255 are held for IANA allocation.
        let octets = addr.octets();
        if octets[1] == 0 && octets[2] == 0 {
            return Err(DpdError::Invalid(format!(
                "{addr} is in the reserved IPv4 SSM subnet \
                 (232.0.0.0/24, RFC 4607)",
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

    // Admit only scopes usable for switch-forwarded delivery, independent
    // of the flags nibble: admin-local (4), site-local (5),
    // organization-local (8), and global (e). [RFC 7346 §2] reserves 0 and
    // f, scopes 1 and 2 never leave a host or link, and 6, 7, and 9
    // through d are unassigned ([RFC 4291 §2.7]).
    //
    // Realm-local (3) is defined per network technology ([RFC 7346 §3]
    // covers only IEEE 802.15.4), so it is excluded absent an Ethernet
    // realm definition.
    //
    // [RFC 4291 §2.7]: https://www.rfc-editor.org/rfc/rfc4291#section-2.7
    // [RFC 7346 §2]: https://www.rfc-editor.org/rfc/rfc7346#section-2
    // [RFC 7346 §3]: https://www.rfc-editor.org/rfc/rfc7346#section-3
    let seg0 = addr.segments()[0];
    let scope_name = match seg0 & 0x000f {
        0x0 | 0xf => Some("reserved"),
        0x1 => Some("interface-local"),
        0x2 => Some("link-local"),
        0x3 => Some("realm-local"),
        0x4 | 0x5 | 0x8 | 0xe => None,
        _ => Some("unassigned"),
    };
    if let Some(scope_name) = scope_name {
        return Err(DpdError::Invalid(format!(
            "{addr} has {scope_name} multicast scope ({seg0:x}::/16) and \
             cannot be used for group creation",
        )));
    }

    // If this is SSM, require specific sources (RFC 4607)
    if is_ssm(addr.into()) {
        if sources.is_none() || sources.unwrap().is_empty() {
            return Err(DpdError::Invalid(format!(
                "{addr} is an IPv6 Source-Specific Multicast address (ff3x::/32) \
                 and requires at least one source to be defined",
            )));
        }
        if contains_any_source(sources.unwrap()) {
            return Err(DpdError::Invalid(format!(
                "{addr} is an IPv6 Source-Specific Multicast address (ff3x::/32) \
                 and requires specific sources (IpSrc::Any is not allowed)",
            )));
        }

        // Only the low 32 bits of an SSM block form the group ID.
        // RFC 4607 §1 invalidates IDs below 0x40000000 and §4.3 reserves
        // 0x40000000 through 0x7fffffff for IANA allocation, leaving
        // ff3x::8000:0 through ff3x::ffff:ffff for dynamic allocation.
        let segs = addr.segments();
        let within_prefix =
            segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0;
        let group_id = (u32::from(segs[6]) << 16) | u32::from(segs[7]);
        if !within_prefix || group_id < 0x8000_0000 {
            return Err(DpdError::Invalid(format!(
                "{addr} is not a dynamically allocatable IPv6 SSM address \
                 (ff3x::8000:0 through ff3x::ffff:ffff per RFC 4607)",
            )));
        }
        return Ok(());
    }

    Ok(())
}

/// Validates that IPv6 addresses are not in the reserved underlay subnet.
///
/// External groups may use admin-local addresses (ff04::/16) but not the
/// reserved underlay subnet (ff04::/64), which is used for internal underlay
/// multicast group allocation.
pub(crate) fn validate_not_underlay_subnet(addr: IpAddr) -> DpdResult<()> {
    if let IpAddr::V6(ipv6) = addr
        && UNDERLAY_MULTICAST_SUBNET.contains(ipv6)
    {
        return Err(DpdError::Invalid(format!(
            "{addr} is in the reserved underlay multicast subnet (ff04::/64, \
             within admin-local scope ff04::/16) and must be created via the \
             internal multicast API",
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

/// Validates tag format for group creation.
///
/// Delegates to [`MulticastTag::from_str`] which enforces:
/// - Length: 1-80 ASCII bytes
/// - Characters: alphanumeric, hyphens, underscores, colons, or periods
///
/// Auto-generated tags use the format `{uuid}:{group_ip}`.
pub(crate) fn validate_tag_format(tag: &str) -> DpdResult<()> {
    tag.parse::<MulticastTag>()
        .map(|_| ())
        .map_err(|e| DpdError::Invalid(e.to_string()))
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
    use common::network::{MacAddr, Vni};
    use dpd_types::mcast::MAX_TAG_LENGTH;

    /// Admin-local IPv6 multicast prefix (ff04::/16, scope 4).
    const ADMIN_LOCAL_PREFIX: u16 = 0xff04;

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

        // SSM with any-source is not allowed (RFC 4607)
        assert!(validate_ipv4_multicast(ssm_addr, Some(&any_source)).is_err());

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
        let ssm_addr = Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234);
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

        // SSM with any-source is not allowed (RFC 4607)
        assert!(validate_ipv6_multicast(ssm_addr, Some(&any_source)).is_err());

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
    fn test_reserved_and_unallocatable_addresses() {
        let v4_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        let v6_sources = vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1,
        )))];

        // The first /24 of IPv4 SSM is reserved (RFC 4607 section 4.3).
        assert!(
            validate_ipv4_multicast(
                Ipv4Addr::new(232, 0, 0, 0),
                Some(&v4_sources)
            )
            .is_err()
        );
        assert!(
            validate_ipv4_multicast(
                Ipv4Addr::new(232, 0, 0, 1),
                Some(&v4_sources)
            )
            .is_err()
        );

        // The 232/8 boundary is exact. The rest of the SSM block is
        // allocatable with sources, and the /8's immediate ASM neighbors
        // need none. Nexus's `validate_multicast_range` rejects any pool
        // range that crosses or contains this boundary.
        assert!(
            validate_ipv4_multicast(
                Ipv4Addr::new(232, 0, 1, 0),
                Some(&v4_sources)
            )
            .is_ok()
        );
        assert!(
            validate_ipv4_multicast(
                Ipv4Addr::new(232, 255, 255, 255),
                Some(&v4_sources)
            )
            .is_ok()
        );
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(231, 255, 255, 255), None)
                .is_ok()
        );
        assert!(
            validate_ipv4_multicast(Ipv4Addr::new(233, 0, 0, 0), None).is_ok()
        );

        // IPv6 SSM group IDs below 0x80000000 are invalid or held for
        // IANA allocation (RFC 4607 sections 1 and 4.3).
        for (hi, lo) in [(0, 0x1234), (0x3fff, 0xffff), (0x4000, 0)] {
            assert!(
                validate_ipv6_multicast(
                    Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, hi, lo),
                    Some(&v6_sources)
                )
                .is_err(),
                "group ID {hi:#06x}{lo:04x} should be rejected"
            );
        }

        // Inside the ff3e::/32 SSM block but outside ff3e::/96, so not a
        // valid 32-bit group ID.
        assert!(
            validate_ipv6_multicast(
                Ipv6Addr::new(0xff3e, 0, 0x1234, 0, 0, 0, 0, 0x1),
                Some(&v6_sources)
            )
            .is_err()
        );

        // Unusable and unassigned scope nibbles are rejected across flag
        // variants, SSM included.
        for seg0 in [
            0xff30, 0xff31, 0xff32, 0xff33, 0xff36, 0xff39, 0xff3d, 0xff3f,
            0xff03, 0xff11, 0xff12, 0xff13, 0xff07, 0xff1a,
        ] {
            assert!(
                validate_ipv6_multicast(
                    Ipv6Addr::new(seg0, 0, 0, 0, 0, 0, 0x8000, 0x1),
                    Some(&v6_sources)
                )
                .is_err(),
                "{seg0:x}::/16 should be rejected for its scope"
            );
        }
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
        // RFC 4607 classifies the full /32 as SSM to leave room for possible
        // future use of the network-prefix field.
        assert!(is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff3e, 0, 0x1234, 0, 0, 0, 0, 0x1
        ))));

        // Not SSM
        assert!(!is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff0e, 0, 0, 0, 0, 0, 0, 0x1
        )))); // Flag bit not 3
        assert!(!is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff1e, 0, 0, 0, 0, 0, 0, 0x1
        )))); // Flag bit not 3
        // RFC 3306 unicast-prefix-based ASM address: shares ff30::/12 but has
        // plen 32 in the second segment, so it is outside ff3e::/32.
        assert!(!is_ssm(IpAddr::V6(Ipv6Addr::new(
            0xff3e, 0x0020, 0, 0x1234, 0, 0, 0, 0x1
        ))));
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

        // Valid IPv4 SSM address with exact sources
        let ssm_sources =
            vec![IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                Some(&ssm_sources)
            )
            .is_ok()
        );

        // IPv4 SSM with Any is rejected (RFC 4607)
        let ssm_with_any = vec![
            IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpSrc::Any,
        ];
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                Some(&ssm_with_any)
            )
            .is_err()
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
                IpAddr::V6(Ipv6Addr::new(
                    0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234
                )),
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

        // IPv4 ASM with sources (including Any, which is valid for ASM)
        let asm_sources = vec![
            IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            IpSrc::Any,
        ];
        assert!(
            validate_multicast_address(
                IpAddr::V4(Ipv4Addr::new(224, 1, 2, 3)),
                Some(&asm_sources)
            )
            .is_ok()
        );

        // IPv6 SSM without sources
        assert!(
            validate_multicast_address(
                IpAddr::V6(Ipv6Addr::new(
                    0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234
                )),
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
        // Unicast internal IP should be rejected
        let ucast_nat_target = NatTarget {
            internal_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            inner_mac: MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x01),
            vni: Vni::new(100).unwrap(),
        };
        assert!(validate_nat_target(ucast_nat_target).is_err());

        // Valid NAT target in reserved underlay subnet (ff04::/64)
        let valid_nat_target = NatTarget {
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
            inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01),
            vni: Vni::new(100).unwrap(),
        };
        assert!(validate_nat_target(valid_nat_target).is_ok());

        // Admin-local address outside ff04::/64 should be rejected
        // ff04:0:0:1::1234 is in ff04::/16 but not in ff04::/64
        let outside_underlay_nat_target = NatTarget {
            internal_ip: Ipv6Addr::new(
                ADMIN_LOCAL_PREFIX,
                0,
                0,
                1, // This puts it outside ff04::/64
                0,
                0,
                0,
                0x1234,
            ),
            inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01),
            vni: Vni::new(100).unwrap(),
        };
        assert!(validate_nat_target(outside_underlay_nat_target).is_err());
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
    fn test_validate_not_underlay_subnet() {
        // Reserved underlay subnet (ff04::/64) should be rejected
        let underlay_addr =
            IpAddr::V6(Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1));
        assert!(validate_not_underlay_subnet(underlay_addr).is_err());

        // Another address in ff04::/64
        let underlay_addr2 =
            IpAddr::V6(Ipv6Addr::new(0xff04, 0, 0, 0, 0xdead, 0xbeef, 0, 1));
        assert!(validate_not_underlay_subnet(underlay_addr2).is_err());

        // Other admin-local /64s should be allowed (e.g., ff04:0:0:1::/64)
        let other_admin_local =
            IpAddr::V6(Ipv6Addr::new(0xff04, 0, 0, 1, 0, 0, 0, 1));
        assert!(validate_not_underlay_subnet(other_admin_local).is_ok());

        // ff04:0:0:2::/64 should also be allowed
        let other_admin_local2 =
            IpAddr::V6(Ipv6Addr::new(0xff04, 0, 0, 2, 0, 0, 0, 1));
        assert!(validate_not_underlay_subnet(other_admin_local2).is_ok());

        // IPv4 multicast should always be allowed (not in underlay subnet)
        let ipv4_mcast = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 3));
        assert!(validate_not_underlay_subnet(ipv4_mcast).is_ok());

        // Non-admin-local IPv6 multicast should be allowed
        let global_mcast =
            IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 1));
        assert!(validate_not_underlay_subnet(global_mcast).is_ok());

        // Site-local multicast should be allowed
        let site_local = IpAddr::V6(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 1));
        assert!(validate_not_underlay_subnet(site_local).is_ok());
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
