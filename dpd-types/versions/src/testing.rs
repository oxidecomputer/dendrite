// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Proptest generators for multicast group addresses, importable by
//! downstream crates through the `testing` feature.
//!
//! The generators encode the rules of version [`MCAST_EXTERNAL_SCOPE`]. Each
//! group generator checks its address against that version's external
//! multicast validator and SSM check, failing the test at generation if either
//! rule narrows.
//!
//! [`MCAST_EXTERNAL_SCOPE`]: crate::v14::mcast

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;

use crate::latest::mcast::{
    IPV4_SSM_SUBNET, IPV6_ADMIN_SCOPED_MULTICAST_PREFIX, IPV6_SSM_SUBNETS,
};
use crate::v14::mcast::{
    is_ssm_address, validate_external_multicast_ipv4,
    validate_external_multicast_ipv6,
};

const IPV4_MULTICAST_FIRST_OCTET: u8 = 224;
const IPV6_MULTICAST_PREFIX: u16 = 0xff00;
/// SSM flags nibble (R=0, P=T=1) for `ff3x` addresses (RFC 7371 §4.1.2).
const IPV6_SSM_FLAGS: u16 = 0x3;
const IPV6_NON_SSM_FLAGS: [u16; 4] = [0x0, 0x1, 0x8, 0x9];

/// Usable IPv6 multicast scopes, containing every scope
/// `ExternalMulticastIp::new` accepts (3 through f).
const USABLE_MULTICAST_SCOPES: [u8; 13] =
    [0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

/// Generate a usable IPv6 multicast scope nibble.
pub fn usable_scope_strategy() -> impl Strategy<Value = u8> {
    proptest::sample::select(&USABLE_MULTICAST_SCOPES[..])
}

/// Generate ASM (non-SSM) IPv4 multicast groups.
///
/// This skips the local network control block (224.0.0.0/24) and 232/8,
/// weighting the arms toward the 224.0/16 boundary.
pub fn ipv4_asm_group_strategy() -> impl Strategy<Value = Ipv4Addr> {
    let mcast_base = IPV4_MULTICAST_FIRST_OCTET;
    let mcast_end = mcast_base + 15;
    let ssm_first = IPV4_SSM_SUBNET.addr().octets()[0];

    prop_oneof![
        // mcast_base.0.1.0 - mcast_base.0.255.255
        (1u8..=u8::MAX, any::<u8>())
            .prop_map(move |(c, d)| Ipv4Addr::new(mcast_base, 0, c, d)),
        // mcast_base.1.0.0 - mcast_base.255.255.255
        (1u8..=u8::MAX, any::<u8>(), any::<u8>())
            .prop_map(move |(b, c, d)| Ipv4Addr::new(mcast_base, b, c, d)),
        // (mcast_base + 1).x.x.x - (ssm_first - 1).x.x.x
        ((mcast_base + 1)..=ssm_first - 1, any::<[u8; 3]>())
            .prop_map(|(a, [b, c, d])| Ipv4Addr::new(a, b, c, d)),
        // (ssm_first + 1).x.x.x - mcast_end.x.x.x
        ((ssm_first + 1)..=mcast_end, any::<[u8; 3]>())
            .prop_map(|(a, [b, c, d])| Ipv4Addr::new(a, b, c, d)),
    ]
    .prop_map(|addr| checked_ipv4_group(addr, false))
}

/// Generate SSM IPv4 multicast groups (232/8), skipping the first /24, which
/// holds the SSM null address and the addresses reserved for IANA allocation
/// (RFC 4607 §4.3).
pub fn ipv4_ssm_group_strategy() -> impl Strategy<Value = Ipv4Addr> {
    let ssm_first = IPV4_SSM_SUBNET.addr().octets()[0];
    prop_oneof![
        // 232.1.0.0 - 232.255.255.255
        (1u8..=u8::MAX, any::<u8>(), any::<u8>())
            .prop_map(move |(b, c, d)| Ipv4Addr::new(ssm_first, b, c, d)),
        // 232.0.1.0 - 232.0.255.255
        (1u8..=u8::MAX, any::<u8>())
            .prop_map(move |(c, d)| Ipv4Addr::new(ssm_first, 0, c, d)),
    ]
    .prop_map(|addr| checked_ipv4_group(addr, true))
}

/// Generate ASM (non-SSM) IPv6 multicast groups.
///
/// This covers the non-SSM flags and the SSM flags with a nonzero prefix
/// length. It never produces embedded-RP groups (`ff7x`, `fffx`) or
/// prefix-based `ffbx` groups.
pub fn ipv6_asm_group_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        // `ff<flags><scope>::` where flags != `IPV6_SSM_FLAGS`
        (
            proptest::sample::select(&IPV6_NON_SSM_FLAGS[..]),
            usable_scope_strategy(),
            any::<[u16; 7]>(),
        )
            .prop_map(|(flags, scope, mut segs)| {
                let first =
                    IPV6_MULTICAST_PREFIX | (flags << 4) | u16::from(scope);
                // An admin-local address containing zero bits between `ff04`
                // and the /64 boundary would fall in the reserved underlay
                // subnet (`ff04::/64`), which `ExternalMulticastIp::new`
                // rejects.
                //
                // Flags 0 with all of its remaining segments being zero
                // would be the reserved base address `ff0x::`. In either case,
                // the conditional sets the second segment to 1.
                let in_underlay = first == IPV6_ADMIN_SCOPED_MULTICAST_PREFIX
                    && segs[..3] == [0, 0, 0];
                let is_base = flags == 0 && segs == [0; 7];
                if in_underlay || is_base {
                    segs[0] = 1;
                }
                checked_ipv6_group(
                    Ipv6Addr::new(
                        first, segs[0], segs[1], segs[2], segs[3], segs[4],
                        segs[5], segs[6],
                    ),
                    false,
                )
            }),
        // Use flags 3 with a nonzero prefix length to stay as ASM.
        (
            usable_scope_strategy(),
            any::<u8>(),
            1u8..=u8::MAX,
            any::<[u16; 6]>(),
        )
            .prop_map(|(scope, rsvd, plen, segs)| {
                let first = IPV6_MULTICAST_PREFIX
                    | (IPV6_SSM_FLAGS << 4)
                    | u16::from(scope);
                let seg1 = (u16::from(rsvd) << 8) | u16::from(plen);
                checked_ipv6_group(
                    Ipv6Addr::new(
                        first, seg1, segs[0], segs[1], segs[2], segs[3],
                        segs[4], segs[5],
                    ),
                    false,
                )
            }),
    ]
}

/// Generate SSM IPv6 multicast groups (`ff3x::/32`).
///
/// Addresses stay within the dynamic range: the prefix bits between the /32
/// boundary and the 32-bit group ID are zero, and the group ID is at least
/// `0x80000000` (RFC 3307 §4.3). This also avoids the null address
/// `ff3x::4000:0` (RFC 4607 §4.3).
pub fn ipv6_ssm_group_strategy() -> impl Strategy<Value = Ipv6Addr> {
    let ssm_base = IPV6_SSM_SUBNETS[0].addr().segments()[0];
    (usable_scope_strategy(), 0x8000u16..=u16::MAX, any::<u16>()).prop_map(
        move |(scope, id_hi, id_lo)| {
            checked_ipv6_group(
                Ipv6Addr::new(
                    ssm_base | u16::from(scope),
                    0,
                    0,
                    0,
                    0,
                    0,
                    id_hi,
                    id_lo,
                ),
                true,
            )
        },
    )
}

fn checked_ipv4_group(addr: Ipv4Addr, ssm: bool) -> Ipv4Addr {
    validate_external_multicast_ipv4(addr)
        .expect("generated IPv4 group is valid");
    assert_eq!(
        is_ssm_address(IpAddr::V4(addr)),
        ssm,
        "generated IPv4 group {addr} has the wrong SSM classification"
    );
    addr
}

fn checked_ipv6_group(addr: Ipv6Addr, ssm: bool) -> Ipv6Addr {
    validate_external_multicast_ipv6(addr)
        .expect("generated IPv6 group is valid");
    assert_eq!(
        is_ssm_address(IpAddr::V6(addr)),
        ssm,
        "generated IPv6 group {addr} has the wrong SSM classification"
    );
    addr
}
