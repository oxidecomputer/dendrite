// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Property-based tests for multicast address validation.
//!
//! Properties stated with `iff` hold bidirectionally: the implementation
//! accepts an input if and only if the spec does.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use test_strategy::{Arbitrary, proptest};

use crate::impls::test_util::{json_round_trip, outcome};
use crate::latest::mcast::{
    EmbeddedIpv4, ExternalMulticastIp, ExternalMulticastIpError,
    InvalidEmbeddedRp, InvalidMulticastSource, MAX_TAG_LENGTH,
    MulticastSourceError, MulticastTag, UnderlayMulticastIpv6, UnicastAddrV4,
    UnicastAddrV6, is_ssm_address,
};

/// Usable IPv6 multicast scopes, containing every scope
/// `ExternalMulticastIp::new` accepts (3 through f).
const USABLE_MULTICAST_SCOPES: [u8; 13] =
    [0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

/// Generate a usable IPv6 multicast scope nibble.
fn usable_scope_strategy() -> impl Strategy<Value = u8> {
    proptest::sample::select(&USABLE_MULTICAST_SCOPES[..])
}

/// Spec for SSM classification per RFC 4607 §1, RFC 7371 §4.1.2, and
/// RFC 3306 §6, with the `ff2` and `rsvd` nibbles ignored upon receipt
/// (RFC 7371 §4.1.1, RFC 3956 §3).
fn spec_is_ssm(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0] == 232,
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let flags = (bits >> 116) & 0xf;
            let plen = (bits >> 96) & 0xff;
            bits >> 120 == 0xff && flags & 0x7 == 0x3 && plen == 0
        }
    }
}

/// Spec for an IPv4 group per RFC 1112 §4 and RFC 4607 §4.3.
fn spec_group_v4(addr: Ipv4Addr) -> Result<(), ExternalMulticastIpError> {
    let ip = IpAddr::V4(addr);
    if addr.octets()[0] & 0xf0 != 0xe0 {
        return Err(ExternalMulticastIpError::NotMulticast(ip));
    }
    if addr.octets() == [224, 0, 0, 0] {
        return Err(ExternalMulticastIpError::ReservedBaseAddress(ip));
    }
    if addr.octets() == [232, 0, 0, 0] {
        return Err(ExternalMulticastIpError::ReservedSsmNull(ip));
    }
    Ok(())
}

/// Spec for the RP address embedded in a group per RFC 3956 §3 and §4.
fn spec_embedded_rp(addr: Ipv6Addr, plen: u32, riid: u16) -> Ipv6Addr {
    let prefix = (u128::from(addr) >> 32) as u64;
    let mask = if plen == 0 { 0 } else { u64::MAX << (64 - plen) };
    Ipv6Addr::from((u128::from(prefix & mask) << 64) | u128::from(riid))
}

/// Spec for a usable RP address per RFC 3956 §4 and §10.
fn spec_rp_usable(rp: Ipv6Addr) -> bool {
    rp.segments()[0] != 0 && !rp.is_unicast_link_local() && !rp.is_multicast()
}

/// Spec for an IPv6 group per RFC 4291 §2.7, RFC 3306 §4, RFC 3956 §3,
/// RFC 4607 §4.3, and RFC 7371 §4, plus the Oxide `ff04::/64` internal
/// underlay reservation.
fn spec_group_v6(addr: Ipv6Addr) -> Result<(), ExternalMulticastIpError> {
    let ip = IpAddr::V6(addr);
    let bits = u128::from(addr);
    if bits >> 120 != 0xff {
        return Err(ExternalMulticastIpError::NotMulticast(ip));
    }
    match (bits >> 112) & 0xf {
        0 => return Err(ExternalMulticastIpError::ReservedIpv6Scope(ip)),
        1 | 2 => return Err(ExternalMulticastIpError::LocalIpv6Scope(ip)),
        _ => {}
    }
    if bits >> 64 == 0xff04_0000_0000_0000 {
        return Err(ExternalMulticastIpError::ReservedUnderlaySubnet(ip));
    }
    let flags = (bits >> 116) & 0xf;
    if flags == 0 && bits & ((1u128 << 112) - 1) == 0 {
        return Err(ExternalMulticastIpError::ReservedBaseAddress(ip));
    }
    let r_flag = flags & 0x4 != 0;
    let p_flag = flags & 0x2 != 0;
    let t_flag = flags & 0x1 != 0;
    let plen = ((bits >> 96) & 0xff) as u32;
    let riid = ((bits >> 104) & 0xf) as u16;
    let rp_err = |reason| {
        Err(ExternalMulticastIpError::MalformedEmbeddedRp { addr: ip, reason })
    };

    if r_flag {
        if !p_flag {
            return rp_err(InvalidEmbeddedRp::RequiresPrefixBased);
        }
        if !t_flag {
            return rp_err(InvalidEmbeddedRp::RequiresTransient);
        }
        if !(1..=64).contains(&plen) {
            return rp_err(InvalidEmbeddedRp::PrefixLengthOutOfRange(
                plen as u8,
            ));
        }
        if riid == 0 {
            return rp_err(InvalidEmbeddedRp::ZeroInterfaceId);
        }
        let rp = spec_embedded_rp(addr, plen, riid);
        if !spec_rp_usable(rp) {
            return rp_err(InvalidEmbeddedRp::UnusableAddress(rp));
        }
    } else if p_flag && !t_flag {
        return Err(ExternalMulticastIpError::MalformedPrefixBased {
            addr: ip,
        });
    }

    let network_prefix = (bits >> 32) as u64;
    let group_id = bits as u32;

    if spec_is_ssm(ip) && network_prefix == 0 && group_id == 0x4000_0000 {
        return Err(ExternalMulticastIpError::ReservedSsmNull(ip));
    }
    Ok(())
}

/// Spec for the Oxide underlay multicast subnet `ff04::/64`.
fn spec_underlay(addr: Ipv6Addr) -> bool {
    u128::from(addr) >> 64 == 0xff04_0000_0000_0000
}

/// Spec for an IPv4 (S,G) source per RFC 919 §7, RFC 1122 §3.2.1.3,
/// RFC 3927, and RFC 6890.
fn spec_source_v4(addr: Ipv4Addr) -> Result<(), MulticastSourceError> {
    if addr.is_multicast() {
        return Err(MulticastSourceError::NotUnicast(IpAddr::V4(addr)));
    }
    let first_octet = addr.octets()[0];
    let reason = if addr.is_unspecified() {
        InvalidMulticastSource::Unspecified
    } else if addr.is_loopback() {
        InvalidMulticastSource::Loopback
    } else if addr.is_broadcast() {
        InvalidMulticastSource::Broadcast
    } else if addr.is_link_local() {
        InvalidMulticastSource::LinkLocal
    } else if first_octet == 0 {
        InvalidMulticastSource::ThisNetwork
    } else if first_octet >= 240 {
        InvalidMulticastSource::Reserved
    } else {
        return Ok(());
    };
    Err(MulticastSourceError::InvalidIpv4 { addr, reason })
}

/// Spec for an IPv6 (S,G) source per RFC 4291 §2.5.
fn spec_source_v6(addr: Ipv6Addr) -> Result<(), MulticastSourceError> {
    if addr.is_multicast() {
        return Err(MulticastSourceError::NotUnicast(IpAddr::V6(addr)));
    }
    let embedded =
        |form| Err(MulticastSourceError::Ipv4Embedded { addr, form });
    let reason = if addr.is_unspecified() {
        InvalidMulticastSource::Unspecified
    } else if addr.is_loopback() {
        InvalidMulticastSource::Loopback
    } else if addr.is_unicast_link_local() {
        InvalidMulticastSource::LinkLocal
    } else if addr.to_ipv4_mapped().is_some() {
        return embedded(EmbeddedIpv4::Mapped);
    } else if u128::from(addr) >> 32 == 0 {
        return embedded(EmbeddedIpv4::Compatible);
    } else {
        return Ok(());
    };
    Err(MulticastSourceError::InvalidIpv6 { addr, reason })
}

/// Generate candidate IPv4 bits biased toward 224/4, 224.0.0.0, 232.0.0.0,
/// and the class E block above 224/4.
fn group_v4_candidate_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        any::<u32>(),
        // 224.0.0.0/4, multicast
        0xe000_0000u32..=0xefff_ffff,
        // 224.0.0.0, reserved base address
        Just(0xe000_0000u32),
        // 232.0.0.0, SSM null address
        Just(0xe800_0000u32),
        // 224.0.0.0/24, local network control block
        0xe000_0000u32..=0xe000_00ff,
        // 232.0.0.0/24, SSM block reserved for IANA allocation
        0xe800_0000u32..=0xe800_00ff,
        // 240.0.0.0/4, class E
        0xf000_0000u32..=u32::MAX,
    ]
}

/// Generate an IPv6 group from independently chosen flags, scope, `rsvd`,
/// RIID, prefix length, network prefix, and group ID fields.
#[derive(Debug, Arbitrary)]
struct GroupV6Case {
    #[strategy(0u16..=0xf)]
    flags: u16,
    #[strategy(0u16..=0xf)]
    scope: u16,
    #[strategy(0u16..=0xf)]
    rsvd: u16,
    #[strategy(0u16..=0xf)]
    riid: u16,
    #[strategy(prop_oneof![
        Just(0u16),
        Just(16u16),
        Just(32u16),
        Just(48u16),
        Just(64u16),
        Just(65u16),
        1u16..=64,
        65u16..=255,
    ])]
    plen: u16,
    #[strategy(prop_oneof![Just([0u16; 4]), any::<[u16; 4]>()])]
    prefix: [u16; 4],
    #[strategy(prop_oneof![Just(0x4000_0000u32), Just(0u32), any::<u32>()])]
    group_id: u32,
}

impl GroupV6Case {
    fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            0xff00 | (self.flags << 4) | self.scope,
            (self.rsvd << 12) | (self.riid << 8) | self.plen,
            self.prefix[0],
            self.prefix[1],
            self.prefix[2],
            self.prefix[3],
            (self.group_id >> 16) as u16,
            self.group_id as u16,
        )
    }
}

/// Generate an embedded-RP group (i.e., R, P, and T flags set) whose derived RP
/// address is biased toward the `::/16`, link-local, and multicast boundaries
/// of `spec_rp_usable`, with the RP interface ID biased toward zero.
#[derive(Debug, Arbitrary)]
struct EmbeddedRpCase {
    #[strategy(proptest::sample::select(&[0x7u16, 0xf][..]))]
    flags: u16,
    #[strategy(usable_scope_strategy())]
    scope: u8,
    #[strategy(0u16..=0xf)]
    rsvd: u16,
    #[strategy(prop_oneof![Just(0u16), 1u16..=0xf])]
    riid: u16,
    #[strategy(prop_oneof![
        Just(0u16),
        Just(16u16),
        Just(32u16),
        Just(48u16),
        Just(64u16),
        Just(65u16),
        1u16..=64,
    ])]
    plen: u16,
    #[strategy(prop_oneof![
        Just(0u16),
        0xfe00u16..=0xfe7f,
        0xfe80u16..=0xfebf,
        0xfec0u16..=0xfeff,
        0xff00u16..=0xffff,
        any::<u16>(),
    ])]
    prefix_first: u16,
    prefix_rest: [u16; 3],
    group_id: u32,
}

impl EmbeddedRpCase {
    fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            0xff00 | (self.flags << 4) | u16::from(self.scope),
            (self.rsvd << 12) | (self.riid << 8) | self.plen,
            self.prefix_first,
            self.prefix_rest[0],
            self.prefix_rest[1],
            self.prefix_rest[2],
            (self.group_id >> 16) as u16,
            self.group_id as u16,
        )
    }
}

/// Generate candidate IPv6 addresses biased toward the group rules:
/// independent fields, embedded RP, `ff04::/64` (including `ff04::`, which
/// is also a base address), the `ff0x::` base addresses, and the SSM null
/// addresses `ff3x::4000:0` and `ffbx::4000:0`, with and without nonzero
/// `rsvd` and RIID nibbles.
fn group_v6_candidate_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        6 => any::<GroupV6Case>().prop_map(|case| case.addr()),
        2 => any::<EmbeddedRpCase>().prop_map(|case| case.addr()),
        1 => any::<u64>().prop_map(|low| {
            Ipv6Addr::from((0xff04u128 << 112) | u128::from(low))
        }),
        1 => Just(Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 0)),
        1 => (0u16..=0xf).prop_map(|scope| {
            Ipv6Addr::new(0xff00 | scope, 0, 0, 0, 0, 0, 0, 0)
        }),
        1 => (proptest::sample::select(&[0x3u16, 0xb][..]), 0u16..=0xf)
            .prop_map(|(flags, scope)| {
                Ipv6Addr::new(
                    0xff00 | (flags << 4) | scope,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0x4000,
                    0,
                )
            }),
        1 => (
            proptest::sample::select(&[0x3u16, 0xb][..]),
            0u16..=0xf,
            0u16..=0xf,
            0u16..=0xf,
        )
            .prop_map(|(flags, scope, rsvd, riid)| {
                Ipv6Addr::new(
                    0xff00 | (flags << 4) | scope,
                    (rsvd << 12) | (riid << 8),
                    0,
                    0,
                    0,
                    0,
                    0x4000,
                    0,
                )
            }),
        1 => any::<u128>().prop_map(Ipv6Addr::from),
    ]
}

/// Generate candidate IPv4 bits biased toward the source rule blocks.
fn source_v4_candidate_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![
        any::<u32>(),
        // 0.0.0.0/8 -> this host on this network
        0u32..=0x00ff_ffff,
        // 0.0.0.0, unspecified
        Just(0u32),
        // 127.0.0.0/8, loopback
        0x7f00_0000u32..=0x7fff_ffff,
        // 169.254.0.0/16, link-local
        0xa9fe_0000u32..=0xa9fe_ffff,
        // 240.0.0.0/4, class E
        0xf000_0000u32..=u32::MAX,
        // 255.255.255.255, limited broadcast
        Just(u32::MAX),
        // 224.0.0.0/4, multicast
        0xe000_0000u32..=0xefff_ffff,
        // 10.0.0.0/8, private (RFC 1918) and accepted
        0x0a00_0000u32..=0x0aff_ffff,
    ]
}

/// Generate candidate IPv6 addresses biased toward the source rule blocks.
fn source_v6_candidate_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        any::<u128>(),
        // `::`, unspecified
        Just(0u128),
        // `::1`, loopback
        Just(1u128),
        // `fe80::/10`, link-local
        any::<u128>().prop_map(|bits| (0xfe80u128 << 112) | (bits >> 10)),
        // `::ffff:0:0/96`, IPv4-mapped
        any::<u32>().prop_map(|ipv4| (0xffffu128 << 32) | u128::from(ipv4)),
        // `::/96`, IPv4-compatible
        any::<u32>().prop_map(u128::from),
        // `ff00::/8`, multicast
        any::<u128>().prop_map(|bits| (0xffu128 << 120) | (bits >> 8)),
        // `fc00::/7`, unique local (RFC 4193) and accepted
        any::<u128>().prop_map(|bits| (0xfcu128 << 120) | (bits >> 7)),
        // `64:ff9b::/96`, NAT64 well-known prefix (RFC 6052) and accepted
        any::<u32>().prop_map(|ipv4| (0x64_ff9bu128 << 96) | u128::from(ipv4)),
    ]
    .prop_map(Ipv6Addr::from)
}

/// Generate addresses biased toward the SSM ranges and their flag and
/// prefix-length neighbors.
fn ssm_candidate_strategy() -> impl Strategy<Value = IpAddr> {
    let flags = prop_oneof![Just(0x3u16), Just(0xbu16), 0u16..=0xf];
    let plen = prop_oneof![Just(0u16), 0u16..=0xff];
    prop_oneof![
        any::<u32>().prop_map(|bits| IpAddr::V4(Ipv4Addr::from(bits))),
        (0u32..=0x00ff_ffff)
            .prop_map(|low| IpAddr::V4(Ipv4Addr::from(0xe800_0000 | low))),
        (flags, 0u16..=0xf, any::<u8>(), plen, any::<[u16; 6]>()).prop_map(
            |(flags, scope, seg1_high, plen, segs)| {
                IpAddr::V6(Ipv6Addr::new(
                    0xff00 | (flags << 4) | scope,
                    (u16::from(seg1_high) << 8) | plen,
                    segs[0],
                    segs[1],
                    segs[2],
                    segs[3],
                    segs[4],
                    segs[5],
                ))
            }
        ),
        any::<u128>().prop_map(|bits| IpAddr::V6(Ipv6Addr::from(bits))),
    ]
}

/// Generate candidate IPv6 addresses inside, near, and outside `ff04::/64`.
fn underlay_candidate_strategy() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        any::<u64>().prop_map(|low| (0xff04u128 << 112) | u128::from(low)),
        (1u64..(1 << 48), any::<u64>()).prop_map(|(mid, low)| {
            (0xff04u128 << 112) | (u128::from(mid) << 64) | u128::from(low)
        }),
        (any::<u16>(), any::<u64>()).prop_map(|(first, low)| {
            (u128::from(first) << 112) | u128::from(low)
        }),
        any::<u128>(),
    ]
    .prop_map(Ipv6Addr::from)
}

/// Property: `UnderlayMulticastIpv6::new` accepts an input iff
/// `spec_underlay` accepts it, and deserialization round-trips to the
/// constructed value
#[proptest]
fn prop_underlay_matches_spec(
    #[strategy(underlay_candidate_strategy())] addr: Ipv6Addr,
) {
    let got = UnderlayMulticastIpv6::new(addr);
    prop_assert_eq!(
        got.is_ok(),
        spec_underlay(addr),
        "{}: construction disagrees with spec",
        addr
    );
    prop_assert_eq!(
        json_round_trip(&addr, UnderlayMulticastIpv6::ip)?,
        got.as_ref().ok().map(UnderlayMulticastIpv6::ip),
        "{}: deserialization disagrees with construction",
        addr
    );
}

/// Property: `ExternalMulticastIp::new` and `spec_group_v4` provide the same
/// outcome, including the error variant, and deserialization round-trips to
/// the constructed value
#[proptest]
fn prop_group_v4_matches_spec(
    #[strategy(group_v4_candidate_strategy())]
    #[map(Ipv4Addr::from)]
    addr: Ipv4Addr,
) {
    let got = ExternalMulticastIp::new(IpAddr::V4(addr));
    let want = spec_group_v4(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_round_trip(&IpAddr::V4(addr), ExternalMulticastIp::ip)?,
        got.as_ref().ok().map(ExternalMulticastIp::ip),
        "{}: deserialization disagrees with construction",
        addr
    );
}

/// Property: `ExternalMulticastIp::new` and `spec_group_v6` provide the same
/// outcome, including the error variant, and deserialization round-trips to
/// the constructed value
#[proptest]
fn prop_group_v6_matches_spec(
    #[strategy(group_v6_candidate_strategy())] addr: Ipv6Addr,
) {
    let got = ExternalMulticastIp::new(IpAddr::V6(addr));
    let want = spec_group_v6(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_round_trip(&IpAddr::V6(addr), ExternalMulticastIp::ip)?,
        got.as_ref().ok().map(ExternalMulticastIp::ip),
        "{}: deserialization disagrees with construction",
        addr
    );
}

/// Property: `UnicastAddrV4::new` and `spec_source_v4` provide the same
/// outcome, including the error variant and its variant-order precedence,
/// and deserialization round-trips to the constructed value
#[proptest]
fn prop_source_v4_matches_spec(
    #[strategy(source_v4_candidate_strategy())]
    #[map(Ipv4Addr::from)]
    addr: Ipv4Addr,
) {
    let got = UnicastAddrV4::new(addr);
    let want = spec_source_v4(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_round_trip(&addr, UnicastAddrV4::ip)?,
        got.as_ref().ok().map(UnicastAddrV4::ip),
        "{}: deserialization disagrees with construction",
        addr
    );
}

/// Property: `UnicastAddrV6::new` and `spec_source_v6` provide the same
/// outcome, including the error variant and its variant-order precedence,
/// and deserialization round-trips to the constructed value
#[proptest]
fn prop_source_v6_matches_spec(
    #[strategy(source_v6_candidate_strategy())] addr: Ipv6Addr,
) {
    let got = UnicastAddrV6::new(addr);
    let want = spec_source_v6(addr);
    prop_assert_eq!(outcome(&got), outcome(&want), "{}", addr);
    prop_assert_eq!(
        json_round_trip(&addr, UnicastAddrV6::ip)?,
        got.as_ref().ok().map(UnicastAddrV6::ip),
        "{}: deserialization disagrees with construction",
        addr
    );
}

/// Property: `is_ssm_address` matches `spec_is_ssm`
#[proptest]
fn prop_is_ssm_matches_spec(
    #[strategy(ssm_candidate_strategy())] addr: IpAddr,
) {
    prop_assert_eq!(is_ssm_address(addr), spec_is_ssm(addr), "{}", addr);
}

/// Spec for a multicast tag: 1 to 80 bytes, each an ASCII alphanumeric
/// character or one of `-`, `_`, `:`, and `.`.
fn spec_tag(tag: &str) -> bool {
    (1..=80).contains(&tag.len())
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
}

/// Generate candidate tags biased toward the length bounds and the allowed
/// character set.
fn tag_candidate_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[a-zA-Z0-9_.:-]{1,80}",
        "[a-zA-Z0-9_.:-]{81,100}",
        "[a-zA-Z0-9_.:-]{0,40}[^a-zA-Z0-9_.:-][a-zA-Z0-9_.:-]{0,39}",
        Just(String::new()),
        Just("a".repeat(MAX_TAG_LENGTH)),
        Just("a".repeat(MAX_TAG_LENGTH + 1)),
    ]
}

/// Property: parsing a `MulticastTag` succeeds iff the spec accepts the tag,
/// and deserialization round-trips to the parsed value
#[proptest]
fn prop_tag_matches_spec(#[strategy(tag_candidate_strategy())] tag: String) {
    let got = tag.parse::<MulticastTag>();
    prop_assert_eq!(got.is_ok(), spec_tag(&tag), "{:?}", tag);
    prop_assert_eq!(
        json_round_trip(&tag, |t: &MulticastTag| t.as_ref().to_string())?,
        got.ok().map(String::from),
        "{:?}: deserialization disagrees with parsing",
        tag
    );
}
