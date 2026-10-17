// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Validation and conversions for the multicast types re-exported by
//! [`crate::latest::mcast`].
//!
//! Most of this module is centered on address validation. IPv4 excludes the
//! reserved base address of `224.0.0.0` ([RFC 1112] §4) and the SSM null
//! address. IPv6 rejects reserved scope `0x0`, the interface-local and
//! link-local scopes that routers must not forward past ([RFC 4291] §2.7),
//! the reserved base addresses `ff0x::` ([RFC 4291] §2.7.1), and the
//! internally reserved underlay subnet `ff04::/64`. IPv6 then checks the
//! prefix-based and embedded rendezvous point (RP) flag rules of [RFC 3306]
//! and [RFC 3956] (as updated by [RFC 7371]), and the SSM null channel of
//! [RFC 4607] §4.3.
//!
//! Exact source addresses follow the rule set of OPTE's source validator, as
//! described on [`crate::latest::mcast::ExactSource`].
//!
//! [RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112.html
//! [RFC 3306]: https://www.rfc-editor.org/rfc/rfc3306.html
//! [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
//! [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
//! [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use omicron_common::address::{IPV4_SSM_SUBNET, UNDERLAY_MULTICAST_SUBNET};

use crate::latest::mcast::{
    AsmMulticastGroupCreate, EmbeddedIpv4, Error, ExactSource,
    ExternalForwarding, ExternalInternalForwarding, ExternalMulticastIp,
    ExternalMulticastIpError, InvalidMulticastSource, IpSrc,
    MulticastGroupCreateExternalEntry, MulticastGroupCreateExternalError,
    MulticastGroupResponse, MulticastTag, NonEmptyExactSources, SourceEntry,
    SourceFilter, SsmMulticastGroupCreate, SsmMulticastIp,
    UnderlayMulticastIpv6,
};

/// Maximum length for multicast tags.
pub const MAX_TAG_LENGTH: usize = 80;

/// Error parsing a multicast tag from a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MulticastTagParseError(pub(crate) String);

impl UnderlayMulticastIpv6 {
    /// Create a new UnderlayMulticastIpv6 if the address is within the
    /// underlay multicast subnet (ff04::/64).
    pub fn new(addr: Ipv6Addr) -> Result<Self, Error> {
        if !UNDERLAY_MULTICAST_SUBNET.contains(addr) {
            return Err(Error::InvalidUnderlayMulticastIp(addr));
        }
        Ok(Self(addr))
    }
}

impl From<UnderlayMulticastIpv6> for IpAddr {
    fn from(addr: UnderlayMulticastIpv6) -> Self {
        IpAddr::V6(addr.0)
    }
}

impl fmt::Display for UnderlayMulticastIpv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for UnderlayMulticastIpv6 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: Ipv6Addr = s
            .parse()
            .map_err(|e| Error::InvalidIpv6Address(s.to_string(), e))?;
        Self::new(addr)
    }
}

impl FromStr for ExternalMulticastIp {
    type Err = ExternalMulticastIpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: IpAddr = s.parse().map_err(|e| {
            ExternalMulticastIpError::InvalidIpAddress(s.to_string(), e)
        })?;
        Self::new(addr)
    }
}

impl FromStr for ExactSource {
    type Err = MulticastGroupCreateExternalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: IpAddr = s.parse().map_err(|e| {
            MulticastGroupCreateExternalError::InvalidSourceIpAddress(
                s.to_string(),
                e,
            )
        })?;
        Self::new(addr)
    }
}

const IPV4_RESERVED_BASE: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 0);
const IPV4_SSM_RESERVED_NULL: Ipv4Addr = Ipv4Addr::new(232, 0, 0, 0);
const IPV6_SSM_NULL_GROUP_ID: u32 = 0x4000_0000;
const IPV6_SCOPE_MASK: u16 = 0x000f;
const IPV6_SCOPE_RESERVED_ZERO: u16 = 0x0;
const IPV6_SCOPE_INTERFACE_LOCAL: u16 = 0x1;
const IPV6_SCOPE_LINK_LOCAL: u16 = 0x2;

// Flags field: the nibble above scope (RFC 4291 §2.7).

const IPV6_FLAGS_SHIFT: u16 = 4;
const IPV6_FLAGS_MASK: u16 = 0xf;
const IPV6_FLAG_TRANSIENT: u16 = 0x1;
const IPV6_FLAG_PREFIX_BASED: u16 = 0x2;
const IPV6_FLAG_EMBEDDED_RP: u16 = 0x4;
const IPV6_RIID_SHIFT: u16 = 8;
const IPV6_RIID_MASK: u16 = 0xf;
const IPV6_PREFIX_BASED_PLEN_MASK: u16 = 0xff;
const IPV6_PREFIX_BASED_MAX_PLEN: u16 = 64;

// Reasons an embedded-Rendezvous Point (RP) address gets rejected
// (RFC 7371 §4.2.2, §4.2.3; RFC 3956 §4, §6.3, §10).

const RP_REQUIRES_PREFIX_BASED: &str = "the P flag is required";
const RP_REQUIRES_TRANSIENT: &str = "the T flag is required";
const RP_PLEN_OUT_OF_RANGE: &str =
    "the prefix length must be from 1 through 64";
const RP_RIID_ZERO: &str = "the RP interface ID must be nonzero";
const RP_UNUSABLE_ADDRESS: &str =
    "the derived RP address is in ::/16, link-local, or multicast space";

// SSM flag pattern: R=0, P=T=1 (RFC 7371 §4.1.2).
const IPV6_SSM_PREFIX: u16 = 0xff30;
const IPV6_SSM_PREFIX_MASK: u16 = 0xff70;

fn embedded_rendezvous_point_address(
    segs: [u16; 8],
    plen: u16,
    riid: u16,
) -> Ipv6Addr {
    let mut rp = [0u16; 8];
    for (index, segment) in segs[2..6].iter().enumerate() {
        let offset = (index as u16) * 16;
        rp[index] = if offset >= plen {
            0
        } else if offset + 16 > plen {
            segment & (!0u16 << (16 - (plen - offset)))
        } else {
            *segment
        };
    }
    rp[7] = riid;
    Ipv6Addr::from(rp)
}

fn is_usable_rendezvous_point_address(rp: Ipv6Addr) -> bool {
    let first = rp.segments()[0];
    first != 0 && first & 0xffc0 != 0xfe80 && first >> 8 != 0xff
}

const fn ipv6_segments_are_ssm(segs: [u16; 8]) -> bool {
    segs[0] & IPV6_SSM_PREFIX_MASK == IPV6_SSM_PREFIX
        && segs[1] & IPV6_PREFIX_BASED_PLEN_MASK == 0
}

/// Reject an address that cannot identify an external multicast group.
///
/// This enforces the RFC constraints on the address, plus one Oxide allocation
/// rule: the underlay subnet `ff04::/64` belongs to the internal multicast API.
///
/// See [`crate::v14::mcast::ExternalMulticastIp`] for the constraints and
/// their citations.
pub(crate) fn validate_external_multicast_ip(
    addr: IpAddr,
) -> Result<(), ExternalMulticastIpError> {
    if !addr.is_multicast() {
        return Err(ExternalMulticastIpError::NotMulticast(addr));
    }

    if let IpAddr::V6(ipv6) = addr {
        let segs = ipv6.segments();
        match segs[0] & IPV6_SCOPE_MASK {
            IPV6_SCOPE_RESERVED_ZERO => {
                return Err(ExternalMulticastIpError::ReservedIpv6Scope(addr));
            }
            IPV6_SCOPE_INTERFACE_LOCAL | IPV6_SCOPE_LINK_LOCAL => {
                return Err(ExternalMulticastIpError::LocalIpv6Scope(addr));
            }
            _ => {}
        }

        if UNDERLAY_MULTICAST_SUBNET.contains(ipv6) {
            return Err(ExternalMulticastIpError::ReservedUnderlaySubnet(addr));
        }

        // With P set, the low octet of the 2nd segment is the prefix length.
        //
        // See RFC 3306 §4 and RFC 7371 §4.1.1.
        let flags = (segs[0] >> IPV6_FLAGS_SHIFT) & IPV6_FLAGS_MASK;
        let plen = segs[1] & IPV6_PREFIX_BASED_PLEN_MASK;

        if flags == 0 && segs[1..].iter().all(|seg| *seg == 0) {
            return Err(ExternalMulticastIpError::ReservedBaseAddress(addr));
        }

        if flags & IPV6_FLAG_EMBEDDED_RP != 0 {
            let riid = (segs[1] >> IPV6_RIID_SHIFT) & IPV6_RIID_MASK;
            let malformed = |reason| {
                Err(ExternalMulticastIpError::MalformedEmbeddedRp {
                    addr,
                    reason,
                })
            };

            if flags & IPV6_FLAG_PREFIX_BASED == 0 {
                return malformed(RP_REQUIRES_PREFIX_BASED);
            }
            if flags & IPV6_FLAG_TRANSIENT == 0 {
                return malformed(RP_REQUIRES_TRANSIENT);
            }
            if plen == 0 || plen > IPV6_PREFIX_BASED_MAX_PLEN {
                return malformed(RP_PLEN_OUT_OF_RANGE);
            }
            if riid == 0 {
                return malformed(RP_RIID_ZERO);
            }
            if !is_usable_rendezvous_point_address(
                embedded_rendezvous_point_address(segs, plen, riid),
            ) {
                return malformed(RP_UNUSABLE_ADDRESS);
            }
        } else if flags & IPV6_FLAG_PREFIX_BASED != 0
            && flags & IPV6_FLAG_TRANSIENT == 0
        {
            return Err(ExternalMulticastIpError::MalformedPrefixBased {
                addr,
            });
        }

        // RFC 3306 §6 places the zero network prefix requirement on the node
        // that forms an address, and RFC 4607 §1 has the system treat all of
        // the ff3x::/32 block as SSM. The prefix matters only for the reserved
        // null address ff3x::4000:0 (RFC 4607 §4.3), the one SSM destination
        // rejected here. Group IDs below 0x4000_0000 are assigned with P=T=0
        // (RFC 3307 §4.1), making them invalid SSM addresses that a router may
        // drop (RFC 4607 §1). 0x4000_0001 through 0x7fff_ffff are reserved for
        // IANA allocation (RFC 3307 §4.2), and 0x8000_0000 and above are the
        // dynamic range (RFC 3307 §4.3), which RFC 10028 §3 partitions, with
        // host SSM allocation at 0xf000_0000 through 0xfcff_ffff.
        if ipv6_segments_are_ssm(segs) {
            let within_prefix =
                segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0;
            let group_id = (u32::from(segs[6]) << 16) | u32::from(segs[7]);
            if within_prefix && group_id == IPV6_SSM_NULL_GROUP_ID {
                return Err(ExternalMulticastIpError::InvalidIpv6Ssm(addr));
            }
        }
    }

    if let IpAddr::V4(ipv4) = addr {
        if ipv4 == IPV4_RESERVED_BASE {
            return Err(ExternalMulticastIpError::ReservedBaseAddress(addr));
        }
        if ipv4 == IPV4_SSM_RESERVED_NULL {
            return Err(ExternalMulticastIpError::ReservedSsmNull(addr));
        }
    }

    Ok(())
}

/// Check whether an address is a source-specific multicast one.
///
/// IPv4 is all of `232.0.0.0/8` ([RFC 4607] §1). IPv6 is `ff3x::/32` or
/// `ffbx::/32` with a zero prefix length; the `ff2` and `rsvd` nibbles are
/// ignored ([RFC 7371] §4.1.1, §4.1.2; [RFC 3956] §3).
///
/// [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
/// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
pub(crate) fn is_ssm_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ipv4) => IPV4_SSM_SUBNET.contains(ipv4),
        IpAddr::V6(ipv6) => ipv6_segments_are_ssm(ipv6.segments()),
    }
}

const IPV4_SOURCE_RESERVED_FIRST_OCTET: u8 = 240;

/// Reject a source address that cannot appear in a source filter.
///
/// A source must be unicast and routable. IPv4 excludes loopback, broadcast
/// ([RFC 919] §7), the unspecified address, link-local ([RFC 3927]),
/// `0.0.0.0/8` ([RFC 1122] §3.2.1.3), and `240.0.0.0/4` ([RFC 1112] §4).
/// IPv6 excludes loopback, the unspecified address, link-local
/// ([RFC 4291] §2.5.6), and the IPv4-mapped ([RFC 4291] §2.5.5.2) and
/// IPv4-compatible ([RFC 4291] §2.5.5.1) forms.
///
/// [RFC 919]: https://www.rfc-editor.org/rfc/rfc919.html
/// [RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112.html
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122.html
/// [RFC 3927]: https://www.rfc-editor.org/rfc/rfc3927.html
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
pub(crate) fn validate_exact_source(
    ip: IpAddr,
) -> Result<(), MulticastGroupCreateExternalError> {
    if ip.is_multicast() {
        return Err(MulticastGroupCreateExternalError::SourceNotUnicast(ip));
    }

    match ip {
        IpAddr::V4(addr) => {
            let reason = match addr.octets() {
                [0, 0, 0, 0] => InvalidMulticastSource::Unspecified,
                [127, ..] => InvalidMulticastSource::Loopback,
                [255, 255, 255, 255] => InvalidMulticastSource::Broadcast,
                [169, 254, ..] => InvalidMulticastSource::LinkLocal,
                [0, ..] => InvalidMulticastSource::ThisNetwork,
                [IPV4_SOURCE_RESERVED_FIRST_OCTET..=u8::MAX, ..] => {
                    InvalidMulticastSource::Reserved
                }
                _ => return Ok(()),
            };
            Err(MulticastGroupCreateExternalError::InvalidIpv4Source {
                addr,
                reason,
            })
        }
        IpAddr::V6(addr) => {
            let embedded = |form| {
                Err(MulticastGroupCreateExternalError::Ipv4EmbeddedSource {
                    addr,
                    form,
                })
            };
            let reason = match addr.segments() {
                [0, 0, 0, 0, 0, 0, 0, 0] => InvalidMulticastSource::Unspecified,
                [0, 0, 0, 0, 0, 0, 0, 1] => InvalidMulticastSource::Loopback,
                [0xfe80..=0xfebf, ..] => InvalidMulticastSource::LinkLocal,
                [0, 0, 0, 0, 0, 0xffff, ..] => {
                    return embedded(EmbeddedIpv4::Mapped);
                }
                [0, 0, 0, 0, 0, 0, ..] => {
                    return embedded(EmbeddedIpv4::Compatible);
                }
                _ => return Ok(()),
            };
            Err(MulticastGroupCreateExternalError::InvalidIpv6Source {
                addr,
                reason,
            })
        }
    }
}

/// A request's sources whether in ASM or SSM structure, driven by its
/// group address.
pub(crate) enum RequestSources {
    /// Any-source group, with the filter already canonicalized.
    Asm(SourceFilter),
    /// Source-specific group, carrying the narrowed address alongside the
    /// sources that [RFC 4607] requires it to have.
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    Ssm { group_ip: SsmMulticastIp, sources: NonEmptyExactSources },
}

impl RequestSources {
    /// Disambiguate a create request into its any-source (ASM) or
    /// source-specific (SSM) structure, validating each source against the
    /// group address.
    ///
    /// This rejects any source whose address family differs from the group's.
    /// An SSM group rejects an `Any` entry and requires at least one exact
    /// source, since routers must ignore a request for an SSM destination
    /// that names no source ([RFC 4607] §2); an ASM group accepts either form.
    ///
    /// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
    pub(crate) fn new(
        group_ip: ExternalMulticastIp,
        sources: Option<&[SourceEntry]>,
    ) -> Result<Self, MulticastGroupCreateExternalError> {
        let group: IpAddr = group_ip.into();
        let sources = sources.unwrap_or_default();
        let has_any = sources.iter().any(|s| matches!(s, SourceEntry::Any));
        let exact = sources
            .iter()
            .filter_map(|source| match source {
                SourceEntry::Any => None,
                SourceEntry::Exact(source) => Some(*source),
            })
            .collect::<Vec<_>>();

        if let Some(source) =
            exact.iter().find(|source| source.ip().is_ipv4() != group.is_ipv4())
        {
            return Err(
                MulticastGroupCreateExternalError::SourceFamilyMismatch {
                    source_ip: source.ip(),
                    group,
                },
            );
        }

        match (SsmMulticastIp::new(group_ip), has_any) {
            (None, true) => Ok(Self::Asm(SourceFilter::Any)),
            (None, false) => Ok(Self::Asm(SourceFilter::from_exact(exact))),
            (Some(_), true) => Err(
                MulticastGroupCreateExternalError::SsmRejectsAnySource(group),
            ),
            (Some(group_ip), false) => NonEmptyExactSources::new(exact)
                .map(|sources| Self::Ssm { group_ip, sources })
                .ok_or(MulticastGroupCreateExternalError::SsmRequiresSources(
                    group,
                )),
        }
    }
}

impl From<&MulticastGroupCreateExternalEntry> for SourceFilter {
    /// Build the stored filter from a validated create request.
    fn from(entry: &MulticastGroupCreateExternalEntry) -> Self {
        match entry {
            MulticastGroupCreateExternalEntry::Asm(group) => {
                group.sources.clone()
            }
            MulticastGroupCreateExternalEntry::Ssm(group) => {
                Self::Exact(group.sources.clone())
            }
        }
    }
}

impl SourceFilter {
    /// Borrow the exact sources or `None` if the filter is unrestricted.
    pub fn exact_sources(&self) -> Option<&[ExactSource]> {
        match self {
            Self::Any => None,
            Self::Exact(sources) => Some(sources.as_slice()),
        }
    }

    /// Validate and canonicalize source entries against the given
    /// `group_ip`.
    ///
    /// Each entry has previously been validated on its own address.
    /// This checks only the address-family (mis-)match and the ASM/SSM
    /// disambiguation.
    ///
    /// # Errors
    ///
    /// Returns an [`MulticastGroupCreateExternalError`] if a source and the
    /// group IP use different address families, or if an SSM group requests
    /// an `Any`, or if it does not supply an exact source at all.
    pub fn from_entries(
        group_ip: ExternalMulticastIp,
        sources: Option<&[SourceEntry]>,
    ) -> Result<Self, MulticastGroupCreateExternalError> {
        Ok(match RequestSources::new(group_ip, sources)? {
            RequestSources::Asm(sources) => sources,
            RequestSources::Ssm { sources, .. } => Self::Exact(sources),
        })
    }

    /// Build a filter from the exact source list, collapsing an empty list
    /// into `Any`.
    pub fn from_exact(sources: impl IntoIterator<Item = ExactSource>) -> Self {
        match NonEmptyExactSources::new(sources.into_iter().collect()) {
            Some(sources) => Self::Exact(sources),
            None => Self::Any,
        }
    }

    /// Iterate over source entries.
    pub fn iter(&self) -> impl Iterator<Item = IpSrc> + '_ {
        let (any, exact) = match self {
            Self::Any => (Some(IpSrc::Any), [].as_slice()),
            Self::Exact(sources) => (None, sources.as_slice()),
        };
        any.into_iter().chain(exact.iter().copied().map(IpSrc::from))
    }

    /// Project the filter back into its serialized form.
    ///
    /// [`SourceFilter::Any`] emits an absent list, not an explicit
    /// `[Any]` one.
    ///
    /// A request that mixes `Any` with exact sources does not round-trip.
    pub fn to_ip_sources(&self) -> Option<Vec<IpSrc>> {
        match self {
            Self::Any => None,
            Self::Exact(sources) => Some(
                sources.as_slice().iter().copied().map(IpSrc::from).collect(),
            ),
        }
    }

    /// Project the source filter into the request's entry shape.
    ///
    /// [`SourceFilter::Any`] emits an absent list and not an explicit
    /// [`SourceEntry::Any`] one, as with
    /// [`SourceFilter::to_ip_sources`].
    pub fn to_entries(&self) -> Option<Vec<SourceEntry>> {
        match self {
            Self::Any => None,
            Self::Exact(sources) => Some(
                sources
                    .as_slice()
                    .iter()
                    .copied()
                    .map(SourceEntry::Exact)
                    .collect(),
            ),
        }
    }
}

impl AsmMulticastGroupCreate {
    /// Return the multicast group address.
    pub fn group_ip(&self) -> ExternalMulticastIp {
        self.group_ip
    }

    /// Return the requested tag, if present.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// Return the internal forwarding configuration.
    pub fn internal_forwarding(&self) -> &ExternalInternalForwarding {
        &self.internal_forwarding
    }

    /// Return the external forwarding configuration.
    pub fn external_forwarding(&self) -> &ExternalForwarding {
        &self.external_forwarding
    }

    /// Return the source filter in its serialized form.
    pub fn sources(&self) -> Option<Vec<IpSrc>> {
        self.sources.to_ip_sources()
    }

    /// Return exact sources, or `None` for an unrestricted filter.
    pub fn exact_sources(&self) -> Option<&[ExactSource]> {
        self.sources.exact_sources()
    }

    /// Return whether the group accepts every source address.
    pub fn allows_any_source(&self) -> bool {
        matches!(self.sources, SourceFilter::Any)
    }
}

impl SsmMulticastGroupCreate {
    /// Return the SSM group address.
    pub fn group_ip(&self) -> SsmMulticastIp {
        self.group_ip
    }

    /// Return the requested tag, if present.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// Return the internal forwarding configuration.
    pub fn internal_forwarding(&self) -> &ExternalInternalForwarding {
        &self.internal_forwarding
    }

    /// Return the external forwarding configuration.
    pub fn external_forwarding(&self) -> &ExternalForwarding {
        &self.external_forwarding
    }

    /// Return the exact source addresses.
    pub fn sources(&self) -> &[ExactSource] {
        self.sources.as_slice()
    }
}

impl MulticastGroupCreateExternalEntry {
    /// Return the multicast group address.
    pub fn group_ip(&self) -> ExternalMulticastIp {
        match self {
            Self::Asm(group) => group.group_ip,
            Self::Ssm(group) => group.group_ip.into(),
        }
    }

    /// Return the requested tag, if present.
    pub fn tag(&self) -> Option<&str> {
        match self {
            Self::Asm(group) => group.tag(),
            Self::Ssm(group) => group.tag(),
        }
    }

    /// Return the internal forwarding configuration.
    pub fn internal_forwarding(&self) -> &ExternalInternalForwarding {
        match self {
            Self::Asm(group) => group.internal_forwarding(),
            Self::Ssm(group) => group.internal_forwarding(),
        }
    }

    /// Return the external forwarding configuration.
    pub fn external_forwarding(&self) -> &ExternalForwarding {
        match self {
            Self::Asm(group) => group.external_forwarding(),
            Self::Ssm(group) => group.external_forwarding(),
        }
    }

    /// Return the source filter in its serialized form.
    pub fn sources(&self) -> Option<Vec<IpSrc>> {
        match self {
            Self::Asm(group) => group.sources.to_ip_sources(),
            Self::Ssm(group) => {
                Some(group.sources().iter().copied().map(IpSrc::from).collect())
            }
        }
    }
}

impl AsRef<str> for MulticastTag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<MulticastTag> for String {
    fn from(tag: MulticastTag) -> Self {
        tag.0
    }
}

impl From<String> for MulticastTag {
    fn from(tag: String) -> Self {
        MulticastTag(tag)
    }
}

impl fmt::Display for MulticastTagParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for MulticastTagParseError {}

impl FromStr for MulticastTag {
    type Err = MulticastTagParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(MulticastTagParseError(
                "tag cannot be empty".to_string(),
            ));
        }
        if s.len() > MAX_TAG_LENGTH {
            return Err(MulticastTagParseError(format!(
                "tag cannot exceed {MAX_TAG_LENGTH} bytes"
            )));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.')
        }) {
            return Err(MulticastTagParseError(
                "tag must contain only ASCII alphanumeric characters, hyphens, \
                 underscores, colons, or periods"
                    .to_string(),
            ));
        }
        Ok(MulticastTag(s.to_string()))
    }
}

impl MulticastGroupResponse {
    /// Return the multicast group IP address.
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Underlay(resp) => resp.group_ip.into(),
            Self::External(resp) => resp.group_ip.into(),
        }
    }

    /// Return the tag.
    pub fn tag(&self) -> &str {
        match self {
            Self::Underlay(resp) => &resp.tag,
            Self::External(resp) => &resp.tag,
        }
    }
}

impl fmt::Display for IpSrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSrc::Exact(ip) => write!(f, "{ip}"),
            IpSrc::Any => write!(f, "any"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::v14::mcast::MulticastGroupCreateExternalEntryShadow;

    #[test]
    fn tag_format() {
        let parse = |tag: &str| tag.parse::<MulticastTag>();

        // Valid tags
        assert!(parse("my-tag").is_ok());
        assert!(parse("nexus").is_ok());
        assert!(parse("a1b2c3").is_ok());
        assert!(parse("tag_with_underscore").is_ok());
        assert!(parse("tag.with.periods").is_ok());
        assert!(parse("tag:with:colons").is_ok());
        assert!(parse("mixed-tag_v1.0:test").is_ok());

        // Auto-generated tag format (uuid:ip)
        assert!(
            parse("550e8400-e29b-41d4-a716-446655440000:224.1.2.3").is_ok()
        );

        // Tag at exactly MAX_TAG_LENGTH characters is valid
        assert!(parse(&"a".repeat(MAX_TAG_LENGTH)).is_ok());

        // Empty tag rejected
        assert!(parse("").is_err());

        // Tag exceeding MAX_TAG_LENGTH characters rejected
        assert!(parse(&"a".repeat(MAX_TAG_LENGTH + 1)).is_err());

        // Invalid characters rejected
        assert!(parse("tag with spaces").is_err());
        assert!(parse("tag/with/slashes").is_err());
        assert!(parse("tag@with@at").is_err());
        assert!(parse("tag#with#hash").is_err());
    }

    #[test]
    fn accepts_ipv4_asm() {
        for addr in
            ["224.1.2.3", "239.255.255.250", "225.0.0.1", "231.255.255.255"]
        {
            let parsed = addr.parse::<ExternalMulticastIp>().unwrap();
            assert_eq!(IpAddr::from(parsed), addr.parse::<IpAddr>().unwrap());
        }
    }

    #[test]
    fn accepts_ipv4_ssm() {
        for addr in ["232.0.0.1", "232.1.2.3", "232.255.255.255"] {
            assert!(
                addr.parse::<ExternalMulticastIp>().is_ok(),
                "{addr} should be accepted"
            );
        }
    }

    #[test]
    fn accepts_admin_local_ipv6_outside_underlay_subnet() {
        for addr in ["ff04:1::1", "ff04::1:0:0:0:1", "ff14::1"] {
            assert!(
                addr.parse::<ExternalMulticastIp>().is_ok(),
                "{addr} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_non_multicast() {
        for addr in ["10.0.0.1", "192.168.1.1", "2001:db8::1", "::1"] {
            assert!(
                matches!(
                    addr.parse::<ExternalMulticastIp>(),
                    Err(ExternalMulticastIpError::NotMulticast(_))
                ),
                "{addr} should be rejected as non-multicast"
            );
        }
    }

    #[test]
    fn accepts_forwardable_ipv6_scopes() {
        for addr in [
            "ff03::1",
            "ff05::1",
            "ff06::1",
            "ff07::1",
            "ff08::1",
            "ff09::1",
            "ff0d::1",
            "ff0e::1",
            "ff0f::1",
            "ff3e::4000:1",
        ] {
            assert!(
                addr.parse::<ExternalMulticastIp>().is_ok(),
                "{addr} should be accepted"
            );
        }

        for addr in ["ff01::1", "ff02::1", "ff11::1", "ff32::4000:1"] {
            assert!(
                matches!(
                    addr.parse::<ExternalMulticastIp>(),
                    Err(ExternalMulticastIpError::LocalIpv6Scope(_))
                ),
                "{addr} should be rejected as an unforwardable scope"
            );
        }

        assert!(
            matches!(
                "ff00::1".parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::ReservedIpv6Scope(_))
            ),
            "ff00::1 should be rejected as reserved scope 0"
        );
    }

    #[test]
    fn rejects_underlay_subnet() {
        for addr in ["ff04::1", "ff04::ffff:ffff:ffff:ffff"] {
            assert!(
                matches!(
                    addr.parse::<ExternalMulticastIp>(),
                    Err(ExternalMulticastIpError::ReservedUnderlaySubnet(_))
                ),
                "{addr} should be rejected as underlay"
            );
        }
    }

    #[test]
    fn rejects_reserved_ssm_null() {
        assert!(
            matches!(
                "232.0.0.0".parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::ReservedSsmNull(_))
            ),
            "232.0.0.0 should be rejected as reserved"
        );
        for addr in ["232.0.0.1", "232.0.0.255", "232.0.1.0"] {
            assert!(
                addr.parse::<ExternalMulticastIp>().is_ok(),
                "{addr} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_malformed_embedded_rendezvous_point() {
        for (addr, expected) in [
            ("ff5e:140:2001:db8::1", RP_REQUIRES_PREFIX_BASED),
            ("ff6e:140:2001:db8::1", RP_REQUIRES_TRANSIENT),
            ("ff7e:100:2001:db8::1", RP_PLEN_OUT_OF_RANGE),
            ("ff7e:180:2001:db8::1", RP_PLEN_OUT_OF_RANGE),
            ("ff7e:40:2001:db8::1", RP_RIID_ZERO),
            ("ff7e:140::1", RP_UNUSABLE_ADDRESS),
            ("ff7e:140:fe80::1", RP_UNUSABLE_ADDRESS),
            ("ff7e:140:ff00::1", RP_UNUSABLE_ADDRESS),
        ] {
            match addr.parse::<ExternalMulticastIp>() {
                Err(ExternalMulticastIpError::MalformedEmbeddedRp {
                    reason,
                    ..
                }) => assert_eq!(
                    reason, expected,
                    "{addr} rejected for the wrong reason"
                ),
                other => panic!(
                    "{addr} should be rejected as malformed embedded-RP, \
                     got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn accepts_embedded_rendezvous_point_as_asm() {
        for addr in [
            "ff7e:140:2001:db8::1",
            "ff7e:120:2001:db8::1",
            "ff7e:f140:2001:db8:beef:feed:0:1234",
            "ff7e:140:2001:db8:beef:feed:0:1234",
        ] {
            let parsed = addr
                .parse::<ExternalMulticastIp>()
                .unwrap_or_else(|e| panic!("{addr} should be accepted: {e}"));
            assert!(!parsed.is_ssm(), "{addr} should not be SSM");
        }
    }

    #[test]
    fn derives_embedded_rendezvous_point_address() {
        for (group, expected) in [
            ("ff7e:140:2001:db8:beef:feed::", "2001:db8:beef:feed::1"),
            ("ff7e:120:2001:db8::", "2001:db8::1"),
            ("ff7e:120:2001:db8:dead::", "2001:db8::1"),
            ("ff7e:130:2001:db8:beef::", "2001:db8:beef::1"),
            ("ff7e:128:2001:db8:beef::", "2001:db8:be00::1"),
        ] {
            let segs = group.parse::<Ipv6Addr>().unwrap().segments();
            let plen = segs[1] & IPV6_PREFIX_BASED_PLEN_MASK;
            let riid = (segs[1] >> IPV6_RIID_SHIFT) & IPV6_RIID_MASK;

            assert_eq!(
                embedded_rendezvous_point_address(segs, plen, riid),
                expected.parse::<Ipv6Addr>().unwrap(),
                "{group} should derive RP {expected}"
            );
        }
    }

    #[test]
    fn detects_ssm_addresses() {
        for addr in [
            "232.0.0.1",
            "232.255.255.255",
            "ff3e::4000:1",
            "ff35::4000:1",
            "ffbe::4000:1",
            "ff3e:f000::4000:1",
            "ff3e:100::4000:1",
        ] {
            assert!(
                addr.parse::<ExternalMulticastIp>().unwrap().is_ssm(),
                "{addr} should be SSM"
            );
        }
        for addr in [
            "224.1.2.3",
            "231.0.0.1",
            "233.0.0.0",
            "ff0e::1",
            "ff05::1",
            "ffbe:20::4000:1",
            "ff3e:20::4000:1",
        ] {
            assert!(
                !addr.parse::<ExternalMulticastIp>().unwrap().is_ssm(),
                "{addr} should not be SSM"
            );
        }
    }

    #[test]
    fn rejects_invalid_ipv6_ssm_group_ids() {
        for addr in ["ff3e::4000:0", "ff3e:f000::4000:0"] {
            assert!(
                matches!(
                    addr.parse::<ExternalMulticastIp>(),
                    Err(ExternalMulticastIpError::InvalidIpv6Ssm(_))
                ),
                "{addr} should be rejected as invalid SSM"
            );
        }
    }

    #[test]
    fn accepts_valid_ipv6_ssm_group_ids() {
        for addr in [
            "ff3e::1",
            "ff3e::1234",
            "ff3e::3fff:ffff",
            "ff3e::4000:1",
            "ff3e::7fff:ffff",
            "ff3e::8000:0",
            "ff3e::ffff:ffff",
            "ff35::4000:1",
            "ff3e:0:1234::f000:1",
            "ff3e:f000:1234::1",
            "ff3e:0:1234::4000:0",
        ] {
            assert!(
                addr.parse::<ExternalMulticastIp>().is_ok(),
                "{addr} should be accepted"
            );
        }
    }

    #[test]
    fn accepts_rfc3306_unicast_prefix_ipv6_as_asm() {
        let parsed: ExternalMulticastIp = "ff3e:20:1234::1".parse().unwrap();
        assert!(!parsed.is_ssm());
    }

    fn internal_forwarding() -> ExternalInternalForwarding {
        serde_json::from_value(
            serde_json::json!({ "nat_target": nat_target_json() }),
        )
        .unwrap()
    }

    fn nat_target_json() -> serde_json::Value {
        serde_json::json!({
            "internal_ip": "ff04::1",
            "inner_mac": { "a": [1, 0, 94, 0, 0, 1] },
            "vni": 100,
        })
    }

    #[test]
    fn nat_target_validates_on_deserialize() {
        let forwarding =
            |nat_target| serde_json::json!({ "nat_target": nat_target });

        assert!(
            serde_json::from_value::<ExternalInternalForwarding>(forwarding(
                nat_target_json()
            ),)
            .is_ok()
        );
        assert!(
            serde_json::from_value::<ExternalInternalForwarding>(forwarding(
                serde_json::Value::Null
            ),)
            .is_err()
        );

        let mut unicast_mac = nat_target_json();
        unicast_mac["inner_mac"] =
            serde_json::json!({ "a": [0, 0, 94, 0, 0, 1] });
        assert!(
            serde_json::from_value::<ExternalInternalForwarding>(forwarding(
                unicast_mac
            ),)
            .is_err()
        );

        let mut outside_underlay = nat_target_json();
        outside_underlay["internal_ip"] = serde_json::json!("ff04:0:0:1::1");
        assert!(
            serde_json::from_value::<ExternalInternalForwarding>(forwarding(
                outside_underlay
            ),)
            .is_err()
        );
    }

    fn entry(
        group_ip: &str,
        sources: Option<Vec<IpSrc>>,
    ) -> Result<
        MulticastGroupCreateExternalEntry,
        MulticastGroupCreateExternalError,
    > {
        let sources = sources
            .map(|sources| {
                sources.into_iter().map(SourceEntry::try_from).collect()
            })
            .transpose()?;

        MulticastGroupCreateExternalEntry::try_from(
            MulticastGroupCreateExternalEntryShadow {
                group_ip: group_ip.parse().unwrap(),
                tag: None,
                internal_forwarding: internal_forwarding(),
                external_forwarding: ExternalForwarding { vlan_id: None },
                sources,
            },
        )
    }

    fn exact(addr: &str) -> IpSrc {
        IpSrc::Exact(addr.parse().unwrap())
    }

    #[test]
    fn ssm_requires_sources() {
        for sources in [None, Some(vec![])] {
            for group in ["232.1.2.3", "ff3e::4000:1", "ff35::4000:1"] {
                assert!(matches!(
                    entry(group, sources.clone()),
                    Err(MulticastGroupCreateExternalError::SsmRequiresSources(
                        _
                    ))
                ));
            }
        }
    }

    #[test]
    fn ssm_rejects_any_source() {
        for (group, source) in
            [("232.1.2.3", "10.1.1.1"), ("ff35::4000:1", "2001:db8::1")]
        {
            for sources in [vec![IpSrc::Any], vec![exact(source), IpSrc::Any]] {
                assert!(matches!(
                    entry(group, Some(sources)),
                    Err(
                        MulticastGroupCreateExternalError::SsmRejectsAnySource(
                            _
                        )
                    )
                ));
            }
        }
    }

    #[test]
    fn ssm_accepts_exact_sources() {
        let group = entry("232.1.2.3", Some(vec![exact("10.1.1.1")])).unwrap();
        let MulticastGroupCreateExternalEntry::Ssm(ssm) = group else {
            panic!("232.1.2.3 should classify as SSM");
        };
        assert_eq!(
            ssm.sources().iter().map(ExactSource::ip).collect::<Vec<_>>(),
            vec!["10.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            IpAddr::from(ssm.group_ip()),
            "232.1.2.3".parse::<IpAddr>().unwrap()
        );

        for group in ["ff3e::4000:1", "ff35::4000:1"] {
            assert!(matches!(
                entry(group, Some(vec![exact("2001:db8::1")])),
                Ok(MulticastGroupCreateExternalEntry::Ssm(_))
            ));
        }
    }

    #[test]
    fn asm_accepts_any_source_and_no_sources() {
        for sources in [
            None,
            Some(vec![]),
            Some(vec![IpSrc::Any]),
            Some(vec![exact("10.1.1.1"), IpSrc::Any]),
        ] {
            let group = entry("224.1.2.3", sources.clone()).unwrap();
            assert!(
                matches!(group, MulticastGroupCreateExternalEntry::Asm(_)),
                "224.1.2.3 with {sources:?} should classify as ASM"
            );
            assert_eq!(group.sources(), None);
        }

        assert!(matches!(
            entry("ff0e::1", Some(vec![IpSrc::Any])),
            Ok(MulticastGroupCreateExternalEntry::Asm(_))
        ));
    }

    #[test]
    fn rejects_source_family_mismatch() {
        for (group_ip, source) in [
            ("232.1.2.3", "2001:db8::1"),
            ("ff3e::4000:1", "10.1.1.1"),
            ("224.1.2.3", "2001:db8::1"),
            ("ff0e::1", "10.1.1.1"),
        ] {
            assert!(
                matches!(
                    entry(group_ip, Some(vec![exact(source)])),
                    Err(
                        MulticastGroupCreateExternalError::SourceFamilyMismatch { .. }
                    )
                ),
                "{source} for {group_ip} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_invalid_exact_sources() {
        assert!(matches!(
            entry("224.1.2.3", Some(vec![exact("224.9.9.9")])),
            Err(MulticastGroupCreateExternalError::SourceNotUnicast(_))
        ));
        assert!(matches!(
            entry("ff0e::1", Some(vec![exact("ff0e::2")])),
            Err(MulticastGroupCreateExternalError::SourceNotUnicast(_))
        ));

        for (source, expected) in [
            ("127.0.0.1", InvalidMulticastSource::Loopback),
            ("255.255.255.255", InvalidMulticastSource::Broadcast),
            ("0.0.0.0", InvalidMulticastSource::Unspecified),
            ("0.1.2.3", InvalidMulticastSource::ThisNetwork),
            ("169.254.10.1", InvalidMulticastSource::LinkLocal),
            ("240.0.0.1", InvalidMulticastSource::Reserved),
            ("255.255.255.254", InvalidMulticastSource::Reserved),
        ] {
            assert!(
                matches!(
                    entry("232.1.2.3", Some(vec![exact(source)])),
                    Err(MulticastGroupCreateExternalError::InvalidIpv4Source {
                        reason,
                        ..
                    }) if reason == expected
                ),
                "{source} should be rejected as {expected:?}"
            );
        }

        for (source, expected) in [
            ("::", InvalidMulticastSource::Unspecified),
            ("::1", InvalidMulticastSource::Loopback),
            ("fe80::1", InvalidMulticastSource::LinkLocal),
            ("febf:ffff::1", InvalidMulticastSource::LinkLocal),
        ] {
            assert!(
                matches!(
                    entry("ff0e::1", Some(vec![exact(source)])),
                    Err(MulticastGroupCreateExternalError::InvalidIpv6Source {
                        reason,
                        ..
                    }) if reason == expected
                ),
                "{source} should be rejected as {expected:?}"
            );
        }

        for source in ["100.64.0.1", "223.255.255.255"] {
            assert!(
                entry("232.1.2.3", Some(vec![exact(source)])).is_ok(),
                "{source} should be accepted as a source"
            );
        }

        for (source, expected) in [
            ("::ffff:192.0.2.1", EmbeddedIpv4::Mapped),
            ("::192.0.2.1", EmbeddedIpv4::Compatible),
        ] {
            assert!(
                matches!(
                    entry("ff0e::1", Some(vec![exact(source)])),
                    Err(MulticastGroupCreateExternalError::Ipv4EmbeddedSource {
                        form,
                        ..
                    }) if form == expected
                ),
                "{source} should be rejected as {expected:?}"
            );
        }
    }

    #[test]
    fn deserialize_enforces_joint_validation() {
        let body = |group_ip: &str, sources: serde_json::Value| {
            serde_json::json!({
                "group_ip": group_ip,
                "tag": null,
                "internal_forwarding": { "nat_target": nat_target_json() },
                "external_forwarding": { "vlan_id": null },
                "sources": sources,
            })
        };

        assert!(
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(body(
                "232.1.2.3",
                serde_json::Value::Null,
            ))
            .is_err()
        );

        assert!(matches!(
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(body(
                "232.1.2.3",
                serde_json::json!([{ "Exact": "10.1.1.1" }]),
            ))
            .unwrap(),
            MulticastGroupCreateExternalEntry::Ssm(_)
        ));

        assert!(matches!(
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(body(
                "224.1.2.3",
                serde_json::Value::Null,
            ))
            .unwrap(),
            MulticastGroupCreateExternalEntry::Asm(_)
        ));
    }

    #[test]
    fn serde_round_trips_flat_request_form() {
        for (body, expected) in [
            (
                serde_json::json!({
                    "group_ip": "224.1.2.3",
                    "tag": "asm-tag",
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": 10 },
                    "sources": ["Any"],
                }),
                serde_json::json!({
                    "group_ip": "224.1.2.3",
                    "tag": "asm-tag",
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": 10 },
                    "sources": null,
                }),
            ),
            (
                serde_json::json!({
                    "group_ip": "ff0e::1",
                    "tag": null,
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": null },
                    "sources": null,
                }),
                serde_json::json!({
                    "group_ip": "ff0e::1",
                    "tag": null,
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": null },
                    "sources": null,
                }),
            ),
            (
                serde_json::json!({
                    "group_ip": "232.1.2.3",
                    "tag": "ssm-tag",
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": null },
                    "sources": [
                        { "Exact": "10.1.1.1" },
                        { "Exact": "10.1.1.2" },
                    ],
                }),
                serde_json::json!({
                    "group_ip": "232.1.2.3",
                    "tag": "ssm-tag",
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": null },
                    "sources": [
                        { "Exact": "10.1.1.1" },
                        { "Exact": "10.1.1.2" },
                    ],
                }),
            ),
            (
                serde_json::json!({
                    "group_ip": "ff3e::4000:1",
                    "tag": null,
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": 4094 },
                    "sources": [{ "Exact": "2001:db8::1" }],
                }),
                serde_json::json!({
                    "group_ip": "ff3e::4000:1",
                    "tag": null,
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": 4094 },
                    "sources": [{ "Exact": "2001:db8::1" }],
                }),
            ),
        ] {
            let parsed = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(body)
            .unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_malformed_rfc3306_prefix_based() {
        for addr in ["ff2e:20:2001:db8::1", "ff2e::1"] {
            assert!(
                matches!(
                    addr.parse::<ExternalMulticastIp>(),
                    Err(ExternalMulticastIpError::MalformedPrefixBased { .. })
                ),
                "{addr} should be rejected as malformed prefix-based"
            );
        }
    }

    #[test]
    fn accepts_prefix_based_ipv6_as_asm() {
        for addr in [
            "ff3e:40::1",
            "ff3e:80::1",
            "ff3e:f020::1",
            "ff3e:ff20::1",
            "ff3e:140:2001:db8::1",
            "ff3e:40:2001:db8::1",
            "ff7e:140:2001:db8:beef:feed:0:1234",
            "ff7e:f140:2001:db8:beef:feed:0:1234",
            "fffe:f40:2001:db8:beef:feed:0:1234",
        ] {
            assert!(
                matches!(
                    entry(addr, None),
                    Ok(MulticastGroupCreateExternalEntry::Asm(_))
                ),
                "{addr} should be accepted as ASM"
            );
        }
    }

    #[test]
    fn accepts_transient_flagged_ipv6_as_asm() {
        assert!(matches!(
            entry("ff1e::1", None),
            Ok(MulticastGroupCreateExternalEntry::Asm(_))
        ));
    }

    #[test]
    fn accepts_ipv4_local_network_control_block() {
        for addr in [
            "224.0.0.1",
            "224.0.0.22",
            "224.0.0.251",
            "224.0.0.255",
            "224.0.1.0",
        ] {
            let parsed = addr.parse::<ExternalMulticastIp>().unwrap();
            assert_eq!(IpAddr::from(parsed), addr.parse::<IpAddr>().unwrap());
        }
    }

    #[test]
    fn rejects_only_reserved_base_addresses() {
        for addr in ["224.0.0.0", "ff03::", "ff05::", "ff0e::", "ff0f::"] {
            assert!(
                matches!(
                    addr.parse::<ExternalMulticastIp>(),
                    Err(ExternalMulticastIpError::ReservedBaseAddress(_))
                ),
                "{addr} should be rejected as a reserved base address"
            );
        }
        for addr in ["224.0.0.1", "ff05::1", "ff0e::1", "ff1e::"] {
            assert!(
                addr.parse::<ExternalMulticastIp>().is_ok(),
                "{addr} should be accepted"
            );
        }
    }

    #[test]
    fn source_validation_precedes_family_mismatch() {
        assert!(matches!(
            entry("232.1.2.3", Some(vec![exact("::1")])),
            Err(MulticastGroupCreateExternalError::InvalidIpv6Source {
                reason: InvalidMulticastSource::Loopback,
                ..
            })
        ));
    }

    #[test]
    fn deduplicates_exact_sources() {
        let asm_group = entry(
            "224.1.2.3",
            Some(vec![exact("10.1.1.1"), exact("10.1.1.1")]),
        )
        .unwrap();
        let MulticastGroupCreateExternalEntry::Asm(asm) = asm_group else {
            panic!("224.1.2.3 should classify as ASM");
        };
        assert_eq!(asm.exact_sources().unwrap().len(), 1);

        let ssm_group = entry(
            "232.1.2.3",
            Some(vec![exact("10.1.1.1"), exact("10.1.1.1")]),
        )
        .unwrap();
        let MulticastGroupCreateExternalEntry::Ssm(ssm) = ssm_group else {
            panic!("232.1.2.3 should classify as SSM");
        };
        assert_eq!(ssm.sources().len(), 1);
    }

    #[test]
    fn mixed_any_and_exact_sources_serialize_to_null() {
        let parsed =
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(
                serde_json::json!({
                    "group_ip": "224.1.2.3",
                    "tag": null,
                    "internal_forwarding": { "nat_target": nat_target_json() },
                    "external_forwarding": { "vlan_id": null },
                    "sources": ["Any", { "Exact": "1.2.3.4" }],
                }),
            )
            .unwrap();

        assert_eq!(
            serde_json::to_value(parsed).unwrap(),
            serde_json::json!({
                "group_ip": "224.1.2.3",
                "tag": null,
                "internal_forwarding": { "nat_target": nat_target_json() },
                "external_forwarding": { "vlan_id": null },
                "sources": null,
            })
        );
    }

    #[test]
    fn external_multicast_ip_serde_uses_plain_string() {
        let parsed =
            serde_json::from_str::<ExternalMulticastIp>("\"239.1.1.1\"")
                .unwrap();
        assert_eq!(
            IpAddr::from(parsed),
            "239.1.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"239.1.1.1\"");

        assert!(
            serde_json::from_str::<ExternalMulticastIp>("\"10.0.0.1\"")
                .is_err()
        );
        assert!(
            serde_json::from_str::<ExternalMulticastIp>("\"ff04::1\"").is_err()
        );
    }

    #[test]
    fn underlay_multicast_ipv6_validates_subnet() {
        let parsed: UnderlayMulticastIpv6 = "ff04::1".parse().unwrap();
        assert_eq!(IpAddr::from(parsed), "ff04::1".parse::<IpAddr>().unwrap());

        for addr in ["ff04:0:0:1::1", "ff05::1", "2001:db8::1"] {
            assert!(
                matches!(
                    UnderlayMulticastIpv6::new(addr.parse().unwrap()),
                    Err(Error::InvalidUnderlayMulticastIp(_))
                ),
                "{addr} should be rejected as outside ff04::/64"
            );
        }
    }
}
