// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Unversioned constants and conversions for the multicast types re-exported
//! by [`crate::latest::mcast`].
//!
//! [`IPV4_SSM_SUBNET`], [`IPV6_SSM_SUBNETS`], and
//! [`IPV6_ADMIN_SCOPED_MULTICAST_PREFIX`] are unversioned because [RFC 4607]
//! and [RFC 4291] establish them for every API version. The validators,
//! [`is_ssm_address`], and the source rules are defined in the
//! [`MCAST_EXTERNAL_SCOPE`] module because they encode Oxide policy or our
//! interpretation of the RFCs. [`UNDERLAY_MULTICAST_SUBNET`] and the tag
//! rules are defined in [`MCAST_STRICT_UNDERLAY`].
//!
//! [`is_ssm_address`]: crate::v14::mcast::is_ssm_address
//! [`MCAST_EXTERNAL_SCOPE`]: crate::v14::mcast
//! [`MCAST_STRICT_UNDERLAY`]: crate::v8::mcast
//! [`UNDERLAY_MULTICAST_SUBNET`]: crate::v8::mcast::UNDERLAY_MULTICAST_SUBNET
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
//! [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use oxnet::{Ipv4Net, Ipv6Net};

use crate::latest::mcast::{
    AsmMulticastGroupCreate, ExactSource, ExternalForwarding,
    ExternalInternalForwarding, ExternalMulticastIp, IpSrc,
    MulticastGroupCreateExternalEntry, MulticastGroupCreateExternalError,
    MulticastGroupResponse, NonEmptyExactSources, SourceEntry, SourceFilter,
    SsmMulticastGroupCreate, SsmMulticastIp,
};

/// IPv4 Source-Specific Multicast (SSM) subnet (`232.0.0.0/8`) per
/// [RFC 4607] §1.
///
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
// TODO: move to oxnet with `IPV6_SSM_SUBNETS`, next to its multicast scope
// predicates, along with an RFC 4607 `is_ssm` predicate.
pub const IPV4_SSM_SUBNET: Ipv4Net =
    Ipv4Net::new_unchecked(Ipv4Addr::new(232, 0, 0, 0), 8);

const fn ipv6_ssm_subnet(scope: u16) -> Ipv6Net {
    Ipv6Net::new_unchecked(
        Ipv6Addr::new(0xff30 | scope, 0, 0, 0, 0, 0, 0, 0),
        32,
    )
}

/// IPv6 Source-Specific Multicast (SSM) subnets, one per scope field value.
///
/// [RFC 4607] §1 specifies "ff3x::/32 for each scope x", meaning one /32
/// block per scope (ff30::/32, ff31::/32, ..., ff3f::/32).
///
/// These blocks cannot be represented by a single CIDR: the scope nibble
/// precedes the 16 zero bits that complete each /32. In particular, ff3e:1::
/// is outside ff3e::/32, even though it is inside the broader ff30::/12
/// prefix.
///
/// These are the allocation blocks only. An address can be classified
/// via the [`is_ssm_address`] predicate, which also accepts the `ffbx`
/// (X flag set) form, a nonzero `ff2` nibble ([RFC 7371] §4.1.1), and a
/// nonzero `rsvd` nibble (RIID in [RFC 3956] §3).
///
/// [`is_ssm_address`]: crate::v14::mcast::is_ssm_address
/// [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
/// [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
pub const IPV6_SSM_SUBNETS: [Ipv6Net; 16] = [
    ipv6_ssm_subnet(0x0),
    ipv6_ssm_subnet(0x1),
    ipv6_ssm_subnet(0x2),
    ipv6_ssm_subnet(0x3),
    ipv6_ssm_subnet(0x4),
    ipv6_ssm_subnet(0x5),
    ipv6_ssm_subnet(0x6),
    ipv6_ssm_subnet(0x7),
    ipv6_ssm_subnet(0x8),
    ipv6_ssm_subnet(0x9),
    ipv6_ssm_subnet(0xa),
    ipv6_ssm_subnet(0xb),
    ipv6_ssm_subnet(0xc),
    ipv6_ssm_subnet(0xd),
    ipv6_ssm_subnet(0xe),
    ipv6_ssm_subnet(0xf),
];

/// Admin-local IPv6 multicast prefix (ff04::/16) as a `u16`, used for address
/// construction of underlay multicast addresses.
///
/// See [RFC 4291] §2.7 and [RFC 7346] for the multicast address format and
/// associated scope definitions.
///
/// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
/// [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346.html
pub const IPV6_ADMIN_SCOPED_MULTICAST_PREFIX: u16 = 0xff04;

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
mod proptests;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::latest::mcast::{
        EmbeddedIpv4, ExternalMulticastIpError, InvalidEmbeddedRp,
        InvalidMulticastSource, MAX_TAG_LENGTH, MulticastSourceError,
        MulticastTag, UnderlayMulticastError, UnderlayMulticastIpv6,
    };
    use crate::v14::mcast::MulticastGroupCreateExternalEntryShadow;

    #[test]
    fn tag_schema_bounds() {
        let schema =
            serde_json::to_value(schemars::schema_for!(MulticastTag)).unwrap();
        assert_eq!(schema["maxLength"].as_u64(), Some(MAX_TAG_LENGTH as u64));
        assert_eq!(schema["minLength"].as_u64(), Some(1));
    }

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
            assert_eq!(
                addr.parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::NotMulticast(
                    addr.parse::<IpAddr>().unwrap()
                )),
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
            assert_eq!(
                addr.parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::LocalIpv6Scope(
                    addr.parse::<IpAddr>().unwrap()
                )),
                "{addr} should be rejected as an unforwardable scope"
            );
        }

        assert_eq!(
            "ff00::1".parse::<ExternalMulticastIp>(),
            Err(ExternalMulticastIpError::ReservedIpv6Scope(
                "ff00::1".parse::<IpAddr>().unwrap()
            )),
            "ff00::1 should be rejected as reserved scope 0"
        );
    }

    #[test]
    fn rejects_underlay_subnet() {
        for addr in ["ff04::1", "ff04::ffff:ffff:ffff:ffff"] {
            assert_eq!(
                addr.parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::ReservedUnderlaySubnet(
                    addr.parse::<IpAddr>().unwrap()
                )),
                "{addr} should be rejected as underlay"
            );
        }
    }

    #[test]
    fn rejects_reserved_ssm_null() {
        assert_eq!(
            "232.0.0.0".parse::<ExternalMulticastIp>(),
            Err(ExternalMulticastIpError::ReservedSsmNull(
                "232.0.0.0".parse::<IpAddr>().unwrap()
            )),
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
            ("ff5e:140:2001:db8::1", InvalidEmbeddedRp::RequiresPrefixBased),
            ("ff6e:140:2001:db8::1", InvalidEmbeddedRp::RequiresTransient),
            (
                "ff7e:100:2001:db8::1",
                InvalidEmbeddedRp::PrefixLengthOutOfRange(0),
            ),
            (
                "ff7e:180:2001:db8::1",
                InvalidEmbeddedRp::PrefixLengthOutOfRange(128),
            ),
            ("ff7e:40:2001:db8::1", InvalidEmbeddedRp::ZeroInterfaceId),
            ("ff4e::1", InvalidEmbeddedRp::RequiresPrefixBased),
            (
                "ff7e:140::1",
                InvalidEmbeddedRp::UnusableAddress(Ipv6Addr::LOCALHOST),
            ),
            (
                "ff7e:140:fe80::1",
                InvalidEmbeddedRp::UnusableAddress("fe80::1".parse().unwrap()),
            ),
            (
                "ff7e:140:ff00::1",
                InvalidEmbeddedRp::UnusableAddress("ff00::1".parse().unwrap()),
            ),
            (
                "ff7e:104:fff::1",
                InvalidEmbeddedRp::UnusableAddress(Ipv6Addr::LOCALHOST),
            ),
            (
                "ff7e:108:ff12::1",
                InvalidEmbeddedRp::UnusableAddress("ff00::1".parse().unwrap()),
            ),
        ] {
            assert_eq!(
                addr.parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::MalformedEmbeddedRp {
                    addr: addr.parse::<IpAddr>().unwrap(),
                    reason: expected,
                }),
                "{addr} should be rejected as {expected:?}"
            );
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
    fn rejects_ipv6_ssm_null_address() {
        for addr in ["ff3e::4000:0", "ff3e:f000::4000:0"] {
            assert_eq!(
                addr.parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::ReservedSsmNull(
                    addr.parse::<IpAddr>().unwrap()
                )),
                "{addr} should be rejected as the SSM null address"
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
                assert_eq!(
                    entry(group, sources.clone()).err(),
                    Some(
                        MulticastGroupCreateExternalError::SsmRequiresSources(
                            group.parse::<IpAddr>().unwrap()
                        )
                    ),
                    "{group} with sources {sources:?} should be rejected"
                );
            }
        }
    }

    #[test]
    fn ssm_rejects_any_source() {
        for (group, source) in
            [("232.1.2.3", "10.1.1.1"), ("ff35::4000:1", "2001:db8::1")]
        {
            for sources in [vec![IpSrc::Any], vec![exact(source), IpSrc::Any]] {
                assert_eq!(
                    entry(group, Some(sources.clone())).err(),
                    Some(
                        MulticastGroupCreateExternalError::SsmRejectsAnySource(
                            group.parse::<IpAddr>().unwrap()
                        )
                    ),
                    "{group} with sources {sources:?} should be rejected"
                );
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
            assert_eq!(
                entry(group_ip, Some(vec![exact(source)])).err(),
                Some(MulticastGroupCreateExternalError::SourceFamilyMismatch {
                    source_ip: source.parse::<IpAddr>().unwrap(),
                    group: group_ip.parse::<IpAddr>().unwrap(),
                }),
                "{source} for {group_ip} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_invalid_exact_sources() {
        assert_eq!(
            entry("224.1.2.3", Some(vec![exact("224.9.9.9")])).err(),
            Some(MulticastGroupCreateExternalError::InvalidSource(
                MulticastSourceError::NotUnicast(
                    "224.9.9.9".parse::<IpAddr>().unwrap()
                )
            ))
        );
        assert_eq!(
            entry("ff0e::1", Some(vec![exact("ff0e::2")])).err(),
            Some(MulticastGroupCreateExternalError::InvalidSource(
                MulticastSourceError::NotUnicast(
                    "ff0e::2".parse::<IpAddr>().unwrap()
                )
            ))
        );

        for (source, expected) in [
            ("127.0.0.1", InvalidMulticastSource::Loopback),
            ("255.255.255.255", InvalidMulticastSource::Broadcast),
            ("0.0.0.0", InvalidMulticastSource::Unspecified),
            ("0.1.2.3", InvalidMulticastSource::ThisNetwork),
            ("169.254.10.1", InvalidMulticastSource::LinkLocal),
            ("240.0.0.1", InvalidMulticastSource::Reserved),
            ("255.255.255.254", InvalidMulticastSource::Reserved),
        ] {
            assert_eq!(
                entry("232.1.2.3", Some(vec![exact(source)])).err(),
                Some(MulticastGroupCreateExternalError::InvalidSource(
                    MulticastSourceError::InvalidIpv4 {
                        addr: source.parse::<Ipv4Addr>().unwrap(),
                        reason: expected,
                    }
                )),
                "{source} should be rejected as {expected:?}"
            );
        }

        for (source, expected) in [
            ("::", InvalidMulticastSource::Unspecified),
            ("::1", InvalidMulticastSource::Loopback),
            ("fe80::1", InvalidMulticastSource::LinkLocal),
            ("febf:ffff::1", InvalidMulticastSource::LinkLocal),
        ] {
            assert_eq!(
                entry("ff0e::1", Some(vec![exact(source)])).err(),
                Some(MulticastGroupCreateExternalError::InvalidSource(
                    MulticastSourceError::InvalidIpv6 {
                        addr: source.parse::<Ipv6Addr>().unwrap(),
                        reason: expected,
                    }
                )),
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
            assert_eq!(
                entry("ff0e::1", Some(vec![exact(source)])).err(),
                Some(MulticastGroupCreateExternalError::InvalidSource(
                    MulticastSourceError::Ipv4Embedded {
                        addr: source.parse::<Ipv6Addr>().unwrap(),
                        form: expected,
                    }
                )),
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
            assert_eq!(
                addr.parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::MalformedPrefixBased {
                    addr: addr.parse::<IpAddr>().unwrap(),
                }),
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
            assert_eq!(
                addr.parse::<ExternalMulticastIp>(),
                Err(ExternalMulticastIpError::ReservedBaseAddress(
                    addr.parse::<IpAddr>().unwrap()
                )),
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
        assert_eq!(
            entry("232.1.2.3", Some(vec![exact("::1")])).err(),
            Some(MulticastGroupCreateExternalError::InvalidSource(
                MulticastSourceError::InvalidIpv6 {
                    addr: Ipv6Addr::LOCALHOST,
                    reason: InvalidMulticastSource::Loopback,
                }
            ))
        );
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
        assert_eq!(asm.sources.exact_sources().unwrap().len(), 1);

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
                    Err(UnderlayMulticastError::InvalidUnderlayMulticastIp(_))
                ),
                "{addr} should be rejected as outside ff04::/64"
            );
        }
    }
}
