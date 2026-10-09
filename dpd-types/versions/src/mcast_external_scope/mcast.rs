// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Multicast types added in API version `MCAST_EXTERNAL_SCOPE`.
//!
//! The incoming request format remains flat. The deserialization boundary
//! is where we can classify the request as any-source multicast (ASM) or
//! source-specific multicast (SSM).
//!
//! Validation of an external group address is limited to what the RFCs
//! require, with one Oxide exception: `ff04::/64` is our underlay subnet
//! and belongs to the internal multicast API. We reject addresses on this
//! subnet, even though the rest of admin-local `ff04::/16` is permitted.
//!
//! All IPv6 scopes are admitted except for the reserved scope of `0x0` and
//! the interface-local `0x1` and link-local `0x2` ones, which a router must
//! not forward past ([RFC 4291] §2.7). Scope `0xf` is retained because
//! [RFC 4291] §2.7 treats it as global when it is sent or received. IPv4 admits
//! the whole multicast range apart from the base address of `224.0.0.0`,
//! which [RFC 1112] §4 guarantees is never assigned to a group, and the
//! SSM null address of `232.0.0.0` ([RFC 4607] §4.3).
//!
//! The four flag bits above the scope nibble are `|X|R|P|T|` ([RFC 7371]
//! §4.2.1): T marks a transient address, P a prefix-based one, R an embedded
//! rendezvous point, and X may be either zero or one. [RFC 7371] §4.1.1
//! names the same field `|X|Y|P|T|`, where Y is the bit that [RFC 3956]
//! defines as the R flag.
//!
//! Prefix-based addresses require only that the P flag implies the T flag
//! ([RFC 7371] §4.1.1, which replaces that passage of [RFC 3306] §4). The
//! replacement drops the "reserved field MUST be zero" rule: the `ff2` and
//! `rsvd` nibbles are sent as zero and ignored on receipt instead, per
//! [RFC 7371] §4.1.1 and [RFC 3956] §3, so neither is validated here. The
//! prefix length is otherwise unbounded, since the `plen` ceiling of 64
//! comes from [RFC 3956] §4 and applies to embedded rendezvous point (RP)
//! addresses only. [RFC 3306] §4 notes the same 64-bit ceiling on the
//! network prefix without requiring it.
//!
//! Embedded RP addresses require the R, P, and T flags ([RFC 7371] §4.2.2
//! and §4.2.3), a prefix length from 1 through 64, a nonzero RP interface ID
//! ([RFC 3956] §6.3), and a derived RP address outside `::/16`, link-local
//! space, and the multicast range. [RFC 3956] §4 states those exclusions
//! as requirements; §10 repeats them as a security consideration.
//!
//! Classifying SSM addresses follows [RFC 4607] and [RFC 7371]. IPv4 SSM uses
//! `232.0.0.0/8`. IPv6 SSM covers `ff3x::/32` and `ffbx::/32`, the latter
//! with the X flag set. Both IPv6 ranges require R=0, P=T=1, and a zero
//! prefix length. The `ff2` and `rsvd` nibbles lie between `scop` and
//! `plen` and are ignored on receipt ([RFC 7371] §4.1.1, [RFC 3956] §3).
//! This implementation masks both nibbles off before testing for SSM-range
//! membership, and an address that sets either of them is still considered
//! an SSM one.
//!
//! The only SSM address rejected is the reserved null address of
//! `ff3x::4000:0` from [RFC 4607] §4.3. The network prefix is unchecked
//! otherwise: [RFC 3306] §6 applies to the node that's forming the address,
//! and [RFC 4607] §1 has a system treat all of the `ff3x::/32` block as SSM.
//! Group IDs below `4000:0` are assigned with flags P=T=0 ([RFC 3307] §4.1),
//! making them invalid SSM addresses that routers may drop ([RFC 4607] §1).
//! The band just above it, `4000:0001` through `7fff:ffff`, is reserved for
//! IANA allocation ([RFC 4607] §4.3, [RFC 3307] §4.2) rather than forbidden
//! as a destination. From `8000:0` up is the dynamic range of [RFC 3307]
//! §4.3, which [RFC 10028] §3 partitions; host SSM allocation sits at
//! `f000:0` through `fcff:ffff`. All of these are accepted.
//!
//! Permanently assigned addresses (T=0) with the P and R flags cleared are
//! permitted. They face the same `ff04::/64` underlay reservation as any
//! other address, and the all-zero group ID `ff0x::` is refused outright,
//! since [RFC 4291] §2.7.1 reserves it and never assigns it. A registered
//! meaning is independent of scope ([RFC 4291] §2.7), so `ff0e::101` and
//! `ff05::fb` keep those meanings in the overlay.
//!
//! [RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112.html
//! [RFC 3306]: https://www.rfc-editor.org/rfc/rfc3306.html
//! [RFC 3307]: https://www.rfc-editor.org/rfc/rfc3307.html
//! [RFC 3956]: https://www.rfc-editor.org/rfc/rfc3956.html
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
//! [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
//! [RFC 7371]: https://www.rfc-editor.org/rfc/rfc7371.html
//! [RFC 10028]: https://www.rfc-editor.org/rfc/rfc10028.html

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::impls::mcast::{
    RequestSources, is_ssm_address, validate_exact_source,
    validate_external_multicast_ip,
};
use crate::v1;
use crate::v1::mcast::{
    ExternalForwarding, InternalForwarding, MulticastGroupId,
};
use crate::v1::network::{MacAddr, NatTarget, Vni};
use crate::v7;
use crate::v7::mcast::IpSrc;
use crate::v8;
use crate::v8::mcast::{MulticastGroupUnderlayResponse, UnderlayMulticastIpv6};

/// A validated IP address for a customer-visible overlay multicast group.
///
/// JSON uses the ordinary IP-address string form. Deserialization applies
/// the module's validation rules before the request reaches an endpoint
/// handler.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    JsonSchema,
)]
#[serde(try_from = "IpAddr", into = "IpAddr")]
pub struct ExternalMulticastIp(IpAddr);

impl TryFrom<IpAddr> for ExternalMulticastIp {
    type Error = ExternalMulticastIpError;

    fn try_from(addr: IpAddr) -> Result<Self, Self::Error> {
        Self::new(addr)
    }
}

impl From<ExternalMulticastIp> for IpAddr {
    fn from(addr: ExternalMulticastIp) -> Self {
        addr.0
    }
}

impl ExternalMulticastIp {
    /// Create a new `ExternalMulticastIp` if the address is valid for an
    /// external multicast group.
    ///
    /// # Errors
    ///
    /// Returns [`ExternalMulticastIpError`] if `addr` cannot identify an
    /// external multicast group.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::IpAddr;
    /// use dpd_types_versions::latest::mcast::ExternalMulticastIp;
    ///
    /// let global: IpAddr = "ff0e::1".parse().unwrap();
    /// assert!(ExternalMulticastIp::new(global).is_ok());
    ///
    /// let underlay: IpAddr = "ff04::1".parse().unwrap();
    /// assert!(ExternalMulticastIp::new(underlay).is_err());
    /// ```
    pub fn new(addr: IpAddr) -> Result<Self, ExternalMulticastIpError> {
        validate_external_multicast_ip(addr)?;
        Ok(Self(addr))
    }

    /// Check whether this address is a Source-Specific Multicast address.
    pub fn is_ssm(&self) -> bool {
        is_ssm_address(self.0)
    }
}

impl fmt::Display for ExternalMulticastIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Errors returned when parsing or validating an [`ExternalMulticastIp`].
#[derive(Clone, Debug, thiserror::Error)]
pub enum ExternalMulticastIpError {
    /// The address is not a multicast address.
    #[error("Address {0} is not a multicast address")]
    NotMulticast(IpAddr),

    /// The IPv6 multicast scope value zero is reserved.
    #[error("Address {0} uses reserved IPv6 multicast scope 0")]
    ReservedIpv6Scope(IpAddr),

    /// The IPv6 multicast scope is interface-local or link-local, which a
    /// router must not forward beyond (RFC 4291 §2.7).
    #[error(
        "Address {0} has interface-local or link-local IPv6 multicast scope, \
         which routers must not forward beyond (RFC 4291 §2.7)"
    )]
    LocalIpv6Scope(IpAddr),

    /// The address is in the reserved `ff04::/64` underlay subnet for internal
    /// routing.
    #[error(
        "Address {0} is in the reserved underlay multicast subnet (ff04::/64, \
         within admin-local scope ff04::/16) and must be created via the \
         internal multicast API"
    )]
    ReservedUnderlaySubnet(IpAddr),

    /// The address is reserved and never assigned to any multicast group:
    /// `224.0.0.0` (RFC 1112 §4) or `ff0x::` (RFC 4291 §2.7.1).
    #[error(
        "Address {0} is reserved and never assigned to a multicast group \
         (RFC 1112 §4, RFC 4291 §2.7.1)"
    )]
    ReservedBaseAddress(IpAddr),

    /// The IPv4 SSM null address `232.0.0.0` must not be used as a
    /// destination.
    #[error(
        "Address {0} is the reserved IPv4 SSM null address and must not be \
         used as a destination (RFC 4607 §4.3)"
    )]
    ReservedSsmNull(IpAddr),

    /// The IPv6 SSM address is the reserved null address of `ff3x::4000:0`.
    #[error(
        "Address {0} is the reserved IPv6 SSM null address ff3x::4000:0 and \
         must not be used as a destination (RFC 4607 §4.3)"
    )]
    InvalidIpv6Ssm(IpAddr),

    /// The prefix-based P flag is set without the T flag (RFC 7371 §4.1.1,
    /// amending RFC 3306 §4).
    #[error(
        "Address {addr} sets the P flag, but RFC 7371 §4.1.1 requires the T \
         flag to be set as well"
    )]
    MalformedPrefixBased {
        /// The rejected group address.
        addr: IpAddr,
    },

    /// The embedded-Rendezvous (RP) R flag is set with an invalid flag
    /// combination, prefix length, RP interface ID, or a derived RP address
    /// (RFC 7371 §4.2.2, §4.2.3; RFC 3956 §4, §6.3, §10).
    #[error(
        "Address {addr} sets the R flag, but {reason} (RFC 3956, RFC 7371)"
    )]
    MalformedEmbeddedRp {
        /// The rejected group address.
        addr: IpAddr,
        /// The embedded-RP rule that failed.
        reason: &'static str,
    },

    /// The given string does not parse as an IP address.
    #[error("Invalid IP address '{0}': {1}")]
    InvalidIpAddress(String, std::net::AddrParseError),
}

/// Errors returned when validating an external multicast group creation
/// request.
#[derive(Clone, Debug, thiserror::Error)]
pub enum MulticastGroupCreateExternalError {
    /// The group IP failed external multicast address validation, returning an
    /// [`ExternalMulticastIpError`].
    #[error(transparent)]
    InvalidGroupIp(#[from] ExternalMulticastIpError),

    /// An exact source address supplied in the request uses a different
    /// address family than the given group IP address.
    #[error(
        "Source IP {source_ip} does not match multicast group address family \
         ({group})"
    )]
    SourceFamilyMismatch {
        /// The rejected source address.
        source_ip: IpAddr,
        /// The group address whose family it must match.
        group: IpAddr,
    },

    /// An exact source address supplied in the request is a multicast address
    /// (not a unicast one).
    #[error(
        "Source IP {0} must be a unicast address (multicast addresses are not \
         allowed)"
    )]
    SourceNotUnicast(IpAddr),

    /// An exact IPv4 source address supplied in the request is invalid if it
    /// is loopback, broadcast, unspecified, link-local, in the "this host on
    /// this network" block `0.0.0.0/8`, or in the class E block `240.0.0.0/4`.
    /// [`InvalidMulticastSource`] names the rule that failed.
    #[error("Source IP {addr} {reason}, which is not a valid source address")]
    InvalidIpv4Source {
        /// The rejected source address.
        addr: Ipv4Addr,
        /// The source rule that failed.
        reason: InvalidMulticastSource,
    },

    /// An exact IPv6 source address supplied in the request is invalid if it
    /// is loopback, unspecified, or link-local. [`InvalidMulticastSource`] names
    /// the rule that failed.
    #[error("Source IP {addr} {reason}, which is not a valid source address")]
    InvalidIpv6Source {
        /// The rejected source address.
        addr: Ipv6Addr,
        /// The source rule that failed.
        reason: InvalidMulticastSource,
    },

    /// An exact IPv6 source address supplied in the request is invalid if it
    /// uses an IPv4-mapped (RFC 4291 §2.5.5.2) or IPv4-compatible (RFC 4291
    /// §2.5.5.1) representation. [`EmbeddedIpv4`] names the form.
    #[error(
        "Source IP {addr} embeds an IPv4 address, {form}, which is not a \
         valid IPv6 source address"
    )]
    Ipv4EmbeddedSource {
        /// The rejected source address.
        addr: Ipv6Addr,
        /// The embedded IPv4 form it uses.
        form: EmbeddedIpv4,
    },

    /// An SSM group requires at least one exact source.
    #[error(
        "Group IP {0} is a Source-Specific Multicast address and requires at \
         least one source to be defined"
    )]
    SsmRequiresSources(IpAddr),

    /// An SSM group cannot use `IpSrc::Any` (only ASM groups can).
    #[error(
        "Group IP {0} is a Source-Specific Multicast address and requires \
         specific sources (IpSrc::Any is not allowed)"
    )]
    SsmRejectsAnySource(IpAddr),

    /// The internal forwarding config is missing or invalid.
    #[error(transparent)]
    InvalidInternalForwarding(#[from] ExternalInternalForwardingError),

    /// The given string does not parse as an IP address.
    #[error("Invalid source IP address '{0}': {1}")]
    InvalidSourceIpAddress(String, std::net::AddrParseError),
}

/// The reason an address cannot serve as a multicast (S,G) source.
///
/// The rules are validated in variant order; an address caught by more
/// than one invalid rule only reports the first hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidMulticastSource {
    /// `0.0.0.0` or `::`.
    Unspecified,

    /// `127.0.0.0/8` or `::1`.
    Loopback,

    /// `255.255.255.255`, the limited broadcast address that [RFC 919 §7]
    /// dictates must not be forwarded. IPv6 has no broadcast address, making
    /// this IPv4 only.
    ///
    /// [RFC 919 §7]: https://www.rfc-editor.org/rfc/rfc919#section-7
    Broadcast,

    /// `169.254.0.0/16` ([RFC 3927]) or `fe80::/10` ([RFC 4291 §2.5.6]).
    ///
    /// [RFC 3927]: https://www.rfc-editor.org/rfc/rfc3927
    /// [RFC 4291 §2.5.6]: https://www.rfc-editor.org/rfc/rfc4291#section-2.5.6
    LinkLocal,

    /// `0.0.0.0/8`. [RFC 1122 §3.2.1.3] permits it as a source before a
    /// host learns its own address, but reverse-path forwarding cannot
    /// resolve it to an incoming interface.
    ///
    /// [RFC 1122 §3.2.1.3]: https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.3
    ThisNetwork,

    /// The class E block `240.0.0.0/4`, which the IANA special-purpose
    /// registry ([RFC 6890]) marks "Source: False".
    ///
    /// [RFC 6890]: https://www.rfc-editor.org/rfc/rfc6890
    Reserved,
}

impl fmt::Display for InvalidMulticastSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => write!(f, "is the unspecified address"),
            Self::Loopback => write!(f, "is a loopback address"),
            Self::Broadcast => write!(f, "is the broadcast address"),
            Self::LinkLocal => write!(f, "is a link-local address"),
            Self::ThisNetwork => {
                write!(f, "is in 0.0.0.0/8 (this host on this network)")
            }
            Self::Reserved => {
                write!(f, "is in the reserved class E block (240.0.0.0/4)")
            }
        }
    }
}

/// The IPv6 representation of an embedded IPv4 address.
///
/// Both variants carry the IPv4 address within the low 32 bits and differ only
/// in the 96-bit prefix ahead of those bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddedIpv4 {
    /// The `::ffff:0:0/96` form, which represents an IPv4 node's address
    /// to an IPv6 application ([RFC 4291 §2.5.5.2]).
    ///
    /// [RFC 4291 §2.5.5.2]: https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2
    Mapped,

    /// The `::/96` form, which [RFC 4291 §2.5.5.1] deprecates because the
    /// transition mechanisms that used it are obsolete.
    ///
    /// [RFC 4291 §2.5.5.1]: https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.1
    Compatible,
}

impl fmt::Display for EmbeddedIpv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapped => {
                write!(f, "IPv4-mapped (::ffff:0:0/96, RFC 4291 §2.5.5.2)")
            }
            Self::Compatible => {
                write!(f, "IPv4-compatible (::/96, RFC 4291 §2.5.5.1)")
            }
        }
    }
}

/// A validated external SSM group address.
///
/// IPv4 SSM addresses must be within the `232.0.0.0/8` range, excluding the
/// reserved `232.0.0.0` null address.
///
/// IPv6 SSM addresses satisfy the SSM checks on [`ExternalMulticastIp`].
///
/// SSM channels are identified by an `(S,G)` pairing; an any-source (ASM)
/// filter is invalid for this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SsmMulticastIp(ExternalMulticastIp);

/// A validated exact multicast source address.
///
/// Sources must be unicast and use the same address family as the group. The
/// rule set matches OPTE's source validator.
///
/// IPv4 loopback, broadcast, unspecified, link-local, and "this host on this
/// network" (`0.0.0.0/8`, RFC 1122 §3.2.1.3) addresses are rejected as
/// sources, as is the class E block (`240.0.0.0/4`), which RFC 1112 §4
/// reserves and the IANA special-purpose registry (RFC 6890) marks as
/// "Source: False". Shared address space (`100.64.0.0/10`, RFC 6598) is
/// permitted because it can source traffic inside an operator network.
///
/// IPv6 loopback, unspecified, link-local, IPv4-mapped (RFC 4291 §2.5.5.2),
/// and IPv4-compatible (RFC 4291 §2.5.5.1) addresses are rejected as sources.
/// A link-local source is never forwarded off-link (RFC 3927 §2.7, RFC 4291
/// §2.5.6), and `0.0.0.0/8` is marked as not forwardable in the IANA
/// special-purpose registry (RFC 6890, per RFC 1812 §5.3.7), which means
/// that neither of these could ever match a source filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactSource(IpAddr);

/// A non-empty list of validated exact multicast source addresses
/// (sorted and deduplicated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptyExactSources(Vec<ExactSource>);

/// Stored source filter for an external multicast group.
///
/// A list that is absent, empty, a singleton `Any` (wildcard), or containing
/// `Any` alongside exact entries always collapses to just the singleton `Any`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceFilter {
    /// Any source, maps to the `(*,G)` wildcard.
    Any,
    /// Exact sources only, the `(S,G)` list.
    Exact(NonEmptyExactSources),
}

/// A requested source entry, which is validated on its own address.
///
/// The incoming deserialized form is an [`IpSrc`].
///
/// The validations that depend on the group address, namely the
/// address-family match and the ASM/SSM source-list disambiguation, are
/// applied once the group IP is known.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(try_from = "IpSrc", into = "IpSrc")]
pub enum SourceEntry {
    /// Wildcard entry, which collapses an ASM filter to unrestricted.
    Any,
    /// A single source that passed unicast validation.
    Exact(ExactSource),
}

impl JsonSchema for SourceEntry {
    fn schema_name() -> String {
        IpSrc::schema_name()
    }

    fn is_referenceable() -> bool {
        IpSrc::is_referenceable()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        IpSrc::schema_id()
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        IpSrc::json_schema(generator)
    }
}

impl TryFrom<IpSrc> for SourceEntry {
    type Error = MulticastGroupCreateExternalError;

    fn try_from(source: IpSrc) -> Result<Self, Self::Error> {
        Ok(match source {
            IpSrc::Any => Self::Any,
            IpSrc::Exact(ip) => Self::Exact(ExactSource::new(ip)?),
        })
    }
}

impl From<SourceEntry> for IpSrc {
    fn from(entry: SourceEntry) -> Self {
        match entry {
            SourceEntry::Any => IpSrc::Any,
            SourceEntry::Exact(source) => IpSrc::Exact(source.ip()),
        }
    }
}

/// NAT target for an external multicast group.
///
/// The MAC must be a multicast MAC and the internal IP must lie within the
/// `ff04::/64` internal underlay block.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
#[serde(try_from = "NatTarget", into = "NatTarget")]
pub struct ExternalNatTarget {
    internal_ip: UnderlayMulticastIpv6,
    inner_mac: MacAddr,
    vni: Vni,
}

/// Errors from constructing an [`ExternalNatTarget`].
#[derive(Clone, Debug, thiserror::Error)]
pub enum ExternalNatTargetError {
    /// The inner MAC is not multicast.
    #[error("NAT target inner MAC address {0} is not a multicast MAC address")]
    InvalidInnerMac(MacAddr),
    /// The internal IP is outside `ff04::/64`.
    #[error(
        "NAT target internal IP address {0} is not in the reserved underlay \
         multicast subnet (ff04::/64)"
    )]
    InvalidInternalIp(Ipv6Addr),
}

/// Errors from converting the older optional forwarding shape.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ExternalInternalForwardingError {
    /// The request omitted its NAT target.
    #[error("External multicast groups require a NAT target")]
    MissingNatTarget,
    /// The NAT target failed validation.
    #[error(transparent)]
    InvalidNatTarget(#[from] ExternalNatTargetError),
}

/// Internal forwarding for an external multicast group.
///
/// External groups always carry a NAT target.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
pub struct ExternalInternalForwarding {
    /// The group's underlay NAT target.
    pub nat_target: ExternalNatTarget,
}

impl TryFrom<NatTarget> for ExternalNatTarget {
    type Error = ExternalNatTargetError;

    fn try_from(target: NatTarget) -> Result<Self, Self::Error> {
        if !target.inner_mac.is_multicast() {
            return Err(ExternalNatTargetError::InvalidInnerMac(
                target.inner_mac,
            ));
        }

        let internal_ip = UnderlayMulticastIpv6::new(target.internal_ip)
            .map_err(|_| {
                ExternalNatTargetError::InvalidInternalIp(target.internal_ip)
            })?;

        Ok(Self { internal_ip, inner_mac: target.inner_mac, vni: target.vni })
    }
}

impl From<ExternalNatTarget> for NatTarget {
    fn from(target: ExternalNatTarget) -> Self {
        Self {
            internal_ip: target.internal_ip.into(),
            inner_mac: target.inner_mac,
            vni: target.vni,
        }
    }
}

impl From<ExternalNatTarget> for UnderlayMulticastIpv6 {
    fn from(target: ExternalNatTarget) -> Self {
        target.internal_ip
    }
}

impl TryFrom<InternalForwarding> for ExternalInternalForwarding {
    type Error = ExternalInternalForwardingError;

    fn try_from(forwarding: InternalForwarding) -> Result<Self, Self::Error> {
        let nat_target = forwarding
            .nat_target
            .ok_or(ExternalInternalForwardingError::MissingNatTarget)?
            .try_into()?;
        Ok(Self { nat_target })
    }
}

impl From<ExternalInternalForwarding> for InternalForwarding {
    fn from(forwarding: ExternalInternalForwarding) -> Self {
        Self { nat_target: Some(forwarding.nat_target.into()) }
    }
}

impl NonEmptyExactSources {
    /// Create a sorted, deduplicated list, while returning `None` for empty
    /// input(s).
    pub(crate) fn new(sources: Vec<ExactSource>) -> Option<Self> {
        let sources: Vec<_> =
            sources.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
        (!sources.is_empty()).then_some(Self(sources))
    }

    fn into_vec(self) -> Vec<ExactSource> {
        self.0
    }

    /// Return the sources as a slice representation.
    pub fn as_slice(&self) -> &[ExactSource] {
        &self.0
    }
}

impl SsmMulticastIp {
    /// Return the SSM form of an [`ExternalMulticastIp`] or `None` for ASM.
    pub fn new(addr: ExternalMulticastIp) -> Option<Self> {
        addr.is_ssm().then_some(Self(addr))
    }

    /// Return the underlying external multicast address.
    pub fn ip(&self) -> ExternalMulticastIp {
        self.0
    }
}

impl From<SsmMulticastIp> for ExternalMulticastIp {
    fn from(addr: SsmMulticastIp) -> Self {
        addr.0
    }
}

impl From<SsmMulticastIp> for IpAddr {
    fn from(addr: SsmMulticastIp) -> Self {
        addr.0.into()
    }
}

impl fmt::Display for SsmMulticastIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ExactSource {
    /// Validate an exact multicast source address.
    ///
    /// # Errors
    ///
    /// Returns [`MulticastGroupCreateExternalError`] if `ip` is multicast or
    /// cannot be used as a unicast source.
    pub fn new(ip: IpAddr) -> Result<Self, MulticastGroupCreateExternalError> {
        validate_exact_source(ip)?;
        Ok(Self(ip))
    }

    /// Return the source address.
    pub fn ip(&self) -> IpAddr {
        self.0
    }
}

impl From<ExactSource> for IpAddr {
    fn from(source: ExactSource) -> Self {
        source.0
    }
}

impl From<ExactSource> for IpSrc {
    fn from(source: ExactSource) -> Self {
        IpSrc::Exact(source.0)
    }
}

impl fmt::Display for ExactSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// An external any-source (ASM) multicast group used at creation time.
///
/// ASM uses the host-group model described in [RFC 1112], with member
/// subscribers receiving traffic sent to this group from any permissible
/// source.
///
/// The requested source list may be absent, empty, exact-only, [`IpSrc::Any`],
/// or a mixture of `Any` and exact entries.
///
/// A source of `Any` subsumes all exact source entries (related to the
/// filter-mode merge rules of [RFC 3376] §3.2). Upon subsumption,
/// every exact entry is validated first, then any-source constructs (mixed
/// lists included) are canonicalized to an unrestricted filter
/// at deserialization, and then exact-only lists are kept around.
///
/// [RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112.html
/// [RFC 3376]: https://www.rfc-editor.org/rfc/rfc3376.html
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsmMulticastGroupCreate {
    pub(crate) group_ip: ExternalMulticastIp,
    pub(crate) tag: Option<String>,
    pub(crate) internal_forwarding: ExternalInternalForwarding,
    pub(crate) external_forwarding: ExternalForwarding,
    pub(crate) sources: SourceFilter,
}

/// An external source-specific (SSM) multicast group used at creation time.
///
/// SSM uses the `(S,G)` channel model from [RFC 4607].
///
/// The source list must always contain at least one exact source;
/// `IpSrc::Any` cannot occur in this request type.
///
/// [RFC 4607]: https://www.rfc-editor.org/rfc/rfc4607.html
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsmMulticastGroupCreate {
    pub(crate) group_ip: SsmMulticastIp,
    pub(crate) tag: Option<String>,
    pub(crate) internal_forwarding: ExternalInternalForwarding,
    pub(crate) external_forwarding: ExternalForwarding,
    pub(crate) sources: NonEmptyExactSources,
}

/// A validated external multicast group creation entry.
///
/// Deserializing the flat request validates the group IP and source list
/// and picks the ASM (any-source) or SSM (source-specific) shape.
///
/// Serializing emits the canonical flat form. A request that mixed `Any`
/// (wildcard) with exact sources does not round-trip.
///
/// On decode, this checks the group address, each exact source, and
/// the address-family relationship. Source-list rules follow the appropriate
/// ASM or SSM split.
///
/// # Examples
///
/// An SSM group with a populated NAT target:
///
/// ```
/// use dpd_types_versions::latest::mcast::MulticastGroupCreateExternalEntry;
///
/// let body = serde_json::json!({
///     "group_ip": "232.1.2.3",
///     "tag": "client",
///     "internal_forwarding": {
///         "nat_target": {
///             "internal_ip": "ff04::1",
///             "inner_mac": { "a": [1, 0, 94, 0, 0, 1] },
///             "vni": 100
///         }
///     },
///     "external_forwarding": { "vlan_id": null },
///     "sources": [{ "Exact": "10.0.0.1" }]
/// });
///
/// let group: MulticastGroupCreateExternalEntry =
///     serde_json::from_value(body).unwrap();
/// assert!(matches!(group, MulticastGroupCreateExternalEntry::Ssm(_)));
/// ```
///
/// An ASM group with the source list omitted:
///
/// ```
/// use dpd_types_versions::latest::mcast::MulticastGroupCreateExternalEntry;
///
/// let body = serde_json::json!({
///     "group_ip": "239.1.2.3",
///     "tag": null,
///     "internal_forwarding": {
///         "nat_target": {
///             "internal_ip": "ff04::1",
///             "inner_mac": { "a": [1, 0, 94, 0, 0, 1] },
///             "vni": 100
///         }
///     },
///
///     "external_forwarding": { "vlan_id": null }
/// });
///
/// let group: MulticastGroupCreateExternalEntry =
///     serde_json::from_value(body).unwrap();
/// assert!(matches!(group, MulticastGroupCreateExternalEntry::Asm(_)));
/// ```
///
/// An ASM group may carry exact sources, but a source of `Any` (wildcard), a
/// singleton `["Any"]`, or an empty list all collapse to the same unrestricted
/// shape.
///
/// ```
/// use dpd_types_versions::latest::mcast::MulticastGroupCreateExternalEntry;
///
/// let mut body = serde_json::json!({
///     "group_ip": "239.1.2.3",
///     "tag": null,
///     "internal_forwarding": {
///         "nat_target": {
///             "internal_ip": "ff04::1",
///             "inner_mac": { "a": [1, 0, 94, 0, 0, 1] },
///             "vni": 100
///         }
///     },
///     "external_forwarding": { "vlan_id": null },
///     "sources": [{ "Exact": "10.0.0.1" }, { "Exact": "10.0.0.2" }]
/// });
///
/// let entry: MulticastGroupCreateExternalEntry =
///     serde_json::from_value(body.clone()).unwrap();
/// let MulticastGroupCreateExternalEntry::Asm(group) = &entry else {
///     panic!("239.1.2.3 is an ASM address");
/// };
/// assert_eq!(group.exact_sources().unwrap().len(), 2);
///
/// for sources in [
///     serde_json::json!(["Any", { "Exact": "10.0.0.1" }]),
///     serde_json::json!(["Any"]),
///     serde_json::json!([]),
/// ] {
///     body["sources"] = sources;
///     let entry: MulticastGroupCreateExternalEntry =
///         serde_json::from_value(body.clone()).unwrap();
///     let MulticastGroupCreateExternalEntry::Asm(group) = &entry else {
///         panic!("239.1.2.3 is an ASM address");
///     };
///     assert!(group.allows_any_source());
///     assert_eq!(
///         serde_json::to_value(&entry).unwrap()["sources"],
///         serde_json::Value::Null
///     );
/// }
/// ```
///
/// An SSM group must carry exact sources, while ASM can omit them. Both an
/// absent list and a singleton `Any` (wildcard) are rejected:
///
/// ```
/// use dpd_types_versions::latest::mcast::MulticastGroupCreateExternalEntry;
///
/// let mut body = serde_json::json!({
///     "group_ip": "232.1.2.3",
///     "tag": null,
///     "internal_forwarding": {
///         "nat_target": {
///             "internal_ip": "ff04::1",
///             "inner_mac": { "a": [1, 0, 94, 0, 0, 1] },
///             "vni": 100
///         }
///     },
///     "external_forwarding": { "vlan_id": null }
/// });
///
/// let no_sources =
///     serde_json::from_value::<MulticastGroupCreateExternalEntry>(body.clone());
/// assert!(no_sources.is_err());
///
/// body["sources"] = serde_json::json!(["Any"]);
/// let singleton_any =
///     serde_json::from_value::<MulticastGroupCreateExternalEntry>(body);
/// assert!(singleton_any.is_err());
/// ```
///
/// IPv6 SSM groups, in the `ff3x::/32` prefix of RFC 4607 and in `ffbx::/32`
/// with the X flag set:
///
/// ```
/// use dpd_types_versions::latest::mcast::MulticastGroupCreateExternalEntry;
///
/// for group_ip in ["ff3e::4000:1", "ffbe::4000:1"] {
///     let body = serde_json::json!({
///         "group_ip": group_ip,
///         "tag": null,
///         "internal_forwarding": {
///             "nat_target": {
///                 "internal_ip": "ff04::1",
///                 "inner_mac": { "a": [1, 0, 94, 0, 0, 1] },
///                 "vni": 100
///             }
///         },
///         "external_forwarding": { "vlan_id": null },
///         "sources": [{ "Exact": "2001:db8::1" }]
///     });
///
///     let group: MulticastGroupCreateExternalEntry =
///         serde_json::from_value(body).unwrap();
///     assert!(matches!(group, MulticastGroupCreateExternalEntry::Ssm(_)));
/// }
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    try_from = "MulticastGroupCreateExternalEntryShadow",
    into = "MulticastGroupCreateExternalEntryShadow"
)]
pub enum MulticastGroupCreateExternalEntry {
    /// Any-source group; the source filter is canonicalized at parse.
    Asm(AsmMulticastGroupCreate),
    /// Source-specific group, carrying at least one validated exact source.
    Ssm(SsmMulticastGroupCreate),
}

/// A flat request schema for creating a customer-visible overlay multicast
/// group.
///
/// The group IP address disambiguates whether the group is ASM or SSM.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[schemars(rename = "MulticastGroupCreateExternalEntry")]
pub(crate) struct MulticastGroupCreateExternalEntryShadow {
    /// The multicast address for the group.
    pub(crate) group_ip: ExternalMulticastIp,
    /// Tag for validating update/delete requests. If a tag is not provided,
    /// one is auto-generated as `{uuid}:{group_ip}`.
    pub(crate) tag: Option<String>,
    /// The required NAT target is checked against switch state by the server.
    pub(crate) internal_forwarding: ExternalInternalForwarding,
    /// Egress VLAN configuration for external forwarding.
    pub(crate) external_forwarding: ExternalForwarding,
    /// Optional source list.
    ///
    /// A source list can be absent from ASM group requests. If absent,
    /// empty, or containing `Any`, the group permits every source (i.e., a
    /// wildcard).
    ///
    /// SSM groups require at least one exact source in the list and
    /// reject `Any` wildcard entries.
    pub(crate) sources: Option<Vec<SourceEntry>>,
}

impl TryFrom<MulticastGroupCreateExternalEntryShadow>
    for MulticastGroupCreateExternalEntry
{
    type Error = MulticastGroupCreateExternalError;

    fn try_from(
        entry: MulticastGroupCreateExternalEntryShadow,
    ) -> Result<Self, Self::Error> {
        let classified =
            RequestSources::new(entry.group_ip, entry.sources.as_deref())?;

        Ok(match classified {
            RequestSources::Asm(sources) => {
                Self::Asm(AsmMulticastGroupCreate {
                    group_ip: entry.group_ip,
                    tag: entry.tag,
                    internal_forwarding: entry.internal_forwarding,
                    external_forwarding: entry.external_forwarding,
                    sources,
                })
            }
            RequestSources::Ssm { group_ip, sources } => {
                Self::Ssm(SsmMulticastGroupCreate {
                    group_ip,
                    tag: entry.tag,
                    internal_forwarding: entry.internal_forwarding,
                    external_forwarding: entry.external_forwarding,
                    sources,
                })
            }
        })
    }
}

impl From<MulticastGroupCreateExternalEntry>
    for MulticastGroupCreateExternalEntryShadow
{
    fn from(entry: MulticastGroupCreateExternalEntry) -> Self {
        match entry {
            MulticastGroupCreateExternalEntry::Asm(group) => Self {
                group_ip: group.group_ip,
                tag: group.tag,
                internal_forwarding: group.internal_forwarding,
                external_forwarding: group.external_forwarding,
                sources: group.sources.to_entries(),
            },
            MulticastGroupCreateExternalEntry::Ssm(group) => Self {
                group_ip: group.group_ip.into(),
                tag: group.tag,
                internal_forwarding: group.internal_forwarding,
                external_forwarding: group.external_forwarding,
                sources: Some(
                    group
                        .sources
                        .into_vec()
                        .into_iter()
                        .map(SourceEntry::Exact)
                        .collect(),
                ),
            },
        }
    }
}

impl JsonSchema for MulticastGroupCreateExternalEntry {
    fn schema_name() -> String {
        MulticastGroupCreateExternalEntryShadow::schema_name()
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        MulticastGroupCreateExternalEntryShadow::json_schema(generator)
    }
}

impl TryFrom<v7::mcast::MulticastGroupCreateExternalEntry>
    for MulticastGroupCreateExternalEntry
{
    type Error = MulticastGroupCreateExternalError;

    fn try_from(
        entry: v7::mcast::MulticastGroupCreateExternalEntry,
    ) -> Result<Self, Self::Error> {
        let sources = entry
            .sources
            .map(|sources| {
                sources.into_iter().map(SourceEntry::try_from).collect()
            })
            .transpose()?;

        Self::try_from(MulticastGroupCreateExternalEntryShadow {
            group_ip: ExternalMulticastIp::new(entry.group_ip)?,
            tag: entry.tag,
            internal_forwarding: entry.internal_forwarding.try_into()?,
            external_forwarding: entry.external_forwarding,
            sources,
        })
    }
}

/// Updated forwarding and source-filter settings for an external group.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupUpdateExternalEntry {
    /// Required internal forwarding config.
    pub internal_forwarding: ExternalInternalForwarding,
    /// External VLAN config.
    pub external_forwarding: ExternalForwarding,
    /// Replacement source list, or `None` to preserve the current filter.
    pub sources: Option<Vec<SourceEntry>>,
}

impl TryFrom<v8::mcast::MulticastGroupUpdateExternalEntry>
    for MulticastGroupUpdateExternalEntry
{
    type Error = MulticastGroupCreateExternalError;

    fn try_from(
        entry: v8::mcast::MulticastGroupUpdateExternalEntry,
    ) -> Result<Self, Self::Error> {
        let sources = match entry.sources {
            Some(sources) => sources
                .into_iter()
                .map(SourceEntry::try_from)
                .collect::<Result<_, _>>()?,
            None => vec![SourceEntry::Any],
        };

        Ok(Self {
            internal_forwarding: entry.internal_forwarding.try_into()?,
            external_forwarding: entry.external_forwarding,
            sources: Some(sources),
        })
    }
}

/// Used to identify an external multicast group by IP address.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastExternalGroupIpParam {
    /// A validated external multicast group IP address.
    pub group_ip: ExternalMulticastIp,
}

impl TryFrom<v1::mcast::MulticastGroupIpParam>
    for MulticastExternalGroupIpParam
{
    type Error = ExternalMulticastIpError;

    fn try_from(
        param: v1::mcast::MulticastGroupIpParam,
    ) -> Result<Self, Self::Error> {
        Ok(Self { group_ip: ExternalMulticastIp::new(param.group_ip)? })
    }
}

/// Response structure for external multicast group operations.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupExternalResponse {
    /// The validated multicast address of the group.
    pub group_ip: ExternalMulticastIp,
    /// ASIC replication group ID for the external group.
    pub external_group_id: MulticastGroupId,
    /// Tag for validating update/delete requests. Always present and generated
    /// as `{uuid}:{group_ip}` if not provided at creation time.
    pub tag: String,
    /// NAT target for forwarding onto the underlay.
    pub internal_forwarding: ExternalInternalForwarding,
    /// Egress VLAN configuration for external forwarding.
    pub external_forwarding: ExternalForwarding,
    /// Source filter, or `None` when any source is permitted.
    pub sources: Option<Vec<IpSrc>>,
}

impl From<MulticastGroupExternalResponse>
    for v8::mcast::MulticastGroupExternalResponse
{
    fn from(resp: MulticastGroupExternalResponse) -> Self {
        Self {
            group_ip: resp.group_ip.into(),
            external_group_id: resp.external_group_id,
            tag: resp.tag,
            internal_forwarding: resp.internal_forwarding.into(),
            external_forwarding: resp.external_forwarding,
            sources: resp.sources,
        }
    }
}

/// Unified response type for operations that return mixed group types.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MulticastGroupResponse {
    /// An internal group on the underlay, with members.
    Underlay(MulticastGroupUnderlayResponse),
    /// An external overlay group; NAT target and VLAN, no direct members.
    External(MulticastGroupExternalResponse),
}

impl From<MulticastGroupResponse> for v8::mcast::MulticastGroupResponse {
    fn from(resp: MulticastGroupResponse) -> Self {
        match resp {
            MulticastGroupResponse::Underlay(u) => Self::Underlay(u),
            MulticastGroupResponse::External(e) => Self::External(e.into()),
        }
    }
}
