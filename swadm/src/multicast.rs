// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Inspection, creation, and deletion of the multicast groups programmed on
//! the switch.
//!
//! An example session against a running dpd is shown below. Each `add` creates
//! an external group along with the underlay group it maps to. By default,
//! `del` checks both tags, then deletes the external group followed by its
//! underlay:
//!
//! ```text
//! $ swadm multicast add 232.123.45.99 -i ff04::1 \
//!     --member rear0/0:underlay --member qsfp0/0:external \
//!     -m 33:33:00:00:00:01 -v 77 --vlan 10 -s 10.0.0.1 -s 10.0.0.2 \
//!     -t oxide-demo
//! $ swadm multicast add 224.0.1.50 -i ff04::2 \
//!     -m 33:33:00:00:00:02 -v 88 -t oxide-demo
//! ```
//!
//! ```text
//! $ swadm multicast list -t oxide-demo
//! Group IP       Kind      Ext Group ID  UL Group ID  Tag         Detail
//! 224.0.1.50     external  65532         -            oxide-demo  nat=ff04::2 mac=33:33:00:00:00:02 vni=88 vlan=- src=any
//! 232.123.45.99  external  65534         -            oxide-demo  nat=ff04::1 mac=33:33:00:00:00:01 vni=77 vlan=10 src=10.0.0.1,10.0.0.2
//! ff04::1        underlay  65534         65533        oxide-demo  rear0/0(underlay) qsfp0/0(external)
//! ff04::2        underlay  65532         65531        oxide-demo  -
//! ```
//!
//! ```text
//! $ swadm multicast get 232.123.45.99
//! Group IP:           232.123.45.99
//! Kind:               external
//! External group ID:  65534
//! Tag:                oxide-demo
//! NAT target:         ff04::1 (mac 33:33:00:00:00:01, vni 77)
//! VLAN:               10
//! Sources:            10.0.0.1,10.0.0.2
//! ```
//!
//! ```text
//! $ swadm multicast get ff04::1
//! Group IP:           ff04::1
//! Kind:               underlay
//! External group ID:  65534
//! Underlay group ID:  65533
//! Tag:                oxide-demo
//! Members:
//!   rear0/0(underlay)
//!   qsfp0/0(external)
//! ```
//!
//! ```text
//! $ swadm multicast del ff04::1 -t oxide-demo
//! Error: ff04::1 is an underlay group; delete the external group that maps to it
//! $ swadm multicast del 224.0.1.50 -t oxide-demo
//! $ swadm multicast del 232.123.45.99 -t oxide-demo
//! ```
//!
//! If deleting the external group succeeds but deleting its underlay fails,
//! retry the underlay deletion:
//!
//! ```text
//! $ swadm multicast del ff04::1 --underlay-only -t oxide-demo
//! ```

use std::fmt;
use std::io::{Write, stdout};
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::Context;
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use futures::stream::{StreamExt, TryStreamExt};
use tabwriter::TabWriter;

use common::network::{MacAddr, Vni};
use dpd_client::{Client, ClientInfo, types};
use dpd_types::mcast::{
    ExactSource, ExternalMulticastIp, ExternalMulticastIpError, MulticastTag,
    SourceEntry, SourceFilter, UnderlayMulticastIpv6,
};

use crate::LinkPath;

/// Replication kind for a multicast group, matching the `Kind` column.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum GroupKind {
    /// Groups with a NAT target and no direct members.
    External,
    /// Groups in the reserved underlay subnet (ff04::/64) that replicate
    /// to member ports.
    Underlay,
}

#[derive(Debug, Subcommand)]
/// Inspect, create, and delete the multicast groups programmed on the switch.
pub enum Multicast {
    /// List multicast groups, optionally filtered by tag.
    #[clap(visible_alias = "ls")]
    List {
        /// Limit the listing to groups with the given tag.
        #[clap(short = 't', long)]
        tag: Option<MulticastTag>,
        /// Limit the listing to external or underlay groups.
        #[clap(short = 'k', long = "kind")]
        kind: Option<GroupKind>,
    },
    /// Show the full configuration of a single multicast group.
    Get {
        /// Group IP address (IPv4, external IPv6, or underlay IPv6).
        group_ip: GroupAddr,
    },
    /// Create an external multicast group and the associated underlay group
    /// that it maps to (1:1).
    Add(AddArgs),
    /// Delete an external multicast group as well as the underlay group that
    /// it maps to, or just the unreferenced underlay group with
    /// --underlay-only.
    Del {
        /// External group address (IPv4, or IPv6 outside ff04::/64), or
        /// an underlay address with --underlay-only.
        group_ip: GroupAddr,
        /// The tag the groups were created with; defaults to the client tag.
        #[clap(short = 't', long)]
        tag: Option<MulticastTag>,
        /// Delete only an unreferenced underlay group.
        #[clap(long)]
        underlay_only: bool,
    },
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// External group address (IPv4, or IPv6 outside ff04::/64).
    group_ip: ExternalMulticastIp,
    /// Underlay group address, within the internal ff04::/64 block.
    #[clap(short = 'i', long)]
    underlay: UnderlayMulticastIpv6,
    /// Member described as `port/link:direction`, where direction is underlay
    /// or external.
    ///
    /// Repeat for each member.
    #[clap(long = "member")]
    members: Vec<MemberArg>,
    /// Inner MAC address for the NAT target.
    #[clap(short = 'm', long = "mac")]
    inner_mac: MacAddr,
    /// Geneve VNI for the NAT target.
    #[clap(short = 'v', long)]
    vni: Vni,
    /// VLAN ID to tag on decapsulated packet copies sent to external members.
    #[clap(long)]
    vlan: Option<u16>,
    /// Source address to filter on.
    ///
    /// Repeat for each source. Each source must match the group's
    /// address family. SSM requires at least one source; omitting this option
    /// accepts any source for ASM.
    #[clap(short = 's', long = "source")]
    sources: Vec<ExactSource>,
    /// Tag to create both groups with; defaults to the client tag.
    #[clap(short = 't', long)]
    tag: Option<MulticastTag>,
}

/// A multicast group address that is either an underlay (`ff04::/64`) or
/// external.
#[derive(Debug, Clone, Copy)]
pub enum GroupAddr {
    /// An external multicast group address.
    External(ExternalMulticastIp),
    /// An underlay group address within `ff04::/64`.
    Underlay(UnderlayMulticastIpv6),
}

/// Errors from parsing a [`GroupAddr`].
#[derive(Debug, thiserror::Error)]
pub enum GroupAddrParseError {
    /// The input is not an IP address.
    #[error(transparent)]
    InvalidIp(#[from] std::net::AddrParseError),
    /// The address is neither an underlay group nor a valid external group.
    #[error(
        "{0}; expected an external multicast group or an underlay group \
         within ff04::/64"
    )]
    InvalidGroup(#[from] ExternalMulticastIpError),
}

impl FromStr for GroupAddr {
    type Err = GroupAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: IpAddr = s.parse()?;
        if let IpAddr::V6(v6) = ip
            && let Ok(underlay) = UnderlayMulticastIpv6::new(v6)
        {
            return Ok(Self::Underlay(underlay));
        }
        Ok(Self::External(ExternalMulticastIp::new(ip)?))
    }
}

impl From<GroupAddr> for IpAddr {
    fn from(addr: GroupAddr) -> Self {
        match addr {
            GroupAddr::External(ip) => ip.into(),
            GroupAddr::Underlay(ip) => ip.into(),
        }
    }
}

impl fmt::Display for GroupAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        IpAddr::from(*self).fmt(f)
    }
}

fn tag_or_client_default(
    client: &Client,
    tag: Option<MulticastTag>,
) -> anyhow::Result<MulticastTag> {
    match tag {
        Some(tag) => Ok(tag),
        None => {
            let tag = &client.inner().tag;
            tag.parse().with_context(|| format!("invalid client tag {tag}"))
        }
    }
}

/// A group member parsed from `port/link:direction`.
#[derive(Debug, Clone)]
pub struct MemberArg {
    link: LinkPath,
    direction: types::Direction,
}

impl FromStr for MemberArg {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (link, direction) = s.split_once(':').with_context(|| {
            format!("expected port/link:direction, got {s}")
        })?;
        let direction = match direction {
            "underlay" => Some(types::Direction::Underlay),
            "external" => Some(types::Direction::External),
            _ => None,
        }
        .with_context(|| {
            format!(
                "invalid direction {direction}: expected underlay or external"
            )
        })?;
        Ok(Self { link: link.parse()?, direction })
    }
}

struct DirectionLabel<'a>(&'a types::Direction);

impl fmt::Display for DirectionLabel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            types::Direction::Underlay => f.write_str("underlay"),
            types::Direction::External => f.write_str("external"),
        }
    }
}

struct MembersSummary<'a>(&'a [types::MulticastGroupMember]);

impl fmt::Display for MembersSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("-");
        }
        let members = self
            .0
            .iter()
            .map(|member| {
                format!(
                    "{}/{}({})",
                    member.port_id,
                    *member.link_id,
                    DirectionLabel(&member.direction),
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        f.write_str(&members)
    }
}

struct SourcesSummary<'a>(Option<&'a [types::IpSrc]>);

impl fmt::Display for SourcesSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(sources) if !sources.is_empty() => {
                let sources = sources
                    .iter()
                    .map(|source| match source {
                        types::IpSrc::Exact(ip) => ip.to_string(),
                        types::IpSrc::Any => "any".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                f.write_str(&sources)
            }
            _ => f.write_str("any"),
        }
    }
}

struct ExternalSummary<'a> {
    internal_forwarding: &'a types::ExternalInternalForwarding,
    external_forwarding: &'a types::ExternalForwarding,
    sources: Option<&'a [types::IpSrc]>,
}

impl fmt::Display for ExternalSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nat_target = &self.internal_forwarding.nat_target;
        write!(
            f,
            "nat={} mac={} vni={}",
            nat_target.internal_ip,
            nat_target.inner_mac,
            nat_target.vni.as_u32(),
        )?;
        match self.external_forwarding.vlan_id {
            Some(v) => write!(f, " vlan={v}")?,
            None => f.write_str(" vlan=-")?,
        }
        write!(f, " src={}", SourcesSummary(self.sources))
    }
}

async fn multicast_list(
    client: &Client,
    tag: Option<MulticastTag>,
    kind: Option<GroupKind>,
) -> anyhow::Result<()> {
    let mut groups = match &tag {
        Some(tag) => {
            client.multicast_groups_list_by_tag_stream(tag, None).boxed()
        }
        None => client.multicast_groups_list_stream(None).boxed(),
    };

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}",
        "Group IP".underline(),
        "Kind".underline(),
        "Ext Group ID".underline(),
        "UL Group ID".underline(),
        "Tag".underline(),
        "Detail".underline(),
    )?;

    while let Some(group) =
        groups.try_next().await.context("failed to list multicast groups")?
    {
        if !matches!(
            (kind, &group),
            (None, _)
                | (
                    Some(GroupKind::External),
                    types::MulticastGroupResponse::External { .. }
                )
                | (
                    Some(GroupKind::Underlay),
                    types::MulticastGroupResponse::Underlay { .. }
                )
        ) {
            continue;
        }
        match &group {
            types::MulticastGroupResponse::Underlay {
                group_ip,
                external_group_id,
                underlay_group_id,
                tag,
                members,
            } => writeln!(
                &mut tw,
                "{}\tunderlay\t{}\t{}\t{}\t{}",
                group_ip,
                external_group_id,
                underlay_group_id,
                tag,
                MembersSummary(members),
            )?,
            types::MulticastGroupResponse::External {
                group_ip,
                external_group_id,
                tag,
                internal_forwarding,
                external_forwarding,
                sources,
            } => writeln!(
                &mut tw,
                "{}\texternal\t{}\t-\t{}\t{}",
                group_ip,
                external_group_id,
                tag,
                ExternalSummary {
                    internal_forwarding,
                    external_forwarding,
                    sources: sources.as_deref(),
                },
            )?,
        }
    }

    tw.flush()?;
    Ok(())
}

/// Create both an underlay group and its associated external group with a
/// shared tag.
///
/// # Rollback
///
/// A failed creation step removes what this command created:
///
/// - Underlay creation fails with a dpd rollback failure: dpd kept the
///   underlay group, and it is removed.
/// - External creation fails: the underlay group is removed. When dpd reports
///   a rollback failure, it kept the external group, and that group is removed
///   first.
/// - External creation fails without a dpd response: the external group is
///   removed first only if a read-back shows it has this tag and targets
///   the new underlay group.
///
/// This preserves the initial creation error and includes any cleanup failure.
async fn multicast_add(client: &Client, args: AddArgs) -> anyhow::Result<()> {
    let AddArgs {
        group_ip,
        underlay,
        members,
        inner_mac,
        vni,
        vlan,
        sources,
        tag,
    } = args;
    let tag = tag_or_client_default(client, tag)?;
    let source_entries =
        sources.into_iter().map(SourceEntry::Exact).collect::<Vec<_>>();
    let sources = SourceFilter::from_entries(group_ip, Some(&source_entries))?;
    let underlay_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: underlay,
        tag: Some(String::from(tag.clone())),
        members: members
            .into_iter()
            .map(|m| types::MulticastGroupMember {
                port_id: m.link.port_id,
                link_id: m.link.link_id,
                direction: m.direction,
            })
            .collect(),
    };

    let underlay_context =
        || format!("failed to create underlay multicast group {underlay}");

    match client.multicast_group_create_underlay(&underlay_entry).await {
        Ok(_) => {}
        Err(err)
            if has_error_code(
                &err,
                dpd_client::ROLLBACK_FAILURE_ERROR_CODE,
            ) =>
        {
            let err = anyhow::Error::new(err).context(underlay_context());
            let cleanup = remove_underlay(client, underlay, &tag).await;
            return Err(with_cleanup_failure(err, "cleanup", cleanup));
        }
        Err(err)
            if !matches!(
                err,
                dpd_client::Error::ErrorResponse(_)
                    | dpd_client::Error::InvalidRequest(_)
            ) =>
        {
            return Err(anyhow::Error::new(err).context(format!(
                "{}; dpd may have created underlay group {underlay}. If \
                 `swadm multicast get {underlay}` shows tag {tag}, remove \
                 the group with `swadm multicast del {underlay} \
                 --underlay-only -t {tag}`",
                underlay_context()
            )));
        }
        Err(err) => {
            return Err(anyhow::Error::new(err).context(underlay_context()));
        }
    }

    let external_entry = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(String::from(tag.clone())),
        internal_forwarding: types::ExternalInternalForwarding {
            nat_target: types::ExternalNatTarget {
                internal_ip: underlay,
                inner_mac: inner_mac.into(),
                vni,
            },
        },
        external_forwarding: types::ExternalForwarding { vlan_id: vlan },
        sources: sources.exact_sources().map(|sources| {
            sources
                .iter()
                .map(|source| types::IpSrc::Exact(source.ip()))
                .collect()
        }),
    };

    let created = client.multicast_group_create_external(&external_entry).await;

    if let Err(err) = created {
        let failure = ExternalCreateFailure::from(&err);
        let err = anyhow::Error::new(err).context(format!(
            "failed to create external multicast group {group_ip}"
        ));
        let rollback =
            multicast_add_rollback(client, failure, group_ip, underlay, &tag)
                .await;
        return Err(with_cleanup_failure(err, "rollback", rollback));
    }
    Ok(())
}

fn with_cleanup_failure(
    err: anyhow::Error,
    what: &str,
    cleanup: anyhow::Result<()>,
) -> anyhow::Error {
    cleanup
        .err()
        .map(|cleanup_err| {
            anyhow::anyhow!("{err:#}; {what} also failed ({cleanup_err:#})")
        })
        .unwrap_or(err)
}

fn has_error_code(err: &dpd_client::Error<types::Error>, code: &str) -> bool {
    matches!(
        err,
        dpd_client::Error::ErrorResponse(response)
            if response.error_code.as_deref() == Some(code)
    )
}

fn is_not_found(err: &dpd_client::Error<types::Error>) -> bool {
    err.status() == Some(reqwest::StatusCode::NOT_FOUND)
}

/// Whether a failed external create left the external group on the switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalCreateFailure {
    /// dpd rejected the request without keeping the group.
    NotRetained,
    /// dpd's unwind failed and it kept the group, marked for repair.
    Retained,
    /// No dpd error response arrived, so the group may or may not exist.
    Unknown,
}

impl From<&dpd_client::Error<types::Error>> for ExternalCreateFailure {
    fn from(err: &dpd_client::Error<types::Error>) -> Self {
        match err {
            _ if has_error_code(
                err,
                dpd_client::ROLLBACK_FAILURE_ERROR_CODE,
            ) =>
            {
                Self::Retained
            }
            dpd_client::Error::ErrorResponse(_)
            | dpd_client::Error::InvalidRequest(_) => Self::NotRetained,
            _ => Self::Unknown,
        }
    }
}

/// Whether `group` is the external group this `add` would have created.
///
/// The underlay was created by the same command, so only an external group
/// with this tag and that underlay NAT target can belong to it.
fn created_by_this_add(
    group: &types::MulticastGroupResponse,
    underlay: UnderlayMulticastIpv6,
    tag: &MulticastTag,
) -> bool {
    matches!(
        group,
        types::MulticastGroupResponse::External {
            internal_forwarding,
            tag: group_tag,
            ..
        } if group_tag == tag.as_ref()
            && internal_forwarding.nat_target.internal_ip == underlay
    )
}

async fn reconcile_external_create(
    client: &Client,
    group_ip: ExternalMulticastIp,
    underlay: UnderlayMulticastIpv6,
    tag: &MulticastTag,
) -> ExternalCreateFailure {
    match multicast_group_for_delete(client, group_ip.into()).await {
        Ok(group) if created_by_this_add(&group, underlay, tag) => {
            ExternalCreateFailure::Retained
        }
        Ok(_) => ExternalCreateFailure::NotRetained,
        Err(e)
            if e.downcast_ref::<dpd_client::Error<types::Error>>()
                .is_some_and(is_not_found) =>
        {
            ExternalCreateFailure::NotRetained
        }
        Err(_) => ExternalCreateFailure::Unknown,
    }
}

async fn multicast_add_rollback(
    client: &Client,
    failure: ExternalCreateFailure,
    group_ip: ExternalMulticastIp,
    underlay: UnderlayMulticastIpv6,
    tag: &MulticastTag,
) -> anyhow::Result<()> {
    let failure = match failure {
        ExternalCreateFailure::Unknown => {
            reconcile_external_create(client, group_ip, underlay, tag).await
        }
        known => known,
    };

    match failure {
        ExternalCreateFailure::Retained => {
            match client.multicast_group_delete(&group_ip.into(), tag).await {
                Err(e) if is_not_found(&e) => {}
                removed => {
                    removed.with_context(|| {
                        format!(
                            "failed to remove external group {group_ip}; it \
                             and underlay group {underlay} remain, remove \
                             both with `swadm multicast del {group_ip} -t \
                             {tag}`"
                        )
                    })?;
                }
            }
        }
        ExternalCreateFailure::NotRetained | ExternalCreateFailure::Unknown => {
        }
    }

    match client.multicast_group_delete(&underlay.into(), tag).await {
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e)
            if has_error_code(
                &e,
                dpd_client::MCAST_GROUP_REFERENCED_ERROR_CODE,
            ) =>
        {
            Err(e).with_context(|| {
                format!(
                    "failed to remove underlay group {underlay}; external \
                     group {group_ip} may reference it. If `swadm multicast \
                     get {group_ip}` shows NAT target {underlay}, remove both \
                     with `swadm multicast del {group_ip} -t {tag}`"
                )
            })
        }
        removed => removed.map(|_| ()).with_context(|| {
            format!(
                "failed to remove underlay group {underlay}; it remains, \
                 remove it with \
                 `swadm multicast del {underlay} --underlay-only -t {tag}`"
            )
        }),
    }
}

async fn remove_underlay(
    client: &Client,
    underlay: UnderlayMulticastIpv6,
    tag: &MulticastTag,
) -> anyhow::Result<()> {
    match client.multicast_group_delete(&underlay.into(), tag).await {
        Err(e) if is_not_found(&e) => Ok(()),
        removed => removed.map(|_| ()).with_context(|| {
            format!(
                "failed to remove underlay group {underlay}; it remains, \
                 remove it with \
                 `swadm multicast del {underlay} --underlay-only -t {tag}`"
            )
        }),
    }
}

fn underlay_for_delete(
    group_ip: ExternalMulticastIp,
    group: types::MulticastGroupResponse,
    tag: &MulticastTag,
) -> anyhow::Result<UnderlayMulticastIpv6> {
    match group {
        types::MulticastGroupResponse::External {
            internal_forwarding,
            tag: group_tag,
            ..
        } => {
            anyhow::ensure!(
                group_tag == tag.as_ref(),
                "tag mismatch for multicast group {group_ip}: given {tag}, \
                 group has {group_tag}"
            );

            Ok(internal_forwarding.nat_target.internal_ip)
        }
        types::MulticastGroupResponse::Underlay { .. } => {
            anyhow::bail!("multicast group {group_ip} is not an external group")
        }
    }
}

fn validate_underlay_for_delete(
    underlay: UnderlayMulticastIpv6,
    group: types::MulticastGroupResponse,
    tag: &MulticastTag,
) -> anyhow::Result<()> {
    let underlay_tag = match group {
        types::MulticastGroupResponse::Underlay { tag, .. } => tag,
        types::MulticastGroupResponse::External { .. } => {
            anyhow::bail!(
                "multicast group {underlay} is not an underlay group"
            );
        }
    };

    anyhow::ensure!(
        underlay_tag == tag.as_ref(),
        "tag mismatch for underlay multicast group {underlay}: given {tag}, \
         group has {underlay_tag}"
    );
    Ok(())
}

async fn multicast_del(
    client: &Client,
    addr: GroupAddr,
    tag: MulticastTag,
    underlay_only: bool,
) -> anyhow::Result<()> {
    let group_ip = match (addr, underlay_only) {
        (GroupAddr::Underlay(underlay), true) => {
            client
                .multicast_group_delete(&underlay.into(), &tag)
                .await
                .with_context(|| {
                    format!("failed to delete multicast group {underlay}")
                })?;
            return Ok(());
        }
        (GroupAddr::External(group_ip), true) => anyhow::bail!(
            "cannot use --underlay-only with external multicast group \
             {group_ip}"
        ),
        (GroupAddr::Underlay(underlay), false) => anyhow::bail!(
            "{underlay} is an underlay group; delete the external group that \
             maps to it"
        ),
        (GroupAddr::External(group_ip), false) => group_ip,
    };

    let external_group =
        multicast_group_for_delete(client, group_ip.into()).await?;
    let underlay = underlay_for_delete(group_ip, external_group, &tag)?;

    let underlay_group =
        multicast_group_for_delete(client, underlay.into()).await?;
    validate_underlay_for_delete(underlay, underlay_group, &tag)?;

    client.multicast_group_delete(&group_ip.into(), &tag).await.with_context(
        || format!("failed to delete multicast group {group_ip}"),
    )?;

    client.multicast_group_delete(&underlay.into(), &tag).await.with_context(
        || {
            format!(
                "failed to delete underlay group {underlay}; retry with \
                 `swadm multicast del {underlay} --underlay-only -t {tag}`"
            )
        },
    )?;
    Ok(())
}

async fn multicast_group_for_delete(
    client: &Client,
    group_ip: IpAddr,
) -> anyhow::Result<types::MulticastGroupResponse> {
    let err = match client.multicast_group_get(&group_ip).await {
        Ok(group) => return Ok(group.into_inner()),
        Err(err) => err,
    };

    if has_error_code(&err, dpd_client::MCAST_REPAIR_PENDING_ERROR_CODE) {
        let mut groups = client.multicast_groups_list_stream(None);
        while let Some(group) = groups
            .try_next()
            .await
            .context("failed to list multicast groups pending repair")?
        {
            let addr = match &group {
                types::MulticastGroupResponse::External {
                    group_ip, ..
                } => IpAddr::from(*group_ip),
                types::MulticastGroupResponse::Underlay {
                    group_ip, ..
                } => IpAddr::from(*group_ip),
            };

            if addr == group_ip {
                return Ok(group);
            }

            if addr > group_ip {
                break;
            }
        }
    }

    Err(err)
        .with_context(|| format!("failed to get multicast group {group_ip}"))
}

async fn multicast_get(
    client: &Client,
    group: GroupAddr,
) -> anyhow::Result<()> {
    let group_ip = IpAddr::from(group);
    let group = client
        .multicast_group_get(&group_ip)
        .await
        .with_context(|| format!("failed to get multicast group {group_ip}"))?
        .into_inner();

    let mut tw = TabWriter::new(stdout());
    match group {
        types::MulticastGroupResponse::Underlay {
            group_ip,
            external_group_id,
            underlay_group_id,
            tag,
            members,
        } => {
            writeln!(&mut tw, "Group IP:\t{group_ip}")?;
            writeln!(&mut tw, "Kind:\tunderlay")?;
            writeln!(&mut tw, "External group ID:\t{external_group_id}")?;
            writeln!(&mut tw, "Underlay group ID:\t{underlay_group_id}")?;
            writeln!(&mut tw, "Tag:\t{tag}")?;
            writeln!(&mut tw, "Members:")?;
            if members.is_empty() {
                writeln!(&mut tw, "  (none)")?;
            }
            for member in &members {
                writeln!(
                    &mut tw,
                    "  {}/{}({})",
                    member.port_id,
                    *member.link_id,
                    DirectionLabel(&member.direction),
                )?;
            }
        }
        types::MulticastGroupResponse::External {
            group_ip,
            external_group_id,
            tag,
            internal_forwarding,
            external_forwarding,
            sources,
        } => {
            writeln!(&mut tw, "Group IP:\t{group_ip}")?;
            writeln!(&mut tw, "Kind:\texternal")?;
            writeln!(&mut tw, "External group ID:\t{external_group_id}")?;
            writeln!(&mut tw, "Tag:\t{tag}")?;
            let nat_target = &internal_forwarding.nat_target;
            writeln!(
                &mut tw,
                "NAT target:\t{} (mac {}, vni {})",
                nat_target.internal_ip,
                nat_target.inner_mac,
                nat_target.vni.as_u32(),
            )?;
            match external_forwarding.vlan_id {
                Some(v) => writeln!(&mut tw, "VLAN:\t{v}")?,
                None => writeln!(&mut tw, "VLAN:\t(none)")?,
            }
            writeln!(
                &mut tw,
                "Sources:\t{}",
                SourcesSummary(sources.as_deref())
            )?;
        }
    }

    tw.flush()?;
    Ok(())
}

pub async fn multicast_cmd(
    client: &Client,
    cmd: Multicast,
) -> anyhow::Result<()> {
    match cmd {
        Multicast::List { tag, kind } => {
            multicast_list(client, tag, kind).await
        }
        Multicast::Get { group_ip } => multicast_get(client, group_ip).await,
        Multicast::Add(args) => multicast_add(client, args).await,
        Multicast::Del { group_ip, tag, underlay_only } => {
            let tag = tag_or_client_default(client, tag)?;
            multicast_del(client, group_ip, tag, underlay_only).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn external_group(
        tag: &str,
    ) -> anyhow::Result<types::MulticastGroupResponse> {
        Ok(types::MulticastGroupResponse::External {
            group_ip: "232.123.45.99".parse()?,
            external_group_id: 65534_u16,
            tag: tag.to_string(),
            internal_forwarding: types::ExternalInternalForwarding {
                nat_target: types::ExternalNatTarget {
                    internal_ip: "ff04::1".parse()?,
                    inner_mac: "11:22:33:44:55:66".parse::<MacAddr>()?.into(),
                    vni: Vni::new(77)?,
                },
            },
            external_forwarding: types::ExternalForwarding {
                vlan_id: Some(10),
            },
            sources: Some(vec![types::IpSrc::Exact("10.0.0.1".parse()?)]),
        })
    }

    fn underlay_group(
        tag: &str,
    ) -> anyhow::Result<types::MulticastGroupResponse> {
        Ok(types::MulticastGroupResponse::Underlay {
            group_ip: "ff04::1".parse()?,
            external_group_id: 65534_u16,
            underlay_group_id: 65533_u16,
            tag: tag.to_string(),
            members: vec![],
        })
    }

    #[test]
    fn group_addr_parses_underlay_and_external() -> anyhow::Result<()> {
        for addr in ["ff04::1", "ff04::ffff:1"] {
            assert!(matches!(addr.parse()?, GroupAddr::Underlay(_)), "{addr}");
        }

        for addr in ["232.123.45.99", "224.1.2.3", "ff0e::1", "ff04:0:0:1::1"] {
            assert!(matches!(addr.parse()?, GroupAddr::External(_)), "{addr}");
        }

        for addr in ["10.0.0.1", "ff02::1", "not-an-ip"] {
            addr.parse::<GroupAddr>()
                .expect_err("non-group addresses should be rejected");
        }
        Ok(())
    }

    #[tokio::test]
    async fn add_validates_sources_before_underlay() -> anyhow::Result<()> {
        use dpd_types::mcast::MulticastGroupCreateExternalError;

        let client = Client::new_with_client(
            "http://127.0.0.1:0",
            reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(1))
                .build()?,
            dpd_client::ClientState {
                tag: "test_tag".to_string(),
                log: slog::Logger::root(slog::Discard, slog::o!()),
            },
        );

        for (group, source) in [
            ("232.123.45.99", None),
            ("ff3e::8000:1234", None),
            ("224.1.2.3", Some("2001:db8::1")),
            ("ff0e::1", Some("10.0.0.1")),
            ("232.123.45.99", Some("2001:db8::1")),
            ("ff3e::8000:1234", Some("10.0.0.1")),
        ] {
            let group_ip: ExternalMulticastIp = group.parse()?;
            let source = source
                .map(|source| source.parse::<ExactSource>())
                .transpose()?;
            let expected = match source {
                Some(source) => {
                    MulticastGroupCreateExternalError::SourceFamilyMismatch {
                        source_ip: source.ip(),
                        group: group_ip.into(),
                    }
                }
                None => MulticastGroupCreateExternalError::SsmRequiresSources(
                    group_ip.into(),
                ),
            };
            let err = multicast_add(
                &client,
                AddArgs {
                    group_ip,
                    underlay: "ff04::1".parse()?,
                    members: vec![],
                    inner_mac: "11:22:33:44:55:66".parse()?,
                    vni: Vni::new(77)?,
                    vlan: None,
                    sources: source.into_iter().collect(),
                    tag: None,
                },
            )
            .await
            .expect_err("invalid sources should fail before creating a group");

            assert_eq!(
                err.downcast_ref::<MulticastGroupCreateExternalError>(),
                Some(&expected),
                "{group} with source {source:?}: {err:#}",
            );
        }
        Ok(())
    }

    #[test]
    fn delete_external_requires_matching_tag() -> anyhow::Result<()> {
        let group_ip = "232.123.45.99".parse()?;
        underlay_for_delete(
            group_ip,
            external_group("other_tag")?,
            &"test_tag".parse()?,
        )
        .expect_err("a mismatched external tag should prevent deletion");
        Ok(())
    }

    #[test]
    fn delete_external_rejects_underlay_response() -> anyhow::Result<()> {
        let group_ip = "232.123.45.99".parse()?;
        underlay_for_delete(
            group_ip,
            underlay_group("test_tag")?,
            &"test_tag".parse()?,
        )
        .expect_err("an external address resolving to an underlay group");
        Ok(())
    }

    #[test]
    fn delete_pair_validates_underlay() -> anyhow::Result<()> {
        let group_ip = "232.123.45.99".parse()?;
        let underlay: UnderlayMulticastIpv6 = "ff04::1".parse()?;
        let tag: MulticastTag = "test_tag".parse()?;
        assert_eq!(
            underlay_for_delete(group_ip, external_group("test_tag")?, &tag)?,
            underlay
        );
        validate_underlay_for_delete(
            underlay,
            underlay_group("test_tag")?,
            &tag,
        )?;

        validate_underlay_for_delete(
            underlay,
            underlay_group("other_tag")?,
            &tag,
        )
        .expect_err("a mismatched underlay tag should prevent deletion");

        validate_underlay_for_delete(
            underlay,
            external_group("test_tag")?,
            &tag,
        )
        .expect_err("pair deletion should require an underlay group");
        Ok(())
    }

    #[test]
    fn member_arg_parses_direction() -> anyhow::Result<()> {
        let member: MemberArg = "int0/0:external".parse()?;
        assert!(matches!(member.direction, types::Direction::External));
        let member: MemberArg = "int0/0:underlay".parse()?;
        assert!(matches!(member.direction, types::Direction::Underlay));
        Ok(())
    }

    #[test]
    fn member_arg_rejects_bad_input() {
        "int0/0".parse::<MemberArg>().expect_err("a member needs a direction");
        "int0/0:sideways"
            .parse::<MemberArg>()
            .expect_err("direction must be underlay or external");
    }

    fn error_response(
        status: reqwest::StatusCode,
        error_code: Option<&str>,
    ) -> dpd_client::Error<types::Error> {
        dpd_client::Error::ErrorResponse(dpd_client::ResponseValue::new(
            types::Error {
                error_code: error_code.map(str::to_string),
                message: "test".to_string(),
                request_id: "test".to_string(),
            },
            status,
            reqwest::header::HeaderMap::new(),
        ))
    }

    #[test]
    fn external_create_failure_from_responses() {
        let unwind = error_response(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            Some(dpd_client::ROLLBACK_FAILURE_ERROR_CODE),
        );
        assert_eq!(
            ExternalCreateFailure::from(&unwind),
            ExternalCreateFailure::Retained
        );

        for err in [
            error_response(reqwest::StatusCode::CONFLICT, None),
            error_response(reqwest::StatusCode::BAD_REQUEST, None),
            error_response(
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                Some(dpd_client::MCAST_REPAIR_PENDING_ERROR_CODE),
            ),
            dpd_client::Error::InvalidRequest("unsent".to_string()),
        ] {
            assert_eq!(
                ExternalCreateFailure::from(&err),
                ExternalCreateFailure::NotRetained,
                "{err:?} must not trigger external group removal"
            );
        }

        assert_eq!(
            ExternalCreateFailure::from(&dpd_client::Error::Custom(
                "hook".to_string()
            )),
            ExternalCreateFailure::Unknown
        );
    }

    #[test]
    fn reconcile_matches_only_this_adds_group() -> anyhow::Result<()> {
        let ours: UnderlayMulticastIpv6 = "ff04::1".parse()?;
        let tag: MulticastTag = "test_tag".parse()?;
        assert!(created_by_this_add(&external_group("test_tag")?, ours, &tag));

        let other_underlay: UnderlayMulticastIpv6 = "ff04::2".parse()?;
        assert!(
            !created_by_this_add(
                &external_group("test_tag")?,
                other_underlay,
                &tag
            ),
            "a pre-existing group targeting another underlay is not ours"
        );
        assert!(
            !created_by_this_add(&external_group("other_tag")?, ours, &tag),
            "a group with another tag is not ours"
        );
        assert!(
            !created_by_this_add(&underlay_group("test_tag")?, ours, &tag),
            "an underlay group is never the external group we created"
        );
        Ok(())
    }

    mod proptests {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use dpd_types_versions::latest::mcast::{UnicastAddrV4, UnicastAddrV6};
        use dpd_types_versions::testing::{
            ipv4_asm_group_strategy, ipv4_ssm_group_strategy,
            ipv6_asm_group_strategy, ipv6_ssm_group_strategy,
        };
        use proptest::prelude::*;

        use super::*;

        fn external_group_strategy() -> impl Strategy<Value = IpAddr> {
            prop_oneof![
                ipv4_asm_group_strategy().prop_map(IpAddr::V4),
                ipv4_ssm_group_strategy().prop_map(IpAddr::V4),
                ipv6_asm_group_strategy().prop_map(IpAddr::V6),
                ipv6_ssm_group_strategy().prop_map(IpAddr::V6),
            ]
        }

        fn unicast_source_strategy() -> impl Strategy<Value = IpAddr> {
            prop_oneof![
                any::<UnicastAddrV4>().prop_map(IpAddr::from),
                any::<UnicastAddrV6>().prop_map(IpAddr::from),
            ]
        }

        fn port_strategy() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("int0".to_string()),
                (0u8..32).prop_map(|n| format!("rear{n}")),
                (0u8..32).prop_map(|n| format!("qsfp{n}")),
            ]
        }

        proptest! {
            #[test]
            fn group_addr_parses_external_groups(
                addr in external_group_strategy(),
            ) {
                let parsed: GroupAddr = addr.to_string().parse().unwrap();
                prop_assert!(matches!(parsed, GroupAddr::External(_)));
                prop_assert_eq!(IpAddr::from(parsed), addr);
                prop_assert_eq!(parsed.to_string(), addr.to_string());
            }

            #[test]
            fn group_addr_parses_underlay_groups(
                underlay in any::<UnderlayMulticastIpv6>(),
            ) {
                let addr = IpAddr::from(underlay);
                let parsed: GroupAddr = addr.to_string().parse().unwrap();
                prop_assert!(matches!(parsed, GroupAddr::Underlay(_)));
                prop_assert_eq!(IpAddr::from(parsed), addr);
                prop_assert_eq!(parsed.to_string(), addr.to_string());
            }

            #[test]
            fn group_addr_rejects_unicast(addr in unicast_source_strategy()) {
                prop_assert!(addr.to_string().parse::<GroupAddr>().is_err());
            }

            #[test]
            fn member_arg_parses(
                port in port_strategy(),
                link in 0u8..8,
                external in any::<bool>(),
            ) {
                let direction = if external { "external" } else { "underlay" };
                let member: MemberArg =
                    format!("{port}/{link}:{direction}").parse().unwrap();
                prop_assert_eq!(member.link.port_id.to_string(), port);
                prop_assert_eq!(*member.link.link_id, link);
                prop_assert_eq!(
                    DirectionLabel(&member.direction).to_string(),
                    direction
                );
            }
        }

        #[test]
        fn group_addr_rejects_unspecified() {
            for addr in [
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ] {
                addr.to_string()
                    .parse::<GroupAddr>()
                    .expect_err("unspecified addresses are not groups");
            }
        }
    }
}
