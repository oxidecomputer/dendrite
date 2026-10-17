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
//!     --member rear0/0:underlay --member rear0/0:external \
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
//! ff04::1        underlay  65534         65533        oxide-demo  rear0/0(underlay) rear0/0(external)
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
//!   rear0/0(external)
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
use dpd_types::mcast::{ExternalMulticastIp, UnderlayMulticastIpv6};

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
        /// Limit the listing to groups carrying the given tag.
        #[clap(short = 't', long)]
        tag: Option<String>,
        /// Limit the listing to external or underlay groups.
        #[clap(short = 'k', long = "kind")]
        kind: Option<GroupKind>,
    },
    /// Show the full configuration of a single multicast group.
    Get {
        /// Group IP address (IPv4, external IPv6, or underlay IPv6).
        group_ip: IpAddr,
    },
    /// Create an external multicast group and the associated underlay group
    /// that it maps to (1:1).
    Add(AddArgs),
    /// Delete an external multicast group and the underlay group that it maps to.
    Del {
        /// External group address (IPv4, or IPv6 outside ff04::/64), or
        /// an underlay address with --underlay-only.
        group_ip: IpAddr,
        /// The tag the groups were created with; defaults to the client tag.
        #[clap(short = 't', long)]
        tag: Option<String>,
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
    /// VLAN ID to tag forwarded packets with.
    #[clap(long)]
    vlan: Option<u16>,
    /// Source address to filter on.
    ///
    /// Repeat for each source. Each source must match the group's
    /// address family. SSM requires at least one source; omitting this option
    /// accepts any source for ASM.
    #[clap(short = 's', long = "source")]
    sources: Vec<IpAddr>,
    /// Tag to create both groups with; defaults to the client tag.
    #[clap(short = 't', long)]
    tag: Option<String>,
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
            nat_target.internal_ip, nat_target.inner_mac, *nat_target.vni,
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
    tag: Option<String>,
    kind: Option<GroupKind>,
) -> anyhow::Result<()> {
    let tag = tag
        .map(|tag| {
            tag.parse::<types::MulticastTag>().context("invalid multicast tag")
        })
        .transpose()?;
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
/// If external creation fails, attempt to remove the underlay group.
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
    let tag = tag.unwrap_or_else(|| client.inner().tag.clone());
    let underlay_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: underlay,
        tag: Some(tag),
        members: members
            .into_iter()
            .map(|m| types::MulticastGroupMember {
                port_id: m.link.port_id,
                link_id: m.link.link_id,
                direction: m.direction,
            })
            .collect(),
    };

    let tag = client
        .multicast_group_create_underlay(&underlay_entry)
        .await
        .with_context(|| {
            format!("failed to create underlay multicast group {underlay}")
        })?
        .into_inner()
        .tag;

    let external_entry = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(tag.clone()),
        internal_forwarding: types::ExternalInternalForwarding {
            nat_target: types::ExternalNatTarget {
                internal_ip: underlay,
                inner_mac: inner_mac.into(),
                vni: types::Vni::from(vni),
            },
        },
        external_forwarding: types::ExternalForwarding { vlan_id: vlan },
        sources: (!sources.is_empty())
            .then(|| sources.into_iter().map(types::IpSrc::Exact).collect()),
    };

    let created = client
        .multicast_group_create_external(&external_entry)
        .await
        .with_context(|| {
            format!("failed to create external multicast group {group_ip}")
        });

    if let Err(err) = created {
        let underlay_ip = IpAddr::from(underlay);
        let rollback = async {
            let tag: types::MulticastTag =
                tag.parse().with_context(|| format!("invalid tag {tag}"))?;
            client
                .multicast_group_delete(&underlay_ip, &tag)
                .await
                .with_context(|| {
                    format!("failed to remove underlay group {underlay}")
                })
        };

        return match rollback.await {
            Ok(_) => Err(err),
            Err(rollback_err) => Err(err.context(format!("{rollback_err:#}"))),
        };
    }
    Ok(())
}

fn underlay_for_delete(
    group_ip: IpAddr,
    group: types::MulticastGroupResponse,
    tag: &str,
    underlay_only: bool,
) -> anyhow::Result<Option<IpAddr>> {
    match group {
        types::MulticastGroupResponse::External {
            internal_forwarding,
            tag: group_tag,
            ..
        } => {
            anyhow::ensure!(
                !underlay_only,
                "cannot use --underlay-only with external multicast group {group_ip}"
            );

            anyhow::ensure!(
                group_tag == tag,
                "tag mismatch for multicast group {group_ip}"
            );

            Ok(Some(IpAddr::from(internal_forwarding.nat_target.internal_ip)))
        }
        types::MulticastGroupResponse::Underlay { .. } => {
            anyhow::ensure!(
                underlay_only,
                "{group_ip} is an underlay group; delete the external group that \
                 maps to it"
            );
            Ok(None)
        }
    }
}

fn validate_underlay_for_delete(
    underlay: IpAddr,
    group: types::MulticastGroupResponse,
    tag: &str,
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
        underlay_tag == tag,
        "tag mismatch for underlay multicast group {underlay}"
    );
    Ok(())
}

async fn multicast_del(
    client: &Client,
    group_ip: IpAddr,
    tag: String,
    underlay_only: bool,
) -> anyhow::Result<()> {
    let tag_param: types::MulticastTag =
        tag.parse().with_context(|| format!("invalid tag {tag}"))?;

    let group = client
        .multicast_group_get(&group_ip)
        .await
        .with_context(|| format!("failed to get multicast group {group_ip}"))?
        .into_inner();
    let underlay = underlay_for_delete(group_ip, group, &tag, underlay_only)?;

    if let Some(underlay) = underlay {
        let underlay_group = client
            .multicast_group_get(&underlay)
            .await
            .with_context(|| {
                format!("failed to get underlay multicast group {underlay}")
            })?
            .into_inner();
        validate_underlay_for_delete(underlay, underlay_group, &tag)?;
    }

    client.multicast_group_delete(&group_ip, &tag_param).await.with_context(
        || format!("failed to delete multicast group {group_ip}"),
    )?;

    if let Some(underlay) = underlay {
        client
            .multicast_group_delete(&underlay, &tag_param)
            .await
            .with_context(|| {
                format!(
                    "failed to delete underlay group {underlay}; use \
                     --underlay-only to retry its deletion"
                )
            })?;
    }
    Ok(())
}

async fn multicast_get(
    client: &Client,
    group_ip: IpAddr,
) -> anyhow::Result<()> {
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
                nat_target.internal_ip, nat_target.inner_mac, *nat_target.vni,
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
            let tag = tag.unwrap_or_else(|| client.inner().tag.clone());
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
                    vni: types::Vni::from(77_u32),
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
    fn delete_external_requires_matching_tag() -> anyhow::Result<()> {
        let group_ip = "232.123.45.99".parse()?;
        underlay_for_delete(
            group_ip,
            external_group("other_tag")?,
            "test_tag",
            false,
        )
        .expect_err("a mismatched external tag should prevent deletion");
        Ok(())
    }

    #[test]
    fn delete_underlay_only_rejects_external() -> anyhow::Result<()> {
        let group_ip = "232.123.45.99".parse()?;
        underlay_for_delete(
            group_ip,
            external_group("test_tag")?,
            "test_tag",
            true,
        )
        .expect_err("--underlay-only should reject external groups");
        Ok(())
    }

    #[test]
    fn delete_underlay_requires_underlay_only() -> anyhow::Result<()> {
        let group_ip = "ff04::1".parse()?;
        underlay_for_delete(
            group_ip,
            underlay_group("test_tag")?,
            "test_tag",
            false,
        )
        .expect_err("underlay deletion should require --underlay-only");
        Ok(())
    }

    #[test]
    fn delete_underlay_only_skips_pair_deletion() -> anyhow::Result<()> {
        let group_ip = "ff04::1".parse()?;
        assert_eq!(
            underlay_for_delete(
                group_ip,
                underlay_group("test_tag")?,
                "test_tag",
                true,
            )?,
            None
        );
        Ok(())
    }

    #[test]
    fn delete_pair_validates_underlay() -> anyhow::Result<()> {
        let group_ip = "232.123.45.99".parse()?;
        let underlay = "ff04::1".parse()?;
        assert_eq!(
            underlay_for_delete(
                group_ip,
                external_group("test_tag")?,
                "test_tag",
                false,
            )?,
            Some(underlay)
        );
        validate_underlay_for_delete(
            underlay,
            underlay_group("test_tag")?,
            "test_tag",
        )?;

        validate_underlay_for_delete(
            underlay,
            underlay_group("other_tag")?,
            "test_tag",
        )
        .expect_err("a mismatched underlay tag should prevent deletion");

        validate_underlay_for_delete(
            underlay,
            external_group("test_tag")?,
            "test_tag",
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
}
