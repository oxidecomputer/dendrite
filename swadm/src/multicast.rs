// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Inspection of the multicast groups programmed on the switch.
//!
//! Here's an example set of output against a running dpd bin:
//!
//! ```text
//! $ swadm multicast list
//! GROUP IP       KIND      EXT GROUP ID  UL GROUP ID  TAG         DETAIL
//! 224.0.1.50     external  65532         -            oxide-demo  nat=ff04::2 mac=33:33:00:00:00:02 vni=88 vlan=- src=any
//! 232.123.45.99  external  65534         -            oxide-demo  nat=ff04::1 mac=33:33:00:00:00:01 vni=77 vlan=10 src=10.0.0.1,10.0.0.2
//! ff04::1        underlay  65534         65533        oxide-demo  rear0/0(underlay) rear0/0(external)
//! ff04::2        underlay  65532         65531        oxide-demo  -
//! ```
//!
//! ```text
//! $ swadm multicast get 232.123.45.99
//! Group IP:          232.123.45.99
//! Kind:              external
//! External group ID: 65534
//! Tag:               oxide-demo
//! NAT target:        ff04::1 (mac 33:33:00:00:00:01, vni 77)
//! VLAN:              10
//! Sources:           10.0.0.1,10.0.0.2
//! ```
//!
//! ```text
//! $ swadm multicast get ff04::1
//! Group IP:          ff04::1
//! Kind:              underlay
//! External group ID: 65534
//! Underlay group ID: 65533
//! Tag:               oxide-demo
//! Members:
//!   rear0/0 (underlay)
//!   rear0/0 (external)
//! ```

use std::fmt;
use std::io::{Write, stdout};
use std::net::IpAddr;

use anyhow::Context;
use clap::{Subcommand, ValueEnum};
use colored::Colorize;
use futures::stream::TryStreamExt;
use tabwriter::TabWriter;

use dpd_client::{Client, types};

/// Replication kind for a multicast group, matching the `KIND` column.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum GroupKind {
    /// Groups with a NAT target and no direct members.
    External,
    /// Groups in the reserved underlay subnet (ff04::/64) that replicate
    /// to member ports.
    Underlay,
}

#[derive(Debug, Subcommand)]
/// Inspect the multicast groups programmed on the switch.
pub enum Multicast {
    /// List multicast groups, optionally filtered by tag.
    #[clap(visible_alias = "ls")]
    List {
        /// Limit the listing to groups carrying the given tag.
        #[clap(short = 't')]
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
    internal_forwarding: &'a types::InternalForwarding,
    external_forwarding: &'a types::ExternalForwarding,
    sources: Option<&'a [types::IpSrc]>,
}

impl fmt::Display for ExternalSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.internal_forwarding.nat_target {
            Some(t) => write!(
                f,
                "nat={} mac={} vni={}",
                t.internal_ip, t.inner_mac, *t.vni,
            )?,
            None => f.write_str("nat=- mac=- vni=-")?,
        }
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
    let groups: Vec<types::MulticastGroupResponse> = match &tag {
        Some(tag) => {
            let tag = tag
                .parse::<types::MulticastTag>()
                .map_err(|e| anyhow::anyhow!("invalid multicast tag: {e}"))?;
            client
                .multicast_groups_list_by_tag_stream(&tag, None)
                .try_collect()
                .await
                .context("failed to list multicast groups by tag")?
        }
        None => client
            .multicast_groups_list_stream(None)
            .try_collect()
            .await
            .context("failed to list multicast groups")?,
    };

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}",
        "GROUP IP".underline(),
        "KIND".underline(),
        "EXT GROUP ID".underline(),
        "UL GROUP ID".underline(),
        "TAG".underline(),
        "DETAIL".underline(),
    )?;

    for group in groups.iter().filter(|group| {
        matches!(
            (kind, group),
            (None, _)
                | (
                    Some(GroupKind::External),
                    types::MulticastGroupResponse::External { .. }
                )
                | (
                    Some(GroupKind::Underlay),
                    types::MulticastGroupResponse::Underlay { .. }
                )
        )
    }) {
        match group {
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

async fn multicast_get(
    client: &Client,
    group_ip: IpAddr,
) -> anyhow::Result<()> {
    let group = client
        .multicast_group_get(&group_ip)
        .await
        .with_context(|| format!("failed to get multicast group {group_ip}"))?
        .into_inner();

    match group {
        types::MulticastGroupResponse::Underlay {
            group_ip,
            external_group_id,
            underlay_group_id,
            tag,
            members,
        } => {
            println!("Group IP:          {group_ip}");
            println!("Kind:              underlay");
            println!("External group ID: {external_group_id}");
            println!("Underlay group ID: {underlay_group_id}");
            println!("Tag:               {tag}");
            println!("Members:");
            if members.is_empty() {
                println!("  (none)");
            }
            for member in &members {
                println!(
                    "  {}/{} ({})",
                    member.port_id,
                    *member.link_id,
                    DirectionLabel(&member.direction),
                );
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
            println!("Group IP:          {group_ip}");
            println!("Kind:              external");
            println!("External group ID: {external_group_id}");
            println!("Tag:               {tag}");
            match &internal_forwarding.nat_target {
                Some(t) => println!(
                    "NAT target:        {} (mac {}, vni {})",
                    t.internal_ip, t.inner_mac, *t.vni,
                ),
                None => println!("NAT target:        (none)"),
            }
            match external_forwarding.vlan_id {
                Some(v) => println!("VLAN:              {v}"),
                None => println!("VLAN:              (none)"),
            }
            println!(
                "Sources:           {}",
                SourcesSummary(sources.as_deref())
            );
        }
    }

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
    }
}
