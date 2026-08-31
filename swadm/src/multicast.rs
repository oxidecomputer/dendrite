// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::io::{Write, stdout};
use std::net::IpAddr;

use anyhow::Context;
use clap::Subcommand;
use colored::Colorize;
use futures::stream::TryStreamExt;
use tabwriter::TabWriter;

use dpd_client::{Client, types};

#[derive(Debug, Subcommand)]
/// Inspect the multicast groups programmed on the switch.
pub enum Multicast {
    /// List multicast groups, optionally filtered by tag.
    #[clap(visible_alias = "ls")]
    List {
        /// Limit the listing to groups carrying the given tag.
        #[clap(short = 't')]
        tag: Option<String>,
    },
    /// Show the full configuration of a single multicast group.
    Get {
        /// Group IP address (IPv4, external IPv6, or underlay IPv6).
        group_ip: IpAddr,
    },
}

/// Lowercase label for a member's replication direction, matching the
/// lowercase `KIND` column.
fn direction_label(direction: &types::Direction) -> &'static str {
    match direction {
        types::Direction::Underlay => "underlay",
        types::Direction::External => "external",
    }
}

/// Render the members of an underlay group as a compact `port/link(dir)` list.
fn members_summary(members: &[types::MulticastGroupMember]) -> String {
    if members.is_empty() {
        return "-".to_string();
    }
    members
        .iter()
        .map(|member| {
            format!(
                "{}/{}({})",
                member.port_id,
                *member.link_id,
                direction_label(&member.direction)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render the NAT target, VLAN, and source filter of an external group.
fn external_summary(
    internal_forwarding: &types::InternalForwarding,
    external_forwarding: &types::ExternalForwarding,
    sources: Option<&Vec<types::IpSrc>>,
) -> String {
    let nat = match &internal_forwarding.nat_target {
        Some(t) => format!("nat={}", t.internal_ip),
        None => "nat=-".to_string(),
    };
    let vlan = match external_forwarding.vlan_id {
        Some(v) => format!("vlan={v}"),
        None => "vlan=-".to_string(),
    };
    let srcs = match sources {
        Some(s) if !s.is_empty() => {
            let list = s
                .iter()
                .map(|src| match src {
                    types::IpSrc::Exact(ip) => ip.to_string(),
                    types::IpSrc::Any => "any".to_string(),
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("src={list}")
        }
        _ => "src=any".to_string(),
    };
    format!("{nat} {vlan} {srcs}")
}

async fn multicast_list(
    client: &Client,
    tag: Option<String>,
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

    for group in &groups {
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
                members_summary(members),
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
                external_summary(
                    internal_forwarding,
                    external_forwarding,
                    sources.as_ref(),
                ),
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
                    direction_label(&member.direction)
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
            print!("Sources:           ");
            match &sources {
                Some(s) if !s.is_empty() => {
                    let list = s
                        .iter()
                        .map(|src| match src {
                            types::IpSrc::Exact(ip) => ip.to_string(),
                            types::IpSrc::Any => "any".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!("{list}");
                }
                _ => println!("any"),
            }
        }
    }

    Ok(())
}

pub async fn multicast_cmd(
    client: &Client,
    cmd: Multicast,
) -> anyhow::Result<()> {
    match cmd {
        Multicast::List { tag } => multicast_list(client, tag).await,
        Multicast::Get { group_ip } => multicast_get(client, group_ip).await,
    }
}
