// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::convert::TryFrom;
use std::io::{Read, Write, stdout};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::Context;
use clap::Subcommand;
use colored::*;
use futures::stream::TryStreamExt;
use tabwriter::TabWriter;

use common::network::{MacAddr, Vni};
use dpd_client::Client;
use dpd_client::types;

#[derive(Debug, Subcommand)]
/// manage NAT reservations
pub enum Nat {
    /// list all NAT reservations
    #[clap(visible_alias = "ls")]
    List {
        /// limit to the given external IP address",
        #[clap(short = 'e', conflicts_with = "tag")]
        external: Option<IpAddr>,
        /// limit to the entries carrying the given tag
        #[clap(short = 't', long)]
        tag: Option<String>,
    },
    /// apply the complete set of IPv4 NAT entries for a tag
    ///
    /// The request is a JSON array of NAT entries; dpd diffs it against
    /// current state and converges. Entries carrying the tag but absent
    /// from the request are removed, so an empty array removes them all.
    ApplyIpv4 {
        /// tag identifying the set of entries
        #[clap(short = 't', long)]
        tag: String,
        /// file containing the request body (defaults to stdin)
        file: Option<PathBuf>,
    },
    /// apply the complete set of IPv6 NAT entries for a tag
    ///
    /// The request is a JSON array of NAT entries; dpd diffs it against
    /// current state and converges. Entries carrying the tag but absent
    /// from the request are removed, so an empty array removes them all.
    ApplyIpv6 {
        /// tag identifying the set of entries
        #[clap(short = 't', long)]
        tag: String,
        /// file containing the request body (defaults to stdin)
        file: Option<PathBuf>,
    },
    /// get a single NAT reservation
    Get {
        /// external IP address
        #[clap(short = 'e')]
        external: IpAddr,
        /// any port within the external port range
        #[clap(short = 'p')]
        port: u16,
    },
    /// add a new NAT reservation
    Add {
        /// external IP address
        #[clap(short = 'e')]
        external: IpAddr,
        /// start of external port range
        #[clap(short = 'l')]
        low: u16,
        /// end of external port range
        #[clap(short = 'H')]
        high: u16,
        /// internal IP address
        #[clap(short = 'i')]
        internal: Ipv6Addr,
        /// inner MAC address
        #[clap(short = 'm')]
        inner: MacAddr,
        /// Geneve VNI
        #[clap(short = 'v')]
        vni: Vni,
    },
    /// delete a single NAT reservation
    Del {
        /// external IP address
        external: IpAddr,
        /// low end of external port range
        port: u16,
    },
}

async fn nat_list(
    client: &Client,
    external: Option<IpAddr>,
) -> anyhow::Result<()> {
    // Collect all addresses we're listing mappings for.
    let (v4_addrs, v6_addrs) = match external {
        Some(external) => match external {
            IpAddr::V4(v4) => (vec![v4], vec![]),
            IpAddr::V6(v6) => (vec![], vec![v6]),
        },
        None => (
            client
                .nat_ipv4_addresses_list_stream(None)
                .try_collect()
                .await
                .context("failed to list IPv4 addresses for NAT")?,
            client
                .nat_ipv6_addresses_list_stream(None)
                .try_collect()
                .await
                .context("failed to list IPv6 addresses for NAT")?,
        ),
    };

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}",
        "External IP".underline(),
        "Port low".underline(),
        "Port high".underline(),
        "Internal IP".underline(),
        "Inner MAC".underline(),
        "VNI".underline()
    )?;

    for addr in v4_addrs {
        let mut entries = client.nat_ipv4_list_stream(&addr, None);
        while let Some(entry) = entries.try_next().await.context(format!(
            "failed to get IPv4 mappings for address {addr}"
        ))? {
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}\t{}\t{}",
                entry.external,
                entry.low,
                entry.high,
                entry.target.internal_ip,
                MacAddr::from(entry.target.inner_mac),
                entry.target.vni.0,
            )?;
        }
    }

    for addr in v6_addrs {
        let mut entries = client.nat_ipv6_list_stream(&addr, None);
        while let Some(entry) = entries.try_next().await.context(format!(
            "failed to get IPv6 mappings for address {addr}"
        ))? {
            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}\t{}\t{}",
                entry.external,
                entry.low,
                entry.high,
                entry.target.internal_ip,
                MacAddr::from(entry.target.inner_mac),
                entry.target.vni.0,
            )?;
        }
    }
    tw.flush()?;

    Ok(())
}

async fn nat_list_tagged(client: &Client, tag: &str) -> anyhow::Result<()> {
    let tag = tag
        .parse::<types::NatTag>()
        .map_err(|e| anyhow::anyhow!("invalid tag: {e}"))?;

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}",
        "External IP".underline(),
        "Port low".underline(),
        "Port high".underline(),
        "Internal IP".underline(),
        "Inner MAC".underline(),
        "VNI".underline()
    )?;

    let mut v4 = client.nat_tagged_ipv4_list_stream(&tag, None);
    while let Some(entry) =
        v4.try_next().await.context("failed to list tagged IPv4 NAT entries")?
    {
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}",
            entry.external,
            entry.low,
            entry.high,
            entry.target.internal_ip,
            MacAddr::from(entry.target.inner_mac),
            entry.target.vni.0,
        )?;
    }

    let mut v6 = client.nat_tagged_ipv6_list_stream(&tag, None);
    while let Some(entry) =
        v6.try_next().await.context("failed to list tagged IPv6 NAT entries")?
    {
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}",
            entry.external,
            entry.low,
            entry.high,
            entry.target.internal_ip,
            MacAddr::from(entry.target.inner_mac),
            entry.target.vni.0,
        )?;
    }
    tw.flush()?;

    Ok(())
}

fn read_request(file: Option<PathBuf>) -> anyhow::Result<String> {
    match file {
        Some(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display())),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read request from stdin")?;
            Ok(buf)
        }
    }
}

async fn nat_apply_ipv4(
    client: &Client,
    tag: &str,
    file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let tag = tag
        .parse::<types::NatTag>()
        .map_err(|e| anyhow::anyhow!("invalid tag: {e}"))?;

    let entries: Vec<types::Ipv4Nat> =
        serde_json::from_str(&read_request(file)?)
            .context("failed to parse request")?;

    let result = client
        .nat_tagged_ipv4_apply(&tag, &entries)
        .await
        .context("failed to apply tagged IPv4 NAT entries")?
        .into_inner();

    println!(
        "{} unchanged, {} added, {} removed, \
         {} add failures, {} remove failures",
        result.unchanged.len(),
        result.added.len(),
        result.removed.len(),
        result.add_failures.len(),
        result.remove_failures.len(),
    );
    for f in &result.add_failures {
        eprintln!(
            "failed to add {}/{}-{}: {}",
            f.entry.external, f.entry.low, f.entry.high, f.error
        );
    }
    for f in &result.remove_failures {
        eprintln!(
            "failed to remove {}/{}-{}: {}",
            f.entry.external, f.entry.low, f.entry.high, f.error
        );
    }
    if !result.add_failures.is_empty() || !result.remove_failures.is_empty() {
        anyhow::bail!("apply completed with failures");
    }

    Ok(())
}

async fn nat_apply_ipv6(
    client: &Client,
    tag: &str,
    file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let tag = tag
        .parse::<types::NatTag>()
        .map_err(|e| anyhow::anyhow!("invalid tag: {e}"))?;

    let entries: Vec<types::Ipv6Nat> =
        serde_json::from_str(&read_request(file)?)
            .context("failed to parse request")?;

    let result = client
        .nat_tagged_ipv6_apply(&tag, &entries)
        .await
        .context("failed to apply tagged IPv6 NAT entries")?
        .into_inner();

    println!(
        "{} unchanged, {} added, {} removed, \
         {} add failures, {} remove failures",
        result.unchanged.len(),
        result.added.len(),
        result.removed.len(),
        result.add_failures.len(),
        result.remove_failures.len(),
    );
    for f in &result.add_failures {
        eprintln!(
            "failed to add {}/{}-{}: {}",
            f.entry.external, f.entry.low, f.entry.high, f.error
        );
    }
    for f in &result.remove_failures {
        eprintln!(
            "failed to remove {}/{}-{}: {}",
            f.entry.external, f.entry.low, f.entry.high, f.error
        );
    }
    if !result.add_failures.is_empty() || !result.remove_failures.is_empty() {
        anyhow::bail!("apply completed with failures");
    }

    Ok(())
}

async fn nat_get(
    client: &Client,
    external: IpAddr,
    port: u16,
) -> anyhow::Result<()> {
    match external {
        IpAddr::V4(ipv4) => {
            let target = client
                .nat_ipv4_get(&ipv4, port)
                .await
                .map(|r| {
                    common::network::NatTarget::try_from(r.into_inner())
                        .expect("Invalid NAT target from server")
                })
                .context("failed to get IPv4 NAT mapping")?;
            println!("target: {target}");
        }
        IpAddr::V6(ipv6) => {
            let target = client
                .nat_ipv6_get(&ipv6, port)
                .await
                .map(|r| {
                    common::network::NatTarget::try_from(r.into_inner())
                        .expect("Invalid NAT target from server")
                })
                .context("failed to get IPv6 NAT mapping")?;
            println!("target: {target}");
        }
    };
    Ok(())
}

async fn nat_add(
    client: &Client,
    external: IpAddr,
    low_port: u16,
    high_port: u16,
    internal_ip: Ipv6Addr,
    inner_mac: MacAddr,
    vni: Vni,
) -> anyhow::Result<()> {
    let tgt = types::NatTarget {
        internal_ip,
        inner_mac: inner_mac.into(),
        vni: types::Vni::from(vni),
    };
    match external {
        IpAddr::V4(ext) => client
            .nat_ipv4_create(&ext, low_port, high_port, &tgt)
            .await
            .context("failed to set IPv4 NAT mapping")
            .map(|_| ()),
        IpAddr::V6(ext) => client
            .nat_ipv6_create(&ext, low_port, high_port, &tgt)
            .await
            .context("failed to set IPv6 NAT mapping")
            .map(|_| ()),
    }
}

async fn nat_del(
    client: &Client,
    external: IpAddr,
    port: u16,
) -> anyhow::Result<()> {
    match external {
        IpAddr::V4(ext) => client
            .nat_ipv4_delete(&ext, port)
            .await
            .context("failed to delete IPv4 NAT entry")
            .map(|_| ()),
        IpAddr::V6(ext) => client
            .nat_ipv6_delete(&ext, port)
            .await
            .context("failed to delete IPv6 NAT entry")
            .map(|_| ()),
    }
}

pub async fn nat_cmd(client: &Client, n: Nat) -> anyhow::Result<()> {
    match n {
        // clap rejects combining `--tag` with `-e`.
        Nat::List { tag: Some(tag), .. } => nat_list_tagged(client, &tag).await,
        Nat::List { external, tag: None } => nat_list(client, external).await,
        Nat::ApplyIpv4 { tag, file } => {
            nat_apply_ipv4(client, &tag, file).await
        }
        Nat::ApplyIpv6 { tag, file } => {
            nat_apply_ipv6(client, &tag, file).await
        }
        Nat::Get { external, port } => nat_get(client, external, port).await,
        Nat::Add { external, low, high, internal, inner, vni } => {
            nat_add(client, external, low, high, internal, inner, vni).await
        }
        Nat::Del { external, port } => nat_del(client, external, port).await,
    }
}
