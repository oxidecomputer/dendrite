// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use colored::*;
use futures::stream::TryStreamExt;
use structopt::*;
use tabwriter::TabWriter;

use common::nat;
use common::network::MacAddr;
use dpd_client::types;
use dpd_client::Client;

#[derive(Debug, StructOpt)]
#[structopt(about = "manage NAT reservations")]
pub enum Nat {
    #[structopt(about = "list all NAT reservations", alias = "ls")]
    List {
        #[structopt(
            help = "limit to the given external IP address",
            short = "e"
        )]
        external: Option<Ipv4Addr>,
    },
    #[structopt(about = "get a single NAT reservation")]
    Get {
        #[structopt(help = "external IP address", short = "e")]
        external: IpAddr,
        #[structopt(
            help = "any port within the external port range",
            short = "p"
        )]
        port: u16,
    },
    #[structopt(about = "add a new NAT reservation")]
    Add {
        #[structopt(help = "external IP address", short = "e")]
        external: IpAddr,
        #[structopt(help = "start of external port range", short = "l")]
        low: u16,
        #[structopt(help = "end of external port range", short = "h")]
        high: u16,
        #[structopt(help = "internal IP address", short = "i")]
        internal: Ipv6Addr,
        #[structopt(help = "inner MAC address", short = "m")]
        inner: MacAddr,
        #[structopt(help = "Geneve VNI", short = "v")]
        vni: nat::Vni,
    },
    #[structopt(about = "delete a single NAT reservation")]
    Del {
        #[structopt(help = "external IP address")]
        external: IpAddr,
        #[structopt(help = "low end of external port range")]
        port: u16,
    },
}

async fn nat_list(
    client: &Client,
    external: Option<Ipv4Addr>,
) -> anyhow::Result<()> {
    // Collect all addresses we're listing mappings for.
    let addrs = match external {
        Some(a) => vec![a],
        None => client
            .nat_ipv4_addresses_list_stream(None)
            .try_collect()
            .await
            .context("failed to list IPv4 addresses for NAT")?,
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

    for addr in addrs {
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
    tw.flush()?;

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
                    nat::NatTarget::try_from(r.into_inner())
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
                    nat::NatTarget::try_from(r.into_inner())
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
    vni: nat::Vni,
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
        Nat::List { external } => nat_list(client, external).await,
        Nat::Get { external, port } => nat_get(client, external, port).await,
        Nat::Add {
            external,
            low,
            high,
            internal,
            inner,
            vni,
        } => nat_add(client, external, low, high, internal, inner, vni).await,
        Nat::Del { external, port } => nat_del(client, external, port).await,
    }
}
