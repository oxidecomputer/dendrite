// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::convert::TryFrom;
use std::io::{Write, stdout};
use std::net::Ipv6Addr;

use anyhow::Context;
use clap::Subcommand;
use colored::*;
use futures::stream::TryStreamExt;
use oxnet::IpNet;
use tabwriter::TabWriter;

use common::network::{MacAddr, Vni};
use dpd_client::Client;
use dpd_client::types;

#[derive(Debug, Subcommand)]
/// manage external subnet mappings
pub enum ExtSub {
    /// list all external subnet mappings
    #[clap(visible_alias = "ls")]
    List {
        /// list v4 subnets
        #[clap(short = '4')]
        v4: bool,
        /// list v6 subnets
        #[clap(short = '6')]
        v6: bool,
    },
    /// get a single external subnet mapping
    Get {
        /// external subnet
        #[clap(short = 'e')]
        extsub: IpNet,
    },
    /// add a new external subnet mapping
    Add {
        /// external subnet
        #[clap(short = 'e')]
        extsub: IpNet,
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
    /// delete a single external subnet mapping
    Del {
        /// external subnet
        extsub: IpNet,
    },
}

async fn extsub_list(
    client: &Client,
    mut v4: bool,
    mut v6: bool,
) -> anyhow::Result<()> {
    if !v4 && !v6 {
        v4 = true;
        v6 = true;
    }
    let mappings: Vec<types::ExtSubnetEntry> = client
        .external_subnet_list_stream(None)
        .try_collect()
        .await
        .context("failed to list external subnets")?;

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}",
        "External Subnet".underline(),
        "Internal IP".underline(),
        "Inner MAC".underline(),
        "VNI".underline()
    )?;

    for m in mappings.iter().filter(|m| match m.subnet {
        IpNet::V4(_) => v4,
        IpNet::V6(_) => v6,
    }) {
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}",
            m.subnet,
            m.tgt.internal_ip,
            MacAddr::from(m.tgt.inner_mac.clone()),
            m.tgt.vni.0,
        )?;
    }
    tw.flush()?;

    Ok(())
}

async fn extsub_get(client: &Client, extsub: IpNet) -> anyhow::Result<()> {
    let target = client
        .external_subnet_get(&extsub)
        .await
        .map(|r| {
            common::network::InstanceTarget::try_from(r.into_inner())
                .expect("Invalid internal target from server")
        })
        .context("failed to get IPv4 NAT mapping")?;
    println!("target: {target}");
    Ok(())
}

async fn extsub_add(
    client: &Client,
    extsub: IpNet,
    internal_ip: Ipv6Addr,
    inner_mac: MacAddr,
    vni: Vni,
) -> anyhow::Result<()> {
    let tgt = types::InstanceTarget {
        internal_ip,
        inner_mac: inner_mac.into(),
        vni: types::Vni::from(vni),
    };
    client
        .external_subnet_create(&extsub, &tgt)
        .await
        .context("failed to create external subnet mapping")
        .map(|_| ())
}

async fn extsub_del(client: &Client, extsub: IpNet) -> anyhow::Result<()> {
    client
        .external_subnet_delete(&extsub)
        .await
        .context("failed to delete external subnet mapping")
        .map(|_| ())
}

pub async fn extsub_cmd(client: &Client, e: ExtSub) -> anyhow::Result<()> {
    match e {
        ExtSub::List { v4, v6 } => extsub_list(client, v4, v6).await,
        ExtSub::Get { extsub } => extsub_get(client, extsub).await,
        ExtSub::Add {
            extsub,
            internal,
            inner,
            vni,
        } => extsub_add(client, extsub, internal, inner, vni).await,
        ExtSub::Del { extsub } => extsub_del(client, extsub).await,
    }
}
