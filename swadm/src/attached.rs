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
/// manage attached subnet mappings
pub enum AttachedSubnet {
    /// list all attached subnet mappings
    #[clap(visible_alias = "ls")]
    List {
        /// list v4 subnets
        #[clap(short = '4')]
        v4: bool,
        /// list v6 subnets
        #[clap(short = '6')]
        v6: bool,
    },
    /// get a single attached subnet mapping
    Get {
        /// attached subnet
        #[clap(short = 'e')]
        attsub: IpNet,
    },
    /// add a new attached subnet mapping
    Add {
        /// attached subnet
        #[clap(short = 'e')]
        attsub: IpNet,
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
    /// delete a single attached subnet mapping
    Del {
        /// attached subnet
        attsub: IpNet,
    },
}

async fn attsub_list(
    client: &Client,
    mut v4: bool,
    mut v6: bool,
) -> anyhow::Result<()> {
    if !v4 && !v6 {
        v4 = true;
        v6 = true;
    }
    let mappings: Vec<types::AttachedSubnetEntry> = client
        .attached_subnet_list_stream(None)
        .try_collect()
        .await
        .context("failed to list attached subnets")?;

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}",
        "Attached Subnet".underline(),
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

async fn attsub_get(client: &Client, attsub: IpNet) -> anyhow::Result<()> {
    let target = client
        .attached_subnet_get(&attsub)
        .await
        .map(|r| {
            common::network::InstanceTarget::try_from(r.into_inner())
                .expect("Invalid internal target from server")
        })
        .context("failed to get IPv4 NAT mapping")?;
    println!("target: {target}");
    Ok(())
}

async fn attsub_add(
    client: &Client,
    attsub: IpNet,
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
        .attached_subnet_create(&attsub, &tgt)
        .await
        .context("failed to create attached subnet mapping")
        .map(|_| ())
}

async fn attsub_del(client: &Client, attsub: IpNet) -> anyhow::Result<()> {
    client
        .attached_subnet_delete(&attsub)
        .await
        .context("failed to delete attached subnet mapping")
        .map(|_| ())
}

pub async fn attsub_cmd(
    client: &Client,
    e: AttachedSubnet,
) -> anyhow::Result<()> {
    match e {
        AttachedSubnet::List { v4, v6 } => attsub_list(client, v4, v6).await,
        AttachedSubnet::Get { attsub } => attsub_get(client, attsub).await,
        AttachedSubnet::Add {
            attsub,
            internal,
            inner,
            vni,
        } => attsub_add(client, attsub, internal, inner, vni).await,
        AttachedSubnet::Del { attsub } => attsub_del(client, attsub).await,
    }
}
