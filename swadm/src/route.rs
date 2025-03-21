// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::io::{stdout, Write};
use std::net::IpAddr;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use colored::*;
use futures::stream::TryStreamExt;
use oxnet::IpNet;
use structopt::*;
use tabwriter::TabWriter;

use dpd_client::types;
use dpd_client::Client;

use crate::IpFamily;
use crate::LinkPath;

#[derive(Debug, StructOpt)]
#[structopt(about = "manage the L3 routing table")]
pub enum Route {
    #[structopt(about = "list all routes", visible_alias = "ls")]
    List {
        #[structopt(about = "IPv4 or IPv6")]
        family: Option<IpFamily>,
    },
    #[structopt(about = "get one route")]
    Get {
        #[structopt(help = "route CIDR")]
        cidr: IpNet,
    },
    /// Add a route to a link.
    Add {
        /// The CIDR block describing destinations to which the route applies.
        cidr: IpNet,
        /// Egress switch port and link.
        ///
        /// Routes are used to direct traffic for a subnet to a particular
        /// endpoint, a link within a switch port. This should be specified as
        /// `port_id/link_id`, e.g., `qsfp0/0`.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
        /// The gateway to which traffic should be sent.
        ///
        /// The family of the address must be the same as the family of the CIDR
        /// block itself.
        gw: IpAddr,
        /// If specified, this indicates the VLAN tag that will be applied to
        /// packets forwarded across this route.
        #[structopt(alias = "vlan")]
        vlan_id: Option<u16>,
    },
    #[structopt(about = "delete one route")]
    Del {
        #[structopt(help = "route CIDR")]
        cidr: IpNet,
        /// Identify a specific target to delete
        #[structopt(parse(try_from_str))]
        link_path: Option<LinkPath>,
        /// Identify a specific target to delete
        gw: Option<IpAddr>,
    },
}

fn print_route_header(
    tw: &mut TabWriter<std::io::Stdout>,
) -> anyhow::Result<()> {
    writeln!(
        tw,
        "{}\t{}\t{}\t{}\t{}",
        "Subnet".underline(),
        "Port".underline(),
        "Link".underline(),
        "Gateway".underline(),
        "Vlan".underline(),
    )
    .map_err(|e| e.into())
}

fn print_route(
    tw: &mut TabWriter<std::io::Stdout>,
    entry: types::Route,
) -> anyhow::Result<()> {
    let mut cidr = entry.cidr.to_string();
    for t in entry.targets {
        let (port, link, ip, vlan) = match t {
            types::RouteTarget::V4(tgt) => (
                tgt.port_id.to_string(),
                tgt.link_id.to_string(),
                IpAddr::V4(tgt.tgt_ip),
                tgt.vlan_id,
            ),
            types::RouteTarget::V6(tgt) => (
                tgt.port_id.to_string(),
                tgt.link_id.to_string(),
                IpAddr::V6(tgt.tgt_ip),
                tgt.vlan_id,
            ),
        };

        let vlan = match vlan {
            None => String::new(),
            Some(id) => id.to_string(),
        };

        writeln!(tw, "{cidr}\t{port}\t{link:<}\t{ip}\t{vlan}")?;
        cidr = String::new();
    }
    Ok(())
}

async fn route_list_family(
    tw: &mut TabWriter<std::io::Stdout>,
    client: &Client,
    family: IpFamily,
) -> anyhow::Result<()> {
    let routes: Vec<types::Route> = match family {
        IpFamily::V4 => client
            .route_ipv4_list_stream(None)
            .try_collect()
            .await
            .context("failed to get IPv4 routes")?,
        IpFamily::V6 => client
            .route_ipv6_list_stream(None)
            .try_collect()
            .await
            .context("failed to get IPv6 routes")?,
    };
    for entry in routes {
        print_route(tw, entry)?;
    }
    Ok(())
}

async fn route_list(
    client: &Client,
    family: Option<IpFamily>,
) -> anyhow::Result<()> {
    let (v4, v6) = match family {
        None => (true, true),
        Some(f) => match f {
            IpFamily::V4 => (true, false),
            IpFamily::V6 => (false, true),
        },
    };

    let mut tw = TabWriter::new(stdout());
    print_route_header(&mut tw)?;
    if v4 {
        route_list_family(&mut tw, client, IpFamily::V4).await?;
    }
    if v6 {
        route_list_family(&mut tw, client, IpFamily::V6).await?;
    }
    tw.flush().map_err(|e| e.into())
}

async fn route_get(client: &Client, cidr: IpNet) -> anyhow::Result<()> {
    let targets = match &cidr {
        IpNet::V4(c) => client
            .route_ipv4_get(c)
            .await
            .context("failed to get IPv4 route")?
            .into_inner()
            .iter()
            .map(|r| types::RouteTarget::V4(r.clone()))
            .collect(),
        IpNet::V6(c) => client
            .route_ipv6_get(c)
            .await
            .context("failed to get IPv6 route")?
            .into_inner()
            .iter()
            .map(|r| types::RouteTarget::V6(r.clone()))
            .collect(),
    };

    let route = types::Route { cidr, targets };
    let mut tw = TabWriter::new(stdout());
    print_route_header(&mut tw)?;
    print_route(&mut tw, route)?;
    tw.flush().map_err(|e| e.into())
}

async fn route_add(
    client: &Client,
    cidr: IpNet,
    link_path: LinkPath,
    gw: IpAddr,
    vlan_id: Option<u16>,
) -> anyhow::Result<()> {
    match gw {
        IpAddr::V4(tgt_ip) => client
            .route_ipv4_add(&types::RouteAdd {
                cidr,
                target: types::RouteTarget::V4(types::Ipv4Route {
                    tag: client.inner().tag.clone(),
                    port_id: link_path.port_id,
                    link_id: link_path.link_id,
                    tgt_ip,
                    vlan_id,
                }),
            })
            .await
            .context("adding IPv4 route")
            .map(|_| ()),
        IpAddr::V6(tgt_ip) => client
            .route_ipv6_add(&types::RouteAdd {
                cidr,
                target: types::RouteTarget::V6(types::Ipv6Route {
                    tag: client.inner().tag.clone(),
                    port_id: link_path.port_id,
                    link_id: link_path.link_id,
                    tgt_ip,
                    vlan_id,
                }),
            })
            .await
            .context("adding IPv6 route")
            .map(|_| ()),
    }
}

async fn route_del(
    client: &Client,
    cidr: IpNet,
    link_path: Option<LinkPath>,
    gw: Option<IpAddr>,
) -> anyhow::Result<()> {
    if link_path.is_some() != gw.is_some() {
        bail!(
            "must provide both a LinkPath and gateway when specifying a target"
        );
    }
    match cidr {
        IpNet::V4(c) => match gw {
            Some(IpAddr::V4(gw)) => {
                let link_path = link_path.unwrap();
                let port = link_path.port_id;
                let link = link_path.link_id;
                client
                    .route_ipv4_delete_target(&c, &port, &link, &gw)
                    .await
                    .context("deleting IPv4 route")
                    .map(|_| ())
            }
            Some(IpAddr::V6(_)) => {
                Err(anyhow!("ipv4 route must have ipv4 gateway"))
            }
            None => client
                .route_ipv4_delete(&c)
                .await
                .context("deleting IPv4 route")
                .map(|_| ()),
        },
        IpNet::V6(c) => match gw {
            Some(_) => Err(anyhow!("not supported")),
            None => client
                .route_ipv6_delete(&c)
                .await
                .context("deleting IPv6 route")
                .map(|_| ()),
        },
    }
}

pub async fn route_cmd(client: &Client, cmd: Route) -> anyhow::Result<()> {
    match cmd {
        Route::List { family } => route_list(client, family).await,
        Route::Get { cidr } => route_get(client, cidr).await,
        Route::Add {
            cidr,
            link_path,
            gw,
            vlan_id,
        } => route_add(client, cidr, link_path, gw, vlan_id).await,
        Route::Del {
            cidr,
            link_path,
            gw,
        } => route_del(client, cidr, link_path, gw).await,
    }
}
