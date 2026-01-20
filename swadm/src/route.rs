// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::io::{Write, stdout};
use std::net::IpAddr;

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use clap::Subcommand;
use colored::*;
use futures::stream::TryStreamExt;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use tabwriter::TabWriter;

use dpd_client::Client;
use dpd_client::ClientInfo;
use dpd_client::types;

use crate::IpFamily;
use crate::LinkPath;

#[derive(Debug, Subcommand)]
/// manage the L3 routing table
pub enum Route {
    /// list all routes
    #[clap(visible_alias = "ls")]
    List {
        /// IPv4 or IPv6
        family: Option<IpFamily>,
    },
    /// get one route
    Get {
        /// route CIDR
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
        link_path: LinkPath,
        /// The gateway to which traffic should be sent.
        ///
        /// The family of the address must be the same as the family of the CIDR
        /// block itself.
        gw: IpAddr,
        /// If specified, this indicates the VLAN tag that will be applied to
        /// packets forwarded across this route.
        #[clap(visible_alias = "vlan")]
        vlan_id: Option<u16>,
    },
    /// delete one route
    Del {
        /// route CIDR
        cidr: IpNet,
        /// Identify a specific target to delete
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

fn print_ipv4_route(
    tw: &mut TabWriter<std::io::Stdout>,
    cidr: Ipv4Net,
    targets: &Vec<types::Route>,
) -> anyhow::Result<()> {
    let mut cidr = cidr.to_string();
    for t in targets {
        match t {
            types::Route::V4(t) => {
                writeln!(
                    tw,
                    "{}\t{}\t{:<}\t{}\t{}",
                    cidr,
                    t.port_id,
                    t.link_id,
                    t.tgt_ip,
                    t.vlan_id.map_or(String::new(), |id| id.to_string()),
                )?;
            }
            types::Route::V6(t) => {
                writeln!(
                    tw,
                    "{}\t{}\t{:<}\t{}\t{}",
                    cidr,
                    t.port_id,
                    t.link_id,
                    t.tgt_ip,
                    t.vlan_id.map_or(String::new(), |id| id.to_string()),
                )?;
            }
        }
        cidr = String::new();
    }
    Ok(())
}

fn print_ipv6_route(
    tw: &mut TabWriter<std::io::Stdout>,
    cidr: Ipv6Net,
    targets: &Vec<types::Ipv6Route>,
) -> anyhow::Result<()> {
    let mut cidr = cidr.to_string();
    for t in targets {
        writeln!(
            tw,
            "{}\t{}\t{:<}\t{}\t{}",
            cidr,
            t.port_id,
            t.link_id,
            t.tgt_ip,
            t.vlan_id.map_or(String::new(), |id| id.to_string()),
        )?;
        cidr = String::new();
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
        let routes: Vec<types::Ipv4Routes> = client
            .route_ipv4_list_stream(None)
            .try_collect()
            .await
            .context("failed to get IPv4 routes")?;
        for r in routes {
            print_ipv4_route(&mut tw, r.cidr, &r.targets)?;
        }
    }
    if v6 {
        let routes: Vec<types::Ipv6Routes> = client
            .route_ipv6_list_stream(None)
            .try_collect()
            .await
            .context("failed to get IPv6 routes")?;
        for r in routes {
            print_ipv6_route(&mut tw, r.cidr, &r.targets)?;
        }
    }
    tw.flush().map_err(|e| e.into())
}

async fn route_get(client: &Client, cidr: IpNet) -> anyhow::Result<()> {
    let mut tw = TabWriter::new(stdout());
    print_route_header(&mut tw)?;
    match &cidr {
        IpNet::V4(c) => {
            let targets = client
                .route_ipv4_get(c)
                .await
                .context("failed to get IPv4 route")?
                .into_inner();
            print_ipv4_route(&mut tw, *c, &targets)?;
        }
        IpNet::V6(c) => {
            let targets = client
                .route_ipv6_get(c)
                .await
                .context("failed to get IPv6 route")?
                .into_inner();
            print_ipv6_route(&mut tw, *c, &targets)?;
        }
    }
    tw.flush().map_err(|e| e.into())
}

async fn route_add(
    client: &Client,
    cidr: IpNet,
    link_path: LinkPath,
    gw: IpAddr,
    vlan_id: Option<u16>,
) -> anyhow::Result<()> {
    match (gw, cidr) {
        (IpAddr::V4(tgt_ip), IpNet::V4(cidr)) => client
            .route_ipv4_add(&types::Ipv4RouteUpdate {
                cidr,
                target: types::Ipv4Route {
                    tag: client.inner().tag.clone(),
                    port_id: link_path.port_id,
                    link_id: link_path.link_id,
                    tgt_ip,
                    vlan_id,
                },
                replace: false,
            })
            .await
            .context("adding IPv4 route")
            .map(|_| ()),
        (IpAddr::V6(tgt_ip), IpNet::V6(cidr)) => client
            .route_ipv6_add(&types::Ipv6RouteUpdate {
                cidr,
                target: types::Ipv6Route {
                    tag: client.inner().tag.clone(),
                    port_id: link_path.port_id,
                    link_id: link_path.link_id,
                    tgt_ip,
                    vlan_id,
                },
                replace: false,
            })
            .await
            .context("adding IPv6 route")
            .map(|_| ()),
        (IpAddr::V6(tgt_ip), IpNet::V4(cidr)) => client
            .route_ipv4_over_ipv6_add(&types::Ipv4OverIpv6RouteUpdate {
                cidr,
                target: types::Ipv6Route {
                    tag: client.inner().tag.clone(),
                    port_id: link_path.port_id,
                    link_id: link_path.link_id,
                    tgt_ip,
                    vlan_id,
                },
                replace: false,
            })
            .await
            .context("adding IPv4 or IPv6 route")
            .map(|_| ()),
        (IpAddr::V4(_), IpNet::V6(_)) => {
            Err(anyhow!("cannot have an IPv6 route to an IPv4 address"))
        }
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
        Route::Add { cidr, link_path, gw, vlan_id } => {
            route_add(client, cidr, link_path, gw, vlan_id).await
        }
        Route::Del { cidr, link_path, gw } => {
            route_del(client, cidr, link_path, gw).await
        }
    }
}
