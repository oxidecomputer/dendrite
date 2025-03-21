// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::io::{stdout, Write};
use std::net::IpAddr;

use anyhow::Context;
use colored::*;
use futures::stream::TryStreamExt;
use structopt::*;
use tabwriter::TabWriter;

use dpd_client::Client;

use crate::misc_err;
use crate::LinkName;
use crate::LinkPath;

#[derive(Debug, StructOpt)]
#[structopt(about = "address management")]
pub enum Addr {
    /// List addresses assigned to a link.
    #[structopt(visible_alias = "ls")]
    List {
        #[structopt(about = "limit output to IPv4", short = "4")]
        ipv4: bool,
        #[structopt(about = "limit output to IPv6", short = "6")]
        ipv6: bool,
        #[structopt(help = "provide parseable output", short = "p")]
        parseable: bool,
        /// List addresses for a specific link
        #[structopt(parse(try_from_str))]
        link: Option<LinkName>,
    },
    /// Add an address to a link.
    Add {
        /// The link on which to add the address.
        #[structopt(parse(try_from_str))]
        link: LinkName,
        /// The IP address to add.
        addr: IpAddr,
    },
    /// Delete an IP address from a link.
    Del {
        /// The link from which to delete the address.
        #[structopt(parse(try_from_str))]
        link: LinkName,
        /// The IP address to delete.
        addr: IpAddr,
    },
}

#[derive(Eq, PartialEq)]
enum AddrShow {
    V4,
    V6,
    Both,
}

async fn addr_list_all(
    client: &Client,
    addr_show: AddrShow,
    parseable: bool,
) -> anyhow::Result<()> {
    let mut tw = TabWriter::new(stdout());
    if !parseable {
        match addr_show {
            AddrShow::V4 => {
                writeln!(
                    &mut tw,
                    "{}\t{}",
                    "Link".underline(),
                    "IPv4".underline()
                )
            }
            AddrShow::V6 => {
                writeln!(
                    &mut tw,
                    "{}\t{}",
                    "Link".underline(),
                    "IPv6".underline()
                )
            }
            AddrShow::Both => writeln!(
                &mut tw,
                "{}\t{}\t{}",
                "Link".underline(),
                "IPv4".underline(),
                "IPv6".underline()
            ),
        }?;
    }
    let links = client
        .link_list_all(None)
        .await
        .context("failed to list all links")?
        .into_inner();
    for link in links {
        if parseable {
            let addrs: Vec<String> = match addr_show {
                AddrShow::V4 => client
                    .link_ipv4_list_stream(&link.port_id, &link.link_id, None)
                    .map_ok(|e| e.addr.to_string())
                    .try_collect()
                    .await
                    .context("failed to list IPv4 addresses")?,
                AddrShow::V6 => client
                    .link_ipv6_list_stream(&link.port_id, &link.link_id, None)
                    .map_ok(|e| e.addr.to_string())
                    .try_collect()
                    .await
                    .context("failed to list IPv6 addresses")?,
                _ => {
                    anyhow::bail!("must specify -4 or -6 for parseable output")
                }
            };
            if !addrs.is_empty() {
                println!("{},{}", link, addrs.join(","));
            }
        } else {
            let mut name = format!("{link}");
            let mut ipv4_addrs = client
                .link_ipv4_list_stream(&link.port_id, &link.link_id, None)
                .map_ok(|e| e.addr.to_string());
            let mut ipv6_addrs = client
                .link_ipv6_list_stream(&link.port_id, &link.link_id, None)
                .map_ok(|e| e.addr.to_string());
            loop {
                let ipv4 = match addr_show {
                    AddrShow::V6 => String::new(),
                    _ => ipv4_addrs
                        .try_next()
                        .await
                        .context("failed to list IPv4 addresses")?
                        .unwrap_or_default(),
                };
                let ipv6 = match addr_show {
                    AddrShow::V4 => String::new(),
                    _ => ipv6_addrs
                        .try_next()
                        .await
                        .context("failed to list IPv6 addresses")?
                        .unwrap_or_default(),
                };
                if ipv4.is_empty() && ipv6.is_empty() {
                    break;
                }
                match addr_show {
                    AddrShow::V4 => {
                        writeln!(&mut tw, "{name:>}\t{ipv4}")
                    }
                    AddrShow::V6 => {
                        writeln!(&mut tw, "{name:>}\t{ipv6}")
                    }
                    AddrShow::Both => {
                        writeln!(&mut tw, "{name:>}\t{ipv4}\t{ipv6}")
                    }
                }?;
                name = String::new();
            }
        }
    }

    let loopback_v4: Vec<String> = client
        .loopback_ipv4_list()
        .await?
        .into_inner()
        .iter()
        .map(|a| a.addr.to_string())
        .collect();

    let loopback_v6: Vec<String> = client
        .loopback_ipv6_list()
        .await?
        .into_inner()
        .iter()
        .map(|a| a.addr.to_string())
        .collect();

    if parseable {
        let addrs: &Vec<String> = match addr_show {
            AddrShow::V4 => &loopback_v4,
            AddrShow::V6 => &loopback_v6,
            _ => {
                return Err(misc_err(
                    "must specify -4 or -6 for parseable output".to_string(),
                )
                .into())
            }
        };
        if !addrs.is_empty() {
            println!("loopback,{}", addrs.join(","));
        }
    } else {
        match addr_show {
            AddrShow::V4 => {
                for ipv4 in &loopback_v4 {
                    writeln!(&mut tw, "loopback\t{ipv4}")?
                }
            }
            AddrShow::V6 => {
                for ipv6 in &loopback_v6 {
                    writeln!(&mut tw, "loopback\t{ipv6}")?
                }
            }
            AddrShow::Both => {
                for ipv4 in &loopback_v4 {
                    writeln!(&mut tw, "loopback\t{ipv4}")?
                }
                for ipv6 in &loopback_v6 {
                    writeln!(&mut tw, "loopback\t{ipv6}")?
                }
            }
        }
    }
    tw.flush().map_err(|e| e.into())
}

fn show_addr_vec(a: Vec<String>, parseable: bool) {
    if !parseable {
        for i in a {
            println!("{i}");
        }
    } else if !a.is_empty() {
        println!("{}", a.join(","));
    }
}

async fn addr_list_loopback(
    client: &Client,
    addr_show: AddrShow,
    parseable: bool,
) -> anyhow::Result<()> {
    let (show_ipv4, show_ipv6) = match addr_show {
        AddrShow::V4 => Ok((true, false)),
        AddrShow::V6 => Ok((false, true)),
        AddrShow::Both => match parseable {
            true => Err(misc_err(
                "must specify -4 or -6 for parseable output".to_string(),
            )),
            false => Ok((true, true)),
        },
    }?;

    if show_ipv4 {
        let ipv4 = client
            .loopback_ipv4_list()
            .await
            .context("failed to get IPv4 addresses")
            .map(|r| r.into_inner())?;
        show_addr_vec(
            ipv4.iter().map(|a| a.addr.to_string()).collect(),
            parseable,
        );
    }
    if show_ipv6 {
        let ipv6 = client
            .loopback_ipv6_list()
            .await
            .context("failed to get IPv6 addresses")
            .map(|r| r.into_inner())?;
        show_addr_vec(
            ipv6.iter().map(|a| a.addr.to_string()).collect(),
            parseable,
        );
    }
    Ok(())
}

async fn addr_list_one(
    client: &Client,
    addr_show: AddrShow,
    parseable: bool,
    link: &LinkPath,
) -> anyhow::Result<()> {
    let (show_ipv4, show_ipv6) = match addr_show {
        AddrShow::V4 => Ok((true, false)),
        AddrShow::V6 => Ok((false, true)),
        AddrShow::Both => match parseable {
            true => Err(misc_err(
                "must specify -4 or -6 for parseable output".to_string(),
            )),
            false => Ok((true, true)),
        },
    }?;

    if show_ipv4 {
        let ipv4: Vec<String> = client
            .link_ipv4_list_stream(&link.port_id, &link.link_id, None)
            .map_ok(|entry| entry.addr.to_string())
            .try_collect()
            .await
            .context("failed to get IPv4 addresses")?;
        show_addr_vec(ipv4, parseable);
    }
    if show_ipv6 {
        let ipv6 = client
            .link_ipv6_list_stream(&link.port_id, &link.link_id, None)
            .map_ok(|entry| entry.addr.to_string())
            .try_collect()
            .await
            .context("failed to get IPv6 addresses")?;
        show_addr_vec(ipv6, parseable);
    }
    Ok(())
}

async fn addr_list(
    client: &Client,
    ipv4: bool,
    ipv6: bool,
    parseable: bool,
    port: Option<LinkName>,
) -> anyhow::Result<()> {
    let addr_show = match (ipv4, ipv6) {
        (true, false) => AddrShow::V4,
        (false, true) => AddrShow::V6,
        _ => AddrShow::Both,
    };

    match port {
        Some(port) => match &port {
            LinkName::Loopback => {
                addr_list_loopback(client, addr_show, parseable).await
            }
            LinkName::Link(l) => {
                addr_list_one(client, addr_show, parseable, l).await
            }
        },
        None => addr_list_all(client, addr_show, parseable).await,
    }
}

async fn addr_add(
    client: &Client,
    link: &LinkPath,
    addr: IpAddr,
) -> anyhow::Result<()> {
    match addr {
        IpAddr::V4(addr) => {
            let entry = client.ipv4_entry(addr);
            client
                .link_ipv4_create(&link.port_id, &link.link_id, &entry)
                .await
                .context("failed to add IPv4 address")
                .map(|_| ())
        }
        IpAddr::V6(addr) => {
            let entry = client.ipv6_entry(addr);
            client
                .link_ipv6_create(&link.port_id, &link.link_id, &entry)
                .await
                .context("failed to add IPv6 address")
                .map(|_| ())
        }
    }
}

async fn addr_add_loopback(
    client: &Client,
    addr: IpAddr,
) -> anyhow::Result<()> {
    match addr {
        IpAddr::V4(addr) => {
            let entry = client.ipv4_entry(addr);
            client
                .loopback_ipv4_create(&entry)
                .await
                .context("failed to add IPv4 address")
                .map(|_| ())
        }
        IpAddr::V6(addr) => {
            let entry = client.ipv6_entry(addr);
            client
                .loopback_ipv6_create(&entry)
                .await
                .context("failed to add IPv6 address")
                .map(|_| ())
        }
    }
}

async fn addr_del(
    client: &Client,
    link: &LinkPath,
    addr: IpAddr,
) -> anyhow::Result<()> {
    match addr {
        IpAddr::V4(addr) => client
            .link_ipv4_delete(&link.port_id, &link.link_id, &addr)
            .await
            .context("failed to delete IPv4 address")
            .map(|_| ()),
        IpAddr::V6(addr) => client
            .link_ipv6_delete(&link.port_id, &link.link_id, &addr)
            .await
            .context("failed to delete IPv6 address")
            .map(|_| ()),
    }
}

async fn addr_del_loopback(
    client: &Client,
    addr: IpAddr,
) -> anyhow::Result<()> {
    match addr {
        IpAddr::V4(addr) => client
            .loopback_ipv4_delete(&addr)
            .await
            .context("failed to delete IPv4 address")
            .map(|_| ()),
        IpAddr::V6(addr) => client
            .loopback_ipv6_delete(&addr)
            .await
            .context("failed to delete IPv6 address")
            .map(|_| ()),
    }
}

pub async fn addr_cmd(client: &Client, a: Addr) -> anyhow::Result<()> {
    match a {
        Addr::List {
            ipv4,
            ipv6,
            parseable,
            link,
        } => addr_list(client, ipv4, ipv6, parseable, link).await,
        Addr::Add { link, addr } => match &link {
            LinkName::Loopback => addr_add_loopback(client, addr).await,
            LinkName::Link(l) => addr_add(client, l, addr).await,
        },
        Addr::Del { link, addr } => match &link {
            LinkName::Loopback => addr_del_loopback(client, addr).await,
            LinkName::Link(l) => addr_del(client, l, addr).await,
        },
    }
}
