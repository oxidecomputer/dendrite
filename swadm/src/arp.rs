// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::io::{stdout, Write};
use std::net::IpAddr;

use anyhow::Context;
use chrono::prelude::*;
use colored::*;
use futures::stream::TryStreamExt;
use structopt::*;
use tabwriter::TabWriter;

use common::network::MacAddr;
use dpd_client::types;
use dpd_client::Client;

use crate::IpFamily;

#[derive(Debug, StructOpt)]
#[structopt(about = "manage the ARP or NDP tables")]
pub enum Arp {
    #[structopt(about = "list all ARP / NDP entries")]
    List {
        #[structopt(about = "IPv4 or IPv6")]
        family: Option<IpFamily>,
    },
    #[structopt(about = "get one ARP / NDP table entry")]
    Get {
        #[structopt(help = "host IP address")]
        ip: IpAddr,
    },
    #[structopt(about = "add one ARP / NDP table entry")]
    Add {
        #[structopt(help = "host IP address")]
        ip: IpAddr,
        #[structopt(help = "MAC address")]
        mac: MacAddr,
    },
    #[structopt(about = "delete one ARP / NDP entry")]
    Del {
        #[structopt(help = "host IP address")]
        ip: IpAddr,
    },
}

fn timestamp_to_age(t: String) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(&t) {
        let now = Utc::now();
        if now < dt {
            "future".to_string()
        } else {
            let mut secs =
                DateTime::signed_duration_since(now, dt).num_seconds();
            if secs > 60 {
                let mut mins = secs / 60;
                secs -= mins * 60;
                if mins > 60 {
                    let hours = mins / 60;
                    mins -= hours * 60;
                    format!("{hours}h{mins}m{secs}s")
                } else {
                    format!("{mins}m{secs}s")
                }
            } else {
                format!("{secs}s")
            }
        }
    } else {
        "unknown".to_string()
    }
}

async fn arp_list(
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

    let mut entries = Vec::new();
    if v4 {
        entries = client
            .arp_list_stream(None)
            .try_collect()
            .await
            .context("failed to fetch ARP entries")?;
    }
    if v6 {
        let v: Vec<types::ArpEntry> = client
            .ndp_list_stream(None)
            .try_collect()
            .await
            .context("failed to fetch NDP entries")?;
        entries.extend(v);
    }

    let mut tw = TabWriter::new(stdout());
    writeln!(
        tw,
        "{}\t{}\t{}",
        "host".underline(),
        "mac".underline(),
        "age".underline()
    )?;
    for e in entries {
        let mac = common::network::MacAddr::from(e.mac);
        let mac = if mac.is_null() {
            "incomplete".into()
        } else {
            mac.to_string()
        };
        let age = timestamp_to_age(e.update);
        writeln!(tw, "{}\t{}\t{}", e.ip, mac, age).unwrap();
    }
    tw.flush().map_err(|e| e.into())
}

async fn arp_get(client: &Client, ip: IpAddr) -> anyhow::Result<()> {
    let mac = match ip {
        IpAddr::V4(addr) => client.arp_get(&addr).await?,
        IpAddr::V6(addr) => client.ndp_get(&addr).await?,
    }
    .into_inner()
    .mac;
    println!("{}", common::network::MacAddr::from(mac));
    Ok(())
}

async fn arp_add(
    client: &Client,
    ip: IpAddr,
    mac: MacAddr,
) -> anyhow::Result<()> {
    let entry = types::ArpEntry {
        ip,
        mac: mac.into(),
        tag: client.inner().tag.clone(),
        update: String::new(),
    };
    if ip.is_ipv4() {
        client
            .arp_create(&entry)
            .await
            .context("failed to add IPv4 ARP entry")
    } else {
        client
            .ndp_create(&entry)
            .await
            .context("failed to add IPv6 NDP entry")
    }
    .map(|_| ())
}

async fn arp_del(client: &Client, ip: IpAddr) -> anyhow::Result<()> {
    match ip {
        IpAddr::V4(addr) => client
            .arp_delete(&addr)
            .await
            .context("deleting IPv4 ARP entry")
            .map(|_| ()),
        IpAddr::V6(addr) => client
            .ndp_delete(&addr)
            .await
            .context("deleting IPv6 NDP entry")
            .map(|_| ()),
    }
}

pub async fn arp_cmd(client: &Client, cmd: Arp) -> anyhow::Result<()> {
    match cmd {
        Arp::List { family } => arp_list(client, family).await,
        Arp::Get { ip } => arp_get(client, ip).await,
        Arp::Add { ip, mac } => arp_add(client, ip, mac).await,
        Arp::Del { ip } => arp_del(client, ip).await,
    }
}
