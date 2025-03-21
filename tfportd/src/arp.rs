// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;

use anyhow::anyhow;
use futures::TryStreamExt;
use slog::{debug, error, info};

use crate::poll_interval;
use crate::sidecar;
use crate::Global;
use common::network::MacAddr;
use dpd_client::types;
use dpd_client::Client;

const ARP: &str = "/usr/sbin/arp";
const DEFAULT_IPV4_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

// Information about a single ARP entry.
#[derive(Debug)]
struct Arp {
    iface: String,
    ip: Ipv4Addr,
    _mask: Ipv4Addr,
    _flags: String,
    mac: MacAddr,
}

impl fmt::Display for Arp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}", self.ip, self.mac)
    }
}

async fn arp_update(
    g: &Global,
    log: &slog::Logger,
    illumos: &[Arp],
    dpd: &[Arp],
) {
    let mut remove = Vec::new();
    let mut add = Vec::new();

    for i in illumos.iter() {
        match dpd.iter().find(|d| i.ip == d.ip) {
            Some(old) => {
                if old.mac != i.mac && i.mac != MacAddr::ZERO {
                    // the mapping changed
                    remove.push(old);
                    add.push(i);
                }
            }
            None => add.push(i),
        }
    }

    for d in dpd.iter() {
        if !illumos.iter().any(|i| i.ip == d.ip) {
            remove.push(d);
        }
    }

    while let Some(r) = remove.pop() {
        if let Err(e) = g.client.arp_delete(&r.ip).await {
            error!(log, "failed to remove stale ARP entry {}: {:?}", r, e);
        } else {
            info!(log, "removed stale ARP entry {}", r);
        }
    }

    while let Some(a) = add.pop() {
        let entry = types::ArpEntry {
            ip: IpAddr::V4(a.ip),
            mac: a.mac.into(),
            tag: g.client.inner().tag.clone(),
            update: String::new(),
        };
        if let Err(e) = g.client.arp_create(&entry).await {
            error!(g.log, "failed to add new ARP entry: {e:?}";
		   "entry" => a.to_string(),
		   "interface" => &a.iface);
        } else {
            info!(g.log, "added new ARP entry";
		  "entry" => a.to_string(),
		  "interface" => &a.iface);

            if let Some(asic_id) =
                g.tfport_to_asic.lock().unwrap().get(&a.iface)
            {
                sidecar::process_packet_queue(
                    g,
                    *asic_id,
                    IpAddr::V4(a.ip),
                    a.mac,
                );
            }
        }
    }
}

// Each line looks like one of the following:
//
// vioif0 224.0.0.251          255.255.255.255 S        01:00:5e:00:00:fb
// vioif0 224.0.0.251          255.255.255.255          01:00:5e:00:00:fb
// vioif0 224.0.0.251          255.255.255.255 U
//
// We split the line on whitespace and parse the fields individually
//
fn parse_arp(line: &str) -> anyhow::Result<Arp> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let last = fields.len() - 1;

    if last < 3 {
        return Err(anyhow!("bad arp line: {}", line));
    }

    let iface = fields[0].to_string();
    let ip = fields[1]
        .parse()
        .map_err(|_| anyhow!("bad IP address: {}:", fields[1]))?;
    let mask = fields[2]
        .parse()
        .map_err(|_| anyhow!("bad mask: {}:", fields[2]))?;
    let mac = match fields[last].parse() {
        Ok(m) => m,
        _ => MacAddr::new(0, 0, 0, 0, 0, 0),
    };
    let flags = if last > 3 {
        fields[last].to_string()
    } else {
        String::new()
    };

    Ok(Arp {
        iface,
        ip,
        _mask: mask,
        _flags: flags,
        mac,
    })
}

// arp doesn't have a "parseable" output option, so we have to do it by hand.  We
// start by skipping over the header, using the "----" separator as our signal that
// we're in to real data.
fn illumos_arp_get(log: &slog::Logger) -> anyhow::Result<Vec<Arp>> {
    let args = vec!["-a", "-n"];

    let out = Command::new(ARP).args(&args).output()?;
    if !out.status.success() {
        return Err(anyhow!("arp failed: {}", String::from_utf8(out.stderr)?));
    }

    let mut processing = false;
    let mut data = Vec::new();
    for line in String::from_utf8(out.stdout)?.lines() {
        if processing {
            match parse_arp(line) {
                Ok(a) => data.push(a),
                Err(e) => {
                    debug!(log, "failed to parse arp line {}: {:?}", line, e)
                }
            }
        } else if line.starts_with("-----") {
            processing = true;
        }
    }

    Ok(data)
}

async fn dpd_arp_get(
    client: &Client,
    log: &slog::Logger,
) -> anyhow::Result<Vec<Arp>> {
    client
        .arp_list_stream(None)
        .try_filter_map(|entry| async move {
            match entry.ip {
                IpAddr::V6(ip) => {
                    error!(log, "found IPv6 addr {ip} in ARP table");
                    Ok(None)
                }
                IpAddr::V4(ip) => Ok(Some(Arp {
                    iface: String::new(),
                    ip,
                    _mask: DEFAULT_IPV4_MASK,
                    _flags: String::new(),
                    mac: entry.mac.into(),
                })),
            }
        })
        .try_collect()
        .await
        .map_err(|e| anyhow!("failed to fetch ARP data from dpd: {e:?}"))
}

async fn arp_process(g: &Global, log: &slog::Logger) {
    let i = match illumos_arp_get(log) {
        Ok(i) => i,
        Err(e) => {
            error!(log, "failed to fetch Illumos ARP data: {:?}", e);
            return;
        }
    };

    let d = match dpd_arp_get(&g.client, log).await {
        Ok(d) => d,
        Err(e) => {
            error!(log, "failed to fetch dpd ARP data: {:?}", e);
            return;
        }
    };

    arp_update(g, log, &i, &d).await;
}

pub async fn arp_loop(g: Arc<Global>) {
    while g.get_running() {
        arp_process(&g, &g.log).await;
        tokio::time::sleep(poll_interval()).await;
    }

    debug!(g.log, "arp loop exiting");
}
