// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::anyhow;
use dpd_client::types;
use futures::TryStreamExt;
use slog::{debug, error, info};

use crate::poll_interval;
use crate::sidecar;
use crate::Global;
use common::network::MacAddr;

const NDP: &str = "/usr/sbin/ndp";

#[derive(Clone, Eq, PartialEq, Debug)]
enum NdpType {
    Dynamic,
    Local,
    Other,
    Static,
}

impl FromStr for NdpType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dynamic" => Ok(NdpType::Dynamic),
            "local" => Ok(NdpType::Local),
            "other" => Ok(NdpType::Other),
            "static" => Ok(NdpType::Static),
            x => Err(format!("invalid ndp type: {x}")),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
enum NdpState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Unreachable,
    Unknown,
}

impl FromStr for NdpState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "incomplete" => Ok(NdpState::Incomplete),
            "reachable" => Ok(NdpState::Reachable),
            "stale" => Ok(NdpState::Stale),
            "delay" => Ok(NdpState::Delay),
            "probe" => Ok(NdpState::Probe),
            "unreachable" => Ok(NdpState::Unreachable),
            "unknown" => Ok(NdpState::Unknown),
            x => Err(format!("invalid ndp state: {x}")),
        }
    }
}

#[derive(Clone, Debug)]
struct Ndp {
    iface: String,
    ip: Ipv6Addr,
    _ntype: NdpType,
    _state: NdpState,
    mac: MacAddr,
}

impl fmt::Display for Ndp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}->{}", self.iface, self.ip, self.mac)
    }
}

async fn ndp_update(g: &Global, illumos: &[Ndp], dpd: &[Ndp]) {
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
        if let Err(e) = g.client.ndp_delete(&r.ip).await {
            error!(g.log, "failed to remove stale NDP entry {}: {:?}", r, e);
        } else {
            info!(g.log, "removed stale NDP entry {}", r);
        }
    }

    while let Some(a) = add.pop() {
        let entry = types::ArpEntry {
            ip: IpAddr::V6(a.ip),
            mac: a.mac.into(),
            tag: g.client.inner().tag.clone(),
            update: String::new(),
        };
        if let Err(e) = g.client.ndp_create(&entry).await {
            error!(g.log, "failed to add new NDP entry: {e:?}";
		   "entry" => a.to_string(),
		   "interface" => &a.iface);
        } else {
            info!(g.log, "added new NDP entry";
		  "entry" => a.to_string(),
		  "interface" => &a.iface);

            if let Some(asic_id) =
                g.tfport_to_asic.lock().unwrap().get(&a.iface)
            {
                sidecar::process_packet_queue(
                    g,
                    *asic_id,
                    IpAddr::V6(a.ip),
                    a.mac,
                );
            }
        }
    }
}

// Each line looks like:
//
// tfport13_0 33:33:00:00:00:fb  other   REACHABLE    ff02::fb
//
// We split the line on whitespace and parse the fields individually
//
fn parse_ndp(line: &str) -> anyhow::Result<Ndp> {
    let fields: Vec<&str> = line.split_whitespace().collect();

    if fields.len() != 5 {
        return Err(anyhow!(format!(
            "bad line with {} fields: {}",
            fields.len(),
            line
        )));
    }

    let iface = fields[0].to_string();
    let mac = fields[1]
        .parse()
        .map_err(|_| anyhow!("bad mac: {}:", fields[1]))?;
    let ntype = fields[2].parse().map_err(|e: String| anyhow!(e))?;
    let state = fields[3].parse().map_err(|e: String| anyhow!(e))?;
    let ip = fields[4]
        .parse()
        .map_err(|_| anyhow!("bad IP address: {}:", fields[1]))?;

    Ok(Ndp {
        iface,
        mac,
        ip,
        _ntype: ntype,
        _state: state,
    })
}

// ndp doesn't have a "parseable" output option, so we have to do it by hand.  We
// start by skipping over the header, using the "----" separator as our signal that
// we're in to real data.
fn illumos_ndp_get(g: &Global) -> anyhow::Result<Vec<Ndp>> {
    let args = vec!["-a", "-n"];

    let out = Command::new(NDP).args(&args).output()?;
    if !out.status.success() {
        return Err(anyhow!("ndp failed: {}", String::from_utf8(out.stderr)?));
    }

    let mut processing = false;
    let mut data = Vec::new();
    for line in String::from_utf8(out.stdout)?.lines() {
        if processing && !line.is_empty() {
            match parse_ndp(line) {
                Ok(n) => {
                    if n.iface.starts_with("tfport") && !n.ip.is_multicast() {
                        data.push(n);
                    }
                }
                Err(e) => {
                    debug!(g.log, "failed to parse ndp line {}: {:?}", line, e)
                }
            }
        } else if line.starts_with("-----") {
            processing = true;
        }
    }

    Ok(data)
}

async fn dpd_ndp_get(g: &Global) -> anyhow::Result<Vec<Ndp>> {
    g.client
        .ndp_list_stream(None)
        .try_filter_map(|entry| async move {
            match entry.ip {
                IpAddr::V4(ip) => {
                    error!(g.log, "found IPv4 addr {ip} in NDP table");
                    Ok(None)
                }
                IpAddr::V6(ip) => Ok(Some(Ndp {
                    iface: String::new(),
                    ip,
                    _ntype: NdpType::Other,
                    _state: NdpState::Reachable,
                    mac: entry.mac.into(),
                })),
            }
        })
        .try_collect()
        .await
        .map_err(|e| anyhow!("failed to fetch NDP data from dpd: {e:?}"))
}

async fn ndp_process(g: &Global) {
    let i = match illumos_ndp_get(g) {
        Ok(i) => i,
        Err(e) => {
            error!(g.log, "failed to fetch Illumos NDP data: {:?}", e);
            return;
        }
    };

    let d = match dpd_ndp_get(g).await {
        Ok(d) => d,
        Err(e) => {
            error!(g.log, "failed to fetch dpd NDP data: {:?}", e);
            return;
        }
    };

    ndp_update(g, &i, &d).await;
}

pub async fn ndp_loop(g: Arc<Global>) {
    while g.get_running() {
        ndp_process(&g).await;
        tokio::time::sleep(poll_interval()).await;
    }

    debug!(g.log, "ndp loop exiting");
}
