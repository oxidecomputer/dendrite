// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use dpd_client::types::Ipv6Entry;
use futures::{StreamExt, TryStreamExt};
use slog::{debug, error, warn};

use crate::Global;
use crate::oxstats::link;
use crate::poll_interval;
use common::illumos;
use dpd_client::{ClientInfo, types};

async fn simnet_tfport_get() -> anyhow::Result<Vec<String>> {
    // dladm show-simnet seems to be broken when not in the global zone.
    illumos::dladm(&["show-link", "-p", "-o", "link"])
        .await
        .map_err(|e| e.into())
        .map(|lines| {
            lines.into_iter().filter(|s| s.starts_with("tfport")).collect()
        })
}

async fn ipadm_addrs() -> anyhow::Result<Vec<(String, IpAddr)>> {
    illumos::ipadm(&["show-addr", "-p", "-o", "addrobj,addr"])
        .await
        .map_err(|e| e.into())
        .map(|lines| {
            lines
                .iter()
                .filter_map(|s| {
                    // divide the address object and address fields
                    let (aobj, addr) = s.split_once(':')?;
                    // Clean up the ":" escapes added by ipadm
                    let addr = addr.replace('\\', "");
                    // Drop any interface suffix
                    let addr = addr
                        .split('%')
                        .next()
                        .expect("a split must return at least one item");
                    // Drop any subnet suffix
                    let addr = addr
                        .split('/')
                        .next()
                        .expect("a split must return at least one item");
                    let addr: IpAddr = addr.parse().ok()?;
                    Some((aobj.to_owned(), addr))
                })
                .collect()
        })
}

pub async fn simnet_loop(g: Arc<Global>) {
    while g.get_running() {
        if let Err(e) = simnet_process(&g).await {
            error!(g.log, "simnet_process: {e}");
        }
        tokio::time::sleep(poll_interval()).await;
    }

    debug!(g.log, "simnet loop exiting");
}

/// Reconciles each port's illumos IPv6 link local address with
/// the link config in DPD.
async fn simnet_process(g: &Global) -> anyhow::Result<()> {
    let simports = simnet_tfport_get().await?;
    debug!(g.log, "found simports {:#?}", simports);
    let addrs = ipadm_addrs().await?;
    let tag = g.client.inner().tag.as_str();

    for p in &simports {
        if let Err(e) = illumos::iface_ensure(p).await {
            warn!(g.log, "{e}");
            continue;
        }

        let p_addrs = addrs
            .iter()
            .filter_map(|(name, addr)| {
                if let IpAddr::V6(v6) = addr
                    && v6.is_unicast_link_local()
                    && name.starts_with(p)
                {
                    return Some(*v6);
                }
                None
            })
            .collect::<Vec<Ipv6Addr>>();

        if p_addrs.is_empty() {
            warn!(g.log, "{p} has no IPv6 unicast link local addr(s)");
            continue;
        } else {
            debug!(g.log, "sync {p} addrs {:?}", p_addrs);
        }

        // need to go from tfport<something>M_N to port_id=<something>M link_id=N
        let Some(port_name) = p.strip_prefix("tfport") else {
            continue;
        };
        let port_name = port_name.split('_').next().unwrap();

        // breakouts not a thing yet, just assume the 0th link
        let link_id = types::LinkId(0);
        let port_id = match types::PortId::from_str(port_name) {
            Ok(name) => name,
            Err(e) => {
                error!(g.log, "failed to parse port name {port_name}: {e}");
                continue;
            }
        };

        // ensure the link for the tfport exists
        if g.client.link_get(&port_id, &link_id).await.is_err() {
            // this is for softnpu environments which do not currently care
            // about these parameters, so just pick some
            let params = types::LinkCreate {
                lane: None,
                speed: types::PortSpeed::Speed100G,
                fec: Some(types::PortFec::None),
                autoneg: false,
                kr: false,
                tx_eq: None,
                allow_ddm_traffic: false,
            };
            if let Err(e) = g.client.link_create(&port_id, &params).await {
                error!(
                    g.log,
                    "failed to create link for tfport {port_name}: {e}"
                );
            }
        };

        // track the metrics for the simport link
        if let Err(e) = g.link_tracker.track_link(p, link::ModelType::Simport) {
            error!(g.log, "failed to track link {p}: {e}");
        }

        let maybe_addrs: Result<HashSet<_>, _> = g
            .client
            .link_ipv6_list_stream(&port_id, &link_id, None)
            .filter_map(|res| async {
                match res {
                    Ok(entry) if entry.tag == tag => Some(Ok(entry.addr)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                }
            })
            .try_collect()
            .await;

        let asic_ll = match maybe_addrs {
            Ok(addrs) => addrs,
            Err(e) => {
                error!(
                    g.log,
                    "failed to collect stream of ipv6 addresses: {e}"
                );
                continue;
            }
        };

        for addr in &asic_ll {
            if p_addrs.contains(addr) {
                continue;
            }
            if let Err(e) = g
                .client
                .link_ipv6_delete(&port_id, &link_id, addr, Some(tag))
                .await
            {
                error!(g.log, "failed to delete v6 address {addr}: {e}");
            }
        }

        let mut entry =
            Ipv6Entry { addr: Ipv6Addr::UNSPECIFIED, tag: tag.to_string() };
        for addr in &p_addrs {
            if asic_ll.contains(addr) {
                continue;
            }
            entry.addr = *addr;
            if let Err(e) =
                g.client.link_ipv6_create(&port_id, &link_id, &entry).await
            {
                error!(g.log, "failed to create v6 address {addr}: {e}");
            }
        }
    }
    Ok(())
}
