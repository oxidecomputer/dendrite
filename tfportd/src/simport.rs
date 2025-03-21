// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use futures::TryStreamExt;
use slog::{debug, error, warn};

use crate::oxstats::link;
use crate::poll_interval;
use crate::Global;
use common::illumos;
use dpd_client::types;

async fn simnet_tfport_get() -> anyhow::Result<Vec<String>> {
    // dladm show-simnet seems to be broken when not in the global zone.
    illumos::dladm(&["show-link", "-p", "-o", "link"])
        .await
        .map_err(|e| e.into())
        .map(|lines| {
            lines
                .into_iter()
                .filter(|s| s.starts_with("tfport"))
                .collect()
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

async fn simnet_process(g: &Global) -> anyhow::Result<()> {
    let simports = simnet_tfport_get().await?;
    debug!(g.log, "found simports {:#?}", simports);
    let addrs = ipadm_addrs().await?;
    for p in &simports {
        if let Err(e) = illumos::iface_ensure(p).await {
            warn!(g.log, "{e}");
            continue;
        }
        let p_addrs = addrs
            .iter()
            .filter_map(|(name, addr)| {
                if name.starts_with(p) {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect::<Vec<IpAddr>>();

        if p_addrs.is_empty() {
            warn!(g.log, "{p} has no addrs");
            continue;
        } else {
            debug!(g.log, "sync {p} addrs {:?}", p_addrs);
        }

        // need to go from tfport<something>M_N to port_id=<something>M link_id=N
        let port_name = match p.strip_prefix("tfport") {
            Some(name) => name,
            None => continue,
        };
        let port_name = port_name.split('_').next().unwrap();

        // breakouts not a thing yet, just assume the 0th link
        let link_id = types::LinkId(0);
        let port_id = match common::ports::PortId::from_str(port_name) {
            Ok(name) => name,
            Err(e) => {
                error!(g.log, "failed to parse port name {port_name}: {e}");
                continue;
            }
        };
        // ensure the link for the tfport exists
        match g.client.link_get(&port_id, &link_id).await {
            Ok(_) => {}
            Err(_) => {
                // this is for softnpu environments which do not currently care
                // about these parameters, so just pick some
                let params = types::LinkCreate {
                    lane: None,
                    speed: types::PortSpeed::Speed100G,
                    fec: Some(types::PortFec::None),
                    autoneg: false,
                    kr: false,
                    tx_eq: None,
                };
                if let Err(e) = g.client.link_create(&port_id, &params).await {
                    error!(
                        g.log,
                        "failed to create link for tfport {port_name}: {e}"
                    );
                }
            }
        };

        // track the metrics for the simport link
        if let Err(e) = g.link_tracker.track_link(p, link::ModelType::Simport) {
            error!(g.log, "failed to track link {p}: {e}");
        }

        // sync addresses to the ASIC
        let asic_v4_addrs: HashSet<Ipv4Addr> = match g
            .client
            .link_ipv4_list_stream(&port_id, &link_id, None)
            .map_ok(|entry| entry.addr)
            .try_collect()
            .await
        {
            Ok(addrs) => addrs,
            Err(e) => {
                error!(
                    g.log,
                    "failed to collect stream of ipv4 addresses: {e}"
                );
                continue;
            }
        };

        let asic_v6_addrs: HashSet<Ipv6Addr> = match g
            .client
            .link_ipv6_list_stream(&port_id, &link_id, None)
            .map_ok(|entry| entry.addr)
            .try_collect()
            .await
        {
            Ok(addrs) => addrs,
            Err(e) => {
                error!(
                    g.log,
                    "failed to collect stream of ipv6 addresses: {e}"
                );
                continue;
            }
        };

        let mut port_v4_addrs: HashSet<Ipv4Addr> = HashSet::new();
        let mut port_v6_addrs: HashSet<Ipv6Addr> = HashSet::new();
        for a in &p_addrs {
            match a {
                IpAddr::V4(a) => {
                    port_v4_addrs.insert(*a);
                }
                IpAddr::V6(a) => {
                    port_v6_addrs.insert(*a);
                }
            }
        }

        let to_add_v4 = port_v4_addrs.difference(&asic_v4_addrs);
        let to_del_v4 = asic_v4_addrs.difference(&port_v4_addrs);

        let to_add_v6 = port_v6_addrs.difference(&asic_v6_addrs);
        let to_del_v6 = asic_v6_addrs.difference(&port_v6_addrs);

        for a in to_add_v4 {
            let entry = g.client.ipv4_entry(*a);
            if let Err(e) =
                g.client.link_ipv4_create(&port_id, &link_id, &entry).await
            {
                error!(g.log, "failed to add v4 address {a}: {e}");
            }
        }

        for a in to_del_v4 {
            if let Err(e) =
                g.client.link_ipv4_delete(&port_id, &link_id, a).await
            {
                error!(g.log, "failed to delete v4 address {a}: {e}");
            }
        }

        for a in to_add_v6 {
            let entry = g.client.ipv6_entry(*a);
            if let Err(e) =
                g.client.link_ipv6_create(&port_id, &link_id, &entry).await
            {
                error!(g.log, "failed to add v6 address {a}: {e}");
            }
        }

        for a in to_del_v6 {
            if let Err(e) =
                g.client.link_ipv6_delete(&port_id, &link_id, a).await
            {
                error!(g.log, "failed to delete v6 address {a}: {e}");
            }
        }
    }
    Ok(())
}
