// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use dpd_client::types::Ipv6Entry;
use oxnet::UnicastLinkLocalIpv6Addr;
use slog::{debug, error, warn};

use crate::Global;
use crate::oxstats::link;
use crate::poll_interval;
use common::{addr::IpAddrLike, illumos};
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

async fn ipadm_addrs() -> anyhow::Result<impl Iterator<Item = (String, IpAddr)>>
{
    Ok(illumos::ipadm(&["show-addr", "-p", "-o", "addrobj,addr"])
        .await?
        .into_iter()
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
        }))
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

/// Reconciles the IPv6 link local address from illumos to DPD
/// for all links DPD is aware of.
async fn simnet_process(g: &Global) -> anyhow::Result<()> {
    let simports = simnet_tfport_get().await?;
    debug!(g.log, "found simports {:#?}", simports);

    let addrs = ipadm_addrs()
        .await?
        .filter_map(|(name, addr)| {
            let addr = UnicastLinkLocalIpv6Addr::new(addr.v6()?).ok()?;
            Some((name, addr))
        })
        .collect::<Vec<_>>();
    let tag = g.client.inner().tag.as_str();

    let dpd_ports = g.client.tfport_data().await?.into_inner();
    for p in &simports {
        if let Err(e) = illumos::iface_ensure(p).await {
            warn!(g.log, "{e}");
            continue;
        }

        // breakouts not a thing yet, just assume the 0th link
        let link_id = types::LinkId(0);
        let link_local = addrs
            .iter()
            .find_map(|(name, addr)| name.starts_with(p).then_some(addr));

        let Some(link_local) = link_local.copied() else {
            warn!(g.log, "{p} has no IPv6 unicast link local addr(s)");
            continue;
        };
        debug!(g.log, "sync {p} addr {link_local:?}");

        // need to go from tfport<something>M_N to port_id=<something>M link_id=N
        let Some(port_name) = p.strip_prefix("tfport") else {
            continue;
        };
        let port_name = port_name.split('_').next().unwrap();

        let port_id = match types::PortId::from_str(port_name) {
            Ok(name) => name,
            Err(e) => {
                error!(g.log, "failed to parse port name {port_name}: {e}");
                continue;
            }
        };

        let Some(conf) = dpd_ports
            .iter()
            .find(|entry| entry.port_id == port_id && entry.link_id == link_id)
        else {
            error!(
                g.log,
                "Cannot reconcile {port_id}/{link_id}. Not found in tfport_data()"
            );
            continue;
        };

        // track the metrics for the simport link
        if let Err(e) = g.link_tracker.track_link(p, link::ModelType::Simport) {
            error!(g.log, "failed to track link {p}: {e}");
        }

        if conf.link_local == Some(link_local) {
            continue;
        }

        if let Some(addr) = conf.link_local
            && let Err(e) = g
                .client
                .link_ipv6_delete(&port_id, &link_id, &addr, Some(tag))
                .await
        {
            error!(g.log, "failed to delete v6 address {addr}: {e}");
        }

        if let Err(e) = g
            .client
            .link_ipv6_create(
                &port_id,
                &link_id,
                &Ipv6Entry { addr: link_local.into(), tag: tag.to_string() },
            )
            .await
        {
            error!(g.log, "failed to create v6 address {link_local}: {e}");
        }
    }

    Ok(())
}
