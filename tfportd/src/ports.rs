// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Create `tfport`s on the host that represent `dpd` links.
//!
//! `tfportd` and `dpd` share responsibility for maintaining the tfport devices.
//! `dpd` instantiates tofino links based on a config file describing the
//! backplane and admin input describing the links on the front plane.  Each
//! link is assigned a MAC address by dpd, derived by combining the link ID and
//! a per-sidecar value.  For each port configured at `dpd`, `tfportd`
//! instantiates a `tfport` dladm link and instructs illumos to assign it a
//! link-local IPv6 address.  When that address has been assigned, `tfportd`
//! notifies `dpd` to push that address into the tofino's p4 tables.
//!
//! `tfportd` regularly polls `dpd` for the population of configured ports and
//! the addresses it knows about.  If `tfportd` finds a discrepancy with the set
//! of `tfport` devices it maintains, it takes corrective action.
//!
//! In addition to maintaining the population of `tfport` links, this daemon
//! also montors the `tfpkt` source for packets arriving tagged with Sidecar
//! headers.  Those headers include a bit of extra information, added by the
//! Sidecar P4 program, such as the ASIC ID (a Tofino-level identifier for the
//! link); or why it was forwarded to the host (such as for NDP resolution).
//! This allows us to use the illumos host OS address resolution mechanisms,
//! such as the NDP daemon. The P4 program forwards packets that need
//! resolution; illumos resolves them and sends them back when that's complete.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use dpd_client::types;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;

use crate::poll_interval;
use crate::tfport;
use crate::Global;
use common::network::MacAddr;

/// Information about a single link in `dpd`, and its associated `tfport` if it
/// exists.
pub struct LinkInfo {
    /// The name of the link.
    pub name: String,
    /// The switch port ID for this link.
    pub port_id: common::ports::PortId,
    /// The link ID for this link.
    pub link_id: types::LinkId,
    /// The low-level Tofino ID used to refer to this link.
    pub asic_id: u16,
    /// The MAC address for the link.
    pub mac: MacAddr,
    /// Is this link configured to support IPv6?
    pub ipv6_enabled: bool,
    /// The IPv6 link-local address of the link in dpd, if it exists.
    pub dpd_link_local: Option<Ipv6Addr>,

    /// The name of the `tfport` device, if it exists.
    pub tfport: Option<String>,
    /// The index of the `tfport` interface, if it exists.
    pub tfport_ifindex: Option<u32>,
    /// The IPv6 link-local address of the tfport in illumos, if it exists.
    pub tfport_link_local: Option<Ipv6Addr>,
}

impl fmt::Display for LinkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&types::TfportData> for LinkInfo {
    fn from(t: &types::TfportData) -> Self {
        LinkInfo {
            name: t.to_string(),
            port_id: t.port_id,
            link_id: t.link_id,
            asic_id: t.asic_id,
            mac: t.mac.clone().into(),
            ipv6_enabled: t.ipv6_enabled,
            dpd_link_local: t.link_local,
            tfport: None,
            tfport_ifindex: None,
            tfport_link_local: None,
        }
    }
}

/// The set of all links on the system, and their `tfports`.
type LinkMap = BTreeMap<String, LinkInfo>;

// Return the name for a `tfport` device, based on the link it represents.
fn tfport_name(link: &types::TfportData) -> String {
    format!("tfport{}_{}", link.port_id, *link.link_id)
}

// Fetch the set of ports configured by dpd and update our internal LinkMap
async fn dpd_port_update(g: &Global, links: &mut LinkMap) -> Result<()> {
    // Fetch all links that `dpd` knows about.
    let dpd_data = g
        .client
        .tfport_data()
        .await
        .context("failed to list all links")?
        .into_inner()
        .into_iter();

    let mut current_links: BTreeSet<String> = links.keys().cloned().collect();

    // Iterate over the dpd list, updating our LinkInfo for each port with the
    // current illumos state.  Any dpd ports that don't already have LinkInfo
    // entries will have them created at this point.
    for entry in dpd_data {
        let expected_tfport = tfport_name(&entry);
        let _ = current_links.remove(&expected_tfport);
        let link = links
            .entry(expected_tfport.clone())
            .or_insert((&entry).into());
        let entry_mac = entry.mac.into();
        link.dpd_link_local = entry.link_local;

        // Check to see if the state in dpd matches our in-core state.
        // Neither of these should change, so it's definitely worth logging.
        // Any change here should cause a mismatch when looking at the existing
        // tfports.
        if link.mac != entry_mac {
            warn!(g.log, "tfport changed mac addresses";
			  "tfport" => &expected_tfport,
			  "mac" => entry_mac.to_string(),
			  "stale_mac" => link.mac.to_string());
            link.mac = entry_mac;
        }
        if link.asic_id != entry.asic_id {
            warn!(g.log, "tfport changed asic IDs";
			  "tfport" => &expected_tfport,
			  "asic_id" => entry.asic_id,
			  "stale_asic_id" => link.asic_id);
            link.asic_id = entry.asic_id;
        }
    }

    // Stop tracking any ports that no longer exist
    while let Some(link) = current_links.pop_first() {
        info!(g.log, "{link} no longer exists at dpd");
        let _ = links.remove(&link);
    }

    Ok(())
}

// Fetch the tfports configured in illumos and update our internal LinkMap.
// Returns a list of the tfports that no longer have corresponding ports in dpd.
async fn illumos_port_update(
    g: &Global,
    links: &mut LinkMap,
) -> Result<Vec<String>> {
    // Fetch the list of tfports configured in illumos
    let mut illumos_data = tfport::tfport_list().await?;

    for (tfport, link) in links {
        match illumos_data.get(tfport) {
            Some(data) => {
                // If the local port matches the dpd-configured port (as we
                // generally expect it will), update the LinkInfo struct
                // with the illumos state.  If the port doesn't match, we
                // leave the entry in the illumos_data to get cleaned up in
                // the next step as an orphan.
                if link.asic_id == data.port && link.mac == data.mac {
                    let data = illumos_data
                        .remove(tfport)
                        .expect("existence already checked");
                    link.tfport = Some(tfport.to_string());
                    link.tfport_ifindex = data.ifindex;
                    link.tfport_link_local = data.link_local;
                    continue;
                } else {
                    info!(g.log, "tfport found with stale data";
				  "tfport" => tfport,
				  "mac" => link.mac.to_string(),
				  "stale_mac" => data.mac.to_string(),
				  "asic_id" => link.asic_id,
				  "stale_asic_id" => data.port);
                }
            }
            None => {
                if link.tfport.is_some() {
                    info!(g.log, "tfport disappeared";
			  "tfport" => tfport);
                }
            }
        }

        // If we get here, it's because the current tfport (if any) doesn't
        // match the dpd state.  Clearing these fields will cause the
        // correct tfport to get created.
        link.tfport = None;
        link.tfport_ifindex = None;
        link.tfport_link_local = None;
    }

    // Any ports left in this list either had no correponding dpd info, or had
    // stale dpd info.  Either way, we return them as "orphans" to be cleaned up.
    Ok(illumos_data.keys().cloned().collect())
}

// Make sure that any link-local address configured in dpd matches the address
// set on the local tfport by illumos.
//
// This happens in two steps:
//
//   1. If there is a link-local address in dpd, we delete it if there is no
//      link-local address in illumos or if the illumos address is different
//      than that at dpd (*).
//
//   2. If there is a link-local address in illumos, we send that to dpd if dpd
//      doesn't already have a matching address.
//
// If dpd and illumos both have the same link-local address (i.e., Some(dpd) ==
// Some(illumos)), or neither has an address at all (i.e., None == None), then
// there is no action to be taken.
//
// (*) It would be very weird for the two sides to have different link-local
//     addresses, since they are derived from the mac address.  This should only
//     happen if the mac address changes which, as noted in dpd_port_update(),
//     would also be very weird.
async fn ensure_address_match(g: &Global, link: &LinkInfo) -> Result<()> {
    if let Some(addr) = link.dpd_link_local {
        if link.dpd_link_local != link.tfport_link_local {
            warn!(g.log, "deleting stale dpd address: {addr}");
            g.client
                .link_ipv6_delete(&link.port_id, &link.link_id, &addr)
                .await
                .context("deleting stale link-local address")?;
        }
    }

    if let Some(addr) = link.tfport_link_local {
        if link.dpd_link_local != link.tfport_link_local {
            info!(g.log, "sending new tfport address: {addr}");
            g.client
                .link_ipv6_create(
                    &link.port_id,
                    &link.link_id,
                    &types::Ipv6Entry {
                        tag: g.client.inner().tag.clone(),
                        addr,
                    },
                )
                .await
                .context("sending new link-local address")?;
        }
    }

    Ok(())
}

pub async fn port_loop(g: Arc<Global>) {
    let mut link_map = LinkMap::new();
    while g.get_running() {
        // Fetch the latest link state from dpd and update our LinkMap
        if let Err(e) = dpd_port_update(&g, &mut link_map).await {
            error!(g.log, "{:?}", e);
        }

        // Fetch the latest tfport state from illumos, including the list of any
        // "orphaned" tfports that no longer have matching links in dpd.
        let orphans = match illumos_port_update(&g, &mut link_map).await {
            Ok(orphans) => orphans,
            Err(e) => {
                error!(g.log, "{:?}", e);
                Vec::new()
            }
        };

        // Clean up any orphaned tfports
        for tfport in orphans {
            if let Err(e) = tfport::tfport_delete(&g, &tfport).await {
                error!(g.log,
		       "failed to clean up stale tfport: {e:?}";
		       "tfport" => tfport)
            }
        }

        let mut tfport_to_asic = BTreeMap::new();
        let mut asic_to_ifindex = BTreeMap::new();
        // Iterate over all of the links and ensure that the local tfport state
        // is in sync with the dpd state.  While we're at it, update the maps
        // used elsewhere in the daemon.
        for (tfport, link) in &link_map {
            tfport_to_asic.insert(tfport.to_string(), link.asic_id);
            if let Some(ifindex) = link.tfport_ifindex {
                asic_to_ifindex.insert(link.asic_id, ifindex);
            }

            if let Err(e) = tfport::tfport_ensure(&g, tfport, link).await {
                error!(g.log,
		       "tfport_ensure() failed: {e:?}";
		       "tfport" => tfport)
            }

            if let Err(e) = ensure_address_match(&g, link).await {
                error!(g.log,
		       "ensure_address_match() failed: {e:?}";
		       "tfport" => tfport)
            }
        }
        *g.tfport_to_asic.lock().unwrap() = tfport_to_asic;
        *g.asic_to_ifindex.lock().unwrap() = asic_to_ifindex;

        tokio::time::sleep(poll_interval()).await;
    }

    debug!(g.log, "port loop exiting");
}
