// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use serde::Deserialize;
use slog::error;
use slog::info;

use crate::linklocal;
use crate::oxstats::link;
use crate::Global;
use common::illumos;

#[derive(Debug, Deserialize)]
struct PortMapEntry {
    port: u16,
    _link_partner: String,
    vlan_name: String,
}

/// Mapping of vlan names to vlan IDs specified in a config file at startup
#[derive(Debug)]
pub struct Vlan {
    pub vid: u16,
    pub name: String,
}

/// The information illumos maintains about a single vlan
#[derive(Debug)]
pub struct VlanInfo {
    /// VLAN ID
    pub vid: u16,
    /// index of the interface created by `ipadm`
    pub ifindex: Option<u32>,
    /// link-local address assigned to the vlan by Illumos
    pub link_local: Option<Ipv6Addr>,
}

/// Get the list of vlans created on top of a tfport
async fn vlans_get(tfport: &str) -> anyhow::Result<BTreeMap<String, VlanInfo>> {
    let link_locals = linklocal::get_all().await?;
    let lines =
        illumos::dladm(&["show-vlan", "-p", "-o", "link,vid,over"]).await?;

    // Iterate over the dladm output, extracting the vlan name and vid from each
    // line.  For each vlan created on top of this tfport, add an entry to the
    // BTreeMap with the network configuration for each one.
    let mut rval = BTreeMap::new();
    for vlan in lines {
        let fields: Vec<String> = vlan.split(':').map(str::to_string).collect();
        if fields.len() != 3 {
            bail!("show-vlan returned invalid result: {vlan}");
        }
        if fields[2] != tfport {
            continue;
        }

        let link = fields[0].to_string();
        let vid = fields[1].parse::<u16>().context("invalid vlan_id")?;
        let ifindex = crate::netsupport::get_ifindex(&link);
        let link_local = link_locals.get(&link).copied();
        rval.insert(
            link,
            VlanInfo {
                vid,
                ifindex,
                link_local,
            },
        );
    }
    Ok(rval)
}

/// Delete a single vlan and any interfaces on top of it
async fn vlan_delete(g: &Global, vlan: &str) -> anyhow::Result<()> {
    let _ = illumos::iface_remove(vlan).await;
    // First, untrack the vlan.
    if let Err(e) = g.link_tracker.untrack_link(vlan) {
        error!(g.log, "failed to untrack vlan {vlan}: {e:?}");
    }

    // Then, delete the vlan.
    illumos::vlan_delete(vlan).await?;
    Ok(())
}

/// Delete all of the vlans created over the given tfport link
pub async fn vlans_cleanup(g: &Global, tfport: &str) -> anyhow::Result<()> {
    let vlans = vlans_get(tfport)
        .await
        .map_err(|e| anyhow!("failed to get vlan list for {tfport}: {e:?}"))?;

    for (name, vlan) in &vlans {
        let vid = vlan.vid;
        match vlan_delete(g, name).await {
            Ok(_) => info!(g.log, "deleted vlan {vid}:{name} on {tfport}"),
            Err(e) => error!(
                g.log,
                "failed to delete vlan {vid}:{name} on {tfport}: {e:?}"
            ),
        }
    }

    Ok(())
}

/// Create all of the vlans called for in the port_map.csv file.  This routine
/// assumes that the caller has already created the tfport over which the vlans
/// should be created.
pub async fn ensure_vlans(g: &Global, link: &str) -> anyhow::Result<()> {
    let mut existing_vlans = vlans_get(link).await?;
    let mut to_create = BTreeMap::new();

    // Compare the lists of current and desired vlans to build up lists of vlan
    // links that should be created and/or deleted.  We start by pessimistically
    // assuming that each vlan needs to be deleted, removing them from the
    // to_delete list if we find them on the "expected" list below.
    let mut to_delete =
        existing_vlans.keys().cloned().collect::<BTreeSet<String>>();
    for expected_vlan in &g.vlans {
        if let Some(current_vlan) = existing_vlans.get(&expected_vlan.name) {
            if current_vlan.vid == expected_vlan.vid {
                // This vlan has the right name and ID, so we leave it alone
                let _ = to_delete.remove(&expected_vlan.name);
                continue;
            }
        }
        to_create.insert(expected_vlan.name.to_string(), expected_vlan.vid);
    }

    // Delete any vlans that were unexpected
    for name in &to_delete {
        if let Err(e) = vlan_delete(g, name).await {
            error!(g.log, "failed to delete vlan {name}: {e:?}");
        }
        let _ = existing_vlans.remove(name);
    }

    // Create any missing vlans
    for (name, vid) in to_create {
        match illumos::vlan_create(link, vid, &name).await {
            Ok(()) => {
                info!(g.log, "created vlan {vid}:{name} on {link}");
                existing_vlans.insert(
                    name.to_string(),
                    VlanInfo {
                        vid,
                        ifindex: None,
                        link_local: None,
                    },
                );

                // Once the vlan is created, we can track it as a potential
                // network link.
                if let Err(e) = g
                    .link_tracker
                    .track_link(name.to_string(), link::ModelType::Vlan)
                {
                    error!(g.log, "failed to track vlan {name}: {e:?}");
                }
            }
            Err(e) => {
                error!(g.log, "failed to create vlan {vid}:{name}: {e:?}")
            }
        }
    }

    // Iterate over all of the vlans (old and new) and ensure that they have a
    // link-local address.
    for (name, info) in existing_vlans.iter_mut() {
        // If the interface exists but the address doesn't, we need to remove the
        // interface before creating the link-local address due to stlouis#531.
        if info.link_local.is_none()
            && info.ifindex.is_some()
            && illumos::iface_remove(name).await.is_ok()
        {
            info.ifindex = None;
        }
        if info.ifindex.is_none() {
            match illumos::iface_ensure(name).await {
                Ok(()) => {
                    slog::debug!(g.log, "created interface for vlan: {name}")
                }
                Err(e) => {
                    slog::error!(
                        g.log,
                        "failed to create interface for vlan: {name}: {e}"
                    );
                    continue;
                }
            }
        }
        if info.link_local.is_none() {
            match linklocal::create(g, name).await {
                Ok(()) => {
                    slog::debug!(g.log, "created link-local for vlan: {name}")
                }
                Err(e) => slog::error!(
                    g.log,
                    "failed to create link-local for vlan: {name}: {e}"
                ),
            }
        }
    }

    Ok(())
}

/// Parse the port_map.csv file and return a vector of (vid, name) tuples for all
/// the vlans that should be created.
pub fn init(csv_file: &str) -> anyhow::Result<Vec<Vlan>> {
    let mut vlans = Vec::new();
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .comment(Some(b'#'))
        .from_path(csv_file)?;
    for entry in rdr.deserialize() {
        let e: PortMapEntry = entry?;

        vlans.push(Vlan {
            vid: e.port + 0x100,
            name: e.vlan_name,
        });
    }
    Ok(vlans)
}
