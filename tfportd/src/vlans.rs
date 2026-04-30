// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::Ipv6Addr;

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use iddqd::IdOrdItem;
use iddqd::IdOrdMap;
use iddqd::id_upcast;
use serde::Deserialize;
use slog::error;
use slog::info;
use slog::warn;

use crate::Global;
use crate::linklocal;
use crate::oxstats::link;
use common::illumos;

/// An entry in the `port_map.csv` file provided at program startup.
#[derive(Debug, Deserialize)]
struct PortMapEntry {
    /// The VSC7448 port number.
    port: u16,
    /// A human-friendly string naming the logical partner on the link.
    _link_partner: String,
    /// The name of the VLAN object to be created mapping to the link partner.
    vlan_name: String,
}

/// Mapping of vlan names to vlan IDs specified in a config file at startup
#[derive(Debug)]
pub struct Vlan {
    pub vid: u16,
    pub name: String,
}

/// The information illumos maintains about a single VLAN
#[derive(Debug)]
pub struct VlanInfo {
    /// The name of the VLAN device.
    pub name: String,
    /// VLAN ID
    pub vid: u16,
    /// index of the interface created by `ipadm`
    pub ifindex: Option<u32>,
    /// link-local address assigned to the vlan by Illumos
    pub link_local: Option<Ipv6Addr>,
}

impl VlanInfo {
    /// Return true if this VLAN should allow DHCPv6 autoconfiguration.
    fn supports_dhcp(&self) -> bool {
        self.name.starts_with("techport")
    }
}

impl IdOrdItem for VlanInfo {
    type Key<'a> = &'a str;

    fn key(&self) -> Self::Key<'_> {
        &self.name
    }

    id_upcast!();
}

/// Get the list of vlans created on top of a tfport
async fn vlans_get(tfport: &str) -> anyhow::Result<IdOrdMap<VlanInfo>> {
    let link_locals = linklocal::get_all().await?;
    let lines =
        illumos::dladm(&["show-vlan", "-p", "-o", "link,vid,over"]).await?;

    // Iterate over the dladm output, extracting the vlan name and vid from each
    // line.  For each vlan created on top of this tfport, add an entry to the
    // map with the network configuration for each one.
    let mut rval = IdOrdMap::new();
    for vlan in lines {
        let fields: Vec<_> = vlan.split(':').collect();
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
        let vlan = VlanInfo { name: link, vid, ifindex, link_local };

        // NOTE: We previously used a BTreeMap here, and ignored any duplicates.
        // Keep the same behavior, ignoring the error.
        let _ = rval.insert_overwrite(vlan);
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

    for vlan in &vlans {
        let name = &vlan.name;
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
    let mut to_delete = existing_vlans
        .iter()
        .map(|vlan| vlan.name.to_string())
        .collect::<BTreeSet<_>>();
    for expected_vlan in &g.vlans {
        if let Some(current_vlan) =
            existing_vlans.get(expected_vlan.name.as_str())
            && current_vlan.vid == expected_vlan.vid
        {
            // This vlan has the right name and ID, so we leave it alone
            let _ = to_delete.remove(expected_vlan.name.as_str());
            continue;
        }
        to_create.insert(expected_vlan.name.to_string(), expected_vlan.vid);
    }

    // Delete any vlans that were unexpected
    for name in &to_delete {
        if let Err(e) = vlan_delete(g, name).await {
            error!(g.log, "failed to delete vlan {name}: {e:?}");
        }
        let _ = existing_vlans.remove(name.as_str());
    }

    // Create any missing vlans
    for (name, vid) in to_create {
        match illumos::vlan_create(link, vid, &name).await {
            Ok(()) => {
                info!(g.log, "created vlan {vid}:{name} on {link}");
                let vlan = VlanInfo {
                    name: name.clone(),
                    vid,
                    ifindex: None,
                    link_local: None,
                };
                // NOTE: We previously used a BTreeMap here, and ignored any duplicates.
                // Keep the same behavior, logging an error.
                if let Some(old) = existing_vlans.insert_overwrite(vlan) {
                    warn!(
                        &g.log,
                        "overwriting duplicate VLAN for tfport";
                        "tfport" => link,
                        "vlan" => old.name,
                        "vid" => old.vid,
                    );
                }

                // Once the vlan is created, we can track it as a potential
                // network link.
                if let Err(e) =
                    g.link_tracker.track_link(&name, link::ModelType::Vlan)
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
    for mut info in existing_vlans.iter_mut() {
        // If the interface exists but the address doesn't, we need to remove the
        // interface before creating the link-local address due to stlouis#531.
        if info.link_local.is_none()
            && info.ifindex.is_some()
            && illumos::iface_remove(&info.name).await.is_ok()
        {
            info.ifindex = None;
        }
        if info.ifindex.is_none() {
            match illumos::iface_ensure(&info.name).await {
                Ok(()) => {
                    slog::debug!(
                        g.log,
                        "created interface for vlan: {}",
                        &info.name
                    )
                }
                Err(e) => {
                    slog::error!(
                        g.log,
                        "failed to create interface for vlan: {}: {e}",
                        &info.name,
                    );
                    continue;
                }
            }
        }
        if info.link_local.is_none() {
            if info.supports_dhcp() {
                let _ = linklocal::create_with_dhcpv6(g, &info.name).await;
            } else {
                let _ = linklocal::create(g, &info.name).await;
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

        vlans.push(Vlan { vid: e.port + 0x100, name: e.vlan_name });
    }
    Ok(vlans)
}
