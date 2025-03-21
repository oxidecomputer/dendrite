// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;

use crate::linklocal;
use crate::netsupport;
use crate::oxstats::link;
use crate::packet_queue;
use crate::ports;
use crate::vlans;
use crate::Global;
use common::illumos;
use common::network::MacAddr;

/// The information illumos maintains about a single tfport device
pub struct TfportInfo {
    /// name of the tfport link created with `dladm`
    pub name: String,
    /// ASIC ID in tofino, which is used by the sidecar header to identify the
    /// port
    pub port: u16,
    /// mac address assigned to the port by `dpd`
    pub mac: MacAddr,
    /// index of the interface created by `ipadm`
    pub ifindex: Option<u32>,
    /// link-local address assigned to the tfport interface by Illumos
    pub link_local: Option<Ipv6Addr>,
}

// Parse a single line of dladm output to extract the 3 different expected
// fields
fn parse_tfport_line(line: &str) -> Result<TfportInfo> {
    let parts: Vec<String> =
        line.splitn(3, ':').map(|s| s.to_string()).collect();
    if parts.len() != 3 {
        bail!("malformed dladm line: {line}");
    }

    let name = parts[0].to_string();
    let maybe_port = &parts[1];
    let maybe_mac = &parts[2];

    let port = maybe_port.parse::<u16>().map_err(|_| {
        anyhow!("unable to parse {maybe_port} as a port_id for {name}")
    })?;

    // The parseable output of `dladm show-tfport` uses `:` as the field
    // separator, so the `:` separating the MAC address octets are escaped.
    // Remove the escaping before parsing, and then return whether the data
    // matches exactly or not.
    let mac = maybe_mac
        .trim()
        .replace('\\', "")
        .parse::<MacAddr>()
        .map_err(|_| {
            anyhow!("unable to parse {maybe_mac} as a mac address for {name}")
        })?;

    Ok(TfportInfo {
        name,
        port,
        mac,
        ifindex: None,
        link_local: None,
    })
}

async fn lldp_toggle_disabled(
    log: &slog::Logger,
    tfport: &str,
    val: bool,
) -> anyhow::Result<()> {
    let client = lldpd_client::Client::new(
        &format!("http://localhost:{}", lldpd_client::default_port()),
        log.clone(),
    );

    // Convert a tfport name into a dpd port name.  So, tfportqsfp0_0 -> qsfp0/0.
    let port = tfport.replace("tfport", "").replace("_", "/");

    match client.interface_set_disabled(&port, val).await {
        Ok(_) => Ok(()),
        Err(e) => match e.status() {
            Some(http::StatusCode::NOT_FOUND) => Ok(()),
            _ => Err(e),
        },
    }
    .context("failed to set the lldp disabled flag to {val}")
}

// Get the list of tfports active in the system
pub async fn tfport_list() -> Result<BTreeMap<String, TfportInfo>> {
    let link_locals = linklocal::get_all().await?;
    let mut rval = BTreeMap::new();

    for line in
        illumos::dladm(&["show-tfport", "-p", "-o", "link,port,macaddress"])
            .await?
    {
        match parse_tfport_line(&line) {
            Ok(mut tfport) => {
                if &tfport.name != "tfport0" {
                    tfport.ifindex = netsupport::get_ifindex(&tfport.name);
                    tfport.link_local = link_locals.get(&tfport.name).copied();
                    rval.insert(tfport.name.to_string(), tfport);
                }
            }
            Err(err) => eprintln!("{err:?}"),
        }
    }
    Ok(rval)
}

/// Delete a single tfport, identified by the link name.  This call will
/// remove all addresses assigned to the port before destroying the port itself.
pub async fn tfport_delete(g: &Global, link: &str) -> anyhow::Result<()> {
    debug!(g.log, "cleaning up tfport {link}");
    let mut err: Option<anyhow::Error> = None;

    match illumos::iface_exists(link)
        .await
        .context("failed to look up {link} iface")
    {
        Err(e) => err = Some(e),
        Ok(false) => {
            // interface already deleted
        }
        Ok(true) => {
            if let Err(e) = illumos::iface_remove(link)
                .await
                .context("failed to remove {link} iface")
            {
                err = Some(e);
            }
        }
    }

    if let Err(e) = vlans::vlans_cleanup(g, link)
        .await
        .context("failed to clean up vlans on {link}")
    {
        if err.is_none() {
            err = Some(e);
        }
    }

    if let Some(asic_id) = g.tfport_to_asic.lock().unwrap().get(link) {
        packet_queue::ensure_queue_removed(g, *asic_id);
    }

    // Before we delete the tfport, we need to untrack it.
    if let Err(e) = g.link_tracker.untrack_link(link) {
        error!(g.log, "failed to untrack tfport {link}: {e}");
    }

    // Try to disable lldp on this port.  This could fail if the lldp daemon
    // isn't running or if the port isn't configured for lldp.  Even if it does
    // fail, we'll plow on because _we_ only care about lldp to the extent that
    // it causes the tfport_delete() to fail because lldpd is holding the file
    // descriptor open.
    if let Err(e) = lldp_toggle_disabled(&g.log, link, true).await {
        warn!(g.log, "failed to disable lldp daemon on {link}: {e:?}");
    }

    if let Err(e) = illumos::tfport_delete(link)
        .await
        .context("failed to delete tport {link}")
    {
        if err.is_none() {
            err = Some(e);
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Ensure that the provided `tfport` exists with the given parameters.
pub async fn tfport_ensure(
    g: &Global,
    tfport: &str,
    link: &ports::LinkInfo,
) -> anyhow::Result<()> {
    if link.tfport.is_none() {
        illumos::tfport_create(
            &g.pkt_source,
            link.asic_id,
            Some(link.mac),
            tfport,
        )
        .await?;

        // We log, but otherwise ignore, any lldp errors.  The intent here is to
        // undo any previous disable we invoked when tearing down a previous
        // instance of this tfport.  If the daemon is offline, the port will be
        // automatically enabled when the daemon comes back up.
        if let Err(e) = lldp_toggle_disabled(&g.log, tfport, false).await {
            warn!(g.log, "failed to enable lldp daemon on {link}: {e:?}");
        }
    }

    // Once the tfport is created, we can then start tracking it.
    if let Err(e) = g.link_tracker.track_link(tfport, link::ModelType::Tfport) {
        error!(g.log, "failed to track tfport {tfport}: {e}");
    }

    // If the tfport is the vlan link, ensure that the vlans are created.
    if let Some(vlan_link) = &g.vlan_link {
        if tfport == vlan_link {
            vlans::ensure_vlans(g, tfport).await?;
        }
    }

    packet_queue::ensure_queue_exists(g, tfport, link.asic_id);

    // If the interface exists but the address doesn't, we need to remove the
    // interface before creating the link-local address due to stlouis#531.
    let mut ifindex = link.tfport_ifindex;
    if link.ipv6_enabled
        && link.tfport_link_local.is_none()
        && ifindex.is_some()
    {
        illumos::iface_remove(tfport).await?;
        ifindex = None;
    }
    if ifindex.is_none() {
        illumos::iface_ensure(tfport).await?;
    }
    if link.ipv6_enabled && link.tfport_link_local.is_none() {
        linklocal::create(g, tfport).await?;
    }
    Ok(())
}

/// Delete all existing tfports on the system.
pub async fn tfport_cleanup(g: &Global) {
    let tfports = match tfport_list().await {
        Ok(tfports) => tfports,
        Err(e) => {
            error!(g.log, "failed to get tfport list: {:?}", e);
            BTreeMap::new()
        }
    };

    for tfport in tfports.values() {
        let name = &tfport.name;

        match tfport_delete(g, name).await {
            Ok(()) => {
                info!(g.log, "deleted tfport {}", name);
            }
            Err(e) => {
                error!(g.log, "failed to delete tfport {}: {:?}", name, e)
            }
        }
        packet_queue::ensure_queue_removed(g, tfport.port);
    }
}

/// If tfport0 doesn't already exist, create it.
pub async fn create_tfport0(g: &Global) {
    // Once the tfport0 is created or re-created, we can then start tracking it.
    if let Err(e) = g
        .link_tracker
        .track_link("tfport0", link::ModelType::Tfport)
    {
        error!(g.log, "failed to track tfport0: {e}");
    }

    match illumos::tfport_exists("tfport0")
        .await
        .expect("dladm failed")
    {
        true => {
            info!(
                g.log,
                "found pre-existing tfport0, will attempt to re-track it"
            );
        }
        false => {
            info!(g.log, "creating tfport0");
            illumos::tfport_create(&g.pkt_source, 0, None, "tfport0")
                .await
                .expect("unable to create tfport0");
        }
    }
}

#[test]
fn test_parse_tfport() -> Result<()> {
    // test a valid line
    let t = parse_tfport_line(r"tfport0:10:ba\:70\:57\:bf\:a1\:38")?;
    assert_eq!(t.name, "tfport0");
    assert_eq!(t.port, 10);
    assert_eq!(t.mac, MacAddr::new(0xba, 0x70, 0x57, 0xbf, 0xa1, 0x38));

    // Too few fields
    assert!(parse_tfport_line(r"tfport0:ba\:70\:57\:bf\:a1\:38").is_err());

    // Too many fields
    assert!(parse_tfport_line(r"tfport0:10:10:ba\:70\:57\:bf\:a1\:38").is_err());
    // Invalid mac addresses
    assert!(
        parse_tfport_line(r"tfport0:10:ba\:70\:57\:bf\:a1\:38\:44").is_err()
    );
    assert!(parse_tfport_line(r"tfport0:10:ba\:70\:57\:bf\:a1\:GG").is_err());
    assert!(parse_tfport_line(r"tfport0:10:ba\:70\:57\:bf\:a1").is_err());

    // Invalid port number
    assert!(parse_tfport_line(r"tfport0:foo:ba\:70\:57\:bf\:a1\:38").is_err());
    assert!(
        parse_tfport_line(r"tfport0:1000000000:ba\:70\:57\:bf\:a1\:38")
            .is_err()
    );

    Ok(())
}
