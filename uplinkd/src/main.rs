// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

// This is a very limited function daemon.  It watches the smf database, looking
// for entries in the uplinks/* property group.  Each entry contains a tofino
// link name and one or more addresses.  For each link that has a corresponding
// tfport interface, the daemon ensures that each of those addresses exists on
// the interface, and cleans up any addresses on the interface that aren't
// listed in the property.
//
// Interfaces on the system that don't have corresponding smf properties are
// left untouched.  Entries in the database that don't have corresponding
// illumos interfaces are ignored - this daemon does not create or destroy
// interfaces.
//
// TODO: there is a gap at startup time.  If the daemon crashes, when we restart
// we won't know which addresses are managed and which aren't.  This is only a
// problem if the configured population changes between crashing and restarting.
//
// TODO: currently setting an interface into PtP mode seems to screw it up
// somehow.  Even after removing that address, you can't add a new address to
// it.  Maybe there is a way to reset an interface to broadcast mode after
// deleting its point-to-point link(s)?
//
// TODO: get repeated log messages under control.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use libc::c_int;
use oxnet::IpNet;
use oxnet::Ipv4Net;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGQUIT;
use signal_hook::consts::SIGTERM;
use signal_hook::consts::SIGUSR1;
use signal_hook::iterator::Signals;
use slog::debug;
use slog::error;
use slog::info;
use structopt::StructOpt;

use common::illumos;

struct Global {
    log: slog::Logger,
    // system has a working ipadm
    ipadm_works: bool,
    // Addresses configured in the smf database
    desired: BTreeMap<String, BTreeSet<IpNet>>,
    // Addresses instantiated on the local illumos system
    current: BTreeMap<String, BTreeMap<String, IpNet>>,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "uplinkd", about = "uplink address management daemon")]
struct Opt {
    #[structopt(long, short, about = "use ipadm to establish PtP links")]
    ipadm: bool,

    #[structopt(long, about = "log file")]
    log_file: Option<String>,

    #[structopt(
        long,
        short = "l",
        default_value = "human",
        about = "log format",
        help = "format logs for 'human' or 'json' consumption"
    )]
    log_format: common::logging::LogFormat,
}

fn parse_vlan_id(vlan_id: &str) -> Result<Option<u16>, anyhow::Error> {
    match vlan_id.parse() {
        Err(_) => Err(anyhow!("invalid vlan id: {vlan_id}")),
        Ok(vlan_id) if vlan_id > 1 && vlan_id < 4096 => Ok(Some(vlan_id)),
        Ok(vlan_id) => Err(anyhow!("vlan id out of range: {vlan_id}")),
    }
}

// Given an interface, return a tuple with the underlying link name and any
// vlan_id. Our convention is to name vlans by appending a ".<vlan_id>" to the
// interface.
fn interface_vlan_id(iface: &str) -> (String, Option<u16>) {
    let fields: Vec<&str> = iface.split('.').collect();

    let mut rval = None;
    if fields.len() == 2 {
        if let Ok(Some(vlan_id)) = parse_vlan_id(fields[1]) {
            rval = Some(vlan_id);
        }
    }
    (fields[0].to_string(), rval)
}

fn parse_uplink_property(
    prop: &str,
) -> Result<(IpNet, Option<u16>), anyhow::Error> {
    let fields: Vec<&str> = prop.split(';').collect();
    let (address, vlan_id) = match fields.len() {
        1 => Ok((fields[0], None)),
        2 => Ok((fields[0], parse_vlan_id(fields[1])?)),
        _ => Err(anyhow!("not a valid uplink address: {prop}")),
    }?;
    let address = address
        .parse()
        .map_err(|_| anyhow!("not a valid ip address: {address}"))?;
    Ok((address, vlan_id))
}

fn is_link_local(cidr: &IpNet) -> bool {
    match cidr {
        IpNet::V6(c) => (c.addr().segments()[0] & 0xffc0) == 0xfe80,
        _ => false,
    }
}

// Update our in-memory list of the uplink interfaces that have been configured
// in the smf database.
fn refresh_smf_config(g: &mut Global) -> Result<()> {
    // Create an SMF context and take a snapshot of the current settings
    let scf = smf::Scf::new().context("creating scf handle")?;
    let instance = scf.get_self_instance().context("getting smf instance")?;
    let snapshot = instance
        .get_running_snapshot()
        .context("getting running snapshot")?;

    // All the properties relevant to us fall under the "uplinks" property group
    let pg = match snapshot
        .get_pg("uplinks")
        .context("getting 'uplinks' propertygroup")?
    {
        Some(c) => c,
        None => return Ok(()),
    };

    // From the snapshot, we extract all of the per-link addresses.  We build a
    // BTreeMap, indexed by the link's tfport interface name, and populated with
    // a BTreeSet corresponding to all of the addresses we should set on it.
    let mut uplinks = BTreeMap::new();
    let mut properties = pg.properties()?;
    while let Some(property) = properties.next().transpose()? {
        let link = match property.name() {
            Ok(name) => name,
            Err(e) => {
                error!(g.log, "failed to get link name: {e:?}");
                continue;
            }
        };

        let mut values = match property.values() {
            Ok(v) => v,
            Err(e) => {
                error!(g.log, "failed to get addresses for {link}: {e:?}");
                continue;
            }
        };

        // An uplink may have one or more addresses configured on it, each of
        // which may be associated with a vlan.  Build a map of each vlan, with
        // all addresses associated with that vlan.
        let mut vlans = BTreeMap::new();
        while let Some(v) = values.next().transpose()? {
            let s = match v.as_string() {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        g.log,
                        "failed to extract address for {link}: {e:?}"
                    );
                    continue;
                }
            };

            let (addr, vlan_id) = match parse_uplink_property(&s) {
                Ok(a) => a,
                Err(e) => {
                    error!(g.log,
                        "failed to parse {s} as an uplink address for {link}: {e:?}"
                        );
                    continue;
                }
            };

            let addrs = vlans.entry(vlan_id).or_insert(BTreeSet::new());
            addrs.insert(addr);
        }
        for (vlan_id, addrs) in vlans {
            // convert a link name (e.g., qsfp0_0) into a tfport name (e.g.,
            // tfportqsfp0_0).  VLAN x on the interface becomes tfportqsfp0_0.x.
            let iface = match vlan_id {
                None => format!("tfport{link}"),
                Some(x) => format!("tfport{link}.{x}"),
            };
            uplinks.insert(iface, addrs);
        }
    }
    g.desired = uplinks;
    Ok(())
}

// parse an address from ipadm into a CIDR.
fn parse_ipadm_address(addr: &str) -> Result<IpNet> {
    // Special handling for point-to-point links, which ipadm displays as:
    //    10.5.255.35->10.5.255.34
    if let Some((local, _)) = addr.split_once("->") {
        let prefix = local.parse()?;
        Ok(IpNet::V4(Ipv4Net::new(prefix, 31).unwrap()))
    } else {
        addr.parse()
            .map_err(|e| anyhow!("unable to parse {addr} as a CIDR: {e:?}"))
    }
}

// Get all of the configured interfaces on the system
async fn get_interfaces(log: &slog::Logger) -> BTreeSet<String> {
    match illumos::ipadm(&["show-if", "-p", "-o", "ifname"]).await {
        Err(e) => {
            error!(log, "failed to get interface list: {e:?}");
            BTreeSet::new()
        }
        Ok(lines) => lines.into_iter().collect(),
    }
}

// For an interface, return a map of all the addresses on the interface indexed
// by the object name.
async fn get_addrs(
    log: &slog::Logger,
    iface: &str,
) -> Result<BTreeMap<String, IpNet>> {
    let if_name = format!("{iface}/");

    let mut addrs = BTreeMap::new();
    for line in
        illumos::ipadm(&["show-addr", "-p", "-o", "addrobj,addr", &if_name])
            .await?
    {
        let (addrobj, address) = line
            .split_once(':')
            // clean up the ":" escaped from the parseable output
            .map(|(addrobj, address)| (addrobj, address.replace(r"\:", ":")))
            .expect("ipadm output format is predictable");

        match parse_ipadm_address(&address) {
            Ok(cidr) => {
                // We don't manage link-local addresses, so skip over them
                if !is_link_local(&cidr) {
                    addrs.insert(addrobj.to_string(), cidr);
                }
            }
            Err(e) => {
                error!(log, "unparseable address {address} on {iface} -> {e:?}")
            }
        }
    }
    Ok(addrs)
}

// Delete an address object.
//
// We can delete an address using ipadm, regardless of whether it is broadcast
// or PtP.
async fn delete_addrobj(log: &slog::Logger, addrobj: &str) -> Result<()> {
    match illumos::address_remove(addrobj).await {
        Err(e) => {
            // XXX: if we get an undeletable interface, this could generate
            // endless log data.  We should track those and just stop trying at
            // some point.
            error!(log, "failed to delete addrobj {addrobj}: {e:?}");
            Err(anyhow!("failed to delete {addrobj}"))
        }
        Ok(_) => {
            info!(log, "deleted addrobj {addrobj}");
            Ok(())
        }
    }
}

// Ideally this would create an IPv6 PtP link using ifconfig, but I haven't
// managed to get that to work yet.
fn create_v6_ptp_link(_iface: &str, _local: Ipv6Addr) -> Result<String> {
    Err(anyhow!("V6 point-to-point links are unsupported"))
}

// Create an IPv4 PtP link using ipadm
async fn create_v4_ptp_link_ipadm(
    iface: &str,
    tag: &str,
    local: Ipv4Addr,
) -> Result<String> {
    // In a point-to-point link, the addresses are identical except for the
    // final bit.
    let remote = Ipv4Addr::from(u32::from(local) ^ 1u32).to_string();
    let local = local.to_string();
    let addrobj = format!("{iface}/{tag}");
    let ptp_addr_arg = format!("local={local},remote={remote}");

    illumos::ipadm(&[
        "create-addr",
        "-t",
        "-T",
        "static",
        "-a",
        &ptp_addr_arg,
        &addrobj,
    ])
    .await?;

    Ok(format!(
        "created {local} as PtP link to {remote} as {addrobj}"
    ))
}

// Create an IPv4 PtP link using ifconfig
async fn create_v4_ptp_link_ifconfig(
    iface: &str,
    local: Ipv4Addr,
) -> Result<String> {
    // In a point-to-point link, the addresses are identical except for the
    // final bit.
    let remote = Ipv4Addr::from(u32::from(local) ^ 1u32).to_string();
    let local = local.to_string();

    illumos::ifconfig(&[
        iface,
        "plumb",
        &local,
        "destination",
        &remote,
        "netmask",
        "255.255.255.255",
        "up",
    ])
    .await
    .map(|_| format!("created {local} as PtP link to {remote} on {iface}"))
    .map_err(|e| e.into())
}

// Add a normal, non-PtP link using ipadm
async fn create_link(iface: &str, tag: &str, addr: &IpNet) -> Result<String> {
    illumos::address_add(iface, tag, *addr)
        .await
        .map(|_| format!("created {addr} as addrobj {iface}/{tag}"))
        .map_err(|e| e.into())
}

// Assign an address as the provided addrobj
async fn create_addrobj(
    log: &slog::Logger,
    ipadm_works: bool,
    iface: &str,
    tag: &str,
    addr: &IpNet,
) -> Result<()> {
    debug!(
        log,
        "create_addrobj addr: {addr}  iface: {iface}  tag: {tag}"
    );
    // ipadm can't create point-to-point links, so we need to special-case them
    match addr {
        IpNet::V4(v4cidr) if v4cidr.width() == 31 => match ipadm_works {
            true => create_v4_ptp_link_ipadm(iface, tag, v4cidr.addr()).await,
            false => create_v4_ptp_link_ifconfig(iface, v4cidr.addr()).await,
        },
        IpNet::V6(v6cidr) if v6cidr.width() == 127 => {
            create_v6_ptp_link(iface, v6cidr.addr())
        }
        addr => create_link(iface, tag, addr).await,
    }
    .map(|msg| info!(log, "{msg}"))
    .map_err(|e| {
        // XXX: if we get an uncreateable interface, this could generate
        // endless log data.  We should track those and just stop trying at
        // some point.
        error!(log, "failed to create {addr}: {e:?}");
        e
    })
}

// Query illumos for all of the addresses on the interfaces we've been asked to
// manage.
async fn refresh_illumos_state(g: &mut Global) {
    let desired_ifaces: BTreeSet<String> =
        g.desired.keys().map(|i| i.to_string()).collect();
    let current_ifaces: BTreeSet<String> = g.current.keys().cloned().collect();
    let system_ifaces = get_interfaces(&g.log).await;
    let mut current = BTreeMap::new();

    // We iterate over all of the interfaces configured in SMF as well as the
    // interfaces we have addresses on.  This lets us clean up when an interface
    // has disappeared from the SMF config.
    for iface in current_ifaces.union(&desired_ifaces) {
        let addrs = match get_addrs(&g.log, iface).await {
            Ok(a) => a,
            Err(e) => {
                if system_ifaces.contains(iface) {
                    // The get_addrs() call will fail if the interface
                    // exists but has no addresses on it.
                    BTreeMap::new()
                } else {
                    error!(g.log, "failed to get addresses for {iface}: {e:?}");
                    continue;
                }
            }
        };
        current.insert(iface.to_string(), addrs);
    }
    g.current = current;
}

async fn reconcile_interfaces(g: &mut Global) {
    // Build a list of the interfaces we were managing, but which no longer
    // have any smf entries.
    let unmanaged: Vec<String> = g
        .current
        .keys()
        .filter(|iface| !g.desired.contains_key(*iface))
        .cloned()
        .collect();

    // Delete any addresses we created on these abandoned interfaces.
    for iface in unmanaged {
        debug!(g.log, "cleaning up addresses on unmanaged {iface}");
        for addrobj in g
            .current
            .get(&iface)
            .expect("existence guaranteed above")
            .keys()
        {
            let _ = delete_addrobj(&g.log, addrobj).await;
        }

        // We created the vlan links, so it's up to us to clean them up.
        let (_link, vlan_id) = interface_vlan_id(&iface);
        if vlan_id.is_some() {
            info!(g.log, "removing vlan interface {iface}");
            if let Err(e) = illumos::iface_remove(&iface).await {
                error!(g.log, "failed to remove vlan interface {iface}: {e:?}");
                // Even if we failed to remove the interface, we'll still try to
                // remove the underlying link.  The most likely reason for the
                // interface deletion to fail is that it's already gone.
            }
            info!(g.log, "removing vlan link {iface}");
            if let Err(e) = illumos::vlan_delete(&iface).await {
                error!(g.log, "failed to remove vlan link {iface}: {e:?}");
            }
        }
    }

    // Compare the list of available interfaces with the list of interfaces
    // listed in SMF.  We create any missing vlan links.
    let desired_ifaces: Vec<String> = g.desired.keys().cloned().collect();
    for iface in &desired_ifaces {
        if let Entry::Vacant(e) = g.current.entry(iface.to_string()) {
            if let (link, Some(vlan_id)) = interface_vlan_id(iface) {
                info!(g.log, "creating vlan link {iface}");
                if let Err(e) =
                    illumos::vlan_create(&link, vlan_id, iface).await
                {
                    error!(g.log, "failed to create vlan link {iface}: {e:?}");
                }

                // Even if the vlan link creation failed, we will still attempt
                // to create the desired addresses.  In the best case, the
                // creation failed because it already exists, so we definitely
                // want to set up the addresses.  In the worst case, the link
                // doesn't exist, and the subsequent address creation will also
                // fail.
                e.insert(BTreeMap::new());
            }
        }
    }
}

// Compare the desired config from SMF with the actual config from illumos and
// try to make the latter match the former.
async fn reconcile(g: &mut Global) {
    reconcile_interfaces(g).await;

    for (iface, desired_addrs) in &g.desired {
        let current_addrs = match g.current.get(iface) {
            Some(a) => a,
            None => continue,
        };

        // Our address objects are named uplinkX.  Find the highest numbered
        // object on this interface, so we know where to start creating new
        // ones.
        let mut max_uplink = 0;
        let uplink_prefix = format!("{iface}/uplink");
        for addrobj in current_addrs.keys() {
            if let Some(idx) = addrobj.strip_prefix(&uplink_prefix) {
                if let Ok(idx) = idx.parse::<u32>() {
                    if idx > max_uplink {
                        max_uplink = idx;
                    }
                }
            }
        }

        // Iterate over all of the addresses assigned to this interface.
        // If the desired address isn't already assigned, create it.
        for desired in desired_addrs {
            if !current_addrs.values().any(|addr| addr == desired) {
                max_uplink += 1;
                _ = create_addrobj(
                    &g.log,
                    g.ipadm_works,
                    iface,
                    &format!("uplink{max_uplink}"),
                    desired,
                )
                .await;
            }
        }

        // Remove any managed addresses from illumos that aren't in SMF
        for (addrobj, addr) in current_addrs {
            if !desired_addrs.iter().any(|x| x == addr) {
                _ = delete_addrobj(&g.log, addrobj).await;
            }
        }
    }
}

// Each signal we receive is converted into a message we send to the main
// thread.
#[derive(Debug, PartialEq)]
enum Messages {
    Refresh,
    Exit,
}

fn handle_signals(log: slog::Logger, tx: mpsc::Sender<Messages>) {
    const SIGNALS: &[c_int] = &[SIGTERM, SIGQUIT, SIGINT, SIGUSR1];
    let mut signals = Signals::new(SIGNALS).unwrap();

    for signal in signals.forever() {
        match signal {
            SIGTERM | SIGQUIT | SIGINT => {
                info!(log, "received signal"; "sig" => signal);
                tx.send(Messages::Exit).unwrap();
                return;
            }
            SIGUSR1 => {
                info!(log, "handling SMF refresh");
                tx.send(Messages::Refresh).unwrap();
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opt::from_args();

    let mut global = Global {
        log: common::logging::init("uplinkd", &opts.log_file, opts.log_format)?,
        ipadm_works: opts.ipadm,
        desired: BTreeMap::new(),
        current: BTreeMap::new(),
    };

    let signal_log = global.log.clone();
    let (tx, rx) = mpsc::channel();
    let handler = std::thread::spawn(|| handle_signals(signal_log, tx));

    let mut smf_refresh_needed = true;
    loop {
        if smf_refresh_needed {
            match refresh_smf_config(&mut global) {
                Ok(_) => {
                    info!(global.log, "SMF properties refreshed");
                    smf_refresh_needed = false;
                }
                Err(e) => error!(global.log, "SMF re-load failed: {e:?}"),
            }
        }
        refresh_illumos_state(&mut global).await;
        reconcile(&mut global).await;

        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Messages::Refresh) => smf_refresh_needed = true,
            Ok(Messages::Exit) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                info!(global.log, "signal handler shut down");
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }

    let _ = handler.join();
    Ok(())
}
