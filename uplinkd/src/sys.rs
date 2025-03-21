// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::process::Command;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use libc::c_int;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGQUIT;
use signal_hook::consts::SIGTERM;
use signal_hook::consts::SIGUSR1;
use signal_hook::iterator::Signals;
use slog::debug;
use slog::error;
use slog::info;
use structopt::StructOpt;

use common::network::Cidr;
use common::network::Ipv4Cidr;

const DLADM: &str = "/usr/sbin/dladm";
const IPADM: &str = "/usr/sbin/ipadm";
const IFCONFIG: &str = "/usr/sbin/ifconfig";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct UplinkAddress {
    address: Cidr,
    vlan_id: Option<u16>,
}

impl UplinkAddress {
    pub fn new(address: Cidr, vlan_id: Option<u16>) -> Result<UplinkAddress> {
        if let Some(vlan_id) = vlan_id {
            common::network::validate_vlan(vlan_id)?;
        }
        Ok(UplinkAddress { address, vlan_id })
    }
}

/// Convert a string into an UplinkAddress
/// 192.168.1.1/24 => UplinkAddress { 192.168.1.1/24, None }
/// 192.168.1.1/24;200 => UplinkAddress { 192.168.1.1/24, Some(200) }
impl FromStr for UplinkAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = s.split(';').collect();
        let (address, vlan_id) = match fields.len() {
            1 => Ok((fields[0], None)),
            2 => Ok((fields[0], Some(fields[1]))),
            _ => Err(anyhow!("not a valid uplink address: {s}")),
        }?;
        let address = address
            .parse()
            .map_err(|_| anyhow!("not a valid ip address: {address}"))?;
        let vlan_id = match vlan_id {
            None => Ok(None),
            Some(v) => match v.parse() {
                Err(_) => Err(anyhow!("invalid vlan id: {v}")),
                Ok(vlan_id) if vlan_id > 1 && vlan_id < 4096 => {
                    Ok(Some(vlan_id))
                }
                Ok(vlan_id) => Err(anyhow!("vlan id out of range: {vlan_id}")),
            },
        }?;
        Ok(UplinkAddress { address, vlan_id })
    }
}

fn is_link_local(cidr: &Cidr) -> bool {
    match cidr {
        Cidr::V6(c) => (c.prefix.segments()[0] & 0xffc0) == 0xfe80,
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

        let mut addrs = BTreeSet::new();
        while let Some(v) = values.next().transpose()? {
            // Pull the next value from the list as a string and attempt to
            // parse it as an UplinkAddress.
            match v.as_string() {
                Ok(value) => match value.parse() {
                    Ok(cidr) => _ = addrs.insert(cidr),
                    Err(e) => {
                        error!(
                            g.log,
                        "failed to parse {value} as a CIDR for {link}: {e:?}"
                        );
                    }
                },
                Err(e) => {
                    error!(
                        g.log,
                        "failed to extract address for {link}: {e:?}"
                    );
                }
            };
        }
        // convert a link name (e.g., qsfp0_0) into a tfport name (e.g.,
        // tfportqsfp0_0)
        let iface = format!("tfport{link}");
        uplinks.insert(iface, addrs);
    }
    g.desired = uplinks;
    Ok(())
}

// parse an address from ipadm into a CIDR.
fn parse_ipadm_address(addr: &str) -> Result<Cidr> {
    // Special handling for point-to-point links, which ipadm displays as:
    //    10.5.255.35->10.5.255.34
    if let Some((local, _)) = addr.split_once("->") {
        let prefix = local.parse()?;
        Ok(Cidr::V4(Ipv4Cidr {
            prefix,
            prefix_len: 31,
        }))
    } else {
        addr.parse()
            .map_err(|e| anyhow!("unable to parse {addr} as a CIDR: {e:?}"))
    }
}

// Get all of the configured interfaces on the system
fn get_interfaces(log: &slog::Logger) -> BTreeSet<String> {
    let args = vec!["show-if", "-p", "-o", "ifname"];

    let mut interfaces = BTreeSet::new();
    let out = match Command::new(IPADM).args(&args).output() {
        Ok(o) => o,
        Err(e) => {
            error!(log, "failed to get interface list: {e:?}");
            return interfaces;
        }
    };
    if !out.status.success() {
        error!(
            log,
            "failed to get interface list: {}",
            String::from_utf8_lossy(&out.stderr).into_owned()
        );
        return interfaces;
    }

    for ifname in String::from_utf8_lossy(&out.stdout).lines() {
        interfaces.insert(ifname.into());
    }

    interfaces
}

// For an interface, return a map of all the addresses on the interface indexed
// by the object name.
fn get_addrs(
    log: &slog::Logger,
    iface: &str,
) -> Result<BTreeMap<String, UplinkAddress>> {
    let if_name = format!("{iface}/");
    let args = vec!["show-addr", "-p", "-o", "addrobj,addr", &if_name];

    let mut addrs = BTreeMap::new();
    let out = Command::new(IPADM).args(&args).output()?;
    if !out.status.success() {
        return Err(anyhow!(String::from_utf8_lossy(&out.stderr).into_owned()));
    }

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let (addrobj, address) = line
            .split_once(':')
            // clean up the ":" escaped from the parseable output
            .map(|(addrobj, address)| (addrobj, address.replace(r"\:", ":")))
            .expect("ipadm output format is predictable");

        match parse_ipadm_address(&address) {
            Ok(cidr) => {
                // We don't manage link-local addresses, so skip over them
                if !is_link_local(&cidr) {
                    addrs.insert(
                        addrobj.to_string(),
                        UplinkAddress::new(cidr, None).unwrap(),
                    );
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
fn delete_addrobj(log: &slog::Logger, addrobj: &str) -> Result<()> {
    let args = vec!["delete-addr", addrobj];

    let out = Command::new(IPADM).args(&args).output()?;
    if out.status.success() {
        info!(log, "deleted addrobj {addrobj}");
        Ok(())
    } else {
        // XXX: if we get an undeletable interface, this could generate
        // endless log data.  We should track those and just stop trying at
        // some point.
        error!(
            log,
            "failed to delete addrobj {addrobj}: {}",
            String::from_utf8_lossy(&out.stderr).into_owned()
        );
        Err(anyhow!("failed to delete {addrobj}"))
    }
}

// Ideally this would create an IPv6 PtP link using ifconfig, but I haven't
// managed to get that to work yet.
fn create_v6_ptp_link(_iface: &str, _local: Ipv6Addr) -> Result<String> {
    Err(anyhow!("V6 point-to-point links are unsupported"))
}

// Create an IPv4 PtP link using ipadm
fn create_v4_ptp_link_ipadm(addrobj: &str, local: Ipv4Addr) -> Result<String> {
    // In a point-to-point link, the addresses are identical except for the
    // final bit.
    let remote = Ipv4Addr::from(u32::from(local) ^ 1u32).to_string();
    let local = local.to_string();
    let addr_arg = format!("local={local},remote={remote}");
    let args = vec![
        "create-addr",
        "-t",
        "-T",
        "static",
        "-a",
        &addr_arg,
        addrobj,
    ];
    let out = Command::new(IPADM).args(&args).output()?;
    if out.status.success() {
        Ok(format!(
            "created {local} as PtP link to {remote} as {addrobj}"
        ))
    } else {
        Err(anyhow!(
            "ifconfig failed: {}",
            String::from_utf8_lossy(&out.stderr).into_owned()
        ))
    }
}

// Create an IPv4 PtP link using ifconfig
fn create_v4_ptp_link_ifconfig(iface: &str, local: Ipv4Addr) -> Result<String> {
    // In a point-to-point link, the addresses are identical except for the
    // final bit.
    let remote = Ipv4Addr::from(u32::from(local) ^ 1u32).to_string();
    let local = local.to_string();
    let args = vec![
        iface,
        &local,
        "destination",
        &remote,
        "netmask",
        "255.255.255.255",
        "up",
    ];
    let out = Command::new(IFCONFIG).args(&args).output()?;
    if out.status.success() {
        Ok(format!(
            "created {local} as PtP link to {remote} on {iface}"
        ))
    } else {
        Err(anyhow!(
            "ifconfig failed: {}",
            String::from_utf8_lossy(&out.stderr).into_owned()
        ))
    }
}

// Add a normal, non-PtP link using ipadm
fn create_link(addrobj: &str, addr: &Cidr) -> Result<String> {
    let addr = addr.to_string();
    let args = vec!["create-addr", "-t", "-T", "static", "-a", &addr, addrobj];

    let out = Command::new(IPADM).args(&args).output()?;
    if out.status.success() {
        Ok(format!("created {addr} as addrobj {addrobj}"))
    } else {
        Err(anyhow!(
            "ipadm failed: {}",
            String::from_utf8_lossy(&out.stderr).into_owned()
        ))
    }
}

// Assign an address as the provided addrobj
fn create_addrobj(
    log: &slog::Logger,
    ipadm_works: bool,
    iface: &str,
    addrobj: &str,
    addr: &Cidr,
) -> Result<()> {
    debug!(
        log,
        "create_addrobj addr: {addr}  iface: {iface}  addrobj: {addrobj}"
    );
    // ipadm can't create point-to-point links, so we need to special-case them
    match addr {
        Cidr::V4(v4cidr) if v4cidr.prefix_len == 31 => match ipadm_works {
            true => create_v4_ptp_link_ipadm(addrobj, v4cidr.prefix),
            false => create_v4_ptp_link_ifconfig(iface, v4cidr.prefix),
        },
        Cidr::V6(v6cidr) if v6cidr.prefix_len == 127 => {
            create_v6_ptp_link(iface, v6cidr.prefix)
        }
        addr => create_link(addrobj, addr),
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
