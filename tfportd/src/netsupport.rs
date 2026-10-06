// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use anyhow::anyhow;
use libnet::IpInfo;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv6Addr};

unsafe extern "C" {
    pub fn link_local_get(
        ifname: *const ::std::os::raw::c_char,
        addr: *mut u8,
    ) -> ::std::os::raw::c_int;
    pub fn ifindex_get(
        ifname: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
    pub fn trigger_ndp(ifindex: u32, addr: *const u8) -> ::std::os::raw::c_int;
    pub fn trigger_arp(ifindex: u32, addr: *const u8) -> ::std::os::raw::c_int;
    pub fn netsupport_init() -> ::std::os::raw::c_int;
    pub fn netsupport_fini();
}

pub fn trigger_resolution(ifindex: u32, addr: IpAddr) -> Result<(), String> {
    match addr {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            unsafe {
                match trigger_arp(ifindex, octets.as_ptr()) {
                    0 => Ok(()),
                    x => Err(format!("trigger_arp failed: {x}")),
                }
            }
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            unsafe {
                match trigger_ndp(ifindex, octets.as_ptr()) {
                    0 => Ok(()),
                    x => Err(format!("trigger_ndp failed: {x}")),
                }
            }
        }
    }
}

pub fn get_link_local(name: &str) -> Option<Ipv6Addr> {
    let c_name = match CString::new(name.to_string()) {
        Ok(c) => c,
        Err(_) => return None,
    };

    let raw = c_name.into_raw();
    unsafe {
        let mut addr = [0u8; 16];
        let addr_ptr = addr.as_mut_ptr();

        let ipv6 = match link_local_get(raw, addr_ptr) {
            0 => Some(Ipv6Addr::from(addr)),
            _ => None,
        };
        // retake ownership so we can free the memory
        let _c_name = CString::from_raw(raw);
        ipv6
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GetDhcp6Error {
    #[error("libnet error: {0}")]
    Libnet(#[from] libnet::Error),

    #[cfg(not(test))]
    #[error("error mapping ifname to addrobj: {0}")]
    IfnameToAddrobj(String),
}

#[cfg(not(test))]
fn get_ipaddrs() -> Result<BTreeMap<String, Vec<IpInfo>>, GetDhcp6Error> {
    libnet::get_ipaddrs().map_err(GetDhcp6Error::Libnet)
}

#[cfg(test)]
fn get_ipaddrs() -> Result<BTreeMap<String, Vec<IpInfo>>, GetDhcp6Error> {
    Ok(BTreeMap::from([
        (
            String::from("net0"),
            vec![IpInfo {
                ifname: String::from("net0"),
                index: 0,
                addr: "1.2.3.0".parse().unwrap(),
                mask: 24,
                family: 4,
                state: libnet::IpState::OK,
            }],
        ),
        (
            String::from("net1"),
            vec![
                // One static IPv4 address
                IpInfo {
                    ifname: String::from("net1"),
                    index: 1,
                    addr: "1.2.4.0".parse().unwrap(),
                    mask: 24,
                    family: 4,
                    state: libnet::IpState::OK,
                },
                // One link-local IPv6
                IpInfo {
                    ifname: String::from("net1"),
                    index: 2,
                    addr: "fe80::1".parse().unwrap(),
                    mask: 64,
                    family: 6,
                    state: libnet::IpState::OK,
                },
                // A "bootstrap" address
                IpInfo {
                    ifname: String::from("net1"),
                    index: 2,
                    addr: "fdb1::1".parse().unwrap(),
                    mask: 64,
                    family: 6,
                    state: libnet::IpState::OK,
                },
                // And a DHCPv6 address
                IpInfo {
                    ifname: String::from("net1"),
                    index: 2,
                    addr: "2001:db8::1".parse().unwrap(),
                    mask: 64,
                    family: 6,
                    state: libnet::IpState::OK,
                },
            ],
        ),
    ]))
}

#[cfg(not(test))]
fn ifname_to_addrobj(
    name: &str,
    family: u16,
) -> Result<(String, String), GetDhcp6Error> {
    libnet::ip::ifname_to_addrobj(name, family)
        .map_err(GetDhcp6Error::IfnameToAddrobj)
}

#[cfg(test)]
fn ifname_to_addrobj(
    name: &str,
    family: u16,
) -> Result<(String, String), GetDhcp6Error> {
    match family {
        4 => Ok((format!("{name}/v4"), String::from("static"))),
        6 => Ok((format!("{name}/v6"), String::from("addrconf"))),
        _ => unreachable!(),
    }
}

pub fn get_dhcpv6(
    ifname: &str,
) -> anyhow::Result<Vec<Ipv6Addr>, GetDhcp6Error> {
    let mut result = Vec::default();
    for (ifx, addrs) in get_ipaddrs()?.into_iter() {
        for addr in addrs {
            let (addrobj, src) = ifname_to_addrobj(ifx.as_str(), addr.family)?;

            // filter to the specified ifname
            if !addrobj.starts_with(ifname) {
                continue;
            }

            // only consider addrconf addresses (dhcpv6 is an addrconf address)
            if src != "addrconf" {
                continue;
            }

            if let IpAddr::V6(v6) = &addr.addr {
                // skip link local addresses
                if v6.is_unicast_link_local() {
                    continue;
                }

                // skip locally generated SLAAC addresses
                if [0xfdb1, 0xfdb2].contains(&v6.segments()[0]) {
                    continue;
                }

                // if we've gotten this far, the address is an addrconf address
                // that is not link local and not SLAAC, so it should be dhcpv6
                result.push(*v6);
            }
        }
    }
    Ok(result)
}

pub fn get_ifindex(name: &str) -> Option<u32> {
    let c_name = match CString::new(name.to_string()) {
        Ok(c) => c,
        Err(_) => return None,
    };

    let raw = c_name.into_raw();
    unsafe {
        let idx = match ifindex_get(raw) {
            n if n >= 0 => Some(n as u32),
            _ => None,
        };
        // retake ownership so we can free the memory
        let _c_name = CString::from_raw(raw);
        idx
    }
}

pub fn fini() {
    unsafe { netsupport_fini() };
}

pub fn init() -> anyhow::Result<()> {
    match unsafe { netsupport_init() } {
        0 => Ok(()),
        _ => Err(anyhow!("failed to initialize netsupport code")),
    }
}

#[cfg(test)]
mod tests {
    use super::get_dhcpv6;
    use super::get_ipaddrs;

    #[test]
    fn test_get_dhcpv6() {
        let all_addrs = get_ipaddrs().unwrap();
        let addrs = get_dhcpv6("net1").unwrap();

        assert_eq!(addrs.len(), 1);
        let addr = addrs[0];

        // We should have skipped the IPv4 address, the link-local, and the
        // simulated bootstrap address.
        assert_eq!(addr, all_addrs["net1"].last().as_ref().unwrap().addr);
    }
}
