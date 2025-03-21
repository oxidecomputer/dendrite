// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::ffi::CString;
use std::net::{IpAddr, Ipv6Addr};

use anyhow::anyhow;

extern "C" {
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
