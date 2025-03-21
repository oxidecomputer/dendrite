// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::ffi::{CStr, CString};
use std::fmt;
use std::sync::Mutex;

mod ffi;

pub enum HandleType {
    File,
    Interface,
}

pub struct Pcap {
    htype: HandleType,
    name: String,
    activated: bool,
    lib_hdl: *mut ffi::pcap,
    raw_fd: std::os::raw::c_int,
    lock: Mutex<()>,
}
unsafe impl Send for Pcap {}
unsafe impl Sync for Pcap {}

impl fmt::Debug for Pcap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            match self.htype {
                HandleType::Interface => "interface",
                HandleType::File => "file",
            },
            self.name
        )
    }
}

const PCAP_ERRBUF_SIZE: usize = 256;
const EMPTY_DATA: [u8; 0] = [];

pub enum Ternary<T, E> {
    None,
    Ok(T),
    Err(E),
}

impl Pcap {
    fn get_error(hdl: *mut ffi::pcap) -> String {
        unsafe {
            CStr::from_ptr(ffi::pcap_geterr(hdl))
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn activate(&mut self) -> Result<(), String> {
        let _lock = self.lock.lock();

        if self.activated {
            return Err("already activated".to_string());
        }

        if unsafe { ffi::pcap_activate(self.lib_hdl) } < 0 {
            return Err(Pcap::get_error(self.lib_hdl));
        }
        self.activated = true;

        unsafe {
            let mut err = [0i8; PCAP_ERRBUF_SIZE];
            let fd = ffi::pcap_get_selectable_fd(self.lib_hdl);
            if fd >= 0 {
                ffi::pcap_setnonblock(self.lib_hdl, 1, err.as_mut_ptr());
                self.raw_fd = fd;
            }
        }

        Ok(())
    }

    pub fn close(&self) {
        let _lock = self.lock.lock();
        if self.activated {
            /*
            if self.raw_fd >= 0 {
                let _ = nix::unistd::close(self.raw_fd);
            }
            */
            unsafe { ffi::pcap_close(self.lib_hdl) };
        }
    }

    pub fn breakloop(&self) {
        unsafe { ffi::pcap_breakloop(self.lib_hdl) };
    }

    // Built on top of pcap's "get next packet" call, this routine will block
    // until a packet arrives and will invoke the provided callback to process
    // it.
    pub fn dispatch<T: Copy>(
        &self,
        cnt: u32,
        callback: fn(&Pcap, &[u8], T),
        cookie: T,
    ) -> Result<(), String> {
        let mut packets = 0;
        loop {
            let mut hdr: *mut ffi::pcap_pkthdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null_mut();

            let _lock = self.lock.lock();
            if !self.activated {
                break;
            }
            let x =
                unsafe { ffi::pcap_next_ex(self.lib_hdl, &mut hdr, &mut data) };
            if x == -2 {
                // -2 means a clean shutdown
                break;
            }
            if x < 0 {
                // According to the man page, -1 is returned for all errors.
                // This turns out not be the case.
                return Err(Pcap::get_error(self.lib_hdl));
            }

            let packet;
            unsafe {
                let pkt_len = (*hdr).caplen as usize;
                packet = std::slice::from_raw_parts(data, pkt_len);
            }
            callback(self, packet, cookie);

            packets += 1;
            if cnt > 0 && packets >= cnt {
                break;
            }
        }
        Ok(())
    }

    fn fetch(&self) -> Ternary<&[u8], String> {
        let mut hdr: *mut ffi::pcap_pkthdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null_mut();

        let _lock = self.lock.lock();
        unsafe {
            match ffi::pcap_next_ex(self.lib_hdl, &mut hdr, &mut data) {
                -2 => Ternary::None,
                -1 => Ternary::Err(Pcap::get_error(self.lib_hdl)),
                0 => Ternary::Ok(&EMPTY_DATA),
                1 => {
                    let pkt_len = (*hdr).caplen as usize;
                    let s = std::slice::from_raw_parts(data, pkt_len);
                    Ternary::Ok(s)
                }
                x => Ternary::Err(format!("unexpected rval from pcap: {x}")),
            }
        }
    }

    // Block until a packet arrives
    pub fn next(&self) -> Ternary<&[u8], String> {
        // This loop is here because libpcap's timeout and breakloop mechanisms
        // don't seem all that reliable, and because closing the pcap handle
        // and/or file descriptor doesn't interrupt a blocked process.
        // Note: even this isn't sufficient to get a timely, clean shutdown on
        // all systems since even pcap_setnonblock() also doesn't seem reliable
        // everywhere.  Sigh.
        loop {
            if self.raw_fd >= 0 {
                let rval = unsafe { ffi::block_on(self.raw_fd, 100, 50000) };
                if rval < 0 {
                    return Ternary::Err(format!(
                        "unix error during poll: {rval}"
                    ));
                }
                let _lock = self.lock.lock();
                if !self.activated {
                    return Ternary::Err("pcap closed".to_string());
                }
            }

            match self.fetch() {
                Ternary::None => return Ternary::None,
                Ternary::Err(e) => return Ternary::Err(e),
                Ternary::Ok(data) => {
                    if !data.is_empty() {
                        return Ternary::Ok(data);
                    }
                }
            }
        }
    }

    pub fn next_owned(&self) -> Ternary<Vec<u8>, String> {
        match self.next() {
            Ternary::None => Ternary::None,
            Ternary::Err(e) => Ternary::Err(e),
            Ternary::Ok(data) => Ternary::Ok(data.to_vec()),
        }
    }

    // Send a single packet
    pub fn send(&self, packet: &[u8]) -> Result<(), String> {
        let _lock = self.lock.lock();
        if !self.activated {
            return Err("pcap not activated".to_string());
        }
        unsafe {
            let ptr = packet.as_ptr() as *const core::ffi::c_void;
            let len = packet.len();
            if ffi::pcap_inject(self.lib_hdl, ptr, len) < 0 {
                Err(Pcap::get_error(self.lib_hdl))
            } else {
                Ok(())
            }
        }
    }

    // Prior to activating the pcap handle, set the read timeout
    pub fn set_timeout(&self, ms: i32) -> Result<(), String> {
        let _lock = self.lock.lock();
        unsafe {
            if ffi::pcap_set_timeout(self.lib_hdl, ms) < 0 {
                Err(Pcap::get_error(self.lib_hdl))
            } else {
                Ok(())
            }
        }
    }

    // Pass a compiled BPF program to pcap to impose a filter on the packets
    // returned.
    pub fn set_filter(&self, fp: &mut ffi::bpf_program) -> Result<(), String> {
        match unsafe { ffi::pcap_setfilter(self.lib_hdl, fp) } {
            -1 => Err(Pcap::get_error(self.lib_hdl)),
            _ => Ok(()),
        }
    }

    // Compile a BPF filter/program from text to BPF code
    pub fn compile(
        &self,
        program: &str,
        netmask: u32,
    ) -> Result<ffi::bpf_program, String> {
        let mut bpf = ffi::bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };

        match unsafe {
            let arg = CString::new(program).expect("CString::new failed");
            ffi::pcap_compile(self.lib_hdl, &mut bpf, arg.as_ptr(), 0, netmask)
        } {
            -1 => Err(Pcap::get_error(self.lib_hdl)),
            _ => Ok(bpf),
        }
    }
}

/// Open a network interface for pcap access and return an opaque handle to the
/// caller, which will be used for all subsequent operations on the interface.
///
/// If the interface name is `None`, then the return `Pcap` will capture packets
/// from all interfaces.
pub fn create(iface: &Option<&str>) -> Result<Pcap, String> {
    // If we're provided an interface name, use it. Otherwise use `"any"` to
    // indicate we want to intercept packets from all interfaces.
    let iface_name = iface.unwrap_or_else(|| "any");
    let s = CString::new(iface_name).unwrap();
    let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

    unsafe {
        let lib_hdl = ffi::pcap_create(s.as_ptr(), errbuf.as_mut_ptr());
        if lib_hdl.is_null() {
            let msg = CStr::from_ptr(&errbuf as *const i8);
            return Err(msg.to_string_lossy().into_owned());
        }
        Ok(Pcap {
            htype: HandleType::Interface,
            name: iface_name.to_string(),
            activated: false,
            lib_hdl,
            raw_fd: -1,
            lock: Mutex::new(()),
        })
    }
}

// Open a file as a pcap source, and return an opaque handle to the caller.
pub fn open_offline(name: &str) -> Result<Pcap, String> {
    let filename = CString::new(name).unwrap();
    let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

    unsafe {
        let cap =
            ffi::pcap_open_offline(filename.as_ptr(), errbuf.as_mut_ptr());
        if cap.is_null() {
            let msg = CStr::from_ptr(&errbuf as *const i8);
            return Err(msg.to_string_lossy().into_owned());
        }
        Ok(Pcap {
            htype: HandleType::File,
            name: name.to_string(),
            activated: false,
            lib_hdl: cap,
            raw_fd: -1,
            lock: Mutex::new(()),
        })
    }
}

pub fn null() -> Pcap {
    Pcap {
        htype: HandleType::File,
        name: String::new(),
        activated: false,
        lib_hdl: std::ptr::null_mut(),
        raw_fd: -1,
        lock: Mutex::new(()),
    }
}
