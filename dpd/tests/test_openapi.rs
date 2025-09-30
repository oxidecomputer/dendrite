// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

#![allow(clippy::missing_safety_doc)]

// NOTE: This is a horrible hack that appears to be necessary.
//
// We use a mapfile in the tofino_sde repo to declare the QSFP management
// functions extern. Those are actually defined in
// `asic/src/tofino_asic/qsfp.rs`, and we link against the BF SDE when the
// `tofino_asic` feature is used. That all works fine.
//
// However, this is an integration test. It relies on the `dpd` binary existing,
// which is also fine, but it also appears to use the same build script as the
// `dpd` binary itself. Given that we want to test the OpenAPI document when the
// `tofino_asic` feature is enabled, that means we have all the link flags for
// linking against the BF SDE libraries, e.g., `libpltfm_mgr.so`. Since that no
// longer defines the QSFP functions, but we link against it, we get link
// failures when building this completely unrelated integration test binary.
//
// So we just define those functions here to panic. Nothing should call them
// ever under any circumstances.
//
// There are probably other hacks that work, but here's what does _not_ seem to
// work:
//
// - Putting this in its some other crate doesn't work because you can't depend
// on `dpd`, which is a binary-only crate. We could make `dpd` a library, but
// that's really not correct. - Putting this as a unit test in say
// `api_server.rs`. That doesn't work because those get run prior to the actual
// binary target being built. - Trying to generate an integration-test-only
// build script. This seems to have been a feature that was requested and
// abandoned a long time ago.

use libc::c_int;
use libc::c_uint;
use libc::c_void;

#[unsafe(no_mangle)]
pub extern "C" fn bf_pltfm_qsfp_init(_: *mut c_void) -> c_int {
    panic!();
}

#[unsafe(no_mangle)]
pub extern "C" fn bf_pltfm_detect_qsfp(_module: c_uint) -> bool {
    panic!();
}

#[unsafe(no_mangle)]
pub extern "C" fn bf_pltfm_qsfp_read_module(
    _module: c_uint,
    _offset: c_int,
    _len: c_int,
    _buf: *mut u8,
) -> c_int {
    panic!();
}

#[unsafe(no_mangle)]
pub extern "C" fn bf_pltfm_qsfp_write_module(
    _module: c_uint,
    _offset: c_int,
    _len: c_int,
    _buf: *mut u8,
) -> c_int {
    panic!();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bf_pltfm_qsfp_get_presence_mask(
    _port_1_32: *mut u32,
    _port_33_64: *mut u32,
    _cpu_port: *mut u32,
) -> c_int {
    panic!()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bf_pltfm_qsfp_get_int_mask(
    _port_1_32: *mut u32,
    _port_33_64: *mut u32,
    _cpu_port: *mut u32,
) -> c_int {
    panic!();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bf_pltfm_qsfp_get_lpmode_mask(
    _port_1_32: *mut u32,
    _port_33_64: *mut u32,
    _cpu_port: *mut u32,
) -> c_int {
    panic!()
}

#[unsafe(no_mangle)]
pub extern "C" fn bf_pltfm_qsfp_set_lpmode(
    _module: c_int,
    _lp_mode: bool,
) -> c_int {
    panic!();
}

#[unsafe(no_mangle)]
pub extern "C" fn bf_pltfm_qsfp_module_reset(
    _module: c_int,
    _reset: bool,
) -> c_int {
    panic!();
}
