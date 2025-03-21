// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

#![cfg(feature = "tofino_stub")]
#![allow(nonstandard_style)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::AsicError;
use crate::{BF_LAG_COUNT, BF_PORT_COUNT};

pub type BfCommon = bfw_common_t;

pub struct bfw_common_t {
    pub mcast_hdl: bf_mc_session_hdl_t,
}

pub type bf_status_t = ::std::os::raw::c_int;
pub type pipe_status_t = ::std::os::raw::c_int;

pub type bf_rt_id_t = u32;
pub type bf_dev_pipe_t = u32;
pub type bf_mc_port_map_t = [u8; 36usize];
pub type bf_mc_lag_map_t = [u8; 32usize];
pub type bf_mc_session_hdl_t = u32;
pub type bf_mc_mgrp_hdl_t = u32;
pub type bf_mc_node_hdl_t = u32;
pub type bf_dev_id_t = i32;

pub const BF_MC_PORT_ARRAY_SIZE: usize = (BF_PORT_COUNT as usize + 7) / 8;
pub const BF_MC_LAG_ARRAY_SIZE: usize = (BF_LAG_COUNT as usize + 7) / 8;

pub fn pipe_error_str(err: bf_status_t) -> String {
    format!("pipe error: {}", err)
}

pub fn bf_error_str(err: bf_status_t) -> String {
    format!("bf error: {}", err)
}

pub fn bf_init() -> Result<BfCommon, AsicError> {
    Ok(BfCommon { mcast_hdl: 0 })
}

pub fn bf_fini(_bf: &mut BfCommon) {}
