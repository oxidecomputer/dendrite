// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `INITIAL` of the DPD API.
//!
//! This is the first version of the API. All types first published in v1 live
//! here.

pub mod arp;
pub mod counters;
pub mod fault;
pub mod link;
pub mod loopback;
pub mod mcast;
pub mod misc;
pub mod nat;
pub mod port;
pub mod port_map;
pub mod route;
pub mod serdes;
pub mod switch_identifiers;
pub mod switch_port;
pub mod table;
pub mod transceivers;
