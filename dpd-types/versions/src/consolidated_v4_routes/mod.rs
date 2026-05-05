// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `CONSOLIDATED_V4_ROUTES` of the DPD API.
//!
//! Changed `Ipv4RouteUpdate` to accept `RouteTarget` (IPv4 or IPv6) instead of
//! just `Ipv4Route`, and changed `RouteTargetIpv4Path` to use `IpAddr` for
//! `tgt_ip` instead of `Ipv4Addr`.

pub mod route;
