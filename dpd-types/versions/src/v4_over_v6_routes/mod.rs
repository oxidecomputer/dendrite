// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `V4_OVER_V6_ROUTES` of the DPD API.
//!
//! Added `Route` enum (V4/V6) and `RouteTarget`, changed `Ipv4Routes` to use
//! `Vec<Route>` instead of `Vec<Ipv4Route>`, and added `Ipv4OverIpv6RouteUpdate`.

pub mod route;
