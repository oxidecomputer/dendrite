// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `MULTI_ROUTER` of the DPD API.
//!
//! Adds router-scoped route and loopback endpoints under
//! `/router/{router_id}/...`.  A `RouterId` selects one of the switch's
//! routing tables; table 0 is the default table, which all pre-multi-router
//! endpoints continue to operate on.

pub mod loopback;
pub mod route;
