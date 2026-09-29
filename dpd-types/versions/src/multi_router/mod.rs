// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `MULTI_ROUTER` of the DPD API.
//!
//! Adds routers, identified by the control plane's uuid, and router-scoped
//! route and loopback endpoints under `/router/{router_id}/...`.  A router
//! must be created before it is used.  The default router has the nil uuid,
//! always exists, and is the one all pre-multi-router endpoints operate on.

pub mod loopback;
pub mod route;
