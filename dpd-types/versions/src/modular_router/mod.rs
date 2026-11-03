// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `MODULAR_ROUTER` of the DPD API.
//!
//! Adds routers, each with its own routes and endpoint, under
//! `/router/{router_id}/...`.  The `/route/...` endpoints act on the default
//! routing table.

pub mod route;
