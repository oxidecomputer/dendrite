// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `ALLOW_DDM_TRAFFIC` of the DPD API.
//!
//! Added an `allow_ddm_traffic` field to `LinkCreate`. `LinkSettings` and
//! `PortSettings` are updated to carry the new `LinkCreate`.

pub mod link;
pub mod port;
