// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `PRBS_ERROR_TRACKING` of the DPD API.
//!
//! Dropped support for PRBS modes not producible by the Tofino ASIC, which
//! changes the published `LinkView` type; added an endpoint for measuring the
//! PRBS bit-error rate with a `MsDuration` body.

pub mod link;
pub mod port;
