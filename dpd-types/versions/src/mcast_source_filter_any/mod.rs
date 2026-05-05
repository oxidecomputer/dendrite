// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `MCAST_SOURCE_FILTER_ANY` of the DPD API.
//!
//! Changed `IpSrc` from `{Exact, Subnet}` to `{Exact, Any}`. External
//! multicast types updated to use the new `IpSrc`.

pub mod mcast;
