// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `MCAST_STRICT_UNDERLAY` of the DPD API.
//!
//! Introduced `UnderlayMulticastIpv6` (ff04::/64 validation), `MulticastTag`,
//! `MulticastGroupTagQuery`, and `MulticastTagPath`. Changed underlay multicast
//! types to use `UnderlayMulticastIpv6` instead of `AdminScopedIpv6`, and
//! changed response `tag` fields from `Option<String>` to `String`.

pub mod mcast;
