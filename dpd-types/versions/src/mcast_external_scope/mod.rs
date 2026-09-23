// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `MCAST_EXTERNAL_SCOPE` of the DPD API.
//!
//! This version added validated external multicast address, source, and NAT
//! target types.
//! This migration changed `MulticastGroupCreateExternalEntry` from a struct to
//! an ASM/SSM enum disambiguated at deserialization, and modified the external
//! `group_ip` and `internal_forwarding` fields to the validated types.

pub mod mcast;
