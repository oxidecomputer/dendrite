// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `NAT_TAGGED_APPLY` of the DPD API.
//!
//! Adds a tag on NAT entries, an endpoint for declaratively applying the
//! complete set of NAT entries for a tag, and endpoints for listing the
//! entries carrying a tag.

pub mod nat;
