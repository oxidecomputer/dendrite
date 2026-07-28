// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `ADDR_OWNERSHIP` of the DPD API.
//!
//! Addresses on a link are shared, refcounted resources that may be claimed
//! by multiple clients, each identified by a validated owner [`tag::Tag`].
//! Address list responses report the complete owner set for each address.
//! A claim is created idempotently with `PUT`, released for a single owner
//! via the address's `owner` subresource, and the address is removed from
//! the ASIC only when its last owner releases it; deleting the address
//! itself removes it regardless of ownership.  Port-settings transactions
//! name the owner they act for, and their diffs are scoped to that owner's
//! claims.

pub mod link;
pub mod tag;
