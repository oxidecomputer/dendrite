// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Version `SNAPSHOT` of the DPD API.
//!
//! Added PHV snapshot capture and scope-checking endpoints with
//! `SnapshotDirection`, `SnapshotTrigger`, `SnapshotCreate`, `SnapshotResult`,
//! and related types. Also added `TableDumpOptions`.

pub mod snapshot;
