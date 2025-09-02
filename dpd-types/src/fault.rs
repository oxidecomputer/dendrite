// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A Fault represents a specific kind of failure, and carries some additional
/// context.  Currently Faults are only used to describe Link failures, but
/// there is no reason they couldn't be used elsewhere.
#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum Fault {
    LinkFlap(String),
    Autoneg(String),
    Injected(String),
}
