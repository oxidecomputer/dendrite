// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::net::Ipv4Net;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::network::MacAddr;

/** represents an external subnet mapping */
pub(crate) struct ExtSubnetEntry {
    pub subnet: Ipv4Net,
    pub tgt: Interl,
}
