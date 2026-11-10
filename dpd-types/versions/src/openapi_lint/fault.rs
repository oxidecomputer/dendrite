// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

/// A Fault represents a specific kind of failure, and carries some additional
/// context.  Currently Faults are only used to describe Link failures, but
/// there is no reason they couldn't be used elsewhere.
#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    LinkFlap(String),
    Autoneg(String),
    Injected(String),
}

/**
 * Represents a potential fault condtion on a link
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct FaultCondition {
    pub fault: Option<Fault>,
}

impl From<Fault> for v1::fault::Fault {
    fn from(new: Fault) -> Self {
        match new {
            Fault::LinkFlap(detail) => Self::LinkFlap(detail),
            Fault::Autoneg(detail) => Self::Autoneg(detail),
            Fault::Injected(detail) => Self::Injected(detail),
        }
    }
}

impl From<FaultCondition> for v1::fault::FaultCondition {
    fn from(new: FaultCondition) -> Self {
        Self { fault: new.fault.map(Into::into) }
    }
}
