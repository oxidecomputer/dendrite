// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::ports::{PortFec, PortSpeed, TxEq};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

/// Parameters used to create a link on a switch port.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct LinkCreate {
    /// The first lane of the port to use for the new link
    pub lane: Option<v1::link::LinkId>,
    /// The requested speed of the link.
    pub speed: PortSpeed,
    /// The requested forward-error correction method.  If this is None, the
    /// standard FEC for the underlying media will be applied if it can be
    /// determined.
    pub fec: Option<PortFec>,
    /// Whether the link is configured to autonegotiate with its peer during
    /// link training.
    ///
    /// This is generally only true for backplane links, and defaults to
    /// `false`.
    #[serde(default)]
    pub autoneg: bool,
    /// Whether the link is configured in KR mode, an electrical specification
    /// generally only true for backplane link.
    ///
    /// This defaults to `false`.
    #[serde(default)]
    pub kr: bool,

    /// Transceiver equalization adjustment parameters.
    /// This defaults to `None`.
    #[serde(default)]
    pub tx_eq: Option<TxEq>,

    /// Whether DDM traffic is allowed on this link.
    ///
    /// This defaults to `false`.
    #[serde(default)]
    pub allow_ddm_traffic: bool,
}

impl From<v1::link::LinkCreate> for LinkCreate {
    fn from(old: v1::link::LinkCreate) -> Self {
        Self {
            lane: old.lane,
            speed: old.speed,
            fec: old.fec,
            autoneg: old.autoneg,
            kr: old.kr,
            tx_eq: old.tx_eq,
            allow_ddm_traffic: false,
        }
    }
}

impl From<LinkCreate> for v1::link::LinkCreate {
    fn from(new: LinkCreate) -> Self {
        Self {
            lane: new.lane,
            speed: new.speed,
            fec: new.fec,
            autoneg: new.autoneg,
            kr: new.kr,
            tx_eq: new.tx_eq,
        }
    }
}
