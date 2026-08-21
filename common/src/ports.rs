// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::network::MacAddr;

pub use dpd_types::port::{
    InternalPort, Ipv4Entry, Ipv6Entry, PORT_COUNT_INTERNAL, PORT_COUNT_QSFP,
    PORT_COUNT_REAR, PortFec, PortId, PortMedia, PortPrbsMode, PortSpeed,
    QsfpPort, RearPort, TxEq, TxEqConfig, TxEqSwHw,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
pub struct PortSpeedFec {
    pub speed: PortSpeed,
    pub fec: PortFec,
}

/** Represents the state of a configured port */
#[derive(Debug)]
pub struct PortData {
    pub port: u16,
    pub name: String,
    pub updated: i64,
    pub speed: PortSpeed,
    pub fec: PortFec,
    pub media: PortMedia,
    pub enabled: bool,
    pub kr: bool,
    pub autoneg: bool,
    pub prbs: PortPrbsMode,
    pub link_up: bool,
    pub ipv4: Vec<Ipv4Entry>,
    pub ipv6: Vec<Ipv6Entry>,
    pub mac: MacAddr,
}

/// Default transceiver settings
#[derive(Clone, Default, Debug, Deserialize, Serialize, JsonSchema)]
pub struct XcvrSettings {
    /// FEC setting
    pub fec: Option<PortFec>,
    /// Equalization settings
    pub tx_eq: TxEqConfig,
}
