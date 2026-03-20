// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Types from API version 10 (ASIC_DETAILS) that changed in
//! version 11 (PRBS_IMPROVEMENT).
//!
//! Dropped API support for PRBS modes not supported by the Tofino ASIC.

use std::convert::TryFrom;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use common::network::MacAddr;
use common::ports::{PortFec, PortId, PortMedia, PortSpeed};
use dpd_types::link::{LinkId, LinkState};

/// Legal PRBS modes
#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
pub enum PortPrbsMode {
    Mode31,
    Mode23,
    Mode15,
    Mode13,
    Mode11,
    Mode9,
    Mode7,
    Mission, // i.e. PRBS disabled
}

impl TryFrom<PortPrbsMode> for common::ports::PortPrbsMode {
    type Error = String;

    fn try_from(x: PortPrbsMode) -> Result<Self, Self::Error> {
        match x {
            PortPrbsMode::Mode9 => Ok(common::ports::PortPrbsMode::Mode9),
            PortPrbsMode::Mode13 => Ok(common::ports::PortPrbsMode::Mode13),
            PortPrbsMode::Mode15 => Ok(common::ports::PortPrbsMode::Mode15),
            PortPrbsMode::Mode31 => Ok(common::ports::PortPrbsMode::Mode31),
            PortPrbsMode::Mission => Ok(common::ports::PortPrbsMode::Mission),
            x => Err(format!("{x:?} is not a supported PRBS mode")),
        }
    }
}

impl From<common::ports::PortPrbsMode> for PortPrbsMode {
    fn from(x: common::ports::PortPrbsMode) -> Self {
        match x {
            common::ports::PortPrbsMode::Mode9 => PortPrbsMode::Mode9,
            common::ports::PortPrbsMode::Mode13 => PortPrbsMode::Mode13,
            common::ports::PortPrbsMode::Mode15 => PortPrbsMode::Mode15,
            common::ports::PortPrbsMode::Mode31 => PortPrbsMode::Mode31,
            common::ports::PortPrbsMode::Mission => PortPrbsMode::Mission,
        }
    }
}

/// An Ethernet-capable link within a switch port.
//
// NOTE: This is a view onto `crate::link::Link`.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct Link {
    /// The switch port on which this link exists.
    pub port_id: PortId,
    /// The `LinkId` within the switch port for this link.
    pub link_id: LinkId,
    /// The Tofino connector number associated with this link.
    pub tofino_connector: u16,
    /// The lower-level ASIC ID used to refer to this object in the switch
    /// driver software.
    pub asic_id: u16,
    /// True if the transceiver module has detected a media presence.
    pub presence: bool,
    /// True if this link is in KR mode, i.e., is on a cabled backplane.
    pub kr: bool,
    /// True if this link is configured to autonegotiate with its peer.
    pub autoneg: bool,
    /// Current state in the autonegotiation/link-training finite state machine
    pub fsm_state: String,
    /// The speed of the link.
    pub speed: PortSpeed,
    /// The error-correction scheme for this link.
    pub fec: Option<PortFec>,
    /// The physical media underlying this link.
    pub media: PortMedia,
    /// True if this link is enabled.
    pub enabled: bool,
    /// The PRBS mode.
    pub prbs: PortPrbsMode,
    /// The state of the Ethernet link.
    pub link_state: LinkState,
    /// The MAC address for the link.
    pub address: MacAddr,
    /// The link is configured for IPv6 use
    pub ipv6_enabled: bool,
}

impl From<dpd_types::views::Link> for Link {
    fn from(value: dpd_types::views::Link) -> Self {
        Self {
            port_id: value.port_id,
            link_id: value.link_id,
            tofino_connector: value.tofino_connector,
            asic_id: value.asic_id,
            presence: value.presence,
            kr: value.kr,
            autoneg: value.autoneg,
            fsm_state: value.fsm_state,
            speed: value.speed,
            fec: value.fec,
            media: value.media,
            enabled: value.enabled,
            prbs: value.prbs.into(),
            link_state: value.link_state,
            address: value.address,
            ipv6_enabled: value.ipv6_enabled,
        }
    }
}
