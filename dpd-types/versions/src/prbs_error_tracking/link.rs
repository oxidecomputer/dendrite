// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::{
    network::MacAddr,
    ports::{PortFec, PortId, PortMedia, PortPrbsMode, PortSpeed},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

// `MsDuration` lives alongside `LinkView` because it is the body type for the
// link-scoped PRBS bit-error measurement endpoint introduced in this version.

/// Duration in milliseconds
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MsDuration {
    /// Duration in milliseconds
    pub ms: u32,
}

/// An Ethernet-capable link within a switch port.
//
// NOTE: This is a view onto `dpd::link::Link`.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename = "Link")]
pub struct LinkView {
    /// The switch port on which this link exists.
    pub port_id: PortId,
    /// The `LinkId` within the switch port for this link.
    pub link_id: v1::link::LinkId,
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
    pub link_state: v1::link::LinkState,
    /// The MAC address for the link.
    pub address: MacAddr,
    /// The link is configured for IPv6 use
    pub ipv6_enabled: bool,
}

impl From<LinkView> for v1::link::LinkView {
    fn from(value: LinkView) -> Self {
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
