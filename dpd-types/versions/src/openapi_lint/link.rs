// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;
use crate::v1::link::LinkId;
use crate::v1::network::MacAddr;
use crate::v1::port::{PortId, TxEq};
use crate::v12;
use crate::v13;

use super::fault::Fault;
use super::port::{PortFec, PortMedia, PortPrbsMode, PortSpeed};

/// The state of a data link with a peer.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum LinkState {
    /// An error was encountered while trying to configure the link in the
    /// switch hardware.
    ConfigError(String),
    /// The link is up.
    Up,
    /// The link is down.
    Down,
    /// The Link is offline due to a fault
    Faulted(Fault),
    /// The link's state is not known.
    Unknown,
}

impl std::fmt::Debug for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LinkState::Up => write!(f, "Up"),
            LinkState::Down => write!(f, "Down"),
            LinkState::ConfigError(detail) => {
                write!(f, "ConfigError - {detail:?}")
            }
            LinkState::Faulted(reason) => write!(f, "Faulted - {reason:?}"),
            LinkState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Parameters used to create a link on a switch port.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct LinkCreate {
    /// The first lane of the port to use for the new link
    pub lane: Option<LinkId>,
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
    /// This only applies to the qsfp front ports. Rear ports always have DDM
    /// enabled, regardless of this setting.
    ///
    /// The actual effect of this is to enable IPv6 routing on front ports and
    /// ensure they are not an uplink.
    ///
    /// This defaults to `false`.
    #[serde(default)]
    pub allow_ddm_traffic: bool,
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

impl From<LinkState> for v1::link::LinkState {
    fn from(new: LinkState) -> Self {
        match new {
            LinkState::ConfigError(detail) => Self::ConfigError(detail),
            LinkState::Up => Self::Up,
            LinkState::Down => Self::Down,
            LinkState::Faulted(fault) => Self::Faulted(fault.into()),
            LinkState::Unknown => Self::Unknown,
        }
    }
}

impl From<v13::link::LinkCreate> for LinkCreate {
    fn from(old: v13::link::LinkCreate) -> Self {
        Self {
            lane: old.lane,
            speed: old.speed.into(),
            fec: old.fec.map(Into::into),
            autoneg: old.autoneg,
            kr: old.kr,
            tx_eq: old.tx_eq,
            allow_ddm_traffic: old.allow_ddm_traffic,
        }
    }
}

impl From<LinkCreate> for v13::link::LinkCreate {
    fn from(new: LinkCreate) -> Self {
        Self {
            lane: new.lane,
            speed: new.speed.into(),
            fec: new.fec.map(Into::into),
            autoneg: new.autoneg,
            kr: new.kr,
            tx_eq: new.tx_eq,
            allow_ddm_traffic: new.allow_ddm_traffic,
        }
    }
}

impl From<LinkView> for v12::link::LinkView {
    fn from(new: LinkView) -> Self {
        Self {
            port_id: new.port_id,
            link_id: new.link_id,
            tofino_connector: new.tofino_connector,
            asic_id: new.asic_id,
            presence: new.presence,
            kr: new.kr,
            autoneg: new.autoneg,
            fsm_state: new.fsm_state,
            speed: new.speed.into(),
            fec: new.fec.map(Into::into),
            media: new.media.into(),
            enabled: new.enabled,
            prbs: new.prbs.into(),
            link_state: new.link_state.into(),
            address: new.address,
            ipv6_enabled: new.ipv6_enabled,
        }
    }
}
