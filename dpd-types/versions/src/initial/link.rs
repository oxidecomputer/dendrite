// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{
    network::MacAddr,
    ports::{PortFec, PortId, PortMedia, PortSpeed, TxEq},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::fault::Fault;
use super::port::PortPrbsMode;

/// An identifier for a link within a switch port.
///
/// A switch port identified by a [`PortId`] may have multiple links within it,
/// each identified by a `LinkId`. These are unique within a switch port only.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct LinkId(pub u8);

/// The state of a data link with a peer.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
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

/// Reports how many times a link has transitioned from Down to Up.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct LinkUpCounter {
    /// Link being reported
    pub link_path: String,
    /// LinkUp transitions since the link was last enabled
    pub current: u32,
    /// LinkUp transitions since the link was created
    pub total: u32,
}

/// Reports how many times a given autoneg/link-training state has been entered
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct LinkFsmCounter {
    /// FSM state being counted
    pub state_name: String,
    /// Times entered since the link was last enabled
    pub current: u32,
    /// Times entered since the link was created
    pub total: u32,
}

/// Reports all the autoneg/link-training states a link has transitioned into.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct LinkFsmCounters {
    /// Link being reported
    pub link_path: String,
    /// All the states this link has entered, along with counts of how many
    /// times each state was entered.
    pub counters: Vec<LinkFsmCounter>,
}

/// Identifies a logical link on a physical port.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LinkPath {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LinkIpv4Path {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
    /// The IPv4 address on which to operate.
    pub address: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LinkIpv6Path {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
    /// The IPv6 address on which to operate.
    pub address: Ipv6Addr,
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
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct LinkFilter {
    /// Filter links to those whose name contains the provided string.
    ///
    /// If not provided, then all links are returned.
    pub filter: Option<String>,
}

// View types: public API representations of internal Dendrite data.

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

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkEvent {
    /// Time the event occurred.  The time is represented in milliseconds,
    /// starting at an undefined time in the past.  This means that timestamps
    /// can be used to measure the time between events, but not to determine the
    /// wall-clock time at which the event occurred.
    pub timestamp: i64,
    /// Channel ID for sub-link-level events
    pub channel: Option<u8>,
    /// Event class
    pub class: String,
    /// Event subclass
    pub subclass: String,
    /// Optionally, additional details about the event
    pub details: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkHistory {
    /// The timestamp in milliseconds at which this history was collected.
    pub timestamp: i64,
    /// The set of historical events recorded
    pub events: Vec<LinkEvent>,
}

/// The per-link data consumed by tfportd
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct TfportData {
    /// The switch port ID for this link.
    pub port_id: PortId,
    /// The link ID for this link.
    pub link_id: LinkId,
    /// The lower-level ASIC ID used to refer to this object in the switch
    /// driver software.
    pub asic_id: u16,
    /// The MAC address for the link.
    pub mac: MacAddr,
    /// Is ipv6 enabled for this link
    pub ipv6_enabled: bool,
    /// The IPv6 link-local address of the link, if it exists.
    pub link_local: Option<Ipv6Addr>,
}
