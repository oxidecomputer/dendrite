// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Public API view types, exposing the internal Dendrite data in a manner
//! suitable for API clients.

use std::{collections::BTreeMap, net::Ipv6Addr};

use common::{
    network::MacAddr,
    ports::{PortFec, PortId, PortMedia, PortPrbsMode, PortSpeed},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    link::{LinkId, LinkState},
    transceivers::QsfpDevice,
};

/// A physical port on the Sidecar switch.
//
// NOTE: This is the public API view onto `types::SwitchPort`.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct SwitchPort {
    /// The identifier for the switch port.
    pub port_id: PortId,
    /// Information for QSFP port functionality. This will be empty for non-QSFP
    /// switch ports.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub qsfp_device: Option<QsfpDevice>,
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

impl std::fmt::Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.port_id, self.link_id)
    }
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

/// Each entry in a P4 table is addressed by matching against a set of key
/// values.  If an entry is found, an action is taken with an action-specific
/// set of arguments.
///
/// Note: each entry will have the same key fields and each instance of any
/// given action will have the same argument names, so a vector of TableEntry
/// structs will contain a signficant amount of redundant data.  We could
/// consider tightening this up by including a schema of sorts in the "struct
/// Table".
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TableEntry {
    /// Names and values of each of the key fields.
    pub keys: BTreeMap<String, String>,
    /// Name of the action to take on a match
    pub action: String,
    /// Names and values for the arguments to the action implementation.
    pub action_args: BTreeMap<String, String>,
}

impl TableEntry {
    pub fn new(
        key: impl aal::MatchParse,
        action: impl aal::ActionParse,
    ) -> Self {
        TableEntry {
            keys: key.key_values(),
            action: action.action_name(),
            action_args: action.action_args(),
        }
    }
}

/// Represents the contents of a P4 table
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Table {
    /// A user-friendly name for the table
    pub name: String,
    /// The maximum number of entries the table can hold
    pub size: usize,
    /// There will be an entry for each populated slot in the table
    pub entries: Vec<TableEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TableCounterEntry {
    /// Names and values of each of the key fields.
    pub keys: BTreeMap<String, String>,
    /// Counter values
    pub data: aal::CounterData,
}

impl TableCounterEntry {
    pub fn new(key: impl aal::MatchParse, data: aal::CounterData) -> Self {
        TableCounterEntry { keys: key.key_values(), data }
    }
}
