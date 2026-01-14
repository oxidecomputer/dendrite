// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::fault::Fault;

/// An identifier for a link within a switch port.
///
/// A switch port identified by a [`PortId`] may have multiple links within it,
/// each identified by a `LinkId`. These are unique within a switch port only.
///
/// [`PortId`]: common::ports::PortId
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

impl From<LinkId> for u8 {
    fn from(l: LinkId) -> Self {
        l.0
    }
}

impl From<LinkId> for u16 {
    fn from(l: LinkId) -> Self {
        l.0 as u16
    }
}

impl From<u8> for LinkId {
    fn from(x: u8) -> Self {
        Self(x)
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

impl LinkState {
    /// A shortcut to tell whether a LinkState is Faulted or not, allowing for
    /// cleaner code in the callers.
    pub fn is_fault(&self) -> bool {
        matches!(self, LinkState::Faulted(_))
    }

    /// If the link is in a faulted state, return the Fault.  If not, return
    /// None.
    pub fn get_fault(&self) -> Option<Fault> {
        match self {
            LinkState::Faulted(f) => Some(f.clone()),
            _ => None,
        }
    }
}

impl std::fmt::Display for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LinkState::Up => write!(f, "Up"),
            LinkState::Down => write!(f, "Down"),
            LinkState::ConfigError(_) => write!(f, "ConfigError"),
            LinkState::Faulted(_) => write!(f, "Faulted"),
            LinkState::Unknown => write!(f, "Unknown"),
        }
    }
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
