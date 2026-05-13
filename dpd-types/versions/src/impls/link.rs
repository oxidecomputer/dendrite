// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::{fmt, str::FromStr};

use crate::latest::fault::Fault;
use crate::latest::link::{LinkId, LinkState, LinkView};

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

impl FromStr for LinkId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u8>().map(LinkId)
    }
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

impl fmt::Display for LinkState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LinkState::Up => write!(f, "Up"),
            LinkState::Down => write!(f, "Down"),
            LinkState::ConfigError(_) => write!(f, "ConfigError"),
            LinkState::Faulted(_) => write!(f, "Faulted"),
            LinkState::Unknown => write!(f, "Unknown"),
        }
    }
}

impl fmt::Display for LinkView {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.port_id, self.link_id)
    }
}
