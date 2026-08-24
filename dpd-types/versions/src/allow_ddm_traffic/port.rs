// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

use super::link::LinkCreate;

/// A port settings transaction object. When posted to the
/// `/port-settings/{port_id}` API endpoint, these settings will be applied
/// holistically, and to the extent possible atomically to a given port.
#[derive(Default, Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct PortSettings {
    /// The link settings to apply to the port on a per-link basis. Any links
    /// not in this map that are resident on the switch port will be removed.
    /// Any links that are in this map that are not resident on the switch port
    /// will be added. Any links that are resident on the switch port and in
    /// this map, and are different, will be modified. Links are indexed by
    /// spatial index within the port.
    pub links: HashMap<u8, LinkSettings>,
}

/// An object with link settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkSettings {
    pub params: LinkCreate,
    pub addrs: HashSet<IpAddr>,
}

impl From<v1::port::PortSettings> for PortSettings {
    fn from(old: v1::port::PortSettings) -> Self {
        Self {
            links: old
                .links
                .into_iter()
                .map(|(index, settings)| (index, settings.into()))
                .collect(),
        }
    }
}

impl From<PortSettings> for v1::port::PortSettings {
    fn from(new: PortSettings) -> Self {
        Self {
            links: new
                .links
                .into_iter()
                .map(|(index, settings)| (index, settings.into()))
                .collect(),
        }
    }
}

impl From<v1::port::LinkSettings> for LinkSettings {
    fn from(old: v1::port::LinkSettings) -> Self {
        Self { params: old.params.into(), addrs: old.addrs }
    }
}

impl From<LinkSettings> for v1::port::LinkSettings {
    fn from(new: LinkSettings) -> Self {
        Self { params: new.params.into(), addrs: new.addrs }
    }
}
