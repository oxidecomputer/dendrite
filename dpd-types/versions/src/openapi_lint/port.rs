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
use crate::v12;
use crate::v13;

use super::link::LinkCreate;

#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PortMedia {
    Copper,
    Optical,
    #[serde(rename = "cpu")]
    CPU,
    None,
    Unknown,
}

#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PortFec {
    None,
    Firecode,
    #[serde(rename = "rs")]
    RS,
}

/// Speeds with which a single port may be configured
#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PortSpeed {
    Speed0G,
    Speed1G,
    Speed10G,
    Speed25G,
    Speed40G,
    Speed50G,
    Speed100G,
    Speed200G,
    Speed400G,
}

/// Legal PRBS modes
#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PortPrbsMode {
    Mode31,
    Mode15,
    Mode13,
    Mode9,
    Mission, // i.e. PRBS disabled
}

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

impl From<PortMedia> for v1::port::PortMedia {
    fn from(new: PortMedia) -> Self {
        match new {
            PortMedia::Copper => Self::Copper,
            PortMedia::Optical => Self::Optical,
            PortMedia::CPU => Self::CPU,
            PortMedia::None => Self::None,
            PortMedia::Unknown => Self::Unknown,
        }
    }
}

impl From<v1::port::PortFec> for PortFec {
    fn from(old: v1::port::PortFec) -> Self {
        match old {
            v1::port::PortFec::None => Self::None,
            v1::port::PortFec::Firecode => Self::Firecode,
            v1::port::PortFec::RS => Self::RS,
        }
    }
}

impl From<PortFec> for v1::port::PortFec {
    fn from(new: PortFec) -> Self {
        match new {
            PortFec::None => Self::None,
            PortFec::Firecode => Self::Firecode,
            PortFec::RS => Self::RS,
        }
    }
}

impl From<v1::port::PortSpeed> for PortSpeed {
    fn from(old: v1::port::PortSpeed) -> Self {
        match old {
            v1::port::PortSpeed::Speed0G => Self::Speed0G,
            v1::port::PortSpeed::Speed1G => Self::Speed1G,
            v1::port::PortSpeed::Speed10G => Self::Speed10G,
            v1::port::PortSpeed::Speed25G => Self::Speed25G,
            v1::port::PortSpeed::Speed40G => Self::Speed40G,
            v1::port::PortSpeed::Speed50G => Self::Speed50G,
            v1::port::PortSpeed::Speed100G => Self::Speed100G,
            v1::port::PortSpeed::Speed200G => Self::Speed200G,
            v1::port::PortSpeed::Speed400G => Self::Speed400G,
        }
    }
}

impl From<PortSpeed> for v1::port::PortSpeed {
    fn from(new: PortSpeed) -> Self {
        match new {
            PortSpeed::Speed0G => Self::Speed0G,
            PortSpeed::Speed1G => Self::Speed1G,
            PortSpeed::Speed10G => Self::Speed10G,
            PortSpeed::Speed25G => Self::Speed25G,
            PortSpeed::Speed40G => Self::Speed40G,
            PortSpeed::Speed50G => Self::Speed50G,
            PortSpeed::Speed100G => Self::Speed100G,
            PortSpeed::Speed200G => Self::Speed200G,
            PortSpeed::Speed400G => Self::Speed400G,
        }
    }
}

impl From<v12::port::PortPrbsMode> for PortPrbsMode {
    fn from(old: v12::port::PortPrbsMode) -> Self {
        match old {
            v12::port::PortPrbsMode::Mode31 => Self::Mode31,
            v12::port::PortPrbsMode::Mode15 => Self::Mode15,
            v12::port::PortPrbsMode::Mode13 => Self::Mode13,
            v12::port::PortPrbsMode::Mode9 => Self::Mode9,
            v12::port::PortPrbsMode::Mission => Self::Mission,
        }
    }
}

impl From<PortPrbsMode> for v12::port::PortPrbsMode {
    fn from(new: PortPrbsMode) -> Self {
        match new {
            PortPrbsMode::Mode31 => Self::Mode31,
            PortPrbsMode::Mode15 => Self::Mode15,
            PortPrbsMode::Mode13 => Self::Mode13,
            PortPrbsMode::Mode9 => Self::Mode9,
            PortPrbsMode::Mission => Self::Mission,
        }
    }
}

impl From<v13::port::PortSettings> for PortSettings {
    fn from(old: v13::port::PortSettings) -> Self {
        Self {
            links: old
                .links
                .into_iter()
                .map(|(index, settings)| (index, settings.into()))
                .collect(),
        }
    }
}

impl From<PortSettings> for v13::port::PortSettings {
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

impl From<v13::port::LinkSettings> for LinkSettings {
    fn from(old: v13::port::LinkSettings) -> Self {
        Self { params: old.params.into(), addrs: old.addrs }
    }
}

impl From<LinkSettings> for v13::port::LinkSettings {
    fn from(new: LinkSettings) -> Self {
        Self { params: new.params.into(), addrs: new.addrs }
    }
}
