// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::ports::{PortFec, PortId, PortSpeed};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::link::LinkCreate;

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

/// Parameter used to create a port.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct PortCreateParams {
    /// The name of the port. This should be a string like `"3:0"`.
    pub name: String,
    /// The speed at which to configure the port.
    pub speed: PortSpeed,
    /// The forward error-correction scheme for the port.
    pub fec: PortFec,
}

/// Represents the free MAC channels on a single physical port.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct FreeChannels {
    /// The switch port.
    pub port_id: PortId,
    /// The Tofino connector for this port.
    ///
    /// This describes the set of electrical connections representing this port
    /// object, which are defined by the pinout and board design of the Sidecar.
    pub connector: String,
    /// The set of available channels (lanes) on this connector.
    pub channels: Vec<u8>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortIdPathParams {
    /// The switch port on which to operate.
    pub port_id: PortId,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortSettingsTag {
    /// Restrict operations on this port to the provided tag.
    pub tag: Option<String>,
}

/**
 * Represents a cursor into a paginated request for all port data.  Because we
 * don't (yet) support filtering or arbitrary sorting, it is sufficient to
 * track the last port returned.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortToken {
    pub port: u16,
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

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortIpv4Path {
    pub port: String,
    pub ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortIpv6Path {
    pub port: String,
    pub ipv6: Ipv6Addr,
}
