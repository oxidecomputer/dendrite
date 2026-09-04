use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::v13;
use crate::v15::LinkIpAddr;

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
    pub params: v13::link::LinkCreate,
    pub addrs: HashSet<LinkIpAddr>,
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
        Self {
            params: old.params,
            addrs: old
                .addrs
                .into_iter()
                .filter_map(|ip| LinkIpAddr::try_from(ip).ok())
                .collect(),
        }
    }
}

impl From<LinkSettings> for v13::port::LinkSettings {
    fn from(new: LinkSettings) -> Self {
        Self {
            params: new.params,
            addrs: new.addrs.into_iter().map(IpAddr::from).collect(),
        }
    }
}
