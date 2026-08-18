// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::link::LinkCreate;

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
#[serde(try_from = "String", into = "String")]
pub struct RearPort(pub(crate) u8);

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
#[serde(try_from = "String", into = "String")]
pub struct QsfpPort(pub(crate) u8);

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
#[serde(try_from = "String", into = "String")]
pub struct InternalPort(pub(crate) u8);

/// An identifier for a physical switch port.
#[derive(
    Copy,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(untagged, try_from = "String", into = "String")]
pub enum PortId {
    /// The CPU port on the Tofino (also called the AUX or Ethernet port).
    ///
    /// The CPU port is not connected to a SERDES, but instead goes through the
    /// attached PCIe link, where generally speaking the host CPU will be the
    /// peer (hence the name).
    Internal(InternalPort),

    /// A rear-facing switch port, connecting components within the rack to one
    /// another. This includes the connections on the cabled backplane.
    Rear(RearPort),

    /// A numbered QSFP port on the switch front panel.
    Qsfp(QsfpPort),
}

impl JsonSchema for PortId {
    fn schema_name() -> String {
        String::from("PortId")
    }

    fn json_schema(
        _: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        const QSFP_REGEX: &str =
            r#"(^[qQ][sS][fF][pP](([0-9])|([1-2][0-9])|(3[0-1]))$)"#;
        const REAR_REGEX: &str =
            r#"(^[rR][eE][aA][rR](([0-9])|([1-2][0-9])|(3[0-1]))$)"#;
        const INTERNAL_REGEX: &str = r#"(^[iI][nN][tT]0$)"#;

        schemars::schema::SchemaObject {
            metadata: Some(Box::new(schemars::schema::Metadata {
                title: Some("PortId".to_string()),
                description: Some(
                    "Physical switch port identifier".to_string(),
                ),
                examples: vec!["qsfp0".into()],
                ..Default::default()
            })),
            subschemas: Some(Box::new(schemars::schema::SubschemaValidation {
                one_of: Some(vec![
                    schemars::schema::SchemaObject {
                        metadata: Some(Box::new(schemars::schema::Metadata {
                            title: Some("internal".to_string()),

                            ..Default::default()
                        })),
                        instance_type: Some(
                            schemars::schema::InstanceType::String.into(),
                        ),
                        string: Some(Box::new(
                            schemars::schema::StringValidation {
                                pattern: Some(INTERNAL_REGEX.to_string()),
                                ..Default::default()
                            },
                        )),
                        ..Default::default()
                    }
                    .into(),
                    schemars::schema::SchemaObject {
                        metadata: Some(Box::new(schemars::schema::Metadata {
                            title: Some("rear".to_string()),

                            ..Default::default()
                        })),
                        instance_type: Some(
                            schemars::schema::InstanceType::String.into(),
                        ),
                        string: Some(Box::new(
                            schemars::schema::StringValidation {
                                pattern: Some(REAR_REGEX.to_string()),
                                ..Default::default()
                            },
                        )),
                        ..Default::default()
                    }
                    .into(),
                    schemars::schema::SchemaObject {
                        metadata: Some(Box::new(schemars::schema::Metadata {
                            title: Some("qsfp".to_string()),

                            ..Default::default()
                        })),
                        instance_type: Some(
                            schemars::schema::InstanceType::String.into(),
                        ),
                        string: Some(Box::new(
                            schemars::schema::StringValidation {
                                pattern: Some(QSFP_REGEX.to_string()),
                                ..Default::default()
                            },
                        )),
                        ..Default::default()
                    }
                    .into(),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

// Number of internal ports
pub const PORT_COUNT_INTERNAL: u8 = 1;
// Number of rear/backplane ports
pub const PORT_COUNT_REAR: u8 = 32;
// Number of front/qsfp ports
pub const PORT_COUNT_QSFP: u8 = 32;

macro_rules! impl_port_type {
    ($name:ident, $prefix:literal, $n_ports:ident) => {
        impl $name {
            pub fn new(index: u8) -> Result<Self, &'static str> {
                Self::try_from(index)
            }

            /// Return the inner value of `self`.
            pub const fn as_u8(&self) -> u8 {
                self.0
            }
        }

        impl TryFrom<u8> for $name {
            type Error = &'static str;

            fn try_from(index: u8) -> Result<Self, Self::Error> {
                if index < $n_ports {
                    Ok(Self(index))
                } else {
                    Err("Invalid port index")
                }
            }
        }

        impl std::str::FromStr for $name {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if !s.is_ascii() {
                    return Err("Port IDs must be ASCII");
                }
                let Some((head, tail)) = s.split_at_checked($prefix.len())
                else {
                    return Err("Invalid port kind");
                };
                if head.eq_ignore_ascii_case($prefix) {
                    tail.parse::<u8>()
                        .map_err(|_| "Invalid port index")
                        .and_then(Self::try_from)
                } else {
                    Err("Invalid port kind")
                }
            }
        }

        impl TryFrom<String> for $name {
            type Error = <Self as FromStr>::Err;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::try_from(s.as_str())
            }
        }

        impl TryFrom<&str> for $name {
            type Error = &'static str;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        impl From<$name> for String {
            fn from(n: $name) -> String {
                format!("{n}")
            }
        }
    };
}

impl_port_type!(RearPort, "rear", PORT_COUNT_REAR);
impl_port_type!(QsfpPort, "qsfp", PORT_COUNT_QSFP);
impl_port_type!(InternalPort, "int", PORT_COUNT_INTERNAL);

impl From<RearPort> for PortId {
    fn from(n: RearPort) -> PortId {
        PortId::Rear(n)
    }
}

impl From<QsfpPort> for PortId {
    fn from(n: QsfpPort) -> PortId {
        PortId::Qsfp(n)
    }
}

impl From<InternalPort> for PortId {
    fn from(n: InternalPort) -> PortId {
        PortId::Internal(n)
    }
}

impl PortId {
    /// Return the inner value of `self` as `u8`.
    pub const fn as_u8(&self) -> u8 {
        match self {
            PortId::Internal(p) => p.as_u8(),
            PortId::Rear(p) => p.as_u8(),
            PortId::Qsfp(p) => p.as_u8(),
        }
    }
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortId::Internal(inner) => write!(f, "{inner}"),
            PortId::Rear(inner) => write!(f, "{inner}"),
            PortId::Qsfp(inner) => write!(f, "{inner}"),
        }
    }
}

impl FromStr for PortId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(internal) = s.parse() {
            return Ok(PortId::Internal(internal));
        }
        if let Ok(rear) = s.parse() {
            return Ok(PortId::Rear(rear));
        }
        if let Ok(qsfp) = s.parse() {
            return Ok(PortId::Qsfp(qsfp));
        }
        if let Ok(internal) = s.parse() {
            return Ok(PortId::Internal(internal));
        }
        Err("Invalid switch port ID")
    }
}

impl TryFrom<String> for PortId {
    type Error = <Self as FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&str> for PortId {
    type Error = <Self as FromStr>::Err;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<PortId> for String {
    fn from(p: PortId) -> String {
        format!("{p}")
    }
}

/// An IPv6 address assigned to a link.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct Ipv6Entry {
    /// Client-side tag for this object.
    pub tag: String,
    /// The IP address.
    pub addr: Ipv6Addr,
}

/// An IPv4 address assigned to a link.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct Ipv4Entry {
    /// Client-side tag for this object.
    pub tag: String,
    /// The IP address.
    pub addr: Ipv4Addr,
}

#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
pub enum PortMedia {
    Copper,
    Optical,
    CPU,
    None,
    Unknown,
}

#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
pub enum PortFec {
    None,
    Firecode,
    RS,
}

/// Speeds with which a single port may be configured
#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
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

/// Parameters to adjust the transceiver equalization settings for a link on a
/// switch.  These parameters match those available on a tofino-based sidecar,
/// and may need to be adapted when we move to a new switch ASIC.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    JsonSchema,
)]
pub struct TxEq {
    pub pre1: Option<i32>,
    pub pre2: Option<i32>,
    pub main: Option<i32>,
    pub post2: Option<i32>,
    pub post1: Option<i32>,
}

/// This represents the software-determined equalization value initially
/// assigned to the transceiver and the value actually being used by the
/// hardware.  The values may differ on transceivers that are capable of tuning
/// their own settings at run time.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema,
)]
pub struct TxEqSwHw {
    pub sw: TxEq,
    pub hw: TxEq,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ids_are_ascii() {
        let e = PortId::try_from("abč0")
            .expect_err("Should have returned an error");
        assert_eq!(e.to_string(), "Invalid switch port ID");
    }
}
