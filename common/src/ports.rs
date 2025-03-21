// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::network::MacAddr;

// Number of internal ports
pub const PORT_COUNT_INTERNAL: u8 = 1;
// Number of rear/backplane ports
pub const PORT_COUNT_REAR: u8 = 32;
// Number of front/qsfp ports
pub const PORT_COUNT_QSFP: u8 = 32;

// Helper macro to make newtypes for the various kinds of switch ports we
// support. The macro looks like:
//
// ```
// make_port_type!(NewtypeName, "prefix_string", n_ports);
// ```
//
// For example, this invocation:
//
// ```
// make_port_type!(QsfpPort, "qsfp", 32)
// ```
//
// creates a type like:
//
// ```
// pub struct QsfpPort(u8);
// ```
//
// where that includes a `FromStr` impl that matches strings like `qsfpX`, with
// the constraint that `X` is between 0 and 31. It also checks that limit in the
// constructor as well.
macro_rules! make_port_type {
    ($name:ident, $prefix:literal, $n_ports:ident) => {
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
        pub struct $name(pub(crate) u8);

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
                if s.len() <= $prefix.len() {
                    return Err("Invalid port kind");
                }
                let (head, tail) = s.split_at($prefix.len());
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

make_port_type!(RearPort, "rear", PORT_COUNT_REAR);
make_port_type!(QsfpPort, "qsfp", PORT_COUNT_QSFP);
make_port_type!(InternalPort, "int", PORT_COUNT_INTERNAL);

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

impl JsonSchema for PortId {
    fn schema_name() -> String {
        String::from("PortId")
    }

    fn json_schema(
        _: &mut schemars::gen::SchemaGenerator,
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

/// An IPv6 address assigned to a link.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct Ipv6Entry {
    /// Client-side tag for this object.
    pub tag: String,
    /// The IP address.
    pub addr: Ipv6Addr,
}

impl PartialEq for Ipv6Entry {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl PartialOrd for Ipv6Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ipv6Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.addr.cmp(&other.addr)
    }
}

impl Eq for Ipv6Entry {}

/// An IPv4 address assigned to a link.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct Ipv4Entry {
    /// Client-side tag for this object.
    pub tag: String,
    /// The IP address.
    pub addr: Ipv4Addr,
}

impl PartialEq for Ipv4Entry {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl PartialOrd for Ipv4Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ipv4Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.addr.cmp(&other.addr)
    }
}

impl Eq for Ipv4Entry {}

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

impl fmt::Display for PortMedia {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortMedia::Copper => write!(f, "Copper"),
            PortMedia::Optical => write!(f, "Optical"),
            PortMedia::CPU => write!(f, "CPU"),
            PortMedia::None => write!(f, "None"),
            PortMedia::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(
    Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize, JsonSchema,
)]
pub enum PortFec {
    None,
    Firecode,
    RS,
}

impl FromStr for PortFec {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(PortFec::None),
            "fc" | "firecode" => Ok(PortFec::Firecode),
            "rs" => Ok(PortFec::RS),
            _ => Err("invalid fec"),
        }
    }
}

impl fmt::Display for PortFec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortFec::None => write!(f, "None"),
            PortFec::Firecode => write!(f, "FC"),
            PortFec::RS => write!(f, "RS"),
        }
    }
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

impl fmt::Display for PortSpeed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortSpeed::Speed0G => write!(f, "None"),
            PortSpeed::Speed1G => write!(f, "1G"),
            PortSpeed::Speed10G => write!(f, "10G"),
            PortSpeed::Speed25G => write!(f, "25G"),
            PortSpeed::Speed40G => write!(f, "40G"),
            PortSpeed::Speed50G => write!(f, "50G"),
            PortSpeed::Speed100G => write!(f, "100G"),
            PortSpeed::Speed200G => write!(f, "200G"),
            PortSpeed::Speed400G => write!(f, "400G"),
        }
    }
}

impl FromStr for PortSpeed {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "0g" => Ok(PortSpeed::Speed0G),
            "1g" => Ok(PortSpeed::Speed1G),
            "10g" => Ok(PortSpeed::Speed10G),
            "25g" => Ok(PortSpeed::Speed25G),
            "40g" => Ok(PortSpeed::Speed40G),
            "50g" => Ok(PortSpeed::Speed50G),
            "100g" => Ok(PortSpeed::Speed100G),
            "200g" => Ok(PortSpeed::Speed200G),
            "400g" => Ok(PortSpeed::Speed400G),
            _ => Err("invalid speed"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
pub struct PortSpeedFec {
    pub speed: PortSpeed,
    pub fec: PortFec,
}

/// Legal PRBS modes
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

impl fmt::Display for PortPrbsMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortPrbsMode::Mode31 => write!(f, "31"),
            PortPrbsMode::Mode23 => write!(f, "23"),
            PortPrbsMode::Mode15 => write!(f, "15"),
            PortPrbsMode::Mode13 => write!(f, "13"),
            PortPrbsMode::Mode11 => write!(f, "11"),
            PortPrbsMode::Mode9 => write!(f, "9"),
            PortPrbsMode::Mode7 => write!(f, "7"),
            PortPrbsMode::Mission => write!(f, "Off"),
        }
    }
}

impl FromStr for PortPrbsMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "Mode31" | "mode31" | "31" => Ok(PortPrbsMode::Mode31),
            "Mode23" | "mode23" | "23" => Ok(PortPrbsMode::Mode23),
            "Mode15" | "mode15" | "15" => Ok(PortPrbsMode::Mode15),
            "Mode11" | "mode11" | "11" => Ok(PortPrbsMode::Mode11),
            "Mode9" | "mode9" | "9" => Ok(PortPrbsMode::Mode9),
            "Mode7" | "mode7" | "7" => Ok(PortPrbsMode::Mode7),
            "off" | "none" | "mission" => Ok(PortPrbsMode::Mission),
            _ => Err("invalid prbs mode"),
        }
    }
}

/** Represents the state of a configured port */
#[derive(Debug)]
pub struct PortData {
    pub port: u16,
    pub name: String,
    pub updated: i64,
    pub speed: PortSpeed,
    pub fec: PortFec,
    pub media: PortMedia,
    pub enabled: bool,
    pub kr: bool,
    pub autoneg: bool,
    pub prbs: PortPrbsMode,
    pub link_up: bool,
    pub ipv4: Vec<Ipv4Entry>,
    pub ipv6: Vec<Ipv6Entry>,
    pub mac: MacAddr,
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

/// Default transceiver settings
#[derive(Clone, Default, Debug, Deserialize, Serialize, JsonSchema)]
pub struct XcvrSettings {
    /// FEC setting
    pub fec: Option<PortFec>,
    /// Equalization settings
    pub tx_eq: Option<TxEq>,
}
