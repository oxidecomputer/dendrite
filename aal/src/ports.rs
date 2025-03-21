// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::cmp::Ordering;
use std::convert::Into;

#[derive(Clone, Copy, Debug, PartialEq, Hash)]
pub struct PortHdl {
    pub connector: Connector,
    pub channel: u8,
}

impl PortHdl {
    pub fn new(connector: Connector, channel: u8) -> Self {
        PortHdl { connector, channel }
    }

    pub fn is_cpu(&self) -> bool {
        self.connector == Connector::CPU
    }

    pub fn qsfp_port(&self) -> Option<u16> {
        match self.connector {
            Connector::CPU => None,
            Connector::QSFP(port) => Some(port as u16),
        }
    }
}

impl From<&PortHdl> for u64 {
    fn from(hdl: &PortHdl) -> Self {
        let connector_field = match hdl.connector {
            Connector::CPU => 0xff,
            Connector::QSFP(port) => port,
        };

        ((connector_field as u64) << 8) | (hdl.channel as u64)
    }
}

impl From<PortHdl> for u64 {
    fn from(hdl: PortHdl) -> Self {
        (&hdl).into()
    }
}

impl From<&u64> for PortHdl {
    fn from(item: &u64) -> Self {
        let channel = (item & 0xff) as u8;
        let connector = match (item >> 8) & 0xff {
            0xff => Connector::CPU,
            x => Connector::QSFP(x as u32),
        };

        PortHdl { connector, channel }
    }
}

impl From<u64> for PortHdl {
    fn from(item: u64) -> Self {
        (&item).into()
    }
}

impl Ord for PortHdl {
    fn cmp(&self, other: &Self) -> Ordering {
        let a: u64 = self.into();
        let b: u64 = other.into();

        a.cmp(&b)
    }
}

impl PartialOrd for PortHdl {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PortHdl {}

impl std::fmt::Display for PortHdl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.connector {
            Connector::CPU => write!(f, "CPU"),
            Connector::QSFP(port) => write!(f, "{}:{}", port, self.channel),
        }
    }
}

impl std::str::FromStr for PortHdl {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = "invalid port name";

        let v: Vec<&str> = s.splitn(2, ':').collect();
        let (connector, channel) = match v.len() {
            1 => {
                if v[0] == "CPU" {
                    Ok((Connector::CPU, 0))
                } else {
                    Err(err)
                }
            }
            2 => {
                let port = v[0].parse::<u32>().map_err(|_| err)?;
                let channel = v[1].parse::<u8>().map_err(|_| err)?;
                Ok((Connector::QSFP(port), channel))
            }
            _ => Err(err),
        }?;
        Ok(PortHdl { connector, channel })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Connector {
    QSFP(u32),
    CPU,
}

impl std::fmt::Display for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Connector::QSFP(x) => write!(f, "QSFP({x})"),
            Connector::CPU => write!(f, "CPU"),
        }
    }
}

impl Connector {
    /// Return the Tofino SDE connector number as an integer.
    pub const fn as_u16(&self) -> u16 {
        match self {
            Connector::CPU => 0,
            Connector::QSFP(x) => *x as _,
        }
    }
}
