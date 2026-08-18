// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;
use std::str::FromStr;

use crate::latest::port::{
    Ipv4Entry, Ipv6Entry, PortFec, PortMedia, PortPrbsMode, PortSpeed,
};

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

impl fmt::Display for PortPrbsMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortPrbsMode::Mode31 => write!(f, "31"),
            PortPrbsMode::Mode15 => write!(f, "15"),
            PortPrbsMode::Mode13 => write!(f, "13"),
            PortPrbsMode::Mode9 => write!(f, "9"),
            PortPrbsMode::Mission => write!(f, "Off"),
        }
    }
}

impl FromStr for PortPrbsMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mode31" | "31" => Ok(PortPrbsMode::Mode31),
            "mode13" | "13" => Ok(PortPrbsMode::Mode13),
            "mode15" | "15" => Ok(PortPrbsMode::Mode15),
            "mode9" | "9" => Ok(PortPrbsMode::Mode9),
            "off" | "none" | "mission" => Ok(PortPrbsMode::Mission),
            _ => Err("invalid prbs mode"),
        }
    }
}
