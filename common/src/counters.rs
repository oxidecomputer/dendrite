// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

pub use dpd_types::counters::{
    FecRSCounters, PcsCounters, RMonCounters, RMonCountersAll,
};

/// sidecar.p4 defines the following set of indirect counters.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum CounterId {
    Service,
    Ingress,
    Egress,
    Packet,
    DropPort,
    DropReason,
    EgressPipeline(EgressCounterId),
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum EgressCounterId {
    DropPort,
    DropReason,
    Unicast,
    Multicast,
    MulticastExt,
    MulticastLL,
    MulticastUL,
    MulticastDrop,
}

impl fmt::Display for CounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CounterId::Service => "Service".to_string(),
                CounterId::Ingress => "Ingress".to_string(),
                CounterId::Egress => "Egress".to_string(),
                CounterId::Packet => "Packet".to_string(),
                CounterId::DropPort => "Ingress_Drop_Port".to_string(),
                CounterId::DropReason => "Ingress_Drop_Reason".to_string(),
                CounterId::EgressPipeline(id) => id.to_string(),
            }
        )
    }
}

impl std::str::FromStr for CounterId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace(['_'], "").as_str() {
            "service" => Ok(CounterId::Service),
            "ingress" => Ok(CounterId::Ingress),
            "egress" => Ok(CounterId::Egress),
            "packet" => Ok(CounterId::Packet),
            "ingressdropport" => Ok(CounterId::DropPort),
            "ingressdropreason" => Ok(CounterId::DropReason),
            "egressdropport" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::DropPort))
            }
            "egressdropreason" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::DropReason))
            }
            "unicast" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::Unicast))
            }
            "multicast" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::Multicast))
            }
            "multicastext" | "multicastexternal" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::MulticastExt))
            }
            "multicastll" | "multicastlinklocal" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::MulticastLL))
            }
            "multicastul" | "multicastunderlay" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::MulticastUL))
            }
            "multicastdrop" => {
                Ok(CounterId::EgressPipeline(EgressCounterId::MulticastDrop))
            }
            x => Err(format!("No such counter: {x}")),
        }
    }
}
impl fmt::Display for EgressCounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EgressCounterId::DropPort => "Egress_Drop_Port",
                EgressCounterId::DropReason => "Egress_Drop_Reason",
                EgressCounterId::Unicast => "Unicast",
                EgressCounterId::Multicast => "Multicast",
                EgressCounterId::MulticastExt => "Multicast_External",
                EgressCounterId::MulticastLL => "Multicast_Link_Local",
                EgressCounterId::MulticastUL => "Multicast_Underlay",
                EgressCounterId::MulticastDrop => "Multicast_Drop",
            }
        )
    }
}
