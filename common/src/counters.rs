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
    Packet,
    DropPort,
    DropReason,
    Forwarded,
    Unicast,
    /// Link-local IPv6 multicast (ff02::/16). Not feature-gated because
    /// link-local forwarding uses standard routing, not replication groups.
    MulticastLL,
    EgressDropPort,
    EgressDropReason,
    #[cfg(feature = "multicast")]
    Multicast(MulticastCounterId),
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
#[cfg(feature = "multicast")]
pub enum MulticastCounterId {
    Multicast,
    MulticastExt,
    MulticastUL,
}

impl fmt::Display for CounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CounterId::Service => "Service".to_string(),
                CounterId::Ingress => "Ingress".to_string(),
                CounterId::Packet => "Packet".to_string(),
                CounterId::DropPort => "Ingress_Drop_Port".to_string(),
                CounterId::DropReason => "Ingress_Drop_Reason".to_string(),
                CounterId::Forwarded => "Forwarded".to_string(),
                CounterId::Unicast => "Unicast".to_string(),
                CounterId::MulticastLL => "Multicast_Link_Local".to_string(),
                CounterId::EgressDropPort => "Egress_Drop_Port".to_string(),
                CounterId::EgressDropReason => "Egress_Drop_Reason".to_string(),
                #[cfg(feature = "multicast")]
                CounterId::Multicast(id) => id.to_string(),
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
            "packet" => Ok(CounterId::Packet),
            "ingressdropport" => Ok(CounterId::DropPort),
            "ingressdropreason" => Ok(CounterId::DropReason),
            "forwarded" => Ok(CounterId::Forwarded),
            "unicast" => Ok(CounterId::Unicast),
            "multicastll" | "multicastlinklocal" => Ok(CounterId::MulticastLL),
            "egressdropport" => Ok(CounterId::EgressDropPort),
            "egressdropreason" => Ok(CounterId::EgressDropReason),
            #[cfg(feature = "multicast")]
            x => match x {
                "multicast" => {
                    Ok(CounterId::Multicast(MulticastCounterId::Multicast))
                }
                "multicastext" | "multicastexternal" => {
                    Ok(CounterId::Multicast(MulticastCounterId::MulticastExt))
                }
                "multicastul" | "multicastunderlay" => {
                    Ok(CounterId::Multicast(MulticastCounterId::MulticastUL))
                }
                x => Err(format!("No such counter: {x}")),
            },
            #[cfg(not(feature = "multicast"))]
            x => Err(format!("No such counter: {x}")),
        }
    }
}

#[cfg(feature = "multicast")]
impl fmt::Display for MulticastCounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MulticastCounterId::Multicast => "Multicast",
                MulticastCounterId::MulticastExt => "Multicast_External",
                MulticastCounterId::MulticastUL => "Multicast_Underlay",
            }
        )
    }
}
