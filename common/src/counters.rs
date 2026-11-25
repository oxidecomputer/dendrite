// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

pub use dpd_types::counters::{
    FecRsCounters, PcsCounters, RMonCounters, RMonCountersAll,
};

/// Per-port counter label for the userspace service port, which has no link
/// of its own on the current switch.
pub const SERVICE_PORT_LABEL: &str = "service";

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
    IngressPipeline(IngressCounterId),
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
pub enum IngressCounterId {
    Service,
    Ingress,
    Packet,
    DropPort,
    DropReason,
    MulticastDrop,
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
    Forwarded,
    DropPort,
    DropReason,
    Unicast,
    Multicast,
    MulticastExt,
    MulticastLL,
    MulticastUL,
    /// Multicast traffic sent from the switch zone through to `sc_egress`
    /// (that's not IPv6 link-local, i.e., outside of `ff02::/16`). IPv6
    /// link-local switch-zone multicast packets count through `MulticastLL`,
    /// whereas any IPv4 local network control (`224.0.0.0/24`) packets still
    /// count here.
    MulticastUserspace,
}

impl fmt::Display for CounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CounterId::IngressPipeline(id) => fmt::Display::fmt(id, f),
            CounterId::EgressPipeline(id) => fmt::Display::fmt(id, f),
        }
    }
}

impl std::str::FromStr for CounterId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use EgressCounterId as E;
        use IngressCounterId as I;

        let id = match s.to_lowercase().replace(['_'], "").as_str() {
            "service" => CounterId::IngressPipeline(I::Service),
            "ingress" => CounterId::IngressPipeline(I::Ingress),
            "packet" => CounterId::IngressPipeline(I::Packet),
            "ingressdropport" => CounterId::IngressPipeline(I::DropPort),
            "ingressdropreason" => CounterId::IngressPipeline(I::DropReason),
            "multicastdrop" => CounterId::IngressPipeline(I::MulticastDrop),
            "forwarded" => CounterId::EgressPipeline(E::Forwarded),
            "egressdropport" => CounterId::EgressPipeline(E::DropPort),
            "egressdropreason" => CounterId::EgressPipeline(E::DropReason),
            "unicast" => CounterId::EgressPipeline(E::Unicast),
            "multicast" => CounterId::EgressPipeline(E::Multicast),
            "multicastext" | "multicastexternal" => {
                CounterId::EgressPipeline(E::MulticastExt)
            }
            "multicastll" | "multicastlinklocal" => {
                CounterId::EgressPipeline(E::MulticastLL)
            }
            "multicastul" | "multicastunderlay" => {
                CounterId::EgressPipeline(E::MulticastUL)
            }
            "multicastuserspace" => {
                CounterId::EgressPipeline(E::MulticastUserspace)
            }
            x => return Err(format!("No such counter: {x}")),
        };
        Ok(id)
    }
}

impl fmt::Display for IngressCounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            IngressCounterId::Service => "Service",
            IngressCounterId::Ingress => "Ingress",
            IngressCounterId::Packet => "Packet",
            IngressCounterId::DropPort => "Ingress_Drop_Port",
            IngressCounterId::DropReason => "Ingress_Drop_Reason",
            IngressCounterId::MulticastDrop => "Multicast_Drop",
        })
    }
}

impl fmt::Display for EgressCounterId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            EgressCounterId::Forwarded => "Forwarded",
            EgressCounterId::DropPort => "Egress_Drop_Port",
            EgressCounterId::DropReason => "Egress_Drop_Reason",
            EgressCounterId::Unicast => "Unicast",
            EgressCounterId::Multicast => "Multicast",
            EgressCounterId::MulticastExt => "Multicast_External",
            EgressCounterId::MulticastLL => "Multicast_Link_Local",
            EgressCounterId::MulticastUL => "Multicast_Underlay",
            EgressCounterId::MulticastUserspace => "Multicast_Userspace",
        })
    }
}
