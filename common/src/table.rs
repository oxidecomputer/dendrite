// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum TableError {
    #[error("No such table: {0}")]
    NoSuchTable(String),
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
pub enum TableType {
    RouteIdxIpv4,
    RouteFwdIpv4,
    RouteIdxIpv6,
    RouteFwdIpv6,
    #[cfg(feature = "multicast")]
    RouteIpv4Mcast,
    #[cfg(feature = "multicast")]
    RouteIpv6Mcast,
    ArpIpv4,
    NeighborIpv6,
    PortMacAddress,
    PortAddrIpv4,
    PortAddrIpv6,
    NatIngressIpv4,
    NatIngressIpv6,
    UplinkIngress,
    UplinkEgress,
    AttachedSubnetIpv4,
    AttachedSubnetIpv6,
    #[cfg(feature = "multicast")]
    McastIpv6,
    #[cfg(feature = "multicast")]
    McastIpv4SrcFilter,
    #[cfg(feature = "multicast")]
    McastIpv6SrcFilter,
    #[cfg(feature = "multicast")]
    NatIngressIpv4Mcast,
    #[cfg(feature = "multicast")]
    NatIngressIpv6Mcast,
    #[cfg(feature = "multicast")]
    PortMacAddressMcast,
    #[cfg(feature = "multicast")]
    McastEgressDecapPorts,
    #[cfg(feature = "multicast")]
    McastEgressPortMapping,
    Counter(crate::counters::CounterId),
}

/// Returns a vec of all the normal table types.  This will not include the
/// tables used to collect counter data, which are managed separately.
pub fn get_table_types() -> Vec<TableType> {
    let mut base_tables = vec![
        TableType::RouteIdxIpv4,
        TableType::RouteFwdIpv4,
        TableType::RouteIdxIpv6,
        TableType::RouteFwdIpv6,
        TableType::ArpIpv4,
        TableType::NeighborIpv6,
        TableType::PortMacAddress,
        TableType::PortAddrIpv4,
        TableType::PortAddrIpv6,
        TableType::NatIngressIpv4,
        TableType::NatIngressIpv6,
        TableType::UplinkIngress,
        TableType::UplinkEgress,
        TableType::AttachedSubnetIpv4,
        TableType::AttachedSubnetIpv6,
    ];

    let mut multicast_tables;
    #[cfg(feature = "multicast")]
    {
        multicast_tables = vec![
            TableType::RouteIpv4Mcast,
            TableType::RouteIpv6Mcast,
            TableType::McastIpv6,
            TableType::McastIpv4SrcFilter,
            TableType::McastIpv6SrcFilter,
            TableType::NatIngressIpv4Mcast,
            TableType::NatIngressIpv6Mcast,
            TableType::PortMacAddressMcast,
            TableType::McastEgressDecapPorts,
            TableType::McastEgressPortMapping,
        ];
    }
    #[cfg(not(feature = "multicast"))]
    {
        multicast_tables = Vec::new();
    }
    base_tables.append(&mut multicast_tables);
    base_tables
}

// This is the name that will be displayed in the log and presented to the user.
// It is similar to the name used in the p4 code, to simplify debugging, but
// isn't required to be identical.
impl fmt::Display for TableType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TableType::RouteIdxIpv4 => {
                    "Ingress.l3_router.Router4.lookup_idx.lookup".to_string()
                }
                TableType::RouteFwdIpv4 => {
                    "Ingress.l3_router.Router4.lookup_idx.route".to_string()
                }
                TableType::RouteIdxIpv6 => {
                    "Ingress.l3_router.Router6.lookup_idx.lookup".to_string()
                }
                TableType::RouteFwdIpv6 => {
                    "Ingress.l3_router.Router6.lookup_idx.route".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::RouteIpv4Mcast => {
                    "Ingress.l3_router.MulticastRouter4.tbl".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::RouteIpv6Mcast => {
                    "Ingress.l3_router.MulticastRouter6.tbl".to_string()
                }
                TableType::ArpIpv4 => "Ingress.l3_router.Arp.tbl".to_string(),
                TableType::NeighborIpv6 =>
                    "Ingress.l3_router.Ndp.tbl".to_string(),
                TableType::PortMacAddress =>
                    "Ingress.mac_rewrite.mac_rewrite".to_string(),
                TableType::PortAddrIpv4 =>
                    "Ingress.filter.switch_ipv4_addr".to_string(),
                TableType::PortAddrIpv6 =>
                    "Ingress.filter.switch_ipv6_addr".to_string(),
                TableType::NatIngressIpv4 =>
                    "Ingress.nat_ingress.ingress_ipv4".to_string(),
                TableType::NatIngressIpv6 =>
                    "Ingress.nat_ingress.ingress_ipv6".to_string(),
                TableType::UplinkIngress =>
                    "Ingress.filter.uplink_ports".to_string(),
                TableType::UplinkEgress =>
                    "Ingress.egress_filter.egress_filter".to_string(),
                TableType::AttachedSubnetIpv4 => {
                    "Ingress.attached_subnet_ingress.attached_subnets_v4"
                        .to_string()
                }
                TableType::AttachedSubnetIpv6 => {
                    "Ingress.attached_subnet_ingress.attached_subnets_v6"
                        .to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::McastIpv6 => {
                    "Ingress.mcast_ingress.mcast_replication_ipv6".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::McastIpv4SrcFilter => {
                    "Ingress.mcast_ingress.mcast_source_filter_ipv4".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::McastIpv6SrcFilter => {
                    "Ingress.mcast_ingress.mcast_source_filter_ipv6".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::NatIngressIpv4Mcast => {
                    "Ingress.nat_ingress.ingress_ipv4_mcast".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::NatIngressIpv6Mcast => {
                    "Ingress.nat_ingress.ingress_ipv6_mcast".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::PortMacAddressMcast =>
                    "Egress.mac_rewrite.mac_rewrite".to_string(),
                #[cfg(feature = "multicast")]
                TableType::McastEgressDecapPorts => {
                    "Egress.mcast_egress.tbl_decap_ports".to_string()
                }
                #[cfg(feature = "multicast")]
                TableType::McastEgressPortMapping => {
                    "Egress.mcast_egress.asic_id_to_port".to_string()
                }
                TableType::Counter(c) => format!("Counter({c})"),
            }
        )
    }
}

impl TryFrom<&str> for TableType {
    type Error = TableError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        let name = name.to_lowercase();
        match name.as_str() {
            "ingress.l3_router.router4.lookup_idx.lookup" => {
                Ok(TableType::RouteIdxIpv4)
            }

            "ingress.l3_router.router4.lookup_idx.route" => {
                Ok(TableType::RouteFwdIpv4)
            }

            "ingress.l3_router.router6.lookup_idx.lookup" => {
                Ok(TableType::RouteIdxIpv6)
            }

            "ingress.l3_router.router6.lookup_idx.route" => {
                Ok(TableType::RouteFwdIpv6)
            }
            #[cfg(feature = "multicast")]
            "ingress.l3_router.multicastrouter4.tbl" => {
                Ok(TableType::RouteIpv4Mcast)
            }

            #[cfg(feature = "multicast")]
            "ingress.l3_router.multicastrouter6.tbl" => {
                Ok(TableType::RouteIpv6Mcast)
            }
            "ingress.l3_router.arp.tbl" => Ok(TableType::ArpIpv4),
            "ingress.l3_router.ndp.tbl" => Ok(TableType::NeighborIpv6),
            "ingress.mac_rewrite.mac_rewrite" => Ok(TableType::PortMacAddress),
            "ingress.filter.switch_ipv4_addr" => Ok(TableType::PortAddrIpv4),
            "ingress.filter.switch_ipv6_addr" => Ok(TableType::PortAddrIpv6),
            "ingress.nat_ingress.ingress_ipv4" => Ok(TableType::NatIngressIpv4),
            "ingress.nat_ingress.ingress_ipv6" => Ok(TableType::NatIngressIpv6),
            "ingress.filter.uplink_ports" => Ok(TableType::UplinkIngress),
            "ingress.egress_filter.egress_filter" => {
                Ok(TableType::UplinkEgress)
            }
            "ingress.attached_subnet_ingress.attached_subnets_v4" => {
                Ok(TableType::AttachedSubnetIpv4)
            }

            "ingress.attached_subnet_ingress.attached_subnets_v6" => {
                Ok(TableType::AttachedSubnetIpv6)
            }

            #[cfg(feature = "multicast")]
            "ingress.mcast_ingress.mcast_replication_ipv6" => {
                Ok(TableType::McastIpv6)
            }

            #[cfg(feature = "multicast")]
            "ingress.mcast_ingress.mcast_source_filter_ipv4" => {
                Ok(TableType::McastIpv4SrcFilter)
            }

            #[cfg(feature = "multicast")]
            "ingress.mcast_ingress.mcast_source_filter_ipv6" => {
                Ok(TableType::McastIpv6SrcFilter)
            }

            #[cfg(feature = "multicast")]
            "ingress.nat_ingress.ingress_ipv4_mcast" => {
                Ok(TableType::NatIngressIpv4Mcast)
            }

            #[cfg(feature = "multicast")]
            "ingress.nat_ingress.ingress_ipv6_mcast" => {
                Ok(TableType::NatIngressIpv6Mcast)
            }

            #[cfg(feature = "multicast")]
            "egress.mac_rewrite.mac_rewrite" => {
                Ok(TableType::PortMacAddressMcast)
            }
            #[cfg(feature = "multicast")]
            "egress.mcast_egress.tbl_decap_ports" => {
                Ok(TableType::McastEgressDecapPorts)
            }

            #[cfg(feature = "multicast")]
            "egress.mcast_egress.asic_id_to_port" => {
                Ok(TableType::McastEgressPortMapping)
            }
            _ => Err(TableError::NoSuchTable(name)),
        }
    }
}
