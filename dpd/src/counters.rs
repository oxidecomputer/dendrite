// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

/// This module contains the support for reading the indirect counters defined
/// by the p4 program.  While direct counters are attached to an existing table,
/// indirect counters are implemented in the ASIC as standalone tables.  They
/// differ from regular match-action tables in that they are accessed with an
/// index number rather than a match-key, and they have no actions associated
/// with them.
///
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::sync::Arc;
use std::sync::Mutex;

use crate::table;
use crate::types::{DpdError, DpdResult};
use crate::views;
use crate::Switch;
use aal::MatchParse;
use aal_macros::*;
use asic::Handle;

use anyhow::Context;

// Counters in an indirect table are accessed by their index number rather than
// a key.  Still, we define a key anyway to allow us to use the direct counter
// infrastructure to extract the counter data.
#[derive(MatchParse, Hash, Debug)]
struct IndexKey {
    #[match_xlate(name = "$COUNTER_INDEX", type = "value")]
    idx: u16,
}

/// Represents an indirect counter in a P4 program.
pub struct Counter {
    /// The CounterId assigned to this counter at build time.
    id: CounterId,
    /// The asic-layer Table structure used to identify the indirect counter in
    /// the program.
    table: table::Table,
}

/// sidecar.p4 defines the following set of indirect counters.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum CounterId {
    Service,
    Ingress,
    Egress,
    Packet,
    DropPort,
    DropReason,
}

impl From<CounterId> for u8 {
    fn from(c: CounterId) -> u8 {
        c as u8
    }
}

/// Each indirect counter is identified by different names at different places
/// in the code flow.  This structure is used to define all the different names
/// used by each table in a single place.
struct CounterDescription {
    // Each counter is assigned an ID, which lets us associate the static
    // definitions with the Counter state maintained in the switch
    // structure.
    id: CounterId,
    // The name by which clients will identify a table
    client_name: &'static str,
    // The name assigned to the table in the compiled p4 program
    p4_name: &'static str,
}

const COUNTERS: [CounterDescription; 6] = [
    CounterDescription {
        id: CounterId::Service,
        client_name: "Service",
        p4_name: "pipe.Ingress.services.service_ctr",
    },
    CounterDescription {
        id: CounterId::Ingress,
        client_name: "Ingress",
        p4_name: "pipe.Ingress.ingress_ctr",
    },
    CounterDescription {
        id: CounterId::Egress,
        client_name: "Egress",
        p4_name: "pipe.Ingress.egress_ctr",
    },
    CounterDescription {
        id: CounterId::Packet,
        client_name: "Packet",
        p4_name: "pipe.Ingress.packet_ctr",
    },
    CounterDescription {
        id: CounterId::DropPort,
        client_name: "Drop_Port",
        p4_name: "pipe.Ingress.drop_port_ctr",
    },
    CounterDescription {
        id: CounterId::DropReason,
        client_name: "Drop_Reason",
        p4_name: "pipe.Ingress.drop_reason_ctr",
    },
];

/// Get the list of names by which end users can refer to a counter.
pub fn get_counter_names() -> DpdResult<Vec<String>> {
    Ok(COUNTERS.iter().map(|c| c.client_name.to_string()).collect())
}

/// Fetch a counter by name from the switch's list of counters.  This call
/// returns a pointer to the mutex that controls access to the counter, and the
/// caller is responsible for locking the mutex.
fn get_counter<'a>(
    switch: &'a Switch,
    name: &str,
) -> DpdResult<&'a Mutex<Counter>> {
    let name = name.to_lowercase();
    switch
        .counters
        .get(&name)
        .ok_or(DpdError::Invalid("no such counter".to_string()))
}

/// Given an index into the Packet table, convert it from a bitmap of parsed
/// headers into an ASCII label.
fn packet_label(ctr: u16) -> Option<String> {
    const PKT_ETHER: u16 = 0x200;
    const PKT_LLDP: u16 = 0x100;
    const PKT_VLAN: u16 = 0x080;
    const PKT_SIDECAR: u16 = 0x040;
    const PKT_ICMP: u16 = 0x020;
    const PKT_IPV4: u16 = 0x010;
    const PKT_IPV6: u16 = 0x008;
    const PKT_UDP: u16 = 0x004;
    const PKT_TCP: u16 = 0x002;
    const PKT_ARP: u16 = 0x001;

    fn has_bit(ctr: u16, bit: u16) -> bool {
        ctr & bit == bit
    }

    let mut f = String::new();

    if has_bit(ctr, PKT_ETHER) {
        f.push('E');
    } else {
        f.push('-');
    }
    if has_bit(ctr, PKT_LLDP) {
        f.push('L');
    } else {
        f.push('-');
    }
    if has_bit(ctr, PKT_VLAN) {
        f.push('V');
    } else {
        f.push('-');
    }
    if has_bit(ctr, PKT_SIDECAR) {
        f.push('S');
    } else {
        f.push('-');
    }
    if has_bit(ctr, PKT_ARP) {
        f.push('A');
    } else if has_bit(ctr, PKT_IPV4) {
        f.push('4');
    } else if has_bit(ctr, PKT_IPV6) {
        f.push('6');
    } else {
        f.push('-');
    }
    if has_bit(ctr, PKT_UDP) {
        f.push('U');
    } else if has_bit(ctr, PKT_TCP) {
        f.push('T');
    } else if has_bit(ctr, PKT_ICMP) {
        f.push('I');
    } else {
        f.push('-');
    }
    Some(f)
}

// Given an index into the Service table, return the name of the service action
// it represents.
fn service_label(ctr: u8) -> Option<String> {
    let label = match ctr {
        0 => "fw_to_user".to_string(),
        1 => "fw_from_user".to_string(),
        2 => "ping_v4_reply".to_string(),
        3 => "ping_v6_reply".to_string(),
        4 => "bad_ping".to_string(),
        x => format!("unknown service counter {x}"),
    };
    Some(label)
}

// The hardcoded ID of the drop reason, matching those defined in constants.p4
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum DropReason {
    Accepted,
    Ipv4SwitchAddrMiss,
    Ipv6SwitchAddrMiss,
    BadPing,
    NatHeaderError,
    ArpNull,
    ArpMiss,
    NdpNull,
    NdpMiss,
    MulticastToLocalInterface,
    Ipv4ChecksumErr,
    Ipv4TtlInvalid,
    Ipv4TtlExceeded,
    Ipv6TtlInvalid,
    Ipv6TtlExceeded,
    Ipv4Unrouteable,
    Ipv6Unrouteable,
    NatIngressMiss,
}

impl TryFrom<u8> for DropReason {
    type Error = String;

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(DropReason::Accepted),
            1 => Ok(DropReason::Ipv4SwitchAddrMiss),
            2 => Ok(DropReason::Ipv6SwitchAddrMiss),
            3 => Ok(DropReason::BadPing),
            4 => Ok(DropReason::NatHeaderError),
            5 => Ok(DropReason::ArpNull),
            6 => Ok(DropReason::ArpMiss),
            7 => Ok(DropReason::NdpNull),
            8 => Ok(DropReason::NdpMiss),
            9 => Ok(DropReason::MulticastToLocalInterface),
            10 => Ok(DropReason::Ipv4ChecksumErr),
            11 => Ok(DropReason::Ipv4TtlInvalid),
            12 => Ok(DropReason::Ipv4TtlExceeded),
            13 => Ok(DropReason::Ipv6TtlInvalid),
            14 => Ok(DropReason::Ipv6TtlExceeded),
            15 => Ok(DropReason::Ipv4Unrouteable),
            16 => Ok(DropReason::Ipv6Unrouteable),
            17 => Ok(DropReason::NatIngressMiss),
            x => Err(format!("Unrecognized drop reason: {x}")),
        }
    }
}

fn reason_label(ctr: u8) -> Result<Option<String>, String> {
    let ctr = DropReason::try_from(ctr)?;
    let label = match ctr {
        // A 'drop reason' of 0 means that the packet wasn't dropped
        DropReason::Accepted => return Ok(None),
        DropReason::Ipv4SwitchAddrMiss => "ipv4_switch_addr_miss".to_string(),
        DropReason::Ipv6SwitchAddrMiss => "ipv6_switch_addr_miss".to_string(),
        DropReason::BadPing => "bad_ping".to_string(),
        DropReason::NatHeaderError => "nat_header_error".to_string(),
        DropReason::ArpNull => "arp_mapping_null".to_string(),
        DropReason::ArpMiss => "arp_miss".to_string(),
        DropReason::NdpNull => "ndp_mapping_null".to_string(),
        DropReason::NdpMiss => "ndp_miss".to_string(),
        DropReason::MulticastToLocalInterface => {
            "multicast_to_local_interface".to_string()
        }
        DropReason::Ipv4ChecksumErr => "ipv4_checksum_err".to_string(),
        DropReason::Ipv4TtlInvalid => "ipv4_ttl_invalid".to_string(),
        DropReason::Ipv4TtlExceeded => "ipv4_ttl_exceeded".to_string(),
        DropReason::Ipv6TtlInvalid => "ipv6_ttl_invalid".to_string(),
        DropReason::Ipv6TtlExceeded => "ipv6_ttl_exceeded".to_string(),
        DropReason::Ipv4Unrouteable => "ipv6_unrouteable".to_string(),
        DropReason::Ipv6Unrouteable => "ipv4_unrouteable".to_string(),
        DropReason::NatIngressMiss => "nat_ingress_miss".to_string(),
    };
    Ok(Some(label))
}

// The per-port counters include all possible ASIC ports, even though only a few
// dozen are associated with configured links at any given time.  If this ID
// doesn't match to a port, it's not an error.
async fn port_label(switch: &Switch, ctr: u16) -> Option<String> {
    switch
        .asic_port_id_to_port_link(ctr)
        .map(|(port, link)| format!("{}/{}", port, link))
        .ok()
}

/// Fetch all of the accumulated values for this counter.
pub async fn get_values(
    switch: &Arc<Switch>,
    force_sync: bool,
    counter_name: String,
) -> DpdResult<Vec<views::TableCounterEntry>> {
    let counter_id = {
        // While we are grabbing the CounterId here, the primary purpose of this
        // little dance is to verify that the counter exists before referencing it
        // in the closure below.  We can't just pass the counter into the closure,
        // because the compiler is worried that the Counter lifetime will exceed
        // that of the Switch that contains it.
        get_counter(switch, &counter_name)?.lock().unwrap().id
    };

    let counters = {
        let switch = switch.clone();
        let name = counter_name.clone();
        // Because this call may initiate an ASIC->memory sync operation it can
        // be long-running, so we run it in a new task.
        tokio::task::spawn_blocking(move || {
            get_counter(&switch, &name)
                .expect("verified that the table exists in the outer function")
                .lock()
                .unwrap()
                .table
                .get_counters::<IndexKey>(&switch.asic_hdl, force_sync)
        })
        .await
        .unwrap()
    }?;

    let mut entries = Vec::new();
    for (idx, data) in counters {
        // Given the indirect counter index, look up the label.
        let key = match counter_id {
            CounterId::Packet => packet_label(idx.idx),
            CounterId::Service => service_label(idx.idx as u8),
            CounterId::Ingress | CounterId::Egress | CounterId::DropPort => {
                port_label(switch, idx.idx).await
            }
            CounterId::DropReason => reason_label(idx.idx as u8)?,
        };

        if let Some(key) = key {
            // The packet counter has 256 possible combinations, most of which
            // we will never see, many of which (e.g. an icmp packet that is
            // neither IPv4 nor IPv6) are even possible.  We don't record
            // combinations with 0 hits.
            if counter_id == CounterId::Packet && data.pkts == Some(0) {
                continue;
            }

            let mut keys = BTreeMap::new();
            // In an indirect counter table, the only "key" is the index in the
            // table.  We've already translated the index into a label, so
            // that's what we're calling the key now.
            keys.insert("label".to_string(), key);
            entries.push(views::TableCounterEntry { keys, data });
        }
    }

    Ok(entries)
}

pub fn reset(switch: &Switch, counter_name: String) -> DpdResult<()> {
    let mut counter = get_counter(switch, &counter_name)?.lock().unwrap();
    counter.table.clear(&switch.asic_hdl)
}

/// Create internal structures for managing the counters built into sidecar.p4
pub fn init(hdl: &Handle) -> anyhow::Result<BTreeMap<String, Mutex<Counter>>> {
    let mut counters = BTreeMap::new();
    for c in COUNTERS {
        counters.insert(
            c.client_name.to_string().to_lowercase(),
            Mutex::new(Counter {
                id: c.id,
                table: table::Table::new(hdl, c.p4_name).with_context(
                    || format!("creating {} counter", c.client_name),
                )?,
            }),
        );
    }
    Ok(counters)
}
