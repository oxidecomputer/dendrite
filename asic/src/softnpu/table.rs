// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use slog::{error, trace};
use softnpu_lib::{ManagementRequest, TableAdd, TableRemove};

use crate::softnpu::Handle;
use aal::{
    ActionParse, AsicError, AsicResult, CounterData, MatchEntryField,
    MatchEntryValue, MatchParse, TableOps, ValueTypes,
};

/// Represents a handle to a SoftNPU ASIC table. The `id` member corresponds to
/// the table path in the P4 program. Well known sidecar-lite.p4 paths follow
/// below.
pub struct Table {
    id: Option<String>,
    dpd_id: Option<String>,
    size: usize,
}

// soft-npu table names
const ROUTER_V4_RT: &str = "ingress.router.v4_route.rtr";
const ROUTER_V4_IDX: &str = "ingress.router.v4_idx.rtr";
const ROUTER_V6: &str = "ingress.router.v6.rtr";
const LOCAL_V6: &str = "ingress.local.local_v6";
const LOCAL_V4: &str = "ingress.local.local_v4";
const NAT_V4: &str = "ingress.nat.nat_v4";
const NAT_V6: &str = "ingress.nat.nat_v6";
const _NAT_ICMP_V6: &str = "ingress.nat.nat_icmp_v6";
const _NAT_ICMP_V4: &str = "ingress.nat.nat_icmp_v4";
const RESOLVER_V4: &str = "ingress.resolver.resolver_v4";
const RESOLVER_V6: &str = "ingress.resolver.resolver_v6";
const MAC_REWRITE: &str = "ingress.mac.mac_rewrite";
const _PROXY_ARP: &str = "ingress.pxarp.proxy_arp";

// sidecar.p4 table names
const SWITCH_ADDR4: &str = "pipe.Ingress.filter.switch_ipv4_addr";
const SWITCH_ADDR6: &str = "pipe.Ingress.filter.switch_ipv6_addr";
const ROUTER4_LOOKUP_RT: &str =
    "pipe.Ingress.l3_router.Router4.lookup_idx.route";
const ROUTER4_LOOKUP_IDX: &str =
    "pipe.Ingress.l3_router.Router4.lookup_idx.lookup";
const ROUTER6_LOOKUP: &str = "pipe.Ingress.l3_router.Router6.lookup.tbl";
const NDP: &str = "pipe.Ingress.l3_router.Router6.Ndp.tbl";
const ARP: &str = "pipe.Ingress.l3_router.Router4.Arp.tbl";
const DPD_MAC_REWRITE: &str = "pipe.Ingress.mac_rewrite.mac_rewrite";
const NAT_INGRESS4: &str = "pipe.Ingress.nat_ingress.ingress_ipv4";
const NAT_INGRESS6: &str = "pipe.Ingress.nat_ingress.ingress_ipv6";

// All tables are defined to be 1024 entries deep
const TABLE_SIZE: usize = 4096;

impl TableOps<Handle> for Table {
    fn new(_hdl: &Handle, name: &str) -> AsicResult<Table> {
        // TODO just mapping sidecar.p4 things onto simplified sidecar-lite.p4
        // things to get started.
        let (id, dpd_id) = match name {
            ROUTER4_LOOKUP_RT => {
                (Some(ROUTER_V4_RT.into()), Some(ROUTER4_LOOKUP_RT.into()))
            }
            ROUTER4_LOOKUP_IDX => {
                (Some(ROUTER_V4_IDX.into()), Some(ROUTER4_LOOKUP_IDX.into()))
            }
            ROUTER6_LOOKUP => {
                (Some(ROUTER_V6.into()), Some(ROUTER6_LOOKUP.into()))
            }
            SWITCH_ADDR4 => (Some(LOCAL_V4.into()), Some(SWITCH_ADDR4.into())),
            SWITCH_ADDR6 => (Some(LOCAL_V6.into()), Some(SWITCH_ADDR6.into())),
            NDP => (Some(RESOLVER_V6.into()), Some(NDP.into())),
            ARP => (Some(RESOLVER_V4.into()), Some(ARP.into())),
            DPD_MAC_REWRITE => {
                (Some(MAC_REWRITE.into()), Some(DPD_MAC_REWRITE.into()))
            }
            NAT_INGRESS4 => (Some(NAT_V4.into()), Some(NAT_INGRESS4.into())),
            NAT_INGRESS6 => (Some(NAT_V6.into()), Some(NAT_INGRESS6.into())),
            x => {
                println!("TABLE NOT HANDLED {x}");
                (None, None)
            }
        };

        Ok(Table {
            id,
            dpd_id,
            size: TABLE_SIZE,
        })
    }

    fn size(&self) -> usize {
        self.size
    }

    fn clear(&self, _hdl: &Handle) -> AsicResult<()> {
        //TODO implement in softnpu
        Ok(())
    }

    fn entry_add<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        let table = match &self.id {
            None => return Ok(()),
            Some(id) => id.clone(),
        };
        let dpd_table = match &self.dpd_id {
            None => return Ok(()),
            Some(id) => id.clone(),
        };

        let match_data = key.key_to_ir().unwrap();
        let action_data = data.action_to_ir().unwrap();

        trace!(hdl.log, "entry_add called");
        trace!(hdl.log, "table: {}", table);
        trace!(hdl.log, "match_data:\n{:#?}", match_data);
        trace!(hdl.log, "action_data:\n{:#?}", action_data);

        let keyset_data = keyset_data(match_data.fields, &table);

        let (action, parameter_data) = match (
            dpd_table.as_str(),
            action_data.action.as_str(),
        ) {
            // TODO: implement mappings for natv6 actions
            (SWITCH_ADDR4, "claimv4") => ("local", Vec::new()),
            (SWITCH_ADDR6, "claimv6") => ("local", Vec::new()),
            (ROUTER4_LOOKUP_IDX, "index") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => {
                            // 16 bit index
                            // 8 bit slot count
                            match arg.name.as_str() {
                                "idx" => {
                                    let v = *v as u16;
                                    params.extend_from_slice(&v.to_le_bytes());
                                }
                                "slots" => {
                                    let v = *v as u8;
                                    params.extend_from_slice(&v.to_le_bytes());
                                }
                                x => {
                                    error!(hdl.log, "unexpected parameter: {dpd_table}::index {x}")
                                }
                            }
                        }
                        ValueTypes::Ptr(v) => {
                            params.extend_from_slice(v.as_slice());
                        }
                    }
                }
                ("index", params)
            }
            (ROUTER4_LOOKUP_RT, "forward") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => {
                            // 16 bit port
                            // 32 bit nexthop
                            match arg.name.as_str() {
                                "port" => {
                                    params.extend_from_slice(
                                        &(*v as u16).to_le_bytes(),
                                    );
                                }
                                "nexthop" => {
                                    params.extend_from_slice(
                                        &(*v as u32).to_le_bytes(),
                                    );
                                }
                                x => {
                                    error!(hdl.log, "unexpected parameter: {dpd_table}::forward {x}")
                                }
                            }
                        }
                        ValueTypes::Ptr(v) => {
                            params.extend_from_slice(v.as_slice());
                        }
                    }
                }
                ("forward", params)
            }
            (ROUTER4_LOOKUP_RT, "forward_vlan") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => {
                            // 16 bit port
                            // 32 bit nexthop
                            // 12 bit vlan
                            match arg.name.as_str() {
                                "vlan_id" => {
                                    params.extend_from_slice(
                                        &(*v as u16).to_le_bytes(),
                                    );
                                }
                                "port" => {
                                    params.extend_from_slice(
                                        &(*v as u16).to_le_bytes(),
                                    );
                                }
                                "nexthop" => {
                                    params.extend_from_slice(
                                        &(*v as u32).to_le_bytes(),
                                    );
                                }
                                x => {
                                    error!(hdl.log, "unexpected parameter: {dpd_table}::forward_vlan {x}")
                                }
                            }
                        }
                        ValueTypes::Ptr(v) => {
                            params.extend_from_slice(v.as_slice());
                        }
                    }
                }
                ("forward_vlan", params)
            }
            (ROUTER6_LOOKUP, "forward") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => match arg.name.as_str() {
                            "port" => {
                                params.extend_from_slice(
                                    &(*v as u16).to_le_bytes(),
                                );
                            }
                            x => {
                                error!(hdl.log, "unexpected parameter: {dpd_table}::forward {x}")
                            }
                        },
                        ValueTypes::Ptr(v) => {
                            let mut buf = v.clone();
                            buf.reverse();
                            params.extend_from_slice(buf.as_slice());
                        }
                    }
                }
                ("forward", params)
            }
            (ROUTER6_LOOKUP, "forward_vlan") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => match arg.name.as_str() {
                            "port" => {
                                params.extend_from_slice(
                                    &(*v as u16).to_le_bytes(),
                                );
                            }
                            "vlan_id" => {
                                params.extend_from_slice(
                                    &(*v as u16).to_le_bytes(),
                                );
                            }
                            x => {
                                error!(hdl.log, "unexpected parameter: {dpd_table}::forward_vlan {x}")
                            }
                        },
                        ValueTypes::Ptr(v) => {
                            let mut buf = v.clone();
                            buf.reverse();
                            params.extend_from_slice(buf.as_slice());
                        }
                    }
                }
                ("forward_vlan", params)
            }
            (ARP, "rewrite") => {
                let mut params = Vec::new();
                for arg in action_data.args {
                    match arg.value {
                        ValueTypes::U64(v) => {
                            let mac = v.to_le_bytes();
                            params.extend_from_slice(&mac[0..6]);
                        }
                        ValueTypes::Ptr(v) => {
                            params.extend_from_slice(v.as_slice());
                        }
                    }
                }
                ("rewrite_dst", params)
            }
            (NDP, "rewrite") => {
                let mut params = Vec::new();
                for arg in action_data.args {
                    match arg.value {
                        ValueTypes::U64(v) => {
                            let mac = v.to_le_bytes();
                            params.extend_from_slice(&mac[0..6]);
                        }
                        ValueTypes::Ptr(v) => {
                            params.extend_from_slice(v.as_slice());
                        }
                    }
                }
                ("rewrite_dst", params)
            }
            (DPD_MAC_REWRITE, "rewrite") => {
                let mut params = Vec::new();
                for arg in action_data.args {
                    match arg.value {
                        ValueTypes::U64(v) => {
                            let mac = v.to_le_bytes();
                            params.extend_from_slice(&mac[0..6]);
                        }
                        ValueTypes::Ptr(v) => {
                            params.extend_from_slice(v.as_slice());
                        }
                    }
                }
                ("rewrite", params)
            }
            (NAT_INGRESS4, "forward_ipv4_to") => {
                let mut target = Vec::new();
                let mut vni = Vec::new();
                let mut mac = Vec::new();
                for arg in action_data.args {
                    match arg.name.as_str() {
                        "target" => {
                            // "target" is 128 bits
                            let mut data: Vec<u8> = Vec::new();
                            match &arg.value {
                                ValueTypes::U64(_) => {
                                    // Currently the ValueType is always Ptr
                                    error!(
                                        hdl.log,
                                        "expected ValueType::Ptr, \
                                        received ValueType::U64"
                                    );
                                    return Ok(());
                                }
                                ValueTypes::Ptr(v) => {
                                    data.extend_from_slice(v.as_slice());
                                }
                            }
                            let len = data.len();
                            let buf = &mut data[len - 16..];
                            buf.reverse();
                            target.extend_from_slice(buf);
                        }
                        "vni" => {
                            // "vni" is 24 bits
                            let mut data: Vec<u8> = Vec::new();
                            match &arg.value {
                                ValueTypes::U64(v) => {
                                    data.extend_from_slice(&v.to_le_bytes());
                                }
                                ValueTypes::Ptr(_) => {
                                    // Currently the ValueType is always U64
                                    error!(
                                        hdl.log,
                                        "expected ValueType::U64, \
                                        received ValueType::Ptr"
                                    );
                                    return Ok(());
                                }
                            }
                            vni.extend_from_slice(&data[0..3]);
                        }
                        "inner_mac" => {
                            // "mac" is 48 bits
                            let mut data: Vec<u8> = Vec::new();
                            match &arg.value {
                                ValueTypes::U64(v) => {
                                    data.extend_from_slice(&v.to_le_bytes());
                                }
                                ValueTypes::Ptr(_) => {
                                    // Currently the ValueType is always U64
                                    error!(
                                        hdl.log,
                                        "expected ValueType::U64, \
                                        received ValueType::Ptr"
                                    );
                                    return Ok(());
                                }
                            }
                            mac.extend_from_slice(&data[0..6])
                        }
                        _ => {
                            error!(hdl.log, "unknown argument: {}", arg.name);
                            return Ok(());
                        }
                    }
                }
                let mut params = Vec::new();
                // arguments currently don't arrive in the correct order,
                // so we'll order them manually
                params.extend_from_slice(target.as_slice());
                params.extend_from_slice(vni.as_slice());
                params.extend_from_slice(mac.as_slice());
                ("forward_to_sled", params)
            }
            (tbl, x) => {
                println!("ACTION NOT HANDLED {tbl} {x}");
                return Ok(());
            }
        };
        let action = action.to_string();
        trace!(hdl.log, "sending request to softnpu");
        trace!(hdl.log, "table: {}", table);
        trace!(hdl.log, "action: {:#?}", action);
        trace!(hdl.log, "keyset_data:\n{:#?}", keyset_data);
        trace!(hdl.log, "parameter_data:\n{:#?}", parameter_data);

        let msg = ManagementRequest::TableAdd(TableAdd {
            table,
            action,
            keyset_data,
            parameter_data,
        });

        crate::softnpu::mgmt::write(msg, &hdl.mgmt_config);

        Ok(())
    }

    fn entry_update<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        let table = match &self.id {
            None => return Ok(()),
            Some(id) => id.clone(),
        };
        let match_data = key.key_to_ir().unwrap();
        let action_data = data.action_to_ir().unwrap();

        trace!(hdl.log, "entry_update called");
        trace!(hdl.log, "table: {}", table);
        trace!(hdl.log, "match_data:\n{:#?}", match_data);
        trace!(hdl.log, "action_data:\n{:#?}", action_data);

        //TODO implement in softnpu
        Ok(())
    }

    fn entry_del<M: MatchParse>(
        &self,
        hdl: &Handle,
        key: &M,
    ) -> AsicResult<()> {
        let table = match &self.id {
            None => return Ok(()),
            Some(id) => id.clone(),
        };
        let match_data = key.key_to_ir().unwrap();

        trace!(hdl.log, "entry_del called");
        trace!(hdl.log, "table: {}", table);
        trace!(hdl.log, "match_data:\n{:#?}", match_data);

        let keyset_data = keyset_data(match_data.fields, &table);

        trace!(hdl.log, "sending request to softnpu");
        trace!(hdl.log, "table: {}", table);
        trace!(hdl.log, "keyset_data:\n{:#?}", keyset_data);

        let msg =
            ManagementRequest::TableRemove(TableRemove { keyset_data, table });

        crate::softnpu::mgmt::write(msg, &hdl.mgmt_config);

        Ok(())
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        _hdl: &Handle,
    ) -> AsicResult<Vec<(M, A)>> {
        Err(aal::AsicError::OperationUnsupported)
    }
    fn get_counters<M: MatchParse>(
        &self,
        _hdl: &Handle,
        _force_sync: bool,
    ) -> AsicResult<Vec<(M, CounterData)>> {
        Err(AsicError::OperationUnsupported)
    }
}

/// Extract keys from `match_data` and ensure that they are
/// in a data structure with the correct length
fn keyset_data(match_data: Vec<MatchEntryField>, table: &str) -> Vec<u8> {
    let mut keyset_data: Vec<u8> = Vec::new();
    for m in match_data {
        match m.value {
            // Exact match
            MatchEntryValue::Value(x) => {
                let mut data: Vec<u8> = Vec::new();
                match table {
                    RESOLVER_V4 => {
                        // "nexthop_ipv4" => bit<32>
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    RESOLVER_V6 => {
                        // "nexthop_ipv4" => bit<128>
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    MAC_REWRITE => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..2]);
                    }
                    ROUTER_V4_RT => {
                        // "idx" => exact => bit<16>
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..2]);
                    }
                    NAT_V4 => {
                        // "dst_addr" => hdr.ipv4.dst: exact => bit<32>
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    LOCAL_V6 => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    _ => {
                        serialize_value_type(&x, &mut keyset_data);
                    }
                }
            }
            // Longest prefix
            MatchEntryValue::Lpm(x) => {
                let mut data: Vec<u8> = Vec::new();
                match table {
                    ROUTER_V4_IDX => {
                        // prefix for longest prefix match operation
                        // "dst_addr" => hdr.ipv4.dst: lpm => bit<32>
                        serialize_value_type_be(&x.prefix, &mut data);
                        keyset_data.extend_from_slice(&data[data.len() - 4..]);
                        // prefix length for longest prefix match operation
                        keyset_data.push(x.len as u8)
                    }
                    _ => {
                        serialize_value_type_be(&x.prefix, &mut keyset_data);
                        keyset_data.push(x.len as u8);
                    }
                }
            }
            // Ranges (i.e. port ranges)
            MatchEntryValue::Range(x) => {
                match table {
                    NAT_V4 => {
                        // "l4_dst_port" => ingress.nat_id: range =>  bit<16>
                        let low = &x.low.to_le_bytes();
                        let high = &x.high.to_le_bytes();
                        keyset_data.extend_from_slice(&low[..2]);
                        keyset_data.extend_from_slice(&high[..2]);
                    }
                    _ => {
                        keyset_data.extend_from_slice(&x.low.to_le_bytes());
                        keyset_data.extend_from_slice(&x.high.to_le_bytes());
                    }
                }
            }
            // Masked (ternary match)
            MatchEntryValue::Mask(x) => {
                keyset_data.extend_from_slice(&x.val.to_le_bytes());
                keyset_data.extend_from_slice(&x.mask.to_le_bytes());
            }
        }
    }
    keyset_data
}

fn serialize_value_type(x: &ValueTypes, data: &mut Vec<u8>) {
    match x {
        ValueTypes::U64(v) => {
            data.extend_from_slice(&v.to_le_bytes());
        }
        ValueTypes::Ptr(v) => {
            data.extend_from_slice(v.as_slice());
        }
    }
}

fn serialize_value_type_be(x: &ValueTypes, data: &mut Vec<u8>) {
    match x {
        ValueTypes::U64(v) => {
            data.extend_from_slice(&v.to_be_bytes());
        }
        ValueTypes::Ptr(v) => {
            data.extend_from_slice(v.as_slice());
        }
    }
}
