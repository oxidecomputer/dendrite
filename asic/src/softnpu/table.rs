// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use slog::{error, trace};
use softnpu_lib::{ManagementRequest, TableAdd, TableRemove};

use crate::softnpu::Handle;
use aal::{
    ActionParse, AsicError, AsicResult, CounterData, MatchEntryField,
    MatchEntryValue, MatchParse, TableOps, ValueTypes,
};
use common::table::TableType;

/// Represents a handle to a SoftNPU ASIC table. The `id` member corresponds to
/// the table path in the P4 program. Well known sidecar-lite.p4 paths follow
/// below.
pub struct Table {
    type_: TableType,
    implemented: bool,
    size: usize,
}

impl Table {
    pub fn softnpu_table_name(&self) -> Option<&'static str> {
        if self.implemented {
            match self.type_ {
                TableType::RouteFwdIpv4 => Some("ingress.router.v4_route.rtr"),
                TableType::RouteIdxIpv4 => Some("ingress.router.v4_idx.rtr"),
                TableType::RouteFwdIpv6 => Some("ingress.router.v6_route.rtr"),
                TableType::RouteIdxIpv6 => Some("ingress.router.v6_idx.rtr"),
                TableType::PortAddrIpv6 => Some("ingress.local.local_v6"),
                TableType::PortAddrIpv4 => Some("ingress.local.local_v4"),
                TableType::NatIngressIpv4 => Some("ingress.nat.nat_v4"),
                TableType::NatIngressIpv6 => Some("ingress.nat.nat_v6"),
                TableType::AttachedSubnetIpv4 => {
                    Some("ingress.attached.attached_subnet_v4")
                }
                TableType::AttachedSubnetIpv6 => {
                    Some("ingress.attached.attached_subnet_v6")
                }
                TableType::ArpIpv4 => Some("ingress.resolver.resolver_v4"),
                TableType::NeighborIpv6 => Some("ingress.resolver.resolver_v6"),
                TableType::PortMacAddress => Some("ingress.mac.mac_rewrite"),
                _ => panic!(
                    "implemented table {} has no softnpu table",
                    self.type_
                ),
            }
        } else {
            None
        }
    }
}

// All tables are defined to be 1024 entries deep
const TABLE_SIZE: usize = 4096;

impl TableOps<Handle> for Table {
    fn new(hdl: &Handle, type_: TableType) -> AsicResult<Table> {
        // TODO just mapping sidecar.p4 things onto simplified sidecar-lite.p4
        // things to get started.
        let implemented = match type_ {
            TableType::RouteIdxIpv4
            | TableType::RouteFwdIpv4
            | TableType::RouteIdxIpv6
            | TableType::RouteFwdIpv6
            | TableType::PortAddrIpv4
            | TableType::PortAddrIpv6
            | TableType::ArpIpv4
            | TableType::NeighborIpv6
            | TableType::PortMacAddress
            | TableType::NatIngressIpv4
            | TableType::NatIngressIpv6
            | TableType::AttachedSubnetIpv4
            | TableType::AttachedSubnetIpv6 => true,
            x => {
                error!(hdl.log, "TABLE NOT HANDLED {x}");
                false
            }
        };

        Ok(Table { type_, implemented, size: TABLE_SIZE })
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
        let Some(table) = self.softnpu_table_name() else {
            return Ok(());
        };
        let name = self.type_.to_string();
        let match_data = key.key_to_ir().unwrap();
        let action_data = data.action_to_ir().unwrap();

        trace!(hdl.log, "entry_add called");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "match_data:\n{:#?}", match_data);
        trace!(hdl.log, "action_data:\n{:#?}", action_data);

        let keyset_data = keyset_data(match_data.fields, self.type_);

        let (action, parameter_data) = match (
            self.type_,
            action_data.action.as_str(),
        ) {
            // TODO: implement mappings for natv6 actions
            (TableType::PortAddrIpv4, "claimv4") => ("local", Vec::new()),
            (TableType::PortAddrIpv6, "claimv6") => ("local", Vec::new()),
            (TableType::RouteIdxIpv4, "index") => {
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
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::index {x}"
                                    )
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
            (TableType::RouteFwdIpv4, "forward") => {
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
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::forward {x}"
                                    )
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
            (TableType::RouteFwdIpv4, "forward_v6") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => {
                            // 16 bit port
                            match arg.name.as_str() {
                                "port" => {
                                    params.extend_from_slice(
                                        &(*v as u16).to_le_bytes(),
                                    );
                                }
                                x => {
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::forward {x}"
                                    )
                                }
                            }
                        }
                        ValueTypes::Ptr(v) => {
                            let mut buf = v.clone();
                            buf.reverse();
                            params.extend_from_slice(buf.as_slice());
                        }
                    }
                }
                ("forward_v6", params)
            }
            (TableType::RouteFwdIpv4, "forward_vlan") => {
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
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::forward_vlan {x}"
                                    )
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
            (TableType::RouteFwdIpv4, "forward_vlan_v6") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => {
                            // 16 bit port
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
                                x => {
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::forward_vlan {x}"
                                    )
                                }
                            }
                        }
                        ValueTypes::Ptr(v) => {
                            let mut buf = v.clone();
                            buf.reverse();
                            params.extend_from_slice(buf.as_slice());
                        }
                    }
                }
                ("forward_vlan_v6", params)
            }
            (TableType::RouteIdxIpv6, "index") => {
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
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::index {x}"
                                    )
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
            (TableType::RouteFwdIpv6, "forward") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => {
                            // 16 bit port
                            match arg.name.as_str() {
                                "port" => {
                                    params.extend_from_slice(
                                        &(*v as u16).to_le_bytes(),
                                    );
                                }
                                x => {
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::forward {x}"
                                    )
                                }
                            }
                        }
                        ValueTypes::Ptr(v) => {
                            let mut buf = v.clone();
                            buf.reverse();
                            params.extend_from_slice(buf.as_slice());
                        }
                    }
                }
                ("forward", params)
            }
            (TableType::RouteFwdIpv6, "forward_vlan") => {
                let mut params = Vec::new();
                for arg in action_data.args.iter() {
                    match &arg.value {
                        ValueTypes::U64(v) => {
                            // 16 bit port
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
                                x => {
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {name}::forward_vlan {x}"
                                    )
                                }
                            }
                        }
                        ValueTypes::Ptr(v) => {
                            let mut buf = v.clone();
                            buf.reverse();
                            params.extend_from_slice(buf.as_slice());
                        }
                    }
                }
                ("forward_vlan", params)
            }
            (TableType::ArpIpv4, "rewrite") => {
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
            (TableType::NeighborIpv6, "rewrite") => {
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
            (TableType::PortMacAddress, "rewrite") => {
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
            (TableType::NatIngressIpv4, "forward_ipv4_to")
            | (TableType::NatIngressIpv6, "forward_ipv6_to")
            | (TableType::AttachedSubnetIpv4, "forward_to_v4")
            | (TableType::AttachedSubnetIpv6, "forward_to_v6") => {
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
            (_, x) => {
                error!(hdl.log, "ACTION NOT HANDLED {name} {x}");
                return Ok(());
            }
        };
        let action = action.to_string();
        trace!(hdl.log, "sending request to softnpu");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "action: {:#?}", action);
        trace!(hdl.log, "keyset_data:\n{:#?}", keyset_data);
        trace!(hdl.log, "parameter_data:\n{:#?}", parameter_data);

        let msg = ManagementRequest::TableAdd(TableAdd {
            table: table.to_string(),
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
        let Some(_table) = self.softnpu_table_name() else {
            return Ok(());
        };
        let name = self.type_.to_string();

        let match_data = key.key_to_ir().unwrap();
        let action_data = data.action_to_ir().unwrap();

        trace!(hdl.log, "entry_update called");
        trace!(hdl.log, "table: {name}");
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
        let Some(table) = self.softnpu_table_name() else {
            return Ok(());
        };
        let name = self.type_.to_string();
        let match_data = key.key_to_ir().unwrap();

        trace!(hdl.log, "entry_del called");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "match_data:\n{:#?}", match_data);

        let keyset_data = keyset_data(match_data.fields, self.type_);

        trace!(hdl.log, "sending request to softnpu");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "keyset_data:\n{:#?}", keyset_data);

        let msg = ManagementRequest::TableRemove(TableRemove {
            keyset_data,
            table: table.to_string(),
        });

        crate::softnpu::mgmt::write(msg, &hdl.mgmt_config);

        Ok(())
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        _hdl: &Handle,
        _from_hardware: bool,
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
fn keyset_data(match_data: Vec<MatchEntryField>, table: TableType) -> Vec<u8> {
    let mut keyset_data: Vec<u8> = Vec::new();
    for m in match_data {
        match m.value {
            // Exact match
            MatchEntryValue::Value(x) => {
                let mut data: Vec<u8> = Vec::new();
                match table {
                    TableType::ArpIpv4 => {
                        // "nexthop_ipv4" => bit<32>
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    TableType::NeighborIpv6 => {
                        // "nexthop_ipv4" => bit<128>
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    TableType::PortMacAddress => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..2]);
                    }
                    TableType::RouteIdxIpv4 => {
                        // "idx" => exact => bit<16>
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..2]);
                    }
                    TableType::NatIngressIpv4 => {
                        // "dst_addr" => hdr.ipv4.dst: exact => bit<32>
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    TableType::NatIngressIpv6 => {
                        // "dst_addr" => hdr.ipv6.dst: exact => bit<128>
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    TableType::PortAddrIpv6 => {
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
                    TableType::RouteIdxIpv4 | TableType::AttachedSubnetIpv4 => {
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
                    TableType::NatIngressIpv4 | TableType::NatIngressIpv6 => {
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
