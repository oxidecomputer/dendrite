// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::hash::Hash;

use slog::{error, trace};
use softnpu_lib::{ManagementRequest, TableAdd, TableRemove};

use crate::softnpu::Handle;

// Match field names used by the VLAN validity dispatch.
const VALID_FIELD: &str = "$valid";
const VLAN_ID_FIELD: &str = "vlan_id";

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
    /// Alternate sidecar-lite table for untagged entries
    /// ([`VALID_FIELD`] is false). x4c does not support `$valid` as
    /// a table key, so any table that matches on VLAN validity splits
    /// into tagged/untagged variants with per-entry dispatch.
    /// [`VLAN_ID_FIELD`] is stripped from the keyset for the untagged
    /// table.
    ///
    /// Currently used by multicast NAT (`nat_v4_mcast` /
    /// `nat_v4_mcast_untagged`, `nat_v6_mcast` /
    /// `nat_v6_mcast_untagged`).
    untagged_id: Option<String>,
    size: usize,
}

impl Table {
    /// Inspect the VLAN `$valid` match field to route entries to the
    /// tagged or untagged sidecar-lite table. Returns the primary ID
    /// for tables without a VLAN split.
    fn resolve_vlan_table_id(
        &self,
        fields: &[MatchEntryField],
    ) -> Option<&str> {
        if let Some(ref untagged) = self.untagged_id {
            let is_untagged = fields.iter().any(|f| {
                f.name == VALID_FIELD
                    && matches!(
                        &f.value,
                        MatchEntryValue::Value(ValueTypes::U64(0))
                    )
            });
            if is_untagged {
                return Some(untagged.as_str());
            }
        }
        self.id.as_deref()
    }

    /// Filter match fields for sidecar-lite serialization. Strips
    /// the `$valid` field (consumed by `resolve_vlan_table_id`) and
    /// strips `vlan_id` when targeting the untagged table.
    fn filter_vlan_match_fields(
        &self,
        fields: Vec<MatchEntryField>,
        target_table: &str,
    ) -> Vec<MatchEntryField> {
        if self.untagged_id.is_none() {
            return fields;
        }
        let is_untagged = self.untagged_id.as_deref() == Some(target_table);
        fields
            .into_iter()
            .filter(|f| {
                // $valid is consumed by dispatch, not serialized.
                if f.name == VALID_FIELD {
                    return false;
                }
                // Untagged table has no vlan_id key.
                if is_untagged && f.name == VLAN_ID_FIELD {
                    return false;
                }
                true
            })
            .collect()
    }
}

// sidecar-lite table names
// https://github.com/oxidecomputer/sidecar-lite/blob/main/p4/sidecar-lite.p4
const ROUTER_V4_RT: &str = "ingress.router.v4_route.rtr";
const ROUTER_V4_IDX: &str = "ingress.router.v4_idx.rtr";
const ROUTER_V6_RT: &str = "ingress.router.v6_route.rtr";
const ROUTER_V6_IDX: &str = "ingress.router.v6_idx.rtr";
const LOCAL_V6: &str = "ingress.local.local_v6";
const LOCAL_V4: &str = "ingress.local.local_v4";
const NAT_V4: &str = "ingress.nat.nat_v4";
const NAT_V6: &str = "ingress.nat.nat_v6";
const ATTACHED_SUBNET_V4: &str = "ingress.attached.attached_subnet_v4";
const ATTACHED_SUBNET_V6: &str = "ingress.attached.attached_subnet_v6";
const _NAT_ICMP_V6: &str = "ingress.nat.nat_icmp_v6";
const _NAT_ICMP_V4: &str = "ingress.nat.nat_icmp_v4";
const RESOLVER_V4: &str = "ingress.resolver.resolver_v4";
const RESOLVER_V6: &str = "ingress.resolver.resolver_v6";
const MAC_REWRITE: &str = "ingress.mac.mac_rewrite";
const _PROXY_ARP: &str = "ingress.pxarp.proxy_arp";

// sidecar-lite multicast table names
const MCAST_REPLICATION_V6: &str = "ingress.mcast.mcast_replication_v6";
const MCAST_SRC_FILTER_V4: &str = "ingress.mcast.mcast_source_filter_v4";
const MCAST_SRC_FILTER_V6: &str = "ingress.mcast.mcast_source_filter_v6";
const MCAST_NAT_V4: &str = "ingress.nat.nat_v4_mcast";
const MCAST_NAT_V6: &str = "ingress.nat.nat_v6_mcast";
const MCAST_NAT_V4_UNTAGGED: &str = "ingress.nat.nat_v4_mcast_untagged";
const MCAST_NAT_V6_UNTAGGED: &str = "ingress.nat.nat_v6_mcast_untagged";
const MCAST_EGRESS_DECAP: &str = "egress.tbl_decap_ports";
const MCAST_SRC_MAC: &str = "egress.mcast_src_mac";

// sidecar.p4 table names (what DPD programs)
// https://github.com/oxidecomputer/dendrite/blob/main/dpd/p4/sidecar.p4
const SWITCH_ADDR4: &str = "pipe.Ingress.filter.switch_ipv4_addr";
const SWITCH_ADDR6: &str = "pipe.Ingress.filter.switch_ipv6_addr";
const ROUTER4_LOOKUP_RT: &str =
    "pipe.Ingress.l3_router.Router4.lookup_idx.route";
const ROUTER4_LOOKUP_IDX: &str =
    "pipe.Ingress.l3_router.Router4.lookup_idx.lookup";
const ROUTER6_LOOKUP_RT: &str =
    "pipe.Ingress.l3_router.Router6.lookup_idx.route";
const ROUTER6_LOOKUP_IDX: &str =
    "pipe.Ingress.l3_router.Router6.lookup_idx.lookup";
const NDP: &str = "pipe.Ingress.l3_router.Ndp.tbl";
const ARP: &str = "pipe.Ingress.l3_router.Arp.tbl";
const DPD_MAC_REWRITE: &str = "pipe.Ingress.mac_rewrite.mac_rewrite";
const NAT_INGRESS4: &str = "pipe.Ingress.nat_ingress.ingress_ipv4";
const NAT_INGRESS6: &str = "pipe.Ingress.nat_ingress.ingress_ipv6";
const ATTACHED_SUBNET_INGRESS4: &str =
    "pipe.Ingress.attached_subnet_ingress.attached_subnets_v4";
const ATTACHED_SUBNET_INGRESS6: &str =
    "pipe.Ingress.attached_subnet_ingress.attached_subnets_v6";

// sidecar.p4 multicast table names
const MCAST_INGRESS_REPLICATION_IPV6: &str =
    "pipe.Ingress.mcast_ingress.mcast_replication_ipv6";
const MCAST_INGRESS_SRC_FILTER_IPV4: &str =
    "pipe.Ingress.mcast_ingress.mcast_source_filter_ipv4";
const MCAST_INGRESS_SRC_FILTER_IPV6: &str =
    "pipe.Ingress.mcast_ingress.mcast_source_filter_ipv6";
const MCAST_NAT_INGRESS4: &str = "pipe.Ingress.nat_ingress.ingress_ipv4_mcast";
const MCAST_NAT_INGRESS6: &str = "pipe.Ingress.nat_ingress.ingress_ipv6_mcast";
const MCAST_EGRESS_DECAP_PORTS: &str =
    "pipe.Egress.mcast_egress.tbl_decap_ports";
const MCAST_EGRESS_PORT_MAC: &str = "pipe.Egress.mac_rewrite.mac_rewrite";

const TABLE_SIZE: usize = 4096;

impl TableOps<Handle> for Table {
    fn new(hdl: &Handle, name: &str) -> AsicResult<Table> {
        // Mapping sidecar.p4 table names onto sidecar-lite.p4 equivalents.
        let (id, dpd_id, untagged_id) = match name {
            ROUTER4_LOOKUP_RT => (
                Some(ROUTER_V4_RT.into()),
                Some(ROUTER4_LOOKUP_RT.into()),
                None,
            ),
            ROUTER4_LOOKUP_IDX => (
                Some(ROUTER_V4_IDX.into()),
                Some(ROUTER4_LOOKUP_IDX.into()),
                None,
            ),
            ROUTER6_LOOKUP_RT => (
                Some(ROUTER_V6_RT.into()),
                Some(ROUTER6_LOOKUP_RT.into()),
                None,
            ),
            ROUTER6_LOOKUP_IDX => (
                Some(ROUTER_V6_IDX.into()),
                Some(ROUTER6_LOOKUP_IDX.into()),
                None,
            ),
            SWITCH_ADDR4 => {
                (Some(LOCAL_V4.into()), Some(SWITCH_ADDR4.into()), None)
            }
            SWITCH_ADDR6 => {
                (Some(LOCAL_V6.into()), Some(SWITCH_ADDR6.into()), None)
            }
            NDP => (Some(RESOLVER_V6.into()), Some(NDP.into()), None),
            ARP => (Some(RESOLVER_V4.into()), Some(ARP.into()), None),
            DPD_MAC_REWRITE => {
                (Some(MAC_REWRITE.into()), Some(DPD_MAC_REWRITE.into()), None)
            }
            NAT_INGRESS4 => {
                (Some(NAT_V4.into()), Some(NAT_INGRESS4.into()), None)
            }
            NAT_INGRESS6 => {
                (Some(NAT_V6.into()), Some(NAT_INGRESS6.into()), None)
            }
            ATTACHED_SUBNET_INGRESS4 => (
                Some(ATTACHED_SUBNET_V4.into()),
                Some(ATTACHED_SUBNET_INGRESS4.into()),
                None,
            ),
            ATTACHED_SUBNET_INGRESS6 => (
                Some(ATTACHED_SUBNET_V6.into()),
                Some(ATTACHED_SUBNET_INGRESS6.into()),
                None,
            ),
            MCAST_NAT_INGRESS4 => (
                Some(MCAST_NAT_V4.into()),
                Some(MCAST_NAT_INGRESS4.into()),
                Some(MCAST_NAT_V4_UNTAGGED.into()),
            ),
            MCAST_NAT_INGRESS6 => (
                Some(MCAST_NAT_V6.into()),
                Some(MCAST_NAT_INGRESS6.into()),
                Some(MCAST_NAT_V6_UNTAGGED.into()),
            ),
            MCAST_INGRESS_REPLICATION_IPV6 => (
                Some(MCAST_REPLICATION_V6.into()),
                Some(MCAST_INGRESS_REPLICATION_IPV6.into()),
                None,
            ),
            MCAST_INGRESS_SRC_FILTER_IPV4 => (
                Some(MCAST_SRC_FILTER_V4.into()),
                Some(MCAST_INGRESS_SRC_FILTER_IPV4.into()),
                None,
            ),
            MCAST_INGRESS_SRC_FILTER_IPV6 => (
                Some(MCAST_SRC_FILTER_V6.into()),
                Some(MCAST_INGRESS_SRC_FILTER_IPV6.into()),
                None,
            ),
            MCAST_EGRESS_DECAP_PORTS => (
                Some(MCAST_EGRESS_DECAP.into()),
                Some(MCAST_EGRESS_DECAP_PORTS.into()),
                None,
            ),
            MCAST_EGRESS_PORT_MAC => (
                Some(MCAST_SRC_MAC.into()),
                Some(MCAST_EGRESS_PORT_MAC.into()),
                None,
            ),
            x => {
                error!(hdl.log, "TABLE NOT HANDLED {x}");
                (None, None, None)
            }
        };

        Ok(Table { id, dpd_id, untagged_id, size: TABLE_SIZE })
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
        let dpd_table = match &self.dpd_id {
            None => return Ok(()),
            Some(id) => id.clone(),
        };

        let match_data = key.key_to_ir().unwrap();
        let action_data = data.action_to_ir().unwrap();

        let table = match self.resolve_vlan_table_id(&match_data.fields) {
            None => return Ok(()),
            Some(id) => id.to_string(),
        };
        let fields = self.filter_vlan_match_fields(match_data.fields, &table);

        trace!(hdl.log, "entry_add called");
        trace!(hdl.log, "table: {}", table);
        trace!(hdl.log, "match_data (filtered): {fields:#?}");
        trace!(hdl.log, "action_data:\n{:#?}", action_data);

        let keyset_data = keyset_data(fields, &table);

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
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {dpd_table}::index {x}"
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
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {dpd_table}::forward {x}"
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
            (ROUTER4_LOOKUP_RT, "forward_v6") => {
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
                                        "unexpected parameter: {dpd_table}::forward {x}"
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
                                    error!(
                                        hdl.log,
                                        "unexpected parameter: {dpd_table}::forward_vlan {x}"
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
            (ROUTER4_LOOKUP_RT, "forward_vlan_v6") => {
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
                                        "unexpected parameter: {dpd_table}::forward_vlan {x}"
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
            (ROUTER6_LOOKUP_IDX, "index") => {
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
                                        "unexpected parameter: {dpd_table}::index {x}"
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
            (ROUTER6_LOOKUP_RT, "forward") => {
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
                                        "unexpected parameter: {dpd_table}::forward {x}"
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
            (ROUTER6_LOOKUP_RT, "forward_vlan") => {
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
                                        "unexpected parameter: {dpd_table}::forward_vlan {x}"
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
            (NAT_INGRESS4, "forward_ipv4_to")
            | (NAT_INGRESS6, "forward_ipv6_to")
            | (MCAST_NAT_INGRESS4, "mcast_forward_ipv4_to")
            | (MCAST_NAT_INGRESS6, "mcast_forward_ipv6_to")
            | (ATTACHED_SUBNET_INGRESS4, "forward_to_v4")
            | (ATTACHED_SUBNET_INGRESS6, "forward_to_v6") => {
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
            // Multicast source filters: no action parameters.
            #[cfg(feature = "multicast")]
            (MCAST_INGRESS_SRC_FILTER_IPV4, "allow_source_mcastv4")
            | (MCAST_INGRESS_SRC_FILTER_IPV6, "allow_source_mcastv6") => {
                ("allow_source", Vec::new())
            }
            // Multicast replication: translate group IDs to port bitmaps.
            //
            // DPD sends configure_mcastv6 with (mcast_grp_a, mcast_grp_b,
            // rid, level1_excl_id, level2_excl_id). Sidecar-lite expects
            // set_port_bitmap with (external, underlay, rid). We look up
            // the group membership in McGroupData and build the bitmaps.
            #[cfg(feature = "multicast")]
            (MCAST_INGRESS_REPLICATION_IPV6, "configure_mcastv6") => {
                let mut external_grp: u16 = 0;
                let mut underlay_grp: u16 = 0;
                let mut rid: u16 = 0;
                for arg in action_data.args.iter() {
                    if let ValueTypes::U64(v) = &arg.value {
                        match arg.name.as_str() {
                            "mcast_grp_a" => external_grp = *v as u16,
                            "mcast_grp_b" => underlay_grp = *v as u16,
                            "rid" => rid = *v as u16,
                            _ => {}
                        }
                    }
                }

                let mc_data = hdl.mc_data.lock().unwrap();
                let external_bitmap = mc_data.port_bitmap(external_grp);
                let underlay_bitmap = mc_data.port_bitmap(underlay_grp);
                drop(mc_data);

                let mut params = Vec::new();
                params.extend_from_slice(&external_bitmap.to_le_bytes());
                params.extend_from_slice(&underlay_bitmap.to_le_bytes());
                params.extend_from_slice(&rid.to_le_bytes());
                ("set_port_bitmap", params)
            }
            // Multicast egress decap: pack 8x32-bit bitmap into 128 bits.
            //
            // DPD sends set_decap_ports with 8x32-bit bitmap fields
            // keyed on RID. Sidecar-lite expects a single 128-bit
            // bitmap. We pack the low 4 chunks (ports 0-127) into a
            // u128 for sidecar-lite's bit<128> decap_bitmap field.
            #[cfg(feature = "multicast")]
            (MCAST_EGRESS_DECAP_PORTS, "set_decap_ports") => {
                ("set_decap_ports", pack_decap_bitmap(&action_data))
            }
            #[cfg(feature = "multicast")]
            (MCAST_EGRESS_DECAP_PORTS, "set_decap_ports_and_vlan") => {
                let mut params = pack_decap_bitmap(&action_data);
                let mut vlan_id: u16 = 0;
                for arg in action_data.args.iter() {
                    if let ValueTypes::U64(v) = &arg.value
                        && arg.name.as_str() == "vlan_id"
                    {
                        vlan_id = *v as u16;
                    }
                }
                params.extend_from_slice(&vlan_id.to_le_bytes());
                ("set_decap_ports_and_vlan", params)
            }
            // Multicast egress MAC rewrite.
            #[cfg(feature = "multicast")]
            (MCAST_EGRESS_PORT_MAC, "rewrite") => {
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
                ("rewrite_src_mac", params)
            }
            (tbl, x) => {
                error!(hdl.log, "ACTION NOT HANDLED {tbl} {x}");
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

    fn entry_update<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        // Softnpu does not currently support in-place updates.
        // Delete the old entry and re-add with the new action data.
        // Both operations are currently fire-and-forget over the
        // management channel, so neither can fail from DPD's
        // perspective.
        self.entry_del(hdl, key)?;
        self.entry_add(hdl, key, data)
    }

    fn entry_del<M: MatchParse>(
        &self,
        hdl: &Handle,
        key: &M,
    ) -> AsicResult<()> {
        let match_data = key.key_to_ir().unwrap();

        let table = match self.resolve_vlan_table_id(&match_data.fields) {
            None => return Ok(()),
            Some(id) => id.to_string(),
        };
        let fields = self.filter_vlan_match_fields(match_data.fields, &table);

        trace!(hdl.log, "entry_del called");
        trace!(hdl.log, "table: {}", table);
        trace!(hdl.log, "match_data (filtered): {fields:#?}");

        let keyset_data = keyset_data(fields, &table);

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

/// Pack DPD's 8x32-bit decap port bitmap into a byte vector for
/// sidecar-lite's decap_bitmap field. All 8 chunks are serialized
/// little-endian and the P4 field width determines how many are consumed.
#[cfg(feature = "multicast")]
fn pack_decap_bitmap(args: &aal::ActionData) -> Vec<u8> {
    let mut chunks = [0u32; 8];
    for arg in &args.args {
        if let ValueTypes::U64(v) = &arg.value {
            match arg.name.as_str() {
                "ports_0" => chunks[0] = *v as u32,
                "ports_1" => chunks[1] = *v as u32,
                "ports_2" => chunks[2] = *v as u32,
                "ports_3" => chunks[3] = *v as u32,
                "ports_4" => chunks[4] = *v as u32,
                "ports_5" => chunks[5] = *v as u32,
                "ports_6" => chunks[6] = *v as u32,
                "ports_7" => chunks[7] = *v as u32,
                _ => {}
            }
        }
    }
    chunks.iter().flat_map(|c| c.to_le_bytes()).collect()
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
                        // "nexthop_ipv6" => bit<128>
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
                    NAT_V6 => {
                        // "dst_addr" => hdr.ipv6.dst: exact => bit<128>
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    LOCAL_V6 => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // mcast replication: hdr.ipv6.dst => bit<128>
                    MCAST_REPLICATION_V6 => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // mcast source filter exact keys: inner dst => bit<32>
                    // or bit<128>. The lpm src key is handled in the Lpm arm.
                    MCAST_SRC_FILTER_V4 => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    MCAST_SRC_FILTER_V6 => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // mcast NAT: dst (bit<32> or bit<128>) and optionally
                    // vlan_id (bit<12>) after VLAN field filtering.
                    MCAST_NAT_V4 | MCAST_NAT_V4_UNTAGGED => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    MCAST_NAT_V6 | MCAST_NAT_V6_UNTAGGED => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // mcast egress: egress.port => bit<16>
                    MCAST_EGRESS_DECAP | MCAST_SRC_MAC => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..2]);
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
                    ROUTER_V4_IDX | ATTACHED_SUBNET_V4
                    | MCAST_SRC_FILTER_V4 => {
                        // prefix for longest prefix match operation
                        // "dst_addr" / "src_addr" => bit<32> lpm
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
                    NAT_V4 | NAT_V6 => {
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
