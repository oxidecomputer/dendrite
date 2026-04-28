// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::hash::Hash;

use slog::{error, trace};
use softnpu_lib::{ManagementRequest, TableAdd, TableRemove};

use crate::softnpu::Handle;
use aal::{
    ActionParse, AsicError, AsicResult, CounterData, MatchEntryField,
    MatchEntryValue, MatchParse, TableOps, ValueTypes,
};
use common::table::TableType;

// Match field names used by the VLAN validity dispatch.
#[cfg(feature = "multicast")]
const VALID_FIELD: &str = "$valid";
#[cfg(feature = "multicast")]
const VLAN_ID_FIELD: &str = "vlan_id";

// Sidecar-lite untagged table names for VLAN dispatch.
#[cfg(feature = "multicast")]
const MCAST_NAT_V4_UNTAGGED: &str = "ingress.nat.nat_v4_mcast_untagged";
#[cfg(feature = "multicast")]
const MCAST_NAT_V6_UNTAGGED: &str = "ingress.nat.nat_v6_mcast_untagged";

/// Represents a handle to a SoftNPU ASIC table. The `type_` member identifies
/// the table and `softnpu_table_name()` maps it to the corresponding
/// sidecar-lite.p4 path.
pub struct Table {
    type_: TableType,
    implemented: bool,
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
    untagged_id: Option<&'static str>,
    size: usize,
}

impl Table {
    /// Return the sidecar-lite table name for this table, or `None` if the
    /// table is not implemented in the softnpu backend.
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
                #[cfg(feature = "multicast")]
                TableType::McastIpv6 => {
                    Some("ingress.mcast.mcast_replication_v6")
                }
                #[cfg(feature = "multicast")]
                TableType::McastIpv4SrcFilter => {
                    Some("ingress.mcast.mcast_source_filter_v4")
                }
                #[cfg(feature = "multicast")]
                TableType::McastIpv6SrcFilter => {
                    Some("ingress.mcast.mcast_source_filter_v6")
                }
                #[cfg(feature = "multicast")]
                TableType::NatIngressIpv4Mcast => {
                    Some("ingress.nat.nat_v4_mcast")
                }
                #[cfg(feature = "multicast")]
                TableType::NatIngressIpv6Mcast => {
                    Some("ingress.nat.nat_v6_mcast")
                }
                #[cfg(feature = "multicast")]
                TableType::McastEgressDecapPorts => {
                    Some("egress.tbl_decap_ports")
                }
                #[cfg(feature = "multicast")]
                TableType::PortMacAddressMcast => Some("egress.mcast_src_mac"),
                _ => panic!(
                    "implemented table {} has no softnpu table",
                    self.type_
                ),
            }
        } else {
            None
        }
    }

    /// Inspect the VLAN `$valid` match field to route entries to the
    /// tagged or untagged sidecar-lite table. Returns the primary table
    /// name for tables without a VLAN split.
    #[cfg(feature = "multicast")]
    fn resolve_vlan_table_id(
        &self,
        fields: &[MatchEntryField],
    ) -> Option<&str> {
        if let Some(untagged) = self.untagged_id {
            let is_untagged = fields.iter().any(|f| {
                f.name == VALID_FIELD
                    && matches!(
                        &f.value,
                        MatchEntryValue::Value(ValueTypes::U64(0))
                    )
            });
            if is_untagged {
                return Some(untagged);
            }
        }
        self.softnpu_table_name()
    }

    /// Filter match fields for sidecar-lite serialization. Strips
    /// the `$valid` field (consumed by `resolve_vlan_table_id`) and
    /// strips `vlan_id` when targeting the untagged table.
    #[cfg(feature = "multicast")]
    fn filter_vlan_match_fields(
        &self,
        fields: Vec<MatchEntryField>,
        target_table: &str,
    ) -> Vec<MatchEntryField> {
        if self.untagged_id.is_none() {
            return fields;
        }
        let is_untagged = self.untagged_id == Some(target_table);
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

// All tables are defined to be 4096 entries deep.
const TABLE_SIZE: usize = 4096;

impl TableOps<Handle> for Table {
    fn new(hdl: &Handle, type_: TableType) -> AsicResult<Table> {
        // Mapping sidecar.p4 table types onto simplified sidecar-lite.p4
        // equivalents.
        let (implemented, untagged_id) = match type_ {
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
            | TableType::AttachedSubnetIpv6 => (true, None),
            #[cfg(feature = "multicast")]
            TableType::McastIpv6
            | TableType::McastIpv4SrcFilter
            | TableType::McastIpv6SrcFilter
            | TableType::McastEgressDecapPorts
            | TableType::PortMacAddressMcast => (true, None),
            #[cfg(feature = "multicast")]
            TableType::NatIngressIpv4Mcast => {
                (true, Some(MCAST_NAT_V4_UNTAGGED))
            }
            #[cfg(feature = "multicast")]
            TableType::NatIngressIpv6Mcast => {
                (true, Some(MCAST_NAT_V6_UNTAGGED))
            }
            x => {
                error!(hdl.log, "table not handled: {x}");
                (false, None)
            }
        };

        Ok(Table { type_, implemented, untagged_id, size: TABLE_SIZE })
    }

    fn size(&self) -> usize {
        self.size
    }

    fn clear(&self, _hdl: &Handle) -> AsicResult<()> {
        // TODO: implement in softnpu
        Ok(())
    }

    fn entry_add<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        let Some(default_table) = self.softnpu_table_name() else {
            return Ok(());
        };
        let name = self.type_.to_string();
        let match_data = key.key_to_ir().unwrap();
        let action_data = data.action_to_ir().unwrap();

        // For tables with VLAN dispatch, resolve which sidecar-lite table
        // to target and filter out synthetic match fields.
        #[cfg(feature = "multicast")]
        let (table, fields) = {
            let resolved = self
                .resolve_vlan_table_id(&match_data.fields)
                .unwrap_or(default_table);
            let filtered =
                self.filter_vlan_match_fields(match_data.fields, resolved);
            (resolved.to_string(), filtered)
        };
        #[cfg(not(feature = "multicast"))]
        let (table, fields) = (default_table.to_string(), match_data.fields);

        trace!(hdl.log, "entry_add called");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "match_data (filtered): {fields:#?}");
        trace!(hdl.log, "action_data:\n{:#?}", action_data);

        let keyset_data = keyset_data(fields, self.type_, &table);

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
                forward_to_sled_params(hdl, &name, action_data)?
            }
            #[cfg(feature = "multicast")]
            (TableType::NatIngressIpv4Mcast, "mcast_forward_ipv4_to")
            | (TableType::NatIngressIpv6Mcast, "mcast_forward_ipv6_to") => {
                forward_to_sled_params(hdl, &name, action_data)?
            }
            // Multicast source filters: no action parameters.
            #[cfg(feature = "multicast")]
            (TableType::McastIpv4SrcFilter, "allow_source_mcastv4")
            | (TableType::McastIpv6SrcFilter, "allow_source_mcastv6") => {
                ("allow_source", Vec::new())
            }
            // Multicast replication: translate group IDs to port bitmaps.
            //
            // DPD sends configure_mcastv6 with (mcast_grp_a, mcast_grp_b,
            // rid, level1_excl_id, level2_excl_id). Sidecar-lite expects
            // set_port_bitmap with (external, underlay, rid). We look up
            // the group membership in McGroupData and build the bitmaps.
            #[cfg(feature = "multicast")]
            (TableType::McastIpv6, "configure_mcastv6") => {
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
            (TableType::McastEgressDecapPorts, "set_decap_ports") => {
                ("set_decap_ports", pack_decap_bitmap(&action_data))
            }
            #[cfg(feature = "multicast")]
            (TableType::McastEgressDecapPorts, "set_decap_ports_and_vlan") => {
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
            (TableType::PortMacAddressMcast, "rewrite") => {
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
            (_, x) => {
                error!(hdl.log, "action not handled: {name} {x}");
                return Ok(());
            }
        };
        let action = action.to_string();
        trace!(hdl.log, "sending request to softnpu");
        trace!(hdl.log, "table: {table}");
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
        let Some(default_table) = self.softnpu_table_name() else {
            return Ok(());
        };
        let name = self.type_.to_string();
        let match_data = key.key_to_ir().unwrap();

        #[cfg(feature = "multicast")]
        let (table, fields) = {
            let resolved = self
                .resolve_vlan_table_id(&match_data.fields)
                .unwrap_or(default_table);
            let filtered =
                self.filter_vlan_match_fields(match_data.fields, resolved);
            (resolved.to_string(), filtered)
        };
        #[cfg(not(feature = "multicast"))]
        let (table, fields) = (default_table.to_string(), match_data.fields);

        trace!(hdl.log, "entry_del called");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "match_data (filtered): {fields:#?}");

        let keyset_data = keyset_data(fields, self.type_, &table);

        trace!(hdl.log, "sending request to softnpu");
        trace!(hdl.log, "table: {table}");
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

/// Extract the forward_to_sled action parameters shared by unicast and
/// multicast NAT/attached-subnet actions. Returns the sidecar-lite action
/// name and serialized parameter bytes.
fn forward_to_sled_params(
    hdl: &Handle,
    name: &str,
    action_data: aal::ActionData,
) -> AsicResult<(&'static str, Vec<u8>)> {
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
                        return Ok(("forward_to_sled", Vec::new()));
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
                        return Ok(("forward_to_sled", Vec::new()));
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
                        return Ok(("forward_to_sled", Vec::new()));
                    }
                }
                mac.extend_from_slice(&data[0..6])
            }
            _ => {
                error!(hdl.log, "unknown argument: {} in {name}", arg.name);
                return Ok(("forward_to_sled", Vec::new()));
            }
        }
    }
    let mut params = Vec::new();
    // Arguments currently don't arrive in the correct order,
    // so we order them manually.
    params.extend_from_slice(target.as_slice());
    params.extend_from_slice(vni.as_slice());
    params.extend_from_slice(mac.as_slice());
    Ok(("forward_to_sled", params))
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
/// in a data structure with the correct length. The `table_name`
/// parameter is the resolved sidecar-lite table name, which may
/// differ from the primary name for VLAN-dispatched tables.
fn keyset_data(
    match_data: Vec<MatchEntryField>,
    table: TableType,
    table_name: &str,
) -> Vec<u8> {
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
                        // "nexthop_ipv6" => bit<128>
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
                    // Multicast replication: hdr.ipv6.dst => bit<128>
                    #[cfg(feature = "multicast")]
                    TableType::McastIpv6 => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // Multicast source filter exact keys: inner dst =>
                    // bit<32> or bit<128>. The LPM src key is handled
                    // in the Lpm arm.
                    #[cfg(feature = "multicast")]
                    TableType::McastIpv4SrcFilter => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    #[cfg(feature = "multicast")]
                    TableType::McastIpv6SrcFilter => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // Multicast NAT: dst (bit<32> or bit<128>) and
                    // optionally vlan_id (bit<12>) after VLAN field
                    // filtering. The resolved table_name determines
                    // whether the tagged or untagged variant is used;
                    // the keyset width is the same for both.
                    #[cfg(feature = "multicast")]
                    TableType::NatIngressIpv4Mcast => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    #[cfg(feature = "multicast")]
                    TableType::NatIngressIpv6Mcast => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // Multicast egress tables: port => bit<16>
                    #[cfg(feature = "multicast")]
                    TableType::McastEgressDecapPorts
                    | TableType::PortMacAddressMcast => {
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
                #[allow(unused_mut)]
                let mut handled = false;
                match table {
                    TableType::RouteIdxIpv4 | TableType::AttachedSubnetIpv4 => {
                        // prefix for longest prefix match operation
                        // "dst_addr" => hdr.ipv4.dst: lpm => bit<32>
                        serialize_value_type_be(&x.prefix, &mut data);
                        keyset_data.extend_from_slice(&data[data.len() - 4..]);
                        // prefix length for longest prefix match operation
                        keyset_data.push(x.len as u8);
                        handled = true;
                    }
                    #[cfg(feature = "multicast")]
                    TableType::McastIpv4SrcFilter => {
                        // "src_addr" => bit<32> lpm
                        serialize_value_type_be(&x.prefix, &mut data);
                        keyset_data.extend_from_slice(&data[data.len() - 4..]);
                        keyset_data.push(x.len as u8);
                        handled = true;
                    }
                    _ => {}
                }
                if !handled {
                    serialize_value_type_be(&x.prefix, &mut keyset_data);
                    keyset_data.push(x.len as u8);
                }
            }
            // Ranges (i.e. port ranges)
            MatchEntryValue::Range(x) => {
                match table {
                    TableType::NatIngressIpv4 | TableType::NatIngressIpv6 => {
                        // "l4_dst_port" => ingress.nat_id: range => bit<16>
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
    let _ = table_name;
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
