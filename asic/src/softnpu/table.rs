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

/// Represents a handle to a SoftNPU ASIC table.
///
/// The `type_` member identifies the table and `softnpu_table_name()`
/// maps it to the corresponding path in sidecar-lite.p4.
pub struct Table {
    type_: TableType,
    implemented: bool,
    size: usize,
}

impl Table {
    /// Return the sidecar-lite table name for this table, or `None` if the
    /// table is not implemented in the SoftNPU backend.
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
                TableType::McastIpv6 => {
                    Some(crate::softnpu::mcast::MCAST_REPLICATION_V6_TABLE)
                }
                TableType::McastIpv4SrcFilter => {
                    Some("ingress.mcast.mcast_source_filter_v4")
                }
                TableType::McastIpv6SrcFilter => {
                    Some("ingress.mcast.mcast_source_filter_v6")
                }
                TableType::NatIngressIpv4Mcast => {
                    Some("ingress.nat.nat_v4_mcast")
                }
                TableType::NatIngressIpv6Mcast => {
                    Some("ingress.nat.nat_v6_mcast")
                }
                TableType::McastEgressDecapPorts => {
                    Some("egress.tbl_decap_ports")
                }
                TableType::PortMacAddressMcast => Some("egress.mcast_src_mac"),
                TableType::McastEgressPortMapping => {
                    Some("egress.asic_id_to_port")
                }
                _ => panic!(
                    "implemented table {} has no softnpu table",
                    self.type_
                ),
            }
        } else {
            None
        }
    }

    /// Translate a `configure_mcastv6` request into a sidecar-lite
    /// `set_port_bitmap` addition, holding the replication tracking lock across
    /// the entire op.
    ///
    /// DPD sends `(mcast_grp_a, mcast_grp_b, rid, level1_excl_id,
    /// level2_excl_id)`, while sidecar-lite expects `(external, underlay, rid)`,
    /// from `McGroupData` membership. On SoftNPU, the bitmap is a write-time
    /// snapshot, unlike the live replication engine on the sidecar, allowing
    /// recorded group references to recompute later membership changes to the
    /// entry.
    ///
    /// The lock is held from the bitmap snapshot through to the table write on
    /// a concurrent membership refresh, which takes the same lock across its
    /// own rewrite (see @ `mc_port_add`).
    ///
    /// This cannot interleave a newer bitmap that this older snapshot would
    /// then overwrite.
    fn mcast_replication_add(
        &self,
        hdl: &Handle,
        table: String,
        keyset_data: Vec<u8>,
        action_data: &aal::ActionData,
    ) -> AsicResult<()> {
        let action = &action_data.action;
        let external_grp = arg_u16(hdl, action_data, action, "mcast_grp_a")?;
        let underlay_grp = arg_u16(hdl, action_data, action, "mcast_grp_b")?;
        let rid = arg_u16(hdl, action_data, action, "rid")?;

        let mut mc_data = hdl.mc_data.lock().unwrap();
        let external_bitmap = mc_data.port_bitmap(external_grp);
        let underlay_bitmap = mc_data.port_bitmap(underlay_grp);
        mc_data.record_repl_entry(
            keyset_data.clone(),
            external_grp,
            underlay_grp,
            rid,
        );

        let parameter_data = [
            external_bitmap.to_le_bytes().as_slice(),
            underlay_bitmap.to_le_bytes().as_slice(),
            rid.to_le_bytes().as_slice(),
        ]
        .concat();

        // Logged at debug for the initial bitmap snapshot to be visible in a
        // release build.
        slog::debug!(
            hdl.log,
            "mcast replication add: external_grp={external_grp} \
             underlay_grp={underlay_grp} external_bitmap={external_bitmap:#x} \
             underlay_bitmap={underlay_bitmap:#x} rid={rid}"
        );
        trace!(hdl.log, "table: {table}");
        trace!(hdl.log, "keyset_data:\n{keyset_data:#?}");
        trace!(hdl.log, "parameter_data:\n{parameter_data:#?}");

        add_entry(
            hdl,
            table,
            crate::softnpu::mcast::SET_PORT_BITMAP_ACTION.to_string(),
            keyset_data,
            parameter_data,
        );

        Ok(())
    }
}

fn add_entry(
    hdl: &Handle,
    table: String,
    action: String,
    keyset_data: Vec<u8>,
    parameter_data: Vec<u8>,
) {
    let add = ManagementRequest::TableAdd(TableAdd {
        table,
        action,
        keyset_data,
        parameter_data,
    });
    crate::softnpu::mgmt::write(add, &hdl.mgmt_config);
}

// All tables are defined to be 4096 entries deep.
const TABLE_SIZE: usize = 4096;

impl TableOps<Handle> for Table {
    fn new(hdl: &Handle, type_: TableType) -> AsicResult<Table> {
        // Mapping sidecar.p4 table types onto simplified sidecar-lite.p4
        // equivalents.
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
            | TableType::AttachedSubnetIpv6
            | TableType::McastIpv6
            | TableType::McastIpv4SrcFilter
            | TableType::McastIpv6SrcFilter
            | TableType::McastEgressDecapPorts
            | TableType::McastEgressPortMapping
            | TableType::PortMacAddressMcast
            | TableType::NatIngressIpv4Mcast
            | TableType::NatIngressIpv6Mcast => true,
            x => {
                error!(hdl.log, "table not handled: {x}");
                false
            }
        };

        Ok(Table { type_, implemented, size: TABLE_SIZE })
    }

    fn size(&self) -> usize {
        self.size
    }

    fn clear(&self, hdl: &Handle) -> AsicResult<()> {
        // TODO: the management protocol has no clear message (yet).
        //
        // For now, only the multicast replication entries tracked in `mc_data`
        // get removed here, one `TableRemove` per keyset, and every other
        // table retains its entries.
        //
        // Send a `TableClear` once softnpu and propolis support one (the
        // pipeline side landed in oxidecomputer/p4#278).
        if self.type_ != TableType::McastIpv6 {
            return Ok(());
        }

        let Some(table) = self.softnpu_table_name() else {
            return Ok(());
        };

        let mut mc_data = hdl.mc_data.lock().unwrap();
        for keyset_data in mc_data.repl_keysets() {
            let remove = ManagementRequest::TableRemove(TableRemove {
                table: table.to_string(),
                keyset_data: keyset_data.to_vec(),
            });
            crate::softnpu::mgmt::write(remove, &hdl.mgmt_config);
        }
        mc_data.clear_repl_entries();
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
        let table = table.to_string();
        let name = self.type_.to_string();
        let match_data = key.key_to_ir().unwrap();
        let action_data = data.action_to_ir().unwrap();
        let fields = match_data.fields;

        trace!(hdl.log, "entry_add called");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "match_data: {fields:#?}");
        trace!(hdl.log, "action_data:\n{:#?}", action_data);

        let keyset_data = keyset_data(fields, self.type_);

        // Multicast replication is handled ahead of the generic match so the
        // replication tracking lock can be held from the bitmap snapshot through
        // to the table write.
        if let (TableType::McastIpv6, "configure_mcastv6") =
            (self.type_, action_data.action.as_str())
        {
            return self.mcast_replication_add(
                hdl,
                table,
                keyset_data,
                &action_data,
            );
        }

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
            (TableType::NatIngressIpv4Mcast, "mcast_forward_ipv4_to")
            | (TableType::NatIngressIpv6Mcast, "mcast_forward_ipv6_to") => {
                forward_to_sled_params(hdl, &name, action_data)?
            }
            // Multicast source filters: no action parameters.
            (TableType::McastIpv4SrcFilter, "allow_source_mcastv4")
            | (TableType::McastIpv6SrcFilter, "allow_source_mcastv6") => {
                ("allow_source", Vec::new())
            }
            // Multicast egress decap: pack 8x32-bit bitmap into 128 bits.
            //
            // DPD sends set_decap_ports with 8x32-bit bitmap fields
            // keyed on the RID. Sidecar-lite expects a single 128-bit
            // bitmap. We pack the low 4 chunks (ports 0-127) into a
            // u128 for sidecar-lite's bit<128> decap_bitmap field.
            (TableType::McastEgressDecapPorts, "set_decap_ports") => {
                ("set_decap_ports", pack_decap_bitmap(&action_data))
            }
            (TableType::McastEgressDecapPorts, "set_decap_ports_and_vlan") => {
                let mut params = pack_decap_bitmap(&action_data);
                let vlan_id = arg_u16(hdl, &action_data, &name, "vlan_id")?;
                params.extend_from_slice(&vlan_id.to_le_bytes());
                ("set_decap_ports_and_vlan", params)
            }
            // Multicast egress MAC rewrite.
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
            (TableType::McastEgressPortMapping, "set_port_number") => {
                ("set_port_number", vec![port_number_param(&action_data)?])
            }
            // Sidecar-lite's resolvers support drop (by default).
            (TableType::ArpIpv4, "drop")
            | (TableType::NeighborIpv6, "drop") => ("drop", Vec::new()),
            // The local_v4/local_v6 tables have no drop action and dpd programs
            // dropv4/dropv6 during port IP setup.
            (TableType::PortAddrIpv4, "dropv4")
            | (TableType::PortAddrIpv6, "dropv6") => return Ok(()),
            (_, x) => {
                error!(hdl.log, "action not handled: {name} {x}");
                return Err(AsicError::InvalidArg(format!(
                    "{name}: action {x} not handled by the softnpu backend"
                )));
            }
        };
        let action = action.to_string();
        trace!(hdl.log, "sending request to softnpu");
        trace!(hdl.log, "table: {table}");
        trace!(hdl.log, "action: {:#?}", action);
        trace!(hdl.log, "keyset_data:\n{:#?}", keyset_data);
        trace!(hdl.log, "parameter_data:\n{:#?}", parameter_data);

        add_entry(hdl, table, action, keyset_data, parameter_data);

        Ok(())
    }

    fn entry_update<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        // SoftNPU does not currently support in-place updates. The key is
        // removed via `entry_del` and added back with the new action data.
        //
        // Note: this is not an atomic op, as a lookup between the two messages
        // could miss the entry, and mgmt IO failures panic in mgmt::write
        // rather than surface errors.
        self.entry_del(hdl, key)?;
        self.entry_add(hdl, key, data)
    }

    fn entry_del<M: MatchParse>(
        &self,
        hdl: &Handle,
        key: &M,
    ) -> AsicResult<()> {
        let Some(table) = self.softnpu_table_name() else {
            return Ok(());
        };
        let table = table.to_string();
        let name = self.type_.to_string();
        let match_data = key.key_to_ir().unwrap();
        let fields = match_data.fields;

        trace!(hdl.log, "entry_del called");
        trace!(hdl.log, "table: {name}");
        trace!(hdl.log, "match_data: {fields:#?}");

        let keyset_data = keyset_data(fields, self.type_);

        // Stop tracking a replication entry once it leaves the pipeline so a
        // later membership change does not resurrect a stale bitmap.
        if self.type_ == TableType::McastIpv6 {
            hdl.mc_data.lock().unwrap().forget_repl_entry(&keyset_data);
        }

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

/// Extract the `forward_to_sled` action parameters shared by unicast and
/// multicast NAT/attached-subnet actions.
///
/// Returns the sidecar-lite action name and serialized parameter bytes.
fn forward_to_sled_params(
    hdl: &Handle,
    name: &str,
    action_data: aal::ActionData,
) -> AsicResult<(&'static str, Vec<u8>)> {
    for arg in &action_data.args {
        if !matches!(arg.name.as_str(), "target" | "vni" | "inner_mac") {
            error!(hdl.log, "unknown argument: {} in {name}", arg.name);
            return Err(AsicError::InvalidArg(format!(
                "{name}: unknown argument {}",
                arg.name
            )));
        }
    }

    let target = arg_ptr(hdl, &action_data, name, "target")?;
    let vni = arg_u64(hdl, &action_data, name, "vni")?;
    let mac = arg_u64(hdl, &action_data, name, "inner_mac")?;

    let Some(start) = target.len().checked_sub(16) else {
        return Err(AsicError::InvalidArg(format!(
            "{name}: target is {} bytes, expected at least 16",
            target.len()
        )));
    };

    let mut params = Vec::new();
    let mut target_bytes = target[start..].to_vec();
    target_bytes.reverse();
    params.extend_from_slice(&target_bytes);
    params.extend_from_slice(&vni.to_le_bytes()[0..3]);
    params.extend_from_slice(&mac.to_le_bytes()[0..6]);
    Ok(("forward_to_sled", params))
}

fn find_arg<'a>(
    action_data: &'a aal::ActionData,
    action: &str,
    arg_name: &str,
) -> AsicResult<&'a ValueTypes> {
    action_data
        .args
        .iter()
        .find(|arg| arg.name == arg_name)
        .map(|arg| &arg.value)
        .ok_or_else(|| {
            AsicError::InvalidArg(format!(
                "{action}: missing argument {arg_name}"
            ))
        })
}

fn arg_u64(
    hdl: &Handle,
    action_data: &aal::ActionData,
    action: &str,
    arg_name: &str,
) -> AsicResult<u64> {
    match find_arg(action_data, action, arg_name)? {
        ValueTypes::U64(v) => Ok(*v),
        ValueTypes::Ptr(_) => {
            error!(hdl.log, "expected ValueType::U64, received ValueType::Ptr");
            Err(AsicError::InvalidArg(format!(
                "{action}: {arg_name} expects ValueType::U64"
            )))
        }
    }
}

fn arg_u16(
    hdl: &Handle,
    action_data: &aal::ActionData,
    action: &str,
    arg_name: &str,
) -> AsicResult<u16> {
    let v = arg_u64(hdl, action_data, action, arg_name)?;
    u16::try_from(v).map_err(|_| {
        AsicError::InvalidArg(format!("{action}: {arg_name} {v} exceeds u16"))
    })
}

fn arg_ptr<'a>(
    hdl: &Handle,
    action_data: &'a aal::ActionData,
    action: &str,
    arg_name: &str,
) -> AsicResult<&'a [u8]> {
    match find_arg(action_data, action, arg_name)? {
        ValueTypes::Ptr(v) => Ok(v.as_slice()),
        ValueTypes::U64(_) => {
            error!(hdl.log, "expected ValueType::Ptr, received ValueType::U64");
            Err(AsicError::InvalidArg(format!(
                "{action}: {arg_name} expects ValueType::Ptr"
            )))
        }
    }
}

/// Pack the low 4 chunks (ports 0-127) of DPD's 8x32-bit decap port
/// bitmap into the 16 bytes of sidecar-lite's bit<128> decap_bitmap
/// field (in little-endian).
///
/// Caveats: The high chunks are always zero on this backend and ports >= 128
/// are rejected when adding members. Emitting exactly 16 bytes keeps
/// any following action parameter (the tagged variant's vlan_id) at
/// the offset sidecar-lite reads it from.
fn pack_decap_bitmap(args: &aal::ActionData) -> Vec<u8> {
    let mut chunks = [0u32; 4];
    for arg in &args.args {
        if let ValueTypes::U64(v) = &arg.value {
            match arg.name.as_str() {
                "ports_0" => chunks[0] = *v as u32,
                "ports_1" => chunks[1] = *v as u32,
                "ports_2" => chunks[2] = *v as u32,
                "ports_3" => chunks[3] = *v as u32,
                _ => {}
            }
        }
    }
    chunks.iter().flat_map(|c| c.to_le_bytes()).collect()
}

fn port_number_param(args: &aal::ActionData) -> AsicResult<u8> {
    args.args
        .iter()
        .find(|arg| arg.name == "port_number")
        .and_then(|arg| u8::try_from(&arg.value).ok())
        .ok_or_else(|| {
            AsicError::InvalidArg(format!(
                "{}: missing or invalid port_number",
                args.action
            ))
        })
}

/// Extract keys from `match_data` and ensure that they are
/// in a data structure with the correct length.
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
                    TableType::McastIpv6 => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // Multicast source filter exact keys: inner dst =>
                    // bit<32> or bit<128>. The LPM src key is handled
                    // in the LPM branch.
                    TableType::McastIpv4SrcFilter => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    TableType::McastIpv6SrcFilter => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // Multicast NAT: dst => bit<32> or bit<128>
                    TableType::NatIngressIpv4Mcast => {
                        serialize_value_type(&x, &mut data);
                        keyset_data.extend_from_slice(&data[..4]);
                    }
                    TableType::NatIngressIpv6Mcast => {
                        let mut buf = Vec::new();
                        serialize_value_type(&x, &mut buf);
                        buf.reverse();
                        keyset_data.extend_from_slice(&buf);
                    }
                    // Multicast egress tables: port => bit<16>
                    TableType::McastEgressDecapPorts
                    | TableType::McastEgressPortMapping
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
                match table {
                    TableType::RouteIdxIpv4 | TableType::AttachedSubnetIpv4 => {
                        // prefix for longest prefix match operation
                        // "dst_addr" => hdr.ipv4.dst: lpm => bit<32>
                        serialize_value_type_be(&x.prefix, &mut data);
                        keyset_data.extend_from_slice(&data[data.len() - 4..]);
                        // prefix length for longest prefix match operation
                        keyset_data.push(x.len as u8);
                    }
                    TableType::McastIpv4SrcFilter => {
                        // "src_addr" => bit<32> lpm
                        serialize_value_type_be(&x.prefix, &mut data);
                        keyset_data.extend_from_slice(&data[data.len() - 4..]);
                        keyset_data.push(x.len as u8);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_mapping_serializes_for_sidecar_lite() {
        let fields = vec![MatchEntryField {
            name: "egress_port".to_string(),
            value: MatchEntryValue::Value(ValueTypes::U64(0x0102)),
        }];
        assert_eq!(
            keyset_data(fields, TableType::McastEgressPortMapping),
            vec![0x02, 0x01]
        );

        let action_data = aal::ActionData {
            action: "set_port_number".to_string(),
            args: vec![aal::ActionArg {
                name: "port_number".to_string(),
                value: ValueTypes::U64(17),
            }],
        };
        assert_eq!(port_number_param(&action_data).unwrap(), 17);

        let missing = aal::ActionData {
            action: "set_port_number".to_string(),
            args: Vec::new(),
        };
        assert!(matches!(
            port_number_param(&missing),
            Err(AsicError::InvalidArg(_))
        ));
    }

    #[test]
    fn mcast_nat_keys_serialize_for_sidecar_lite() {
        let v4 = vec![MatchEntryField {
            name: "dst_addr".to_string(),
            value: MatchEntryValue::Value(ValueTypes::U64(0xe000_0101)),
        }];
        assert_eq!(
            keyset_data(v4, TableType::NatIngressIpv4Mcast),
            vec![0x01, 0x01, 0x00, 0xe0]
        );

        let addr: std::net::Ipv6Addr = "ff0e::1:1010".parse().unwrap();
        let v6 = vec![MatchEntryField {
            name: "dst_addr".to_string(),
            value: MatchEntryValue::Value(ValueTypes::Ptr(
                addr.octets().to_vec(),
            )),
        }];
        let mut expected = addr.octets().to_vec();
        expected.reverse();
        assert_eq!(keyset_data(v6, TableType::NatIngressIpv6Mcast), expected);
    }
}
