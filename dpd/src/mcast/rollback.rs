// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Rollback contexts for multicast group operations.
//!
//! This module provides consistent rollback handling for multicast group
//! creation and update operations. It includes context helpers that capture
//! rollback parameters once and provide reusable error handling throughout
//! multi-step operations.

use std::{fmt, net::IpAddr};

use aal::AsicMulticastOps;
use oxnet::Ipv4Net;
use slog::{debug, error};

use common::{network::NatTarget, ports::PortId};

use super::{
    Direction, IpSrc, LinkId, MulticastGroup, MulticastGroupId,
    MulticastGroupMember, MulticastReplicationInfo, add_source_filters,
    remove_source_filters, update_fwding_tables, update_replication_tables,
};
use crate::{Switch, table, types::DpdResult};

/// Trait providing shared rollback functionality for multicast group operations.
///
/// This trait encapsulates common rollback operations that are needed by both
/// group creation and update contexts.
trait RollbackOps {
    fn switch(&self) -> &Switch;
    fn group_ip(&self) -> IpAddr;
    fn external_group_id(&self) -> MulticastGroupId;
    fn underlay_group_id(&self) -> MulticastGroupId;

    /// Rollback port changes (removing added ports, re-adding removed ports).
    /// Each group type implements this differently - external groups are no-op, internal groups handle ports.
    fn rollback_ports(
        &self,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
        replication_info: &MulticastReplicationInfo,
    ) -> DpdResult<()>;

    /// Rollback source filter changes.
    fn rollback_source_filters(
        &self,
        new_sources: Option<&[IpSrc]>,
        orig_sources: Option<&[IpSrc]>,
    ) -> DpdResult<()> {
        self.log_rollback_error(
            "remove new source filters",
            &format!("for group {}", self.group_ip()),
            remove_source_filters(self.switch(), self.group_ip(), new_sources),
        );
        self.log_rollback_error(
            "restore original source filters",
            &format!("for group {}", self.group_ip()),
            add_source_filters(self.switch(), self.group_ip(), orig_sources),
        );
        Ok(())
    }

    /// Rollback internal group changes (ports only, no sources).
    fn rollback_internal_update(
        &self,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
        replication_info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        self.collect_rollback_result("port changes", || {
            self.rollback_ports(added_ports, removed_ports, replication_info)
        });

        Ok(())
    }

    /// Execute rollback operation and track errors for summary logging.
    fn collect_rollback_result<F>(&self, operation: &str, f: F) -> bool
    where
        F: FnOnce() -> DpdResult<()>,
    {
        match f() {
            Ok(()) => false,
            Err(e) => {
                debug!(
                    self.switch().log,
                    "failed operation during rollback";
                    "operation" => operation,
                    "error" => ?e,
                );
                true
            }
        }
    }

    /// Log rollback errors without propagating them.
    fn log_rollback_error<T, E: fmt::Debug>(
        &self,
        operation: &str,
        context: &str,
        result: Result<T, E>,
    ) {
        if let Err(e) = result {
            debug!(
                self.switch().log,
                "failed operation during rollback";
                "operation" => operation,
                "context" => context,
                "error" => ?e,
            );
        }
    }
}

/// Rollback context for multicast group creation operations.
pub(crate) struct GroupCreateRollbackContext<'a> {
    switch: &'a Switch,
    group_ip: IpAddr,
    external_id: MulticastGroupId,
    underlay_id: MulticastGroupId,
    nat_target: Option<NatTarget>,
    sources: Option<&'a [IpSrc]>,
}

impl RollbackOps for GroupCreateRollbackContext<'_> {
    fn switch(&self) -> &Switch {
        self.switch
    }

    fn group_ip(&self) -> IpAddr {
        self.group_ip
    }

    fn external_group_id(&self) -> MulticastGroupId {
        self.external_id
    }

    fn underlay_group_id(&self) -> MulticastGroupId {
        self.underlay_id
    }

    fn rollback_ports(
        &self,
        added_ports: &[MulticastGroupMember],
        _removed_ports: &[MulticastGroupMember],
        _replication_info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        if self.nat_target.is_some() {
            Ok(())
        } else {
            debug!(
                self.switch.log,
                "rolling back multicast group creation";
                "group" => %self.group_ip,
                "ports" => added_ports.len(),
            );

            let mut first_error = None;
            let mut failed_port_resolution = Vec::new();
            let mut failed_port_removal = Vec::new();

            for member in added_ports {
                let group_id = match member.direction {
                    Direction::External => self.external_id,
                    Direction::Underlay => self.underlay_id,
                };

                match self
                    .switch
                    .port_link_to_asic_id(member.port_id, member.link_id)
                {
                    Ok(asic_id) => {
                        if let Err(e) = self
                            .switch
                            .asic_hdl
                            .mc_port_remove(group_id, asic_id)
                        {
                            error!(
                                self.switch.log,
                                "failed to remove port during rollback";
                                "port" => %member.port_id,
                                "asic_id" => asic_id,
                                "group" => group_id,
                                "error" => ?e,
                            );

                            first_error.get_or_insert_with(|| e.into());

                            failed_port_removal
                                .push((member.port_id, member.link_id));
                        }
                    }
                    Err(e) => {
                        error!(
                            self.switch.log,
                            "failed to resolve port link during rollback";
                            "port" => %member.port_id,
                            "link" => %member.link_id,
                            "error" => ?e,
                        );

                        first_error.get_or_insert(e);
                        failed_port_resolution
                            .push((member.port_id, member.link_id));
                    }
                }
            }

            // Log summary of any failures
            if !failed_port_resolution.is_empty() {
                error!(
                    self.switch.log,
                    "rollback failed to resolve port links";
                    "count" => failed_port_resolution.len(),
                    "ports" => ?failed_port_resolution,
                    "warning" => "These ports may remain in inconsistent state",
                );
            }

            if !failed_port_removal.is_empty() {
                error!(
                    self.switch.log,
                    "rollback failed to remove ports from ASIC";
                    "count" => failed_port_removal.len(),
                    "ports" => ?failed_port_removal,
                    "warning" => "These ports may remain in inconsistent state",
                );
            }

            // Return the first error encountered, if any
            match first_error {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }
}

impl<'a> GroupCreateRollbackContext<'a> {
    /// Create rollback context for external group operations.
    pub(crate) fn new_external(
        switch: &'a Switch,
        group_ip: IpAddr,
        external_id: MulticastGroupId,
        underlay_id: MulticastGroupId,
        nat_target: NatTarget,
        sources: Option<&'a [IpSrc]>,
    ) -> Self {
        Self {
            switch,
            group_ip,
            external_id,
            underlay_id,
            nat_target: Some(nat_target),
            sources,
        }
    }

    /// Create rollback context for internal group operations.
    pub(crate) fn new_internal(
        switch: &'a Switch,
        group_ip: IpAddr,
        external_id: MulticastGroupId,
        underlay_id: MulticastGroupId,
    ) -> Self {
        Self {
            switch,
            group_ip,
            external_id,
            underlay_id,
            nat_target: None,
            sources: None,
        }
    }

    /// Perform rollback with member context and return error.
    pub(crate) fn rollback_with_members_and_return_error<E>(
        &self,
        error: E,
        added_members: &[(PortId, LinkId, Direction)],
        replication_info: &MulticastReplicationInfo,
    ) -> E {
        if let Err(rollback_err) =
            self.perform_group_create_rollback(added_members, replication_info)
        {
            error!(
                self.switch.log,
                "rollback failed for group creation";
                "group" => %self.group_ip,
                "error" => ?rollback_err,
            );
        }
        error
    }

    /// Perform rollback and return error.
    pub(crate) fn rollback_and_return_error<E>(&self, error: E) -> E {
        self.rollback_with_members_and_return_error(
            error,
            &[],                                  // No members
            &MulticastReplicationInfo::default(), // Dummy replication info
        )
    }

    /// Perform group creation rollback.
    fn perform_group_create_rollback(
        &self,
        added_members: &[(PortId, LinkId, Direction)],
        replication_info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        let added_members_converted: Vec<MulticastGroupMember> = added_members
            .iter()
            .map(|(port_id, link_id, direction)| MulticastGroupMember {
                port_id: *port_id,
                link_id: *link_id,
                direction: *direction,
            })
            .collect();

        self.collect_rollback_result("port removal", || {
            self.rollback_ports(&added_members_converted, &[], replication_info)
        });
        self.collect_rollback_result("ASIC group deletion", || {
            self.remove_groups()
        });
        self.collect_rollback_result("table cleanup", || self.remove_tables());

        Ok(())
    }

    /// Remove multicast groups from ASIC.
    fn remove_groups(&self) -> DpdResult<()> {
        // External groups don't destroy ASIC groups (they're shared with internal group)
        if self.nat_target.is_none() {
            self.log_rollback_error(
                "remove external multicast group",
                &format!(
                    "for IP {} with ID {}",
                    self.group_ip, self.external_id
                ),
                self.switch.asic_hdl.mc_group_destroy(self.external_id),
            );
            self.log_rollback_error(
                "remove underlay multicast group",
                &format!(
                    "for IP {} with ID {}",
                    self.group_ip, self.underlay_id
                ),
                self.switch.asic_hdl.mc_group_destroy(self.underlay_id),
            );
        }
        Ok(())
    }

    /// Remove table entries.
    fn remove_tables(&self) -> DpdResult<()> {
        match self.group_ip {
            IpAddr::V4(ipv4) => {
                // IPv4 groups are always external-only and never create bitmap entries
                // (only IPv6 internal groups with replication create bitmap entries)

                if let Some(srcs) = self.sources {
                    for src in srcs {
                        match src {
                            IpSrc::Exact(IpAddr::V4(src)) => {
                                self.log_rollback_error(
                                    "delete IPv4 source filter entry",
                                    &format!("for source {src} and group {ipv4}"),
                                    table::mcast::mcast_src_filter::del_ipv4_entry(
                                        self.switch,
                                        Ipv4Net::new(*src, 32).unwrap(),
                                        ipv4,
                                    ),
                                );
                            }
                            IpSrc::Subnet(subnet) => {
                                self.log_rollback_error(
                                    "delete IPv4 source filter subnet entry",
                                    &format!("for subnet {subnet} and group {ipv4}"),
                                    table::mcast::mcast_src_filter::del_ipv4_entry(
                                        self.switch, *subnet, ipv4,
                                    ),
                                );
                            }
                            _ => {}
                        }
                    }
                }
                if self.nat_target.is_some() {
                    self.log_rollback_error(
                        "delete IPv4 NAT entry",
                        &format!("for group {ipv4}"),
                        table::mcast::mcast_nat::del_ipv4_entry(
                            self.switch,
                            ipv4,
                        ),
                    );
                }
                self.log_rollback_error(
                    "delete IPv4 route entry",
                    &format!("for group {ipv4}"),
                    table::mcast::mcast_route::del_ipv4_entry(
                        self.switch,
                        ipv4,
                    ),
                );
            }
            IpAddr::V6(ipv6) => {
                // Clean up external bitmap entry only if both external and underlay groups exist
                // (bitmap entries are only created for internal groups with both group types)
                self.log_rollback_error(
                    "delete IPv6 egress bitmap entry",
                    &format!("for external group {}", self.external_id),
                    table::mcast::mcast_egress::del_bitmap_entry(
                        self.switch,
                        self.external_id,
                    ),
                );

                self.log_rollback_error(
                    "delete IPv6 replication entry",
                    &format!("for group {ipv6}"),
                    table::mcast::mcast_replication::del_ipv6_entry(
                        self.switch,
                        ipv6,
                    ),
                );

                if let Some(srcs) = self.sources {
                    for src in srcs {
                        if let IpSrc::Exact(IpAddr::V6(src)) = src {
                            self.log_rollback_error(
                                "delete IPv6 source filter entry",
                                &format!("for source {src} and group {ipv6}"),
                                table::mcast::mcast_src_filter::del_ipv6_entry(
                                    self.switch,
                                    *src,
                                    ipv6,
                                ),
                            );
                        }
                    }
                }
                if self.nat_target.is_some() {
                    self.log_rollback_error(
                        "delete IPv6 NAT entry",
                        &format!("for group {ipv6}"),
                        table::mcast::mcast_nat::del_ipv6_entry(
                            self.switch,
                            ipv6,
                        ),
                    );
                }
                self.log_rollback_error(
                    "delete IPv6 route entry",
                    &format!("for group {ipv6}"),
                    table::mcast::mcast_route::del_ipv6_entry(
                        self.switch,
                        ipv6,
                    ),
                );
            }
        }
        Ok(())
    }
}

/// Rollback context for multicast group update operations.
pub(crate) struct GroupUpdateRollbackContext<'a> {
    switch: &'a Switch,
    group_ip: IpAddr,
    original_group: &'a MulticastGroup,
}

impl RollbackOps for GroupUpdateRollbackContext<'_> {
    fn switch(&self) -> &Switch {
        self.switch
    }

    fn group_ip(&self) -> IpAddr {
        self.group_ip
    }

    fn external_group_id(&self) -> MulticastGroupId {
        self.original_group.external_group_id()
    }

    fn underlay_group_id(&self) -> MulticastGroupId {
        self.original_group.underlay_group_id()
    }

    fn rollback_ports(
        &self,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
        replication_info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        // External groups don't need port rollback
        if self.original_group.replication_info.is_none() {
            return Ok(());
        }

        // Internal group - perform actual port rollback
        debug!(
            self.switch.log,
            "rolling back multicast group update";
            "group" => ?self.group_ip,
            "added_ports" => added_ports.len(),
            "removed_ports" => removed_ports.len(),
        );

        let mut first_error = None;
        let mut failed_port_resolution = Vec::new();
        let mut failed_port_removal = Vec::new();
        let mut failed_port_addition = Vec::new();

        // Remove added ports
        for member in added_ports {
            let group_id = match member.direction {
                Direction::External => self.external_group_id(),
                Direction::Underlay => self.underlay_group_id(),
            };

            match self
                .switch
                .port_link_to_asic_id(member.port_id, member.link_id)
            {
                Ok(asic_id) => {
                    if let Err(e) =
                        self.switch.asic_hdl.mc_port_remove(group_id, asic_id)
                    {
                        error!(
                            self.switch.log,
                            "failed to remove port during rollback";
                            "port" => %member.port_id,
                            "asic_id" => asic_id,
                            "group" => group_id,
                            "error" => ?e,
                        );

                        first_error.get_or_insert_with(|| e.into());
                        failed_port_removal
                            .push((member.port_id, member.link_id));
                    }
                }
                Err(e) => {
                    error!(
                        self.switch.log,
                        "failed to resolve port link during rollback";
                        "port" => %member.port_id,
                        "link" => %member.link_id,
                        "error" => ?e,
                    );

                    first_error.get_or_insert(e);
                    failed_port_resolution
                        .push((member.port_id, member.link_id));
                }
            }
        }

        // Re-add removed ports
        for member in removed_ports {
            let group_id = match member.direction {
                Direction::External => self.external_group_id(),
                Direction::Underlay => self.underlay_group_id(),
            };

            match self
                .switch
                .port_link_to_asic_id(member.port_id, member.link_id)
            {
                Ok(asic_id) => {
                    if let Err(e) = self.switch.asic_hdl.mc_port_add(
                        group_id,
                        asic_id,
                        replication_info.rid,
                        replication_info.level1_excl_id,
                    ) {
                        error!(
                            self.switch.log,
                            "failed to add port during rollback";
                            "port" => %member.port_id,
                            "asic_id" => asic_id,
                            "group" => group_id,
                            "error" => ?e,
                        );

                        first_error.get_or_insert_with(|| e.into());
                        failed_port_addition
                            .push((member.port_id, member.link_id));
                    }
                }
                Err(e) => {
                    error!(
                        self.switch.log,
                        "failed to resolve port link during rollback";
                        "port" => %member.port_id,
                        "link" => %member.link_id,
                        "error" => ?e,
                    );

                    first_error.get_or_insert(e);
                    failed_port_resolution
                        .push((member.port_id, member.link_id));
                }
            }
        }

        // Log summary of any failures
        if !failed_port_resolution.is_empty() {
            error!(
                self.switch.log,
                "rollback failed to resolve port links";
                "count" => failed_port_resolution.len(),
                "ports" => ?failed_port_resolution,
                "warning" => "These ports may remain in inconsistent state",
            );
        }

        if !failed_port_removal.is_empty() {
            error!(
                self.switch.log,
                "rollback failed to remove ports from ASIC";
                "count" => failed_port_removal.len(),
                "ports" => ?failed_port_removal,
                "warning" => "These ports may remain in inconsistent state",
            );
        }

        if !failed_port_addition.is_empty() {
            error!(
                self.switch.log,
                "rollback failed to re-add ports to ASIC";
                "count" => failed_port_addition.len(),
                "ports" => ?failed_port_addition,
                "warning" => "These ports may remain in inconsistent state",
            );
        }

        // Return the first error encountered, if any
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<'a> GroupUpdateRollbackContext<'a> {
    /// Create rollback context for group update operations.
    pub(crate) fn new(
        switch: &'a Switch,
        group_ip: IpAddr,
        original_group: &'a MulticastGroup,
    ) -> Self {
        Self { switch, group_ip, original_group }
    }

    /// Restore tables and return error.
    pub(crate) fn rollback_and_restore<E>(&self, error: E) -> E {
        if let Err(rollback_err) = self.restore_tables() {
            error!(
                self.switch.log,
                "failed to restore tables during rollback";
                "group" => %self.group_ip,
                "error" => ?rollback_err,
            );
        }
        error
    }

    /// Restore table entries to original state.
    fn restore_tables(&self) -> DpdResult<()> {
        let external_group_id = self.original_group.external_group_id();
        let underlay_group_id = self.original_group.underlay_group_id();
        let replication_info = &self.original_group.replication_info;
        let vlan_id = self.original_group.ext_fwding.vlan_id;
        let nat_target = self.original_group.int_fwding.nat_target;
        let prev_members = self.original_group.members.to_vec();

        if let Some(replication_info) = replication_info {
            self.log_rollback_error(
                "restore replication settings",
                &format!("for group {}", self.group_ip),
                update_replication_tables(
                    self.switch,
                    self.group_ip,
                    external_group_id,
                    underlay_group_id,
                    replication_info,
                ),
            );
        }

        // Restore NAT settings
        match (self.group_ip, nat_target) {
            (IpAddr::V4(ipv4), Some(nat)) => {
                self.log_rollback_error(
                    "restore IPv4 NAT settings",
                    &format!("for group {}", self.group_ip),
                    table::mcast::mcast_nat::update_ipv4_entry(
                        self.switch,
                        ipv4,
                        nat,
                    ),
                );
            }
            (IpAddr::V6(ipv6), Some(nat)) => {
                self.log_rollback_error(
                    "restore IPv6 NAT settings",
                    &format!("for group {}", self.group_ip),
                    table::mcast::mcast_nat::update_ipv6_entry(
                        self.switch,
                        ipv6,
                        nat,
                    ),
                );
            }
            (IpAddr::V4(ipv4), None) => {
                self.log_rollback_error(
                    "remove IPv4 NAT settings",
                    &format!("for group {}", self.group_ip),
                    table::mcast::mcast_nat::del_ipv4_entry(self.switch, ipv4),
                );
            }
            (IpAddr::V6(ipv6), None) => {
                self.log_rollback_error(
                    "remove IPv6 NAT settings",
                    &format!("for group {}", self.group_ip),
                    table::mcast::mcast_nat::del_ipv6_entry(self.switch, ipv6),
                );
            }
        }

        self.log_rollback_error(
            "restore VLAN settings",
            &format!("for group {}", self.group_ip),
            update_fwding_tables(
                self.switch,
                self.group_ip,
                external_group_id,
                underlay_group_id,
                &prev_members,
                vlan_id,
            ),
        );
        Ok(())
    }

    /// Rollback external group updates.
    pub(crate) fn rollback_external<E>(
        &self,
        error: E,
        new_sources: Option<&[IpSrc]>,
    ) -> E {
        if new_sources.is_some() {
            self.collect_rollback_result("source filter restoration", || {
                self.rollback_source_filters(new_sources, None)
            });
        }
        error
    }

    /// Rollback internal group updates.
    pub(crate) fn rollback_internal<E>(
        &self,
        error: E,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
    ) -> E {
        // Get replication info from original group
        if let Some(replication_info) = &self.original_group.replication_info
            && let Err(rollback_err) = self.rollback_internal_update(
                added_ports,
                removed_ports,
                replication_info,
            )
        {
            error!(
                self.switch.log,
                "rollback failed for internal group update";
                "group" => %self.group_ip,
                "error" => ?rollback_err,
            );
        }
        error
    }
}
