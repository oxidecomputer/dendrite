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

use aal::{AsicError, AsicMulticastOps};
use slog::{debug, error, warn};

use super::{
    Direction, GroupKind, IpSrc, MulticastGroup, MulticastGroupId,
    MulticastGroupMember, MulticastReplicationInfo, Replication, SourceFilter,
    add_group_bitmap_entries, add_replication_entry, add_source_filter,
    remove_source_filter, restore_source_filters, update_fwding_tables,
    update_replication_tables,
};
use crate::{
    Switch, table,
    types::{DpdError, DpdResult, after_unwind, ignore_exists, ignore_missing},
};

const ROLLBACK_FAILURE_MSG: &str = "failed operation during rollback";

/// Consume all undo results and return the first rollback error, if any.
///
/// Lazy undo steps execute during the fold, even after a failure.
// `try_fold` would skip remaining undo steps after the first error.
#[allow(clippy::manual_try_fold)]
pub(super) fn unwind_outcome(
    steps: impl IntoIterator<Item = DpdResult<()>>,
) -> DpdResult<()> {
    steps.into_iter().fold(Ok(()), |unwind, step| unwind.and(step))
}

/// Remove each filter entry, reporting failures without aborting early.
fn remove_source_filters<E>(
    sources: &SourceFilter,
    mut remove: impl FnMut(IpSrc) -> Result<(), E>,
) -> Vec<(IpSrc, E)> {
    sources
        .iter()
        .filter_map(|source| remove(source.clone()).err().map(|e| (source, e)))
        .collect()
}

/// Trait providing shared rollback functionality for multicast group operations.
///
/// This trait encapsulates common rollback operations that are needed by both
/// group creation and update contexts.
trait RollbackOps {
    fn switch(&self) -> &Switch;
    fn group_ip(&self) -> IpAddr;
    fn external_group_id(&self) -> MulticastGroupId;
    fn underlay_group_id(&self) -> MulticastGroupId;

    /// ASIC group that carries members of `direction`.
    fn group_id(&self, direction: Direction) -> MulticastGroupId {
        match direction {
            Direction::External => self.external_group_id(),
            Direction::Underlay => self.underlay_group_id(),
        }
    }

    /// Undo port changes in reverse: first remove `added_ports`, then re-add
    /// `removed_ports`. Every port is tried through and  the first error is
    /// returned.
    fn undo_port_changes(
        &self,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
        replication_info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        let switch = self.switch();
        let mut first_err = None;
        let mut failed_port_resolution = Vec::new();
        let mut failed_port_removal = Vec::new();
        let mut failed_port_addition = Vec::new();

        // Remove added ports
        for member in added_ports.iter().rev() {
            let group_id = self.group_id(member.direction);

            match switch.port_link_to_asic_id(member.port_id, member.link_id) {
                Ok(asic_id) => {
                    if let Err(e) =
                        switch.asic_hdl.mc_port_remove(group_id, asic_id)
                    {
                        error!(
                            switch.log,
                            "failed to remove port during rollback";
                            "port" => %member.port_id,
                            "asic_id" => asic_id,
                            "group_id" => group_id,
                            "error" => ?e,
                        );

                        if let Err(e) = ignore_missing(Err(DpdError::from(e))) {
                            first_err.get_or_insert(e);
                            failed_port_removal
                                .push((member.port_id, member.link_id));
                        }
                    }
                }
                Err(e) => {
                    error!(
                        switch.log,
                        "failed to resolve port link during rollback";
                        "port" => %member.port_id,
                        "link" => %member.link_id,
                        "error" => ?e,
                    );

                    first_err.get_or_insert(e);
                    failed_port_resolution
                        .push((member.port_id, member.link_id));
                }
            }
        }

        // Re-add removed ports
        for member in removed_ports.iter().rev() {
            let group_id = self.group_id(member.direction);

            match switch.port_link_to_asic_id(member.port_id, member.link_id) {
                Ok(asic_id) => {
                    if let Err(e) = switch.asic_hdl.mc_port_add(
                        group_id,
                        asic_id,
                        replication_info.rid,
                        replication_info.level1_excl_id,
                    ) {
                        error!(
                            switch.log,
                            "failed to add port during rollback";
                            "port" => %member.port_id,
                            "asic_id" => asic_id,
                            "group_id" => group_id,
                            "error" => ?e,
                        );

                        if let Err(e) = ignore_exists(Err(DpdError::from(e))) {
                            first_err.get_or_insert(e);
                            failed_port_addition
                                .push((member.port_id, member.link_id));
                        }
                    }
                }
                Err(e) => {
                    error!(
                        switch.log,
                        "failed to resolve port link during rollback";
                        "port" => %member.port_id,
                        "link" => %member.link_id,
                        "error" => ?e,
                    );

                    first_err.get_or_insert(e);
                    failed_port_resolution
                        .push((member.port_id, member.link_id));
                }
            }
        }

        // Log summary of any failures
        if !failed_port_resolution.is_empty() {
            error!(
                switch.log,
                "rollback failed to resolve port links";
                "count" => failed_port_resolution.len(),
                "ports" => ?failed_port_resolution,
                "warning" => "These ports may remain in inconsistent state",
            );
        }

        if !failed_port_removal.is_empty() {
            error!(
                switch.log,
                "rollback failed to remove ports from ASIC";
                "count" => failed_port_removal.len(),
                "ports" => ?failed_port_removal,
                "warning" => "These ports may remain in inconsistent state",
            );
        }

        if !failed_port_addition.is_empty() {
            error!(
                switch.log,
                "rollback failed to re-add ports to ASIC";
                "count" => failed_port_addition.len(),
                "ports" => ?failed_port_addition,
                "warning" => "These ports may remain in inconsistent state",
            );
        }

        // Return the first error encountered, if any
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn remove_source_filters(&self, sources: &SourceFilter) -> DpdResult<()> {
        unwind_outcome(
            remove_source_filters(sources, |source| {
                remove_source_filter(self.switch(), self.group_ip(), source)
            })
            .into_iter()
            .map(|(source, err)| {
                self.log_cleanup_error(
                    "delete source filter entry",
                    &format!(
                        "for source {source:?} and group {}",
                        self.group_ip()
                    ),
                    Err::<(), _>(err),
                )
            }),
        )
    }

    /// Rollback source filter changes.
    fn rollback_source_filters(
        &self,
        new_sources: &SourceFilter,
        orig_sources: &SourceFilter,
    ) -> DpdResult<()> {
        unwind_outcome(
            restore_source_filters(
                self.switch(),
                self.group_ip(),
                new_sources,
                orig_sources,
            )
            .err()
            .into_iter()
            .flatten()
            .map(|(source, err)| {
                self.log_rollback_error(
                    "restore original source filters",
                    &format!(
                        "for source {source:?} and group {}",
                        self.group_ip()
                    ),
                    Err::<(), _>(err),
                )
            }),
        )
    }

    /// Log a rollback failure and report it to the caller.
    ///
    /// Undo steps that delete active state use [`Self::log_cleanup_error`],
    /// which tolerates entries already cleaned up beforehand.
    fn log_rollback_error<T, E>(
        &self,
        operation: &str,
        context: &str,
        result: Result<T, E>,
    ) -> DpdResult<()>
    where
        E: fmt::Debug + Into<DpdError>,
    {
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                error!(
                    self.switch().log,
                    "{ROLLBACK_FAILURE_MSG}";
                    "operation" => operation,
                    "context" => context,
                    "error" => ?e,
                );

                Err(e.into())
            }
        }
    }

    fn log_cleanup_error<T, E>(
        &self,
        operation: &str,
        context: &str,
        result: Result<T, E>,
    ) -> DpdResult<()>
    where
        E: fmt::Debug + Into<DpdError>,
    {
        match result.map(|_| ()).map_err(Into::into) {
            Err(DpdError::Switch(AsicError::Missing(detail))) => {
                debug!(
                    self.switch().log,
                    "rollback cleanup found entry already absent";
                    "operation" => operation,
                    "context" => context,
                    "detail" => detail,
                );
                Ok(())
            }
            res => self.log_rollback_error(operation, context, res),
        }
    }

    /// Restore a group's bitmap VLAN to `vlan_id`, the value in place before
    /// the failed operation.
    ///
    /// A missing entry is logged and re-added from the group's membership.
    /// Failures, including a failed re-add, are logged and returned.
    fn restore_bitmap_vlan(
        &self,
        group: &MulticastGroup,
        vlan_id: Option<u16>,
    ) -> DpdResult<()> {
        let restored = match super::update_bitmap_vlan(
            self.switch(),
            group,
            vlan_id,
        ) {
            Err(DpdError::Switch(AsicError::Missing(detail))) => {
                warn!(
                    self.switch().log,
                    "re-adding missing multicast bitmap entry during rollback";
                    "group" => group.external_group_id(),
                    "detail" => detail,
                );
                upsert_bitmap_entry(self.switch(), group, vlan_id)
            }
            res => res,
        };

        self.log_rollback_error(
            "restore multicast bitmap VLAN",
            &format!("for group {}", group.external_group_id()),
            restored,
        )
    }
}

fn upsert_bitmap_entry(
    switch: &Switch,
    group: &MulticastGroup,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    match add_group_bitmap_entries(switch, group, vlan_id) {
        Err(DpdError::Switch(AsicError::Exists(_))) => {
            super::update_bitmap_vlan(switch, group, vlan_id)
        }
        res => res,
    }
}

/// Rollback context for multicast group creation operations.
pub(crate) struct GroupCreateRollbackContext<'a> {
    switch: &'a Switch,
    group_ip: IpAddr,
    external_id: MulticastGroupId,
    underlay_id: MulticastGroupId,
    kind: CreateRollbackKind<'a>,
}

/// Group kind disambiguation for a creation request rollback, determining
/// which state to undo.
///
/// Both rollback kinds delete the group's multicast route entry.
#[derive(Clone, Copy)]
enum CreateRollbackKind<'a> {
    /// External creation: remove source filters and the NAT entry. The ASIC
    /// groups remain after rollback because they belong to the underlay group
    /// this external group targets.
    External { sources: &'a SourceFilter, vlan_id: Option<u16> },
    /// Underlay creation: destroy the ASIC groups and, for IPv6, the egress
    /// bitmap and replication entries. No source filters or NAT entries were
    /// installed.
    Underlay,
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
}

impl<'a> GroupCreateRollbackContext<'a> {
    /// Create rollback context for external group operations.
    pub(crate) fn new_external(
        switch: &'a Switch,
        group_ip: IpAddr,
        external_id: MulticastGroupId,
        underlay_id: MulticastGroupId,
        sources: &'a SourceFilter,
        vlan_id: Option<u16>,
    ) -> Self {
        Self {
            switch,
            group_ip,
            external_id,
            underlay_id,
            kind: CreateRollbackKind::External { sources, vlan_id },
        }
    }

    /// Create rollback context for underlay group operations.
    pub(crate) fn new_underlay(
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
            kind: CreateRollbackKind::Underlay,
        }
    }

    /// Restore a referenced underlay group's bitmap VLAN, then roll back the
    /// failed creation step.
    pub(crate) fn rollback_with_vlan_restore(
        &self,
        err: DpdError,
        underlay_group: &MulticastGroup,
        previous_vlan: Option<u16>,
    ) -> DpdError {
        let restored = self.restore_bitmap_vlan(underlay_group, previous_vlan);
        self.rollback(after_unwind(err, restored))
    }

    /// Perform rollback and return error.
    pub(crate) fn rollback(&self, err: DpdError) -> DpdError {
        after_unwind(
            err,
            unwind_outcome([self.remove_groups(), self.remove_tables()]),
        )
    }

    /// Remove multicast groups from ASIC.
    fn remove_groups(&self) -> DpdResult<()> {
        // External groups don't destroy ASIC groups (they're shared with underlay group).
        if !matches!(self.kind, CreateRollbackKind::Underlay) {
            return Ok(());
        }

        unwind_outcome([
            self.log_cleanup_error(
                "remove external multicast group",
                &format!(
                    "for IP {} with ID {}",
                    self.group_ip, self.external_id
                ),
                self.switch.asic_hdl.mc_group_destroy(self.external_id),
            ),
            self.log_cleanup_error(
                "remove underlay multicast group",
                &format!(
                    "for IP {} with ID {}",
                    self.group_ip, self.underlay_id
                ),
                self.switch.asic_hdl.mc_group_destroy(self.underlay_id),
            ),
        ])
    }

    /// Remove table entries.
    fn remove_tables(&self) -> DpdResult<()> {
        unwind_outcome([
            self.remove_underlay_entries(),
            // Source filters only exist for external groups (which have
            // NAT targets). Underlay groups don't have source filtering.
            self.remove_external_entries(),
            self.remove_route_entry(),
        ])
    }

    fn remove_underlay_entries(&self) -> DpdResult<()> {
        let (CreateRollbackKind::Underlay, IpAddr::V6(ipv6)) =
            (self.kind, self.group_ip)
        else {
            return Ok(());
        };

        unwind_outcome([
            self.log_cleanup_error(
                "delete IPv6 egress bitmap entry",
                &format!("for external group {}", self.external_id),
                table::mcast::mcast_egress::del_bitmap_entry(
                    self.switch,
                    self.external_id,
                ),
            ),
            self.log_cleanup_error(
                "delete IPv6 replication entry",
                &format!("for group {ipv6}"),
                table::mcast::mcast_replication::del_ipv6_entry(
                    self.switch,
                    ipv6,
                ),
            ),
        ])
    }

    fn remove_external_entries(&self) -> DpdResult<()> {
        let CreateRollbackKind::External { sources, vlan_id } = self.kind
        else {
            return Ok(());
        };

        let filters_removed = self.remove_source_filters(sources);
        let nat_removed = match self.group_ip {
            IpAddr::V4(ipv4) => self.log_cleanup_error(
                "delete IPv4 NAT entry",
                &format!("for group {ipv4}"),
                table::mcast::mcast_nat::del_ipv4_entry(
                    self.switch,
                    ipv4,
                    vlan_id,
                ),
            ),
            IpAddr::V6(ipv6) => self.log_cleanup_error(
                "delete IPv6 NAT entry",
                &format!("for group {ipv6}"),
                table::mcast::mcast_nat::del_ipv6_entry(
                    self.switch,
                    ipv6,
                    vlan_id,
                ),
            ),
        };

        filters_removed.and(nat_removed)
    }

    fn remove_route_entry(&self) -> DpdResult<()> {
        match self.group_ip {
            IpAddr::V4(ipv4) => self.log_cleanup_error(
                "delete IPv4 route entry",
                &format!("for group {ipv4}"),
                table::mcast::mcast_route::del_ipv4_entry(self.switch, ipv4),
            ),
            IpAddr::V6(ipv6) => self.log_cleanup_error(
                "delete IPv6 route entry",
                &format!("for group {ipv6}"),
                table::mcast::mcast_route::del_ipv6_entry(self.switch, ipv6),
            ),
        }
    }
}

/// Rollback context for multicast group update operations.
pub(crate) struct GroupUpdateRollbackContext<'a> {
    switch: &'a Switch,
    original_group: &'a MulticastGroup,
    table_vlan_id: Option<u16>,
}

impl RollbackOps for GroupUpdateRollbackContext<'_> {
    fn switch(&self) -> &Switch {
        self.switch
    }

    fn group_ip(&self) -> IpAddr {
        self.original_group.ip()
    }

    fn external_group_id(&self) -> MulticastGroupId {
        self.original_group.external_group_id()
    }

    fn underlay_group_id(&self) -> MulticastGroupId {
        self.original_group.underlay_group_id()
    }
}

impl<'a> GroupUpdateRollbackContext<'a> {
    fn rollback_underlay_update(
        &self,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
        replication_info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        // Underlay group -> perform actual port rollback
        debug!(
            self.switch.log,
            "rolling back multicast group update";
            "group" => %self.group_ip(),
            "added_ports" => added_ports.len(),
            "removed_ports" => removed_ports.len(),
        );

        self.log_rollback_error(
            "port changes",
            &format!("for group {}", self.group_ip()),
            self.undo_port_changes(
                added_ports,
                removed_ports,
                replication_info,
            ),
        )
    }

    /// Create the rollback context for an update on the `original_group`.
    ///
    /// `table_vlan_id` is the attempted VLAN for an external update, or the VLAN
    /// propagated from the referencing external group for an underlay update.
    ///
    /// On rollback, we restore the external group's original VLAN and leave
    /// the underlay group's one in place.
    pub(crate) fn new(
        switch: &'a Switch,
        original_group: &'a MulticastGroup,
        table_vlan_id: Option<u16>,
    ) -> Self {
        Self { switch, original_group, table_vlan_id }
    }

    /// Restore table entries to original state.
    fn restore_tables(&self) -> DpdResult<()> {
        unwind_outcome([
            self.restore_replication(),
            self.remove_added_bitmap(),
            self.restore_fwding_tables(),
        ])
    }

    fn restore_replication(&self) -> DpdResult<()> {
        let GroupKind::Underlay {
            group_ip,
            replication: Replication::Active { info: replication_info, .. },
        } = &self.original_group.kind
        else {
            return Ok(());
        };

        let restored = match update_replication_tables(
            self.switch,
            (*group_ip).into(),
            self.original_group.external_group_id(),
            self.original_group.underlay_group_id(),
            replication_info,
        ) {
            Err(DpdError::Switch(AsicError::Missing(detail))) => {
                warn!(
                    self.switch.log,
                    "re-adding missing multicast replication entry during rollback";
                    "group" => %group_ip,
                    "detail" => detail,
                );
                add_replication_entry(
                    self.switch,
                    self.original_group,
                    replication_info,
                )
            }
            res => res,
        };

        self.log_rollback_error(
            "restore replication settings",
            &format!("for group {group_ip}"),
            restored,
        )
    }

    fn remove_added_bitmap(&self) -> DpdResult<()> {
        let GroupKind::Underlay { replication: Replication::Empty, .. } =
            &self.original_group.kind
        else {
            return Ok(());
        };

        self.log_cleanup_error(
            "delete newly added multicast bitmap",
            &format!("for group {}", self.group_ip()),
            table::mcast::mcast_egress::del_bitmap_entry(
                self.switch,
                self.original_group.external_group_id(),
            ),
        )
    }

    fn restore_fwding_tables(&self) -> DpdResult<()> {
        let restore_vlan_id = match &self.original_group.kind {
            GroupKind::External { vlan_id, .. } => *vlan_id,
            GroupKind::Underlay { .. } => self.table_vlan_id,
        };

        self.log_rollback_error(
            "restore VLAN settings",
            &format!("for group {}", self.group_ip()),
            update_fwding_tables(
                self.switch,
                self.original_group,
                self.table_vlan_id,
                restore_vlan_id,
            ),
        )
    }

    /// Rollback external group updates.
    ///
    /// Note: `new_sources` should be the normalized sources that were actually
    /// applied to the tables (not the raw request sources).
    pub(crate) fn rollback_external(
        &self,
        err: DpdError,
        new_sources: &SourceFilter,
    ) -> DpdError {
        // Underlay groups have no source filters to restore.
        let unwind = match &self.original_group.kind {
            GroupKind::External { sources, .. } => {
                self.rollback_source_filters(new_sources, sources)
            }
            GroupKind::Underlay { .. } => Ok(()),
        };
        after_unwind(err, unwind.and(self.restore_fwding_tables()))
    }

    /// Rollback underlay group updates.
    pub(crate) fn rollback_underlay(
        &self,
        err: DpdError,
        replication_info: &MulticastReplicationInfo,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
    ) -> DpdError {
        after_unwind(
            err,
            self.rollback_underlay_update(
                added_ports,
                removed_ports,
                replication_info,
            ),
        )
    }

    /// Restore the bitmap VLAN on every group in `updates`, then report the
    /// initial failure together with that failure's outcome.
    ///
    /// This attempts every group even if an earlier restore fails.
    pub(crate) fn rollback_with_bitmap_restore<'b>(
        &self,
        err: DpdError,
        updates: impl IntoIterator<Item = (&'b MulticastGroup, Option<u16>)>,
    ) -> DpdError {
        let restored =
            unwind_outcome(updates.into_iter().map(|(group, vlan_id)| {
                self.restore_bitmap_vlan(group, vlan_id)
            }));

        after_unwind(err, restored)
    }

    /// Undo an underlay group's port changes, restore its tables, and report
    /// the result with the failure that originally triggered the rollback.
    pub(crate) fn rollback_underlay_and_restore(
        &self,
        err: DpdError,
        replication_info: &MulticastReplicationInfo,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
    ) -> DpdError {
        after_unwind(
            err,
            self.rollback_underlay_update(
                added_ports,
                removed_ports,
                replication_info,
            )
            .and(self.restore_tables()),
        )
    }
}

/// A deletion step recorded for rollback, including partially completed steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeleteStep {
    /// Source filter entries, recorded before removal since removal is per
    /// entry and can fail partway.
    SourceFilters,
    /// The external group's NAT ingress entry.
    Nat,
    /// The underlay group's replication entry.
    Replication,
    /// The underlay group's egress decap bitmap entry.
    Bitmap,
    /// The group's multicast route entry.
    Route,
    /// The underlay group's external and underlay ASIC domains.
    Domains,
}

/// Rollback context for multicast group delete operations.
pub(crate) struct GroupDeleteRollbackContext<'a> {
    switch: &'a Switch,
    group: &'a MulticastGroup,
}

impl RollbackOps for GroupDeleteRollbackContext<'_> {
    fn switch(&self) -> &Switch {
        self.switch
    }

    fn group_ip(&self) -> IpAddr {
        self.group.ip()
    }

    fn external_group_id(&self) -> MulticastGroupId {
        self.group.external_group_id()
    }

    fn underlay_group_id(&self) -> MulticastGroupId {
        self.group.underlay_group_id()
    }
}

impl<'a> GroupDeleteRollbackContext<'a> {
    /// Create rollback context for deleting `group`.
    pub(crate) fn new(switch: &'a Switch, group: &'a MulticastGroup) -> Self {
        Self { switch, group }
    }

    /// Restore the `deleted` steps and report the result with the failure
    /// that triggered the rollback.
    pub(crate) fn rollback(
        &self,
        err: DpdError,
        deleted: &[DeleteStep],
    ) -> DpdError {
        after_unwind(err, self.restore_tables(deleted))
    }

    /// Restore a referenced underlay group's bitmap VLAN to this external
    /// group's VLAN; then, restore the `deleted` steps in sequence.
    pub(crate) fn rollback_with_vlan_restore(
        &self,
        err: DpdError,
        underlay_group: &MulticastGroup,
        deleted: &[DeleteStep],
    ) -> DpdError {
        let restored =
            self.restore_bitmap_vlan(underlay_group, self.group.vlan_id());
        self.rollback(after_unwind(err, restored), deleted)
    }

    fn restore_tables(&self, deleted: &[DeleteStep]) -> DpdResult<()> {
        let restore = |step: DeleteStep, f: &dyn Fn() -> DpdResult<()>| {
            if deleted.contains(&step) { f() } else { Ok(()) }
        };

        match &self.group.kind {
            GroupKind::External { sources, nat_target, vlan_id, .. } => {
                unwind_outcome([
                    restore(DeleteStep::SourceFilters, &|| {
                        self.readd_source_filters(sources)
                    }),
                    restore(DeleteStep::Nat, &|| {
                        self.readd_nat(*nat_target, *vlan_id)
                    }),
                    restore(DeleteStep::Route, &|| self.readd_route(*vlan_id)),
                ])
            }
            GroupKind::Underlay {
                replication: Replication::Active { info, .. },
                ..
            } => unwind_outcome([
                restore(DeleteStep::Domains, &|| self.restore_domains()),
                restore(DeleteStep::Bitmap, &|| self.readd_bitmap()).and_then(
                    |()| {
                        restore(DeleteStep::Replication, &|| {
                            self.readd_replication(info)
                        })
                    },
                ),
                restore(DeleteStep::Route, &|| self.readd_route(None)),
            ]),
            GroupKind::Underlay { replication: Replication::Empty, .. } => {
                unwind_outcome([
                    restore(DeleteStep::Domains, &|| self.restore_domains()),
                    restore(DeleteStep::Route, &|| self.readd_route(None)),
                ])
            }
        }
    }

    fn restore_domains(&self) -> DpdResult<()> {
        unwind_outcome(
            [Direction::External, Direction::Underlay]
                .into_iter()
                .map(|direction| self.restore_domain(direction)),
        )
    }

    fn restore_domain(&self, direction: Direction) -> DpdResult<()> {
        let group_id = self.group_id(direction);

        if !self.switch.asic_hdl.mc_group_exists(group_id) {
            self.log_rollback_error(
                "restore multicast group",
                &format!("for IP {} with ID {group_id}", self.group_ip()),
                ignore_exists(
                    self.switch
                        .asic_hdl
                        .mc_group_create(group_id)
                        .map_err(DpdError::from),
                ),
            )?;
        }

        let Some(Replication::Active { info, members }) =
            self.group.replication()
        else {
            return Ok(());
        };

        unwind_outcome(
            members.iter().filter(|member| member.direction == direction).map(
                |member| {
                    let added = self
                        .switch
                        .port_link_to_asic_id(member.port_id, member.link_id)
                        .and_then(|asic_id| {
                            ignore_exists(
                                self.switch
                                    .asic_hdl
                                    .mc_port_add(
                                        group_id,
                                        asic_id,
                                        info.rid,
                                        info.level1_excl_id,
                                    )
                                    .map_err(DpdError::from),
                            )
                        });

                    self.log_rollback_error(
                        "restore multicast group member",
                        &format!(
                            "for port {} link {} in group {} with ID {group_id}",
                            member.port_id,
                            member.link_id,
                            self.group_ip()
                        ),
                        added,
                    )
                },
            ),
        )
    }

    fn readd_source_filters(&self, sources: &SourceFilter) -> DpdResult<()> {
        unwind_outcome(sources.iter().map(|source| {
            self.log_rollback_error(
                "restore source filter entry",
                &format!("for source {source:?} and group {}", self.group_ip()),
                ignore_exists(add_source_filter(
                    self.switch,
                    self.group_ip(),
                    source.clone(),
                )),
            )
        }))
    }

    fn readd_nat(
        &self,
        nat_target: dpd_types::mcast::ExternalNatTarget,
        vlan_id: Option<u16>,
    ) -> DpdResult<()> {
        let nat_target = nat_target.into();
        let result = match self.group_ip() {
            IpAddr::V4(ipv4) => table::mcast::mcast_nat::update_ipv4_entry(
                self.switch,
                ipv4,
                nat_target,
                nat_target,
                vlan_id,
                vlan_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::mcast_nat::update_ipv6_entry(
                self.switch,
                ipv6,
                nat_target,
                nat_target,
                vlan_id,
                vlan_id,
            ),
        };

        self.log_rollback_error(
            "restore NAT entry",
            &format!("for group {}", self.group_ip()),
            result,
        )
    }

    fn readd_route(&self, vlan_id: Option<u16>) -> DpdResult<()> {
        let result = match self.group_ip() {
            IpAddr::V4(ipv4) => table::mcast::mcast_route::ensure_ipv4_entry(
                self.switch,
                ipv4,
                vlan_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::mcast_route::ensure_ipv6_entry(
                self.switch,
                ipv6,
                vlan_id,
            ),
        };

        self.log_rollback_error(
            "restore route entry",
            &format!("for group {}", self.group_ip()),
            result,
        )
    }

    fn readd_bitmap(&self) -> DpdResult<()> {
        self.log_rollback_error(
            "restore multicast bitmap entry",
            &format!("for group {}", self.group.external_group_id()),
            upsert_bitmap_entry(self.switch, self.group, None),
        )
    }

    fn readd_replication(
        &self,
        info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        self.log_rollback_error(
            "restore replication entry",
            &format!("for group {}", self.group_ip()),
            add_replication_entry(self.switch, self.group, info),
        )
    }
}

#[cfg(test)]
mod tests {
    use dpd_types::mcast::ExactSource;

    use super::*;

    #[test]
    fn test_source_filter_rollback_reports_all_failures() {
        let sources = SourceFilter::from_exact(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
                .map(|address| address.parse::<ExactSource>().unwrap()),
        );
        let expected: Vec<_> = sources.iter().collect();

        let mut attempted = Vec::new();
        let errs = remove_source_filters(&sources, |source| {
            let index = attempted.len();
            attempted.push(source);
            if index == 1 { Ok(()) } else { Err(index) }
        });

        // The first and third removals fail, but every source
        // should still be attempted.
        assert_eq!(attempted, expected);

        // These errors should follow in source order.
        assert_eq!(
            errs,
            vec![(expected[0].clone(), 0), (expected[2].clone(), 2)]
        );
    }

    #[test]
    fn test_source_filter_rollback_attempts_any_just_once() {
        for fail in [false, true] {
            let mut attempted = Vec::new();
            let errs = remove_source_filters(&SourceFilter::Any, |source| {
                attempted.push(source);
                if fail { Err("delete failed") } else { Ok(()) }
            });

            assert_eq!(attempted, vec![IpSrc::Any]);
            if fail {
                assert_eq!(errs, vec![(IpSrc::Any, "delete failed")]);
            } else {
                assert!(errs.is_empty());
            }
        }
    }
}

/// Rollback tests driven by the `chaos` ASIC backend, which fails table and
/// ASIC operations at configured probabilities.
#[cfg(all(test, feature = "chaos"))]
mod chaos_tests {
    use std::{
        collections::BTreeMap,
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    use common::{
        network::{MacAddr, NatTarget, Vni, multicast_mac_addr},
        ports::RearPort,
        table::TableType,
    };
    use dpd_types::link::LinkId;
    use dpd_types::mcast::{ExactSource, SourceEntry};
    use slog::{Drain, KV};

    use super::*;
    use crate::{
        Switch, config::Config, mcast::*, table::mcast::mcast_nat,
        types::DpdError,
    };

    /// Captures the fields of each [`ROLLBACK_FAILURE_MSG`] record.
    #[derive(Clone, Default)]
    struct RollbackLog {
        entries: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    }

    struct LogFields(BTreeMap<String, String>);

    impl slog::Serializer for LogFields {
        fn emit_arguments(
            &mut self,
            key: slog::Key,
            value: &std::fmt::Arguments<'_>,
        ) -> slog::Result {
            self.0.insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    impl Drain for RollbackLog {
        type Ok = ();
        type Err = Infallible;

        fn log(
            &self,
            record: &slog::Record<'_>,
            _values: &slog::OwnedKVList,
        ) -> Result<(), Infallible> {
            if record.msg().to_string() == ROLLBACK_FAILURE_MSG {
                let mut fields = LogFields(BTreeMap::new());
                record.kv().serialize(record, &mut fields).unwrap();
                self.entries.lock().unwrap().push(fields.0);
            }
            Ok(())
        }
    }

    /// Build a switch whose logger feeds `RollbackLog`, registered with the
    /// tables that the multicast paths use.
    fn chaos_switch(config: Config) -> (Switch, RollbackLog) {
        let logs = RollbackLog::default();
        let log = slog::Logger::root(logs.clone().fuse(), slog::o!());
        let mut switch = Switch::new(log, "sidecar", config).unwrap();
        for table in [
            TableType::McastIpv6,
            TableType::RouteIpv4Mcast,
            TableType::McastIpv4SrcFilter,
            TableType::NatIngressIpv4Mcast,
            TableType::RouteIpv6Mcast,
            TableType::McastEgressDecapPorts,
            TableType::McastIpv6SrcFilter,
            TableType::NatIngressIpv6Mcast,
        ] {
            switch.table_add(table).unwrap();
        }

        (switch, logs)
    }

    /// Install the underlay fixture at `ff04::123` in the reserved `ff04::/64`
    /// block.
    fn install_underlay_group(
        switch: &Switch,
    ) -> (UnderlayMulticastIpv6, GroupKey) {
        install_underlay_group_at(switch, "ff04::123".parse().unwrap())
    }

    /// Install an underlay group directly into the tables and the group map,
    /// without an external group mapping.
    fn install_underlay_group_at(
        switch: &Switch,
        underlay_ip: UnderlayMulticastIpv6,
    ) -> (UnderlayMulticastIpv6, GroupKey) {
        let underlay_key = GroupKey::underlay(underlay_ip);
        let (external_scoped_group, underlay_scoped_group) = {
            let mut groups = switch.mcast.lock().unwrap();
            (
                groups.generate_group_id().unwrap(),
                groups.generate_group_id().unwrap(),
            )
        };
        let repl = MulticastReplicationInfo::new(external_scoped_group.id());
        let members = vec![
            MulticastGroupMember {
                port_id: RearPort::new(0).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            },
            MulticastGroupMember {
                port_id: RearPort::new(1).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::Underlay,
            },
        ];

        configure_underlay_tables(
            switch,
            underlay_ip,
            external_scoped_group.id(),
            underlay_scoped_group.id(),
            Some(&repl),
            &members,
            None,
        )
        .unwrap();

        let underlay = MulticastGroup {
            external_scoped_group,
            underlay_scoped_group,
            tag: "underlay-rollback-test".to_string(),
            kind: GroupKind::Underlay {
                group_ip: underlay_ip,
                replication: Replication::new(repl, members),
            },
        };
        switch.mcast.lock().unwrap().groups.insert(underlay_key, underlay);

        (underlay_ip, underlay_key)
    }

    /// Install a memberless underlay group at `ff04::123`: a route entry and
    /// the stored group, with no bitmap or replication entry.
    fn install_empty_underlay_group(
        switch: &Switch,
    ) -> (UnderlayMulticastIpv6, GroupKey) {
        let underlay_ip: UnderlayMulticastIpv6 = "ff04::123".parse().unwrap();
        let underlay_key = GroupKey::underlay(underlay_ip);
        let (external_scoped_group, underlay_scoped_group) = {
            let mut groups = switch.mcast.lock().unwrap();
            (
                groups.generate_group_id().unwrap(),
                groups.generate_group_id().unwrap(),
            )
        };

        configure_underlay_tables(
            switch,
            underlay_ip,
            external_scoped_group.id(),
            underlay_scoped_group.id(),
            None,
            &[],
            None,
        )
        .unwrap();

        let underlay = MulticastGroup {
            external_scoped_group,
            underlay_scoped_group,
            tag: "underlay-empty-test".to_string(),
            kind: GroupKind::Underlay {
                group_ip: underlay_ip,
                replication: Replication::Empty,
            },
        };
        switch.mcast.lock().unwrap().groups.insert(underlay_key, underlay);

        (underlay_ip, underlay_key)
    }

    /// Return occupancy, inserts, deletes, and updates (in that order).
    fn table_usage(switch: &Switch, table: TableType) -> (u32, u64, u64, u64) {
        let table = switch.table_get(table).unwrap();
        (
            table.usage.occupancy,
            table.usage.inserts,
            table.usage.deletes,
            table.usage.updates,
        )
    }

    fn bitmap_entry(
        switch: &Switch,
        external_group_id: MulticastGroupId,
    ) -> Option<(table::mcast::mcast_egress::PortBitmap, Option<u16>)> {
        let dump = table::mcast::mcast_egress::bitmap_table_dump(switch, false)
            .unwrap();

        let group_id = external_group_id.to_string();
        let entry = dump.entries.into_iter().find(|entry| {
            entry.keys.get("mcast_external_grp") == Some(&group_id)
        })?;

        let mut ports = [0u32; 8];
        for (index, word) in ports.iter_mut().enumerate() {
            *word =
                entry.action_args[&format!("ports_{index}")].parse().unwrap();
        }

        let vlan_id = entry
            .action_args
            .get("vlan_id")
            .map(|vlan_id| vlan_id.parse().unwrap());
        Some((ports.into(), vlan_id))
    }

    fn route_action(
        switch: &Switch,
        group_ip: IpAddr,
    ) -> Option<(String, Option<String>)> {
        let dump = match group_ip {
            IpAddr::V4(_) => {
                table::mcast::mcast_route::ipv4_table_dump(switch, false)
            }
            IpAddr::V6(_) => {
                table::mcast::mcast_route::ipv6_table_dump(switch, false)
            }
        }
        .unwrap();

        let address = group_ip.to_string();
        dump.entries
            .into_iter()
            .find(|entry| entry.keys.get("dst_addr") == Some(&address))
            .map(|entry| {
                (entry.action, entry.action_args.get("vlan_id").cloned())
            })
    }

    fn source_filter_prefixes(
        switch: &Switch,
        group_ip: IpAddr,
    ) -> BTreeSet<String> {
        let dump = match group_ip {
            IpAddr::V4(_) => {
                table::mcast::mcast_src_filter::ipv4_table_dump(switch, false)
            }
            IpAddr::V6(_) => {
                table::mcast::mcast_src_filter::ipv6_table_dump(switch, false)
            }
        }
        .unwrap();

        let address = group_ip.to_string();
        dump.entries
            .into_iter()
            .filter(|entry| entry.keys.get("dst_addr") == Some(&address))
            .map(|entry| entry.keys["src_addr"].clone())
            .collect()
    }

    fn external_tables(group_ip: IpAddr) -> (TableType, TableType, TableType) {
        match group_ip {
            IpAddr::V4(_) => (
                TableType::RouteIpv4Mcast,
                TableType::McastIpv4SrcFilter,
                TableType::NatIngressIpv4Mcast,
            ),
            IpAddr::V6(_) => (
                TableType::RouteIpv6Mcast,
                TableType::McastIpv6SrcFilter,
                TableType::NatIngressIpv6Mcast,
            ),
        }
    }

    fn external_nat_target(
        group_ip: IpAddr,
        underlay_ip: UnderlayMulticastIpv6,
    ) -> NatTarget {
        let inner_mac = match group_ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                MacAddr::new(
                    0x01,
                    0x00,
                    0x5e,
                    octets[1] & 0x7f,
                    octets[2],
                    octets[3],
                )
            }
            IpAddr::V6(ip) => multicast_mac_addr(ip),
        };
        NatTarget {
            internal_ip: underlay_ip.into(),
            inner_mac,
            vni: Vni::new(100).unwrap(),
        }
    }

    fn external_entry(
        group_ip: IpAddr,
        tag: &str,
        nat_target: NatTarget,
        vlan_id: Option<u16>,
        sources: serde_json::Value,
    ) -> MulticastGroupCreateExternalEntry {
        serde_json::from_value(serde_json::json!({
            "group_ip": group_ip,
            "tag": tag,
            "internal_forwarding": { "nat_target": nat_target },
            "external_forwarding": { "vlan_id": vlan_id },
            "sources": sources,
        }))
        .unwrap()
    }

    /// Fail external group creation for `external_ip` on a full route table and
    /// assert that the mapped underlay group remains.
    ///
    /// When `fail_source_removal` is true, each of the three filter deletions
    /// fails and is logged separately. When false, all three succeed.
    ///
    /// The failed route insertion leaves no entry to delete. Cleanup logs the
    /// missing entry at debug level, without a `ROLLBACK_FAILURE_MSG` record.
    fn external_create_failure(external_ip: IpAddr, fail_source_removal: bool) {
        let (route_table, source_table, nat_table) =
            external_tables(external_ip);
        let mut config = Config::default();

        if fail_source_removal {
            config.asic_config.table_entry_del.values.insert(source_table, 1.0);
        }

        config.asic_config.mc_config.mc_group_destroy =
            asic::chaos::Chaos::new(1.0);
        config.asic_config.mc_config.mc_port_remove =
            asic::chaos::Chaos::new(1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);

        let (before_group, before_repl) = {
            let groups = switch.mcast.lock().unwrap();
            let underlay = groups.groups.get(&underlay_key).unwrap();
            (
                serde_json::to_value(
                    MulticastGroupUnderlayResponse::try_from(underlay).unwrap(),
                )
                .unwrap(),
                underlay.replication_info().cloned(),
            )
        };

        let before_tables: BTreeMap<_, _> = [
            TableType::McastIpv6,
            TableType::McastEgressDecapPorts,
            TableType::RouteIpv6Mcast,
            route_table,
        ]
        .into_iter()
        .map(|table| (table, table_usage(&switch, table)))
        .collect();

        {
            let mut route = switch.table_get(route_table).unwrap();
            route.usage.size = route.usage.occupancy;
        }

        let source_ips = if external_ip.is_ipv4() {
            ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        } else {
            ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
        };

        let nat_target = external_nat_target(external_ip, underlay_ip);
        let entry = external_entry(
            external_ip,
            "external-rollback-test",
            nat_target,
            None,
            serde_json::json!(
                source_ips.map(|ip| serde_json::json!({ "Exact": ip }))
            ),
        );

        let err = add_group_external(&switch, entry).unwrap_err();
        assert_eq!(
            matches!(err, DpdError::Unwind { .. }),
            fail_source_removal,
            "unexpected rollback failure reporting: {err:?}"
        );

        let init: &DpdError = match &err {
            DpdError::Unwind { initial: init, .. } => init,
            err => err,
        };
        assert!(
            matches!(
                init,
                DpdError::TableFull(table)
                    if *table == route_table.to_string()
            ),
            "creation error was replaced: {err:?}"
        );

        for (table, before) in before_tables {
            assert_eq!(table_usage(&switch, table), before, "{table}");
        }

        let groups = switch.mcast.lock().unwrap();
        assert_eq!(groups.groups.len(), 1);
        assert!(!groups.groups.contains_key(&external_ip));
        assert!(groups.nat_target_refs.is_empty());

        let underlay = groups.groups.get(&underlay_key).unwrap();
        assert_eq!(
            serde_json::to_value(
                MulticastGroupUnderlayResponse::try_from(underlay).unwrap()
            )
            .unwrap(),
            before_group
        );
        assert_eq!(underlay.replication_info().cloned(), before_repl);
        assert_eq!(table_usage(&switch, nat_table), (0, 1, 1, 0));
        let remaining = if fail_source_removal { 3 } else { 0 };
        assert_eq!(
            table_usage(&switch, source_table),
            (remaining, 3, u64::from(3 - remaining), 0)
        );

        let errs = logs.entries.lock().unwrap();
        assert_eq!(errs.len(), remaining as usize, "{errs:?}");
        for (err, source) in errs.iter().zip(source_ips) {
            assert_eq!(err["operation"], "delete source filter entry");
            assert!(err["context"].contains(source));
            assert!(err["error"].contains("table_entry_del"));
        }
    }

    #[test]
    fn test_external_create_failure_preserves_underlay() {
        for group_ip in ["232.1.2.3", "ff3e::4000:1"] {
            external_create_failure(group_ip.parse().unwrap(), false);
        }
    }

    #[test]
    fn test_external_create_failure_with_cleanup_errors() {
        for group_ip in ["232.1.2.3", "ff3e::4000:1"] {
            external_create_failure(group_ip.parse().unwrap(), true);
        }
    }

    #[test]
    fn test_external_vlan_prop_failure_reports_restore_failure() {
        let mut config = Config::default();
        config
            .asic_config
            .table_entry_update
            .values
            .insert(TableType::McastEgressDecapPorts, 1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);

        let before_underlay = {
            let groups = switch.mcast.lock().unwrap();
            serde_json::to_value(
                MulticastGroupUnderlayResponse::try_from(
                    &groups.groups[&underlay_key],
                )
                .unwrap(),
            )
            .unwrap()
        };

        let external_ip: IpAddr = "239.10.10.10".parse().unwrap();
        let (route_table, source_table, nat_table) =
            external_tables(external_ip);
        let before_decap =
            table_usage(&switch, TableType::McastEgressDecapPorts);

        let nat_target = external_nat_target(external_ip, underlay_ip);
        let entry = external_entry(
            external_ip,
            "external-vlan-propagation-test",
            nat_target,
            Some(10),
            serde_json::json!([{ "Exact": "192.0.2.1" }]),
        );

        let err = add_group_external(&switch, entry).unwrap_err();
        assert!(
            matches!(
                err,
                DpdError::Unwind { initial: ref init, .. }
                    if matches!(**init, DpdError::McastGroupFailure(_))
            ),
            "creation error was replaced: {err:?}"
        );

        assert_eq!(table_usage(&switch, route_table), (0, 1, 1, 0));
        assert_eq!(table_usage(&switch, source_table), (0, 1, 1, 0));
        assert_eq!(table_usage(&switch, nat_table), (0, 1, 1, 0));
        assert_eq!(
            table_usage(&switch, TableType::McastEgressDecapPorts),
            before_decap
        );

        let errs = logs.entries.lock().unwrap();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert_eq!(errs[0]["operation"], "restore multicast bitmap VLAN");
        assert!(errs[0]["error"].contains("table_entry_update"));
        let groups = switch.mcast.lock().unwrap();
        assert_eq!(groups.groups.len(), 1);
        assert!(groups.nat_target_refs.is_empty());
        assert_eq!(
            serde_json::to_value(
                MulticastGroupUnderlayResponse::try_from(
                    &groups.groups[&underlay_key]
                )
                .unwrap(),
            )
            .unwrap(),
            before_underlay
        );
    }

    /// Check the rollback process for VLAN changes and NAT retargets on
    /// `external_ip`.
    ///
    /// `retarget` keeps the existing test VLAN and changes the NAT target;
    /// otherwise, the VLAN will get modified. Sources change either way, and
    /// NAT programming will fail.
    ///
    /// A retarget keeps the NAT key and hits the injected `table_entry_update`
    /// failure. A VLAN change attempts to delete the old key first; the injected
    /// `table_entry_del` failure stops it there.
    fn external_update_failure(external_ip: IpAddr, retarget: bool) {
        let (route_table, source_table, nat_table) =
            external_tables(external_ip);
        let mut config = Config::default();
        let failures = if retarget {
            &mut config.asic_config.table_entry_update
        } else {
            &mut config.asic_config.table_entry_del
        };

        failures.values.insert(nat_table, 1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (target_ip, target_key) = if retarget {
            let (ip, key) = install_underlay_group_at(
                &switch,
                "ff04::124".parse().unwrap(),
            );
            (ip, Some(key))
        } else {
            (underlay_ip, None)
        };
        let nat_target = external_nat_target(external_ip, underlay_ip);
        let tag = "external-update-test";

        let entry = external_entry(
            external_ip,
            tag,
            nat_target,
            Some(10),
            serde_json::Value::Null,
        );

        let og = add_group_external(&switch, entry).unwrap();
        let before_route = table_usage(&switch, route_table);
        let before_bitmap =
            table_usage(&switch, TableType::McastEgressDecapPorts);
        let before_filters = table_usage(&switch, source_table);
        let before_route_action = route_action(&switch, external_ip);
        let bitmap_group_ids: Vec<MulticastGroupId> = {
            let groups = switch.mcast.lock().unwrap();
            [Some(underlay_key), target_key]
                .into_iter()
                .flatten()
                .map(|key| groups.groups[&key].external_group_id())
                .collect()
        };

        let before_bitmap_entries: Vec<_> = bitmap_group_ids
            .iter()
            .map(|group_id| bitmap_entry(&switch, *group_id))
            .collect();
        let before_target = target_key.map(|key| {
            let groups = switch.mcast.lock().unwrap();
            serde_json::to_value(
                MulticastGroupUnderlayResponse::try_from(&groups.groups[&key])
                    .unwrap(),
            )
            .unwrap()
        });

        let new_source = SourceEntry::Exact(
            if external_ip.is_ipv4() { "192.0.2.1" } else { "2001:db8::1" }
                .parse()
                .unwrap(),
        );

        let err = modify_group_external(
            &switch,
            ExternalMulticastIp::new(external_ip).unwrap(),
            tag,
            MulticastGroupUpdateExternalEntry {
                internal_forwarding: ExternalInternalForwarding {
                    nat_target: NatTarget {
                        internal_ip: target_ip.into(),
                        ..nat_target
                    }
                    .try_into()
                    .unwrap(),
                },
                external_forwarding: ExternalForwarding {
                    vlan_id: Some(if retarget { 10 } else { 20 }),
                },
                sources: Some(vec![new_source]),
            },
        )
        .unwrap_err();

        assert!(
            matches!(err, DpdError::Switch(_)),
            "update error was replaced or unwound: {err:?}"
        );
        assert_eq!(table_usage(&switch, nat_table), (1, 1, 0, 0));

        let after_route = table_usage(&switch, route_table);
        assert_eq!(
            (after_route.0, after_route.1, after_route.2),
            (before_route.0, before_route.1, before_route.2),
            "route entries were added or removed"
        );
        assert_eq!(
            route_action(&switch, external_ip),
            before_route_action,
            "route action was not restored"
        );

        let after_bitmap =
            table_usage(&switch, TableType::McastEgressDecapPorts);
        assert_eq!(
            (after_bitmap.0, after_bitmap.1, after_bitmap.2),
            (before_bitmap.0, before_bitmap.1, before_bitmap.2),
            "bitmap entries were added or removed"
        );
        assert_eq!(
            bitmap_group_ids
                .iter()
                .map(|group_id| bitmap_entry(&switch, *group_id))
                .collect::<Vec<_>>(),
            before_bitmap_entries,
            "bitmap entries were not restored"
        );

        assert_eq!(
            table_usage(&switch, source_table).0,
            before_filters.0,
            "source filter occupancy was not restored"
        );

        let groups = switch.mcast.lock().unwrap();
        let group_ip = ExternalMulticastIp::new(external_ip).unwrap();
        let group_key = GroupKey::external(group_ip);

        assert_eq!(groups.nat_target_refs.len(), 1);
        assert_eq!(groups.nat_target_refs.get(&underlay_ip), Some(&group_key));

        let group = &groups.groups[&group_key];
        assert_eq!(
            serde_json::to_value(
                MulticastGroupExternalResponse::try_from(group).unwrap()
            )
            .unwrap(),
            serde_json::to_value(og).unwrap()
        );
        assert_eq!(
            group.underlay_group_id(),
            groups.groups[&underlay_key].underlay_group_id()
        );

        if let (Some(key), Some(before)) = (target_key, before_target.as_ref())
        {
            assert_eq!(
                serde_json::to_value(
                    MulticastGroupUnderlayResponse::try_from(
                        &groups.groups[&key]
                    )
                    .unwrap()
                )
                .unwrap(),
                *before,
                "retarget destination group changed"
            );
        }
        remove_source_filter(&switch, external_ip, IpSrc::Any).unwrap();
        assert!(matches!(
            remove_source_filter(&switch, external_ip, new_source.into()),
            Err(DpdError::Switch(aal::AsicError::Missing(_)))
        ));
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_external_update_nat_failure_restores_state() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            external_update_failure(group_ip.parse().unwrap(), false);
        }
    }

    #[test]
    fn test_external_retarget_failure_restores_bitmaps() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            external_update_failure(group_ip.parse().unwrap(), true);
        }
    }

    /// Delete the underlay bitmap entry behind an external group on
    /// `external_ip`, then check that updating the group succeeds and re-adds
    /// the entry.
    ///
    /// `retarget` moves the NAT target to a second underlay group, forcing the
    /// missing entry to be the one whose VLAN gets cleared; otherwise, the VLAN
    /// changes on the same underlay group.
    fn external_update_readds_missing_bitmap(
        external_ip: IpAddr,
        retarget: bool,
    ) {
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, _) = install_underlay_group(&switch);
        let target_ip = if retarget {
            install_underlay_group_at(&switch, "ff04::124".parse().unwrap()).0
        } else {
            underlay_ip
        };
        let nat_target = external_nat_target(external_ip, underlay_ip);
        let tag = "external-readd-test";

        let entry =
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(
                serde_json::json!({
                    "group_ip": external_ip,
                    "tag": tag,
                    "internal_forwarding": { "nat_target": nat_target },
                    "external_forwarding": { "vlan_id": 10 },
                    "sources": null,
                }),
            )
            .unwrap();
        let og = add_group_external(&switch, entry).unwrap();

        table::mcast::mcast_egress::del_bitmap_entry(
            &switch,
            og.external_group_id,
        )
        .unwrap();
        let before_bitmap =
            table_usage(&switch, TableType::McastEgressDecapPorts);

        modify_group_external(
            &switch,
            ExternalMulticastIp::new(external_ip).unwrap(),
            tag,
            MulticastGroupUpdateExternalEntry {
                internal_forwarding: ExternalInternalForwarding {
                    nat_target: NatTarget {
                        internal_ip: target_ip.into(),
                        ..nat_target
                    }
                    .try_into()
                    .unwrap(),
                },
                external_forwarding: ExternalForwarding {
                    vlan_id: Some(if retarget { 10 } else { 20 }),
                },
                sources: None,
            },
        )
        .unwrap();

        let after_bitmap =
            table_usage(&switch, TableType::McastEgressDecapPorts);
        assert_eq!(after_bitmap.0, before_bitmap.0 + 1, "bitmap not re-added");
        assert_eq!(after_bitmap.1, before_bitmap.1 + 1);
        assert_eq!(
            table_usage(&switch, TableType::McastIpv6).0,
            if retarget { 2 } else { 1 }
        );
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_external_vlan_update_readds_missing_bitmap() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            external_update_readds_missing_bitmap(
                group_ip.parse().unwrap(),
                false,
            );
        }
    }

    #[test]
    fn test_external_retarget_readds_missing_bitmap() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            external_update_readds_missing_bitmap(
                group_ip.parse().unwrap(),
                true,
            );
        }
    }

    #[test]
    fn test_external_update_failure_keeps_readded_bitmap() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (_, _, nat_table) = external_tables(external_ip);
            let mut config = Config::default();
            config.asic_config.table_entry_del.values.insert(nat_table, 1.0);

            let (switch, logs) = chaos_switch(config);
            let (underlay_ip, _) = install_underlay_group(&switch);
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-readd-rollback-test";

            let entry = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(serde_json::json!({
                "group_ip": external_ip,
                "tag": tag,
                "internal_forwarding": { "nat_target": nat_target },
                "external_forwarding": { "vlan_id": 10 },
                "sources": null,
            }))
            .unwrap();
            let og = add_group_external(&switch, entry).unwrap();
            table::mcast::mcast_egress::del_bitmap_entry(
                &switch,
                og.external_group_id,
            )
            .unwrap();

            let err = modify_group_external(
                &switch,
                ExternalMulticastIp::new(external_ip).unwrap(),
                tag,
                MulticastGroupUpdateExternalEntry {
                    internal_forwarding: ExternalInternalForwarding {
                        nat_target: nat_target.try_into().unwrap(),
                    },
                    external_forwarding: ExternalForwarding {
                        vlan_id: Some(20),
                    },
                    sources: None,
                },
            )
            .unwrap_err();
            assert!(matches!(err, DpdError::Switch(_)), "{err:?}");

            let dump =
                table::mcast::mcast_egress::bitmap_table_dump(&switch, false)
                    .unwrap();
            assert_eq!(dump.entries.len(), 1, "re-added bitmap was removed");
            assert_eq!(
                dump.entries[0].action_args.get("vlan_id").map(String::as_str),
                Some("10")
            );
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_external_create_clears_orphaned_entries() {
        for (group_ip, stale_source, source) in [
            ("224.1.2.3", "192.0.2.9", "192.0.2.1"),
            ("ff0e::1", "2001:db8::9", "2001:db8::1"),
        ] {
            let (switch, logs) = chaos_switch(Config::default());
            let (underlay_ip, _) = install_underlay_group(&switch);
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (route_table, source_table, nat_table) =
                external_tables(external_ip);
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let stale_source: IpAddr = stale_source.parse().unwrap();

            match (external_ip, stale_source) {
                (IpAddr::V4(group), IpAddr::V4(src)) => {
                    table::mcast::mcast_nat::add_ipv4_entry(
                        &switch,
                        group,
                        nat_target,
                        Some(10),
                    )
                    .unwrap();
                    table::mcast::mcast_src_filter::add_ipv4_entry(
                        &switch,
                        oxnet::Ipv4Net::host_net(src),
                        group,
                    )
                    .unwrap();
                    table::mcast::mcast_route::add_ipv4_entry(
                        &switch,
                        group,
                        Some(10),
                    )
                    .unwrap();
                }
                (IpAddr::V6(group), IpAddr::V6(src)) => {
                    table::mcast::mcast_nat::add_ipv6_entry(
                        &switch,
                        group,
                        nat_target,
                        Some(10),
                    )
                    .unwrap();
                    table::mcast::mcast_src_filter::add_ipv6_entry(
                        &switch,
                        oxnet::Ipv6Net::host_net(src),
                        group,
                    )
                    .unwrap();
                    table::mcast::mcast_route::add_ipv6_entry(
                        &switch,
                        group,
                        Some(10),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let before: Vec<_> = [route_table, source_table, nat_table]
                .into_iter()
                .map(|table| table_usage(&switch, table))
                .collect();

            let entry = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(serde_json::json!({
                "group_ip": external_ip,
                "tag": "external-orphan-test",
                "internal_forwarding": { "nat_target": nat_target },
                "external_forwarding": { "vlan_id": 20 },
                "sources": [{ "Exact": source }],
            }))
            .unwrap();
            add_group_external(&switch, entry).unwrap();

            for (table, before) in
                [route_table, source_table, nat_table].into_iter().zip(before)
            {
                assert_eq!(
                    table_usage(&switch, table),
                    (before.0, before.1 + 1, before.2 + 1, before.3),
                    "{table}"
                );
            }
            let nat_dump = match external_ip {
                IpAddr::V4(_) => {
                    table::mcast::mcast_nat::ipv4_table_dump(&switch, false)
                }
                IpAddr::V6(_) => {
                    table::mcast::mcast_nat::ipv6_table_dump(&switch, false)
                }
            }
            .unwrap();
            assert_eq!(nat_dump.entries.len(), 1);
            assert_eq!(
                nat_dump.entries[0].keys.get("vlan_id").map(String::as_str),
                Some("20")
            );
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_underlay_update_readds_missing_entries() {
        let (switch, logs) = chaos_switch(Config::default());
        let free_ids = {
            let groups = switch.mcast.lock().unwrap();
            groups.free_group_ids.lock().unwrap().len()
        };
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (external_id, tag, members) = {
            let groups = switch.mcast.lock().unwrap();
            let group = &groups.groups[&underlay_key];
            (
                group.external_group_id(),
                group.tag.clone(),
                group.members().cloned().collect::<Vec<_>>(),
            )
        };
        table::mcast::mcast_egress::del_bitmap_entry(&switch, external_id)
            .unwrap();
        table::mcast::mcast_replication::del_ipv6_entry(
            &switch,
            underlay_ip.into(),
        )
        .unwrap();

        let new_members: Vec<_> = members
            .iter()
            .filter(|member| member.direction == Direction::Underlay)
            .cloned()
            .collect();
        assert!(!new_members.is_empty() && new_members.len() < members.len());

        let response = modify_group_underlay(
            &switch,
            underlay_ip,
            &tag,
            MulticastGroupUpdateUnderlayEntry { members: new_members.clone() },
        )
        .unwrap();
        assert_eq!(response.members, new_members);

        let groups = switch.mcast.lock().unwrap();
        assert!(groups.groups.contains_key(&underlay_key));
        assert_eq!(groups.free_group_ids.lock().unwrap().len(), free_ids - 2);
        for table in [
            TableType::McastIpv6,
            TableType::RouteIpv6Mcast,
            TableType::McastEgressDecapPorts,
        ] {
            assert_eq!(table_usage(&switch, table).0, 1, "{table}");
        }
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    fn external_update_after_underlay_abandoned(retarget: bool) {
        let (switch, _logs) = chaos_switch(Config::default());
        let free_ids = {
            let groups = switch.mcast.lock().unwrap();
            groups.free_group_ids.lock().unwrap().len()
        };
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);

        let external_ip: IpAddr = "ff0e::1".parse().unwrap();
        let group_ip = ExternalMulticastIp::new(external_ip).unwrap();
        let external_key = GroupKey::external(group_ip);
        let nat_target = external_nat_target(external_ip, underlay_ip);
        let tag = "external-abandon-test";
        let entry =
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(
                serde_json::json!({
                    "group_ip": external_ip,
                    "tag": tag,
                    "internal_forwarding": { "nat_target": nat_target },
                    "external_forwarding": { "vlan_id": null },
                    "sources": null,
                }),
            )
            .unwrap();
        add_group_external(&switch, entry).unwrap();

        let underlay =
            switch.mcast.lock().unwrap().groups.remove(&underlay_key).unwrap();
        let ipv6 = Ipv6Addr::from(underlay_ip);
        table::mcast::mcast_egress::del_bitmap_entry(
            &switch,
            underlay.external_group_id(),
        )
        .unwrap();
        table::mcast::mcast_replication::del_ipv6_entry(&switch, ipv6).unwrap();
        table::mcast::mcast_route::del_ipv6_entry(&switch, ipv6).unwrap();
        drop(underlay);

        {
            let groups = switch.mcast.lock().unwrap();
            assert_eq!(groups.groups.len(), 1);
            assert!(groups.groups.contains_key(&external_key));
            assert_eq!(
                groups.nat_target_refs.get(&underlay_ip),
                Some(&external_key)
            );
            assert_eq!(
                groups.free_group_ids.lock().unwrap().len(),
                free_ids - 2
            );
        }

        let update = |internal_ip: UnderlayMulticastIpv6| {
            MulticastGroupUpdateExternalEntry {
                internal_forwarding: ExternalInternalForwarding {
                    nat_target: NatTarget {
                        internal_ip: internal_ip.into(),
                        ..nat_target
                    }
                    .try_into()
                    .unwrap(),
                },
                external_forwarding: ExternalForwarding { vlan_id: None },
                sources: None,
            }
        };

        let err =
            modify_group_external(&switch, group_ip, tag, update(underlay_ip))
                .unwrap_err();
        assert!(matches!(err, DpdError::MissingNatTarget(_)), "{err:?}");
        let http_err = dropshot::HttpError::from(err);
        assert_eq!(http_err.status_code.as_u16(), 409);
        assert_eq!(
            http_err.error_code.as_deref(),
            Some(common::MISSING_NAT_TARGET_ERROR_CODE)
        );

        let (target_ip, target_key) = if retarget {
            install_underlay_group_at(&switch, "ff04::124".parse().unwrap())
        } else {
            install_underlay_group_at(&switch, underlay_ip)
        };

        let response =
            modify_group_external(&switch, group_ip, tag, update(target_ip))
                .unwrap();
        let groups = switch.mcast.lock().unwrap();
        let target = &groups.groups[&target_key];
        assert_eq!(response.external_group_id, target.external_group_id());
        assert_eq!(
            groups.groups[&external_key].underlay_group_id(),
            target.underlay_group_id()
        );
        assert_eq!(groups.nat_target_refs.len(), 1);
        assert_eq!(groups.nat_target_refs.get(&target_ip), Some(&external_key));
        assert_eq!(groups.free_group_ids.lock().unwrap().len(), free_ids - 2);
    }

    #[test]
    fn test_underlay_rollback_restores_propagated_vlan() {
        for fail_port_add in [false, true] {
            let mut config = Config::default();
            config
                .asic_config
                .table_entry_del
                .values
                .insert(TableType::McastIpv6, 1.0);
            if fail_port_add {
                config.asic_config.mc_config.mc_port_add =
                    asic::chaos::Chaos::new(1.0);
            }
            let (switch, _logs) = chaos_switch(config);
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);

            let external_ip: IpAddr = "ff0e::1".parse().unwrap();
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let entry = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(serde_json::json!({
                "group_ip": external_ip,
                "tag": "external-vlan-rollback-test",
                "internal_forwarding": { "nat_target": nat_target },
                "external_forwarding": { "vlan_id": 10 },
                "sources": null,
            }))
            .unwrap();
            add_group_external(&switch, entry).unwrap();

            let bitmap_vlan = || {
                let dump = table::mcast::mcast_egress::bitmap_table_dump(
                    &switch, false,
                )
                .unwrap();
                assert_eq!(dump.entries.len(), 1);
                dump.entries[0].action_args.get("vlan_id").cloned()
            };
            assert_eq!(bitmap_vlan().as_deref(), Some("10"));

            let (underlay_tag, members) =
                underlay_tag_and_members(&switch, underlay_key);

            let err = modify_group_underlay(
                &switch,
                underlay_ip,
                &underlay_tag,
                MulticastGroupUpdateUnderlayEntry { members: Vec::new() },
            )
            .unwrap_err();

            let init = match &err {
                DpdError::Unwind { initial: init, unwind } => {
                    assert!(
                        fail_port_add
                            && unwind.len() == 1
                            && matches!(
                                &unwind.head,
                                DpdError::Switch(
                                    aal::AsicError::Synthetic(op)
                                ) if op == "mc_port_add"
                            ),
                        "{err:?}"
                    );
                    init.as_ref()
                }
                err => {
                    assert!(!fail_port_add, "{err:?}");
                    err
                }
            };
            assert!(
                matches!(
                    init,
                    DpdError::Switch(aal::AsicError::Synthetic(op))
                        if op == "table_entry_del"
                ),
                "{err:?}"
            );
            assert_eq!(bitmap_vlan().as_deref(), Some("10"));
            assert_eq!(
                underlay_tag_and_members(&switch, underlay_key).1,
                members
            );
        }
    }

    fn nat_vlan_change_failure(
        group_ip: IpAddr,
        restore_fails: bool,
    ) -> (Switch, TableType, DpdError) {
        let (switch, _logs) = chaos_switch(Config::default());
        let (_, _, nat_table) = external_tables(group_ip);
        let tgt = external_nat_target(group_ip, "ff04::123".parse().unwrap());
        let (old_vlan, new_vlan) = (Some(10), Some(4095));

        match group_ip {
            IpAddr::V4(ip) => {
                mcast_nat::add_ipv4_entry(&switch, ip, tgt, old_vlan)
            }
            IpAddr::V6(ip) => {
                mcast_nat::add_ipv6_entry(&switch, ip, tgt, old_vlan)
            }
        }
        .unwrap();

        if restore_fails {
            switch.table_get(nat_table).unwrap().usage.size = 0;
        }

        let err = match group_ip {
            IpAddr::V4(ip) => mcast_nat::update_ipv4_entry(
                &switch, ip, tgt, tgt, old_vlan, new_vlan,
            ),
            IpAddr::V6(ip) => mcast_nat::update_ipv6_entry(
                &switch, ip, tgt, tgt, old_vlan, new_vlan,
            ),
        }
        .unwrap_err();

        (switch, nat_table, err)
    }

    #[test]
    fn test_nat_vlan_change_failure_restores_entry() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            let group_ip: IpAddr = group_ip.parse().unwrap();
            let (switch, nat_table, err) =
                nat_vlan_change_failure(group_ip, false);

            assert!(!matches!(err, DpdError::Unwind { .. }), "{err:?}");
            assert_eq!(table_usage(&switch, nat_table), (1, 2, 1, 0));

            let dump = match group_ip {
                IpAddr::V4(_) => mcast_nat::ipv4_table_dump(&switch, false),
                IpAddr::V6(_) => mcast_nat::ipv6_table_dump(&switch, false),
            }
            .unwrap();
            assert_eq!(dump.entries.len(), 1);
            assert_eq!(
                dump.entries[0].keys.get("vlan_id").map(String::as_str),
                Some("10"),
                "{:?}",
                dump.entries[0].keys
            );
        }
    }

    #[test]
    fn test_nat_vlan_change_failure_reports_lost_entry() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            let (switch, nat_table, err) =
                nat_vlan_change_failure(group_ip.parse().unwrap(), true);

            assert!(
                matches!(
                    err,
                    DpdError::Unwind { ref unwind, .. }
                        if unwind.len() == 1
                            && matches!(unwind.head, DpdError::TableFull(_))
                ),
                "{err:?}"
            );
            assert_eq!(table_usage(&switch, nat_table), (0, 1, 1, 0));
        }
    }

    #[test]
    fn test_underlay_first_members_overwrite_stale_bitmap() {
        let (switch, logs) = chaos_switch(Config::default());
        let (_, underlay_key) = install_empty_underlay_group(&switch);
        let group = switch.mcast.lock().unwrap().groups[&underlay_key].clone();

        table::mcast::mcast_egress::add_bitmap_entry(
            &switch,
            group.external_group_id(),
            &table::mcast::mcast_egress::PortBitmap::new(),
            Some(10),
        )
        .unwrap();

        let members = vec![MulticastGroupMember {
            port_id: RearPort::new(0).unwrap().into(),
            link_id: LinkId(0),
            direction: Direction::External,
        }];
        update_underlay_group_bitmap_tables(&switch, &group, &members, None)
            .unwrap();

        assert_eq!(
            table_usage(&switch, TableType::McastEgressDecapPorts),
            (1, 1, 0, 1)
        );
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_del_empty_underlay_clears_stale_entries() {
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_empty_underlay_group(&switch);
        let group = switch.mcast.lock().unwrap().groups[&underlay_key].clone();
        let repl = MulticastReplicationInfo::new(group.external_group_id());

        table::mcast::mcast_egress::add_bitmap_entry(
            &switch,
            group.external_group_id(),
            &table::mcast::mcast_egress::PortBitmap::new(),
            None,
        )
        .unwrap();
        table::mcast::mcast_replication::add_ipv6_entry(
            &switch,
            underlay_ip.into(),
            group.underlay_group_id(),
            group.external_group_id(),
            repl.rid,
            repl.level1_excl_id,
            repl.level2_excl_id,
        )
        .unwrap();

        del_group(&switch, underlay_key.ip(), &group.tag).unwrap();

        for table in [
            TableType::McastIpv6,
            TableType::McastEgressDecapPorts,
            TableType::RouteIpv6Mcast,
        ] {
            assert_eq!(table_usage(&switch, table), (0, 1, 1, 0), "{table}");
        }
        assert!(switch.mcast.lock().unwrap().groups.is_empty());
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_underlay_create_clears_stale_entries() {
        let mut config = Config::default();
        config.asic_config.mc_config.mc_group_create =
            asic::chaos::Chaos::new(1.0);

        let (switch, _logs) = chaos_switch(config);
        let free_ids = {
            let groups = switch.mcast.lock().unwrap();
            groups.free_group_ids.lock().unwrap().len()
        };
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        drop(switch.mcast.lock().unwrap().groups.remove(&underlay_key));

        let err = add_group_underlay(
            &switch,
            MulticastGroupCreateUnderlayEntry {
                group_ip: underlay_ip,
                tag: Some("underlay-stale-test".to_string()),
                members: Vec::new(),
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, DpdError::Switch(aal::AsicError::Synthetic(_))),
            "{err:?}"
        );

        for table in [TableType::McastIpv6, TableType::RouteIpv6Mcast] {
            assert_eq!(table_usage(&switch, table), (0, 1, 1, 0), "{table}");
        }
        let groups = switch.mcast.lock().unwrap();
        assert!(groups.groups.is_empty());
        assert_eq!(groups.free_group_ids.lock().unwrap().len(), free_ids);
    }

    #[test]
    fn test_external_update_after_underlay_abandoned_recreate() {
        external_update_after_underlay_abandoned(false);
    }

    #[test]
    fn test_external_update_after_underlay_abandoned_retarget() {
        external_update_after_underlay_abandoned(true);
    }

    #[test]
    fn test_external_create_rejects_deleted_underlay() {
        let (switch, logs) = chaos_switch(Config::default());
        let free_ids = {
            let groups = switch.mcast.lock().unwrap();
            groups.free_group_ids.lock().unwrap().len()
        };
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (tag, _) = underlay_tag_and_members(&switch, underlay_key);
        del_group(&switch, underlay_key.ip(), &tag).unwrap();

        let tables = [
            TableType::McastIpv6,
            TableType::McastEgressDecapPorts,
            TableType::RouteIpv6Mcast,
            TableType::RouteIpv4Mcast,
            TableType::McastIpv4SrcFilter,
            TableType::McastIpv6SrcFilter,
            TableType::NatIngressIpv4Mcast,
            TableType::NatIngressIpv6Mcast,
        ];

        let before: BTreeMap<_, _> = tables
            .into_iter()
            .map(|table| (table, table_usage(&switch, table)))
            .collect();

        for external_ip in ["239.1.2.3", "ff0e::1"] {
            let external_ip: IpAddr = external_ip.parse().unwrap();
            let entry = external_entry(
                external_ip,
                "external-deleted-underlay-test",
                external_nat_target(external_ip, underlay_ip),
                Some(10),
                serde_json::Value::Null,
            );

            let err = add_group_external(&switch, entry).unwrap_err();
            assert!(matches!(err, DpdError::MissingNatTarget(_)), "{err:?}");
            let http_err = dropshot::HttpError::from(err);
            assert_eq!(http_err.status_code.as_u16(), 409);
            assert_eq!(
                http_err.error_code.as_deref(),
                Some(common::MISSING_NAT_TARGET_ERROR_CODE)
            );
        }

        for (table, usage) in before {
            assert_eq!(table_usage(&switch, table), usage, "{table}");
        }

        let groups = switch.mcast.lock().unwrap();
        assert!(groups.groups.is_empty());
        assert!(groups.nat_target_refs.is_empty());
        assert_eq!(groups.free_group_ids.lock().unwrap().len(), free_ids);
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_del_external_nat_failure_keeps_underlay_vlan() {
        let external_ip: IpAddr = "239.1.2.3".parse().unwrap();
        let (_, source_table, nat_table) = external_tables(external_ip);
        let mut config = Config::default();
        config.asic_config.table_entry_del.values.insert(nat_table, 1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, _) = install_underlay_group(&switch);
        let nat_target = external_nat_target(external_ip, underlay_ip);
        let tag = "external-del-nat-failure-test";

        let entry =
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(
                serde_json::json!({
                    "group_ip": external_ip,
                    "tag": tag,
                    "internal_forwarding": { "nat_target": nat_target },
                    "external_forwarding": { "vlan_id": 10 },
                    "sources": null,
                }),
            )
            .unwrap();
        add_group_external(&switch, entry).unwrap();

        let before_decap =
            table_usage(&switch, TableType::McastEgressDecapPorts);
        assert_eq!(before_decap, (1, 1, 0, 1));
        let before_filters = table_usage(&switch, source_table);
        assert_eq!(before_filters.0, 1);

        let err = del_group(&switch, external_ip, tag).unwrap_err();
        assert!(matches!(err, DpdError::Switch(_)), "{err:?}");

        assert_eq!(
            table_usage(&switch, TableType::McastEgressDecapPorts),
            before_decap,
            "underlay VLAN was cleared"
        );
        assert_eq!(table_usage(&switch, nat_table), (1, 1, 0, 0));
        assert_eq!(
            table_usage(&switch, source_table),
            (1, 2, 1, 0),
            "source filters were not restored"
        );

        let external_key =
            GroupKey::external(ExternalMulticastIp::new(external_ip).unwrap());
        let groups = switch.mcast.lock().unwrap();
        assert!(groups.groups.contains_key(&external_key));
        assert_eq!(
            groups.nat_target_refs.get(&underlay_ip),
            Some(&external_key)
        );
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_underlay_bitmap_failure_skips_repl_and_route() {
        let mut config = Config::default();
        config
            .asic_config
            .table_entry_add
            .values
            .insert(TableType::McastEgressDecapPorts, 1.0);

        let (switch, logs) = chaos_switch(config);
        let underlay_ip: UnderlayMulticastIpv6 = "ff04::123".parse().unwrap();
        let (external_scoped_group, underlay_scoped_group) = {
            let mut groups = switch.mcast.lock().unwrap();
            (
                groups.generate_group_id().unwrap(),
                groups.generate_group_id().unwrap(),
            )
        };
        let repl = MulticastReplicationInfo::new(external_scoped_group.id());
        let members = vec![MulticastGroupMember {
            port_id: RearPort::new(0).unwrap().into(),
            link_id: LinkId(0),
            direction: Direction::External,
        }];

        let before: Vec<_> = [
            TableType::McastEgressDecapPorts,
            TableType::McastIpv6,
            TableType::RouteIpv6Mcast,
        ]
        .into_iter()
        .map(|table| (table, table_usage(&switch, table)))
        .collect();

        let err = configure_underlay_tables(
            &switch,
            underlay_ip,
            external_scoped_group.id(),
            underlay_scoped_group.id(),
            Some(&repl),
            &members,
            Some(10),
        )
        .unwrap_err();
        assert!(matches!(err, DpdError::Switch(_)), "{err:?}");

        for (table, before) in before {
            assert_eq!(table_usage(&switch, table), before, "{table}");
        }
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_reset_tag_underlay_failure_after_externals() {
        let mut config = Config::default();
        config.asic_config.mc_config.mc_group_destroy =
            asic::chaos::Chaos::new(1.0);

        let (switch, logs) = chaos_switch(config);
        let tag = "reset-tag-failure-test";
        let underlay_ips: [UnderlayMulticastIpv6; 2] =
            ["ff04::123", "ff04::124"].map(|ip| ip.parse().unwrap());
        let external_ips: [IpAddr; 2] =
            ["239.1.2.3", "ff0e::1"].map(|ip| ip.parse().unwrap());
        let other_ip: UnderlayMulticastIpv6 = "ff04::125".parse().unwrap();

        for group_ip in underlay_ips.into_iter().chain([other_ip]) {
            let group_tag =
                if group_ip == other_ip { "reset-tag-other-test" } else { tag };
            add_group_underlay(
                &switch,
                MulticastGroupCreateUnderlayEntry {
                    group_ip,
                    tag: Some(group_tag.to_string()),
                    members: Vec::new(),
                },
            )
            .unwrap();
        }

        for (external_ip, underlay_ip) in
            external_ips.into_iter().zip(underlay_ips)
        {
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let entry = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(serde_json::json!({
                "group_ip": external_ip,
                "tag": tag,
                "internal_forwarding": { "nat_target": nat_target },
                "external_forwarding": { "vlan_id": null },
                "sources": null,
            }))
            .unwrap();
            add_group_external(&switch, entry).unwrap();
        }

        let err = reset_tag(&switch, tag).unwrap_err();
        assert!(matches!(err, DpdError::Switch(_)), "{err:?}");

        let groups = switch.mcast.lock().unwrap();
        for external_ip in external_ips {
            assert!(!groups.groups.contains_key(&external_ip));
        }
        for underlay_ip in underlay_ips {
            assert!(groups.groups.contains_key(&IpAddr::from(underlay_ip)));
        }
        assert!(groups.groups.contains_key(&IpAddr::from(other_ip)));
        assert_eq!(groups.groups.len(), 3);
        assert!(groups.nat_target_refs.is_empty());
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_del_underlay_bitmap_failure_restores_repl() {
        let mut config = Config::default();
        config
            .asic_config
            .table_entry_del
            .values
            .insert(TableType::McastEgressDecapPorts, 1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (tag, members) = underlay_tag_and_members(&switch, underlay_key);
        let before_repl = table_usage(&switch, TableType::McastIpv6);
        assert_eq!(before_repl.0, 1);

        let err = del_group(&switch, underlay_key.ip(), &tag).unwrap_err();
        assert!(matches!(err, DpdError::Switch(_)), "{err:?}");

        assert_eq!(
            table_usage(&switch, TableType::McastIpv6).0,
            before_repl.0,
            "replication entry was not restored"
        );
        assert!(
            switch.mcast.lock().unwrap().groups.contains_key(&underlay_key)
        );
        assert!(logs.entries.lock().unwrap().is_empty());

        let response = modify_group_underlay(
            &switch,
            underlay_ip,
            &tag,
            MulticastGroupUpdateUnderlayEntry { members: members.clone() },
        )
        .unwrap();
        assert_eq!(response.members, members);
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_del_external_restore_failure_reports_unwind() {
        let external_ip: IpAddr = "239.1.2.3".parse().unwrap();
        let (route_table, source_table, nat_table) =
            external_tables(external_ip);
        let mut config = Config::default();
        config.asic_config.table_entry_del.values.insert(nat_table, 1.0);
        config.asic_config.table_entry_add.values.insert(source_table, 1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let nat_target = external_nat_target(external_ip, underlay_ip);
        let IpAddr::V4(ipv4) = external_ip else { unreachable!() };
        mcast_nat::add_ipv4_entry(&switch, ipv4, nat_target, None).unwrap();
        table::mcast::mcast_route::add_ipv4_entry(&switch, ipv4, None).unwrap();

        let tag = "external-del-restore-failure-test";
        let group_ip = ExternalMulticastIp::new(external_ip).unwrap();
        let external_key = GroupKey::external(group_ip);
        {
            let mut groups = switch.mcast.lock().unwrap();
            let underlay = &groups.groups[&underlay_key];
            let external = MulticastGroup {
                external_scoped_group: underlay.external_scoped_group.clone(),
                underlay_scoped_group: underlay.underlay_scoped_group.clone(),
                tag: tag.to_string(),
                kind: GroupKind::External {
                    group_ip,
                    nat_target: nat_target.try_into().unwrap(),
                    vlan_id: None,
                    sources: SourceFilter::from_exact(["192.0.2.1"
                        .parse::<ExactSource>()
                        .unwrap()]),
                },
            };
            groups.groups.insert(external_key, external);
            groups.add_forwarding_refs(external_key, underlay_ip);
        }

        let before_route = table_usage(&switch, route_table);

        let err = del_group(&switch, external_ip, tag).unwrap_err();
        assert!(
            matches!(
                err,
                DpdError::Unwind { initial: ref init, ref unwind }
                    if matches!(**init, DpdError::Switch(_))
                        && unwind.len() == 1
            ),
            "{err:?}"
        );

        let http_err = dropshot::HttpError::from(err);
        assert_eq!(http_err.status_code.as_u16(), 418);
        assert_eq!(
            http_err.error_code.as_deref(),
            Some(common::ROLLBACK_FAILURE_ERROR_CODE)
        );

        assert_eq!(table_usage(&switch, nat_table), (1, 1, 0, 0));
        assert_eq!(table_usage(&switch, route_table), before_route);
        assert_eq!(table_usage(&switch, source_table).0, 0);

        let errs = logs.entries.lock().unwrap();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert_eq!(errs[0]["operation"], "restore source filter entry");
        assert!(errs[0]["context"].contains("192.0.2.1"));
        assert!(errs[0]["error"].contains("table_entry_add"));

        let groups = switch.mcast.lock().unwrap();
        assert!(groups.groups.contains_key(&external_key));
        assert_eq!(
            groups.nat_target_refs.get(&underlay_ip),
            Some(&external_key)
        );
    }

    #[test]
    fn test_external_update_readds_missing_source_filters() {
        for (group_ip, source_ips) in [
            ("224.1.2.3", ["192.0.2.1", "192.0.2.2"]),
            ("ff0e::1", ["2001:db8::1", "2001:db8::2"]),
        ] {
            let (switch, logs) = chaos_switch(Config::default());
            let (underlay_ip, _) = install_underlay_group(&switch);
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (_, source_table, _) = external_tables(external_ip);
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-readd-sources-test";

            let entry = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(serde_json::json!({
                "group_ip": external_ip,
                "tag": tag,
                "internal_forwarding": { "nat_target": nat_target },
                "external_forwarding": { "vlan_id": 10 },
                "sources": source_ips.map(|ip| {
                    serde_json::json!({ "Exact": ip })
                }),
            }))
            .unwrap();

            add_group_external(&switch, entry).unwrap();
            assert_eq!(table_usage(&switch, source_table).0, 2);

            for source_ip in source_ips {
                match (external_ip, source_ip.parse::<IpAddr>().unwrap()) {
                    (IpAddr::V4(group), IpAddr::V4(source)) => {
                        table::mcast::mcast_src_filter::del_ipv4_entry(
                            &switch,
                            oxnet::Ipv4Net::host_net(source),
                            group,
                        )
                    }
                    (IpAddr::V6(group), IpAddr::V6(source)) => {
                        table::mcast::mcast_src_filter::del_ipv6_entry(
                            &switch,
                            oxnet::Ipv6Net::host_net(source),
                            group,
                        )
                    }
                    _ => unreachable!(),
                }
                .unwrap();
            }
            assert_eq!(table_usage(&switch, source_table).0, 0);

            let sources = source_ips
                .map(|ip| SourceEntry::Exact(ip.parse().unwrap()))
                .to_vec();
            modify_group_external(
                &switch,
                ExternalMulticastIp::new(external_ip).unwrap(),
                tag,
                MulticastGroupUpdateExternalEntry {
                    internal_forwarding: ExternalInternalForwarding {
                        nat_target: nat_target.try_into().unwrap(),
                    },
                    external_forwarding: ExternalForwarding {
                        vlan_id: Some(10),
                    },
                    sources: Some(sources),
                },
            )
            .unwrap();

            assert_eq!(
                table_usage(&switch, source_table).0,
                2,
                "source filters were not re-added"
            );
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_underlay_update_readds_missing_repl() {
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (tag, members) = underlay_tag_and_members(&switch, underlay_key);

        table::mcast::mcast_replication::del_ipv6_entry(
            &switch,
            underlay_ip.into(),
        )
        .unwrap();
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 0);

        let response = modify_group_underlay(
            &switch,
            underlay_ip,
            &tag,
            MulticastGroupUpdateUnderlayEntry { members: members.clone() },
        )
        .unwrap();
        assert_eq!(response.members, members);

        assert_eq!(
            table_usage(&switch, TableType::McastIpv6).0,
            1,
            "replication entry was not re-added"
        );
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_underlay_update_rollback_readds_missing_repl() {
        for fail_port_remove in [false, true] {
            let mut config = Config::default();
            config
                .asic_config
                .table_entry_update
                .values
                .insert(TableType::McastEgressDecapPorts, 1.0);
            if fail_port_remove {
                config.asic_config.mc_config.mc_port_remove =
                    asic::chaos::Chaos::new(1.0);
            }

            let (switch, logs) = chaos_switch(config);
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);
            let (tag, members) =
                underlay_tag_and_members(&switch, underlay_key);

            table::mcast::mcast_replication::del_ipv6_entry(
                &switch,
                underlay_ip.into(),
            )
            .unwrap();

            let before_repl = table_usage(&switch, TableType::McastIpv6);
            assert_eq!(before_repl.0, 0);

            let mut new_members = members.clone();
            new_members.push(MulticastGroupMember {
                port_id: RearPort::new(2).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            });

            let err = modify_group_underlay(
                &switch,
                underlay_ip,
                &tag,
                MulticastGroupUpdateUnderlayEntry { members: new_members },
            )
            .unwrap_err();

            let rollback_op = if fail_port_remove {
                "mc_port_remove"
            } else {
                "table_entry_update"
            };
            assert!(
                matches!(
                    err,
                    DpdError::Unwind { initial: ref init, ref unwind }
                        if matches!(
                            init.as_ref(),
                            DpdError::Switch(
                                aal::AsicError::Synthetic(op)
                            ) if op == "table_entry_update"
                        ) && unwind.len() == 1
                            && matches!(
                                &unwind.head,
                                DpdError::Switch(
                                    aal::AsicError::Synthetic(op)
                                ) if op == rollback_op
                            )
                ),
                "{err:?}"
            );

            assert_eq!(
                table_usage(&switch, TableType::McastIpv6),
                (1, before_repl.1 + 1, before_repl.2, before_repl.3),
                "replication entry was not re-added by rollback"
            );

            let errs = logs.entries.lock().unwrap();
            let expected: &[(&str, &str)] = if fail_port_remove {
                &[
                    ("port changes", "mc_port_remove"),
                    ("restore VLAN settings", "table_entry_update"),
                ]
            } else {
                &[("restore VLAN settings", "table_entry_update")]
            };
            assert_eq!(errs.len(), expected.len(), "{errs:?}");
            for (err, &(op, failed_call)) in errs.iter().zip(expected) {
                assert_eq!(err["operation"], op);
                assert!(err["error"].contains(failed_call));
            }

            let groups = switch.mcast.lock().unwrap();
            let group = &groups.groups[&underlay_key];
            assert_eq!(group.members().cloned().collect::<Vec<_>>(), members);
        }
    }

    #[test]
    fn test_del_external_rollback_bitmap_readd_hits_full_table() {
        let external_ip: IpAddr = "239.1.2.3".parse().unwrap();
        let (route_table, _, nat_table) = external_tables(external_ip);
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let nat_target = external_nat_target(external_ip, underlay_ip);
        let tag = "external-del-missing-bitmap-test";

        let entry =
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(
                serde_json::json!({
                    "group_ip": external_ip,
                    "tag": tag,
                    "internal_forwarding": { "nat_target": nat_target },
                    "external_forwarding": { "vlan_id": 10 },
                    "sources": null,
                }),
            )
            .unwrap();
        add_group_external(&switch, entry).unwrap();

        let external_group_id = switch.mcast.lock().unwrap().groups
            [&underlay_key]
            .external_group_id();
        table::mcast::mcast_egress::del_bitmap_entry(
            &switch,
            external_group_id,
        )
        .unwrap();

        {
            let mut decap =
                switch.table_get(TableType::McastEgressDecapPorts).unwrap();
            decap.usage.size = decap.usage.occupancy;
        }

        let before_decap =
            table_usage(&switch, TableType::McastEgressDecapPorts);
        assert_eq!(before_decap.0, 0);

        let err = del_group(&switch, external_ip, tag).unwrap_err();
        assert!(
            matches!(
                err,
                DpdError::Unwind { initial: ref init, ref unwind }
                    if matches!(**init, DpdError::TableFull(_))
                        && unwind.len() == 1
                        && matches!(unwind.head, DpdError::TableFull(_))
            ),
            "{err:?}"
        );

        assert_eq!(
            table_usage(&switch, TableType::McastEgressDecapPorts),
            before_decap
        );
        assert!(bitmap_entry(&switch, external_group_id).is_none());
        assert_eq!(table_usage(&switch, nat_table).0, 1);
        assert_eq!(table_usage(&switch, route_table).0, 1);
        assert_eq!(
            route_action(&switch, external_ip)
                .and_then(|(_, vlan_id)| vlan_id)
                .as_deref(),
            Some("10")
        );

        let errs = logs.entries.lock().unwrap();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert_eq!(errs[0]["operation"], "restore multicast bitmap VLAN");

        let external_key =
            GroupKey::external(ExternalMulticastIp::new(external_ip).unwrap());
        let groups = switch.mcast.lock().unwrap();
        assert!(groups.groups.contains_key(&external_key));
        assert_eq!(
            groups.nat_target_refs.get(&underlay_ip),
            Some(&external_key)
        );
    }

    fn underlay_tag_and_members(
        switch: &Switch,
        underlay_key: GroupKey,
    ) -> (String, Vec<MulticastGroupMember>) {
        let groups = switch.mcast.lock().unwrap();
        let group = &groups.groups[&underlay_key];
        (group.tag.clone(), group.members().cloned().collect())
    }

    #[test]
    fn test_del_underlay_destroy_failure_keeps_group_usable() {
        let mut config = Config::default();
        config.asic_config.mc_config.mc_group_destroy =
            asic::chaos::Chaos::new(1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (tag, members) = underlay_tag_and_members(&switch, underlay_key);
        let tables = [
            TableType::McastIpv6,
            TableType::McastEgressDecapPorts,
            TableType::RouteIpv6Mcast,
        ];
        for table in tables {
            assert_eq!(table_usage(&switch, table).0, 1, "{table}");
        }

        let err = del_group(&switch, underlay_key.ip(), &tag).unwrap_err();
        assert!(
            matches!(
                err,
                DpdError::Switch(aal::AsicError::Synthetic(ref op))
                    if op == "mc_group_destroy"
            ),
            "{err:?}"
        );

        for table in tables {
            assert_eq!(table_usage(&switch, table).0, 1, "{table}");
        }
        assert_eq!(underlay_tag_and_members(&switch, underlay_key).1, members);
        assert!(logs.entries.lock().unwrap().is_empty());

        let response = modify_group_underlay(
            &switch,
            underlay_ip,
            &tag,
            MulticastGroupUpdateUnderlayEntry { members: members.clone() },
        )
        .unwrap();
        assert_eq!(response.members, members);
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_del_underlay_domain_restore_failure_reports_unwind() {
        for fail_create in [true, false] {
            let mut config = Config::default();
            config.asic_config.mc_config.mc_group_destroy =
                asic::chaos::Chaos::new(1.0);
            if fail_create {
                config.asic_config.mc_config.mc_group_create =
                    asic::chaos::Chaos::new(1.0);
            } else {
                config.asic_config.mc_config.mc_port_add =
                    asic::chaos::Chaos::new(1.0);
            }
            let (op, failed_call) = if fail_create {
                ("restore multicast group", "mc_group_create")
            } else {
                ("restore multicast group member", "mc_port_add")
            };

            let (switch, logs) = chaos_switch(config);
            let (_, underlay_key) = install_underlay_group(&switch);
            let (tag, members) =
                underlay_tag_and_members(&switch, underlay_key);

            let err = del_group(&switch, underlay_key.ip(), &tag).unwrap_err();
            assert!(
                matches!(
                    err,
                    DpdError::Unwind { initial: ref init, ref unwind }
                        if matches!(**init, DpdError::Switch(_))
                            && unwind.len() == 1
                ),
                "{err:?}"
            );

            let errs = logs.entries.lock().unwrap();
            assert_eq!(errs.len(), 2, "{errs:?}");
            for err in errs.iter() {
                assert_eq!(err["operation"], op);
                assert!(err["error"].contains(failed_call), "{err:?}");
            }

            for table in [
                TableType::McastIpv6,
                TableType::McastEgressDecapPorts,
                TableType::RouteIpv6Mcast,
            ] {
                assert_eq!(table_usage(&switch, table).0, 1, "{table}");
            }
            assert_eq!(
                underlay_tag_and_members(&switch, underlay_key).1,
                members
            );
        }
    }

    #[test]
    fn test_underlay_unchanged_update_readd_failure_keeps_members() {
        let mut config = Config::default();
        config.asic_config.mc_config.mc_port_add = asic::chaos::Chaos::new(1.0);
        config.asic_config.mc_config.mc_port_remove =
            asic::chaos::Chaos::new(1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (tag, members) = underlay_tag_and_members(&switch, underlay_key);

        let err = modify_group_underlay(
            &switch,
            underlay_ip,
            &tag,
            MulticastGroupUpdateUnderlayEntry { members: members.clone() },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                DpdError::Switch(aal::AsicError::Synthetic(ref op))
                    if op == "mc_port_add"
            ),
            "{err:?}"
        );

        assert_eq!(underlay_tag_and_members(&switch, underlay_key).1, members);
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_underlay_unchanged_update_readds_missing_bitmap() {
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (tag, members) = underlay_tag_and_members(&switch, underlay_key);
        let external_id = switch.mcast.lock().unwrap().groups[&underlay_key]
            .external_group_id();

        table::mcast::mcast_egress::del_bitmap_entry(&switch, external_id)
            .unwrap();
        assert_eq!(table_usage(&switch, TableType::McastEgressDecapPorts).0, 0);

        let response = modify_group_underlay(
            &switch,
            underlay_ip,
            &tag,
            MulticastGroupUpdateUnderlayEntry { members: members.clone() },
        )
        .unwrap();
        assert_eq!(response.members, members);

        assert_eq!(
            bitmap_entry(&switch, external_id),
            Some((create_port_bitmap(&members, Direction::External), None)),
            "bitmap entry was not re-added"
        );
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_external_update_readds_retained_source_filters() {
        for (group_ip, [first, second, third]) in [
            ("224.1.2.3", ["192.0.2.1", "192.0.2.2", "192.0.2.3"]),
            ("ff0e::1", ["2001:db8::1", "2001:db8::2", "2001:db8::3"]),
        ] {
            let (switch, logs) = chaos_switch(Config::default());
            let (underlay_ip, _) = install_underlay_group(&switch);
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-retained-sources-test";
            let [first, second, third]: [IpAddr; 3] =
                [first, second, third].map(|ip| ip.parse().unwrap());
            let prefix_len = if external_ip.is_ipv4() { 32 } else { 128 };
            let [first_prefix, second_prefix, third_prefix] =
                [first, second, third].map(|ip| format!("{ip}/{prefix_len}"));

            let entry = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(serde_json::json!({
                "group_ip": external_ip,
                "tag": tag,
                "internal_forwarding": { "nat_target": nat_target },
                "external_forwarding": { "vlan_id": 10 },
                "sources": [{ "Exact": first }, { "Exact": second }],
            }))
            .unwrap();

            add_group_external(&switch, entry).unwrap();
            assert_eq!(
                source_filter_prefixes(&switch, external_ip),
                BTreeSet::from([first_prefix.clone(), second_prefix.clone()])
            );

            remove_source_filter(&switch, external_ip, IpSrc::Exact(second))
                .unwrap();
            assert_eq!(
                source_filter_prefixes(&switch, external_ip),
                BTreeSet::from([first_prefix])
            );

            let sources = [second, third]
                .map(|ip| SourceEntry::Exact(ExactSource::new(ip).unwrap()))
                .to_vec();
            modify_group_external(
                &switch,
                ExternalMulticastIp::new(external_ip).unwrap(),
                tag,
                MulticastGroupUpdateExternalEntry {
                    internal_forwarding: ExternalInternalForwarding {
                        nat_target: nat_target.try_into().unwrap(),
                    },
                    external_forwarding: ExternalForwarding {
                        vlan_id: Some(10),
                    },
                    sources: Some(sources),
                },
            )
            .unwrap();

            assert!(logs.entries.lock().unwrap().is_empty());
            assert_eq!(
                source_filter_prefixes(&switch, external_ip),
                BTreeSet::from([second_prefix, third_prefix])
            );
        }
    }

    fn forwarding_table_snapshot(
        switch: &Switch,
        table_type: TableType,
    ) -> serde_json::Value {
        let mut dump =
            table::get_entries(switch, table_type.to_string(), false).unwrap();
        dump.entries.sort_by(|left, right| left.keys.cmp(&right.keys));
        serde_json::to_value(dump).unwrap()
    }

    #[test]
    fn test_put_readds_missing_external_nat_and_routes() {
        for external_ip in ["239.1.2.3", "ff0e::1"] {
            for vlan_id in [None, Some(10)] {
                for (remove_nat, remove_route) in
                    [(true, false), (false, true), (true, true)]
                {
                    let (switch, logs) = chaos_switch(Config::default());
                    let (underlay_ip, _) = install_underlay_group(&switch);
                    let external_ip: IpAddr = external_ip.parse().unwrap();
                    let (route_table, _, nat_table) =
                        external_tables(external_ip);
                    let nat_target =
                        external_nat_target(external_ip, underlay_ip);
                    let tag = "external-put-repair-test";
                    let entry = serde_json::from_value::<
                        MulticastGroupCreateExternalEntry,
                    >(serde_json::json!({
                        "group_ip": external_ip,
                        "tag": tag,
                        "internal_forwarding": { "nat_target": nat_target },
                        "external_forwarding": { "vlan_id": vlan_id },
                        "sources": null,
                    }))
                    .unwrap();
                    add_group_external(&switch, entry).unwrap();
                    let before_route =
                        forwarding_table_snapshot(&switch, route_table);
                    let before_nat =
                        forwarding_table_snapshot(&switch, nat_table);

                    match external_ip {
                        IpAddr::V4(ipv4) => {
                            if remove_nat {
                                mcast_nat::del_ipv4_entry(
                                    &switch, ipv4, vlan_id,
                                )
                                .unwrap();
                            }
                            if remove_route {
                                table::mcast::mcast_route::del_ipv4_entry(
                                    &switch, ipv4,
                                )
                                .unwrap();
                            }
                        }
                        IpAddr::V6(ipv6) => {
                            if remove_nat {
                                mcast_nat::del_ipv6_entry(
                                    &switch, ipv6, vlan_id,
                                )
                                .unwrap();
                            }
                            if remove_route {
                                table::mcast::mcast_route::del_ipv6_entry(
                                    &switch, ipv6,
                                )
                                .unwrap();
                            }
                        }
                    }

                    for _ in 0..2 {
                        modify_group_external(
                            &switch,
                            ExternalMulticastIp::new(external_ip).unwrap(),
                            tag,
                            MulticastGroupUpdateExternalEntry {
                                internal_forwarding:
                                    ExternalInternalForwarding {
                                        nat_target: nat_target
                                            .try_into()
                                            .unwrap(),
                                    },
                                external_forwarding: ExternalForwarding {
                                    vlan_id,
                                },
                                sources: None,
                            },
                        )
                        .unwrap();
                        assert_eq!(
                            forwarding_table_snapshot(&switch, route_table),
                            before_route,
                        );
                        assert_eq!(
                            forwarding_table_snapshot(&switch, nat_table),
                            before_nat,
                        );
                    }
                    assert!(logs.entries.lock().unwrap().is_empty());
                }
            }
        }
    }

    #[test]
    fn test_put_readds_missing_underlay_routes() {
        for (was_active, want_active) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let (switch, logs) = chaos_switch(Config::default());
            let (underlay_ip, underlay_key) = if was_active {
                install_underlay_group(&switch)
            } else {
                install_empty_underlay_group(&switch)
            };
            let (tag, original_members) =
                underlay_tag_and_members(&switch, underlay_key);
            let members = if want_active {
                if was_active {
                    original_members
                } else {
                    vec![MulticastGroupMember {
                        port_id: RearPort::new(0).unwrap().into(),
                        link_id: LinkId(0),
                        direction: Direction::External,
                    }]
                }
            } else {
                Vec::new()
            };
            let before_route =
                forwarding_table_snapshot(&switch, TableType::RouteIpv6Mcast);
            table::mcast::mcast_route::del_ipv6_entry(
                &switch,
                underlay_ip.into(),
            )
            .unwrap();
            assert_eq!(table_usage(&switch, TableType::RouteIpv6Mcast).0, 0);

            for _ in 0..2 {
                let response = modify_group_underlay(
                    &switch,
                    underlay_ip,
                    &tag,
                    MulticastGroupUpdateUnderlayEntry {
                        members: members.clone(),
                    },
                )
                .unwrap();
                assert_eq!(response.members, members);
                assert_eq!(
                    forwarding_table_snapshot(
                        &switch,
                        TableType::RouteIpv6Mcast,
                    ),
                    before_route,
                );
                for table_type in
                    [TableType::McastIpv6, TableType::McastEgressDecapPorts]
                {
                    assert_eq!(
                        table_usage(&switch, table_type).0,
                        u32::from(want_active),
                        "{table_type}",
                    );
                }
            }
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }
}
