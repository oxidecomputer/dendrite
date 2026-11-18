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
    Direction, ExternalMulticastIp, GroupKind, IpSrc, MulticastGroup,
    MulticastGroupId, MulticastGroupMember, MulticastReplicationInfo,
    Replication, SourceFilter, UnderlayMulticastIpv6, clear_source_filter,
    create_port_bitmap, mc_group_clear, mc_group_set, mc_port_clear,
    mc_port_set, restore_source_filters, set_group_bitmap_entries,
    set_replication_entry, set_source_filter, update_fwding_tables,
};
use crate::{
    Switch, table,
    types::{DpdError, DpdResult, after_unwind},
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

    /// ASIC group with members of `direction`.
    fn group_id(&self, direction: Direction) -> MulticastGroupId {
        match direction {
            Direction::External => self.external_group_id(),
            Direction::Underlay => self.underlay_group_id(),
        }
    }

    /// Undo port changes in reverse: first remove `added_ports`, then re-add
    /// `removed_ports`. Every port is attempted; the first error is returned.
    fn undo_port_changes(
        &self,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
        repl: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        let switch = self.switch();
        let mut first_err = None;

        // Remove added ports
        for member in added_ports.iter().rev() {
            let group_id = self.group_id(member.direction);

            match switch.port_link_to_asic_id(member.port_id, member.link_id) {
                Ok(asic_id) => {
                    if let Err(e) = mc_port_clear(switch, group_id, asic_id) {
                        error!(
                            switch.log,
                            "failed to remove port during rollback";
                            "port" => %member.port_id,
                            "asic_id" => asic_id,
                            "group_id" => group_id,
                            "error" => ?e,
                        );

                        first_err.get_or_insert(e);
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
                }
            }
        }

        // Re-add removed ports
        for member in removed_ports.iter().rev() {
            let group_id = self.group_id(member.direction);

            match switch.port_link_to_asic_id(member.port_id, member.link_id) {
                Ok(asic_id) => {
                    if let Err(e) = mc_port_set(switch, group_id, asic_id, repl)
                    {
                        error!(
                            switch.log,
                            "failed to add port during rollback";
                            "port" => %member.port_id,
                            "asic_id" => asic_id,
                            "group_id" => group_id,
                            "error" => ?e,
                        );

                        first_err.get_or_insert(e);
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
                }
            }
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
                clear_source_filter(self.switch(), self.group_ip(), source)
            })
            .into_iter()
            .map(|(source, err)| {
                self.log_rollback_error(
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
                set_group_bitmap_entries(self.switch(), group, vlan_id)
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
    External { sources: &'a SourceFilter },
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
        group_ip: ExternalMulticastIp,
        external_id: MulticastGroupId,
        underlay_id: MulticastGroupId,
        sources: &'a SourceFilter,
    ) -> Self {
        Self {
            switch,
            group_ip: group_ip.into(),
            external_id,
            underlay_id,
            kind: CreateRollbackKind::External { sources },
        }
    }

    /// Create rollback context for underlay group operations.
    pub(crate) fn new_underlay(
        switch: &'a Switch,
        group_ip: UnderlayMulticastIpv6,
        external_id: MulticastGroupId,
        underlay_id: MulticastGroupId,
    ) -> Self {
        Self {
            switch,
            group_ip: group_ip.into(),
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
    ) -> DpdError {
        let restored = self.restore_bitmap_vlan(underlay_group, None);
        self.rollback(after_unwind(err, restored))
    }

    /// Perform rollback and return error.
    pub(crate) fn rollback(&self, err: DpdError) -> DpdError {
        after_unwind(
            err,
            unwind_outcome([self.remove_tables(), self.remove_groups()]),
        )
    }

    /// Remove multicast groups from ASIC.
    fn remove_groups(&self) -> DpdResult<()> {
        // External groups don't destroy ASIC groups (they're shared with underlay group).
        if !matches!(self.kind, CreateRollbackKind::Underlay) {
            return Ok(());
        }

        unwind_outcome([
            self.log_rollback_error(
                "remove external multicast group",
                &format!(
                    "for IP {} with ID {}",
                    self.group_ip, self.external_id
                ),
                mc_group_clear(self.switch, self.external_id),
            ),
            self.log_rollback_error(
                "remove underlay multicast group",
                &format!(
                    "for IP {} with ID {}",
                    self.group_ip, self.underlay_id
                ),
                mc_group_clear(self.switch, self.underlay_id),
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

        self.log_rollback_error(
            "delete IPv6 replication entry",
            &format!("for group {ipv6}"),
            table::mcast::mcast_replication::clear_ipv6_entry(
                self.switch,
                ipv6,
            ),
        )
        .inspect_err(|_| {
            warn!(
                self.switch.log,
                "replication entry delete failed, skipping decap bitmap delete";
                "group" => %ipv6,
                "external_group_id" => %self.external_id,
            );
        })
        .and_then(|_| {
            self.log_rollback_error(
                "delete IPv6 egress bitmap entry",
                &format!("for external group {}", self.external_id),
                table::mcast::mcast_egress::clear_bitmap_entry(
                    self.switch,
                    self.external_id,
                ),
            )
        })
    }

    fn remove_external_entries(&self) -> DpdResult<()> {
        let CreateRollbackKind::External { sources } = self.kind else {
            return Ok(());
        };

        let filters_removed = self.remove_source_filters(sources);
        let nat_removed = match self.group_ip {
            IpAddr::V4(ipv4) => self.log_rollback_error(
                "delete IPv4 NAT entry",
                &format!("for group {ipv4}"),
                table::mcast::mcast_nat::clear_ipv4_entry(self.switch, ipv4),
            ),
            IpAddr::V6(ipv6) => self.log_rollback_error(
                "delete IPv6 NAT entry",
                &format!("for group {ipv6}"),
                table::mcast::mcast_nat::clear_ipv6_entry(self.switch, ipv6),
            ),
        };

        filters_removed.and(nat_removed)
    }

    fn remove_route_entry(&self) -> DpdResult<()> {
        match self.group_ip {
            IpAddr::V4(ipv4) => self.log_rollback_error(
                "delete IPv4 route entry",
                &format!("for group {ipv4}"),
                table::mcast::mcast_route::clear_ipv4_entry(self.switch, ipv4),
            ),
            IpAddr::V6(ipv6) => self.log_rollback_error(
                "delete IPv6 route entry",
                &format!("for group {ipv6}"),
                table::mcast::mcast_route::clear_ipv6_entry(self.switch, ipv6),
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
    pub(crate) fn rollback_underlay_update(
        &self,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
        repl: &MulticastReplicationInfo,
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
            self.undo_port_changes(added_ports, removed_ports, repl),
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

    fn restore_union_bitmap(
        &self,
        added_ports: &[MulticastGroupMember],
    ) -> DpdResult<()> {
        if !matches!(
            self.original_group.kind,
            GroupKind::Underlay { replication: Replication::Active { .. }, .. }
        ) {
            return Ok(());
        }

        // Port rollback can immediately enable replicas on Tofino for example.
        //
        // This restores decapsulation for the original and added members before
        // modifying any ports.
        let union_bitmap = create_port_bitmap(
            self.original_group.members().chain(added_ports),
            Direction::External,
        );
        self.log_rollback_error(
            "restore decap bitmap",
            &format!("for group {}", self.group_ip()),
            table::mcast::mcast_egress::set_bitmap_entry(
                self.switch,
                self.external_group_id(),
                &union_bitmap,
                self.table_vlan_id,
            ),
        )
    }

    fn restore_tables(
        &self,
        added_ports: &[MulticastGroupMember],
        ports_restored: bool,
    ) -> DpdResult<()> {
        match &self.original_group.kind {
            GroupKind::Underlay {
                replication: Replication::Active { .. },
                ..
            } => {
                self.restore_replication()?;
                if ports_restored
                    && added_ports
                        .iter()
                        .any(|member| member.direction == Direction::External)
                {
                    self.restore_fwding_tables()
                } else {
                    Ok(())
                }
            }
            GroupKind::Underlay { replication: Replication::Empty, .. } => {
                unwind_outcome([
                    self.remove_added_bitmap(),
                    self.restore_fwding_tables(),
                ])
            }
            GroupKind::External { .. } => self.restore_fwding_tables(),
        }
    }

    fn restore_replication(&self) -> DpdResult<()> {
        let GroupKind::Underlay {
            group_ip,
            replication: Replication::Active { info: repl, .. },
        } = &self.original_group.kind
        else {
            return Ok(());
        };

        self.log_rollback_error(
            "restore replication settings",
            &format!("for group {group_ip}"),
            set_replication_entry(self.switch, self.original_group, repl),
        )
    }

    fn remove_added_bitmap(&self) -> DpdResult<()> {
        let GroupKind::Underlay { replication: Replication::Empty, .. } =
            &self.original_group.kind
        else {
            return Ok(());
        };

        self.log_rollback_error(
            "delete newly added multicast bitmap",
            &format!("for group {}", self.group_ip()),
            super::cleanup_empty_group_replication(
                self.switch,
                self.original_group,
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
    ///
    /// If the decap bitmap can't be restored to cover both original
    /// and added members, rollback removes the added ports and avoids re-adding
    /// removed ports.
    pub(crate) fn rollback_underlay_and_restore(
        &self,
        err: DpdError,
        repl: &MulticastReplicationInfo,
        added_ports: &[MulticastGroupMember],
        removed_ports: &[MulticastGroupMember],
    ) -> DpdError {
        if let Err(unwind) = self.restore_union_bitmap(added_ports) {
            if !removed_ports.is_empty() {
                warn!(
                    self.switch.log,
                    "decap bitmap restore failed, leaving removed ports out \
                     of the group";
                    "group" => %self.group_ip(),
                    "skipped_ports" => removed_ports.len(),
                );
            }
            let ports = self.rollback_underlay_update(added_ports, &[], repl);
            return after_unwind(err, unwind_outcome([Err(unwind), ports]));
        }
        let ports =
            self.rollback_underlay_update(added_ports, removed_ports, repl);
        let tables = self.restore_tables(added_ports, ports.is_ok());
        after_unwind(err, ports.and(tables))
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
                    restore(DeleteStep::Nat, &|| self.readd_nat(*nat_target)),
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
                mc_group_set(self.switch, group_id),
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
                            mc_port_set(self.switch, group_id, asic_id, info)
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
                set_source_filter(self.switch, self.group_ip(), source.clone()),
            )
        }))
    }

    fn readd_nat(
        &self,
        nat_target: dpd_types::mcast::ExternalNatTarget,
    ) -> DpdResult<()> {
        self.log_rollback_error(
            "restore NAT entry",
            &format!("for group {}", self.group_ip()),
            super::update_nat_tables(
                self.switch,
                self.group_ip(),
                nat_target.into(),
            ),
        )
    }

    fn readd_route(&self, vlan_id: Option<u16>) -> DpdResult<()> {
        let result = match self.group_ip() {
            IpAddr::V4(ipv4) => table::mcast::mcast_route::set_ipv4_entry(
                self.switch,
                ipv4,
                vlan_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::mcast_route::set_ipv6_entry(
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
            set_group_bitmap_entries(self.switch, self.group, None),
        )
    }

    fn readd_replication(
        &self,
        info: &MulticastReplicationInfo,
    ) -> DpdResult<()> {
        self.log_rollback_error(
            "restore replication entry",
            &format!("for group {}", self.group_ip()),
            set_replication_entry(self.switch, self.group, info),
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
        for removal_fails in [false, true] {
            let mut attempted = Vec::new();
            let errs = remove_source_filters(&SourceFilter::Any, |source| {
                attempted.push(source);
                if removal_fails { Err("delete failed") } else { Ok(()) }
            });

            assert_eq!(attempted, vec![IpSrc::Any]);
            if removal_fails {
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

    use aal::AsicId;
    use asic::chaos::{CallRange, McOp, TableOp};
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

        create_asic_groups(
            switch,
            underlay_ip,
            external_scoped_group.id(),
            underlay_scoped_group.id(),
        );
        add_ports_to_groups(
            switch,
            underlay_ip.into(),
            &members,
            external_scoped_group.id(),
            underlay_scoped_group.id(),
            &repl,
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
        create_asic_groups(
            switch,
            underlay_ip,
            external_scoped_group.id(),
            underlay_scoped_group.id(),
        );

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

    fn create_asic_groups(
        switch: &Switch,
        underlay_ip: UnderlayMulticastIpv6,
        external_group_id: MulticastGroupId,
        underlay_group_id: MulticastGroupId,
    ) {
        for group_id in [external_group_id, underlay_group_id] {
            create_asic_group(switch, group_id, underlay_ip.into()).unwrap();
        }
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

    fn nat_target_addr(switch: &Switch, group_ip: IpAddr) -> Option<String> {
        let dump = match group_ip {
            IpAddr::V4(_) => {
                table::mcast::mcast_nat::ipv4_table_dump(switch, false)
            }
            IpAddr::V6(_) => {
                table::mcast::mcast_nat::ipv6_table_dump(switch, false)
            }
        }
        .unwrap();

        let address = group_ip.to_string();
        dump.entries
            .into_iter()
            .find(|entry| entry.keys.get("dst_addr") == Some(&address))
            .and_then(|entry| entry.action_args.get("target").cloned())
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
    /// When `source_removal_fails` is true, each of the three filter deletions
    /// fails and is logged separately. When false, all three succeed.
    ///
    /// The failed route insertion leaves no entry to delete. Cleanup logs the
    /// missing entry at debug level, without a `ROLLBACK_FAILURE_MSG` record.
    fn external_create_failure(
        external_ip: IpAddr,
        source_removal_fails: bool,
    ) {
        let (route_table, source_table, nat_table) =
            external_tables(external_ip);
        let mut config = Config::default();

        if source_removal_fails {
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
        let sources = source_ips
            .map(|ip| serde_json::json!({ "type": "exact", "value": ip }));
        let entry = external_entry(
            external_ip,
            "external-rollback-test",
            nat_target,
            None,
            serde_json::json!(sources),
        );

        let err = add_group_external(&switch, entry).unwrap_err();
        assert_eq!(
            matches!(err, DpdError::Unwind { .. }),
            source_removal_fails,
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
        assert_eq!(groups.groups.len(), 1 + usize::from(source_removal_fails));
        assert_eq!(
            groups.groups.contains_key(&external_ip),
            source_removal_fails
        );
        assert_eq!(groups.nat_target_refs.is_empty(), !source_removal_fails);
        assert_eq!(
            groups.pending_repairs.contains(&external_ip),
            source_removal_fails
        );

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
        let remaining = if source_removal_fails { 3 } else { 0 };
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
            serde_json::json!([{ "type": "exact", "value": "192.0.2.1" }]),
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

        {
            let errs = logs.entries.lock().unwrap();
            assert_eq!(errs.len(), 1, "{errs:?}");
            assert_eq!(errs[0]["operation"], "restore multicast bitmap VLAN");
            assert!(errs[0]["error"].contains("table_entry_update"));
        }
        let groups = switch.mcast.lock().unwrap();
        assert_eq!(groups.groups.len(), 2);
        assert!(groups.groups.contains_key(&external_ip));
        assert!(!groups.nat_target_refs.is_empty());
        assert!(groups.pending_repairs.contains(&external_ip));
        assert!(groups.pending_repairs.contains(&underlay_key));
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
    /// When `target_changed` is true, the NAT target changes and the VLAN
    /// remains as is. Otherwise, the VLAN gets modified. Sources change either
    /// way, and NAT programming fails.
    ///
    /// The NAT key is always just the destination address; both cases
    /// update the entry in place and hit the injected `table_entry_update`
    /// failure.
    fn external_update_failure(external_ip: IpAddr, target_changed: bool) {
        let (route_table, source_table, nat_table) =
            external_tables(external_ip);
        let mut config = Config::default();
        config.asic_config.table_entry_update.values.insert(nat_table, 1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (target_ip, target_key) = if target_changed {
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
                    vlan_id: Some(if target_changed { 10 } else { 20 }),
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
        let any_prefix =
            if external_ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
        assert_eq!(
            source_filter_prefixes(&switch, external_ip),
            BTreeSet::from([any_prefix.to_string()])
        );
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_external_failed_unwind_repairs_on_read() {
        for (group_ip, source_ip) in
            [("224.1.2.3", "192.0.2.1"), ("ff0e::1", "2001:db8::1")]
        {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (_, source_table, _) = external_tables(external_ip);
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-repair-test";
            add_group_external(
                &switch,
                external_entry(
                    external_ip,
                    tag,
                    nat_target,
                    Some(10),
                    serde_json::Value::Null,
                ),
            )
            .unwrap();
            let stored =
                serde_json::to_value(get_group(&switch, external_ip).unwrap())
                    .unwrap();
            let stored_sources = source_filter_prefixes(&switch, external_ip);
            let stored_route = route_action(&switch, external_ip);

            switch.asic_hdl.inject_table_faults(
                source_table,
                TableOp::EntryDel,
                CallRange::starting_at(1),
                AsicError::Synthetic,
            );
            let update = || MulticastGroupUpdateExternalEntry {
                internal_forwarding: ExternalInternalForwarding {
                    nat_target: nat_target.try_into().unwrap(),
                },
                external_forwarding: ExternalForwarding { vlan_id: Some(20) },
                sources: Some(vec![SourceEntry::Exact(
                    ExactSource::new(source_ip.parse().unwrap()).unwrap(),
                )]),
            };
            let group = ExternalMulticastIp::new(external_ip).unwrap();

            let err = modify_group_external(&switch, group, tag, update())
                .unwrap_err();
            assert!(matches!(err, DpdError::Unwind { .. }), "{err:?}");
            assert_ne!(
                source_filter_prefixes(&switch, external_ip),
                stored_sources
            );
            {
                let mcast = switch.mcast.lock().unwrap();
                assert!(mcast.pending_repairs.contains(&external_ip));
                assert!(mcast.pending_repairs.contains(&underlay_key));
            }

            let res = get_group(&switch, external_ip);
            assert!(
                matches!(res, Err(DpdError::McastRepairPending(_))),
                "{res:?}"
            );
            let res = modify_group_external(&switch, group, tag, update());
            assert!(
                matches!(res, Err(DpdError::McastRepairPending(_))),
                "{res:?}"
            );
            let listed = get_range(&switch, None, 1, Some(tag)).unwrap();
            assert_eq!(serde_json::to_value(&listed[0]).unwrap(), stored);

            switch.asic_hdl.clear_table_faults(source_table, TableOp::EntryDel);
            assert_eq!(
                serde_json::to_value(get_group(&switch, external_ip).unwrap())
                    .unwrap(),
                stored,
            );
            assert_eq!(
                source_filter_prefixes(&switch, external_ip),
                stored_sources
            );
            assert_eq!(route_action(&switch, external_ip), stored_route);

            get_group(&switch, underlay_key.ip()).unwrap();
            assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
        }
    }

    #[test]
    fn test_external_cleanup_without_listing() {
        for (group_ip, source_ip, del) in [
            ("224.1.2.3", "192.0.2.1", false),
            ("ff0e::1", "2001:db8::1", false),
            ("224.1.2.3", "192.0.2.1", true),
            ("ff0e::1", "2001:db8::1", true),
        ] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (_, source_table, _) = external_tables(external_ip);
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, _) = install_underlay_group(&switch);
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-unlisted-cleanup-test";
            add_group_external(
                &switch,
                external_entry(
                    external_ip,
                    tag,
                    nat_target,
                    None,
                    serde_json::json!([
                        { "type": "exact", "value": source_ip }
                    ]),
                ),
            )
            .unwrap();
            let stored =
                serde_json::to_value(get_group(&switch, external_ip).unwrap())
                    .unwrap();
            let stored_sources = source_filter_prefixes(&switch, external_ip);

            switch.asic_hdl.inject_table_faults(
                source_table,
                TableOp::EntryList,
                CallRange::starting_at(1),
                |_| AsicError::OperationUnsupported,
            );
            switch.asic_hdl.inject_table_faults(
                source_table,
                TableOp::EntryDel,
                CallRange::starting_at(1),
                AsicError::Synthetic,
            );
            let err = modify_group_external(
                &switch,
                ExternalMulticastIp::new(external_ip).unwrap(),
                tag,
                MulticastGroupUpdateExternalEntry {
                    internal_forwarding: ExternalInternalForwarding {
                        nat_target: nat_target.try_into().unwrap(),
                    },
                    external_forwarding: ExternalForwarding { vlan_id: None },
                    sources: Some(vec![SourceEntry::Any]),
                },
            )
            .unwrap_err();
            assert!(matches!(err, DpdError::Unwind { .. }), "{err:?}");
            assert_eq!(table_usage(&switch, source_table).0, 2);

            let res = if del {
                del_group(&switch, external_ip, tag)
            } else {
                get_group(&switch, external_ip).map(|_| ())
            };
            assert!(
                matches!(res, Err(DpdError::McastRepairPending(_))),
                "{res:?}"
            );
            assert_eq!(table_usage(&switch, source_table).0, 2);
            {
                let mcast = switch.mcast.lock().unwrap();
                assert!(mcast.pending_repairs.contains(&external_ip));
                assert_eq!(
                    mcast.pending_repairs.sources(&external_ip),
                    BTreeSet::from([IpSrc::Any])
                );
                assert_eq!(
                    serde_json::to_value(MulticastGroupResponse::from(
                        &mcast.groups[&external_ip]
                    ))
                    .unwrap(),
                    stored,
                );
                assert_eq!(
                    mcast.nat_target_refs.get(&underlay_ip).map(GroupKey::ip),
                    Some(external_ip)
                );
            }

            switch.asic_hdl.clear_table_faults(source_table, TableOp::EntryDel);
            if del {
                del_group(&switch, external_ip, tag).unwrap();
                assert_eq!(table_usage(&switch, source_table).0, 0);
                assert!(route_action(&switch, external_ip).is_none());
                assert!(nat_target_addr(&switch, external_ip).is_none());
                let mcast = switch.mcast.lock().unwrap();
                assert!(!mcast.groups.contains_key(&external_ip));
                assert!(!mcast.nat_target_refs.contains_key(&underlay_ip));
            } else {
                assert_eq!(
                    serde_json::to_value(
                        get_group(&switch, external_ip).unwrap()
                    )
                    .unwrap(),
                    stored,
                );
                assert_eq!(table_usage(&switch, source_table).0, 1);
            }
            assert!(
                !switch
                    .mcast
                    .lock()
                    .unwrap()
                    .pending_repairs
                    .contains(&external_ip)
            );

            switch
                .asic_hdl
                .clear_table_faults(source_table, TableOp::EntryList);
            assert_eq!(
                source_filter_prefixes(&switch, external_ip),
                if del { BTreeSet::new() } else { stored_sources }
            );
        }
    }

    #[test]
    fn test_external_delete_removes_untracked_source_filters() {
        for (group_ip, source_ip, stray_ip) in [
            ("224.1.2.3", "192.0.2.1", "192.0.2.2"),
            ("ff0e::1", "2001:db8::1", "2001:db8::2"),
        ] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, _) = install_underlay_group(&switch);
            let tag = "external-delete-filters-test";
            add_group_external(
                &switch,
                external_entry(
                    external_ip,
                    tag,
                    external_nat_target(external_ip, underlay_ip),
                    None,
                    serde_json::json!([
                        { "type": "exact", "value": source_ip }
                    ]),
                ),
            )
            .unwrap();
            set_source_filter(
                &switch,
                external_ip,
                IpSrc::Exact(stray_ip.parse().unwrap()),
            )
            .unwrap();
            assert_eq!(source_filter_prefixes(&switch, external_ip).len(), 2);

            del_group(&switch, external_ip, tag).unwrap();
            assert!(source_filter_prefixes(&switch, external_ip).is_empty());
        }
    }

    // Without per-table dumps (e.g., SoftNPU), only the group's stored
    // sources get removed; the untracked entries remain in place.
    #[test]
    fn test_delete_unlisted_source_filters() {
        for (group_ip, first_source, second_source, stray_ip) in [
            ("224.1.2.3", "192.0.2.1", "192.0.2.2", "192.0.2.3"),
            ("ff0e::1", "2001:db8::1", "2001:db8::2", "2001:db8::3"),
        ] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (_, source_table, _) = external_tables(external_ip);
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, _) = install_underlay_group(&switch);
            let tag = "external-delete-unlisted-test";
            add_group_external(
                &switch,
                external_entry(
                    external_ip,
                    tag,
                    external_nat_target(external_ip, underlay_ip),
                    None,
                    serde_json::json!([
                        { "type": "exact", "value": first_source },
                        { "type": "exact", "value": second_source },
                    ]),
                ),
            )
            .unwrap();
            set_source_filter(
                &switch,
                external_ip,
                IpSrc::Exact(stray_ip.parse().unwrap()),
            )
            .unwrap();
            assert_eq!(source_filter_prefixes(&switch, external_ip).len(), 3);

            switch.asic_hdl.inject_table_faults(
                source_table,
                TableOp::EntryList,
                CallRange::starting_at(1),
                |_| AsicError::OperationUnsupported,
            );
            del_group(&switch, external_ip, tag).unwrap();
            switch
                .asic_hdl
                .clear_table_faults(source_table, TableOp::EntryList);

            let prefix_len = if external_ip.is_ipv4() { 32 } else { 128 };
            assert_eq!(
                source_filter_prefixes(&switch, external_ip),
                BTreeSet::from([format!("{stray_ip}/{prefix_len}")])
            );
        }
    }

    #[test]
    fn test_external_delete_vlan_cleanup_failure_marks_group() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);
            let tag = "external-delete-vlan-test";
            add_group_external(
                &switch,
                external_entry(
                    external_ip,
                    tag,
                    external_nat_target(external_ip, underlay_ip),
                    Some(10),
                    serde_json::Value::Null,
                ),
            )
            .unwrap();
            let stored =
                serde_json::to_value(get_group(&switch, external_ip).unwrap())
                    .unwrap();

            switch.asic_hdl.inject_table_faults(
                TableType::McastEgressDecapPorts,
                TableOp::EntryUpdate,
                CallRange::starting_at(1),
                AsicError::Synthetic,
            );
            let err = del_group(&switch, external_ip, tag).unwrap_err();
            assert!(matches!(err, DpdError::Unwind { .. }), "{err:?}");
            {
                let mcast = switch.mcast.lock().unwrap();
                assert!(mcast.groups.contains_key(&external_ip));
                assert!(mcast.pending_repairs.contains(&external_ip));
                assert!(mcast.pending_repairs.contains(&underlay_key));
            }

            switch.asic_hdl.clear_table_faults(
                TableType::McastEgressDecapPorts,
                TableOp::EntryUpdate,
            );
            assert_eq!(
                serde_json::to_value(get_group(&switch, external_ip).unwrap())
                    .unwrap(),
                stored,
            );
            get_group(&switch, underlay_key.ip()).unwrap();
            assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());

            del_group(&switch, external_ip, tag).unwrap();
            assert!(source_filter_prefixes(&switch, external_ip).is_empty());
            assert!(route_action(&switch, external_ip).is_none());
        }
    }

    #[test]
    fn test_underlay_create_unwind_failure() {
        let members = membership_members();
        let (switch, _logs) = chaos_switch(Config::default());
        let create = || MulticastGroupCreateUnderlayEntry {
            group_ip: membership_group_ip(),
            tag: Some(MEMBERSHIP_TEST_TAG.to_string()),
            members: members[..2].to_vec(),
        };
        switch.asic_hdl.inject_table_faults(
            TableType::RouteIpv6Mcast,
            TableOp::EntryAdd,
            CallRange::nth(1),
            AsicError::Synthetic,
        );
        switch.asic_hdl.inject_table_faults(
            TableType::McastIpv6,
            TableOp::EntryDel,
            CallRange::nth(1),
            AsicError::Synthetic,
        );

        let err = add_group_underlay(&switch, create()).unwrap_err();
        assert!(matches!(err, DpdError::Unwind { .. }), "{err:?}");
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);

        let key = GroupKey::underlay(membership_group_ip());
        let retained = {
            let mcast = switch.mcast.lock().unwrap();
            assert!(mcast.pending_repairs.contains(&key));
            let group = &mcast.groups[&key];
            [group.external_group_id(), group.underlay_group_id()]
        };

        let err = add_group_underlay(&switch, create()).unwrap_err();
        assert!(matches!(err, DpdError::Exists(_)), "{err:?}");

        let other = add_group_underlay(
            &switch,
            MulticastGroupCreateUnderlayEntry {
                group_ip: "ff04::124".parse().unwrap(),
                tag: Some(MEMBERSHIP_TEST_TAG.to_string()),
                members: Vec::new(),
            },
        )
        .unwrap();
        assert!(!retained.contains(&other.external_group_id));
        assert!(!retained.contains(&other.underlay_group_id));

        switch.asic_hdl.inject_table_faults(
            TableType::RouteIpv6Mcast,
            TableOp::EntryAdd,
            CallRange::starting_at(1),
            AsicError::Synthetic,
        );
        let err =
            get_group_underlay(&switch, membership_group_ip()).unwrap_err();
        assert!(matches!(err, DpdError::McastRepairPending(_)), "{err:?}");
        {
            let mcast = switch.mcast.lock().unwrap();
            assert!(mcast.pending_repairs.contains(&key));
            let group = &mcast.groups[&key];
            assert_eq!(
                [group.external_group_id(), group.underlay_group_id()],
                retained,
            );
            assert_eq!(
                group.members().cloned().collect::<Vec<_>>(),
                members[..2],
            );
        }

        switch
            .asic_hdl
            .clear_table_faults(TableType::RouteIpv6Mcast, TableOp::EntryAdd);
        switch
            .asic_hdl
            .clear_table_faults(TableType::McastIpv6, TableOp::EntryDel);
        let response =
            get_group_underlay(&switch, membership_group_ip()).unwrap();
        assert_eq!(
            [response.external_group_id, response.underlay_group_id],
            retained,
        );
        assert!(response.members.is_empty());
        assert_eq!(
            asic_membership(&switch),
            [Vec::<AsicId>::new(), Vec::new()],
        );
        assert!(bitmap_entry(&switch, retained[0]).is_none());
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 0);
        assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
        assert!(route_action(&switch, key.ip()).is_some());

        del_group(&switch, key.ip(), MEMBERSHIP_TEST_TAG).unwrap();
        assert!(route_action(&switch, key.ip()).is_none());
        let mcast = switch.mcast.lock().unwrap();
        assert!(!mcast.groups.contains_key(&key));
        let free_group_ids = mcast.free_group_ids.lock().unwrap();
        for group_id in retained {
            assert!(!switch.asic_hdl.mc_group_exists(group_id));
            assert!(free_group_ids.contains(&group_id));
        }
    }

    #[test]
    fn test_repair_pending_group_allows_tag_read_and_delete() {
        let members = membership_members();
        let (switch, _logs) = chaos_switch(Config::default());
        create_membership_group(&switch, &members[..2]);
        let key = GroupKey::underlay(membership_group_ip());
        switch.mcast.lock().unwrap().pending_repairs.insert(key);
        switch
            .asic_hdl
            .inject_mc_faults(McOp::McPortList, CallRange::starting_at(1));

        let err =
            get_group_underlay(&switch, membership_group_ip()).unwrap_err();
        assert!(matches!(err, DpdError::McastRepairPending(_)), "{err:?}");
        let http_err = dropshot::HttpError::from(err);
        assert_eq!(http_err.status_code.as_u16(), 503);
        assert_eq!(
            http_err.error_code.as_deref(),
            Some(common::MCAST_REPAIR_PENDING_ERROR_CODE)
        );
        assert_eq!(
            http_err
                .headers
                .as_ref()
                .and_then(|headers| headers.get("retry-after"))
                .and_then(|value| value.to_str().ok()),
            Some("10")
        );
        let tag = group_tag(&switch, key.ip()).unwrap();
        assert_eq!(tag, MEMBERSHIP_TEST_TAG);

        del_group(&switch, key.ip(), &tag).unwrap();
        let mcast = switch.mcast.lock().unwrap();
        assert!(!mcast.groups.contains_key(&key));
        assert!(mcast.pending_repairs.is_empty());
    }

    #[test]
    fn test_underlay_create_group_failure_keeps_group_ids() {
        let (switch, _logs) = chaos_switch(Config::default());
        switch
            .asic_hdl
            .inject_mc_faults(McOp::McGroupCreate, CallRange::nth(2));
        switch
            .asic_hdl
            .inject_mc_faults(McOp::McGroupDestroy, CallRange::nth(1));

        let err = add_group_underlay(
            &switch,
            MulticastGroupCreateUnderlayEntry {
                group_ip: membership_group_ip(),
                tag: Some(MEMBERSHIP_TEST_TAG.to_string()),
                members: Vec::new(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, DpdError::Unwind { .. }), "{err:?}");

        let key = GroupKey::underlay(membership_group_ip());
        let [external_id, underlay_id] = {
            let mcast = switch.mcast.lock().unwrap();
            assert!(mcast.pending_repairs.contains(&key));
            let group = &mcast.groups[&key];
            [group.external_group_id(), group.underlay_group_id()]
        };
        assert!(switch.asic_hdl.mc_group_exists(external_id));
        assert!(!switch.asic_hdl.mc_group_exists(underlay_id));

        switch.asic_hdl.clear_mc_faults(McOp::McGroupCreate);
        switch.asic_hdl.clear_mc_faults(McOp::McGroupDestroy);
        get_group_underlay(&switch, membership_group_ip()).unwrap();
        assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
        assert!(switch.asic_hdl.mc_group_exists(underlay_id));

        del_group(&switch, key.ip(), MEMBERSHIP_TEST_TAG).unwrap();
        assert!(!switch.asic_hdl.mc_group_exists(external_id));
        assert!(!switch.asic_hdl.mc_group_exists(underlay_id));
    }

    #[test]
    fn test_external_create_failed_unwind_keeps_target_reservation() {
        for (group_ip, other_ip) in
            [("224.1.2.3", "224.1.2.4"), ("ff0e::1", "ff0e::2")]
        {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let other_ip: IpAddr = other_ip.parse().unwrap();
            let (route_table, _, nat_table) = external_tables(external_ip);
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-create-reservation-test";
            let create = || {
                external_entry(
                    external_ip,
                    tag,
                    nat_target,
                    None,
                    serde_json::Value::Null,
                )
            };
            switch.asic_hdl.inject_table_faults(
                route_table,
                TableOp::EntryAdd,
                CallRange::nth(1),
                AsicError::Synthetic,
            );
            switch.asic_hdl.inject_table_faults(
                nat_table,
                TableOp::EntryDel,
                CallRange::nth(1),
                AsicError::Synthetic,
            );

            let err = add_group_external(&switch, create()).unwrap_err();
            assert!(matches!(err, DpdError::Unwind { .. }), "{err:?}");
            assert_eq!(table_usage(&switch, nat_table).0, 1);
            let retained = {
                let mcast = switch.mcast.lock().unwrap();
                assert!(mcast.pending_repairs.contains(&external_ip));
                assert!(mcast.pending_repairs.contains(&underlay_key));
                assert_eq!(
                    mcast.nat_target_refs.get(&underlay_ip).map(GroupKey::ip),
                    Some(external_ip),
                );
                serde_json::to_value(
                    MulticastGroupExternalResponse::try_from(
                        &mcast.groups[&external_ip],
                    )
                    .unwrap(),
                )
                .unwrap()
            };

            let err = add_group_external(&switch, create()).unwrap_err();
            assert!(matches!(err, DpdError::Exists(_)), "{err:?}");

            assert!(
                add_group_external(
                    &switch,
                    external_entry(
                        other_ip,
                        tag,
                        external_nat_target(other_ip, underlay_ip),
                        None,
                        serde_json::Value::Null,
                    ),
                )
                .is_err()
            );
            let underlay_tag =
                underlay_tag_and_members(&switch, underlay_key).0;
            let err = del_group(&switch, underlay_key.ip(), &underlay_tag)
                .unwrap_err();
            assert!(
                matches!(err, DpdError::McastGroupReferenced(ref message)
                    if message.contains("still referenced")),
                "{err:?}"
            );

            switch.asic_hdl.inject_table_faults(
                route_table,
                TableOp::EntryAdd,
                CallRange::starting_at(1),
                AsicError::Synthetic,
            );
            let err = get_group(&switch, external_ip).unwrap_err();
            assert!(matches!(err, DpdError::McastRepairPending(_)), "{err:?}");
            {
                let mcast = switch.mcast.lock().unwrap();
                assert!(mcast.pending_repairs.contains(&external_ip));
                assert_eq!(
                    mcast.nat_target_refs.get(&underlay_ip).map(GroupKey::ip),
                    Some(external_ip),
                );
            }

            switch.asic_hdl.clear_table_faults(route_table, TableOp::EntryAdd);
            switch.asic_hdl.clear_table_faults(nat_table, TableOp::EntryDel);
            let MulticastGroupResponse::External(response) =
                get_group(&switch, external_ip).unwrap()
            else {
                panic!("expected an external response");
            };
            assert_eq!(serde_json::to_value(response).unwrap(), retained);
            assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
            assert_eq!(table_usage(&switch, nat_table).0, 1);
            assert_eq!(
                source_filter_prefixes(&switch, external_ip),
                BTreeSet::from([if external_ip.is_ipv4() {
                    "0.0.0.0/0".to_string()
                } else {
                    "::/0".to_string()
                }]),
            );
            assert_eq!(
                route_action(&switch, external_ip),
                Some(("forward".to_string(), None)),
            );

            del_group(&switch, external_ip, tag).unwrap();
            assert_eq!(table_usage(&switch, nat_table).0, 0);
            assert!(source_filter_prefixes(&switch, external_ip).is_empty());
            assert!(route_action(&switch, external_ip).is_none());
            let mcast = switch.mcast.lock().unwrap();
            assert!(!mcast.groups.contains_key(&external_ip));
            assert!(mcast.nat_target_refs.is_empty());
            assert!(mcast.pending_repairs.is_empty());
        }
    }

    #[test]
    fn test_external_create_vlan_unwind_failure() {
        let external_ip: IpAddr = "ff0e::1".parse().unwrap();
        let (switch, _logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (_, members) = underlay_tag_and_members(&switch, underlay_key);
        let external_id = switch.mcast.lock().unwrap().groups[&underlay_key]
            .external_group_id();
        table::mcast::mcast_egress::clear_bitmap_entry(&switch, external_id)
            .unwrap();
        switch.asic_hdl.inject_table_faults(
            TableType::McastIpv6,
            TableOp::EntryUpdate,
            CallRange::nth(1),
            AsicError::Synthetic,
        );
        switch.asic_hdl.inject_table_faults(
            TableType::McastEgressDecapPorts,
            TableOp::EntryUpdate,
            CallRange::nth(1),
            AsicError::Synthetic,
        );

        let tag = "external-create-vlan-test";
        let err = add_group_external(
            &switch,
            external_entry(
                external_ip,
                tag,
                external_nat_target(external_ip, underlay_ip),
                Some(10),
                serde_json::Value::Null,
            ),
        )
        .unwrap_err();
        assert!(matches!(err, DpdError::Unwind { .. }), "{err:?}");
        let bitmap = create_port_bitmap(&members, Direction::External);
        assert_eq!(
            bitmap_entry(&switch, external_id),
            Some((bitmap.clone(), Some(10)))
        );
        {
            let mcast = switch.mcast.lock().unwrap();
            assert!(mcast.pending_repairs.contains(&underlay_key));
            assert!(mcast.pending_repairs.contains(&external_ip));
        }

        switch
            .asic_hdl
            .clear_table_faults(TableType::McastIpv6, TableOp::EntryUpdate);
        switch.asic_hdl.clear_table_faults(
            TableType::McastEgressDecapPorts,
            TableOp::EntryUpdate,
        );
        get_group(&switch, external_ip).unwrap();
        get_group(&switch, underlay_key.ip()).unwrap();
        assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);
        assert_eq!(
            bitmap_entry(&switch, external_id),
            Some((bitmap.clone(), Some(10)))
        );

        del_group(&switch, external_ip, tag).unwrap();
        assert_eq!(bitmap_entry(&switch, external_id), Some((bitmap, None)));
    }

    #[test]
    fn test_external_create_repairs_marked_target() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-create-repair-test";
            let create = || {
                external_entry(
                    external_ip,
                    tag,
                    nat_target,
                    None,
                    serde_json::Value::Null,
                )
            };

            table::mcast::mcast_route::clear_ipv6_entry(
                &switch,
                underlay_ip.into(),
            )
            .unwrap();
            switch.mcast.lock().unwrap().pending_repairs.insert(underlay_key);
            switch
                .asic_hdl
                .inject_mc_faults(McOp::McPortList, CallRange::starting_at(1));

            let err = add_group_external(&switch, create()).unwrap_err();
            assert!(matches!(err, DpdError::McastRepairPending(_)), "{err:?}");
            {
                let mcast = switch.mcast.lock().unwrap();
                assert!(mcast.pending_repairs.contains(&underlay_key));
                assert!(!mcast.groups.contains_key(&external_ip));
                assert!(!mcast.nat_target_refs.contains_key(&underlay_ip));
            }
            assert!(nat_target_addr(&switch, external_ip).is_none());
            assert!(route_action(&switch, external_ip).is_none());
            assert!(source_filter_prefixes(&switch, external_ip).is_empty());
            assert!(route_action(&switch, underlay_ip.into()).is_none());

            switch.asic_hdl.clear_mc_faults(McOp::McPortList);
            add_group_external(&switch, create()).unwrap();

            assert!(route_action(&switch, underlay_ip.into()).is_some());
            assert!(route_action(&switch, external_ip).is_some());
            assert_eq!(
                nat_target_addr(&switch, external_ip),
                Some(Ipv6Addr::from(underlay_ip).to_string()),
            );
            let mcast = switch.mcast.lock().unwrap();
            assert!(mcast.pending_repairs.is_empty());
            assert!(mcast.groups.contains_key(&external_ip));
            assert_eq!(
                mcast.nat_target_refs.get(&underlay_ip).map(GroupKey::ip),
                Some(external_ip),
            );
        }
    }

    #[test]
    fn test_external_retarget_repairs_marked_target() {
        for group_ip in ["224.1.2.3", "ff0e::1"] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let (switch, _logs) = chaos_switch(Config::default());
            let (underlay_ip, _) = install_underlay_group(&switch);
            let (target_ip, target_key) = install_underlay_group_at(
                &switch,
                "ff04::124".parse().unwrap(),
            );
            let nat_target = external_nat_target(external_ip, underlay_ip);
            let tag = "external-retarget-repair-test";
            add_group_external(
                &switch,
                external_entry(
                    external_ip,
                    tag,
                    nat_target,
                    None,
                    serde_json::Value::Null,
                ),
            )
            .unwrap();
            switch.mcast.lock().unwrap().pending_repairs.insert(target_key);

            let retarget = || MulticastGroupUpdateExternalEntry {
                internal_forwarding: ExternalInternalForwarding {
                    nat_target: NatTarget {
                        internal_ip: target_ip.into(),
                        ..nat_target
                    }
                    .try_into()
                    .unwrap(),
                },
                external_forwarding: ExternalForwarding { vlan_id: None },
                sources: None,
            };
            let group = ExternalMulticastIp::new(external_ip).unwrap();

            switch
                .asic_hdl
                .inject_mc_faults(McOp::McPortList, CallRange::starting_at(1));
            let err = modify_group_external(&switch, group, tag, retarget())
                .unwrap_err();
            assert!(matches!(err, DpdError::McastRepairPending(_)), "{err:?}");
            {
                let mcast = switch.mcast.lock().unwrap();
                assert!(mcast.pending_repairs.contains(&target_key));
                assert_eq!(
                    mcast.nat_target_refs.get(&underlay_ip).map(GroupKey::ip),
                    Some(external_ip),
                );
                assert!(!mcast.nat_target_refs.contains_key(&target_ip));
            }
            assert_eq!(
                nat_target_addr(&switch, external_ip),
                Some(Ipv6Addr::from(underlay_ip).to_string()),
            );

            switch.asic_hdl.clear_mc_faults(McOp::McPortList);
            modify_group_external(&switch, group, tag, retarget()).unwrap();
            assert_eq!(
                nat_target_addr(&switch, external_ip),
                Some(Ipv6Addr::from(target_ip).to_string()),
            );
            let mcast = switch.mcast.lock().unwrap();
            assert!(mcast.pending_repairs.is_empty());
            assert_eq!(
                mcast.nat_target_refs.get(&target_ip).map(GroupKey::ip),
                Some(external_ip),
            );
            assert!(!mcast.nat_target_refs.contains_key(&underlay_ip));
        }
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
    /// When `target_changed` is true, the NAT target moves to another underlay
    /// group and the old bitmap VLAN is cleared. Otherwise, the VLAN changes
    /// on the same underlay group.
    fn external_update_readds_missing_bitmap(
        external_ip: IpAddr,
        target_changed: bool,
    ) {
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (target_ip, target_key) = if target_changed {
            install_underlay_group_at(&switch, "ff04::124".parse().unwrap())
        } else {
            (underlay_ip, underlay_key)
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

        table::mcast::mcast_egress::clear_bitmap_entry(
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
                    vlan_id: Some(if target_changed { 10 } else { 20 }),
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
            if target_changed { 2 } else { 1 }
        );
        let bitmap_vlan = |key: GroupKey| {
            let external_id =
                switch.mcast.lock().unwrap().groups[&key].external_group_id();
            bitmap_entry(&switch, external_id).map(|(_, vlan_id)| vlan_id)
        };
        if target_changed {
            assert_eq!(bitmap_vlan(underlay_key), Some(None));
            assert_eq!(bitmap_vlan(target_key), Some(Some(10)));
        } else {
            assert_eq!(bitmap_vlan(underlay_key), Some(Some(20)));
        }
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
            config.asic_config.table_entry_update.values.insert(nat_table, 1.0);

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
            table::mcast::mcast_egress::clear_bitmap_entry(
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
    fn test_external_create_tables_replace_existing_entries() {
        for external_ip in ["239.1.2.3", "ff0e::1"] {
            for full in [false, true] {
                let (switch, logs) = chaos_switch(Config::default());
                let external_ip: IpAddr = external_ip.parse().unwrap();
                let (route_table, source_table, nat_table) =
                    external_tables(external_ip);
                let old_target = external_nat_target(
                    external_ip,
                    "ff04::123".parse().unwrap(),
                );
                let entry = external_entry(
                    external_ip,
                    "external-create-set-test",
                    old_target,
                    Some(10),
                    serde_json::Value::Null,
                );
                let sources = SourceFilter::from(&entry);
                configure_external_tables(&switch, &entry, &sources).unwrap();

                if full {
                    for table in [route_table, source_table, nat_table] {
                        let mut table = switch.table_get(table).unwrap();
                        table.usage.size = table.usage.occupancy;
                    }
                }

                let new_target = external_nat_target(
                    external_ip,
                    "ff04::456".parse().unwrap(),
                );

                for vlan_id in [Some(20), None] {
                    let entry = external_entry(
                        external_ip,
                        "external-create-set-test",
                        new_target,
                        vlan_id,
                        serde_json::Value::Null,
                    );
                    configure_external_tables(&switch, &entry, &sources)
                        .unwrap();

                    let expected_route = match vlan_id {
                        Some(vlan_id) => (
                            "forward_vlan".to_string(),
                            Some(vlan_id.to_string()),
                        ),
                        None => ("forward".to_string(), None),
                    };
                    assert_eq!(
                        route_action(&switch, external_ip),
                        Some(expected_route)
                    );
                    let nat = forwarding_table_snapshot(&switch, nat_table);
                    assert_eq!(
                        nat["entries"][0]["action_args"],
                        serde_json::json!({
                            "target": new_target.internal_ip.to_string(),
                            "inner_mac": new_target.inner_mac.to_string(),
                            "vni": new_target.vni.as_u32().to_string(),
                        })
                    );
                    for table in [route_table, source_table, nat_table] {
                        assert_eq!(table_usage(&switch, table).0, 1, "{table}");
                    }
                }
                assert!(logs.entries.lock().unwrap().is_empty());
            }
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
                    table::mcast::mcast_nat::set_ipv4_entry(
                        &switch, group, nat_target,
                    )
                    .unwrap();
                    table::mcast::mcast_src_filter::set_ipv4_entry(
                        &switch,
                        oxnet::Ipv4Net::host_net(src),
                        group,
                    )
                    .unwrap();
                    table::mcast::mcast_route::set_ipv4_entry(
                        &switch,
                        group,
                        Some(10),
                    )
                    .unwrap();
                }
                (IpAddr::V6(group), IpAddr::V6(src)) => {
                    table::mcast::mcast_nat::set_ipv6_entry(
                        &switch, group, nat_target,
                    )
                    .unwrap();
                    table::mcast::mcast_src_filter::set_ipv6_entry(
                        &switch,
                        oxnet::Ipv6Net::host_net(src),
                        group,
                    )
                    .unwrap();
                    table::mcast::mcast_route::set_ipv6_entry(
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
                "sources": [{ "type": "exact", "value": source }],
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
                route_action(&switch, external_ip),
                Some(("forward_vlan".to_string(), Some("20".to_string())))
            );
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_underlay_update_readds_missing_entries() {
        for membership_changed in [false, true] {
            for (repl_missing, bitmap_missing) in
                [(true, false), (false, true), (true, true)]
            {
                let context = format!(
                    "membership_changed={membership_changed}, \
                     repl_missing={repl_missing}, \
                     bitmap_missing={bitmap_missing}"
                );
                let (switch, logs) = chaos_switch(Config::default());
                let free_ids = {
                    let groups = switch.mcast.lock().unwrap();
                    groups.free_group_ids.lock().unwrap().len()
                };
                let (underlay_ip, underlay_key) =
                    install_underlay_group(&switch);
                let (tag, members) =
                    underlay_tag_and_members(&switch, underlay_key);
                let external_id = switch.mcast.lock().unwrap().groups
                    [&underlay_key]
                    .external_group_id();

                if repl_missing {
                    table::mcast::mcast_replication::clear_ipv6_entry(
                        &switch,
                        underlay_ip.into(),
                    )
                    .unwrap();
                }
                if bitmap_missing {
                    table::mcast::mcast_egress::clear_bitmap_entry(
                        &switch,
                        external_id,
                    )
                    .unwrap();
                }
                assert_eq!(
                    table_usage(&switch, TableType::McastIpv6).0,
                    u32::from(!repl_missing),
                    "{context}"
                );
                assert_eq!(
                    table_usage(&switch, TableType::McastEgressDecapPorts).0,
                    u32::from(!bitmap_missing),
                    "{context}"
                );
                switch
                    .mcast
                    .lock()
                    .unwrap()
                    .pending_repairs
                    .insert(underlay_key);

                let requested_members = if membership_changed {
                    let kept: Vec<_> = members
                        .iter()
                        .filter(|member| {
                            member.direction == Direction::Underlay
                        })
                        .cloned()
                        .collect();
                    kept
                } else {
                    members
                };
                let response = modify_group_underlay(
                    &switch,
                    underlay_ip,
                    &tag,
                    MulticastGroupUpdateUnderlayEntry {
                        members: requested_members.clone(),
                    },
                )
                .unwrap();
                assert_eq!(response.members, requested_members, "{context}");
                assert_eq!(
                    bitmap_entry(&switch, external_id),
                    Some((
                        create_port_bitmap(
                            &requested_members,
                            Direction::External,
                        ),
                        None,
                    )),
                    "{context}"
                );

                let groups = switch.mcast.lock().unwrap();
                assert!(groups.groups.contains_key(&underlay_key));
                assert!(
                    !groups.pending_repairs.contains(&underlay_key),
                    "{context}"
                );
                assert_eq!(
                    groups.free_group_ids.lock().unwrap().len(),
                    free_ids - 2,
                    "{context}"
                );
                for table in [
                    TableType::McastIpv6,
                    TableType::RouteIpv6Mcast,
                    TableType::McastEgressDecapPorts,
                ] {
                    assert_eq!(
                        table_usage(&switch, table).0,
                        1,
                        "{context}: {table}"
                    );
                }
                assert!(logs.entries.lock().unwrap().is_empty());
            }
        }
    }

    fn external_update_after_underlay_abandoned(target_changed: bool) {
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
        table::mcast::mcast_egress::clear_bitmap_entry(
            &switch,
            underlay.external_group_id(),
        )
        .unwrap();
        table::mcast::mcast_replication::clear_ipv6_entry(&switch, ipv6)
            .unwrap();
        table::mcast::mcast_route::clear_ipv6_entry(&switch, ipv6).unwrap();
        drop(underlay);

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

        let (target_ip, target_key) = if target_changed {
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

    /// Scenarios for which emptying an underlay group's membership fails in
    /// [`underlay_rollback_restores_propagated_vlan`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum VlanRestoreCase {
        /// Deleting the replication entry fails.
        ReplicationDelFails,
        /// The bitmap entry is missing before the update.
        BitmapMissing,
        /// The bitmap table has no room to re-add the entry.
        BitmapTableFull,
        /// Deleting the bitmap entry fails.
        BitmapDelFails,
    }

    /// Check the bitmap VLAN after a failed attempt to remove all underlay
    /// members. VLAN 10 comes from the referencing external group.
    ///
    /// `port_add_fails` prevents rollback from restoring removed members.
    fn underlay_rollback_restores_propagated_vlan(
        case: VlanRestoreCase,
        port_add_fails: bool,
    ) {
        let context = format!("{case:?}, port_add_fails: {port_add_fails}");
        let mut config = Config::default();
        if case != VlanRestoreCase::BitmapDelFails {
            config
                .asic_config
                .table_entry_del
                .values
                .insert(TableType::McastIpv6, 1.0);
        }
        let (switch, _logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);

        let external_ip: IpAddr = "ff0e::1".parse().unwrap();
        let nat_target = external_nat_target(external_ip, underlay_ip);
        let entry =
            serde_json::from_value::<MulticastGroupCreateExternalEntry>(
                serde_json::json!({
                    "group_ip": external_ip,
                    "tag": "external-vlan-rollback-test",
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
        let (underlay_tag, members) =
            underlay_tag_and_members(&switch, underlay_key);
        let original_bitmap =
            (create_port_bitmap(&members, Direction::External), Some(10));
        assert_eq!(
            bitmap_entry(&switch, external_group_id),
            Some(original_bitmap.clone())
        );

        match case {
            VlanRestoreCase::ReplicationDelFails => {}
            VlanRestoreCase::BitmapMissing => {
                table::mcast::mcast_egress::clear_bitmap_entry(
                    &switch,
                    external_group_id,
                )
                .unwrap();
                assert!(bitmap_entry(&switch, external_group_id).is_none());
            }
            VlanRestoreCase::BitmapTableFull => {
                let mut bitmap =
                    switch.table_get(TableType::McastEgressDecapPorts).unwrap();
                bitmap.usage.size = bitmap.usage.occupancy;
            }
            VlanRestoreCase::BitmapDelFails => {
                switch.asic_hdl.inject_table_faults(
                    TableType::McastEgressDecapPorts,
                    TableOp::EntryDel,
                    CallRange::nth(1),
                    AsicError::Synthetic,
                );
            }
        }
        if port_add_fails {
            switch
                .asic_hdl
                .inject_mc_faults(McOp::McPortAdd, CallRange::starting_at(1));
        }

        let (occupancy, inserts, deletes, updates) =
            table_usage(&switch, TableType::McastEgressDecapPorts);

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
                    port_add_fails
                        && unwind.len() == 1
                        && matches!(
                            &unwind.head,
                            DpdError::Switch(aal::AsicError::Synthetic(op))
                                if op == "mc_port_add"
                        ),
                    "{context}: {err:?}"
                );
                init.as_ref()
            }
            err => {
                assert!(!port_add_fails, "{context}: {err:?}");
                err
            }
        };
        assert!(
            matches!(
                init,
                DpdError::Switch(aal::AsicError::Synthetic(op))
                    if op == "table_entry_del"
            ),
            "{context}: {err:?}"
        );

        let resynced_empty =
            case == VlanRestoreCase::BitmapDelFails && port_add_fails;
        let expected_usage = match case {
            VlanRestoreCase::BitmapMissing => {
                (occupancy + 1, inserts + 1, deletes, updates)
            }
            _ if resynced_empty => {
                (occupancy - 1, inserts, deletes + 1, updates + 1)
            }
            _ => (occupancy, inserts, deletes, updates + 1),
        };
        assert_eq!(
            table_usage(&switch, TableType::McastEgressDecapPorts),
            expected_usage,
            "{context}"
        );

        let (expected_bitmap, expected_members, expected_repl) =
            if resynced_empty {
                (None, Vec::new(), 0)
            } else {
                (Some(original_bitmap), members, 1)
            };
        assert_eq!(
            bitmap_entry(&switch, external_group_id),
            expected_bitmap,
            "{context}"
        );
        assert_eq!(
            table_usage(&switch, TableType::McastIpv6).0,
            expected_repl,
            "{context}"
        );
        assert_eq!(
            underlay_tag_and_members(&switch, underlay_key).1,
            expected_members,
            "{context}"
        );
        let read = get_group_underlay(&switch, underlay_ip);
        if port_add_fails && !resynced_empty {
            assert!(
                matches!(read, Err(DpdError::McastRepairPending(_))),
                "{context}"
            );
        } else {
            assert_eq!(read.unwrap().members, expected_members, "{context}");
        }
    }

    #[test]
    fn test_underlay_rollback_restores_propagated_vlan() {
        for case in [
            VlanRestoreCase::ReplicationDelFails,
            VlanRestoreCase::BitmapMissing,
            VlanRestoreCase::BitmapTableFull,
            VlanRestoreCase::BitmapDelFails,
        ] {
            for port_add_fails in [false, true] {
                underlay_rollback_restores_propagated_vlan(
                    case,
                    port_add_fails,
                );
            }
        }
    }

    #[test]
    fn test_underlay_create_tables_replace_existing_entries() {
        for full in [false, true] {
            let (switch, logs) = chaos_switch(Config::default());
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);
            let group =
                switch.mcast.lock().unwrap().groups[&underlay_key].clone();
            let external_id = group.external_group_id();
            let underlay_id = group.underlay_group_id();
            let members = vec![rear_member(2, Direction::External)];
            let info = MulticastReplicationInfo {
                rid: external_id,
                level1_excl_id: 7,
                level2_excl_id: 9,
            };
            let tables = [
                TableType::McastEgressDecapPorts,
                TableType::McastIpv6,
                TableType::RouteIpv6Mcast,
            ];
            if full {
                for table in tables {
                    let mut table = switch.table_get(table).unwrap();
                    table.usage.size = table.usage.occupancy;
                }
            }

            for vlan_id in [Some(20), None] {
                configure_underlay_tables(
                    &switch,
                    underlay_ip,
                    external_id,
                    underlay_id,
                    Some(&info),
                    &members,
                    vlan_id,
                )
                .unwrap();

                assert_eq!(
                    bitmap_entry(&switch, external_id),
                    Some((
                        create_port_bitmap(&members, Direction::External),
                        vlan_id,
                    ))
                );
                let repl =
                    forwarding_table_snapshot(&switch, TableType::McastIpv6);
                assert_eq!(
                    repl["entries"][0]["action_args"],
                    serde_json::json!({
                        "mcast_grp_a": external_id.to_string(),
                        "mcast_grp_b": underlay_id.to_string(),
                        "rid": info.rid.to_string(),
                        "level1_excl_id": info.level1_excl_id.to_string(),
                        "level2_excl_id": info.level2_excl_id.to_string(),
                    })
                );
                assert_eq!(
                    route_action(&switch, underlay_ip.into()),
                    Some(("forward".to_string(), None))
                );
                for table in tables {
                    assert_eq!(table_usage(&switch, table).0, 1, "{table}");
                }
            }
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_underlay_first_members_overwrite_stale_bitmap() {
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_empty_underlay_group(&switch);
        let group = switch.mcast.lock().unwrap().groups[&underlay_key].clone();

        table::mcast::mcast_egress::set_bitmap_entry(
            &switch,
            group.external_group_id(),
            &table::mcast::mcast_egress::PortBitmap::new(),
            Some(10),
        )
        .unwrap();

        {
            let mut bitmap =
                switch.table_get(TableType::McastEgressDecapPorts).unwrap();
            bitmap.usage.size = bitmap.usage.occupancy;
        }

        let [external_member, underlay_member, _] = membership_members();
        let members = vec![external_member, underlay_member];
        let response = modify_group_underlay(
            &switch,
            underlay_ip,
            &group.tag,
            MulticastGroupUpdateUnderlayEntry { members: members.clone() },
        )
        .unwrap();
        assert_eq!(response.members, members);

        assert_eq!(stored_membership(&switch), members);
        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, &members)
        );
        assert_eq!(
            bitmap_entry(&switch, group.external_group_id()),
            Some((create_port_bitmap(&members, Direction::External), None))
        );
        assert_eq!(table_usage(&switch, TableType::McastEgressDecapPorts).0, 1);
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);
        assert!(logs.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn test_del_empty_underlay_clears_stale_entries() {
        let (switch, logs) = chaos_switch(Config::default());
        let (underlay_ip, underlay_key) = install_empty_underlay_group(&switch);
        let group = switch.mcast.lock().unwrap().groups[&underlay_key].clone();
        let repl = MulticastReplicationInfo::new(group.external_group_id());

        table::mcast::mcast_egress::set_bitmap_entry(
            &switch,
            group.external_group_id(),
            &table::mcast::mcast_egress::PortBitmap::new(),
            None,
        )
        .unwrap();
        table::mcast::mcast_replication::set_ipv6_entry(
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
        let (switch, _logs) = chaos_switch(Config::default());
        let free_ids = {
            let groups = switch.mcast.lock().unwrap();
            groups.free_group_ids.lock().unwrap().len()
        };
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        drop(switch.mcast.lock().unwrap().groups.remove(&underlay_key));
        switch
            .asic_hdl
            .inject_mc_faults(McOp::McGroupCreate, CallRange::starting_at(1));

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
        mcast_nat::set_ipv4_entry(&switch, ipv4, nat_target).unwrap();
        table::mcast::mcast_route::set_ipv4_entry(&switch, ipv4, None).unwrap();

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

        {
            let errs = logs.entries.lock().unwrap();
            assert_eq!(errs.len(), 1, "{errs:?}");
            assert_eq!(errs[0]["operation"], "restore source filter entry");
            assert!(errs[0]["context"].contains("192.0.2.1"));
            assert!(errs[0]["error"].contains("table_entry_add"));
        }

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
            ("224.1.2.3", ["192.0.2.1", "192.0.2.2", "192.0.2.3"]),
            ("ff0e::1", ["2001:db8::1", "2001:db8::2", "2001:db8::3"]),
        ] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let [first, second, third]: [IpAddr; 3] =
                source_ips.map(|ip| ip.parse().unwrap());
            let prefix_len = if external_ip.is_ipv4() { 32 } else { 128 };
            for sources_changed in [false, true] {
                let context =
                    format!("{external_ip}: sources_changed={sources_changed}");
                let (switch, logs) = chaos_switch(Config::default());
                let (underlay_ip, _) = install_underlay_group(&switch);
                let (_, source_table, _) = external_tables(external_ip);
                let nat_target = external_nat_target(external_ip, underlay_ip);
                let tag = "external-readd-sources-test";
                let initial_sources = [first, second];
                let init_sources = initial_sources.map(
                    |ip| serde_json::json!({ "type": "exact", "value": ip }),
                );
                add_group_external(
                    &switch,
                    external_entry(
                        external_ip,
                        tag,
                        nat_target,
                        Some(10),
                        serde_json::json!(init_sources),
                    ),
                )
                .unwrap();
                assert_eq!(
                    source_filter_prefixes(&switch, external_ip),
                    BTreeSet::from(
                        initial_sources.map(|ip| format!("{ip}/{prefix_len}"))
                    ),
                    "{context}"
                );
                let missing = if sources_changed {
                    &initial_sources[1..]
                } else {
                    &initial_sources[..]
                };
                for source in missing {
                    clear_source_filter(
                        &switch,
                        external_ip,
                        IpSrc::Exact(*source),
                    )
                    .unwrap();
                }
                assert_eq!(
                    source_filter_prefixes(&switch, external_ip),
                    if sources_changed {
                        BTreeSet::from([format!("{first}/{prefix_len}")])
                    } else {
                        BTreeSet::new()
                    },
                    "{context}"
                );
                if sources_changed {
                    set_source_filter(&switch, external_ip, IpSrc::Any)
                        .unwrap();
                }

                let wanted = if sources_changed {
                    [second, third]
                } else {
                    initial_sources
                };
                let sources = wanted
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

                assert_eq!(
                    table_usage(&switch, source_table).0,
                    2,
                    "{context}"
                );
                assert_eq!(
                    source_filter_prefixes(&switch, external_ip),
                    BTreeSet::from(
                        wanted.map(|ip| format!("{ip}/{prefix_len}"))
                    ),
                    "{context}"
                );
                assert!(logs.entries.lock().unwrap().is_empty());
            }
        }
    }

    #[test]
    fn test_underlay_update_rollback_readds_missing_repl() {
        for port_remove_fails in [false, true] {
            let mut config = Config::default();
            if port_remove_fails {
                config.asic_config.mc_config.mc_port_remove =
                    asic::chaos::Chaos::new(1.0);
            }

            let (switch, logs) = chaos_switch(config);
            let (underlay_ip, underlay_key) = install_underlay_group(&switch);
            let (tag, members) =
                underlay_tag_and_members(&switch, underlay_key);
            switch.asic_hdl.inject_table_faults(
                TableType::McastIpv6,
                TableOp::EntryAdd,
                CallRange::between(1, 2),
                AsicError::Synthetic,
            );

            table::mcast::mcast_replication::clear_ipv6_entry(
                &switch,
                underlay_ip.into(),
            )
            .unwrap();

            let before_repl = table_usage(&switch, TableType::McastIpv6);
            assert_eq!(before_repl.0, 0);

            let added_member = MulticastGroupMember {
                port_id: RearPort::new(2).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            };
            let mut new_members = members.clone();
            new_members.push(added_member.clone());

            let err = modify_group_underlay(
                &switch,
                underlay_ip,
                &tag,
                MulticastGroupUpdateUnderlayEntry { members: new_members },
            )
            .unwrap_err();

            let rollback_op = if port_remove_fails {
                "mc_port_remove"
            } else {
                "table_entry_add"
            };
            assert!(
                matches!(
                    err,
                    DpdError::Unwind { initial: ref init, ref unwind }
                        if matches!(
                            init.as_ref(),
                            DpdError::Switch(
                                aal::AsicError::Synthetic(op)
                            ) if op == "table_entry_add"
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
                "replication entry was not re-added by recovery"
            );

            let expected: &[(&str, &str)] = if port_remove_fails {
                &[
                    ("port changes", "mc_port_remove"),
                    ("restore replication settings", "table_entry_add"),
                ]
            } else {
                &[("restore replication settings", "table_entry_add")]
            };
            {
                let errs = logs.entries.lock().unwrap();
                assert_eq!(errs.len(), expected.len(), "{errs:?}");
                for (err, &(op, failed_call)) in errs.iter().zip(expected) {
                    assert_eq!(err["operation"], op);
                    assert!(err["error"].contains(failed_call));
                }
            }

            let expected_members = if port_remove_fails {
                vec![members[0].clone(), members[1].clone(), added_member]
            } else {
                members
            };
            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &expected_members)
            );
            let external_id = membership_group_id(&switch, Direction::External);
            assert_eq!(
                bitmap_entry(&switch, external_id),
                Some((
                    create_port_bitmap(&expected_members, Direction::External),
                    None,
                ))
            );
            let groups = switch.mcast.lock().unwrap();
            let group = &groups.groups[&underlay_key];
            assert_eq!(
                group.members().cloned().collect::<Vec<_>>(),
                expected_members
            );
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
        table::mcast::mcast_egress::clear_bitmap_entry(
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

        {
            let errs = logs.entries.lock().unwrap();
            assert_eq!(errs.len(), 1, "{errs:?}");
            assert_eq!(errs[0]["operation"], "restore multicast bitmap VLAN");
        }

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
        for group_create_fails in [true, false] {
            let (op, failed_call, failed_op) = if group_create_fails {
                (
                    "restore multicast group",
                    "mc_group_create",
                    McOp::McGroupCreate,
                )
            } else {
                (
                    "restore multicast group member",
                    "mc_port_add",
                    McOp::McPortAdd,
                )
            };

            let (switch, logs) = chaos_switch(Config::default());
            let (_, underlay_key) = install_underlay_group(&switch);
            let (tag, members) =
                underlay_tag_and_members(&switch, underlay_key);
            switch
                .asic_hdl
                .inject_mc_faults(McOp::McGroupDestroy, CallRange::nth(2));
            switch.asic_hdl.inject_mc_faults(failed_op, CallRange::nth(1));

            let (external_id, underlay_id) = {
                let groups = switch.mcast.lock().unwrap();
                let group = &groups.groups[&underlay_key];
                (group.external_group_id(), group.underlay_group_id())
            };
            let underlay_ports =
                switch.asic_hdl.mc_port_list(underlay_id).unwrap();

            let err = del_group(&switch, underlay_key.ip(), &tag).unwrap_err();
            assert!(
                matches!(
                    err,
                    DpdError::Unwind { initial: ref init, ref unwind }
                        if is_synthetic(init, McOp::McGroupDestroy)
                            && unwind.len() == 1
                            && is_synthetic(&unwind.head, failed_op)
                ),
                "{err:?}"
            );

            assert!(
                switch.asic_hdl.mc_port_list(external_id).unwrap().is_empty()
            );
            assert_eq!(
                switch.asic_hdl.mc_port_list(underlay_id).unwrap(),
                underlay_ports
            );

            {
                let errs = logs.entries.lock().unwrap();
                assert_eq!(errs.len(), 1, "{errs:?}");
                assert_eq!(errs[0]["operation"], op);
                assert!(errs[0]["error"].contains(failed_call), "{errs:?}");
            }

            for table in [
                TableType::McastIpv6,
                TableType::McastEgressDecapPorts,
                TableType::RouteIpv6Mcast,
            ] {
                assert_eq!(table_usage(&switch, table).0, 1, "{table}");
            }

            let underlay_members = members
                .iter()
                .filter(|member| member.direction == Direction::Underlay)
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(
                underlay_tag_and_members(&switch, underlay_key).1,
                underlay_members
            );
            assert_eq!(
                bitmap_entry(&switch, external_id),
                Some((
                    create_port_bitmap(&underlay_members, Direction::External),
                    None
                ))
            );
        }
    }

    #[test]
    fn test_underlay_unchanged_update_readd_failure_keeps_members() {
        let mut config = Config::default();
        config.asic_config.mc_config.mc_port_remove =
            asic::chaos::Chaos::new(1.0);

        let (switch, logs) = chaos_switch(config);
        let (underlay_ip, underlay_key) = install_underlay_group(&switch);
        let (tag, members) = underlay_tag_and_members(&switch, underlay_key);
        switch
            .asic_hdl
            .inject_mc_faults(McOp::McPortAdd, CallRange::starting_at(1));
        let tables = [TableType::McastIpv6, TableType::McastEgressDecapPorts];
        let before = tables.map(|table| table_usage(&switch, table));

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
        assert_eq!(tables.map(|table| table_usage(&switch, table)), before);
        assert!(logs.entries.lock().unwrap().is_empty());

        switch.asic_hdl.clear_mc_faults(McOp::McPortAdd);
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
    fn test_external_update_repairs_untracked_source_filters() {
        for (group_ip, other_ip, source_ip, stale_ip) in [
            ("224.1.2.3", "224.1.2.4", "192.0.2.1", "192.0.2.2"),
            ("ff0e::1", "ff0e::2", "2001:db8::1", "2001:db8::2"),
        ] {
            let external_ip: IpAddr = group_ip.parse().unwrap();
            let other_ip: IpAddr = other_ip.parse().unwrap();
            let stale_ip: IpAddr = stale_ip.parse().unwrap();
            let exact = SourceEntry::Exact(
                ExactSource::new(source_ip.parse().unwrap()).unwrap(),
            );
            for (source, cleanup_fails) in
                [(SourceEntry::Any, false), (exact, false), (exact, true)]
            {
                let (_, source_table, _) = external_tables(external_ip);
                let mut config = Config::default();
                if cleanup_fails {
                    config
                        .asic_config
                        .table_entry_del
                        .values
                        .insert(source_table, 1.0);
                }
                let (switch, logs) = chaos_switch(config);
                let (underlay_ip, _) = install_underlay_group(&switch);
                let nat_target = external_nat_target(external_ip, underlay_ip);
                let tag = "external-source-filter-repair-test";
                add_group_external(
                    &switch,
                    external_entry(
                        external_ip,
                        tag,
                        nat_target,
                        None,
                        serde_json::json!([source]),
                    ),
                )
                .unwrap();
                let wanted = source_filter_prefixes(&switch, external_ip);
                let stored = serde_json::to_value(
                    get_group(&switch, external_ip).unwrap(),
                )
                .unwrap();

                set_source_filter(&switch, external_ip, IpSrc::Any).unwrap();
                set_source_filter(&switch, external_ip, IpSrc::Exact(stale_ip))
                    .unwrap();
                set_source_filter(&switch, other_ip, IpSrc::Any).unwrap();
                let other_sources = source_filter_prefixes(&switch, other_ip);
                let installed = source_filter_prefixes(&switch, external_ip);
                assert_ne!(installed, wanted);
                {
                    let mut table = switch.table_get(source_table).unwrap();
                    table.usage.size = table.usage.occupancy;
                }

                let res = modify_group_external(
                    &switch,
                    ExternalMulticastIp::new(external_ip).unwrap(),
                    tag,
                    MulticastGroupUpdateExternalEntry {
                        internal_forwarding: ExternalInternalForwarding {
                            nat_target: nat_target.try_into().unwrap(),
                        },
                        external_forwarding: ExternalForwarding {
                            vlan_id: None,
                        },
                        sources: None,
                    },
                );
                let expected = if cleanup_fails {
                    let err = res.unwrap_err();
                    assert!(
                        matches!(
                            err,
                            DpdError::Switch(AsicError::Synthetic(ref op))
                                if op == "table_entry_del"
                        ),
                        "{err:?}"
                    );
                    &installed
                } else {
                    res.unwrap();
                    &wanted
                };
                assert_eq!(
                    &source_filter_prefixes(&switch, external_ip),
                    expected
                );
                assert_eq!(
                    source_filter_prefixes(&switch, other_ip),
                    other_sources
                );
                assert_eq!(
                    serde_json::to_value(
                        get_group(&switch, external_ip).unwrap()
                    )
                    .unwrap(),
                    stored
                );
                assert!(logs.entries.lock().unwrap().is_empty());
            }
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
                                mcast_nat::clear_ipv4_entry(&switch, ipv4)
                                    .unwrap();
                            }
                            if remove_route {
                                table::mcast::mcast_route::clear_ipv4_entry(
                                    &switch, ipv4,
                                )
                                .unwrap();
                            }
                        }
                        IpAddr::V6(ipv6) => {
                            if remove_nat {
                                mcast_nat::clear_ipv6_entry(&switch, ipv6)
                                    .unwrap();
                            }
                            if remove_route {
                                table::mcast::mcast_route::clear_ipv6_entry(
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
    fn test_underlay_update_repairs_missing_route_when_marked() {
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
            table::mcast::mcast_route::clear_ipv6_entry(
                &switch,
                underlay_ip.into(),
            )
            .unwrap();
            assert_eq!(table_usage(&switch, TableType::RouteIpv6Mcast).0, 0);
            switch.mcast.lock().unwrap().pending_repairs.insert(underlay_key);

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

    const MEMBERSHIP_TEST_TAG: &str = "underlay-membership-test";

    fn membership_group_ip() -> UnderlayMulticastIpv6 {
        "ff04::123".parse().unwrap()
    }

    fn rear_member(port: u8, direction: Direction) -> MulticastGroupMember {
        MulticastGroupMember {
            port_id: RearPort::new(port).unwrap().into(),
            link_id: LinkId(0),
            direction,
        }
    }

    fn membership_members() -> [MulticastGroupMember; 3] {
        [
            rear_member(0, Direction::External),
            rear_member(1, Direction::Underlay),
            rear_member(2, Direction::External),
        ]
    }

    fn create_membership_group(
        switch: &Switch,
        members: &[MulticastGroupMember],
    ) {
        add_group_underlay(
            switch,
            MulticastGroupCreateUnderlayEntry {
                group_ip: membership_group_ip(),
                tag: Some(MEMBERSHIP_TEST_TAG.to_string()),
                members: members.to_vec(),
            },
        )
        .unwrap();
    }

    fn put_membership(
        switch: &Switch,
        members: &[MulticastGroupMember],
    ) -> DpdResult<MulticastGroupUnderlayResponse> {
        modify_group_underlay(
            switch,
            membership_group_ip(),
            MEMBERSHIP_TEST_TAG,
            MulticastGroupUpdateUnderlayEntry { members: members.to_vec() },
        )
    }

    fn stored_membership(switch: &Switch) -> Vec<MulticastGroupMember> {
        let mcast = switch.mcast.lock().unwrap();
        mcast.groups[&GroupKey::underlay(membership_group_ip())]
            .members()
            .cloned()
            .collect()
    }

    #[derive(Clone, Copy, Debug)]
    enum Reader {
        Underlay,
        Group,
        List,
    }

    const READERS: [Reader; 3] =
        [Reader::Underlay, Reader::Group, Reader::List];

    fn read_membership(
        switch: &Switch,
        reader: Reader,
    ) -> Vec<MulticastGroupMember> {
        let response = match reader {
            Reader::Underlay => {
                return get_group_underlay(switch, membership_group_ip())
                    .unwrap()
                    .members;
            }
            Reader::Group => {
                get_group(switch, membership_group_ip().into()).unwrap()
            }
            Reader::List => {
                get_range(switch, None, 1, Some(MEMBERSHIP_TEST_TAG))
                    .unwrap()
                    .pop()
                    .unwrap()
            }
        };
        let MulticastGroupResponse::Underlay(group) = response else {
            panic!("expected an underlay response");
        };
        group.members
    }

    fn read_memberships(switch: &Switch) -> [Vec<MulticastGroupMember>; 3] {
        READERS.map(|reader| read_membership(switch, reader))
    }

    fn assert_uncertain_reads(switch: &Switch) {
        for res in [
            get_group_underlay(switch, membership_group_ip()).map(|_| ()),
            get_group(switch, membership_group_ip().into()).map(|_| ()),
        ] {
            assert!(
                matches!(res, Err(DpdError::McastRepairPending(_))),
                "{res:?}"
            );
        }
        let MulticastGroupResponse::Underlay(listed) =
            get_range(switch, None, 1, Some(MEMBERSHIP_TEST_TAG))
                .unwrap()
                .pop()
                .unwrap()
        else {
            panic!("expected an underlay response");
        };
        assert_eq!(listed.members, stored_membership(switch));
    }

    #[test]
    fn test_underlay_member_order_is_consistent() {
        let unsorted = [
            rear_member(2, Direction::Underlay),
            rear_member(0, Direction::External),
            rear_member(1, Direction::Underlay),
            rear_member(0, Direction::Underlay),
        ];
        let sorted = [
            rear_member(0, Direction::Underlay),
            rear_member(0, Direction::External),
            rear_member(1, Direction::Underlay),
            rear_member(2, Direction::Underlay),
        ];

        let mut with_dup = unsorted.to_vec();
        with_dup.push(unsorted[1].clone());

        let (switch, _logs) = chaos_switch(Config::default());

        let created = add_group_underlay(
            &switch,
            MulticastGroupCreateUnderlayEntry {
                group_ip: membership_group_ip(),
                tag: Some(MEMBERSHIP_TEST_TAG.to_string()),
                members: unsorted.to_vec(),
            },
        )
        .unwrap();
        assert_eq!(created.members, sorted);
        assert_consistent_membership(&switch, &sorted);

        let updated = put_membership(&switch, &with_dup).unwrap();
        assert_eq!(updated.members, sorted);
        assert_consistent_membership(&switch, &sorted);
    }

    fn assert_consistent_membership(
        switch: &Switch,
        expected: &[MulticastGroupMember],
    ) {
        assert_eq!(stored_membership(switch), expected);
        for (reader, read) in READERS.into_iter().zip(read_memberships(switch))
        {
            assert_eq!(read, expected, "{reader:?}");
        }
        assert_eq!(
            asic_membership(switch),
            expected_membership(switch, expected)
        );
    }

    #[test]
    fn test_underlay_reads_repair_marked_group() {
        for reader in READERS {
            underlay_reads_repair_marked_group(reader);
        }
    }

    fn underlay_reads_repair_marked_group(reader: Reader) {
        let members = membership_members();
        let (switch, _logs) = chaos_switch(Config::default());
        create_membership_group(&switch, &members[..2]);

        {
            let mut mcast = switch.mcast.lock().unwrap();
            let group = mcast
                .groups
                .get_mut(&GroupKey::underlay(membership_group_ip()))
                .unwrap();
            let external_id = group.external_group_id();
            let GroupKind::Underlay { replication, .. } = &mut group.kind
            else {
                panic!("expected an underlay group");
            };
            replication.add_members(
                MulticastReplicationInfo::new(external_id),
                &members,
            );
            mcast
                .pending_repairs
                .insert(GroupKey::underlay(membership_group_ip()));
        }
        switch.asic_hdl.inject_table_faults(
            TableType::McastIpv6,
            TableOp::EntryUpdate,
            CallRange::starting_at(1),
            AsicError::Synthetic,
        );

        assert_uncertain_reads(&switch);
        assert_eq!(stored_membership(&switch), members);

        switch
            .asic_hdl
            .inject_mc_faults(McOp::McPortList, CallRange::starting_at(1));
        assert_uncertain_reads(&switch);
        assert_eq!(stored_membership(&switch), members);

        switch.asic_hdl.clear_mc_faults(McOp::McPortList);
        switch
            .asic_hdl
            .clear_table_faults(TableType::McastIpv6, TableOp::EntryUpdate);

        assert_eq!(
            read_membership(&switch, reader),
            members[..2],
            "{reader:?}"
        );
        assert_eq!(stored_membership(&switch), members[..2], "{reader:?}");
        assert!(
            switch.mcast.lock().unwrap().pending_repairs.is_empty(),
            "{reader:?}"
        );
        for read in read_memberships(&switch) {
            assert_eq!(read, members[..2]);
        }

        switch.asic_hdl.inject_table_faults(
            TableType::McastIpv6,
            TableOp::EntryUpdate,
            CallRange::starting_at(1),
            AsicError::Synthetic,
        );
        for read in read_memberships(&switch) {
            assert_eq!(read, members[..2]);
        }
        switch
            .asic_hdl
            .inject_mc_faults(McOp::McPortList, CallRange::starting_at(1));
        for read in read_memberships(&switch) {
            assert_eq!(read, members[..2]);
        }
        assert_eq!(stored_membership(&switch), members[..2]);

        switch.asic_hdl.clear_mc_faults(McOp::McPortList);
        switch
            .asic_hdl
            .clear_table_faults(TableType::McastIpv6, TableOp::EntryUpdate);
        put_membership(&switch, &members).unwrap();
        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, &members),
        );
    }

    #[test]
    fn test_underlay_read_recreates_missing_groups() {
        let members = membership_members();
        let (switch, _logs) = chaos_switch(Config::default());
        create_membership_group(&switch, &members);
        let group_ids = [Direction::External, Direction::Underlay]
            .map(|direction| membership_group_id(&switch, direction));
        for group_id in group_ids {
            switch.asic_hdl.mc_group_destroy(group_id).unwrap();
        }
        switch
            .mcast
            .lock()
            .unwrap()
            .pending_repairs
            .insert(GroupKey::underlay(membership_group_ip()));

        get_group_underlay(&switch, membership_group_ip()).unwrap();
        for group_id in group_ids {
            assert!(switch.asic_hdl.mc_group_exists(group_id));
        }
        assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
    }

    #[test]
    fn test_underlay_read_restores_tables() {
        for reader in READERS {
            underlay_read_restores_tables(reader);
        }
    }

    fn underlay_read_restores_tables(reader: Reader) {
        for failed_table in [
            TableType::McastIpv6,
            TableType::McastEgressDecapPorts,
            TableType::RouteIpv6Mcast,
        ] {
            let members = membership_members();
            let (switch, _logs) = chaos_switch(Config::default());
            create_membership_group(&switch, &members);
            let external_ip: IpAddr = "239.1.2.3".parse().unwrap();
            add_group_external(
                &switch,
                external_entry(
                    external_ip,
                    "external-read-repair-test",
                    external_nat_target(external_ip, membership_group_ip()),
                    Some(100),
                    serde_json::Value::Null,
                ),
            )
            .unwrap();
            let external_id = membership_group_id(&switch, Direction::External);
            match failed_table {
                TableType::McastIpv6 => {
                    table::mcast::mcast_replication::clear_ipv6_entry(
                        &switch,
                        membership_group_ip().into(),
                    )
                    .unwrap();
                }
                TableType::McastEgressDecapPorts => {
                    table::mcast::mcast_egress::clear_bitmap_entry(
                        &switch,
                        external_id,
                    )
                    .unwrap();
                }
                TableType::RouteIpv6Mcast => {
                    table::mcast::mcast_route::clear_ipv6_entry(
                        &switch,
                        membership_group_ip().into(),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            switch
                .mcast
                .lock()
                .unwrap()
                .pending_repairs
                .insert(GroupKey::underlay(membership_group_ip()));
            switch.asic_hdl.inject_table_faults(
                failed_table,
                TableOp::EntryAdd,
                CallRange::starting_at(1),
                AsicError::Synthetic,
            );

            assert_uncertain_reads(&switch);
            assert!(
                switch
                    .mcast
                    .lock()
                    .unwrap()
                    .pending_repairs
                    .contains(&GroupKey::underlay(membership_group_ip()))
            );
            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &members),
            );

            switch.asic_hdl.clear_table_faults(failed_table, TableOp::EntryAdd);
            let context = format!("{reader:?}, {failed_table}");
            let expected = members.iter().cloned().collect::<HashSet<_>>();
            assert_eq!(
                read_membership(&switch, reader)
                    .into_iter()
                    .collect::<HashSet<_>>(),
                expected,
                "{context}"
            );
            assert!(
                switch.mcast.lock().unwrap().pending_repairs.is_empty(),
                "{context}"
            );
            for read in read_memberships(&switch) {
                assert_eq!(read.into_iter().collect::<HashSet<_>>(), expected);
            }
            assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);
            assert_eq!(
                bitmap_entry(&switch, external_id),
                Some((
                    create_port_bitmap(&members, Direction::External),
                    Some(100),
                )),
            );
            assert!(
                route_action(&switch, membership_group_ip().into()).is_some()
            );

            let response =
                get_group_underlay(&switch, membership_group_ip()).unwrap();
            modify_group_underlay(
                &switch,
                membership_group_ip(),
                &response.tag,
                MulticastGroupUpdateUnderlayEntry { members: Vec::new() },
            )
            .unwrap();
            for read in read_memberships(&switch) {
                assert!(read.is_empty());
            }
            for table in
                [TableType::McastIpv6, TableType::McastEgressDecapPorts]
            {
                assert_eq!(table_usage(&switch, table).0, 0, "{table}");
            }
        }
    }

    fn membership_group_id(
        switch: &Switch,
        direction: Direction,
    ) -> MulticastGroupId {
        let groups = switch.mcast.lock().unwrap();
        groups.groups[&GroupKey::underlay(membership_group_ip())]
            .group_id(direction)
    }

    fn asic_membership(switch: &Switch) -> [Vec<AsicId>; 2] {
        [Direction::External, Direction::Underlay].map(|direction| {
            switch
                .asic_hdl
                .mc_port_list(membership_group_id(switch, direction))
                .unwrap()
        })
    }

    fn expected_membership(
        switch: &Switch,
        members: &[MulticastGroupMember],
    ) -> [Vec<AsicId>; 2] {
        [Direction::External, Direction::Underlay].map(|direction| {
            members
                .iter()
                .filter(|member| member.direction == direction)
                .map(|member| {
                    switch
                        .port_link_to_asic_id(member.port_id, member.link_id)
                        .unwrap()
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
    }

    #[test]
    fn test_underlay_update_recreates_missing_asic_groups() {
        let (switch, _logs) = chaos_switch(Config::default());
        let members = membership_members();
        create_membership_group(&switch, &members);

        for direction in [Direction::External, Direction::Underlay] {
            let group_id = membership_group_id(&switch, direction);
            switch.asic_hdl.mc_group_destroy(group_id).unwrap();
        }
        switch
            .mcast
            .lock()
            .unwrap()
            .pending_repairs
            .insert(GroupKey::underlay(membership_group_ip()));

        put_membership(&switch, &members).unwrap();

        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, &members)
        );
        assert_eq!(stored_membership(&switch), members.to_vec());
    }

    fn add_unwanted_member(switch: &Switch, member: &MulticastGroupMember) {
        let group_id = membership_group_id(switch, member.direction);
        let repl = MulticastReplicationInfo::new(membership_group_id(
            switch,
            Direction::External,
        ));
        let asic_id = switch
            .port_link_to_asic_id(member.port_id, member.link_id)
            .unwrap();
        switch
            .asic_hdl
            .mc_port_add(group_id, asic_id, repl.rid, repl.level1_excl_id)
            .unwrap();
    }

    fn is_synthetic(err: &DpdError, op: McOp) -> bool {
        matches!(
            err,
            DpdError::Switch(aal::AsicError::Synthetic(failed))
                if *failed == op.to_string()
        )
    }

    #[test]
    fn test_underlay_update_rollback_preserves_membership() {
        let [kept_member, added_member, failing_member] = membership_members();
        let init_members = [kept_member.clone()];
        let tgt_members = [kept_member.clone(), added_member, failing_member];

        for stray_member in [None, Some(rear_member(3, Direction::External))] {
            let context = format!("stray_member={stray_member:?}");
            let (switch, logs) = chaos_switch(Config::default());
            create_membership_group(&switch, &init_members);
            if let Some(member) = &stray_member {
                add_unwanted_member(&switch, member);
            }
            let mut installed_members = init_members.to_vec();
            installed_members.extend(stray_member);
            let domains = switch.asic_hdl.mc_domains();
            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &installed_members),
                "{context}"
            );

            let before_group = {
                let groups = switch.mcast.lock().unwrap();
                format!(
                    "{:?}",
                    groups.groups[&GroupKey::underlay(membership_group_ip())]
                )
            };

            let tables = [
                TableType::McastIpv6,
                TableType::McastEgressDecapPorts,
                TableType::RouteIpv6Mcast,
            ];

            let before =
                tables.map(|table| forwarding_table_snapshot(&switch, table));

            switch.asic_hdl.inject_mc_faults(
                McOp::McPortAdd,
                CallRange::nth(tgt_members.len() as u64),
            );
            let err = put_membership(&switch, &tgt_members).unwrap_err();
            assert!(is_synthetic(&err, McOp::McPortAdd), "{context}: {err:?}");

            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &installed_members),
                "{context}"
            );
            assert_eq!(switch.asic_hdl.mc_domains(), domains, "{context}");

            {
                let groups = switch.mcast.lock().unwrap();
                assert_eq!(
                    format!(
                        "{:?}",
                        groups.groups
                            [&GroupKey::underlay(membership_group_ip())]
                    ),
                    before_group,
                    "{context}"
                );
            }

            for (table, before) in tables.into_iter().zip(before) {
                assert_eq!(
                    forwarding_table_snapshot(&switch, table),
                    before,
                    "{context}: {table}"
                );
            }
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_underlay_narrow_failure_restores_group() {
        let members = membership_members();
        for replacement in [None, Some(rear_member(3, Direction::External))] {
            let context = format!("replacement={replacement:?}");
            let narrow_call = 1 + u64::from(replacement.is_some());
            let mut new_members = members[..2].to_vec();
            new_members.extend(replacement);
            let (switch, logs) = chaos_switch(Config::default());
            create_membership_group(&switch, &members);

            let external_id = membership_group_id(&switch, Direction::External);
            let bitmap_before = bitmap_entry(&switch, external_id);
            let repl_before =
                forwarding_table_snapshot(&switch, TableType::McastIpv6);
            let repl_updates = table_usage(&switch, TableType::McastIpv6).3;
            let group_before = {
                let groups = switch.mcast.lock().unwrap();
                format!(
                    "{:?}",
                    groups.groups[&GroupKey::underlay(membership_group_ip())]
                )
            };

            switch.asic_hdl.inject_table_faults(
                TableType::McastEgressDecapPorts,
                TableOp::EntryUpdate,
                CallRange::nth(narrow_call),
                AsicError::Synthetic,
            );
            let err = put_membership(&switch, &new_members).unwrap_err();
            assert!(
                matches!(
                    &err,
                    DpdError::Switch(AsicError::Synthetic(op))
                        if op == "table_entry_update"
                ),
                "{context}: {err:?}"
            );
            switch.asic_hdl.clear_table_faults(
                TableType::McastEgressDecapPorts,
                TableOp::EntryUpdate,
            );

            assert_eq!(
                bitmap_entry(&switch, external_id),
                bitmap_before,
                "{context}"
            );
            assert_eq!(
                forwarding_table_snapshot(&switch, TableType::McastIpv6),
                repl_before,
                "{context}"
            );
            assert_eq!(
                table_usage(&switch, TableType::McastIpv6).3,
                repl_updates + 2,
                "{context}"
            );
            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &members),
                "{context}"
            );
            let groups = switch.mcast.lock().unwrap();
            let key = GroupKey::underlay(membership_group_ip());
            assert_eq!(
                format!("{:?}", groups.groups[&key]),
                group_before,
                "{context}"
            );
            assert!(!groups.pending_repairs.contains(&key), "{context}");
            assert!(logs.entries.lock().unwrap().is_empty(), "{context}");
        }
    }

    #[test]
    fn test_underlay_rollback_keeps_decap() {
        #[derive(Clone, Copy, Debug)]
        enum RestoreFailure {
            Bitmap,
            Ports,
            Replication,
        }

        for (narrow_applied, failure) in [
            (false, RestoreFailure::Replication),
            (true, RestoreFailure::Replication),
            (true, RestoreFailure::Ports),
            (true, RestoreFailure::Bitmap),
        ] {
            let context =
                format!("narrow_applied={narrow_applied}, failure={failure:?}");
            let [removed, underlay, added] = membership_members();
            let members = [removed, underlay.clone()];
            let new_members = [underlay, added];
            let (switch, logs) = chaos_switch(Config::default());
            create_membership_group(&switch, &members);
            let original = switch.mcast.lock().unwrap().groups
                [&GroupKey::underlay(membership_group_ip())]
                .clone();
            let repl = original.replication_info().unwrap();
            let external_id = original.external_group_id();
            let union_bitmap = create_port_bitmap(
                members.iter().chain(&new_members),
                Direction::External,
            );
            let new_bitmap =
                create_port_bitmap(&new_members, Direction::External);

            table::mcast::mcast_egress::set_bitmap_entry(
                &switch,
                external_id,
                &union_bitmap,
                None,
            )
            .unwrap();
            let mut added_ports = Vec::new();
            let mut removed_ports = Vec::new();
            process_membership_changes(
                &switch,
                &new_members,
                &original,
                repl,
                &mut added_ports,
                &mut removed_ports,
            )
            .unwrap();

            set_replication_entry(&switch, &original, repl).unwrap();
            if narrow_applied {
                table::mcast::mcast_egress::set_bitmap_entry(
                    &switch,
                    external_id,
                    &new_bitmap,
                    None,
                )
                .unwrap();
            }

            let repl_before = table_usage(&switch, TableType::McastIpv6);
            let (op, failed_call) = match failure {
                RestoreFailure::Bitmap => {
                    switch.asic_hdl.inject_table_faults(
                        TableType::McastEgressDecapPorts,
                        TableOp::EntryUpdate,
                        CallRange::nth(1),
                        AsicError::Synthetic,
                    );
                    ("restore decap bitmap", "table_entry_update")
                }
                RestoreFailure::Ports => {
                    switch.asic_hdl.inject_mc_faults(
                        McOp::McPortRemove,
                        CallRange::nth(1),
                    );
                    ("port changes", "mc_port_remove")
                }
                RestoreFailure::Replication => {
                    switch.asic_hdl.inject_table_faults(
                        TableType::McastIpv6,
                        TableOp::EntryUpdate,
                        CallRange::nth(1),
                        AsicError::Synthetic,
                    );
                    ("restore replication settings", "table_entry_update")
                }
            };

            let err = GroupUpdateRollbackContext::new(&switch, &original, None)
                .rollback_underlay_and_restore(
                    DpdError::Switch(AsicError::Synthetic(
                        "table_entry_update".to_string(),
                    )),
                    repl,
                    &added_ports,
                    &removed_ports,
                );
            let DpdError::Unwind { initial, unwind } = &err else {
                panic!("{context}: expected a failed unwind: {err:?}");
            };
            assert!(
                matches!(
                    initial.as_ref(),
                    DpdError::Switch(AsicError::Synthetic(op))
                        if op == "table_entry_update"
                ),
                "{context}: {err:?}"
            );
            assert_eq!(unwind.len(), 1, "{context}: {err:?}");
            assert!(
                matches!(
                    &unwind.head,
                    DpdError::Switch(AsicError::Synthetic(op))
                        if op == failed_call
                ),
                "{context}: {err:?}"
            );

            let expected_bitmap = match failure {
                RestoreFailure::Bitmap => new_bitmap,
                _ => union_bitmap.clone(),
            };
            assert_eq!(
                bitmap_entry(&switch, external_id),
                Some((expected_bitmap, None)),
                "{context}"
            );
            let expected_members: Vec<_> = match failure {
                RestoreFailure::Bitmap => new_members[..1].to_vec(),
                RestoreFailure::Ports => {
                    members.iter().chain(&new_members[1..]).cloned().collect()
                }
                RestoreFailure::Replication => members.to_vec(),
            };
            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &expected_members),
                "{context}"
            );
            let repl_updates =
                u64::from(matches!(failure, RestoreFailure::Ports));
            assert_eq!(
                table_usage(&switch, TableType::McastIpv6),
                (
                    repl_before.0,
                    repl_before.1,
                    repl_before.2,
                    repl_before.3 + repl_updates,
                ),
                "{context}"
            );
            {
                let errors = logs.entries.lock().unwrap();
                assert_eq!(errors.len(), 1, "{context}: {errors:?}");
                assert_eq!(errors[0]["operation"], op, "{context}");
                assert!(
                    errors[0]["error"].contains(failed_call),
                    "{context}: {errors:?}"
                );
            }

            let mut pending = original.clone();
            let GroupKind::Underlay { replication, .. } = &mut pending.kind
            else {
                panic!("expected an underlay group");
            };
            replication.add_members(repl.clone(), &new_members);
            switch.asic_hdl.inject_table_faults(
                TableType::McastIpv6,
                TableOp::EntryUpdate,
                CallRange::nth(1),
                AsicError::Synthetic,
            );
            assert!(
                resync_after_failed_unwind(&switch, &pending, None).is_none(),
                "{context}"
            );
            assert_eq!(
                bitmap_entry(&switch, external_id),
                Some((union_bitmap, None)),
                "{context}"
            );
        }
    }

    #[test]
    fn test_underlay_write_removes_member_left_by_failed_unwind() {
        let [kept_member, added_member, failing_member] = membership_members();
        let init_members = [kept_member.clone()];
        let tgt_members =
            [kept_member.clone(), added_member.clone(), failing_member];

        let (switch, logs) = chaos_switch(Config::default());
        create_membership_group(&switch, &init_members);
        let domains = switch.asic_hdl.mc_domains();

        switch.asic_hdl.inject_mc_faults(
            McOp::McPortAdd,
            CallRange::nth(tgt_members.len() as u64),
        );
        switch.asic_hdl.inject_mc_faults(McOp::McPortRemove, CallRange::nth(1));
        let err = put_membership(&switch, &tgt_members).unwrap_err();
        let DpdError::Unwind { initial, unwind } = &err else {
            panic!("expected a failed unwind: {err:?}");
        };
        assert!(is_synthetic(initial, McOp::McPortAdd), "{err:?}");
        assert_eq!(unwind.len(), 1, "{err:?}");
        assert!(is_synthetic(&unwind.head, McOp::McPortRemove), "{err:?}");

        let asic_members = vec![kept_member.clone(), added_member];
        assert_eq!(stored_membership(&switch), asic_members);
        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, &asic_members)
        );
        assert_eq!(switch.asic_hdl.mc_domains(), domains);

        {
            let errs = logs.entries.lock().unwrap();
            assert_eq!(errs.len(), 1, "{errs:?}");
            assert_eq!(errs[0]["operation"], "port changes");
            assert!(errs[0]["error"].contains("mc_port_remove"), "{errs:?}");
        }
        assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());

        let response =
            put_membership(&switch, std::slice::from_ref(&kept_member))
                .unwrap();
        assert_eq!(response.members, vec![kept_member.clone()]);
        assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());

        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, std::slice::from_ref(&kept_member))
        );
        assert_eq!(stored_membership(&switch), vec![kept_member]);
        assert_eq!(switch.asic_hdl.mc_domains(), domains);
        assert_eq!(logs.entries.lock().unwrap().len(), 1);
    }

    fn assert_failed_resync_cleared_group(switch: &Switch) {
        assert!(
            matches!(
                get_group_underlay(switch, membership_group_ip()),
                Err(DpdError::Missing(_))
            ),
            "group was kept after a failed resync"
        );
        assert!(switch.asic_hdl.mc_domains().is_empty());
        for table_type in [
            TableType::McastIpv6,
            TableType::McastEgressDecapPorts,
            TableType::RouteIpv6Mcast,
        ] {
            assert_eq!(table_usage(switch, table_type).0, 0, "{table_type}");
        }
        assert!(
            route_action(switch, IpAddr::from(membership_group_ip())).is_none()
        );
    }

    fn assert_recreate_programs_exact_members(
        switch: &Switch,
        members: &[MulticastGroupMember],
    ) {
        create_membership_group(switch, members);

        assert_eq!(
            stored_membership(switch).into_iter().collect::<HashSet<_>>(),
            members.iter().cloned().collect::<HashSet<_>>()
        );
        assert_eq!(
            asic_membership(switch),
            expected_membership(switch, members)
        );
        assert_eq!(switch.asic_hdl.mc_domains().len(), 2);
        assert_eq!(
            bitmap_entry(
                switch,
                membership_group_id(switch, Direction::External)
            ),
            Some((create_port_bitmap(members, Direction::External), None))
        );
        for table_type in [TableType::McastIpv6, TableType::RouteIpv6Mcast] {
            assert_eq!(table_usage(switch, table_type).0, 1, "{table_type}");
        }
    }

    fn clear_membership_faults(switch: &Switch) {
        for op in [McOp::McPortAdd, McOp::McPortRemove, McOp::McPortList] {
            switch.asic_hdl.clear_mc_faults(op);
        }
    }

    #[test]
    fn test_underlay_unobservable_unwind_clears_group() {
        let [kept_member, added_member, failing_member] = membership_members();
        let init_members = [kept_member.clone()];
        let tgt_members = [kept_member, added_member, failing_member];

        for readback_fails in [false, true] {
            let context = if readback_fails { "readback" } else { "mapping" };
            let (switch, logs) = chaos_switch(Config::default());
            create_membership_group(&switch, &init_members);
            if readback_fails {
                switch
                    .asic_hdl
                    .inject_mc_faults(McOp::McPortList, CallRange::nth(1));
            } else {
                assert!(switch.asic_id_to_port_link(AsicId::MAX).is_err());
                let info = MulticastReplicationInfo::new(membership_group_id(
                    &switch,
                    Direction::External,
                ));
                switch
                    .asic_hdl
                    .mc_port_add(
                        membership_group_id(&switch, Direction::Underlay),
                        AsicId::MAX,
                        info.rid,
                        info.level1_excl_id,
                    )
                    .unwrap();
            }

            switch.asic_hdl.inject_mc_faults(
                McOp::McPortAdd,
                CallRange::nth(tgt_members.len() as u64),
            );
            switch
                .asic_hdl
                .inject_mc_faults(McOp::McPortRemove, CallRange::nth(1));
            let err = put_membership(&switch, &tgt_members).unwrap_err();
            let DpdError::Unwind { initial, unwind } = &err else {
                panic!("{context}: expected a failed unwind: {err:?}");
            };
            assert!(
                is_synthetic(initial, McOp::McPortAdd),
                "{context}: {err:?}"
            );
            assert_eq!(unwind.len(), 1, "{context}: {err:?}");
            assert!(
                is_synthetic(&unwind.head, McOp::McPortRemove),
                "{context}: {err:?}"
            );

            clear_membership_faults(&switch);
            assert_failed_resync_cleared_group(&switch);
            assert_eq!(logs.entries.lock().unwrap().len(), 1, "{context}");

            assert_recreate_programs_exact_members(&switch, &tgt_members);
            assert_eq!(logs.entries.lock().unwrap().len(), 1, "{context}");
        }
    }

    fn fail_unwind_to_empty_group(switch: &Switch) {
        switch.asic_hdl.inject_mc_faults(McOp::McPortList, CallRange::nth(1));
        switch.asic_hdl.inject_mc_faults(McOp::McPortAdd, CallRange::nth(1));
        let err = put_membership(switch, &[]).unwrap_err();
        let DpdError::Unwind { initial, unwind } = &err else {
            panic!("expected a failed unwind: {err:?}");
        };
        assert!(is_synthetic(initial, McOp::McPortList), "{err:?}");
        assert_eq!(unwind.len(), 1, "{err:?}");
        assert!(is_synthetic(&unwind.head, McOp::McPortAdd), "{err:?}");
        assert_eq!(asic_membership(switch), [Vec::<AsicId>::new(), Vec::new()]);
    }

    fn failed_unwind_leaves_empty_group() -> (Switch, RollbackLog) {
        let [kept_member, _, _] = membership_members();
        let (switch, logs) = chaos_switch(Config::default());
        create_membership_group(&switch, &[kept_member]);

        fail_unwind_to_empty_group(&switch);
        assert!(stored_membership(&switch).is_empty());
        for table_type in
            [TableType::McastIpv6, TableType::McastEgressDecapPorts]
        {
            assert_eq!(table_usage(&switch, table_type).0, 0, "{table_type}");
        }
        assert_eq!(table_usage(&switch, TableType::RouteIpv6Mcast).0, 1);
        assert_eq!(logs.entries.lock().unwrap().len(), 1);
        (switch, logs)
    }

    #[test]
    fn test_underlay_empty_update_clears_tables_after_failed_unwind() {
        let (switch, logs) = failed_unwind_leaves_empty_group();
        let domains = switch.asic_hdl.mc_domains();
        let group = switch.mcast.lock().unwrap().groups
            [&GroupKey::underlay(membership_group_ip())]
            .clone();

        for _ in 0..2 {
            table::mcast::mcast_egress::set_bitmap_entry(
                &switch,
                group.external_group_id(),
                &table::mcast::mcast_egress::PortBitmap::new(),
                None,
            )
            .unwrap();
            set_replication_entry(
                &switch,
                &group,
                &MulticastReplicationInfo::new(group.external_group_id()),
            )
            .unwrap();
            for table_type in
                [TableType::McastIpv6, TableType::McastEgressDecapPorts]
            {
                assert_eq!(table_usage(&switch, table_type).0, 1);
            }

            let response = put_membership(&switch, &[]).unwrap();
            assert!(response.members.is_empty());
            assert!(stored_membership(&switch).is_empty());
            assert_eq!(
                asic_membership(&switch),
                [Vec::<AsicId>::new(), Vec::new()]
            );
            assert_eq!(switch.asic_hdl.mc_domains(), domains);
            for table_type in
                [TableType::McastIpv6, TableType::McastEgressDecapPorts]
            {
                assert_eq!(
                    table_usage(&switch, table_type).0,
                    0,
                    "{table_type}"
                );
            }
            assert_eq!(table_usage(&switch, TableType::RouteIpv6Mcast).0, 1);
        }
        assert_eq!(logs.entries.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_underlay_empty_resync_cleanup_failure_keeps_old_entry() {
        let [kept_member, _, _] = membership_members();
        for failed_table in
            [TableType::McastIpv6, TableType::McastEgressDecapPorts]
        {
            let (switch, logs) = chaos_switch(Config::default());
            create_membership_group(
                &switch,
                std::slice::from_ref(&kept_member),
            );
            let domains = switch.asic_hdl.mc_domains();
            switch.asic_hdl.inject_table_faults(
                failed_table,
                TableOp::EntryDel,
                CallRange::starting_at(1),
                AsicError::Synthetic,
            );

            fail_unwind_to_empty_group(&switch);
            assert_eq!(stored_membership(&switch), vec![kept_member.clone()]);
            assert_eq!(switch.asic_hdl.mc_domains(), domains);
            assert_eq!(
                table_usage(&switch, TableType::McastIpv6).0,
                u32::from(failed_table == TableType::McastIpv6)
            );
            assert_eq!(
                table_usage(&switch, TableType::McastEgressDecapPorts).0,
                1
            );
            assert_eq!(logs.entries.lock().unwrap().len(), 1);

            assert_uncertain_reads(&switch);
            assert_eq!(stored_membership(&switch), vec![kept_member.clone()]);

            switch.asic_hdl.clear_table_faults(failed_table, TableOp::EntryDel);
            for read in read_memberships(&switch) {
                assert!(read.is_empty());
            }
            assert!(stored_membership(&switch).is_empty());
            assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
            for table_type in
                [TableType::McastIpv6, TableType::McastEgressDecapPorts]
            {
                assert_eq!(
                    table_usage(&switch, table_type).0,
                    0,
                    "{table_type}"
                );
            }
            assert_eq!(logs.entries.lock().unwrap().len(), 1);
        }
    }

    fn external_member_put_with_failed_unwind(
        init_members: &[MulticastGroupMember],
        tgt_members: &[MulticastGroupMember],
        update_failures: CallRange,
        before_put: impl FnOnce(&Switch),
    ) -> (Switch, RollbackLog) {
        let (switch, logs) = chaos_switch(Config::default());
        create_membership_group(&switch, init_members);
        before_put(&switch);
        switch.asic_hdl.inject_table_faults(
            TableType::McastIpv6,
            TableOp::EntryUpdate,
            update_failures,
            AsicError::Synthetic,
        );
        let removals = init_members
            .iter()
            .filter(|member| !tgt_members.contains(member))
            .count() as u64;
        switch
            .asic_hdl
            .inject_mc_faults(McOp::McPortRemove, CallRange::nth(removals + 1));

        let err = put_membership(&switch, tgt_members).unwrap_err();
        let DpdError::Unwind { initial, unwind } = &err else {
            panic!("expected a failed unwind: {err:?}");
        };
        assert!(
            matches!(
                initial.as_ref(),
                DpdError::Switch(AsicError::Synthetic(op))
                    if op == "table_entry_update"
            ),
            "{err:?}"
        );
        assert!(is_synthetic(&unwind.head, McOp::McPortRemove), "{err:?}");

        (switch, logs)
    }

    fn extending_members()
    -> (Vec<MulticastGroupMember>, Vec<MulticastGroupMember>) {
        let [a, _, c] = membership_members();
        (vec![a.clone()], vec![a, c])
    }

    fn replacing_members()
    -> (Vec<MulticastGroupMember>, Vec<MulticastGroupMember>) {
        let [a, b, c] = membership_members();
        (vec![a, b.clone()], vec![b, c])
    }

    #[test]
    fn test_underlay_failed_unwind_reprograms_bitmap_from_asic_members() {
        let (init_members, tgt_members) = extending_members();
        let (switch, logs) = external_member_put_with_failed_unwind(
            &init_members,
            &tgt_members,
            CallRange::nth(1),
            |_| {},
        );
        let external_id = membership_group_id(&switch, Direction::External);

        let stored = stored_membership(&switch);
        assert_eq!(
            stored.iter().cloned().collect::<HashSet<_>>(),
            tgt_members.iter().cloned().collect::<HashSet<_>>()
        );
        assert_eq!(
            expected_membership(&switch, &stored),
            asic_membership(&switch)
        );
        assert_eq!(
            bitmap_entry(&switch, external_id),
            Some((create_port_bitmap(&stored, Direction::External), None))
        );
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);
        assert_eq!(table_usage(&switch, TableType::RouteIpv6Mcast).0, 1);
        assert_eq!(logs.entries.lock().unwrap().len(), 1);
    }

    fn clear_external_member_put_faults(switch: &Switch) {
        switch
            .asic_hdl
            .clear_table_faults(TableType::McastIpv6, TableOp::EntryUpdate);
        clear_membership_faults(switch);
    }

    #[test]
    fn test_underlay_failed_unwind_reprogram_failure_clears_group() {
        let (init_members, tgt_members) = extending_members();
        let (switch, logs) = external_member_put_with_failed_unwind(
            &init_members,
            &tgt_members,
            CallRange::starting_at(1),
            |_| {},
        );

        clear_external_member_put_faults(&switch);
        assert_failed_resync_cleared_group(&switch);
        assert_eq!(logs.entries.lock().unwrap().len(), 2);

        assert_recreate_programs_exact_members(&switch, &tgt_members);
        assert_eq!(logs.entries.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_underlay_failed_unwind_referenced_group_stores_member_union() {
        let external_ip: IpAddr = "239.1.2.3".parse().unwrap();
        let (init_members, tgt_members) = replacing_members();
        let (switch, logs) = external_member_put_with_failed_unwind(
            &init_members,
            &tgt_members,
            CallRange::starting_at(1),
            |switch| {
                add_group_external(
                    switch,
                    external_entry(
                        external_ip,
                        "external-failed-resync-test",
                        external_nat_target(external_ip, membership_group_ip()),
                        None,
                        serde_json::Value::Null,
                    ),
                )
                .unwrap();
            },
        );

        clear_external_member_put_faults(&switch);
        let union = membership_members().to_vec();
        assert_eq!(stored_membership(&switch), union);
        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, &union)
        );
        assert_eq!(switch.asic_hdl.mc_domains().len(), 2);
        assert!(route_action(&switch, membership_group_ip().into()).is_some());
        assert_eq!(logs.entries.lock().unwrap().len(), 2);

        get_group(&switch, external_ip).unwrap();
        assert!(route_action(&switch, external_ip).is_some());
        let groups = switch.mcast.lock().unwrap();
        assert_eq!(
            groups
                .nat_target_refs
                .get(&membership_group_ip())
                .map(|key| key.ip()),
            Some(external_ip)
        );
    }

    #[test]
    fn test_underlay_failed_unwind_teardown_failure_stores_member_union() {
        for group_destroy_fails in [true, false] {
            let (init_members, tgt_members) = replacing_members();
            let (switch, logs) = external_member_put_with_failed_unwind(
                &init_members,
                &tgt_members,
                CallRange::starting_at(1),
                |switch| {
                    if group_destroy_fails {
                        switch.asic_hdl.inject_mc_faults(
                            McOp::McGroupDestroy,
                            CallRange::nth(1),
                        );
                    } else {
                        switch.asic_hdl.inject_table_faults(
                            TableType::RouteIpv6Mcast,
                            TableOp::EntryDel,
                            CallRange::nth(1),
                            AsicError::Synthetic,
                        );
                    }
                },
            );

            clear_external_member_put_faults(&switch);
            switch.asic_hdl.clear_mc_faults(McOp::McGroupDestroy);
            switch.asic_hdl.clear_table_faults(
                TableType::RouteIpv6Mcast,
                TableOp::EntryDel,
            );

            assert_eq!(
                stored_membership(&switch),
                membership_members().to_vec()
            );
            assert_eq!(
                switch.asic_hdl.mc_domains().len(),
                if group_destroy_fails { 1 } else { 2 }
            );
            assert_eq!(
                table_usage(&switch, TableType::RouteIpv6Mcast).0,
                u32::from(!group_destroy_fails)
            );
            assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 0);
            assert_eq!(logs.entries.lock().unwrap().len(), 2);

            del_group(
                &switch,
                membership_group_ip().into(),
                MEMBERSHIP_TEST_TAG,
            )
            .unwrap();
            assert_failed_resync_cleared_group(&switch);
            assert_recreate_programs_exact_members(&switch, &tgt_members);
            assert_eq!(logs.entries.lock().unwrap().len(), 2);
        }
    }

    #[test]
    fn test_underlay_empty_unwind_repair() {
        let [kept_member, _, _] = membership_members();
        let tgt_members = [kept_member];

        let (switch, logs) = chaos_switch(Config::default());
        create_membership_group(&switch, &[]);
        let external_id = membership_group_id(&switch, Direction::External);
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 0);

        switch.asic_hdl.inject_table_faults(
            TableType::McastIpv6,
            TableOp::EntryAdd,
            CallRange::nth(1),
            AsicError::Synthetic,
        );
        switch.asic_hdl.inject_mc_faults(McOp::McPortRemove, CallRange::nth(1));
        let err = put_membership(&switch, &tgt_members).unwrap_err();

        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, &tgt_members),
        );
        assert_eq!(stored_membership(&switch), tgt_members.to_vec());
        assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());
        assert_eq!(table_usage(&switch, TableType::McastIpv6).0, 1);
        assert_eq!(
            bitmap_entry(&switch, external_id),
            Some((create_port_bitmap(&tgt_members, Direction::External), None)),
        );
        assert_eq!(logs.entries.lock().unwrap().len(), 1);

        let DpdError::Unwind { initial, unwind } = &err else {
            panic!("expected a failed unwind: {err:?}");
        };
        assert!(
            matches!(
                initial.as_ref(),
                DpdError::Switch(AsicError::Synthetic(op))
                    if op == "table_entry_add"
            ),
            "{err:?}"
        );
        assert!(is_synthetic(&unwind.head, McOp::McPortRemove), "{err:?}");
    }

    #[test]
    fn test_underlay_empty_update_removes_unwanted_members() {
        let [kept_member, added_member, failing_member] = membership_members();
        for init_members in [Vec::new(), vec![kept_member.clone()]] {
            let (switch, logs) = chaos_switch(Config::default());
            create_membership_group(&switch, &init_members);
            for unwanted_member in [&added_member, &failing_member] {
                add_unwanted_member(&switch, unwanted_member);
            }
            let domains = switch.asic_hdl.mc_domains();
            assert_ne!(
                asic_membership(&switch),
                expected_membership(&switch, &init_members)
            );

            let response = put_membership(&switch, &[]).unwrap();
            assert!(response.members.is_empty());

            assert_eq!(
                asic_membership(&switch),
                [Vec::<AsicId>::new(), Vec::new()]
            );
            assert!(stored_membership(&switch).is_empty());
            assert_eq!(switch.asic_hdl.mc_domains(), domains);
            for table_type in
                [TableType::McastIpv6, TableType::McastEgressDecapPorts]
            {
                assert_eq!(
                    table_usage(&switch, table_type).0,
                    0,
                    "{table_type}"
                );
            }
            assert!(logs.entries.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn test_underlay_update_fails_when_unwanted_member_remains() {
        let [kept_member, added_member, _] = membership_members();
        for members in [Vec::new(), vec![kept_member.clone()]] {
            let (switch, logs) = chaos_switch(Config::default());
            create_membership_group(&switch, &members);
            add_unwanted_member(&switch, &added_member);
            let mut with_unwanted_member = members.clone();
            with_unwanted_member.push(added_member.clone());

            switch
                .asic_hdl
                .inject_mc_faults(McOp::McPortRemove, CallRange::nth(1));
            let err = put_membership(&switch, &members).unwrap_err();
            assert!(is_synthetic(&err, McOp::McPortRemove), "{err:?}");

            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &with_unwanted_member)
            );
            assert_eq!(stored_membership(&switch), members);
            assert!(logs.entries.lock().unwrap().is_empty());
            assert!(
                switch
                    .mcast
                    .lock()
                    .unwrap()
                    .pending_repairs
                    .contains(&GroupKey::underlay(membership_group_ip()))
            );

            switch
                .asic_hdl
                .inject_mc_faults(McOp::McPortList, CallRange::starting_at(1));
            let read = get_group_underlay(&switch, membership_group_ip());
            assert!(
                matches!(read, Err(DpdError::McastRepairPending(_))),
                "{read:?}"
            );

            switch.asic_hdl.clear_mc_faults(McOp::McPortList);
            let read = get_group_underlay(&switch, membership_group_ip())
                .unwrap()
                .members
                .into_iter()
                .collect::<HashSet<_>>();
            assert_eq!(
                read,
                with_unwanted_member.iter().cloned().collect::<HashSet<_>>()
            );
            assert!(switch.mcast.lock().unwrap().pending_repairs.is_empty());

            put_membership(&switch, &members).unwrap();
            assert_eq!(
                asic_membership(&switch),
                expected_membership(&switch, &members)
            );
        }
    }

    #[test]
    fn test_underlay_unchanged_update_with_full_replication_table() {
        let [kept_member, added_member, _] = membership_members();
        let members = vec![kept_member, added_member];
        let (switch, logs) = chaos_switch(Config::default());
        create_membership_group(&switch, &members);

        let before = table_usage(&switch, TableType::McastIpv6);
        assert_eq!(before.0, 1);
        {
            let mut repl = switch.table_get(TableType::McastIpv6).unwrap();
            repl.usage.size = repl.usage.occupancy;
        }

        let response = put_membership(&switch, &members).unwrap();
        assert_eq!(response.members, members);

        assert_eq!(
            table_usage(&switch, TableType::McastIpv6),
            (before.0, before.1, before.2, before.3 + 1)
        );
        assert_eq!(
            asic_membership(&switch),
            expected_membership(&switch, &members)
        );
        assert!(logs.entries.lock().unwrap().is_empty());
    }
}
