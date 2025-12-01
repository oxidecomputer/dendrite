// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Multicast group management and configuration.
//!
//! This is the entrypoint for managing multicast groups, including creating,
//! modifying, and deleting groups.
//!
//! ## Overview
//!
//! There are two types of multicast groups:
//! - **External (Overlay) groups**: Entry points for overlay traffic,
//!   have NAT targets, VLAN IDs, and no direct members. External groups
//!   reference internal groups via NAT targets to perform the
//!   actual packet replication and forwarding.
//!
//! - **Internal (Underlay) groups**: Handle actual packet replication to
//!   members, containing ALL members (either direction - overlay or
//!   underlay).
//!
//! ### Member Directions
//!
//! Internal groups contain members with two traffic directions:
//! - **External direction**: Members in overlay networks (customer networks),
//!   which receive decapsulated packets with (possible) VLAN tags on multicast
//!   egress.
//!
//! - **Underlay direction**: Members in underlay networks
//!   (rack infrastructure, instances), which receive encapsulated Geneve
//!   packets on multicast egress.
//!
//! ### Bifurcated Multicast Design:
//!
//! The multicast implementation uses a bifurcated design that separates
//! external (customer) and (internal) underlay traffic:
//!
//! 1. External-only groups (IPv4 and non-admin-local IPv6):
//!    - Created from API control plane IPs for customer traffic
//!    - Handle customer traffic to/from outside the rack
//!    - Use the external multicast API (/multicast/external-groups)
//!    - Must have NAT targets pointing to internal groups for proper forwarding
//!
//! 2. Internal groups (admin-local IPv6 multicast):
//!    - Admin-local = scope 4 (ff04::/16) as defined in
//!      [RFC 7346] and [RFC 4291]
//!    - Geneve encapsulated multicast traffic (NAT targets of external-only groups)
//!    - Use the internal multicast API (/multicast/underlay-groups)
//!    - Can replicate to:
//!      a) External group members (customer traffic)
//!      b) Underlay-only members (infrastructure traffic)
//!      c) Both external and underlay members (bifurcated replication)
//!
//! [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346.html
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html

use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Bound,
    sync::{Arc, Mutex, Weak},
};

use aal::{AsicError, AsicOps};
use common::{nat::NatTarget, ports::PortId};
use dpd_types::{
    link::LinkId,
    mcast::{
        AdminScopedIpv6, Direction, ExternalForwarding, InternalForwarding,
        IpSrc, MulticastGroupCreateExternalEntry,
        MulticastGroupCreateUnderlayEntry, MulticastGroupExternalResponse,
        MulticastGroupId, MulticastGroupMember, MulticastGroupResponse,
        MulticastGroupUnderlayResponse, MulticastGroupUpdateExternalEntry,
        MulticastGroupUpdateUnderlayEntry,
    },
};
use oxnet::Ipv4Net;
use slog::{debug, error, warn};

use crate::{
    Switch, table,
    types::{DpdError, DpdResult},
};

mod rollback;
mod validate;

use rollback::{GroupCreateRollbackContext, GroupUpdateRollbackContext};
use validate::{
    validate_multicast_address, validate_nat_target,
    validate_not_admin_local_ipv6,
};

#[derive(Debug)]
struct ScopedIdInner(MulticastGroupId, Weak<Mutex<Vec<MulticastGroupId>>>);

impl Drop for ScopedIdInner {
    /// Only return to free pool if not taken and if the free pool still
    /// exists.
    fn drop(&mut self) {
        if self.0 != 0
            && let Some(free_ids) = self.1.upgrade()
            && let Ok(mut pool) = free_ids.lock()
        {
            pool.push(self.0);
        }
    }
}

/// Wrapper for multicast group IDs during allocation that automatically
/// returns them to the free pool when dropped. This prevents group ID leaks
/// when operations fail during group creation.
#[derive(Clone, Debug)]
struct ScopedGroupId(Arc<ScopedIdInner>);

impl ScopedGroupId {
    /// Get the underlying group ID value.
    fn id(&self) -> MulticastGroupId {
        self.0.0
    }
}

impl From<ScopedIdInner> for ScopedGroupId {
    fn from(value: ScopedIdInner) -> Self {
        Self(value.into())
    }
}

/// Multicast replication configuration (internal only).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MulticastReplicationInfo {
    rid: u16,
    level1_excl_id: u16,
    level2_excl_id: u16,
}

/// Represents a multicast group configuration.
///
/// This structure is used to manage multicast groups, including their
/// replication information, forwarding settings, and associated members.
#[derive(Clone, Debug)]
pub(crate) struct MulticastGroup {
    external_scoped_group: ScopedGroupId,
    underlay_scoped_group: ScopedGroupId,
    pub(crate) tag: Option<String>,
    pub(crate) int_fwding: InternalForwarding,
    pub(crate) ext_fwding: ExternalForwarding,
    pub(crate) sources: Option<Vec<IpSrc>>,
    replication_info: Option<MulticastReplicationInfo>,
    pub(crate) members: Vec<MulticastGroupMember>,
}

impl MulticastGroup {
    fn external_group_id(&self) -> MulticastGroupId {
        self.external_scoped_group.id()
    }

    fn underlay_group_id(&self) -> MulticastGroupId {
        self.underlay_scoped_group.id()
    }

    fn external_scoped_group_id(&self) -> &ScopedGroupId {
        &self.external_scoped_group
    }

    fn underlay_scoped_group_id(&self) -> &ScopedGroupId {
        &self.underlay_scoped_group
    }

    fn to_external_response(
        &self,
        group_ip: IpAddr,
    ) -> MulticastGroupExternalResponse {
        MulticastGroupExternalResponse {
            group_ip,
            external_group_id: self.external_group_id(),
            tag: self.tag.clone(),
            internal_forwarding: self.int_fwding.clone(),
            external_forwarding: self.ext_fwding.clone(),
            sources: self.sources.clone(),
        }
    }

    fn to_underlay_response(
        &self,
        group_ip: AdminScopedIpv6,
    ) -> MulticastGroupUnderlayResponse {
        MulticastGroupUnderlayResponse {
            group_ip,
            external_group_id: self.external_group_id(),
            underlay_group_id: self.underlay_group_id(),
            tag: self.tag.clone(),
            members: self.members.clone(),
        }
    }

    fn to_response(&self, group_ip: IpAddr) -> MulticastGroupResponse {
        match group_ip {
            IpAddr::V4(_) => MulticastGroupResponse::External(
                self.to_external_response(group_ip),
            ),
            IpAddr::V6(ipv6) => {
                // Try to create AdminScopedIpv6 - if successful, it's an underlay group
                match AdminScopedIpv6::new(ipv6) {
                    Ok(admin_scoped) => MulticastGroupResponse::Underlay(
                        self.to_underlay_response(admin_scoped),
                    ),
                    Err(_) => MulticastGroupResponse::External(
                        self.to_external_response(group_ip),
                    ),
                }
            }
        }
    }
}

/// Stores multicast group configurations.
#[derive(Debug)]
pub struct MulticastGroupData {
    /// Multicast group configurations keyed by group IP.
    groups: BTreeMap<IpAddr, MulticastGroup>,
    /// Stack of available group IDs for O(1) allocation.
    /// Pre-populated with all IDs from GENERATOR_START to u16::MAX-1.
    free_group_ids: Arc<Mutex<Vec<MulticastGroupId>>>,
    /// 1:1 mapping from admin-local group IP to external group that uses it as NAT
    /// target (admin_local_ip -> external_group_ip)
    nat_target_refs: BTreeMap<AdminScopedIpv6, IpAddr>,
}

impl MulticastGroupData {
    const GENERATOR_START: u16 = 100;

    /// Creates a new instance of MulticastGroupData with pre-populated free
    /// group IDs.
    pub(crate) fn new() -> Self {
        // Pre-populate with all available IDs from GENERATOR_START to u16::MAX-1
        // Using a Vec as a stack for O(1) push/pop operations
        let free_group_ids = Arc::new(Mutex::new(
            (Self::GENERATOR_START..MulticastGroupId::MAX).collect(),
        ));

        Self {
            groups: BTreeMap::new(),
            free_group_ids,
            nat_target_refs: BTreeMap::new(),
        }
    }

    /// Generates a unique multicast group ID with automatic cleanup on drop.
    ///
    /// O(1) allocation from pre-populated free list. Never allocates.
    ///
    /// IDs below GENERATOR_START (100) to avoid conflicts with reserved ranges.
    ///
    /// Returns a ScopedGroupId that will automatically return the ID to the
    /// free pool when dropped.
    fn generate_group_id(&mut self) -> DpdResult<ScopedGroupId> {
        let mut pool = self.free_group_ids.lock().unwrap();
        let id = pool.pop().ok_or_else(|| {
            DpdError::McastGroupFailure(
                "no free multicast group IDs available (exhausted range 100-65534)".to_string(),
            )
        })?;

        Ok(ScopedIdInner(id, Arc::downgrade(&self.free_group_ids)).into())
    }

    /// Add 1:1 forwarding reference from admin-local IP to external group's IP.
    fn add_forwarding_refs(
        &mut self,
        external_group_ip: IpAddr,
        admin_scoped_ip: AdminScopedIpv6,
    ) {
        self.nat_target_refs
            .insert(admin_scoped_ip, external_group_ip);
    }

    /// Remove 1:1 forwarding reference.
    fn rm_forwarding_refs(&mut self, admin_scoped_ip: AdminScopedIpv6) {
        self.nat_target_refs.remove(&admin_scoped_ip);
    }

    /// Get the VLAN ID for an internal multicast group by looking up
    /// the referencing external group (1:1 mapping).
    fn get_vlan_for_internal_addr(
        &self,
        internal_ip: AdminScopedIpv6,
    ) -> Option<u16> {
        self.nat_target_refs
            .get(&internal_ip)
            .and_then(|external_ip| self.groups.get(external_ip))
            .and_then(|group| group.ext_fwding.vlan_id)
    }
}

impl Default for MulticastGroupData {
    fn default() -> Self {
        Self::new()
    }
}

/// Add an external multicast group to the switch, which creates the group on
/// the ASIC and associates it with a group IP address and updates associated
/// tables for NAT and L3 routing.
///
/// If anything fails, the group is cleaned up and an error is returned.
pub(crate) fn add_group_external(
    s: &Switch,
    group_info: MulticastGroupCreateExternalEntry,
) -> DpdResult<MulticastGroupExternalResponse> {
    let group_ip = group_info.group_ip;

    // Acquire the lock to the multicast data structure at the start to ensure
    // deterministic operation order
    let mut mcast = s.mcast.lock().unwrap();

    let nat_target =
        group_info.internal_forwarding.nat_target.ok_or_else(|| {
            DpdError::Invalid(
                "external groups must have NAT target".to_string(),
            )
        })?;

    validate_external_group_creation(&mcast, group_ip, &group_info)?;
    validate_nat_target(nat_target)?;

    // Validate that NAT target points to an existing group and get its IDs
    let internal_group_ip = nat_target.internal_ip.into();
    let internal_group =
        mcast.groups.get(&internal_group_ip).ok_or_else(|| {
            DpdError::Invalid(format!(
                "multicast group for IP address {group_ip} must have a NAT target \
                 that is also a tracked multicast group",
            ))
        })?;

    // Set IDs to match the internal group from the NAT target
    let scoped_external_id = internal_group.external_scoped_group.clone();
    let scoped_underlay_id = internal_group.underlay_scoped_group.clone();

    // Create rollback context once for reuse throughout this function
    let rollback_ctx = GroupCreateRollbackContext::new_external(
        s,
        group_ip,
        scoped_external_id.id(),
        scoped_underlay_id.id(),
        nat_target,
        group_info.sources.as_deref(),
    );

    // Configure external tables and handle VLAN propagation
    configure_external_tables(s, &group_info)
        .and_then(|_| {
            // Perform VLAN propagation if needed
            if let Some(vlan_id) = group_info.external_forwarding.vlan_id {
                perform_vlan_propagation(
                    s,
                    &mcast,
                    group_ip,
                    vlan_id,
                    nat_target.internal_ip.into(),
                )
            } else {
                Ok(())
            }
        })
        .map_err(|e| rollback_ctx.rollback_and_return_error(e))?;

    // Validate the admin-local IP early to avoid partial state
    let admin_local_ip = AdminScopedIpv6::new(nat_target.internal_ip)?;

    let group = MulticastGroup {
        external_scoped_group: scoped_external_id,
        underlay_scoped_group: scoped_underlay_id,
        tag: group_info.tag,
        int_fwding: group_info.internal_forwarding.clone(),
        ext_fwding: group_info.external_forwarding.clone(),
        sources: group_info.sources.clone(),
        replication_info: None,
        // External groups are entry points only - actual members reside in referenced internal groups
        members: Vec::new(),
    };

    mcast.groups.insert(group_ip, group.clone());
    mcast.add_forwarding_refs(group_ip, admin_local_ip);

    Ok(group.to_external_response(group_ip))
}

/// Add an internal multicast group to the switch, which creates the group on
/// the ASIC and associates it with a group IP address and updates associated
/// tables for multicast replication and L3 routing.
///
/// If anything fails, the group is cleaned up and an error is returned.
pub(crate) fn add_group_internal(
    s: &Switch,
    group_info: MulticastGroupCreateUnderlayEntry,
) -> DpdResult<MulticastGroupUnderlayResponse> {
    let group_ip = group_info.group_ip;

    // Acquire the lock to the multicast data structure at the start to ensure
    // deterministic operation order
    let mut mcast = s.mcast.lock().unwrap();

    validate_internal_group_creation(&mcast, group_ip)?;

    let (scoped_external_id, scoped_underlay_id) =
        allocate_multicast_group_ids(s, &mut mcast, group_ip.into())?;

    // Create rollback context for cleanup if operations fail
    let rollback_ctx = GroupCreateRollbackContext::new_internal(
        s,
        group_ip.into(),
        scoped_external_id.id(),
        scoped_underlay_id.id(),
    );

    // Get VLAN ID from referencing external groups
    let vlan_id = mcast.get_vlan_for_internal_addr(group_ip);
    let external_group_id = scoped_external_id.id();
    let underlay_group_id = scoped_underlay_id.id();
    let mut added_members = Vec::new();

    // Only configure replication if there are members
    let replication_info = if !group_info.members.is_empty() {
        let replication_info = configure_replication(external_group_id);

        add_ports_to_groups(
            s,
            group_ip.into(),
            &group_info.members,
            external_group_id,
            underlay_group_id,
            &replication_info,
            &mut added_members,
        )
        .map_err(|e| rollback_ctx.rollback_and_return_error(e))?;

        configure_internal_tables(
            s,
            group_ip.into(),
            external_group_id,
            underlay_group_id,
            Some(&replication_info),
            &added_members,
            vlan_id,
        )
        .map_err(|e| rollback_ctx.rollback_and_return_error(e))?;

        Some(replication_info)
    } else {
        // No members - configure minimal tables for empty group
        configure_internal_tables(
            s,
            group_ip.into(),
            external_group_id,
            underlay_group_id,
            None,
            &added_members,
            vlan_id,
        )
        .map_err(|e| rollback_ctx.rollback_and_return_error(e))?;

        None
    };

    // Generic internal datastructure (vs API interface)
    let group = MulticastGroup {
        external_scoped_group: scoped_external_id,
        underlay_scoped_group: scoped_underlay_id,
        tag: group_info.tag,
        int_fwding: InternalForwarding {
            nat_target: None, // Internal groups don't have NAT targets
        },
        ext_fwding: ExternalForwarding {
            vlan_id: None, // Internal groups don't have VLANs
        },
        sources: None, // Internal groups don't have sources
        replication_info,
        members: group_info.members,
    };

    mcast.groups.insert(group_ip.into(), group.clone());

    Ok(group.to_underlay_response(group_ip))
}

/// Delete a multicast group from the switch, including all associated tables
/// and port mappings.
pub(crate) fn del_group(s: &Switch, group_ip: IpAddr) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().unwrap();

    let group = mcast.groups.remove(&group_ip).ok_or_else(|| {
        DpdError::Missing(format!(
            "Multicast group for IP {group_ip} not found",
        ))
    })?;

    let nat_target_to_remove = group
        .int_fwding
        .nat_target
        .map(|nat| nat.internal_ip.into());

    debug!(s.log, "deleting multicast group for IP {group_ip}");

    delete_group_tables(s, group_ip, &group)?;

    // Only delete ASIC groups for internal groups (groups without NAT targets).
    // External groups share ASIC resources with their referenced internal groups.
    if group.int_fwding.nat_target.is_none() {
        delete_multicast_groups(
            s,
            group_ip,
            group.external_scoped_group_id().clone(),
            group.underlay_scoped_group_id().clone(),
        )?;
    }

    if let Some(IpAddr::V6(ipv6)) = nat_target_to_remove {
        mcast.rm_forwarding_refs(AdminScopedIpv6::new(ipv6)?);
    }

    Ok(())
}

/// Get an internal multicast group configuration by admin-local IPv6 address.
pub(crate) fn get_group_internal(
    s: &Switch,
    admin_local: AdminScopedIpv6,
) -> DpdResult<MulticastGroupUnderlayResponse> {
    let mcast = s.mcast.lock().unwrap();
    let group_ip = IpAddr::V6(admin_local.into());

    let group = mcast.groups.get(&group_ip).ok_or_else(|| {
        DpdError::Missing(format!(
            "internal multicast group for IP {group_ip} not found",
        ))
    })?;

    Ok(group.to_underlay_response(admin_local))
}

/// Get a multicast group configuration.
pub(crate) fn get_group(
    s: &Switch,
    group_ip: IpAddr,
) -> DpdResult<MulticastGroupResponse> {
    let mcast = s.mcast.lock().unwrap();

    let group = mcast.groups.get(&group_ip).ok_or_else(|| {
        DpdError::Missing(format!(
            "multicast group for IP {group_ip} not found",
        ))
    })?;

    Ok(group.to_response(group_ip))
}

pub(crate) fn modify_group_external(
    s: &Switch,
    group_ip: IpAddr,
    new_group_info: MulticastGroupUpdateExternalEntry,
) -> DpdResult<MulticastGroupExternalResponse> {
    let mut mcast = s.mcast.lock().unwrap();

    if !mcast.groups.contains_key(&group_ip) {
        return Err(DpdError::Missing(format!(
            "Multicast group for IP {group_ip} not found",
        )));
    }

    let nat_target =
        new_group_info
            .internal_forwarding
            .nat_target
            .ok_or_else(|| {
                DpdError::Invalid(
                    "external groups must have NAT target".to_string(),
                )
            })?;

    validate_multicast_address(group_ip, new_group_info.sources.as_deref())?;
    validate_nat_target(nat_target)?;

    let group_entry = mcast.groups.remove(&group_ip).unwrap();
    let old_nat_target = group_entry.int_fwding.nat_target;

    // Create rollback context for external group update
    let group_entry_for_rollback = group_entry.clone();
    let rollback_ctx =
        GroupUpdateRollbackContext::new(s, group_ip, &group_entry_for_rollback);

    // Try to update external tables first
    if let Err(e) =
        update_external_tables(s, group_ip, &group_entry, &new_group_info)
    {
        // Restore original group and return error
        mcast.groups.insert(group_ip, group_entry);
        return Err(rollback_ctx
            .rollback_external(e, new_group_info.sources.as_deref()));
    }

    let mut updated_group = group_entry.clone();

    // Update NAT target references if NAT target changed
    if let Some(old_nat) = old_nat_target {
        let old_internal_ip = old_nat.internal_ip;
        let new_internal_ip = nat_target.internal_ip;

        if old_internal_ip != new_internal_ip {
            mcast.rm_forwarding_refs(AdminScopedIpv6::new(old_internal_ip)?);
            mcast.add_forwarding_refs(
                group_ip,
                AdminScopedIpv6::new(new_internal_ip)?,
            );
        }
    }

    // Update the external group fields
    updated_group.tag = new_group_info.tag.or(updated_group.tag);
    updated_group.int_fwding.nat_target = Some(nat_target);

    let old_vlan_id = updated_group.ext_fwding.vlan_id;
    updated_group.ext_fwding.vlan_id = new_group_info
        .external_forwarding
        .vlan_id
        .or(updated_group.ext_fwding.vlan_id);
    updated_group.sources = new_group_info.sources.or(updated_group.sources);

    // Update bitmap tables with new VLAN if VLAN changed
    // Also, handles possible membership skew between update internal + external calls.
    if old_vlan_id != updated_group.ext_fwding.vlan_id {
        let internal_ip = nat_target.internal_ip.into();

        let bitmap_result = match mcast.groups.get(&internal_ip) {
            Some(internal_group)
                if internal_group.replication_info.is_some() =>
            {
                // Only update bitmap if internal group has replication
                let port_bitmap = create_port_bitmap(
                    &internal_group.members,
                    Direction::External,
                );

                // During external group update, bitmap entry exists - update it
                table::mcast::mcast_egress::update_bitmap_entry(
                    s,
                    internal_group.external_group_id(),
                    &port_bitmap,
                    updated_group.ext_fwding.vlan_id,
                )
            }
            Some(_) => Ok(()), // Internal group exists but has no replication
            None => Err(DpdError::Invalid(format!(
                "internal group not found when updating bitmap: internal_ip={internal_ip}, external_group={group_ip}",
            ))),
        };

        if let Err(e) = bitmap_result {
            // Rollback the external table changes and return the error
            mcast.groups.insert(group_ip, group_entry);

            error!(
                s.log,
                "failed to update bitmap table for external group {group_ip}: {e:?}"
            );
            return Err(rollback_ctx.rollback_and_restore(e));
        }
    }

    let response = updated_group.to_external_response(group_ip);
    mcast.groups.insert(group_ip, updated_group);
    Ok(response)
}

pub(crate) fn modify_group_internal(
    s: &Switch,
    group_ip: AdminScopedIpv6,
    new_group_info: MulticastGroupUpdateUnderlayEntry,
) -> DpdResult<MulticastGroupUnderlayResponse> {
    let mut mcast = s.mcast.lock().unwrap();

    if !mcast.groups.contains_key(&group_ip.into()) {
        return Err(DpdError::Missing(format!(
            "Multicast group for IP {group_ip} not found",
        )));
    }

    let mut group_entry = mcast.groups.remove(&group_ip.into()).unwrap();

    // Create rollback context for internal group update
    let group_entry_for_rollback = group_entry.clone();
    let rollback_ctx = GroupUpdateRollbackContext::new(
        s,
        group_ip.into(),
        &group_entry_for_rollback,
    );

    // Internal groups don't update sources - always `None`
    debug_assert!(
        group_entry.sources.is_none(),
        "Internal groups should not have sources"
    );
    let sources = None;

    // Configure replication based on member count transitions
    let replication_info = match (
        new_group_info.members.is_empty(),
        group_entry.replication_info.is_some(),
    ) {
        (true, true) => {
            // Transition from members to empty - cleanup tables
            cleanup_empty_group_replication(s, group_ip.into(), &group_entry)
                .map_err(|e| rollback_ctx.rollback_and_restore(e))?;
            // Immediately clear replication_info to maintain consistency
            group_entry.replication_info = None;
            None
        }
        (false, false) => {
            // Transition from empty to members - configure replication
            Some(configure_replication(group_entry.external_group_id()))
        }
        (false, true) => {
            // Already has members and replication - keep existing
            group_entry.replication_info.clone()
        }
        (true, false) => {
            // Already empty and no replication - keep none
            None
        }
    };

    // Early return for no-replication case - just update metadata
    if replication_info.is_none() {
        group_entry.tag = new_group_info.tag.or(group_entry.tag.clone());
        group_entry.sources = sources;
        group_entry.members = new_group_info.members;

        let response = group_entry.to_underlay_response(group_ip);
        mcast.groups.insert(group_ip.into(), group_entry);
        return Ok(response);
    }

    // Continue with replication processing
    let repl_info = replication_info.as_ref().unwrap();
    let (added_members, removed_members) = process_membership_changes(
        s,
        group_ip.into(),
        &new_group_info.members,
        &mut group_entry,
        repl_info,
    )
    .inspect_err(|_e| {
        // Restore group to mcast data structure
        mcast.groups.insert(group_ip.into(), group_entry.clone());
    })
    .map_err(|e| rollback_ctx.rollback_internal(e, &[], &[]))?;

    // Perform table updates
    update_group_tables(
        s,
        group_ip.into(),
        &group_entry,
        repl_info,
        &sources,
        &group_entry.sources,
    )
    .map_err(|e| {
        // Restore group to mcast data structure
        mcast.groups.insert(group_ip.into(), group_entry.clone());
        rollback_ctx.rollback_internal(e, &added_members, &removed_members)
    })?;

    let filter_by_direction =
        |members: &[MulticastGroupMember], direction: Direction| {
            members
                .iter()
                .filter(|m| m.direction == direction)
                .cloned()
                .collect::<Vec<_>>()
        };

    // Update bitmap tables if overlay members changed
    let old_external_members =
        filter_by_direction(&group_entry.members, Direction::External);
    let new_external_members =
        filter_by_direction(&new_group_info.members, Direction::External);

    if old_external_members != new_external_members {
        // VLAN mapping maintained via add_forwarding_refs/rm_forwarding_refs
        let external_group_vlan_id = mcast.get_vlan_for_internal_addr(group_ip);

        update_internal_group_bitmap_tables(
            s,
            group_entry.external_group_id(),
            &new_group_info.members,
            &group_entry.members,
            external_group_vlan_id,
        )
        .map_err(|e| {
            // Restore group to mcast data structure
            mcast.groups.insert(group_ip.into(), group_entry.clone());
            rollback_ctx.rollback_and_restore(e)
        })?;
    }

    // Update group metadata and return success
    group_entry.tag = new_group_info.tag.or(group_entry.tag.clone());
    group_entry.sources = sources;
    group_entry.replication_info = replication_info;
    group_entry.members = new_group_info.members;

    let response = group_entry.to_underlay_response(group_ip);
    mcast.groups.insert(group_ip.into(), group_entry.clone());

    Ok(response)
}

/// List all multicast groups over a range.
pub(crate) fn get_range(
    s: &Switch,
    last: Option<IpAddr>,
    limit: usize,
    tag: Option<&str>,
) -> Vec<MulticastGroupResponse> {
    let mcast = s.mcast.lock().unwrap();

    let lower_bound = match last {
        None => Bound::Unbounded,
        Some(last_ip) => Bound::Excluded(last_ip),
    };

    mcast
        .groups
        .range((lower_bound, Bound::Unbounded))
        .filter(|&(_ip, group)| {
            // Filter by tag if specified
            tag.is_none_or(|tag_filter| {
                group.tag.as_deref() == Some(tag_filter)
            })
        })
        .map(|(ip, group)| group.to_response(*ip))
        .take(limit)
        .collect()
}

/// Reset all multicast groups (and associated routes) for a given tag.
pub(crate) fn reset_tag(s: &Switch, tag: &str) -> DpdResult<()> {
    let groups_to_delete = {
        let mcast = s.mcast.lock().unwrap();
        mcast
            .groups
            .iter()
            .filter_map(|(ip, group)| {
                (group.tag.as_deref() == Some(tag)).then_some(*ip)
            })
            .collect::<Vec<_>>()
    };

    for group_ip in groups_to_delete {
        if let Err(e) = del_group(s, group_ip) {
            error!(
                s.log,
                "failed to delete multicast group for IP {group_ip}: {e:?}"
            );
            return Err(e);
        }
    }

    Ok(())
}

/// Reset all multicast groups (and associated routes) without a tag.
pub(crate) fn reset_untagged(s: &Switch) -> DpdResult<()> {
    let groups_to_delete = {
        let mcast = s.mcast.lock().unwrap();
        mcast
            .groups
            .iter()
            .filter_map(
                |(ip, group)| {
                    if group.tag.is_none() { Some(*ip) } else { None }
                },
            )
            .collect::<Vec<_>>()
    };

    for group_ip in groups_to_delete {
        if let Err(e) = del_group(s, group_ip) {
            error!(
                s.log,
                "failed to delete multicast group for IP {group_ip}: {e:?}"
            );
            return Err(e);
        }
    }

    Ok(())
}

/// Reset all multicast groups (and associated routes).
pub(crate) fn reset(s: &Switch) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().unwrap();

    // Destroy ASIC groups
    let group_ids = s.asic_hdl.mc_domains();
    for group_id in group_ids {
        if let Err(e) = s.asic_hdl.mc_group_destroy(group_id) {
            error!(
                s.log,
                "failed to delete multicast group with ID {group_id}: {e:?}"
            );
            return Err(e.into());
        }
    }

    // Reset all table entries
    table::mcast::mcast_replication::reset_ipv6(s)?;
    table::mcast::mcast_src_filter::reset_ipv4(s)?;
    table::mcast::mcast_src_filter::reset_ipv6(s)?;
    table::mcast::mcast_nat::reset_ipv4(s)?;
    table::mcast::mcast_nat::reset_ipv6(s)?;
    table::mcast::mcast_route::reset_ipv4(s)?;
    table::mcast::mcast_route::reset_ipv6(s)?;
    table::mcast::mcast_egress::reset_bitmap_table(s)?;

    // Clear data structures
    mcast.groups.clear();
    mcast.nat_target_refs.clear();

    Ok(())
}

/// Performs VLAN propagation for external groups.
fn perform_vlan_propagation(
    s: &Switch,
    mcast: &MulticastGroupData,
    group_ip: IpAddr,
    vlan_id: u16,
    internal_ip: IpAddr,
) -> DpdResult<()> {
    debug!(
        s.log,
        "external group with VLAN references internal group, propagating VLAN";
        "external_group" => %group_ip,
        "vlan" => vlan_id,
        "internal_group" => %internal_ip,
    );

    let internal_group = mcast.groups.get(&internal_ip).ok_or_else(|| {
        DpdError::McastGroupFailure(format!(
            "internal group not found during VLAN propagation: \
             internal_group={internal_ip}, external_group={group_ip}"
        ))
    })?;

    let (external_group_id, members) = (
        internal_group.external_scoped_group_id().clone(),
        internal_group.members.clone(),
    );

    // Update bitmap entry with VLAN if internal group has members
    if !members.is_empty() {
        let port_bitmap = create_port_bitmap(&members, Direction::External);
        table::mcast::mcast_egress::update_bitmap_entry(
            s,
            external_group_id.id(),
            &port_bitmap,
            Some(vlan_id),
        ).map_err(|e| {
            DpdError::McastGroupFailure(format!(
                "failed to update external bitmap: vlan={vlan_id}, internal_group={internal_ip}, error={e:?}",
            ))
        })?;
    }
    Ok(())
}

/// Remove source filters for a multicast group.
fn remove_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => remove_ipv4_source_filters(s, ipv4, sources),
        IpAddr::V6(ipv6) => remove_ipv6_source_filters(s, ipv6, sources),
    }
}

fn remove_ipv4_source_filters(
    s: &Switch,
    ipv4: Ipv4Addr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    if let Some(srcs) = sources {
        for src in srcs {
            match src {
                IpSrc::Exact(IpAddr::V4(src)) => {
                    table::mcast::mcast_src_filter::del_ipv4_entry(
                        s,
                        Ipv4Net::new(*src, 32).unwrap(),
                        ipv4,
                    )?;
                }
                IpSrc::Subnet(src) => {
                    table::mcast::mcast_src_filter::del_ipv4_entry(
                        s, *src, ipv4,
                    )?;
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn remove_ipv6_source_filters(
    s: &Switch,
    ipv6: Ipv6Addr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    if let Some(srcs) = sources {
        for src in srcs {
            if let IpSrc::Exact(IpAddr::V6(src)) = src {
                table::mcast::mcast_src_filter::del_ipv6_entry(s, *src, ipv6)?;
            }
        }
    }

    Ok(())
}

/// Add source filters for a multicast group.
fn add_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    let Some(srcs) = sources else { return Ok(()) };

    match group_ip {
        IpAddr::V4(ipv4) => add_ipv4_source_filters(s, srcs, ipv4),
        IpAddr::V6(ipv6) => add_ipv6_source_filters(s, srcs, ipv6),
    }
}

fn add_ipv4_source_filters(
    s: &Switch,
    sources: &[IpSrc],
    dest_ip: Ipv4Addr,
) -> DpdResult<()> {
    for src in sources {
        match src {
            IpSrc::Exact(IpAddr::V4(src)) => {
                table::mcast::mcast_src_filter::add_ipv4_entry(
                    s,
                    Ipv4Net::new(*src, 32).unwrap(),
                    dest_ip,
                )
            }
            IpSrc::Subnet(subnet) => {
                table::mcast::mcast_src_filter::add_ipv4_entry(
                    s, *subnet, dest_ip,
                )
            }
            _ => Ok(()),
        }?;
    }

    Ok(())
}

fn add_ipv6_source_filters(
    s: &Switch,
    sources: &[IpSrc],
    dest_ip: Ipv6Addr,
) -> DpdResult<()> {
    for src in sources {
        if let IpSrc::Exact(IpAddr::V6(src)) = src {
            table::mcast::mcast_src_filter::add_ipv6_entry(s, *src, dest_ip)?;
        }
    }

    Ok(())
}

fn validate_internal_group_creation(
    mcast: &MulticastGroupData,
    group_ip: AdminScopedIpv6,
) -> DpdResult<()> {
    validate_group_exists(mcast, group_ip.into())?;
    Ok(())
}

fn validate_external_group_creation(
    mcast: &MulticastGroupData,
    group_ip: IpAddr,
    group_info: &MulticastGroupCreateExternalEntry,
) -> DpdResult<()> {
    validate_group_exists(mcast, group_ip)?;
    validate_multicast_address(group_ip, group_info.sources.as_deref())?;
    validate_not_admin_local_ipv6(group_ip)?;
    Ok(())
}

fn validate_group_exists(
    mcast: &MulticastGroupData,
    group_ip: IpAddr,
) -> DpdResult<()> {
    if mcast.groups.contains_key(&group_ip) {
        return Err(DpdError::Exists(format!(
            "multicast group for IP {group_ip} already exists",
        )));
    }
    Ok(())
}

/// Configures external tables for an external multicast group.
fn configure_external_tables(
    s: &Switch,
    group_info: &MulticastGroupCreateExternalEntry,
) -> DpdResult<()> {
    let group_ip = group_info.group_ip;
    let nat_target =
        group_info.internal_forwarding.nat_target.ok_or_else(|| {
            DpdError::Invalid(
                "external groups must have NAT target".to_string(),
            )
        })?;

    // Add source filter entries if needed
    add_source_filters(s, group_ip, group_info.sources.as_deref())?;

    // Add NAT entry
    match group_ip {
        IpAddr::V4(ipv4) => {
            table::mcast::mcast_nat::add_ipv4_entry(s, ipv4, nat_target)?;
        }
        IpAddr::V6(ipv6) => {
            table::mcast::mcast_nat::add_ipv6_entry(s, ipv6, nat_target)?;
        }
    }

    // Add routing entry
    match group_ip {
        IpAddr::V4(ipv4) => table::mcast::mcast_route::add_ipv4_entry(
            s,
            ipv4,
            group_info.external_forwarding.vlan_id,
        ),
        IpAddr::V6(ipv6) => table::mcast::mcast_route::add_ipv6_entry(
            s,
            ipv6,
            group_info.external_forwarding.vlan_id,
        ),
    }
}

/// Creates multicast group IDs for external and underlay groups.
///
/// Groups can be created without members initially, and members are added later
/// when instances are added.
fn allocate_multicast_group_ids(
    s: &Switch,
    mcast: &mut MulticastGroupData,
    group_ip: IpAddr,
) -> DpdResult<(ScopedGroupId, ScopedGroupId)> {
    debug!(s.log, "creating multicast group IDs for IP {group_ip}");

    // Always allocate both group IDs to avoid allocation delays during member addition
    let external_group_id = mcast.generate_group_id()?;
    let underlay_group_id = mcast.generate_group_id()?;

    // Create ASIC groups without holding the lock
    create_asic_group(s, external_group_id.id(), group_ip)?;
    create_asic_group(s, underlay_group_id.id(), group_ip)?;

    Ok((external_group_id, underlay_group_id))
}

fn delete_multicast_groups(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: ScopedGroupId,
    underlay_group_id: ScopedGroupId,
) -> DpdResult<()> {
    let external_id = external_group_id.id();
    if let Err(e) = s.asic_hdl.mc_group_destroy(external_id) {
        warn!(
            s.log,
            "failed to delete external multicast group";
            "IP" => %group_ip,
            "ID" => external_id,
            "error" => ?e,
        );
    }

    let underlay_id = underlay_group_id.id();
    if let Err(e) = s.asic_hdl.mc_group_destroy(underlay_id) {
        warn!(
            s.log,
            "failed to delete underlay multicast group";
            "IP" => %group_ip,
            "ID" => underlay_id,
            "error" => ?e,
        );
    }

    Ok(())
}

fn create_asic_group(
    s: &Switch,
    group_id: MulticastGroupId,
    group_ip: IpAddr,
) -> DpdResult<()> {
    s.asic_hdl
        .mc_group_create(group_id)
        .map_err(|e: AsicError| {
            DpdError::McastGroupFailure(format!(
                "failed to create multicast group for IP {group_ip} with ID \
                 {group_id}: {e:?}"
            ))
        })
}

fn add_ports_to_groups(
    s: &Switch,
    group_ip: IpAddr,
    members: &[MulticastGroupMember],
    external_group_id: MulticastGroupId,
    underlay_group_id: MulticastGroupId,
    replication_info: &MulticastReplicationInfo,
    added_members: &mut Vec<(PortId, LinkId, Direction)>,
) -> DpdResult<()> {
    for member in members {
        let group_id = match member.direction {
            Direction::External => external_group_id,
            Direction::Underlay => underlay_group_id,
        };

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        s.asic_hdl
            .mc_port_add(
                group_id,
                asic_id,
                replication_info.rid,
                replication_info.level1_excl_id,
            )
            .map_err(|e| {
                DpdError::McastGroupFailure(format!(
                    "failed to add port {port_id} to group for IP {group_ip}: {e:?}",
                    port_id = member.port_id
                ))
            })?;

        added_members.push((member.port_id, member.link_id, member.direction));
    }

    Ok(())
}

fn process_membership_changes(
    s: &Switch,
    group_ip: IpAddr,
    new_members: &[MulticastGroupMember],
    group_entry: &mut MulticastGroup,
    replication_info: &MulticastReplicationInfo,
) -> DpdResult<(Vec<MulticastGroupMember>, Vec<MulticastGroupMember>)> {
    // First validate that IPv4 doesn't have underlay members
    if group_ip.is_ipv4()
        && new_members
            .iter()
            .any(|m| m.direction == Direction::Underlay)
    {
        return Err(DpdError::Invalid(format!(
            "multicast group for IPv4 {group_ip} cannot have underlay members"
        )));
    }

    let prev_members =
        group_entry.members.iter().cloned().collect::<HashSet<_>>();
    let new_members_set = new_members.iter().cloned().collect::<HashSet<_>>();

    let mut added_members = Vec::new();
    let mut removed_members = Vec::new();

    // Remove members from ASIC
    for member in prev_members.difference(&new_members_set) {
        let group_id = match member.direction {
            Direction::External => group_entry.external_group_id(),
            Direction::Underlay => group_entry.underlay_group_id(),
        };

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        s.asic_hdl.mc_port_remove(group_id, asic_id).map_err(|e| {
            DpdError::McastGroupFailure(format!(
                "failed to remove port {port_id} from group for IP {group_ip}: {e:?}",
                port_id = member.port_id
            ))
        })?;

        removed_members.push(member.clone());
    }

    // Add new members to ASIC
    for member in new_members_set.difference(&prev_members) {
        if group_ip.is_ipv4() && member.direction == Direction::Underlay {
            continue;
        }

        let group_id = match member.direction {
            Direction::External => group_entry.external_group_id(),
            Direction::Underlay => group_entry.underlay_group_id(),
        };

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        s.asic_hdl
            .mc_port_add(
                group_id,
                asic_id,
                replication_info.rid,
                replication_info.level1_excl_id,
            )
            .map_err(|e| {
                DpdError::McastGroupFailure(format!(
                    "failed to add port {port_id} to group for IP {group_ip}: {e:?}",
                    port_id = member.port_id
                ))
            })?;

        added_members.push(member.clone());
    }

    Ok((added_members, removed_members))
}

/// Default level exclusion IDs to 0 for internal groups
/// since they can only be configured internally without API calls.
fn configure_replication(
    external_group_id: MulticastGroupId,
) -> MulticastReplicationInfo {
    MulticastReplicationInfo {
        rid: external_group_id,
        level1_excl_id: 0,
        level2_excl_id: 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn configure_internal_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: MulticastGroupId,
    underlay_group_id: MulticastGroupId,
    replication_info: Option<&MulticastReplicationInfo>,
    added_members: &[(PortId, LinkId, Direction)],
    vlan_id: Option<u16>, // VLAN ID from referencing external group
) -> DpdResult<()> {
    match (group_ip, replication_info) {
        // Note: There are no internal IPv4 groups, only external IPv4 groups
        (IpAddr::V4(_), _) => Err(DpdError::Invalid(
            "IPv4 groups cannot be created as internal groups".to_string(),
        )),

        (IpAddr::V6(ipv6), Some(replication_info)) => {
            table::mcast::mcast_replication::add_ipv6_entry(
                s,
                ipv6,
                underlay_group_id,
                external_group_id,
                replication_info.rid,
                replication_info.level1_excl_id,
                replication_info.level2_excl_id,
            )
            .and_then(|_| {
                table::mcast::mcast_route::add_ipv6_entry(
                    s, ipv6,
                    vlan_id, // VLAN from referencing external group
                )
            })
            .and_then(|_| {
                // Add bitmap entry for overlay members only
                // (decapsulation decision only needed for overlay traffic)
                let external_port_bitmap =
                    create_external_port_bitmap(added_members);
                table::mcast::mcast_egress::add_bitmap_entry(
                    s,
                    external_group_id,
                    &external_port_bitmap,
                    vlan_id, // VLAN from referencing external group
                )
            })
        }

        (IpAddr::V6(ipv6), None) => {
            // For empty groups, just add basic route entry - no replication needed yet
            table::mcast::mcast_route::add_ipv6_entry(
                s, ipv6, vlan_id, // VLAN from referencing external group
            )
        }
    }
}

fn update_group_tables(
    s: &Switch,
    group_ip: IpAddr,
    group_entry: &MulticastGroup,
    replication_info: &MulticastReplicationInfo,
    new_sources: &Option<Vec<IpSrc>>,
    old_sources: &Option<Vec<IpSrc>>,
) -> DpdResult<()> {
    if let Some(existing_replication) = &group_entry.replication_info {
        if replication_info.rid != existing_replication.rid
            || replication_info.level1_excl_id
                != existing_replication.level1_excl_id
            || replication_info.level2_excl_id
                != existing_replication.level2_excl_id
        {
            update_replication_tables(
                s,
                group_ip,
                group_entry.external_group_id(),
                group_entry.underlay_group_id(),
                replication_info,
            )?;
        }
    } else {
        // First time setting up replication for this group - use add instead of update
        match group_ip {
            IpAddr::V4(_) => {} // IPv4 groups don't have replication entries
            IpAddr::V6(ipv6) => {
                table::mcast::mcast_replication::add_ipv6_entry(
                    s,
                    ipv6,
                    group_entry.underlay_group_id(),
                    group_entry.external_group_id(),
                    replication_info.rid,
                    replication_info.level1_excl_id,
                    replication_info.level2_excl_id,
                )?;
            }
        }
    }

    if new_sources != old_sources {
        remove_source_filters(s, group_ip, old_sources.as_deref())?;
        add_source_filters(s, group_ip, new_sources.as_deref())?;
    }

    Ok(())
}

fn update_external_tables(
    s: &Switch,
    group_ip: IpAddr,
    group_entry: &MulticastGroup,
    new_group_info: &MulticastGroupUpdateExternalEntry,
) -> DpdResult<()> {
    // Update sources if they changed
    if new_group_info.sources != group_entry.sources {
        remove_source_filters(s, group_ip, group_entry.sources.as_deref())?;
        add_source_filters(s, group_ip, new_group_info.sources.as_deref())?;
    }

    // Update NAT target - external groups always have NAT targets
    if Some(
        new_group_info
            .internal_forwarding
            .nat_target
            .ok_or_else(|| {
                DpdError::Invalid(
                    "external groups must have NAT target".to_string(),
                )
            })?,
    ) != group_entry.int_fwding.nat_target
    {
        update_nat_tables(
            s,
            group_ip,
            Some(new_group_info.internal_forwarding.nat_target.ok_or_else(
                || {
                    DpdError::Invalid(
                        "external groups must have NAT target".to_string(),
                    )
                },
            )?),
            group_entry.int_fwding.nat_target,
        )?;
    }

    // Update VLAN if it changed
    if new_group_info.external_forwarding.vlan_id
        != group_entry.ext_fwding.vlan_id
    {
        match group_ip {
            IpAddr::V4(ipv4) => table::mcast::mcast_route::update_ipv4_entry(
                s,
                ipv4,
                new_group_info.external_forwarding.vlan_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::mcast_route::update_ipv6_entry(
                s,
                ipv6,
                new_group_info.external_forwarding.vlan_id,
            ),
        }?;
    }

    Ok(())
}

/// Delete bitmap entries for a group with replication checks.
fn delete_group_bitmap_entries(
    s: &Switch,
    group: &MulticastGroup,
) -> DpdResult<()> {
    // Only delete bitmap entries if the group had replication info
    // (which indicates bitmap entries were created)
    if group.replication_info.is_none() {
        return Ok(()); // No bitmap entries were ever created
    }
    // Delete external bitmap entry only (underlay doesn't use decap bitmap)
    table::mcast::mcast_egress::del_bitmap_entry(s, group.external_group_id())
}

/// Cleanup replication tables when transitioning group to empty membership.
///
/// Handles the complete cleanup process including bitmap and
/// replication entries.
fn cleanup_empty_group_replication(
    s: &Switch,
    group_ip: IpAddr,
    group_entry: &MulticastGroup,
) -> DpdResult<()> {
    debug!(s.log, "cleaning up replication for empty group {group_ip}");

    // Only proceed if group actually has replication info to clean up
    if group_entry.replication_info.is_none() {
        return Ok(());
    }

    // Attempt cleanup operations in sequence
    delete_group_bitmap_entries(s, group_entry)
        .and_then(|_| delete_replication_entries(s, group_ip, group_entry))
}

/// Create a port bitmap for external (overlay) members only.
fn create_external_port_bitmap(
    added_members: &[(PortId, LinkId, Direction)],
) -> table::mcast::mcast_egress::PortBitmap {
    let external_members: Vec<MulticastGroupMember> = added_members
        .iter()
        .filter(|(_, _, direction)| *direction == Direction::External)
        .map(|(port_id, link_id, direction)| MulticastGroupMember {
            port_id: *port_id,
            link_id: *link_id,
            direction: *direction,
        })
        .collect();
    create_port_bitmap(&external_members, Direction::External)
}

/// Delete replication table entries.
fn delete_replication_entries(
    s: &Switch,
    group_ip: IpAddr,
    group: &MulticastGroup,
) -> DpdResult<()> {
    // Only delete replication entries if the group had replication info
    // (which indicates replication entries were created)
    if group.replication_info.is_none() {
        return Ok(()); // No replication entries were ever created
    }

    // Delete replication entry (only IPv6 has replication table)
    match group_ip {
        IpAddr::V4(_) => Ok(()), // IPv4 doesn't use replication table
        IpAddr::V6(ipv6) => {
            table::mcast::mcast_replication::del_ipv6_entry(s, ipv6)
        }
    }
}

fn delete_group_tables(
    s: &Switch,
    group_ip: IpAddr,
    group: &MulticastGroup,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => {
            remove_ipv4_source_filters(s, ipv4, group.sources.as_deref())?;

            if group.int_fwding.nat_target.is_some() {
                table::mcast::mcast_nat::del_ipv4_entry(s, ipv4)?;
            }

            delete_group_bitmap_entries(s, group)?;

            table::mcast::mcast_route::del_ipv4_entry(s, ipv4)?;
        }
        IpAddr::V6(ipv6) => {
            delete_replication_entries(s, group_ip, group)?;

            remove_ipv6_source_filters(s, ipv6, group.sources.as_deref())?;

            if group.int_fwding.nat_target.is_some() {
                table::mcast::mcast_nat::del_ipv6_entry(s, ipv6)?;
            }

            delete_group_bitmap_entries(s, group)?;

            table::mcast::mcast_route::del_ipv6_entry(s, ipv6)?;
        }
    }

    Ok(())
}

fn update_replication_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: MulticastGroupId,
    underlay_group_id: MulticastGroupId,
    replication_info: &MulticastReplicationInfo,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(_) => Ok(()),
        IpAddr::V6(ipv6) => table::mcast::mcast_replication::update_ipv6_entry(
            s,
            ipv6,
            underlay_group_id,
            external_group_id,
            replication_info.rid,
            replication_info.level1_excl_id,
            replication_info.level2_excl_id,
        ),
    }
}

fn update_nat_tables(
    s: &Switch,
    group_ip: IpAddr,
    new_nat_target: Option<NatTarget>,
    old_nat_target: Option<NatTarget>,
) -> DpdResult<()> {
    match (group_ip, new_nat_target, old_nat_target) {
        (IpAddr::V4(ipv4), Some(nat), Some(_)) => {
            // NAT to NAT - update existing entry
            table::mcast::mcast_nat::update_ipv4_entry(s, ipv4, nat)
        }
        (IpAddr::V6(ipv6), Some(nat), Some(_)) => {
            // NAT to NAT - update existing entry
            table::mcast::mcast_nat::update_ipv6_entry(s, ipv6, nat)
        }
        (IpAddr::V4(ipv4), Some(nat), None) => {
            // No NAT to NAT - add new entry
            table::mcast::mcast_nat::add_ipv4_entry(s, ipv4, nat)
        }
        (IpAddr::V6(ipv6), Some(nat), None) => {
            // No NAT to NAT - add new entry
            table::mcast::mcast_nat::add_ipv6_entry(s, ipv6, nat)
        }
        (IpAddr::V4(ipv4), None, Some(_)) => {
            // NAT to no NAT - delete entry
            table::mcast::mcast_nat::del_ipv4_entry(s, ipv4)
        }
        (IpAddr::V6(ipv6), None, Some(_)) => {
            // NAT to no NAT - delete entry
            table::mcast::mcast_nat::del_ipv6_entry(s, ipv6)
        }
        _ => Ok(()), // No change (None → None)
    }
}

/// Update internal group's bitmap entries when members change.
fn update_internal_group_bitmap_tables(
    s: &Switch,
    external_group_id: MulticastGroupId,
    new_members: &[MulticastGroupMember],
    old_members: &[MulticastGroupMember],
    external_group_vlan: Option<u16>,
) -> DpdResult<()> {
    let prev_had_members = !old_members.is_empty();
    let now_has_members = !new_members.is_empty();

    // Create bitmap for overlay members only (decapsulation decision applies only to overlay traffic)
    let external_port_bitmap =
        create_port_bitmap(new_members, Direction::External);

    if !prev_had_members && now_has_members {
        // First time adding members - use add_bitmap_entry with external group's VLAN
        table::mcast::mcast_egress::add_bitmap_entry(
            s,
            external_group_id,
            &external_port_bitmap,
            external_group_vlan, // Use external group's VLAN for bitmap entries
        )?;
    } else if prev_had_members && now_has_members {
        // Members changed but still have members - use external group's VLAN
        table::mcast::mcast_egress::update_bitmap_entry(
            s,
            external_group_id,
            &external_port_bitmap,
            external_group_vlan, // Use external group's VLAN for bitmap entries
        )?;
    }

    Ok(())
}

fn update_fwding_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: MulticastGroupId,
    underlay_group_id: MulticastGroupId,
    members: &[MulticastGroupMember],
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => {
            table::mcast::mcast_route::update_ipv4_entry(s, ipv4, vlan_id)
        }
        IpAddr::V6(ipv6) => {
            table::mcast::mcast_route::update_ipv6_entry(s, ipv6, vlan_id)
                .and_then(|_| {
                    // Update external bitmap for external members
                    let external_port_bitmap =
                        create_port_bitmap(members, Direction::External);
                    table::mcast::mcast_egress::update_bitmap_entry(
                        s,
                        external_group_id,
                        &external_port_bitmap,
                        vlan_id,
                    )
                })
                .and_then(|_| {
                    // Update underlay bitmap for underlay members
                    let underlay_port_bitmap =
                        create_port_bitmap(members, Direction::Underlay);
                    table::mcast::mcast_egress::update_bitmap_entry(
                        s,
                        underlay_group_id,
                        &underlay_port_bitmap,
                        vlan_id,
                    )
                })
        }
    }
}

/// Create port bitmap from members filtered by direction.
fn create_port_bitmap(
    members: &[MulticastGroupMember],
    direction: Direction,
) -> table::mcast::mcast_egress::PortBitmap {
    let mut port_bitmap = table::mcast::mcast_egress::PortBitmap::new();
    for member in members {
        if member.direction == direction {
            port_bitmap.add_port(member.port_id.as_u8());
        }
    }
    port_bitmap
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_scoped_group_id_drop_returns_to_pool() {
        let free_ids = Arc::new(Mutex::new(vec![100, 101, 102]));
        {
            let scoped_id = ScopedGroupId::from(ScopedIdInner(
                101,
                Arc::downgrade(&free_ids),
            ));
            assert_eq!(scoped_id.id(), 101);
        }

        // ID should be returned to pool
        let pool = free_ids.lock().unwrap();
        assert!(pool.contains(&101));
        assert_eq!(pool.len(), 4); // Original 3 + returned 1
    }

    #[test]
    fn test_scoped_group_id_weak_reference_cleanup() {
        let free_ids = Arc::new(Mutex::new(vec![100, 101, 102]));
        let scoped_id = ScopedIdInner(101, Arc::downgrade(&free_ids));

        // Drop the Arc, leaving only the weak reference
        drop(free_ids);

        // When ScopedGroupId is dropped, it should handle the dead weak
        // reference gracefully
        drop(scoped_id); // Should not panic
    }

    #[test]
    fn test_multicast_group_data_generate_id_allocation() {
        let mut mcast_data = MulticastGroupData::new();

        // Generate first ID (Vec is used as stack, so pop() returns highest ID first)
        let scoped_id1 = mcast_data.generate_group_id().unwrap();
        assert_eq!(scoped_id1.id(), MulticastGroupId::MAX - 1); // Should be highest available ID

        // Generate second ID
        let scoped_id2 = mcast_data.generate_group_id().unwrap();
        assert_eq!(scoped_id2.id(), MulticastGroupId::MAX - 2);

        // Drop the second ID, it should return to pool
        drop(scoped_id2);

        // Generate third ID, should reuse the returned ID
        let scoped_id3 = mcast_data.generate_group_id().unwrap();
        assert_eq!(scoped_id3.id(), MulticastGroupId::MAX - 2); // Should reuse the returned ID
    }

    #[test]
    fn test_multicast_group_data_id_exhaustion() {
        let mut mcast_data = MulticastGroupData::new();

        // Exhaust the pool
        {
            let mut pool = mcast_data.free_group_ids.lock().unwrap();
            pool.clear();
        }

        // Should return error when no IDs available
        let result = mcast_data.generate_group_id();
        assert!(result.is_err());

        match result.unwrap_err() {
            DpdError::McastGroupFailure(msg) => {
                assert!(msg.contains("no free multicast group IDs available"));
            }
            _ => panic!("Expected McastGroupFailure error"),
        }
    }

    #[test]
    fn test_concurrent_id_allocation() {
        let mcast_data = Arc::new(Mutex::new(MulticastGroupData::new()));
        let mut handles = Vec::new();

        // Spawn multiple threads to allocate IDs concurrently
        for _ in 0..10 {
            let mcast_data_clone = Arc::clone(&mcast_data);
            let handle = thread::spawn(move || {
                let mut data = mcast_data_clone.lock().unwrap();
                data.generate_group_id().unwrap()
            });
            handles.push(handle);
        }

        // Collect all allocated IDs
        let mut allocated_ids = Vec::new();
        for handle in handles {
            allocated_ids.push(handle.join().unwrap());
        }

        let mut ids: Vec<_> = allocated_ids.iter().map(|v| v.id()).collect();

        // All IDs should be unique
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 10);

        // All IDs should be in valid range
        for id in ids {
            assert!(id >= MulticastGroupData::GENERATOR_START);
            assert!(id < MulticastGroupId::MAX);
        }
    }

    #[test]
    fn test_concurrent_allocation_and_deallocation() {
        let mcast_data = Arc::new(Mutex::new(MulticastGroupData::new()));
        let mut handles = Vec::new();

        // Spawn threads that allocate and immediately drop (deallocate)
        for _ in 0..5 {
            let mcast_data_clone = Arc::clone(&mcast_data);
            let handle = thread::spawn(move || {
                for _ in 0..10 {
                    let scoped_id = {
                        let mut data = mcast_data_clone.lock().unwrap();
                        data.generate_group_id().unwrap()
                    };
                    drop(scoped_id);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Pool should have all IDs back (minus any that might still be in use)
        let pool_size = {
            let data = mcast_data.lock().unwrap();

            data.free_group_ids.lock().unwrap().len()
        };

        // Should have close to the original number of IDs
        let expected_size = (MulticastGroupId::MAX
            - MulticastGroupData::GENERATOR_START)
            as usize;
        assert_eq!(pool_size, expected_size);
    }

    #[test]
    fn test_id_range_boundaries() {
        let mcast_data = MulticastGroupData::new();

        // Check that initial pool contains correct range
        let pool = mcast_data.free_group_ids.lock().unwrap();
        let expected_size = (MulticastGroupId::MAX
            - MulticastGroupData::GENERATOR_START)
            as usize;
        assert_eq!(pool.len(), expected_size);

        // Check that minimum and maximum IDs are in range
        assert!(pool.contains(&MulticastGroupData::GENERATOR_START));
        assert!(pool.contains(&(MulticastGroupId::MAX - 1)));
        assert!(!pool.contains(&(MulticastGroupData::GENERATOR_START - 1)));
        assert!(!pool.contains(&MulticastGroupId::MAX));
    }

    #[test]
    fn test_paired_allocation_and_cleanup() {
        let mut mcast_data = MulticastGroupData::new();

        // Get initial pool size
        let initial_pool_size = {
            let pool = mcast_data.free_group_ids.lock().unwrap();
            pool.len()
        };

        // Allocate both group IDs as a pair (simulating our "always allocate both" architecture)
        let external_id;
        let underlay_id;
        {
            external_id = mcast_data.generate_group_id().unwrap();
            underlay_id = mcast_data.generate_group_id().unwrap();

            // Verify both IDs are different
            assert_ne!(external_id.id(), underlay_id.id());

            // Pool should have 2 fewer IDs
            let pool = mcast_data.free_group_ids.lock().unwrap();
            assert_eq!(pool.len(), initial_pool_size - 2);
        }

        // Drop both IDs simultaneously (simulating MulticastGroup being dropped)
        drop(external_id);
        drop(underlay_id);

        // Both IDs should be returned to pool automatically
        let final_pool_size = {
            let pool = mcast_data.free_group_ids.lock().unwrap();
            pool.len()
        };

        // Pool should be back to original size
        assert_eq!(final_pool_size, initial_pool_size);
    }
}
