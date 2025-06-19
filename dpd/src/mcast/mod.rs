// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Multicast group management and configuration.
//!
//! This is the entrypoint for managing multicast groups, including creating,
//! modifying, and deleting groups.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Bound,
    sync::atomic::{AtomicU16, Ordering},
};

use crate::{
    link::LinkId,
    table,
    types::{DpdError, DpdResult},
    Switch,
};
use aal::{AsicError, AsicOps};
use common::{nat::NatTarget, ports::PortId};
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, error};

mod validate;
use validate::{
    is_ssm, validate_multicast_address, validate_nat_target,
    validate_not_admin_scoped_ipv6,
};

/// Type alias for multicast group IDs.
pub(crate) type MulticastGroupId = u16;

/// Source filter match key for multicast traffic.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub(crate) enum IpSrc {
    /// Exact match for the source IP address.
    Exact(IpAddr),
    /// Subnet match for the source IP address.
    Subnet(Ipv4Net),
}

impl fmt::Display for IpSrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSrc::Exact(ip) => write!(f, "{}", ip),
            IpSrc::Subnet(subnet) => write!(f, "{}", subnet),
        }
    }
}

/// Represents a member of a multicast group.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub(crate) struct MulticastGroupMember {
    pub port_id: PortId,
    pub link_id: LinkId,
    pub direction: Direction,
}

/// Represents the NAT target for multicast traffic for internal/underlay
/// forwarding.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub(crate) struct InternalForwarding {
    pub nat_target: Option<NatTarget>,
}

/// Represents the forwarding configuration for external multicast traffic.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub(crate) struct ExternalForwarding {
    pub vlan_id: Option<u16>,
}

/// Represents a multicast replication configuration.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
pub(crate) struct MulticastReplicationInfo {
    pub(crate) rid: u16,
    pub(crate) level1_excl_id: u16,
    pub(crate) level2_excl_id: u16,
}

/// Represents a multicast group configuration.
///
/// This structure is used to manage multicast groups, including their
/// replication information, forwarding settings, and associated members.
#[derive(Clone, Debug)]
pub(crate) struct MulticastGroup {
    pub(crate) external_group_id: Option<MulticastGroupId>,
    pub(crate) underlay_group_id: Option<MulticastGroupId>,
    pub(crate) tag: Option<String>,
    pub(crate) int_fwding: InternalForwarding,
    pub(crate) ext_fwding: ExternalForwarding,
    pub(crate) sources: Option<Vec<IpSrc>>,
    pub(crate) replication_info: Option<MulticastReplicationInfo>,
    pub(crate) members: Vec<MulticastGroupMember>,
}

/// Represents a multicast replication entry for POST requests.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastReplicationEntry {
    level1_excl_id: Option<u16>,
    level2_excl_id: Option<u16>,
}

/// A multicast group configuration for POST requests for internal (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupCreateEntry {
    group_ip: IpAddr,
    tag: Option<String>,
    sources: Option<Vec<IpSrc>>,
    replication_info: MulticastReplicationEntry,
    members: Vec<MulticastGroupMember>,
}

/// A multicast group configuration for POST requests for external (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupCreateExternalEntry {
    group_ip: IpAddr,
    tag: Option<String>,
    nat_target: NatTarget,
    vlan_id: Option<u16>,
    sources: Option<Vec<IpSrc>>,
}

/// Represents a multicast replication entry for PUT requests for internal
/// (to the rack) groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupUpdateEntry {
    tag: Option<String>,
    sources: Option<Vec<IpSrc>>,
    replication_info: MulticastReplicationEntry,
    members: Vec<MulticastGroupMember>,
}

/// A multicast group update entry for PUT requests for external (to the rack)
/// groups.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupUpdateExternalEntry {
    tag: Option<String>,
    nat_target: NatTarget,
    vlan_id: Option<u16>,
    sources: Option<Vec<IpSrc>>,
}

/// Response structure for multicast group operations.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupResponse {
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
    tag: Option<String>,
    int_fwding: InternalForwarding,
    ext_fwding: ExternalForwarding,
    sources: Option<Vec<IpSrc>>,
    replication_info: Option<MulticastReplicationInfo>,
    members: Vec<MulticastGroupMember>,
}

impl MulticastGroupResponse {
    fn new(group_ip: IpAddr, group: &MulticastGroup) -> Self {
        Self {
            group_ip,
            external_group_id: group.external_group_id,
            underlay_group_id: group.underlay_group_id,
            tag: group.tag.clone(),
            int_fwding: InternalForwarding {
                nat_target: group.int_fwding.nat_target,
            },
            ext_fwding: ExternalForwarding {
                vlan_id: group.ext_fwding.vlan_id,
            },
            sources: group.sources.clone(),
            replication_info: group.replication_info.as_ref().cloned(),
            members: group.members.to_vec(),
        }
    }

    /// Get the multicast group IP address.
    pub(crate) fn ip(&self) -> IpAddr {
        self.group_ip
    }
}

/// Direction the multicast traffic either being replicated to the underlay
/// or replicated externally.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub(crate) enum Direction {
    Underlay,
    External,
}

/// Stores multicast group configurations.
#[derive(Debug)]
pub struct MulticastGroupData {
    /// Multicast group configurations keyed by group IP.
    groups: BTreeMap<IpAddr, MulticastGroup>,
    /// Atomic counter for generating unique multicast group IDs, which
    /// are assigned in the dataplane.
    id_generator: AtomicU16,
    /// Set of in-use group IDs for fast lookup
    used_group_ids: HashSet<MulticastGroupId>,
    /// Mapping from admin-scoped group IP to external groups that use it as NAT
    /// target (admin_scoped_ip -> set of external_group_ips)
    nat_target_refs: BTreeMap<IpAddr, HashSet<IpAddr>>,
}

impl MulticastGroupData {
    const GENERATOR_START: u16 = 100;

    pub(crate) fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            id_generator: AtomicU16::new(Self::GENERATOR_START),
            used_group_ids: HashSet::new(),
            nat_target_refs: BTreeMap::new(),
        }
    }

    /// Generates a unique multicast group ID by finding the next available ID.
    fn generate_group_id(&self) -> DpdResult<MulticastGroupId> {
        for _ in Self::GENERATOR_START..u16::MAX {
            let id = self.id_generator.fetch_add(1, Ordering::SeqCst);

            if !self.used_group_ids.contains(&id) {
                return Ok(id);
            }
        }
        Err(DpdError::McastGroupFailure(
            "no free multicast group IDs available".to_string(),
        ))
    }

    /// Add a NAT target reference from external group to admin-scoped group.
    fn add_nat_target_ref(
        &mut self,
        external_group_ip: IpAddr,
        admin_scoped_ip: IpAddr,
    ) {
        self.nat_target_refs
            .entry(admin_scoped_ip)
            .or_insert_with(HashSet::new)
            .insert(external_group_ip);
    }

    /// Remove a NAT target reference.
    fn remove_nat_target_ref(
        &mut self,
        external_group_ip: IpAddr,
        admin_scoped_ip: IpAddr,
    ) {
        if let Some(refs) = self.nat_target_refs.get_mut(&admin_scoped_ip) {
            refs.remove(&external_group_ip);
            if refs.is_empty() {
                self.nat_target_refs.remove(&admin_scoped_ip);
            }
        }
    }

    /// Get VLAN ID for an internal group from its referencing external groups.
    fn get_vlan_for_internal_addr(&self, internal_ip: IpAddr) -> Option<u16> {
        // Find the first external group that references this internal group
        // and return its VLAN ID
        if let Some(external_refs) = self.nat_target_refs.get(&internal_ip) {
            for external_ip in external_refs {
                if let Some(external_group) = self.groups.get(external_ip) {
                    if let Some(vlan_id) = external_group.ext_fwding.vlan_id {
                        return Some(vlan_id);
                    }
                }
            }
        }
        None
    }
}

/// Update the VLAN metadata for an existing internal group's table entries.
fn propagate_vlan_to_internal_group(
    s: &Switch,
    internal_ip: IpAddr,
    vlan_id: u16,
) -> DpdResult<()> {
    let mcast = s.mcast.lock().unwrap();

    let internal_group = mcast.groups.get(&internal_ip).ok_or_else(|| {
        DpdError::Invalid(format!("Internal group {} not found", internal_ip))
    })?;

    let external_group_id = internal_group.external_group_id;
    let underlay_group_id = internal_group.underlay_group_id;

    drop(mcast); // Release lock for table operations

    // Note: Route table entries for admin-scoped groups remain as "Forward" action
    // The VLAN is applied in the egress bitmap tables below

    // For bitmap entries, we need to reconstruct the port bitmap from the
    // group's members and then update the bitmap entry with the new VLAN
    let mcast = s.mcast.lock().unwrap();
    if let Some(internal_group) = mcast.groups.get(&internal_ip) {
        let members = internal_group.members.clone();
        drop(mcast);

        if let Some(external_id) = external_group_id {
            let mut port_bitmap = table::mcast::mcast_egress::PortBitmap::new();
            for member in &members {
                if member.direction == Direction::External {
                    port_bitmap.add_port(member.port_id.as_u8());
                }
            }
            table::mcast::mcast_egress::update_bitmap_entry(
                s,
                external_id,
                &port_bitmap,
                Some(vlan_id),
            )?;
        }

        if let Some(underlay_id) = underlay_group_id {
            let mut port_bitmap = table::mcast::mcast_egress::PortBitmap::new();
            for member in &members {
                if member.direction == Direction::Underlay {
                    port_bitmap.add_port(member.port_id.as_u8());
                }
            }
            table::mcast::mcast_egress::update_bitmap_entry(
                s,
                underlay_id,
                &port_bitmap,
                Some(vlan_id),
            )?;
        }
    }

    Ok(())
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
) -> DpdResult<MulticastGroupResponse> {
    let mut mcast = s.mcast.lock().unwrap();
    let group_ip = group_info.group_ip;

    validate_external_group_creation(&mcast, group_ip, &group_info)?;
    validate_nat_target(group_info.nat_target)?;

    // Validate that NAT target points to an existing group
    if !mcast
        .groups
        .contains_key(&group_info.nat_target.internal_ip.into())
    {
        return Err(DpdError::Invalid(format!(
            "multicast group for IP address {} must have a NAT target that is also a tracked multicast group",
            group_ip
        )));
    }

    let res = configure_external_tables(s, &group_info);

    if let Err(e) = res {
        // Use unified rollback with optional NAT for external groups
        rollback_on_group_create(
            s,
            group_ip,
            (None, None), // External groups don't create ASIC groups
            &[],          // No members added externally
            &MulticastReplicationInfo::default(), // Dummy replication info
            Some(group_info.nat_target), // External groups have NAT targets
            group_info.sources.as_deref(),
        )
        .ok(); // Ignore rollback errors, log the original error
        return Err(e);
    }

    let group = MulticastGroup {
        external_group_id: None,
        underlay_group_id: None,
        tag: group_info.tag,
        int_fwding: InternalForwarding {
            nat_target: Some(group_info.nat_target),
        },
        ext_fwding: ExternalForwarding {
            vlan_id: group_info.vlan_id,
        },
        sources: group_info.sources,
        replication_info: None,
        members: Vec::new(), // External groups have no members
    };

    mcast.groups.insert(group_ip, group.clone());

    // Track NAT target reference for VLAN propagation
    mcast
        .add_nat_target_ref(group_ip, group_info.nat_target.internal_ip.into());

    // Update internal group's tables with the VLAN if it exists and has a VLAN
    if let Some(vlan_id) = group_info.vlan_id {
        let internal_ip = group_info.nat_target.internal_ip.into();
        debug!(
            s.log,
            "External group {} with VLAN {} references internal group {}",
            group_ip,
            vlan_id,
            internal_ip
        );
        debug!(
            s.log,
            "Propagating VLAN {} to existing internal group {}",
            vlan_id,
            internal_ip
        );
        drop(mcast); // Release lock before table operations
        if let Err(e) =
            propagate_vlan_to_internal_group(s, internal_ip, vlan_id)
        {
            error!(
                s.log,
                "Failed to update VLAN {} for internal group {}: {:?}",
                vlan_id,
                internal_ip,
                e
            );
        }
    }

    Ok(MulticastGroupResponse::new(group_ip, &group))
}

/// Add an internal multicast group to the switch, which creates the group on
/// the ASIC and associates it with a group IP address and updates associated
/// tables for multicast replication and L3 routing.
///
/// If anything fails, the group is cleaned up and an error is returned.
pub(crate) fn add_group_internal(
    s: &Switch,
    group_info: MulticastGroupCreateEntry,
) -> DpdResult<MulticastGroupResponse> {
    add_group_internal_only(s, group_info)
}

fn add_group_internal_only(
    s: &Switch,
    group_info: MulticastGroupCreateEntry,
) -> DpdResult<MulticastGroupResponse> {
    let mut mcast = s.mcast.lock().unwrap();
    let group_ip = group_info.group_ip;

    validate_internal_group_creation(&mcast, group_ip, &group_info)?;

    let ipv6 = match group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => unreachable!("Should have been handled above"),
    };

    let (external_group_id, underlay_group_id) =
        create_multicast_group_ids(s, &mcast, ipv6, &group_info)?;

    let mut added_members = Vec::new();

    let replication_info = configure_replication(
        &group_info,
        external_group_id,
        underlay_group_id,
    );

    add_ports_to_groups(
        s,
        group_ip,
        &group_info.members,
        external_group_id,
        underlay_group_id,
        &replication_info,
        &mut added_members,
    )?;

    // Get VLAN ID from referencing external groups
    let vlan_id = mcast.get_vlan_for_internal_addr(group_ip);

    configure_internal_tables(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
        Some(&replication_info),
        &group_info,
        &added_members,
        vlan_id,
    )?;

    let group = MulticastGroup {
        external_group_id,
        underlay_group_id,
        tag: group_info.tag,
        int_fwding: InternalForwarding {
            nat_target: None, // Internal groups don't have NAT targets
        },
        ext_fwding: ExternalForwarding {
            vlan_id: None, // Internal groups don't have VLANs
        },
        sources: group_info.sources,
        replication_info: Some(replication_info),
        members: group_info.members,
    };

    mcast.groups.insert(group_ip, group.clone());

    if let Some(external_group_id) = group.external_group_id {
        mcast.used_group_ids.insert(external_group_id);
    }

    if let Some(underlay_group_id) = group.underlay_group_id {
        mcast.used_group_ids.insert(underlay_group_id);
    }

    Ok(MulticastGroupResponse::new(group_ip, &group))
}

/// Delete a multicast group from the switch, including all associated tables
/// and port mappings.
pub(crate) fn del_group(s: &Switch, group_ip: IpAddr) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().unwrap();

    let group: MulticastGroup =
        mcast.groups.remove(&group_ip).ok_or_else(|| {
            DpdError::Missing(format!(
                "Multicast group for IP {} not found",
                group_ip
            ))
        })?;

    if let Some(external_id) = group.external_group_id {
        mcast.used_group_ids.remove(&external_id);
    }

    if let Some(underlay_id) = group.underlay_group_id {
        mcast.used_group_ids.remove(&underlay_id);
    }

    // Remove NAT target reference if this was an external group
    if let Some(nat_target) = group.int_fwding.nat_target {
        mcast.remove_nat_target_ref(group_ip, nat_target.internal_ip.into());
    }

    drop(mcast);

    debug!(s.log, "deleting multicast group for IP {}", group_ip);

    delete_group_tables(s, group_ip, &group)?;

    delete_multicast_groups(
        s,
        group_ip,
        group.external_group_id,
        group.underlay_group_id,
    )?;

    Ok(())
}

/// Get a multicast group configuration.
pub(crate) fn get_group(
    s: &Switch,
    group_ip: IpAddr,
) -> DpdResult<MulticastGroupResponse> {
    let mcast = s.mcast.lock().unwrap();

    let group = mcast
        .groups
        .get(&group_ip)
        .ok_or_else(|| {
            DpdError::Missing(format!(
                "multicast group for IP {} not found",
                group_ip
            ))
        })?
        .clone();

    Ok(MulticastGroupResponse::new(group_ip, &group))
}

pub(crate) fn modify_group_external(
    s: &Switch,
    group_ip: IpAddr,
    new_group_info: MulticastGroupUpdateExternalEntry,
) -> DpdResult<MulticastGroupResponse> {
    let mut mcast = s.mcast.lock().unwrap();

    if !mcast.groups.contains_key(&group_ip) {
        return Err(DpdError::Missing(format!(
            "Multicast group for IP {} not found",
            group_ip
        )));
    }

    let mut group_entry = mcast.groups.remove(&group_ip).unwrap();

    let res =
        update_external_tables(s, group_ip, &group_entry, &new_group_info);

    if let Err(e) = res {
        mcast.groups.insert(group_ip, group_entry);

        // Use unified rollback for external modify failures
        // The group_entry we just restored has the original state
        rollback_on_group_update(
            s,
            group_ip,
            &[], // External groups don't have member changes
            &[], // External groups don't have member changes
            mcast.groups.get_mut(&group_ip).unwrap(),
            new_group_info.sources.as_deref(), // New sources that might need rollback
        )
        .ok(); // Ignore rollback errors, return original error

        return Err(e);
    }

    // Update NAT target references if NAT target changed
    if let Some(old_nat_target) = group_entry.int_fwding.nat_target {
        if old_nat_target.internal_ip != new_group_info.nat_target.internal_ip {
            // Remove old reference
            mcast.remove_nat_target_ref(
                group_ip,
                old_nat_target.internal_ip.into(),
            );
            // Add new reference
            mcast.add_nat_target_ref(
                group_ip,
                new_group_info.nat_target.internal_ip.into(),
            );
        }
    }

    // Update the external group fields
    group_entry.tag = new_group_info.tag.or(group_entry.tag.clone());
    group_entry.int_fwding.nat_target = Some(new_group_info.nat_target);
    group_entry.ext_fwding.vlan_id =
        new_group_info.vlan_id.or(group_entry.ext_fwding.vlan_id);
    group_entry.sources =
        new_group_info.sources.or(group_entry.sources.clone());

    let response = MulticastGroupResponse::new(group_ip, &group_entry);
    mcast.groups.insert(group_ip, group_entry);

    Ok(response)
}

pub(crate) fn modify_group_internal(
    s: &Switch,
    group_ip: IpAddr,
    new_group_info: MulticastGroupUpdateEntry,
) -> DpdResult<MulticastGroupResponse> {
    modify_group_internal_only(s, group_ip, new_group_info)
}

/// Modify an internal multicast group configuration.
fn modify_group_internal_only(
    s: &Switch,
    group_ip: IpAddr,
    new_group_info: MulticastGroupUpdateEntry,
) -> DpdResult<MulticastGroupResponse> {
    let mut mcast = s.mcast.lock().unwrap();

    if !mcast.groups.contains_key(&group_ip) {
        return Err(DpdError::Missing(format!(
            "Multicast group for IP {} not found",
            group_ip
        )));
    }

    let mut group_entry = mcast.groups.remove(&group_ip).unwrap();

    let (sources, sources_diff) = validate_sources_update(
        group_ip,
        new_group_info.sources.clone(),
        &group_entry,
        &mut mcast,
    )?;

    let replication_info =
        if let Some(existing_replication) = &group_entry.replication_info {
            Some(MulticastReplicationInfo {
                rid: existing_replication.rid,
                level1_excl_id: new_group_info
                    .replication_info
                    .level1_excl_id
                    .unwrap_or(existing_replication.level1_excl_id),
                level2_excl_id: new_group_info
                    .replication_info
                    .level2_excl_id
                    .unwrap_or(existing_replication.level2_excl_id),
            })
        } else {
            None
        };

    let (added_members, removed_members) =
        if let Some(ref repl_info) = replication_info {
            process_membership_changes(
                s,
                group_ip,
                &new_group_info.members,
                &mut group_entry,
                repl_info,
                &mut mcast,
            )?
        } else {
            (Vec::new(), Vec::new())
        };

    if let Some(ref repl_info) = replication_info {
        if let Err(e) = update_group_tables(
            s,
            group_ip,
            &group_entry,
            repl_info,
            &sources,
            &group_entry.sources,
        ) {
            mcast.groups.insert(group_ip, group_entry);

            rollback_on_group_update(
                s,
                group_ip,
                &added_members,
                &removed_members,
                mcast.groups.get_mut(&group_ip).unwrap(),
                sources_diff.then_some(sources.as_ref().unwrap()),
            )?;

            return Err(e);
        }
    }

    group_entry.tag = new_group_info.tag.or(group_entry.tag.clone());

    // Internal groups don't update NAT targets or VLANs - only update these fields:
    group_entry.sources = sources;
    group_entry.replication_info = replication_info;
    group_entry.members = new_group_info.members;

    let response = MulticastGroupResponse::new(group_ip, &group_entry);
    mcast.groups.insert(group_ip, group_entry);

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

    let groups_btree: BTreeMap<IpAddr, &MulticastGroup> = mcast
        .groups
        .iter()
        .map(|(ip, group)| (*ip, group))
        .collect();

    let lower_bound = match last {
        None => Bound::Unbounded,
        Some(last_ip) => Bound::Excluded(last_ip),
    };

    groups_btree
        .range((lower_bound, Bound::Unbounded))
        .filter_map(|(ip, group)| {
            if let Some(tag_filter) = tag {
                if group.tag.as_deref() != Some(tag_filter) {
                    return None;
                }
            }

            Some(MulticastGroupResponse::new(*ip, group))
        })
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
            .filter(|(_, group)| group.tag.as_deref() == Some(tag))
            .map(|(ip, _)| *ip)
            .collect::<Vec<_>>()
    };

    if groups_to_delete.is_empty() {
        return Ok(());
    }

    for group_ip in groups_to_delete {
        if let Err(e) = del_group(s, group_ip) {
            error!(
                s.log,
                "failed to delete multicast group for IP {}: {:?}", group_ip, e
            );
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
            .filter(|(_, group)| group.tag.is_none())
            .map(|(ip, _)| *ip)
            .collect::<Vec<_>>()
    };

    if groups_to_delete.is_empty() {
        return Ok(());
    }

    for group_ip in groups_to_delete {
        if let Err(e) = del_group(s, group_ip) {
            error!(
                s.log,
                "failed to delete multicast group for IP {}: {:?}", group_ip, e
            );
        }
    }

    Ok(())
}

/// Reset all multicast groups (and associated routes).
pub(crate) fn reset(s: &Switch) -> DpdResult<()> {
    let group_ids = s.asic_hdl.mc_domains();

    for group_id in group_ids {
        if let Err(e) = s.asic_hdl.mc_group_destroy(group_id) {
            error!(
                s.log,
                "failed to delete multicast group with ID {}: {:?}",
                group_id,
                e
            );
        }
    }

    let mut mcast = s.mcast.lock().unwrap();
    table::mcast::mcast_replication::reset_ipv6(s)?;
    table::mcast::mcast_src_filter::reset_ipv4(s)?;
    table::mcast::mcast_src_filter::reset_ipv6(s)?;
    table::mcast::mcast_nat::reset_ipv4(s)?;
    table::mcast::mcast_nat::reset_ipv6(s)?;
    table::mcast::mcast_route::reset_ipv4(s)?;
    table::mcast::mcast_route::reset_ipv6(s)?;
    table::mcast::mcast_egress::reset_bitmap_table(s)?;
    mcast.groups.clear();
    mcast.nat_target_refs.clear();

    Ok(())
}

fn remove_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => remove_ipv4_source_filters(s, ipv4, sources)?,
        IpAddr::V6(ipv6) => remove_ipv6_source_filters(s, ipv6, sources)?,
    }

    Ok(())
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

fn add_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    if let Some(srcs) = sources {
        match group_ip {
            IpAddr::V4(ipv4) => add_ipv4_source_filters(s, srcs, ipv4)?,
            IpAddr::V6(ipv6) => add_ipv6_source_filters(s, srcs, ipv6)?,
        }
    }

    Ok(())
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
    group_ip: IpAddr,
    group_info: &MulticastGroupCreateEntry,
) -> DpdResult<()> {
    validate_group_exists(mcast, group_ip)?;
    validate_multicast_address(group_ip, group_info.sources.as_deref())?;
    // Internal API is only for admin-scoped IPv6 groups
    if group_ip.is_ipv4() {
        return Err(DpdError::Invalid(
            "IPv4 multicast groups must use the external API (/multicast/groups/external)".to_string(),
        ));
    }

    let ipv6 = match group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => unreachable!("Already checked above"),
    };

    if !Ipv6Net::new_unchecked(ipv6, 128).is_admin_scoped_multicast() {
        return Err(DpdError::Invalid(format!(
            "Non-admin-scoped IPv6 multicast groups must use the external API (/multicast/groups/external). Address {} is not admin-scoped (ff04::/16, ff05::/16, ff08::/16)",
            group_ip
        )));
    }

    Ok(())
}

fn validate_external_group_creation(
    mcast: &MulticastGroupData,
    group_ip: IpAddr,
    group_info: &MulticastGroupCreateExternalEntry,
) -> DpdResult<()> {
    validate_group_exists(mcast, group_ip)?;
    validate_multicast_address(group_ip, group_info.sources.as_deref())?;
    validate_not_admin_scoped_ipv6(group_ip)?;
    Ok(())
}

fn validate_group_exists(
    mcast: &MulticastGroupData,
    group_ip: IpAddr,
) -> DpdResult<()> {
    if mcast.groups.contains_key(&group_ip) {
        return Err(DpdError::Invalid(format!(
            "multicast group for IP {} already exists",
            group_ip
        )));
    }
    Ok(())
}

fn validate_sources_update(
    group_ip: IpAddr,
    new_sources: Option<Vec<IpSrc>>,
    group_entry: &MulticastGroup,
    mcast: &mut MulticastGroupData,
) -> DpdResult<(Option<Vec<IpSrc>>, bool)> {
    if let Some(new_srcs) = new_sources {
        if is_ssm(group_ip) && new_srcs.is_empty() {
            mcast.groups.insert(group_ip, group_entry.clone());
            return Err(DpdError::Invalid(format!(
                "IP {} is a Source-Specific Multicast address and requires at least one source to be defined",
                group_ip
            )));
        }
        Ok((Some(new_srcs), true))
    } else {
        Ok((group_entry.sources.clone(), false))
    }
}

fn configure_external_tables(
    s: &Switch,
    group_info: &MulticastGroupCreateExternalEntry,
) -> DpdResult<()> {
    let group_ip = group_info.group_ip;
    let nat_target = group_info.nat_target;

    // Add source filter entries if needed
    let mut res = if let Some(srcs) = &group_info.sources {
        match group_ip {
            IpAddr::V4(ipv4) => add_ipv4_source_filters(s, srcs, ipv4),
            IpAddr::V6(ipv6) => add_ipv6_source_filters(s, srcs, ipv6),
        }
    } else {
        Ok(())
    };

    // Add NAT entry
    if res.is_ok() {
        res = match group_ip {
            IpAddr::V4(ipv4) => {
                table::mcast::mcast_nat::add_ipv4_entry(s, ipv4, nat_target)
            }
            IpAddr::V6(ipv6) => {
                table::mcast::mcast_nat::add_ipv6_entry(s, ipv6, nat_target)
            }
        };
    }

    // Add routing entry
    if res.is_ok() {
        res = match group_ip {
            IpAddr::V4(ipv4) => table::mcast::mcast_route::add_ipv4_entry(
                s,
                ipv4,
                group_info.vlan_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::mcast_route::add_ipv6_entry(
                s,
                ipv6,
                group_info.vlan_id,
            ),
        };
    }

    res
}

fn create_multicast_group_ids(
    s: &Switch,
    mcast: &MulticastGroupData,
    group_ip: Ipv6Addr,
    group_info: &MulticastGroupCreateEntry,
) -> DpdResult<(Option<MulticastGroupId>, Option<MulticastGroupId>)> {
    let mut external_group_id = None;
    let mut underlay_group_id = None;

    let has_external_member = group_info
        .members
        .iter()
        .any(|m| m.direction == Direction::External);
    let has_underlay_member = group_info
        .members
        .iter()
        .any(|m| m.direction == Direction::Underlay);

    if !has_external_member && !has_underlay_member {
        return Err(DpdError::Invalid(format!(
            "multicast group for admin-scoped IP {} must have at least one external/underlay member",
            group_ip
        )));
    }

    debug!(s.log, "creating multicast group IDs for IP {}", group_ip);

    if has_external_member {
        let group_id = mcast.generate_group_id()?;
        create_asic_group(s, group_id, group_ip.into())?;
        external_group_id = Some(group_id);
    }

    if has_underlay_member {
        let group_id = mcast.generate_group_id()?;
        create_asic_group(s, group_id, group_ip.into())?;
        underlay_group_id = Some(group_id);
    }
    Ok((external_group_id, underlay_group_id))
}

fn delete_multicast_groups(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
) -> DpdResult<()> {
    if let Some(external_id) = external_group_id {
        s.asic_hdl.mc_group_destroy(external_id).map_err(|e| {
            DpdError::McastGroupFailure(format!(
                "failed to delete external multicast group for IP {} with ID {}: {:?}",
                group_ip, external_id, e
            ))
        })?;
    }

    if let Some(underlay_id) = underlay_group_id {
        s.asic_hdl.mc_group_destroy(underlay_id).map_err(|e| {
            DpdError::McastGroupFailure(format!(
                "failed to delete underlay multicast group for IP {} with ID {}: {:?}",
                group_ip, underlay_id, e
            ))
        })?;
    }

    Ok(())
}

fn create_asic_group(
    s: &Switch,
    group_id: u16,
    group_ip: IpAddr,
) -> DpdResult<()> {
    s.asic_hdl
        .mc_group_create(group_id)
        .map_err(|e: AsicError| {
            DpdError::McastGroupFailure(format!(
                "failed to create multicast group for IP {} with ID {}: {:?}",
                group_ip, group_id, e
            ))
        })
}

fn add_ports_to_groups(
    s: &Switch,
    group_ip: IpAddr,
    members: &[MulticastGroupMember],
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
    replication_info: &MulticastReplicationInfo,
    added_members: &mut Vec<(PortId, LinkId, Direction)>,
) -> DpdResult<()> {
    for member in members {
        let group_id = match member.direction {
            Direction::External => external_group_id,
            Direction::Underlay => underlay_group_id,
        };

        let Some(group_id) = group_id else {
            continue;
        };

        let asic_id = s
            .port_link_to_asic_id(member.port_id, member.link_id)
            .inspect_err(|_e| {
                rollback_on_group_create(
                    s,
                    group_ip,
                    (external_group_id, underlay_group_id),
                    added_members,
                    replication_info,
                    None,
                    None,
                )
                .ok();
            })?;

        s.asic_hdl
            .mc_port_add(
                group_id,
                asic_id,
                replication_info.rid,
                replication_info.level1_excl_id,
            )
            .map_err(|e| {
                rollback_on_group_create(
                    s,
                    group_ip,
                    (external_group_id, underlay_group_id),
                    added_members,
                    replication_info,
                    None,
                    None,
                )
                .ok();

                DpdError::McastGroupFailure(format!(
                    "failed to add port {} to group for IP {}: {:?}",
                    member.port_id, group_ip, e
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
    mcast: &mut MulticastGroupData,
) -> DpdResult<(Vec<MulticastGroupMember>, Vec<MulticastGroupMember>)> {
    // First validate that IPv4 doesn't have underlay members
    if group_ip.is_ipv4()
        && new_members
            .iter()
            .any(|m| m.direction == Direction::Underlay)
    {
        mcast.groups.insert(group_ip, group_entry.clone());
        return Err(DpdError::Invalid(format!(
            "multicast group for IPv4 {} cannot have underlay members",
            group_ip
        )));
    }

    let prev_members =
        group_entry.members.iter().cloned().collect::<HashSet<_>>();
    let new_members_set = new_members.iter().cloned().collect::<HashSet<_>>();

    let mut added_members = Vec::new();
    let mut removed_members = Vec::new();

    for member in prev_members.difference(&new_members_set) {
        let group_id = match member.direction {
            Direction::External => group_entry.external_group_id,
            Direction::Underlay => group_entry.underlay_group_id,
        };

        let Some(group_id) = group_id else {
            continue;
        };

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;
        s.asic_hdl.mc_port_remove(group_id, asic_id)?;

        removed_members.push(member.clone());
    }

    ensure_external_group_exists(
        s,
        group_ip,
        &new_members_set,
        group_entry,
        mcast,
    )?;

    if group_ip.is_ipv6() {
        ensure_underlay_group_exists(
            s,
            group_ip,
            &new_members_set,
            group_entry,
            mcast,
        )?;
    }

    for member in new_members_set.difference(&prev_members) {
        if group_ip.is_ipv4() && member.direction == Direction::Underlay {
            continue;
        }

        let group_id = match member.direction {
            Direction::External => group_entry.external_group_id,
            Direction::Underlay => group_entry.underlay_group_id,
        };

        let Some(group_id) = group_id else {
            continue;
        };

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;
        s.asic_hdl.mc_port_add(
            group_id,
            asic_id,
            replication_info.rid,
            replication_info.level1_excl_id,
        )?;
        added_members.push(member.clone());
    }

    Ok((added_members, removed_members))
}

fn ensure_external_group_exists(
    s: &Switch,
    group_ip: IpAddr,
    members: &HashSet<MulticastGroupMember>,
    group_entry: &mut MulticastGroup,
    mcast: &mut MulticastGroupData,
) -> DpdResult<()> {
    if group_entry.external_group_id.is_none()
        && members.iter().any(|m| m.direction == Direction::External)
    {
        let group_id = mcast.generate_group_id()?;
        create_asic_group(s, group_id, group_ip)?;

        group_entry.external_group_id = Some(group_id);
        mcast.used_group_ids.insert(group_id);
    }

    Ok(())
}

fn ensure_underlay_group_exists(
    s: &Switch,
    group_ip: IpAddr,
    members: &HashSet<MulticastGroupMember>,
    group_entry: &mut MulticastGroup,
    mcast: &mut MulticastGroupData,
) -> DpdResult<()> {
    if group_entry.underlay_group_id.is_none()
        && members.iter().any(|m| m.direction == Direction::Underlay)
    {
        let group_id = mcast.generate_group_id()?;
        create_asic_group(s, group_id, group_ip)?;

        group_entry.underlay_group_id = Some(group_id);
        mcast.used_group_ids.insert(group_id);
    }

    Ok(())
}

fn configure_replication(
    group_info: &MulticastGroupCreateEntry,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
) -> MulticastReplicationInfo {
    let (level1_excl_id, level2_excl_id) = (
        group_info.replication_info.level1_excl_id.unwrap_or(0),
        group_info.replication_info.level2_excl_id.unwrap_or(0),
    );

    let rid = external_group_id.or(underlay_group_id).unwrap();

    MulticastReplicationInfo {
        rid,
        level1_excl_id,
        level2_excl_id,
    }
}

fn configure_internal_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
    replication_info: Option<&MulticastReplicationInfo>,
    group_info: &MulticastGroupCreateEntry,
    added_members: &[(PortId, LinkId, Direction)],
    vlan_id: Option<u16>, // VLAN ID from referencing external group
) -> DpdResult<()> {
    let res = match (group_ip, replication_info) {
        // Note: There are no internal IPv4 groups, only external IPv4 groups
        (IpAddr::V4(_), _) => {
            return Err(DpdError::Invalid(
                "IPv4 groups cannot be created as internal groups".to_string(),
            ));
        }

        (IpAddr::V6(ipv6), Some(replication_info)) => {
            let mut res = table::mcast::mcast_replication::add_ipv6_entry(
                s,
                ipv6,
                underlay_group_id,
                external_group_id,
                replication_info.rid,
                replication_info.level1_excl_id,
                replication_info.level2_excl_id,
            );

            if res.is_ok() {
                if let Some(srcs) = &group_info.sources {
                    res = add_ipv6_source_filters(s, srcs, ipv6);
                }
            }

            if res.is_ok() {
                res = table::mcast::mcast_route::add_ipv6_entry(
                    s, ipv6,
                    vlan_id, // VLAN from referencing external group
                );
            }

            if res.is_ok()
                && external_group_id.is_some()
                && underlay_group_id.is_some()
            {
                let mut port_bitmap =
                    table::mcast::mcast_egress::PortBitmap::new();
                for (port_id, _link_id, direction) in added_members {
                    if *direction == Direction::External {
                        let port_number = port_id.as_u8();
                        port_bitmap.add_port(port_number);
                    }
                }

                res = table::mcast::mcast_egress::add_bitmap_entry(
                    s,
                    external_group_id.unwrap(),
                    &port_bitmap,
                    vlan_id, // VLAN from referencing external group
                );
            }

            res
        }

        (IpAddr::V6(_), None) => {
            return Err(DpdError::Invalid(
                "Internal, admin-scoped IPv6 groups must have replication info"
                    .to_string(),
            ));
        }
    };

    if let Err(e) = res {
        if let Some(replication_info) = replication_info {
            rollback_on_group_create(
                s,
                group_ip,
                (external_group_id, underlay_group_id),
                added_members,
                replication_info,
                None, // Internal groups don't have NAT targets
                group_info.sources.as_deref(),
            )?;
        }
        return Err(e);
    }

    Ok(())
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
                group_entry.external_group_id,
                group_entry.underlay_group_id,
                replication_info,
            )?;
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
    if Some(new_group_info.nat_target) != group_entry.int_fwding.nat_target {
        update_nat_tables(
            s,
            group_ip,
            Some(new_group_info.nat_target),
            group_entry.int_fwding.nat_target,
        )?;
    }

    // Update VLAN if it changed
    if new_group_info.vlan_id != group_entry.ext_fwding.vlan_id {
        match group_ip {
            IpAddr::V4(ipv4) => table::mcast::mcast_route::update_ipv4_entry(
                s,
                ipv4,
                new_group_info.vlan_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::mcast_route::update_ipv6_entry(
                s,
                ipv6,
                new_group_info.vlan_id,
            ),
        }?;
    }

    Ok(())
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

            table::mcast::mcast_route::del_ipv4_entry(s, ipv4)?;
        }
        IpAddr::V6(ipv6) => {
            if group.external_group_id.is_some()
                && group.underlay_group_id.is_some()
            {
                table::mcast::mcast_egress::del_bitmap_entry(
                    s,
                    group.external_group_id.unwrap(),
                )?;
            }

            table::mcast::mcast_replication::del_ipv6_entry(s, ipv6)?;

            remove_ipv6_source_filters(s, ipv6, group.sources.as_deref())?;

            if group.int_fwding.nat_target.is_some() {
                table::mcast::mcast_nat::del_ipv6_entry(s, ipv6)?;
            }

            table::mcast::mcast_route::del_ipv6_entry(s, ipv6)?;
        }
    }

    Ok(())
}

fn update_replication_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
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
        (IpAddr::V4(ipv4), Some(nat), _) => {
            table::mcast::mcast_nat::update_ipv4_entry(s, ipv4, nat)
        }
        (IpAddr::V6(ipv6), Some(nat), _) => {
            table::mcast::mcast_nat::update_ipv6_entry(s, ipv6, nat)
        }
        (IpAddr::V4(ipv4), None, Some(_)) => {
            table::mcast::mcast_nat::del_ipv4_entry(s, ipv4)
        }
        (IpAddr::V6(ipv6), None, Some(_)) => {
            table::mcast::mcast_nat::del_ipv6_entry(s, ipv6)
        }
        _ => Ok(()),
    }
}

fn update_fwding_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
    members: &[MulticastGroupMember],
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => {
            table::mcast::mcast_route::update_ipv4_entry(s, ipv4, vlan_id)
        }
        IpAddr::V6(ipv6) => {
            let mut res =
                table::mcast::mcast_route::update_ipv6_entry(s, ipv6, vlan_id);

            if res.is_ok()
                && external_group_id.is_some()
                && underlay_group_id.is_some()
            {
                let mut port_bitmap =
                    table::mcast::mcast_egress::PortBitmap::new();

                for member in members {
                    if member.direction == Direction::External {
                        port_bitmap.add_port(member.port_id.as_u8());
                    }
                }

                res = table::mcast::mcast_egress::update_bitmap_entry(
                    s,
                    external_group_id.unwrap(),
                    &port_bitmap,
                    vlan_id,
                );
            }

            res
        }
    }
}

/// Rollback function for a multicast group creation failure.
///
/// Cleans up all resources created during a failed multicast group creation.
///
/// This function is reused for both external and internal group failures.
fn rollback_on_group_create(
    s: &Switch,
    group_ip: IpAddr,
    group_ids: (Option<MulticastGroupId>, Option<MulticastGroupId>),
    added_members: &[(PortId, LinkId, Direction)],
    replication_info: &MulticastReplicationInfo,
    nat_target: Option<NatTarget>,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    debug!(
        s.log,
        "rolling back multicast group creation for IP {}", group_ip
    );

    let (external_group_id, underlay_group_id) = group_ids;

    let mut contains_errors = false;

    let added_members_converted: Vec<MulticastGroupMember> = added_members
        .iter()
        .map(|(port_id, link_id, direction)| MulticastGroupMember {
            port_id: *port_id,
            link_id: *link_id,
            direction: *direction,
        })
        .collect();

    if let Err(e) = rollback_ports(
        s,
        &added_members_converted,
        &[],
        replication_info,
        external_group_id,
        underlay_group_id,
    ) {
        error!(s.log, "error removing ports during rollback: {:?}", e);
        contains_errors = true;
    }

    if let Err(e) = rollback_remove_groups(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
    ) {
        error!(s.log, "error deleting groups during rollback: {:?}", e);
        contains_errors = true;
    }

    if let Err(e) = rollback_remove_tables(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
        nat_target,
        sources,
    ) {
        error!(
            s.log,
            "Error deleting table entries during rollback: {:?}", e
        );
        contains_errors = true;
    }

    if contains_errors {
        error!(s.log, "rollback completed with errors for IP {}", group_ip);
    } else {
        debug!(
            s.log,
            "successfully rolled back multicast group creation for IP {}",
            group_ip
        );
    }

    Ok(())
}

/// Rollback function for a multicast group modification if it fails on updates.
///
/// Restores the group to its original state.
///
/// This function is reused for both external and internal group modifications.
fn rollback_on_group_update(
    s: &Switch,
    group_ip: IpAddr,
    added_ports: &[MulticastGroupMember],
    removed_ports: &[MulticastGroupMember],
    orig_group_info: &MulticastGroup,
    new_sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    debug!(
        s.log,
        "rolling back multicast group update for IP {}", group_ip
    );

    let mut contains_errors = false;

    if let Some(replication_info) = &orig_group_info.replication_info {
        if let Err(e) = rollback_ports(
            s,
            added_ports,
            removed_ports,
            replication_info,
            orig_group_info.external_group_id,
            orig_group_info.underlay_group_id,
        ) {
            error!(
                s.log,
                "error handling ports during update rollback: {:?}", e
            );
            contains_errors = true;
        }
    }

    if new_sources.is_some() {
        if let Err(e) = rollback_source_filters(
            s,
            group_ip,
            new_sources,
            orig_group_info.sources.as_deref(),
        ) {
            error!(
                s.log,
                "error restoring source filters during update rollback: {:?}",
                e
            );
            contains_errors = true;
        }
    }

    if let Err(e) = rollback_restore_tables(s, group_ip, orig_group_info) {
        error!(
            s.log,
            "error restoring table entries during update rollback: {:?}", e
        );
        contains_errors = true;
    }

    if contains_errors {
        error!(
            s.log,
            "update rollback completed with errors for IP {}", group_ip
        );
    } else {
        debug!(
            s.log,
            "successfully rolled back multicast group update for IP {}",
            group_ip
        );
    }

    Ok(())
}

fn rollback_ports(
    s: &Switch,
    added_ports: &[MulticastGroupMember],
    removed_ports: &[MulticastGroupMember],
    replication_info: &MulticastReplicationInfo,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
) -> DpdResult<()> {
    for member in added_ports {
        let group_id = match member.direction {
            Direction::External => external_group_id,
            Direction::Underlay => underlay_group_id,
        };

        if group_id.is_none() {
            continue;
        }

        match s.port_link_to_asic_id(member.port_id, member.link_id) {
            Ok(asic_id) => {
                if let Err(e) =
                    s.asic_hdl.mc_port_remove(group_id.unwrap(), asic_id)
                {
                    debug!(
                        s.log,
                        "failed to remove port during rollback: port={}, link={}, error={:?}",
                        member.port_id, member.link_id, e
                    );
                }
            }
            Err(e) => {
                debug!(
                    s.log,
                    "failed to get ASIC ID for port during rollback: port={}, link={}, error={:?}",
                    member.port_id, member.link_id, e
                );
            }
        }
    }

    for member in removed_ports {
        let group_id = match member.direction {
            Direction::External => external_group_id,
            Direction::Underlay => underlay_group_id,
        };

        if group_id.is_none() {
            continue;
        }

        match s.port_link_to_asic_id(member.port_id, member.link_id) {
            Ok(asic_id) => {
                if let Err(e) = s.asic_hdl.mc_port_add(
                    group_id.unwrap(),
                    asic_id,
                    replication_info.rid,
                    replication_info.level1_excl_id,
                ) {
                    debug!(
                        s.log,
                        "failed to restore port during rollback: port={}, link={}, error={:?}",
                        member.port_id, member.link_id, e
                    );
                }
            }
            Err(e) => {
                debug!(
                    s.log,
                    "failed to get ASIC ID for port during rollback: port={}, link={}, error={:?}",
                    member.port_id, member.link_id, e
                );
            }
        }
    }

    Ok(())
}

fn rollback_remove_groups(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
) -> DpdResult<()> {
    if let Some(external_id) = external_group_id {
        if let Err(e) = s.asic_hdl.mc_group_destroy(external_id) {
            debug!(
                s.log,
                "failed to remove external multicast group for IP {} with ID {} during rollback: {:?}",
                group_ip, external_id, e
            );
        }
    }

    if let Some(underlay_id) = underlay_group_id {
        if let Err(e) = s.asic_hdl.mc_group_destroy(underlay_id) {
            debug!(
                s.log,
                "failed to remove underlay multicast group for IP {} with ID {} during rollback: {:?}",
                group_ip, underlay_id, e
            );
        }
    }

    Ok(())
}

fn rollback_remove_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
    nat_target: Option<NatTarget>,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => {
            if let Some(srcs) = sources {
                for src in srcs {
                    match src {
                        IpSrc::Exact(IpAddr::V4(src)) => {
                            if let Err(e) =
                                table::mcast::mcast_src_filter::del_ipv4_entry(
                                    s,
                                    Ipv4Net::new(*src, 32).unwrap(),
                                    ipv4,
                                )
                            {
                                debug!(s.log, "failed to remove IPv4 source filter during rollback: {:?}", e);
                            }
                        }
                        IpSrc::Subnet(subnet) => {
                            if let Err(e) =
                                table::mcast::mcast_src_filter::del_ipv4_entry(
                                    s, *subnet, ipv4,
                                )
                            {
                                debug!(s.log, "failed to remove IPv4 subnet filter during rollback: {:?}", e);
                            }
                        }
                        _ => {}
                    }
                }
            }

            if nat_target.is_some() {
                if let Err(e) = table::mcast::mcast_nat::del_ipv4_entry(s, ipv4)
                {
                    debug!(
                        s.log,
                        "failed to remove IPv4 NAT entry during rollback: {:?}",
                        e
                    );
                }
            }

            if let Err(e) = table::mcast::mcast_route::del_ipv4_entry(s, ipv4) {
                debug!(
                    s.log,
                    "failed to remove IPv4 route entry during rollback: {:?}",
                    e
                );
            }
        }
        IpAddr::V6(ipv6) => {
            if external_group_id.is_some() && underlay_group_id.is_some() {
                if let Err(e) = table::mcast::mcast_egress::del_bitmap_entry(
                    s,
                    external_group_id.unwrap(),
                ) {
                    debug!(s.log, "failed to remove external egress entry during rollback: {:?}", e);
                }
            }

            if let Err(e) =
                table::mcast::mcast_replication::del_ipv6_entry(s, ipv6)
            {
                debug!(s.log, "failed to remove IPv6 replication entry during rollback: {:?}", e);
            }

            if let Some(srcs) = sources {
                for src in srcs {
                    if let IpSrc::Exact(IpAddr::V6(src)) = src {
                        if let Err(e) =
                            table::mcast::mcast_src_filter::del_ipv6_entry(
                                s, *src, ipv6,
                            )
                        {
                            debug!(s.log, "failed to remove IPv6 source filter during rollback: {:?}", e);
                        }
                    }
                }
            }

            if nat_target.is_some() {
                if let Err(e) = table::mcast::mcast_nat::del_ipv6_entry(s, ipv6)
                {
                    debug!(
                        s.log,
                        "failed to remove IPv6 NAT entry during rollback: {:?}",
                        e
                    );
                }
            }

            if let Err(e) = table::mcast::mcast_route::del_ipv6_entry(s, ipv6) {
                debug!(
                    s.log,
                    "failed to remove IPv6 route entry during rollback: {:?}",
                    e
                );
            }
        }
    }

    Ok(())
}

fn rollback_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    new_sources: Option<&[IpSrc]>,
    orig_sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    if let Err(e) = remove_source_filters(s, group_ip, new_sources) {
        debug!(
            s.log,
            "failed to remove new source filters during rollback: {:?}", e
        );
    }

    if let Err(e) = add_source_filters(s, group_ip, orig_sources) {
        debug!(
            s.log,
            "failed to restore original source filters during rollback: {:?}",
            e
        );
    }

    Ok(())
}

fn rollback_restore_tables(
    s: &Switch,
    group_ip: IpAddr,
    orig_group_info: &MulticastGroup,
) -> DpdResult<()> {
    let external_group_id = orig_group_info.external_group_id;
    let underlay_group_id = orig_group_info.underlay_group_id;
    let replication_info = &orig_group_info.replication_info;
    let vlan_id = orig_group_info.ext_fwding.vlan_id;
    let nat_target = orig_group_info.int_fwding.nat_target;
    let prev_members = orig_group_info.members.to_vec();

    if let Some(replication_info) = replication_info {
        if let Err(e) = update_replication_tables(
            s,
            group_ip,
            external_group_id,
            underlay_group_id,
            replication_info,
        ) {
            debug!(
                s.log,
                "failed to restore replication settings during rollback: {:?}",
                e
            );
        }
    }

    match group_ip {
        IpAddr::V4(ipv4) => rollback_restore_nat_v4(s, ipv4, nat_target),
        IpAddr::V6(ipv6) => rollback_restore_nat_v6(s, ipv6, nat_target),
    }

    if let Err(e) = update_fwding_tables(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
        &prev_members,
        vlan_id,
    ) {
        debug!(
            s.log,
            "failed to restore VLAN settings during rollback: {:?}", e
        );
    }

    Ok(())
}

fn rollback_restore_nat_v4(
    s: &Switch,
    ipv4: Ipv4Addr,
    nat_target: Option<NatTarget>,
) {
    if let Some(nat) = nat_target {
        if let Err(e) = table::mcast::mcast_nat::update_ipv4_entry(s, ipv4, nat)
        {
            debug!(
                s.log,
                "failed to restore IPv4 NAT settings during rollback: {:?}", e
            );
        }
    } else if let Err(e) = table::mcast::mcast_nat::del_ipv4_entry(s, ipv4) {
        debug!(
            s.log,
            "failed to remove IPv4 NAT entry during rollback: {:?}", e
        );
    }
}

fn rollback_restore_nat_v6(
    s: &Switch,
    ipv6: Ipv6Addr,
    nat_target: Option<NatTarget>,
) {
    if let Some(nat) = nat_target {
        if let Err(e) = table::mcast::mcast_nat::update_ipv6_entry(s, ipv6, nat)
        {
            debug!(
                s.log,
                "failed to restore IPv6 NAT settings during rollback: {:?}", e
            );
        }
    } else if let Err(e) = table::mcast::mcast_nat::del_ipv6_entry(s, ipv6) {
        debug!(
            s.log,
            "failed to remove IPv6 NAT entry during rollback: {:?}", e
        );
    }
}
