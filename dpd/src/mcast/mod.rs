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
use oxnet::Ipv4Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, error};

mod validate;
use validate::{is_ssm, validate_multicast_address, validate_nat_target};

/// Type alias for multicast group IDs.
pub(crate) type MulticastGroupId = u16;

/// Source filter match key for IPv4 multicast traffic.
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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
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
    pub(crate) replication_info: MulticastReplicationInfo,
    pub(crate) members: Vec<MulticastGroupMember>,
}

/// A multicast group entry for POST requests.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastReplicationEntry {
    level1_excl_id: Option<u16>,
    level2_excl_id: Option<u16>,
}

/// A multicast group configuration for POST requests.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupCreateEntry {
    group_ip: IpAddr,
    tag: Option<String>,
    nat_target: Option<NatTarget>,
    vlan_id: Option<u16>,
    sources: Option<Vec<IpSrc>>,
    replication_info: MulticastReplicationEntry,
    members: Vec<MulticastGroupMember>,
}

/// A multicast group update entry for PUT requests.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupUpdateEntry {
    tag: Option<String>,
    nat_target: Option<NatTarget>,
    vlan_id: Option<u16>,
    sources: Option<Vec<IpSrc>>,
    replication_info: MulticastReplicationEntry,
    members: Vec<MulticastGroupMember>,
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
    replication_info: MulticastReplicationInfo,
    members: Vec<MulticastGroupMember>,
}

impl MulticastGroupResponse {
    fn new(group_ip: IpAddr, group: &MulticastGroup) -> Self {
        Self {
            group_ip,
            external_group_id: group.external_group_id,
            underlay_group_id: group.underlay_group_id,
            tag: group.tag.as_deref().map(str::to_owned),
            int_fwding: InternalForwarding {
                nat_target: group.int_fwding.nat_target,
            },
            ext_fwding: ExternalForwarding {
                vlan_id: group.ext_fwding.vlan_id,
            },
            sources: group.sources.clone(),
            replication_info: MulticastReplicationInfo {
                rid: group.replication_info.rid,
                level1_excl_id: group.replication_info.level1_excl_id,
                level2_excl_id: group.replication_info.level2_excl_id,
            },
            members: group.members.to_vec(),
        }
    }

    /// Get the multicast group IP address.
    pub(crate) fn ip(&self) -> IpAddr {
        self.group_ip
    }
}

/// Direction of multicast traffic, either underlay or external.
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
}

impl MulticastGroupData {
    const GENERATOR_START: u16 = 100;

    pub(crate) fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            // Start at a threshold to avoid early allocations
            id_generator: AtomicU16::new(Self::GENERATOR_START),
            used_group_ids: HashSet::new(),
        }
    }

    /// Generate a unique multicast group ID.
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
}

impl Default for MulticastGroupData {
    fn default() -> Self {
        Self::new()
    }
}

/// Add a multicast group to the switch, which creates the group on the ASIC and
/// associates it with a group IP address and updates associated tables for
/// multicast replication, NAT, and L3 routing.
///
/// If anything fails, the group is cleaned up and an error is returned.
pub(crate) fn add_group(
    s: &Switch,
    group_info: MulticastGroupCreateEntry,
) -> DpdResult<MulticastGroupResponse> {
    let mut mcast = s.mcast.lock().unwrap();
    let group_ip = group_info.group_ip;

    // Validate inputs
    validate_group_creation(&mcast, group_ip, &group_info)?;

    // Create multicast groups based on IP version
    let (external_group_id, underlay_group_id) =
        create_multicast_groups(s, &mut mcast, group_ip, &group_info)?;

    // Track added members for potential cleanup on errors
    let mut added_members = Vec::new();

    // Set up the replication configuration
    let replication_info = configure_replication(
        &group_info,
        external_group_id,
        underlay_group_id,
    );

    // Add ports to the multicast groups
    add_ports_to_groups(
        s,
        group_ip,
        &group_info.members,
        external_group_id,
        underlay_group_id,
        &replication_info,
        &mut added_members,
    )?;

    // Configure tables for the multicast group
    configure_tables(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
        &replication_info,
        &group_info,
        &added_members,
    )?;

    // Only store configuration if all operations succeeded
    let group = MulticastGroup {
        external_group_id,
        underlay_group_id,
        tag: group_info.tag,
        int_fwding: InternalForwarding {
            nat_target: group_info.nat_target,
        },
        ext_fwding: ExternalForwarding {
            vlan_id: group_info.vlan_id,
        },
        sources: group_info.sources,
        replication_info,
        members: group_info.members,
    };

    // Update the multicast data
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

    // Check if the group exists
    let group: MulticastGroup =
        mcast.groups.remove(&group_ip).ok_or_else(|| {
            DpdError::Missing(format!(
                "Multicast group for IP {} not found",
                group_ip
            ))
        })?;

    // Free up used group IDs
    if let Some(external_id) = group.external_group_id {
        mcast.used_group_ids.remove(&external_id);
    }

    if let Some(underlay_id) = group.underlay_group_id {
        mcast.used_group_ids.remove(&underlay_id);
    }

    // Release lock early to avoid potential deadlocks
    drop(mcast);

    debug!(s.log, "deleting multicast group for IP {}", group_ip);

    // Delete table entries first
    delete_group_tables(s, group_ip, &group)?;

    // Delete the multicast groups
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

/// Modify a multicast group configuration.
pub(crate) fn modify_group(
    s: &Switch,
    group_ip: IpAddr,
    new_group_info: MulticastGroupUpdateEntry,
) -> DpdResult<MulticastGroupResponse> {
    let mut mcast = s.mcast.lock().unwrap();

    // Check if group exists first
    if !mcast.groups.contains_key(&group_ip) {
        return Err(DpdError::Missing(format!(
            "Multicast group for IP {} not found",
            group_ip
        )));
    }

    // Remove the entry to work with it directly
    let mut group_entry = mcast.groups.remove(&group_ip).unwrap();

    // Validate sources for SSM
    let (sources, sources_diff) = validate_sources_update(
        group_ip,
        new_group_info.sources.clone(),
        &group_entry,
        &mut mcast,
    )?;

    // Update the replication configuration
    let replication_info = MulticastReplicationInfo {
        rid: group_entry.replication_info.rid,
        level1_excl_id: new_group_info
            .replication_info
            .level1_excl_id
            .unwrap_or(group_entry.replication_info.level1_excl_id),
        level2_excl_id: new_group_info
            .replication_info
            .level2_excl_id
            .unwrap_or(group_entry.replication_info.level2_excl_id),
    };

    // Track member changes
    let (added_members, removed_members) = process_membership_changes(
        s,
        group_ip,
        &new_group_info.members,
        &mut group_entry,
        &replication_info,
        &mut mcast,
    )?;

    // Update table entries
    let res = update_group_tables(
        s,
        group_ip,
        &group_entry,
        &new_group_info,
        &replication_info,
        &sources,
        &group_entry.sources,
    );

    // Handle rollback on errors
    if let Err(e) = res {
        // Put the entry back before handling rollback
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

    // Update the group entry with the new values
    group_entry.tag = new_group_info.tag.or(group_entry.tag.clone());

    group_entry.int_fwding.nat_target = new_group_info
        .nat_target
        .or(group_entry.int_fwding.nat_target);

    group_entry.ext_fwding.vlan_id =
        new_group_info.vlan_id.or(group_entry.ext_fwding.vlan_id);

    group_entry.sources = sources;
    group_entry.replication_info = replication_info;
    group_entry.members = new_group_info.members;

    // Put the updated entry back into the map
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

    // Define the range bounds
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
    // Get groups to delete first while holding the lock
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

    // Delete each group (and associated routes)
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
    // Get groups to delete first while holding the lock
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

    // Delete each group (and associated routes)
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

    // Delete each group (and associated routes)
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

    // Clear what we've stored altogether
    let mut mcast = s.mcast.lock().unwrap();
    table::mcast::mcast_replication::reset_ipv4(s)?;
    table::mcast::mcast_replication::reset_ipv6(s)?;
    table::mcast::mcast_src_filter::reset_ipv4(s)?;
    table::mcast::mcast_src_filter::reset_ipv6(s)?;
    table::mcast::mcast_nat::reset_ipv4(s)?;
    table::mcast::mcast_nat::reset_ipv6(s)?;
    table::mcast::mcast_route::reset_ipv4(s)?;
    table::mcast::mcast_route::reset_ipv6(s)?;
    table::mcast::mcast_egress::reset_bitmap_table(s)?;
    mcast.groups.clear();

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

fn validate_group_creation(
    mcast: &MulticastGroupData,
    group_ip: IpAddr,
    group_info: &MulticastGroupCreateEntry,
) -> DpdResult<()> {
    // Check if the group already exists
    if mcast.groups.contains_key(&group_ip) {
        return Err(DpdError::Invalid(format!(
            "multicast group for IP {} already exists",
            group_ip
        )));
    }

    // Validate if the requested multicast address is allowed
    validate_multicast_address(group_ip, group_info.sources.as_deref())?;

    // Validate the NAT target if provided
    if let Some(nat_target) = group_info.nat_target {
        validate_nat_target(nat_target)?;
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
            // Put the entry back before returning error
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

fn create_multicast_groups(
    s: &Switch,
    mcast: &mut MulticastGroupData,
    group_ip: IpAddr,
    group_info: &MulticastGroupCreateEntry,
) -> DpdResult<(Option<MulticastGroupId>, Option<MulticastGroupId>)> {
    let mut external_group_id = None;
    let mut underlay_group_id = None;

    match group_ip {
        IpAddr::V4(_) => {
            // For IPv4, validate and create external group
            let has_external_member = group_info
                .members
                .iter()
                .any(|m| m.direction == Direction::External);
            let has_underlay_member = group_info
                .members
                .iter()
                .any(|m| m.direction == Direction::Underlay);

            if !has_external_member || has_underlay_member {
                return Err(DpdError::Invalid(format!(
            "multicast group for IP {} must have at least one external member and no underlay members",
            group_ip
        )));
            }

            debug!(s.log, "creating multicast group for IP {}", group_ip);

            let group_id = mcast.generate_group_id()?;
            create_asic_group(s, group_id, group_ip)?;

            external_group_id = Some(group_id);
        }
        IpAddr::V6(_) => {
            // For IPv6, create external and/or underlay groups as needed
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
            "multicast group for IP {} must have at least one external/underlay member",
            group_ip
        )));
            }

            debug!(s.log, "creating multicast group for IP {}", group_ip);

            if has_external_member {
                let group_id = mcast.generate_group_id()?;
                create_asic_group(s, group_id, group_ip)?;
                external_group_id = Some(group_id);
            }

            if has_underlay_member {
                let group_id = mcast.generate_group_id()?;
                create_asic_group(s, group_id, group_ip)?;
                underlay_group_id = Some(group_id);
            }
        }
    }

    Ok((external_group_id, underlay_group_id))
}

fn delete_multicast_groups(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
) -> DpdResult<()> {
    // Delete external group if it exists
    if let Some(external_id) = external_group_id {
        s.asic_hdl.mc_group_destroy(external_id).map_err(|e| {
            DpdError::McastGroupFailure(format!(
                "failed to delete external multicast group for IP {} with ID {}: {:?}",
                group_ip, external_id, e
            ))
        })?;
    }

    // Delete underlay group if it exists
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

        // Skip if no group exists for this direction
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

        // Track added members for cleanup
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
        // Return the group entry to the map before returning the error
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

    // Process removed ports
    for member in prev_members.difference(&new_members_set) {
        let group_id = match member.direction {
            Direction::External => group_entry.external_group_id,
            Direction::Underlay => group_entry.underlay_group_id,
        };

        // Skip if the group ID doesn't exist for this direction
        let Some(group_id) = group_id else {
            continue;
        };

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;
        s.asic_hdl.mc_port_remove(group_id, asic_id)?;

        removed_members.push(member.clone());
    }

    // Create external group ID if needed
    ensure_external_group_exists(
        s,
        group_ip,
        &new_members_set,
        group_entry,
        mcast,
    )?;

    // Create underlay group ID if needed - only for IPv6
    if group_ip.is_ipv6() {
        ensure_underlay_group_exists(
            s,
            group_ip,
            &new_members_set,
            group_entry,
            mcast,
        )?;
    }

    // Process added ports
    for member in new_members_set.difference(&prev_members) {
        // Double-check that we're not adding an underlay port to an IPv4 group
        if group_ip.is_ipv4() && member.direction == Direction::Underlay {
            continue;
        }

        let group_id = match member.direction {
            Direction::External => group_entry.external_group_id,
            Direction::Underlay => group_entry.underlay_group_id,
        };

        // Skip if the group ID doesn't exist for this direction
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
    // Create external group ID if needed
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
    // Create underlay group ID if needed
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
    let level1_excl_id =
        group_info.replication_info.level1_excl_id.unwrap_or(0);
    let level2_excl_id =
        group_info.replication_info.level2_excl_id.unwrap_or(0);

    // Use the external group ID if available, otherwise use the underlay group ID.
    //
    // We don't allow the API to set these IDs, so we can safely unwrap them.
    let rid = external_group_id.or(underlay_group_id).unwrap();

    MulticastReplicationInfo {
        rid,
        level1_excl_id,
        level2_excl_id,
    }
}

fn configure_tables(
    s: &Switch,
    group_ip: IpAddr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
    replication_info: &MulticastReplicationInfo,
    group_info: &MulticastGroupCreateEntry,
    added_members: &[(PortId, LinkId, Direction)],
) -> DpdResult<()> {
    let res = match group_ip {
        IpAddr::V4(ipv4) => configure_ipv4_tables(
            s,
            ipv4,
            external_group_id.unwrap(), // Safe to unwrap for IPv4
            replication_info,
            group_info,
        ),
        IpAddr::V6(ipv6) => configure_ipv6_tables(
            s,
            ipv6,
            external_group_id,
            underlay_group_id,
            replication_info,
            group_info,
            added_members,
        ),
    };

    if let Err(e) = res {
        rollback_on_group_create(
            s,
            group_ip,
            (external_group_id, underlay_group_id),
            added_members,
            replication_info,
            group_info.nat_target,
            group_info.sources.as_deref(),
        )?;
        return Err(e);
    }

    Ok(())
}

fn configure_ipv4_tables(
    s: &Switch,
    ipv4: Ipv4Addr,
    group_id: MulticastGroupId,
    replication_info: &MulticastReplicationInfo,
    group_info: &MulticastGroupCreateEntry,
) -> DpdResult<()> {
    // Add the multicast replication entry
    let mut res = table::mcast::mcast_replication::add_ipv4_entry(
        s,
        ipv4,
        group_id,
        replication_info.rid,
        replication_info.level1_excl_id,
        replication_info.level2_excl_id,
    );

    // Add source filter entries if needed
    if res.is_ok() {
        if let Some(srcs) = &group_info.sources {
            res = add_ipv4_source_filters(s, srcs, ipv4);
        }
    }

    // Add NAT entry if needed
    if res.is_ok() && group_info.nat_target.is_some() {
        res = table::mcast::mcast_nat::add_ipv4_entry(
            s,
            ipv4,
            group_info.nat_target.unwrap(),
        );
    }

    // Add route entry
    if res.is_ok() {
        res = table::mcast::mcast_route::add_ipv4_entry(
            s,
            ipv4,
            group_info.vlan_id,
        );
    }

    res
}

fn configure_ipv6_tables(
    s: &Switch,
    ipv6: Ipv6Addr,
    external_group_id: Option<MulticastGroupId>,
    underlay_group_id: Option<MulticastGroupId>,
    replication_info: &MulticastReplicationInfo,
    group_info: &MulticastGroupCreateEntry,
    added_members: &[(PortId, LinkId, Direction)],
) -> DpdResult<()> {
    // Add the multicast replication entry
    let mut res = table::mcast::mcast_replication::add_ipv6_entry(
        s,
        ipv6,
        external_group_id,
        underlay_group_id,
        replication_info.rid,
        replication_info.level1_excl_id,
        replication_info.level2_excl_id,
    );

    // Add source filter entries if needed
    if res.is_ok() {
        if let Some(srcs) = &group_info.sources {
            res = add_ipv6_source_filters(s, srcs, ipv6);
        }
    }

    // Add NAT entry if needed
    if res.is_ok() && group_info.nat_target.is_some() {
        res = table::mcast::mcast_nat::add_ipv6_entry(
            s,
            ipv6,
            group_info.nat_target.unwrap(),
        );
    }

    // Add route entry
    if res.is_ok() {
        res = table::mcast::mcast_route::add_ipv6_entry(
            s,
            ipv6,
            group_info.vlan_id,
        );
    }

    // Add egress entry for external group if needed
    if res.is_ok() && external_group_id.is_some() && underlay_group_id.is_some()
    {
        let mut port_bitmap = table::mcast::mcast_egress::PortBitmap::new();
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
            group_info.vlan_id,
        );
    }

    res
}

fn update_group_tables(
    s: &Switch,
    group_ip: IpAddr,
    group_entry: &MulticastGroup,
    new_group_info: &MulticastGroupUpdateEntry,
    replication_info: &MulticastReplicationInfo,
    new_sources: &Option<Vec<IpSrc>>,
    old_sources: &Option<Vec<IpSrc>>,
) -> DpdResult<()> {
    let mut res = Ok(());

    // Update replication settings if needed
    if replication_info.rid != group_entry.replication_info.rid
        || replication_info.level1_excl_id
            != group_entry.replication_info.level1_excl_id
        || replication_info.level2_excl_id
            != group_entry.replication_info.level2_excl_id
    {
        res = update_replication_tables(
            s,
            group_ip,
            group_entry.external_group_id,
            group_entry.underlay_group_id,
            replication_info,
        );
    }

    // Update source filters if needed
    if res.is_ok() && new_sources != old_sources {
        res = remove_source_filters(s, group_ip, old_sources.as_deref())
            .and_then(|_| {
                add_source_filters(s, group_ip, new_sources.as_deref())
            });
    }

    // Update NAT settings if needed
    if res.is_ok()
        && new_group_info.nat_target != group_entry.int_fwding.nat_target
    {
        res = update_nat_tables(
            s,
            group_ip,
            new_group_info.nat_target,
            group_entry.int_fwding.nat_target,
        );
    }

    // Update forwarding/VLAN settings if needed
    if res.is_ok() && new_group_info.vlan_id != group_entry.ext_fwding.vlan_id {
        res = update_fwding_tables(
            s,
            group_ip,
            group_entry.external_group_id,
            group_entry.underlay_group_id,
            &group_entry.members,
            new_group_info.vlan_id,
        );
    }

    res
}

fn delete_group_tables(
    s: &Switch,
    group_ip: IpAddr,
    group: &MulticastGroup,
) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => {
            // Delete replication entry
            table::mcast::mcast_replication::del_ipv4_entry(s, ipv4)?;

            // Delete source filter entries
            remove_ipv4_source_filters(s, ipv4, group.sources.as_deref())?;

            // Delete NAT entry if it exists
            if group.int_fwding.nat_target.is_some() {
                table::mcast::mcast_nat::del_ipv4_entry(s, ipv4)?;
            }

            // Delete route entry
            table::mcast::mcast_route::del_ipv4_entry(s, ipv4)?;
        }
        IpAddr::V6(ipv6) => {
            // Delete egress entries if they exist
            if group.external_group_id.is_some()
                && group.underlay_group_id.is_some()
            {
                table::mcast::mcast_egress::del_bitmap_entry(
                    s,
                    group.external_group_id.unwrap(),
                )?;
            }

            // Delete replication entry
            table::mcast::mcast_replication::del_ipv6_entry(s, ipv6)?;

            // Delete source filter entries
            remove_ipv6_source_filters(s, ipv6, group.sources.as_deref())?;

            // Delete NAT entry if it exists
            if group.int_fwding.nat_target.is_some() {
                table::mcast::mcast_nat::del_ipv6_entry(s, ipv6)?;
            }

            // Delete route entry
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
        IpAddr::V4(ipv4) => table::mcast::mcast_replication::update_ipv4_entry(
            s,
            ipv4,
            external_group_id.unwrap(),
            replication_info.rid,
            replication_info.level1_excl_id,
            replication_info.level2_excl_id,
        ),
        IpAddr::V6(ipv6) => table::mcast::mcast_replication::update_ipv6_entry(
            s,
            ipv6,
            external_group_id,
            underlay_group_id,
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
            // Update route entry
            table::mcast::mcast_route::update_ipv4_entry(s, ipv4, vlan_id)
        }
        IpAddr::V6(ipv6) => {
            // Update route entry
            let mut res =
                table::mcast::mcast_route::update_ipv6_entry(s, ipv6, vlan_id);

            // Update external egress entry if it exists
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

    // 1. Convert added_members to MulticastGroupMember format for rollback_ports
    let added_members_converted: Vec<MulticastGroupMember> = added_members
        .iter()
        .map(|(port_id, link_id, direction)| MulticastGroupMember {
            port_id: *port_id,
            link_id: *link_id,
            direction: *direction,
        })
        .collect();

    // 2. Remove all ports that were added
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

    // 3. Delete the multicast groups
    if let Err(e) = rollback_remove_groups(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
    ) {
        error!(s.log, "error deleting groups during rollback: {:?}", e);
        contains_errors = true;
    }

    // 4. Remove table entries
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

    // We still return Ok() because we want the original error to be returned to the caller,
    // not our rollback errors
    Ok(())
}

/// Rollback function for a multicast group modification if it fails on updates.
///
/// Restores the group to its original state.
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

    // 1. Handle port changes (remove added ports, restore removed ports)
    if let Err(e) = rollback_ports(
        s,
        added_ports,
        removed_ports,
        &orig_group_info.replication_info,
        orig_group_info.external_group_id,
        orig_group_info.underlay_group_id,
    ) {
        error!(
            s.log,
            "error handling ports during update rollback: {:?}", e
        );
        contains_errors = true;
    }

    // 2. Restore source filters if they were modified
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

    // 3. Restore other table entries
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
    // 1. Remove any ports that were added
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

    // 2. Restore any ports that were removed
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
    // Delete external group if it exists
    if let Some(external_id) = external_group_id {
        if let Err(e) = s.asic_hdl.mc_group_destroy(external_id) {
            debug!(
                s.log,
                "failed to remove external multicast group for IP {} with ID {} during rollback: {:?}",
                group_ip, external_id, e
            );
        }
    }

    // Delete underlay group if it exists
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
            // Try to delete replication entry
            if let Err(e) =
                table::mcast::mcast_replication::del_ipv4_entry(s, ipv4)
            {
                debug!(s.log, "failed to remove IPv4 replication entry during rollback: {:?}", e);
            }

            // Try to remove source filters
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

            // Try to delete NAT entry if it exists
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

            // Try to delete route entry
            if let Err(e) = table::mcast::mcast_route::del_ipv4_entry(s, ipv4) {
                debug!(
                    s.log,
                    "failed to remove IPv4 route entry during rollback: {:?}",
                    e
                );
            }
        }
        IpAddr::V6(ipv6) => {
            // Try to delete egress entries if they exist
            if external_group_id.is_some() && underlay_group_id.is_some() {
                if let Err(e) = table::mcast::mcast_egress::del_bitmap_entry(
                    s,
                    external_group_id.unwrap(),
                ) {
                    debug!(s.log, "failed to remove external egress entry during rollback: {:?}", e);
                }
            }

            // Try to delete replication entry
            if let Err(e) =
                table::mcast::mcast_replication::del_ipv6_entry(s, ipv6)
            {
                debug!(s.log, "failed to remove IPv6 replication entry during rollback: {:?}", e);
            }

            // Try to remove source filters
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

            // Try to delete NAT entry if it exists
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

            // Try to delete route entry
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
    // Remove the new source filters
    if let Err(e) = remove_source_filters(s, group_ip, new_sources) {
        debug!(
            s.log,
            "failed to remove new source filters during rollback: {:?}", e
        );
    }

    // Add back the original source filters
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

    // Restore replication settings
    if let Err(e) = update_replication_tables(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
        replication_info,
    ) {
        debug!(
            s.log,
            "failed to restore replication settings during rollback: {:?}", e
        );
    }

    // Restore NAT settings
    match group_ip {
        IpAddr::V4(ipv4) => rollback_restore_nat_v4(s, ipv4, nat_target),
        IpAddr::V6(ipv6) => rollback_restore_nat_v6(s, ipv6, nat_target),
    }

    // Restore VLAN and egress settings
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
