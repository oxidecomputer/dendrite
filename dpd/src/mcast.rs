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
    net::IpAddr,
    ops::Bound,
    sync::atomic::{AtomicU16, Ordering},
};

use crate::{
    link::LinkId,
    table,
    types::{DpdError, DpdResult},
    Switch,
};
use aal::AsicOps;
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
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub(crate) struct InternalForwarding {
    pub nat_target: Option<NatTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub(crate) struct ExternalForwarding {
    pub vlan_id: Option<u16>,
}

/// Represents a multicast replication configuration.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastReplicationInfo {
    pub(crate) replication_id: u16,
    pub(crate) level1_excl_id: u16,
    pub(crate) level2_excl_id: u16,
}

/// Represents a multicast group configuration.
///
/// There's a 1:1 association between multicast groups and multicast routes.
#[derive(Clone, Debug)]
pub(crate) struct MulticastGroup {
    pub group_id: MulticastGroupId,
    pub tag: Option<String>,
    pub int_fwding: InternalForwarding,
    pub ext_fwding: ExternalForwarding,
    pub sources: Option<Vec<IpSrc>>,
    pub replication_info: MulticastReplicationInfo,
    pub members: Vec<MulticastGroupMember>,
}

/// A multicast group entry for POST requests.
#[derive(Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastReplicationEntry {
    replication_id: Option<u16>,
    level1_excl_id: Option<u16>,
    level2_excl_id: Option<u16>,
}

/// A multicast group configuration for POST requests.
#[derive(Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupCreateEntry {
    group_ip: IpAddr,
    tag: Option<String>,
    nat_target: Option<NatTarget>,
    vlan_id: Option<u16>,
    sources: Option<Vec<IpSrc>>,
    replication_info: MulticastReplicationEntry,
    members: Vec<MulticastGroupMember>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub(crate) struct MulticastGroupUpdateEntry {
    tag: Option<String>,
    nat_target: Option<NatTarget>,
    vlan_id: Option<u16>,
    sources: Option<Vec<IpSrc>>,
    replication_info: MulticastReplicationEntry,
    members: Vec<MulticastGroupMember>,
}

/// Response structure for multicast group operations.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupResponse {
    group_ip: IpAddr,
    group_id: MulticastGroupId,
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
            group_id: group.group_id,
            // Use as_deref() to avoid cloning when not needed
            tag: group.tag.as_deref().map(str::to_owned),
            int_fwding: InternalForwarding {
                nat_target: group.int_fwding.nat_target,
            },
            ext_fwding: ExternalForwarding {
                vlan_id: group.ext_fwding.vlan_id,
            },
            sources: group.sources.clone(),
            replication_info: MulticastReplicationInfo {
                replication_id: group.replication_info.replication_id,
                level1_excl_id: group.replication_info.level1_excl_id,
                level2_excl_id: group.replication_info.level2_excl_id,
            },
            members: group.members.clone(),
        }
    }

    pub(crate) fn ip(&self) -> IpAddr {
        self.group_ip
    }
}

/// Identifier for multicast groups, either by IP address or group ID.
#[derive(Clone, Debug)]
pub(crate) enum Identifier {
    Ip(IpAddr),
    GroupId(MulticastGroupId),
}

/// Stores multicast group configurations.
#[derive(Debug)]
pub struct MulticastGroupData {
    /// Multicast group configurations keyed by group ID.
    groups: BTreeMap<IpAddr, MulticastGroup>,
    /// Set of in-use group IDs for fast lookup
    used_group_ids: HashSet<MulticastGroupId>,
    /// Atomic counter for generating unique multicast group IDs.
    id_generator: AtomicU16,
}

impl MulticastGroupData {
    pub(crate) const GENERATOR_START: u16 = 100;

    pub(crate) fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            used_group_ids: HashSet::new(),
            // Start at a threshold to avoid early allocations
            id_generator: AtomicU16::new(Self::GENERATOR_START),
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

        Err(DpdError::ResourceExhausted(
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

    debug!(s.log, "creating multicast group for IP {}", group_ip);

    // Generate group ID
    let group_id = mcast.generate_group_id()?;

    // Track added members for potential cleanup on errors
    let mut added_members = Vec::new();

    // First, create the group on the ASIC
    if let Err(e) = s.asic_hdl.mc_group_create(group_id) {
        return Err(DpdError::McastGroup(format!(
            "failed to create multicast group for IP {} with ID {}: {:?}",
            group_ip, group_id, e
        )));
    }

    // Add ports to the group
    for member in &group_info.members {
        match s.port_link_to_asic_id(member.port_id, member.link_id) {
            Ok(asic_id) => {
                if let Err(e) = s.asic_hdl.mc_port_add(group_id, asic_id) {
                    cleanup_on_group_create(
                        s,
                        group_ip,
                        group_id,
                        &added_members,
                        None,
                        None,
                    )?;

                    return Err(DpdError::McastGroup(format!(
                        "failed to add port {} to group for IP {}: {:?}",
                        member.port_id, group_ip, e
                    )));
                }

                // Track added members for cleanup
                added_members.push((member.port_id, member.link_id));
            }
            Err(e) => {
                cleanup_on_group_create(
                    s,
                    group_ip,
                    group_id,
                    &added_members,
                    None,
                    None,
                )?;
                return Err(e);
            }
        }
    }

    // Set up the table entries - this is where validation will happen
    let rid = group_info
        .replication_info
        .replication_id
        .unwrap_or(group_id);
    let level1_excl_id =
        group_info.replication_info.level1_excl_id.unwrap_or(0);
    let level2_excl_id =
        group_info.replication_info.level2_excl_id.unwrap_or(0);

    let result = match group_ip {
        IpAddr::V4(ipv4) => {
            let mut res = table::mcast::replication::add_ipv4_entry(
                s,
                ipv4,
                group_id,
                rid,
                level1_excl_id,
                level2_excl_id,
            );

            if let Some(ref srcs) = group_info.sources {
                if res.is_ok() {
                    // Add source filter entries for SSM
                    for src in srcs {
                        match src {
                            IpSrc::Exact(IpAddr::V4(src)) => {
                                res = table::mcast::src_filter::add_ipv4_entry(
                                    s,
                                    Ipv4Net::new(*src, 32).unwrap(),
                                    ipv4,
                                );
                            }

                            IpSrc::Subnet(src) => {
                                res = table::mcast::src_filter::add_ipv4_entry(
                                    s, *src, ipv4,
                                );
                            }
                            _ => {}
                        }
                        if res.is_err() {
                            break;
                        }
                    }
                }
            }

            if res.is_ok() && group_info.nat_target.is_some() {
                res = table::mcast::nat::add_ipv4_entry(
                    s,
                    ipv4,
                    group_info.nat_target.unwrap(),
                );
            }

            if res.is_ok() {
                res = table::mcast::route::add_ipv4_entry(
                    s,
                    ipv4,
                    group_info.vlan_id,
                );
            }

            res
        }
        IpAddr::V6(ipv6) => {
            let mut res = table::mcast::replication::add_ipv6_entry(
                s,
                ipv6,
                group_id,
                rid,
                level1_excl_id,
                level2_excl_id,
            );

            if let Some(ref srcs) = group_info.sources {
                if res.is_ok() {
                    // Add source filter entries for SSM
                    for src in srcs {
                        if let IpSrc::Exact(IpAddr::V6(src)) = src {
                            res = table::mcast::src_filter::add_ipv6_entry(
                                s, *src, ipv6,
                            );
                        }

                        if res.is_err() {
                            break;
                        }
                    }
                }
            }

            if res.is_ok() && group_info.nat_target.is_some() {
                res = table::mcast::nat::add_ipv6_entry(
                    s,
                    ipv6,
                    group_info.nat_target.unwrap(),
                );
            }

            if res.is_ok() {
                res = table::mcast::route::add_ipv6_entry(
                    s,
                    ipv6,
                    group_info.vlan_id,
                );
            }

            res
        }
    };

    if let Err(e) = result {
        cleanup_on_group_create(
            s,
            group_ip,
            group_id,
            &added_members,
            group_info.nat_target,
            group_info.sources.as_deref(),
        )?;
        return Err(e);
    }

    // Only store configuration if all operations succeeded
    let group = MulticastGroup {
        group_id,
        tag: group_info.tag,
        int_fwding: InternalForwarding {
            nat_target: group_info.nat_target,
        },
        ext_fwding: ExternalForwarding {
            vlan_id: group_info.vlan_id,
        },
        sources: group_info.sources,
        replication_info: MulticastReplicationInfo {
            replication_id: rid,
            level1_excl_id,
            level2_excl_id,
        },
        members: group_info.members,
    };

    mcast.groups.insert(group_ip, group.clone());
    mcast.used_group_ids.insert(group_id);

    Ok(MulticastGroupResponse::new(group_ip, &group))
}

/// Delete a multicast group from the switch, including all associated tables
/// and port mappings.
pub(crate) fn del_group(s: &Switch, ident: Identifier) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().unwrap();
    let (group_ip, group) = match ident {
        Identifier::Ip(ip) => {
            let group = mcast.groups.remove(&ip).ok_or_else(|| {
                DpdError::Missing(format!(
                    "Multicast group for IP {} not found",
                    ip
                ))
            })?;
            (ip, group)
        }
        Identifier::GroupId(group_id) => {
            let (ip, group) = mcast
                .groups
                .iter()
                .find(|(_, g)| g.group_id == group_id)
                .map(|(ip, _)| *ip)
                .ok_or_else(|| {
                    DpdError::Missing(format!(
                        "Multicast group ID {} not found",
                        group_id
                    ))
                })
                .and_then(|ip| {
                    mcast
                        .groups
                        .remove(&ip)
                        .map(|group| (ip, group))
                        .ok_or_else(|| {
                            DpdError::Missing(
                                "Group not found on second fetch".to_string(),
                            )
                        })
                })?;
            (ip, group)
        }
    };
    mcast.used_group_ids.remove(&group.group_id);

    drop(mcast);

    debug!(s.log, "deleting multicast group for IP {}", group_ip);

    del_entry(s, group_ip, &group)?;

    s.asic_hdl.mc_group_destroy(group.group_id).map_err(|e| {
        DpdError::McastGroup(format!(
            "failed to delete multicast group for IP {} with ID {}: {:?}",
            group_ip, group.group_id, e
        ))
    })?;

    Ok(())
}

/// Get a multicast group configuration.
pub(crate) fn get_group(
    s: &Switch,
    ident: Identifier,
) -> DpdResult<MulticastGroupResponse> {
    let mcast = s.mcast.lock().unwrap();

    match ident {
        Identifier::Ip(ip) => {
            let group = mcast
                .groups
                .get(&ip)
                .ok_or_else(|| {
                    DpdError::Missing(format!(
                        "multicast group for IP {} not found",
                        ip
                    ))
                })?
                .clone();

            Ok(MulticastGroupResponse::new(ip, &group))
        }
        Identifier::GroupId(group_id) => {
            // We still need to clone here to avoid lifetime issues
            let (ip, group) = mcast
                .groups
                .iter()
                .find(|(_, g)| g.group_id == group_id)
                .map(|(ip, g)| (*ip, g.clone()))
                .ok_or_else(|| {
                    DpdError::Missing(format!(
                        "multicast group with ID {} not found",
                        group_id
                    ))
                })?;

            Ok(MulticastGroupResponse::new(ip, &group))
        }
    }
}

/// Modify a multicast group configuration.
pub(crate) fn modify_group(
    s: &Switch,
    ident: Identifier,
    new_group_info: MulticastGroupUpdateEntry,
) -> DpdResult<MulticastGroupResponse> {
    let mut mcast = s.mcast.lock().unwrap();

    let (group_ip, group_entry) = match ident {
        Identifier::Ip(ip) => {
            let entry = mcast.groups.get_mut(&ip).ok_or_else(|| {
                DpdError::Missing(format!(
                    "Multicast group for IP {} not found",
                    ip
                ))
            })?;
            (ip, entry)
        }
        Identifier::GroupId(group_id) => {
            let (ip, entry) = mcast
                .groups
                .iter_mut()
                .find(|(_, g)| g.group_id == group_id)
                .ok_or_else(|| {
                    DpdError::Missing(format!(
                        "Multicast group ID {} not found",
                        group_id
                    ))
                })?;
            (*ip, entry)
        }
    };

    let (srcs, srcs_diff) = if let Some(new_srcs) =
        new_group_info.sources.clone()
    {
        if is_ssm(group_ip) && new_srcs.is_empty() {
            return Err(DpdError::Invalid(format!(
                "{} is a Source-Specific Multicast address and requires at least one source to be defined",
                group_ip
            )));
        } else {
            (Some(new_srcs), true)
        }
    } else {
        (group_entry.sources.clone(), false)
    };

    let prev_members: HashSet<_> =
        group_entry.members.iter().cloned().collect();
    let new_members: HashSet<_> =
        new_group_info.members.iter().cloned().collect();
    let mut added_ports = Vec::new();
    let mut removed_ports = Vec::new();

    for member in prev_members.difference(&new_members) {
        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;
        s.asic_hdl.mc_port_remove(group_entry.group_id, asic_id)?;
        removed_ports.push(member.clone());
    }

    for member in new_members.difference(&prev_members) {
        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;
        s.asic_hdl.mc_port_add(group_entry.group_id, asic_id)?;
        added_ports.push(member.clone());
    }

    let rid = new_group_info
        .replication_info
        .replication_id
        .unwrap_or(group_entry.replication_info.replication_id);
    let level1_excl_id = new_group_info
        .replication_info
        .level1_excl_id
        .unwrap_or(group_entry.replication_info.level1_excl_id);
    let level2_excl_id = new_group_info
        .replication_info
        .level2_excl_id
        .unwrap_or(group_entry.replication_info.level2_excl_id);

    let mut result = Ok(());

    if rid != group_entry.replication_info.replication_id
        || level1_excl_id != group_entry.replication_info.level1_excl_id
        || level2_excl_id != group_entry.replication_info.level2_excl_id
    {
        result = match group_ip {
            IpAddr::V4(ipv4) => table::mcast::replication::update_ipv4_entry(
                s,
                ipv4,
                group_entry.group_id,
                rid,
                level1_excl_id,
                level2_excl_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::replication::update_ipv6_entry(
                s,
                ipv6,
                group_entry.group_id,
                rid,
                level1_excl_id,
                level2_excl_id,
            ),
        };
    }

    if result.is_ok() && srcs_diff {
        remove_source_filters(s, group_ip, group_entry.sources.as_deref());
        add_source_filters(s, group_ip, srcs.as_deref());
    }

    if result.is_ok()
        && new_group_info.nat_target != group_entry.int_fwding.nat_target
    {
        result = match (
            group_ip,
            new_group_info.nat_target,
            group_entry.int_fwding.nat_target,
        ) {
            (IpAddr::V4(ipv4), Some(nat), _) => {
                table::mcast::nat::update_ipv4_entry(s, ipv4, nat)
            }
            (IpAddr::V6(ipv6), Some(nat), _) => {
                table::mcast::nat::update_ipv6_entry(s, ipv6, nat)
            }
            (IpAddr::V4(ipv4), None, Some(_)) => {
                table::mcast::nat::del_ipv4_entry(s, ipv4)
            }
            (IpAddr::V6(ipv6), None, Some(_)) => {
                table::mcast::nat::del_ipv6_entry(s, ipv6)
            }
            _ => Ok(()),
        };
    }

    if result.is_ok()
        && new_group_info.vlan_id != group_entry.ext_fwding.vlan_id
    {
        result = match group_ip {
            IpAddr::V4(ipv4) => table::mcast::route::update_ipv4_entry(
                s,
                ipv4,
                new_group_info.vlan_id,
            ),
            IpAddr::V6(ipv6) => table::mcast::route::update_ipv6_entry(
                s,
                ipv6,
                new_group_info.vlan_id,
            ),
        };
    }

    if let Err(e) = result {
        cleanup_on_group_update(
            s,
            group_ip,
            &added_ports,
            &removed_ports,
            group_entry,
            srcs_diff.then_some(srcs.as_ref().unwrap()),
        )?;
        return Err(e);
    }

    group_entry.tag = new_group_info.tag.or(group_entry.tag.clone());
    group_entry.int_fwding.nat_target = new_group_info
        .nat_target
        .or(group_entry.int_fwding.nat_target);
    group_entry.ext_fwding.vlan_id =
        new_group_info.vlan_id.or(group_entry.ext_fwding.vlan_id);
    group_entry.sources = srcs;
    group_entry.replication_info = MulticastReplicationInfo {
        replication_id: rid,
        level1_excl_id,
        level2_excl_id,
    };
    group_entry.members = new_group_info.members.clone();

    Ok(MulticastGroupResponse::new(group_ip, group_entry))
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
        if let Err(e) = del_group(s, Identifier::Ip(group_ip)) {
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
        if let Err(e) = del_group(s, Identifier::Ip(group_ip)) {
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
    table::mcast::replication::reset_ipv4(s)?;
    table::mcast::replication::reset_ipv6(s)?;
    table::mcast::src_filter::reset_ipv4(s)?;
    table::mcast::src_filter::reset_ipv6(s)?;
    table::mcast::nat::reset_ipv4(s)?;
    table::mcast::nat::reset_ipv6(s)?;
    table::mcast::route::reset_ipv4(s)?;
    table::mcast::route::reset_ipv6(s)?;
    mcast.groups.clear();

    Ok(())
}

fn del_entry(
    s: &Switch,
    ip: IpAddr,
    group_info: &MulticastGroup,
) -> DpdResult<()> {
    match ip {
        IpAddr::V4(ipv4) => {
            table::mcast::replication::del_ipv4_entry(s, ipv4)?;

            for src in group_info.sources.iter().flatten() {
                match src {
                    IpSrc::Exact(IpAddr::V4(src)) => {
                        table::mcast::src_filter::del_ipv4_entry(
                            s,
                            Ipv4Net::new(*src, 32).unwrap(),
                            ipv4,
                        )?;
                    }
                    IpSrc::Subnet(src) => {
                        table::mcast::src_filter::del_ipv4_entry(
                            s, *src, ipv4,
                        )?;
                    }
                    _ => {}
                }
            }

            if group_info.int_fwding.nat_target.is_some() {
                table::mcast::nat::del_ipv4_entry(s, ipv4)?;
            }

            table::mcast::route::del_ipv4_entry(s, ipv4)?;
        }
        IpAddr::V6(ipv6) => {
            table::mcast::replication::del_ipv6_entry(s, ipv6)?;

            for src in group_info.sources.iter().flatten() {
                if let IpSrc::Exact(IpAddr::V6(src)) = src {
                    table::mcast::src_filter::del_ipv6_entry(s, *src, ipv6)?;
                }
            }

            if group_info.int_fwding.nat_target.is_some() {
                table::mcast::nat::del_ipv6_entry(s, ipv6)?;
            }
            table::mcast::route::del_ipv6_entry(s, ipv6)?;
        }
    }

    Ok(())
}

/// Cleanup function for a multicast group creation failure.
fn cleanup_on_group_create(
    s: &Switch,
    group_ip: IpAddr,
    group_id: MulticastGroupId,
    added_members: &[(PortId, LinkId)],
    nat_target: Option<NatTarget>,
    sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    for (port_id, link_id) in added_members {
        if let Ok(asic_id) = s.port_link_to_asic_id(*port_id, *link_id) {
            s.asic_hdl.mc_port_remove(group_id, asic_id)?;
        }
    }
    // Destroy the group
    s.asic_hdl.mc_group_destroy(group_id)?;

    // Remove table entries
    match group_ip {
        IpAddr::V4(ipv4) => {
            let _ = table::mcast::replication::del_ipv4_entry(s, ipv4);
            remove_source_filters(s, group_ip, sources);

            if nat_target.is_some() {
                let _ = table::mcast::nat::del_ipv4_entry(s, ipv4);
            }

            let _ = table::mcast::route::del_ipv4_entry(s, ipv4);
        }
        IpAddr::V6(ipv6) => {
            let _ = table::mcast::replication::del_ipv6_entry(s, ipv6);
            remove_source_filters(s, group_ip, sources);

            if nat_target.is_some() {
                let _ = table::mcast::nat::del_ipv6_entry(s, ipv6);
            }

            let _ = table::mcast::route::del_ipv6_entry(s, ipv6);
        }
    }

    Ok(())
}

/// Cleanup function for a multicast group modification if it fails
/// on updates.
fn cleanup_on_group_update(
    s: &Switch,
    group_ip: IpAddr,
    added_ports: &[MulticastGroupMember],
    removed_ports: &[MulticastGroupMember],
    orig_group_info: &MulticastGroup,
    new_sources: Option<&[IpSrc]>,
) -> DpdResult<()> {
    let group_id = orig_group_info.group_id;
    let orig_replication_info = &orig_group_info.replication_info;
    let orig_vlan_id = orig_group_info.ext_fwding.vlan_id;
    let orig_nat_target = orig_group_info.int_fwding.nat_target;
    let srcs_modified = new_sources.is_some();

    // Remove any ports that were added during the modification
    for member in added_ports {
        match s.port_link_to_asic_id(member.port_id, member.link_id) {
            Ok(asic_id) => {
                let _ = s.asic_hdl.mc_port_remove(group_id, asic_id);
            }
            Err(_) => {
                error!(s.log, "Failed to remove added port during group modification cleanup";
                    "group_ip" => %group_ip,
                    "port_id" => %member.port_id,
                    "link_id" => %member.link_id
                );
            }
        }
    }

    // Restore ports that were removed during the modification
    for member in removed_ports {
        match s.port_link_to_asic_id(member.port_id, member.link_id) {
            Ok(asic_id) => {
                let _ = s.asic_hdl.mc_port_add(group_id, asic_id);
            }
            Err(_) => {
                error!(s.log, "Failed to restore removed port during group modification cleanup";
                    "group_ip" => %group_ip,
                    "port_id" => %member.port_id,
                    "link_id" => %member.link_id
                );
            }
        }
    }

    // If sources were modified, restore the original source filters
    if srcs_modified {
        remove_source_filters(s, group_ip, new_sources);
        // Restore the original source filters
        add_source_filters(s, group_ip, orig_group_info.sources.as_deref());
    }

    // Revert table entries based on IP version
    match group_ip {
        IpAddr::V4(ipv4) => {
            let _ = table::mcast::replication::update_ipv4_entry(
                s,
                ipv4,
                group_id,
                orig_replication_info.replication_id,
                orig_replication_info.level1_excl_id,
                orig_replication_info.level2_excl_id,
            );

            if let Some(nat_target) = orig_nat_target {
                let _ =
                    table::mcast::nat::update_ipv4_entry(s, ipv4, nat_target);
            } else {
                let _ = table::mcast::nat::del_ipv4_entry(s, ipv4);
            }

            let _ =
                table::mcast::route::update_ipv4_entry(s, ipv4, orig_vlan_id);
        }
        IpAddr::V6(ipv6) => {
            let _ = table::mcast::replication::update_ipv6_entry(
                s,
                ipv6,
                group_id,
                orig_replication_info.replication_id,
                orig_replication_info.level1_excl_id,
                orig_replication_info.level2_excl_id,
            );

            if let Some(nat_target) = orig_nat_target {
                let _ =
                    table::mcast::nat::update_ipv6_entry(s, ipv6, nat_target);
            } else {
                let _ = table::mcast::nat::del_ipv6_entry(s, ipv6);
            }

            let _ =
                table::mcast::route::update_ipv6_entry(s, ipv6, orig_vlan_id);
        }
    }

    Ok(())
}

fn remove_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    sources: Option<&[IpSrc]>,
) {
    match group_ip {
        IpAddr::V4(ipv4) => {
            if let Some(srcs) = sources {
                for src in srcs {
                    match src {
                        IpSrc::Exact(IpAddr::V4(src)) => {
                            let _ = table::mcast::src_filter::del_ipv4_entry(
                                s,
                                Ipv4Net::new(*src, 32).unwrap(),
                                ipv4,
                            );
                        }
                        IpSrc::Subnet(subnet) => {
                            let _ = table::mcast::src_filter::del_ipv4_entry(
                                s, *subnet, ipv4,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        IpAddr::V6(ipv6) => {
            if let Some(srcs) = sources {
                for src in srcs {
                    if let IpSrc::Exact(IpAddr::V6(src)) = src {
                        let _ = table::mcast::src_filter::del_ipv6_entry(
                            s, *src, ipv6,
                        );
                    }
                }
            }
        }
    }
}

fn add_source_filters(s: &Switch, group_ip: IpAddr, sources: Option<&[IpSrc]>) {
    match group_ip {
        IpAddr::V4(ipv4) => {
            if let Some(srcs) = sources {
                for src in srcs {
                    match src {
                        IpSrc::Exact(IpAddr::V4(src)) => {
                            let _ = table::mcast::src_filter::add_ipv4_entry(
                                s,
                                Ipv4Net::new(*src, 32).unwrap(),
                                ipv4,
                            );
                        }
                        IpSrc::Subnet(subnet) => {
                            let _ = table::mcast::src_filter::add_ipv4_entry(
                                s, *subnet, ipv4,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        IpAddr::V6(ipv6) => {
            if let Some(srcs) = sources {
                for src in srcs {
                    if let IpSrc::Exact(IpAddr::V6(src)) = src {
                        let _ = table::mcast::src_filter::add_ipv6_entry(
                            s, *src, ipv6,
                        );
                    }
                }
            }
        }
    }
}
