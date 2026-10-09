// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Multicast group management and configuration.
//!
//! This is the entrypoint for managing multicast groups, including creating,
//! modifying, and deleting groups.
//!
//! An external group has an ingress NAT entry keyed by its address and an
//! optional VLAN. On the sidecar, the NAT target fields are the action
//! parameters. Its `internal_ip` identifies the underlay group, which owns the
//! replication members.
//!
//! Underlay groups exist in an `ff04::/64` internal block, within the
//! admin-local scope `ff04::/16` ([RFC 7346], [RFC 4291]). A copy to an
//! external member is decapsulated, and picks up a VLAN tag if one is set.
//! Underlay copies keep their Geneve encapsulation.
//!
//! Rack-originated traffic arrives already encapsulated to the underlay
//! address. No external NAT. The `mcast_tag` selects the external replication
//! group, the underlay replication group, or both. Packet copies for
//! `Direction::External` members are decapsulated before delivery.
//!
//! Scope is not carried through to encapsulation. External IPv6 group
//! validation admits every scope except reserved `0x0` and the
//! interface-local `0x1` and link-local `0x2` scopes that a router must not
//! forward past (RFC 4291 §2.7). Each group maps to an `ff04::` (scope-4)
//! underlay address. A scope check on the outer header sees admin-local scope
//! for scope-3, scope-5, and scope-8 external groups, while containment for the
//! NAT path comes from both egress port and VLAN config.
//!
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html
//! [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346.html

use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, HashSet, btree_map::Entry},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Bound,
    sync::{Arc, Mutex, Weak},
};

use aal::{AsicError, AsicMulticastOps};
use common::network::NatTarget;
use dpd_types::mcast::{
    Direction, ExternalForwarding, ExternalInternalForwarding,
    ExternalMulticastIp, ExternalNatTarget, IpSrc,
    MulticastGroupCreateExternalEntry, MulticastGroupCreateUnderlayEntry,
    MulticastGroupExternalResponse, MulticastGroupId, MulticastGroupMember,
    MulticastGroupResponse, MulticastGroupUnderlayResponse,
    MulticastGroupUpdateExternalEntry, MulticastGroupUpdateUnderlayEntry,
    MulticastTag, SourceFilter, UnderlayMulticastIpv6,
};
use nonempty::NonEmpty;
use oxnet::{Ipv4Net, Ipv6Net};
use slog::{debug, error, warn};
use uuid::Uuid;

use crate::{
    Switch, table,
    types::{DpdError, DpdResult, after_unwind, ignore_exists, ignore_missing},
};

mod rollback;

use rollback::{
    DeleteStep, GroupCreateRollbackContext, GroupDeleteRollbackContext,
    GroupUpdateRollbackContext, unwind_outcome,
};

/// The key identifier for a multicast group, built only from a validated
/// group address.
///
/// The group's "kind" lives in its [`GroupKind`] type (not in the key).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct GroupKey(IpAddr);

impl GroupKey {
    /// Key an external group by its address.
    fn external(ip: ExternalMulticastIp) -> Self {
        Self(ip.into())
    }

    /// Key an underlay group by its `ff04::/64` address.
    fn underlay(ip: UnderlayMulticastIpv6) -> Self {
        Self(IpAddr::V6(ip.into()))
    }

    /// Return the keyed address.
    fn ip(&self) -> IpAddr {
        self.0
    }
}

impl Borrow<IpAddr> for GroupKey {
    fn borrow(&self) -> &IpAddr {
        &self.0
    }
}

/// Inner ID holding a weak handle to the free pool it returns.
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

/// Reference-counted ID wrapper for a multicast group ID during allocation.
/// Dropping it returns the ID to the free pool, making sure a failed creation
/// does not leak it.
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

/// Multicast replication configuration (underlay groups only).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MulticastReplicationInfo {
    rid: u16,
    level1_excl_id: u16,
    level2_excl_id: u16,
}

impl MulticastReplicationInfo {
    /// Default level exclusion IDs to 0 for underlay groups
    /// since they can only be configured internally without API calls.
    fn new(rid: MulticastGroupId) -> Self {
        Self { rid, level1_excl_id: 0, level2_excl_id: 0 }
    }
}

/// Represents a multicast group configuration.
///
/// This structure is used to manage multicast groups, including their
/// replication information, forwarding settings, and associated members.
#[derive(Clone, Debug)]
pub(crate) struct MulticastGroup {
    external_scoped_group: ScopedGroupId,
    underlay_scoped_group: ScopedGroupId,
    /// Tag for validating update/delete requests. Always present and generated
    /// as `{uuid}:{group_ip}` if not provided at creation time.
    pub(crate) tag: String,
    kind: GroupKind,
}

/// The kind of a [`MulticastGroup`]: external or underlay.
///
/// An external group carries ingress state: where to NAT, the egress VLAN,
/// and the source filter.
///
/// An underlay group carries replication state in [`Replication`].
#[derive(Clone, Debug)]
enum GroupKind {
    /// A customer-visible overlay multicast group.
    ///
    /// The ingress entry point that NATs inbound traffic to an underlay group.
    External {
        group_ip: ExternalMulticastIp,
        nat_target: ExternalNatTarget,
        vlan_id: Option<u16>,
        sources: SourceFilter,
    },
    /// An underlay group in the internal `ff04::/64` block that drives
    /// replication to its members (subscribers).
    ///
    /// Packet copies to [`Direction::External`] members are decapsulated.
    /// Packet copies to [`Direction::Underlay`] members retain Geneve
    /// encapsulation. The packet's `mcast_tag` selects external replication,
    /// underlay replication, or both (bifurcated replication).
    Underlay { group_ip: UnderlayMulticastIpv6, replication: Replication },
}

/// The replication state of an underlay group.
///
/// Member subscribers and replication info exist when `Active`, which
/// means the group owns both a decap bitmap entry and a replication entry.
#[derive(Clone, Debug)]
enum Replication {
    /// No members.
    ///
    /// Groups are created memberless and filled in eventually on joins.
    Empty,
    /// Replicating to a non-empty member set.
    Active {
        info: MulticastReplicationInfo,
        members: NonEmpty<MulticastGroupMember>,
    },
}

impl Replication {
    fn new(
        info: MulticastReplicationInfo,
        members: Vec<MulticastGroupMember>,
    ) -> Self {
        match NonEmpty::from_vec(members) {
            Some(members) => Self::Active { info, members },
            None => Self::Empty,
        }
    }

    fn info(&self) -> Option<&MulticastReplicationInfo> {
        match self {
            Self::Empty => None,
            Self::Active { info, .. } => Some(info),
        }
    }

    fn members(&self) -> impl Iterator<Item = &MulticastGroupMember> {
        match self {
            Self::Empty => None,
            Self::Active { members, .. } => Some(members.iter()),
        }
        .into_iter()
        .flatten()
    }
}

impl MulticastGroup {
    /// Return the group's address as read from its [`GroupKind`].
    fn ip(&self) -> IpAddr {
        match &self.kind {
            GroupKind::External { group_ip, .. } => (*group_ip).into(),
            GroupKind::Underlay { group_ip, .. } => (*group_ip).into(),
        }
    }

    fn nat_target(&self) -> Option<ExternalNatTarget> {
        match &self.kind {
            GroupKind::External { nat_target, .. } => Some(*nat_target),
            GroupKind::Underlay { .. } => None,
        }
    }

    fn vlan_id(&self) -> Option<u16> {
        match &self.kind {
            GroupKind::External { vlan_id, .. } => *vlan_id,
            GroupKind::Underlay { .. } => None,
        }
    }

    fn replication(&self) -> Option<&Replication> {
        match &self.kind {
            GroupKind::External { .. } => None,
            GroupKind::Underlay { replication, .. } => Some(replication),
        }
    }

    fn members(&self) -> impl Iterator<Item = &MulticastGroupMember> {
        self.replication().into_iter().flat_map(Replication::members)
    }

    fn replication_info(&self) -> Option<&MulticastReplicationInfo> {
        self.replication().and_then(Replication::info)
    }

    fn external_group_id(&self) -> MulticastGroupId {
        self.external_scoped_group.id()
    }

    fn underlay_group_id(&self) -> MulticastGroupId {
        self.underlay_scoped_group.id()
    }

    /// ASIC group that carries members of `direction`.
    fn group_id(&self, direction: Direction) -> MulticastGroupId {
        match direction {
            Direction::External => self.external_group_id(),
            Direction::Underlay => self.underlay_group_id(),
        }
    }
}

impl TryFrom<&MulticastGroup> for MulticastGroupExternalResponse {
    type Error = DpdError;

    /// Build the external API response for an external group.
    ///
    /// # Errors
    ///
    /// Returns [`DpdError::Invalid`] if `group` is an underlay group.
    fn try_from(group: &MulticastGroup) -> DpdResult<Self> {
        match MulticastGroupResponse::from(group) {
            MulticastGroupResponse::External(response) => Ok(response),
            MulticastGroupResponse::Underlay(response) => {
                Err(DpdError::Invalid(format!(
                    "multicast group {} is not an external group",
                    response.group_ip
                )))
            }
        }
    }
}

impl TryFrom<&MulticastGroup> for MulticastGroupUnderlayResponse {
    type Error = DpdError;

    /// Build the underlay response for an underlay group.
    ///
    /// # Errors
    ///
    /// Returns [`DpdError::Invalid`] if `group` is an external group.
    fn try_from(group: &MulticastGroup) -> DpdResult<Self> {
        match MulticastGroupResponse::from(group) {
            MulticastGroupResponse::Underlay(response) => Ok(response),
            MulticastGroupResponse::External(response) => {
                Err(DpdError::Invalid(format!(
                    "multicast group {} is not an underlay group",
                    response.group_ip
                )))
            }
        }
    }
}

impl From<&MulticastGroup> for MulticastGroupResponse {
    /// Build the response variant matching the group's [`GroupKind`].
    fn from(group: &MulticastGroup) -> Self {
        match &group.kind {
            GroupKind::External { group_ip, nat_target, vlan_id, sources } => {
                Self::External(MulticastGroupExternalResponse {
                    group_ip: *group_ip,
                    external_group_id: group.external_group_id(),
                    tag: group.tag.clone(),
                    internal_forwarding: ExternalInternalForwarding {
                        nat_target: *nat_target,
                    },
                    external_forwarding: ExternalForwarding {
                        vlan_id: *vlan_id,
                    },
                    sources: sources.to_ip_sources(),
                })
            }
            GroupKind::Underlay { group_ip, replication } => {
                Self::Underlay(MulticastGroupUnderlayResponse {
                    group_ip: *group_ip,
                    external_group_id: group.external_group_id(),
                    underlay_group_id: group.underlay_group_id(),
                    tag: group.tag.clone(),
                    members: replication.members().cloned().collect(),
                })
            }
        }
    }
}

/// Stores multicast group configurations.
#[derive(Debug)]
pub struct MulticastGroupData {
    /// Multicast group configurations keyed by group IP.
    groups: BTreeMap<GroupKey, MulticastGroup>,
    /// The stack of available group IDs for O(1) allocation.
    /// Pre-populated with all IDs from GENERATOR_START to u16::MAX-1.
    free_group_ids: Arc<Mutex<Vec<MulticastGroupId>>>,
    /// 1:1 mapping from admin-local group IP to the external group that uses it
    /// as NAT a target (admin_local_ip -> external_group_ip).
    nat_target_refs: BTreeMap<UnderlayMulticastIpv6, GroupKey>,
}

impl MulticastGroupData {
    /// The lowest group ID that could be available in the free pool; lower IDs
    /// remain reserved.
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
            DpdError::ResourceExhausted(
                "no free multicast group IDs available (exhausted range 100-65534)".to_string(),
            )
        })?;

        Ok(ScopedIdInner(id, Arc::downgrade(&self.free_group_ids)).into())
    }

    /// Add 1:1 forwarding reference from admin-local IP to external group's IP.
    fn add_forwarding_refs(
        &mut self,
        external_group_key: GroupKey,
        admin_scoped_ip: UnderlayMulticastIpv6,
    ) {
        self.nat_target_refs.insert(admin_scoped_ip, external_group_key);
    }

    /// Remove 1:1 forwarding reference.
    fn rm_forwarding_refs(&mut self, admin_scoped_ip: UnderlayMulticastIpv6) {
        self.nat_target_refs.remove(&admin_scoped_ip);
    }

    /// Get the VLAN ID for an underlay multicast group by looking up
    /// the referencing external group (1:1 mapping).
    fn get_vlan_for_underlay_addr(
        &self,
        internal_ip: UnderlayMulticastIpv6,
    ) -> Option<u16> {
        self.nat_target_refs
            .get(&internal_ip)
            .and_then(|external_key| self.groups.get(external_key))
            .and_then(|group| group.vlan_id())
    }

    fn validate_group_exists(&self, group_key: GroupKey) -> DpdResult<()> {
        if self.groups.contains_key(&group_key) {
            return Err(DpdError::Exists(format!(
                "multicast group for IP {} already exists",
                group_key.ip(),
            )));
        }
        Ok(())
    }

    fn get_nat_target_group(
        &self,
        group_addr: IpAddr,
        nat_target: ExternalNatTarget,
    ) -> DpdResult<&MulticastGroup> {
        let internal_ip: UnderlayMulticastIpv6 = nat_target.into();
        if let Some(existing_ref) = self.nat_target_refs.get(&internal_ip)
            && existing_ref.ip() != group_addr
        {
            return Err(DpdError::Invalid(format!(
                "underlay group {internal_ip} is already referenced by external group {}",
                existing_ref.ip(),
            )));
        }

        let Some(underlay_group) = self.groups.get(&IpAddr::from(internal_ip))
        else {
            return Err(DpdError::MissingNatTarget(format!(
                "underlay group {internal_ip} referenced by external group \
                 {group_addr} is absent from the switch",
            )));
        };

        let GroupKind::Underlay { .. } = &underlay_group.kind else {
            return Err(DpdError::Invalid(format!(
                "multicast group for IP {internal_ip} is not an underlay group",
            )));
        };
        Ok(underlay_group)
    }
}

impl Default for MulticastGroupData {
    fn default() -> Self {
        Self::new()
    }
}

/// Add an external multicast group to the switch: bind the address to its
/// NAT-target underlay group's ASIC groups and program the NAT and L3 route
/// entries.
///
/// If anything fails, the group is cleaned up and an error is returned.
pub(crate) fn add_group_external(
    s: &Switch,
    group_info: MulticastGroupCreateExternalEntry,
) -> DpdResult<MulticastGroupExternalResponse> {
    let group_ip = group_info.group_ip();
    let group_key = GroupKey::external(group_ip);
    let group_addr: IpAddr = group_ip.into();
    let sources = SourceFilter::from(&group_info);

    // Acquire the lock to the multicast data structure at the start to ensure
    // deterministic operation order
    let mut mcast = s.mcast.lock().unwrap();

    let nat_target = group_info.internal_forwarding().nat_target;

    mcast.validate_group_exists(group_key)?;

    let underlay_group = mcast.get_nat_target_group(group_addr, nat_target)?;
    let tag = match group_info.tag() {
        Some(t) => String::from(t.parse::<MulticastTag>()?),
        None => generate_default_tag(group_addr),
    };

    // Set IDs to match the underlay group from the NAT target
    let scoped_external_id = underlay_group.external_scoped_group.clone();
    let scoped_underlay_id = underlay_group.underlay_scoped_group.clone();

    let group = MulticastGroup {
        external_scoped_group: scoped_external_id,
        underlay_scoped_group: scoped_underlay_id,
        tag,
        kind: GroupKind::External {
            group_ip,
            nat_target,
            vlan_id: group_info.external_forwarding().vlan_id,
            sources: sources.clone(),
        },
    };
    let response = MulticastGroupExternalResponse::try_from(&group)?;

    let admin_local_ip: UnderlayMulticastIpv6 = nat_target.into();
    let previous_vlan = mcast.get_vlan_for_underlay_addr(admin_local_ip);

    clear_external_entries(s, group_addr)?;

    // Create rollback context once for reuse throughout this function
    let rollback_ctx = GroupCreateRollbackContext::new_external(
        s,
        group_addr,
        group.external_group_id(),
        group.underlay_group_id(),
        &sources,
        group_info.external_forwarding().vlan_id,
    );

    configure_external_tables(s, &group_info, &sources)
        .map_err(|e| rollback_ctx.rollback(e))?;

    do_vlan_propagation(
        s,
        group_addr,
        group_info.external_forwarding().vlan_id,
        underlay_group,
    )
    .map_err(|e| {
        rollback_ctx.rollback_with_vlan_restore(
            e,
            underlay_group,
            previous_vlan,
        )
    })?;

    // VLAN propagation is the last fallible step. Any fallible work added
    // below must also restore the underlay group's previous bitmap VLAN.
    mcast.groups.insert(group_key, group);
    mcast.add_forwarding_refs(group_key, admin_local_ip);

    Ok(response)
}

/// Add an underlay multicast group to the switch, which creates the group on
/// the ASIC and associates it with a group IP address and updates associated
/// tables for multicast replication and L3 routing.
///
/// If anything fails, the group is cleaned up and an error is returned.
pub(crate) fn add_group_underlay(
    s: &Switch,
    group_info: MulticastGroupCreateUnderlayEntry,
) -> DpdResult<MulticastGroupUnderlayResponse> {
    let group_ip = group_info.group_ip;
    let group_key = GroupKey::underlay(group_ip);

    // Acquire the lock to the multicast data structure at the start to ensure
    // deterministic operation order
    let mut mcast = s.mcast.lock().unwrap();

    mcast.validate_group_exists(group_key)?;

    let ipv6 = Ipv6Addr::from(group_ip);
    ignore_missing(table::mcast::mcast_replication::del_ipv6_entry(s, ipv6))?;
    ignore_missing(table::mcast::mcast_route::del_ipv6_entry(s, ipv6))?;

    let tag = match &group_info.tag {
        Some(t) => String::from(t.parse::<MulticastTag>()?),
        None => generate_default_tag(group_ip.into()),
    };
    let (scoped_external_id, scoped_underlay_id) =
        allocate_multicast_group_ids(s, &mut mcast, group_ip.into())?;

    // Create rollback context for cleanup if operations fail
    let rollback_ctx = GroupCreateRollbackContext::new_underlay(
        s,
        group_ip.into(),
        scoped_external_id.id(),
        scoped_underlay_id.id(),
    );

    // Get VLAN ID from referencing external groups
    let vlan_id = mcast.get_vlan_for_underlay_addr(group_ip);
    let external_group_id = scoped_external_id.id();
    let underlay_group_id = scoped_underlay_id.id();
    let mut added_members = Vec::new();

    // Only configure replication if there are members
    let replication_info = (!group_info.members.is_empty())
        .then(|| MulticastReplicationInfo::new(external_group_id));

    if let Some(replication_info) = &replication_info {
        add_ports_to_groups(
            s,
            group_ip.into(),
            &group_info.members,
            external_group_id,
            underlay_group_id,
            replication_info,
            &mut added_members,
        )
        .map_err(|e| rollback_ctx.rollback(e))?;
    }

    configure_underlay_tables(
        s,
        group_ip,
        external_group_id,
        underlay_group_id,
        replication_info.as_ref(),
        &added_members,
        vlan_id,
    )
    .map_err(|e| rollback_ctx.rollback(e))?;

    // Generic internal datastructure (vs API interface)
    let group = MulticastGroup {
        external_scoped_group: scoped_external_id,
        underlay_scoped_group: scoped_underlay_id,
        tag,
        kind: GroupKind::Underlay {
            group_ip,
            replication: match replication_info {
                Some(info) => Replication::new(info, group_info.members),
                None => Replication::Empty,
            },
        },
    };

    mcast.groups.insert(group_key, group.clone());

    MulticastGroupUnderlayResponse::try_from(&group)
}

/// Delete a multicast group from the switch, including all associated tables
/// and port mappings.
///
/// This operation is idempotent: deleting a non-existent group returns
/// `NotFound` rather than a tag mismatch error, making deletes safe to retry.
///
/// # Arguments
///
/// * `s` - Switch instance containing the multicast state.
/// * `group_ip` - IP address of the multicast group to delete.
/// * `tag` - Tag for validation. Must match the group's existing tag.
///
/// # Errors
///
/// Returns an error if:
/// - Attempting to delete an underlay group that is still referenced by an
///   external group via NAT target
/// - The provided tag does not match the group's existing tag
pub(crate) fn del_group(
    s: &Switch,
    group_ip: IpAddr,
    tag: &str,
) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().unwrap();
    del_group_locked(s, &mut mcast, group_ip, tag)
}

fn del_group_locked(
    s: &Switch,
    mcast: &mut MulticastGroupData,
    group_ip: IpAddr,
    tag: &str,
) -> DpdResult<()> {
    let group = mcast.groups.get(&group_ip).ok_or_else(|| {
        DpdError::Missing(format!(
            "Multicast group for IP {group_ip} not found"
        ))
    })?;

    // Check if this is an underlay group referenced by an external group.
    // Underlay groups are identified by addresses in the reserved underlay
    // subnet (i.e., ff04::/64).
    if let IpAddr::V6(ipv6) = group_ip
        && let Ok(admin_scoped) = UnderlayMulticastIpv6::new(ipv6)
        && let Some(external_ip) = mcast.nat_target_refs.get(&admin_scoped)
    {
        return Err(DpdError::Invalid(format!(
            "cannot delete underlay group {group_ip}: still referenced \
             by external group {} via NAT target",
            external_ip.ip(),
        )));
    }

    // Validate tag before removing the group.
    validate_tag(&group.tag, tag)?;

    let nat_target_to_remove =
        group.nat_target().map(UnderlayMulticastIpv6::from);

    debug!(s.log, "deleting multicast group for IP {group_ip}");

    let rollback_ctx = GroupDeleteRollbackContext::new(s, group);
    let mut deleted = Vec::new();

    delete_group_tables(s, group, &mut deleted)
        .map_err(|e| rollback_ctx.rollback(e, &deleted))?;

    if let Some(internal_ip) = nat_target_to_remove
        && group.vlan_id().is_some()
        && let Some(underlay_group) =
            mcast.groups.get(&IpAddr::from(internal_ip))
    {
        ensure_bitmap_vlan(s, underlay_group, None).map_err(|e| {
            rollback_ctx.rollback_with_vlan_restore(e, underlay_group, &deleted)
        })?;
    }

    // External groups share ASIC resources with their referenced underlay groups.
    if matches!(group.kind, GroupKind::Underlay { .. }) {
        deleted.push(DeleteStep::Domains);
        delete_multicast_groups(
            s,
            group_ip,
            group.external_group_id(),
            group.underlay_group_id(),
        )
        .map_err(|e| rollback_ctx.rollback(e, &deleted))?;
    }

    if let Some(internal_ip) = nat_target_to_remove {
        mcast.rm_forwarding_refs(internal_ip);
    }

    mcast.groups.remove(&group_ip);
    Ok(())
}

/// Get an underlay multicast group configuration by admin-local IPv6 address.
pub(crate) fn get_group_underlay(
    s: &Switch,
    admin_local: UnderlayMulticastIpv6,
) -> DpdResult<MulticastGroupUnderlayResponse> {
    let mcast = s.mcast.lock().unwrap();
    let group_ip = IpAddr::V6(admin_local.into());

    let group = mcast.groups.get(&group_ip).ok_or_else(|| {
        DpdError::Missing(format!(
            "underlay multicast group for IP {group_ip} not found",
        ))
    })?;

    MulticastGroupUnderlayResponse::try_from(group)
}

/// Get a multicast group configuration.
pub(crate) fn get_group(
    s: &Switch,
    group_ip: IpAddr,
) -> DpdResult<MulticastGroupResponse> {
    let mcast = s.mcast.lock().unwrap();

    let group = mcast.groups.get(&group_ip).ok_or_else(|| {
        DpdError::Missing(format!(
            "multicast group for IP {group_ip} not found"
        ))
    })?;

    Ok(group.into())
}

/// Update an external group's forwarding, VLAN, and sources under its tag.
pub(crate) fn modify_group_external(
    s: &Switch,
    group_ip: ExternalMulticastIp,
    tag: &str,
    new_group_info: MulticastGroupUpdateExternalEntry,
) -> DpdResult<MulticastGroupExternalResponse> {
    let group_key = GroupKey::external(group_ip);
    let group_addr: IpAddr = group_ip.into();
    let mut mcast = s.mcast.lock().unwrap();

    // Check existence and validate tag before making any changes
    let existing_group = mcast.groups.get(&group_key).ok_or_else(|| {
        DpdError::Missing(format!(
            "Multicast group for IP {group_addr} not found"
        ))
    })?;
    validate_tag(&existing_group.tag, tag)?;

    let GroupKind::External {
        sources: old_sources,
        nat_target: old_nat_target,
        vlan_id: old_vlan_id,
        ..
    } = &existing_group.kind
    else {
        return Err(DpdError::Invalid(format!(
            "multicast group {group_addr} is not an external group"
        )));
    };

    let old_nat_target = *old_nat_target;
    let old_vlan_id = *old_vlan_id;

    let new_sources = match new_group_info.sources.as_deref() {
        Some(sources) => SourceFilter::from_entries(group_ip, Some(sources))
            .map_err(|e| DpdError::Invalid(e.to_string()))?,
        None => old_sources.clone(),
    };

    let nat_target = new_group_info.internal_forwarding.nat_target;
    let new_underlay_group =
        mcast.get_nat_target_group(group_addr, nat_target)?;
    let group_entry = existing_group.clone();

    let old_underlay_ip: UnderlayMulticastIpv6 = old_nat_target.into();
    let new_underlay_ip: UnderlayMulticastIpv6 = nat_target.into();

    let target_changed = old_underlay_ip != new_underlay_ip;
    let old_underlay_group =
        mcast.groups.get(&IpAddr::V6(old_underlay_ip.into()));
    // VLAN is assigned directly: `Some(x)` sets the VLAN, `None` removes it.
    // Unlike `sources`, `None` does not preserve the current value.
    let new_vlan_id = new_group_info.external_forwarding.vlan_id;

    let bitmap_updates = [
        (target_changed || old_vlan_id != new_vlan_id).then(|| {
            BitmapVlanUpdate {
                group: new_underlay_group,
                old_vlan_id: mcast.get_vlan_for_underlay_addr(new_underlay_ip),
                new_vlan_id,
            }
        }),
        old_underlay_group.filter(|_| target_changed).map(|group| {
            BitmapVlanUpdate { group, old_vlan_id, new_vlan_id: None }
        }),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    // Create rollback context for external group update
    let rollback_ctx =
        GroupUpdateRollbackContext::new(s, &group_entry, new_vlan_id);

    update_external_tables(
        s,
        &group_entry,
        &new_group_info,
        old_nat_target,
        old_sources,
        &new_sources,
        &bitmap_updates,
    )
    .map_err(|e| rollback_ctx.rollback_external(e, &new_sources))?;

    let updated_group = MulticastGroup {
        external_scoped_group: new_underlay_group.external_scoped_group.clone(),
        underlay_scoped_group: new_underlay_group.underlay_scoped_group.clone(),
        kind: GroupKind::External {
            group_ip,
            nat_target,
            vlan_id: new_vlan_id,
            sources: new_sources,
        },
        ..group_entry
    };

    // Update NAT target references if NAT target changed
    if target_changed {
        mcast.rm_forwarding_refs(old_underlay_ip);
        mcast.add_forwarding_refs(group_key, new_underlay_ip);
    }

    let response = MulticastGroupExternalResponse::try_from(&updated_group);
    mcast.groups.insert(group_key, updated_group);
    response
}

/// Update an underlay group's members under its tag.
pub(crate) fn modify_group_underlay(
    s: &Switch,
    group_ip: UnderlayMulticastIpv6,
    tag: &str,
    new_group_info: MulticastGroupUpdateUnderlayEntry,
) -> DpdResult<MulticastGroupUnderlayResponse> {
    let mut mcast = s.mcast.lock().unwrap();

    let group_key = GroupKey::underlay(group_ip);
    let external_group_vlan_id = mcast.get_vlan_for_underlay_addr(group_ip);

    // Check existence and validate tag before making any changes
    let Entry::Occupied(existing_group) = mcast.groups.entry(group_key) else {
        return Err(DpdError::Missing(format!(
            "Multicast group for IP {group_ip} not found"
        )));
    };

    validate_tag(&existing_group.get().tag, tag)?;

    if !matches!(existing_group.get().kind, GroupKind::Underlay { .. }) {
        return Err(DpdError::Invalid(format!(
            "multicast group {group_ip} is not an underlay group"
        )));
    }

    // Repair the route before changing memberships or replication.
    table::mcast::mcast_route::ensure_ipv6_entry(s, group_ip.into(), None)?;

    let mut group_entry = existing_group.remove();

    // Create rollback context for underlay group update
    let group_entry_for_rollback = group_entry.clone();
    let rollback_ctx = GroupUpdateRollbackContext::new(
        s,
        &group_entry_for_rollback,
        external_group_vlan_id,
    );

    let mut added_members = Vec::new();
    let mut removed_members = Vec::new();

    // Configure replication based on member count transitions
    let replication_info = match (
        new_group_info.members.is_empty(),
        group_entry_for_rollback.replication_info(),
    ) {
        (true, Some(repl_info)) => {
            // Transition from members to empty.
            //
            // First, remove ports from ASIC groups before cleaning up
            // replication table entries, otherwise stale ports cause subsequent
            // re-adds to fail with "already contains port".
            if let Err(e) = process_membership_changes(
                s,
                &new_group_info.members,
                &group_entry,
                repl_info,
                &mut added_members,
                &mut removed_members,
            ) {
                mcast.groups.insert(group_key, group_entry);
                return Err(rollback_ctx.rollback_underlay(
                    e,
                    repl_info,
                    &added_members,
                    &removed_members,
                ));
            }

            if let Err(e) = cleanup_empty_group_replication(
                s,
                &group_entry,
                external_group_vlan_id,
            ) {
                mcast.groups.insert(group_key, group_entry);
                return Err(rollback_ctx.rollback_underlay_and_restore(
                    e,
                    repl_info,
                    &added_members,
                    &removed_members,
                ));
            }

            None
        }
        (false, None) => {
            // Transition from empty to members - configure replication
            Some(MulticastReplicationInfo::new(group_entry.external_group_id()))
        }
        (false, Some(_)) => {
            // Already has members and replication - keep existing
            group_entry.replication_info().cloned()
        }
        (true, None) => {
            // Already empty and no replication - keep none
            None
        }
    };

    // Early return for no-replication case -> just update metadata
    // Tags are immutable (validated above, never changed)
    let Some(replication_info) = replication_info else {
        group_entry.kind =
            GroupKind::Underlay { group_ip, replication: Replication::Empty };
        let response = MulticastGroupUnderlayResponse::try_from(&group_entry);
        mcast.groups.insert(group_key, group_entry);
        return response;
    };

    // Continue with replication processing
    let repl_info = &replication_info;
    if let Err(e) = process_membership_changes(
        s,
        &new_group_info.members,
        &group_entry,
        repl_info,
        &mut added_members,
        &mut removed_members,
    ) {
        // Restore group to mcast data structure
        mcast.groups.insert(group_key, group_entry);
        return Err(rollback_ctx.rollback_underlay(
            e,
            repl_info,
            &added_members,
            &removed_members,
        ));
    }

    // Ensure the bitmap exists before the replication entry. The VLAN comes
    // from the referencing external group.
    if let Err(e) = update_underlay_group_bitmap_tables(
        s,
        &group_entry,
        &new_group_info.members,
        external_group_vlan_id,
    ) {
        // Restore the group and roll back
        mcast.groups.insert(group_key, group_entry);
        return Err(rollback_ctx.rollback_underlay_and_restore(
            e,
            repl_info,
            &added_members,
            &removed_members,
        ));
    }

    // Ensure the replication entry on every update with members.
    //
    // An entry lost to a partial delete can then come back. It's inserted after
    // the bitmap, where a rollback deletes a newly added bitmap on failure, and
    // if that delete also fails, then the leftover is a bitmap that nothing
    // can replicate toward (instead of a replication entry with no decap entry).
    if let Err(e) = add_replication_entry(s, &group_entry, repl_info) {
        mcast.groups.insert(group_key, group_entry);
        return Err(rollback_ctx.rollback_underlay_and_restore(
            e,
            repl_info,
            &added_members,
            &removed_members,
        ));
    }

    // Update group metadata and return success
    // Tags are immutable (validated above, never changed)
    group_entry.kind = GroupKind::Underlay {
        group_ip,
        replication: Replication::new(replication_info, new_group_info.members),
    };
    let response = MulticastGroupUnderlayResponse::try_from(&group_entry);
    mcast.groups.insert(group_key, group_entry);

    response
}

/// List all multicast groups over a range.
pub(crate) fn get_range(
    s: &Switch,
    last: Option<IpAddr>,
    limit: usize,
    tag: Option<&str>,
) -> DpdResult<Vec<MulticastGroupResponse>> {
    let mcast = s.mcast.lock().unwrap();

    let lower_bound = match last {
        None => Bound::Unbounded,
        Some(last_ip) => Bound::Excluded(last_ip),
    };

    Ok(mcast
        .groups
        .range((lower_bound, Bound::Unbounded))
        .filter(|&(_key, group)| {
            // Filter by tag if specified
            tag.is_none_or(|tag_filter| group.tag == tag_filter)
        })
        .map(|(_key, group)| group.into())
        .take(limit)
        .collect())
}

/// Reset all multicast groups (and associated routes) for a given tag.
pub(crate) fn reset_tag(s: &Switch, tag: &str) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().unwrap();
    let (external_groups, underlay_groups) = mcast
        .groups
        .iter()
        .filter_map(|(key, group)| {
            (group.tag == tag).then_some((
                key.ip(),
                matches!(group.kind, GroupKind::External { .. }),
            ))
        })
        .partition::<Vec<_>, _>(|(_, is_external)| *is_external);

    // Delete external groups first since they reference underlay groups
    // via NAT targets. Pass the tag for validation.
    for (group_ip, _) in external_groups.into_iter().chain(underlay_groups) {
        if let Err(e) = del_group_locked(s, &mut mcast, group_ip, tag) {
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
fn do_vlan_propagation(
    s: &Switch,
    group_ip: IpAddr,
    vlan_id: Option<u16>,
    underlay_group: &MulticastGroup,
) -> DpdResult<()> {
    let internal_ip = underlay_group.ip();
    debug!(
        s.log,
        "external group with VLAN references underlay group, propagating VLAN";
        "external_group" => %group_ip,
        "vlan" => ?vlan_id,
        "underlay_group" => %internal_ip,
    );

    ensure_bitmap_vlan(s, underlay_group, vlan_id).map_err(|e| {
        DpdError::McastGroupFailure(format!(
            "failed to update external bitmap: vlan={vlan_id:?}, underlay_group={internal_ip}, error={e:?}",
        ))
    })
}

/// Update the VLAN on an active underlay group's bitmap entry, failing if the
/// entry is missing.
///
/// Rollback calls this method first when restoring a VLAN, and then re-adds the
/// entry itself if it is missing.
fn update_bitmap_vlan(
    s: &Switch,
    group: &MulticastGroup,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    if group.replication_info().is_none() {
        return Ok(());
    }

    let port_bitmap = create_port_bitmap(group.members(), Direction::External);
    table::mcast::mcast_egress::update_bitmap_entry(
        s,
        group.external_group_id(),
        &port_bitmap,
        vlan_id,
    )
}

/// Set the VLAN on an active underlay group's bitmap entry, re-adding the
/// entry if it is missing.
///
/// The bitmap comes from the group's external members and `vlan_id`.
/// If it is missing, [`readd_underlay_entries`] restores it before the
/// replication entry and route.
fn ensure_bitmap_vlan(
    s: &Switch,
    group: &MulticastGroup,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    let Some(Replication::Active { info, .. }) = group.replication() else {
        return Ok(());
    };

    match update_bitmap_vlan(s, group, vlan_id) {
        Err(DpdError::Switch(AsicError::Missing(detail))) => warn!(
            s.log,
            "re-adding missing multicast bitmap entry";
            "group_ip" => %group.ip(),
            "detail" => detail,
        ),
        res => return res,
    }

    let port_bitmap = create_port_bitmap(group.members(), Direction::External);
    readd_underlay_entries(s, group, info, &port_bitmap, vlan_id)
}

/// Re-add the bitmap, replication, and route entries for an active
/// underlay group whose bitmap entry went missing.
///
/// The entries are rebuilt from the caller's bitmap and VLAN, the group's IDs,
/// and replication `info`. An existing replication entry gets rewritten, since
/// its IDs could be stale. Existing routes are kept because underlay routes
/// don't carry a VLAN.
fn readd_underlay_entries(
    s: &Switch,
    group: &MulticastGroup,
    info: &MulticastReplicationInfo,
    port_bitmap: &table::mcast::mcast_egress::PortBitmap,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    table::mcast::mcast_egress::add_bitmap_entry(
        s,
        group.external_group_id(),
        port_bitmap,
        vlan_id,
    )?;

    let IpAddr::V6(ipv6) = group.ip() else {
        return Ok(());
    };

    add_replication_entry(s, group, info)?;

    ignore_exists(table::mcast::mcast_route::add_ipv6_entry(s, ipv6, vlan_id))
}

/// Remove source filters for a multicast group.
fn remove_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    sources: &SourceFilter,
) -> DpdResult<()> {
    apply_each(sources.iter(), |source| {
        ignore_missing(remove_source_filter(s, group_ip, source))
    })
    .map_err(|failures| failures.head.1)
}

/// Apply an operation, `op`, to every source, moving past failures.
///
/// # Errors
///
/// Returns each failing source paired with its error (in iteration order).
fn apply_each(
    sources: impl Iterator<Item = IpSrc>,
    mut op: impl FnMut(IpSrc) -> DpdResult<()>,
) -> Result<(), NonEmpty<(IpSrc, DpdError)>> {
    match NonEmpty::collect(
        sources
            .filter_map(|source| op(source.clone()).err().map(|e| (source, e))),
    ) {
        Some(failures) => Err(failures),
        None => Ok(()),
    }
}

/// Synchronize ASIC source-filter entries with the given `desired`
/// source filter.
///
/// This operation adds every entry into `desired`, and, if successful,
/// then removes entries in `current` that are not in the `desired` filter.
///
/// Existing additions and missing removals are ignored.
pub(super) fn sync_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    current: &SourceFilter,
    desired: &SourceFilter,
) -> Result<(), NonEmpty<(IpSrc, DpdError)>> {
    let current: BTreeSet<IpSrc> = current.iter().collect();
    let desired: BTreeSet<IpSrc> = desired.iter().collect();

    apply_each(desired.iter().cloned(), |source| {
        ignore_exists(add_source_filter(s, group_ip, source))
    })?;

    apply_each(current.difference(&desired).cloned(), |source| {
        ignore_missing(remove_source_filter(s, group_ip, source))
    })
}

/// Restore ASIC source-filter entries from `applied` to the `original`
/// source filter.
///
/// This operation adds every entry in `original`, then removes entries
/// present in the `applied` filter but not in the `original` one. The removals
/// run even if some additions fail.
///
/// Existing additions and missing removals are ignored. Failures from both
/// steps are returned along with their source.
pub(super) fn restore_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    applied: &SourceFilter,
    original: &SourceFilter,
) -> Result<(), NonEmpty<(IpSrc, DpdError)>> {
    let applied: BTreeSet<IpSrc> = applied.iter().collect();
    let original: BTreeSet<IpSrc> = original.iter().collect();

    let added = apply_each(original.iter().cloned(), |source| {
        ignore_exists(add_source_filter(s, group_ip, source))
    });
    let removed =
        apply_each(applied.difference(&original).cloned(), |source| {
            ignore_missing(remove_source_filter(s, group_ip, source))
        });

    match (added, removed) {
        (Err(mut failures), Err(more)) => {
            failures.extend(more);
            Err(failures)
        }
        (Err(failures), Ok(())) | (Ok(()), Err(failures)) => Err(failures),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[derive(Clone, Copy)]
enum SourceFilterKey {
    V4 { group: Ipv4Addr, prefix: Ipv4Net },
    V6 { group: Ipv6Addr, prefix: Ipv6Net },
}

impl SourceFilterKey {
    /// Pair a group address with a source as a source-filter table key.
    ///
    /// `IpSrc::Any` converts into the family's `/0` prefix (generic); an
    /// exact source becomes a host prefix.
    ///
    /// # Errors
    ///
    /// Returns [`DpdError::Invalid`] if an exact source's address family
    /// differs from `group_ip`'s.
    fn new(group_ip: IpAddr, source: IpSrc) -> DpdResult<Self> {
        match (group_ip, source) {
            (IpAddr::V4(group), IpSrc::Any) => Ok(Self::V4 {
                group,
                prefix: Ipv4Net::new_unchecked(Ipv4Addr::UNSPECIFIED, 0),
            }),
            (IpAddr::V4(group), IpSrc::Exact(IpAddr::V4(addr))) => {
                Ok(Self::V4 { group, prefix: Ipv4Net::host_net(addr) })
            }
            (IpAddr::V6(group), IpSrc::Any) => Ok(Self::V6 {
                group,
                prefix: Ipv6Net::new_unchecked(Ipv6Addr::UNSPECIFIED, 0),
            }),
            (IpAddr::V6(group), IpSrc::Exact(IpAddr::V6(addr))) => {
                Ok(Self::V6 { group, prefix: Ipv6Net::host_net(addr) })
            }
            (_, IpSrc::Exact(source)) => Err(DpdError::Invalid(format!(
                "source {source} does not match multicast group address \
                 family ({group_ip})"
            ))),
        }
    }

    /// Add this key's entry to the source-filter table.
    fn add(self, s: &Switch) -> DpdResult<()> {
        match self {
            Self::V4 { group, prefix } => {
                table::mcast::mcast_src_filter::add_ipv4_entry(s, prefix, group)
            }
            Self::V6 { group, prefix } => {
                table::mcast::mcast_src_filter::add_ipv6_entry(s, prefix, group)
            }
        }
    }

    /// Delete this key's entry from the source-filter table.
    fn del(self, s: &Switch) -> DpdResult<()> {
        match self {
            Self::V4 { group, prefix } => {
                table::mcast::mcast_src_filter::del_ipv4_entry(s, prefix, group)
            }
            Self::V6 { group, prefix } => {
                table::mcast::mcast_src_filter::del_ipv6_entry(s, prefix, group)
            }
        }
    }
}

fn add_source_filter(
    s: &Switch,
    group_ip: IpAddr,
    source: IpSrc,
) -> DpdResult<()> {
    SourceFilterKey::new(group_ip, source).and_then(|key| key.add(s))
}

fn remove_source_filter(
    s: &Switch,
    group_ip: IpAddr,
    source: IpSrc,
) -> DpdResult<()> {
    SourceFilterKey::new(group_ip, source).and_then(|key| key.del(s))
}

/// Validates that the request tag matches the existing group's tag.
///
/// Tags are immutable after group creation. A matching tag is evidence the
/// caller created the group.
fn validate_tag(existing_tag: &str, request_tag: &str) -> DpdResult<()> {
    if request_tag != existing_tag {
        return Err(DpdError::Invalid(
            "tag mismatch: provided tag does not match the group's tag"
                .to_string(),
        ));
    }
    Ok(())
}

/// Generate a default tag for a multicast group if none is provided.
///
/// Format: `{uuid}:{group_ip}` to match Omicron's tag format.
/// This ensures uniqueness across the group's lifecycle and prevents
/// tag collision when group IPs are reused after deletion.
fn generate_default_tag(group_ip: IpAddr) -> String {
    format!("{}:{group_ip}", Uuid::new_v4())
}

fn add_source_filters(
    s: &Switch,
    group_ip: IpAddr,
    sources: &SourceFilter,
) -> DpdResult<()> {
    let keys = sources
        .iter()
        .map(|source| SourceFilterKey::new(group_ip, source))
        .collect::<DpdResult<Vec<_>>>()?;

    keys.iter().enumerate().try_for_each(|(added, &key)| {
        key.add(s).map_err(|e| {
            after_unwind(
                e,
                unwind_outcome(keys[..added].iter().map(|key| key.del(s))),
            )
        })
    })
}

/// Delete every route, NAT, and source-filter entry identified by `group_ip`,
/// all before an external group is created at that address.
///
/// When group creation fails, a rollback failure can leave entries around
/// that no stored group owns. The NAT key includes the VLAN, so an entry
/// left under a different VLAN could keep translating this VLAN's traffic to
/// a stale target. And, a leftover source filter could keep admitting sources
/// a group should no longer allow.
fn clear_external_entries(s: &Switch, group_ip: IpAddr) -> DpdResult<()> {
    match group_ip {
        IpAddr::V4(ipv4) => {
            table::mcast::mcast_src_filter::del_ipv4_entries(s, ipv4)?;
            table::mcast::mcast_nat::del_ipv4_entries(s, ipv4)?;
            ignore_missing(table::mcast::mcast_route::del_ipv4_entry(s, ipv4))
        }
        IpAddr::V6(ipv6) => {
            table::mcast::mcast_src_filter::del_ipv6_entries(s, ipv6)?;
            table::mcast::mcast_nat::del_ipv6_entries(s, ipv6)?;
            ignore_missing(table::mcast::mcast_route::del_ipv6_entry(s, ipv6))
        }
    }
}

/// Configures external tables for an external multicast group.
fn configure_external_tables(
    s: &Switch,
    group_info: &MulticastGroupCreateExternalEntry,
    sources: &SourceFilter,
) -> DpdResult<()> {
    let group_ip: IpAddr = group_info.group_ip().into();
    let nat_target: NatTarget =
        group_info.internal_forwarding().nat_target.into();
    let vlan_id = group_info.external_forwarding().vlan_id;

    // Add source filter entries if needed
    add_source_filters(s, group_ip, sources)?;

    // Add NAT entry
    match group_ip {
        IpAddr::V4(ipv4) => {
            table::mcast::mcast_nat::add_ipv4_entry(
                s, ipv4, nat_target, vlan_id,
            )?;
        }
        IpAddr::V6(ipv6) => {
            table::mcast::mcast_nat::add_ipv6_entry(
                s, ipv6, nat_target, vlan_id,
            )?;
        }
    }

    // Add routing entry
    match group_ip {
        IpAddr::V4(ipv4) => {
            table::mcast::mcast_route::add_ipv4_entry(s, ipv4, vlan_id)
        }
        IpAddr::V6(ipv6) => {
            table::mcast::mcast_route::add_ipv6_entry(s, ipv6, vlan_id)
        }
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

    // Always allocate both group IDs to avoid allocation delays during member
    // addition
    let external_group_id = mcast.generate_group_id()?;
    let underlay_group_id = mcast.generate_group_id()?;

    // Remove any stale decap bitmap data for external multicast groups
    // before using the recycled external ID.
    //
    // A failed rollback can leave ASIC entries behind. A restart can also
    // repopulate the free pool while the ASIC retains its entries.
    // `tbl_decap_ports` is keyed only by `egress_rid`, so a group without a
    // bitmap of its own could inherit a stale entry.
    ignore_missing(table::mcast::mcast_egress::del_bitmap_entry(
        s,
        external_group_id.id(),
    ))?;

    create_asic_group(s, external_group_id.id(), group_ip)?;
    create_asic_group(s, underlay_group_id.id(), group_ip).map_err(|e| {
        after_unwind(
            e,
            ignore_missing(
                s.asic_hdl
                    .mc_group_destroy(external_group_id.id())
                    .map_err(DpdError::from),
            ),
        )
    })?;

    Ok((external_group_id, underlay_group_id))
}

fn delete_multicast_groups(
    s: &Switch,
    group_ip: IpAddr,
    external_id: MulticastGroupId,
    underlay_id: MulticastGroupId,
) -> DpdResult<()> {
    let mut first_err = None;

    match s.asic_hdl.mc_group_destroy(external_id) {
        Ok(()) | Err(AsicError::Missing(_)) => {}
        Err(e) => {
            warn!(
                s.log,
                "failed to delete external multicast group";
                "group_ip" => %group_ip,
                "group_id" => external_id,
                "error" => ?e,
            );
            first_err.get_or_insert_with(|| e.into());
        }
    }

    match s.asic_hdl.mc_group_destroy(underlay_id) {
        Ok(()) | Err(AsicError::Missing(_)) => {}
        Err(e) => {
            warn!(
                s.log,
                "failed to delete underlay multicast group";
                "group_ip" => %group_ip,
                "group_id" => underlay_id,
                "error" => ?e,
            );
            first_err.get_or_insert_with(|| e.into());
        }
    }

    match first_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn create_asic_group(
    s: &Switch,
    group_id: MulticastGroupId,
    group_ip: IpAddr,
) -> DpdResult<()> {
    let log_failure = |e: AsicError| {
        error!(
            s.log,
            "failed to create multicast group";
            "group_ip" => %group_ip,
            "group_id" => group_id,
            "error" => ?e,
        );
        DpdError::from(e)
    };

    match s.asic_hdl.mc_group_create(group_id) {
        Err(AsicError::Exists(detail)) => {
            warn!(
                s.log,
                "recreating recycled multicast group";
                "group_ip" => %group_ip,
                "group_id" => group_id,
                "detail" => detail,
            );

            ignore_missing(
                s.asic_hdl.mc_group_destroy(group_id).map_err(DpdError::from),
            )?;

            s.asic_hdl.mc_group_create(group_id).map_err(log_failure)
        }
        res => res.map_err(log_failure),
    }
}

fn add_ports_to_groups(
    s: &Switch,
    group_ip: IpAddr,
    members: &[MulticastGroupMember],
    external_group_id: MulticastGroupId,
    underlay_group_id: MulticastGroupId,
    replication_info: &MulticastReplicationInfo,
    added_members: &mut Vec<MulticastGroupMember>,
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
                error!(
                    s.log,
                    "failed to add port to multicast group";
                    "group_ip" => %group_ip,
                    "port" => %member.port_id,
                    "error" => ?e,
                );
                DpdError::from(e)
            })?;

        added_members.push(member.clone());
    }

    Ok(())
}

fn process_membership_changes(
    s: &Switch,
    new_members: &[MulticastGroupMember],
    group_entry: &MulticastGroup,
    replication_info: &MulticastReplicationInfo,
    added_members: &mut Vec<MulticastGroupMember>,
    removed_members: &mut Vec<MulticastGroupMember>,
) -> DpdResult<()> {
    let group_ip = group_entry.ip();

    let prev_members = group_entry.members().collect::<HashSet<_>>();
    let new_members_set = new_members.iter().collect::<HashSet<_>>();

    // Remove members from ASIC
    let mut seen = HashSet::new();
    for member in group_entry
        .members()
        .filter(|m| !new_members_set.contains(m) && seen.insert(*m))
    {
        let group_id = group_entry.group_id(member.direction);

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        removed_members.push(member.clone());

        match s.asic_hdl.mc_port_remove(group_id, asic_id) {
            Ok(()) => {}
            Err(AsicError::Missing(detail)) => debug!(
                s.log,
                "port already absent from multicast group";
                "group_ip" => %group_ip,
                "port" => %member.port_id,
                "detail" => detail,
            ),
            Err(e) => {
                error!(
                    s.log,
                    "failed to remove port from multicast group";
                    "group_ip" => %group_ip,
                    "port" => %member.port_id,
                    "error" => ?e,
                );
                return Err(e.into());
            }
        }
    }

    // Add all members to the ASIC with those already present being ignored
    let mut seen = HashSet::new();
    for member in new_members.iter().filter(|m| seen.insert(*m)) {
        let group_id = group_entry.group_id(member.direction);

        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        match s.asic_hdl.mc_port_add(
            group_id,
            asic_id,
            replication_info.rid,
            replication_info.level1_excl_id,
        ) {
            Ok(()) => {}
            Err(AsicError::Exists(detail)) => debug!(
                s.log,
                "port already present in multicast group";
                "group_ip" => %group_ip,
                "port" => %member.port_id,
                "detail" => detail,
            ),
            Err(e) => {
                error!(
                    s.log,
                    "failed to add port to multicast group";
                    "group_ip" => %group_ip,
                    "port" => %member.port_id,
                    "error" => ?e,
                );
                return Err(e.into());
            }
        }

        if !prev_members.contains(member) {
            added_members.push(member.clone());
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn configure_underlay_tables(
    s: &Switch,
    group_ip: UnderlayMulticastIpv6,
    external_group_id: MulticastGroupId,
    underlay_group_id: MulticastGroupId,
    replication_info: Option<&MulticastReplicationInfo>,
    added_members: &[MulticastGroupMember],
    vlan_id: Option<u16>, // VLAN ID from referencing external group
) -> DpdResult<()> {
    let ipv6 = Ipv6Addr::from(group_ip);

    if let Some(replication_info) = replication_info {
        // Add a bitmap entry for overlay members only
        // (the decap decision is only needed for overlay traffic)
        let external_port_bitmap =
            create_port_bitmap(added_members, Direction::External);
        table::mcast::mcast_egress::add_bitmap_entry(
            s,
            external_group_id,
            &external_port_bitmap,
            vlan_id, // VLAN from referencing external group
        )?;
        table::mcast::mcast_replication::add_ipv6_entry(
            s,
            ipv6,
            underlay_group_id,
            external_group_id,
            replication_info.rid,
            replication_info.level1_excl_id,
            replication_info.level2_excl_id,
        )?;
    }

    table::mcast::mcast_route::add_ipv6_entry(
        s, ipv6, vlan_id, // VLAN from referencing external group
    )
}

fn add_replication_entry(
    s: &Switch,
    group_entry: &MulticastGroup,
    replication_info: &MulticastReplicationInfo,
) -> DpdResult<()> {
    let GroupKind::Underlay { group_ip, .. } = &group_entry.kind else {
        return Ok(());
    };

    let ipv6 = Ipv6Addr::from(*group_ip);

    match table::mcast::mcast_replication::add_ipv6_entry(
        s,
        ipv6,
        group_entry.underlay_group_id(),
        group_entry.external_group_id(),
        replication_info.rid,
        replication_info.level1_excl_id,
        replication_info.level2_excl_id,
    ) {
        Err(DpdError::Switch(AsicError::Exists(_))) => {
            update_replication_tables(
                s,
                ipv6,
                group_entry.external_group_id(),
                group_entry.underlay_group_id(),
                replication_info,
            )
        }
        res => res,
    }
}

/// A pending VLAN change to an underlay group's port bitmap.
///
/// An external multicast group propagates its VLAN onto the underlay group
/// mapped by its NAT target. Retargeting the NAT target or modifying the
/// VLAN yields an update for the new underlay group, and, when that target
/// is moved, a second update clearing the old one.
struct BitmapVlanUpdate<'a> {
    group: &'a MulticastGroup,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
}

fn update_external_tables(
    s: &Switch,
    group_entry: &MulticastGroup,
    new_group_info: &MulticastGroupUpdateExternalEntry,
    old_nat_target: ExternalNatTarget,
    old_sources: &SourceFilter,
    new_sources: &SourceFilter,
    bitmap_updates: &[BitmapVlanUpdate<'_>],
) -> DpdResult<()> {
    let group_ip = group_entry.ip();

    // Sync sources first
    sync_source_filters(s, group_ip, old_sources, new_sources)
        .map_err(|failures| failures.head.1)?;

    let old_vlan_id = group_entry.vlan_id();
    let new_vlan_id = new_group_info.external_forwarding.vlan_id;

    let new_nat_target = new_group_info.internal_forwarding.nat_target;

    // Route tables use simple dst_addr matching but select forward vs forward_vlan action
    match group_ip {
        IpAddr::V4(ipv4) => {
            table::mcast::mcast_route::ensure_ipv4_entry(s, ipv4, new_vlan_id)
        }
        IpAddr::V6(ipv6) => {
            table::mcast::mcast_route::ensure_ipv6_entry(s, ipv6, new_vlan_id)
        }
    }?;

    let mut attempted_bitmaps = 0;

    let res = (|| {
        for update in bitmap_updates {
            attempted_bitmaps += 1;
            ensure_bitmap_vlan(s, update.group, update.new_vlan_id)?;
        }

        // Update NAT target as external groups always have NAT targets;
        // this also handles VLAN changes since VLAN is part of the NAT match
        // key
        update_nat_tables(
            s,
            group_ip,
            new_nat_target.into(),
            old_nat_target.into(),
            old_vlan_id,
            new_vlan_id,
        )?;
        Ok(())
    })();

    match res {
        Ok(()) => Ok(()),
        Err(e) => {
            let rollback_ctx =
                GroupUpdateRollbackContext::new(s, group_entry, new_vlan_id);

            Err(rollback_ctx.rollback_with_bitmap_restore(
                e,
                bitmap_updates[..attempted_bitmaps]
                    .iter()
                    .rev()
                    .map(|update| (update.group, update.old_vlan_id)),
            ))
        }
    }
}

/// Delete bitmap entries for a group with replication checks.
fn delete_group_bitmap_entries(
    s: &Switch,
    group: &MulticastGroup,
) -> DpdResult<()> {
    // Underlay groups delete entries even when `Replication::Empty` because
    // a failed rollback can leave entries behind.
    //
    // Note: external groups share the underlay group's IDs, but never own
    // a bitmap entry.
    if group.replication().is_none() {
        return Ok(()); // External group
    }
    // Delete external bitmap entry only (underlay doesn't use decap bitmap)
    ignore_missing(table::mcast::mcast_egress::del_bitmap_entry(
        s,
        group.external_group_id(),
    ))
}

fn add_group_bitmap_entries(
    s: &Switch,
    group: &MulticastGroup,
    vlan_id: Option<u16>,
) -> DpdResult<()> {
    if group.replication_info().is_none() {
        return Ok(());
    }
    let port_bitmap = create_port_bitmap(group.members(), Direction::External);
    table::mcast::mcast_egress::add_bitmap_entry(
        s,
        group.external_group_id(),
        &port_bitmap,
        vlan_id,
    )
}

/// Cleanup replication tables when transitioning group to empty membership.
///
/// Handles the complete cleanup process including bitmap and
/// replication entries.
fn cleanup_empty_group_replication(
    s: &Switch,
    group_entry: &MulticastGroup,
    external_group_vlan_id: Option<u16>,
) -> DpdResult<()> {
    let group_ip = group_entry.ip();

    debug!(s.log, "cleaning up replication for empty group {group_ip}");

    // Only proceed if group actually has replication info to clean up
    if group_entry.replication_info().is_none() {
        return Ok(());
    }

    delete_group_bitmap_entries(s, group_entry)?;

    if let Err(err) = delete_replication_entries(s, group_entry) {
        if let Err(restore_err) =
            add_group_bitmap_entries(s, group_entry, external_group_vlan_id)
        {
            return Err(DpdError::McastGroupFailure(format!(
                "failed to delete replication entry: {err:?}; failed to restore bitmap: {restore_err:?}"
            )));
        }
        return Err(err);
    }

    Ok(())
}

/// Delete replication table entries.
fn delete_replication_entries(
    s: &Switch,
    group: &MulticastGroup,
) -> DpdResult<()> {
    // As with the bitmap, underlay groups delete even when
    // `Replication::Empty`.
    let GroupKind::Underlay { group_ip, .. } = &group.kind else {
        return Ok(());
    };
    ignore_missing(table::mcast::mcast_replication::del_ipv6_entry(
        s,
        Ipv6Addr::from(*group_ip),
    ))
}

fn delete_group_tables(
    s: &Switch,
    group: &MulticastGroup,
    deleted: &mut Vec<DeleteStep>,
) -> DpdResult<()> {
    let group_ip = group.ip();

    match &group.kind {
        GroupKind::External { sources, vlan_id, .. } => {
            deleted.push(DeleteStep::SourceFilters);
            remove_source_filters(s, group_ip, sources)?;
            ignore_missing(match group_ip {
                IpAddr::V4(ipv4) => {
                    table::mcast::mcast_nat::del_ipv4_entry(s, ipv4, *vlan_id)
                }
                IpAddr::V6(ipv6) => {
                    table::mcast::mcast_nat::del_ipv6_entry(s, ipv6, *vlan_id)
                }
            })?;
            deleted.push(DeleteStep::Nat);
        }
        GroupKind::Underlay { .. } => {
            delete_replication_entries(s, group)?;
            deleted.push(DeleteStep::Replication);

            delete_group_bitmap_entries(s, group)?;
            deleted.push(DeleteStep::Bitmap);
        }
    }

    ignore_missing(match group_ip {
        IpAddr::V4(ipv4) => table::mcast::mcast_route::del_ipv4_entry(s, ipv4),
        IpAddr::V6(ipv6) => table::mcast::mcast_route::del_ipv6_entry(s, ipv6),
    })?;
    deleted.push(DeleteStep::Route);

    Ok(())
}

fn update_replication_tables(
    s: &Switch,
    group_ip: Ipv6Addr,
    external_group_id: MulticastGroupId,
    underlay_group_id: MulticastGroupId,
    replication_info: &MulticastReplicationInfo,
) -> DpdResult<()> {
    table::mcast::mcast_replication::update_ipv6_entry(
        s,
        group_ip,
        underlay_group_id,
        external_group_id,
        replication_info.rid,
        replication_info.level1_excl_id,
        replication_info.level2_excl_id,
    )
}

fn update_nat_tables(
    s: &Switch,
    group_ip: IpAddr,
    new_nat_target: NatTarget,
    old_nat_target: NatTarget,
    old_vlan_id: Option<u16>,
    new_vlan_id: Option<u16>,
) -> DpdResult<()> {
    // The VLAN is part of the NAT match key, which must be handled
    // inside the table update.
    match group_ip {
        IpAddr::V4(ipv4) => table::mcast::mcast_nat::update_ipv4_entry(
            s,
            ipv4,
            new_nat_target,
            old_nat_target,
            old_vlan_id,
            new_vlan_id,
        ),
        IpAddr::V6(ipv6) => table::mcast::mcast_nat::update_ipv6_entry(
            s,
            ipv6,
            new_nat_target,
            old_nat_target,
            old_vlan_id,
            new_vlan_id,
        ),
    }
}

/// Set an underlay group's bitmap entry from its members.
fn update_underlay_group_bitmap_tables(
    s: &Switch,
    group: &MulticastGroup,
    new_members: &[MulticastGroupMember],
    external_group_vlan: Option<u16>,
) -> DpdResult<()> {
    let external_group_id = group.external_group_id();
    if new_members.is_empty() {
        return Ok(());
    }

    // Create bitmap for overlay members only (decapsulation decision applies only to overlay traffic)
    let external_port_bitmap =
        create_port_bitmap(new_members, Direction::External);

    let Some(Replication::Active { info, .. }) = group.replication() else {
        // First time adding members - use add_bitmap_entry with external group's VLAN
        return match table::mcast::mcast_egress::add_bitmap_entry(
            s,
            external_group_id,
            &external_port_bitmap,
            external_group_vlan, // Use external group's VLAN for bitmap entries
        ) {
            Err(DpdError::Switch(AsicError::Exists(_))) => {
                table::mcast::mcast_egress::update_bitmap_entry(
                    s,
                    external_group_id,
                    &external_port_bitmap,
                    external_group_vlan,
                )
            }
            res => res,
        };
    };

    // Members remain -> update the entry with the external group's VLAN
    match table::mcast::mcast_egress::update_bitmap_entry(
        s,
        external_group_id,
        &external_port_bitmap,
        external_group_vlan, // Use external group's VLAN for bitmap entries
    ) {
        Err(DpdError::Switch(AsicError::Missing(detail))) => {
            warn!(
                s.log,
                "re-adding missing multicast bitmap entry";
                "group_ip" => %group.ip(),
                "detail" => detail,
            );
            readd_underlay_entries(
                s,
                group,
                info,
                &external_port_bitmap,
                external_group_vlan,
            )
        }
        res => res,
    }
}

/// Update forwarding tables during rollback.
///
/// Only updates the external bitmap entry since that's the only bitmap
/// entry created during group configuration. The underlay replication
/// is handled separately via the ASIC's multicast group primitives.
///
/// # Arguments
///
/// * `s` - Switch instance for table operations.
/// * `group` - The group's state before the failed update. The IPv6 path
///   rewrites its bitmap entry only if it is a [`Replication::Active`]
///   underlay group.
/// * `current_vlan_id` - VLAN currently in the table (may be the attempted new
///   VLAN).
/// * `target_vlan_id` - VLAN to restore to (the original VLAN).
fn update_fwding_tables(
    s: &Switch,
    group: &MulticastGroup,
    current_vlan_id: Option<u16>,
    target_vlan_id: Option<u16>,
) -> DpdResult<()> {
    match group.ip() {
        IpAddr::V4(ipv4) => table::mcast::mcast_route::update_ipv4_entry(
            s,
            ipv4,
            current_vlan_id,
            target_vlan_id,
        ),
        IpAddr::V6(ipv6) => table::mcast::mcast_route::update_ipv6_entry(
            s,
            ipv6,
            current_vlan_id,
            target_vlan_id,
        )
        .and_then(|_| {
            // Update external bitmap for external members (only external bitmap
            // entries exist, whereas underlay replication uses ASIC multicast
            // groups directly).
            //
            // `update_bitmap_vlan` skips groups that are not replicating, so
            // rollback on an empty or external group leaves the bitmap alone.
            update_bitmap_vlan(s, group, target_vlan_id)
        }),
    }
}

/// Create port bitmap from members filtered by direction.
fn create_port_bitmap<'a>(
    members: impl IntoIterator<Item = &'a MulticastGroupMember>,
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
    use std::thread;

    use common::ports::RearPort;
    use dpd_types::link::LinkId;
    use dpd_types::mcast::{
        ExactSource, MAX_TAG_LENGTH, MulticastGroupCreateExternalError,
        SourceEntry,
    };

    use super::*;

    #[test]
    fn test_validate_tag() {
        // Existing tag matches request tag
        assert!(validate_tag("my-tag", "my-tag").is_ok());

        // Existing tag but request has different tag
        assert!(validate_tag("owner-a", "owner-b").is_err());
        assert!(validate_tag("owner-a", "").is_err());
        assert!(validate_tag("owner-a", "tag/with/slashes").is_err());
    }

    #[test]
    fn test_tag_format_error_maps_to_bad_request() {
        for tag in [
            String::new(),
            "a".repeat(MAX_TAG_LENGTH + 1),
            "tag with spaces".to_string(),
        ] {
            let err = tag.parse::<MulticastTag>().unwrap_err();
            let expected = err.to_string();
            let err = DpdError::from(err);
            assert!(
                matches!(&err, DpdError::Invalid(message) if message == &expected)
            );
            let err = dropshot::HttpError::from(err);
            assert_eq!(err.status_code.as_u16(), 400);
            assert_eq!(err.external_message, expected);
        }
    }

    #[test]
    fn test_scoped_group_id_drop_returns_to_pool() {
        let free_ids = Arc::new(Mutex::new(vec![100, 102]));
        {
            let scoped_id = ScopedGroupId::from(ScopedIdInner(
                101,
                Arc::downgrade(&free_ids),
            ));
            assert_eq!(scoped_id.id(), 101);
        }

        // ID should be returned to pool
        assert_eq!(*free_ids.lock().unwrap(), vec![100, 102, 101]);
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
        match result.unwrap_err() {
            DpdError::ResourceExhausted(msg) => {
                assert!(msg.contains("no free multicast group IDs available"));
            }
            _ => panic!("Expected ResourceExhausted error"),
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

        // Every `ScopedGroupId` was already dropped before the join, meaning
        // that the pool is exactly full once again.
        let pool_size = {
            let data = mcast_data.lock().unwrap();

            data.free_group_ids.lock().unwrap().len()
        };

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

    #[test]
    fn test_create_port_bitmap_empty() {
        let members: Vec<MulticastGroupMember> = vec![];
        let bitmap = create_port_bitmap(&members, Direction::External);
        // Empty bitmap should have no ports
        assert!(!bitmap.contains_port(0));
        assert!(!bitmap.contains_port(1));
    }

    #[test]
    fn test_create_port_bitmap_filters_by_direction() {
        let members = vec![
            MulticastGroupMember {
                port_id: RearPort::new(1).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            },
            MulticastGroupMember {
                port_id: RearPort::new(2).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::Underlay,
            },
            MulticastGroupMember {
                port_id: RearPort::new(3).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            },
        ];

        // External bitmap should only contain ports 1 and 3
        let external_bitmap = create_port_bitmap(&members, Direction::External);
        assert!(external_bitmap.contains_port(1));
        assert!(!external_bitmap.contains_port(2));
        assert!(external_bitmap.contains_port(3));

        // Underlay bitmap should only contain port 2
        let underlay_bitmap = create_port_bitmap(&members, Direction::Underlay);
        assert!(!underlay_bitmap.contains_port(1));
        assert!(underlay_bitmap.contains_port(2));
        assert!(!underlay_bitmap.contains_port(3));
    }

    #[test]
    fn test_create_port_bitmap_all_same_direction() {
        let members = vec![
            MulticastGroupMember {
                port_id: RearPort::new(5).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            },
            MulticastGroupMember {
                port_id: RearPort::new(10).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            },
            MulticastGroupMember {
                port_id: RearPort::new(15).unwrap().into(),
                link_id: LinkId(0),
                direction: Direction::External,
            },
        ];

        let bitmap = create_port_bitmap(&members, Direction::External);
        assert!(bitmap.contains_port(5));
        assert!(bitmap.contains_port(10));
        assert!(bitmap.contains_port(15));
        assert!(!bitmap.contains_port(1)); // Not in members

        // Underlay bitmap should be empty
        let underlay_bitmap = create_port_bitmap(&members, Direction::Underlay);
        assert!(!underlay_bitmap.contains_port(5));
        assert!(!underlay_bitmap.contains_port(10));
        assert!(!underlay_bitmap.contains_port(15));
    }

    fn external_ip(addr: &str) -> ExternalMulticastIp {
        addr.parse().unwrap()
    }

    #[test]
    fn test_nat_target_group_must_exist() {
        let mcast_data = MulticastGroupData::new();
        let nat_target = NatTarget {
            internal_ip: "ff04::1".parse().unwrap(),
            inner_mac: common::network::MacAddr::new(1, 0, 0x5e, 0, 0, 1),
            vni: common::network::Vni::new(1).unwrap(),
        };

        let err = mcast_data
            .get_nat_target_group(
                "239.1.1.1".parse().unwrap(),
                nat_target.try_into().unwrap(),
            )
            .unwrap_err();
        assert!(matches!(err, DpdError::MissingNatTarget(_)), "{err:?}");
    }

    fn source_entries(
        sources: Option<&[IpSrc]>,
    ) -> Result<Option<Vec<SourceEntry>>, MulticastGroupCreateExternalError>
    {
        sources
            .map(|sources| {
                sources.iter().cloned().map(SourceEntry::try_from).collect()
            })
            .transpose()
    }

    fn canonicalize_sources(
        group_ip: ExternalMulticastIp,
        sources: Option<Vec<IpSrc>>,
    ) -> Option<Vec<IpSrc>> {
        let entries = source_entries(sources.as_deref()).unwrap();

        SourceFilter::from_entries(group_ip, entries.as_deref())
            .unwrap()
            .to_ip_sources()
    }

    #[test]
    fn test_canonicalize_sources() {
        let asm_group = external_ip("224.1.2.3");

        // None stays None
        assert_eq!(canonicalize_sources(asm_group, None), None);

        // Empty vec normalizes to None
        assert_eq!(canonicalize_sources(asm_group, Some(vec![])), None);

        // Vec with only IpSrc::Any normalizes to None
        assert_eq!(
            canonicalize_sources(asm_group, Some(vec![IpSrc::Any])),
            None
        );

        // Vec with Any mixed with Exact normalizes to None (Any subsumes all)
        assert_eq!(
            canonicalize_sources(
                asm_group,
                Some(vec![
                    IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    IpSrc::Any,
                ])
            ),
            None
        );

        // A vec with only Exact sources is deduplicated and sorted
        assert_eq!(
            canonicalize_sources(
                asm_group,
                Some(vec![
                    IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                ])
            ),
            Some(vec![
                IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                IpSrc::Exact(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            ])
        );

        // Single Exact source stays as-is
        let ipv6_group = external_ip("ff0e::1");
        assert_eq!(
            canonicalize_sources(
                ipv6_group,
                Some(vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
                )))])
            ),
            Some(vec![IpSrc::Exact(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
            )))])
        );
    }

    #[test]
    fn test_group_key_order_and_lookup() {
        let first_external = external_ip("224.1.2.3");
        let second_external = external_ip("239.255.255.250");
        let third_external = external_ip("ff0e::1");
        let underlay: UnderlayMulticastIpv6 = "ff04::1".parse().unwrap();

        let mut map: BTreeMap<GroupKey, u8> = BTreeMap::new();
        map.insert(GroupKey::external(third_external), 4);
        map.insert(GroupKey::external(second_external), 2);
        map.insert(GroupKey::underlay(underlay), 3);
        map.insert(GroupKey::external(first_external), 1);

        assert_eq!(map.get(&"224.1.2.3".parse::<IpAddr>().unwrap()), Some(&1));
        assert_eq!(
            map.get(&"239.255.255.250".parse::<IpAddr>().unwrap()),
            Some(&2)
        );
        assert_eq!(map.get(&"ff04::1".parse::<IpAddr>().unwrap()), Some(&3));
        assert_eq!(map.get(&"10.0.0.1".parse::<IpAddr>().unwrap()), None);

        let ipv6_only: Vec<IpAddr> = map
            .range((
                Bound::Included("ff00::".parse::<IpAddr>().unwrap()),
                Bound::Unbounded,
            ))
            .map(|(key, _)| key.ip())
            .collect();
        assert_eq!(
            ipv6_only,
            vec![
                "ff04::1".parse::<IpAddr>().unwrap(),
                "ff0e::1".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_source_filter_create_and_update_agree() {
        type SourceFilterCase =
            (&'static str, Option<Vec<IpSrc>>, Option<SourceFilter>);

        let exact_source = |addr: &str| addr.parse::<ExactSource>().unwrap();
        let exact = |addr: &str| IpSrc::Exact(addr.parse::<IpAddr>().unwrap());

        let cases: Vec<SourceFilterCase> = vec![
            // ASM: 1) absent, 2) empty, 3) just Any, and 4) mixed Any for
            // any source.
            ("224.1.2.3", None, Some(SourceFilter::Any)),
            ("224.1.2.3", Some(vec![]), Some(SourceFilter::Any)),
            ("224.1.2.3", Some(vec![IpSrc::Any]), Some(SourceFilter::Any)),
            (
                "224.1.2.3",
                Some(vec![IpSrc::Any, exact("10.1.1.1")]),
                Some(SourceFilter::Any),
            ),
            // ASM: exact sources are deduplicated and sorted.
            (
                "224.1.2.3",
                Some(vec![exact("10.1.1.2"), exact("10.1.1.1")]),
                Some(SourceFilter::from_exact([
                    exact_source("10.1.1.1"),
                    exact_source("10.1.1.2"),
                ])),
            ),
            // SSM: exact sources are required and preserved.
            (
                "232.1.2.3",
                Some(vec![exact("10.1.1.1")]),
                Some(SourceFilter::from_exact([exact_source("10.1.1.1")])),
            ),
            // SSM: 1) absent, 2) empty, 3) Any, and 4) mixed Any are rejected.
            ("232.1.2.3", None, None),
            ("232.1.2.3", Some(vec![]), None),
            ("232.1.2.3", Some(vec![IpSrc::Any]), None),
            ("232.1.2.3", Some(vec![IpSrc::Any, exact("10.1.1.1")]), None),
            ("ff0e::1", None, Some(SourceFilter::Any)),
            ("ff0e::1", Some(vec![]), Some(SourceFilter::Any)),
            ("ff0e::1", Some(vec![IpSrc::Any]), Some(SourceFilter::Any)),
            (
                "ff0e::1",
                Some(vec![IpSrc::Any, exact("2001:db8::1")]),
                Some(SourceFilter::Any),
            ),
            (
                "ff3e::4000:1",
                Some(vec![
                    exact("2001:db8::2"),
                    exact("2001:db8::1"),
                    exact("2001:db8::2"),
                ]),
                Some(SourceFilter::from_exact([
                    exact_source("2001:db8::1"),
                    exact_source("2001:db8::2"),
                ])),
            ),
            ("ff3e::4000:1", None, None),
            ("ff3e::4000:1", Some(vec![]), None),
            ("ff3e::4000:1", Some(vec![IpSrc::Any]), None),
            (
                "ff3e::4000:1",
                Some(vec![IpSrc::Any, exact("2001:db8::1")]),
                None,
            ),
            // Invalid source addresses and family mismatches are rejected.
            ("224.1.2.3", Some(vec![exact("2001:db8::1")]), None),
            ("ff0e::1", Some(vec![exact("10.1.1.1")]), None),
            ("232.1.2.3", Some(vec![exact("0.0.0.0")]), None),
            ("ff3e::4000:1", Some(vec![exact("fe80::1")]), None),
            ("224.1.2.3", Some(vec![IpSrc::Any, exact("224.9.9.9")]), None),
            ("224.1.2.3", Some(vec![IpSrc::Any, exact("2001:db8::1")]), None),
            (
                "ff0e::1",
                Some(vec![IpSrc::Any, exact("::ffff:192.0.2.1")]),
                None,
            ),
            ("ff0e::1", Some(vec![IpSrc::Any, exact("10.1.1.1")]), None),
        ];

        for (group_ip, sources, expected) in cases {
            let group = external_ip(group_ip);
            let body = serde_json::json!({
                "group_ip": group_ip,
                "tag": null,
                "internal_forwarding": {
                    "nat_target": {
                        "internal_ip": "ff04::1",
                        "inner_mac": { "a": [1, 0, 94, 0, 0, 1] },
                        "vni": 100,
                    }
                },
                "external_forwarding": { "vlan_id": null },
                "sources": serde_json::to_value(&sources).unwrap(),
            });

            let created = serde_json::from_value::<
                MulticastGroupCreateExternalEntry,
            >(body);
            let updated =
                source_entries(sources.as_deref()).and_then(|entries| {
                    SourceFilter::from_entries(group, entries.as_deref())
                });

            match expected {
                Some(expected) => {
                    let created = SourceFilter::from(&created.unwrap());
                    assert_eq!(
                        created, expected,
                        "create filter for {group_ip} with {sources:?}"
                    );
                    assert_eq!(
                        updated.unwrap(),
                        expected,
                        "update filter for {group_ip} with {sources:?}"
                    );
                }
                None => {
                    assert!(
                        created.is_err(),
                        "create should reject {group_ip} with {sources:?}"
                    );
                    assert!(
                        updated.is_err(),
                        "update should reject {group_ip} with {sources:?}"
                    );
                }
            }
        }
    }
}
