use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::atomic::{AtomicU16, Ordering},
};

use crate::{
    link::LinkId,
    route, table,
    types::{DpdError, DpdResult},
    Switch,
};
use aal::{AsicId, AsicOps};
use common::{nat::NatTarget, ports::PortId};
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, error};

/// Type alias for multicast group IDs.
pub type MulticastGroupId = u16;

/// Represents a member of a multicast group.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupMember {
    pub port_id: PortId,
    pub link_id: LinkId,
    pub vlan_id: Option<u16>,
    pub nat_target: Option<NatTarget>,
}

/// Represents a multicast group configuration.
#[derive(Clone, Debug)]
pub struct MulticastGroup {
    pub tag: Option<String>,
    pub members: Vec<MulticastGroupMember>,
}

/// Stores multicast group configurations.
#[derive(Debug)]
pub struct MulticastGroupData {
    /// Multicast group configurations keyed by group ID.
    groups: HashMap<MulticastGroupId, MulticastGroup>,
    /// Top-level routes mapping IP addresses to multicast group IDs and ASIC
    /// table parameters.
    routes: MulticastRoutes,
    /// Atomic counter for generating unique multicast group IDs.
    id_generator: AtomicU16,
}

impl MulticastGroupData {
    pub const GENERATOR_START: u16 = 100;

    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            routes: MulticastRoutes::new(),
            // Start at a threshold to avoid early allocations
            id_generator: AtomicU16::new(Self::GENERATOR_START),
        }
    }

    /// Generate a unique multicast group ID.
    pub fn generate_group_id(&self) -> DpdResult<MulticastGroupId> {
        // Use a range starting from current counter value
        for _ in Self::GENERATOR_START..u16::MAX {
            // Atomically get the next ID from our counter
            let id = self.id_generator.fetch_add(1, Ordering::SeqCst);

            // Check if this ID is already in use
            if !self.groups.contains_key(&id) {
                return Ok(id);
            }
        }

        // We couldn't find any free ID in the entire range
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

/// Represents a multicast route configuration.
pub struct MulticastRoute {
    pub group_id: MulticastGroupId,
    pub group_info: (MulticastGroup, Vec<IpAddr>),
    pub ip: IpAddr,
    pub level1_excl_id: u16,
    pub level2_excl_id: u16,
}

/// Add a multicast group to the switch, which creates the group on the ASIC.
pub async fn add_group(
    s: &Switch,
    group_id: MulticastGroupId,
    tag: Option<impl ToString>,
    members: Vec<MulticastGroupMember>,
) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().await;

    if mcast.groups.contains_key(&group_id) {
        return Err(DpdError::Invalid(format!(
            "multicast group {} already exists",
            group_id
        )));
    }

    debug!(s.log, "creating multicast group {}", group_id);

    // First, create the group on the ASIC
    s.asic_hdl.mc_group_create(group_id).map_err(|e| {
        DpdError::McastGroup(format!(
            "failed to create multicast group: {:?}",
            e
        ))
    })?;

    for member in &members {
        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        match s.asic_hdl.mc_port_add(group_id, asic_id) {
            Ok(_) => {
                if let Some(nat_target) = member.nat_target {
                    // Use asic_id as replication_id for NAT entries
                    table::mcast::add_nat_entry(
                        s, group_id, asic_id, nat_target,
                    )?
                }
            }
            Err(e) => {
                if let Err(clean_err) = s.asic_hdl.mc_group_destroy(group_id) {
                    error!(s.log, "cleanup failed after port add error";
                        "group_id" => group_id,
                        "error" => ?clean_err
                    );
                }
                return Err(DpdError::McastGroup(format!(
                    "failed to add port: {:?}",
                    e
                )));
            }
        }
    }

    // Store the configuration
    mcast.groups.insert(
        group_id,
        MulticastGroup {
            tag: tag.map(|t| t.to_string()),
            members,
        },
    );

    Ok(())
}

/// Delete a multicast group from the switch.
pub async fn del_group(
    s: &Switch,
    group_id: MulticastGroupId,
) -> DpdResult<()> {
    // First, get the lock to validate the group and retrieve routes
    let mut mcast = s.mcast.lock().await;

    if !mcast.groups.contains_key(&group_id) {
        return Err(DpdError::Missing(format!(
            "multicast group {} not found",
            group_id
        )));
    }

    let routes = mcast.routes.get_routes_for_group(group_id);

    for ip in routes {
        mcast.routes.remove_route(&ip, group_id);

        // We only delete the entry from the underlying table if it's not used
        // by any other group (i.e., no routes left for this IP)
        if mcast.routes.get_groups_for_route(&ip).is_empty() {
            del_entry(s, ip).await?;
        }
    }

    // Then, remove each member from the nat table
    for member in &mcast.groups[&group_id].members {
        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;
        if member.nat_target.is_some() {
            del_nat_entry(s, group_id, asic_id)?;
        }
    }

    // Delete the group from the ASIC, which also deletes the associated ports
    s.asic_hdl.mc_group_destroy(group_id).map_err(|e| {
        DpdError::McastGroup(format!(
            "failed to delete multicast group: {:?}",
            e
        ))
    })?;

    // Remove from our tracking
    mcast.groups.remove(&group_id);

    debug!(s.log, "deleting multicast group {}", group_id);

    Ok(())
}

/// Get a multicast group configuration.
pub async fn get_group(
    s: &Switch,
    group_id: MulticastGroupId,
) -> DpdResult<(MulticastGroup, Vec<IpAddr>)> {
    let mcast = s.mcast.lock().await;

    let group = mcast.groups.get(&group_id).cloned().ok_or_else(|| {
        DpdError::Missing(format!("multicast group {} not found", group_id))
    })?;

    let routes = mcast.routes.get_routes_for_group(group_id);
    Ok((group, routes))
}

/// Modify a multicast group configuration.
pub async fn modify_group(
    s: &Switch,
    group_id: MulticastGroupId,
    tag: Option<impl ToString>,
    members: Vec<MulticastGroupMember>,
) -> DpdResult<(MulticastGroup, Vec<IpAddr>)> {
    let mut mcast = s.mcast.lock().await;

    if !mcast.groups.contains_key(&group_id) {
        return Err(DpdError::Missing(format!(
            "multicast group {} not found",
            group_id
        )));
    }

    let mut seen_ports = HashSet::new();
    // Validate the new member list before making any changes
    for member in &members {
        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        // Check if this port is already in the group
        if !seen_ports.insert(asic_id) {
            return Err(DpdError::Invalid(format!(
            "duplicate port in multicast group: port {} link {} (asic_id {})",
            member.port_id, member.link_id, asic_id
        )));
        }
    }

    // Remove the existing group members
    for member in &mcast.groups[&group_id].members {
        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;
        match s.asic_hdl.mc_port_remove(group_id, asic_id) {
            Ok(_) => {
                if member.nat_target.is_some() {
                    del_nat_entry(s, group_id, asic_id)?;
                }
            }
            Err(e) => {
                return Err(DpdError::McastGroup(format!(
                    "failed to remove port: {:?}",
                    e
                )));
            }
        }
    }

    // Then, add the new members
    for member in &members {
        let asic_id = s.port_link_to_asic_id(member.port_id, member.link_id)?;

        match (s.asic_hdl.mc_port_add(group_id, asic_id), member.nat_target) {
            (Ok(_), Some(nat_target)) => {
                // Use asic_id as replication_id for NAT entries
                table::mcast::add_nat_entry(s, group_id, asic_id, nat_target)
                    .or_else(|e| {
                    if let DpdError::Exists(_) = &e {
                        table::mcast::update_nat_entry(
                            s, group_id, asic_id, nat_target,
                        )
                    } else {
                        Err(e)
                    }
                })?;
            }
            (Ok(_), None) => {
                // Port added successfully, no NAT target needed
            }
            (Err(e), _) => {
                // Port add failed, return an error
                return Err(DpdError::McastGroup(format!(
                    "failed to add port: {:?}",
                    e
                )));
            }
        }
    }

    // Update the group configuration
    let new_group = MulticastGroup {
        tag: tag.map(|t| t.to_string()),
        members,
    };

    mcast.groups.insert(group_id, new_group.clone());

    // Get the routes for this group
    let routes = mcast.routes.get_routes_for_group(group_id);

    Ok((new_group, routes))
}

/// List all multicast groups.
pub async fn list_groups(
    s: &Switch,
    tag: Option<&str>,
) -> Vec<(MulticastGroupId, MulticastGroup, Vec<IpAddr>)> {
    let mcast = s.mcast.lock().await;
    mcast
        .groups
        .iter()
        .filter(|(_, group)| tag.is_none() || group.tag.as_deref() == tag)
        .map(|(id, group)| {
            let routes = mcast.routes.get_routes_for_group(*id);
            (*id, group.clone(), routes)
        })
        .collect()
}

/// Reset all multicast groups (and associated routes) for a given tag.
pub async fn reset_tag(s: &Switch, tag: &str) -> DpdResult<()> {
    // Get groups to delete first while holding the lock
    let groups_to_delete = {
        let mcast = s.mcast.lock().await;
        mcast
            .groups
            .iter()
            .filter(|(_, group)| group.tag.as_deref() == Some(tag))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
    };

    if groups_to_delete.is_empty() {
        return Ok(());
    }

    // Delete each group (and associated routes)
    for group_id in groups_to_delete {
        if let Err(e) = del_group(s, group_id).await {
            error!(
                s.log,
                "failed to delete multicast group {}: {:?}", group_id, e
            );
        }
    }

    Ok(())
}

/// Reset all multicast groups (and associated routes) without a tag.
pub async fn reset_untagged(s: &Switch) -> DpdResult<()> {
    // Get groups to delete first while holding the lock
    let groups_to_delete = {
        let mcast = s.mcast.lock().await;
        mcast
            .groups
            .iter()
            .filter(|(_, group)| group.tag.is_none())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
    };

    if groups_to_delete.is_empty() {
        return Ok(());
    }

    // Delete each group (and associated route)
    for group_id in groups_to_delete {
        if let Err(e) = del_group(s, group_id).await {
            error!(
                s.log,
                "failed to delete multicast group {}: {:?}", group_id, e
            );
        }
    }

    Ok(())
}

/// Reset all multicast groups (and associated routes).
pub async fn reset(s: &Switch) -> DpdResult<()> {
    let group_ids = s.asic_hdl.mc_domains();

    // Delete each group
    for group_id in group_ids {
        if let Err(e) = s.asic_hdl.mc_group_destroy(group_id) {
            error!(
                s.log,
                "failed to delete multicast group {}: {:?}", group_id, e
            );
        }
    }

    // Clear what we've stored altogether
    let mut mcast = s.mcast.lock().await;
    table::mcast::reset_ipv4(s)?;
    table::mcast::reset_ipv6(s)?;
    table::mcast::reset_nat(s)?;
    mcast.groups.clear();
    mcast.routes.clear();

    Ok(())
}

/// Add a multicast route with associated group management.
pub async fn add_route(
    s: &Switch,
    ip: IpAddr,
    group_id: MulticastGroupId,
    level1_excl_id: Option<u16>,
    level2_excl_id: Option<u16>,
) -> DpdResult<MulticastRoute> {
    // Use default values for optional parameters
    let level1_excl_id = level1_excl_id.unwrap_or(0);
    let level2_excl_id = level2_excl_id.unwrap_or(0);

    // Check that the group exists
    let (group, routes) = get_group(s, group_id).await?;

    // Check if the route already exists for this group
    if routes.contains(&ip) {
        return Err(DpdError::Invalid(format!(
            "multicast route {} already exists in group {}",
            ip, group_id
        )));
    }

    let table = if ip.is_ipv4() {
        table::TableType::McastIpv4
    } else {
        table::TableType::McastIpv6
    };

    let table_size = s.table_size(table)?;
    if routes.len() as u32 > table_size - 1 {
        return Err(DpdError::TableFull(format!(
            "{table:?} full: {table_size} max routes / groups",
            table = table,
            table_size = table_size
        )));
    }

    // Create the multicast routes in the underlying tables
    match ip {
        IpAddr::V4(ipv4) => {
            table::mcast::add_ipv4_entry(
                s,
                ipv4,
                group_id,
                level1_excl_id,
                level2_excl_id,
            )?;

            // Create a /32 subnet for this specific multicast address
            let ipv4_net = Ipv4Net::new(ipv4, 32).map_err(|e| {
                DpdError::InvalidRoute(format!("invalid IPv4 address: {}", e))
            })?;

            // Add route information to router lookup
            for member in &group.members {
                let ipv4_route = route::Ipv4Route {
                    tag: group_id.to_string(), // Use group ID as tag for routes
                    port_id: member.port_id,
                    link_id: member.link_id,
                    tgt_ip: ipv4,
                    vlan_id: member.vlan_id,
                };

                route::add_route_ipv4(s, ipv4_net, ipv4_route).await?;
            }

            Ok::<(), DpdError>(())
        }
        IpAddr::V6(ipv6) => {
            table::mcast::add_ipv6_entry(
                s,
                ipv6,
                group_id,
                level1_excl_id,
                level2_excl_id,
            )?;

            // Create a /128 subnet for this specific multicast address
            let ipv6_net = Ipv6Net::new(ipv6, 128).map_err(|e| {
                DpdError::InvalidRoute(format!("invalid IPv6 address: {}", e))
            })?;

            // Add route information to router lookup
            for member in &group.members {
                let ipv6_route = route::Ipv6Route {
                    tag: group_id.to_string(), // Use group ID as tag for routes
                    port_id: member.port_id,
                    link_id: member.link_id,
                    tgt_ip: ipv6,
                    vlan_id: member.vlan_id,
                };

                route::add_route_ipv6(s, ipv6_net, ipv6_route).await?;
            }

            Ok::<(), DpdError>(())
        }
    }?;

    // Store the route in our mapping
    let mut mcast = s.mcast.lock().await;
    mcast
        .routes
        .add_route(ip, group_id, level1_excl_id, level2_excl_id);

    Ok(MulticastRoute {
        group_id,
        group_info: (group, routes),
        ip,
        level1_excl_id,
        level2_excl_id,
    })
}

/// Represents a route information representation.
pub enum RouteInfo {
    Results(Vec<MulticastRoute>),
    Result(MulticastRoute),
}

/// Get a multicast route configuration.
pub async fn get_route_info(
    s: &Switch,
    ip: IpAddr,
    group_id: Option<MulticastGroupId>,
) -> DpdResult<RouteInfo> {
    // Get route info while holding the lock
    let route_info = {
        let mcast = s.mcast.lock().await;
        mcast.routes.get_groups_for_route(&ip)
    };

    // Filter by group_id if specified
    let filtered_route_info = if let Some(gid) = group_id {
        route_info
            .into_iter()
            .filter(|info| info.group_id == gid)
            .collect()
    } else {
        route_info
    };

    // If there are no routes for this IP (and group if specified),
    // return an error
    if filtered_route_info.is_empty() {
        let error_msg: String = if let Some(gid) = group_id {
            format!("multicast route {} not found in group {}", ip, gid)
        } else {
            format!("multicast route {} not found in any group", ip)
        };

        return Err(DpdError::Missing(error_msg));
    }

    let mut routes = vec![];
    for info in filtered_route_info {
        // Use synchronous call or handle the async call correctly
        let (group, _) = get_group(s, info.group_id).await?;
        routes.push(MulticastRoute {
            group_id: info.group_id,
            group_info: (group, vec![ip]),
            ip,
            level1_excl_id: info.level1_excl_id,
            level2_excl_id: info.level2_excl_id,
        });
    }

    // Return either a single entry or multiple entries based on whether a group_id was specified
    match group_id {
        Some(_) => {
            // A group_id was specified, so we should have filtered to exactly one route
            let route = routes.into_iter().next().unwrap();
            Ok(RouteInfo::Result(route))
        }
        None => {
            // No group_id was specified, return all matching routes
            Ok(RouteInfo::Results(routes))
        }
    }
}

/// Modify a multicast route configuration.
pub async fn modify_route(
    s: &Switch,
    ip: IpAddr,
    group_id: MulticastGroupId,
    level1_excl_id: Option<u16>,
    level2_excl_id: Option<u16>,
) -> DpdResult<MulticastRoute> {
    // Use default values for optional parameters
    let level1_excl_id = level1_excl_id.unwrap_or(0);
    let level2_excl_id = level2_excl_id.unwrap_or(0);

    // Check that the group exists
    let (group, routes) = get_group(s, group_id).await?;

    // Check if the route already exists for this group
    if !routes.contains(&ip) {
        return Err(DpdError::Invalid(format!(
            "multicast route {} not found in group {}",
            ip, group_id
        )));
    }

    // Update the route in the underlying tables
    match ip {
        IpAddr::V4(ipv4) => {
            table::mcast::update_ipv4_entry(
                s,
                ipv4,
                group_id,
                level1_excl_id,
                level2_excl_id,
            )?;

            Ok::<(), DpdError>(())
        }
        IpAddr::V6(ipv6) => {
            table::mcast::update_ipv6_entry(
                s,
                ipv6,
                group_id,
                level1_excl_id,
                level2_excl_id,
            )?;

            Ok::<(), DpdError>(())
        }
    }?;

    // Update the route in our mapping
    let mut mcast = s.mcast.lock().await;
    mcast
        .routes
        .add_route(ip, group_id, level1_excl_id, level2_excl_id);

    let updated_routes = mcast.routes.get_routes_for_group(group_id);

    Ok(MulticastRoute {
        group_id,
        group_info: (group, updated_routes),
        ip,
        level1_excl_id,
        level2_excl_id,
    })
}

/// Delete a multicast route.
pub async fn del_route(
    s: &Switch,
    ip: IpAddr,
    group_id: Option<MulticastGroupId>,
) -> DpdResult<()> {
    let mut mcast = s.mcast.lock().await;

    if let Some(group_id) = group_id {
        // Check if the group exists
        if !mcast.groups.contains_key(&group_id) {
            return Err(DpdError::Missing(format!(
                "multicast group {} not found",
                group_id
            )));
        }

        mcast.routes.remove_route(&ip, group_id);
    } else {
        // Get all groups this route belongs to
        let group_ids = mcast
            .routes
            .get_groups_for_route(&ip)
            .into_iter()
            .map(|info| info.group_id)
            .collect::<Vec<_>>();

        if group_ids.is_empty() {
            return Err(DpdError::Missing(format!(
                "multicast route {} not found in any group",
                ip
            )));
        }

        // Remove route from all groups in our mapping
        for group_id in group_ids {
            mcast.routes.remove_route(&ip, group_id);
        }
    }

    // We only delete the entry from the table if it's not used by any other
    // group
    if mcast.routes.get_groups_for_route(&ip).is_empty() {
        del_entry(s, ip).await?;
    }

    Ok(())
}

async fn del_entry(s: &Switch, ip: IpAddr) -> DpdResult<()> {
    match ip {
        IpAddr::V4(ipv4) => {
            table::mcast::del_ipv4_entry(s, ipv4)?;

            let ipv4_net = Ipv4Net::new(ipv4, 32).map_err(|e| {
                DpdError::InvalidRoute(format!("invalid IPv4 address: {}", e))
            })?;

            // Also delete from the underlying route tables
            route::delete_route_ipv4(s, ipv4_net).await?;
        }
        IpAddr::V6(ipv6) => {
            table::mcast::del_ipv6_entry(s, ipv6)?;

            let ipv6_net = Ipv6Net::new(ipv6, 128).map_err(|e| {
                DpdError::InvalidRoute(format!("invalid IPv6 address: {}", e))
            })?;

            // Also delete from the underlying route tables
            route::delete_route_ipv6(s, ipv6_net).await?;
        }
    }

    Ok(())
}

fn del_nat_entry(
    s: &Switch,
    group_id: MulticastGroupId,
    asic_id: AsicId,
) -> DpdResult<()> {
    table::mcast::del_nat_entry(s, group_id, asic_id)
}

/// Represents a multicast route configuration.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct MulticastRouteInfo {
    pub level1_excl_id: u16,
    pub level2_excl_id: u16,
    pub group_id: MulticastGroupId,
}

/// Represents a set of multicast routes mapping IP addresses to group IDs and
/// table parameters, as multicast routes can belong to multiple groups.
#[derive(Debug)]
struct MulticastRoutes {
    routes: HashMap<IpAddr, HashSet<MulticastRouteInfo>>,
}

impl MulticastRoutes {
    fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    fn add_route(
        &mut self,
        ip: IpAddr,
        group_id: MulticastGroupId,
        level1_excl_id: u16,
        level2_excl_id: u16,
    ) {
        let info = MulticastRouteInfo {
            level1_excl_id,
            level2_excl_id,
            group_id,
        };

        self.routes.entry(ip).or_default().insert(info);
    }

    fn remove_route(&mut self, ip: &IpAddr, group_id: MulticastGroupId) {
        if let Some(route_data) = self.routes.get_mut(ip) {
            route_data.retain(|info| info.group_id != group_id);
            if route_data.is_empty() {
                self.routes.remove(ip);
            }
        }
    }

    fn get_groups_for_route(&self, ip: &IpAddr) -> Vec<MulticastRouteInfo> {
        match self.routes.get(ip) {
            Some(info_set) => info_set.iter().cloned().collect(),
            None => Vec::new(),
        }
    }

    fn get_routes_for_group(&self, group_id: u16) -> Vec<IpAddr> {
        let mut routes = Vec::new();

        for (ip, info_set) in &self.routes {
            if info_set.iter().any(|i| i.group_id == group_id) {
                routes.push(*ip);
            }
        }

        routes
    }

    fn clear(&mut self) {
        self.routes.clear();
    }
}
