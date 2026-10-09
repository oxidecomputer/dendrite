// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use common::ports::Ipv6Entry;
use uuid::Uuid;

use dpd_types::route::DEFAULT_ROUTER;

use crate::route::{self, RouteData};
use crate::types::{DpdError, DpdResult};
use crate::{Switch, loopback};

/// A router's uuid, as used in the API.  The nil uuid (`DEFAULT_ROUTER`, also
/// `RouterUuid::default()`) names table 0.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouterUuid(Uuid);

impl RouterUuid {
    pub fn is_default(&self) -> bool {
        self.0 == DEFAULT_ROUTER
    }
}

impl From<Uuid> for RouterUuid {
    fn from(uuid: Uuid) -> Self {
        RouterUuid(uuid)
    }
}

impl From<RouterUuid> for Uuid {
    fn from(router: RouterUuid) -> Self {
        router.0
    }
}

impl std::fmt::Display for RouterUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The number of a routing table on the switch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RoutingTableId(u8);

/// The routing table for underlay routes and the `DEFAULT_ROUTER`.
impl Default for RoutingTableId {
    fn default() -> Self {
        RoutingTableId(0)
    }
}

impl From<u8> for RoutingTableId {
    fn from(table_id: u8) -> Self {
        RoutingTableId(table_id)
    }
}

impl From<RoutingTableId> for u8 {
    fn from(table_id: RoutingTableId) -> Self {
        table_id.0
    }
}

impl std::fmt::Display for RoutingTableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A logical router: its endpoint and its routing table id.
#[derive(Clone, Copy)]
struct Router {
    endpoint: Ipv6Addr,
    table_id: RoutingTableId,
}

/// The logical routers keyed by their control-plane uuid.
#[derive(Default)]
pub struct Routers(BTreeMap<RouterUuid, Router>);

impl Routers {
    /// The routing table used by `router_uuid`.
    pub fn table_id(
        &self,
        router_uuid: RouterUuid,
    ) -> DpdResult<RoutingTableId> {
        if router_uuid.is_default() {
            return Ok(RoutingTableId::default());
        }
        self.0.get(&router_uuid).map(|r| r.table_id).ok_or_else(|| {
            DpdError::Missing(format!("no such router {router_uuid}"))
        })
    }

    /// Checks if endpoint address is taken.
    pub fn check_not_endpoint(&self, addr: Ipv6Addr) -> DpdResult<()> {
        match self.0.iter().find(|(_, r)| r.endpoint == addr) {
            Some((router, _)) => Err(DpdError::Exists(format!(
                "{addr} is the endpoint of router {router}"
            ))),
            None => Ok(()),
        }
    }

    /// Lists endpoints by their uuids.
    pub fn list(&self) -> BTreeMap<Uuid, Ipv6Addr> {
        self.0
            .iter()
            .map(|(router, r)| ((*router).into(), r.endpoint))
            .collect()
    }

    /// Returns the endpoint of `router_uuid`.
    pub fn endpoint(&self, router_uuid: RouterUuid) -> DpdResult<Ipv6Addr> {
        self.0.get(&router_uuid).map(|r| r.endpoint).ok_or_else(|| {
            DpdError::Missing(format!("no such router {router_uuid}"))
        })
    }

    /// Create `router`, claiming `endpoint` as a loopback for the router's
    /// routing table.
    pub fn create(
        &mut self,
        switch: &Switch,
        router: RouterUuid,
        endpoint: Ipv6Addr,
    ) -> DpdResult<()> {
        if router.is_default() {
            return Err(DpdError::Invalid(format!(
                "router {router} names table 0, which can't be created"
            )));
        }
        if let Some(r) = self.0.get(&router) {
            if r.endpoint == endpoint {
                return Ok(());
            }
            return Err(DpdError::Exists(format!(
                "router {router} already has endpoint {}",
                r.endpoint
            )));
        }
        let table_id = (1..=u8::MAX)
            .map(RoutingTableId::from)
            .find(|table_id| self.0.values().all(|r| r.table_id != *table_id))
            .ok_or_else(|| {
                DpdError::TableFull("no routing tables available".into())
            })?;
        let entry = Ipv6Entry { tag: router.to_string(), addr: endpoint };
        loopback::add_loopback_ipv6(switch, &entry, table_id)?;
        self.0.insert(router, Router { endpoint, table_id });
        Ok(())
    }
}

/// Delete `router` along with its endpoint and routes.
///
/// The router is forgotten only once everything under it has been removed,
/// so its table is never given to another router while entries for it
/// remain.  If a removal fails, the router still exists and the delete can be
/// retried.
pub fn delete(
    switch: &Switch,
    route_data: &mut RouteData,
    router: RouterUuid,
) -> DpdResult<()> {
    if router.is_default() {
        return Err(DpdError::Invalid(format!(
            "router {router} names table 0, which can't be deleted"
        )));
    }
    remove(switch, route_data, router)
}

/// Delete every router.
pub fn reset(switch: &Switch, route_data: &mut RouteData) -> DpdResult<()> {
    let all: Vec<RouterUuid> = route_data.routers.0.keys().copied().collect();
    for router in all {
        remove(switch, route_data, router)?;
    }
    Ok(())
}

fn remove(
    switch: &Switch,
    route_data: &mut RouteData,
    router: RouterUuid,
) -> DpdResult<()> {
    let Some(&Router { endpoint, table_id }) =
        route_data.routers.0.get(&router)
    else {
        return Ok(());
    };
    loopback::delete_loopback_ipv6(switch, &endpoint)?;
    route::delete_table(switch, route_data, table_id)?;
    route_data.routers.0.remove(&router);
    Ok(())
}
