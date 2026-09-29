// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Routers, identified by the control plane's uuid.
//!
//! Each router is given one of the switch's routing tables, selected by the
//! `router_id` the P4 program matches on.  That number is chosen here and
//! never appears in the API.  The default router has the nil uuid, always
//! exists, and always uses table 0.
//!
//! The set of routers is kept in `RouteData`, under the same lock as the
//! routes.  Every router-scoped operation holds that lock from looking up
//! the router until it is done, so a router can't be deleted, and its table
//! number reused, in the middle of an operation.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::types::{DpdError, DpdResult};
use crate::{Switch, loopback, route};

/// The router that all pre-multi-router endpoints operate on.
pub const DEFAULT_ROUTER: Uuid = Uuid::nil();

/// Selects one of the switch's routing tables.  Table 0 is the default
/// router's.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouterId(pub u8);

impl std::fmt::Display for RouterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The routers that exist, and the routing table each one uses.
pub struct Routers(BTreeMap<Uuid, RouterId>);

impl Default for Routers {
    fn default() -> Self {
        Routers(BTreeMap::from([(DEFAULT_ROUTER, RouterId(0))]))
    }
}

impl Routers {
    /// The routing table used by `router`.
    pub fn get(&self, router: Uuid) -> DpdResult<RouterId> {
        self.0.get(&router).copied().ok_or_else(|| {
            DpdError::Missing(format!("no such router {router}"))
        })
    }

    fn create(&mut self, router: Uuid) -> DpdResult<()> {
        if self.0.contains_key(&router) {
            return Ok(());
        }
        let id = (1..=u8::MAX)
            .map(RouterId)
            .find(|id| !self.0.values().any(|used| used == id))
            .ok_or_else(|| {
                DpdError::ResourceExhausted(
                    "no routing tables available".into(),
                )
            })?;
        self.0.insert(router, id);
        Ok(())
    }
}

pub async fn list(switch: &Switch) -> Vec<Uuid> {
    let route_data = switch.routes.lock().await;
    route_data.routers.0.keys().copied().collect()
}

pub async fn create(switch: &Switch, router: Uuid) -> DpdResult<()> {
    let mut route_data = switch.routes.lock().await;
    route_data.routers.create(router)
}

/// Delete a router along with all of its routes and loopback addresses.
///
/// The router is forgotten only once everything under it has been removed,
/// so its table number is never reused while entries for it remain.  If a
/// removal fails, the router still exists and the delete can be retried.
pub async fn delete(switch: &Switch, router: Uuid) -> DpdResult<()> {
    if router == DEFAULT_ROUTER {
        return Err(DpdError::Invalid(
            "the default router can't be deleted".into(),
        ));
    }
    let mut route_data = switch.routes.lock().await;
    let Ok(rid) = route_data.routers.get(router) else {
        return Ok(());
    };
    route::delete_router_routes(switch, &mut route_data, rid)?;
    loopback::delete_router_ipv6(switch, rid)?;
    route_data.routers.0.remove(&router);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_router_exists() {
        let routers = Routers::default();
        assert_eq!(routers.get(DEFAULT_ROUTER).unwrap(), RouterId(0));
        assert!(matches!(
            routers.get(Uuid::new_v4()),
            Err(DpdError::Missing(_))
        ));
    }

    #[test]
    fn create_is_idempotent() {
        let mut routers = Routers::default();
        let router = Uuid::new_v4();
        routers.create(router).unwrap();
        let id = routers.get(router).unwrap();
        assert_eq!(id, RouterId(1));
        routers.create(router).unwrap();
        assert_eq!(routers.get(router).unwrap(), id);
        routers.create(DEFAULT_ROUTER).unwrap();
        assert_eq!(routers.get(DEFAULT_ROUTER).unwrap(), RouterId(0));
    }

    #[test]
    fn create_fails_when_tables_run_out() {
        let mut routers = Routers::default();
        let created: Vec<Uuid> =
            (1..=u8::MAX).map(|_| Uuid::new_v4()).collect();
        for router in &created {
            routers.create(*router).unwrap();
        }
        assert!(matches!(
            routers.create(Uuid::new_v4()),
            Err(DpdError::ResourceExhausted(_))
        ));

        // A table freed by a delete can be given to a new router.
        let freed = routers.get(created[9]).unwrap();
        routers.0.remove(&created[9]);
        let router = Uuid::new_v4();
        routers.create(router).unwrap();
        assert_eq!(routers.get(router).unwrap(), freed);
    }
}
