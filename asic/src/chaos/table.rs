// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Mutex;

use crate::chaos::{table_unfurl, Handle};
use aal::{
    ActionParse, AsicError, AsicResult, CounterData, MatchParse, TableOps,
};

// These names line up with the table names in the sidecar P4 program.
pub const ROUTE_IPV4: &str = "pipe.Ingress.l3_router.routes_ipv4";
pub const ROUTE_IPV6: &str = "pipe.Ingress.l3_router.routes_ipv6";
pub const ARP_IPV4: &str = "pipe.Ingress.l3_router.arp_ipv4";
pub const NEIGHBOR_IPV6: &str = "pipe.Ingress.l3_router.neighbor_ipv6";
pub const MAC_REWRITE: &str = "pipe.Ingress.mac_rewrite.mac_rewrite";
pub const SWITCH_IPV4_ADDR: &str = "pipe.Ingress.filter.switch_ipv4_addr";
pub const SWITCH_IPV6_ADDR: &str = "pipe.Ingress.filter.switch_ipv6_addr";
pub const NAT_INGRESS_IPV4: &str = "pipe.Ingress.nat_ingress.ingress_ipv4";
pub const NAT_INGRESS_IPV6: &str = "pipe.Ingress.nat_ingress.ingress_ipv6";

pub struct Table {
    name: String,
    keys: Mutex<HashSet<u64>>,
}

impl TableOps<Handle> for Table {
    fn new(hdl: &Handle, name: &str) -> AsicResult<Table> {
        table_unfurl!(hdl, name, table_new);
        Ok(Table {
            name: name.into(),
            keys: Mutex::new(HashSet::new()),
        })
    }

    fn size(&self) -> usize {
        // The table size must be large enough to allow the maximum number of
        // entries inserted by the chaos tests.  Inserts may still fail
        // chaotically, but we can't allow them to fail deterministically.
        // Otherwise the test will get the wrong error code:
        // INSUFFICIENT_STORAGE rather than the expected IM_A_TEAPOT.
        1024
    }

    fn clear(&self, hdl: &Handle) -> AsicResult<()> {
        table_unfurl!(hdl, &self.name, table_clear);
        let mut keys = self.keys.lock().unwrap();
        *keys = HashSet::new();
        Ok(())
    }

    fn entry_add<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        _data: &A,
    ) -> AsicResult<()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let x: u64 = hasher.finish();

        let mut keys = self.keys.lock().unwrap();
        if keys.contains(&x) {
            return Err(AsicError::Exists);
        }
        table_unfurl!(hdl, &self.name, table_entry_add);
        keys.insert(x);
        Ok(())
    }

    fn entry_update<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        _data: &A,
    ) -> AsicResult<()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let x: u64 = hasher.finish();

        let keys = self.keys.lock().unwrap();
        if !keys.contains(&x) {
            return Err(AsicError::Missing(
                "table entry not found".to_string(),
            ));
        }
        table_unfurl!(hdl, &self.name, table_entry_update);
        Ok(())
    }

    fn entry_del<M: MatchParse + Hash>(
        &self,
        hdl: &Handle,
        key: &M,
    ) -> AsicResult<()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let x: u64 = hasher.finish();

        let mut keys = self.keys.lock().unwrap();
        if !keys.contains(&x) {
            return Err(AsicError::Missing(
                "table entry not found".to_string(),
            ));
        }
        table_unfurl!(hdl, &self.name, table_entry_del);
        keys.remove(&x);
        Ok(())
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        _hdl: &Handle,
    ) -> AsicResult<Vec<(M, A)>> {
        Err(AsicError::OperationUnsupported)
    }

    fn get_counters<M: MatchParse>(
        &self,
        _hdl: &Handle,
        _force_sync: bool,
    ) -> AsicResult<Vec<(M, CounterData)>> {
        Err(AsicError::OperationUnsupported)
    }
}
