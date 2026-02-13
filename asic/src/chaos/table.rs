// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Mutex;

use crate::chaos::{Handle, table_unfurl};
use aal::{
    ActionParse, AsicError, AsicResult, CounterData, MatchParse, TableOps,
};
use common::table::TableType;

pub struct Table {
    name: String,
    type_: TableType,
    keys: Mutex<HashSet<u64>>,
}

impl TableOps<Handle> for Table {
    fn new(hdl: &Handle, type_: TableType) -> AsicResult<Table> {
        let name = type_.to_string();
        table_unfurl!(hdl, type_, table_new);
        Ok(Table { name, type_, keys: Mutex::new(HashSet::new()) })
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
        table_unfurl!(hdl, self.type_, table_clear);
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
        table_unfurl!(hdl, self.type_, table_entry_add);
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
        table_unfurl!(hdl, self.type_, table_entry_update);
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
        table_unfurl!(hdl, self.type_, table_entry_del);
        keys.remove(&x);
        Ok(())
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        _hdl: &Handle,
        _from_hardware: bool,
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
